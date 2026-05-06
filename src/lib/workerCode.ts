export const WORKER_CODE = `
self.onmessage = async function(e) {
  const { type, file, text, fileIndex, fileName } = e.data;
  const TS_PATTERNS = [
    /^\\[\\d{4}-\\d{2}-\\d{2}\\s\\d{2}:\\d{2}:\\d{2}\\]/,
    /^\\[(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\\s+\\d+\\s+\\d{2}:\\d{2}:\\d{2}\\]/,
    /^\\[?\\d{2}\\/\\w{3}\\/\\d{4}:\\d{2}:\\d{2}:\\d{2}\\s[+-]\\d{4}\\]?/,
    /^\\d{4}\\/\\d{2}\\/\\d{2} \\d{2}:\\d{2}:\\d{2} \\[(?:error|warn|notice|info|crit|alert|emerg)\\]/,
    /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\\s+\\d+\\s+\\d{2}:\\d{2}:\\d{2}/,
    /\\d{4}[-/]\\d{2}[-/]\\d{2}[T\\s]\\d{2}:\\d{2}:\\d{2}/
  ];
  const FORMATS = ['asterisk','asterisk-short','nginx/apache','nginx/error','syslog','generic'];
  const BUCKET_MS = 60000;
  const buckets = {};
  const bucketSamples = {};
  const groups = {};
  let lineCount = 0, bytesProcessed = 0;
  const fileSize = (type === 'file' && file) ? file.size : (text ? text.length : 0);
  let format = 'unknown', formatLocked = false, firstTs = null, lastTs = null, pendingBlock = '';
  const severity = { error: 0, warn: 0, info: 0, debug: 0, other: 0 };

  function isLogLine(line) {
    const l = line.trim();
    if (!l) return false;
    if (/^\\s*</.test(l) || /^HTTP\\//.test(l) || /^\\{/.test(l) || /^#/.test(l) || /^;/.test(l)) return false;
    return TS_PATTERNS.some(p => p.test(l));
  }

  function getFmt(line) {
    for (let i = 0; i < TS_PATTERNS.length; i++) {
      if (TS_PATTERNS[i].test(line)) return FORMATS[i];
    }
    return 'unknown';
  }

  function getTS(line) {
    const patterns = [
      { re: /(\\d{4})\\/(\\d{2})\\/(\\d{2}) (\\d{2}:\\d{2}:\\d{2})/, fmt: (m) => m[1]+'-'+m[2]+'-'+m[3]+' '+m[4] },
      { re: /\\[(\\d{2})\\/(\\w{3})\\/(\\d{4}):(\\d{2}:\\d{2}:\\d{2})\\s[+-]\\d{4}\\]/, fmt: (m) => { const mn={Jan:'01',Feb:'02',Mar:'03',Apr:'04',May:'05',Jun:'06',Jul:'07',Aug:'08',Sep:'09',Oct:'10',Nov:'11',Dec:'12'}; return m[3]+'-'+(mn[m[2]]||'01')+'-'+m[1]+' '+m[4]; } },
      { re: /\\[(\\d{4}-\\d{2}-\\d{2}\\s\\d{2}:\\d{2}:\\d{2})\\]/, fmt: (m) => m[1] },
      { re: /^\\[(\\w{3})\\s+(\\d+)\\s+(\\d{2}:\\d{2}:\\d{2})\\]/, fmt: (m) => { const mn={Jan:'01',Feb:'02',Mar:'03',Apr:'04',May:'05',Jun:'06',Jul:'07',Aug:'08',Sep:'09',Oct:'10',Nov:'11',Dec:'12'}; return new Date().getFullYear()+'-'+(mn[m[1]]||'01')+'-'+m[2].padStart(2,'0')+' '+m[3]; } },
      { re: /^(\\w{3})\\s+(\\d+)\\s+(\\d{2}:\\d{2}:\\d{2})/, fmt: (m) => { const mn={Jan:'01',Feb:'02',Mar:'03',Apr:'04',May:'05',Jun:'06',Jul:'07',Aug:'08',Sep:'09',Oct:'10',Nov:'11',Dec:'12'}; return new Date().getFullYear()+'-'+(mn[m[1]]||'01')+'-'+m[2].padStart(2,'0')+' '+m[3]; } },
      { re: /(\\d{4}-\\d{2}-\\d{2}[T\\s]\\d{2}:\\d{2}:\\d{2})/, fmt: (m) => m[1].replace('T',' ') }
    ];
    for (const p of patterns) {
      const m = line.match(p.re);
      if (m) {
        try {
          const ts = new Date(p.fmt(m)).getTime();
          if (!isNaN(ts)) return ts;
        } catch(err) {}
      }
    }
    return null;
  }

  function getSeverity(line) {
    const u = line.toUpperCase();
    if (/\\b(ERROR|FATAL|CRIT|ALERT|EMERG|CRITICAL)\\b/.test(u)) return 'error';
    if (/\\b(WARN|WARNING|NOTICE)\\b/.test(u)) return 'warn';
    if (/\\b(INFO|INFORMATION|NOTICE)\\b/.test(u)) return 'info';
    if (/\\b(DEBUG|TRACE|VERBOSE)\\b/.test(u)) return 'debug';
    return 'other';
  }

  function norm(line) {
    return line
      .replace(/\\b\\d{1,3}(\\.\\d{1,3}){3}\\b/g,'<IP>')
      .replace(/\\b\\d{4}[-/]\\d{2}[-/]\\d{2}[T\\s]\\d{2}:\\d{2}:\\d{2}[^\\s,]*/g,'<TS>')
      .replace(/\\b\\d{4}\\/\\d{2}\\/\\d{2} \\d{2}:\\d{2}:\\d{2}/g,'<TS>')
      .replace(/\\b\\d{1,5}\\b/g,'<N>')
      .replace(/\\b[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\\b/gi,'<UUID>')
      .replace(/\\*\\d+/g,'<CONN>')
      .replace(/#\\d+/g,'<PID>')
      .replace(/\\b[a-f0-9]{6,}\\b/gi,'<HEX>')
      .replace(/\\?.*?(?=["\\s]|$)/g,'?<PARAMS>')
      .trim();
  }

  function processBlock(block) {
    if (!block || !block.trim()) return;
    const lines = block.split('\\n');
    const firstLogLine = lines.find(isLogLine);
    if (!firstLogLine) return;
    lineCount++;
    if (!formatLocked) {
      format = getFmt(firstLogLine) || format;
      if (format !== 'unknown') formatLocked = true;
    }
    const ts = getTS(firstLogLine);
    if (ts) {
      const bucket = Math.floor(ts / BUCKET_MS) * BUCKET_MS;
      buckets[bucket] = (buckets[bucket] || 0) + 1;
      if (!bucketSamples[bucket]) bucketSamples[bucket] = [];
      if (bucketSamples[bucket].length < 15) bucketSamples[bucket].push(firstLogLine);
      if (!firstTs) firstTs = ts;
      lastTs = ts;
    }
    const sev = getSeverity(firstLogLine);
    severity[sev] = (severity[sev] || 0) + 1;
    const tpl = norm(block.replace(/\\n/g,' | '));
    groups[tpl] = (groups[tpl] || 0) + 1;
  }

  try {
    if (type === 'file' && file) {
      const CHUNK = 1024 * 1024;
      let offset = 0, buffer = '';
      while (offset < file.size) {
        const blob = file.slice(offset, offset + CHUNK);
        const txt = await new Promise((res, rej) => {
          const r = new FileReader();
          r.onload = () => res(r.result);
          r.onerror = rej;
          r.readAsText(blob);
        });
        buffer += txt;
        const parts = buffer.split('\\n');
        buffer = parts.pop();
        for (const l of parts) {
          if (isLogLine(l) && pendingBlock) { processBlock(pendingBlock); pendingBlock = ''; }
          pendingBlock += (pendingBlock ? '\\n' : '') + l;
        }
        bytesProcessed = offset + txt.length;
        self.postMessage({ type: 'progress', percent: Math.min(bytesProcessed / fileSize * 100, 99), lines: lineCount, fileIndex });
        offset += CHUNK;
      }
      if (buffer.trim()) pendingBlock += '\\n' + buffer;
      if (pendingBlock.trim()) processBlock(pendingBlock);
    } else if (type === 'text' && text) {
      const lines = text.split('\\n');
      for (let i = 0; i < lines.length; i++) {
        const l = lines[i];
        if (isLogLine(l) && pendingBlock) { processBlock(pendingBlock); pendingBlock = ''; }
        pendingBlock += (pendingBlock ? '\\n' : '') + l;
        if (i % 20000 === 0) {
          self.postMessage({ type: 'progress', percent: Math.min(i / lines.length * 100, 99), lines: lineCount, fileIndex });
        }
      }
      if (pendingBlock.trim()) processBlock(pendingBlock);
    }
    self.postMessage({
      type: 'done',
      fileIndex,
      data: { buckets, bucketSamples, groups, lineCount, format, firstTs, lastTs, fileName: fileName || 'Unknown', severity }
    });
  } catch (err) {
    self.postMessage({ type: 'error', message: err.message, fileIndex });
  }
};
`;
