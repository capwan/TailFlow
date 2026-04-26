document.addEventListener('DOMContentLoaded', () => {

  // ==================== WORKER CODE (INLINE) ====================
  const workerCode = `
    self.onmessage = async function(e) {
      const { type, file, text } = e.data;
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
      const buckets = {}; const bucketSamples = {}; const groups = {};
      let lineCount = 0, bytesProcessed = 0;
      let fileSize = (type === 'file' && file) ? file.size : (text ? text.length : 0);
      let format = 'unknown', formatLocked = false, firstTs = null, lastTs = null, pendingBlock = '';

      function isLogLine(line) { const l = line.trim(); if (!l) return false; if (/^\\s*</.test(l) || /^HTTP\\//.test(l) || /^\\{/.test(l) || /^#/.test(l) || /^;/.test(l)) return false; return TS_PATTERNS.some(p => p.test(l)); }
      function getFmt(line) { for (let i = 0; i < TS_PATTERNS.length; i++) if (TS_PATTERNS[i].test(line)) return FORMATS[i]; return 'unknown'; }
      function getTS(line) {
        const patterns = [
          { re: /^(\\d{4})\\/(\\d{2})\\/(\\d{2}) (\\d{2}:\\d{2}:\\d{2})/, fmt: (m) => m[1]+'-'+m[2]+'-'+m[3]+' '+m[4] },
          { re: /\\[(\\d{2})\\/(\\w{3})\\/(\\d{4}):(\\d{2}:\\d{2}:\\d{2})\\s[+-]\\d{4}\\]/, fmt: (m) => { const mnt = {Jan:'01',Feb:'02',Mar:'03',Apr:'04',May:'05',Jun:'06',Jul:'07',Aug:'08',Sep:'09',Oct:'10',Nov:'11',Dec:'12'}; return m[3]+'-'+(mnt[m[2]]||'01')+'-'+m[1]+' '+m[4]; } },
          { re: /\\[(\\d{4}-\\d{2}-\\d{2}\\s\\d{2}:\\d{2}:\\d{2})\\]/, fmt: (m) => m[1] },
          { re: /^\\[(\\w{3})\\s+(\\d+)\\s+(\\d{2}:\\d{2}:\\d{2})\\]/, fmt: (m) => { const mnt = {Jan:'01',Feb:'02',Mar:'03',Apr:'04',May:'05',Jun:'06',Jul:'07',Aug:'08',Sep:'09',Oct:'10',Nov:'11',Dec:'12'}; return new Date().getFullYear()+'-'+(mnt[m[1]]||'01')+'-'+m[2].padStart(2,'0')+' '+m[3]; } },
          { re: /^(\\w{3})\\s+(\\d+)\\s+(\\d{2}:\\d{2}:\\d{2})/, fmt: (m) => { const mnt = {Jan:'01',Feb:'02',Mar:'03',Apr:'04',May:'05',Jun:'06',Jul:'07',Aug:'08',Sep:'09',Oct:'10',Nov:'11',Dec:'12'}; return new Date().getFullYear()+'-'+(mnt[m[1]]||'01')+'-'+m[2].padStart(2,'0')+' '+m[3]; } },
          { re: /(\\d{4}-\\d{2}-\\d{2}[T\\s]\\d{2}:\\d{2}:\\d{2})/, fmt: (m) => m[1].replace('T', ' ') }
        ];
        for (const p of patterns) { const m = line.match(p.re); if (m) { try { const ts = new Date(p.fmt(m)).getTime(); if (!isNaN(ts)) return ts; } catch(e) {} } } return null;
      }
      function norm(line) {
        return line.replace(/\\b\\d{1,3}(\\.\\d{1,3}){3}\\b/g, '<IP>').replace(/\\b\\d{4}[-/]\\d{2}[-/]\\d{2}[T\\s]\\d{2}:\\d{2}:\\d{2}[^\\s,]*/g, '<TS>')
                   .replace(/\\b\\d{4}\\/\\d{2}\\/\\d{2} \\d{2}:\\d{2}:\\d{2}/g, '<TS>').replace(/\\b\\d{1,5}\\b/g, '<N>')
                   .replace(/\\b[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\\b/gi, '<UUID>').replace(/\\*\\d+/g, '<CONN>').replace(/#\\d+/g, '<PID>')
                   .replace(/\\b[a-f0-9]{6,}\\b/gi, '<HEX>').replace(/\\?.*?(?=["\\s]|$)/g, '?<PARAMS>').trim();
      }
      function processBlock(block) {
        if (!block || !block.trim()) return; const lines = block.split('\\n'); const firstLogLine = lines.find(isLogLine); if (!firstLogLine) return;
        lineCount++;
        if (!formatLocked) { format = getFmt(firstLogLine) || format; if (format !== 'unknown') formatLocked = true; }
        const ts = getTS(firstLogLine);
        if (ts) {
          const bucket = Math.floor(ts / BUCKET_MS) * BUCKET_MS; buckets[bucket] = (buckets[bucket] || 0) + 1;
          if (!bucketSamples[bucket]) bucketSamples[bucket] = [];
          if (bucketSamples[bucket].length < 15) bucketSamples[bucket].push(firstLogLine);
          if (!firstTs) firstTs = ts; lastTs = ts;
        }
        const tpl = norm(block.replace(/\\n/g, ' | ')); groups[tpl] = (groups[tpl] || 0) + 1;
      }
      try {
        if (type === 'file' && file) {
          const CHUNK = 1024 * 1024; let offset = 0, buffer = '';
          while (offset < file.size) {
            const blob = file.slice(offset, offset + CHUNK);
            const txt = await new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(r.result); r.onerror = rej; r.readAsText(blob); });
            buffer += txt; const parts = buffer.split('\\n'); buffer = parts.pop();
            for (const l of parts) { if (isLogLine(l) && pendingBlock) { processBlock(pendingBlock); pendingBlock = ''; } pendingBlock += (pendingBlock ? '\\n' : '') + l; }
            bytesProcessed = offset + txt.length;
            self.postMessage({ type: 'progress', percent: Math.min(bytesProcessed / fileSize * 100, 99), lines: lineCount });
            offset += CHUNK;
          }
          if (buffer.trim()) pendingBlock += '\\n' + buffer;
          if (pendingBlock.trim()) processBlock(pendingBlock);
        } else if (type === 'text' && text) {
          const lines = text.split('\\n');
          for (let i = 0; i < lines.length; i++) { const l = lines[i]; if (isLogLine(l) && pendingBlock) { processBlock(pendingBlock); pendingBlock = ''; } pendingBlock += (pendingBlock ? '\\n' : '') + l; if (i % 20000 === 0) self.postMessage({ type: 'progress', percent: Math.min(i / lines.length * 100, 99), lines: lineCount }); }
          if (pendingBlock.trim()) processBlock(pendingBlock);
        }
        self.postMessage({ type: 'done', data: { buckets: buckets, bucketSamples: bucketSamples, groups: groups, lineCount: lineCount, format: format, firstTs: firstTs, lastTs: lastTs } });
      } catch (err) { self.postMessage({ type: 'error', message: err.message }); }
    };
  `;

  // ==================== DOM ELEMENTS ====================
  const $ = id => document.getElementById(id);
  const els = {
    fileZone: $('fileZone'),
    pasteZone: $('pasteZone'),
    fileInput: $('fileInput'),
    pasteInput: $('pasteInput'),
    parsePasteBtn: $('parsePasteBtn'),
    progressBar: $('progressBar'),
    status: $('status'),
    controls: $('controls'),
    filterInput: $('filterInput'),
    exportBtn: $('exportBtn'),
    statsPanel: $('statsPanel'),
    totalLines: $('totalLines'),
    format: $('format'),
    timeRange: $('timeRange'),
    uniqueGroups: $('uniqueGroups'),
    chartWrap: $('chartWrap'),
    chart: $('chart'),
    chartTooltip: $('chartTooltip'),
    groupsContainer: $('groupsContainer'),
    historyPanel: $('historyPanel'),
    historyList: $('historyList'),
    historyBtn: $('historyBtn'),
    clearHistoryBtn: $('clearHistoryBtn'),
    compareBtn: $('compareBtn'),
    detailModal: $('detailModal'),
    detailTitle: $('detailTitle'),
    detailContent: $('detailContent'),
    closeDetailBtn: $('closeDetailBtn'),
    compareModal: $('compareModal'),
    compareContent: $('compareContent'),
    closeCompareBtn: $('closeCompareBtn'),
    tzSelect: $('tzSelect'),
    formatToggle: $('formatToggle'),
    themeToggle: $('themeToggle'),
    tabs: document.querySelectorAll('.tab')
  };

  // ==================== STATE ====================
  let lastParsedData = null, prevParsedData = null, workerBusy = false, currentFileName = 'File';
  let worker, selectedBucket = null;
  const settings = { tz: 'Local', hour12: false, theme: 'dark' };

  // ==================== HELPERS ====================

  // Apply light or dark theme class on body
  function applyTheme(theme) {
    if (theme === 'light') {
      document.body.classList.add('light');
    } else {
      document.body.classList.remove('light');
    }
  }

  // Load settings from localStorage and apply
  function loadSettings() {
    const s = JSON.parse(localStorage.getItem('tailflow_settings') || '{}');
    if (s.tz === 'Local' || s.tz === 'UTC') settings.tz = s.tz;
    if (typeof s.hour12 === 'boolean') settings.hour12 = s.hour12;
    settings.theme = s.theme === 'light' ? 'light' : 'dark'; // default dark
    els.tzSelect.value = settings.tz;
    els.formatToggle.textContent = settings.hour12 ? '12h' : '24h';
    applyTheme(settings.theme);
  }

  // Save settings to localStorage and re-render if data present
  function saveSettings() {
    localStorage.setItem('tailflow_settings', JSON.stringify(settings));
    if (lastParsedData) renderUI(lastParsedData);
  }

  // Time formatter respecting timezone and 12/24h
  function getTimeFormatter() {
    return new Intl.DateTimeFormat('en-US', {
      timeZone: settings.tz === 'Local' ? undefined : settings.tz,
      hour12: settings.hour12,
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hourCycle: settings.hour12 ? 'h12' : 'h23'
    });
  }

  function getDateFormatter() {
    return new Intl.DateTimeFormat('en-US', {
      timeZone: settings.tz === 'Local' ? undefined : settings.tz,
      year: 'numeric', month: 'short', day: '2-digit'
    });
  }

  function formatTime(ts) { return getTimeFormatter().format(new Date(ts)); }
  function formatDate(ts) { return getDateFormatter().format(new Date(ts)) + ' ' + formatTime(ts); }

  // Reset UI to initial state
  function resetUI() {
    els.progressBar.style.width = '0%';
    els.status.textContent = 'Ready to analyze logs';
    els.statsPanel.classList.add('hidden');
    els.chartWrap.classList.add('hidden');
    els.groupsContainer.classList.add('hidden');
    els.controls.classList.add('hidden');
    els.filterInput.value = '';
    els.compareBtn.disabled = true;
  }

  // Render UI with parsed data
  function renderUI(d) {
    els.statsPanel.classList.remove('hidden');
    els.chartWrap.classList.remove('hidden');
    els.groupsContainer.classList.remove('hidden');
    els.controls.classList.remove('hidden');
    els.totalLines.textContent = d.lineCount.toLocaleString();
    els.format.textContent = d.format;
    if (d.firstTs) els.timeRange.textContent = formatDate(d.firstTs) + ' → ' + formatTime(d.lastTs);
    els.uniqueGroups.textContent = Object.keys(d.groups).length.toLocaleString();
    drawHistogram(d.buckets, d.bucketSamples);
    renderGroups(d.groups, els.filterInput.value);
  }

  // Syntax highlighting for log templates
  function hl(text) {
    return text.replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/(<IP>)/g, '<span class="hl-ip">$1</span>')
      .replace(/(<TS>)/g, '<span class="hl-ts">$1</span>')
      .replace(/(<CONN>|<PID>|<N>)/g, '<span class="hl-num">$1</span>')
      .replace(/(<HEX>|<UUID>)/g, '<span class="hl-uuid">$1</span>')
      .replace(/(\\b(?:ERROR|FATAL|CRIT|ALERT|EMERG)\\b)/gi, '<span class="hl-err">$1</span>')
      .replace(/(\\b(?:WARN|WARNING|NOTICE)\\b)/gi, '<span class="hl-warn">$1</span>');
  }

  // Render grouped patterns list with optional filter
  function renderGroups(groups, query) {
    query = query || '';
    els.groupsContainer.innerHTML = '';
    const q = query.toLowerCase();
    const sorted = Object.entries(groups)
      .filter(([tpl]) => !q || tpl.toLowerCase().includes(q))
      .sort((a, b) => b[1] - a[1])
      .slice(0, 1000);
    if (!sorted.length) {
      els.groupsContainer.innerHTML = '<div class="group"><div class="tpl">No matches found</div></div>';
      return;
    }
    for (const [tpl, count] of sorted) {
      const div = document.createElement('div');
      div.className = 'group';
      div.innerHTML = '<div class="tpl">' + hl(tpl) + '</div><div class="cnt">' + count.toLocaleString() + '×</div>';
      els.groupsContainer.appendChild(div);
    }
  }

  // Draw interactive histogram on canvas
  function drawHistogram(buckets, bucketSamples) {
    const canvas = els.chart;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    canvas.width = canvas.clientWidth * dpr;
    canvas.height = canvas.clientHeight * dpr;
    ctx.scale(dpr, dpr);
    const keys = Object.keys(buckets).map(Number).sort((a, b) => a - b);
    if (!keys.length) return;
    const max = Math.max(...Object.values(buckets));
    const w = canvas.clientWidth, h = canvas.clientHeight;
    const pad = { t: 20, r: 10, b: 30, l: 40 };
    const plotW = w - pad.l - pad.r, plotH = h - pad.t - pad.b;
    const barW = Math.max(2, (plotW / keys.length) - 2);

    ctx.fillStyle = '#15181e';
    ctx.fillRect(0, 0, w, h);
    ctx.strokeStyle = '#334155';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(pad.l, pad.t);
    ctx.lineTo(pad.l, h - pad.b);
    ctx.lineTo(w - pad.r, h - pad.b);
    ctx.stroke();

    ctx.fillStyle = '#94a3b8';
    ctx.font = '11px system-ui';
    ctx.textAlign = 'right';
    for (let i = 0; i <= 4; i++) {
      const val = Math.round(max * (i / 4));
      ctx.fillText(val.toLocaleString(), pad.l - 5, h - pad.b - (plotH * (i / 4)) + 4);
    }

    ctx.textAlign = 'center';
    const step = Math.max(1, Math.floor(keys.length / 6));
    keys.forEach((k, i) => {
      if (i % step === 0 || i === keys.length - 1) {
        ctx.fillText(formatTime(k), pad.l + i * (barW + 2) + barW / 2, h - pad.b + 18);
      }
    });

    window._chartMap = [];
    window._bucketSamples = bucketSamples;
    keys.forEach((k, i) => {
      const val = buckets[k];
      const barH = (val / max) * plotH;
      const x = pad.l + i * (barW + 2);
      const y = h - pad.b - barH;
      ctx.fillStyle = (val / max) > 0.8 ? '#ef4444' : (val / max) > 0.5 ? '#f59e0b' : '#3b82f6';
      ctx.fillRect(x, y, barW, barH);
      window._chartMap.push({ x, y, w: barW, h: barH, time: k, val });
    });
    ctx.fillStyle = '#e2e8f0';
    ctx.font = '13px system-ui';
    ctx.textAlign = 'left';
    ctx.fillText('📈 Events Timeline (by minute)', pad.l, 14);
  }

  // Show detail modal for a selected time bucket
  function showDetails(time) {
    const samples = window._bucketSamples?.[time] || [];
    els.detailTitle.textContent = formatDate(time) + ' (' + (window._chartMap?.find(b => b.time === time)?.val || 0) + ' events)';
    let html = samples.length
      ? samples.map(s => `<div class="detail-row">${s.replace(/</g, '&lt;')}</div>`).join('')
      : '<div style="color:var(--muted);padding:16px;text-align:center">No raw logs captured for this bucket.</div>';
    els.detailContent.innerHTML = html;
    els.detailModal.classList.add('open');

    // Click a row to copy log line to clipboard
    els.detailContent.querySelectorAll('.detail-row').forEach(row => {
      row.addEventListener('click', () => {
        navigator.clipboard.writeText(row.textContent.trim());
        row.style.background = '#1e3a5f';
        setTimeout(() => row.style.background = '', 200);
      });
    });
  }

  // Export analysis as JSON
  function exportData() {
    if (!lastParsedData) return alert('No data to export');
    const p = {
      meta: { format: lastParsedData.format, lines: lastParsedData.lineCount, range: [lastParsedData.firstTs, lastParsedData.lastTs] },
      histogram: lastParsedData.buckets,
      groups: Object.entries(lastParsedData.groups).sort((a, b) => b[1] - a[1]).slice(0, 500).map(([t, c]) => ({ template: t, count: c }))
    };
    const b = new Blob([JSON.stringify(p, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(b);
    a.download = 'tailflow-' + (currentFileName || 'export') + '-' + Date.now() + '.json';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  // Save analysis to history in localStorage
  function saveToHistory(name, d) {
    try {
      const h = JSON.parse(localStorage.getItem('tailflow_history') || '[]');
      h.unshift({
        id: Date.now(),
        name,
        date: new Date().toLocaleString('en-US', { timeZone: settings.tz === 'Local' ? undefined : settings.tz }),
        lines: d.lineCount,
        format: d.format
      });
      if (h.length > 10) h.pop();
      localStorage.setItem('tailflow_history', JSON.stringify(h));
      renderHistory();
    } catch (e) { console.warn(e); }
  }

  // Render history panel
  function renderHistory() {
    const h = JSON.parse(localStorage.getItem('tailflow_history') || '[]');
    els.historyList.innerHTML = h.length
      ? ''
      : '<div style="color:var(--muted);padding:10px;text-align:center">No history yet</div>';
    h.forEach(i => {
      els.historyList.innerHTML += `<div class="history-item"><div class="h-title">${i.name}</div><div class="h-meta">${i.date} · ${i.lines.toLocaleString()} lines · ${i.format}</div></div>`;
    });
  }

  // Compare current and previous analysis
  function openCompare() {
    if (!prevParsedData || !lastParsedData) return;
    const curr = lastParsedData.groups, prev = prevParsedData.groups;
    const all = [...new Set([...Object.keys(curr), ...Object.keys(prev)])].sort((a, b) => (curr[b] || 0) - (curr[a] || 0));
    let html = '';
    all.forEach(k => {
      const c = curr[k] || 0, p = prev[k] || 0;
      if (c === p && c === 0) return;
      const cls = p === 0 ? 'diff-new' : (c === 0 ? 'diff-old' : 'diff-chg');
      html += `<div class="compare-row"><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${k}</span><span class="${cls}">${p || '-'} → ${c || '-'}</span></div>`;
    });
    els.compareContent.innerHTML = html || '<div style="color:var(--muted);text-align:center;padding:16px">No differences</div>';
    els.compareModal.classList.add('open');
  }

  // Start file processing via worker
  function parseFile(file) {
    if (workerBusy) { els.status.textContent = '⏳ Processing...'; return; }
    currentFileName = file.name;
    workerBusy = true;
    prevParsedData = lastParsedData;
    els.status.textContent = '⏳ Starting...';
    els.progressBar.style.width = '0%';
    resetUI();
    worker.postMessage({ type: 'file', file });
  }

  // ==================== EVENT LISTENERS ====================

  // Tab switching (File / Paste)
  els.tabs.forEach(t => {
    t.addEventListener('click', () => {
      els.tabs.forEach(x => x.classList.remove('active'));
      t.classList.add('active');
      els.fileZone.classList.toggle('hidden', t.dataset.mode !== 'file');
      els.pasteZone.classList.toggle('hidden', t.dataset.mode !== 'paste');
      resetUI();
    });
  });

  // File drop zone
  els.fileZone.addEventListener('click', () => els.fileInput.click());
  els.fileZone.addEventListener('dragover', e => { e.preventDefault(); els.fileZone.classList.add('dragover'); });
  els.fileZone.addEventListener('dragleave', () => els.fileZone.classList.remove('dragover'));
  els.fileZone.addEventListener('drop', e => {
    e.preventDefault();
    els.fileZone.classList.remove('dragover');
    const f = e.dataTransfer.files[0];
    if (f) parseFile(f);
  });
  els.fileInput.addEventListener('change', e => {
    if (e.target.files[0]) parseFile(e.target.files[0]);
  });

  // Paste zone
  els.parsePasteBtn.addEventListener('click', () => {
    const txt = els.pasteInput.value.trim();
    if (!txt) return alert('Please paste log content');
    currentFileName = 'Pasted Text';
    if (txt.length > 10_000_000 && !confirm('Text >10 MB may slow down the browser. Continue?')) return;
    worker.postMessage({ type: 'text', text: txt });
  });

  // Filter
  els.filterInput.addEventListener('input', () => {
    if (lastParsedData) renderGroups(lastParsedData.groups, els.filterInput.value);
  });

  // Export / History / Compare buttons
  els.exportBtn.addEventListener('click', exportData);
  els.historyBtn.addEventListener('click', () => els.historyPanel.classList.toggle('open'));
  els.compareBtn.addEventListener('click', openCompare);
  els.clearHistoryBtn.addEventListener('click', () => {
    localStorage.removeItem('tailflow_history');
    renderHistory();
  });

  // Close modals
  els.closeDetailBtn.addEventListener('click', () => els.detailModal.classList.remove('open'));
  els.closeCompareBtn.addEventListener('click', () => els.compareModal.classList.remove('open'));

  // Settings: timezone
  els.tzSelect.addEventListener('change', e => {
    settings.tz = e.target.value;
    saveSettings();
  });

  // Settings: 12/24h format
  els.formatToggle.addEventListener('click', () => {
    settings.hour12 = !settings.hour12;
    els.formatToggle.textContent = settings.hour12 ? '12h' : '24h';
    saveSettings();
  });

  // Settings: theme toggle
  els.themeToggle.addEventListener('click', () => {
    settings.theme = settings.theme === 'dark' ? 'light' : 'dark';
    applyTheme(settings.theme);
    saveSettings();
  });

  // Chart interactions
  els.chart.addEventListener('mousemove', e => {
    const rect = els.chart.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    const hit = window._chartMap?.find(b => mx >= b.x && mx <= b.x + b.w && my >= b.y && my <= b.y + b.h);
    const tt = els.chartTooltip;
    if (!hit) {
      tt.style.opacity = 0;
      selectedBucket = null;
      return;
    }
    selectedBucket = hit.time;
    tt.style.opacity = 1;
    tt.style.left = Math.min(e.clientX - rect.left + 10, rect.width - 180) + 'px';
    tt.style.top = (e.clientY - rect.top - 8) + 'px';
    tt.querySelector('.tt-time').textContent = formatDate(hit.time);
    tt.querySelector('.tt-val').textContent = hit.val.toLocaleString() + ' events in this minute';
  });

  els.chart.addEventListener('click', () => {
    if (selectedBucket) showDetails(selectedBucket);
  });

  // Close modals with Escape key
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      if (els.detailModal.classList.contains('open')) els.detailModal.classList.remove('open');
      if (els.compareModal.classList.contains('open')) els.compareModal.classList.remove('open');
    }
  });

  // Close modals by clicking on overlay
  els.detailModal.addEventListener('click', e => {
    if (e.target === els.detailModal) els.detailModal.classList.remove('open');
  });
  els.compareModal.addEventListener('click', e => {
    if (e.target === els.compareModal) els.compareModal.classList.remove('open');
  });

  // ==================== WORKER INIT ====================
  function initWorker() {
    try {
      const blob = new Blob([workerCode], { type: 'application/javascript' });
      worker = new Worker(URL.createObjectURL(blob));
      worker.onmessage = e => {
        const m = e.data;
        if (m.type === 'progress') {
          els.progressBar.style.width = m.percent.toFixed(1) + '%';
          els.status.textContent = '🔄 ' + m.lines.toLocaleString() + ' lines';
        } else if (m.type === 'done') {
          lastParsedData = m.data;
          renderUI(m.data);
          saveToHistory(currentFileName, m.data);
          workerBusy = false;
          els.status.textContent = '✅ Analysis complete';
          els.compareBtn.disabled = !prevParsedData;
        } else if (m.type === 'error') {
          els.status.textContent = '⚠️ Error: ' + m.message;
          console.error(m.message);
          workerBusy = false;
        }
      };
      worker.onerror = e => {
        els.status.textContent = '⚠️ Worker crashed';
        console.error(e);
        workerBusy = false;
      };
      console.log('✅ Worker initialized');
    } catch (e) {
      els.status.textContent = '❌ Worker failed: ' + e.message;
    }
  }

  // ==================== STARTUP ====================
  loadSettings();
  initWorker();
  renderHistory();
});