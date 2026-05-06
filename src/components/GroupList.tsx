import { SeverityLevel } from "@/lib/types";

interface GroupListProps {
  groups: Record<string, number>;
  filter: string;
  severity: SeverityLevel;
}

function hl(text: string): string {
  return text
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/(&lt;IP&gt;)/g, '<span class="text-cyan-400 bg-cyan-400/10 px-1 rounded text-[11px]">$1</span>')
    .replace(/(&lt;TS&gt;)/g, '<span class="text-slate-500 text-[11px]">$1</span>')
    .replace(/(&lt;(?:CONN|PID|N)&gt;)/g, '<span class="text-purple-400 text-[11px]">$1</span>')
    .replace(/(&lt;(?:HEX|UUID)&gt;)/g, '<span class="text-emerald-400 text-[11px]">$1</span>')
    .replace(/\b(ERROR|FATAL|CRIT|ALERT|EMERG|CRITICAL)\b/gi, '<span class="text-red-400 font-bold">$1</span>')
    .replace(/\b(WARN|WARNING|NOTICE)\b/gi, '<span class="text-amber-400 font-bold">$1</span>')
    .replace(/\b(INFO|INFORMATION)\b/gi, '<span class="text-blue-400 font-bold">$1</span>')
    .replace(/\b(DEBUG|TRACE|VERBOSE)\b/gi, '<span class="text-slate-400 font-bold">$1</span>');
}

function matchesSeverity(tpl: string, sev: SeverityLevel): boolean {
  if (sev === "all") return true;
  const u = tpl.toUpperCase();
  if (sev === "error") return /\b(ERROR|FATAL|CRIT|ALERT|EMERG|CRITICAL)\b/.test(u);
  if (sev === "warn") return /\b(WARN|WARNING|NOTICE)\b/.test(u);
  if (sev === "info") return /\b(INFO|INFORMATION)\b/.test(u);
  if (sev === "debug") return /\b(DEBUG|TRACE|VERBOSE)\b/.test(u);
  return true;
}

export function GroupList({ groups, filter, severity }: GroupListProps) {
  const q = filter.toLowerCase();
  const sorted = Object.entries(groups)
    .filter(([tpl]) => (!q || tpl.toLowerCase().includes(q)) && matchesSeverity(tpl, severity))
    .sort((a, b) => b[1] - a[1])
    .slice(0, 1000);

  if (!sorted.length) {
    return (
      <div className="p-8 text-center text-muted-foreground text-sm">
        No patterns match the current filter.
      </div>
    );
  }

  return (
    <>
      {sorted.map(([tpl, count], i) => (
        <div
          key={i}
          className="flex items-start gap-3 px-3 py-2.5 border-b border-border last:border-0 font-mono text-[11px] leading-relaxed hover:bg-muted/20 transition-colors"
          data-testid={`group-row-${i}`}
        >
          <span
            className="flex-1 break-all text-muted-foreground"
            dangerouslySetInnerHTML={{ __html: hl(tpl) }}
          />
          <span className="shrink-0 bg-secondary text-secondary-foreground px-2 py-0.5 rounded text-[11px] font-bold min-w-[52px] text-center">
            {count.toLocaleString()}×
          </span>
        </div>
      ))}
    </>
  );
}
