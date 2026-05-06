import { X } from "lucide-react";
import { ParsedData } from "@/lib/types";
import { formatDate, TZ } from "@/lib/timeFormat";

interface CompareModalProps {
  open: boolean;
  datasets: ParsedData[];
  tz: TZ;
  hour12: boolean;
  onClose: () => void;
}

export function CompareModal({ open, datasets, tz, hour12, onClose }: CompareModalProps) {
  if (!open || datasets.length < 2) return null;

  const allKeys = Array.from(new Set(datasets.flatMap(d => Object.keys(d.groups)))).sort(
    (a, b) => {
      const maxA = Math.max(...datasets.map(d => d.groups[a] || 0));
      const maxB = Math.max(...datasets.map(d => d.groups[b] || 0));
      return maxB - maxA;
    }
  ).slice(0, 200);

  return (
    <div
      className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 animate-in fade-in duration-150"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
      data-testid="compare-modal"
    >
      <div className="bg-card border border-border rounded-xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border shrink-0">
          <div>
            <h2 className="font-bold text-base text-foreground">Multi-File Comparison</h2>
            <p className="text-xs text-muted-foreground mt-0.5">Comparing {datasets.length} analyses</p>
          </div>
          <button
            onClick={onClose}
            className="text-muted-foreground hover:text-foreground p-1.5 rounded-md hover:bg-muted transition-colors"
            data-testid="button-close-compare"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="overflow-auto flex-1">
          <div className="p-4 space-y-4">
            {/* Summary cards */}
            <div className="grid gap-3" style={{ gridTemplateColumns: `repeat(${Math.min(datasets.length, 3)}, 1fr)` }}>
              {datasets.map((d, i) => (
                <div key={i} className="bg-muted/20 border border-border rounded-lg p-3">
                  <p className="font-semibold text-sm text-foreground truncate mb-1">{d.fileName}</p>
                  <p className="text-xs text-muted-foreground">{d.lineCount.toLocaleString()} lines</p>
                  <p className="text-xs text-muted-foreground">{d.format}</p>
                  {d.firstTs && (
                    <p className="text-xs text-muted-foreground truncate">
                      {formatDate(d.firstTs, tz, hour12).slice(0, 20)}
                    </p>
                  )}
                  <div className="flex gap-2 mt-2 flex-wrap">
                    {d.severity.error > 0 && (
                      <span className="text-[10px] font-bold text-red-400 bg-red-400/10 px-1.5 py-0.5 rounded">
                        {d.severity.error} ERR
                      </span>
                    )}
                    {d.severity.warn > 0 && (
                      <span className="text-[10px] font-bold text-amber-400 bg-amber-400/10 px-1.5 py-0.5 rounded">
                        {d.severity.warn} WARN
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>

            {/* Pattern diff table */}
            <div>
              <h3 className="text-sm font-bold text-foreground mb-2">Pattern Counts</h3>
              <div className="rounded-lg border border-border overflow-hidden">
                <table className="w-full text-[11px] font-mono">
                  <thead className="bg-muted/40">
                    <tr>
                      <th className="text-left px-3 py-2 text-muted-foreground font-semibold">Pattern</th>
                      {datasets.map((d, i) => (
                        <th key={i} className="px-3 py-2 text-center text-muted-foreground font-semibold whitespace-nowrap" style={{ minWidth: 80 }}>
                          #{i + 1} {d.fileName.slice(0, 12)}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {allKeys.map((key, i) => {
                      const counts = datasets.map(d => d.groups[key] || 0);
                      const max = Math.max(...counts);
                      return (
                        <tr key={i} className="border-t border-border hover:bg-muted/10 transition-colors">
                          <td className="px-3 py-2 text-foreground/70 break-all max-w-[300px]">{key}</td>
                          {counts.map((c, j) => {
                            const isNew = c > 0 && counts.filter((_, k) => k !== j).every(x => x === 0);
                            const isGone = c === 0 && counts.some(x => x > 0);
                            return (
                              <td key={j} className={`px-3 py-2 text-center font-bold ${isNew ? "text-green-400" : isGone ? "text-red-400 line-through opacity-50" : c === max && max > 0 ? "text-amber-400" : "text-foreground/60"}`}>
                                {c > 0 ? c.toLocaleString() : "—"}
                              </td>
                            );
                          })}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <p className="text-[10px] text-muted-foreground mt-2">
                <span className="text-green-400 font-bold">Green</span> = only in this file &nbsp;
                <span className="text-amber-400 font-bold">Amber</span> = highest count &nbsp;
                <span className="text-red-400 font-bold">Red strikethrough</span> = absent
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
