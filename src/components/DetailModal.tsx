import { X, Copy, Check } from "lucide-react";
import { useState } from "react";
import { formatDate, TZ } from "@/lib/timeFormat";

interface DetailModalProps {
  open: boolean;
  time: number | null;
  samples: string[];
  count: number;
  tz: TZ;
  hour12: boolean;
  onClose: () => void;
}

export function DetailModal({ open, time, samples, count, tz, hour12, onClose }: DetailModalProps) {
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);

  if (!open || time === null) return null;

  const handleCopy = (text: string, idx: number) => {
    navigator.clipboard.writeText(text.trim()).then(() => {
      setCopiedIdx(idx);
      setTimeout(() => setCopiedIdx(null), 1200);
    });
  };

  return (
    <div
      className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 animate-in fade-in duration-150"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
      data-testid="detail-modal"
    >
      <div className="bg-card border border-border rounded-xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border shrink-0">
          <div>
            <h2 className="font-bold text-base text-foreground">Bucket Details</h2>
            {time && (
              <p className="text-xs text-muted-foreground mt-0.5">
                {formatDate(time, tz, hour12)} — {count.toLocaleString()} events
              </p>
            )}
          </div>
          <button
            onClick={onClose}
            className="text-muted-foreground hover:text-foreground p-1.5 rounded-md hover:bg-muted transition-colors"
            data-testid="button-close-detail"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="overflow-y-auto p-4 flex flex-col gap-2">
          {samples.length === 0 ? (
            <p className="text-muted-foreground text-sm text-center py-8">No raw logs captured for this bucket.</p>
          ) : (
            samples.map((s, i) => (
              <div
                key={i}
                className="group relative bg-muted/30 hover:bg-muted/60 rounded-lg px-3 py-2.5 font-mono text-[11px] text-foreground/80 whitespace-pre-wrap break-all cursor-pointer transition-colors border border-transparent hover:border-border"
                onClick={() => handleCopy(s, i)}
                data-testid={`log-line-${i}`}
              >
                {s}
                <span className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
                  {copiedIdx === i ? (
                    <Check className="w-3.5 h-3.5 text-green-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5 text-muted-foreground" />
                  )}
                </span>
              </div>
            ))
          )}
        </div>
        <div className="px-4 py-3 border-t border-border shrink-0">
          <p className="text-[11px] text-muted-foreground">Click any log line to copy to clipboard</p>
        </div>
      </div>
    </div>
  );
}
