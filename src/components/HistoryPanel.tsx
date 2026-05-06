import { X, Trash2 } from "lucide-react";
import { HistoryItem } from "@/lib/types";

interface HistoryPanelProps {
  open: boolean;
  history: HistoryItem[];
  onClear: () => void;
  onClose: () => void;
}

export function HistoryPanel({ open, history, onClear, onClose }: HistoryPanelProps) {
  if (!open) return null;

  return (
    <div className="fixed right-4 top-20 w-72 max-w-[90vw] bg-card border border-border rounded-xl shadow-2xl z-40 flex flex-col max-h-[70vh] animate-in slide-in-from-top-2 duration-200">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border shrink-0">
        <h3 className="font-bold text-sm text-foreground">Recent Analyses</h3>
        <button
          onClick={onClose}
          className="text-muted-foreground hover:text-foreground p-1 rounded-md hover:bg-muted transition-colors"
          data-testid="button-close-history"
        >
          <X className="w-4 h-4" />
        </button>
      </div>
      <div className="overflow-y-auto flex-1 p-2">
        {history.length === 0 ? (
          <p className="text-muted-foreground text-xs text-center py-6">No history yet</p>
        ) : (
          history.map((item) => (
            <div
              key={item.id}
              className="px-3 py-2.5 rounded-lg mb-1 hover:bg-muted/40 transition-colors cursor-default border border-transparent hover:border-border"
              data-testid={`history-item-${item.id}`}
            >
              <p className="font-semibold text-sm text-foreground truncate">{item.name}</p>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                {item.date} · {item.lines.toLocaleString()} lines · {item.format}
              </p>
            </div>
          ))
        )}
      </div>
      <div className="p-3 border-t border-border shrink-0">
        <button
          onClick={onClear}
          className="w-full flex items-center justify-center gap-2 text-xs text-muted-foreground hover:text-destructive bg-muted/30 hover:bg-destructive/10 px-3 py-2 rounded-lg transition-colors font-semibold"
          data-testid="button-clear-history"
        >
          <Trash2 className="w-3.5 h-3.5" />
          Clear History
        </button>
      </div>
    </div>
  );
}
