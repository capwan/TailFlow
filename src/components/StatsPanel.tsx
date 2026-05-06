import { ParsedData } from "@/lib/types";
import { formatDate, TZ } from "@/lib/timeFormat";

interface StatsPanelProps {
  data: ParsedData;
  tz: TZ;
  hour12: boolean;
}

function StatCard({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div className="bg-card border border-border rounded-xl p-4 text-center">
      <div className={`text-xl font-extrabold mb-1 ${accent ? "text-primary" : "text-foreground"}`}>{value}</div>
      <div className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">{label}</div>
    </div>
  );
}

export function StatsPanel({ data, tz, hour12 }: StatsPanelProps) {
  const timeRange = data.firstTs
    ? `${formatDate(data.firstTs, tz, hour12)} → ${formatDate(data.lastTs!, tz, hour12)}`
    : "—";

  const total = data.severity.error + data.severity.warn + data.severity.info + data.severity.debug + data.severity.other;

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="Total Lines" value={data.lineCount.toLocaleString()} accent />
        <StatCard label="Format" value={data.format} />
        <StatCard label="Unique Patterns" value={Object.keys(data.groups).length.toLocaleString()} accent />
        <StatCard label="Time Range" value={data.firstTs ? formatDate(data.firstTs, tz, hour12).slice(0, 12) : "—"} />
      </div>
      <div className="text-[11px] text-muted-foreground text-center font-mono">{timeRange}</div>

      {total > 0 && (
        <div className="flex gap-2 flex-wrap justify-center">
          {data.severity.error > 0 && (
            <span className="text-[11px] font-bold text-red-400 bg-red-400/10 border border-red-400/20 px-2.5 py-1 rounded-full">
              {data.severity.error.toLocaleString()} ERROR
            </span>
          )}
          {data.severity.warn > 0 && (
            <span className="text-[11px] font-bold text-amber-400 bg-amber-400/10 border border-amber-400/20 px-2.5 py-1 rounded-full">
              {data.severity.warn.toLocaleString()} WARN
            </span>
          )}
          {data.severity.info > 0 && (
            <span className="text-[11px] font-bold text-blue-400 bg-blue-400/10 border border-blue-400/20 px-2.5 py-1 rounded-full">
              {data.severity.info.toLocaleString()} INFO
            </span>
          )}
          {data.severity.debug > 0 && (
            <span className="text-[11px] font-bold text-slate-400 bg-slate-400/10 border border-slate-400/20 px-2.5 py-1 rounded-full">
              {data.severity.debug.toLocaleString()} DEBUG
            </span>
          )}
        </div>
      )}
    </div>
  );
}
