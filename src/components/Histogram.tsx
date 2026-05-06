import { useEffect, useRef, useCallback } from "react";
import { formatTime, formatDate, TZ } from "@/lib/timeFormat";

interface ChartBucket {
  x: number;
  y: number;
  w: number;
  h: number;
  time: number;
  val: number;
}

interface HistogramProps {
  buckets: Record<string, number>;
  bucketSamples: Record<string, string[]>;
  tz: TZ;
  hour12: boolean;
  theme: "dark" | "light";
  onBucketClick: (time: number, samples: string[], count: number) => void;
}

export function Histogram({ buckets, bucketSamples, tz, hour12, theme, onBucketClick }: HistogramProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);
  const chartMapRef = useRef<ChartBucket[]>([]);
  const selectedBucketRef = useRef<number | null>(null);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = canvas.clientWidth * dpr;
    canvas.height = canvas.clientHeight * dpr;
    ctx.scale(dpr, dpr);

    const keys = Object.keys(buckets).map(Number).sort((a, b) => a - b);
    if (!keys.length) return;

    const max = Math.max(...Object.values(buckets));
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    const pad = { t: 20, r: 10, b: 30, l: 44 };
    const plotW = w - pad.l - pad.r;
    const plotH = h - pad.t - pad.b;
    const barW = Math.max(2, plotW / keys.length - 2);

    const isDark = theme === "dark";
    const bgColor = isDark ? "#0f1117" : "#f1f5f9";
    const gridColor = isDark ? "#1e293b" : "#cbd5e1";
    const textColor = isDark ? "#94a3b8" : "#475569";

    ctx.fillStyle = bgColor;
    ctx.fillRect(0, 0, w, h);

    ctx.strokeStyle = gridColor;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(pad.l, pad.t);
    ctx.lineTo(pad.l, h - pad.b);
    ctx.lineTo(w - pad.r, h - pad.b);
    ctx.stroke();

    ctx.fillStyle = textColor;
    ctx.font = "11px system-ui";
    ctx.textAlign = "right";
    for (let i = 0; i <= 4; i++) {
      const val = Math.round(max * (i / 4));
      const y = h - pad.b - plotH * (i / 4);
      ctx.fillText(val.toLocaleString(), pad.l - 6, y + 4);
      if (i > 0) {
        ctx.strokeStyle = gridColor;
        ctx.setLineDash([2, 4]);
        ctx.beginPath();
        ctx.moveTo(pad.l, y);
        ctx.lineTo(w - pad.r, y);
        ctx.stroke();
        ctx.setLineDash([]);
      }
    }

    ctx.textAlign = "center";
    const step = Math.max(1, Math.floor(keys.length / 6));
    keys.forEach((k, i) => {
      if (i % step === 0 || i === keys.length - 1) {
        ctx.fillStyle = textColor;
        ctx.fillText(formatTime(k, tz, hour12), pad.l + i * (barW + 2) + barW / 2, h - pad.b + 18);
      }
    });

    const map: ChartBucket[] = [];
    keys.forEach((k, i) => {
      const val = buckets[k];
      const ratio = val / max;
      const barH = ratio * plotH;
      const x = pad.l + i * (barW + 2);
      const y = h - pad.b - barH;
      const color = ratio > 0.8 ? "#ef4444" : ratio > 0.5 ? "#f59e0b" : "#3b82f6";
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.roundRect(x, y, barW, barH, Math.min(2, barW / 2));
      ctx.fill();
      map.push({ x, y, w: barW, h: barH, time: k, val });
    });
    chartMapRef.current = map;
  }, [buckets, tz, hour12, theme]);

  useEffect(() => {
    draw();
    const ro = new ResizeObserver(() => draw());
    if (canvasRef.current) ro.observe(canvasRef.current);
    return () => ro.disconnect();
  }, [draw]);

  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current!.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const hit = chartMapRef.current.find(b => mx >= b.x && mx <= b.x + b.w && my >= b.y && my <= b.y + b.h);
    const tt = tooltipRef.current;
    if (!tt) return;
    if (!hit) {
      tt.style.opacity = "0";
      selectedBucketRef.current = null;
      return;
    }
    selectedBucketRef.current = hit.time;
    tt.style.opacity = "1";
    tt.style.left = Math.min(e.clientX - rect.left + 12, rect.width - 200) + "px";
    tt.style.top = Math.max(e.clientY - rect.top - 48, 0) + "px";
    tt.querySelector(".tt-time")!.textContent = formatDate(hit.time, tz, hour12);
    tt.querySelector(".tt-val")!.textContent = hit.val.toLocaleString() + " events in this minute";
  }, [tz, hour12]);

  const handleMouseLeave = () => {
    if (tooltipRef.current) tooltipRef.current.style.opacity = "0";
  };

  const handleClick = () => {
    if (selectedBucketRef.current !== null) {
      const time = selectedBucketRef.current;
      const samples = bucketSamples[time] || [];
      const count = buckets[time] || 0;
      onBucketClick(time, samples, count);
    }
  };

  return (
    <div className="relative">
      <canvas
        ref={canvasRef}
        className="w-full h-[200px] block rounded-md cursor-crosshair"
        data-testid="histogram-canvas"
        onMouseMove={handleMouseMove}
        onMouseLeave={handleMouseLeave}
        onClick={handleClick}
      />
      <div
        ref={tooltipRef}
        className="absolute pointer-events-none opacity-0 transition-opacity bg-card border border-border rounded-lg px-3 py-2 text-xs shadow-xl z-10 min-w-[160px]"
        style={{ transition: "opacity 0.15s" }}
      >
        <span className="tt-time block text-primary font-bold text-[13px] mb-1"></span>
        <span className="tt-val block text-green-500 font-bold"></span>
      </div>
    </div>
  );
}
