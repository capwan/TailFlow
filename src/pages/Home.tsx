import { useState, useRef, useEffect, useCallback } from "react";
import {
  Upload, ClipboardPaste, History, GitCompare, Download,
  Sun, Moon, Palette, Filter, BarChart3, Search, Printer,
  Plus, X, MonitorDown
} from "lucide-react";
import { ParsedData, HistoryItem, AppSettings, SeverityLevel } from "@/lib/types";
import { WORKER_CODE } from "@/lib/workerCode";
import { formatDate, formatTime, TZ } from "@/lib/timeFormat";
import { Histogram } from "@/components/Histogram";
import { GroupList } from "@/components/GroupList";
import { DetailModal } from "@/components/DetailModal";
import { CompareModal } from "@/components/CompareModal";
import { HistoryPanel } from "@/components/HistoryPanel";
import { ThemeCustomizer } from "@/components/ThemeCustomizer";
import { StatsPanel } from "@/components/StatsPanel";

const DEFAULT_SETTINGS: AppSettings = {
  tz: "Local",
  hour12: false,
  theme: "dark",
  accentHue: 217,
  accentSat: 91,
  accentLit: 60,
};

function loadSettings(): AppSettings {
  try {
    const s = JSON.parse(localStorage.getItem("tailflow_settings") || "{}");
    return { ...DEFAULT_SETTINGS, ...s };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

function loadHistory(): HistoryItem[] {
  try {
    return JSON.parse(localStorage.getItem("tailflow_history") || "[]");
  } catch {
    return [];
  }
}

function createWorker(): Worker {
  const blob = new Blob([WORKER_CODE], { type: "application/javascript" });
  return new Worker(URL.createObjectURL(blob));
}

export default function Home() {
  const [mode, setMode] = useState<"file" | "paste">("file");
  const [settings, setSettings] = useState<AppSettings>(loadSettings);
  const [history, setHistory] = useState<HistoryItem[]>(loadHistory);
  const [datasets, setDatasets] = useState<ParsedData[]>([]);
  const [activeIdx, setActiveIdx] = useState(0);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState("Ready to analyze logs");
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState("");
  const [severity, setSeverity] = useState<SeverityLevel>("all");
  const [showHistory, setShowHistory] = useState(false);
  const [showCompare, setShowCompare] = useState(false);
  const [showTheme, setShowTheme] = useState(false);
  const [detailState, setDetailState] = useState<{ open: boolean; time: number | null; samples: string[]; count: number }>({ open: false, time: null, samples: [], count: 0 });
  const [installPrompt, setInstallPrompt] = useState<Event | null>(null);
  const [installed, setInstalled] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const pasteRef = useRef<HTMLTextAreaElement>(null);
  const workerRef = useRef<Worker | null>(null);

  // PWA install prompt listener
  useEffect(() => {
    const handler = (e: Event) => { e.preventDefault(); setInstallPrompt(e); };
    window.addEventListener("beforeinstallprompt", handler);
    window.addEventListener("appinstalled", () => { setInstalled(true); setInstallPrompt(null); });
    return () => window.removeEventListener("beforeinstallprompt", handler);
  }, []);

  const handleInstall = async () => {
    if (!installPrompt) return;
    (installPrompt as any).prompt();
    const { outcome } = await (installPrompt as any).userChoice;
    if (outcome === "accepted") { setInstalled(true); setInstallPrompt(null); }
  };

  // Apply settings side effects
  useEffect(() => {
    const s = settings;
    document.documentElement.classList.toggle("dark", s.theme === "dark");
    document.documentElement.style.setProperty("--accent-h", String(s.accentHue));
    document.documentElement.style.setProperty("--accent-s", `${s.accentSat}%`);
    document.documentElement.style.setProperty("--accent-l", `${s.accentLit}%`);
    localStorage.setItem("tailflow_settings", JSON.stringify(s));
  }, [settings]);

  const updateSettings = useCallback((patch: Partial<AppSettings>) => {
    setSettings(prev => ({ ...prev, ...patch }));
  }, []);

  const saveToHistory = useCallback((name: string, d: ParsedData) => {
    setHistory(prev => {
      const item: HistoryItem = {
        id: Date.now(),
        name,
        date: new Date().toLocaleString("en-US"),
        lines: d.lineCount,
        format: d.format,
      };
      const next = [item, ...prev].slice(0, 10);
      localStorage.setItem("tailflow_history", JSON.stringify(next));
      return next;
    });
  }, []);

  const parseWith = useCallback((payload: { type: "file"; file: File; fileIndex: number; fileName: string } | { type: "text"; text: string; fileIndex: number; fileName: string }) => {
    if (workerRef.current) workerRef.current.terminate();
    const worker = createWorker();
    workerRef.current = worker;
    setBusy(true);
    setProgress(0);
    setStatus("Analyzing...");

    worker.onmessage = (e) => {
      const m = e.data;
      if (m.type === "progress") {
        setProgress(m.percent);
        setStatus(`Processing... ${m.lines.toLocaleString()} lines`);
      } else if (m.type === "done") {
        const parsed: ParsedData = m.data;
        setDatasets(prev => {
          const next = [...prev];
          next[m.fileIndex] = parsed;
          return next;
        });
        setActiveIdx(m.fileIndex);
        setProgress(100);
        setStatus("Analysis complete");
        setBusy(false);
        saveToHistory(parsed.fileName, parsed);
        setTimeout(() => setProgress(0), 1200);
      } else if (m.type === "error") {
        setStatus("Error: " + m.message);
        setBusy(false);
      }
    };

    worker.onerror = (e) => {
      setStatus("Worker error: " + e.message);
      setBusy(false);
    };

    worker.postMessage(payload);
  }, [saveToHistory]);

  const parseFile = useCallback((file: File, fileIndex?: number) => {
    const idx = fileIndex ?? datasets.length;
    parseWith({ type: "file", file, fileIndex: idx, fileName: file.name });
  }, [datasets.length, parseWith]);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const files = Array.from(e.dataTransfer.files).filter(f => f.name.match(/\.(log|txt)$/i));
    if (files.length > 0) {
      files.forEach((f, i) => parseFile(f, datasets.length + i));
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || []);
    files.forEach((f, i) => parseFile(f, datasets.length + i));
    e.target.value = "";
  };

  const handlePasteAnalyze = () => {
    const txt = pasteRef.current?.value.trim();
    if (!txt) return;
    if (txt.length > 10_000_000 && !confirm("Text >10 MB may slow down the browser. Continue?")) return;
    parseWith({ type: "text", text: txt, fileIndex: datasets.length, fileName: "Pasted Text" });
  };

  const removeDataset = (idx: number) => {
    setDatasets(prev => prev.filter((_, i) => i !== idx));
    setActiveIdx(prev => Math.max(0, Math.min(prev, datasets.length - 2)));
  };

  const exportData = () => {
    const d = datasets[activeIdx];
    if (!d) return;
    const payload = {
      meta: { format: d.format, lines: d.lineCount, range: [d.firstTs, d.lastTs], fileName: d.fileName },
      histogram: d.buckets,
      groups: Object.entries(d.groups).sort((a, b) => b[1] - a[1]).slice(0, 500).map(([t, c]) => ({ template: t, count: c })),
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `tailflow-${d.fileName}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const handlePrint = () => window.print();

  const activeData = datasets[activeIdx];

  return (
    <div className="min-h-screen bg-background text-foreground" data-testid="home-page">
      {/* ── Header ── */}
      <div className="sticky top-0 z-30 bg-background/80 backdrop-blur-md border-b border-border">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2 font-extrabold text-xl text-primary tracking-tight mr-1">
            <div className="relative">
              <BarChart3 className="w-6 h-6" />
              {activeData && activeData.severity.error > 0 && (
                <span
                  className="absolute -top-2 -right-2.5 bg-red-500 text-white text-[9px] font-bold rounded-full min-w-[16px] h-4 flex items-center justify-center px-1 leading-none shadow-sm animate-in zoom-in duration-300"
                  title={`${activeData.severity.error} ERROR / FATAL lines`}
                  data-testid="badge-error-count"
                >
                  {activeData.severity.error > 99 ? "99+" : activeData.severity.error}
                </span>
              )}
            </div>
            TailFlow
            <span className="text-[10px] font-semibold text-muted-foreground bg-muted px-1.5 py-0.5 rounded-full ml-1">v0.1.1</span>
          </div>

          {/* Mode tabs */}
          <div className="flex gap-1 bg-card border border-border rounded-lg p-1">
            <button
              onClick={() => setMode("file")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${mode === "file" ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground"}`}
              data-testid="tab-file"
            >
              <Upload className="w-3.5 h-3.5" /> Upload
            </button>
            <button
              onClick={() => setMode("paste")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${mode === "paste" ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground"}`}
              data-testid="tab-paste"
            >
              <ClipboardPaste className="w-3.5 h-3.5" /> Paste
            </button>
          </div>

          {/* Settings strip */}
          <div className="flex items-center gap-1.5 ml-auto flex-wrap">
            <select
              value={settings.tz}
              onChange={e => updateSettings({ tz: e.target.value as TZ })}
              className="text-xs bg-card border border-border rounded-lg px-2 py-1.5 text-foreground cursor-pointer"
              data-testid="select-timezone"
            >
              <option value="Local">Local</option>
              <option value="UTC">UTC</option>
            </select>
            <button
              onClick={() => updateSettings({ hour12: !settings.hour12 })}
              className="text-xs bg-card border border-border rounded-lg px-2.5 py-1.5 text-foreground font-semibold hover:border-primary transition-colors"
              data-testid="button-format-toggle"
            >
              {settings.hour12 ? "12h" : "24h"}
            </button>
            <button
              onClick={() => setShowTheme(v => !v)}
              className="p-1.5 bg-card border border-border rounded-lg text-muted-foreground hover:text-foreground transition-colors"
              title="Customize accent color"
              data-testid="button-theme-customizer"
            >
              <Palette className="w-4 h-4" />
            </button>
            <button
              onClick={() => updateSettings({ theme: settings.theme === "dark" ? "light" : "dark" })}
              className="p-1.5 bg-card border border-border rounded-lg text-muted-foreground hover:text-foreground transition-colors"
              data-testid="button-theme-toggle"
            >
              {settings.theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
            <button
              onClick={() => setShowHistory(v => !v)}
              className="flex items-center gap-1.5 text-xs bg-card border border-border rounded-lg px-2.5 py-1.5 text-muted-foreground hover:text-foreground transition-colors font-semibold"
              data-testid="button-history"
            >
              <History className="w-3.5 h-3.5" /> History
            </button>
            {installPrompt && !installed && (
              <button
                onClick={handleInstall}
                className="flex items-center gap-1.5 text-xs bg-primary text-primary-foreground rounded-lg px-2.5 py-1.5 font-semibold hover:opacity-90 transition-opacity animate-in fade-in duration-300"
                data-testid="button-install-pwa"
                title="Install TailFlow as a desktop app"
              >
                <MonitorDown className="w-3.5 h-3.5" /> Install App
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-4 py-6 space-y-5">
        {/* ── Input Zone ── */}
        {mode === "file" ? (
          <div
            className="border-2 border-dashed border-border hover:border-primary rounded-xl p-10 text-center cursor-pointer transition-all hover:-translate-y-0.5 bg-card/30 hover:bg-card/50"
            onClick={() => fileInputRef.current?.click()}
            onDragOver={e => { e.preventDefault(); e.currentTarget.classList.add("border-primary"); }}
            onDragLeave={e => e.currentTarget.classList.remove("border-primary")}
            onDrop={handleDrop}
            data-testid="drop-zone"
          >
            <Upload className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
            <h2 className="text-base font-bold mb-1">Drop log files here</h2>
            <p className="text-sm text-muted-foreground">or click to browse — .log, .txt files — multiple files supported</p>
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              accept=".log,.txt"
              multiple
              onChange={handleFileChange}
              data-testid="input-file"
            />
          </div>
        ) : (
          <div className="bg-card border border-border rounded-xl p-5">
            <h2 className="text-base font-bold mb-3">Paste log content</h2>
            <textarea
              ref={pasteRef}
              placeholder="Paste log content here... (up to 10 MB recommended)"
              className="w-full h-32 bg-background border border-border rounded-lg p-3 font-mono text-xs text-foreground resize-y focus:outline-none focus:border-primary transition-colors"
              data-testid="input-paste"
            />
            <button
              onClick={handlePasteAnalyze}
              disabled={busy}
              className="mt-3 flex items-center gap-2 bg-primary text-primary-foreground px-4 py-2 rounded-lg text-sm font-bold hover:opacity-90 transition-opacity disabled:opacity-40"
              data-testid="button-analyze-paste"
            >
              Analyze Logs
            </button>
          </div>
        )}

        {/* ── Progress ── */}
        {(busy || progress > 0) && (
          <div>
            <div className="h-1.5 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-primary to-cyan-400 transition-all duration-300 rounded-full"
                style={{ width: `${progress}%` }}
              />
            </div>
            <p className="text-xs text-muted-foreground text-center mt-2">{status}</p>
          </div>
        )}

        {!busy && !activeData && (
          <p className="text-xs text-muted-foreground text-center py-1">{status}</p>
        )}

        {/* ── Dataset Tabs (multi-file) ── */}
        {datasets.length > 0 && (
          <div className="flex gap-2 flex-wrap">
            {datasets.map((d, i) => (
              <div key={i} className="flex items-center">
                <button
                  onClick={() => setActiveIdx(i)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-l-lg text-xs font-semibold border transition-all ${activeIdx === i ? "bg-primary text-primary-foreground border-primary" : "bg-card border-border text-muted-foreground hover:text-foreground"}`}
                  data-testid={`tab-dataset-${i}`}
                >
                  <BarChart3 className="w-3 h-3" />
                  {d.fileName.slice(0, 18)}
                </button>
                <button
                  onClick={() => removeDataset(i)}
                  className={`p-1.5 rounded-r-lg border-y border-r text-xs transition-all ${activeIdx === i ? "bg-primary border-primary text-primary-foreground hover:bg-primary/80" : "bg-card border-border text-muted-foreground hover:text-red-400"}`}
                  data-testid={`button-remove-dataset-${i}`}
                >
                  <X className="w-3 h-3" />
                </button>
              </div>
            ))}
            {datasets.length < 5 && (
              <button
                onClick={() => fileInputRef.current?.click()}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-dashed border-border text-muted-foreground hover:text-foreground hover:border-primary transition-all"
                data-testid="button-add-file"
              >
                <Plus className="w-3 h-3" /> Add file
              </button>
            )}
            {datasets.length >= 2 && (
              <button
                onClick={() => setShowCompare(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-card border border-border text-muted-foreground hover:text-foreground hover:border-primary transition-all"
                data-testid="button-compare"
              >
                <GitCompare className="w-3.5 h-3.5" /> Compare
              </button>
            )}
          </div>
        )}

        {/* ── Main results ── */}
        {activeData && (
          <>
            <StatsPanel data={activeData} tz={settings.tz} hour12={settings.hour12} />

            {/* Histogram */}
            <div className="bg-card border border-border rounded-xl p-4 print:border-border">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-bold flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-primary" /> Events Timeline
                </h3>
                <div className="flex items-center gap-2">
                  <button onClick={handlePrint} className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground bg-muted/30 hover:bg-muted/60 px-2 py-1 rounded-md transition-colors" data-testid="button-print">
                    <Printer className="w-3.5 h-3.5" /> Print / PDF
                  </button>
                  <button onClick={exportData} className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground bg-muted/30 hover:bg-muted/60 px-2 py-1 rounded-md transition-colors" data-testid="button-export">
                    <Download className="w-3.5 h-3.5" /> Export JSON
                  </button>
                </div>
              </div>
              <Histogram
                buckets={activeData.buckets}
                bucketSamples={activeData.bucketSamples}
                tz={settings.tz}
                hour12={settings.hour12}
                theme={settings.theme}
                onBucketClick={(time, samples, count) => setDetailState({ open: true, time, samples, count })}
              />
            </div>

            {/* Filter + Severity */}
            <div className="flex gap-2 flex-wrap items-center">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
                <input
                  type="text"
                  value={filter}
                  onChange={e => setFilter(e.target.value)}
                  placeholder="Filter by pattern: ERROR, <IP>, timeout..."
                  className="w-full bg-card border border-border rounded-lg pl-8 pr-3 py-2 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary transition-colors"
                  data-testid="input-filter"
                />
              </div>
              <div className="relative">
                <Filter className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
                <select
                  value={severity}
                  onChange={e => setSeverity(e.target.value as SeverityLevel)}
                  className="bg-card border border-border rounded-lg pl-8 pr-3 py-2 text-xs text-foreground cursor-pointer focus:outline-none focus:border-primary transition-colors appearance-none"
                  data-testid="select-severity"
                >
                  <option value="all">All levels</option>
                  <option value="error">ERROR / FATAL</option>
                  <option value="warn">WARN / WARNING</option>
                  <option value="info">INFO</option>
                  <option value="debug">DEBUG / TRACE</option>
                </select>
              </div>
            </div>

            {/* Groups */}
            <div className="bg-card border border-border rounded-xl overflow-hidden max-h-[450px] overflow-y-auto">
              <GroupList groups={activeData.groups} filter={filter} severity={severity} />
            </div>
          </>
        )}
      </div>

      {/* ── Panels & Modals ── */}
      <HistoryPanel
        open={showHistory}
        history={history}
        onClear={() => { setHistory([]); localStorage.removeItem("tailflow_history"); }}
        onClose={() => setShowHistory(false)}
      />
      <ThemeCustomizer
        open={showTheme}
        settings={settings}
        onUpdate={updateSettings}
        onClose={() => setShowTheme(false)}
      />
      <DetailModal
        open={detailState.open}
        time={detailState.time}
        samples={detailState.samples}
        count={detailState.count}
        tz={settings.tz}
        hour12={settings.hour12}
        onClose={() => setDetailState(prev => ({ ...prev, open: false }))}
      />
      <CompareModal
        open={showCompare}
        datasets={datasets}
        tz={settings.tz}
        hour12={settings.hour12}
        onClose={() => setShowCompare(false)}
      />

      {/* ── Print styles ── */}
      <style>{`
        @media print {
          body { background: white !important; color: black !important; }
          .sticky { position: static !important; }
          button { display: none !important; }
          [data-testid="drop-zone"] { display: none !important; }
          [data-testid="input-paste"] { display: none !important; }
          .max-h-\\[450px\\] { max-height: none !important; overflow: visible !important; }
        }
      `}</style>
    </div>
  );
}
