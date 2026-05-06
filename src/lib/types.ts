export interface ParsedData {
  buckets: Record<string, number>;
  bucketSamples: Record<string, string[]>;
  groups: Record<string, number>;
  lineCount: number;
  format: string;
  firstTs: number | null;
  lastTs: number | null;
  fileName: string;
  severity: {
    error: number;
    warn: number;
    info: number;
    debug: number;
    other: number;
  };
}

export interface HistoryItem {
  id: number;
  name: string;
  date: string;
  lines: number;
  format: string;
}

export interface AppSettings {
  tz: "Local" | "UTC";
  hour12: boolean;
  theme: "dark" | "light";
  accentHue: number;
  accentSat: number;
  accentLit: number;
}

export type SeverityLevel = "all" | "error" | "warn" | "info" | "debug";

export interface WorkerMessage {
  type: "progress" | "done" | "error";
  percent?: number;
  lines?: number;
  data?: ParsedData;
  message?: string;
}
