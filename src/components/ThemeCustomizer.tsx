import { X, Palette } from "lucide-react";
import { AppSettings } from "@/lib/types";

interface ThemeCustomizerProps {
  open: boolean;
  settings: AppSettings;
  onUpdate: (settings: Partial<AppSettings>) => void;
  onClose: () => void;
}

const PRESETS = [
  { name: "Blue", hue: 217, sat: 91, lit: 60 },
  { name: "Violet", hue: 262, sat: 83, lit: 58 },
  { name: "Emerald", hue: 160, sat: 84, lit: 39 },
  { name: "Amber", hue: 38, sat: 92, lit: 50 },
  { name: "Rose", hue: 346, sat: 87, lit: 60 },
  { name: "Cyan", hue: 189, sat: 94, lit: 43 },
  { name: "Slate", hue: 215, sat: 25, lit: 50 },
  { name: "Orange", hue: 24, sat: 94, lit: 53 },
];

export function ThemeCustomizer({ open, settings, onUpdate, onClose }: ThemeCustomizerProps) {
  if (!open) return null;

  return (
    <div className="fixed right-4 top-20 w-72 bg-card border border-border rounded-xl shadow-2xl z-40 animate-in slide-in-from-top-2 duration-200">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <div className="flex items-center gap-2">
          <Palette className="w-4 h-4 text-primary" />
          <h3 className="font-bold text-sm text-foreground">Accent Color</h3>
        </div>
        <button
          onClick={onClose}
          className="text-muted-foreground hover:text-foreground p-1 rounded-md hover:bg-muted transition-colors"
          data-testid="button-close-theme"
        >
          <X className="w-4 h-4" />
        </button>
      </div>
      <div className="p-4 space-y-4">
        <div>
          <p className="text-xs text-muted-foreground mb-2 font-semibold uppercase tracking-wide">Presets</p>
          <div className="grid grid-cols-4 gap-2">
            {PRESETS.map((p) => {
              const isActive = settings.accentHue === p.hue && settings.accentSat === p.sat && settings.accentLit === p.lit;
              return (
                <button
                  key={p.name}
                  onClick={() => onUpdate({ accentHue: p.hue, accentSat: p.sat, accentLit: p.lit })}
                  className={`flex flex-col items-center gap-1.5 p-2 rounded-lg border transition-all ${isActive ? "border-primary bg-primary/10" : "border-border hover:border-muted-foreground"}`}
                  data-testid={`button-preset-${p.name.toLowerCase()}`}
                  title={p.name}
                >
                  <div
                    className="w-6 h-6 rounded-full shadow-sm"
                    style={{ background: `hsl(${p.hue} ${p.sat}% ${p.lit}%)` }}
                  />
                  <span className="text-[10px] text-muted-foreground font-medium">{p.name}</span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="space-y-3">
          <p className="text-xs text-muted-foreground font-semibold uppercase tracking-wide">Custom</p>
          <div className="flex items-center gap-3">
            <div
              className="w-8 h-8 rounded-full shrink-0 border-2 border-border shadow"
              style={{ background: `hsl(${settings.accentHue} ${settings.accentSat}% ${settings.accentLit}%)` }}
            />
            <div className="flex-1 space-y-1.5">
              <div>
                <label className="text-[10px] text-muted-foreground">Hue ({settings.accentHue}°)</label>
                <input
                  type="range" min={0} max={360} value={settings.accentHue}
                  onChange={e => onUpdate({ accentHue: Number(e.target.value) })}
                  className="w-full h-1.5 appearance-none rounded bg-gradient-to-r from-red-500 via-green-500 via-blue-500 to-red-500 cursor-pointer"
                  data-testid="input-hue"
                />
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground">Saturation ({settings.accentSat}%)</label>
                <input
                  type="range" min={0} max={100} value={settings.accentSat}
                  onChange={e => onUpdate({ accentSat: Number(e.target.value) })}
                  className="w-full h-1.5 accent-primary cursor-pointer"
                  data-testid="input-sat"
                />
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground">Lightness ({settings.accentLit}%)</label>
                <input
                  type="range" min={10} max={90} value={settings.accentLit}
                  onChange={e => onUpdate({ accentLit: Number(e.target.value) })}
                  className="w-full h-1.5 accent-primary cursor-pointer"
                  data-testid="input-lit"
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
