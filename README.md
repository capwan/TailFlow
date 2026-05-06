# TailFlow — Visual Log Parser

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Analyze, group and explore log files directly in the browser. No server, no database, no registration.**

![TailFlow screenshot](assets/screenshots/tail-flow.png)

## ✨ Features

- 🔍 **Auto-detection of log formats** — Asterisk, syslog, nginx/apache, and generic formats
- 🧠 **Smart grouping** — normalization of IPs, UUIDs, numbers, query parameters to extract unique patterns
- 📈 **Interactive histogram** — minute-level event distribution with tooltips; click a bar to see raw log samples
- 🔎 **Drill-down details** — up to 15 raw log lines displayed per bucket; click any line to copy it
- 📂 **Multi-file analysis** — open up to 5 log files simultaneously in separate tabs
- ⚖️ **Multi-file comparison table** — side-by-side pattern diff across all open files, color-coded for new, absent, and dominant entries
- 🚨 **Error badge** — red counter on the header icon shows ERROR / FATAL count instantly after loading
- 🎚️ **Severity filter** — filter grouped patterns by log level (ERROR / FATAL, WARN, INFO, DEBUG) via a dropdown
- 📊 **Per-file severity breakdown** — ERROR, WARN, INFO, and DEBUG counts shown as badges in the stats panel
- 🎨 **Custom accent color** — 8 preset themes plus a full hue / saturation / lightness picker; saved to localStorage
- 🌐 **Timezone support** — Local (browser) and UTC
- 🕒 **12 / 24-hour time format** — toggle with one click
- 🌓 **Dark and light themes** — comfortable in any lighting
- 💾 **History** — last 10 analyses stored in localStorage
- ⬇️ **JSON export** — export all groups and histogram data
- 🖨️ **PDF / print export** — browser print dialog with print-optimized layout
- 📱 **Responsive design** — works on desktop, tablet and mobile
- ⚡ **Web Worker** — heavy parsing runs in a separate thread, UI stays responsive
- 📲 **PWA** — installable as a standalone desktop or mobile app; service worker caches shell assets for offline use

## 🚀 Try It Live

**[TailFlow on GitHub Pages](https://capwan.github.io/TailFlow/)**

No cloning, no dependencies — just open the link and start analyzing logs.

## 🧩 How It Works

- Parsing is performed by an inline Web Worker (Blob URL), keeping the main thread free.
- The parser detects the timestamp format and splits the file into logical blocks.
- Each block is normalized: IPs → `<IP>`, numbers → `<N>`, UUIDs → `<UUID>`, query params stripped, etc. This groups similar messages together.
- A minute-resolution histogram is built from the timestamps.
- The UI is reactive: filtering, timezone / format changes, severity selection, and theme switching update the display instantly.

## 🛠️ Development

Built with **React 18 + Vite + Tailwind CSS v4**.

```bash
npm install
npm run dev       # start dev server
npm run build     # production build → dist/
npm run deploy    # deploy to GitHub Pages (gh-pages package)
```

The `BASE_PATH` environment variable controls the Vite base path (defaults to `/`).  
For GitHub Pages with a project repo, set it to your repo name: `BASE_PATH=/TailFlow/ npm run build`.

## 📦 Changelog

### v0.1.1
- Multi-file analysis (up to 5 tabs) with a comparison table
- Severity filter dropdown + per-file severity badges
- Custom accent color picker (8 presets + HSL sliders)
- PDF / print export with optimized layout
- PWA: installable app with offline service worker
- **Install App** button — appears in the header when the browser is ready to install
- **Error badge** — red counter on the header icon shows ERROR / FATAL count after each load
- New log-analyzer favicon (histogram bars + trend line)

### v0.1.0
- Initial release: single-file analysis, interactive histogram, smart grouping, dark/light themes, history panel, JSON export
