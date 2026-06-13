# Render Notes — WINXP-LAPTOP-2005-EXECUTION.mp4

**Pipeline:** deterministic CDP virtual-time render (per CLAUDE.md "Video annotation & animation pipeline"),
not real-time recordVideo (which is time-dilated on this host).

- **Deck:** `deck/deck.html` — 13 scenes, `data-dur` summing to **199 s**, every scene grounded in the
  run's logs (seq/turn citations + honest negatives). Diagrams: `diagrams/d1…d9` (mmd in `mmd/`).
- **Renderer:** `deck/render.js` — Puppeteer + cached ms-playwright Chromium, headless 'shell',
  `Emulation.setVirtualTimePolicy` paused → `window.__start()` → advance `budget = 1000/fps` per frame +
  `page.screenshot`. FPS 12, viewport 1920×1080.
- **Frames:** 2,389 JPGs (`totalMs=199000`, 12 fps), rendered in 733 s. **Local-only** (`deck/frames/`,
  ~190 MB) — NOT committed; reproducible via `node deck/render.js`.
- **Assembly:** `ffmpeg -framerate 12 -i frames/frame_%06d.jpg -c:v libx264 -pix_fmt yuv420p -crf 20`.

**Output:** `WINXP-LAPTOP-2005-EXECUTION.mp4` — h264, 1920×1080, **2,389 frames, 199.08 s, 3.4 MB**.
**Verified:** ffprobe full-length (not a stub); 5 sample frames sampled across the timeline are all
distinct (5/5 unique); visual spot-check of the "Errors & Recovery" scene confirms grounded content.

**Provenance:** the deterministic deck + 9 diagrams + `CORRELATION-REPORT.md` were authored by a detached
autonomous agent; that agent stalled at the render orchestration (captured only a 100-frame test, then
exited). The full 2,389-frame render + assembly + verification were completed directly. No raw logs were
edited; outputs live only under this `WINXP-LAPTOP-2005-video/` folder.

**Tooling:** mermaid-cli puppeteer (bundled Chromium chromium-1223), ffmpeg (libx264), node.
