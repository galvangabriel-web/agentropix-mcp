# `assets/submission-tour/` — Submission Evidence Tour: output & build inputs

The 2 min 24 s **Submission Evidence Tour** (one animated scene per submission requirement, each
with a live-captured proof panel). The reports/README link the **rendered output**; the **deck and
proof panels** are the render inputs, kept for reproducibility.

## Rendered output (what viewers watch)

| File | What it is |
|---|---|
| `SUBMISSION-TOUR.mp4` | the rendered tour video (linked from the README "Submission Evidence Tour") |
| `watch-tour.html` | GitHub Pages auto-play watch page for the MP4 |
| `submission-tour-poster.png` | poster/thumbnail frame |

## Build inputs (render sources — not read directly)

| File | Role |
|---|---|
| `submission-tour-deck.html` | the animated HTML deck captured (CDP virtual-time) into `SUBMISSION-TOUR.mp4` |
| `proof/repo-front.png` | proof panel — repository front page |
| `proof/license.png` | proof panel — MIT license |
| `proof/archdiag.png` | proof panel — architecture diagram |
| `proof/goldreport.png` | proof panel — gold-standard report |
| `proof/datasets.png` | proof panel — datasets documentation |
| `proof/accuracy.png` | proof panel — accuracy report |
| `proof/evalmap.png` | proof panel — evaluation map |
| `proof/animwalk.png` | proof panel — animated walkthrough |
| `proof/releases.png` | proof panel — GitHub releases |

Each `proof/*.png` is a live-captured screenshot composited into the corresponding tour scene.
