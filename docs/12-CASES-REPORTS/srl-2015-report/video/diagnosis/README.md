# `diagnosis/` — render-verification captures (publication QA)

Playwright screenshots taken against the **published repository pages** to verify that the
cases-reports tree, READMEs, and video blobs actually render for a reader — the
"verify renders against the live blob" step of the portal's pre-push checklist. Kept as the
visual proof of that QA pass (and of the one render bug it caught and fixed).

| File | What it shows |
|---|---|
| [`01-cases-reports-tree.png`](01-cases-reports-tree.png) | the `docs/12-CASES-REPORTS/` tree as served — folder layout readers actually see |
| [`02-readme-blob.png`](02-readme-blob.png) | the cases index `README.md` rendered as a blob page |
| [`03-srl2018-tree.png`](03-srl2018-tree.png) | the `srl-2018-report/` folder view |
| [`04-vanko-tree.png`](04-vanko-tree.png) | the `vanko-report/` folder view |
| [`05-mp4-blob-vanko.png`](05-mp4-blob-vanko.png) | how a committed MP4 presents in the blob viewer (VANKO) |
| [`06-mp4-blob-srl2018.png`](06-mp4-blob-srl2018.png) | the same check for the SRL-2018 session video |
| [`07-fixed-readme-render.png`](07-fixed-readme-render.png) | the index README **after** the video-embed fix — proof the broken embed was repaired |

**Why it matters:** repo-committed MP4s and Mermaid blocks fail silently on the rendered page if
embedded the wrong way (the reason the reports use PNG diagrams and poster-link video embeds);
these captures are the before/after evidence that the published pages were checked visually, not
assumed. See [`../README.md`](../README.md) for the replay video this folder's QA belongs to.
