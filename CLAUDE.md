# CLAUDE.md — Agentropix-SIFT Documentation Portal

Conventions for working on this documentation portal. **Read before editing or adding any page.**
The portal is the reader-facing docs for Agentropix-SIFT; `INDEX.md` is the routed master
index and `README.md` is the landing page. Sections live under `docs/01-overview` … `docs/11-ADR`,
plus `docs/12-CASES-REPORTS` (sealed DFIR case reports) — 12 numbered categories; each section's
reading order is layered on via a "Read in this order" list, non-destructively — filenames are not renamed.

## Source of truth & accuracy
- **Canonical numbers come from [`docs/08-reference/canonical-facts.md`](docs/08-reference/canonical-facts.md)** — `72` MCP tools, `16` forensic
  wrappers, `4464` tests, `72/72 (100%)` disk recall, `108/118 (91.5%)` memory recall, Python `3.12+`.
  **Never state a number that contradicts it.** Stale figures may only appear inside an explicit
  "earlier draft said X, canonical is Y" reconciliation note.
- **The main repo `/home/admin2/agentropix-sift` (docs + `src/`) is the oracle.** Every non-obvious
  claim, command, flag, path, and tool name must be verifiable there; cite the source file. The oracle
  wins any conflict with portal prose or imported source material.

## MCP-call accuracy (validate every tool/plugin against the live MCP)
Docs are full of 🖥️ MCP calls and `run_volatility` plugins; a wrong name is a real, demo-breaking bug.
- **Every documented MCP tool name must exist in the live tool list** (`72` tools — query `tools/list`
  via the MCP, or [`docs/04-mcp-tools/tool-list.md`](docs/04-mcp-tools/tool-list.md)). Non-tools that crept into drafts:
  `get_hashdump`/`hashdump` (no credential-dump capability is exposed — drop the step), `get_srum`
  (→ `srum_extract`), and `mmls` used as an MCP slot (→ `get_partitions`/`parse_gpt`; note `fls` *is* a
  real tool). When unsure, query the live `tools/list` — don't guess.
- **`run_volatility` plugins** must be a short alias (`pslist`,`malfind`,`cmdline`,`netscan`,`svcscan`,
  `pstree`,`dlllist`,…) **or** a full canonical id (`windows.cmdline.CmdLine`). The bare middle form
  `windows.cmdline` is **rejected**.
- **No "identify the OS" step on a raw memory image.** `windows.info`/`banners` are **not allowlisted**,
  and `get_image_info` is **EWF/E01-only** (returns empty on raw `.mem`/`.raw`/`.bin`). The kernel
  profile **auto-detects on the first `windows.*` plugin** (`get_pslist`) — a populated pslist confirms
  the symbol-table match; empty + `kernel.symbol_table_name` error = no profile resolved (honest
  negative). `get_image_info` is correct only for disk/E01 cases.
- Recurring fixes + the full sweep live in [`docs/issues/CASE-GUIDE-AUDIT.md`](docs/issues/CASE-GUIDE-AUDIT.md).

## The documentation template (the standard for this portal)
The gold-standard page is [`docs/01-overview/user-guide.md`](docs/01-overview/user-guide.md). Apply
its conventions to all **operational / how-to** content:

1. **Dual-audience representation.** For any operator action, show BOTH ways to get the same result
   in an eye-catching callout, side by side:
   - **🖥️ Expert (command):** the exact CLI / MCP call.
   - **💬 End-user (prompt):** the plain-language prompt a non-technical user types into Claude
     Desktop / Claude CLI (with the Agentropix MCP connected) — it must map to a **real MCP tool**
     (verify against [`docs/04-mcp-tools/tool-list.md`](docs/04-mcp-tools/tool-list.md)). The point: a simple focused
     question is enough — the session recognizes it as an Agentropix capability and routes the tool.
   *Adapt Agentropix to the user, not the user to Agentropix.*
2. **Execution → Output enumeration.** Label command/result pairs consistently (Execution A → Output
   A, B → Output B …) so it is unambiguous what the reader **runs** vs what they **get back**.
3. **Audience separation + usability matrix.** Where both apply, give a matrix correlating
   **Manual ↔ Autonomous** × **Expert (CLI) ↔ Non-expert (prompt)**; keep the lanes clearly separated.
4. **"How to read this page" / real-data preface.** If a page shows real example output, say up front
   that it comes from a validated prior run (e.g. the 2026-05-29 CFReDS run) so readers expect real
   artifacts/IDs. Explain every **GOTCHA** box (what it is, why real-data quirks appear).
5. **Reference vs operational.** Pure reference/architecture pages (architecture, data, tool reference,
   ADRs) get the *clarity* standard — define terms, explain everything, consistent style — but do not
   force prompt-boxes where there are no commands.

## Diagrams (Mermaid) — GitLab rendering rules
GitLab renders Mermaid client-side (strict security level); respect its limits:
- **No C4 diagrams** (`C4Context/Container/Deployment`) — GitLab can't render them; use `flowchart`/etc.
- **No `timeline` diagrams** — GitLab (and Mermaid 11) reject/mis-render the kill-chain `timeline`
  syntax. Use a vertical `flowchart TD` instead (one node per event).
- **No HTML-tag-like tokens in labels** — GitLab strict parses `<tool>`, `<path>`, `<n>` etc. as HTML
  tags and **silently drops/breaks the diagram** (renders as a raw code box). `<br/>` is the one safe
  exception (line break). Write `PID` not bare `#`; replace `<placeholder>` tokens with quoted plain text.
- In `sequenceDiagram` message text, **no `;`** (use `,`). In `classDiagram` members, **no `{}`**.
- Every `classDef` needs an explicit `color:` (dark text) so it's legible in light AND dark mode.
  (The only `#` allowed are hex colors inside `classDef`/`style`.)
- **Wide diagrams** (GitLab fits to the ~800px column → squished/unreadable): commit a full-size SVG
  under the section's `assets/` and add an **"🔍 Open as SVG — full size, zoomable"** link after the
  block. To find wide ones reliably, **render each diagram and measure its intrinsic width** (the
  `viewBox`/`max-width` of the SVG); **>900px = wide**. `mermaid-cli` (`mmdc`) **works** once pointed at the
  cached ms-playwright Chromium instead of the AppArmor-blocked snap-Chromium:
  `PUPPETEER_EXECUTABLE_PATH=~/.cache/ms-playwright/chromium-1223/chrome-linux64/chrome mmdc -i d.mmd
  -o d.png -p <cfg {"args":["--no-sandbox"]}> -b white -t dark -s 2` (verified 2026-06-08 — flowchart/
  timeline/mindmap all render; see the case-reports recipe below). The **playwright-mcp container** +
  `~/pwshots/gen_svg.cjs` (bundles `mermaid.min.js`, outputs SVG + width) remains the alternative for SVG.

## GitLab rendering & verification (what actually shows on the server)
- **`.md` renders inline** on GitLab — Markdown + tables + Mermaid (Mermaid renders **lazily on scroll**).
  This is the canonical viewable form. **`.html` shows as source** (GitLab never executes repo HTML).
  **`.pdf` opens in GitLab's PDF viewer.** So for a report: ship the `.md` for inline GitLab viewing and
  a light `.pdf` for sharing; an `.html` is download-only.
- **Mermaid-worker caveat (observed 2026-06-08):** this instance's `external_url` is `localhost:8929`,
  so the **client-side Mermaid worker (and telemetry) is fetched from `localhost`** and **fails for any
  remote / LAN-IP browser** (`ERR_CONNECTION_REFUSED`) — Mermaid blocks then show as **raw code**, even
  though they're valid and under the 5000-char limit. Two consequences: (1) verify renders from the host
  GitLab serves, or fix `external_url`; (2) where remote rendering must be **guaranteed** — notably the
  **case reports** (`docs/12-CASES-REPORTS/`) — embed diagrams as **PNG in Markdown** (`![](diagrams/dN.png)`,
  rendered from the Mermaid via `mmdc`/playwright). PNG is same-origin, needs no JS, and always renders.
- **Video:** `![](x.mp4)` renders a native `<video controls>` player, but GitLab **sanitizes
  `<video loop/autoplay>`** — no auto-loop in the blob view (raw file / GitLab Pages only). Commit small
  mp4s directly; move to Git LFS if they accumulate.
- **Verify renders with Playwright** (the `playwright-mcp` container, `--network host`): log into GitLab
  as `root` (password parsed from `gitlab.txt`'s box-table) and open the blob; reuse `~/pwshots/gl_md.cjs`.
  Caveat: the programmatic "is-mermaid-rendered" DOM check is **unreliable** (false negatives) — trust a
  **visual screenshot** or the **intrinsic-width** measurement, not an svg-element count.

## Images
- Screenshots: **crop to the relevant content** so they're legible at column width; capture at 2×
  (`deviceScaleFactor`). Store under the section's `assets/` dir. Reference with relative links.

## Case activation guides & recorded runs (`case-activation/`)
- **`case-activation/*.md`** — per-case Activation Guides (one per `/cases/*` evidence set),
  instantiating the 8-step template with that case's real values. Index: `case-activation/INDEX.md`.
- **`case-activation/runs/<slug>/EXECUTED-RUN.md`** — a real **live MCP** execution of a guide's MANUAL
  sequence (captured tool outputs, honest results incl. GOTCHAs), rendered to an educational
  **`EXECUTED-RUN.mp4`**. Reusable workflows (session-local): `case-run-to-video.js` (one case, args via
  `{guide,outDir,caseId,image,section}`) and `complete-approval-loop.js` (approval→sealed-report fan-out).
  Per-tool MCP timeout must pass the SDK `{timeout:300000, resetTimeoutOnProgress:true}` option, or heavy
  Volatility plugins (e.g. `malfind`) false-timeout at the 180 s default.
- **Video pipeline:** `~/.openclaw/workspace/scripts/render-bmad-md.sh <md> <out> [subtitle]` (MD→1080p
  MP4). It is **NOT concurrency-safe** (shared temp files) — render **one at a time** and `ffprobe`-verify
  each is full-length; a tiny/few-second MP4 = a render collision. MP4s are committed binaries — move to
  Git LFS if they accumulate.
- **Demo approvals are SIMULATED.** Approval is the human HMAC hard-stop; when a recorded run
  auto-approves (Playwright portal or `approve_finding`) it **must be labelled "SIMULATED examiner
  approval (demo only)"** so the showcase never misrepresents the human-in-the-loop control. Loop recipe:
  mint an `index_findings` evidence-gate token → `record_finding dry_run=false` → approve → `report_generate`.

## Video annotation & animation pipeline (validated 2026-06-12)
- **Annotated/highlight videos: NEVER drawbox over scrolling footage** — boxes drift off their
  targets. Build from **stills**: extract one steady frame per key moment (`ffmpeg -ss`), draw the
  boxes on the stills, concat at narration-friendly durations (`-f concat` with per-file
  `duration`). Always **copy — never edit the original video**; commit sources beside the output.
- **Red-box placement is pixel-precise, machine-verified — never eyeballed percentages**: detect
  the block's text extents from frame pixels (grayscale brightness >90), pad into the blank
  gutters, iteratively nudge any edge whose stroke would cross a glyph, and **audit that the 3 px
  stroke ring crosses ZERO text pixels** before shipping (the AMF v3 recipe;
  thin 3 px strokes, tight boxes — not screen-swallowing). If a gap is too small to fit a box
  (e.g. 1 px), re-target the box to the semantically important neighbor line instead.
- **Animation renders are DETERMINISTIC via CDP virtual time** — real-time
  `recordVideo` is non-uniformly time-dilated on this host (a 108 s deck recorded as 832 s).
  Recipe: deck exposes `window.__start` (don't autostart); `goto` → `document.fonts.ready` →
  `Emulation.setVirtualTimePolicy {pause}` → `__start()` → loop `advance budget=1000/fps` +
  `Page.captureScreenshot` with timeout fallbacks; include an invisible `vt-ticker` CSS animation
  so the compositor never stalls. Assemble with `ffmpeg -framerate 12`. Expect ~25–45 min for
  ~1700 frames; zero fallbacks = healthy run.
- **Playback on GitHub:** github.com renders NO player for repo-committed MP4s (any size) and
  `raw.githubusercontent` forces download (`octet-stream` + `nosniff`). Serve via **GitHub Pages**
  (proper `video/mp4`; enabled, `.nojekyll` committed) and link **auto-start watch pages**
  (`<video autoplay muted controls loop playsinline>`). The only inline-autoplay media in READMEs
  is an **animated GIF** (`palettegen/paletteuse dither=none`; flat dark palettes compress to
  ~100–900 KB).
- **Animotion MCP** supplies keyframe CSS + Lucide SVG icons (stdio JSON-RPC; `get_icon`
  takes `{"id":"lucide:name"}`, returns JSON with `svg`; `get_animation_css` by ID; classes are
  `animotion-*` with `animation-fill-mode:backwards` for delayed entrances).
- After every video/GIF change: **Playwright-verify the live artifact** (playback advancing,
  GIF frames differing across scene boundaries — sample >10 s apart, scenes have static holds) and
  audit served frames, not just local ones.

## Case reports (`docs/12-CASES-REPORTS/`)
- **Per-case folders** (`12-CASES-REPORTS/<case>-report/`) under one house-style index `README.md`
  (`# 12 · Cases Reports` → `## Cases` → one `###` heading per case, each with a blurb + its own numbered
  **"Read in this order"** list + the recorded-session video). Two cases live here:
  - **SRL-2018** (`srl-2018-report/`, APT IP-theft): `SRL-2018-FORENSIC-REPORT.md` (image-diagram report),
    `TECHNICAL-APPENDIX.md` (netscan/malfind/evtx depth), `WAZUH-IOC-GALLERY.md`, `diagrams/`, `wazuh/`, mp4.
  - **VANKO** (`vanko-report/`, "Abducted Zebrafish" insider IP-theft, **not a malware intrusion**):
    `VANKO-FORENSIC-REPORT.md` (presentation report, 5 diagrams — mirrors the SRL template),
    `VANKO-DFIR-REPORT.md` (full 7-section **legally-defensible** report — zero first-person, evidentiary
    tone, honest negatives), `WAZUH-VANKO-GALLERY.md` (8 dashboard captures), `report.md` (synthesis),
    `diagrams/`, `wazuh/`, and two videos — `training-session-paged.mp4` (raw action-log playback) + `findings-presentation.mp4` (the ~9-min technical evidence walkthrough, README-featured). 10 confirmed findings (of 19; 9 refuted by the FP gate). The DFIR report ends with a **§8.0 "Validation of Reported Indicators"** mapping the pre-investigation allegations/tasking to the evidence with a status (Confirmed / Corroborated / Artifact-level / External-to-media / Exceeded).
- **Diagrams as PNG, not Mermaid** (Mermaid-worker caveat above). Render with **`mmdc`** (mermaid-cli, at
  `/usr/bin/mmdc`): `PUPPETEER_EXECUTABLE_PATH=~/.cache/ms-playwright/chromium-1223/chrome-linux64/chrome
  mmdc -i dN.mmd -o diagrams/dN.png -p <cfg {"args":["--no-sandbox"]}> -b white -t dark -s 2`.
  flowchart/timeline/mindmap all render; **mindmap is special-char-picky** (avoid `\`/`@`/`()` in leaf text).
- **Recorded-session video:** `make_cast_paged.py` pages `session-actions.log` (per-step `rec.sh` log) →
  asciinema cast → `agg --cols 150 --rows 42 --font-size 14 --fps-cap 8 --theme github-dark` → gif →
  `ffmpeg -r 8 -pix_fmt yuv420p` → mp4. The workspace `.gitignore` ignores `*.mp4`/`*.cast`/
  `session-actions.log`/`step_*.json` → **`git add -f` only the published mp4** (raw artifacts stay local).
- **DFIR-report synthesis** can be driven by an **Opus 4.8 multi-agent workflow** (parallel section
  drafters → IC synthesizer → legal-defensibility critic → reviser), grounded **strictly** in the case's
  `confirmed-findings.json`/`FINDINGS.jsonl` — no fabrication; refuted hypotheses kept as honest negatives.
- **Evidence/presentation video** (the case walkthrough): an **Opus 4.8 workflow** (`findings_presentation_workflow.js`
  — outline agent → parallel scene-builders that read the 3 reports → editor) emits a storyboard of the N key
  facts, each with 2–3 **cross-source correlated artifacts** + a "why it holds" correlation paragraph +
  "what it means". A renderer turns it into Evidence frames (each proof in a **red box**) + Analysis frames
  (correlation + meaning panels), bookended by the `dN` diagrams, paced ~7–9 min. TWO render paths: (a)
  HTML→Playwright (best polish), or (b) **raw CLI** `make_presentation_video.sh` = `jq` + **ImageMagick**
  (`pango:` markup text, drawn red `roundrectangle` proof-boxes, panels) + `ffmpeg` concat. **Gotchas:**
  ImageMagick `pango:` **eats backslashes** — escape `\` → `\\` so `C:\Users\…` / `\\STARK-FILESERVE` render;
  it also parses `&<>` as XML (escape them); pango font `size` is in 1024ths of a pt. ImageMagick must be
  `apt-get install`ed (only `jq`/`ffmpeg`/`agg`/`mmdc` pre-exist). Ground the storyboard in the reports — keep
  the same honest-negatives discipline (no `.DS_Store`/macOS-staging or other refuted claims as "proof").
- Every report keeps an **honest-caveats** section and is grounded in the case's **sealed findings**.
  Recovered malware/artifacts stay **out of the repo** (`/home/admin2/<case>-case-artifacts/`, gitignored).
  **Exception (operator-authorized 2026-06-12):** the VANKO raw working files ARE published —
  `vanko-report/` `ost-investigation.{sh,log}`, `_stepC.sh`, `p3_analyze.py`, `args_*.json`,
  `ost-results/*.carve.json` (fictional FOR500 persona mailbox carves), plus `FINDINGS.jsonl` /
  `confirmed-findings.json`. This is a per-case operator decision, NOT a precedent — other cases'
  working files still stay local unless explicitly authorized.
  Wazuh egress is operator-authorized (decision ledger seq); shared `agentropix_*` CDB lists are
  **replace-per-list** → push an **additive union** (existing live keys + new) to avoid wiping other cases' IOCs.
  The matching run transcript lives at `case-activation/runs/<case>/EXECUTED-RUN.md`.

## Publishing — GitHub only (GitLab retired 2026-06-10)
- **This repo is PUBLIC on GitHub:** `github` remote → `https://github.com/galvangabriel-web/agentropix-mcp`
  (auth via `gh auth setup-git`). Push portal changes with **`git push github main`**. Cut releases with
  `gh release create vX.Y.Z agentropix_mcp/dist/*` (latest: **v0.3.0**).
- **GitLab is RETIRED — do NOT push/fetch/force-push it.** The `origin` remote (internal GitLab
  `192.168.2.227:8929`) still sits in `.git/config` but must not be touched; it diverged earlier and that
  is now moot. (The GitLab-specific Mermaid/rendering rules below still matter — GitHub is *also* strict:
  it rejects `foreignObject` SVGs and shrinks inline Mermaid, so the "PNG-not-Mermaid" guidance holds.)
- The installable server package lives at `agentropix_mcp/` (src layout + `pyproject.toml`; console script
  `agentropix-mcp`; extras `[engine]`/`[forensics]`/`[reports]`); built wheels go to `agentropix_mcp/dist/`
  (gitignored) and are attached to GitHub releases.

## Repo-wide audit & LLM-index artifacts (root, published 2026-06-13)
Auto-generated (Opus 4.8 multi-agent workflows), repo-grounded, every figure source-cited; all live on
`github/main`, linked from `README.md` + `INDEX.md`, and **mirrored into `agentropix-sift/docs/portal/`**:
- `AUDIT-COVERAGE.md` — per-section README/file index-coverage audit (701 tracked files; 0 broken links,
  0 orphans after the build-sources pass). The audit drove a README/INDEX coverage pass + a
  `agentropix_mcp/README.md` "Complete file index" (every package module, docstring-derived, verified).
- `EVIDENCE_DATASET_DOCS.md` — evidence-dataset inventory: provenance, SHA-256 (computed live + manifest
  hashes), schemas, acquire→…→SIEM ingestion pipeline.
- `ACCURACY_REPORT.md` — system accuracy/validation audit (benchmark matrix, recall, drift/threshold
  findings w/ file:line). **GOTCHA: `ACCURACY_REPORT.md` (underscore, root) is a DIFFERENT file from
  `docs/07-sdlc-ops/ACCURACY-REPORT.md` (hyphen) — never confuse or overwrite one with the other.**
- `llms.txt` (curated index) + `llms-full.txt` (expanded: inlines 19 core docs for single-pass LLM
  ingestion). **`llms-full.txt` inlines the README/client-setup content, so it contains the
  operator-sanctioned BURNED bearer token verbatim (same one already public in README ×3 + client-setup
  + vanko `ost-investigation.sh`); if that token is ever rotated, update `llms-full.txt` too.**
- **The featured Case Evaluation video** (`Final_Video/SRL-2015-EVIDENCE-presentation.mp4`, 8:27,
  committed) is on Vimeo (`https://vimeo.com/1201031111`, public+embeddable, oEmbed-verified) and
  README-featured. A ≤5-min cut exists locally (`Final_Video/…-5min.mp4`, 4:58) but is NOT the published
  one — the 8:27 Vimeo exceeds the hackathon ≤5-min demo cap, so a 5-min upload is still the open item.
- **Render/link verification is mandatory after any README/report push** (the established pattern):
  Playwright the GitHub blob (tables render, `rawPipeLines=0`), HTTP-check link targets (raw 200 for
  files; **github.com `tree/` 200 for directory links** — raw 404s on dirs are false positives).
  `.txt` files render as plain text (correct); large `llms-full.txt` ~320 KB still renders (no "too big").
- **Video working area** is the gitignored `video_pre/` (narrated SRL-2015 walkthrough, the BOXED
  terminal-with-command-squares/result-circles deck, the evidence walkthrough + its
  `SRL-2015-EVIDENCE-presentation/` slide set). Sync method that worked: split the asciinema cast into
  per-section sub-casts, render each, stretch each to its narration length (per-segment audio↔video sync);
  Playwright-OCR each section to verify. See auto-memory `video-annotation-pipeline`.

## Security / hygiene
- **Operator published the live secrets by explicit decision (treat as burned):** the demo approver
  password (`docs/05-safety-forensics/approval-portal.md`) and the live tailnet IP + bearer token
  (`docs/09-integrations/client-setup.md` + README "Connect in 60 seconds") are now public on GitHub *and*
  in git history. The same burned token is also embedded verbatim in
  `docs/12-CASES-REPORTS/vanko-report/ost-investigation.sh` (operator decision 2026-06-12; verified
  identical to the published one before embedding — that check is mandatory for any future "restore the
  original value" request). Rotation is still advised but is the operator's call — do **not** silently
  re-scrub them.
- **Do not add NEW secrets** beyond those the operator has already sanctioned — no other tokens, passwords,
  or bearer keys in any tracked file.
- **No raw internal IPs/hostnames in NEW pages** unless operator-authorized for that file — use placeholders
  (`<TAILNET-IP>`) or the documented tailnet hostname. Screenshots that show live data carry a privacy note.
- Gitignored (local-only, never publish): `gitlab.txt`, `compare/`, `end-user/`, `2026-*/`,
  `complete_reports/`, `.claude/`, `docs/issues/*.png`, `videoos/` (local video archive),
  `evaluation/` + `evaluation1/` + `evaluation2/` (judge-evaluation / Stage One self-review drafts —
  grading material; `evaluation/`+`evaluation1/` removed from GitHub HEAD 2026-06-12 but still present
  in git history, `evaluation2/` never tracked; never (re-)track any of them). Confirm
  `git status` won't stage these. (`.claude/` holds the session's `scheduled_tasks.lock` and must never
  be committed — add it to `.gitignore` if absent.)
  - The **multi-tier reports** (ADR-024 engine output) are published under each case run as
    `case-activation/runs/<case>/reports/<tier>.{md,html,pdf}` — the *report artifacts* only. The
    *design/process* folder `2026-06-01-report-engine-design/` (ADR, plan, mockups, root-cause) stays
    **local-only** (gitignored) — "keep the report, not how it was made."
- **`case-activation/` is tracked** (guides + `runs/` transcripts + MP4s) and holds **real case
  inventory + on-disk paths** — now public on GitHub by operator decision (the pre-public scrub was
  waived). Keep the LOCAL-ONLY headers as provenance; don't add NEW unscrubbed case paths without cause.

## Validate before every push
1. **Links/images** — every relative link and image reference resolves (0 broken).
2. **Canonical facts** — no number contradicts `docs/08-reference/canonical-facts.md`.
3. **Mermaid** — every `mermaid` block is flowchart-safe (classDef colors, no `timeline`/`<token>`).
   For diagrams that must render reliably, **commit a PNG** (GitHub shrinks inline Mermaid and rejects
   `foreignObject` SVGs); SVGs need explicit `width`/`height` and no `foreignObject` (render with
   `htmlLabels:false`). Verify renders with Playwright against the GitHub blob.
4. Mirror changed files into `/home/admin2/agentropix-sift/docs/portal/` (the in-repo copy).
5. **Stage surgically — never `git add -A`.** Another session may be writing to this repo concurrently;
   `git add` only the explicit files you changed, and confirm the staged set excludes `.claude/`,
   `__pycache__/`, `dist/`, and any gitignored dir. (The 2026-06-11 parallel-session exclusions —
   `srl-2018*` assets, `vanko-report/` working files — were resolved and published 2026-06-12.)
   Before staging untracked files, classify each against `github/main` (identical → delete the stale
   local copy; differs → check which is newer) so a merge doesn't collide. **Push to GitHub only:
   `git push github main`.**
6. **Known published gaps (Stage One reviews 2026-06-12, see `evaluation1/` + `evaluation2/`
   local-only):** the committed `case-activation/runs/jimmy-wilson-poc/POC-RUN.mp4` on `main` is a
   **9-second silent stub** (render collision) — re-render + `ffprobe`-verify before referencing it;
   the narrated ≤5-min demo video upload (EVALUATION-MAP.md §2) is still pending and is the one
   blocking hackathon requirement. The `evaluation2/` review (22-agent Opus workflow, every verdict
   adversarially re-verified against public `github/main` only; report at
   `evaluation2/STAGE-ONE-REVIEW.md`) confirmed it as the **single eliminating FAIL**: all **14**
   committed MP4s have zero audio streams, the only over-3-min walkthrough
   (`vanko-report/findings-presentation.mp4`, 8:47) exceeds the 5-min cap, and no external
   YouTube/Vimeo/Devpost link exists. Checks 1–3, 5, 7–11 all PASS as published; the Devpost story
   (check 6) is NEEDS MANUAL REVIEW — no Devpost project URL exists yet and the Find Evil! gallery
   is unpublished. Fix list (report §FIX LIST): record a ≤300 s narrated screencast showing one
   self-correction → upload to YouTube/Vimeo → link in README + Devpost → flip the
   EVALUATION-MAP.md ⚠️ row.

## Layout
```
README.md            landing page
INDEX.md             routed master index (audience + "question it answers" per page)
docs/01-overview     what-is, what-you-get, quickstart, user-guide (gold standard), competitive-positioning
docs/02-architecture system-context, component, trinity-loop, swarm-agents, mcp-server, sequence-diagrams, module-map
docs/03-data         data-dictionary, data-models, schema-er, persisted-artifacts, schema-dump
docs/04-mcp-tools    tool-reference, response-envelope, tool-by-agent, capability-map, tool-list
docs/05-safety-forensics  anti-hallucination, provenance-grounding, audit-courtroom, human-in-the-loop, approval-portal, ai-disclosure
docs/06-use-cases    uc-disk/memory/approval/wazuh, demo-walkthrough, case-hypotheses
docs/07-sdlc-ops     implementation, testing, recovery-resilience, security-model, configuration, deployment, dataset-recall, evaluation-scorecard, maintenance-dual-repo, env-vars
docs/08-reference    cli-reference, glossary, adr-index, design-decisions, canonical-facts (governing numeric authority)
docs/09-integrations wazuh-portal, client-setup
docs/10-agents       agentic-architecture, delegation-model, fastmcp-execution, agents-list
docs/11-ADR          all Architecture Decision Records (imported from the oracle); README.md = the ADR index
docs/12-CASES-REPORTS sealed DFIR case reports — one folder per case (README index + forensic report
                     + technical appendix + Wazuh gallery; diagrams as PNG, malware kept out of repo)
case-activation/     per-case Activation Guides (real case data) + runs/<slug>/ executed transcripts + MP4s
                     + runs/<slug>/reports/ (comprehensive + executive-onepager .md/.pdf)
agentropix_mcp/      the installable MCP-server PACKAGE (src/agentropix_mcp/ + pyproject.toml): fastmcp_app,
                     server, thymus_policy, wrappers/, wazuh/, approval_sidecar/, evidence_gate/, reports/,
                     schema/, security/, courtroom + the Trinity engine (trinity/, agents/, detectors/).
                     Console script `agentropix-mcp`; extras [engine]/[forensics]/[reports]; wheels in dist/ (gitignored)
docs/01-overview     …+ lessons-learned, roadmap  ·  docs/03-data …+ recall-ground-truth/ (committed GT fixtures)
docs/06-use-cases    …+ reproduce-datasets (public dataset download URLs)
docs/07-sdlc-ops     …+ observability-and-integrity-notes + assets/sample-sealed-run/ (committed sealed trace artifact)
docs/issues/         QA logs (DIAGRAM-AUDIT.md, CASE-GUIDE-AUDIT.md); docs/issues/*.png are gitignored
```
