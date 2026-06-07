# CLAUDE.md — Agentropix-SIFT Documentation Portal

Conventions for working on this documentation portal. **Read before editing or adding any page.**
The portal is the reader-facing docs for Agentropix-SIFT; `INDEX.md` is the routed master
index and `README.md` is the landing page. Sections live under `docs/01-overview` … `docs/09-integrations`.

## Source of truth & accuracy
- **Canonical numbers come from [`.crew/facts.md`](.crew/facts.md)** — `71` MCP tools, `16` forensic
  wrappers, `4464` tests, `72/72 (100%)` disk recall, `108/118 (91.5%)` memory recall, Python `3.12+`.
  **Never state a number that contradicts it.** Stale figures may only appear inside an explicit
  "earlier draft said X, canonical is Y" reconciliation note.
- **The main repo `/home/admin2/agentropix-sift` (docs + `src/`) is the oracle.** Every non-obvious
  claim, command, flag, path, and tool name must be verifiable there; cite the source file. The oracle
  wins any conflict with portal prose or imported source material.

## MCP-call accuracy (validate every tool/plugin against the live MCP)
Docs are full of 🖥️ MCP calls and `run_volatility` plugins; a wrong name is a real, demo-breaking bug.
- **Every documented MCP tool name must exist in the live tool list** (`71` tools — query `tools/list`
  via the MCP, or [`.crew/tool-list.md`](.crew/tool-list.md)). Non-tools that crept into drafts:
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
- Recurring fixes + the full sweep live in [`issues/CASE-GUIDE-AUDIT.md`](issues/CASE-GUIDE-AUDIT.md).

## The documentation template (the standard for this portal)
The gold-standard page is [`docs/01-overview/user-guide.md`](docs/01-overview/user-guide.md). Apply
its conventions to all **operational / how-to** content:

1. **Dual-audience representation.** For any operator action, show BOTH ways to get the same result
   in an eye-catching callout, side by side:
   - **🖥️ Expert (command):** the exact CLI / MCP call.
   - **💬 End-user (prompt):** the plain-language prompt a non-technical user types into Claude
     Desktop / Claude CLI (with the Agentropix MCP connected) — it must map to a **real MCP tool**
     (verify against [`.crew/tool-list.md`](.crew/tool-list.md)). The point: a simple focused
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
GitLab renders Mermaid client-side; respect its limits:
- **No C4 diagrams** (`C4Context/Container/Deployment`) — GitLab can't render them; use `flowchart`/etc.
- In `sequenceDiagram` message text, **no `;`** (statement separator) — use `,`. **No bare `#`**
  (HTML-entity escape). In `classDiagram` members, **no `{}`**.
- Every `classDef` needs an explicit `color:` (dark text) so it's legible in light AND dark mode.
- Keep diagrams **narrow** (GitLab fits them to the ~800px column); split wide ones, prefer vertical
  layout, and add an **"Open as SVG"** link (committed under the section's `assets/`) for any diagram
  that renders wider than the column. Validate with `mermaid-cli` before pushing.

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

## Security / hygiene (this repo may be made public)
- **No secrets, ever** — no tokens, passwords, or bearer keys in any tracked file.
- **No raw internal IPs/hostnames** in pages — use placeholders (`<TAILNET-IP>`) or the documented
  tailnet hostname. Screenshots that show live data carry a privacy note.
- Gitignored (local-only, never publish): `gitlab.txt`, `compare/`, `end-user/`, `2026-*/`,
  `issues/*.png`. Confirm `git status` won't stage these before committing.
  - **Exception (tracked):** `2026-06-01-report-engine-design/` was **un-ignored 2026-06-07** and is
    published — the multi-tier report engine design + the grounded generated reports (4 cases × 3 tiers
    × md/html/pdf). It carries CTF/training case data + `<TAILNET-HOST>` placeholders only (no secrets).
    The other `2026-*/` folders remain local-only.
- **`case-activation/` is tracked** (guides + `runs/` transcripts + MP4s) but holds **real case
  inventory + on-disk paths** — each file carries a LOCAL-ONLY header. **Scrub paths/case names before
  the repo is made public** (this is the main pre-public task).
- **Demo-credential exception (the ONLY sanctioned secret in the tree):**
  `docs/05-safety-forensics/approval-portal.md` intentionally carries a **time-boxed demo approver
  password** for a closed-network demo, per explicit operator decision. It is already in git history —
  **rotate it AND scrub history (BFG / `git filter-repo`) before the repo goes public**; rotation alone
  won't remove it from past commits. Do not add any other secrets.

## Validate before every push
1. **Links/images** — every relative link and image reference resolves (0 broken).
2. **Canonical facts** — no number contradicts `.crew/facts.md`.
3. **Mermaid** — every `mermaid` block renders (mermaid-cli) and is GitLab-safe.
4. Mirror changed files into `/home/admin2/agentropix-sift/docs/portal/` (the in-repo copy).

## Layout
```
README.md            landing page
INDEX.md             routed master index (audience + "question it answers" per page)
.crew/               canonical facts + reference extracts (facts, tool-list, module-map, …)
docs/01-overview     what-is, what-you-get, quickstart, user-guide (gold standard), competitive-positioning
docs/02-architecture system-context, component, trinity-loop, swarm-agents, mcp-server, sequence-diagrams
docs/03-data         data-dictionary, data-models, schema-er, persisted-artifacts
docs/04-mcp-tools    tool-reference, response-envelope, tool-by-agent, capability-map
docs/05-safety-forensics  anti-hallucination, provenance-grounding, audit-courtroom, human-in-the-loop, approval-portal, ai-disclosure
docs/06-use-cases    uc-disk/memory/approval/wazuh, demo-walkthrough, case-hypotheses
docs/07-sdlc-ops     implementation, testing, recovery-resilience, security-model, configuration, deployment, dataset-recall, evaluation-scorecard, maintenance-dual-repo
docs/08-reference    cli-reference, glossary, adr-index, design-decisions
docs/09-integrations wazuh-portal, client-setup
case-activation/     per-case Activation Guides (real case data) + runs/<slug>/ executed transcripts + MP4s
issues/              QA logs (DIAGRAM-AUDIT.md, CASE-GUIDE-AUDIT.md); issues/*.png are gitignored
```
