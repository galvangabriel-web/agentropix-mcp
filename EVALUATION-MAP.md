# 🧭 Evaluation Map — where each submission requirement lives in this repo

A routed guide for judges: each of the 8 submission requirements below maps to the exact artifacts
that satisfy it, with a reading path. Statuses are honest — ✅ means committed and verifiable here;
⚠️ means an operator action outside this repo is still pending.

| # | Requirement | Status | Start here |
|---|---|---|---|
| 1 | Code repository, README, OSS license | ✅ | [`README.md`](README.md) · [`LICENSE`](LICENSE) |
| 2 | Demo video (≤5 min, narrated, self-correction) | ⚠️ in-repo footage ready; YouTube/Vimeo upload pending | [`case-activation/runs/jimmy-wilson-poc/`](case-activation/runs/jimmy-wilson-poc/) |
| 3 | Architecture diagram + pattern + guardrail split | ✅ | [`docs/02-architecture/main-architectural-agentropix-design.md`](docs/02-architecture/main-architectural-agentropix-design.md) |
| 4 | Written project description (Devpost story) | ✅ distributed across the portal (assembly guide below) | [§4](#4--written-project-description-devpost-story) |
| 5 | Dataset documentation | ✅ | [`docs/06-use-cases/reproduce-datasets.md`](docs/06-use-cases/reproduce-datasets.md) |
| 6 | Accuracy report + evidence-integrity approach | ✅ | [`docs/07-sdlc-ops/dataset-recall.md`](docs/07-sdlc-ops/dataset-recall.md) |
| 7 | Try-it-out instructions | ✅ | [`README.md` → Connect in 60 seconds](README.md#-connect-in-60-seconds) |
| 8 | Agent execution logs | ✅ | [`AGENT-EXECUTION-LOGS-REPORT.md`](docs/12-CASES-REPORTS/srl-2018-report/submission/AGENT-EXECUTION-LOGS-REPORT.md) (gold report) · [`EXECUTION-LOG.md`](case-activation/runs/jimmy-wilson-poc/EXECUTION-LOG.md) |

---

## 1 · Code repository

- **This repo:** `https://github.com/galvangabriel-web/agentropix-mcp` (public).
- **README with setup instructions:** [`README.md`](README.md) — "⚡ Connect in 60 seconds" (live
  server) and "Installation / Quickstart" (Path A wheel install · Path B engine), with the
  step-by-step [Quickstart](docs/01-overview/quickstart.md) and [CLI Reference](docs/08-reference/cli-reference.md).
- **License:** [`LICENSE`](LICENSE) — **MIT**.
- **Installable package + releases:** [`agentropix_mcp/`](agentropix_mcp/README.md); wheels attached
  to the [GitHub releases](https://github.com/galvangabriel-web/agentropix-mcp/releases) (latest v0.3.0).

## 2 · Demo video

- **Committed footage (plays in-browser via GitHub Pages — see each folder's 🎬 section):**
  - [`jimmy-wilson-poc/POC-RUN.mp4`](case-activation/runs/jimmy-wilson-poc/README.md) — live terminal
    screencast of the full engine triage (`uv sync` → `doctor` → `run`, 129 findings · 86 tool calls).
  - Four recorded MCP activation sequences with sealed-report endings:
    [contact-me](case-activation/runs/contact-me-memory/README.md) ·
    [AMF sample001](case-activation/runs/amf-win-sample001/README.md) ·
    [memdump](case-activation/runs/memdump-raw-2014/README.md) ·
    [Notch It Up](case-activation/runs/challenge-notchitup/README.md).
  - [`vanko-report/findings-presentation.mp4`](docs/12-CASES-REPORTS/vanko-report/README.md) — the
    ~9-min narrated-by-slides evidence walkthrough.
  - 🎬 [`EXECUTION-LOGS-ANIMATED.mp4`](https://galvangabriel-web.github.io/agentropix-mcp/docs/12-CASES-REPORTS/srl-2018-report/submission/EXECUTION-LOGS-ANIMATED.mp4) — the **108-second
    Animotion-animated walkthrough** of the Agent Execution Logs package (timestamp chain with the
    91-min wait to scale, the 61-REJECT storm, the 217 µs burst, the self-correcting plan, the seal
    cross-bind); deterministic virtual-time render from the committed
    [deck source](docs/12-CASES-REPORTS/srl-2018-report/submission/execution-logs-animated-deck.html) — a strong visual backbone for the
    ≤5-minute submission cut.
- **The self-correction sequence to show:** the Trinity iteration trace — iteration 1 runs all 13
  agents, the Critic marks 11 **stable**, iterations 2–5 re-run only the 2 still producing new
  evidence (the approach visibly changing). On film in `POC-RUN.mp4`; explained line-by-line in
  [`EXECUTION-LOG.md`](case-activation/runs/jimmy-wilson-poc/EXECUTION-LOG.md). The same
  plan-shrink narrative is documented for two further engine runs (13 → 2 and 13 → 4) in the
  [gold report §5](docs/12-CASES-REPORTS/srl-2018-report/submission/AGENT-EXECUTION-LOGS-REPORT.md), and **already animated scene-by-scene** in `EXECUTION-LOGS-ANIMATED.mp4` above — grounded material for the narration script.
- ⚠️ **Pending operator action:** cut a ≤5-minute screencast **with audio narration** from this
  footage and upload to YouTube/Vimeo ≥48 h before the deadline. The committed MP4s are silent
  screen captures — narration is not yet recorded.

## 3 · Architecture diagram

- **The deliverable:** [`main-architectural-agentropix-design.md`](docs/02-architecture/main-architectural-agentropix-design.md)
  with the rendered one-pager in [`assets/architecture-diagram/`](docs/02-architecture/assets/architecture-diagram/)
  — **PNG, SVG, and HD PDF** (`architecture-diagram-hd.pdf`).
- **Covers exactly what is asked:** agent layer → MCP server → SIFT Workstation tools → data
  sources → output pipeline; the **architectural-pattern verdict: Custom MCP Server**; and an
  explicit **prompt-based vs architectural guardrail split** (every box source-cited).
- Deeper layers: [system context](docs/02-architecture/system-context-c4.md) ·
  [components](docs/02-architecture/component-architecture.md) ·
  [sequence diagrams](docs/02-architecture/sequence-diagrams.md).

## 4 · Written project description (Devpost story)

The story sections map onto committed pages — assemble the Devpost text from these:

| Devpost section | Source page |
|---|---|
| **What it does** | [What is Agentropix](docs/01-overview/what-is-agentropix.md) · [What you get](docs/01-overview/what-you-get.md) |
| **How we built it** | [Implementation](docs/07-sdlc-ops/implementation.md) · [Architecture chapter](docs/02-architecture/README.md) |
| **Challenges** | [Lessons learned](docs/01-overview/lessons-learned.md) (real-data GOTCHAs, render pipeline, recall hunts) |
| **What we learned** | [Lessons learned](docs/01-overview/lessons-learned.md) · [Design decisions](docs/08-reference/design-decisions.md) (tradeoffs, explicitly argued) |
| **What's next** | [🗺️ Project Roadmap](docs/02-architecture/PROJECT-ROADMAP-2026-06-11.md) — phases to GA + **The Future of Agentropix** |
| **Autonomous-execution qualities addressed** | [Safety & anti-hallucination (README §)](README.md#safety--anti-hallucination) · [Invariant audit](docs/02-architecture/SECURITY-INVARIANT-AUDIT-2026-06-11.md) — deterministic halt, no LLM self-rating, human-in-the-loop |

## 5 · Dataset documentation

- **What the agent was tested against + sources:** [`reproduce-datasets.md`](docs/06-use-cases/reproduce-datasets.md)
  (public download URLs) and the [case-activation INDEX](case-activation/INDEX.md) — 14 documented
  evidence sets (CFReDS, DFRWS 2005, SANS FOR500/FOR508, MemLabs, AMF…) with byte-exact sizes and
  custody hashes; per-case detail in each [Activation Guide](case-activation/README.md).
- **What the agent found:** the sealed case reports — [SRL-2015](docs/12-CASES-REPORTS/srl-2015-report/) ·
  [SRL-2018](docs/12-CASES-REPORTS/srl-2018-report/) · [VANKO](docs/12-CASES-REPORTS/vanko-report/) —
  plus the per-run sealed `report.json` records under [`case-activation/runs/`](case-activation/runs/README.md).
- **Ground truth fixtures:** [`docs/03-data/recall-ground-truth/`](docs/03-data/) (committed).

## 6 · Accuracy report

- **Recall self-assessment (missed artifacts quantified):** [`dataset-recall.md`](docs/07-sdlc-ops/dataset-recall.md)
  — disk **72/72 (100%)**, memory **108/118 (91.5%)**: the 10 misses are enumerated, not hidden.
  Scored methodology: [evaluation scorecard](docs/07-sdlc-ops/evaluation-scorecard.md).
- **False positives:** VANKO recorded **19 candidate findings, 9 refuted by the false-positive
  gate, 10 confirmed** — refuted hypotheses kept as honest negatives in the
  [DFIR report](docs/12-CASES-REPORTS/vanko-report/).
- **Hallucinated claims:** the anti-hallucination design + its **source-traced audit**:
  [anti-hallucination](docs/05-safety-forensics/anti-hallucination.md) ·
  [🔒 SECURITY-INVARIANT-AUDIT-2026-06-11](docs/02-architecture/SECURITY-INVARIANT-AUDIT-2026-06-11.md)
  (6 invariants, file:line-cited, 5 Enforced / 1 Partially — the gap stated, not papered over).
- **Evidence integrity & bypass behavior (required section):** the audit's invariants #3/#4 — the
  Thymus deny-by-default policy rejects every write **before** the subprocess spawns, no write tool
  exists in the surface, and each invariant carries an **adversarial test case** describing exactly
  what happens when the agent attempts a bypass. Plus [provenance & grounding](docs/05-safety-forensics/provenance-grounding.md)
  and the pre/post SHA-256 discipline ([honest nuance in README §Safety](README.md#safety--anti-hallucination)).
  **Live-run proof:** the submission package's §6 *Governance & Sealed Audit Correlation* and its raw
  [`base-dc-thymus-audit.jsonl`](docs/12-CASES-REPORTS/srl-2018-report/submission/base-dc-thymus-audit.jsonl) — **146 recorded decisions, 61 real
  `REJECT`s** of out-of-allowlist paths during the run, seals cross-bound to entry counts ([gold report](docs/12-CASES-REPORTS/srl-2018-report/submission/AGENT-EXECUTION-LOGS-REPORT.md)).

## 7 · Try-it-out instructions

- **Live deployment:** the operator's MCP server (tailnet-only) — join steps + client config in
  [Client Setup](docs/09-integrations/client-setup.md) and README "⚡ Connect in 60 seconds".
- **Run locally (no tailnet needed):** README "Installation / Quickstart" Path A — `pip install`
  the released wheel, start `agentropix-mcp` with a token, `claude mcp add …` (3 commands);
  dependencies in [Deployment & requirements](docs/07-sdlc-ops/deployment.md).
- **Provided data to run against:** dataset download URLs in
  [`reproduce-datasets.md`](docs/06-use-cases/reproduce-datasets.md); guided per-case sequences in
  every [Activation Guide](case-activation/README.md) (🖥️ expert command + 💬 plain-language prompt
  for each step).

## 8 · Agent execution logs

- **The gold report (start here):** [`AGENT-EXECUTION-LOGS-REPORT.md`](docs/12-CASES-REPORTS/srl-2018-report/submission/AGENT-EXECUTION-LOGS-REPORT.md) — two engine runs
  (**base-dc** = the SRL-2018 domain controller E01, 22 findings · 176 tool calls; **notch** =
  `Challenge_NotchItUp` raw image, 10 findings · 60 tool calls), every claim in strict
  `file:json-path -> value` citation form: agent roster (§2), **timestamped agent-to-agent handoff
  log** (§3, every edge VERIFIED), **full tool-execution sequence** with worked 3-way cross-file
  correlations (§4), **iteration-over-iteration trace** (§5), sealed-audit correlation (§6), and a
  traceability appendix (§7). The 10 raw evidence files sit beside it
  ([folder README](docs/12-CASES-REPORTS/srl-2018-report/submission/README.md)) — per run: sealed `report.json`, `audit-log.json`,
  `session-key`, **live `run.log`**, and **`thymus-audit.jsonl`** (artifact types no other
  published run folder carries). Its [**Visual Atlas**](docs/12-CASES-REPORTS/srl-2018-report/submission/AGENT-EXECUTION-VISUAL-ATLAS.md)
  renders the same evidence as thirteen color diagrams (communication graph, timestamp chain,
  self-correction funnels, governance pies, seal chain), and the
  [108-second animated walkthrough](https://galvangabriel-web.github.io/agentropix-mcp/docs/12-CASES-REPORTS/srl-2018-report/submission/EXECUTION-LOGS-ANIMATED.mp4)
  plays the same story in motion (in-browser).
- **Persistent-loop trace (iteration-over-iteration, approach changing):**
  [`EXECUTION-LOG.md`](case-activation/runs/jimmy-wilson-poc/EXECUTION-LOG.md) — tool execution log
  with timestamps + durations, the Trinity trace (13 agents → 2 after the Critic marks 11 stable),
  and Blackboard activity. Token usage is an **honest negative** (LLM at the edge, uninstrumented —
  documented, not faked).
- **Agent-to-agent messages with timestamps:**
  [`blackboard-events.jsonl`](case-activation/runs/jimmy-wilson-poc/blackboard-events.jsonl) —
  timestamped agent publish/correlation events.
- **Raw machine records:** sealed `report.json` per run (full tool-call trace embedded) + the
  unedited [`raw/`](case-activation/runs/jimmy-wilson-poc/raw/README.md) triplets of three
  reproducible runs; raw per-step MCP outputs (`step*.json`) in every
  [recorded run folder](case-activation/runs/README.md).

---

*Every number above tracks [`canonical-facts.md`](docs/08-reference/canonical-facts.md)
(72 MCP tools · 16 SIFT wrappers · 4464 tests · 72/72 disk · 108/118 memory recall).*
