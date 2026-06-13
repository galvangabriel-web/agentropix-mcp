# 🧭 Evaluation Map — where each submission requirement lives in this repo

> 🎬 **Watch the 2 min 24 s [Submission Evidence Tour](https://galvangabriel-web.github.io/agentropix-mcp/assets/submission-tour/watch-tour.html)**
> (auto-plays on open) — one animated scene per requirement below, each with a live-captured
> **REAL PROOF** panel and the Built-With tags. Deck source + proof captures:
> [`assets/submission-tour/`](assets/submission-tour/).

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
| 6 | Accuracy report + evidence-integrity approach | ✅ | [`docs/07-sdlc-ops/ACCURACY-REPORT.md`](docs/07-sdlc-ops/ACCURACY-REPORT.md) (§6 evidence integrity) · [visual companion](docs/07-sdlc-ops/evidence-integrity-visual.md) · [recall methodology](docs/07-sdlc-ops/dataset-recall.md) |
| 7 | Try-it-out instructions | ✅ | [`README.md` → Connect in 60 seconds](README.md#-connect-in-60-seconds) |
| 8 | Agent execution logs | ✅ | [`AGENT-EXECUTION-LOGS-REPORT.md`](docs/12-CASES-REPORTS/srl-2018-report/submission/AGENT-EXECUTION-LOGS-REPORT.md) (gold report) · [`EXECUTION-LOG.md`](case-activation/runs/jimmy-wilson-poc/EXECUTION-LOG.md) · [`rocba/EXECUTION-LOG.md`](case-activation/runs/rocba/EXECUTION-LOG.md) · [`WINXP-LAPTOP-2005/`](case-activation/runs/WINXP-LAPTOP-2005/) |

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
  - 🧭 [`SUBMISSION-TOUR.mp4`](https://galvangabriel-web.github.io/agentropix-mcp/assets/submission-tour/watch-tour.html) — the **144-second
    Submission Evidence Tour** (auto-plays): one animated scene per requirement 1–8 with a
    live-captured REAL-PROOF panel each, plus the Built-With tags — an end-to-end visual summary
    of this entire map ([deck source + proof captures](assets/submission-tour/)).
  - 🎞️ [Visual Atlas section animations ×6](docs/12-CASES-REPORTS/srl-2018-report/submission/AGENT-EXECUTION-VISUAL-ATLAS.md) — looping
    Animotion GIFs that auto-play inline throughout the redesigned Atlas (hero banner, the
    agent gossip graph, the 91-min-vs-217-µs clock, the self-correction funnel, the 85/61
    ALLOW-REJECT counters, the findings bar race) — friendly on the surface, every value sealed
    underneath.
  - 🎞️ [`safety-proof-animated.gif`](assets/safety-proof-animated.gif) — the **73-second
    six-guarantee proof reel, v2** (auto-plays inline in the README's Safety section): each
    anti-hallucination guarantee shown with real cited evidence from the SRL-2015 + SRL-2018
    Agent Execution Logs, **plus a plain-language "💡 What you're seeing" explainer panel on
    every scene** ([deck source](assets/safety-proof-deck.html)).
  - 🎞️ [`workflow-animated.gif`](assets/workflow-animated.gif) — the **17-second six-stage
    investigation-workflow animation** (doctor → run → review → human HMAC gate → seal → escalate,
    ending on the SEALED badge). The one asset that **auto-plays inline on github.com itself** —
    embedded in the README's [Recommended investigation workflow](README.md#-recommended-investigation-workflow)
    section ([deck source](assets/workflow-animated-deck.html)).
  - 🎬 [`EXECUTION-LOGS-SRL2015-ANIMATED.mp4`](https://galvangabriel-web.github.io/agentropix-mcp/docs/12-CASES-REPORTS/srl-2015-report/watch-execution-logs.html) — the
    **144-second SRL-2015 multi-host animation** (auto-plays): 4 hosts × disk+memory, 8 sealed
    runs, the 106-minute long-pole to scale, 15-iteration honest traces, and the cross-host
    spinlock.exe → Domain-Controller reveal ([deck source](docs/12-CASES-REPORTS/srl-2015-report/execution-logs-srl2015-deck.html)).
  - 🎬 [`EXECUTION-LOGS-ANIMATED.mp4`](https://galvangabriel-web.github.io/agentropix-mcp/docs/12-CASES-REPORTS/srl-2018-report/submission/watch.html) — the **108-second
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
- **Evidence integrity & bypass behavior (required section):** the consolidated statement lives in
  [ACCURACY-REPORT §6](docs/07-sdlc-ops/ACCURACY-REPORT.md#6-evidence-integrity--how-the-architecture-prevents-original-data-from-being-modified)
  with a [graphical companion](docs/07-sdlc-ops/evidence-integrity-visual.md) (diagrams of the Thymus
  allow/deny flow, architectural-vs-prompt-based guardrails, and a sequence of *what happens when the
  model attempts a bypass*). Grounding: the audit's invariants #3/#4 — the
  Thymus deny-by-default policy rejects every write **before** the subprocess spawns, no write tool
  exists in the surface, and each invariant carries an **adversarial test case** describing exactly
  what happens when the agent attempts a bypass. Plus [provenance & grounding](docs/05-safety-forensics/provenance-grounding.md)
  and the pre/post SHA-256 discipline ([honest nuance in README §Safety](README.md#safety--anti-hallucination)).
  **Proof reel:** the 🎞️ [safety-proof animation](assets/safety-proof-animated.gif) (auto-plays inline
  in the [README's Safety section](README.md#safety--anti-hallucination)) shows all six guarantees with
  real cited values from both Agent Execution Logs reports — the 204,884-entry fls walk, critic pinned
  at 1.0 across 10 runs, 10 distinct evidence SHA-256, the 61 live REJECTs, the seal cross-bind, and
  the 17+12 examiner-approved findings ([deck source](assets/safety-proof-deck.html)).
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
  self-correction funnels, governance pies, seal chain) — **redesigned 2026-06-12 with six looping
  Animotion section animations** (hero, gossip graph, geology-vs-lightning clock, 13-became-2
  funnel, bouncer-and-seal counters, findings bar race; deck sources in
  [`diagrams/animated-decks/`](docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/animated-decks/)) — and the
  [108-second animated walkthrough](https://galvangabriel-web.github.io/agentropix-mcp/docs/12-CASES-REPORTS/srl-2018-report/submission/watch.html)
  plays the same story in motion (in-browser).
- **The multi-host edition:** [`AGENT-EXECUTION-LOGS-REPORT-SRL2015.md`](docs/12-CASES-REPORTS/srl-2015-report/AGENT-EXECUTION-LOGS-REPORT-SRL2015.md)
  — the same discipline scaled to **8 sealed runs** (SRL-2015: 4 hosts × disk/memory, 2,233
  findings, **15-iteration** persistent loops): roster chain recreation, timestamped A2A message
  log, iteration deltas, **cross-host APT correlation** (the spinlock.exe implant traced
  workstation → Domain Controller), inline Thymus trails and a verified-absence GAP register —
  82 claims, all `[host/modality $.jsonpath = value]` cited — with its own
  [2 min 24 s animated walkthrough](https://galvangabriel-web.github.io/agentropix-mcp/docs/12-CASES-REPORTS/srl-2015-report/watch-execution-logs.html) (auto-plays).
- **Persistent-loop trace (iteration-over-iteration, approach changing):**
  [`EXECUTION-LOG.md`](case-activation/runs/jimmy-wilson-poc/EXECUTION-LOG.md) — tool execution log
  with timestamps + durations, the Trinity trace (13 agents → 2 after the Critic marks 11 stable),
  and Blackboard activity. Token usage is an **honest negative** (LLM at the edge, uninstrumented —
  documented, not faked).
- **Live-MCP triage audit (Requirement-8 execution-logs doc):**
  [`rocba/EXECUTION-LOG.md`](case-activation/runs/rocba/EXECUTION-LOG.md) — the ROCBA Hackathon
  2026 Windows-10 insider-IP-theft case (`INC-2026-0613202023`): 31 MCP requests, 2,078 s tool
  runtime, `evidence_register` SHA-256 `f2eb856d` matching ground truth, an `fls` walk of 602,765
  entries, `get_evtx` surfacing ≥5,000 EventID-4625 RDP brute-force hits → the grounded DRAFT
  finding `rocba-rdp-bruteforce-001` (MITRE T1110.003, `indexed:false` = cannot self-approve),
  `bulk_extractor` 5,113,600 features. Backed by the server HTTP audit
  ([`logs/mcp-http-audit.jsonl`](case-activation/runs/rocba/logs)) and the Thymus access log. Keeps
  its **honest negatives** on record (not hidden): a carve driver param-bug (image vs target,
  re-run corrected), the `report_generate` `case_not_found` DRAFT-only gotcha, and a memory-init
  timeout under load. Token usage is uncollected **by design** (client-side).
- **Single-agent / per-tool execution chain:**
  [`WINXP-LAPTOP-2005/`](case-activation/runs/WINXP-LAPTOP-2005/) — a sibling agent-execution-log
  run for the Windows XP laptop (2005) case: a timestamped
  [execution chain](case-activation/runs/WINXP-LAPTOP-2005/WINXP-LAPTOP-2005-execution-chain.md),
  the machine-readable
  [`WINXP-LAPTOP-2005-agent-execution-log.jsonl`](case-activation/runs/WINXP-LAPTOP-2005/WINXP-LAPTOP-2005-agent-execution-log.jsonl)
  + [summary](case-activation/runs/WINXP-LAPTOP-2005/WINXP-LAPTOP-2005.execution-log.summary.md),
  and the extraction tooling that produced them.
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
