# Agentropix-SIFT — Documentation Index

> 🧭 **Judges / evaluators:** start with the [Evaluation Map](EVALUATION-MAP.md) — it routes all
> 8 submission requirements to their evidence in this repository.

**The entry point.** This is the routed master table of contents for the entire
Agentropix-SIFT documentation set. Every chapter is mapped to its primary **audience**
(operator / examiner / developer / auditor) and the **question it answers**, so you can jump
straight to what you need. New readers should follow one of the
[reading paths](#reading-paths-by-audience) below.

Agentropix-SIFT is a local, CLI-driven, bio-agentic DFIR triage engine for the SANS SIFT
Workstation — a Trinity Loop (Architect → 7-agent Swarm → Critic) driving **72 MCP tools**
(**16** of them SIFT forensic wrappers) over one FastMCP server, with a forensic safety spine.
Canonical numbers throughout the docs are governed by [Canonical Facts](docs/08-reference/canonical-facts.md).

**The four audiences** used in the **Audience** column below (and in the reading paths) are:

- **operator** — runs triage day to day (drives the engine, registers evidence, executes cases).
- **examiner** — the human-in-the-loop who reviews, approves, and defends findings before the seal.
- **developer** — extends or maintains the engine (code, architecture, tools, tests).
- **auditor** — independently verifies forensic soundness, chain of custody, and reproducibility.

Each page below lists its primary audience(s) and, in the **What question it answers** column, a
one-line descriptor of exactly what that page resolves — read that column as the page's summary.

Every section also carries a **`README.md`** with a numbered **"Read in this order"** list (intro →
deeper); the same ordering is shown inline under each section heading below. Existing filenames are
unchanged — the reading order is layered on top, non-destructively.

---

## Reading Paths by Audience

- **Operator** (first run, start to finish — **expert _or_ non-technical end-user**): **[User Guide — The Complete Operator Runbook](docs/01-overview/user-guide.md)**
  → [Tool Capability Map](docs/04-mcp-tools/capability-map.md) (pick the right tool by DFIR function)
  → [Per-Case Attack-Chain Hypotheses](docs/06-use-cases/case-hypotheses.md) (which tools to reach for, per case)
  → [Quickstart](docs/01-overview/quickstart.md) (the condensed 3-command path)
  → [CLI Reference](docs/08-reference/cli-reference.md). The single deeply-detailed end-to-end
  runbook: pre-flight → connect/verify MCP → case init/activate → register evidence → the
  investigation tool chain → record findings → approve in the portal → generate/verify the
  sealed report → curate/push IOCs to Wazuh. Written for **two audiences at once** — every action
  carries the **expert CLI/MCP command** and the **plain-language end-user prompt** for the same
  result. Documents **both** execution paths (manual, tool-by-tool · autonomous, headless driver)
  across **both** clients (Claude CLI · Claude Desktop, incl. the 1 MB cap), with the **validated
  2026-05-29 CFReDS run** as a worked example (real commands, real outputs, decision points, and a
  troubleshooting ledger).
- **Operator** (activate a specific case): **[Per-Case Activation Guides](case-activation/INDEX.md)** — a ready-to-run guide for **each `/cases/` image** (13 cases: disk · memory · mixed), instantiating the activation procedure (`case_init → … → report`) with that case's real evidence, plus a numbered **manual and autonomous** prompt sequence to get started. *(Local case inventory + on-disk paths — review before making the repo public.)*
- **Analyst / reviewer** (see real report output): **[Outstanding case reports — per run](case-activation/INDEX.md#recorded-runs)** — each case run carries a `reports/` folder with a **comprehensive multi-audience report** (exec dashboard + risk matrix + IOC catalogue + host/network artefacts + MITRE attack chain + process tree + timeline + coverage attestation) plus a **1-page executive summary**, in **html + pdf**, generated live and grounded in real findings/IOCs/timeline (e.g. `case-activation/runs/challenge-notchitup/reports/comprehensive.pdf`). *(CTF/training case data; reports embed real artifact citations.)*
- **Operator** (runs triage): [What is Agentropix-SIFT?](docs/01-overview/what-is-agentropix.md)
  → [Competitive Positioning](docs/01-overview/competitive-positioning.md)
  → [Quickstart](docs/01-overview/quickstart.md)
  → [Disk Triage use case](docs/06-use-cases/uc-disk-triage.md)
  → [CLI Reference](docs/08-reference/cli-reference.md)
  → [Configuration](docs/07-sdlc-ops/configuration.md).
- **Operator** (connects a remote client to a hosted server): [Connect a Client to a Live Internal MCP Server](docs/09-integrations/client-setup.md)
  → [Deployment](docs/07-sdlc-ops/deployment.md) (the complementary self-host path).
- **Operator** (runs the Wazuh integration): [Push a Finding to Wazuh as an Alert](docs/06-use-cases/uc-wazuh-push.md) (the push mechanics)
  → [Wazuh Portal — Operator's Guide](docs/09-integrations/wazuh-portal.md) (connect the SOC, preview, confirm alerts, read the dashboards)
  → [Configuration](docs/07-sdlc-ops/configuration.md) (the `WAZUH_*` env surface).
- **Examiner** (reviews & approves findings, defends them): [What You Get](docs/01-overview/what-you-get.md)
  → [Anti-Hallucination](docs/05-safety-forensics/anti-hallucination.md)
  → [Provenance & Grounding](docs/05-safety-forensics/provenance-grounding.md)
  → [Approval Portal walkthrough](docs/05-safety-forensics/approval-portal.md) (the browser sign-off form — screenshot + every field)
  → [Human-in-the-Loop](docs/05-safety-forensics/human-in-the-loop.md) (how the gate works underneath)
  → [Approval-Gate use case](docs/06-use-cases/uc-approval-gate.md)
  → [AI Disclosure & Reproducibility](docs/05-safety-forensics/ai-disclosure.md) (what AI is used, what crosses the boundary, how to replay)
  → [Guided Demo Walkthrough](docs/06-use-cases/demo-walkthrough.md) (a run, beat by beat, mapped to the rubric)
  → [Evaluation Scorecard](docs/07-sdlc-ops/evaluation-scorecard.md) (the independent BMAD verdict)
  → [Audit & Courtroom Seal](docs/05-safety-forensics/audit-courtroom.md).
- **Developer** (extends the engine): [Implementation](docs/07-sdlc-ops/implementation.md)
  → [The Trinity Loop](docs/02-architecture/trinity-loop.md)
  → [The Swarm Agents & Blackboard](docs/02-architecture/swarm-agents.md)
  → [The FastMCP Server](docs/02-architecture/mcp-server.md)
  → [Data Models](docs/03-data/data-models.md)
  → [MCP Tool Reference](docs/04-mcp-tools/tool-reference.md)
  → [Testing](docs/07-sdlc-ops/testing.md)
  → [ADR Index](docs/08-reference/adr-index.md) (the routed catalogue)
  → [Architecture Decision Records — Section 11](docs/11-ADR/README.md) (the full ADR corpus, the decision contract)
  → [Design Decisions — Rationale & History](docs/08-reference/design-decisions.md)
  → [Maintenance — The Dual-Repo Sync](docs/07-sdlc-ops/maintenance-dual-repo.md).
- **Auditor** (verifies forensic soundness & chain of custody): [Security Model](docs/07-sdlc-ops/security-model.md)
  → [Audit & Courtroom Seal](docs/05-safety-forensics/audit-courtroom.md)
  → [Provenance & Grounding](docs/05-safety-forensics/provenance-grounding.md)
  → [Persisted Artifacts](docs/03-data/persisted-artifacts.md)
  → [Recovery & Resilience](docs/07-sdlc-ops/recovery-resilience.md)
  → [Evaluation Corpus & Recall Methodology](docs/07-sdlc-ops/dataset-recall.md)
  → [Evaluation Scorecard](docs/07-sdlc-ops/evaluation-scorecard.md)
  → [Architecture Decision Records — Section 11](docs/11-ADR/README.md) (the immutable decision trail, incl. the forensic/safety ADRs 008·011·016·018–022)
  → [Canonical Facts](docs/08-reference/canonical-facts.md).

---

## 0. Landing

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| README — Agentropix-SIFT | all | What is this, at a glance, and where do I go next? | [README.md](README.md) |
| Documentation Index | all | Which document answers my question, for my role? | [INDEX.md](INDEX.md) |

## 1. Overview

> **Read in this order** ([section README](docs/01-overview/README.md)): 1. [what-is-agentropix](docs/01-overview/what-is-agentropix.md) — what/why/who · 2. [what-you-get](docs/01-overview/what-you-get.md) — capability matrix · 3. [quickstart](docs/01-overview/quickstart.md) — install + first run · 4. [user-guide](docs/01-overview/user-guide.md) — the gold-standard end-to-end runbook · 5. [competitive-positioning](docs/01-overview/competitive-positioning.md) — vs alternatives · 6. [lessons-learned](docs/01-overview/lessons-learned.md) — what we learned · 7. [roadmap](docs/01-overview/roadmap.md) — next steps.

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| **User Guide — The Complete Operator Runbook** | operator (expert + non-technical end-user) | **How do I run one complete case end to end, in full operational depth** — pre-flight, connect/verify the MCP, init/activate the case, register evidence, drive the investigation tool chain (**manual tool-by-tool _or_ autonomous headless driver**, on **Claude CLI _or_ Desktop**), record findings, approve in the portal, seal the report, and (optionally) push IOCs to Wazuh? Written for **two audiences at once** — every action carries the **expert CLI/MCP command** *and* the **plain-language end-user prompt** for the same result — with the validated 2026-05-29 CFReDS run as a worked example, a troubleshooting ledger, and a closing **Prompt Playbook appendix** (the numbered, run-it-top-to-bottom manual and autonomous prompt sequences, each step carrying an `Expect:` check). | [docs/01-overview/user-guide.md](docs/01-overview/user-guide.md) |
| What is Agentropix-SIFT? | operator, examiner | What does the tool do, why, who is it for, and how does it compare to manual DFIR? | [docs/01-overview/what-is-agentropix.md](docs/01-overview/what-is-agentropix.md) |
| What You Get | operator, examiner | What are the concrete capabilities and the feature/capability matrix? | [docs/01-overview/what-you-get.md](docs/01-overview/what-you-get.md) |
| Quickstart | operator (expert + end-user) | How do I install, pre-flight the toolchain, and run my first triage? The condensed path, dual-audience — each step carries the **expert CLI/MCP command** and the **plain-language end-user prompt** for the same result. | [docs/01-overview/quickstart.md](docs/01-overview/quickstart.md) |
| Competitive Positioning | operator, examiner | How is this different from Velociraptor + an LLM, and where does it honestly lose? | [docs/01-overview/competitive-positioning.md](docs/01-overview/competitive-positioning.md) |
|

## 2. Architecture

> **Read in this order** ([section README](docs/02-architecture/README.md)): 1. [main-architectural-agentropix-design](docs/02-architecture/main-architectural-agentropix-design.md) — the one-page validated diagram (pattern + guardrails) · 2. [system-diagram](docs/02-architecture/system-diagram.md) — diagram index + rubric/trust-boundary verification · 3. [system-context-c4](docs/02-architecture/system-context-c4.md) — containers/boundaries · 4. [architecture-layers](docs/02-architecture/architecture-layers.md) — determinism map + trust-boundary contract · 5. [component-architecture](docs/02-architecture/component-architecture.md) — layer map · 6. [trinity-loop](docs/02-architecture/trinity-loop.md) — the control loop · 7. [swarm-agents](docs/02-architecture/swarm-agents.md) — specialists + Blackboard · 8. [mcp-server](docs/02-architecture/mcp-server.md) — FastMCP + Thymus · 9. [sequence-diagrams](docs/02-architecture/sequence-diagrams.md) — operations step by step · 10. [ez-tools-integration](docs/02-architecture/ez-tools-integration.md) — EZ Tools wrapping · 11. [module-map](docs/02-architecture/module-map.md) *(shared reference)* · 12. 🗺️ [PROJECT-ROADMAP-2026-06-11](docs/02-architecture/PROJECT-ROADMAP-2026-06-11.md) *(strategic — where it's all going)* · 13. 🔒 [SECURITY-INVARIANT-AUDIT-2026-06-11](docs/02-architecture/SECURITY-INVARIANT-AUDIT-2026-06-11.md) *(audit — invariants traced to source)* · 14. 🎛️ [AGENTROPIX-TUNABLE-FEATURES-CATALOG](docs/02-architecture/AGENTROPIX-TUNABLE-FEATURES-CATALOG.md) *(reference — all 252 tunables)*.

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| Architecture Diagram (validated, PNG/PDF) | developer, examiner, reviewer | What are the moving parts, which architectural pattern is this (Custom MCP Server), and which guardrails are architectural vs prompt-based? | [docs/02-architecture/main-architectural-agentropix-design.md](docs/02-architecture/main-architectural-agentropix-design.md) |
| System Diagram (index + rubric verification) | developer, examiner, reviewer | Where does every rendered system diagram live, are all five rubric elements (agents · SIFT tools · MCP server · evidence · output pipeline) covered, and where is the trust boundary marked? | [docs/02-architecture/system-diagram.md](docs/02-architecture/system-diagram.md) |
| Architecture Layers & Determinism Map | developer, examiner, auditor | Where does stochasticity live (Layer 1 only), where is determinism enforced (Layers 2–4), and what does the L1↔L3 trust-boundary contract prove in court? | [docs/02-architecture/architecture-layers.md](docs/02-architecture/architecture-layers.md) |
| System Context & Containers | developer, examiner | How does the engine sit on the SIFT host and what are its containers/boundaries? | [docs/02-architecture/system-context-c4.md](docs/02-architecture/system-context-c4.md) |
| Component Architecture & Layer Map | developer | What are the internal components and how are the code layers organized? | [docs/02-architecture/component-architecture.md](docs/02-architecture/component-architecture.md) |
| The Trinity Loop | developer, examiner | How do Architect, Swarm, and Critic interact, and how does the deterministic halt work? | [docs/02-architecture/trinity-loop.md](docs/02-architecture/trinity-loop.md) |
| The Swarm Agents & Blackboard | developer | What are the 7 core specialists (+ ATT&CK detectors), how do they correlate via the quorum Blackboard, and how do they self-correct across runs (Hippocampus, Ralph hooks, the chromosome persona)? | [docs/02-architecture/swarm-agents.md](docs/02-architecture/swarm-agents.md) |
| The FastMCP Server | developer | How is the single FastMCP server built, what transports does it use, and where is the Thymus boundary? | [docs/02-architecture/mcp-server.md](docs/02-architecture/mcp-server.md) |
| Sequence Diagrams | developer, examiner | What does each key operation look like step-by-step (full run, single tool call, seal, halt, approval, Wazuh)? | [docs/02-architecture/sequence-diagrams.md](docs/02-architecture/sequence-diagrams.md) |
| EZ Tools / ZimmermanTools Integration | developer | How are Eric Zimmerman's EZ Tools wrapped as governed MCP tools — which invoke the genuine `.NET` binaries vs the three Linux substitutes (Amcache/ShimCache/SRUM)? | [docs/02-architecture/ez-tools-integration.md](docs/02-architecture/ez-tools-integration.md) |
| Module Map | developer | Where does each package and component live in `src/`? (machine-extracted reference) | [docs/02-architecture/module-map.md](docs/02-architecture/module-map.md) |
| 🗺️ Strategic Project Roadmap (2026-06-11) | evaluator, stakeholder, developer | Where is the project now and what is the path to GA — development Gantt & critical path, lifecycle state machine, phase milestones, technical specs, risk mitigation? | [docs/02-architecture/PROJECT-ROADMAP-2026-06-11.md](docs/02-architecture/PROJECT-ROADMAP-2026-06-11.md) |
| 🔒 Security Invariant Audit (2026-06-11) | evaluator, examiner, security engineer | Are the six safety/anti-hallucination guarantees actually enforced in the source — where, at which file:line, and what is the one honest gap? | [docs/02-architecture/SECURITY-INVARIANT-AUDIT-2026-06-11.md](docs/02-architecture/SECURITY-INVARIANT-AUDIT-2026-06-11.md) |
| 🎛️ Tunable Features Catalog | operator, developer | What are all 252 documented tunables (toggles, performance knobs, detection thresholds, security gates, tool paths) and what does each do? | [docs/02-architecture/AGENTROPIX-TUNABLE-FEATURES-CATALOG.md](docs/02-architecture/AGENTROPIX-TUNABLE-FEATURES-CATALOG.md) |

## 3. Data

> **Read in this order** ([section README](docs/03-data/README.md)): 1. [data-dictionary](docs/03-data/data-dictionary.md) — every field · 2. [data-models](docs/03-data/data-models.md) — class diagram · 3. [schema-er](docs/03-data/schema-er.md) — ER diagram · 4. [persisted-artifacts](docs/03-data/persisted-artifacts.md) — what lands on disk · 5. [schema-dump](docs/03-data/schema-dump.md) *(shared reference)*.

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| Data Dictionary | developer, auditor | What is every Pydantic field — its name, type, semantics, and constraints? | [03-data/data-dictionary.md](docs/03-data/data-dictionary.md) |
| Data Models | developer | How do TriageReport, Finding, Agent, and the envelope models relate (class diagram)? | [03-data/data-models.md](docs/03-data/data-models.md) |
| Schema ER Model | developer, auditor | How do the persisted artifacts relate as entities (ER diagram)? | [03-data/schema-er.md](docs/03-data/schema-er.md) |
| Persisted Artifacts | auditor, developer | What gets written to disk — JSON report, JSONL audit log, session keys, Hippocampus — and where? | [03-data/persisted-artifacts.md](docs/03-data/persisted-artifacts.md) |
| Recall Ground-Truth Fixtures | examiner, auditor | What labelled expected-findings are the recall numbers scored against? 4-of-29 committed fixtures + a sealed-run recall summary. | [docs/03-data/recall-ground-truth/README.md](docs/03-data/recall-ground-truth/README.md) |
| Evidence Datasets | examiner, auditor, judge | What is the evidence corpus — per-case provenance (SANS SRL, NIST CFReDS, MemLabs, DFRWS), evidence types, the network-capture story, and which claims the inventory does/does not substantiate? | [docs/03-data/evidence-datasets.md](docs/03-data/evidence-datasets.md) |
| **Network-Capture Verification (proof package)** | examiner, auditor, judge | How was the network-capture inventory **proven** — magic-byte sweep, raw `file(1)`/`xxd`/SHA-256 transcript for all 11 pcaps, claim reconciliation, and the self-caught extension-search error post-mortem? | [docs/03-data/network-evidence-verification/](docs/03-data/network-evidence-verification/README.md) |
| Schema Dump | developer, auditor | The machine-extracted Pydantic model schema (field names, types, constraints) behind the data chapter. | [03-data/schema-dump.md](docs/03-data/schema-dump.md) |

## 4. MCP Tools

> **Read in this order** ([section README](docs/04-mcp-tools/README.md)): 1. [capability-map](docs/04-mcp-tools/capability-map.md) — pick the tool by function · 2. [tool-reference](docs/04-mcp-tools/tool-reference.md) — all 71 in detail · 3. [response-envelope](docs/04-mcp-tools/response-envelope.md) — what a call returns · 4. [tool-by-agent](docs/04-mcp-tools/tool-by-agent.md) — which agent owns which tool · 5. [tool-list](docs/04-mcp-tools/tool-list.md) *(shared reference)*.

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| MCP Tool Reference | developer, operator | What are all 72 MCP tools and the 16 forensic wrappers, in detail? | [04-mcp-tools/tool-reference.md](docs/04-mcp-tools/tool-reference.md) |
| Tool Capability Map (by DFIR function) | operator, examiner, developer | Which tool do I reach for to *do* a thing — the 72-tool surface grouped by DFIR function, with the canonical happy-path ordering? | [04-mcp-tools/capability-map.md](docs/04-mcp-tools/capability-map.md) |
| Tool Response Envelope | developer, auditor | What does a tool call actually return, including the provenance fingerprint and error shape? | [04-mcp-tools/response-envelope.md](docs/04-mcp-tools/response-envelope.md) |
| Tools by Agent | developer | Which Swarm agent invokes which tools? | [04-mcp-tools/tool-by-agent.md](docs/04-mcp-tools/tool-by-agent.md) |
| Tool List | developer, operator | The machine-extracted inventory of all 72 MCP tools, with the 16 SIFT forensic wrappers flagged. | [04-mcp-tools/tool-list.md](docs/04-mcp-tools/tool-list.md) |

## 5. Safety & Forensics

> **Read in this order** ([section README](docs/05-safety-forensics/README.md)): 1. [anti-hallucination](docs/05-safety-forensics/anti-hallucination.md) — fabrication prevented · 2. [provenance-grounding](docs/05-safety-forensics/provenance-grounding.md) — grounding tiers · 3. [human-in-the-loop](docs/05-safety-forensics/human-in-the-loop.md) — the gate mechanics · 4. [approval-portal](docs/05-safety-forensics/approval-portal.md) — the sign-off form · 5. [audit-courtroom](docs/05-safety-forensics/audit-courtroom.md) — HMAC seal · 6. [ai-disclosure](docs/05-safety-forensics/ai-disclosure.md) — AI boundary + replay.

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| Anti-Hallucination | examiner, auditor | How are fabricated findings prevented — determinism, evidence sovereignty, no LLM self-rating? | [docs/05-safety-forensics/anti-hallucination.md](docs/05-safety-forensics/anti-hallucination.md) |
| Provenance & Grounding | examiner, auditor | How are findings grounded in evidence, and what are the provenance tiers / grounding levels? | [docs/05-safety-forensics/provenance-grounding.md](docs/05-safety-forensics/provenance-grounding.md) |
| Audit & Courtroom Seal | auditor, examiner | How is the audit log HMAC-SHA256 sealed and the chain of custody validated? | [docs/05-safety-forensics/audit-courtroom.md](docs/05-safety-forensics/audit-courtroom.md) |
| **Approval Portal walkthrough** | operator, examiner | **How do I use the browser sign-off form** (`https://<siftworkstation-host>:8443/`) — screenshot, every field, how to submit, how to retract/void, and the error matrix? | [docs/05-safety-forensics/approval-portal.md](docs/05-safety-forensics/approval-portal.md) |
| AI Disclosure & Reproducibility | examiner, auditor | What AI models are used (and what is pinned), what data crosses the Anthropic boundary, and how is a run replayed deterministically? | [docs/05-safety-forensics/ai-disclosure.md](docs/05-safety-forensics/ai-disclosure.md) |
| Human-in-the-Loop | examiner, auditor | How does the approval sidecar gate hold findings in DRAFT until an examiner approves — the invariant, state machine, HMAC challenge-response, and hash chain? | [docs/05-safety-forensics/human-in-the-loop.md](docs/05-safety-forensics/human-in-the-loop.md) |

## 6. Use Cases

> **Read in this order** ([section README](docs/06-use-cases/README.md)): 1. [uc-disk-triage](docs/06-use-cases/uc-disk-triage.md) — E01 disk · 2. [uc-memory-triage](docs/06-use-cases/uc-memory-triage.md) — Volatility memory · 3. [uc-approval-gate](docs/06-use-cases/uc-approval-gate.md) — approve before seal · 4. [uc-wazuh-push](docs/06-use-cases/uc-wazuh-push.md) — finding → alert · 5. [demo-walkthrough](docs/06-use-cases/demo-walkthrough.md) — judge-facing run · 6. [case-hypotheses](docs/06-use-cases/case-hypotheses.md) — per-case bias-checks.

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| Triage an E01 Disk Image End to End | operator (expert + end-user) | How do I run a full disk-image triage from start to finish? Dual-audience — every step pairs the **expert CLI/MCP command** with the **plain-language end-user prompt**, laid out Execution → Output. | [docs/06-use-cases/uc-disk-triage.md](docs/06-use-cases/uc-disk-triage.md) |
| Memory Triage with Volatility | operator (expert + end-user) | How do I triage a memory dump with the Volatility-backed agents? Dual-audience — each tool step carries both the **expert command** and the **end-user prompt** for the same result, Execution → Output. | [docs/06-use-cases/uc-memory-triage.md](docs/06-use-cases/uc-memory-triage.md) |
| Examiner Reviews & Approves Before the Seal | examiner (expert + end-user) | How do I review findings and approve them before anything is sealed? Dual-audience — the review/approve actions are shown both as the **expert CLI/MCP command** and as the **plain-language end-user prompt**. | [docs/06-use-cases/uc-approval-gate.md](docs/06-use-cases/uc-approval-gate.md) |
| Push a Finding to Wazuh as an Alert | operator, auditor (expert + end-user) | How do I escalate an APPROVED finding to Wazuh (experimental integration)? Dual-audience — each push step pairs the **expert MCP call** with the **end-user prompt** (which defaults to a dry-run preview). | [docs/06-use-cases/uc-wazuh-push.md](docs/06-use-cases/uc-wazuh-push.md) |
| Guided Demo Walkthrough (Judge-Facing) | examiner, all (expert + end-user) | What does a single end-to-end run look like, beat by beat, mapped to the Devpost rubric with verifiable runtime evidence? Dual-audience — each beat carries both the **expert command** and the **end-user prompt**. | [docs/06-use-cases/demo-walkthrough.md](docs/06-use-cases/demo-walkthrough.md) |
| 3-Minute Hackathon Demo Script (BMAD-M8) | examiner, judge | What is the exact 5-beat, ~3-minute judging-panel demo script — the three cast variants (30-second teaser · real-data walkthrough · 9-beat SHIELDBASE narration), each with its source command, what it shows, and when to play it? | [docs/06-use-cases/demo-script.md](docs/06-use-cases/demo-script.md) |
| Per-Case Attack-Chain Hypotheses | operator, examiner | For each in-scope test case, which attack chain is likely and which tools confirm/refute each link (bias-checks, not findings)? | [docs/06-use-cases/case-hypotheses.md](docs/06-use-cases/case-hypotheses.md) |
| Reproduce the Datasets | judge, developer | Where do I download the evidence to re-run it myself? Real upstream URLs + provenance for the public datasets; honest note on the non-redistributable cases. | [docs/06-use-cases/reproduce-datasets.md](docs/06-use-cases/reproduce-datasets.md) |

## 7. SDLC & Operations

> **Read in this order** ([section README](docs/07-sdlc-ops/README.md)): 1. [implementation](docs/07-sdlc-ops/implementation.md) — code org/build · 2. [testing](docs/07-sdlc-ops/testing.md) — topology + recall · 3. [security-model](docs/07-sdlc-ops/security-model.md) — threat model · 4. [recovery-resilience](docs/07-sdlc-ops/recovery-resilience.md) — failure modes · 5. [configuration](docs/07-sdlc-ops/configuration.md) — env surface · 6. [deployment](docs/07-sdlc-ops/deployment.md) — install + tailnet · 7. [dataset-recall](docs/07-sdlc-ops/dataset-recall.md) — corpus/methodology · 8. [evaluation-scorecard](docs/07-sdlc-ops/evaluation-scorecard.md) — BMAD verdict · 9. [maintenance-dual-repo](docs/07-sdlc-ops/maintenance-dual-repo.md) — `sift` → `mcp` sync · 10. [env-vars](docs/07-sdlc-ops/env-vars.md) *(shared reference)*.

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| Implementation — Code Organization & Build | developer | How is the codebase organized and built (module map)? | [docs/07-sdlc-ops/implementation.md](docs/07-sdlc-ops/implementation.md) |
| Testing — Topology, Gates & Recall | developer, auditor | What is the test topology, the gates, and the ground-truth recall (4464 tests; 72/72 disk; 108/118 memory)? | [docs/07-sdlc-ops/testing.md](docs/07-sdlc-ops/testing.md) |
| Recovery & Resilience | auditor, developer | What are the failure modes and the chaos/recovery classes? | [docs/07-sdlc-ops/recovery-resilience.md](docs/07-sdlc-ops/recovery-resilience.md) |
| Security Model | auditor | What is the threat model — Thymus, denylists, redaction, read-only boundary? | [docs/07-sdlc-ops/security-model.md](docs/07-sdlc-ops/security-model.md) |
| Configuration | operator, developer (expert + end-user) | What `AGENTROPIX_*` env vars exist and what do they tune? Dual-audience — common settings show both the **expert command** to set them and the **end-user prompt** that asks the session to apply/verify the same. | [docs/07-sdlc-ops/configuration.md](docs/07-sdlc-ops/configuration.md) |
| Deployment | operator (expert + end-user) | How do I install on SIFT, expose over a tailnet, and find the runbooks? Dual-audience — install/expose steps pair the **expert CLI command** with the **plain-language end-user prompt**, Execution → Output. | [docs/07-sdlc-ops/deployment.md](docs/07-sdlc-ops/deployment.md) |
| Evaluation Scorecard — BMAD & Rubric | examiner, auditor | What did the independent 10-persona BMAD evaluation and the Devpost rubric self-grade conclude? | [docs/07-sdlc-ops/evaluation-scorecard.md](docs/07-sdlc-ops/evaluation-scorecard.md) |
| Evaluation Corpus & Recall Methodology | examiner, auditor | What evidence corpus are the recall numbers measured against, and how is ground truth defined? | [docs/07-sdlc-ops/dataset-recall.md](docs/07-sdlc-ops/dataset-recall.md) |
| Full-Run Execution Evidence (sanitized sealed reports + transcripts) | judge, auditor | Where is the raw machine-readable proof — the 212-call/275-finding sealed DC run (`report-dc.json`, with `args_hash`/`exit_code`/`thymus_audit` and a worked finding→tool-call trace), the honest `budget_exhausted` sample run, the unedited rate-limit failure cluster, and the seal-verification transcript? | [docs/07-sdlc-ops/assets/full-run-evidence/README.md](docs/07-sdlc-ops/assets/full-run-evidence/README.md) |
| Observability & Integrity Notes (+ sealed-run sample) | judge, auditor | Honest limits: post-run re-hash (not implemented) and token-usage metrics (uncollected by design), plus a committed real sealed-run artifact (245 tool_calls, HMAC seals). | [docs/07-sdlc-ops/observability-and-integrity-notes.md](docs/07-sdlc-ops/observability-and-integrity-notes.md) |
| Maintenance — The Dual-Repo Sync | developer (expert + end-user) | Why are there two repos/package names, and how does the one-way `sift` → `mcp` sync stay faithful? Dual-audience for the sync/verify steps — the **expert command** alongside the **plain-language end-user prompt**, Execution → Output. | [docs/07-sdlc-ops/maintenance-dual-repo.md](docs/07-sdlc-ops/maintenance-dual-repo.md) |
| Env Vars | operator, developer | The full machine-extracted `AGENTROPIX_*` environment-variable surface and what each tunes. | [docs/07-sdlc-ops/env-vars.md](docs/07-sdlc-ops/env-vars.md) |
| Accuracy Report — Curve-Fit Disclosure, FPs & Misses | judge, auditor | What do the recall numbers honestly mean — the verbatim "partially curve-fit" admission, 108/118 (91.5%) with T1003.002=30/40, the April 1/7→7/7 failure history, W-numbered false positives/hallucinations the project caught in itself, and (§6) how the architecture prevents the original evidence from being modified? | [docs/07-sdlc-ops/ACCURACY-REPORT.md](docs/07-sdlc-ops/ACCURACY-REPORT.md) |
| Evidence Integrity, Visualized — Architectural, Not Prompt-Based | judge, auditor | The graphical proof behind ACCURACY-REPORT §6 — colour-coded diagrams (layer interconnection, the Thymus allow/deny flow, architectural-vs-prompt-based guardrails, what happens if the model ignores the restriction) + real-data charts, every figure grounded in code (file:line) and real runs. | [docs/07-sdlc-ops/evidence-integrity-visual.md](docs/07-sdlc-ops/evidence-integrity-visual.md) |
| Cross-Modal Recall Summary (2026-05-06 snapshot) | judge, examiner | The mirrored primary-source snapshot behind dataset-recall §4: 156/156 per-IOC measurements, per-host coherence ranking, and the base-rd-01 0% coherence-by-design finding. | [docs/07-sdlc-ops/cross-modal-recall-summary.md](docs/07-sdlc-ops/cross-modal-recall-summary.md) |

## 8. Reference

> **Read in this order** ([section README](docs/08-reference/README.md)): 1. [cli-reference](docs/08-reference/cli-reference.md) — commands + flags · 2. [glossary](docs/08-reference/glossary.md) — terms/personas/weakness IDs · 3. [adr-index](docs/08-reference/adr-index.md) — decisions made · 4. [design-decisions](docs/08-reference/design-decisions.md) — rationale behind them · 5. [canonical-facts](docs/08-reference/canonical-facts.md) *(shared reference, governing numeric authority)*.

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| CLI Reference | operator (expert + end-user) | What are all the `agentropix-sift` commands and flags? Dual-audience — the headline commands also show the **plain-language end-user prompt** that drives the same MCP tool, Execution → Output. | [08-reference/cli-reference.md](docs/08-reference/cli-reference.md) |
| Glossary | all | What does each term, persona, and weakness ID mean? | [08-reference/glossary.md](docs/08-reference/glossary.md) |
| ADR Index | developer, auditor | What architecture decisions were made and why (routed list of the ADRs)? | [08-reference/adr-index.md](docs/08-reference/adr-index.md) |
| Design Decisions — Rationale & History | developer, auditor | What recurring design principles, hard trade-offs, and discarded approaches sit behind the ADRs? | [08-reference/design-decisions.md](docs/08-reference/design-decisions.md) |
| **Canonical Facts** | all | The **governing numeric authority** — tool count, tests, recall — that wins over any prose anywhere in the docs. | [08-reference/canonical-facts.md](docs/08-reference/canonical-facts.md) |

## 9. Integrations

> **Read in this order** ([section README](docs/09-integrations/README.md)): 1. [client-setup](docs/09-integrations/client-setup.md) — connect a remote client over the tailnet · 2. [wazuh-portal](docs/09-integrations/wazuh-portal.md) — drive the Wazuh SOC integration day to day.

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| Wazuh Portal — Operator's Guide | operator | How do I drive the Wazuh integration day-to-day — connect the SOC, preview a push, confirm alerts landed, and read the dashboards — without the MCP-tool internals? | [docs/09-integrations/wazuh-portal.md](docs/09-integrations/wazuh-portal.md) |
| Connect a Client to a Live Internal MCP Server | operator, developer | How do I point Claude Code CLI or Claude Desktop at an already-running MCP server over a Tailscale tailnet? | [docs/09-integrations/client-setup.md](docs/09-integrations/client-setup.md) |

## 10. Agents

> **Read in this order:** Agentic Architecture → Delegation Model → Agents List → FastMCP Execution.
> Start here whenever "agent" is ambiguous — this section disambiguates the **runtime DFIR swarm**
> from the **build-time BMAD personas**, and ties Trinity ↔ Swarm ↔ MCP into one model.

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| The Agentic Architecture | developer, examiner | What does "agent" mean here (runtime swarm vs BMAD persona vs the stale aspirational runtime), and how do Trinity, the Swarm, and the MCP boundary fit into one model? | [docs/10-agents/agentic-architecture.md](docs/10-agents/agentic-architecture.md) |
| The Delegation Model | developer, auditor | Who are the build-time BMAD review personas (Winston/Murat/…) and the Α–Ζ delivery crews, and what sub-agent delegation protocol produced the codebase? | [docs/10-agents/delegation-model.md](docs/10-agents/delegation-model.md) |
| Agents List | developer | The canonical machine-extracted table of the runtime swarm — the 7 core specialists plus the ATT&CK detectors, each agent's tools and findings. | [docs/10-agents/agents-list.md](docs/10-agents/agents-list.md) |
| FastMCP Execution | developer, examiner | What happens, station by station, when an agent calls a tool — the 11-station traversal, the stdio↔HTTP transport contrast, the three architectural surprises, and the open Ralph PreToolUse seam (W-081)? | [docs/10-agents/fastmcp-execution.md](docs/10-agents/fastmcp-execution.md) |

## 11. Architecture Decision Records (ADRs)

> **Read in this order** ([section README](docs/11-ADR/README.md)): start with the **strategic
> foundations (001–008)** in order — 1. [ADR-001 SDK Selection](docs/11-ADR/ADR-001-sdk-selection.md) ·
> 2. [ADR-002 Execution Engine](docs/11-ADR/ADR-002-execution-engine.md) ·
> 3. [ADR-003 State Persistence](docs/11-ADR/ADR-003-state-persistence.md) ·
> 4. [ADR-004 Identity System](docs/11-ADR/ADR-004-identity-system.md) ·
> 5. [ADR-005 Message Bus](docs/11-ADR/ADR-005-message-bus.md) ·
> 6. [ADR-006 Memory System](docs/11-ADR/ADR-006-memory-system.md) ·
> 7. [ADR-007 Deployment Model](docs/11-ADR/ADR-007-deployment-model.md) ·
> 8. [ADR-008 Safety Architecture](docs/11-ADR/ADR-008-safety-architecture.md) — then the
> **capability & forensic ADRs (009–024)** and the **milestone / defer ADRs** (M6.3, W051/W052/W054).
> The [ADR-TEMPLATE](docs/11-ADR/ADR-TEMPLATE.md) is the format every new ADR follows. **Read the
> status column literally** — *Proposed* ⇒ NOT shipped (ADR-009, ADR-024 header); *Deferred* ⇒
> documented, deliberately not implemented (ADR-021, the W-defers).

This section mirrors the **canonical ADRs from the oracle** (the upstream source repository's `docs/adr/`):
the **immutable decision contract** behind every architectural choice. The
[ADR Index](docs/08-reference/adr-index.md) in Section 8 is the *routed catalogue* (one-line
summaries + live status, with anchors); Section 11 carries the **full text of each record**. The
oracle wins any conflict.

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| **ADR corpus — README & status table** | developer, auditor | What architectural decisions exist, what is their **live status** (Implemented / Proposed-NOT-shipped / Deferred), and in what order should I read them? | [docs/11-ADR/README.md](docs/11-ADR/README.md) |
| Strategic ADRs 001–008 | developer, auditor | What are the eight foundational decisions (SDK · execution engine · state · identity · message bus · memory · deployment · the bio-agentic safety spine)? | [docs/11-ADR/README.md](docs/11-ADR/README.md#strategic-adrs-001008--the-eight-foundational-decisions) |
| Capability & forensic ADRs 009–024 | developer, auditor, examiner | How were the forensic/safety capabilities decided — evidence gates, EVTX/extract-files wrappers, the Courtroom audit + HMAC seal, tailnet exposure, Wazuh IOC push, the AR confirmation gate, credential lifecycle, the multi-tier report engine? | [docs/11-ADR/README.md](docs/11-ADR/README.md#capability--forensic-adrs-009024) |
| Milestone & defer ADRs | developer, auditor | Which decisions are milestone-scoped or deliberately deferred (Plaso event-window, the live-recall defers W051/W052/W054, the M6.3 residual gap)? | [docs/11-ADR/README.md](docs/11-ADR/README.md#milestone--defer-adrs-non-numbered) |
| ADR Template | developer | What is the standard MADR-style format a new ADR must follow? | [docs/11-ADR/ADR-TEMPLATE.md](docs/11-ADR/ADR-TEMPLATE.md) |

---

## 12. Cases Reports

Sealed DFIR case reports — the investigative narratives behind the runs ([section README](docs/12-CASES-REPORTS/README.md)): [SRL-2018 forensic report](docs/12-CASES-REPORTS/srl-2018-report/SRL-2018-FORENSIC-REPORT.md) (exec summary · ATT&CK lifecycle · timeline · IOCs · 10 sealed findings, with [technical appendix](docs/12-CASES-REPORTS/srl-2018-report/TECHNICAL-APPENDIX.md) and [Wazuh IOC gallery](docs/12-CASES-REPORTS/srl-2018-report/WAZUH-IOC-GALLERY.md)) · [SRL-2015 report](docs/12-CASES-REPORTS/srl-2015-report/README.md) · [Vanko report](docs/12-CASES-REPORTS/vanko-report/README.md) · [SRL-2018 artifact inventory](docs/12-CASES-REPORTS/srl-2018-artifact-inventory.md) (9,578 findings across 29 hosts — IPs, hashes, YARA hits, technique matrix).

---

## Documentation QA — issues log (maintainers)

The portal's documentation-QA logs (render audits, case-guide sweeps) live under
[`docs/issues/`](docs/issues/). They are maintainer-facing working notes, not reader chapters; the
accompanying screenshots (`docs/issues/*.png`) are gitignored (local-only). They are listed here for
traceability of the render/accuracy validation behind the published pages.

| Log | What it holds | Link |
|-----|---------------|------|
| Diagram render audit | The Mermaid/diagram GitLab-render audit (every diagram-bearing page, raw-vs-rendered verdicts). | [docs/issues/DIAGRAM-AUDIT.md](docs/issues/DIAGRAM-AUDIT.md) |
| Case-guide audit | The per-case activation-guide accuracy sweep (recurring fixes + the full pass). | [docs/issues/CASE-GUIDE-AUDIT.md](docs/issues/CASE-GUIDE-AUDIT.md) |
| Video playback troubleshooting | Why GitHub shows no in-tab player for repo-committed MP4s (Playwright + ffprobe diagnosis) and the GitHub Pages fix. | [docs/issues/VIDEO-PLAYBACK-TROUBLESHOOTING.md](docs/issues/VIDEO-PLAYBACK-TROUBLESHOOTING.md) |

---

## Shared Reference Artifacts

These are the machine-extracted, low-level reference tables (facts, tool inventory, schema, module
map, env surface, agent roster) pulled directly from the oracle source repo, from which the prose
chapters above are derived. **They were formerly grouped under `.crew/`; they now live inside their
matching docs categories** (listed below with their new homes). Read them when you need the raw
substrate behind a chapter. [Canonical Facts](docs/08-reference/canonical-facts.md) is the governing
authority for every numeric claim — it wins over any prose anywhere in the docs.

| Artifact | What it holds | New home |
|----------|---------------|----------|
| Canonical Facts | The locked numeric table (tool count, tests, recall) — wins over prose | [docs/08-reference/canonical-facts.md](docs/08-reference/canonical-facts.md) |
| Tool List | Inventory of all 72 MCP tools, with the 16 SIFT forensic wrappers flagged | [docs/04-mcp-tools/tool-list.md](docs/04-mcp-tools/tool-list.md) |
| Schema Dump | The extracted Pydantic model schema (field names, types, constraints) behind the data chapter | [docs/03-data/schema-dump.md](docs/03-data/schema-dump.md) |
| Module Map | The code module map (where each package and component lives in `src/`) | [docs/02-architecture/module-map.md](docs/02-architecture/module-map.md) |
| Env Vars | The full `AGENTROPIX_*` environment-variable surface and what each tunes | [docs/07-sdlc-ops/env-vars.md](docs/07-sdlc-ops/env-vars.md) |
| Agents List | The Swarm agent inventory — the 7 core specialists plus the ATT&CK detectors | [docs/10-agents/agents-list.md](docs/10-agents/agents-list.md) |

### Audit Reports (repo-wide, auto-generated)

Two repo-grounded audit artifacts — every figure cites its in-repo source; unmeasured items are
marked as such (no fabrication). Governed, like all docs, by [Canonical Facts](docs/08-reference/canonical-facts.md).

| Report | What it answers | Audience | Location |
|--------|-----------------|----------|----------|
| Evidence Dataset Documentation | What evidence datasets exist — provenance, SHA-256 integrity, schemas, and the acquire→…→SIEM ingestion pipeline | auditor / examiner | [EVIDENCE_DATASET_DOCS.md](EVIDENCE_DATASET_DOCS.md) |
| System Accuracy & Validation Report | How accurate the engine is — component benchmark matrix, recall (72/72 disk · 108/118 memory), and algorithmic-drift findings with file:line refs | auditor / developer | [ACCURACY_REPORT.md](ACCURACY_REPORT.md) |
