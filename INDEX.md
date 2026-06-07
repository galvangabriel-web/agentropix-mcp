# Agentropix-SIFT — Documentation Index

**The entry point.** This is the routed master table of contents for the entire
Agentropix-SIFT documentation set. Every chapter is mapped to its primary **audience**
(operator / examiner / developer / auditor) and the **question it answers**, so you can jump
straight to what you need. New readers should follow one of the
[reading paths](#reading-paths-by-audience) below.

Agentropix-SIFT is a local, CLI-driven, bio-agentic DFIR triage engine for the SANS SIFT
Workstation — a Trinity Loop (Architect → 7-agent Swarm → Critic) driving **71 MCP tools**
(**16** of them SIFT forensic wrappers) over one FastMCP server, with a forensic safety spine.
Canonical numbers throughout the docs are governed by [Canonical Facts](.crew/facts.md).

**The four audiences** used in the **Audience** column below (and in the reading paths) are:

- **operator** — runs triage day to day (drives the engine, registers evidence, executes cases).
- **examiner** — the human-in-the-loop who reviews, approves, and defends findings before the seal.
- **developer** — extends or maintains the engine (code, architecture, tools, tests).
- **auditor** — independently verifies forensic soundness, chain of custody, and reproducibility.

Each page below lists its primary audience(s) and, in the **What question it answers** column, a
one-line descriptor of exactly what that page resolves — read that column as the page's summary.

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
- **Analyst / reviewer** (see real report output): **[Multi-Tier Reports — per case run](case-activation/INDEX.md#recorded-runs)** — each case run carries a `reports/` folder with the ADR-024 engine output projected into **Analyst · Executive · Business** tiers (each in **md / html / pdf**), generated live and grounded in real findings/IOCs/timeline (e.g. `case-activation/runs/challenge-notchitup/reports/analyst.md`). *(CTF/training case data; reports embed real artifact citations.)*
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
  → [ADR Index](docs/08-reference/adr-index.md)
  → [Design Decisions — Rationale & History](docs/08-reference/design-decisions.md)
  → [Maintenance — The Dual-Repo Sync](docs/07-sdlc-ops/maintenance-dual-repo.md).
- **Auditor** (verifies forensic soundness & chain of custody): [Security Model](docs/07-sdlc-ops/security-model.md)
  → [Audit & Courtroom Seal](docs/05-safety-forensics/audit-courtroom.md)
  → [Provenance & Grounding](docs/05-safety-forensics/provenance-grounding.md)
  → [Persisted Artifacts](docs/03-data/persisted-artifacts.md)
  → [Recovery & Resilience](docs/07-sdlc-ops/recovery-resilience.md)
  → [Evaluation Corpus & Recall Methodology](docs/07-sdlc-ops/dataset-recall.md)
  → [Evaluation Scorecard](docs/07-sdlc-ops/evaluation-scorecard.md)
  → [Canonical Facts](.crew/facts.md).

---

## 0. Landing

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| README — Agentropix-SIFT | all | What is this, at a glance, and where do I go next? | [README.md](README.md) |
| Documentation Index | all | Which document answers my question, for my role? | [INDEX.md](INDEX.md) |

## 1. Overview

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| **User Guide — The Complete Operator Runbook** | operator (expert + non-technical end-user) | **How do I run one complete case end to end, in full operational depth** — pre-flight, connect/verify the MCP, init/activate the case, register evidence, drive the investigation tool chain (**manual tool-by-tool _or_ autonomous headless driver**, on **Claude CLI _or_ Desktop**), record findings, approve in the portal, seal the report, and (optionally) push IOCs to Wazuh? Written for **two audiences at once** — every action carries the **expert CLI/MCP command** *and* the **plain-language end-user prompt** for the same result — with the validated 2026-05-29 CFReDS run as a worked example, a troubleshooting ledger, and a closing **Prompt Playbook appendix** (the numbered, run-it-top-to-bottom manual and autonomous prompt sequences, each step carrying an `Expect:` check). | [docs/01-overview/user-guide.md](docs/01-overview/user-guide.md) |
| What is Agentropix-SIFT? | operator, examiner | What does the tool do, why, who is it for, and how does it compare to manual DFIR? | [docs/01-overview/what-is-agentropix.md](docs/01-overview/what-is-agentropix.md) |
| What You Get | operator, examiner | What are the concrete capabilities and the feature/capability matrix? | [docs/01-overview/what-you-get.md](docs/01-overview/what-you-get.md) |
| Quickstart | operator (expert + end-user) | How do I install, pre-flight the toolchain, and run my first triage? The condensed path, dual-audience — each step carries the **expert CLI/MCP command** and the **plain-language end-user prompt** for the same result. | [docs/01-overview/quickstart.md](docs/01-overview/quickstart.md) |
| Competitive Positioning | operator, examiner | How is this different from Velociraptor + an LLM, and where does it honestly lose? | [docs/01-overview/competitive-positioning.md](docs/01-overview/competitive-positioning.md) |

## 2. Architecture

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| System Context & Containers | developer, examiner | How does the engine sit on the SIFT host and what are its containers/boundaries? | [docs/02-architecture/system-context-c4.md](docs/02-architecture/system-context-c4.md) |
| Component Architecture & Layer Map | developer | What are the internal components and how are the code layers organized? | [docs/02-architecture/component-architecture.md](docs/02-architecture/component-architecture.md) |
| The Trinity Loop | developer, examiner | How do Architect, Swarm, and Critic interact, and how does the deterministic halt work? | [docs/02-architecture/trinity-loop.md](docs/02-architecture/trinity-loop.md) |
| The Swarm Agents & Blackboard | developer | What are the 7 core specialists (+ ATT&CK detectors), how do they correlate via the quorum Blackboard, and how do they self-correct across runs (Hippocampus, Ralph hooks, the chromosome persona)? | [docs/02-architecture/swarm-agents.md](docs/02-architecture/swarm-agents.md) |
| The FastMCP Server | developer | How is the single FastMCP server built, what transports does it use, and where is the Thymus boundary? | [docs/02-architecture/mcp-server.md](docs/02-architecture/mcp-server.md) |
| Sequence Diagrams | developer, examiner | What does each key operation look like step-by-step (full run, single tool call, seal, halt, approval, Wazuh)? | [docs/02-architecture/sequence-diagrams.md](docs/02-architecture/sequence-diagrams.md) |

## 3. Data

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| Data Dictionary | developer, auditor | What is every Pydantic field — its name, type, semantics, and constraints? | [03-data/data-dictionary.md](docs/03-data/data-dictionary.md) |
| Data Models | developer | How do TriageReport, Finding, Agent, and the envelope models relate (class diagram)? | [03-data/data-models.md](docs/03-data/data-models.md) |
| Schema ER Model | developer, auditor | How do the persisted artifacts relate as entities (ER diagram)? | [03-data/schema-er.md](docs/03-data/schema-er.md) |
| Persisted Artifacts | auditor, developer | What gets written to disk — JSON report, JSONL audit log, session keys, Hippocampus — and where? | [03-data/persisted-artifacts.md](docs/03-data/persisted-artifacts.md) |

## 4. MCP Tools

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| MCP Tool Reference | developer, operator | What are all 71 MCP tools and the 16 forensic wrappers, in detail? | [04-mcp-tools/tool-reference.md](docs/04-mcp-tools/tool-reference.md) |
| Tool Capability Map (by DFIR function) | operator, examiner, developer | Which tool do I reach for to *do* a thing — the 71-tool surface grouped by DFIR function, with the canonical happy-path ordering? | [04-mcp-tools/capability-map.md](docs/04-mcp-tools/capability-map.md) |
| Tool Response Envelope | developer, auditor | What does a tool call actually return, including the provenance fingerprint and error shape? | [04-mcp-tools/response-envelope.md](docs/04-mcp-tools/response-envelope.md) |
| Tools by Agent | developer | Which Swarm agent invokes which tools? | [04-mcp-tools/tool-by-agent.md](docs/04-mcp-tools/tool-by-agent.md) |

## 5. Safety & Forensics

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| Anti-Hallucination | examiner, auditor | How are fabricated findings prevented — determinism, evidence sovereignty, no LLM self-rating? | [docs/05-safety-forensics/anti-hallucination.md](docs/05-safety-forensics/anti-hallucination.md) |
| Provenance & Grounding | examiner, auditor | How are findings grounded in evidence, and what are the provenance tiers / grounding levels? | [docs/05-safety-forensics/provenance-grounding.md](docs/05-safety-forensics/provenance-grounding.md) |
| Audit & Courtroom Seal | auditor, examiner | How is the audit log HMAC-SHA256 sealed and the chain of custody validated? | [docs/05-safety-forensics/audit-courtroom.md](docs/05-safety-forensics/audit-courtroom.md) |
| **Approval Portal walkthrough** | operator, examiner | **How do I use the browser sign-off form** (`https://siftworkstation.taile7c9ca.ts.net:8443/`) — screenshot, every field, how to submit, how to retract/void, and the error matrix? | [docs/05-safety-forensics/approval-portal.md](docs/05-safety-forensics/approval-portal.md) |
| AI Disclosure & Reproducibility | examiner, auditor | What AI models are used (and what is pinned), what data crosses the Anthropic boundary, and how is a run replayed deterministically? | [docs/05-safety-forensics/ai-disclosure.md](docs/05-safety-forensics/ai-disclosure.md) |
| Human-in-the-Loop | examiner, auditor | How does the approval sidecar gate hold findings in DRAFT until an examiner approves — the invariant, state machine, HMAC challenge-response, and hash chain? | [docs/05-safety-forensics/human-in-the-loop.md](docs/05-safety-forensics/human-in-the-loop.md) |

## 6. Use Cases

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| Triage an E01 Disk Image End to End | operator (expert + end-user) | How do I run a full disk-image triage from start to finish? Dual-audience — every step pairs the **expert CLI/MCP command** with the **plain-language end-user prompt**, laid out Execution → Output. | [docs/06-use-cases/uc-disk-triage.md](docs/06-use-cases/uc-disk-triage.md) |
| Memory Triage with Volatility | operator (expert + end-user) | How do I triage a memory dump with the Volatility-backed agents? Dual-audience — each tool step carries both the **expert command** and the **end-user prompt** for the same result, Execution → Output. | [docs/06-use-cases/uc-memory-triage.md](docs/06-use-cases/uc-memory-triage.md) |
| Examiner Reviews & Approves Before the Seal | examiner (expert + end-user) | How do I review findings and approve them before anything is sealed? Dual-audience — the review/approve actions are shown both as the **expert CLI/MCP command** and as the **plain-language end-user prompt**. | [docs/06-use-cases/uc-approval-gate.md](docs/06-use-cases/uc-approval-gate.md) |
| Push a Finding to Wazuh as an Alert | operator, auditor (expert + end-user) | How do I escalate an APPROVED finding to Wazuh (experimental integration)? Dual-audience — each push step pairs the **expert MCP call** with the **end-user prompt** (which defaults to a dry-run preview). | [docs/06-use-cases/uc-wazuh-push.md](docs/06-use-cases/uc-wazuh-push.md) |
| Guided Demo Walkthrough (Judge-Facing) | examiner, all (expert + end-user) | What does a single end-to-end run look like, beat by beat, mapped to the Devpost rubric with verifiable runtime evidence? Dual-audience — each beat carries both the **expert command** and the **end-user prompt**. | [docs/06-use-cases/demo-walkthrough.md](docs/06-use-cases/demo-walkthrough.md) |
| Per-Case Attack-Chain Hypotheses | operator, examiner | For each in-scope test case, which attack chain is likely and which tools confirm/refute each link (bias-checks, not findings)? | [docs/06-use-cases/case-hypotheses.md](docs/06-use-cases/case-hypotheses.md) |

## 7. SDLC & Operations

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
| Maintenance — The Dual-Repo Sync | developer (expert + end-user) | Why are there two repos/package names, and how does the one-way `sift` → `mcp` sync stay faithful? Dual-audience for the sync/verify steps — the **expert command** alongside the **plain-language end-user prompt**, Execution → Output. | [docs/07-sdlc-ops/maintenance-dual-repo.md](docs/07-sdlc-ops/maintenance-dual-repo.md) |

## 8. Reference

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| CLI Reference | operator (expert + end-user) | What are all the `agentropix-sift` commands and flags? Dual-audience — the headline commands also show the **plain-language end-user prompt** that drives the same MCP tool, Execution → Output. | [08-reference/cli-reference.md](docs/08-reference/cli-reference.md) |
| Glossary | all | What does each term, persona, and weakness ID mean? | [08-reference/glossary.md](docs/08-reference/glossary.md) |
| ADR Index | developer, auditor | What architecture decisions were made and why (routed list of the ADRs)? | [08-reference/adr-index.md](docs/08-reference/adr-index.md) |
| Design Decisions — Rationale & History | developer, auditor | What recurring design principles, hard trade-offs, and discarded approaches sit behind the ADRs? | [08-reference/design-decisions.md](docs/08-reference/design-decisions.md) |

## 9. Integrations

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| Wazuh Portal — Operator's Guide | operator | How do I drive the Wazuh integration day-to-day — connect the SOC, preview a push, confirm alerts landed, and read the dashboards — without the MCP-tool internals? | [docs/09-integrations/wazuh-portal.md](docs/09-integrations/wazuh-portal.md) |
| Connect a Client to a Live Internal MCP Server | operator, developer | How do I point Claude Code CLI or Claude Desktop at an already-running MCP server over a Tailscale tailnet? | [docs/09-integrations/client-setup.md](docs/09-integrations/client-setup.md) |

---

## Shared Reference Artifacts

`.crew/` is the inventory directory: machine-extracted, low-level reference tables (facts, tool
inventory, schema, module map, env surface, agent roster) that were pulled directly from the oracle
source repo and that the prose chapters above are derived from. Read them when you need the raw
substrate behind a chapter. [Canonical Facts](.crew/facts.md) is the governing authority for every
numeric claim — it wins over any prose anywhere in the docs.

| Artifact | What it holds | Link |
|----------|---------------|------|
| Canonical Facts | The locked numeric table (tool count, tests, recall) — wins over prose | [.crew/facts.md](.crew/facts.md) |
| Tool List | Inventory of all 71 MCP tools, with the 16 SIFT forensic wrappers flagged | [.crew/tool-list.md](.crew/tool-list.md) |
| Schema Dump | The extracted Pydantic model schema (field names, types, constraints) behind the data chapter | [.crew/schema-dump.md](.crew/schema-dump.md) |
| Module Map | The code module map (where each package and component lives in `src/`) | [.crew/module-map.md](.crew/module-map.md) |
| Env Vars | The full `AGENTROPIX_*` environment-variable surface and what each tunes | [.crew/env-vars.md](.crew/env-vars.md) |
| Agents List | The Swarm agent inventory — the 7 core specialists plus the ATT&CK detectors | [.crew/agents-list.md](.crew/agents-list.md) |
