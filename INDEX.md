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

---

## Reading Paths by Audience

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
| What is Agentropix-SIFT? | operator, examiner | What does the tool do, why, who is it for, and how does it compare to manual DFIR? | [docs/01-overview/what-is-agentropix.md](docs/01-overview/what-is-agentropix.md) |
| What You Get | operator, examiner | What are the concrete capabilities and the feature/capability matrix? | [docs/01-overview/what-you-get.md](docs/01-overview/what-you-get.md) |
| Quickstart | operator | How do I install, pre-flight the toolchain, and run my first triage? | [docs/01-overview/quickstart.md](docs/01-overview/quickstart.md) |
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
| Triage an E01 Disk Image End to End | operator | How do I run a full disk-image triage from start to finish? | [docs/06-use-cases/uc-disk-triage.md](docs/06-use-cases/uc-disk-triage.md) |
| Memory Triage with Volatility | operator | How do I triage a memory dump with the Volatility-backed agents? | [docs/06-use-cases/uc-memory-triage.md](docs/06-use-cases/uc-memory-triage.md) |
| Examiner Reviews & Approves Before the Seal | examiner | How do I review findings and approve them before anything is sealed? | [docs/06-use-cases/uc-approval-gate.md](docs/06-use-cases/uc-approval-gate.md) |
| Push a Finding to Wazuh as an Alert | operator, auditor | How do I escalate an APPROVED finding to Wazuh (experimental integration)? | [docs/06-use-cases/uc-wazuh-push.md](docs/06-use-cases/uc-wazuh-push.md) |
| Guided Demo Walkthrough (Judge-Facing) | examiner, all | What does a single end-to-end run look like, beat by beat, mapped to the Devpost rubric with verifiable runtime evidence? | [docs/06-use-cases/demo-walkthrough.md](docs/06-use-cases/demo-walkthrough.md) |

## 7. SDLC & Operations

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| Implementation — Code Organization & Build | developer | How is the codebase organized and built (module map)? | [docs/07-sdlc-ops/implementation.md](docs/07-sdlc-ops/implementation.md) |
| Testing — Topology, Gates & Recall | developer, auditor | What is the test topology, the gates, and the ground-truth recall (4464 tests; 72/72 disk; 108/118 memory)? | [docs/07-sdlc-ops/testing.md](docs/07-sdlc-ops/testing.md) |
| Recovery & Resilience | auditor, developer | What are the failure modes and the chaos/recovery classes? | [docs/07-sdlc-ops/recovery-resilience.md](docs/07-sdlc-ops/recovery-resilience.md) |
| Security Model | auditor | What is the threat model — Thymus, denylists, redaction, read-only boundary? | [docs/07-sdlc-ops/security-model.md](docs/07-sdlc-ops/security-model.md) |
| Configuration | operator, developer | What `AGENTROPIX_*` env vars exist and what do they tune? | [docs/07-sdlc-ops/configuration.md](docs/07-sdlc-ops/configuration.md) |
| Deployment | operator | How do I install on SIFT, expose over a tailnet, and find the runbooks? | [docs/07-sdlc-ops/deployment.md](docs/07-sdlc-ops/deployment.md) |
| Evaluation Scorecard — BMAD & Rubric | examiner, auditor | What did the independent 10-persona BMAD evaluation and the Devpost rubric self-grade conclude? | [docs/07-sdlc-ops/evaluation-scorecard.md](docs/07-sdlc-ops/evaluation-scorecard.md) |
| Evaluation Corpus & Recall Methodology | examiner, auditor | What evidence corpus are the recall numbers measured against, and how is ground truth defined? | [docs/07-sdlc-ops/dataset-recall.md](docs/07-sdlc-ops/dataset-recall.md) |
| Maintenance — The Dual-Repo Sync | developer | Why are there two repos/package names, and how does the one-way `sift` → `mcp` sync stay faithful? | [docs/07-sdlc-ops/maintenance-dual-repo.md](docs/07-sdlc-ops/maintenance-dual-repo.md) |

## 8. Reference

| Title | Audience | What question it answers | Link |
|-------|----------|--------------------------|------|
| CLI Reference | operator | What are all the `agentropix-sift` commands and flags? | [08-reference/cli-reference.md](docs/08-reference/cli-reference.md) |
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

These inventory-phase artifacts under `.crew/` are the source-of-truth substrate the chapters
are derived from. [Canonical Facts](.crew/facts.md) is the governing authority for every
numeric claim.

| Artifact | What it holds | Link |
|----------|---------------|------|
| Canonical Facts | The locked numeric table (tool count, tests, recall) — wins over prose | [.crew/facts.md](.crew/facts.md) |
| Tool List | Inventory of the 71 MCP tools | [.crew/tool-list.md](.crew/tool-list.md) |
| Schema Dump | Extracted Pydantic schema | [.crew/schema-dump.md](.crew/schema-dump.md) |
| Module Map | Code module map | [.crew/module-map.md](.crew/module-map.md) |
| Env Vars | `AGENTROPIX_*` environment surface | [.crew/env-vars.md](.crew/env-vars.md) |
| Agents List | The Swarm agent inventory | [.crew/agents-list.md](.crew/agents-list.md) |
