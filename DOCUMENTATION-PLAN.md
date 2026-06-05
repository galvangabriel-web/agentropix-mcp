# Agentropix-SIFT — Documentation Build Plan

**Status:** DRAFT — awaiting operator approval before full generation
**Author:** documentation crew lead (Claude)
**Date:** 2026-06-05
**Source repo:** `/home/admin2/agentropix-sift`
**Output workspace:** `/home/admin2/docu_agentro/`
**Structural model:** Valhuntir / SIFT-MCP README (layout only — content re-derived from our repo)

---

## 0. Canonical facts (locked — every doc must match)

| Fact | Value | Source |
|------|-------|--------|
| MCP tool count | **71** | `CANONICAL_FACTS.md#mcp_tool_count` |
| Forensic wrappers | **16** SIFT tools | `mcp_server/wrappers/` |
| Test count | **4464** | `CANONICAL_FACTS.md#test_count` |
| Disk recall (regression) | **72/72 (100%)** | `CANONICAL_FACTS.md#disk_recall_regression` |
| Memory recall (combined) | **108/118 (91.5%)** | `CANONICAL_FACTS.md#memory_recall_combined` |
| Python | **3.12+** | `pyproject.toml` |
| Agentic pattern | **Trinity Loop** (Architect → Swarm → Critic) | `trinity/`, `agents/` |

> Gate: `scripts/check_canonical_facts.py` must pass on any doc copied back into the source repo.

---

## 1. What we are documenting (verified seed)

Agentropix-SIFT is a **local, CLI-driven bio-agentic DFIR triage engine** for the SANS SIFT Workstation. A **Trinity Loop** (Architect proposes agents → 7-agent Swarm runs deterministic forensic tools → Critic scores and halts on a deterministic convergence fingerprint, *no LLM self-rating*) drives **71 MCP tools** over a single **FastMCP** server. Safety spine: *Thymus* read-only policy, pre/post SHA-256 evidence invariant, deterministic-tools-only findings, **Courtroom** HMAC-SHA256 audit seal, provenance-chain validation, optional human-in-the-loop approval sidecar.

---

## 2. Deliverable file tree (output under `docu_agentro/`)

```
docu_agentro/
├── INDEX.md                         # master routed table of contents (entry point)
├── README.md                        # Valhuntir-style comprehensive landing page
└── docs/
    ├── 01-overview/
    │   ├── what-is-agentropix.md     # what/why/who, positioning vs manual DFIR
    │   ├── what-you-get.md           # feature inventory (capabilities matrix)
    │   └── quickstart.md             # install paths + first triage run
    ├── 02-architecture/
    │   ├── system-context-c4.md      # C4 context + container (Mermaid C4Context)
    │   ├── component-architecture.md # C4 component, layer map
    │   ├── trinity-loop.md           # Architect/Swarm/Critic internals + halt logic
    │   ├── swarm-agents.md           # 5 core + 2 optional agents, Blackboard correlation
    │   ├── mcp-server.md             # FastMCP app, transports, Thymus boundary
    │   └── sequence-diagrams.md      # all key sequenceDiagrams (see §4)
    ├── 03-data/
    │   ├── data-dictionary.md        # every Pydantic field: name/type/semantics/constraints
    │   ├── data-models.md            # classDiagram of TriageReport/Finding/Agent/Envelope
    │   ├── schema-er.md              # erDiagram of persisted artifacts
    │   └── persisted-artifacts.md    # JSON report, JSONL audit, session keys, Hippocampus
    ├── 04-mcp-tools/
    │   ├── tool-reference.md         # full 71-tool table + 16 wrapper deep tables
    │   ├── response-envelope.md      # envelope shape, caveats/advisories/provenance
    │   └── tool-by-agent.md          # which agent invokes which tool
    ├── 05-safety-forensics/
    │   ├── anti-hallucination.md     # determinism, evidence sovereignty (FIRST-CLASS)
    │   ├── provenance-grounding.md   # provenance tiers + grounding levels
    │   ├── audit-courtroom.md        # HMAC seal, audit log, chain-of-custody
    │   └── human-in-the-loop.md      # approval sidecar gate
    ├── 06-use-cases/
    │   ├── uc-disk-triage.md         # E01 disk image triage (use-case + sequence + prose)
    │   ├── uc-memory-triage.md       # volatility memory triage
    │   ├── uc-approval-gate.md       # examiner approves before seal
    │   └── uc-wazuh-push.md          # finding → Wazuh alert (optional integration)
    ├── 07-sdlc-ops/
    │   ├── implementation.md         # module map, code organization
    │   ├── testing.md                # unit/integration/chaos/provenance suites, coverage
    │   ├── recovery-resilience.md    # failure-mode catalogue, R1–R5 chaos classes
    │   ├── security-model.md         # Thymus, denylist, redaction, threat model
    │   ├── configuration.md          # AGENTROPIX_* env var table
    │   └── deployment.md             # SIFT install, tailnet exposure, runbook index
    └── 08-reference/
        ├── cli-reference.md          # every `agentropix-sift` command + flags
        ├── glossary.md               # personas, weakness IDs, terms (from docs/AGENTS.md)
        └── adr-index.md              # routed list of the 24 ADRs
```

Total: **1 index + 1 landing + ~30 chapter files**, every diagram in Mermaid, every diagram paired with prose.

---

## 3. Coverage matrix (existing source → new deliverable → action)

| Existing source in repo | Feeds new deliverable | Action |
|---|---|---|
| `docs/MASTER-PLAN.md` | overview, architecture | summarize + link (authoritative) |
| `CANONICAL_FACTS.md` | all numeric claims | cite verbatim |
| `docs/architecture/_C4-*.md` | 02-architecture | adapt diagrams |
| `docs/architecture/_DOMAIN-CLASS.md`, `_MCP-MODELS.md`, `_SCHEMA-ER.md` | 03-data | adapt class/ER diagrams |
| `docs/ARCHITECTURE-LAYERS.md`, `MCP-REQUEST-FLOW.md` | 02-architecture, sequences | adapt |
| `docs/tools/_TOOL-CATALOGUE.md` + `docs/tools/*` | 04-mcp-tools | expand into full reference |
| `docs/adr/` (24 ADRs) | 08-reference/adr-index | index + cross-link |
| `docs/SIFT-WEAKNESSES.md` | safety, recovery | mine for failure modes |
| `docs/runbooks/` (11) | 07-sdlc-ops/deployment | index + link |
| `docs/guides/`, `docs/integration/` | use-cases, quickstart | adapt |
| `src/.../schema/` (Pydantic) | 03-data | **derive from code** (source of truth) |
| `cli.py` | cli-reference, use-cases | **derive from code** |
| `mcp_server/wrappers/` | tool reference | **derive from code** |
| `trinity/`, `agents/`, `orchestrator.py` | architecture, sequences | **derive from code** |
| `courtroom.py`, `provenance/`, `evidence_gate/`, `thymus_policy.py` | safety chapter | **derive from code** |
| `.env.example` | configuration | extract env var table |

**Gap risk:** the repo's doc corpus is large; primary risk is duplication/drift. Rule enforced: *link, don't duplicate*; code wins over docs; `CANONICAL_FACTS` wins over prose.

---

## 4. Diagram inventory (all Mermaid)

- **C4Context / C4Container** — system context, deployment topology
- **C4Component** — Trinity + MCP + safety components
- **classDiagram** — TriageReport, Finding, SwarmAgent hierarchy, Blackboard, MCP tool envelope
- **erDiagram** — persisted artifacts (report ↔ findings ↔ audit entries ↔ evidence)
- **sequenceDiagram** ×5+: (1) full triage run end-to-end; (2) single MCP tool call through Thymus; (3) finding → provenance classification → seal; (4) Architect↔Swarm↔Critic iteration loop with halt; (5) approval-sidecar human gate; (6) Wazuh push
- **graph** (use-case + flow) for each of the 4 use cases

---

## 5. Agent crew & phasing

| Phase | Crew agent | Produces | Depends on |
|---|---|---|---|
| P0 | Inventory agent | verify coverage matrix, extract canonical facts, schema dump | — |
| P1 (parallel) | Architecture agent | 02-architecture/* + sequence diagrams | P0 |
| P1 (parallel) | Data/schema agent | 03-data/* | P0 |
| P1 (parallel) | MCP/tools agent | 04-mcp-tools/* | P0 |
| P1 (parallel) | Safety/SDLC agent | 05-safety + 07-sdlc-ops/* | P0 |
| P1 (parallel) | Use-case agent | 06-use-cases/* | P0 |
| P2 | Editor/index agent | README.md landing page, INDEX.md, cross-link + consistency pass | P1 |
| P3 | Verifier agent | fact-check every numeric claim vs CANONICAL_FACTS; flag conflicts | P2 |

Execution: multi-agent `Workflow` — P1 fans out in parallel (pipeline), P2 synthesizes, P3 adversarially verifies. Estimated ~8–10 agents.

---

## 6. Definition of done

A reader who has never seen the project can, from `INDEX.md` alone, navigate to learn **what** the tool does, **how** it works under the hood (agentic framework, backend, MCP), **how to** install/operate it, **how** it stays forensically sound (anti-hallucination/recovery/audit), and **how to extend** it — with diagrams + prose covering every major operation, and **no claim that contradicts `CANONICAL_FACTS.md`**.

---

## 7. Open decisions for operator

1. **Output location** — generate into `docu_agentro/` (proposed, keeps source repo clean) vs. directly into `agentropix-sift/docs/`?
2. **Depth vs. speed** — full ~30-file set (thorough, more tokens) vs. a leaner ~12-file core first?
3. **Diagram dialect** — Mermaid (GitHub-native, proposed) confirmed?
