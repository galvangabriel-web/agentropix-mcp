# Agentropix-SIFT — Documentation Build Plan

**Status:** ACTIVE — portal generated; this plan reflects the current published layout.
**Author:** documentation crew lead (Claude)
**Last updated:** 2026-06-07
**Source repo (oracle):** `/home/admin2/agentropix-sift` (`docs/` + `src/`)
**Output workspace (this portal):** `/home/admin2/docu_agentro/`
**In-repo mirror:** `/home/admin2/agentropix-sift/docs/portal/`

---

## 0. Canonical facts (locked — every doc must match)

The governing numeric authority now lives **in the portal** at
[`docs/08-reference/canonical-facts.md`](docs/08-reference/canonical-facts.md) (formerly `.crew/facts.md`).
It wins over any prose anywhere in the docs.

| Fact | Value | Source |
|------|-------|--------|
| MCP tool count | **72** | `docs/08-reference/canonical-facts.md` |
| Forensic wrappers | **16** SIFT tools | `docs/08-reference/canonical-facts.md`, `src/.../mcp_server/wrappers/` |
| Test count | **4687** | `docs/08-reference/canonical-facts.md` |
| Disk recall (regression) | **72/72 (100%)** | `docs/08-reference/canonical-facts.md` |
| Memory recall (combined) | **108/118 (91.5%)** | `docs/08-reference/canonical-facts.md` |
| Python | **3.12+** | `pyproject.toml` |
| Agentic pattern | **Trinity Loop** (Architect → Swarm → Critic) | `trinity/`, `agents/` |

> The oracle (`/home/admin2/agentropix-sift` `docs/` + `src/`) wins any conflict with portal prose.

---

## 1. What we are documenting (verified seed)

Agentropix-SIFT is a **local, CLI-driven bio-agentic DFIR triage engine** for the SANS SIFT
Workstation. A **Trinity Loop** (Architect proposes agents → 7-agent Swarm runs deterministic
forensic tools → Critic scores and halts on a deterministic convergence fingerprint, *no LLM
self-rating*) drives **72 MCP tools** over a single **FastMCP** server. Safety spine: *Thymus*
read-only policy, pre/post SHA-256 evidence invariant, deterministic-tools-only findings,
**Courtroom** HMAC-SHA256 audit seal, provenance-chain validation, optional human-in-the-loop
approval sidecar.

---

## 2. Published layout (11 sections)

The portal is **11 numbered sections** under `docs/`, plus `README.md` (landing) and `INDEX.md`
(routed master index). **Every section carries a `README.md`** with a numbered *"Read in this order"*
list (intro → deeper); the same ordering is mirrored inline under each section heading in `INDEX.md`.
Filenames are stable — reading order is layered on non-destructively (no renames).

```
docu_agentro/
├── INDEX.md                 # routed master ToC: audience + "question it answers" + reading order per page
├── README.md                # comprehensive landing page
├── DOCUMENTATION-PLAN.md    # this file
└── docs/
    ├── 01-overview/         README + what-is, what-you-get, quickstart, user-guide (GOLD STANDARD), competitive-positioning
    ├── 02-architecture/     README + system-context-c4, component-architecture, trinity-loop, swarm-agents,
    │                          mcp-server, sequence-diagrams, ez-tools-integration, module-map*
    ├── 03-data/             README + data-dictionary, data-models, schema-er, persisted-artifacts, schema-dump*
    ├── 04-mcp-tools/        README + capability-map, tool-reference, response-envelope, tool-by-agent, tool-list*
    ├── 05-safety-forensics/ README + anti-hallucination, provenance-grounding, human-in-the-loop,
    │                          approval-portal, audit-courtroom, ai-disclosure
    ├── 06-use-cases/        README + uc-disk-triage, uc-memory-triage, uc-approval-gate, uc-wazuh-push,
    │                          demo-walkthrough, case-hypotheses
    ├── 07-sdlc-ops/         README + implementation, testing, security-model, recovery-resilience, configuration,
    │                          deployment, dataset-recall, evaluation-scorecard, maintenance-dual-repo, env-vars*
    ├── 08-reference/        README + cli-reference, glossary, adr-index, design-decisions, canonical-facts*
    ├── 09-integrations/     README + client-setup, wazuh-portal
    ├── 10-agents/           README + agentic-architecture, delegation-model, agents-list*, fastmcp-execution
    ├── 11-ADR/              README + ADR-001…024, ADR-M6.3-*, ADR-W05*-defer, ADR-TEMPLATE (mirrored from oracle docs/adr/)
    └── issues/              QA logs (DIAGRAM-AUDIT.md, CASE-GUIDE-AUDIT.md); docs/issues/*.png are gitignored
```

`*` = **shared-reference** page (machine-extracted substrate, formerly under `.crew/`; see §3).
`11-ADR/` mirrors the canonical Architecture Decision Records from the oracle (`docs/adr/`) — the
immutable decision contract; the routed catalogue stays at `docs/08-reference/adr-index.md`.
`docs/issues/` holds maintainer-facing documentation-QA logs (not reader chapters); it was moved
under `docs/` so the audit trail ships alongside the pages it validates.

---

## 3. `.crew/` migration (done)

The machine-extracted reference tables formerly grouped under `.crew/` have been **physically moved
into their matching docs categories** (`git mv`), and every citation rewritten — `.crew/` is now empty
and no link points at it. New homes:

| Former `.crew/` artifact | New home |
|--------------------------|----------|
| `facts.md` | [`docs/08-reference/canonical-facts.md`](docs/08-reference/canonical-facts.md) (governing authority) |
| `tool-list.md` | [`docs/04-mcp-tools/tool-list.md`](docs/04-mcp-tools/tool-list.md) |
| schema dump | [`docs/03-data/schema-dump.md`](docs/03-data/schema-dump.md) |
| module map | [`docs/02-architecture/module-map.md`](docs/02-architecture/module-map.md) |
| env-var surface | [`docs/07-sdlc-ops/env-vars.md`](docs/07-sdlc-ops/env-vars.md) |
| agents list | [`docs/10-agents/agents-list.md`](docs/10-agents/agents-list.md) |

These pages stay reference-grade (clarity standard) and are derived from the oracle; prose chapters
cite them.

---

## 4. The `10-agents` category (new)

Added to disambiguate the overloaded word "agent": the **runtime DFIR swarm** vs the **build-time
BMAD personas**, and to tie Trinity ↔ Swarm ↔ MCP into one model.

1. [agentic-architecture.md](docs/10-agents/agentic-architecture.md) — what "agent" means here (category overview).
2. [delegation-model.md](docs/10-agents/delegation-model.md) — BMAD personas + Α–Ζ delivery crews + the delegation protocol.
3. [agents-list.md](docs/10-agents/agents-list.md) — *(shared reference)* the canonical runtime-swarm table.
4. [fastmcp-execution.md](docs/10-agents/fastmcp-execution.md) — one agent tool call, station by station.

---

## 4a. The `11-ADR` category (new) + `docs/issues` move

**`11-ADR`** mirrors the canonical Architecture Decision Records from the oracle
(`/home/admin2/agentropix-sift/docs/adr/`) into the portal — the **immutable decision contract**.
Each ADR page carries the original decision text plus a portal breadcrumb; sibling-ADR links resolve
within the section, source/test/runbook references cite the oracle path (oracle wins any conflict).

1. [README.md](docs/11-ADR/README.md) — the ADR corpus index + the status table (read the status
   column literally: *Proposed* ⇒ NOT shipped; *Deferred* ⇒ documented, not implemented).
2. Strategic ADRs **001–008** — the eight foundational decisions (SDK, execution engine, state,
   identity, message bus, memory, deployment, the bio-agentic safety spine).
3. Capability & forensic ADRs **009–024** — evidence gates, EVTX/extract-files wrappers, the
   Courtroom audit + HMAC seal, tailnet exposure, Wazuh IOC push, the AR confirmation gate,
   credential lifecycle, the multi-tier report engine.
4. Milestone & defer ADRs — M6.3 event-window + residual-gap, the W051/W052/W054 live-recall defers.
5. [ADR-TEMPLATE.md](docs/11-ADR/ADR-TEMPLATE.md) — the MADR-style format every new ADR follows.

The routed *catalogue* (one-line summaries + anchors) stays at
[`docs/08-reference/adr-index.md`](docs/08-reference/adr-index.md) and links into Section 11 for the
full text.

**`docs/issues` move.** The portal's documentation-QA logs (`DIAGRAM-AUDIT.md`, `CASE-GUIDE-AUDIT.md`)
were moved under `docs/` (from the repo root) so the validation audit trail ships alongside the pages
it covers. They are maintainer-facing working notes — *not* reader chapters and *not* listed in the
per-audience reading paths. The accompanying screenshots (`docs/issues/*.png`) stay gitignored
(local-only).

---

## 5. Reading order (non-destructive)

Reading order is published two ways, kept in sync:

1. **Per-section `README.md`** — a numbered *"Read in this order: 1. file — one-line purpose; 2. …"*.
2. **`INDEX.md`** — the same ordering inline under each section heading, plus the audience-routed
   reading paths (operator / examiner / developer / auditor) at the top.

No existing files were renamed; the ordering is metadata layered on top.

---

## 6. House style (enforced)

Per [`CLAUDE.md`](CLAUDE.md): dual-audience callouts (🖥️ expert command + 💬 end-user prompt) for
operational pages; Execution → Output enumeration; Manual ↔ Autonomous × Expert ↔ Non-expert matrix
where both apply; GitLab-safe Mermaid (flowchart/etc., explicit `classDef color:`, no
C4/`timeline`/bare `;`/`#`/`{}`); cite the oracle source for every non-obvious claim; no secrets;
`<TAILNET-HOST>` placeholder for hosts/IPs. Gold-standard page:
[`docs/01-overview/user-guide.md`](docs/01-overview/user-guide.md). Reference/architecture pages get
the clarity standard, not forced prompt-boxes.

---

## 7. Validate before every push

1. **Links/images** — every relative link and image reference resolves (0 broken), including all
   section-`README.md` and `INDEX.md` reading-order links and the `.crew` → new-home rewrites.
2. **Canonical facts** — no number contradicts `docs/08-reference/canonical-facts.md`.
3. **Mermaid** — every block renders (mermaid-cli) and is GitLab-safe.
4. **Mirror** — copy changed files into `/home/admin2/agentropix-sift/docs/portal/`.

---

## 8. Definition of done

A reader who has never seen the project can, from `INDEX.md` (or any section `README.md`) alone,
follow a clear reading order to learn **what** the tool does, **how** it works (agentic framework,
backend, MCP), **how to** install/operate it, **how** it stays forensically sound
(anti-hallucination/recovery/audit), and **how to extend** it — with diagrams + prose covering every
major operation, the agent model disambiguated in `10-agents`, the `.crew` substrate folded into its
categories, and **no claim that contradicts `docs/08-reference/canonical-facts.md`**.
