# Glossary

A decoder ring for the names, IDs, and personas that appear across the
Agentropix-SIFT codebase, weakness ledger, review docs, and commit messages.
This page consolidates the upstream glossary
([`docs/AGENTS.md`](../../../agentropix-sift/docs/AGENTS.md)) with structural facts
confirmed against the code and the shared inventory artifacts.

> **Citation discipline.** Numeric claims (tool count, recall, test count) trace
> to [`.crew/facts.md`](../../.crew/facts.md) / `CANONICAL_FACTS.md`. Persona, story,
> and weakness-stage definitions trace to `docs/AGENTS.md`. Code wins over prose.

---

## Core terms (alphabetized)

| Term | Definition | Source |
|------|------------|--------|
| **Active-triage sentinel** | `.claude/active-triage.json` written by `run` before triage and removed afterward; lets a Claude-Code Stop hook block premature session exit during an in-flight run (W-081 / M8.3). | `cli.py:92-124` |
| **Amcache / Shimcache** | Windows execution-evidence registry artifacts (`Amcache.hve`, AppCompatCache). Parsed by the `ArtifactAgent` via `amcache_parser` / `shimcache_parser`. | `cli.py:190-191`; agents-list |
| **Architect** | Deterministic Trinity-Loop planner (no LLM). Returns the canonical `SWARM` tuple, optionally pruning agents the Critic marked stable; preserves SWARM order so `HuntAgent` stays last. | `trinity/architect.py:146` |
| **Audit log (sealed)** | The Thymus on-disk access trail, drained and independently HMAC-SHA256-sealed into `<stem>.audit-log.json`, then cross-bound into the report seal. | ADR-022; `courtroom.py` |
| **Blackboard** | Asyncio-locked `(agent, Finding)` registry. `correlations()` surfaces tokens (filenames, hashes, IPs, PIDs) appearing across ≥ `quorum_threshold` (default 2) agents; powers `HuntAgent` and the Critic score. | `agents/_blackboard.py:74,86` |
| **Bio-agentic mapping** | The biological metaphor each ADR maps to (e.g. Thymus = self/non-self gate, Cytokine Network = message bus, The Oncologist = safety architecture). | `docs/adr/README.md` |
| **Convergence fingerprint** | The deterministic per-pass fingerprint the Critic halts on when it reaches a fixed point — a halt condition with **no LLM self-rating**. | `trinity/critic.py:67` |
| **Correlation** | A token observed across multiple agents on the Blackboard; ≥ quorum forms a correlation, ≥3-agent agreement feeds `HuntAgent` cross-source findings (S-05). | `agents/_blackboard.py` |
| **Courtroom** | The audit-and-sealing track: high inference constraint + HMAC-SHA256 envelope proving the LLM only orchestrates while deterministic tools generate facts. | ADR-016; `courtroom.py` |
| **Critic** | Deterministic scorer (no LLM). Score = max finding confidence + 0.25·#correlations (capped 1.0). Halts at score ≥ `AGENTROPIX_CRITIC_HALT_THRESHOLD` (default 0.85) **or** convergence fingerprint, gated by a min-iterations guard. | `trinity/critic.py:42,67` |
| **Completion promise** | A per-agent token (e.g. `MEMORY_TRIAGED`) appended to `report.completion_proofs` when an agent publishes ≥1 Finding without a tool error (M8.3d). | agents-list; `cli.py:92-98` |
| **Deterministic-tools-only findings** | Safety invariant: every fact originates from a named deterministic MCP tool; the LLM never authors a finding. | ADR-016; agents-list |
| **doctor** | CLI command verifying the 16 SIFT forensic tools (18 binaries) are installed/resolvable; see the [CLI reference](cli-reference.md#agentropix-sift-doctor). | `cli.py:175-217` |
| **EAR (Executable Registry)** | The "build / promote / get / search" executable-registry tool family added 65→69 in the MCP tool-count lineage. | facts.md (lineage) |
| **Evidence invariant** | Pre/post SHA-256 hash of the evidence image, asserting no writes to evidence (story **S-02**). | facts.md; ADR-008 |
| **EWF / E01** | Expert Witness Format disk image (`.E01`); the SANS SRL-2018 dataset ships 7 of them. Metadata read via `ewfinfo`. | `cli.py:184`; AGENTS.md |
| **Finding** | The unit of evidence published to the Blackboard; carries confidence, `agent` (W-196), and tool-derived payload (hashes, IOCs). | agents-list |
| **Forensic wrappers** | The **16** SIFT-tool wrappers under `mcp_server/wrappers/` that the swarm agents drive. | facts.md |
| **HuntAgent** | The last swarm agent; drives no wrappers, consumes `blackboard.correlations()` to emit high-confidence cross-source findings (S-05). | `agents/hunt.py:68` |
| **Inference constraint = high** | The fixed assertion printed after every run: the LLM is the orchestrator; facts come from MCP tools. | `cli.py:152`; ADR-016 |
| **IOC** | Indicator of Compromise (filename, hash, IP, domain) surfaced by agents and optionally pushed to Wazuh. | ADR-018 |
| **MCP** | Model Context Protocol; the integration substrate for every `mcp_*` tool. The FastMCP server exposes **71** distinct tools. | AGENTS.md; facts.md |
| **Provenance chain** | Validation under `provenance/` that ties findings back to their generating tool calls. | seed; module-map |
| **Quorum threshold** | Minimum number of agents that must observe a token for it to become a correlation (default **2**). | `agents/_blackboard.py:86` |
| **run** | The primary CLI command: runs the Trinity Loop over an image and seals the report. See [CLI reference](cli-reference.md#agentropix-sift-run). | `cli.py:50-152` |
| **SANS SIFT** | The host Linux DFIR workstation this project runs on. | AGENTS.md |
| **Session key** | Per-run 32-byte HMAC key written mode `0600` alongside the sealed report. | `cli.py:132-149`; ADR-022 |
| **SRL-2018** | SANS Reverse-engineered Lab dataset; 7 APT E01 images used in the wargame (incl. case 20180905-001, Cobalt Strike DC). | AGENTS.md |
| **SWARM tuple** | The ordered tuple of agent classes run each Trinity iteration — **13** classes = 7 core specialists + 6 ATT&CK detectors; `HuntAgent` is always last. | `agents/__init__.py`; facts.md |
| **Swarm (7-agent)** | Project-prose name for the 7 first-class DFIR specialists: Memory, Timeline, Filesystem, Artifact, Discovery, Mail, Hunt. | agents-list |
| **Thymus policy** | The read-only safety spine: a self/non-self gate that rejects any write to evidence and pins findings to deterministic tools. | `mcp_server/thymus_policy.py`; ADR-008 |
| **Trinity Loop** | Architect proposes → 7-agent Swarm (+ ATT&CK detectors) runs deterministic tools → Critic scores and halts on a deterministic convergence fingerprint. No LLM self-rating. | agents-list; facts.md |
| **Two-Person Rule** | A deferred control requiring two operators to confirm an Active Response; documented but not implemented. | ADR-021 |
| **Wazuh** | The SIEM the platform optionally pushes IOCs to and integrates Active-Response gating with. | ADR-018, ADR-019, ADR-020 |

---

## Crew / specialist personas

BMAD-style review roles, one per review dimension. Every team-review doc
(`docs/REVIEW-*.md`, `docs/sprint-artifacts/W*-vote-*.md`) dispatches these ten as
parallel specialists. Verbatim from [`docs/AGENTS.md`](../../../agentropix-sift/docs/AGENTS.md).

| Persona | Role (BMAD id) | Lens |
|---------|----------------|------|
| **Winston** | `forge-architect` | Architecture — Trinity Loop, MCP server design, wrapper pattern, EWF handling |
| **Murat** | `forge-tea` | Test strategy — chaos suite, unit vs integration coverage |
| **John** | `forge-pm` | PRD / scope — S-01..S-05 acceptance criteria, deferred items |
| **Bob** | `forge-sm` | Sprint health — weakness-ledger trend, W-XXX path-to-close, burn rate |
| **Amelia** | `forge-dev` | Code quality — wrapper parity, parser edge cases (W-013), tech-debt density |
| **Mary** | `forge-analyst` | Competitive landscape — SANS hackathon criteria, DFIR-AI comparables |
| **Sally** | `forge-ux-designer` | Operator UX — CLI ergonomics, status-report readability, error messages |
| **Alex** | `forge-business-strategist` | Demo-day positioning — what story wins SANS judges |
| **Gulli** | `forge-patterns` | Agentic patterns — Trinity vs ReAct / Reflexion / Debate trade-offs |
| **Paige** | `forge-tech-writer` | Documentation — README, CLAUDE.md, ledger format, glossary gaps |

*Builder-A / Builder-B / Alpha–Epsilon* denote parallel worktree branches during
multi-crew waves (`docs/MASTER-PLAN-STATE.md`).

---

## Weakness-ledger IDs

All weaknesses in [`docs/SIFT-WEAKNESSES.md`](../../../agentropix-sift/docs/SIFT-WEAKNESSES.md)
use monotonic `W-###` (a.k.a. `SIFT-W-###`) IDs — **never reused**. The ledger
currently spans roughly **W-001 … W-296+**. The dashboard groups them by
discovery **stage**:

| Stage | Meaning |
|-------|---------|
| **W0** | Pre-launch placeholders |
| **W1 / W2 / W3** | BMAD review waves (discovery phase) |
| **DryRun** | Dry-run validation on `samples/sample.dd` |
| **Trinity** | Trinity Loop wire-up phase |
| **Audit** | Thymus audit / chain-of-custody verification |
| **RealData** | 7 SANS SRL-2018 E01 images |
| **Cross** | Cross-cutting concerns (across multiple stages) |
| **Wargame** | Multi-agent live-fire against real APT evidence (2026-04-19) |
| **HardTest** | Thymus adversarial battery (2026-04-28 — W-108/W-109) |
| **MCP-100%** | "100% functional MCP tool surface" campaign (W-110/W-111/W-112/W-113) |

**Status values:** `OPEN` · `IN-PROG` (a.k.a. `IN-PROGRESS`) · `RESOLVED` ·
`DEFERRED` · `ACCEPTED`.
**Severity:** `CRITICAL` · `HIGH` · `MEDIUM` · `LOW` · `TRIVIAL`.

A few load-bearing IDs referenced elsewhere in this portal:

| ID | One-liner | Where it surfaces |
|----|-----------|-------------------|
| **W-072** | Credential-dump triage via `impacket-secretsdump.py`. | [ADR-014](adr-index.md#adr-014) |
| **W-081** | Ralph-loop Stop-hook sentinel for in-flight triage (M8.3). | `cli.py:92-114` |
| **W-110** | `run_volatility(plugin="netscan")` rc=1 on SRL-2018 DC. | AGENTS.md (MCP-100%) |
| **W-113** | MCP-100% campaign anchor — definition-of-done for the 71-tool surface. | AGENTS.md |
| **W-164** | Dangling-evidence-symlink rejection preflight (recall-collapse guard). | `cli.py:62-74` |
| **W-196** | Per-agent `Finding.agent` stamping (enables per-agent recall). | `agents/_base.py` |
| **W-282** | Mount-based Plaso fallback for tail-truncated EWF (`AGENTROPIX_PLASO_TAIL_PAD=1`). | SIFT-WEAKNESSES dashboard |

> See the dashboard block in `SIFT-WEAKNESSES.md` for the live count and current
> open/resolved breakdown.

---

## Story IDs (SANS MVP stories)

Verbatim from `docs/AGENTS.md`, plus the loop-control stories referenced by the
CLI.

| ID | Topic | Status anchor |
|----|-------|---------------|
| **S-01** | Hallucination reduction | `samples/ground_truth.yaml`; needs `ground_truth_dc.yaml` for positives |
| **S-02** | Evidence integrity (no writes to evidence) | **PASS** on all 7 wargame E01s via Thymus |
| **S-03** | Accuracy lift iter-1 → iter-N | Blocked on Reflexion-lite + Hippocampus (W-017, W-040) |
| **S-04** | (Undefined — `forge-pm` review weakness W3 MED) | Needs `docs/sprint-artifacts/sift-mvp-stories.md` |
| **S-05** | ≥3 cross-agent correlations | Blackboard `correlations()` in `_blackboard.py` |
| **S-07** | Bounded Trinity-Loop iterations | Exposed as `run --max-iterations` (`cli.py:53`) |
| **S-08** | Idempotent investigations (same seed → identical trace) | agents-list (agent contract) |

> **S-04** is intentionally undefined in the source ledger and is recorded here
> as such rather than invented.

---

## Related references

- [CLI reference](cli-reference.md) — commands, flags, env-var overrides.
- [ADR Index](adr-index.md) — the decisions behind these terms.
- [Agents list](../../.crew/agents-list.md) — Trinity roles and the swarm specialists.
- [Canonical facts](../../.crew/facts.md) — the numeric single source of truth.
