> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-015: Context Engineering — Progressive Disclosure for the Investigation Memory

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-04-25 |
| **Decision Makers** | BMAD-M8 sprint executor (Claude), Operator (gate post-Phase M8.1) |
| **Bio-Agentic Component** | Project memory (`CLAUDE.md` + `skills/` + `.bmad/` + `docs/runbooks/`) |
| **Priority** | P1 — addresses the "context rot" failure mode that turns Claude into a guessing machine when stuffed with 400 tool manuals |

## Context

A naive LLM-DFIR integration loads everything it might need into the system prompt: every wrapper docstring, every weakness ID, every runbook, every persona, every changelog row. The result is severe context rot:

- The model spends most of its window paraphrasing the prompt instead of reasoning over evidence.
- Cache hit-rate collapses because every conversation has a slightly different prompt fingerprint.
- The cost-per-token compounds across every Trinity iteration.
- Worst: the model starts confabulating *because* the relevant context is buried under noise it can't filter.

Modern Claude / Claude Code supports **progressive disclosure** — the agent loads a thin index at session start and pulls in domain-specific *skills* on demand. SIFT's `skills/` directory plus the BMAD `.bmad/_cfg/*-manifest.csv` substrate is the substrate; this ADR documents the *policy* and the *budget targets*.

## Decision

**SIFT memory architecture is hierarchical with strict load-on-demand semantics:**

```
session start                                      ┌── always loaded
                                                   │
  CLAUDE.md ────────── nav hub, ~25 KB ──────────┘
       │
       ├─ @docs/AGENTS.md (10 KB) ─── loaded if mentioned by operator
       ├─ @docs/MASTER-PLAN.md (27 KB) ─ loaded for sprint coordination
       ├─ @docs/runbooks/threat-hunt-phases.md ─ loaded for triage routing
       │
       └─ skills/<domain>/SKILL.md ─── loaded ONLY when domain triggered
              │
              ├─ memory-analysis/         (~3 KB)
              ├─ timeline-analysis/       (~3 KB)
              ├─ artifact-analysis/       (~3 KB)
              ├─ filesystem-hunt/         (~3 KB)
              └─ cross-modal-fusion/      (~3 KB)
```

**BMAD agents** (`.bmad/bmm/agents/*.md`, ~5 KB each — analyst, architect, dev, pm, sm, tea, ux, …) are loaded by `/bmad:<agent>` slash command only. The `<agent-loader>` XML pattern at `.claude/commands/bmad/<role>.md` is the on-demand trampoline.

**Bare-minimum context budget at session start:**

| Component | Size | Tokens (≈) |
|---|---|---|
| `CLAUDE.md` | 25 KB | 7-9k |
| `.bmad/_cfg/*-manifest.csv` (5 files combined) | 4 KB | 1k |
| `MEMORY.md` (operator's auto-memory index) | 1 KB | 250 |
| **Session-start total** | **~30 KB** | **~10k tokens** |

**After triage routing (Phase 1 of `threat-hunt-phases.md`):**

| Component | Size | Cumulative tokens |
|---|---|---|
| Above + 1-4 SKILL.md files (3 KB each) | + 12 KB | ~14k tokens |

**After full Trinity iteration (Phase 4):**

| Component | Cumulative tokens |
|---|---|
| Above + maybe 1 BMAD agent + 1 ADR pulled by Critic feedback | ~22k tokens |

**Hard ceiling: 80 KB / ~25k tokens of project-memory load before Trinity starts emitting actual work.** Anything beyond that is symptom of a failed disclosure, not a feature.

## Mechanism

1. **CLAUDE.md remains the entry point.** It does NOT embed tool docs. It cross-references via markdown links and `@filename.md` Claude Code imports. ~25 KB hard cap (currently 25,108 chars).

2. **`skills/<domain>/SKILL.md` files are the domain charters.** Each declares:
   - `name`, `description`, `domain`, `mitre[]`, `load_when` frontmatter.
   - When to invoke (natural-language triggers).
   - Entry agent + native wrappers (file:line precision).
   - Tunable env vars.
   - Acceptance gates.
   - Tests locking the contract.
   - Related skills.

3. **`docs/runbooks/threat-hunt-phases.md` is the load-order index.** It maps DFIR phases (triage → memory → timeline → artifact → fusion → seal) to which SKILL.md to load. Operator natural-language phrasing → skill map at the bottom.

4. **`.bmad/_cfg/*-manifest.csv`** enables runtime enumeration of agents/tasks/workflows. The `bmad-master.md:54` rule "Load files ONLY when executing menu items" is enforced.

5. **No nested CLAUDE.md files.** Single source of truth at repo root. Subdirectory READMEs (`docs/README.md`, `tests/README.md`) are explicitly NOT auto-loaded.

## Trade-offs considered

### Option A — Monolithic prompt
**Rejected.** ~400 KB of tool docs → 130k+ tokens at session start, blows the 200k window after a couple of Trinity iterations. Cache miss every conversation. Confabulation goes up because model can't filter.

### Option B — Pure on-demand (no CLAUDE.md)
**Rejected.** Without a nav hub, the agent has no way to *know* what skills exist. Discovery requires either listing the `skills/` dir (slow, brittle) or hard-coded knowledge (defeats the purpose).

### Option C — Hierarchical with progressive disclosure (this ADR)
**Accepted.** Lean nav hub + manifest-driven discovery + per-domain SKILL.md + phase-indexed load-order runbook. Caches well (CLAUDE.md is stable across sessions). Skill loads are deterministic functions of evidence type. Budget headroom is preserved.

## Acceptance / Implementation gates

- [x] CLAUDE.md is ≤30 KB (currently 25 KB; budget allows for ~5 KB of growth).
- [x] `skills/` directory exists with one SKILL.md per DFIR domain (M8.1a shipped 5).
- [x] `docs/runbooks/threat-hunt-phases.md` exists and maps phases to skills (M8.1b).
- [x] CLAUDE.md uses `@docs/AGENTS.md` and `@docs/runbooks/threat-hunt-phases.md` import lines (M8.1d shipped; verified at CLAUDE.md:19-20).
- [ ] Token-counter integration test verifies session-start load ≤ 12k tokens (deferred to M9; non-blocking).
- [ ] Mutating skills/ contents triggers a CHANGELOG.md row (operator discipline).

## Verification

The token budget is verifiable two ways:

1. **Static measurement.** `wc -c CLAUDE.md skills/*/SKILL.md .bmad/_cfg/*.csv` — sum should be < 80 KB. Today: ~30 KB session-start, ~45 KB after triage skill load.

2. **Dynamic measurement (optional).** Add `tools/measure_context.py` that reads the live conversation transcript and reports cumulative tokens by source. Skipped for now to avoid pulling in an LLM tokenizer dependency; revisit if cache-hit metrics regress.

## Status decision

**Accepted.** This ADR is the durable design statement that BMAD-M8 Phases M8.1a/b/c/d implement. M8 close should reference this ADR in CHANGELOG.md.

## References

- Oracle: `CLAUDE.md` (repo root) — entry point
- Oracle: `docs/runbooks/threat-hunt-phases.md` — load-order index
- Oracle: `skills/` — domain charters
- Oracle: `docs/exec/BMAD-M8-HACKATHON-SCORECARD.md` — gap analysis driving this ADR
- Oracle: `.bmad/core/agents/bmad-master.md` — "Load files ONLY when executing" rule
- Anthropic's Claude Code prompt-caching documentation — TTL, fingerprint stability, hit-rate impact of monolithic vs. progressive prompts
