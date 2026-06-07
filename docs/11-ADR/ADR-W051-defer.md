> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-W051-defer — DEFER live recall contribution of EventID 4624 detector

**Status:** DEFERRED (code landed, live measurement deferred to M6.3)
**Date:** 2026-04-21
**Sprint:** BMAD M6.2
**Decision owner:** John (PM) + Murat (TEA)

## Context

W-051 wired an EventID 4624 detector into `TimelineAgent` (`agents/timeline.py:246-268`) plus `T_VALID_ACCOUNTS` (T1078) enrichment in `_enrichment.py`. Six unit tests cover LogonType variants, dedup, cap-binds, and enrichment-embeds-`logon`-and-`4624`. All tests pass; suite remains 934/0/0.

P-4 live DC E01 re-run measurement (artefact `M6.2-W050W051W052W054-cli-20260421T213742Z.json`, 43 min wall):

- Total findings emitted: **19**
- `timeline.plaso` findings: **0**
- T4 (`4624 + lateral + logon`) cohit≥2 contribution: **0** (unchanged from M6.1 baseline)
- Critic.score: 1.0 (halt at iter-1)

## Root cause analysis

`TimelineAgent._DEFAULT_MAX_EVENTS = 500` is propagated to `mcp_get_timeline(..., max_events=500)`. The Plaso wrapper runs `psort` with default `--output-time-zone UTC`, which yields events sorted ascending by `datetime`. On a multi-year-old NTFS DC image (creation 2018, attack 2018-2024), the earliest 500 datetime-sorted events are filesystem-metadata events (`filestat` parser; OS install / boot artefacts). The actual EventID 4624 logon events (and the MFT timestomp anomalies for W-054) sit thousands-to-millions of events deep in the timeline and never enter the 500-event window seen by `TimelineAgent.investigate()`.

Confirmed:

- `mcp.get_timeline` ran 2,536,431 ms (42 min) — plaso completed successfully.
- TimelineAgent processed events but matched 0 against any of: LOLBin keywords, winreg Run-key patterns, prefetch suffix, winevtx 4624, MFT timestomp signal.
- No `WRAPPER_TIMEOUT` finding emitted (run completed inside the 3600 s ceiling).

## Decision

DEFER the recall-gate contribution of W-051 to M6.3. The detector code is correct, unit-tested, and committed (`2a2cb1c`). Live measurement showing 0/7 cohit≥2 contribution is a structural event-windowing issue, not a detector bug.

## Consequence

- M6.2 final per-truth table: T4 = 0 → 0 (no improvement).
- Sprint success criterion §1.5 ("Live DC E01 cohit≥2 recall ≥ 4/7") is NOT met (measured 1/7).
- Sprint did NOT regress the M6.1 baseline (cohit≥2 1/7 = 1/7) — no Tier-0 hard stop.
- Demo headline must reflect measured 1/7 cohit≥2, not predicted 4/7.

## Re-attempt condition

M6.3 sprint: redesign `TimelineAgent` event windowing. Candidate strategies (architect to choose):

1. **Date-range filter** — pass `--start-time` to psort, anchored at the earliest forensic timestamp from another agent (e.g., MemoryAgent malware-stage indicator).
2. **Per-parser sampling** — call `mcp_get_timeline` once per parser (e.g., `parsers="winevtx"` only) so each parser gets its own 500-event budget rather than competing.
3. **Bump `_DEFAULT_MAX_EVENTS` to 50000** (within the existing `floor=1, ceiling=100000` env-var guard) — simplest fix, costs ~50 MB memory + ~10 s extra psort, but does not guarantee attack events surface unless the image's mid-timeline density is favourable.
4. **Plaso filter expression** — pass a `--filter` argument to psort that constrains by parser / event source.

The decision belongs to M6.3 design (Winston), not M6.2 scope.

## Residual risk

If M6.3 ships option 3 (max-events bump) without options 1/2/4, the gate may still fail on images where the attack is buried > 50000 events deep. The principled fix is option 1 or 2.
