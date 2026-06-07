> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-W054-defer — DEFER live recall contribution of MFT timestomp detector

**Status:** DEFERRED (code landed, live measurement deferred to M6.3)
**Date:** 2026-04-21
**Sprint:** BMAD M6.2
**Decision owner:** John (PM) + Murat (TEA)

## Context

W-054 added `mft` to the default Plaso parser set (`agents/timeline.py:53` `_DEFAULT_TIMELINE_PARSERS`) plus a $MFT timestomp detector (`agents/timeline.py:270-296`) and `T_TIMESTOMP` (T1070.006) enrichment in `_enrichment.py`. Four unit tests cover default-set membership, env-override drop, fires-on-signal, and never-fabricates-without-signal. All tests pass; suite remains 934/0/0.

P-4 live DC E01 re-run measurement (artefact `M6.2-W050W051W052W054-cli-20260421T213742Z.json`, 43 min wall):

- Total findings emitted: **19**
- `timeline.plaso` findings: **0**
- T5 (`timestomp + MFT + modified`) cohit≥2 contribution: **0** (unchanged from M6.1 baseline)
- Critic.score: 1.0 (halt at iter-1)

## Root cause analysis

Same root cause as W-051 (see `ADR-W051-defer.md`): the `_DEFAULT_MAX_EVENTS=500` budget on `TimelineAgent` returns the earliest 500 datetime-sorted events — predominantly OS-install `filestat` metadata. The MFT timestomp anomalies are produced by Plaso's `mft` parser only when an MFT entry's modification timestamp predates its creation timestamp (or other anomaly signal), which on this DC image is associated with the attacker's anti-forensics activity from late in the attack timeline. Those events sit deep in the sorted timeline and never enter the 500-event window.

Additional secondary risk identified during P-4 analysis (R-M6.2-1 partially realized):

- The MFT parser is high-volume on a fully-populated NTFS volume (~12 GB image yielded a 5 GB `.plaso` storage file, vs ~3.8 GB without MFT in earlier W-050 runs).
- Plaso run-time grew from ~28 min (M6.1 P-C, no MFT) to ~42 min (M6.2 P-4 with MFT), exhausting the 2070 s autoscale ceiling and requiring `AGENTROPIX_PLASO_TIMEOUT=3600` override.
- Even after the MFT events parse successfully, they are sorted to the front of the timeline (creation timestamps from 2018 OS install) ahead of the attack-era 4624 / Run-key / prefetch events.

## Decision

DEFER the recall-gate contribution of W-054 to M6.3. The detector code is correct, unit-tested, and committed (`2a2cb1c`). Live measurement showing 0/7 cohit≥2 contribution is a structural event-windowing issue compounded by MFT parser high-volume — not a detector bug.

## Consequence

- M6.2 final per-truth table: T5 = 0 → 0 (no improvement).
- Sprint success criterion §1.5 not met (see ADR-W051-defer §Consequence).
- The MFT parser remains in `_DEFAULT_TIMELINE_PARSERS` so M6.3's event-windowing redesign can leverage it immediately.

## Re-attempt condition

M6.3 sprint: same event-windowing redesign as W-051 (see `ADR-W051-defer.md` §Re-attempt condition). Additionally for W-054 specifically:

- **Per-parser pass for MFT** — call `mcp_get_timeline(image, parsers="mft")` separately, and within the per-parser pass, post-filter events to those carrying the timestomp signal (`modified` or `timestomp` token in message). This gives MFT its own 500-event budget targeted at the signal class rather than the temporal head.
- **Plaso `--filter` expression** — psort supports `parser is "mft" and message contains "timestomp"`.

## Residual risk

Even with per-parser sampling, MFT timestomp detection on real-world images depends on Plaso emitting a sentinel token (`modified`, `timestomp`, `MACB anomaly`) that the detector can match. If Plaso 20260119+ stops emitting these tokens (e.g., schema migration), the detector silently regresses. M6.3 should add a contract test against a synthetic MFT timestomp event to pin Plaso's output schema.
