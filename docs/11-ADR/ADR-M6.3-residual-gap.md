> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-M6.3-residual-gap: Wrapper succeeds · detector emits zero findings on live DC

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted — **documented gap**, not a design decision |
| **Date** | 2026-04-22 |
| **Decision Makers** | Architect-A (Crew Α, Autonomous Delivery Mode) |
| **Bio-Agentic Component** | Layer 0 (plaso wrapper) ↔ Layer 1 (TimelineAgent) boundary |
| **Priority** | P0 (CRITICAL — blocks any further recall work until understood) |
| **Supersedes** | — (complements `ADR-M6.3-event-window.md`, does not replace it) |

## Context

### What was expected
M6.3 commit `03079f2` replaced `_parse_jsonl_events(jsonl_path, limit=500)`
with a priority-deque + per-parser-deque bucket sampler (see
`ADR-M6.3-event-window.md` for the design). Unit tests
(`tests/unit/test_plaso_event_window.py`, 16 tests) validated:
- Priority events (4624, winreg Run-key, MFT timestomp, LOLBINs)
  survive truncation against a synthetic flood.
- Per-parser deques retain LATEST events (newest-first round-robin).
- Env-var floor/ceiling guards behave correctly.
- A realistic-looking synthetic flood (winevtx + winreg + filestat)
  yields the expected mix.

Expectation: on the live 12 GB `base-dc-cdrive.E01`, the wrapper would
deliver 4624 logon events and $MFT modified-time events into the
TimelineAgent's window, flipping T4 (cohit≥2 = 1/1) and T5 (1/1) from
miss → hit.

### What was measured

Live run artefact:
`/home/admin2/.openclaw/workspace/e01-runs/M6.3-W050W051W054-cli-20260422T000337Z.{json,log}`

- **Wall:** 2043 s (34 min). Well under NFR-06 (45 min).
- **CLI status:** `Status: complete · Findings: 19 · Tool calls: 20`.
- **Trace — `mcp.get_timeline`:** `duration_ms=1985297 · exit_code=0 ·
  result_summary="ok"`. Wrapper call succeeded.
- **Trace — `agent.timeline`:** `duration_ms=1985297 ·
  result_summary="0 finding(s)"`. Agent derived nothing.
- **Findings by source:** `filesystem.fls=12 · artifact.extract=5 ·
  artifact.ewfinfo=1 · hunt.correlate=1 · timeline.plaso=0`.
- **Recall:** legacy 4/7 (unchanged from M6.2), cohit≥2 1/7 (unchanged).

**The wrapper reports success. The agent reports zero findings. There
is no observable error path between them.**

### Why this matters
- The M6.3 sprint gate (cohit≥2 ≥ 4/7) rests on T4 (4624) and T5 ($MFT)
  flipping. Neither flipped.
- The M6.2 diagnosis (`ADR-W051-defer.md`, `ADR-W054-defer.md`) pointed
  to `_DEFAULT_MAX_EVENTS=500` + datetime-ascending truncation as the
  root cause. That hypothesis is **no longer supported** — the
  redesigned wrapper does not truncate the same way, yet recall
  unchanged.
- Until this gap is understood, no further event-window work can be
  scoped with confidence.

## Decision

**Accept the gap, document it here as a P0 residual for M6.4, and do
NOT revert `03079f2`.** Specifically:

1. `ADR-M6.3-event-window.md` keeps its Accepted status — the design
   is sound at the unit-test level and reverting would lose the wider
   default (`_DEFAULT_MAX_EVENTS=2000`) and the per-parser structure
   that will still be useful once the gap is understood.
2. The two live-validation checkboxes in `ADR-M6.3-event-window.md`
   remain `[ ]` (unchecked) and this ADR is the place that records why.
3. W-050 stays at PARTIAL; W-051 and W-054 stay at DEFERRED. The M6.3
   close doc (`PHASE-M6.3-COMPLETE.md`) reflects PARTIAL closure.
4. M6.4 charter opens with an instrumentation sprint (not another
   design sprint).

## Hypotheses to test in M6.4

Ordered by likelihood given the observed trace:

### H1 (most likely): psort JSONL was empty or nearly empty
Plaso log2timeline ran for 33 min ingesting to 16.5 GB storage. If
psort was invoked but produced zero JSONL rows (timeout, format
mismatch, internal error swallowed by `run_with_retry`), the
bucket-sampler has no input and emits zero events. The wrapper still
returns `exit_code=0` because the subprocess did not crash.

**Diagnostic:** add `trace.timeline.jsonl_rows_read` to the wrapper
output. If this is 0 on a live run, H1 is confirmed.

### H2: psort JSONL has rows but sampler predicates don't strike
The priority predicates (`_is_4624`, `_is_winreg_run`,
`_is_mft_timestomp`, `_is_lolbin`) look for substrings in the plaso
`message` / `data_type` / `parser` fields. If real plaso output uses a
slightly different field layout (e.g. `display_name` vs `message`, or
parser name `winevtx/win_evtx` vs `winevtx`), the predicates silently
match zero events.

**Diagnostic:** add `trace.timeline.priority_hits{family}` and
`trace.timeline.parser_deque_sizes{family}` to the wrapper output. A
priority-hits total of 0 across all families on a real run confirms H2.

### H3: sampler emits events but TimelineAgent detectors do not fire
The M6.2 detectors (`agents/timeline.py:246-268` for 4624,
`:270-296` for MFT timestomp) iterate events and check field-level
conditions. If the sampler delivers events in a shape the detectors
don't recognise (e.g. missing `datetime`, `parser`, or `message` keys),
detectors silently skip and produce no findings.

**Diagnostic:** add `trace.timeline.events_received_by_agent` and
`trace.timeline.detectors_fired` to the agent output. Non-zero events
received with zero detectors fired confirms H3.

## Investigation plan (M6.4 charter, estimated 4 h)

1. **Instrumentation (2 h).** Land `trace.timeline.*` counters above.
   No semantic change to sampler or detectors. Ship as
   `feat(sift): W-### — timeline dataflow instrumentation` (new W-ID).
2. **Diagnostic run (45 min).** Re-run DC E01 triage with the new
   trace counters. Read the numbers. One of H1/H2/H3 becomes
   unambiguous.
3. **Targeted fix (1 h).** Fix whichever layer is empty. If H1,
   investigate psort invocation or tmpdir lifecycle; if H2, align
   predicate field names with real psort output (probably by reading a
   snippet of real JSONL); if H3, normalise the sampler's output
   structure to what detectors expect.
4. **Verification (45 min).** Second DC E01 run. Expect cohit≥2 ≥ 4/7.
   Update `PHASE-M6.4-COMPLETE.md`.

## Why we're shipping PARTIAL instead of retrying now

- **Cost of a blind retry:** 34 min wall-clock + identical result with
  very high probability. Trace already shows the wrapper returns
  "ok/0 events" deterministically on this image.
- **Cost of a diagnostic rebuild + instrumented retry:** ~4 h
  instrumentation + 34 min run. Produces actionable data.
- **ADM §0.1 rule 5** (no operator prompts): the operator doesn't need
  to break this tie; the data does. Instrumentation is strictly
  dominant over retry.

## Risk of shipping PARTIAL

- **MVP demo on 2026-04-26:** the SANS SIFT hackathon internal target.
  With cohit≥2 = 1/7 and no timeline.plaso findings, the demo
  narrative leans on artifact-extract (SAM dumps, Amcache) and
  filesystem.fls (suspicious filenames) rather than timeline.
  Mitigation: the demo script (`docs/DEMO-SCRIPT.md`) already
  emphasises the Thymus read-only gate and Trinity halt behaviour, not
  raw recall numbers. Reviewing the demo script against this reality
  is a M6.4 co-item (not a blocker for the 04-26 target).
- **SANS deadline 2026-06-10:** still 7 weeks away; M6.4
  instrumentation + fix + re-run fits in the first week of that
  runway. No schedule risk at the project level.

## References

- `docs/adr/ADR-M6.3-event-window.md` — parent design decision.
- `docs/adr/ADR-W051-defer.md` — M6.2 deferral of 4624 recall.
- `docs/adr/ADR-W054-defer.md` — M6.2 deferral of MFT timestomp recall.
- `/home/admin2/.openclaw/workspace/e01-runs/M6.3-W050W051W054-cli-20260422T000337Z.json` —
  measurement artefact.
- `docs/PHASE-M6.3-COMPLETE.md` — sprint close.
- `src/agentropix_sift/mcp_server/wrappers/plaso.py:45-300` — the new
  sampler.
- `src/agentropix_sift/agents/timeline.py:246-296` — the detectors.

## Post-close update — H1 CONFIRMED + resolved (commit 9d7dd89)

**Investigation window: 2026-04-22 00:37–00:40 UTC, Architect-A.**

While the parallel docs-sync branch was writing this ADR, a concurrent
post-mortem on the `000337Z` artefact identified the actual root cause
of the `wrapper=ok + agent=0 findings` divergence:

**Silent psort failure due to unrecognised CLI flag.**

The plaso wrapper was invoking
`psort.py --storage_file <path> -o json_line -w <out>`, but plaso
20260119 on this host uses PATH as a **positional argument** and
rejects the flag form with `rc=2, unrecognized arguments:
--storage_file`. The wrapper did not check `proc2.returncode`, so the
rc=2 exit was silent — log2timeline produced the `.plaso` storage file,
psort never wrote the JSONL, `_parse_jsonl_events` saw a missing output
file and returned `[]`.

**Manual verification:**
```
$ psort.py --storage_file /tmp/plaso-debug/timeline.plaso -o json_line \
           -w /tmp/plaso-debug/out.jsonl ; echo rc=$?
psort.py: error: unrecognized arguments: --storage_file
rc=2
$ psort.py /tmp/plaso-debug/timeline.plaso -o json_line \
           -w /tmp/plaso-debug/out.jsonl ; echo rc=$?
plaso - psort version 20260119
Processing started. ... Processing completed.
rc=0
```

This maps exactly to hypothesis **H1** above. H2 and H3 are now less
likely but not yet disproven (the priority predicates and detectors
were never exercised because the JSONL was always empty).

**Fix (commit `9d7dd89`, 2026-04-22 00:41 UTC):**
- Switch to positional PATH form.
- Raise `RuntimeError(f"psort failed (rc={proc2.returncode}): ...")`
  on non-zero return so this class of silent failure cannot recur.
- Two regression tests in
  `tests/unit/test_plaso_autoscale.py::TestPsortCommandShape`
  pin (a) the command shape (no `--storage_file`, positional path
  present) and (b) rc-check raises RuntimeError.

**Secondary fix (commit `bc295a0`, 2026-04-22 00:52 UTC):** coerce
null plaso JSONL fields (e.g. `source_short: null` on ext2 filestat
rows) to empty strings so they don't trip TimelineEvent validation —
this was a latent bug that would have caused silent event drops once
psort started producing output.

**M6.4 charter adjustment:** the instrumentation plan below remains
valuable for H2/H3 disambiguation and for general observability, but
is no longer the P0 critical-path item. Re-measure recall first, then
decide whether to land the instrumentation in M6.4 as planned or defer
to M6.5.

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-04-22 | Architect-A (Crew Α, ADM) | Initial draft + accept |
| 2026-04-22 | Architect-A | H1 CONFIRMED + resolved (psort positional PATH) — commit 9d7dd89 |
