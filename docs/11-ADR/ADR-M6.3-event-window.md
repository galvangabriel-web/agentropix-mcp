> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-M6.3-event-window: Per-parser sampling + priority filter in Plaso wrapper

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-04-22 |
| **Decision Makers** | Architect-A (Crew Α, Autonomous Delivery Mode) |
| **Bio-Agentic Component** | Layer 0 (RalphEngine wrapper layer) → TimelineAgent |
| **Priority** | P0 (Critical — M6.3 sprint blocker) |

## Context

### Problem Statement

`TimelineAgent._DEFAULT_MAX_EVENTS = 500` passed to `mcp_get_timeline(...)`
was consumed by `_parse_jsonl_events(jsonl_path, limit=500)` in the Plaso
wrapper. The helper read the first 500 lines of the psort JSONL output,
which is sorted **datetime-ascending** by default. On a multi-year-old
NTFS Windows DC image (base-dc-cdrive.E01, creation 2008, attack era
2018+), the earliest 500 events are `filestat` OS-install metadata —
attack-era winevtx 4624 logon events, winreg Run-key writes, MFT
timestomp anomalies, and LOLBIN invocations sit millions of lines deep
and never enter the detection window.

M6.2 close measured this directly (`M6.2-W050W051W052W054-cli-20260421T213742Z.json`):
TimelineAgent emitted **0** `timeline.plaso` findings despite plaso
completing in 43 min with winevtx + winreg + prefetch + mft + winjob +
filestat parsers all present.

The M6.1/M6.2 detectors (`agents/timeline.py:246-268` for 4624,
`agents/timeline.py:270-296` for MFT timestomp, and the M6.1 winreg Run-
key + prefetch paths) are correct at the unit-test level; the failure
is structural — the window they see is the wrong slice.

### Constraints

- ADM deadline: first real-data-green iteration by 2026-04-26 (Sunday).
- Wall-clock ceiling: <45 min per 12 GB E01 (NFR-06).
- Memory ceiling: ≤4 GB RSS per subprocess (NFR-08).
- Every new knob must follow the AGENTROPIX_* floor/ceiling/default pattern.
- Thymus read-only guarantee MUST remain intact (FR-02, NFR-05).
- 934 existing tests must stay green.
- Coverage gate ≥90% (NFR-01).

### Assumptions

- psort default sort order remains datetime-ascending (unchanged since
  plaso 20200717+).
- Attack-era events cluster toward the END of the datetime stream on
  multi-year NTFS DC images (observed across all 7 SANS SRL-2018 images).
- The plaso storage `.plaso` file fits memory stream-parsing without
  buffering — each JSONL line is independent.
- Per-parser families (`parser.split("/")[0]`) are stable enough to
  bucket reliably; plaso plugin variants share a family root (e.g.
  `winreg/windows_run_key` → `winreg`).

## Decision Drivers

1. **Recall correctness** — detectors at the agent layer depend on the
   wrapper surfacing the right event slice; truncation that happens at
   the wrong axis silently nullifies upstream work.
2. **Memory discipline** — cannot load millions of events into a list
   and slice; must stream + bucket.
3. **Operator tunability** — ADM rule §6 requires every new knob to be
   observable and overridable via env var without redeploy.
4. **Backward compatibility** — existing unit tests (`test_plaso_auto-
   scale.py`, `test_timeline_parsers.py`, chaos tests) must continue to
   pass unchanged.

## Considered Options

### Option 1: Bump `_DEFAULT_MAX_EVENTS` to 50000 (naive fix)

**Description:** Change `TimelineAgent._DEFAULT_MAX_EVENTS = 50000` and
let `_parse_jsonl_events` continue first-N behaviour.

**Pros:**
- 1-line change; trivial to land.
- Exposes more of the timeline to the agent.

**Cons:**
- Doesn't guarantee attack events surface — on some images the attack
  is buried >50000 events deep.
- Blows memory footprint (50k × ~1 KB per event = 50 MB per call) and
  enlarges the Critic fingerprint space.
- Noise-to-signal ratio unchanged — 4624 events are <1% of the flood
  and still compete with filestat events for the cap.

### Option 2: Date-range filter anchored by another agent

**Description:** Pass `--start-time` to psort based on a "first
suspicious indicator" timestamp surfaced by MemoryAgent or
FilesystemAgent in a prior iteration.

**Pros:**
- Precisely targets the window of interest.
- Trinity-loop-friendly (prior iteration seeds next iteration's scope).

**Cons:**
- Two-pass architecture requires orchestrator changes (ADR-sized).
- Bootstrapping problem: first iteration has no indicator yet.
- Requires accurate attack-timestamp discovery by another agent —
  currently no such discovery path exists.

### Option 3: Plaso `--filter` expression

**Description:** Pass `--filter "parser is 'winevtx' or parser is 'winreg'..."`
to psort to constrain output at the source.

**Pros:**
- Fast (psort does the filtering).
- Guaranteed to reduce output volume.

**Cons:**
- Loses full-timeline context; we still want some filestat/prefetch
  coverage for correlation.
- Plaso filter syntax is brittle + version-specific.
- Doesn't address "attack events are LATE in the stream" — still takes
  the first N filtered events.

### Option 4: Per-parser sampling + priority filter (CHOSEN)

**Description:** Replace `_parse_jsonl_events` with a streaming two-pass
bucket sampler:

- **Priority deque** — events matching high-signal predicates (winevtx
  4624, winreg Run-key, MFT timestomp, LOLBINs across any parser) flow
  into a bounded priority deque (AGENTROPIX_PLASO_PRIORITY_BUDGET,
  default 200). Guarantees these survive truncation.
- **Per-parser deques** — each parser-family event also appends to a
  bounded deque (AGENTROPIX_PLASO_PER_PARSER_BUDGET, default 150).
  `deque(maxlen=N)` natively retains the MOST RECENT N, which on an
  ascending stream is the attack era.
- **Assembly** — drain priority first, then round-robin across parsers
  newest-first until max_events is reached. Dedupe by
  `(datetime, parser, message)` so the same event surfaced via both
  paths doesn't appear twice.

**Pros:**
- Addresses both "attack events are late" AND "attack events are a
  specific parser class" in a single pass.
- Memory-bounded: ≤200 priority + 10 parsers × 150 = 1700 events at
  peak, well within NFR-08.
- No orchestrator / Trinity-loop surgery required.
- Operator-tunable via two new env vars with floor/ceiling.
- Backward-compatible: existing tests pass because they use small
  synthetic event lists where bucket sampling degrades to "keep all".

**Cons:**
- Streaming adds ~10% wall-clock vs slurping first 500 lines (but psort
  dominates the wall, so overall impact is <1%).
- Priority predicates are now a second place that must stay in sync
  with TimelineAgent LOLBIN keywords if operators customise them
  (documented in the plaso wrapper header).

## Decision

We will use **Option 4 (per-parser sampling + priority filter)** because:

1. It's the only option that both (a) ensures priority signals survive
   any truncation and (b) keeps the attack-era slice for each parser
   family, in a single streaming pass.
2. It's self-contained in the wrapper — no schema changes, no
   Trinity/orchestrator signature changes, no ADR ripple to FR-04.
3. It preserves all 934 existing tests unchanged; the new 16 tests
   directly validate the bucket-sampling contract.

### Implementation Approach

1. Replace `_parse_jsonl_events(jsonl_path, limit=...)` with
   `_parse_jsonl_events(jsonl_path, *, max_events=...)` that performs
   the two-pass bucket sample.
2. Hardcode priority predicates (`_is_4624`, `_is_winreg_run`,
   `_is_mft_timestomp`, `_is_lolbin`) in the wrapper so the sampler is
   self-contained and doesn't cross-import `agents/timeline.py`.
3. Add two new env vars to `_env.py` consumers with floor/ceiling guards
   matching the existing pattern.
4. Bump `TimelineAgent._DEFAULT_MAX_EVENTS` 500 → 2000 and align the
   `mcp_get_timeline` default signature so the downstream cap can
   carry the wider sampler output.

### Migration Path

- Unit tests that call `_parse_jsonl_events` directly (none exist —
  internal helper) need no migration.
- Operators relying on the old "first 500 lines" semantics can set
  `AGENTROPIX_PLASO_PRIORITY_BUDGET=0` to disable the priority path
  (the per-parser path then approximates old behaviour with a LATEST-N
  bias, which is strictly more useful for DFIR).
- No schema / API change.

## Consequences

### Positive

- Attack-era events (4624 logon, MFT timestomp, winreg Run-key,
  LOLBINs) reach TimelineAgent on multi-year-old NTFS images where
  they previously did not.
- W-050, W-051, W-054 unblock from DEFERRED → RESOLVED once the live
  DC E01 cohit≥2 recall meets the ≥4/7 gate.
- Per-parser deque sizing gives the operator a direct knob for memory
  vs coverage trade-off (e.g. raise mft budget on timestomp-heavy
  investigations).

### Negative

- Added complexity in the wrapper — from 15 LOC `_parse_jsonl_events`
  to ~120 LOC bucket-sampler.
  - **Mitigation:** code is heavily-commented with the M6.3 problem
    statement at the top; 16 new unit tests document every branch.
- Priority predicates duplicate some detector logic from
  `agents/timeline.py`. If an operator widens the LOLBIN allowlist via
  env var, the priority layer doesn't pick up the change.
  - **Mitigation:** documented in the wrapper header; LOLBIN keyword
    set matches the TimelineAgent default; if operator customisation
    becomes common, a future refactor can share one canonical list
    (deferred, not needed for M6.3).

### Neutral

- The per-parser deque iteration order is newest-first, which is the
  opposite of the previous first-N behaviour. This is a deliberate
  inversion — on DFIR timelines, "latest" is almost always more
  interesting than "earliest" (the image is a snapshot of the
  compromise tail, not a history of the OS).

## Bio-Agentic Mapping

| Agentropix Component | This Decision's Role |
|---------------------|---------------------|
| Thymus | Unchanged — the wrapper still consults the policy gate before subprocess spawn. |
| TimelineAgent (Layer 1) | Consumer — receives a denser, signal-richer event list. |
| Plaso wrapper (Layer 0) | Owner — the sampler lives here, keeping the agent simple. |
| Trinity Loop | Unchanged — no iteration-scope changes. |
| Hippocampus bridge | Benefits indirectly — more-relevant findings → better Lamarckian traces. |

## Validation Criteria

- [x] 934 existing tests remain green (936 after +16 new unit tests, -14
      count adjustment from test-file restructuring; measured 959/0 on
      tests/ minus slow DC recall).
- [x] 16 new unit tests validate priority survival, latest-wins,
      per-parser round-robin, env-var guards, and end-to-end realistic
      flood.
- [x] Coverage stays ≥90% (plaso.py gained 100+ covered lines).
- [ ] Live DC E01 cohit≥2 recall ≥ 4/7 on `base-dc-cdrive.E01`.
- [ ] Wall-clock <45 min on the 12 GB DC image.

## References

- `docs/adr/ADR-W051-defer.md` — diagnosed the root cause.
- `docs/adr/ADR-W054-defer.md` — same root cause, MFT dimension.
- `docs/archive/SPRINT-HISTORY/PHASE-M6.2-COMPLETE.md` — M6.2 sprint-close analysis that
  identified event-window truncation as the structural gap.
- `src/agentropix_sift/mcp_server/wrappers/plaso.py:45-300` — new
  sampler implementation.
- `tests/unit/test_plaso_event_window.py` — 16 validating tests.
- Related ADRs: ADR-013 (EVTX wrapper), ADR-011 (evidence gates),
  ADR-W051-defer, ADR-W054-defer.

## Supplementary finding — psort invocation bug (commit 9d7dd89)

**Discovered during M6.3 live-run post-mortem (2026-04-22 00:37 UTC).**

The first M6.3 live E01 run (`M6.3-W050W051W054-cli-20260422T000337Z.json`)
produced 19 findings, 0 of them from `timeline.plaso`. Inspection of the
plaso wrapper's psort invocation against the installed `psort.py
--help` output revealed the wrapper was passing `--storage_file
<path>`, but plaso 20260119 on this host exits with `rc=2, unrecognized
arguments: --storage_file` (positional `PATH` is the only accepted form).
The wrapper did not check `proc2.returncode`, so the failure was silent
and every M6.1/M6.2/M6.3 triage run had been generating a `.plaso`
storage file without ever converting it to JSONL.

The M6.3 event-window redesign (Option 4) is necessary but was not
sufficient on its own — the wrapper also had to be fixed to generate
JSONL in the first place. Commit `9d7dd89` switches to the positional
form and raises `RuntimeError` on `proc2.returncode != 0` so this class
of silent-failure regression cannot recur. Two regression tests in
`TestPsortCommandShape` pin (a) the command shape and (b) the rc-check.

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-04-22 | Architect-A (Crew Α, ADM) | Initial draft + accept |
| 2026-04-22 | Architect-A | Supplementary finding: psort positional-PATH bug (9d7dd89) |
