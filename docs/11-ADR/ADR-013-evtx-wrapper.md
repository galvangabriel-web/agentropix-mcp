> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-013: `mcp_get_evtx` — Windows Event Log (.evtx) wrapper

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-04-19 |
| **Decision date** | 2026-04-19 |
| **Decision Makers** | Forge Orchestrator (author), Operator (gate G-M4.2) |
| **Bio-Agentic Component** | MCP tool surface — event log parsing (detection signal source) |
| **Priority** | P1 (HIGH) — advances W-026 (part 1 of 3), progresses W-019 (wrapper count 8/15 → 9/15) |

## Context

Windows Event Logs (`.evtx`) are a primary detection signal source
during DFIR triage: Security log (4624/4625/4688), System log
(7036/7045), Application log crash events, Sysmon (channel
`Microsoft-Windows-Sysmon/Operational`). After M4.1 landed
`mcp_extract_files`, raw E01 containers can now yield `.evtx` files
onto a session tmpdir — but the SIFT MCP surface had no tool to parse
them. The Critic node could not score "lateral movement" or "persistence"
signals that only surface in Security/Sysmon, so `ArtifactAgent` was
detection-blind on the single richest log source.

W-026 (HIGH, OPEN) tracks three missing high-signal wrappers:
`evtx`, `yara`, and `bulk_extractor`. This ADR covers the first (evtx).
The other two are scheduled for M4.4 / M4.5 per the M4 scope derivation
logged in `memory/2026-04-19.md`.

### Constraints

- **Thymus read-only boundary** — same invariant as M3 / M4.1 wrappers;
  the `.evtx` target must resolve under an allowed read zone.
- **SIFT OVA toolset** — prefer a tool already shipped on the SIFT
  workstation image; avoid adding a new Python dep.
- **Deterministic parsing** — `ArtifactAgent` composes wrapper output
  into Pydantic-modelled findings; the wrapper must return structured
  records, not raw text.
- **Bounded memory** — large Security logs can exceed 100k records.
  Default caps must prevent `ArtifactAgent` from blowing the ATP budget
  on a single log.
- **Filterable at tool boundary** — the Critic-driven loop needs to
  request specific channels or event IDs cheaply (e.g. "4624 logon
  events from Security channel only").

## Decision

Ship a dual-format wrapper (`get_evtx`) that auto-detects tool output
and accepts either:

- `evtx_dump.py` — the python-evtx (Williballenthin) CLI bundled with
  SANS SIFT by default; emits a multi-record XML stream.
- `evtx_dump` — the omerbenamram/evtx Rust binary; emits the same XML
  shape by default and also supports `-o jsonl`.

Expose it via an MCP shim `mcp_get_evtx` following the M3/M4 wrapper
contract.

- **Format sniff** — the first non-blank byte in the tool's stdout is
  sampled: `<` routes through the XML parser, `{` routes through the
  JSONL parser. No format flag on the wrapper surface; operator swaps
  binaries by pointing `AGENTROPIX_EVTX_TOOL` at one or the other.
- **Binary resolution** (revised 2026-04-30, W-136 §3 row 1):
  1. `AGENTROPIX_EVTX_TOOL` wins when set (operator override).
  2. Else, prefer Rust `evtx_dump` if `shutil.which("evtx_dump")` succeeds
     (~30× faster on multi-hundred-MB channels — W-123).
  3. Else, fall back to `evtx_dump.py` (python-evtx, SIFT default).
  This closes the W-133 regression class where a fresh subprocess that
  did not inherit `scripts/start-mcp.sh`'s exported env silently used
  the slow Python parser. The `doctor` command surfaces which binary
  resolved so operators can diagnose drift.
- **Workers cap** (W-136 §4.2): `AGENTROPIX_EVTX_WORKERS` (default 6,
  floor 1, ceiling 12). Passed to the Rust binary as `--threads N`; also
  caps per-channel concurrency in the E01 dispatch path. Avoids the
  W-131-class burst-load thread storm where `--threads 0` would fan out
  one thread per core (24 here) per request.
- **JSONL force on big files** (W-136 §3 row 2): when the resolved
  binary is the Rust `evtx_dump` and the input file size exceeds
  `AGENTROPIX_EVTX_FORCE_JSONL_BYTES` (default 50 MB, floor 1 MB, ceiling
  2 GB), the wrapper passes `-o jsonl` and skips `_sniff_format`'s
  multi-GB-stdout regex scan. This is the actual root cause of the
  W-133 90 s timeout on the 245 MB DC `Security.evtx`.
- **JSONL schema validation** (W-136 §4.3): the JSONL parser tracks a
  run-length counter of malformed-JSON / missing-`Event.System`-envelope
  lines; if it crosses `_SCHEMA_VIOLATION_THRESHOLD` without emitting a
  single event, raises `EvtxOutputSchemaError` instead of silently
  returning `event_count=0`. Catches the W-123 `_sniff_format` regression
  class on a future upstream-binary version bump.
- **Concurrent channel extraction** (W-136 §3 row 3): the E01 dispatch
  path now parses every extracted channel via `asyncio.gather` with a
  bounded semaphore (`AGENTROPIX_EVTX_WORKERS`). Six default channels
  parsing in parallel cuts wall-clock by ~6× on the DC E01.
- **Binary trust pin** (W-136 §4.1): SHA-256 of `evtx_dump`,
  `yara`, and `bulk_extractor` are pinned in
  `src/agentropix_sift/mcp_server/_tool_pins.py`. Verified at startup;
  mismatch logs WARNING by default or aborts when
  `AGENTROPIX_VERIFY_TOOL_PINS=strict`. Pin source-of-truth:
  `docs/EXTERNAL-TOOL-PINS.md`.
- **Filter semantics**: `channels` (case-insensitive set) and
  `event_ids` applied *after* parsing — neither tool exposes a native
  filter, and post-parse filtering is cheap compared to I/O.
- **Truncation contract**: `max_events` (env-overridable via
  `AGENTROPIX_EVTX_MAX_EVENTS`, default 1000, ceiling 100_000) bounds
  the returned event list. When the cap trips, `EvtxReport.truncated =
  True` so callers can widen filters instead of silently missing data.
- **Timeout**: `AGENTROPIX_EVTX_TIMEOUT` (default 180s, floor 5, ceiling
  3600). Parser is killed with `proc.kill()` on expiry; re-raised as
  `TimeoutError` for uniform error handling with the other M3/M4
  wrappers.
- **`raw` preservation**: each `EvtxEvent.raw` keeps the first 2000
  chars of the per-record XML (or serialised JSON) so downstream
  agents can re-parse payloads (logon type, target user, process
  command line) without another subprocess round-trip.
- **Error surface**: same contract as every other wrapper —
  `FileNotFoundError`, `RuntimeError`, `TimeoutError` on the wrapper
  side, translated to `ToolError(tool="get_evtx", error=...)` at the
  MCP boundary by `mcp_get_evtx`.

### Alternatives considered

- **`python-evtx` only** — pure-Python, no extra binary. Rejected as
  the *sole* backend: ≥40× slower than the Rust binary on large
  Security logs. Kept as default because it is pre-installed on SIFT
  and no new dep is required.
- **`evtx_dump` (Rust) only** — fastest, but not installed on a vanilla
  SIFT OVA. Rejected as the *sole* backend for the same reason ADR-012
  rejected libewf-python: assumes a host-side install the operator did
  not commit to. Supported via the same env var when available.
- **Volatility3 `windows.evtscan`** — only useful against memory images,
  not against on-disk `.evtx` files extracted by `mcp_extract_files`.
  Solves a different problem.
- **`Log Parser` / `xsv` style CSV export** — `evtx_dump -o csv` loses
  the nested `EventData` fields that matter for detection; JSONL keeps
  them under the `raw` field so downstream YARA / correlation passes
  can still see the original structure.

## Consequences

### Positive

- `ArtifactAgent` can now surface login / logoff / process-creation
  signals on raw E01 evidence end-to-end.
- Wrapper count advances from 8/15 to 9/15 against the M3 target
  (W-019).
- W-026 partial resolution logged (evtx done; yara + bulk_extractor
  remain).
- The JSONL-per-line streaming pattern is reusable for the M4.5
  `bulk_extractor` wrapper (matching output shape).

### Negative

- Depends on an OS-supplied binary (`evtx_dump`) — adds an implicit
  "SIFT OVA or compatible host" assumption. Mitigated by `_resolve_tool`
  raising `RuntimeError("evtx_dump not found")` at call time, which the
  MCP boundary surfaces as `ToolError` (not a crash).
- Filters applied post-parse mean we always pay the full JSONL parse
  cost even for narrow queries. Acceptable given typical log sizes;
  revisit if a sub-ms filter latency becomes a requirement.

### Rollback plan

Remove `src/agentropix_sift/mcp_server/wrappers/evtx.py`, drop the
`mcp_get_evtx` shim from `mcp_server/server.py`, and revert
`tests/unit/test_evtx.py`. No other consumer depends on the symbol
yet — `ArtifactAgent` integration (`_extract_evtx_and_parse()`) lands in
a follow-up phase, not M4.2.

## Acceptance criteria

- [x] `get_evtx()` returns `EvtxReport` with ≥1 event for a synthetic
      JSONL payload.
- [x] Thymus read-zone violation returns `ToolError` before invoking
      `evtx_dump`.
- [x] `max_events` cap sets `truncated=True` on overflow.
- [x] `channels=` / `event_ids=` filter the returned list (case
      insensitive channel match).
- [x] Timeout kills the subprocess and raises `TimeoutError`.
- [x] Unit coverage = 45 tests (29 JSONL/extract/MCP + 16 XML/sniff/
      dispatch); quality gates green (ruff check 0, ruff format clean,
      pytest 490 unit + 9 integration pass).

## Related

- ADR-011 (Evidence Gates) — Thymus boundary, unchanged.
- ADR-012 (`mcp_extract_files`) — produced the `.evtx` files this
  wrapper consumes.
- W-019 (Wrappers < 15), W-026 (YARA/evtx/bulk_extractor missing).
- Phase M4.2 completion artefact: `docs/archive/SPRINT-HISTORY/PHASE-M4.2-COMPLETE.md`.
