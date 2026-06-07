> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-016: Courtroom Audit — High Inference Constraint + Cryptographic Sealing

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-04-25 |
| **Decision Makers** | BMAD-M8 sprint executor (Claude), Operator (gate post-Phase M8.2) |
| **Bio-Agentic Component** | Courtroom track — chain-of-custody invariants for the SIFT report |
| **Priority** | P0 — addresses the hackathon "Courtroom Problem" judging criterion (25% of the rubric) |

## Context

The hackathon's biggest barrier is the **Courtroom Problem**: if an LLM hallucinates evidence, the case is thrown out. Judges want to see proof that the AI is *only orchestrating* while deterministic court-vetted tools generate the facts.

Pre-M8.2 SIFT had the right *shape* — Trinity Loop's LLM agents (Architect, Critic) read structured Blackboard state, every Finding carries `_source`, every MCP call has `args_hash` + `exit_code` — but it was missing three concrete invariants that make the report **court-defensible**:

1. **A cryptographic seal** so the JSON can't be tampered with after the run.
2. **An evidence-image hash at session start** so the report is provably bound to specific bytes.
3. **The raw tool output captured BEFORE LLM summarisation** so a defense expert can replay the deterministic step.

This ADR establishes those invariants under the umbrella term **High Inference Constraint** (per the GTG-1002 / NOVA Protector concept the operator referenced).

## Decision

**Three load-bearing invariants. All implemented in `agentropix_sift/courtroom.py` (BMAD-M8 Phase M8.2).**

### Invariant 1 — Inference constraint declaration

The report root carries a single string field:

```python
TriageReport.inference_constraint: str = "high"
```

Schema enum: `"high" | "medium" | "low"`. The default `"high"` is correct for SIFT's design (Trinity LLM agents never directly invoke shells; every fact flows through a `@traced` MCP tool with deterministic typed output).

The field is the explicit *declaration* of design intent. It does not enforce anything by itself — but it becomes a contract the rest of the architecture must keep, and judges have a single field to point to when assessing the dimension.

### Invariant 2 — Evidence-image binding

```python
TriageReport.evidence_image_sha256: str | None
```

`courtroom.evidence_image_sha256(path)` streams the image in 1 MiB chunks and returns the hex digest. Graceful degradation rules:

- Missing path / non-file → `None`.
- Image > `AGENTROPIX_HASH_MAX_BYTES` (default 50 GB) → `None` plus a warning. Operators with multi-100 GB containers compute the digest offline and supply it via `AGENTROPIX_EVIDENCE_SHA256`.
- Hash failure (permission, I/O) → `None`.

`None` is a *legitimate* value — silent failure is a bigger courtroom risk than honest "we did not hash this image because [reason]".

### Invariant 3 — Raw-output preservation

Every `ToolCallRecord` (per-MCP-tool trace span) gains an optional field:

```python
class ToolCallRecord(TypedDict, total=False):
    ...
    raw_output: str  # bounded snapshot, capture-time pre-LLM-summarisation
```

`_trace._capture_raw_output(result)` serialises the typed Pydantic return (`model_dump_json`) and clips to `AGENTROPIX_TRACE_RAW_MAX_BYTES` (default 4 KiB; floor 256 B, ceiling 1 MiB). The capture happens *inside* the `@traced` decorator after the tool returns and **before** any LLM-side summarisation. This is the substrate a defense expert can replay.

### Invariant 4 — Cryptographic seal

```python
TriageReport.report_seal: str | None
```

`courtroom.write_sealed_report(report_dict, out_path)`:

1. `secrets.token_bytes(32)` generates a fresh per-run session key.
2. `<out>.session-key` written with mode `0o600` (POSIX user-only).
3. `seal_report(report_dict, key)` computes HMAC-SHA256 over the canonicalised JSON (`sort_keys=True, separators=(",", ":"), ensure_ascii=True`) with the seal field forced to a `"__sealed__"` sentinel.
4. The seal is embedded into `report_dict["report_seal"]`.
5. Pretty-printed JSON written to `out_path`.

Verification (`verify_seal`) recomputes the MAC the same way and uses `hmac.compare_digest` for constant-time comparison.

The *threat model* is **post-hoc tampering**, not impersonation. A long-lived KMS-backed signing key would be over-engineering — a per-run HMAC + sealed key file is the smallest primitive that makes "did anything change after the run wrote the JSON?" a deterministic yes/no.

## Architecture diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                       Trinity Loop (LLM orchestration)                 │
│                                                                        │
│   Architect.plan()  ──►  Swarm fan-out  ──►  Critic.score()            │
│        ▲                       │                  │                    │
│        │ feedback              │ MCP calls        │ halt?              │
│        │ (gaps, stable)        ▼                  ▼                    │
│        │                  ┌─────────────┐                              │
│        │                  │  @traced    │  args_hash + exit_code       │
│        │                  │  MCP tools  │  duration_ms + raw_output    │
│        │                  │             │  ──────► trace.tool_calls    │
│        │                  └─────────────┘                              │
└────────│─────────────────────────────────────────┬─────────────────────┘
         │                                         │
         │                                         ▼
   ┌─────┴───────────────────────────┐    ┌──────────────────────────┐
   │ deterministic forensic tools    │    │ courtroom envelope       │
   │ vol3, plaso, fls, regripper,    │    │                          │
   │ amcache, evtx, yara, …          │    │ • inference_constraint   │
   │                                 │    │ • evidence_image_sha256  │
   │ output is typed Pydantic        │    │ • thymus_audit (read-only│
   │ → no raw stdout to LLM          │    │   policy decisions)      │
   │ → raw_output captured pre-LLM   │    │ • report_seal (HMAC-256) │
   │   summarisation                 │    │ • <out>.session-key 0600 │
   └─────────────────────────────────┘    └──────────────────────────┘
```

## Trade-offs considered

### Option A — JOSE / JWS / JWT envelope
**Rejected.** Adds a heavyweight dependency for a single-byte-tamper-detection use case. HMAC-SHA256 over canonical JSON is the same security guarantee for this threat model.

### Option B — KMS / external signing service
**Rejected.** Local-only project (per `MEMORY.md::project_agentropix_sift`). External KMS adds network surface area and trust dependencies. Per-run HMAC keeps the trust boundary inside SIFT's evidence handling.

### Option C — Embed the session key in the report
**Rejected.** Defeats the purpose. Whoever has the key can re-seal a tampered report. Sealed key file (mode 0600) outside the report JSON is the minimum viable separation.

### Option D — Sign per-finding rather than the whole report
**Rejected for now.** Per-finding signatures double or triple report size and add overhead the M8 budget didn't allow. The current report-level seal proves "no findings were added/removed/edited after seal time" — for the post-hoc-tampering threat that's sufficient.

## Acceptance / Implementation gates

- [x] `courtroom.py` shipped with `evidence_image_sha256`, `seal_report`, `verify_seal`, `write_session_key`, `write_sealed_report`.
- [x] `TriageReport` model carries `inference_constraint`, `evidence_image_sha256`, `report_seal`.
- [x] `cli.py` calls `write_sealed_report` instead of plain JSON dump; emits the key path and image hash to stdout.
- [x] `ToolCallRecord` carries optional `raw_output` (≤4 KiB default, capped at 1 MiB).
- [x] `report.schema.json` declares all four new fields with descriptions.
- [x] 16 unit tests in `tests/unit/test_courtroom.py` covering: digest stability, missing-file None, override-via-env, seal/verify roundtrip, tamper detection (byte-level), seal independent of indent, key-file mode 0600, full write-then-verify roundtrip.

## Verification

A judge (or defense expert) verifies a sealed report as follows:

```bash
# 1. Read the report and the session key.
$ jq -r .report_seal report.json
abcd1234...

# 2. Recompute the MAC.
$ python -c "
import json, hmac, hashlib
report = json.load(open('report.json'))
key = open('report.session-key', 'rb').read()
report['report_seal'] = '__sealed__'  # canonical-form placeholder
canonical = json.dumps(report, sort_keys=True, separators=(',', ':')).encode()
print(hmac.new(key, canonical, hashlib.sha256).hexdigest())
"
# 3. Compare to the embedded seal — must match byte-for-byte.
```

If the recomputed MAC matches the embedded `report_seal`, the report has not been altered since SIFT wrote it. If they differ, *something changed*.

## References

- Oracle: `src/agentropix_sift/courtroom.py` — the helpers
- Oracle: `tests/unit/test_courtroom.py` — 16 tests
- Oracle: `docs/exec/BMAD-M8-HACKATHON-SCORECARD.md` — gap analysis
- ADR-011 — evidence-gate policy (per-agent gates run *before* the seal applies)
- ADR-015 — context engineering (progressive disclosure works with this seal because each loaded skill is referenced by name in the trace)
- `_trace.py` — `@traced` decorator captures `raw_output` per call
