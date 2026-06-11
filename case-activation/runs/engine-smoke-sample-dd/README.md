# Engine smoke run — `samples/sample.dd` (the first sealed PoC record)

> **Provenance.** The earliest preserved `agentropix-sift` engine run: 2026-06-09, against the
> repo's own synthetic test image `samples/sample.dd` (evidence SHA-256 `459ea50d…`). **Not a
> case** — a smoke test proving the engine pipeline end-to-end (plan → agents → Critic →
> sealed report) before pointing it at real evidence. Published raw and unedited. The per-run
> HMAC session key is published by explicit operator decision (treat as burned).

## What's in this folder

| File | What it is | What it shows |
|---|---|---|
| [`report1.json`](report1.json) | Sealed machine record | **7 findings · 72 tool calls · 5 iterations** in ~71 s, status `budget_exhausted`, critic_score 1.0, seal `31142f21…` |
| [`report1.audit-log.json`](report1.audit-log.json) | Sealed audit-log companion | `audit_log_enabled: false` — honest as captured |
| [`report1.session-key`](report1.session-key) | Per-run HMAC key (32 B, binary) | Re-verifies the seals of `report1.json` |

## Inside the files (excerpts)

All 7 findings are infrastructure attestations and **honest negatives** — exactly what a tiny
synthetic image should produce. The agents say so instead of inventing detections:

```json
{"_source": "memory.skip", "description": "MemoryAgent skipped: image is not a memory dump (disk-only). Volatility plugins require RAM capture; T1055 dis…"}
```

A real tool failure, recorded as a finding rather than hidden:

```json
{"_source": "discovery.null_session_baseline.error", "description": "NullSessionBaselineAgent failed to read Security.evtx: evtx_dump failed (rc=1): Error: Failed to open evtx fil…"}
```

And the YARA rule-bundle attestation that pins which signature set the run used:

```json
{"_source": "yara_forge.bundle_active", "description": "YARA Forge bundle active: tag=20260505 sha256=87ee463c13d49084…"}
```

## Honest notes

- `samples/sample.dd` has no Windows artifacts, so the EVTX/registry-oriented agents error or
  skip — those errors are first-class findings in the sealed record, not suppressed.
- This run predates the case PoCs in the sibling folders
  ([`dfrws-rodeo-poc/`](../dfrws-rodeo-poc/), [`jimmy-wilson-poc/`](../jimmy-wilson-poc/)); the
  same honest-negatives discipline carries through all of them.
