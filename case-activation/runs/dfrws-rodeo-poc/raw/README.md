# Raw run log — the first DFRWS Rodeo engine run (unedited)

> **Provenance.** The first of the two Rodeo runs, executed 2026-06-10 23:48 → 23:49 UTC —
> four minutes before the published one ([`../report.json`](../report.json)). Produced by one
> invocation of `uv run agentropix-sift run /cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd -o rodeo.json`;
> the engine emits the same per-run **triplet** as every run: sealed report, sealed audit-log
> companion, and the 32-byte HMAC session key that computed both seals.

## Overview of the files

| File | What it is | How it was produced | Why it matters |
|---|---|---|---|
| [`rodeo.json`](rodeo.json) | Run #1 sealed report | `agentropix-sift run … -o rodeo.json` | 9 findings · 68 tool calls · 5 iterations — **identical** to the published run #2 |
| [`rodeo.audit-log.json`](rodeo.audit-log.json) | Run #1 sealed audit-log companion | Engine-written alongside the report | Sealed record that audit-logging was off (`audit_log_seal` `d5991354…`) |
| [`rodeo.session-key`](rodeo.session-key) | Run #1 HMAC key (32 B, binary) | Generated per-run; normally kept off-repo | Re-verifies run #1's seal `e3c8d7b7…` — and only run #1's |

Two runs minutes apart on the same FAT16 image (evidence SHA-256 `ce550424…`) produced the same
9-finding, 68-tool-call outcome — the raw first run is the reproducibility receipt for the
published second one.

## Read a piece of each file

**`rodeo.json` → an honest negative as a first-class finding.** A 2005 FAT16 USB stick has
nothing for a YARA file-hunt to scan, and the agent says so instead of inventing a detection:

```json
{"_source": "yara_hunt.empty", "confidence": 0.2, "description": "YARAHuntAgent found no scannable files under /cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd", "evidence": "scan_root=/cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd", …}
```

**`rodeo.json` → the tool-call trace.** Every agent step is timestamped with a duration and a
result summary — the run is replayable from the trace alone:

```json
{"tool": "agent.memory", "timestamp": "2026-06-10T23:48:42.464385+00:00", "duration_ms": 0.14, "result_summary": "1 finding(s)"}
```

**`rodeo.audit-log.json`.** Same 222-byte sealed-empty shape as every run with audit-logging off
(`audit_log_enabled: false`, zero entries, its own `audit_log_seal`) — a sealed negative, not a
missing file.

**`rodeo.session-key`.** Raw 32-byte binary key, published by explicit operator decision (treat
as burned): it makes run #1's seals independently checkable, and equally re-sealable — a
verification/demo artifact, not a tamper-proof.

## Honest notes

- This is the **honest-negatives case** end to end: 8 of 9 findings are explicit skips, empties,
  or recorded tool errors on a low-signal image — see the run-level
  [`../README.md`](../README.md) for the full breakdown.
- Nothing post-processed: byte-for-byte what the engine wrote.
