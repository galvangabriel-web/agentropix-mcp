# Jimmy Wilson — full engine triage PoC (recorded run + raw logs)

> **Provenance.** Three real `agentropix-sift` engine runs against the **Jimmy Wilson** study case
> (`/cases/study case/2020JimmyWilson.E01`, NTFS disk, evidence SHA-256 `6c18f662…`), all on
> 2026-06-10/11. The third run is the one captured on video and published as the sealed
> [`report.json`](report.json); the two earlier runs are preserved unedited under [`raw/`](raw/).
> This is the self-host **engine** path (Path B) — the full `agentropix-sift` distribution, not the
> MCP-server package. All per-run HMAC session keys are published by explicit operator decision
> (treat as burned): seals are independently re-verifiable, but no longer tamper-proofs.

## What's in this folder

| File | What it is | What it shows |
|---|---|---|
| [`EXECUTED-RUN.md`](EXECUTED-RUN.md) | Narrative of the recorded session | `uv sync` → `doctor` (16 SIFT tools OK) → `run`; result table |
| [`EXECUTION-LOG.md`](EXECUTION-LOG.md) | The agent-execution-log deliverable | Tool calls with timestamps+durations, iteration-over-iteration Trinity trace, Blackboard activity |
| [`POC-RUN.mp4`](POC-RUN.mp4) | The recorded terminal session | The full run as it happened |
| [`report.json`](report.json) | Sealed machine record of the recorded run | **129 findings · 86 tool calls · 5 iterations**, status `budget_exhausted`, critic_score 1.0, seal `ff2f9e1e…` |
| [`report.audit-log.json`](report.audit-log.json) | Sealed audit-log companion | `audit_log_enabled: false` for this run — honest as captured |
| [`report.session-key`](report.session-key) | Per-run HMAC key (32 B, binary) | Re-verifies `report_seal`/`audit_log_seal` of `report.json` |
| [`blackboard-events.jsonl`](blackboard-events.jsonl) | Derived agent publish/correlation timeline | Which agent published how many findings, when |
| [`raw/`](raw/) | The two earlier, unrecorded runs — unedited | Run-to-run reproducibility of the engine on the same evidence |

### `raw/` — the earlier runs (raw logs, unedited)

| Run | Files | Window (UTC) | Result | Seal |
|---|---|---|---|---|
| #1 | `raw/jimmy.json` + `.audit-log.json` + `.session-key` | 2026-06-10 23:53 → 00:02 | 129 findings · 86 tool calls · 5 iterations | `3cc20e1a…` |
| #2 | `raw/jimmyy.json` + `.audit-log.json` + `.session-key` | 2026-06-11 00:05 → 00:16 | 129 findings · 86 tool calls · 5 iterations | `71f30934…` |
| recorded | `report.json` (this folder) | 2026-06-11 00:40 → 00:49 | 129 findings · 86 tool calls · 5 iterations | `ff2f9e1e…` |

Three independent runs on the same image produced the **same finding counts and tool-call counts**
— each sealed with its own per-run key (all three keys published; each key verifies only its own run).

## Inside the files (excerpts)

A timestomp candidate from the 111 Plaso timeline findings in `report.json`:

```json
{"_source": "timeline.plaso", "confidence": 0.7, "description": "[T1070.006 Indicator Removal: Timestomp — MFT entry shows modified-time anomaly (anti-forensics candidate)] MFT entry modified-time anomaly: NTFS:\\$MFT File reference: 4398-2 Attribute name: $STANDARD_INFORMATION Path hints: \\$RECYCLE.BIN\\S-1-5-21-…"}
```

An interactive-logon (lateral-candidate) event, parser-attributed to the EVTX source:

```json
{"_source": "timeline.plaso", "description": "[T1078 Valid Accounts — interactive logon (lateral candidate)] Logon event EventID 4624: [4624 / 0x1210] …", "evidence": "datetime=2014-02-19T17:19:42.482240+00:00 parser=winevtx …"}
```

The Blackboard trace ([`blackboard-events.jsonl`](blackboard-events.jsonl)) showing the timeline
agent landing its 111 findings near the end of the recorded run:

```json
{"ts": "2026-06-11T00:40:37.042522+00:00", "agent": "memory", "event": "publish", "detail": "1 finding(s)", "duration_ms": 0.11}
{"ts": "2026-06-11T00:49:40.886576+00:00", "agent": "timeline", "event": "publish", "detail": "111 finding(s)", …}
```

## Honest notes

- Finding mix in all three runs: 111 `timeline.plaso` + 7 `hunt.correlate` cross-agent correlations
  + honest skips/negatives (e.g. `memory.skip` — disk-only image, no RAM capture to analyze).
- Token usage was **not collected** — the LLM is the edge orchestrator; facts come from
  deterministic tools (see `EXECUTION-LOG.md` §4). Not faked after the fact.
- The audit-log companions are sealed but empty (`audit_log_enabled: false` in these runs).
