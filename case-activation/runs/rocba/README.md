# ROCBA — executed live-MCP triage run (with full agent-execution logs)

> **Provenance.** A real, live-MCP execution capture for the **ROCBA Hackathon 2026** case (Windows 10
> insider-IP-theft / intrusion). Run **2026-06-13** against the evidence at `/cases/rocba`
> (`rocba-cdrive.e01` 23 GB E01 + `Rocba-Memory.raw` 19 GB) via the `agx_gearb` PATH-B autonomous driver
> plus a corrected completion pass, examiner `victor.galvan`, case `INC-2026-0613202023`. On-disk paths
> are operator-sanctioned public (see [`case-activation/`](../../) policy). The run **stops at DRAFT** —
> no approval (human-only HMAC hard-stop) and no Wazuh push were performed. Activation guide:
> [`../../rocba-hackathon-2026.md`](../../rocba-hackathon-2026.md).

## What's in this folder

| File | What it is | What it shows |
|---|---|---|
| `EXECUTED-RUN.md` | Narrative transcript | Scenario, step table, the grounded DRAFT finding, honest negatives, evidence inventory |
| `EXECUTION-LOG.md` | **Agent-execution logs (Find Evil! req. 8)** | Tool-execution table (timestamps + durations), server-side per-request HTTP audit, Thymus access decisions, honest token-usage statement |
| `collect_logs.py` | Re-runnable harvester | Rebuilds `EXECUTION-LOG.md` + `logs/` from the live sources (driver checkpoints, server audit, Thymus log) |
| `logs/disk-driver/` | Per-step driver checkpoints + `SUMMARY.json` + timestamped `driver-run.log` | The disk tool sequence (case_init → fls), args + raw results |
| `logs/mcp-http-audit.jsonl` | Server-side per-request audit | Every MCP call: `timestamp`, `duration_ms`, `request_id`, `session_id`, `req/resp bytes` |
| `logs/thymus-access.log` | Read-only-gate decisions | `Thymus ALLOW/REJECT` — every evidence read policy-checked before any byte is opened |
| `logs/memory/` | Memory-sequence checkpoints + log | Volatility chain attempt, incl. the honest-negative `initialize()` timeout |
| `engine-run/AGENT-BLACKBOARD.md` | **Trinity-engine run — agent ↔ blackboard comms** | The full 13-agent swarm publishing to the shared blackboard (21 publishes), the 5-iteration plan-shrink (13 → 2 agents), 351 findings / 509 tool calls — how the agents communicate in the backend |
| `engine-run/blackboard-events.jsonl` · `report.json` · `report.audit-log.json` | Engine artifacts | Derived agent-publish log, the (trimmed) sealed report with `iterations[]`, and the audit log |

## Headline results (real, grounded)

- **Image integrity verified:** EWF MD5 `5efc207c…` / SHA-1 `645dcd29…` + full-image SHA-256 `f2eb856d…`
  match the case ground-truth exactly.
- **602,765 filesystem entries** walked from the whole-disk NTFS at **offset 0** (`fls`, 177 s).
- **≥5,000 EventID 4625 RDP brute-force failures** on `SRL-FORGE` (`get_evtx`) → **DRAFT finding
  `rocba-rdp-bruteforce-001`** (MITRE **T1110.003**), recorded only because the evidence substantiated it.
- **Honest negatives kept on the record:** a driver carve param-bug (re-run corrected), the documented
  `report_generate` `case_not_found` gotcha, and a memory-init timeout under load.

## Reproduce / refresh the logs

```bash
python3 collect_logs.py   # re-harvests EXECUTION-LOG.md + logs/ from the live log sources
```
