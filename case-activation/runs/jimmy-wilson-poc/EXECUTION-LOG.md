# Agent Execution Log — Jimmy Wilson PoC

> **Section: case-activation/runs.** Structured execution logs for the autonomous triage of
> `2020JimmyWilson.E01` (NTFS disk). The video is [`POC-RUN.mp4`](POC-RUN.mp4); the sealed
> machine record is [`report.json`](report.json) + [`report.audit-log.json`](report.audit-log.json).
> This page extracts the three views a reviewer needs: **tool execution (with timestamps)**,
> **iteration-over-iteration traces**, and **agent / Blackboard activity**. The richer
> evaluator-facing **Agent Execution Logs gold report** — two further engine runs (SRL-2018
> `base-dc` + Challenge_NotchItUp) with `file:json-path -> value` citations, timestamped handoff
> graphs, and raw `run.log` + Thymus audit trails — is at
> [docs/12-CASES-REPORTS/srl-2018-report/submission/](../../../docs/12-CASES-REPORTS/srl-2018-report/submission/AGENT-EXECUTION-LOGS-REPORT.md).

## Run header

| Field | Value |
|---|---|
| Image | `/cases/study case/2020JimmyWilson.E01` |
| Evidence SHA-256 | `6c18f662744d55e2769d9510f6173f04dab668c42b67ef27b675d22e628b4ed5` |
| Status | `budget_exhausted` · iterations 5/5 · critic_score 1.0 |
| Duration | 552s (9.2 min) |
| Findings · Tool calls | **129** findings · **86** tool calls |
| Report seal (HMAC) | `ff2f9e1e77d3465bcf061f4739de2865…` · audit-log seal `3758da6b1f024570a38c4056ea858018…` |
| Inference constraint | `high` |

## 1 · Iteration-over-iteration trace (persistent loop — how the approach changed)

The Trinity Loop's Architect re-plans each iteration; the Critic marks agents **stable** (no new findings) and they are **dropped** from the next plan. Watch the plan shrink as the swarm converges — iteration 1 runs the full roster, then only the agents still finding new evidence are re-run, until the convergence fingerprint halts it.

| Iter | Agents planned | Plan | Dropped | Critic score | Halt? |
|---|---|---|---|---|---|
| 1 | 13 | memory, timeline, filesystem, artifact +9 | 0 | 1.0 | False |
| 2 | 2 | discovery, mail | 11 | 1.0 | False |
| 3 | 2 | discovery, mail | 11 | 1.0 | False |
| 4 | 2 | discovery, mail | 11 | 1.0 | False |
| 5 | 2 | discovery, mail | 11 | 1.0 | False |

## 2 · Tool execution log (timestamps + durations)

All **86** tool/agent invocations are recorded in `report.json` → `trace.tool_calls[]` as `{tool, timestamp, duration_ms, result_summary}`. First 18 shown:

| # | Timestamp (UTC) | Tool / agent | ms | Result |
|---|---|---|---|---|
| 1 | 00:40:37.042 | `agent.memory` | 0.1 | 1 finding(s) |
| 2 | 00:49:40.886 | `agent.timeline` | 543844.1 | 111 finding(s) |
| 3 | 00:49:38.784 | `mcp.get_timeline` | 541730.8 | ok |
| 4 | 00:49:38.940 | `mcp.extract_files.ifind` | 145.6 | miss /Windows/System32/winevt/Logs/Security.ev |
| 5 | 00:49:39.086 | `mcp.extract_files.ifind` | 145.6 | miss /Windows/System32/winevt/Logs/System.evtx |
| 6 | 00:49:39.233 | `mcp.extract_files.ifind` | 147.3 | miss /Windows/System32/winevt/Logs/Application |
| 7 | 00:49:39.588 | `mcp.extract_files.ifind` | 355.0 | miss /Windows/System32/winevt/Logs/Microsoft-W |
| 8 | 00:49:39.857 | `mcp.extract_files.ifind` | 268.6 | miss /Windows/System32/winevt/Logs/Microsoft-W |
| 9 | 00:49:40.003 | `mcp.extract_files.ifind` | 146.4 | miss /Windows/System32/winevt/Logs/Microsoft-W |
| 10 | 00:49:40.151 | `mcp.extract_files.ifind` | 146.8 | miss /Windows/System32/config/SecEvent.Evt |
| 11 | 00:49:40.301 | `mcp.extract_files.ifind` | 149.9 | miss /Windows/System32/config/SysEvent.Evt |
| 12 | 00:49:40.448 | `mcp.extract_files.ifind` | 147.0 | miss /Windows/System32/config/AppEvent.Evt |
| 13 | 00:49:40.594 | `mcp.extract_files.ifind` | 145.8 | miss /WINDOWS/system32/config/SecEvent.Evt |
| 14 | 00:49:40.739 | `mcp.extract_files.ifind` | 145.6 | miss /WINDOWS/system32/config/SysEvent.Evt |
| 15 | 00:49:40.884 | `mcp.extract_files.ifind` | 144.5 | miss /WINDOWS/system32/config/AppEvent.Evt |
| 16 | 00:49:40.884 | `trace.timeline.counters` | 0.0 | jsonl_rows=510498 priority_hits=35735 events_r |
| 17 | 00:49:41.036 | `agent.filesystem` | 149.4 | 1 finding(s) |
| 18 | 00:49:41.035 | `mcp.fls` | 149.2 | ERROR: fls failed (rc=1): Cannot determine fil |

*(+68 more in `report.json`.)*

## 3 · Agent / Blackboard activity (multi-agent)

The 13-agent swarm coordinates over a shared **Blackboard** (each agent `publish()`es Findings; the HuntAgent raises cross-source **correlations** at quorum). A derived, timestamped event log is in [`blackboard-events.jsonl`](blackboard-events.jsonl). Findings by agent:

| Agent | Findings |
|---|---|
| `timeline` | 111 |
| `hunt` | 7 |
| `yara_hunt` | 2 |
| `t1546_008_accessibility_ifeo_hijack` | 2 |
| `memory` | 1 |
| `filesystem` | 1 |
| `artifact` | 1 |
| `null_session_baseline` | 1 |
| `injection_detector` | 1 |
| `t1059_001_iex_loopback_c2` | 1 |
| `t1071_001_svchost_outbound_http` | 1 |

**MITRE ATT&CK coverage** (top): `T1070.006`×62, `T1059`×29, `T1055`×13, `T1547.001`×6, `T1078`×1, `T1087.002`×1, `T1059.001`×1, `T1071.001`×1.

**Timeline priority hits** (TimelineAgent over 510,498 Plaso rows): `4624`=1080, `winreg_run`=19, `mft_timestomp`=32176, `lolbin`=2396, `appdata_staging`=64.

## 4 · Token-usage metrics — honest negative

**Not collected, by design.** Agentropix-SIFT keeps the LLM at the edge as an *orchestrator* (`inference_constraint: high (LLM is orchestrator; facts from MCP tools)`); every fact in this run came from a deterministic SIFT tool, not the model. The engine is therefore **uninstrumented for token usage** — there is no token count to report, and inventing one would be dishonest. Rationale and the broader integrity limits are in [`docs/07-sdlc-ops/observability-and-integrity-notes.md`](../../../docs/07-sdlc-ops/observability-and-integrity-notes.md).

---
*Generated from the sealed `report.json`. The per-run HMAC session key is published alongside it ([`report.session-key`](report.session-key), explicit operator decision — treat as burned): the seals are now independently re-verifiable, at the cost of the key also being able to re-seal a modified report.*
