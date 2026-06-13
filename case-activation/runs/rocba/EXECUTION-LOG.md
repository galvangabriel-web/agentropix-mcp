# ROCBA — Agent Execution Logs (audit bundle)

> **Find Evil! requirement 8 — Agent Execution Logs.** Structured, timestamped tool-execution logs for the ROCBA live-MCP run. This is a **single-agent / tool-sequence** run (the `agx_gearb` PATH-B driver sequences MCP tool calls), so the matching evidence is *tool execution logs with timestamps* (below) plus the server-side per-request audit. Executed against the live MCP (`http://<TAILNET-HOST>:8765/mcp`). Examiner `victor.galvan`.

- **Run window:** `2026-06-13T20:20:23Z` → `2026-06-13T20:33:56Z`
- **Disk session_id:** `a7b33b7486bd404db17e5cde1af9cbd1` (image `/cases/rocba/rocba-cdrive.e01`, offset 0)
- **MCP requests (server audit):** 31 · **total tool runtime (client-measured):** 2078.1s · **real errors (status not in 200/202):** 1
- **Driver steps ok:** 6/7

## Token usage (stated honestly)

The deterministic engine collects **no LLM token-usage metrics — by design**: it is a token-blind tool executor and token accounting belongs to the MCP client / provider (see [`observability-and-integrity-notes.md` §2](../../../docs/07-sdlc-ops/observability-and-integrity-notes.md)). The engine-side telemetry that DOES exist — per-tool **`duration_ms`** and **request/response bytes** — is captured below from the server HTTP audit.

## 1. Tool execution sequence (driver, with timestamps + durations)

| # | Step | Tool | Start (UTC) | Duration | Result |
|---|------|------|-------------|----------|--------|
| 1 | `01_case_init` | `case_init` | 2026-06-13T20:20:23Z | 0.0s | ✅ ok |
| 2 | `02_case_activate` | `case_activate` | 2026-06-13T20:20:23Z | 0.0s | ✅ ok |
| 3 | `03_image_info` | `get_image_info` | 2026-06-13T20:20:23Z | 0.3s | ✅ ok |
| 4 | `04_evidence_register` | `evidence_register` | 2026-06-13T20:20:23Z | 121.1s | ✅ ok |
| 5 | `05_fls_recursive` | `fls` | 2026-06-13T20:22:24Z | 177.4s | ✅ ok |
| 6 | `06_fls_deleted` | `fls` | 2026-06-13T20:25:29Z | 122.1s | ✅ ok |
| 7 | `07_bulk_extractor` | `run_bulk_extractor` | 2026-06-13T20:27:31Z | 0.0s | ❌ FAIL — run_bulk_extractor: missing required params ['target'] (live schema) |
| 8 | `07b_bulk_extractor` | `run_bulk_extractor` | 2026-06-13T20:30:53Z | 1648.5s | ✅ ok |
| 9 | `09_get_evtx_4625` | `get_evtx` | 2026-06-13T20:30:44Z | 8.7s | ✅ ok |
| 10 | `10_record_finding` | `record_finding` | 2026-06-13T20:30:53Z | 0.0s | ✅ ok |
| 11 | `10b_record_finding` | `record_finding` |  | 0.0s | ✅ ok |
| 12 | `11_report_generate` | `report_generate` | 2026-06-13T20:30:53Z | 0.0s | ❌ FAIL — StepFail: report_generate: in-result error: case_not_found: no documents for cas |
| 13 | `11b_case_status` | `case_status` |  | 0.0s | ✅ ok |

## 2. Server-side MCP HTTP audit (authoritative per-request log)

Full JSONL: [`logs/mcp-http-audit.jsonl`](logs/mcp-http-audit.jsonl) — every MCP request with `timestamp`, `duration_ms`, `request_id`, `session_id`, `req_bytes`/`resp_bytes`. Sample (first + last 3):

```json
{"timestamp": "2026-06-13T20:20:23Z", "token_hash": "4fdfe97d0d270aa4", "method": "POST", "path": "/mcp", "status": 200, "duration_ms": 3.6, "client_ip": "100.85.162.82", "request_id": "d81b9ae7786c5d83", "session_id": null, "user_agent": "Python-urllib/3.12", "req_bytes": "171", "resp_bytes": null}
{"timestamp": "2026-06-13T20:33:56Z", "token_hash": "4fdfe97d0d270aa4", "method": "POST", "path": "/mcp", "status": 202, "duration_ms": 0.9, "client_ip": "100.85.162.82", "request_id": "13ad8d8dcc2db4b7", "session_id": "f9c9037c01fe4cbd88d4fe040ca03ab8", "user_agent": "Python-urllib/3.12", "req_bytes": "57", "resp_bytes": "0"}
{"timestamp": "2026-06-13T20:33:56Z", "token_hash": "4fdfe97d0d270aa4", "method": "POST", "path": "/mcp", "status": 200, "duration_ms": 1.5, "client_ip": "100.85.162.82", "request_id": "50d426aa515f8e7b", "session_id": "f9c9037c01fe4cbd88d4fe040ca03ab8", "user_agent": "Python-urllib/3.12", "req_bytes": "51", "resp_bytes": null}
{"timestamp": "2026-06-13T20:33:56Z", "token_hash": "4fdfe97d0d270aa4", "method": "POST", "path": "/mcp", "status": 200, "duration_ms": 1.9, "client_ip": "100.85.162.82", "request_id": "26d093aaffd74b16", "session_id": "f9c9037c01fe4cbd88d4fe040ca03ab8", "user_agent": "Python-urllib/3.12", "req_bytes": "839", "resp_bytes": null}
```

## 3. Thymus access decisions (read-only evidence gate)

Captured 4 `Thymus ALLOW/REJECT` decisions from the server log → [`logs/thymus-access.log`](logs/thymus-access.log). Every evidence read is policy-checked before any byte is opened; `check_write` is unconditionally rejected (no write tool exists).

## 4. Honest negatives

- **Memory sequence:** failed at `initialize()` with a socket timeout / server `500` while the disk run was hashing the 23 GB image (server busy). Captured in [`logs/memory/mem-run.log`](logs/memory/mem-run.log) and visible as the `status:500` row in the HTTP audit — logged as an honest negative, re-run pending.
- **Error responses (status not 200/202):** 1 — `500@2026-06-13T20:22:24Z` (the `500` is the memory-init failure above).
- **`report_generate`** returned the documented `case_not_found` gotcha for a brand-new DRAFT-only case (`case_status` finds the case, but the report index has no case documents until findings are approved) — logged as-is, not worked around.

## 5. Files in this bundle

| Path | What |
|------|------|
| `logs/disk-driver/NN_*.json` | per-step driver checkpoints (args + result) |
| `logs/disk-driver/SUMMARY.json` | driver step summary (ok/elapsed per step) |
| `logs/disk-driver/driver-run.log` | timestamped driver log |
| `logs/mcp-http-audit.jsonl` | server-side per-request audit (the authoritative trace) |
| `logs/thymus-access.log` | Thymus read-only-gate ALLOW/REJECT decisions |
| `logs/memory/` | memory-sequence checkpoints + log (incl. honest-negative timeout) |

