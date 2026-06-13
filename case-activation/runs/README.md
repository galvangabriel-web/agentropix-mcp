# Executed runs — recorded activations & engine PoCs

Every folder here is a **real captured execution** — either a recorded MCP activation sequence
(live `tools/call` outputs saved per step, rendered to an educational MP4) or a full
`agentropix-sift` **engine** triage PoC (sealed `report.json` machine records). Each folder has
its own README with provenance, a file-by-file table, and verbatim excerpts from the captured
outputs. Master tables (with guide cross-links): [`../INDEX.md`](../INDEX.md).

| Folder | Kind | Evidence | Headline |
|---|---|---|---|
| [`contact-me-memory/`](contact-me-memory/) | MCP activation, full loop, video | CTF "Contact Me" RAM dump | manual §3A sequence → finding → SIMULATED approval → report |
| [`amf-win-sample001/`](amf-win-sample001/) | MCP activation, full loop, video | AMF Windows memory sample | manual sequence incl. 300 s `malfind` |
| [`memdump-raw-2014/`](memdump-raw-2014/) | MCP activation, full loop, video | generic 2014 raw RAM image | manual sequence + honest `windows_info` caveat |
| [`challenge-notchitup/`](challenge-notchitup/) | MCP activation, full loop, video | Challenge "Notch It Up" RAM dump | pslist/netscan/malfind/cmdline chain; separate **engine** triage of the same image (10 findings · 60 tool calls, sealed + run.log + Thymus trail) in [the SRL-2018 submission package](../../docs/12-CASES-REPORTS/srl-2018-report/submission/AGENT-EXECUTION-LOGS-REPORT.md) |
| [`srl-2018-compromised-enterprise/`](srl-2018-compromised-enterprise/) | MCP activation only | SRL-2018 DC disk+memory | steps 1–6; full case report in [`docs/12-CASES-REPORTS/`](../../docs/12-CASES-REPORTS/); the autonomous **engine** run over the DC image (`base-dc`: 22 findings · 176 tool calls, sealed) in [the submission package](../../docs/12-CASES-REPORTS/srl-2018-report/submission/AGENT-EXECUTION-LOGS-REPORT.md) |
| [`vanko-abducted-zebrafish/`](vanko-abducted-zebrafish/) | MCP activation only | VANKO 21-segment EWF | steps 1–5; full sealed report in [`docs/12-CASES-REPORTS/vanko-report/`](../../docs/12-CASES-REPORTS/vanko-report/) |
| [`jimmy-wilson-poc/`](jimmy-wilson-poc/) | **Engine** triage PoC, video + raw logs | Jimmy Wilson E01 (NTFS disk) | 129 findings · 86 tool calls × 3 reproducible runs (2 raw + 1 recorded) |
| [`dfrws-rodeo-poc/`](dfrws-rodeo-poc/) | **Engine** triage PoC + raw log | DFRWS 2005 Rodeo USB (FAT16 dd) | 9 findings · 68 tool calls, honest-negatives case, ×2 runs |
| [`engine-smoke-sample-dd/`](engine-smoke-sample-dd/) | **Engine** smoke run | synthetic `samples/sample.dd` | the first sealed record (2026-06-09), 7 honest-negative findings |
| [`rocba/`](rocba/) | live-MCP triage + Agent-Execution Logs (req. 8) | ROCBA Win10 disk+memory (insider IP-theft) | `fls` 602,765 entries @offset 0; `get_evtx` ≥5000 EventID 4625 RDP brute-force on SRL-FORGE → DRAFT finding (MITRE T1110.003, `indexed:false` = cannot self-approve); `bulk_extractor` 5,113,600 features; honest negatives kept (carve param-bug, `report_generate case_not_found`, memory-init timeout) — see [`rocba/EXECUTION-LOG.md`](rocba/EXECUTION-LOG.md) |
| [`WINXP-LAPTOP-2005/`](WINXP-LAPTOP-2005/) | agent-execution-log run + 🎬 rendered video | Windows XP laptop (2005) | 🎬 [execution video — auto-plays (3:19, 2,389-frame animated deck)](https://galvangabriel-web.github.io/agentropix-mcp/case-activation/runs/WINXP-LAPTOP-2005/WINXP-LAPTOP-2005-video/watch.html) + [correlation report](WINXP-LAPTOP-2005/WINXP-LAPTOP-2005-video/CORRELATION-REPORT.md) + [execution-chain log](WINXP-LAPTOP-2005/WINXP-LAPTOP-2005-execution-chain.md) + [session transcript](WINXP-LAPTOP-2005/WINXP-LAPTOP-2005.session-transcript.raw.jsonl) + [video storyboard](WINXP-LAPTOP-2005/WINXP-LAPTOP-2005-video/STORYBOARD.md) + [case-close-tool patch](WINXP-LAPTOP-2005/case-close-tool.patch) |

**Conventions across all folders:**
- `step*.json` / `batch_*.json` = raw captured MCP tool outputs, unedited; empty `.err` files mean
  the captured stderr was empty (clean execution).
- Demo approvals in recorded runs are **SIMULATED examiner approval (demo only)** — in real
  casework, approval is a human HMAC hard-stop.
- Engine PoC folders carry sealed `report*.json` records; their per-run HMAC session keys are
  published by explicit operator decision (treat as burned — seals are independently
  re-verifiable, but no longer tamper-proofs).
- `reports/` subfolders hold the multi-tier report artifacts (comprehensive + executive one-pager).
