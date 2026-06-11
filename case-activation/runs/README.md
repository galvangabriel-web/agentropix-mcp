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
| [`challenge-notchitup/`](challenge-notchitup/) | MCP activation, full loop, video | Challenge "Notch It Up" RAM dump | pslist/netscan/malfind/cmdline chain |
| [`srl-2018-compromised-enterprise/`](srl-2018-compromised-enterprise/) | MCP activation only | SRL-2018 DC disk+memory | steps 1–6; full case report in [`docs/12-CASES-REPORTS/`](../../docs/12-CASES-REPORTS/) |
| [`vanko-abducted-zebrafish/`](vanko-abducted-zebrafish/) | MCP activation only | VANKO 21-segment EWF | steps 1–5; full sealed report in [`docs/12-CASES-REPORTS/vanko-report/`](../../docs/12-CASES-REPORTS/vanko-report/) |
| [`jimmy-wilson-poc/`](jimmy-wilson-poc/) | **Engine** triage PoC, video + raw logs | Jimmy Wilson E01 (NTFS disk) | 129 findings · 86 tool calls × 3 reproducible runs (2 raw + 1 recorded) |
| [`dfrws-rodeo-poc/`](dfrws-rodeo-poc/) | **Engine** triage PoC + raw log | DFRWS 2005 Rodeo USB (FAT16 dd) | 9 findings · 68 tool calls, honest-negatives case, ×2 runs |
| [`engine-smoke-sample-dd/`](engine-smoke-sample-dd/) | **Engine** smoke run | synthetic `samples/sample.dd` | the first sealed record (2026-06-09), 7 honest-negative findings |

**Conventions across all folders:**
- `step*.json` / `batch_*.json` = raw captured MCP tool outputs, unedited; empty `.err` files mean
  the captured stderr was empty (clean execution).
- Demo approvals in recorded runs are **SIMULATED examiner approval (demo only)** — in real
  casework, approval is a human HMAC hard-stop.
- Engine PoC folders carry sealed `report*.json` records; their per-run HMAC session keys are
  published by explicit operator decision (treat as burned — seals are independently
  re-verifiable, but no longer tamper-proofs).
- `reports/` subfolders hold the multi-tier report artifacts (comprehensive + executive one-pager).
