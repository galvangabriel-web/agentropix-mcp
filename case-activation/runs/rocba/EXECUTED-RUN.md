# ROCBA — Case Activation + Triage (EXECUTED)

> **LOCAL / OPERATIONAL — review before publishing.** Contains real case inventory, evidence custody
> hashes, and on-disk paths. Executed **live** against the running MCP server
> (`http://<TAILNET-HOST>:8765/mcp`) via the `agx_gearb` PATH-B autonomous driver + a corrected
> completion pass. **Date:** 2026-06-13. **Examiner:** victor.galvan. **Case:** `INC-2026-0613202023`
> (logical key `rocba`). Full machine-readable trace: [`EXECUTION-LOG.md`](EXECUTION-LOG.md) + [`logs/`](logs/).

## Scenario

**ROCBA Hackathon 2026** — a Windows 10 (Build 19042 / 20H2) host, insider-IP-theft / intrusion scenario.
Mixed evidence: a C-drive **disk** image plus a full physical-**memory** capture. Briefing:
`ROCBA-BACKGROUND.pptx`. Hypotheses from the brief: external **RDP brute-force** (MITRE **T1110.003**)
and **user-execution malware** (T1204.002). See the activation guide
[`case-activation/rocba-hackathon-2026.md`](../../rocba-hackathon-2026.md).

## Result: ROCBA triaged; RDP brute-force confirmed and recorded (DRAFT)

| # | Step | Tool | Duration | Outcome |
|---|------|------|----------|---------|
| 1 | case_init | `case_init` | 0.05s | case_id **INC-2026-0613202023**, status `active`, severity high, scope `/cases/rocba/rocba-cdrive.e01` |
| 2 | case_activate | `case_activate` | 0.02s | active-case pointer written |
| 3 | image_info | `get_image_info` | 0.33s | media **81 GiB (87,431,311,360 B)**, MD5 `5efc207c…`, SHA-1 `645dcd29…`, OS **Win 10 Build 19042**, acq. XWF 20.1 |
| 4 | evidence_register | `evidence_register` | **121.1s** | custody SHA-256 `f2eb856d6fb48e3928e6b6d388b2f116a57b735137354a7eaddca951d81b5c67` (full 23,678,691,658 B image) |
| 5 | fls (recursive) | `fls` | **177.4s** | whole-disk NTFS at **offset 0** → **602,765 filesystem entries** |
| 6 | fls (deleted) | `fls` | 122.1s | deleted-entry enumeration completed |
| 7 | bulk_extractor | `run_bulk_extractor` | — | ❌ driver param bug (`image` vs `target`); re-run corrected below |
| 8 | get_evtx (4625) | `get_evtx` | 8.7s | **≥5,000 EventID 4625** RDP logon failures (capped at `max_events=5000`, `truncated=true`), computer **SRL-FORGE**, provider Microsoft-Windows-Security-Auditing, burst ~2020-11-16T02:03Z |
| 9 | record_finding | `record_finding` | 0.0s | DRAFT finding **`rocba-rdp-bruteforce-001`** (T1110.003), `indexed:false` — **cannot self-approve** |
| 10 | report_generate | `report_generate` | — | ❌ documented `case_not_found` gotcha (DRAFT-only fresh case) — logged, not worked around |
| 11 | bulk_extractor (corrected) | `run_bulk_extractor` | **1648.5s** | ✅ re-run with `target` — **5,113,600 features** carved (truncated): url 1,352,289 · domain 1,311,633 · email 137,671 · json 763,098 · evtx_carved 32,498 · ip 260 · ccn 1,062 |

**Chain-of-custody note:** `get_image_info`'s EWF-embedded **MD5 `5efc207c…` + SHA-1 `645dcd29…`** and the
`evidence_register` full-image **SHA-256 `f2eb856d…`** match the case ground-truth (`MMLS`/`IMAGE_HASH`
audit + the activation guide) **exactly** — independent confirmation the image is intact and read-only.

## The recorded finding (grounded, DRAFT)

```
finding_id   rocba-rdp-bruteforce-001
host         SRL-FORGE
mitre_attack T1110.003 (Brute Force: Password Guessing — RDP)
confidence   0.6   severity  medium
timestamp    2020-11-16T02:03:02Z
title        External RDP brute-force: >=5000 EventID 4625 logon failures (max_events cap, truncated) on SRL-FORGE
source       /cases/rocba/rocba-cdrive.e01 (Security.evtx)   status: DRAFT (indexed:false)
```

It is recorded **only because `get_evtx` substantiated it** — no fabrication. It stays **DRAFT**: the
DRAFT → APPROVED transition is a **human-only HMAC hard-stop** (examiner sign-off), never automated.

## Honest negatives (the project's discipline, in the record)

1. **Carve param bug** — the `agx_gearb` driver passed `image` to `run_bulk_extractor`, but the live
   schema requires `target`. The step failed cleanly (checkpointed) and was re-run corrected (step 11),
   which then carved **5,113,600 features** (truncated) over the 23 GB E01 in 27.5 min.
2. **`report_generate` → `case_not_found`** — a brand-new **DRAFT-only** case returns this (the report
   index has no case documents until findings are approved), even though `case_status` finds the case.
   This is the documented Step-8 gotcha — reported as-is.
3. **Memory sequence timed out at `initialize()`** (server `500`) while the disk run was hashing the
   23 GB image (server busy). Captured in [`logs/memory/mem-run.log`](logs/memory/mem-run.log) and as the
   `status:500` row in the HTTP audit — re-run pending under lower load.

## Evidence inventory (`/cases/rocba`)

- `rocba-cdrive.e01` — Windows 10 system disk (EWF/EnCase, 23 GB container / 81 GiB media).
- `Rocba-Memory/Rocba-Memory.raw` — 19 GB raw physical-memory capture (Vol3-native).
- `ROCBA-BACKGROUND.pptx`, `questions.txt` — scenario brief. (`_work/`, `_archive/`, compressed copies
  are derived/prior output — not source evidence.)

## Deliberately NOT done

- **No approval** — DRAFT → APPROVED is the human-only HMAC examiner hard-stop; never automated. The
  recorded finding remains DRAFT (`indexed:false`).
- **No Wazuh / SIEM push** — IOC egress is operator-gated and out of scope for this triage.

## Audit artifacts

The full structured trace satisfying **Find Evil! requirement 8** is in
[`EXECUTION-LOG.md`](EXECUTION-LOG.md) (tool-execution table with timestamps + durations, server-side
per-request HTTP audit, Thymus access decisions, token-usage statement) and the [`logs/`](logs/) bundle.
