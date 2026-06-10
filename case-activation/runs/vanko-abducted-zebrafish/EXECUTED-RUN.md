# VANKO — Case Activation (EXECUTED)

> **LOCAL / OPERATIONAL — review before publishing.** Contains real case inventory + evidence custody
> hashes + on-disk paths. Executed live against the running MCP server (`http://<TAILNET-HOST>:8765/mcp`)
> via `drivers/mcp_call.py`. **Date:** 2026-06-08. **Examiner:** victor.galvan.

## Scenario

SANS **FOR500 — "The Case of the Abducted Zebrafish."** **Anthony Vanko**, a biochemical
engineer at Stark Enterprises' DC R&D facility, is suspected of **intellectual-property / trade-secret
theft** — classified zebrafish-DNA and cell-regeneration research surfaced on a Chinese university file
share (posted ~June 22–23 2016). On **June 30 2016** the JARVIS monitoring AI flagged a large transfer
from the StarkResearch server (`\StarkResearch\Level 5–8 Classified\`) to Vanko's workstation and
suspended his account. Evidence: a **Surface 3 physical disk image** (FTK Imager; case `20161104`).

## Result: VANKO is now the ACTIVE case

`~/.agentropix/active_case` → **`VANKO-ABDUCTED-ZEBRAFISH`**

| Step | Tool | Outcome |
|---|---|---|
| 1 | `case_init` | case_id **VANKO-ABDUCTED-ZEBRAFISH**, status `active`, severity high, type `insider-threat/ip-theft`, scope `/cases/vanko` |
| 2 | `case_activate` | pointer written to `~/.agentropix/active_case` |
| 3 | `case_status` | **active: true · indexer_reachable: true** (fresh case — 0 findings/iocs/evidence/approvals) |
| 4 | `evidence_register` | `surface_physical.E01` → custody SHA-256 `a085d58338fdb241e8cde27d48a14955270b97d6e67ac93d6307de2c70dd42a2` (first EWF segment, 2,147,328,814 B), indexed → `agentropix-evidence-2026.06.08` |
| 5 | `get_image_info` | EWF set: media **116 GiB (125,069,950,976 B)**, MD5 `4032d556cc866c23f1e797410e95603c`, SHA1 `e0e72dfcef167dd358813726e82f6c235bc85ce7` |

Per-step JSON responses: `step1_case_init.json` … `step5_get_image_info.json` (this dir).

**Chain-of-custody note:** `get_image_info`'s EWF-embedded **MD5 + SHA1 match the FTK Imager acquisition
metadata** (`surface_physical.E01.txt`, examiner Ovie Carroll, acquired 2016-11-04) **exactly** —
independent confirmation the image is intact. (The Step-4 custody SHA-256 is of the **first EWF segment
file**; Step-5 validates the **full logical image** against the embedded hashes.)

## Evidence inventory (`/cases/vanko`)

- `surface_physical.E01`–`.E21` — multi-segment EWF physical image (Samsung MDGAGC, 244,277,248 sectors).
- `vanko-c-drive.CYLR.7z` — CYLR triage collection (C: artifacts).
- `Vanko Student Scenario_D01_01.docx` / `resume.txt` — scenario brief.

## Deliberately NOT done (scope = activation only)

- **No analysis / `record_finding`** — disk tool chain (`get_partitions`/`fls`/`extract_files`/`get_registry`/
  `get_evtx`/`get_mftecmd`/`get_recmd`) not yet run.
- **No approval** — DRAFT → APPROVED is a **human-only HMAC Hard-Stop** (examiner sign-off); never automated.
- **No Wazuh push / report export** — egress + curation, out of scope for "activate".

## To start analysis on the now-active case

Drive the per-image disk chain (resolves to the active case): `get_partitions` / `parse_gpt` →
`fls` / `extract_files` → `get_registry` (SOFTWARE/SYSTEM/NTUSER: USB, network, RecentDocs, ShellBags) →
`get_evtx` (logons, USB, file access) → `get_mftecmd` / `get_recmd` / `get_amcache` (exfil timeline:
file copies from `\StarkResearch\Level 5–8 Classified\`, USB/cloud staging, browser uploads to the CN share).
