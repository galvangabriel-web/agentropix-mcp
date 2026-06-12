# VANKO — "The Case of the Abducted Zebrafish" — executed activation run (activation-only capture)

> **Provenance.** This folder is a real, live-MCP execution capture: five `agentropix` MCP calls
> (`case_init` → `case_activate` → `case_status` → `evidence_register` → `get_image_info`) run on
> **2026-06-08** (step timestamps `04:10:41`–`04:10:54` UTC, examiner `victor.galvan`) against the
> evidence set at `/cases/vanko` — a Surface 3 physical disk image (`surface_physical.E01`,
> multi-segment EWF `.E01`–`.E21`). These on-disk paths are operator-sanctioned public. VANKO is an
> **insider IP-theft case** (SANS FOR500 scenario), **not a malware intrusion**. **The capture stops
> at activation** — no analysis, finding, approval, or Wazuh push was performed. The full
> investigation lives in the sealed case report:
> [`docs/12-CASES-REPORTS/vanko-report/`](../../../docs/12-CASES-REPORTS/vanko-report/).

## What's in this folder

| File | What it is | What it shows |
|---|---|---|
| `EXECUTED-RUN.md` | Narrative transcript of the run | Scenario brief (Anthony Vanko, suspected exfil of classified zebrafish-DNA research), step table, evidence inventory, and an explicit "deliberately NOT done" scope list |
| `step1_case_init.json` | Raw `case_init` response | Case `VANKO-ABDUCTED-ZEBRAFISH` created: status `active`, severity `high`, incident type `insider-threat/ip-theft`, scope `/cases/vanko` |
| `step2_case_activate.json` | Raw `case_activate` response | Active-case pointer written to `/home/admin2/.agentropix/active_case` |
| `step3_case_status.json` | Raw `case_status` response | `active: true`, `indexer_reachable: true`, all counts 0 (fresh case) |
| `step4_evidence_register.json` | Raw `evidence_register` response | First EWF segment registered with custody SHA-256, indexed to `agentropix-evidence-2026.06.08` |
| `step5_get_image_info.json` | Raw `get_image_info` response | EWF-embedded `ewfinfo` acquisition metadata (case `20161104`, examiner Ovie Carroll) + full-image MD5/SHA1 |

## Inside the files (excerpts)

From `step1_case_init.json` — the case record as created:

```json
{
  "case_id": "VANKO-ABDUCTED-ZEBRAFISH",
  "case_name": "Vanko — The Case of the Abducted Zebrafish (FOR500)",
  …
  "examiner_id": "victor.galvan",
  "incident_type": "insider-threat/ip-theft",
  "severity": "high",
  "started_at": "2026-06-08T04:10:41.757173+00:00",
  "scope": "/cases/vanko",
  …
}
```

The incident type is recorded as `insider-threat/ip-theft` from the start — this case was never framed as an intrusion.

From `step4_evidence_register.json` — custody registration of the disk image:

```json
{
  "evidence": {
    "evidence_id": "a085d58338fdb241e8cde27d48a14955270b97d6e67ac93d6307de2c70dd42a2",
    …
    "path": "/cases/vanko/surface_physical.E01",
    "sha256": "0a44ad8d57bad44eb40a59bdaa8110b79ac019a791b8fd388f6efe09c7aa3b1c",
    "size_bytes": 2147328814,
    …
  },
  "indexed_to": "agentropix-evidence-2026.06.08",
  "indexed": true
}
```

The custody `sha256` and the 2,147,328,814-byte size cover the **first EWF segment file only** (`surface_physical.E01` of a 21-segment set), not the whole 116 GiB disk — that is what step 5 is for.

From `step5_get_image_info.json` — the EWF-embedded acquisition metadata (`ewfinfo`):

```text
Case number:		20161104
Examiner name:		Ovie Carroll
Evidence number:	20161104-HD001
Acquisition date:	Fri Nov  4 17:47:41 2016
Media size:		116 GiB (125069950976 bytes)
MD5:			4032d556cc866c23f1e797410e95603c
SHA1:			e0e72dfcef167dd358813726e82f6c235bc85ce7
```

`get_image_info` reads the full multi-segment EWF set and returns the original 2016 acquisition record. Per `EXECUTED-RUN.md`, this MD5 + SHA1 **match the FTK Imager acquisition log (`surface_physical.E01.txt`) exactly** — independent confirmation that the image is intact.

## Honest notes

- **Activation-only by design.** `EXECUTED-RUN.md` lists what was deliberately NOT done: no analysis or `record_finding` (the disk tool chain was not run), no approval (DRAFT → APPROVED is a human-only HMAC Hard-Stop), and no Wazuh push or report export.
- **Two different hashes, two different scopes.** The step-4 custody SHA-256 covers the first EWF segment file; the step-5 MD5/SHA1 are the EWF-embedded hashes of the full logical image. They answer different questions and should not be compared to each other.
- **Transcript table typo.** The step table in `EXECUTED-RUN.md` quotes `a085d583…` as the custody SHA-256; the raw `step4_evidence_register.json` shows that value is the `evidence_id`, while the actual `sha256` field is `0a44ad8d…`. The raw JSON is authoritative.
- **`get_image_info` is EWF/E01-only** — it works here because the evidence is an E01 set; it returns nothing useful on raw images.
