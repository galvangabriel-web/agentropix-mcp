# SRL-2018 Compromised Enterprise — executed activation run (activation-only capture)

> **Provenance.** This folder is a real, live-MCP execution capture: six `agentropix` MCP calls
> (`case_init` → `case_activate` → `case_status` → `evidence_register` ×2 → `get_image_info`) run on
> **2026-06-07** (step timestamps `18:16:27`–`18:17:55` UTC, examiner `victor.galvan`) against the
> evidence set at `/cases/SRL-2018` — specifically `base-dc-cdrive.E01` (domain-controller C-drive,
> EWF/E01) and `base-dc-memory.img` (DC RAM dump). These on-disk paths are operator-sanctioned
> public. **The capture stops at activation** — before any analysis, finding, approval, or report
> step. The full investigation (254 MCP actions, 12 examiner-approved findings) is written up in the
> sealed case report: [`docs/12-CASES-REPORTS/srl-2018-report/`](../../../docs/12-CASES-REPORTS/srl-2018-report/).

## What's in this folder

| File | What it is | What it shows |
|---|---|---|
| `EXECUTED-RUN.md` | Narrative transcript of the run | Step table for the 6 activation calls, plus a summary of the subsequent full investigation and its caveats |
| `step1_case_init.json` | Raw `case_init` response | Case `SRL-2018-COMPROMISED-ENTERPRISE` created: status `active`, severity `high`, incident type `intrusion/apt-c2`, scope `/cases/SRL-2018` |
| `step2_case_activate.json` | Raw `case_activate` response | Active-case pointer written to `/home/admin2/.agentropix/active_case` |
| `step3_case_status.json` | Raw `case_status` response | `active: true`, `indexer_reachable: true`, all counts 0 (fresh case) |
| `step4_evidence_register_dc_disk.json` | Raw `evidence_register` response (DC disk) | `base-dc-cdrive.E01` custody SHA-256 + size, indexed to `agentropix-evidence-2026.06.07` |
| `step5_evidence_register_dc_mem.json` | Raw `evidence_register` response (DC memory) | `base-dc-memory.img` custody SHA-256, 5,368,709,120 B, indexed |
| `step6_get_image_info_dc.json` | Raw `get_image_info` response | EWF-embedded `ewfinfo` acquisition metadata + MD5/SHA1 for the E01 |
| `step1.err` … `step6.err` | Captured stderr per step (all 0 bytes) | Every call completed without stderr output |

## Inside the files (excerpts)

From `step1_case_init.json` — the case record as created:

```json
{"case_id":"SRL-2018-COMPROMISED-ENTERPRISE","case_name":"SRL-2018 Compromised Enterprise Network",…"status":"active","examiner_id":"victor.galvan","incident_type":"intrusion/apt-c2","severity":"high","started_at":"2026-06-07T18:16:27.437817+00:00",…"scope":"/cases/SRL-2018",…}
```

One call yields a fully attributed case record — examiner, incident type, severity, scope directory — timestamped to the microsecond in UTC.

From `step4_evidence_register_dc_disk.json` — chain-of-custody registration of the DC disk image:

```json
{"evidence":{"evidence_id":"ec7d675e86fbde507ab9be2b09b655bcad7ce1d1a66447aa75f1799f649385fa",…"path":"/cases/SRL-2018/base-dc-cdrive.E01",…"sha256":"e2b9cf0cb6759fd079f45fa903d80bde602160ff969c969c6f0cd704965b31b1","size_bytes":12325692793,…},"indexed_to":"agentropix-evidence-2026.06.07","indexed":true,"error":""}
```

The custody SHA-256 and byte size are of the **E01 container file** (12,325,692,793 B); the response also confirms the record was indexed for later search.

From `step6_get_image_info_dc.json` — the EWF-embedded acquisition metadata (`ewfinfo`):

```text
Case number:		20180905-001
Examiner name:		Clint Barton
Notes:			Acquired over network via F-Response
Acquisition date:	Fri Sep  7 21:13:10 2018
Media size:		33 GiB (36110860288 bytes)
MD5:			e18b450127de04afb3211faa456ada27
```

The original 2018 acquisition details (in-scenario examiner, FTK Imager via F-Response) are read out of the EWF header itself. Note the **media** size (36,110,860,288 B of raw disk) is larger than the E01 file registered in step 4 — container vs. logical media.

## Honest notes

- **Activation-only capture.** The step JSONs here cover only `case_init` → `evidence_register` → `get_image_info`. The full investigation that followed (2026-06-07/08) was a separate 254-action session whose raw logs are kept local; its published form is the sealed report linked above.
- **`get_image_info` is EWF/E01-only.** It was run against `base-dc-cdrive.E01` and returned rich metadata; it returns nothing useful on raw images like `base-dc-memory.img` — which is why there is no step for it.
- Per `EXECUTED-RUN.md`: the `42.112.153.164` "C2 IP" circulating in the scenario was an **operator eval injection**, excluded from the investigation; several memory images were **smeared** (non-atomic acquisition), degrading in-memory plugins; and DRAFT → APPROVED remained a **human-only HMAC Hard-Stop** throughout — the agent never self-approved.
