# `wazuh/` — Wazuh egress evidence captures (8 screenshots)

Playwright captures of the **operator-authorized egress** of the VANKO findings to the Wazuh
manager: the 10 examiner-approved findings in the `agentropix-findings-2026.06.08` index, two
granular finding documents, the MITRE / Threat-Hunting correlation modules, and the live read-back
of the manager's `agentropix_*` CDB IOC lists. The narrated walkthrough of these images is
[`../WAZUH-VANKO-GALLERY.md`](../WAZUH-VANKO-GALLERY.md); provenance: 10/10 findings HMAC-approved,
decision ledger seq 139, pushed 2026-06-08.

> **Privacy / sanitization note:** these are screenshots of a lab dashboard processing **fictional
> training-scenario evidence** (SANS FOR500 "Abducted Zebrafish"). They display finding metadata
> (IDs, descriptions, evidence locators) — **no raw mailbox content is shown in any capture**. The
> Wazuh manager's internal address (visible in browser chrome in some source captures) is referred
> to here only as `<WAZUH-MANAGER-IP>`.

All images are binary PNGs — described below with key facts read from the actual pixels (no byte
dumps).

## Files

| File | Type | Size | What it is |
|---|---|---|---|
| `01-login.png` | PNG 1600×1000 | 16 KB | Wazuh dashboard splash ("wazuh. Loading ...") at `https://<WAZUH-MANAGER-IP>` — proves live dashboard access at capture time |
| `02-findings-approved-10.png` | PNG 1680×1050 | 111 KB | Discover, index `agentropix-findings-*`, query `finding_id:VANKO* and status:APPROVED` → **10 hits**: `VANKO-P1-001`, `P2-001/003/004/005`, `P3-002/003/005`, `P4-003/004` (all `Jun 8, 2026 @ 21:54:43`); fields panel shows `finding_id`, `confidence`, `severity`, `hmac_seal`, `source_run_id` |
| `03-findings-lifecycle.png` | PNG 1680×1050 | 194 KB | Same index without the status filter — the full finding-document set including DRAFT-stage registration records (complete DRAFT→APPROVED audit trail, per-finding `title`/`technique` columns) |
| `04-finding-P2-001-staging.png` | PNG 1680×1050 | 142 KB | Expanded document `VANKO-P2-001` (staging): `case_id VANKO-ABDUCTED-ZEBRAFISH`, `confidence 0.88`, description "Masquerading 'defaultprinter' account was USED to stage stolen IP -- Desktop\temp.zip (2.6MB classified archive)", `evidence.locator` ($I record, `$RZQSNFO.zip == temp.zip`, 4720/4724 account-create @ 2016-06-18 20:40:54), `evidence.path` (`/$Recycle.Bin`, `Security.evtx`), `approval.*` HMAC lifecycle fields |
| `05-finding-P4-003-antiforensics.png` | PNG 1680×1050 | 145 KB | Expanded document `VANKO-P4-003` (anti-forensics): `confidence 0.85`, description "Anti-forensic destruction recovered from Shadow Copies -- SDelete prefetch deleted, defaultprinter/temp.zip wiped, Dropbox cache emptied to Recycle Bin", locator cites deleted `SDELETE.EXE-FBA93810.pf`, `temp.zip~RF9b00d6e.TMP`, `~$...Project_Nehemiah 4.docx`, **23,848 total deleted-at-snapshot entries** |
| `06-mitre-attack.png` | PNG 1680×1050 | 130 KB | MITRE ATT&CK module dashboard: top tactics **Impact** + **Defense Evasion**; techniques Stored Data Manipulated / Modify Registry / Data Destruction / File Deletion; per-agent breakdown (`Thinkpad`, `server`) |
| `07-threat-hunting.png` | PNG 1680×1050 | 128 KB | Threat Hunting module: **396 total alerts** (last 24 h), 0 level-12+ alerts, 0 auth failures/successes; alert-level evolution and top-5-agents panels (`Thinkpad`, `wazuh.manager`, `server`) |
| `08-cdb-ioc-lists-readback.png` | PNG 1100×1078 | 259 KB | Terminal capture "Wazuh Manager — agentropix_* CDB IOC lists (live read-back)" via `WazuhClient.get_cdb_list()`: `agentropix_malware_sha256` (10 keys, incl. the highlighted `b210bcd8…` = `vacation photos.7z`), `agentropix_suspect_image` (8 keys: `7za.exe`, `csrss.exe`, `install_msadvapi2.exe`, `p.exe`, `perfmonsvc64.exe`, `perfsvc.exe`, **`sdelete.exe` / `sdelete64.exe`** highlighted), `agentropix_c2_ips` (2 keys), `agentropix_suspect_process` (5 keys) — each key annotated with its source case (`WAZUH-VANKO-MERGED…`) |

## Key facts per capture (what an evaluator should verify)

- **Approval state is visible in-band.** `02` proves exactly **10** `status:APPROVED` VANKO
  findings exist in the index; `04`/`05` show the per-document `approval.status`,
  `approval.hmac_signature`, `approval.prev_doc_hash` field block — the HMAC seal travels with the
  finding into the SIEM.
- **Finding content matches the report.** The descriptions/locators in `04` and `05` are verbatim
  the evidence cited for findings P2-001 and P4-003 in
  [`../VANKO-DFIR-REPORT.md`](../VANKO-DFIR-REPORT.md) (staging via `defaultprinter`, VSS-defeated
  SDelete anti-forensics).
- **IOC round-trip is closed.** `08` reads the CDB lists **back from the manager** after the push —
  the case SHA-256 (`b210bcd8…`) and the anti-forensics tools (`sdelete.exe`/`sdelete64.exe`) are
  present and highlighted, demonstrating the IOCs are live for correlation, not just sent.
- **Correlation modules ingest the findings.** `06`/`07` show the pushed events populating the
  MITRE ATT&CK and Threat Hunting dashboards (396 alerts in the capture window).

Full files: [`01-login.png`](01-login.png) · [`02-findings-approved-10.png`](02-findings-approved-10.png) ·
[`03-findings-lifecycle.png`](03-findings-lifecycle.png) · [`04-finding-P2-001-staging.png`](04-finding-P2-001-staging.png) ·
[`05-finding-P4-003-antiforensics.png`](05-finding-P4-003-antiforensics.png) · [`06-mitre-attack.png`](06-mitre-attack.png) ·
[`07-threat-hunting.png`](07-threat-hunting.png) · [`08-cdb-ioc-lists-readback.png`](08-cdb-ioc-lists-readback.png)
