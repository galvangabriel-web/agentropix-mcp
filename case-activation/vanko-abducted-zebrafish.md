# Case Activation Guide — VANKO "The Case of the Abducted Zebrafish" (FOR500)

> **LOCAL ONLY — real case inventory.** This file lives under
> `/home/admin2/docu_agentro/case-activation/` (tracked, but holds real evidence paths + custody
> hashes — scrub before the repo goes public). The MCP endpoint is shown as the tailnet placeholder
> `http://<TAILNET-HOST>:8765/mcp` — never paste a raw internal IP or the bearer token here.
>
> Procedure source-of-truth: `/home/admin2/agentropix-sift/docs/tools/END-USER-CASE-GUIDE.md`
> (steps 0→8). House style + dual-audience (🖥️ command / 💬 prompt) + numbered playbooks mirror
> `/home/admin2/docu_agentro/docs/01-overview/user-guide.md`. Canonical numbers cite
> `/home/admin2/docu_agentro/.crew/facts.md` (`mcp_tool_count=71`, `test_count=4464`, 16 SIFT wrappers).
> A full sealed forensic report for this case lives at
> `/home/admin2/docu_agentro/docs/12-CASES-REPORTS/vanko-report/`; a captured **activation** run lives at
> [`runs/vanko-abducted-zebrafish/EXECUTED-RUN.md`](./runs/vanko-abducted-zebrafish/EXECUTED-RUN.md).

---

## 1. Identification header

| Field | Value |
|---|---|
| **Case name** | VANKO — "The Case of the Abducted Zebrafish" (SANS FOR500 scenario) |
| **One-line description** | Insider IP-theft: Anthony Vanko, a Stark Enterprises biochemical engineer, exfiltrated classified zebrafish-DNA / cell-regeneration trade secrets to foreign buyer channels (China + Russia). **Not a malware intrusion** — valid credentials, signed admin tools, a masquerade account, USB + cloud channels, then anti-forensics defeated by Volume Shadow Copies. |
| **Evidence type** | **Disk** (physical-disk EWF acquisition of a Microsoft Surface 3) |
| **Image file(s)** | `/cases/vanko/surface_physical.E01` (EWF, primary segment) · `.E02`–`.E21` (20 continuation segments) |
| **Format** | EWF / Expert Witness (`File format: FTK Imager`, `Software version used: ADI2.9.0.13`, compression `deflate`/no compression) — verified by `file` as *EWF/Expert Witness/EnCase image file format* on every segment. |
| **Size** | E01 = 2,147,328,814 B (2.0 GiB on disk); 21 segments total ≈ **42 G** on disk. Logical media (decoded physical disk) = **116 GiB / 125,069,950,976 bytes** (244,277,248 sectors × 512 B). |
| **Integrity** | EWF-verified sound. EWF-embedded **MD5 `4032d556cc866c23f1e797410e95603c`** and **SHA1 `e0e72dfcef167dd358813726e82f6c235bc85ce7`** match the FTK Imager acquisition log (`surface_physical.E01.txt`) exactly — independent confirmation the image is intact. |
| **Suggested `case_id` slug** | **`VANKO-ABDUCTED-ZEBRAFISH`** (matches `^[A-Za-z0-9._-]{1,128}$`: no spaces, no slashes). |
| **OS / scenario** | **Windows** (Microsoft Surface 3, hostname `STARKSURFACE`; subject profile `C:\Users\PC User`, MS account `anthony.vanko`). Drive Model **Samsung MDGAGC** (SN `e65f5f86`), SCSI, 119,276 MB. Acquired `Fri Nov 04 2016` by examiner **Ovie Carroll**, FTK Imager case number **20161104**, evidence **20161104-HD001**, description "Surface 3", notes "Live Physical". Scenario: trade-secret exfiltration flagged by the JARVIS monitoring AI on 2016-06-30. |

### Other artifacts in `/cases/vanko/` (not the primary disk image)

- `vanko-c-drive.CYLR.7z` (525 M) — **CyLR triage collection** of the C: drive (live artifacts: registry, event logs, $MFT, browser/cloud caches) — fast-triage companion to the full disk.
- `Vanko Student Scenario_D01_01.docx` / `resume.txt` — the **scenario brief** (players, tasking, JARVIS tip-off; the readable `resume.txt` is the de-formatted brief).
- `surface_physical.d01` (484 K) / `.E01.adcf` (140 K) — FTK Imager **custody log / AD container metadata** (sidecar, not evidence content).
- `VANKO.zip` (41 G, stored/uncompressed) — a **bundle copy** of the above; the loose `surface_physical.E0*` segments are the canonical evidence — prefer them over re-extracting the zip.

### Recommended path + tool chain (disk evidence)

This is a **disk** image, so the **disk/artifacts** chain applies (Volatility memory plugins do **not** — there
is no standalone `.raw`/`.img`/`.001` memory dump in this case). The case **hinges on Volume Shadow
Copies**: the actor secure-deleted (SDelete) the originals, but VSS snapshots (2016-10-14 / 11-04)
preserved the deleted artifacts — VSS recovery is the load-bearing step here, not an optional one.

1. **Pre-flight / custody** — `doctor` (binaries present) → `ewfverify` (byte-intact) → `ewfinfo` /
   `get_image_info` (acquisition metadata; confirm MD5 `4032d556…` / SHA1 `e0e72dfc…`).
2. **Partition** — `get_partitions` / `parse_gpt` to resolve the **Windows NTFS partition** start sector on
   this physical disk. That offset is load-bearing for every filesystem tool (GOTCHA B2) — carry it forward;
   don't assume `63`.
3. **Volume Shadow Copies** — enumerate + mount VSS (libvshadow) **first**; the deleted/wiped artifacts
   (temp.zip, Dropbox folder, SDelete prefetch, `Project_Nehemiah` lock) live in the snapshots, not the live FS.
4. **Filesystem / MFT** — `fls` (resolved offset) recursive live + `deleted_only` (T1070.004 deletion review) →
   `get_mftecmd` for copy-signatures and `$Recycle.Bin` `$I`/`$R` records (the staged archives).
5. **Registry / execution / event-log artifacts** — `extract_files` → `get_registry`
   (SAM: masquerade `defaultprinter` account; SYSTEM USBSTOR: USB serials; NTUSER TypedPaths
   `\\STARK-FILESERVE`, RecentDocs, ShellBags) → `get_evtx` (Security.evtx 4720/4724 account-create, logons)
   → `get_amcache` / `get_shimcache` / `get_prefetch` (7-Zip, SDelete, FTK Imager, Tor; deleted `SDELETE.EXE-*.pf`).
6. **Cloud / egress corroboration** — `get_srum` (SRUM network egress bytes — Dropbox + OneDrive exfil paths).
7. **IOC carving / YARA** — `run_bulk_extractor` (allowlisted `out_dir`) for emails / domains
   (`nina_kwai@qq.com`, `mmerr001@gmail.com`, `im.cas.cn`) → `scan_yara` (0 matches is the clean signature).
8. **Findings → approval → report** — `record_finding` (DRAFT) → human approval in the portal →
   `report_generate`.

> **Win10-era artifact specifics (NOT XP):** use **`get_evtx`** (Vista+ `.evtx`, NOT `get_evt`);
> **`get_amcache`** IS applicable (Win7+). No "identify the OS" step is needed on a disk image —
> `get_image_info` reads the EWF metadata directly.
>
> **Memory chain — not applicable here.** `get_pslist` / `get_netscan` / `get_malfind` / `build_process_tree`
> (Volatility) are for memory-image cases (SRL-2015/SRL-2018/rocba). This case found **no implant, no C2,
> no injection** (the only YARA "family" hits were generic memory false positives) — it is an insider
> data-theft, so the memory-malware chain is out of scope.

---

## 2. Instantiated procedure — template steps 0→8 with this case's real values

> 🖥️ = exact command / MCP call · 💬 = plain-language prompt to a Claude session with the
> `agentropix-sift` MCP attached. Both hit the same deterministic tool.

### Step 0 — Before you start (pre-flight + custody)

> **🖥️ Expert:**
> ```bash
> uv run agentropix-sift doctor                          # expect: All tools available.
> ewfverify /cases/vanko/surface_physical.E01            # expect: SUCCESS, MD5 4032d556…
> ewfinfo  /cases/vanko/surface_physical.E01             # acquisition metadata
> ```
> **💬 End-user:** *"Check my Agentropix forensic environment is ready, then verify the integrity of the
> Vanko surface_physical E01 image and show me who acquired it and what OS it is."*

Expected: 16-wrapper toolchain resolves `All tools available.`; `ewfverify` → `SUCCESS` with stored MD5
== computed MD5 == `4032d556cc866c23f1e797410e95603c`; `ewfinfo` → case `20161104`, examiner
`Ovie Carroll`, description `Surface 3`, acquired 2016-11-04, media `116 GiB`. (`ewfverify` reads the whole
E01–E21 chain — you point it at the `.E01` only.)

### Step 1 — Pick evidence and choose a `case_id` slug

Evidence is already under `/cases/vanko/`. Slug: **`VANKO-ABDUCTED-ZEBRAFISH`**. Prefer the loose
`surface_physical.E0*` segments over the 41 G `VANKO.zip` bundle (same data); the `.CYLR.7z` is a
triage companion, not the primary image.

### Step 2 — Activate (register) the case — `case_init`

> **🖥️ Expert (MCP call):**
> ```text
> case_init {
>   "case_name":     "Vanko — The Case of the Abducted Zebrafish (FOR500)",
>   "examiner_id":   "victor.galvan",
>   "case_id":       "VANKO-ABDUCTED-ZEBRAFISH",
>   "case_dir":      "/cases/vanko",
>   "description":   "Anthony Vanko (Stark Enterprises biochemical engineer) suspected of exfiltrating classified zebrafish DNA / cell-regeneration research to foreign buyer channels (JARVIS-detected, June 2016). Surface 3 physical disk image.",
>   "incident_type": "insider-threat/ip-theft",
>   "severity":      "high",
>   "scope":         "/cases/vanko",
>   "tags":          ["vanko","for500","insider-threat","ip-theft","zebrafish","stark"]
> }
> ```
> **💬 End-user:** *"Open a new high-severity case `VANKO-ABDUCTED-ZEBRAFISH` for the Vanko Surface 3 disk
> image (FOR500 zebrafish IP-theft scenario), examiner victor.galvan, evidence in /cases/vanko, and make
> it active."*

`case_init` writes the active-case pointer first, then upserts the record. **Idempotent on `case_id`** —
re-running the same slug updates, never duplicates. (Validated: the captured run wrote the active-case
pointer `~/.agentropix/active_case` → `VANKO-ABDUCTED-ZEBRAFISH`.)

### Step 3 — Confirm it's active — `case_status`

> **🖥️ Expert:** `case_status { }` (active pointer) or `case_status { "case_id":"VANKO-ABDUCTED-ZEBRAFISH" }`
> **💬 End-user:** *"Is the Vanko case active and is the indexer reachable?"*

Expected: `active: true`, `indexer_reachable: true` (a fresh case shows `0` findings/iocs/evidence/approvals).
If you skipped activation, pass an explicit `case_id` to later tools (or run
`case_activate { "case_id":"VANKO-ABDUCTED-ZEBRAFISH" }`).

### Step 4 — Register evidence (SHA-256 chain of custody) — `evidence_register`

> **🖥️ Expert (MCP call):**
> ```text
> evidence_register {
>   "path":        "/cases/vanko/surface_physical.E01",
>   "description": "Surface 3 physical disk image (multi-segment EWF, FTK Imager; case 20161104, evidence 20161104-HD001)",
>   "examiner_id": "victor.galvan"
> }
> ```
> **💬 End-user:** *"Register the Vanko E01 image as evidence in this case and give me its SHA-256 custody
> hash."*

Expected (validated capture, 2026-06-08): content **SHA-256
`0a44ad8d57bad44eb40a59bdaa8110b79ac019a791b8fd388f6efe09c7aa3b1c`**, `size_bytes 2147328814` (the first
EWF segment file on disk, ≈2.0 GiB), `evidence_id a085d583…`, `indexed: true` → `agentropix-evidence-2026.06.08`.
Confirm media metadata in-band with `get_image_info { "image":"/cases/vanko/surface_physical.E01" }` →
media_size `116 GiB (125069950976 bytes)`, MD5 `4032d556…`, SHA1 `e0e72dfc…`. (The two sizes differ on
purpose: 2.0 GiB = the on-disk EWF segment container; 116 GiB = the logical decoded physical disk. The
Step-4 custody SHA-256 is of the **first EWF segment file**; Step-5 validates the **full logical image**
against the EWF-embedded hashes, which match the FTK Imager acquisition log.)

### Step 5 — Analyze the evidence (disk chain)

> **🖥️ Expert (MCP calls):**
> ```text
> get_partitions { "image":"/cases/vanko/surface_physical.E01" }       # resolve Windows NTFS start sector
> #   (mount/enumerate Volume Shadow Copies FIRST — the wiped artifacts live in the snapshots)
> fls  { "image":"...E01", "offset":<ntfs_start>, "recursive":true }                       # live listing
> fls  { "image":"...E01", "offset":<ntfs_start>, "recursive":true, "deleted_only":true }  # T1070.004
> get_mftecmd { "image":"...E01", "offset":<ntfs_start> }              # copy-signatures + $Recycle.Bin $I/$R
> extract_files { "image":"...E01", "offset":<ntfs_start>, "paths":["<hive paths>"], "dest":"/tmp/agentropix-sift-vanko-hives" }
> get_registry { ... } ; get_evtx { ... } ; get_amcache { ... } ; get_shimcache { ... } ; get_prefetch { ... }
> get_srum { ... }                                                     # SRUM egress bytes (cloud exfil)
> run_bulk_extractor { "target":"...E01", "out_dir":"/tmp/agentropix-sift-vanko-be", "max_features":1000 }
> scan_yara { "target":"...E01", "rules":["/cases/yara-rules/local/pf_smoketest.yar"], "max_matches":200 }
> ```
> **💬 End-user:** *"Investigate the Vanko disk: find the Windows partition, recover anything in the Volume
> Shadow Copies, list deleted files, pull the registry hives and Security event log, check SRUM for cloud
> uploads, and carve out the email/domain indicators. It's a Windows Surface, insider data-theft — no
> malware expected."*

Expected (grounded in the sealed report): the masquerade local account **`defaultprinter`** created
`2016-06-18 20:40:54 UTC` (Security.evtx EventID 4720 record_id 19669 + 4724); a 2.6 MB classified archive
`defaultprinter\Desktop\temp.zip` and a 1.9 GB local Dropbox folder in `$Recycle.Bin`; SDelete / 7-Zip /
FTK Imager / Tor execution in Amcache/Prefetch; SRUM egress to Dropbox (acct `984347879`) + OneDrive; USB
serials `5650959F`/`C83A6C7B`/`8C059ED1`; carved buyer-channel emails `nina_kwai@qq.com` (China) and
`mmerr001@gmail.com` (Russia). `bulk_extractor` must write to an **allowlisted** `out_dir` (GOTCHA B3 —
under `/tmp/agentropix-sift-*`, `/cases/`, `/mnt/`, `/media/`, `/evidence/`). `scan_yara` → `match_count 0`
is the clean-scan success signature (no malware family — consistent with an insider-theft, not an intrusion).

### Step 6 — Record findings — `record_finding` (DRAFT-gated)

> **🖥️ Expert (MCP call):**
> ```text
> record_finding { "finding": {
>   "finding_id":      "vanko-p1-001",
>   "host":            "STARKSURFACE",
>   "mitre_attack":    "T1136.001",
>   "confidence":      0.75,
>   "timestamp":       "2016-06-18T20:40:54Z",
>   "severity":        "high",
>   "title":           "Masquerading local account 'defaultprinter' created by 'PC User' at start of exfil window",
>   "ioc_value":       "defaultprinter",
>   "ioc_type":        "account",
>   "source_artifact": "/Windows/System32/winevt/Logs/Security.evtx (EventID 4720 record_id 19669)"
> } }
> ```
> **💬 End-user:** *"Record a high-severity finding for the masquerade 'defaultprinter' account created at
> the start of the exfil window, mapped to MITRE T1136.001, citing the Security.evtx 4720 record."*

`record_finding` defaults to `dry_run=True` (preview only). To persist call with `dry_run=False` **and**
a valid `mutation_token`. **Required fields:** `finding_id` (non-empty — GOTCHA B4), `host`,
`mitre_attack`, `confidence` (0.0–1.0), `timestamp`. Coherence: `severity:high` needs `confidence ≥ 0.70`
(`0.75` ✓), `critical` needs `≥ 0.85`. The finding lands **DRAFT** (`indexed:false`) — the engine/LLM
cannot self-approve. (This is the real confirmed finding `VANKO-P1-001` from the sealed
`confirmed-findings.json`; the case has **10 confirmed of 19**, 9 refuted by the false-positive gate.)

### Step 7 — Approve (examiner gate — human-only)

> **🖥️ Expert (in-band attestation):**
> ```text
> approve_finding { "finding_id":"vanko-p1-001", "approver_id":"victor.galvan", "password":"<examiner pw>" }
> ```
> **💬 End-user:** you do this **yourself** in the browser portal — no plain-language shortcut, by design.
> Portal: **`https://siftworkstation.taile7c9ca.ts.net:8443/`** (or local `http://127.0.0.1:8800/`).
> Set From=`DRAFT`, To=`APPROVED`, enter the approver password, Sign & Submit.

**Hard stop.** Examiner crypto sign-off is a human-only, HMAC challenge-response decision. Only the
configured `AGENTROPIX_APPROVER_USER` is accepted; approvals are append-only (correct with `REVOKED`,
never delete). DRAFT → APPROVED is what makes findings surface in the report.

### Step 8 — Report & (optional) push IOCs

> **🖥️ Expert:** `report_generate { "profile":"full", "case_id":"VANKO-ABDUCTED-ZEBRAFISH" }`
> **💬 End-user:** *"Generate the full report for the Vanko case."*

`approved_finding_count` stays `0` until Step 7 approval (working as designed). A brand-new DRAFT-only
case can return `case_not_found` until there is indexed state (register evidence and/or approve a
finding, then re-generate). Optional Phase 8: curate IOCs (buyer-channel emails, USB serials, Dropbox
acct) → mint an `egt_` mutation token → `wazuh_index_findings { dry_run:true }` then live. **Never push
the raw carve** — curate, dedup, tier-tag, attach provenance first; push an **additive union** so other
cases' IOCs in the shared `agentropix_*` CDB lists are not wiped.

---

## 3. Activate & start — prompt sequences

Both lanes hit the **same 71-tool deterministic engine** (`{{ref:CANONICAL_FACTS#mcp_tool_count}}`,
backed by 4464 tests) and reach the same sealed result. Each operator action shows the 🖥️ command
equivalent.

### Manual sequence (ask one focused question per step; inspect each answer before the next)

1. 💬 *"Check my Agentropix forensic environment is ready — are all the forensic tools installed?"*
   🖥️ `uv run agentropix-sift doctor`
   **Expect:** each backing binary `OK <path>` (16 SIFT wrappers + `icat`/`strings`), ending `All tools available.`

2. 💬 *"Verify the integrity of the Vanko E01 image — does its stored hash match?"*
   🖥️ `ewfverify /cases/vanko/surface_physical.E01`
   **Expect:** `SUCCESS`, stored MD5 == computed MD5 == `4032d556cc866c23f1e797410e95603c`.

3. 💬 *"Show me the acquisition details — who acquired it, when, and what OS?"*
   🖥️ `ewfinfo /cases/vanko/surface_physical.E01`
   **Expect:** case `20161104`, examiner `Ovie Carroll`, evidence `20161104-HD001`, acquired `Fri Nov 04 2016`, description `Surface 3`, media `116 GiB`.

4. 💬 *"How many Agentropix forensic tools are available right now?"*
   🖥️ MCP `health`
   **Expect:** `status:"ok"` with a live `tool_count` (canonical `71`; trust the live number, not the banner).

5. 💬 *"Open a new high-severity case `VANKO-ABDUCTED-ZEBRAFISH` for the Vanko Surface 3 image (FOR500 zebrafish IP-theft), examiner victor.galvan, evidence in /cases/vanko, and make it active."*
   🖥️ MCP `case_init {…}` then `case_activate { "case_id":"VANKO-ABDUCTED-ZEBRAFISH" }`
   **Expect:** the `case_id` echoed, status `active`, active-case pointer written.

6. 💬 *"Is the case active and is the indexer reachable?"*
   🖥️ MCP `case_status {}`
   **Expect:** `active:true`, `indexer_reachable:true`.

7. 💬 *"Register the Vanko E01 image as evidence and give me its SHA-256 custody hash."*
   🖥️ MCP `evidence_register { "path":"/cases/vanko/surface_physical.E01", … }`
   **Expect:** content SHA-256 `0a44ad8d…`, `size_bytes 2147328814`, `indexed:true`, bound to the active case.

8. 💬 *"What does Agentropix report about this image's media size and hashes?"*
   🖥️ MCP `get_image_info { "image":"…E01" }`
   **Expect:** media_size `116 GiB (125069950976 bytes)`, MD5 `4032d556…`, SHA1 `e0e72dfc…` (match the FTK Imager log).

9. 💬 *"What's the partition layout, and where does the Windows NTFS partition start?"*
   🖥️ MCP `get_partitions { "image":"…E01" }` (GPT physical disk → also `parse_gpt`)
   **Expect:** the Windows NTFS partition slot + its start sector (carried forward as the `fls`/MFT offset — GOTCHA B2; don't assume 63).

10. 💬 *"Recover anything in the Volume Shadow Copies, then list all files and just the deleted ones."*
    🖥️ MCP enumerate/mount VSS (libvshadow) → `fls { offset:<ntfs_start>, recursive:true }` then `… deleted_only:true`
    **Expect:** the wiped artifacts (temp.zip, the 1.9 GB Dropbox folder, SDelete prefetch) surface from the snapshots, not the live FS.

11. 💬 *"Pull the registry hives and the Security event log — show me account creations, USB devices, and the network shares this user typed."*
    🖥️ MCP `extract_files {…}` → `get_registry` (SAM/SYSTEM/NTUSER) / `get_evtx`
    **Expect:** masquerade `defaultprinter` account (4720/4724 @ 2016-06-18 20:40:54), USBSTOR serials, NTUSER TypedPaths `\\STARK-FILESERVE`.

12. 💬 *"Check SRUM for large cloud uploads, and pull execution history — did 7-Zip, SDelete, or Tor run?"*
    🖥️ MCP `get_srum` → `get_amcache` / `get_shimcache` / `get_prefetch`
    **Expect:** SRUM egress to Dropbox/OneDrive; 7-Zip / SDelete / FTK Imager / Tor execution; deleted `SDELETE.EXE-*.pf`.

13. 💬 *"Carve out all the indicators — emails, domains, IPs, URLs — from the image, then run a YARA scan."*
    🖥️ MCP `run_bulk_extractor { target:"…E01", out_dir:"/tmp/agentropix-sift-vanko-be" }` → `scan_yara {…}`
    **Expect:** buyer-channel emails `nina_kwai@qq.com` / `mmerr001@gmail.com`, domain `im.cas.cn`; `scan_yara` `match_count 0` (no malware family — clean by design for an insider case).

14. 💬 *"Record a high-severity finding for the masquerade 'defaultprinter' account, mapped to MITRE T1136.001, citing the Security.evtx 4720 record."*
    🖥️ MCP `record_finding { finding:{ finding_id:"vanko-p1-001", … } }`
    **Expect:** a valid finding shaped (with `finding_id` — GOTCHA B4) lands `DRAFT` (`indexed:false`); cannot self-approve.

15. 💬 *"Which findings are waiting for my approval and what are their IDs?"*
    🖥️ open portal `https://siftworkstation.taile7c9ca.ts.net:8443/` → approve (or MCP `approve_finding {…}`)
    **Expect:** the DRAFT findings listed (e.g. `vanko-p1-001`); you sign off yourself in the browser — no plain-language approval shortcut.

16. 💬 *"Generate the full report for this case, then verify its seal."*
    🖥️ MCP `report_generate { profile:"full", case_id:"VANKO-ABDUCTED-ZEBRAFISH" }` → `uv run python scripts/verify_seal.py <out>.json`
    **Expect:** `report_id` + section counts; `approved_finding_count` reflects approvals; seal verifies intact (HMAC-SHA256, `evidence_image_sha256`-bound).

### Autonomous sequence (launch driver → monitor → approve → report)

1. 💬 *"You are a DFIR analyst with the Agentropix MCP. Investigate case `VANKO-ABDUCTED-ZEBRAFISH` on image `/cases/vanko/surface_physical.E01`. Run the full SIFT disk sequence (acquisition → examination → analysis → findings), staging findings as DRAFT. Resolve the Windows NTFS offset with `get_partitions` (don't assume 63); enumerate Volume Shadow Copies and recover deleted artifacts from the snapshots. It's a Windows Surface insider data-theft — use `get_evtx`/`get_amcache`, check `get_srum` for cloud egress, and DON'T run the Volatility memory chain (no malware expected). Write `bulk_extractor` `out_dir` under `/tmp/agentropix-sift-vanko`. Do NOT approve findings. Finish by generating the full report."*
   🖥️ Expert detached driver (token from ENV, case_key positional):
   ```bash
   AGENTROPIX_MCP_AUTH_TOKEN="<BEARER_TOKEN>" \
     setsid nohup bash -c "python3 /home/admin2/.openclaw/workspace/drivers/agx_gearb.py vanko > run.log 2>&1" </dev/null >/dev/null 2>&1 &
   disown
   ```
   **Expect:** the agent walks `case_init`→`case_activate`→`evidence_register`→`get_image_info`→`get_partitions`→VSS→`fls` live+deleted→registry/evtx/amcache/srum artifacts→`run_bulk_extractor`→`record_finding × N` (DRAFT)→`report_generate{full}`, stopping before approval. (Launch DETACHED — GOTCHA B5.)

2. 💬 *"How's the investigation going — which steps are done?"*
   🖥️ `tail -f run.log` and read `/home/admin2/.openclaw/workspace/drivers/gearB/vanko/SUMMARY.json`
   **Expect:** per-step `ok`/`elapsed`/`error` checkpoints; final `record_finding` `indexed:false` (DRAFT), `full` report `approved_finding_count 0` (approval gate working as designed).

3. 💬 *"Which findings are waiting for my approval and what are their IDs?"*
   🖥️ open portal `https://siftworkstation.taile7c9ca.ts.net:8443/` (or MCP `approve_finding {…}`)
   **Expect:** the staged DRAFT findings listed (e.g. `vanko-p1-001`); you approve yourself via HMAC sign-off (append-only) — the assistant cannot approve on your behalf.

4. 💬 *"Generate the full report for the Vanko case."*
   🖥️ MCP `report_generate { profile:"full", case_id:"VANKO-ABDUCTED-ZEBRAFISH" }`
   **Expect:** `report_id` + section counts; once a finding is approved, `approved_finding_count` and the report sections populate (a DRAFT-only case may return `case_not_found` until there is indexed state).

5. 💬 *"Verify the seal on this report — confirm it hasn't been tampered with since it was generated."*
   🖥️ `uv run python scripts/verify_seal.py <report>.json`
   **Expect:** the seal verifier confirms the report + audit log are intact and unaltered since sealing (HMAC-SHA256, `evidence_image_sha256`-bound).

---

## Appendix — metadata-only verification (re-run before activation)

```bash
file    /cases/vanko/surface_physical.E01            # EWF/Expert Witness/EnCase image file format
du -sh  /cases/vanko/surface_physical.E0*            # E01 ≈ 2.0G each segment
ls      /cases/vanko/surface_physical.E??            # E01–E21 (21 segments)
ewfinfo /cases/vanko/surface_physical.E01            # Ovie Carroll / Surface 3 / 116 GiB / MD5 4032d556…
```

Confirmed 2026-06-08 (captured activation run): all 21 EWF segments present and valid; EWF-embedded
MD5/SHA1 match the FTK Imager acquisition log (`surface_physical.E01.txt`). The full investigation
(10 confirmed findings of 19) is written up in the sealed report at
`/home/admin2/docu_agentro/docs/12-CASES-REPORTS/vanko-report/`.
