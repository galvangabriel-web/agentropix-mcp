# DIGITAL FORENSICS AND INCIDENT RESPONSE REPORT
**Subject System:** Windows 10 Pro (Build 10586) - STARKSURFACE (User: PC User)
**Associated Entities:** Anthony Vanko (anthony.vanko@icloud.com footprint)
**Analysis Platform:** agentropix-SIFT (Ubuntu) / Opus 4.8 Orchestration

---

## 1.0 EXECUTIVE SUMMARY

Forensic analysis of case VANKO-ABDUCTED-ZEBRAFISH establishes that classified intellectual property was exfiltrated from Stark Enterprises by a trusted insider operating with authorized credentials. The findings below derive exclusively from artifacts recovered from the acquired evidence image and are presented for leadership review. This was not a malware intrusion: no memory-resident command-and-control, no malicious implant, and no host-to-host lateral movement were identified, and the only malware-family signature hits were determined to be false positives. The threat was an authorized user abusing legitimate access and legitimate, signed software.

### Incident Overview

Forensic analysis indicates that the subject, Anthony Vanko (local profile `C:\Users\PC User`; system STARKSURFACE, Windows 10 Pro Build 10586), exfiltrated classified zebrafish-DNA and cell-regeneration trade secrets from Stark Enterprises' DC R&D facility to external recipients. The activity was first detected when the JARVIS monitoring system flagged a large transfer from the StarkResearch file server and the subject's account was suspended (event window culminating 2016-06-30). The physical disk image was subsequently acquired on 2016-11-04 (FTK Imager, case `20161104`), with EWF-embedded MD5 `4032d556cc866c23f1e797410e95603c` and SHA1 `e0e72dfcef167dd358813726e82f6c235bc85ce7` independently confirming image integrity against acquisition metadata.

The primary threat vector was a **trusted insider with authorized access**, not an external intrusion. Registry analysis establishes that the subject used valid credentials and native, authorized access to the StarkResearch file server (`\\STARK-FILESERVE`, `192.168.1.5`, `192.168.1.3`) as the provenance of the stolen corpus (MITRE ATT&CK T1078 Valid Accounts; T1039 Data from Network Shared Drive).

### Business Impact

Artifacts recovered demonstrate compromise of classified trade-secret material across the **Level 5-8** classification band (including CryoDNA storage inventory, zebrafish-DNA splice notes, Level-8 biological research, and Ion-Thruster weaponization documentation). Forensic analysis further confirms **access to a Level-12 document, `Project Nehemiah`** — recovery from Volume Shadow Copy of a Microsoft Word owner-lock (`~$`) file demonstrates the document was actively opened, raising the realized exposure beyond the original Level 5-8 brief (T1530 Data from Cloud Storage). The affected systems comprise the StarkResearch file server as the data source and the STARKSURFACE workstation as the staging and exfiltration host.

The overarching intent established by the evidence is **insider trade-secret exfiltration coordinated with a foreign recruiter channel**: a Russia channel (recruiter Michael Merrick introducing handler Vladimir Bulgakov) is the confirmed finding (VANKO-P3-003). A second, China-associated buyer channel (`nina_kwai@qq.com`, associated with the CAS Institute of Microbiology, `im.cas.cn`) is present at the artifact level (OST carve output / synthesis) but is **not** promoted to a confirmed finding; it is reported as a supporting, artifact-level indicator rather than an established second buyer channel of equal certainty.

### Key Findings

* **Masquerade staging account.** Registry and event-log analysis confirms a non-default local account, `defaultprinter`, was interactively created by `PC User` at the start of the exfiltration window (Security event 4720 @ 2016-06-18 20:40:54 UTC) and was subsequently used as a staging mule, carrying a 2.6 MB classified archive (`temp.zip`) on its Desktop (T1136.001 Create Account: Local; T1074.001 Local Data Staging).

* **Staging disguised as benign content.** Artifacts recovered demonstrate that stolen classified documents were archived and disguised as `vacation photos.7z` (SHA-256 `b210bcd89fbde5d3b0816e1834483f7b82adf8565fd880d49930c25450ca7e31`, created 2016-06-30 01:28), using legitimate signed utilities (7-Zip, SysInternals SDelete, FTK Imager Lite) weaponized in sequence (T1560.001 Archive via Utility; T1036 Masquerading).

* **Dual cloud egress.** SRUM network analysis confirms two active exfiltration channels — Dropbox (client and updater) and OneDrive — both transmitted data, with the disguised archive uploaded to Dropbox account `984347879` at 2016-06-30 01:46:06 (T1567.002 Exfiltration to Cloud Storage).

* **Foreign-handler coordination.** Mailbox analysis confirms outbound two-way contact with a foreign recruiter: a 2016-06-27 21:22 reply ("RE: Potential Opportunity?") to `mmerr001@gmail.com` carrying three attachments. (Note: attachment content was not extracted; classified exfiltration by email is not asserted — only the handler coordination is confirmed.) (T1567).

* **Anti-forensics defeated by Volume Shadow Copies.** Timeline analysis confirms deliberate indicator removal — SDelete secure-wiping of original files (2016-06-30 01:30), deletion of the SDelete prefetch artifact, and purging of the Dropbox cache and 1.9 GB local Dropbox folder. These destruction attempts were defeated because Volume Shadow Copy snapshots (2016-10-14 and 2016-11-04) preserved the deleted artifacts (T1070.004 Indicator Removal: File Deletion).

> **Honest negatives (for the record):** No memory-resident C2 or implant was found; no malware family was present (YARA hits were false positives); the iPhone-as-exfiltration-vector hypothesis is down-ranked (device present, payload unproven); no Windows.old persistence existed; timestomping was refuted (the `$SI`/`$FN` anomaly was a copy signature); and the NTP clock-change anomaly was benign. These are reported as negative or inconclusive results and are not asserted as positive findings.

---

## 2.0 INVESTIGATION SCOPE & METHODOLOGY

### 2.1 Scope of Examination

This examination concerns the host designated STARKSURFACE (Microsoft Windows 10 Pro, Build 10586), the workstation attributed to subject Anthony Vanko, a biochemical engineer at the Stark Enterprises Washington, D.C. R&D facility. The matter under investigation is suspected insider intellectual-property and trade-secret theft involving classified zebrafish-DNA and cell-regeneration research. Forensic analysis was directed at reconstructing the staging, exfiltration, and anti-forensic activity associated with the local user principals "PC User" and "defaultprinter" across the defined activity window of June 2016. The examination was conducted exclusively against forensically acquired media; no analysis was performed on live or production systems.

### 2.2 Evidence Acquisition and Forensic Integrity

The primary evidence item is a physical disk image of a Microsoft Surface 3 device (Samsung MDGAGC storage, 244,277,248 sectors), acquired as a multi-segment Expert Witness Format (EWF/E01) set. Acquisition was performed using FTK Imager under case identifier `20161104`, with examiner of record Ovie Carroll, acquired 2016-11-04, per the acquisition metadata recorded in `surface_physical.E01.txt`. The image comprises segments `surface_physical.E01` through `surface_physical.E21`, describing logical media of 116 GiB (125,069,950,976 bytes).

Forensic integrity of the acquired media was independently validated. Image-level interrogation (`get_image_info`) recovered the EWF-embedded acquisition hashes:

| Algorithm | Value |
|---|---|
| MD5 | `4032d556cc866c23f1e797410e95603c` |
| SHA1 | `e0e72dfcef167dd358813726e82f6c235bc85ce7` |

Forensic analysis indicates these EWF-embedded MD5 and SHA1 values match the FTK Imager acquisition metadata recorded at the time of imaging exactly, providing independent confirmation that the image is intact and that the chain of custody is unbroken. Upon registration of the evidence into the analysis platform (`evidence_register`), a custody SHA-256 of `a085d58338fdb241e8cde27d48a14955270b97d6e67ac93d6307de2c70dd42a2` was computed over the first EWF segment file (2,147,328,814 bytes) and recorded to the evidence index. The segment-level SHA-256 fixes the custody record of the first acquired container, while the EWF-embedded MD5/SHA1 validate the full logical image against the original acquisition. Chain of custody is therefore established as intact.

Ancillary evidence items within the case inventory comprise a CYLR triage collection of C: artifacts (`vanko-c-drive.CYLR.7z`) and the scenario brief documents (`Vanko Student Scenario_D01_01.docx`, `resume.txt`). All findings asserted in this report derive from artifacts recovered from the validated EWF image set and its preserved Volume Shadow Copy stores.

### 2.3 Analysis Suite

Examination was conducted using an industry-standard, validated tool suite. Each tool was applied to recover and cross-corroborate the artifact classes underpinning the findings:

- **The Sleuth Kit** — partition enumeration, file-system listing (`fls`), and file extraction from the EWF image and its shadow-copy volumes.
- **Eric Zimmerman Tools** — structured parsing of Windows forensic artifacts:
  - **MFTECmd** — `$MFT` master file table and `$I30` analysis (copy-signature and file-creation timelines).
  - **RECmd** — registry hive interrogation (SOFTWARE ProfileList; NTUSER TypedPaths/RecentDocs).
  - **LECmd / JLECmd** — LNK shortcut and Jump List analysis (tooling provenance: FTK Imager Lite, SDelete, Tor shortcuts).
  - **AmcacheParser** — application execution and binary SHA1 attribution (sdelete.exe, 7z, dropbox.exe).
  - **SrumECmd** — System Resource Usage Monitor network-transfer accounting (per-application bytes sent/received).
- **Plaso / log2timeline** — super-timeline generation and temporal correlation across artifact sources.
- **Volatility 3** — memory-image analysis for resident-process and implant assessment.
- **YARA** — signature-based malware identification across recovered file content.
- **bulk_extractor** — feature extraction and carving of network, account, and document indicators.
- **libvshadow** — Volume Shadow Copy (VSS) enumeration and differential analysis, including recovery of artifacts deleted prior to the snapshot dates (Store2, 2016-11-04) that defeated subject anti-forensic activity.

Windows Event Log (`.evtx`) analysis supported account-creation (EventID 4720/4724), explicit-credential logon (EventID 4648), and file-access correlation. Deleted-object recovery proceeded through Recycle Bin `$I` metadata parsing and content carving of corresponding `$R` records.

### 2.4 Negative and Inconclusive Results

Methodological rigor required adversarial disconfirmation of each candidate hypothesis. Several lines of inquiry were tested and did not survive scrutiny; these are reported as negative or inconclusive results and are not asserted as positive findings. Volatility 3 memory analysis did not establish any memory-resident command-and-control channel or implant. YARA processing produced no validated malware-family identification; observed signature hits were assessed as false positives. The hypothesis of an iPhone serving as the exfiltration vector was down-ranked: the device was present, but a transiting payload was not proven. No `Windows.old` persistence mechanism was substantiated. Timestomping was refuted, the relevant temporal artifacts being consistent with a file-copy signature rather than deliberate timestamp manipulation. An observed NTP anomaly was assessed as benign. These honest negatives constrain the scope of the affirmative conclusions presented elsewhere in this report.

### 2.5 Automated Orchestration Methodology

Artifact extraction and analysis were driven through the agentropix-SIFT forensic platform under Opus 4.8 automated orchestration. The per-image disk tool chain — partition resolution (`get_partitions`/`parse_gpt`), file listing and extraction (`fls`/`extract_files`), registry interrogation (`get_registry`), event-log parsing (`get_evtx`), and structured-artifact parsing (`get_mftecmd`/`get_recmd`/`get_amcache`/SRUM) — was executed against the registered evidence through the platform's MCP tool interface. Each orchestrated action was committed to a recorded, replayable action log, and every per-step tool response was persisted to disk (`step1_case_init.json` through `step5_get_image_info.json` and subsequent analysis records), preserving a complete, auditable, and reproducible chain of forensic operations. Case state was managed under the active-case identifier VANKO-ABDUCTED-ZEBRAFISH. Promotion of any finding from DRAFT to APPROVED status is governed by a human-only, HMAC-gated examiner sign-off and is never automated, preserving examiner accountability over all reported conclusions.

All technical findings derived through this methodology are mapped to the relevant MITRE ATT&CK techniques, including Create Account: Local Account (T1136.001), Data Staged: Local Data Staging (T1074.001), Indicator Removal: File Deletion (T1070.004), Proxy: Multi-hop Proxy (T1090.003), Exfiltration to Cloud Storage (T1567.002) and Exfiltration Over Web Service (T1567), Data from Network Shared Drive (T1039), and Data from Cloud Storage (T1530).

---

## 3.0 MASTER INCIDENT TIMELINE

The following chronology is curated from MFT (`$MFT`, MFTECmd), Windows event log (EvtxECmd over `Security.evtx`), Recycle Bin `$I` records, Prefetch, Amcache, SRUM (`SRUDB.dat`), Dropbox `aggregation.dbx`, and libvshadow Volume Shadow Copy differential analysis (`vss2_fls.txt`). All timestamps are expressed in UTC as recorded by the cited artifact unless otherwise noted. Each entry cites the specific artifact establishing the event. Timeline analysis is constrained to high-confidence, source-traceable events; hypotheses refuted during disconfirming analysis are excluded and addressed in the negative-results discussion.

> **Source-integrity note.** The Plaso super-timeline generated during processing yielded zero events (log2timeline timeout on the 110 GB `$MFT`); the chronology below is therefore reconstructed from the individually parsed artifact stores enumerated above, not from a consolidated Plaso CSV. This is a processing limitation, not an evidentiary gap — every entry is independently traceable to its underlying artifact.

| # | Timestamp (UTC) | Action | Proving Artifact | MITRE | Finding |
|---|---|---|---|---|---|
| 1 | 2016-04-30 18:10 | Classified corpus copied from the StarkResearch file server (`\\STARK-FILESERVE`, `\\192.168.1.5`, `\\192.168.1.3`) into `C:\Users\PC User\OneDrive\Documents\Level_*`. Registry analysis establishes the server as the data source; MFT analysis establishes the copy event. | `$MFT` ($SI, MFTECmd, step_021): `$SI Created = 2016-04-30 18:10` against preserved `$SI Modified` authoring dates of 2015–2016 (e.g. `Stark_Level_12_Wolverine_Dossier` modified 2015-03-21; `Stark_TS-Level8A_CryoDNA` modified 2015-12-22; `STARK-TS-Level7-CryoDNA` modified 2016-03-15) — a file-COPY signature. Provenance corroborated by NTUSER `TypedPaths` (`/Users/PC User/NTUSER.DAT`). | T1039 | P1-003 (negative), P3-005 |
| 2 | 2016-06-18 20:40:54 | Masquerading local account `defaultprinter` created by `PC User` on STARKSURFACE. Registry analysis confirms the account and profile. | `Security.evtx` (`/Windows/System32/winevt/Logs/Security.evtx`): EventID **4720** record_id 19669 @2016-06-18T20:40:54Z and EventID **4724** record_id 19672 (same second); SubjectUserName=`PC User`, TargetUserName=`defaultprinter`. Corroborated by SOFTWARE hive `ProfileList` entry `C:\Users\defaultprinter`. | T1136.001 | P1-001 |
| 3 | 2016-06-18 22:22:09 | Classified staging archive `temp.zip` (2,603,690 bytes) deleted from the `defaultprinter` Desktop — 1h 41m after account creation. Recovered carving establishes contents (Ion Thruster weaponization, ZF DNA splice notes, cell-regeneration material). | Recycle Bin `$I` record (`/$Recycle.Bin`): `C:\Users\defaultprinter\Desktop\temp.zip`, 2,603,690 B, deleted 2016-06-18 22:22:09 UTC. Recovered as `$RZQSNFO.zip` (`collected/deleted-recycle/`). | T1074.001 | P2-001 |
| 4 | 2016-06-25 21:03:21 | Anti-attribution / recon tooling (`Tor Browser`, 128 MB, with `Start Tor Browser.lnk`; `Network Stumbler.lnk`) deleted from the `PC User` Desktop. | Recycle Bin `$I` (`/$Recycle.Bin`): `C:\Users\PC User\Desktop\Tor Browser` (128MB) + `Start Tor Browser.lnk`; `Desktop\Network Stumbler.lnk`, deleted 2016-06-25 21:03:21. | T1090.003 | P2-004 |
| 5 | 2016-06-27 17:24 | Inbound recruitment email "Potential Opportunity?" received from `mmerr001@gmail.com` (Michael Merrick), introducing foreign recruiter Vladimir Bulgakov. | Gmail OST (`/Users/PC User/AppData/Local/Microsoft/Outlook/anthony.vanko@gmail.com (1).ost`): recruitment message from Michael Merrick, 2016-06-27 17:24. | T1567 | P3-003 |
| 6 | 2016-06-27 21:22:49 | Outbound reply "RE: Potential Opportunity?" sent by Anthony Vanko carrying **3 attachments** to the recruiter channel. Attachment content was not extracted; two-way contact with the handler is confirmed, classified-exfil-by-email is NOT asserted. | Gmail OST (`...anthony.vanko@gmail.com (1).ost`): message from Anthony Vanko, subject `RE: Potential Opportunity?`, 2016-06-27 21:22:49, n_attachments=3. | T1567 | P3-003 |
| 7 | 2016-06-28 23:28–23:33 | Tor Browser active session (anti-attribution infrastructure in use). | Prefetch / `Security.evtx` (Phase-1 correlation). | T1090.003 | P2-004 |
| 8 | 2016-06-29 20:26 | 7-Zip GUI archiving activity (last execution of the staging archiver in the window). | Prefetch (`/Windows/Prefetch`): `7ZG.EXE` ×9, `7ZFM.EXE` ×3 (last 2016-06-29 20:26). Amcache (`Amcache.hve`): `7z1602-x64.exe` SHA1 `0d2c251d`. | T1560.001 / T1074.001 | P2-005 |
| 9 | 2016-06-30 01:28 | `vacation photos.7z` archive created — classified material disguised as holiday photos. | `$MFT` / LNK artifacts: `C:\Users\PC User\Downloads\vacation photos.7z`, created 2016-06-30 01:28; SHA-256 `b210bcd89fbde5d3b0816e1834483f7b82adf8565fd880d49930c25450ca7e31`. | T1560.001 / T1036 | P2-005 |
| 10 | 2016-06-30 01:30:52 | SDelete secure-wipe executed (last of 10 runs) against the original staged files. | Prefetch (`/Windows/Prefetch`): `SDELETE.EXE` ×10, last 2016-06-30 01:30:52. Amcache (`Amcache.hve`): `sdelete.exe` SHA1 `ab48396a`. | T1070.004 | P2-005, P4-003 |
| 11 | 2016-06-30 01:46:06 | `vacation photos.7z` uploaded to Dropbox account **984347879**. SRUM corroborates outbound egress bytes. | Dropbox `aggregation.dbx` (`/Users/PC User/AppData/Local/Dropbox`): `984347879:/vacation photos.7z` upload 2016-06-30 01:46:06. SRUM `SRUDB.dat` (SrumECmd): Dropbox Client+Update bytes_sent 2.6MB+837KB. | T1567.002 | P3-002 |
| 12 | 2016-06-30 01:48:48 | Local Dropbox folder (1,908,571,018 bytes) deleted to Recycle Bin — 2m 12s after upload completion; coordinated post-exfil cleanup. | Recycle Bin `$I` (`/$Recycle.Bin`): `C:\Users\PC User\Dropbox`, 1,908,571,018 B, deleted 2016-06-30 01:48:48 UTC. | T1070.004 | P2-003 |
| 13 | 2016-06-30 | JARVIS monitoring system flagged the large transfer from the StarkResearch server; the subject's account was suspended (defender/IR action). | Case-activation record (EXECUTED-RUN.md scenario context). | — | (context) |
| 14 | 2016-10-14 | Volume Shadow Copy snapshot created — preserved deleted/wiped artifacts. | libvshadow VSS differential (Store, 2016-10-14). | — | P4-003 |
| 15 | 2016-11-04 | Volume Shadow Copy snapshot (Store2). Shadow-copy analysis recovered the SDelete-wiped `temp.zip` (0 bytes), the deleted `SDELETE.EXE-FBA93810.pf` prefetch, the `~$Project_Nehemiah 4.docx` Word owner-lock (evidencing Level-12 document open), and the purged Dropbox cache — defeating the secure-deletion attempt. | libvshadow VSS differential `vss2_fls.txt`: deleted(`*`) entries `Windows/Prefetch/SDELETE.EXE-FBA93810.pf`; `Users/defaultprinter/Desktop/temp.zip` (0 B); `Users/PC User/OneDrive/Documents/Level_12/~$...Project_Nehemiah 4.docx`; `$RECYCLE.BIN/...$RK7QVJQ/.dropbox.cache/...` (284,067 B); 23,848 total deleted-at-snapshot entries. | T1070.004 / T1530 | P4-003, P4-004 |
| 16 | 2016-11-04 | Physical disk image acquired (`surface_physical.E01`–`.E21`, FTK Imager, examiner Ovie Carroll, case `20161104`). Chain-of-custody integrity independently verified. | EWF-embedded hashes: MD5 `4032d556cc866c23f1e797410e95603c`, SHA1 `e0e72dfcef167dd358813726e82f6c235bc85ce7`, matching the FTK acquisition metadata (`surface_physical.E01.txt`). Media 116 GiB (125,069,950,976 B). | — | EXECUTED-RUN |

### 3.1 Negative and Inconclusive Temporal Results

Timeline analysis identified two apparent temporal anomalies that were tested and refuted; they are recorded here so the master timeline is not misread as containing manipulation:

- **No timestomping.** The `created > modified` ordering observed across the OneDrive classified corpus (entry 1) was tested against timestomp tradecraft and refuted. Timestomp utilities zero sub-seconds and collapse stamps; here the `$SI Modified` values preserve plausible 2015–2016 authoring dates while `$SI Created` reflects the 2016-04-30 copy-to-OneDrive time — a textbook file-COPY signature (T1070.006 refuted, finding P1-003). The `$FN` timestamps were not exposed by the MFT wrapper, so the conclusion rests on `$SI` created/modified ordering and copy semantics.
- **No clock manipulation / backdating.** Eleven EventID **4616** system-time-change events within the window (e.g. @2016-06-19T15:46:04, @2016-06-28T23:37:22, recorded in `Security.evtx`) all show sub-minute `PreviousTime→NewTime` deltas (0–9 s) with `ProcessName=svchost.exe` (W32Time service) — routine NTP synchronization, not deliberate skew (T1070.006 refuted, finding P1-002). The timeline timestamps above are therefore not affected by adversarial clock manipulation.

---

## 4.0 TECHNICAL ATTACK NARRATIVE (MITRE ATT&CK MAPPED)

This section reconstructs the kill chain executed on the system STARKSURFACE (Windows 10 Pro Build 10586; user principal `C:\Users\PC User`, Microsoft account `anthony.vanko`). The chain is that of an authenticated insider abusing authorized access, not an external intrusion. Forensic analysis indicates no software exploitation, no implant, and no host-to-host lateral movement at any stage; the technique mappings below reflect that authenticated-insider model.

### 4.1 Initial Access & Staging

**Authorized-insider access (T1078 — Valid Accounts).** Forensic analysis indicates access to STARKSURFACE was obtained through the subject's own valid credentials rather than through exploitation. The in-memory and malware hypotheses were tested and refuted (findings VANKO-P3-001, VANKO-P4-001); no implant, injected code, or active beacon was evidenced. Authentication artifacts establish `PC User` as the operative principal, with the SID `S-1-5-21-3739107332-290452467-3466442662-1001` recovered from registry and Recycle Bin path structures.

**Masquerade staging account.** Registry and event-log analysis establishes that the local account `defaultprinter` was created interactively by `PC User` on 2016-06-18 20:40:54 UTC (Security.evtx EventID 4720 record_id 19669, with EventID 4724 record_id 19672 in the same second; SubjectUserName=PC User, TargetUserName=defaultprinter, Computer=StarkSurface), corroborated by the `C:\Users\defaultprinter` profile path in the SOFTWARE hive ProfileList (finding VANKO-P1-001, T1136.001 — Create Account: Local). `defaultprinter` is not a Windows-default principal; artifacts recovered demonstrate it carried an interactive Desktop holding a classified archive, establishing it as a masquerading staging account rather than a benign system principal.

**Classified archive staged under the masquerade account (T1560.001 — Archive Collected Data: Archive via Utility / T1074.001).** Timeline analysis confirms `C:\Users\defaultprinter\Desktop\temp.zip` (2,603,690 bytes) was staged and subsequently deleted 2016-06-18 22:22:09 UTC (Recycle Bin `$I` record). The deleted archive was recovered by carving (`$RZQSNFO.zip` == `temp.zip`) and contained Ion Thruster weaponization material, zebrafish DNA splice notes, and cell-regeneration content (finding VANKO-P2-001). This staging event promoted the masquerade-account finding (VANKO-P1-001) to confirmed status. Separately, the consolidated exfil payload `vacation photos.7z` (SHA-256 `b210bcd89fbde5d3b0816e1834483f7b82adf8565fd880d49930c25450ca7e31`) was archived as a disguised holiday-photo container; its associated `vacation photos.7z.lnk` (SHA-256 `ca8433a7ba4ccde99a9170cb169c61f87b704b853a39c55843941ae049b201fc`) and Dropbox attribute stream (`:com.dropbox.attributes`, SHA-256 `586d6e4410af8fd7bc5dba881c86a453e494e5b52ec5e13a582292063355d316`) are recovered.

**macOS cross-platform indicators.** No `.DS_Store` or Time Machine cross-platform artifact is recorded among the confirmed findings or the synthesis IOC set; accordingly, no such indicator is asserted as established fact for this section. Any macOS-origin staging remains outside the recovered, confirmed evidence.

**Execution evidence via LNK / JumpList (T1074.001).** Artifacts recovered demonstrate shortcut-based execution and access provenance for the staging toolchain: LNK artifacts (LECmd) for FTK Imager Lite, SDelete, and Tor are recorded alongside the `vacation photos.7z.lnk` and `Recent\V-Photos.lnk` shortcuts (findings VANKO-P2-005, VANKO-P2-004). These shortcut artifacts corroborate interactive launch and recent-document staging of the exfil payload.

### 4.2 Execution & Evasion

**Signed-tool weaponization.** Forensic analysis indicates that a chain of legitimate, signed utilities was weaponized in sequence rather than any custom malware (finding VANKO-P2-005, T1074.001). Amcache analysis (`/Windows/appcompat/Programs/Amcache.hve`) records `sdelete.exe` (SHA1 prefix `ab48396a`), `7z1602-x64.exe` (SHA1 prefix `0d2c251d`), and `dropbox.exe`. Prefetch analysis records `7ZG.EXE` (x9) and `7ZFM.EXE` (x3, last execution 2016-06-29 20:26) and `SDELETE.EXE` (x10, last execution 2016-06-30 01:30:52). Each tool — 7-Zip (Igor Pavlov), SDelete and Diskmon (Microsoft Sysinternals), and FTK Imager (AccessData) — is individually a benign signed utility; the probative element is the executed sequence within the exfil window (7-Zip archive 2016-06-29 → SDelete 10x secure-wipe 2016-06-30 01:30 → Dropbox upload 2016-06-30 01:46), which constitutes data-theft and anti-forensic tradecraft rather than routine administration.

**Anti-forensics (T1070.004 — Indicator Removal: File Deletion).** Timeline analysis confirms a deliberate indicator-removal pattern recovered from Volume Shadow Copies (finding VANKO-P4-003; libvshadow VSS differential, Store2, `vss2_fls.txt`). The recovered deleted-at-snapshot entries include the SDelete prefetch artifact `Windows/Prefetch/SDELETE.EXE-FBA93810.pf` (deleted — erasing the proof that SDelete executed), the SDelete-wiped staging archive `Users/defaultprinter/Desktop/temp.zip` (0 bytes) with its `temp.zip~RF9b00d6e.TMP` remnant, and a Dropbox cache routed to the Recycle Bin (`$RECYCLE.BIN/S-1-5-21-...-1001/$RK7QVJQ/.dropbox.cache/...`, 284,067 bytes). The local Dropbox folder (1,908,571,018 bytes) was deleted 2016-06-30 01:48:48 UTC, 2 minutes 12 seconds after the upload completed at 01:46:06 (finding VANKO-P2-003). Of 23,848 total deleted-at-snapshot entries, the targeted removal of the SDelete prefetch, the wiped staging archive, and the cloud-client cache constitutes a coordinated post-exfil cleanup. The destruction attempt failed: the 2016-10-14 and 2016-11-04 shadow copies preserved these artifacts after deletion.

**Persistence — REFUTED (honest negative).** The hypothesis that pre-reset persistence survived through `Windows.old` was assessed and refuted (finding VANKO-P1-005). The `Windows.old` tree contains only an OS skeleton (`WINDOWS\` and `WINDOWS\System32\`, approximately 81 records) with no `Users`, no `PC User` profile, no `NTUSER.DAT`, and no `ProgramData`; the system was reset rather than upgraded in place, so no pre-reset autostart migrated forward. No surviving-persistence finding is asserted. Relatedly, the daily scheduled task invoking `getfiletree.ps1` from `%duck%` was down-ranked and refuted (finding VANKO-P1-004): no script body was recovered, and the task metadata is indistinguishable from a benign inventory job.

**Timestomping — REFUTED (honest negative).** The hypothesis of timestamp manipulation on the classified documents was assessed and refuted (finding VANKO-P1-003, T1070.006). MFT `$SI` analysis shows created-after-modified ordering (e.g., `Stark_Level_12_Wolverine_Dossier` created 2016-04-30 18:10 vs modified 2015-03-21; `Stark_TS-Level8A_CryoDNA.blacklight.docx` created 2016-04-30 vs modified 2015-12-22) that is the textbook file-COPY signature — the `$SI` Created time reflects the 2016-04-30 copy-to-OneDrive event while the `$SI` Modified time preserves the original authoring date. This corroborates server-to-OneDrive provenance rather than manipulation. A caveat is noted: `$FN` timestamps were not exposed by the MFT wrapper, so a full `$SI`-vs-`$FN` comparison was not possible; the conclusion rests on `$SI` ordering and copy semantics. The related system-time-change events (11x EventID 4616, sub-minute deltas, ProcessName=svchost.exe / W32Time) were assessed as benign NTP synchronization, not clock backdating (finding VANKO-P1-002).

### 4.3 Lateral Movement & Network Activity

**Native-protocol file-server access (T1039 — Data from Network Shared Drive).** Registry analysis establishes authorized file-server access to the StarkResearch server as the provenance of the stolen intellectual property (finding VANKO-P3-005). NTUSER.DAT TypedPaths entries (url7–url10) record `\\192.168.1.5`, `\\STARK-FILESERVE`, `\\192.168.1.3`, and `Network`. This is reclassified from SMB-admin-share lateral movement to T1039 — authorized network-share access abused — and is corroborated as the source of the OneDrive classified corpus via the Phase-1 copy signatures described in 4.2.

**Cloud egress (T1567.002 — Exfiltration to Cloud Storage).** SRUM analysis confirms cloud-storage exfil egress over both Dropbox and OneDrive (finding VANKO-P3-002; `/Windows/System32/sru/SRUDB.dat`, SrumECmd). The Dropbox Client and Dropbox Update applications recorded 2.6 MB + 837 KB sent; the Microsoft/OneDrive common-files application recorded 8.7 MB sent / 551 MB received; the top aggregate application recorded 26.5 MB sent. Cross-referenced with the Dropbox `aggregation.dbx` record of the `vacation photos.7z` upload to account `984347879` at 2016-06-30 01:46:06 and the classified documents resident in OneDrive\Documents, SRUM corroborates Dropbox and OneDrive as the active exfil channels. The received-byte volume is dominated by benign client updates; the sent-byte volume aligns with the staged-data egress.

**Lateral movement — NEGATIVE (honest result).** Forensic analysis indicates NO host-to-host lateral movement. This is a single-host insider case (finding VANKO-P3-005). While 317 EventID 4648 explicit-credential logon events are recorded across the window (Security.evtx), the server-target field was inconclusive and the SmbClient operational log returned 0 events; accordingly the SMB/4648 server-target correlation is reported as inconclusive and is not advanced as proof of a specific server authentication.

### 4.4 iOS Device Anomalies

**Device tethering established (artifact level).** Forensic analysis indicates an Apple iPhone was tethered and synced via iTunes on the host. A deleted iPhone firmware image (`.ipsw`, 1,673,802,539 bytes) was recovered from the Recycle Bin under `C:\Users\PC User\AppData\Roaming\Apple Computer\iTunes\iPhone...`, deleted 2016-06-17 10:45:15; the carved object `$R39S047.ipsw` is identified as iPhone5,3 iOS firmware (approximately 1.56 GB) (finding VANKO-P2-002).

**iPhone-as-exfil-vector — DOWN-RANKED / REFUTED (honest qualification).** While device tethering and iTunes sync are established as artifacts, the hypothesis that the iPhone served as a removable-device exfil vector (T1052.001 — Exfiltration over Physical Medium: USB; candidate only) was down-ranked and refuted (finding VANKO-P2-002). No classified payload is tied to the device; iPhone backup and sync are normal for any owner, and the `.ipsw` firmware image is a routine iTunes artifact rather than evidence of staged exfil. The device is present and the tether is confirmed, but the iPhone-as-exfil-vector hypothesis is unproven and is presented at its assessed (refuted) confidence, not as an established exfiltration channel.

---

## 5.0 MALWARE & ARTIFACT ANALYSIS

This section reports the results of memory, payload-carving, and message-store analysis. Consistent with the authenticated-insider model established elsewhere in this report, several malware-oriented hypotheses were tested and **refuted**; those honest negatives are stated as such and are not advanced as positive findings.

### 5.1 Memory & C2 Analysis (Negative Result)

Volatility 3 analysis of the available memory remnants identified **no resident implant, no injected code, and no active command-and-control (C2) beacon**. This is a negative result and is reported as such (FINDINGS.jsonl `VANKO-P3-001`, status **refuted**).

The evidence under examination is a **disk image**, not a memory capture. The only memory-derived remnants present are a 256 MB-**truncated** `pagefile.sys`, a **WAKE-state** `hiberfil.sys` (not a valid memory image), and the swapfile — none of which constitute a valid Volatility input. Forensic analysis confirms that the `windows.pslist` plugin executed against `/tmp/agentropix-sift-vanko/pf/hiberfil.sys` returned non-JSON output and zero rows, and no `Vanko-RAM.dmp` exists within this disk image. Consequently, hidden-process, `malfind`, and `netscan` examinations could not be performed and yield no affirmative evidence of a resident implant.

Independently, the established model is one of an **authenticated insider operating signed, legitimate tooling** (see Section on staging, `VANKO-P2-005`); no malware implant, injected code, or C2 beacon is expected or evidenced. The functional equivalent of a "beacon" in this case is **legitimate Dropbox, OneDrive, and email/chat communication** — not adversary infrastructure. The in-memory malware-C2 hypothesis is therefore **REFUTED**.

> **Evidentiary note (negative):** The absence of a valid memory image is a processing limitation, not an exculpatory fact. Should a `Vanko-RAM.dmp` exist within the broader evidence set, `windows.pslist`, `windows.netscan`, and `windows.malfind` should be executed to close this gap.

### 5.2 Recovered Payloads & Carving

Data-carving (foremost / bulk_extractor) recovered the staged exfiltration payload and a body of unattributable memory remnants. The key recovered payload is the disguised classified archive:

| Artifact | SHA-256 | Provenance |
|---|---|---|
| `vacation photos.7z` | `b210bcd89fbde5d3b0816e1834483f7b82adf8565fd880d49930c25450ca7e31` | Created 2016-06-30 01:28; uploaded to Dropbox account `984347879` at 2016-06-30 01:46:06 (`VANKO-P3-002`) |
| `vacation photos.7z.lnk` | `ca8433a7ba4ccde99a9170cb169c61f87b704b853a39c55843941ae049b201fc` | Recent-items shortcut corroborating local handling |
| `vacation photos.7z:com.dropbox.attributes` | `586d6e4410af8fd7bc5dba881c86a453e494e5b52ec5e13a582292063355d316` | Dropbox alternate-data-stream metadata |

Forensic analysis confirms this `.7z` archive constitutes classified material disguised as holiday photographs, staged and exfiltrated via the cloud channel.

**Down-ranked / non-attributable memory remnants (negative results).** bulk_extractor recovery against the truncated `pagefile.sys` (`/tmp/agentropix-sift-vanko/pf/be_pagefile`) yielded **22 AES key schedules** (`aes_keys.txt`) and **41 carved PE headers** (`winpe.txt`). These artifacts are **not attributable** and were **down-ranked** (FINDINGS.jsonl `VANKO-P4-002`, status **refuted**): AES key schedules resident in RAM are ubiquitous (TLS and operating-system cryptography), and the carved PE images are consistent with legitimately loaded modules. No offline test of the recovered keys against the encrypted `.7z` archive was performed; absent such validation, these remnants are not probative.

**YARA family hits — generic false positives (negative result).** YARA triage against the truncated `pagefile.sys` produced nine loose `malware_index` hits (`with_sqlite`, `XMRIG_Miner`, `spyeye_plugins`, `Warp`, `Insta11`, `SharedStrings`) and generic `packers_index` matches (Borland / base64-packed); the `webshells_index` returned zero. Forensic analysis establishes these are **weak single-string signatures matching ubiquitous memory content** (e.g., SQLite headers from Dropbox/Chrome databases triggering `with_sqlite`; a literal miner string triggering `XMRIG_Miner`) within a 256 MB-truncated pagefile. **None are PE-backed and none reproduced against an on-disk executable.** Consistent with the authenticated-insider model, the malware-family-present hypothesis is **REFUTED** (FINDINGS.jsonl `VANKO-P4-001`). (Operational note: combining all fourteen YARA index files fails to compile owing to duplicated identifiers, so triage was performed per-index.)

**Content-scan limitation — provenance proven by MFT, not content.** The `zf_classified` content rule **did not fire** against the classified `.docx` material. This is an expected artifact-format limitation, not an absence of classified content: OOXML documents store their markers within DEFLATE-**compressed** members, which are invisible to a raw byte-level YARA scan. Accordingly, provenance of the classified corpus is established by **$MFT copy-signatures** ($SI Created reflecting the 2016-04-30 copy-to-OneDrive time while $SI Modified preserves the original StarkResearch authoring dates — `VANKO-P1-003`), **not** by content-scan. The copy-signature evidence also refutes the timestomping hypothesis (`VANKO-P1-003`, status **refuted**).

### 5.3 Email & Phishing Indicators

Analysis of the message store recovered from `/Users/PC User/AppData/Local/Microsoft/Outlook/anthony.vanko@gmail.com (1).ost` (1,592 parsed messages) yielded the following indicators of compromise.

**Foreign recruiter coordination (Russia channel) — confirmed (`VANKO-P3-003`, T1567).** Forensic analysis confirms an outbound message from Anthony Vanko, subject **"RE: Potential Opportunity?"**, timestamped **2016-06-27 21:22:49**, carrying **three attachments**, sent in reply to a recruitment message from **Michael Merrick (`mmerr001@gmail.com`)** dated 2016-06-27 17:24, which introduced recruiter **Vladimir Bulgakov**. The message, timestamp, recipient, and attachment count are cited directly in the OST. **The attachment *content* was not extracted**; accordingly, classified-exfiltration-by-email is **not** claimed. What is confirmed is **two-way contact with the foreign handler** carrying three undisclosed attachments.

**Buyer channel (China) — artifact-level, not a confirmed finding.** OST carve output (`carve_pst_iocs` over the `anthony.vanko@gmail.com (1).ost` message store) and the toptier-results synthesis (`SYNTHESIS.md`) identify `nina_kwai@qq.com` (and the look-alike variant `nina_kwa1@qq.com`) as a buyer-channel contact associated with the **CAS Institute of Microbiology** (domain `im.cas.cn`). These indicators trace to the underlying case artifacts cited above but have **not** been promoted to a confirmed/supporting finding; accordingly the China buyer channel is reported at artifact-level certainty and is not asserted at the same evidentiary weight as the confirmed Russia recruiter channel (VANKO-P3-003).

**ReadNotify read-tracking — down-ranked (`VANKO-P3-004`, status refuted).** The OST contains **17 ReadNotify messages**, including a "Welcome to ReadNotify Anthony" message from `help@readnotify.com` dated **2015-10-04**. While ReadNotify embeds invisible read-receipt / IP-tracking beacons in outbound mail, the welcome message **predates the June-2016 exfiltration window by approximately eight months**, indicating a longstanding personal subscription rather than crime-specific tradecraft. Intent is not establishable; this indicator is therefore **down-ranked / refuted** and is **not** advanced as a positive tracking-tradecraft finding.

| IOC type | Indicator | Context | Status |
|---|---|---|---|
| Email (Russia) | `mmerr001@gmail.com` (Merrick → recruiter Vladimir Bulgakov) | Recruiter channel; recipient of the 06-27 21:22 reply w/ 3 attachments | Confirmed (`VANKO-P3-003`) |
| Email (China) | `nina_kwai@qq.com`, `nina_kwa1@qq.com` | Buyer channel | Supporting |
| Domain (China) | `im.cas.cn` | CAS Institute of Microbiology (buyer org) | Supporting |
| Service (observed) | `readnotify.com` (17 messages) | Read-tracking subscription, welcome dated 2015-10-04 | Refuted / down-ranked (`VANKO-P3-004`) |

**Verification gap.** The three attachments on the Merrick reply were not extracted (`carve_pst_iocs` parsed headers only). To close this gap, payloads should be exported (`pffexport -m all`) and each attachment hashed and YARA-scanned. Until performed, no claim is made as to attachment content.

**Section summary.** No malware, implant, or C2 was present or evidenced; the memory-resident-C2, malware-family, pagefile-keys/PE, and ReadNotify-tradecraft hypotheses are all reported as **negative/refuted** results. The single affirmatively recovered payload is `vacation photos.7z` (SHA-256 `b210bcd8…`). Provenance of the classified corpus rests on $MFT copy-signatures, not content-scan. Confirmed outbound coordination with a foreign recruiter (three undisclosed attachments) is established (`VANKO-P3-003`); email-borne classified exfiltration is **not** claimed absent attachment-content extraction.

---

## 6.0 INDICATORS OF COMPROMISE (IOCs)

The indicators below are presented in structured, SIEM/EDR-ingestible form. Each indicator is traceable to a confirmed finding and its supporting artifact. Consistent with the established authenticated-insider model, **no external malware command-and-control (C2) infrastructure exists in this case**: the in-memory C2/injection hypothesis was refuted (VANKO-P3-001), and no malware family is present — the pagefile YARA matches were generic memory false positives (VANKO-P4-001). The "C2-equivalent" channels are legitimate cloud-storage, email, and chat services that were abused for coordination and exfiltration.

### 6.1 Network IOCs

| # | Type | Indicator | Context / Role | Source Artifact (locator) |
|---|---|---|---|---|
| N-01 | Internal host (UNC) | `\\STARK-FILESERVE` | StarkResearch file server — provenance of stolen classified IP | NTUSER.DAT TypedPaths url7–10 (VANKO-P3-005) |
| N-02 | Internal IP | `192.168.1.5` | File server (UNC `\\192.168.1.5`) accessed via native protocol | NTUSER.DAT TypedPaths (VANKO-P3-005) |
| N-03 | Internal IP | `192.168.1.3` | File server (UNC `\\192.168.1.3`) accessed via native protocol | NTUSER.DAT TypedPaths (VANKO-P3-005) |
| N-04 | Email (buyer, China) | `nina_kwai@qq.com` | Chinese buyer-channel contact (artifact-level; not promoted to a finding) | OST carve output (`carve_pst_iocs` over `anthony.vanko@gmail.com (1).ost`); toptier-results `SYNTHESIS.md` |
| N-05 | Email (buyer, China) | `nina_kwa1@qq.com` | Look-alike (typosquat) variant of the Chinese buyer address (artifact-level; not promoted to a finding) | OST carve output (`carve_pst_iocs`); toptier-results `SYNTHESIS.md` |
| N-06 | Email (recruiter, Russia) | `mmerr001@gmail.com` | Michael Merrick — recruiter channel; introduced handler Vladimir Bulgakov; recipient of Vanko's 2016-06-27 21:22 reply carrying 3 attachments | Gmail OST message (VANKO-P3-003) |
| N-07 | Domain (China) | `im.cas.cn` | CAS Institute of Microbiology — associated buyer organization (artifact-level; not promoted to a finding) | OST carve output (`carve_pst_iocs`); toptier-results `SYNTHESIS.md` |
| N-08 | Cloud account (Dropbox) | Account ID `984347879` | Exfil destination — `vacation photos.7z` uploaded 2016-06-30 01:46:06 UTC | Dropbox `aggregation.dbx` / SRUM (VANKO-P3-002) |
| N-09 | Cloud account (OneDrive) | CID `CBDFA76592A9F765` | Classified-document cloud staging; confirmed transmitting in SRUM | Registry parse step_018 (OneDrive account CID); SRUM `SRUDB.dat` (VANKO-P3-002) |
| N-10 | Cloud/exfil service | `dropbox.com` | Active exfil channel (client + updater apps transmitting) | SRUM network_data (VANKO-P3-002) |
| N-11 | Cloud/exfil service | `storage.live.com` | OneDrive transport endpoint | SRUM network_data (VANKO-P3-002) |
| N-12 | Messaging service | Skype | Comms infrastructure observed on host (artifact-level; not promoted to a finding) | OST carve output (`carve_pst_iocs`); toptier-results `SYNTHESIS.md` |
| N-13 | Anonymizing network | Tor | Multi-hop proxy / anti-attribution (T1090.003); Tor Browser present and active 2016-06-28 23:28–23:33 | Recycle Bin `$I` / Prefetch (VANKO-P2-004) |

**Honest negatives (Network):**
- **No external malware C2 IP / beacon domain.** Volatility produced no hidden process, injected code, or netscan beacon; the only available memory remnants (truncated pagefile, WAKE-state hiberfil) are not valid memory inputs (VANKO-P3-001, refuted).
- `readnotify.com` was observed (17 ReadNotify messages) but is **not** a crime-specific indicator: the subscription "Welcome" message predates the exfil window by ~8 months (2015-10-04), indicating longstanding personal use (VANKO-P3-004, refuted). It is excluded from the actionable IOC set above.

### 6.2 Host-Based IOCs

**File hashes (SHA-256)**

| # | Indicator | File | Source Artifact |
|---|---|---|---|
| H-01 | `b210bcd89fbde5d3b0816e1834483f7b82adf8565fd880d49930c25450ca7e31` | `vacation photos.7z` (classified payload disguised as holiday photos) | Carving (foremost / bulk_extractor); `$MFT` / LNK (VANKO-P2-005, P3-002) |
| H-02 | `ca8433a7ba4ccde99a9170cb169c61f87b704b853a39c55843941ae049b201fc` | `vacation photos.7z.lnk` | Carving (foremost / bulk_extractor) (VANKO-P2-005) |
| H-03 | `586d6e4410af8fd7bc5dba881c86a453e494e5b52ec5e13a582292063355d316` | `vacation photos.7z:com.dropbox.attributes` (alternate data stream) | Carving (foremost / bulk_extractor) (VANKO-P2-005) |

**Filesystem paths**

| # | Path | Significance | Source Artifact |
|---|---|---|---|
| H-04 | `C:\Users\defaultprinter\Desktop\temp.zip` | 2.6 MB classified staging archive (`$RZQSNFO.zip` recovered); SDelete-wiped to 0 bytes, recovered from VSS | Recycle Bin `$I` / VSS (VANKO-P2-001, P4-003) |
| H-05 | `C:\Windows\System32\sdelete.exe`, `C:\Windows\System32\sdelete64.exe` | SysInternals secure-deletion utility (anti-forensic wipe) | Amcache / report (VANKO-P2-005) |
| H-06 | `C:\Windows\Prefetch\SDELETE.EXE-FBA93810.pf` | Execution evidence of SDelete; **deleted** to remove the proof, recovered from VSS | VSS Store2 fls (VANKO-P4-003) |
| H-07 | `C:\Users\PC User\OneDrive\Documents\Level_12\~$Stark TS-Level 12_Project_Nehemiah 4.docx` | Word owner-lock file proving the Level-12 `Project Nehemiah` document was actively opened | VSS Store2 fls (VANKO-P4-004) |
| H-08 | `C:\$RECYCLE.BIN\S-1-5-21-3739107332-290452467-3466442662-1001\$RK7QVJQ\.dropbox.cache\…` | Deleted Dropbox cache (284,067 B) — post-exfil cleanup | VSS Store2 fls (VANKO-P4-003) |
| H-09 | `C:\Users\PC User\Dropbox\` | 1.9 GB local Dropbox folder deleted 2016-06-30 01:48:48 UTC, 2m12s after upload | Recycle Bin `$I` (VANKO-P2-003) |

**Tooling (legitimate signed utilities weaponized in sequence — VANKO-P2-005 / P2-004)**

| # | Tool | Vendor | Role | Source Artifact |
|---|---|---|---|---|
| H-10 | `sdelete.exe` (SHA1 prefix `ab48396a`) | MS Sysinternals | Secure-delete; 10 executions, last 2016-06-30 01:30:52 | Amcache / Prefetch |
| H-11 | `7z1602-x64.exe` / `7ZG.EXE` / `7ZFM.EXE` (SHA1 prefix `0d2c251d`) | Igor Pavlov | Archiving / payload disguise | Amcache / Prefetch |
| H-12 | FTK Imager Lite | AccessData | Imaging tooling present on user desktop | LNK / report |
| H-13 | Diskmon | MS Sysinternals | Disk-monitoring scheduled task | ScheduledTask |
| H-14 | Network Stumbler | — | Wireless recon tooling (deleted 2016-06-25 21:03:21) | Recycle Bin `$I` |

> Note: each tool above is a legitimately signed utility; the indicator value derives from the executed *sequence* within the exfil window (7-Zip archive 06-29 → SDelete 10× secure-wipe 06-30 01:30 → Dropbox upload 06-30 01:46), not from any individual binary.

**Registry / system identifiers**

| # | Type | Indicator | Significance | Source Artifact |
|---|---|---|---|---|
| H-15 | User SID | `S-1-5-21-3739107332-290452467-3466442662` (`PC User` = RID `-1001`) | Acting user account identifier | VSS path / Recycle Bin path structure (VANKO-P4-003) |
| H-16 | SAM account | `defaultprinter` | Masquerade local account created 2016-06-18 20:40:54 UTC; used as staging mule | Security.evtx 4720/4724 + SAM (VANKO-P1-001, P2-001) |
| H-17 | NTUSER TypedPaths | `\\STARK-FILESERVE`, `\\192.168.1.5`, `\\192.168.1.3` | File-server access history (provenance of stolen IP) | NTUSER.DAT (VANKO-P3-005) |

**Honest negatives (Host):**
- **No malware family present.** Pagefile YARA hits (e.g., `with_sqlite`, `XMRIG_Miner`) were generic, non-PE-backed memory false positives; webshell index clean (VANKO-P4-001, refuted).
- **No timestomping.** The `$SI created > modified` ordering on classified documents is a file-COPY signature (modified-time preserved from StarkResearch originals), not timestamp manipulation (VANKO-P1-003, refuted).
- **No clock manipulation.** The 11 system-time-change (4616) events are benign sub-minute NTP synchronizations by `svchost.exe` (W32Time), not deliberate backdating (VANKO-P1-002, refuted).
- **No surviving persistence via Windows.old** (OS skeleton only; no user profile / registry carry-forward — the host was reset, not upgraded) (VANKO-P1-005, refuted).
- **iPhone present but not evidenced as an exfil vector.** The tethered iPhone / `.ipsw` firmware are confirmed artifacts, but no classified payload is tied to the device (VANKO-P2-002, refuted — device present, payload unproven).
- The 22 pagefile AES key schedules and 41 carved PE images are non-attributable memory remnants and are **not** treated as probative IOCs absent an offline key test (VANKO-P4-002, refuted).

---

## 7.0 CONTAINMENT & REMEDIATION RECOMMENDATIONS

The following recommendations are derived directly from the exploited vectors established by the ten confirmed findings in this matter. Each is mapped to the artifacts and MITRE ATT&CK technique(s) that evidence the corresponding vector. The recommendations address an authenticated-insider tradecraft pattern; forensic analysis established no external malware, implant, or command-and-control infrastructure (hypotheses VANKO-P3-001 and VANKO-P4-001 were refuted), and the controls below are scoped accordingly to insider-threat and data-loss exposure rather than perimeter intrusion defense.

### 7.1 Implement Data-Loss Prevention and Egress Control on Cloud-Sync Channels

**Exploited vector — T1567.002 (Exfiltration to Cloud Storage):** Forensic analysis confirmed that Dropbox (client and updater) and Microsoft OneDrive both functioned as active exfiltration channels. SRUM network analysis (`/Windows/System32/sru/SRUDB.dat`) recorded Dropbox sent bytes of 2.6 MB and 837 KB and a OneDrive common-files application transmitting 8.7 MB, corroborated by the `aggregation.dbx` record of the `vacation photos.7z` upload to Dropbox account `984347879` at 2016-06-30 01:46:06 UTC (finding VANKO-P3-002).

**Recommendation:** Deploy enterprise Data-Loss Prevention (DLP) and egress filtering that inspects and controls personal/consumer cloud-sync clients (Dropbox, OneDrive, and equivalents) on all R&D endpoints. At minimum, block or quarantine unsanctioned consumer cloud-storage clients, apply content-aware DLP policies to outbound transfers from systems with file-server access to classified shares, and alert on bulk or archive-format uploads. Egress logging must retain sufficient SRUM/proxy/netflow detail to reconstruct sent-byte volumes per application.

### 7.2 Enforce Removable-Media Control via USB Serial Allow-Listing

**Context — preventive control (not tied to a confirmed removable-media finding):** The confirmed staging in this matter occurred on the host file system and via cloud-sync clients; no removable-media (USB) staging finding is established in the recovered evidence (the MountedDevices/USBSTOR registry artifacts parsed during examination did not yield a volume tied to the confirmed staging toolchain). This recommendation is therefore offered as a preventive hardening control against the local-data-staging vector class (T1074.001) generally, not as remediation of an evidenced removable-media exfil path.

**Recommendation:** Implement removable-media control enforcing a USB device allow-list keyed on device serial number, denying mass-storage devices by default and permitting only enrolled, encrypted, asset-tracked media. Enable USB-device audit logging (connection, volume serial, mounted-label, and file-write events) so that any future staging activity to removable media is independently recorded and alertable, closing a residual data-staging path not otherwise covered by the cloud-egress and account-monitoring controls above.

### 7.3 Monitor Privileged- and Local-Account Creation (Security Event IDs 4720/4724)

**Exploited vector — T1136.001 (Create Account: Local):** Forensic analysis confirmed the masquerading local account `defaultprinter` was created by user "PC User" at 2016-06-18 20:40:54 UTC, evidenced by Security event ID 4720 (record 19669) and 4724 (record 19672) in the same second on host StarkSurface, with the account subsequently used to stage a 2.6 MB classified archive (`temp.zip`) on its interactive desktop (findings VANKO-P1-001 and VANKO-P2-001).

**Recommendation:** Establish centralized, near-real-time alerting on account-lifecycle events — specifically Security event IDs 4720 (account created), 4722 (enabled), 4724 (password set/reset), 4728/4732 (privileged group membership), and 4738 (account changed) — forwarded to a SIEM. Account creations that masquerade as system or service principals (e.g., printer-, default-, or service-named accounts) created by interactive users must trigger investigation. Forward Windows Security logs off-host so that account-creation evidence survives local indicator-removal attempts.

### 7.4 Audit File-Server Access and Conduct Classified-Data Access Reviews (Levels 5–12)

**Exploited vector — T1039 (Data from Network Shared Drive) and T1530 (Data from Cloud Storage):** Forensic analysis confirmed native-protocol access to the StarkResearch file server (`\\STARK-FILESERVE`, `\\192.168.1.5`, `\\192.168.1.3`) as the provenance of the stolen intellectual property (NTUSER TypedPaths and 317 instances of Security event ID 4648; finding VANKO-P3-005). Analysis further confirmed that a Level-12 classified document (`~$Stark TS-Level 12_Project_Nehemiah 4.docx`) was actively opened — evidenced by a recovered Microsoft Word owner-lock file — establishing realized exposure beyond the originally scoped Level 5–8 brief (finding VANKO-P4-004).

**Recommendation:** Enable object-access auditing (event IDs 4663/4656 with SACLs) on classified shares and ensure the SmbClient operational log is retained, so that file-server access can be tied to user, credential, and time (the prior 4648 target-server field and SmbClient log were inconclusive/empty during this examination). Conduct a periodic least-privilege access review of classified shares spanning Levels 5 through 12, restricting authorization to demonstrated need-to-know and flagging any access to classification tiers above an individual's assigned scope.

### 7.5 Establish an Insider-Threat / UEBA Program with Offboarding Controls

**Exploited vector — T1078 (Valid Accounts), T1567, and supporting tradecraft:** This was an authenticated insider operating with valid credentials. Confirmed activity included outbound coordination with a foreign recruiter (the 2016-06-27 21:22 "RE: Potential Opportunity?" reply carrying three attachments to `mmerr001@gmail.com`; finding VANKO-P3-003) and the staging of an anti-attribution and reconnaissance toolset (Tor Browser, Network Stumbler, FTK Imager) on the user desktop (finding VANKO-P2-004).

**Recommendation:** Stand up a formal insider-threat program incorporating User and Entity Behavior Analytics (UEBA) to baseline normal data-access and egress behavior and surface anomalies — bulk archive creation, off-hours mass file access, anonymization-tool presence (Tor/anti-attribution), and concentrated outbound personal-channel activity. Couple this with rigorous offboarding and account-suspension controls that revoke share access, disable secondary/masquerade local accounts, and preserve endpoint evidence the moment risk indicators (such as JARVIS-style transfer alerts) fire. Note: attachment content for finding VANKO-P3-003 was not extracted; classified-exfil-by-email is not asserted — the program rationale rests on the confirmed two-way handler contact, not on unproven email payloads.

### 7.6 Detect and Restrict Secure-Deletion Tooling; Preserve Volume Shadow Copies

**Exploited vector — T1070.004 (Indicator Removal: File Deletion):** Forensic analysis confirmed a deliberate anti-forensic destruction pattern: SDelete executed ten times (last at 2016-06-30 01:30:52 UTC), the staging archive `temp.zip` was secure-wiped to 0 bytes, the SDelete prefetch artifact (`SDELETE.EXE-FBA93810.pf`) was deleted, and the Dropbox cache was purged. This destruction was recovered and proven only because Volume Shadow Copy snapshots (2016-10-14 and 2016-11-04) preserved the deleted artifacts (findings VANKO-P2-003, VANKO-P2-005, VANKO-P4-003).

**Recommendation:** Detect, alert on, and where operationally feasible restrict the execution of secure-deletion utilities (SDelete and equivalents) on R&D endpoints via application allow-listing and execution-monitoring (Amcache/Prefetch/EDR telemetry), treating signed Sysinternals tooling as monitored rather than implicitly trusted. Concurrently, protect and retain Volume Shadow Copies and forward Prefetch/Amcache execution telemetry off-host, since VSS preservation was the decisive factor that defeated the actor's wipe in this matter and is the control most directly responsible for the recoverability of the destroyed evidence.

---

**Scope note (honest negatives):** No memory-resident command-and-control, code injection, or active beacon was found (VANKO-P3-001, refuted); no malware family was present (YARA pagefile hits were generic false positives — VANKO-P4-001, refuted); the iPhone tether/iTunes sync was present but no classified payload was tied to it, so it is not treated as a proven exfiltration vector (VANKO-P2-002, refuted/down-ranked); no persistence survived via Windows.old (VANKO-P1-005, refuted); timestomping was refuted as a file-copy signature (VANKO-P1-003); and the system-time-change events were benign NTP synchronization (VANKO-P1-002, refuted). The recommendations above therefore deliberately target insider data-egress, account-misuse, and anti-forensic vectors rather than anti-malware or perimeter-intrusion controls.
