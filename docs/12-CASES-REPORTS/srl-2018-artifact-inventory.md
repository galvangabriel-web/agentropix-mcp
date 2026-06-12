# SRL-2018 Forensic Artifact Inventory

> *Mirrored (paths sanitized) from the engine repo's `SRL-2018-ARTIFACT-INVENTORY.md`. All IPs/hostnames below are internal to the SANS SRL-2018 case dataset, not this deployment.*

**Case:** SRL-2018 (SANS Holiday Hack / SRL dataset)
**Analysis Date:** 2026-05-04
**Source Reports:**
- `Reports_results/SRL2018-FULL-20260501T000431Z/` — per-host disk IOC extraction
- `Reports_results/FULL-CASE-20260503T204414Z/_analysis/` — full-case correlation analysis
**Total Findings:** 9,578 across 29 hosts (7 disk + 22 memory)
**DC Recall:** 7/7 techniques (100%) — base-dc-cdrive ground truth

---

## Hosts in Scope

| Host | Type | Status | Recall |
|------|------|--------|--------|
| base-dc-cdrive | Disk | PASS | 7/7 (100%) |
| base-file-cdrive | Disk | PASS | PASS_NO_GT_SEALED |
| base-rd-01-cdrive | Disk | PASS | PASS_NO_GT_SEALED |
| base-rd-02-cdrive | Disk | PASS | PASS_NO_GT_SEALED |
| base-wkstn-01-c-drive | Disk | PASS | PASS_NO_GT_SEALED |
| base-wkstn-05-cdrive | Disk | PASS | PASS_NO_GT_SEALED |
| dmz-ftp-cdrive | Disk | PASS | PASS_NO_GT_SEALED |
| base-admin-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-av-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-dc-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-elf-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-file-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-file-snapshot5 | Memory | PASS | PASS_NO_GT_SEALED |
| base-hunt-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-mail-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-rd-02-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-rd-03-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-rd-04-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-rd-05-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-rd-06-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-rd01-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-sp-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-wkstn-01-mem | Memory | PASS | PASS_NO_GT_SEALED |
| base-wkstn-01-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-wkstn-02-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-wkstn-03-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-wkstn-04-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-wkstn-05-memory | Memory | PASS | PASS_NO_GT_SEALED |
| base-wkstn-06-memory | Memory | PASS | PASS_NO_GT_SEALED |

---

## Section 1 — IP Addresses

### 1.1 External / C2 Candidate IPs

| # | Type | Value | Port | Hosts | Confidence | Source File | MITRE |
|---|------|-------|------|-------|------------|-------------|-------|
| 1 | Public | `3.0.0.0` | unknown | base-mail-memory, base-rd-05-memory, base-rd-06-memory (3 hosts) | Medium | iocs_summary.md | T1071.001 |
| 2 | Public | `104.112.204.27` | unknown | base-wkstn-06-memory (1 host) | Medium | iocs_summary.md | T1071.001 |
| 3 | Public | `104.201.158.26` | unknown | base-wkstn-06-memory (1 host) | Medium | iocs_summary.md | T1071.001 |
| 4 | Public | `104.88.80.153` | unknown | base-wkstn-06-memory (1 host) | Medium | iocs_summary.md | T1071.001 |
| 5 | Public | `108.79.235.64` | 33000 | base-hunt-memory (1 host) | High — ESTABLISHED TCP | correlation_summary.md | T1071.001 |
| 6 | Public | `216.232.147.26` | unknown | base-wkstn-06-memory (1 host) | Medium | iocs_summary.md | T1071.001 |
| 7 | Public | `23.194.110.27` | unknown | base-hunt-memory (1 host) | Medium | iocs_summary.md | T1071.001 |
| 8 | Public | `23.45.116.11` | unknown | base-hunt-memory (1 host) | Medium | iocs_summary.md | T1071.001 |
| 9 | Public | `24.139.91.27` | unknown | base-wkstn-06-memory (1 host) | Medium | iocs_summary.md | T1071.001 |
| 10 | Public | `24.91.62.27` | unknown | base-wkstn-06-memory (1 host) | Medium | iocs_summary.md | T1071.001 |
| 11 | Public | `248.86.12.27` | unknown | base-wkstn-06-memory (1 host) | Medium | iocs_summary.md | T1071.001 |
| 12 | Public | `6.3.0.0` | unknown | dmz-ftp-cdrive (1 host) | Medium | iocs_summary.md | T1071.001 |
| 13 | Public | `88.197.234.24` | unknown | base-wkstn-06-memory (1 host) | Medium | iocs_summary.md | T1071.001 |

### 1.2 Internal / RFC1918 IPs (Anomalous)

| # | Type | Value | Port | Context | Hosts | Confidence | Source File | MITRE |
|---|------|-------|------|---------|-------|------------|-------------|-------|
| 1 | RFC1918 | `10.10.200.207` | 5672 (AMQP) | C2 host — ESTABLISHED TCP from multiple workstations; owner java.exe | base-rd-02-memory, base-wkstn-02-memory, base-wkstn-03-memory, base-wkstn-06-memory (4) | High | correlation_summary.md | T1071.001 |
| 2 | RFC1918 | `172.16.4.10` | 8080 (HTTP) | Internal pivot — powershell.exe CLOSE_WAIT/CLOSED connections | base-file-memory, base-hunt-memory, base-rd-02-memory, base-sp-memory, base-wkstn-01-memory, base-wkstn-02-memory, base-wkstn-03-memory, base-wkstn-05-memory (8) | High | correlation_summary.md | T1071.001 |
| 3 | RFC1918 | `172.16.4.4` | 389/3268 (LDAP/GC) | Likely DC — heavy LDAP from 172.16.4.6 (possible Exchange) | base-dc-memory, base-elf-memory, base-file-memory, base-hunt-memory, base-rd-02-memory, base-sp-memory, base-wkstn-01-memory, base-wkstn-03-memory (8) | High | correlation_summary.md | T1078 |
| 4 | RFC1918 | `172.16.4.5` | 445 (SMB) | File server — heavy SMB from multiple hosts; subject_srv.exe port 3262 connection | base-elf-memory, base-file-memory, base-hunt-memory, base-rd-02-memory, base-sp-memory, base-wkstn-01-memory, base-wkstn-02-memory (8) | High | correlation_summary.md | T1021.002 |
| 5 | RFC1918 | `172.16.4.6` | 80/443/135/6577 | Heavy LDAP query target from DC; wkstn-06 OUTLOOK.EXE traffic; wkstn-03 RPC; possibly Exchange | base-dc-memory, base-file-memory, base-hunt-memory, base-wkstn-03-memory, base-wkstn-05-memory, base-wkstn-06-memory (6) | High | correlation_summary.md | T1071.001 |
| 6 | RFC1918 | `172.16.5.50` | 3262 | subject_srv.ex (F-Response) controller — all agents calling home | base-elf-memory, base-file-memory, base-hunt-memory, base-rd-02-memory, base-sp-memory, base-wkstn-01-memory, base-wkstn-02-memory, base-wkstn-03-memory, base-wkstn-05-memory, base-wkstn-06-memory (10) | Medium — benign DFIR agent | correlation_summary.md | — |
| 7 | RFC1918 | `10.10.254.1` | 61613 (ActiveMQ STOMP) | Puppet/MCollective broker — rubyw.exe connections from multiple hosts | base-file-memory, base-hunt-memory, base-rd-02-memory, base-wkstn-02-memory, base-wkstn-03-memory, base-wkstn-06-memory (6) | Medium | correlation_summary.md | T1071.001 |
| 8 | RFC1918 | `172.16.4.7` | 808/22233/3389/445 | SharePoint server — anomalous loopback port 808/22233 connections; RDP in from 172.16.5.26 | base-dc-memory, base-file-memory, base-sp-memory (3) | High | correlation_summary.md | T1021.001 |
| 9 | RFC1918 | `172.16.5.21` | 5985 (WinRM) | WinRM listener — lateral movement from wkstn-01, wkstn-05 | base-elf-memory, base-rd-02-memory, base-wkstn-01-memory, base-wkstn-05-memory (5) | High | correlation_summary.md | T1021.006 |

---

## Section 2 — File Hashes

### 2.1 MD5

| Hash | Host(s) | Tag | Confidence | Source File | MITRE |
|------|---------|-----|------------|-------------|-------|
| `54377DA4EA8D4E044BC107E65CF16EF3` | base-file-cdrive, base-rd-01-cdrive, base-rd-02-cdrive, base-wkstn-01-c-drive, base-wkstn-05-cdrive, dmz-ftp-cdrive (6) | Windows Installer Component GUID — FALSE POSITIVE per Gap A4 | Low — false positive | iocs_summary.md | — |
| `391be74b6830344eace7272f697cf1ae` | base-rd-01-cdrive (1) | Unknown flagged binary | Medium | iocs_summary.md | T1105 |
| `3d077998490d6b156ed95f8190628705` | base-file-cdrive (1) | Unknown flagged binary | Medium | iocs_summary.md | T1105 |
| `7542174a73f980db461103859b49371f` | base-wkstn-05-cdrive (1) | Unknown flagged binary | Medium | iocs_summary.md | T1105 |
| `acab21b25e436b6f1ced4ebd5c6e699f` | dmz-ftp-cdrive (1) | Unknown flagged binary | Medium | iocs_summary.md | T1105 |
| `de75f74d5c65d23d55bc5fc253ddb046` | base-rd-02-cdrive (1) | Unknown flagged binary | Medium | iocs_summary.md | T1105 |
| `e18b450127de04afb3211faa456ada27` | base-dc-cdrive (1) | Unknown flagged binary | Medium | iocs_summary.md | T1105 |
| `fd463e4eb6b5744c84b5ad138e7fec7f` | base-wkstn-01-c-drive (1) | Unknown flagged binary | Medium | iocs_summary.md | T1105 |

### 2.2 SHA-1

| Hash | Host(s) | Tag | Confidence | Source File | MITRE |
|------|---------|-----|------------|-------------|-------|
| (Gap — SHA-1 count 7 reported in iocs_summary.md but values not surfaced in any analysis file) | — | — | — | iocs_summary.md | — |

### 2.3 SHA-256

| Hash | Host(s) | Tag | Confidence | Source File | MITRE |
|------|---------|-----|------------|-------------|-------|
| `0226cfab692edfc1841588a766c1eac54c0906f638363050e63ff0c2168c80a0` | base-wkstn-01-c-drive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `022d0150d7ee137d4bebde8fb584982654cbf5c6a908ff87e97514dbd4d469de` | base-wkstn-05-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `0983a28e9980d5f7d0855ef2c60e4af2c57778c7aad91ef4224be71670a29798` | base-wkstn-05-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `0c3e5a6fe8b83375bc531cc5c6c3a2bad94557d27a51b69969d2423e3f7a5906` | dmz-ftp-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `0f09da4630405f79ca0df27712a21fd30d53558cc34dd74ac7c945ad9c937401` | base-rd-01-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `1e58f1e058d3cfa91206300badec9dc3ca548d8ea9aeddbbdac61dc894191911` | base-rd-01-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `25df045b72ea9ef95164e326a5c1ae2a094059c3e66691fdf8ca849e2d21d345` | dmz-ftp-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `26c8e11e52f99c428cd3bd301e1f8d07b6ef697951cdb8b2269c1633bbf13867` | base-wkstn-05-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `337baa871cb684ae420f4bad04b5f9d0f1cb9b2e2cd7522d33de993616a42897` | base-rd-02-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `4e155a85656a6183f374ff574075abb53d496b95ae22acf120d75656ded24d51` | base-file-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `57f324df769b071dda7189f6ca01c73b5f4f7b455e0f0429a32079b0a221617c` | base-rd-01-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `5d39d594a1f32e4ed8202955ab54b6dca5367c4af4006cc07ae37b951f7228f1` | base-rd-01-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `64931bb48329d424ad28fe781f8522941c6618e18f258c05ddc7e46f90a3b1b8` | base-file-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `82076f02880fc1882dffaaea3bd4ee1a072066d00a8ecc30b07b68ee86600432` | base-file-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `85cde89b715dd8abf1192df36c9c52b779d693ca05b18f0ddf243e24abc5615c` | dmz-ftp-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `8a03ba7621fc0cfd0335c4d2efee4f9403f70c8a6c0462ede76b1a95a02c40d1` | base-dc-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `99e125b3193f4e137c17ae02894facbcffc35fdd9abf71ac4b62073a553ca57b` | base-rd-02-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `9a138ede1ff426d3d1d7048e5ac64448503445651f7d0e99aa060c037dc4c151` | base-wkstn-01-c-drive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `9e379c35bf018e13ffb8a98562f1b40d51c017817b5aac1e76f9231c9e7a427d` | base-dc-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `a1656867b1945c9aece5cc6320a9315ce55cc710b59084ea09acf6adad873521` | dmz-ftp-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `a401840aa8ac8b8e5690ea75ddde29033b53dbc0ca9ce87c5ba606dce4834ad6` | base-dc-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `a8b100c56b8f47a7d50a61199752fff518b24b1d95e97282895b276eee16f973` | base-file-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `bcf639115a6b5995ef56734c76d3d40fd8b758b687a111b2a6f6744d91b9a78d` | base-dc-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `cbaa919d648f2f6f17d75e9f281676b04d4b6c615519f7c80a125bb191dff0bf` | base-wkstn-05-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| `d31f46a5348125c9c500ad029086bf38531a2e3108b4cee6d7565dc4b6603bd9` | base-wkstn-05-cdrive | Flagged binary | Medium | iocs_summary.md | T1105 |
| (10 additional SHA-256s from iocs_summary.md count of 35 not yet listed — values not fully paginated in source) | — | — | — | iocs_summary.md | — |

---

## Section 3 — YARA Rules

### 3.1 Deployed Rules

| Rule Name | File | Target | Hit Count | Source File |
|-----------|------|--------|-----------|-------------|
| (Gap — `yara_hunt.empty` reported per host; no YARA rules were deployed or produced hits in this run) | — | — | 0 | GAPS-2026-05-04.md (Gap B: "YARA empty (`yara_hunt.empty` per host); no rule deployed") |

### 3.2 Derivable YARA Rules (from findings)

| Proposed Rule Name | Basis | Indicator String / Pattern | MITRE |
|--------------------|-------|---------------------------|-------|
| `SRL2018_CobaltStrike_Beacon_Token` | Cross-source 'beacon' token agreement across 7 disk hosts (1360 total findings) | String `"beacon"` appearing in artifact + filesystem + timeline correlation | T1071.001 |
| `SRL2018_PowerShell_IEX_Downloader` | Decoded PowerShell commands from MASTER-IOCS.json; pattern: `-nop -exec bypass -EncodedCommand` followed by `IEX ((new-object net.webclient).downloadstring(` | `IEX ((new-object net.webclient).downloadstring('http://127.0.0.1:` | T1059 |
| `SRL2018_SubjectSrv_Network` | subject_srv.exe connecting to port 3262 across 12 memory hosts | Process `subject_srv.ex` with TCP on port 3262 to 172.16.5.50 | T1071.001 |
| `SRL2018_AMQP_C2_Java` | java.exe ESTABLISHED to 10.10.200.207:5672 across 4 hosts | Process `java.exe` with TCP ESTABLISHED to port 5672 | T1071.001 |
| `SRL2018_RWX_VAD_PowerShell_Injection` | PAGE_EXECUTE_READWRITE VADs in powershell.exe on 4 memory hosts | VAD tag `VadS`, protection `PAGE_EXECUTE_READWRITE`, owner `powershell.exe` | T1055.001 |
| `SRL2018_Userinit_Hijack` | Winlogon Userinit set to `cmd.exe` on base-dc-cdrive | Registry value `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit` = `cmd.exe` | T1547 |
| `SRL2018_PsExec_MOTW` | PsExec confirmed on base-file-cdrive and dmz-ftp-cdrive | Filename `PsExec.exe` or `PsExec64.exe` in user-writable paths | T1570 |
| `SRL2018_Mobsync_Suspect_Beacon` | mobsync.exe identified as suspect beacon process across 7 disk hosts | Filename `mobsync.exe` in hunt.correlate pivot | T1071.001 |

---

## Section 4 — MITRE ATT&CK Techniques

| Technique | Name | Hosts Affected | Finding Count | Confidence | Triggering Artifacts | Source File | Wazuh Default Rule? |
|-----------|------|---------------|--------------|------------|---------------------|-------------|---------------------|
| T1003.002 | SAM — OS Credential Dumping | 7 disk + 11 memory = 18 hosts | 717 | High | artifact.registry.appinitdlls, artifact.registry.lastloggedon, artifact.registry.profilelist, artifact.registry.powershellcore | technique_matrix.md | No — custom rule needed (SAM registry access; Wazuh 4.x has no default SAM dump rule; sysmon rule 11 pattern required) |
| T1053.005 | Scheduled Task | 7 disk hosts | 705 | High | timeline.plaso (schtasks.exe LOLBin), artifact sources | technique_matrix.md | Yes — Rule 60012 (Scheduled Task creation via EID 4698) |
| T1055 | Process Injection | All 29 hosts | 210 | High | memory.malfind, injection_detector (PAGE_EXECUTE_READWRITE VADs) | technique_matrix.md | No — custom rule needed (Wazuh 4.x lacks default memory injection rules; Sigma-based custom rule recommended) |
| T1055.001 | Dynamic-link Library Injection | base-admin-memory, base-rd-03-memory, base-rd-04-memory, base-rd-05-memory, base-rd-06-memory, base-rd01-memory, base-wkstn-04-memory (7 memory) | 108 | High | injection_detector PAGE_EXECUTE_READWRITE VADs; powershell.exe RWX VADs | technique_matrix.md | No — custom rule needed |
| T1059 | Command/Scripting Interpreter | 7 disk hosts | 391 | High | timeline.plaso LOLBin: powershell.exe, cmd.exe, rundll32.exe; MASTER-IOCS.json decoded PS | technique_matrix.md / MASTER-IOCS.json | Yes — Rule 18107 area (cmd.exe execution); No default PS rule — custom needed for EID 4104/4103 |
| T1070.004 | File Deletion | base-dc-cdrive, base-rd-01-cdrive, base-rd-02-cdrive, base-wkstn-01-c-drive, base-wkstn-05-cdrive, dmz-ftp-cdrive (6 disk) | 138 | High | timeline.plaso file deletion events | technique_matrix.md | No — custom rule needed (EID 4663 object deletion, not in Wazuh 4.x defaults) |
| T1070.006 | Timestomp | 7 disk hosts | 375 | High | timeline.plaso MACB anomalies (all 7 disks, ~49–60 findings each) | technique_matrix.md | No — custom rule needed |
| T1071.001 | Web Protocols (C2 over HTTP/S) | 7 disk hosts (beacon token); multiple memory | 7 (disk pivot) + 1360 correlation | High | cross-source 'beacon' token; PowerShell IEX downloadstring; wkstn-06 OUTLOOK/HTTPS; wkstn-05 to 172.16.4.6:443 | technique_matrix.md / correlation_summary.md | No — custom rule needed (requires HTTP content inspection or NGFW) |
| T1078 | Valid Accounts | 7 disk hosts | 10 | High | artifact.registry.profilelist SIDs; EID 4648 explicit credential events; log clear events | technique_matrix.md / MASTER-IOCS.json | Yes — Rule 18107 (EID 4624 logon); Rule 18104 (EID 4625 failed logon) |
| T1105 | Ingress Tool Transfer | 7 disk hosts | 538 | High | timeline.plaso staged binaries (mobsync.exe, PsExec.exe, etc.); prefetch hits | technique_matrix.md | No — custom rule needed (file drop via network share; EID 5140/5145 not default in Wazuh) |
| T1218.011 | Rundll32 | 7 disk hosts | 6 | High | timeline.plaso rundll32.exe LOLBin; correlation token count 50+ across 9 hosts | technique_matrix.md / correlation_summary.md | Yes — Rule 92200-series (Sysmon EID 1 process creation); base Wazuh has no specific rundll32 rule without Sysmon |
| T1543.003 | Windows Service | 10 memory hosts | 4579 | Medium — majority are legitimate services | memory.service (all memory dumps); McAfee/Puppet/svchost services | technique_matrix.md | Yes — Rule 7045 (Service Install EID 7045); Wazuh rule 7045-related (System channel) |
| T1547.001 | Registry Run Keys | 7 disk hosts | 30 | High | timeline.plaso Run key writes; HKLM\...\Run, HKCU\...\Run, WOW6432Node | technique_matrix.md / accounts_summary.md | Yes — Rule 92200-series (Sysmon EID 13 registry set); No default Wazuh rule without Sysmon — custom rule needed for EVTX registry auditing |

---

## Section 5 — Windows Event IDs

| Event ID | Name | Hosts | Count | Context | Source File | Wazuh Rule ID |
|----------|------|-------|-------|---------|-------------|---------------|
| 1102 | Security Log Clear | base-file-cdrive, base-rd-01-cdrive, base-rd-02-cdrive, base-wkstn-05-cdrive, dmz-ftp-cdrive (5) | 5 events | Cleared by: spsql@shieldbase (file), Administrator@WIN10-TEST (rd-01/rd-02), Administrator@MICROSO-KRES3SE (wkstn-05), Administrator@WINDOWS2012R2 (dmz-ftp) | MASTER-IOCS.json | Yes — Rule 18145 |
| 4624 | Logon | All disk hosts (sampled 1 per host) | 1 per host (sampled) | Type-3 network logons visible; full stream not available (Gap A2) | MASTER-IOCS.json / GAPS-2026-05-04.md | Yes — Rule 18107 |
| 4625 | Failed Logon | (Gap — 0 examples extracted due to 1-per-template sampling) | 0 surfaced | Gap A2: verbose evtx mode not enabled | GAPS-2026-05-04.md | Yes — Rule 18104 |
| 4634 | Logoff | (Gap — not extracted) | 0 surfaced | Gap A2 | GAPS-2026-05-04.md | Yes — Rule 18107-related |
| 4648 | Logon with explicit credentials | base-dc-cdrive (17+ events), other disk hosts | 17+ on DC alone | subject_user/target_user fields all null due to truncation (Gap A3); timestamps 2018-09-04 to 2018-09-04 | MASTER-IOCS.json | Yes — Rule 18152 |
| 4672 | Special privileges assigned | (Gap — not extracted per Gap A2) | 0 surfaced | Gap A2 | GAPS-2026-05-04.md | Yes — Rule 18107-related |
| 4698 | Scheduled Task Created | base-rd-01-cdrive, base-rd-02-cdrive, dmz-ftp-cdrive, base-wkstn-01-c-drive, base-wkstn-05-cdrive, base-dc-cdrive, base-file-cdrive (7) | 705 technique findings | Corroborates T1053.005 findings from plaso; task names not extracted | technique_matrix.md | Yes — Rule 60012 |
| 4720 | User Account Created | (Gap — not extracted per Gap A2) | 0 surfaced | Gap A2: T1136 detection blocked | GAPS-2026-05-04.md | Yes — Rule 18140 |
| 7045 | Service Installed | Memory hosts (service enumeration) | 4579 total service findings | Majority legitimate services; McAfee, Puppet (rubyw.exe/mcollective), svchost variants | technique_matrix.md / accounts_summary.md | Yes — Rule 7045-related (Wazuh System channel) |

---

## Section 6 — Registry Keys (Malicious / Suspicious)

| Registry Key | Host(s) | MITRE | Confidence | Context | Source File |
|-------------|---------|-------|------------|---------|-------------|
| `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run` | base-dc-cdrive, base-file-cdrive, base-rd-01-cdrive, base-rd-02-cdrive, base-wkstn-01-c-drive, base-wkstn-05-cdrive, dmz-ftp-cdrive (7) | T1547.001 | High | Run key persistence writes confirmed by timeline.plaso on all 7 disk hosts | iocs_summary.md / accounts_summary.md |
| `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` | base-rd-01-cdrive, base-rd-02-cdrive, base-wkstn-01-c-drive, base-wkstn-05-cdrive (4) | T1547.001 | High | Per-user Run key writes; HKCU persistence | iocs_summary.md / accounts_summary.md |
| `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce` | base-rd-01-cdrive, base-rd-02-cdrive, base-wkstn-01-c-drive, base-wkstn-05-cdrive (4) | T1547.001 | High | RunOnce persistence — single-execution implant staging | iocs_summary.md |
| `HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run` | base-dc-cdrive, base-rd-01-cdrive, base-rd-02-cdrive, base-wkstn-01-c-drive (4) | T1547.001 | High | 32-bit on 64-bit OS Run key persistence | iocs_summary.md / accounts_summary.md |
| `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run` | base-wkstn-05-cdrive (1) | T1547.001 | High | Alternate-case WOW6432Node Run key | iocs_summary.md |
| `HKEY_LOCAL_MACHINE\System\ControlSet001\Control\Session` | base-dc-cdrive, base-rd-01-cdrive, base-rd-02-cdrive, base-wkstn-01-c-drive, base-wkstn-05-cdrive, dmz-ftp-cdrive (6) | T1112 | Medium | Session Manager modifications — potential IFEO or boot persistence | iocs_summary.md |
| `HKEY_LOCAL_MACHINE\System\ControlSet002\Control\Session` | base-dc-cdrive, base-wkstn-05-cdrive, dmz-ftp-cdrive (3) | T1112 | Medium | ControlSet002 session modifications | iocs_summary.md |
| `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\` | base-file-cdrive, base-rd-01-cdrive, base-rd-02-cdrive, base-wkstn-01-c-drive, base-wkstn-05-cdrive, dmz-ftp-cdrive (6) | T1078 | Medium | UserAssist tracks executed programs — reveals attacker-run binaries | iocs_summary.md |
| `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` (Userinit value) | base-dc-cdrive (1) | T1547 | High | Userinit hijack: `cmd.exe` instead of `userinit.exe` — persistence smoking gun | accounts_summary.md |
| `HKEY_LOCAL_MACHINE\System\ControlSet001\Services\SharedAccess\Parameters\Firewall` | base-file-cdrive (1) | T1562.004 | Medium | Firewall configuration modification | iocs_summary.md |
| `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` | base-rd-01-cdrive (1) | T1078 | Medium | RunMRU reveals commands typed in Run dialog | iocs_summary.md |
| `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | dmz-ftp-cdrive (1) | T1078 | Medium | RecentDocs reveals recently accessed files | iocs_summary.md |

---

## Section 7 — Service Names (Flagged)

| Service Name | Binary Path | Host(s) | MITRE | Confidence | Flag Reason | Source File |
|-------------|------------|---------|-------|------------|-------------|-------------|
| mcollective (Marionette Collective Server) | `"C:\Program Files\Puppet Labs\Puppet\sys\ruby\bin\rubyw.exe" -I"C:\Prog...` | base-rd-03-memory, base-rd-04-memory, base-rd-05-memory, base-rd-06-memory, base-wkstn-04-memory | T1543.003 | Medium — Puppet agent; assess as attacker-installed or legitimate | Puppet MCollective: C2-style remote execution framework over AMQP (port 61613 to 10.10.254.1) | accounts_summary.md |
| McShield (McAfee McShield) | `"C:\Program Files\Common Files\McAfee\SystemCore\mcshield.exe"` | base-rd-03-memory, base-rd-04-memory, base-rd-05-memory, base-rd-06-memory, base-rd01-memory, base-wkstn-01-mem, base-wkstn-04-memory (7) | T1543.003 | Low — legitimate AV | McAfee AV — flagged as non-baseline by engine; likely legitimate | accounts_summary.md |
| McAfeeFramework | `"C:\Program Files\McAfee\Agent\x86\macompatsvc.exe"` | base-rd-03-memory, base-rd-04-memory, base-rd-05-memory, base-rd-06-memory, base-wkstn-04-memory | T1543.003 | Low — legitimate AV | McAfee Agent backwards compat service | accounts_summary.md |
| masvc (McAfee Agent Service) | `"C:\Program Files\McAfee\Agent\masvc.exe" /ServiceStart` | base-rd-03-memory, base-rd-04-memory, base-rd-05-memory, base-rd-06-memory | T1543.003 | Low — legitimate AV | McAfee Agent service | accounts_summary.md |
| macmnsvc (McAfee Agent Common Services) | `"C:\Program Files\McAfee\Agent\macmnsvc.exe" /ServiceStart` | base-rd-05-memory, base-rd-06-memory | T1543.003 | Low — legitimate AV | McAfee common services | accounts_summary.md |
| subject_srv (F-Response Subject) | `C:\windows\subject_srv.exe -s "base-hunt.shieldbase.lan:5682" -l 3262 -v "F-Response Subject"` | base-file-memory, base-wkstn-06-memory (and 10 others via TCP port 3262) (12) | — | Low (benign DFIR tool) — per Gap A5 | F-Response commercial DFIR agent — MISLABELED as malware in existing GT (Gap A5); connects to 172.16.5.50:3262 | GAPS-2026-05-04.md |
| WdiServiceHost (Diagnostic Service Host) | `c:\windows\system32\svchost.exe -k localservice -p` | base-admin-memory | T1543.003 | Low — legitimate | Flagged by non-baseline process scan; legitimate Windows service | accounts_summary.md |

---

## Section 8 — C2 / Anomalous Network Connections

| Host | Proto | Local | Foreign | State | Owner Process | PID | Port | Category | Confidence | MITRE |
|------|-------|-------|---------|-------|--------------|-----|------|----------|------------|-------|
| base-hunt-memory | TCPv4 | `172.16.5.25:64720` | `108.79.235.64:33000` | ESTABLISHED | — | 0 | 33000 | External C2 — non-standard port | High | T1071.001 |
| base-hunt-memory | TCPv4 | `172.16.5.25:64722` | `172.16.4.6:443` | ESTABLISHED | — | 0 | 443 | HTTPS to internal server | Medium | T1071.001 |
| base-hunt-memory | TCPv4 | `172.16.5.25:63064` | `172.16.4.5:445` | ESTABLISHED | — | 0 | 445 | SMB lateral movement | Medium | T1021.002 |
| base-hunt-memory | TCPv4 | `172.16.5.25:62541` | `172.16.5.50:445` | ESTABLISHED | — | 0 | 445 | SMB to F-Response controller | Medium | T1021.002 |
| base-file-memory | TCPv4 | `10.10.4.5:59361` | `10.10.254.1:61613` | ESTABLISHED | rubyw.exe | 1156 | 61613 | ActiveMQ STOMP / Puppet broker | Medium | T1071.001 |
| base-file-memory | TCPv4 | `172.16.4.5:3262` | `172.16.5.50:44262` | ESTABLISHED | subject_srv.ex | 6160 | 3262 | F-Response agent — benign | Low | — |
| base-file-memory | TCPv4 | `172.16.4.5:56932` | `172.16.4.10:8080` | CLOSE_WAIT | powershell.exe | 3164 | 8080 | PowerShell HTTP beacon (C2) | High | T1071.001 |
| base-file-memory | TCPv4 | `172.16.4.5:54794` | `172.16.4.10:8080` | CLOSED | powershell.exe | 4072 | 8080 | PowerShell HTTP beacon (C2) | High | T1071.001 |
| base-rd-02-memory | TCPv4 | `10.10.150.180:49722` | `10.10.200.207:5672` | ESTABLISHED | — | 0 | 5672 | AMQP C2 | High | T1071.001 |
| base-rd-02-memory | TCPv4 | `10.10.150.180:61643` | `10.10.254.1:61613` | ESTABLISHED | — | 0 | 61613 | ActiveMQ STOMP / Puppet broker | Medium | T1071.001 |
| base-rd-02-memory | TCPv4 | `172.16.6.12:3262` | `172.16.5.50:50146` | ESTABLISHED | — | 0 | 3262 | F-Response agent | Low | — |
| base-wkstn-02-memory | TCPv4 | `10.10.150.183:49746` | `10.10.200.207:5672` | ESTABLISHED | — | 0 | 5672 | AMQP C2 | High | T1071.001 |
| base-wkstn-02-memory | TCPv4 | `10.10.150.183:52341` | `10.10.254.1:61613` | ESTABLISHED | — | 0 | 61613 | ActiveMQ STOMP / Puppet broker | Medium | T1071.001 |
| base-wkstn-03-memory | TCPv4 | `10.10.150.179:49744` | `10.10.200.207:5672` | ESTABLISHED | — | 0 | 5672 | AMQP C2 | High | T1071.001 |
| base-wkstn-03-memory | TCPv4 | `172.16.7.13:64007` | `172.16.4.10:8080` | ESTABLISHED | — | 0 | 8080 | HTTP internal pivot C2 | High | T1071.001 |
| base-wkstn-03-memory | TCPv4 | `172.16.7.13:62102` | `172.16.4.6:6577` | ESTABLISHED | — | 0 | 6577 | Non-standard port to internal server | Medium | T1071.001 |
| base-wkstn-03-memory | TCPv4 | `172.16.7.13:62103` | `172.16.4.6:6577` | ESTABLISHED | — | 0 | 6577 | Non-standard port to internal server | Medium | T1071.001 |
| base-wkstn-05-memory | TCPv4 | `172.16.7.15:57141` | `172.16.4.6:443` | ESTABLISHED | — | 0 | 443 | HTTPS to internal server | Medium | T1071.001 |
| base-wkstn-05-memory | TCPv4 | `172.16.7.15:57094` | `172.16.4.6:443` | ESTABLISHED | — | 0 | 443 | HTTPS to internal server | Medium | T1071.001 |
| base-wkstn-05-memory | TCPv4 | `172.16.7.15:57170` | `172.16.5.21:5985` | ESTABLISHED | — | 0 | 5985 | WinRM lateral movement | High | T1021.006 |
| base-wkstn-06-memory | TCPv4 | `10.10.150.177:49210` | `10.10.200.207:5672` | ESTABLISHED | java.exe | 1752 | 5672 | AMQP C2 — java.exe owner (needs verification) | High | T1071.001 |
| base-wkstn-06-memory | TCPv4 | `10.10.150.177:58626` | `10.10.254.1:61613` | ESTABLISHED | rubyw.exe | 5796 | 61613 | ActiveMQ STOMP / Puppet broker | Medium | T1071.001 |
| base-wkstn-06-memory | TCPv4 | `172.16.7.16:54103` | `172.16.4.6:80` | ESTABLISHED | OUTLOOK.EXE | 3044 | 80 | Outlook HTTP — possible phishing follow-on | Medium | T1566 |
| base-wkstn-06-memory | TCPv4 | `172.16.7.16:3262` | `172.16.5.50:46980` | ESTABLISHED | subject_srv.ex | 488 | 3262 | F-Response agent — benign | Low | — |
| base-dc-memory | TCPv4 | `172.16.4.4:389` | `172.16.4.6:51960` | ESTABLISHED | — | 0 | 389 | LDAP from 172.16.4.6 to DC — possible Exchange/recon | Medium | T1018 |
| base-dc-memory | TCPv4 | `172.16.4.4:3268` | `172.16.4.6:50442` | ESTABLISHED | — | 0 | 3268 | LDAP Global Catalog query from 172.16.4.6 | Medium | T1018 |
| base-elf-memory | TCPv4 | `172.16.5.21:5985` | `172.16.7.11:55308` | ESTABLISHED | — | 0 | 5985 | WinRM inbound from wkstn-01 | High | T1021.006 |
| base-elf-memory | TCPv4 | `172.16.5.21:53384` | `172.16.4.5:445` | ESTABLISHED | — | 0 | 445 | SMB to file server | Medium | T1021.002 |
| base-sp-memory | TCPv4 | `172.16.4.7:3389` | `172.16.5.26:55716` | ESTABLISHED | — | 0 | 3389 | RDP inbound — lateral movement | High | T1021.001 |

---

## Section 9 — Process Injection Evidence

| Host | Process | PID(s) | VAD Tag | Protection | Address | Finding Count | MITRE | Confidence | Source File |
|------|---------|--------|---------|------------|---------|--------------|-------|------------|-------------|
| base-rd-04-memory | powershell.exe | 2664, 4520, 4896, 5452 | VadS | PAGE_EXECUTE_READWRITE | `0xba00000` (sample) | 26 RWX VADs | T1055.001 | High | powershell_summary.md |
| base-rd-05-memory | powershell.exe | 17144, 17612, 20780 | VadS | PAGE_EXECUTE_READWRITE | `0x900000` (sample) | 38 RWX VADs | T1055.001 | High | powershell_summary.md |
| base-rd01-memory | powershell.exe | 8712 | VadS | PAGE_EXECUTE_READWRITE | `0x1b4ce1a0000` (sample) | 6 RWX VADs | T1055.001 | High | powershell_summary.md |
| base-wkstn-04-memory | powershell.exe | 1288, 4340 | VadS | PAGE_EXECUTE_READWRITE | `0x1c402430000` (sample) | 22 RWX VADs | T1055.001 | High | powershell_summary.md |
| base-av-memory | svchost.exe | multiple | VadS | PAGE_EXECUTE_READWRITE | (not specified) | 86 process + 63 svchost.exe correlation findings | T1055 | High | correlation_summary.md |
| base-rd-04-memory | powershell.exe | 2664, 4520, 4896, 5452 | VadS | PAGE_EXECUTE_READWRITE | (multiple) | 27 malfind total | T1055 | High | technique_matrix.md |
| base-rd-05-memory | powershell.exe | 17144, 17612, 20780 | VadS | PAGE_EXECUTE_READWRITE | (multiple) | 27 malfind total | T1055 | High | technique_matrix.md |
| base-wkstn-04-memory | powershell.exe | 1288, 4340 | VadS | PAGE_EXECUTE_READWRITE | (multiple) | 12 T1055 findings | T1055 | High | technique_matrix.md |
| base-rd-03-memory | (multiple) | (multiple) | VadS | PAGE_EXECUTE_READWRITE | (not specified) | 4 T1055 + 4 malfind findings | T1055 | Medium | technique_matrix.md |
| base-rd-06-memory | (multiple) | (multiple) | VadS | PAGE_EXECUTE_READWRITE | (not specified) | 4 T1055 + 4 malfind findings | T1055 | Medium | technique_matrix.md |

---

## Section 10 — Credential Artifacts

| Type | Value | Host(s) | Context | Confidence | Source File |
|------|-------|---------|---------|------------|-------------|
| User SID | `S-1-5-21-3204118025-1178511089-2137043725-1001` | base-rd-01-cdrive, base-rd-02-cdrive | RID 1001 — non-Administrator local user | Medium | iocs_summary.md / accounts_summary.md |
| User SID | `S-1-5-21-3445421715-2530590580-3149308974-1193` | base-rd-01-cdrive, base-rd-02-cdrive | RID 1193 — domain user; domain S-1-5-21-3445421715-2530590580-3149308974 | Medium | iocs_summary.md / accounts_summary.md |
| User SID | `S-1-5-21-4006758617-974418256-2448025512-1001` | base-rd-01-cdrive, base-rd-02-cdrive | RID 1001 — local user on second domain | Medium | iocs_summary.md / accounts_summary.md |
| User SID (Administrator) | `S-1-5-21-42126767-2996440306-3211011523-500` | base-rd-01-cdrive, base-rd-02-cdrive | RID 500 — built-in Administrator account (third domain) | High | iocs_summary.md / accounts_summary.md |
| User SID | `S-1-5-21-3445421715-2530590580-3149308974-1116` | base-rd-01-cdrive | RID 1116 — domain user (shieldbase domain) | Medium | accounts_summary.md |
| User SID | `S-1-5-21-3445421715-2530590580-3149308974-1177` | base-rd-02-cdrive | RID 1177 — domain user (shieldbase domain) | Medium | accounts_summary.md |
| User SID | `S-1-5-21-3445421715-2530590580-3149308974-1183` | base-rd-02-cdrive | RID 1183 — domain user (shieldbase domain) | Medium | accounts_summary.md |
| User SID | `S-1-5-21-3445421715-2530590580-3149308974-1192` | base-rd-02-cdrive | RID 1192 — domain user (shieldbase domain) | Medium | accounts_summary.md |
| User SID (Admin) | `S-1-5-21-3445421715-2530590580-3149308974-500` | base-rd-01-cdrive | RID 500 — built-in Administrator (shieldbase domain) | High | accounts_summary.md |
| User SID | `S-1-5-21-572887454-1858499753-1978773125-1003` | dmz-ftp-cdrive | RID 1003 — local user on DMZ FTP host | Medium | accounts_summary.md |
| Log Clear Actor | spsql@shieldbase | base-file-cdrive | Cleared Security log at 2018-09-06T16:37:25Z; logon_id 0x7cabe97 | High | MASTER-IOCS.json |
| Log Clear Actor | Administrator@WIN10-TEST | base-rd-01-cdrive, base-rd-02-cdrive | Cleared Security log at 2018-05-04T22:14:29Z; logon_id 0x21fcb6 | High | MASTER-IOCS.json |
| Log Clear Actor | Administrator@MICROSO-KRES3SE | base-wkstn-05-cdrive | Cleared Security log at 2018-05-03T19:15:08Z; logon_id 0x24c0e | High | MASTER-IOCS.json |
| Log Clear Actor | Administrator@WINDOWS2012R2 | dmz-ftp-cdrive | Cleared Security log at 2018-03-14T20:48:48Z; logon_id 0x4a78b | High | MASTER-IOCS.json |
| Explicit Credential Logon (EID 4648) | (values null — Gap A3 truncation) | base-dc-cdrive (17+ events) | Multiple 4648 events 2018-09-04T13:05 through 2018-09-04T22:04; subject/target fields null due to truncation | Medium — timestamp pattern is meaningful | MASTER-IOCS.json |
| Winlogon Userinit Hijack | cmd.exe | base-dc-cdrive | HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon Userinit = cmd.exe | High | accounts_summary.md |
| SAM credential material | Available (offline dump possible) | base-dc-cdrive, base-file-cdrive, base-rd-01-cdrive, base-rd-02-cdrive, base-wkstn-01-c-drive, base-wkstn-05-cdrive, dmz-ftp-cdrive (7) | SOFTWARE hive appinitdlls, lastloggedon, profilelist, powershellcore keys accessible | High | accounts_summary.md |
| Correlation token | `tdungan` | multiple disk hosts | Username appearing 31 times across artifact + timeline; likely operator or privileged account | High | correlation_summary.md |

---

## Section 11 — PowerShell IOCs

| Host | PID | Type | Detail | Confidence | MITRE | Source File |
|------|-----|------|--------|------------|-------|-------------|
| base-file-cdrive | — | Decoded IEX — base64 encoded cmd | `powershell -nop -exec bypass -EncodedCommand` → `IEX ((new-object net.webclient).downloadstring('http://127.0.0.1:45586/'))` at 2018-09-06T17:01:46Z; user BASE-FILE$ | High | T1059 / T1105 | MASTER-IOCS.json |
| base-file-cdrive | — | Decoded IEX — base64 encoded cmd | `IEX ((new-object net.webclient).downloadstring('http://127.0.0.1:54345/'))` at 2018-09-06T17:08:43Z; user BASE-FILE$ | High | T1059 / T1105 | MASTER-IOCS.json |
| base-file-cdrive | — | Decoded IEX — base64 encoded cmd | `IEX ((new-object net.webclient).downloadstring('http://127.0.0.1:37890/'))` at 2018-09-06T17:10:32Z; user BASE-FILE$ | High | T1059 / T1105 | MASTER-IOCS.json |
| base-file-cdrive | — | Decoded IEX — base64 encoded cmd | `IEX ((new-object net.webclient).downloadstring('http://127.0.0.1:51937/'))` at 2018-09-06T17:13:52Z; user BASE-FILE$ | High | T1059 / T1105 | MASTER-IOCS.json |
| base-file-cdrive | — | Decoded IEX — base64 encoded cmd | `IEX ((new-object net.webclient).downloadstring('http://127.0.0.1:23792/'))` at 2018-09-06T17:24:47Z; user BASE-FILE$ | High | T1059 / T1105 | MASTER-IOCS.json |
| base-file-cdrive | — | Decoded IEX — base64 encoded cmd | `IEX ((new-object net.webclient).downloadstring('http://127.0.0.1:61799/'))` at 2018-09-06T17:43:45Z; user BASE-FILE$ | High | T1059 / T1105 | MASTER-IOCS.json |
| base-file-memory | 3164 | Network socket — CLOSE_WAIT | TCP `172.16.4.5:56932` → `172.16.4.10:8080` CLOSE_WAIT | High | T1071.001 | powershell_summary.md |
| base-file-memory | 4072 | Network socket — CLOSED | TCP `172.16.4.5:54794` → `172.16.4.10:8080` CLOSED; also UDP listener | High | T1071.001 | powershell_summary.md |
| base-sp-memory | 7520 | Network socket — UDP listener | UDP `0.0.0.0:0` + UDP `127.0.0.1:53043` listener — DNS or local C2 | Medium | T1071.004 | powershell_summary.md |
| base-rd-04-memory | 2664, 4520, 4896, 5452 | RWX VAD injection | 26 PAGE_EXECUTE_READWRITE VADs in powershell.exe; sample address 0xba00000 | High | T1055.001 | powershell_summary.md |
| base-rd-05-memory | 17144, 17612, 20780 | RWX VAD injection | 38 PAGE_EXECUTE_READWRITE VADs in powershell.exe; sample address 0x900000 | High | T1055.001 | powershell_summary.md |
| base-rd01-memory | 8712 | RWX VAD injection | 6 PAGE_EXECUTE_READWRITE VADs in powershell.exe; sample address 0x1b4ce1a0000 | High | T1055.001 | powershell_summary.md |
| base-wkstn-04-memory | 1288, 4340 | RWX VAD injection | 22 PAGE_EXECUTE_READWRITE VADs in powershell.exe; sample address 0x1c402430000 | High | T1055.001 | powershell_summary.md |
| base-rd-02-memory | 4940, 8276 | Process tree (pslist) | PPID 2600 / 7004 respectively — powershell.exe in suspicious lineage | Medium | T1059 | powershell_summary.md |
| base-wkstn-02-memory | 1844 | Process tree (pslist) | PPID 5408 — powershell.exe in suspicious lineage | Medium | T1059 | powershell_summary.md |
| base-dc-cdrive | — | Registry artifact | artifact.registry.powershellcore — PS core registry key present (T1003.002 credmat context) | Medium | T1059 | powershell_summary.md |
| base-file-cdrive | — | Registry artifact | artifact.registry.powershellcore — PS core registry key present | Medium | T1059 | powershell_summary.md |
| base-rd-01-cdrive | — | Registry artifact | artifact.registry.powershellcore — PS core registry key present | Medium | T1059 | powershell_summary.md |
| base-rd-02-cdrive | — | Registry artifact | artifact.registry.powershellcore — PS core registry key present | Medium | T1059 | powershell_summary.md |
| base-wkstn-01-c-drive | — | Registry artifact | artifact.registry.powershellcore — PS core registry key present | Medium | T1059 | powershell_summary.md |
| base-wkstn-05-cdrive | — | Registry artifact | artifact.registry.powershellcore — PS core registry key present | Medium | T1059 | powershell_summary.md |
| dmz-ftp-cdrive | — | Registry artifact | artifact.registry.powershellcore — PS core registry key present | Medium | T1059 | powershell_summary.md |
| All 7 disk hosts | — | LOLBin timeline | T1059 LOLBin findings in timeline.plaso for powershell.exe: 6 (dc), 9 (file), 2 (rd-01), 9 (rd-02), 10 (wkstn-05), 10 (dmz-ftp) | High | T1059 | powershell_summary.md |

---

## Section 12 — Data Gaps

| Gap ID | Description | Affected Categories | Impact |
|--------|-------------|--------------------|---------| 
| A1 | Plaso event timestamps stripped — `datetime=` field empty in all timeline.plaso findings; only 12 event-time strings survived out of 9,578 findings | Section 4 (technique timeline), Section 5 (event chronology), all time-ordered analysis | Cannot build wall-clock master timeline; cannot compute dwell time; cannot order operator actions chronologically |
| A2 | EVTX events sampled — only 1 example per (event-template × host); 0 examples of EID 4625/4634/4647/4648/4672/4720/4732/4697/4698/7045 in verbose form | Section 5 (Event IDs), Section 10 (Credentials), T1136/T1078/T1021 detection | Cannot build per-account login graph; cannot detect lateral movement via 4624 type-3 patterns; T1136 account creation undetectable |
| A3 | Evidence text truncated mid-string at ~250 chars — 4648 logon events show `S-1-0-0`, `-`, `-`, `0x0` clipped before target user/domain/source-IP | Section 10 (Credentials), Section 1.2 (internal IP attribution) | Cannot extract target username/domain/source IP from logon events; 17+ DC logon events have null fields |
| A4 | False-positive MD5 detection from Windows Installer GUIDs — `54377DA4EA8D4E044BC107E65CF16EF3` on 6 hosts is a Component GUID under `HKLM\Software\...\Installer\UserData\S-1-5-18\Components\` | Section 2.1 (MD5 hashes) | Noise in IOC catalog; risk of misleading threat-intel pivots |
| A5 | subject_srv.exe mislabeled as malware — actually F-Response DFIR agent (`-s "base-hunt.shieldbase.lan:5682" -l 3262 -v "F-Response Subject"`); existing GT incorrectly marks it as "known SRL-2018 malware shimcache hit" | Section 7 (Services), Section 8 (Connections), Section 9 (Process Injection via correlation) | Every future run misclassifies a benign IR tool as malware; wastes analyst time |
| A6 | Missing ground truth for 28/29 hosts — only base-dc-cdrive has a GT file; 6 disk + 22 memory hosts return PASS_NO_GT_SEALED | All sections (recall measurement) | Cannot measure recall for 96% of hosts; engine could be missing 50% of indicators on memory dumps |
| B1 | Initial Access gap — T1190 (Exploit Public-Facing): 0 findings; no web-server log analyzer in agentropix | Section 4 (MITRE matrix) | Initial access vector unconfirmed |
| B2 | Initial Access gap — T1566 (Phishing): 0 findings; OUTLOOK.EXE traffic observed but mail corpus not analyzed | Section 4 (MITRE matrix), Section 8 (Connections) | Phishing as initial access vector cannot be confirmed or ruled out |
| B3 | Discovery gap — T1018/T1083/T1087: 0 findings; no DiscoveryAgent; `net view`, `nltest`, `whoami` would need full EID 4688 stream | Section 4 (MITRE matrix) | Enumeration phase activity undetected |
| B4 | Credential Access gap — T1003.001 LSASS dump: 0 findings; Volatility mimikatz/hashdump plugins not invoked | Section 10 (Credentials) | LSASS dumping cannot be confirmed or ruled out |
| B5 | YARA empty — no YARA rules deployed; `yara_hunt.empty` per host; Mimikatz binary not detected | Section 3 (YARA Rules) | Zero YARA-based detections; Cobalt Strike, Mimikatz binaries not signature-matched |
| B6 | SMB share enumeration — `detect_sweep` wrapper for EID 5140/5145 exists but was not invoked; T1021.002 only partially covered | Section 8 (Connections) | Share access/enumeration activity not systematically detected |
| C1 | Per-file hashes for staged binaries not extracted — mobsync.exe, PsExec.exe, PsExec64.exe confirmed on disk but no hashes computed | Section 2 (Hashes), Section 7 (Services) | Cannot pivot staged binaries to threat-intel; cannot verify file integrity |
| C2 | Process tree sparse for memory dumps — only flagged processes surfaced; full pstree not rendered | Section 9 (Process Injection) | Cannot verify whether mobsync.exe/rundll32.exe/powershell.exe were spawned by suspicious parents |
| C3 | PowerShell script-block content not recovered — 92 RWX VAD findings prove injection but payload unknown; Volatility vaddump not invoked | Section 11 (PowerShell IOCs) | Cannot recover actual implant payloads loaded into injected PowerShell processes |
| C4 | SMB share burst detection not run — `wrappers/correlation.detect_sweep` not invoked in this run | Section 8 (Connections) | EID 5140/5145 burst patterns not analyzed |
| C5 | Mail/Exchange evidence not collected — 172.16.4.6 has heavy LDAP to DC and OUTLOOK traffic on wkstn-06 but no Exchange image in scope | Section 1 (IPs), Section 8 (Connections) | Presence/absence of phishing artifacts on mail server cannot be tested |

---

## ADR / Security-Audit Cross-Reference

| ADR | Relevance to SRL-2018 Findings |
|-----|-------------------------------|
| ADR-001: Timestamp integrity requirement | Gap A1 directly violates: all 9,578 findings have stripped timestamps; wall-clock timeline cannot be reconstructed without patching the agentropix plaso wrapper to populate `datetime=` |
| ADR-002: Ground truth sealed before recall measurement | Gap A6 violates: 28/29 hosts have no GT file; PASS_NO_GT_SEALED status means zero recall accountability for 96% of case; P1 priority to author 6 disk GT files, P3 for 22 memory hosts |
| ADR-003: IOC false-positive suppression | Gap A4 violates: MD5 `54377DA4EA8D4E044BC107E65CF16EF3` (Windows Installer GUID) surfaced across 6 hosts without suppression; Installer Component registry paths must be excluded from hex-string IOC extractor |
| ADR-004: Benign tool labeling in ground truth | Gap A5 violates: F-Response subject_srv.exe labeled as malware in GT (`run_correlation_proof.py:38 KNOWN_IOC = "subject_srv"`); must update GT to remove malware label; replacement with benign baseline label required |
| ADR-005: Verbose EVTX collection | Gap A2 violates: 1-per-template EVTX sampling blocks T1136, T1078 lateral chain, T1021 detection; P1 fix is verbose evtx mode capped at 5,000 events per host for EIDs 4624/4625/4648/4672/4720/4732/4697/4698/7045 |
| ADR-006: YARA coverage requirement | Gap B5 violates: zero YARA rules deployed; yara_hunt.empty per host; Cobalt Strike and Mimikatz binary signatures absent; Section 3.2 derivable rules should be encoded and deployed as a baseline YARA pack |
| ADR-007: Memory forensic completeness | Gaps C2/C3 violate: process tree rendering and RWX VAD dump not automated; 92 injection findings have no recovered payload; `build_process_tree` and `vaddump` for injected VADs ≥ 4KB should be Phase D steps |
| ADR-008: C2 protocol coverage | Gaps B6/C4 partially violate: AMQP (port 5672), ActiveMQ STOMP (port 61613), HTTP beacon (port 8080), non-standard 33000 (external) all detected via memory sockets but not by dedicated C2 heuristic; `detect_sweep` for SMB not invoked |
