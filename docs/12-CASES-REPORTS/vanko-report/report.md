# VANKO — "The Case of the Abducted Zebrafish"
## Forensic Synthesis Report

> **Case:** `VANKO-ABDUCTED-ZEBRAFISH` · **Type:** insider threat / IP theft · **Severity:** high
> **Subject:** Anthony Vanko (`C:\Users\PC User`, MS account `anthony.vanko`), biochemical engineer, Stark Enterprises DC R&D
> **Evidence:** Surface 3 physical disk image `surface_physical.E01`–`.E21` (FTK Imager, examiner Ovie Carroll, acquired **2016-11-04**, case `20161104`) — MD5 `4032d556cc866c23f1e797410e95603c`, SHA1 `e0e72dfcef167dd358813726e82f6c235bc85ce7` (EWF-embedded, verified).
> **Method:** Agentropix-SIFT MCP toolchain (Plaso, MFTECmd, EvtxECmd, RECmd/LECmd/JLECmd, Amcache, SrumECmd, Volatility 3, bulk_extractor, YARA, libvshadow). Every action recorded to `session-actions.log`.
> **Finding base:** 19 findings across 5 phases → **10 confirmed, 9 refuted, 0 unresolved** (`FINDINGS.jsonl`). DRAFT → APPROVED remains a human-only HMAC hard-stop; this report is examiner-review material, not self-approved.

---

## 1. EXECUTIVE SUMMARY

### Overview
Anthony Vanko, a **trusted insider** with authorized access, exfiltrated classified zebrafish-DNA and cell-regeneration trade secrets from Stark Enterprises to **two foreign buyer channels (China and Russia)**. This is **not a malware intrusion** — no implant, no C2 beacon, and no host-to-host lateral movement was found, and the only YARA "family" hits were generic memory false positives. The actor used **his own valid credentials, signed admin tools (7-Zip, SysInternals SDelete, FTK Imager), a masquerade local account, removable media, and cloud/email channels**, then attempted to destroy the evidence with secure-deletion. The wipe **failed** because Volume Shadow Copies preserved the deleted artifacts.

### Timeline (key events, EST → as recorded)
| When | Event |
|---|---|
| 2016-04-30 | Classified docs copied from `\\STARK-FILESERVE` into `OneDrive\Documents\Level_*` (MFT copy-signatures) |
| 2016-06-16 | Internal contact (Kylie Normandy) correspondence resumes |
| 2016-06-18 | **Masquerade local account `defaultprinter` created**; "research paper" thread with `nina_kwai@qq.com` (China) |
| 2016-06-22/23 | Classified material surfaces on a **Chinese university file share** (JARVIS tip-off) |
| 2016-06-27 17:24 | Recruitment email **"Potential Opportunity?"** from `mmerr001@gmail.com` (Merrick → recruiter V. Bulgakov, Russia) |
| 2016-06-27 21:22 | **Vanko replies with 3 attachments** to the Russia channel |
| 2016-06-30 01:28 | `vacation photos.7z` archive created (35 MB) — classified docs disguised as holiday photos |
| 2016-06-30 01:30 | **SDelete wipes the original files** |
| 2016-06-30 01:46:06 | `.7z` **uploaded to Dropbox account 984347879** |
| 2016-06-30 01:48 | Local Dropbox folder (1.9 GB) deleted |
| 2016-06-30 | JARVIS flags the transfer; Vanko's account suspended |
| 2016-10-14 / 11-04 | VSS snapshots (preserve the wiped evidence); image acquired 11-04 |

### Impact
- **Trade-secret loss across Level 5–8 classified material** (CryoDNA storage inventory, ZF DNA splice notes, L8 bio research, Ion-Thruster weaponization) **plus confirmed access to a Level-12 document** (`Project Nehemiah`) — exposure exceeds the original Level 5–8 scope.
- **Two independent buyer channels**: China (`nina_kwai@qq.com` → CAS Institute of Microbiology, `im.cas.cn`) and Russia (Merrick → Bulgakov).
- **Dual exfil paths proven**: Dropbox + OneDrive (SRUM-corroborated egress), with USB removable-media staging (3 distinct volumes).
- Deliberate **anti-forensics** (SDelete, prefetch deletion, Dropbox-cache purge) — defeated by VSS.

---

## 2. ATTACK KILL CHAIN (MITRE ATT&CK)

| # | Step | Tactic | Technique | Evidence |
|---|---|---|---|---|
| 1 | Insider uses own valid credentials on `STARKSURFACE` (no breach) | Initial Access / Defense Evasion | **T1078** Valid Accounts | Authenticated `PC User`; no exploit/implant (P3-001, P4-001 both refuted) |
| 2 | Reads classified corpus from the StarkResearch file server | Collection | **T1039** Data from Network Shared Drive | NTUSER TypedPaths `\\STARK-FILESERVE`, `\\192.168.1.5/.3`; OneDrive copy-provenance (P3-005 ✓) |
| 3 | Creates masquerade local account `defaultprinter` | Persistence / Defense Evasion | **T1136.001** Create Account: Local | SAM RID + account-create event; later used as staging mule (P1-001 ✓) |
| 4 | Stages stolen docs locally (under `defaultprinter`, USB volumes) | Collection | **T1074.001** Local Data Staging | `defaultprinter\Desktop\temp.zip`; USB serials `5650959F`/`C83A6C7B`/`8C059ED1` (P2-001 ✓) |
| 5 | Archives + disguises payload as `vacation photos.7z` | Collection | **T1560.001** Archive via Utility (7-Zip) · **T1036** Masquerading | `.7z` SHA256 `b210bcd8…`, created 06-30 01:28 (P2-005 ✓) |
| 6 | Stages anti-attribution / recon toolset | Defense Evasion | **T1090.003** Multi-hop Proxy (Tor) + recon tooling | Tor Browser, Network Stumbler, FTK Imager on desktop (P2-004 ✓) |
| 7 | Exfiltrates to cloud (Dropbox + OneDrive) | Exfiltration | **T1567.002** Exfil to Cloud Storage | SRUM egress bytes; Dropbox acct `984347879` upload 01:46 (P3-002, P2-003 ✓) |
| 8 | Coordinates with foreign handler (3 attachments) | Exfiltration / Command & Control | **T1567** (email channel) | OST: 06-27 21:22 reply to `mmerr001@gmail.com` w/ 3 att. (P3-003 ✓) |
| 9 | Secure-deletes originals + Dropbox cache; deletes SDelete prefetch | Defense Evasion | **T1070.004** Indicator Removal: File Deletion | SDelete 01:30; Dropbox folder del 01:48; `SDELETE.EXE-*.pf` deleted — all recovered from VSS (P4-003 ✓) |
| 10 | Accesses Level-12 material (scope expansion) | Collection / Impact | **T1530** Data from Cloud Storage | VSS-recovered Word lock `~$…Project_Nehemiah 4.docx` (P4-004 ✓) |

**Refuted along the way (FP gate):** timestomping (T1070.006 — `$SI>$FN` was a copy signature, P1-003), NTP clock-change anomaly (P1-002), Windows.old persistence (P1-005), in-memory C2/injection (P3-001), malware family present (P4-001), iPhone-as-exfil-vector (P2-002), `getfiletree.ps1` scheduled-task malice (P1-004), ReadNotify-as-tradecraft (P3-004), pagefile AES keys/PEs as probative (P4-002).

---

## 3. INDICATORS OF COMPROMISE

### 3a. Network IOCs (IPs / domains / accounts)
| Type | Indicator | Context |
|---|---|---|
| Internal host | `\\STARK-FILESERVE`, `192.168.1.5`, `192.168.1.3` | Source file server for the stolen IP |
| Cloud exfil acct | **Dropbox account `984347879`** | `.7z` upload destination |
| Cloud exfil acct | **OneDrive cid `CBDFA76592A9F765`** | Classified-doc cloud staging |
| Email (China) | `nina_kwai@qq.com`, `nina_kwa1@qq.com` | Buyer channel |
| Domain (China) | `im.cas.cn` | CAS Institute of Microbiology (buyer org) |
| Email (Russia) | `mmerr001@gmail.com` (Michael Merrick → recruiter **Vladimir Bulgakov**) | Recruiter channel |
| Email (subject) | `anthony.vanko@gmail.com`, `kylie.normandy@gmail.com` | Actor + internal contact |
| Service | `dropbox.com`, `storage.live.com`, Skype (`Titan/V-Gen`, `k.normandy`, `fuzzygopher`, `merrick_mike`), Telegram, Tor network | Comms/exfil infrastructure |
| Service (observed) | `readnotify.com` | Read-tracking subscription (refuted as crime-specific; predates window) |

> **Honest note:** there is **no external malware C2 IP** — this is an insider case; the "C2-equivalent" is legitimate cloud/email/chat infrastructure.

### 3b. Host IOCs (hashes / paths / registry)
**File hashes (SHA-256)**
- `vacation photos.7z` — `b210bcd89fbde5d3b0816e1834483f7b82adf8565fd880d49930c25450ca7e31`
- `vacation photos.7z.lnk` — `ca8433a7ba4ccde99a9170cb169c61f87b704b853a39c55843941ae049b201fc`
- `vacation photos.7z:com.dropbox.attributes` — `586d6e4410af8fd7bc5dba881c86a453e494e5b52ec5e13a582292063355d316`

**Filesystem paths**
- `C:\Users\PC User\Downloads\vacation photos.7z` (+ `\Recent\V-Photos.lnk`)
- `C:\Users\defaultprinter\Desktop\temp.zip` (SDelete-wiped, 0 bytes; recovered via VSS)
- `C:\Windows\System32\sdelete.exe`, `sdelete64.exe` (+ `:Zone.Identifier`)
- `C:\Windows\Prefetch\SDELETE.EXE-FBA93810.pf` (**deleted** — recovered from VSS)
- `C:\Users\PC User\OneDrive\Documents\Level_12\~$Stark TS-Level 12_Project_Nehemiah 4.docx`
- `C:\Users\PC User\Documents\NinaResearch\` (Chinese-contact research, incl. "Chinese sturgeon" PNG)
- `C:\Users\PC User\Documents\cpy.txt` (USB copy script), `getfiletree.ps1`
- `C:\$RECYCLE.BIN\S-1-5-21-3739107332-290452467-3466442662-1001\$RK7QVJQ\.dropbox.cache\…` (Dropbox cache, deleted)
- Tor Browser / Network Stumbler / FTK Imager install trees

**Registry / system**
- **USB volume serials:** `5650959F` (StarkResrch), `C83A6C7B` (Stark-IR), `8C059ED1` (W:)
- **SID:** `S-1-5-21-3739107332-290452467-3466442662` (`PC User` = `…-1001`)
- **NTUSER TypedPaths:** `\\STARK-FILESERVE`, `\\192.168.1.5`, `\\192.168.1.3`
- **SAM:** masquerade local account `defaultprinter`; MS account `anthony.vanko`

---

## 4. EVIDENCE GAPS (manual CLI verification required)

These are **processing gaps**, not exonerating facts. Each is reproducible from the mounted C: volume (offset 1411072).

1. **Plaso super-timeline empty (0 events).** `get_timeline` produced a 0-byte output — log2timeline likely timed out on the 110 GB `$MFT`. Re-run pinned + windowed:
   ```bash
   log2timeline.py --parsers winevtx,mft,prefetch,filestat,lnk,olecf \
     --partitions all plaso.dump surface_physical.E01
   psort.py -o l2tcsv -w vanko-timeline.csv plaso.dump \
     "date > '2016-06-22 00:00:00' AND date < '2016-07-01 00:00:00'"
   ```
2. **ShellBags returned 0 entries** (SBECmd could not decode this `UsrClass.dat`). Verify folder-browse history manually:
   ```bash
   SBECmd.exe -f "/Users/PC User/AppData/Local/Microsoft/Windows/UsrClass.dat" --csv ./sbe_out
   # fallback: python3 -m shellbags UsrClass.dat
   ```
3. **No valid memory image.** `hiberfil.sys` is WAKE-state, `pagefile.sys` is 256 MB-truncated — Volatility 3 yielded nothing. If a `Vanko-RAM.dmp` exists in the broader evidence set, run:
   ```bash
   vol3 -f Vanko-RAM.dmp windows.pslist windows.netscan windows.malfind
   ```
4. **`zf_classified.yar` scored 0 on `.docx`** — OOXML markers are DEFLATE-compressed and invisible to raw YARA. Decompress first:
   ```bash
   for f in *.docx; do unzip -p "$f" word/document.xml \
     | yara /usr/share/yara/rules/zf_classified.yar - && echo "HIT: $f"; done
   ```
5. **Merrick reply — 3 attachments not extracted.** `carve_pst_iocs` parsed headers only. Extract payloads + hash/scan:
   ```bash
   pffexport -m all "anthony.vanko@gmail.com (1).ost" -t ost_out
   # then hash + YARA every attachment under ost_out/.../Attachments/
   ```
6. **22 pagefile AES keys never tested** against the encrypted `.7z`. Validate offline:
   ```bash
   # build a wordlist from be_pagefile/aes_keys.txt, then:
   7z2john "vacation photos.7z" > 7z.hash && john --wordlist=keys.txt 7z.hash
   ```
7. **4648 logon targets unresolved; SmbClient operational log empty.** Confirm the file-server auth tying user+credential+time:
   ```bash
   EvtxECmd.exe -f "/Windows/System32/winevt/Logs/Security.evtx" --csv ./evtx_out
   # filter EventId 4648, inspect TargetServerName for STARK-FILESERVE
   ```

---

*Consolidated machine-readable finding set: `FINDINGS.jsonl` (19 objects) and `confirmed-findings.json` (10-object confirmed array). `GROUND_TRUTH` was unset at synthesis time, so the recall-scorer JSON block is omitted per the Phase-5 contract.*
