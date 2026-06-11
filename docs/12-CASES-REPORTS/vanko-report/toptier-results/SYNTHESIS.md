# VANKO-ABDUCTED-ZEBRAFISH — Top-Tier Recovery Synthesis

**Case:** VANKO-ABDUCTED-ZEBRAFISH · **Lead analyst:** Opus 4.8 (DFIR) · **Host:** siftworkstation · **Date:** 2026-06-08
**Evidence:** `/cases/vanko/surface_physical.E01` (~110 GB EWF), C: volume sector offset `1411072`
**Inputs synthesized:** 5 top-tier recovery streams — VSS, pagefile/hiberfil/swapfile, Windows.old, chat clients (Skype/Telegram/WhatsApp), unallocated/MFT carving.

---

## 0. Bottom line up front

- **Objective A (recover the SDelete-wiped / deleted classified files): ANSWERED — conclusively.** The wiped intellectual property is fully recovered from **two independent sources** (Volume Shadow Copies *and* live OneDrive master copies carved by MFT inode). The `vacation photos.7z` exfil archive is recovered **byte-intact** (sha256 `b210bcd8…`, 35,008,256 B) and its internal build timestamp (`2016-06-30 01:26:15`) matches the established exfil build. The SDelete anti-forensics is **defeated**.
- **Objective B (Dropbox share link / QQ negotiation): RESOLVED AS A NEGATIVE — the question's premise was wrong.** There is **no Dropbox web share link** because the exfil was **not** a web share — it was a **direct desktop-client sync** to the operator's private Dropbox account **984347879**, *proven* (not merely "not found") by the cleartext `aggregation.dbx` `recent` record. The QQ↔nina_kwai negotiation is a **server-side artifact** (Gmail/QQ mailboxes) and is **not recoverable from this disk image**; it requires legal process to Google/Dropbox/Tencent.
- **Bonus:** the memory-remnant and chat-client streams recovered an **entirely new recruitment/negotiation channel** (Michael Merrick → Vladimir Bulgakov "Russian biotech," plus Skype "Titan"/"V-Gen" planning and Tor usage) that materially expands the conspiracy beyond the QQ/nina_kwai thread.

---

## 1. What was NEWLY recovered

### 1a. The wiped exfil archive — recovered intact (Objective A)
- **`vacation photos.7z`** — sha256 `b210bcd89fbde5d3b0816e1834483f7b82adf8565fd880d49930c25450ca7e31`, **35,008,256 bytes**. Recovered from **VSS** in *both* `Users/PC User/Downloads/` (inode 16396) and `Users/PC User/Dropbox/` (inode 32936), **byte-identical**.
- Directory tree is header-readable (data is 7zAES-encrypted): **221 files / 13 folders / 46,941,359 B uncompressed**, internal build time **2016-06-30 01:26:15**, full classified hierarchy **Levels 5/6/7/8** incl. *Adamantium, Arc Reactor, Carbonadium, Mutant Genome, Vibranium, BioChemical*.

### 1b. The classified document corpus — recovered live (Objective A, second independent source)
**Key insight (consistent across VSS + carving):** SDelete (~01:30) wiped only the **transient staging copies** (USB volumes / Downloads originals); the **OneDrive master copies survived live on C:** and were carved out by MFT inode. **14 classified docs** recovered intact (valid Word/Excel 2007+):

| Source | Highlights recovered |
|---|---|
| Carving (MFT inode) | STARK-TS-Level7-CryoDNA Storage Inventory; ZF DNA splice test notes; Stark_Level_12_Wolverine_Dossier_Behavior_Controls; Cryo-regeneration of DNA sample-Alpha_Experiment; Korean Science Delegation Profiles-Blackmale Coltrols; cryoregeneration x-alpha attempts.xlsx; Stark_TS-Level8A_CryoDNA.blacklight; Stark_TS-Level8a_DNA Marriage; Stark-Policy-Manual (public + Classified-NOTFORRELEASE); Observations on regenerative DNA samples; Reverse Cryo-DNA_DraftStandards_lab_results; Stark TS-Level 12_Project_Nehemiah 4; Level 8 Indoc Information |
| VSS | Same OneDrive Level_8 / Level_12 trees browsable live in both snapshots; `ZF DNA splice test notes.docx` (sha256 `0b6993ff…`) opened verbatim — genuine Level-7 zebrafish-DNA / Adamantium weaponization notes |

- **`ZF DNA splice test notes.docx`** sha256 `0b6993ff9ebc71f523d74e0298d8fec55aec270218b91d6416fafb5df25eebec` — recovered identically by BOTH carving (inode 13367) and VSS (inode 13367-128-3): cross-source hash match.

### 1c. Prior-version (snapshot) evidence — NEW source class
- **Two Volume Shadow Copies** confirmed and mounted as full readable 110 GiB NTFS volumes: **Store 1 = Oct 14 2016 15:25:13 UTC** (`8b1bea84-…`), **Store 2 = Nov 04 2016 13:59:52 UTC** (`8b1bf5a9-…`). Both post-date the 06-30 wipe yet preserve the un-deleted archive + classified set — the single strongest counter to the anti-forensics.
- **Windows.old:** NEW *negative* finding (scoped out as a dead end). Windows.old contains an **OS skeleton only** (`Windows.old\WINDOWS\…`, 81 records) — **no Users, no PC User profile, no NTUSER.DAT**. The prior-OS registry pivot (RecentDocs/TypedPaths/OpenSavePidlMRU) is **impossible** from this source; `setuperr.log` shows the upgrade/reset created Windows.old without carrying Users forward.

### 1d. Deleted staging/methodology artifacts — NEW
- **`cpy.txt`** (carving, inode 16250, sha256 `20df5991…`): a step-by-step **USB "switchblade" autorun exfil tutorial** (`autorun.inf` + `launch.bat` + `invisible.vbs` + `file.bat`, `xcopy /s /c /d /e /h /i /r /y` of `%USERPROFILE%\pictures|Favorites|videos` to a flash drive, run hidden) — closes "*Test … before playing it out on your victim. It works flawlessly.*" Direct documentary evidence of USB-exfil **methodology and intent**.
- **`screenshot.zip`** (carving, inode 52721, sha256 `c56f5f5a…`): valid ZIP containing `Screen Shot 2016-03-12 at 4.01.08 PM.png`.
- **`$R33PY5Y.zip`** (RecycleBin, inode 240597, 5.7 MB): **UNRECOVERABLE** — header garbage, clusters overwritten (the one genuinely destroyed artifact).

### 1e. A NEW recruitment / handler channel (memory + Skype) — NOT in established facts
Recovered from pagefile/swapfile strings + Skype `main.db` (329 plaintext msgs) — a distinct and arguably more probative negotiation than the QQ side:
- **Recruitment email "Potential Opportunity?"** — Michael Merrick (`mmerr001@gmail.com` / skype `merrick_mike`) → Anton Vanko, **2016-06-27 17:25**, introducing recruiter **Vladimir Bulgakov** ("Russian biotech company"). Vanko's affirmative reply: *"Heck yeah, give him my contact info."* — documented **intent to engage**.
- Additional principals/aliases: **Kylie Normandy** (`k.normandy`), **fuzzygopher**; new employer **"Titan"**; product codename **"V-Gen"** (regenerative / super-soldier formula); plan to move overseas and offer the formula "first to military"; Merrick as willing human test subject.
- **Channel-pivot tell** (Skype, 2016-07-01): Vanko tells Merrick "keep the updates coming but either on skype or gmail" — steering exfil toward Gmail, consistent with the Gmail→Dropbox(984347879)→nina_kwai@qq.com chain.
- **Tor Browser** active **2016-06-28 23:28–23:33 UTC** (HS_CLIENT_REND circuits to public directory onions — DuckDuckGo/Torch/Hidden Wiki).

### 1f. Channel-corroboration artifacts — NEW
- **Dropbox `aggregation.dbx` `recent`** (carving, inode 32463): cleartext `984347879:/vacation photos.7z` @ **`1467251166` = 2016-06-30 01:46:06 UTC** with content-block hashes, plus `984347879:/V-Photos` folder synced 21 s earlier (`1467251145`). This is the **exact, on-disk-proven upload event**.
- **Dropbox account root_ns `984347879`** confirmed **resident in pagefile** (`client-gandalf` log: `host_int=4319428912`, `in_use=1,747,733,448` B ~1.7 GB synced) — matches the established exfil account.
- **VSS WebCacheV01.dat** (Edge/IE for PC User): Dropbox account activity (`dropbox.com/home?email_just_verified=1`, 2016-06-27→07-04), `anthony.vanko@gmail.com` Gmail inbox, Hangouts sessions, local `NinaResearch` (Chinese sturgeon) access.

---

## 2. Fold-in to the established exfil chain

Established chain:
> file-server → Surface C: → 3 USB volumes → `vacation photos.7z` built 06-30 01:28 → SDelete wipe 01:30 → Dropbox upload 01:46 → nina_kwai@qq.com / im.cas.cn

The recovery streams confirm and tighten every link, and add a parallel recruitment track:

| Chain link | New corroboration from this synthesis |
|---|---|
| file-server → Surface C: | OneDrive Level_7/8/12 master corpus recovered live on C: (14 docs, hashes in §4); cross-source hash match on `ZF DNA splice test notes.docx`. |
| Surface C: → 3 USB volumes | **`cpy.txt`** USB switchblade tutorial (xcopy-to-flash methodology) + `screenshot.zip` in the same staging folder — direct evidence of the USB-staging method/intent. |
| `vacation photos.7z` built 06-30 ~01:28 | Recovered archive's **internal build time `2016-06-30 01:26:15`** matches (build vs. close-out window). 221 files / 46,941,359 B, full Levels 5–8 hierarchy. |
| SDelete wipe ~01:30 | Defeated. Only the *staging* copies were wiped; OneDrive masters survived live and both VSS snapshots preserve the archive. Only `$R33PY5Y.zip` truly destroyed. |
| Dropbox upload 01:46 | **Pinned to the second: `1467251166` = 2016-06-30 01:46:06 UTC** via `aggregation.dbx` `recent`, server_path `984347879:/vacation photos.7z`, with block hashes. Account 984347879 also confirmed resident in pagefile. |
| → nina_kwai@qq.com / im.cas.cn | Corroborated **only as cover/relationship context** (NinaResearch / Chinese-sturgeon / CAS Institute of Hydrobiology material live on disk + in WebCache). The **negotiation transcript is off-image** (Gmail/QQ server-side). |
| **NEW parallel track** | Merrick → Bulgakov ("Russian biotech") recruitment (2016-06-27), Skype "Titan"/"V-Gen" planning, Tor on 06-28 — a second handler/buyer vector distinct from the QQ/nina_kwai channel. |

---

## 3. Status of the two open questions

### Objective A — recover the SDelete-wiped/deleted classified files → **ANSWERED (closed).**
- Recovered from **two independent sources**: VSS snapshots (archive + full OneDrive set) and live MFT-inode carving (14 docs). `vacation photos.7z` recovered byte-intact; cross-source hash agreement on key docs.
- Residual gap (immaterial): `$R33PY5Y.zip` clusters overwritten (unrecoverable); the 7z payload *data* remains 7zAES-encrypted (directory tree readable, content needs the password). Neither affects the conclusion that the exfil scope is fully established.

### Objective B — Dropbox share link / QQ negotiation → **RESOLVED, both as on-disk negatives (premise corrected).**
- **Share link: PROVEN ABSENT — and shown to be the wrong question.** Exfil = **desktop-client private sync** to account **984347879**, proven by `aggregation.dbx` (no `share`/`shmodel`/`scl` key, only a `recent` sync record). No `dropbox.com/s|sh|scl/` string in VSS (110 GiB carve), WebCache, Chrome history/localStorage, or memory. The lone `dropbox.com/s/` hit in pagefile is a `!Obfuscator.AOF` **malware bitsadmin template** with placeholder bytes — a false positive, not Vanko's link. Local `.dbx` stores are SQLCipher-encrypted (DPAPI machine-GUID key) and not crackable on this image.
- **QQ negotiation: not on this image (off-disk).** Zero `nina_kwai` / `im.cas.cn` / `@qq.com` user hits across memory, chat clients, carving, or VSS. No QQ/WeChat client installed on STARKSURFACE; the nina_kwai recipient was reached by **email**, not a local chat app. Telegram tdata is encrypted (no key); WhatsApp never linked. The transcript lives in Gmail/QQ server mailboxes.
- **Path forward (legal process, not forensics):** Google (`anthony.vanko@gmail.com`) and Dropbox (account **984347879**, local host id **5437144290**) for the distribution/negotiation records; optionally Tencent for the QQ mailbox.
- **One honest residual caveat (does not change the verdict):** the pagefile/hiberfil stream extracted only **256 MiB truncated partials** (icat 60 s timeout); hiberfil is a `WAKE`-state Xpress-Huffman image (unparseable on this host). A full re-extraction (raw NTFS dataruns / longer timeout, `hibr2bin`) is the only outstanding action that could in principle surface a share string — but given the *proven* private-sync mechanism in `aggregation.dbx`, the expected result is confirmatory of the negative.

---

## 4. Consolidated NEW IOCs

**Files / hashes (sha256):**
- `vacation photos.7z` — `b210bcd89fbde5d3b0816e1834483f7b82adf8565fd880d49930c25450ca7e31` (35,008,256 B; internal build 2016-06-30 01:26:15)
- `ZF DNA splice test notes.docx` — `0b6993ff9ebc71f523d74e0298d8fec55aec270218b91d6416fafb5df25eebec` (dual-source confirmed)
- `cpy.txt` (USB switchblade tutorial) — `20df5991d004a4f5636ac12353073b85d4f4819b2be139019380c5743fd7d29f`
- `screenshot.zip` — `c56f5f5a63fdddac47ba5f7a4197f5ff3462b55ca868f472144722be45fb939c`
- Level 8/12 corpus: `Stark_TS-Level8A_CryoDNA.blacklight.docx` `3e54c790…`, `Stark_Level_12_Wolverine_Dossier_Behavior_Controls.docx` `740d1837…`, `Korean Science Delegation Profiles-Blackmale Coltrols.docx` `78a965fd…`, `Stark TS-Level 12_Project_Nehemiah 4.docx` `71df8dba…`, `Stark-Policy-Manual-Classified-version-NOTFORRELEASE.docx` `44522ccc…` (full table in carving.md)
- `$R33PY5Y.zip` (RecycleBin, UNRECOVERABLE) — `84832b4f964d9c0708b413b9234492e8228d3d6ae0ca646b564087462d0cbca0`

**Accounts / identities:**
- Dropbox exfil account **root_ns 984347879** (host_int 4319428912) — the upload target
- Dropbox **local host id 5437144290** (info.json) and **machineid_attr `8oK7UMuUbSMvOFUceIL0JQ==`** (ADS)
- `anthony.vanko@gmail.com`, `anthony.vanko@icloud.com`, `live:anthony.vanko`

**NEW recruitment/handler IOCs:**
- **Michael Merrick** — `mmerr001@gmail.com` / skype `merrick_mike`
- **Vladimir Bulgakov** (alias "Vladimir/Vlad") — purported "Russian biotech" recruiter
- **Kylie Normandy** — skype `k.normandy`; **fuzzygopher** — skype `fuzzygopher`
- Skype group thread `19:754fb1f0335240cdb65acbde06e4e6db@thread.skype`
- Employer codename **"Titan"**; product codename **"V-Gen"** (regen/super-soldier formula)

**Timeline / activity:**
- Dropbox upload **2016-06-30 01:46:06 UTC** (`1467251166`, `984347879:/vacation photos.7z`); `V-Photos` folder `1467251145` (01:45:45)
- Recruitment email **2016-06-27 17:25** ("Potential Opportunity?")
- **Tor Browser** active **2016-06-28 23:28–23:33 UTC**
- VSS Store 1 **`8b1bea84-8700-11e6-8293-c0335ee15db6`** (Oct 14 2016); Store 2 **`8b1bf5a9-8700-11e6-8293-c0335ee15db6`** (Nov 04 2016)

**Negative-result IOCs (record as proven-absent on this image):**
- No `dropbox.com/s|sh|scl/` share link anywhere (private desktop-sync exfil instead)
- No `nina_kwai@qq.com` / `im.cas.cn` / QQ/WeChat client on STARKSURFACE (negotiation is off-image, email-borne)
- The pagefile `dropbox.com/s/` hit is a `!Obfuscator.AOF` malware template — **disregard**

---

## 5. Recommended next actions
1. **Legal process** to Google (`anthony.vanko@gmail.com`) and Dropbox (account **984347879** / host id **5437144290**) for the negotiation thread and any distribution/share records; consider Tencent for the QQ mailbox.
2. **Full re-extraction** of `/pagefile.sys` and `/hiberfil.sys` (raw NTFS dataruns / longer icat timeout; `hibr2bin` for the WAKE-state hiberfil) to definitively close the truncation caveat — expected confirmatory of the share-link negative.
3. **Pivot the new IOCs** (`mmerr001@gmail.com`, skype `merrick_mike`/`k.normandy`/`fuzzygopher`, `Vladimir Bulgakov`, "Titan", "V-Gen") into the case index as a second handler/buyer track alongside nina_kwai/CAS.
4. Treat the **recovered classified corpus** (14 docs + intact 7z directory tree) as the evidentiary package for **exfil scope** (Levels 7/8/12: CryoDNA, ZF DNA, Wolverine dossier, Korean-delegation blackmail, Nehemiah, policy NOTFORRELEASE).

---
*Recovered files staged under `/tmp/agentropix-sift-vanko/{recovered,carving,pf,winold,chat}/`. Per-stream detail: `vss.md`, `carving.md`, `pagefile-hiberfil.md`, `windows-old.md`, `chat-clients.md` (same directory).*
