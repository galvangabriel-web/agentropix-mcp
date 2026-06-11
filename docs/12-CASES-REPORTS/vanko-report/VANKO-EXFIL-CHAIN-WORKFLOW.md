# VANKO — Exfil-Chain Reconstruction Workflow

> **Goal:** reconstruct the complete data-theft chain end to end —
> **StarkResearch file server → C: (STARKSURFACE) → USB (`Stark-IR`/`StarkResrch` D:) → `vacation photos.7z` → cloud / Chinese-university share** —
> with **exact timestamps**, pinned to the **2016-06-22 → 06-30** window from the case brief.
> Active case `VANKO-ABDUCTED-ZEBRAFISH`; every step recorded to `session-actions.log`.

## Established so far (Phase 0–4)
Host `STARKSURFACE`, user `C:\Users\PC User` (MS account `anthony.vanko`), EST. Vanko opened the named stolen
files (`ZF DNA splice test notes.docx`, `STARK-TS-Level7-CryoDNA Storage Inventory.docx`, `L8-Bio-*`),
navigated `\\STARK-FILESERVE` and `D:\vacation photos\…\Level 7/8 Classified\`, staged `vacation photos.7z`,
and 7 USB devices were connected. **This workflow times and links those events into one chain.**

## Phases

### Phase A — MFT timeline (file provenance + exact timestamps)
Extract `$MFT` (C:) → `get_mftecmd`. Pull the records for the classified files, the `vacation photos` tree,
`vacation photos.7z`, and `Vanko-RAM.dmp`: **$SI vs $FN created/modified/accessed**, parent path, size,
`is_deleted`. **$SI < $FN or copy-clustering = file movement**; map first-appearance on C: and on D:.

### Phase B — USN journal ($UsnJrnl·$J) — the disguise + deletion events
Extract `$Extend\$UsnJrnl:$J` → parse. Find **FILE_CREATE / RENAME_OLD_NAME→RENAME_NEW_NAME / FILE_DELETE**
for the classified files and the `vacation photos*` paths — the literal **rename to "vacation photos"** and
any **secure-delete** of originals. Order events on the USN sequence.

### Phase C — ShellBags (UsrClass.dat) — folder-tree browsing
`get_recmd` on `UsrClass.dat` → ShellBags. Confirm Vanko **browsed the folder tree** of `\\STARK-FILESERVE`,
the `Level 5–8 Classified` subfolders, and the `D:\vacation photos\…` staging tree, with **first/last-interacted**
timestamps per folder (intent + sequence of access).

### Phase D — Cloud / email / browser exfil (the upload)
- **OneDrive:** `C:\Users\PC User\OneDrive\…` listing + logs — was the staged data synced to cloud?
- **Outlook OST:** `anthony.vanko@gmail.com.ost` / `@icloud.com.ost` — outbound mail / attachments (carve).
- **Browser history** (Edge/IE WebCacheV01.dat, Chrome): **uploads to the Chinese university file share**
  (the original JARVIS tip-off) — URLs, POST/upload artifacts, timestamps.

### Phase E — Synthesis
Fuse A–D into one **UTC timeline** + a **chain diagram** (server → C: → USB → archive → cloud/CN-share),
map to the June 22–30 window, list **IOCs** (files, hashes, USB serials, share paths, accounts), and stage
**DRAFT findings** (no approval — human HMAC hard-stop).

## Execution order
A (MFT) → B (USN) → C (ShellBags) → D (cloud/email/browser) → E (synthesis). Heavy parses run as recorded
background steps; per-step JSON saved verbatim; findings re-derived in recorded steps so the transcript is replayable.
