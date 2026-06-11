# VANKO-ABDUCTED-ZEBRAFISH — SOURCE: Windows.old (prior OS install)

Case: VANKO-ABDUCTED-ZEBRAFISH ("Abducted Zebrafish", SANS FOR500)
Analyst: DFIR subagent (Opus 4.8)
Evidence: `/cases/vanko/surface_physical.E01`, C: volume sector offset `1411072`
Date: 2026-06-08

## Objective
Investigate the `Windows.old` prior-OS install (the box was reset) for:
- (A) the SDelete-wiped / deleted classified files (any copy, fragment, prior version)
- (B) the Dropbox share link and/or QQ negotiation with nina_kwai
- An earlier `NTUSER.DAT` for `PC User`, and earlier Documents/Downloads/Desktop that the live profile no longer has.

## BOTTOM LINE / VERDICT
**Clean negative for user data.** `Windows.old` on this image preserved **only the operating-system `WINDOWS\` folder** (and `WINDOWS\System32\`). There is **NO `Users` directory, NO `PC User` profile, NO prior `NTUSER.DAT`, NO `Documents`/`Downloads`/`Desktop`, NO `ProgramData`, and NO `vacation photos.7z`** anywhere under `Windows.old`. Consequently:
- Question (A): no classified file / `.7z` / prior version is recoverable **from this source**. (Every `.7z`, `vacation photos`, and classified-keyword artifact in the MFT resolves to the **live** `C:\Users\PC User` tree, not Windows.old.)
- Question (B): no Dropbox share link or QQ negotiation can be recovered from this source (no user hives, no browser data, no Recent/JumpLists under Windows.old).
- The prior-OS RecentDocs / TypedPaths / OpenSavePidlMRU pivot (assigned step 2) is **not possible** — the prior NTUSER.DAT does not exist in Windows.old.

This is the expected outcome when a Windows "Reset this PC / keep nothing" (or an in-place upgrade that discards profiles) moves only the OS tree into `Windows.old` and discards user profiles, **rather than** the classic upgrade behavior that preserves `Windows.old\Users`.

## Method & verbatim key output

### 1. Locate Windows.old (fls root of C:)
`fls` (TSK) of the C: volume root → 310,582 entries. Only two reference Windows.old, and the recursive walk did NOT descend into it:

```
{'entry_type':'d','allocated':True,'inode':'3146-144-5','name':'Windows.old','full_path':'/Windows.old',
 'modified_time':'2016-04-22 11:12:41 (UTC)', ...}
{'entry_type':'-','allocated':False,'inode':'0','name':'Windows.old','full_path':'/Windows.old', ...}   # stale/0-inode duplicate
```

`fls` by inode `3146-144-5` and its child `144894-144-6` ("WINDOWS") both enumerate Windows/System32 internals; the ONLY allocated directory children are `WINDOWS` (144894, allocated) and `System32` (147489, allocated). All other listed names (`ELAMBKUP`, `en-US`, `Fonts`, `Migration`, `Panther` …) are `allocated:false` (deleted / recycled index entries). No `Users` entry appears.

### 2. Authoritative parent/child resolution via $MFT
Extracted the live C: `$MFT` (256 MB, 262,144 records) and parsed FILE_NAME attributes (parent reference + name + namespace) with a local parser to reconstruct paths.

- `Windows.old` = **MFT record 3146**, `inuse=True isdir=True parent=5 (root) seq=2`.
- **Direct children of record 3146 (FILE_NAME.parent == 3146):**
```
LIVE DIR rec=144894 ns=0 | WINDOWS
count distinct: 1
```
  → Windows.old has exactly **one** child: `WINDOWS`. No `Users`, no `ProgramData`, no `Program Files`.

- **All MFT records that resolve under Windows.old (3146): 81 total**, every one of them inside `Windows.old\WINDOWS\…` (e.g. `…\System32\AutoWorkplace.exe.config`, `…\System32\drivers\…`, `…\setuperr.log`). None under a `Users` path.

- **Every `.7z`, `vacation`, and classified-keyword artifact resolves to the LIVE profile, not Windows.old:**
```
.7z:        rec=16396 LIVE | <PCUser>/Downloads/vacation photos.7z
            rec=32936 LIVE | <PCUser>/Dropbox/vacation photos.7z   (sz=83 -> Dropbox placeholder)
            rec=37717 LIVE | .../vacation photos.7z                (sz=83 -> placeholder)
vacation:   rec=16766 | <PCUser>/Recent/vacation photos.7z.lnk
            rec=36756 | <PCUser>/Recent/vacation photos.lnk
classified: rec=1071  | <PCUser>/Recent/Vibranium.lnk
            rec=3073  | <PCUser>/Recent/Adamantium.lnk
            rec=7479  | <PCUser>/Recent/Mutant Genome.lnk
            rec=1613  | <PCUser>/Recent/BioChemical.lnk
            rec=231688| <PCUser>/OneDrive/Pictures/Arc Reactor Glow.jpg
            (+ many L8-M-Genome-*.jpg/png/gif .lnk, Vibranium.png.lnk, etc.)
```
  (Parent refs ~263009/263026 = the PC User Downloads/Recent dirs, which live in MFT records >262,144 i.e. the live profile region, NOT under Windows.old's record 3146.)

- **NTUSER.DAT records present (all LIVE C:, none under Windows.old):**
```
rec=27773  /Users/defaultprinter/NTUSER.DAT
rec=116961 /Users/Default/NTUSER.DAT
rec=80783  /Windows/ServiceProfiles/NetworkService/NTUSER.DAT
rec=80889  /Windows/ServiceProfiles/LocalService/NTUSER.DAT
(+ stale SoftwareDistribution package entries — not real profiles)
```

### 3. Direct extraction probes (proves absence, not just unparsed)
`extract_files` (TSK ifind+icat) navigated Windows.old successfully for an OS file:
```
extracted: /Windows.old/Windows/setuperr.log  inode=227432  size=374
sha256=7d1a2a1ec40272fa9e75e64ef67f47121e7cbc37d9f12ad9faad02e7a9e9324a
  -> contents: Bluetooth migration "BthMig: Failed to find a match / No BthPort migration information found" warnings (a Windows setup/upgrade migration log).
```
But the user-data paths are confirmed **missing**:
```
extract_files paths:
  /Windows.old/Users/PC User/NTUSER.DAT                 -> missing
  /Windows.old/Users                                    -> missing
  /Windows.old/Users/PC User/Downloads/vacation photos.7z -> missing
  /Windows.old/ProgramData                              -> missing
  /Windows.old/Users/PC User/Documents                  -> missing
extracted: []   missing: [all of the above]
```

## Assessment
- `Windows.old` is a **dead end for user-attributable evidence** in this case. It holds only the OS `WINDOWS\` skeleton; the prior user profile (and any earlier copy of the `.7z`, classified docs, or prior NTUSER.DAT registry MRUs) was not preserved into it.
- The `setuperr.log` confirms a Windows setup/migration ran (consistent with an upgrade/reset that created Windows.old), but with no `Users` carried over.
- The classified-file recovery and Dropbox-link / QQ-negotiation leads must be pursued from **other sources** — the live `C:\Users\PC User` tree (Recent/.lnk, JumpLists, NTUSER, browser/Dropbox app data), USN journal / $LogFile, unallocated-space carving for the SDelete-wiped originals, and the Dropbox/Chrome artifacts on the live volume — NOT from Windows.old.
- The assigned step-2 RecentDocs/TypedPaths/OpenSavePidlMRU pivot against the prior NTUSER.DAT is not achievable: that hive does not exist in Windows.old.

## Artifacts produced (local)
- `/tmp/agentropix-sift-vanko/fls_root.json` — full recursive fls of C: root (310,582 entries).
- `/tmp/agentropix-sift-vanko/fls_winold.json` — fls of Windows.old (inode 3146).
- `/tmp/agentropix-sift-vanko/mft/MFT.bin` — extracted live C: `$MFT` (256 MB).
- `/tmp/agentropix-sift-vanko/records.pkl` — parsed MFT FILE_NAME index (path resolver).
- `/tmp/agentropix-sift-vanko/winold/setuperr.log` — the one OS file pulled from Windows.old (sha256 above).

## IOCs (context, sourced from live volume references — NOT recovered from Windows.old)
- `vacation photos.7z` (Dropbox placeholders sz=83 at `<PCUser>/Dropbox/` and live Downloads copy) — the 35 MB classified archive.
- Classified-document basenames seen as live Recent/.lnk targets: `Adamantium`, `Vibranium(.png)`, `Carbonadium`, `Mutant Genome`, `BioChemical`, `L8-M-Genome-*.{jpg,png,gif}`, `Arc Reactor Glow.jpg`.
