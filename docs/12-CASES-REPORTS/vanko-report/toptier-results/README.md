# `toptier-results/` — Top-tier recovery streams (5 sources + synthesis)

Five parallel deep-recovery investigations run as DFIR sub-agent assignments against the two open
questions of the VANKO case — **(A)** recover the SDelete-wiped classified files, **(B)** find the
Dropbox share link / QQ negotiation — plus the synthesis that merges them. These reports are the
evidentiary backbone of the anti-forensics-defeated and dual-cloud-exfil findings in
[`../VANKO-DFIR-REPORT.md`](../VANKO-DFIR-REPORT.md).

> **Sanitization note:** excerpts below are verbatim from the files except that personal names /
> personal mailbox addresses are replaced with `<REDACTED-PII>`. Adversary-channel indicators
> (`mmerr001@gmail.com`, `nina_kwai@qq.com`, Dropbox account `984347879`) are retained — they are
> the published IOCs of this case. These working reports are local-only (not tracked in the
> published repository).

## Files

| File | Type | Size | What it is |
|---|---|---|---|
| `SYNTHESIS.md` | Markdown report | 16 KB | Merges all 5 streams: Objective A answered conclusively (archive recovered byte-intact from 2 independent sources), Objective B resolved as a proven negative |
| `carving.md` | Markdown report | 12 KB | MFT-inode + targeted carving: 14 classified docs recovered live; decisive `aggregation.dbx` Dropbox-sync proof; tooling gotchas (foremost/bulk_extractor/YARA vs compressed E01) |
| `chat-clients.md` | Markdown report | 11 KB | Skype / Telegram / WhatsApp triage: Skype 329 plaintext messages (recruitment narrative), Telegram encrypted, WhatsApp never linked — clean negative for the share link |
| `pagefile-hiberfil.md` | Markdown report | 11 KB | Memory-remnant carving of pagefile/hiberfil/swapfile: Dropbox account `root_ns 984347879` corroborated; the only `dropbox.com/s/` hit is a malware template, not the exfil link |
| `vss.md` | Markdown report | 12 KB | Volume Shadow Copy analysis: both snapshots mounted; `vacation photos.7z` recovered intact (35,008,256 B); VSS WebCache corroborates the Dropbox/Gmail channel |
| `windows-old.md` | Markdown report | 8 KB | `Windows.old` prior-OS triage: clean negative — OS folder only, no user profiles preserved |

## `SYNTHESIS.md` — bottom line up front

```text
- **Objective A (recover the SDelete-wiped / deleted classified files): ANSWERED — conclusively.**
  The wiped intellectual property is fully recovered from **two independent sources** (Volume
  Shadow Copies *and* live OneDrive master copies carved by MFT inode). The `vacation photos.7z`
  exfil archive is recovered **byte-intact** (sha256 `b210bcd8…`, 35,008,256 B) and its internal
  build timestamp (`2016-06-30 01:26:15`) matches the established exfil build. The SDelete
  anti-forensics is **defeated**.
- **Objective B (Dropbox share link / QQ negotiation): RESOLVED AS A NEGATIVE — the question's
  premise was wrong.** There is **no Dropbox web share link** because the exfil was **not** a web
  share — it was a **direct desktop-client sync** to the operator's private Dropbox account
  **984347879**, *proven* (not merely "not found") by the cleartext `aggregation.dbx` `recent`
  record. The QQ↔nina_kwai negotiation is a **server-side artifact** (Gmail/QQ mailboxes) and is
  **not recoverable from this disk image**; it requires legal process to Google/Dropbox/Tencent.
- **Bonus:** the memory-remnant and chat-client streams recovered an **entirely new
  recruitment/negotiation channel** (Michael Merrick → Vladimir Bulgakov "Russian biotech," plus
  Skype "Titan"/"V-Gen" planning and Tor usage) that materially expands the conspiracy beyond the
  QQ/nina_kwai thread.
```

Full file: `SYNTHESIS.md` *(local-only; not published)*

## `carving.md` — the decisive Dropbox-sync evidence

```text
### Dropbox desktop-client artifacts (the decisive evidence)
`aggregation.dbx` (inode 32463) is a readable SQLite (`snapshot` table). Its only key, `recent`,
holds cleartext:

recent[{"timestamp": 1467251166, "server_path": "984347879:/vacation photos.7z",
        "blocklist": "Yg6M7NfRaO6gLPmgFVz9LwpxbnjYV3Bix7Ejrg8RMjs,...53QzxFOOMLOjc-..."},
       {"timestamp": 1438993270, "server_path": "984347879:/Get Started with Dropbox.pdf", ...},
       {"timestamp": 1467251145, "server_path": "984347879:/V-Photos", "blocklist": "..."}]

- `1467251166` → **2016-06-30 01:46:06 UTC** = exact archive-upload time. Account **984347879**
  confirmed. Also a `984347879:/V-Photos` folder synced 21 s earlier.
- `sqlite3 ... "SELECT key FROM snapshot"` → only `recent`. No `share`/`shmodel`/`/s/`/`/scl/`
  key. **The desktop client recorded a private sync, not a share link.**
```

Full file: `carving.md` *(local-only; not published)*

## `chat-clients.md` — TL;DR / verdict (PII redacted)

```text
- **NO Dropbox share link** (`dropbox.com/s/...` or `/sh/...`) was found in any chat client.
- **NO QQ negotiation with `nina_kwai@qq.com`** exists locally. **No Tencent QQ / WeChat client
  is installed** on STARKSURFACE at all — the QQ recipient was reached over **email**, not a
  local chat client.
- **Skype** is the only chat client with recoverable plaintext message history (329 messages /
  `main.db`). It contains rich espionage-narrative context (Vanko bragging about his "V-Gen"
  breakthrough, plans to leave Stark for "Vladimir/Vlad" at company "Titan", moving overseas,
  offering a "super soldier" formula to a foreign military) **but no exfil link, no archive
  transfer, and no `nina_kwai@qq.com`.** The "Nina" in Skype is a *personal/dating* contact set
  up by coworker <REDACTED-PII> — the cover-story human, not the QQ handle.
- **Telegram Desktop** was installed and active (2016-06-18 → 2016-06-27) but its `tdata` is
  fully encrypted; **no plaintext messages, handles, or links are recoverable.**
- **WhatsApp Desktop** was installed and launched but never linked to a phone — `Databases.db`
  is empty, **no chats exist.**
```

Full file: `chat-clients.md` *(local-only; not published)*

## `pagefile-hiberfil.md` — extraction caveat + account corroboration

```text
**Important caveat:** only **swapfile.sys (16 MiB) extracted cleanly**. The TSK `icat` extraction
of pagefile.sys (inode 44997) and hiberfil.sys (inode 75674) **timed out at 60 s**, leaving
**partial 256 MiB truncated** files on disk. These partial captures still contain real residual
data (verified non-zero pages mid/tail) and were carved, but they are **NOT** the complete
pagefile/hiberfil ...

Dropbox **account artifacts** that ARE present (corroborate established facts, but are not the link):

HOURLY_REFRESH: Event 'client-gandalf_allows' -> {'account':
  <dropbox.client.authentication.interface.Account host_int=4319428912L root_ns=984347879L
   role=1 is_primary=True quota=2147483648L in_use=1747733448 sync_space_used=1747733448>}
dropbox_path = C:\Users\PC User\Dropbox

→ Confirms Dropbox **account root_ns `984347879`** (matches the established exfil account) and
`in_use=1,747,733,448` bytes (~1.7 GB synced).
```

Full file: `pagefile-hiberfil.md` *(local-only; not published)*

## `vss.md` — bottom line (PII redacted)

```text
- **(A) RECOVERED — conclusive.** Two Volume Shadow Copies (Oct 14 2016, Nov 04 2016) exist and
  were mounted as full readable NTFS volumes. They contain a **live, intact copy of the exfil
  archive `vacation photos.7z` (sha256 `b210bcd8…`, 35,008,256 bytes, 221 files / 13 folders)**
  plus dozens of individual classified `.docx/.xlsx/.pdf` files — i.e. the material SDelete wiped
  on the live volume survives in the snapshots.
- **(B) PARTIAL.** No literal `https://www.dropbox.com/s/…` or `/sh/…` share-link string was
  recovered from the shadow copies (Dropbox stores share links server-side; the local `.dbx`
  databases are SQLCipher-encrypted). However the VSS WebCache (Edge/IE history for "PC User")
  corroborates the exfil channel: Dropbox account activity
  (`https://www.dropbox.com/home?email_just_verified=1`, dated 2016-06-27→07-04), the
  <REDACTED-PII> Gmail inbox, Hangouts chat sessions, and the `NinaResearch` file access.
  The QQ negotiation with nina_kwai was **not** present locally (it lives in Gmail/QQ server
  mailboxes).
```

Full file: `vss.md` *(local-only; not published)*

## `windows-old.md` — verdict

```text
**Clean negative for user data.** `Windows.old` on this image preserved **only the
operating-system `WINDOWS\` folder** (and `WINDOWS\System32\`). There is **NO `Users` directory,
NO `PC User` profile, NO prior `NTUSER.DAT`, NO `Documents`/`Downloads`/`Desktop`, NO
`ProgramData`, and NO `vacation photos.7z`** anywhere under `Windows.old`. Consequently:
- Question (A): no classified file / `.7z` / prior version is recoverable **from this source**.
- Question (B): no Dropbox share link or QQ negotiation can be recovered from this source
  (no user hives, no browser data, no Recent/JumpLists under Windows.old).
- The prior-OS RecentDocs / TypedPaths / OpenSavePidlMRU pivot (assigned step 2) is **not
  possible** — the prior NTUSER.DAT does not exist in Windows.old.

This is the expected outcome when a Windows "Reset this PC / keep nothing" (or an in-place
upgrade that discards profiles) moves only the OS tree into `Windows.old` and discards user
profiles, **rather than** the classic upgrade behavior that preserves `Windows.old\Users`.
```

Full file: `windows-old.md` *(local-only; not published)*
