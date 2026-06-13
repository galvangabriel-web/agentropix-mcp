# Execution Video — Storyboard (full technical, ~8–9 min)
## Case `WINXP-LAPTOP-2005` · Windows XP SP2 laptop memory (2005-06-25)

**Render-ready package.** Diagrams are pre-rendered to PNG in `diagrams/` (mmdc).
Feed this to the repo video pipeline (`render-bmad-md.sh <md> <out>` for the
narrated MP4, or `make_presentation_video.sh`). Target runtime **~510s (8:30)**.

**Integrity discipline (per repo conventions):**
- Verdict is **BENIGN** — keep honest negatives; never dress a cleared lead as a hit.
- Approvals here were **REAL human portal approvals** (HMAC, examiner victor.galvan) —
  do **NOT** label them "SIMULATED"; that caveat applies only to auto-approved demos.
- Every figure below is grounded in the sealed case (6 approved findings, 11 timeline
  events, 17 hash-chained approvals).

**Ground-truth data bag (for lower-thirds / callouts):**
| Field | Value |
|---|---|
| Image | `win-xp-laptop-2005-06-25.img` · raw · 512 MB |
| SHA-256 | `c4aeeb1b461378eef796944884d1d60adaa99cbae4d035923c144b08deee1e6e` |
| OS | Windows XP SP2 x86 (vol3 2.28.0) |
| Host/user | win-xp-laptop / **Sarah** (corporate GIS/imagery workstation) |
| Processes | 47 (pslist) · suspicious=0 (pstree) |
| Acquisition | `explorer(1812) → cmd(2624) → dd(4012)` reading `\\.\PhysicalMemory` |
| malfind | 20 hits → 5 RWX in PID 840 dumped → zero-filled → **cleared** |
| Persistence | Run-keys 15 (legit) · svcscan 299 · mutantscan 362 — all clean |
| Case record | 6 findings · 11 timeline · **17 approvals** · 0 IOCs |
| Verdict | **Benign** — clean user session + memory-acquisition footprint |

---

## Scene 1 — Cold open / activation  · 0:00–0:35 (35s)
- **On-screen:** title card → terminal: `case_init WINXP-LAPTOP-2005` + `evidence_register` returning the SHA-256; lower-third with image size/OS.
- **Narration:** "A two-gigabyte — actually 512-megabyte — Windows XP SP2 memory image, acquired in 2005. We open a case, register the evidence under a SHA-256 hash to start chain of custody, and confirm the image is analyzable. No 'identify the OS' step is needed — the kernel profile auto-detects the moment the first Volatility plugin returns processes."

## Scene 2 — First triage: it parses, 47 processes · 0:35–1:10 (35s)
- **On-screen:** `get_pslist` output scrolling; highlight System/smss/winlogon/services/lsass and the user apps.
- **Narration:** "`pslist` returns 47 processes — a populated list confirms the symbol table matched. We see a normal XP boot: System, smss, winlogon spawning services and lsass, a Symantec and Sygate security stack, then the user's shell and apps. This is our baseline; everything later is judged against it."

## Scene 3 — The execution chain  · 1:10–2:05 (55s)
- **On-screen:** `diagrams/d1-execution-chain.png` (build it up; end on the red `dd` node). Cut to `cmdline` row for PID 4012.
- **Narration:** "Linking processes by parent PID and create-time reconstructs the execution chain. explorer launches cmd at 16:57:36, and seventy seconds later cmd launches `dd`. The command line is the smoking gun: `dd if=\\.\PhysicalMemory of=c:\xp-laptop-2005-06-25.img`. That's the memory acquisition itself — the tool that made this dump is captured *inside* the dump. The three orphan processes — explorer among them — are benign: their parents, like userinit, simply exited."

## Scene 4 — The self-referential teaching point · 2:05–2:35 (30s)
- **On-screen:** split — `dd` node + the note "acquisition tool inside its own snapshot".
- **Narration:** "This is the lesson that makes the image a teaching classic: when you see `dd`, `winpmem`, or FTK Imager reading PhysicalMemory, you're looking at the capture event. Orient the whole timeline around it — and remember the observer is part of what's observed."

## Scene 5 — Hunting injection: malfind · 2:35–3:25 (50s)
- **On-screen:** `get_malfind` — 20 hits; highlight PID 840 svchost with 6 RWX VadS regions; show the `` `VWj `` (pushad) bytes.
- **Narration:** "Now we hunt for injected code. `malfind` flags twenty regions. Most are textbook XP false positives — a shared heap region across csrss, winlogon and the browsers. But svchost PID 840 has six read-write-execute regions with pushad-style bytes. On XP that's suggestive — not conclusive. So we don't call it. We prove it."

## Scene 6 — Dump and clear (self-correction) · 3:25–4:15 (50s)
- **On-screen:** `malfind --pid 840 --dump` → the five `.dmp` rows; zoom the Hexdump showing **all zeros**. Stamp "BENIGN".
- **Narration:** "We dump all five regions. And the content rewrites the story: they're zero-filled — empty, reserved executable heap, the kind svchost-netsvcs allocates normally. The pushad bytes were sparse stale fragments, not a contiguous payload. The lead is cleared, on evidence, and recorded as resolved. This is the discipline — a hunch dumped and disproven, not a hunch shipped as a finding."

## Scene 7 — User intent: UserAssist corroborates · 4:15–5:05 (50s)
- **On-screen:** `diagrams/d3-timeline.png`; overlay UserAssist rows — cmd.exe 16:57:36, firefox 16:49:22, iexplore 16:51:02.
- **Narration:** "The registry gives us a second, independent witness. UserAssist in Sarah's hive records GUI launches with timestamps that match the process tree to the second — cmd at 16:57:36, Firefox at 16:49. And note what's absent: `dd` itself. UserAssist only logs Explorer launches, so the registry confirms a human opened the console, while the process tree shows what was typed into it. Two artifacts, one story."

## Scene 8 — Persistence sweep: all clean · 5:05–6:00 (55s)
- **On-screen:** three quick panels — printkey Run (15 entries: Symantec, Sygate, QuickTime, Java, LANDesk, Pictometry), svcscan (299, no temp/user binaries), mutantscan (362, no malware mutexes).
- **Narration:** "We widen the net to persistence. The Run keys hold fifteen autoruns — every one legitimate 2005 software, all stamped the same install date. 299 services: kernel drivers plus Symantec, Sygate, Roxio, a license daemon — none running from temp or user directories. 362 mutexes, none matching known malware. The host profile resolves: a corporate GIS imagery workstation. Nothing hides here."

## Scene 9 — Verdict: benign · 6:00–6:35 (35s)
- **On-screen:** `diagrams/d5-coverage.png` — coverage fanning into the green BENIGN node.
- **Narration:** "Across pslist, pstree, cmdline, malfind-with-dump, UserAssist, hivelist, Run-keys, services and mutexes, the verdict is benign. No injection, no persistence, no rogue services, zero indicators of compromise. The one notable artifact is the acquisition footprint. We say that plainly — manufacturing an intrusion that isn't there would be the real failure."

## Scene 10 — From evidence to record · 6:35–7:05 (30s)
- **On-screen:** `diagrams/d2-pipeline.png` — the six-stage pipeline lighting up; six finding IDs listed.
- **Narration:** "Findings don't float free. Six are drafted — the acquisition chain, the user-intent corroboration, the malfind lead and its resolution, the clean persistence sweep, and a disposition. Each is an append-only, HMAC-sealed record moving through a deliberate pipeline: docket, run, review, approve, seal."

## Scene 11 — The human gate · 7:05–7:50 (45s)
- **On-screen:** `diagrams/d4-approval-chain.png`; portal at `siftworkstation…:8443`; approvals ledger showing 17 APPROVED, genesis `prev_hash` empty.
- **Narration:** "Approval is a hard stop the AI cannot pass. An examiner signs each finding in a portal with a password the model never sees — PBKDF2 and HMAC, computed server-side. Seventeen approvals land in a hash-chained ledger, each linked to the last, tamper-evident end to end. The agent investigates; a human authorizes."

## Scene 12 — Seal · 7:50–8:10 (20s)
- **On-screen:** `report_export` → analyst / executive / business markdown; the analyst report's Mermaid kill-chain.
- **Narration:** "Only after approval does the report populate. Three audience tiers render from the approved record — analyst, executive, and business — sealed and reproducible."

## Scene 13 — How the approach changed (self-corrections) · 8:10–8:40 (30s)
- **On-screen:** montage — (a) 9 `record_timeline_event` ERRORs → fixed with `event_id`; (b) malfind lead → dump → cleared; (c) the sidecar URL: documented default → corrected from source to the real tailnet endpoint.
- **Narration:** "Three honest course-corrections shaped this run: nine timeline writes failed on a missing field and were re-issued; the injection lead was dumped and retracted; and a stale sidecar default was traced through the source code to the real endpoint. Visible mistakes, visibly fixed — that's the trace, not a varnish over it."

## Scene 14 — Closing the gap (bonus) · 8:40–8:55 (15s)
- **On-screen:** the `case_close` patch diffstat (4 files, +241), `git apply --check: CLEAN`, tests passing.
- **Narration:** "When closing the case revealed a missing tool, we didn't fake it — we read the source, confirmed the gap, and wrote a verified `case_close` patch so the next case closes with one call."

## Scene 15 — Disposition / outro · 8:55–9:05 (10s)
- **On-screen:** disposition card: "BENIGN · no escalation · 6 findings, 17 approvals, sealed"; SHA-256 footer.
- **Narration:** "Case WINXP-LAPTOP-2005: benign, no escalation, fully approved and sealed. Evidence in, sealed report out — with the human in the loop the whole way."

---

## Asset manifest
| Scene(s) | Asset |
|---|---|
| 3, 4 | `diagrams/d1-execution-chain.png` |
| 10 | `diagrams/d2-pipeline.png` |
| 7 | `diagrams/d3-timeline.png` |
| 11 | `diagrams/d4-approval-chain.png` |
| 9 | `diagrams/d5-coverage.png` |
| (live captures to add on host) | pslist, cmdline(PID 4012), malfind, malfind --dump hexdump, userassist, printkey Run, svcscan, mutantscan, approvals ledger, report_export, case-close diffstat |

## Render notes
- **Diagrams are PNG** (not inline Mermaid) per repo convention — GitHub/GitLab shrink/reject inline Mermaid; PNG always renders.
- Source `.mmd` files are in `mmd/` if you need to re-render at a different scale (`mmdc -i mmd/dN.mmd -o diagrams/dN.png -b white -t dark -s 2`).
- Narration word counts are paced ~150 wpm to hit the per-scene seconds; total ≈ 8:30–9:05.
- For the live-capture panels (pslist/malfind/etc.), pull frames from a real MCP run on the render host — keep the real IDs/timestamps shown here so the lower-thirds stay truthful.
- Keep the **benign** framing and the **real-approval** (not simulated) note intact.
