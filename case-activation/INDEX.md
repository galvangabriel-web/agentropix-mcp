# Case Activation Guides — Master Index

> **LOCAL / OPERATIONAL — tracked, not yet public-safe.** This directory (`/home/admin2/docu_agentro/case-activation/`) **is** version-controlled and pushed to the internal GitLab, but it holds **real case inventory, on-disk paths, and custody hashes** — scrub paths/case names before the repo is ever made public.

**How to use:** Pick your case from the tables below → open its per-case Activation Guide → run either the **Manual** numbered prompt sequence (interactive, you drive each step) or the **Autonomous** sequence (detached driver runs to a DRAFT, you approve in the portal). Every guide instantiates the 8-step template procedure (`pick → case_init → case_status → evidence_register → analyze → record_finding → approve → report`) from [`END-USER-CASE-GUIDE.md`](/home/admin2/agentropix-sift/docs/tools/END-USER-CASE-GUIDE.md) with that case's real specifics, using the canonical 71-tool / 16-wrapper / 4464-test SIFT MCP surface. The MCP endpoint is shown as a `<TAILNET-HOST>` placeholder in every guide; the approval step is always a human hard-stop.

14 cases documented · 9 folders skipped/duplicate · all evidence paths verified present · directory tracked (internal GitLab).

---

## Disk cases

| Case | Type | Evidence (file · size) | Guide |
|---|---|---|---|
| CFReDS Hacking Case (Greg Schardt / "Mr. Evil") | disk (EWF) | `/cases/cfreds-fresh/4Dell-Latitude-CPi.E01`+`.E02` · 1.1G (media 4.5 GiB) | [cfreds-hacking-case-4dell.md](./cfreds-hacking-case-4dell.md) |
| TheTechHive — Chad_LT (ARM Windows laptop) | disk (EWF) | `/cases/nist3/TheTechHiveScenario/TheTechHiveScenario/Chad_LT.E01` · 86G (media 465 GiB) | [techhive-chad-lt-laptop.md](./techhive-chad-lt-laptop.md) |
| Jimmy Wilson study case | disk (EWF) | `/cases/study case/2020JimmyWilson.E01` · 296M (media 850 MiB) | [jimmy-wilson-study-case.md](./jimmy-wilson-study-case.md) |
| DFRWS 2005 Rodeo USB | disk (raw dd, FAT16) | `/cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd` · 248M (259,506,176 B) | [dfrws-2005-rodeo-usb.md](./dfrws-2005-rodeo-usb.md) |
| VANKO — "Abducted Zebrafish" (FOR500 insider IP-theft) | disk (EWF, 21-segment) | `/cases/vanko/surface_physical.E01`–`.E21` · ≈42G (media 116 GiB / 125,069,950,976 B) | [vanko-abducted-zebrafish.md](./vanko-abducted-zebrafish.md) |

## Memory cases

| Case | Type | Evidence (file · size) | Guide |
|---|---|---|---|
| AMF memory samples (Windows/Linux/Mac RAM dumps) | memory (raw .bin) | `/cases/AMF_MemorySamples/` · 13G (9 Win + 6 Linux + 4 Mac) | [amf-memory-samples.md](./amf-memory-samples.md) |
| Challenge "Notch It Up" | memory (raw) | `/cases/Challenge_NotchItUp/Challenge.raw` · 1.5G (1,610,547,200 B) | [challenge-notch-it-up.md](./challenge-notch-it-up.md) |
| CTF "Contact Me" | memory (raw RAM dump) | `/cases/contact_me/contact_me` · 1.0 GiB (1,073,741,824 B) | [contact-me-memory.md](./contact-me-memory.md) |
| memdump (generic 2014 RAM image) | memory (raw) | `/cases/memdump/memdump.mem` · 512 MiB (536,870,912 B) | [memdump-mem.md](./memdump-mem.md) |
| MemLabs CTF dumps (6 labs + procee tar) | memory (raw) | `/cases/nist4/` · 8.8G | [memlabs-dumps.md](./memlabs-dumps.md) |
| Windows XP laptop 2005 | memory (raw .img)* | `/cases/win-xp-laptop-2005-06-25.img/win-xp-laptop-2005-06-25.img` · 512 MiB (536,715,264 B) | [win-xp-laptop-2005.md](./win-xp-laptop-2005.md) |

\* Folder labelled disk, but profiling (read-only) shows a Windows XP RAM capture — guide routes the memory chain primary, disk chain as fallback.

## Mixed cases (disk + memory, multi-host)

| Case | Type | Evidence (file · size) | Guide |
|---|---|---|---|
| SRL-2015 APT enterprise breach | mixed (4 C-drive EWF + 4 raw memory .001) | `/cases/SRL-2015/` · 56G | [srl-2015-apt-enterprise.md](./srl-2015-apt-enterprise.md) |
| SRL-2018 compromised enterprise | mixed (7 EWF + 22 raw memory .img) | `/cases/SRL-2018/` · 198G | [srl-2018-compromised-enterprise.md](./srl-2018-compromised-enterprise.md) |
| ROCBA Hackathon 2026 | mixed (1 EWF + 1 raw memory) | `/cases/rocba/rocba-cdrive.e01` (23G) + `/cases/rocba/Rocba-Memory/Rocba-Memory.raw` (18G) | [rocba-hackathon-2026.md](./rocba-hackathon-2026.md) |

---

## Skipped folders (not evidence)

These `/cases/*` folders were classified and **not** turned into activation guides:

| Folder | Why skipped |
|---|---|
| `Sierra_10.12.6_16G23a` | Volatility kernel symbol/vtypes profile (macOS Sierra) — analysis-support files, not a disk/memory image. |
| `TheTechHiveScenario` | Only the BitLocker recovery key `.txt`; the real `Chad_LT.E01` lives under `nist3` (→ documented as TechHive). Duplicate of `nist3`. |
| `auto` | Agentropix-SIFT correlation proof-run **output** (process-tree/timeline/IOC JSON + reports) about SRL-2018 — generated, not evidence. |
| `nist2` | Kaggle network-traffic CSV dataset + saved HTML page — tabular data, no image. |
| `srl-2018` (lowercase) | Root-owned empty stub (only an empty `extracted/`); real corpus is `SRL-2018`. Duplicate of `SRL-2018`. |
| `yara-rules` | Local YARA detection rules (`pf_smoketest.yar`) — scanning support asset, not evidence. |

## Duplicates (already covered by a documented case)

| Folder | Duplicate of | Note |
|---|---|---|
| `cfreds-fresh1` | `cfreds-fresh` (CFReDS guide) | Same 4Dell-Latitude-CPi E01 but **missing the .E02 segment** — incomplete copy. |
| `nist1` | `cfreds-fresh` (CFReDS guide) | NIST Hacking Case bundling both the E01/E02 EWF and the SCHARDT.001-008 raw split-dd of the same disk; 4Dell E01 byte-identical to cfreds-fresh. |
| `memlabs` *(removed)* | `nist4` (MemLabs guide) | Was a stuxnet999 MemLabs CTF repo clone (READMEs + one un-extracted `.7z`); folder since deleted — the extracted `.raw` dumps live under `nist4`. |
| `security data` | `study case` (Jimmy Wilson guide) | Identical nested copy of the Jimmy Wilson exam (byte-identical `2020JimmyWilson.E01`, same exam `.md` + PDF). |

---

## Recorded runs

Educational recordings of a real executed activation sequence (live MCP calls, captured output):

| Case | Sequence | Transcript | Video | Sealed report |
|---|---|---|---|---|
| CTF "Contact Me" | §3A manual | [EXECUTED-RUN.md](./runs/contact-me-memory/EXECUTED-RUN.md) | [EXECUTED-RUN.mp4](./runs/contact-me-memory/EXECUTED-RUN.mp4) (50.7s) | ✅ SIMULATED demo |
| AMF Windows sample001 | §3.A manual | [EXECUTED-RUN.md](./runs/amf-win-sample001/EXECUTED-RUN.md) | [EXECUTED-RUN.mp4](./runs/amf-win-sample001/EXECUTED-RUN.mp4) (56s) | ✅ SIMULATED demo |
| memdump (raw 2014) | MANUAL | [EXECUTED-RUN.md](./runs/memdump-raw-2014/EXECUTED-RUN.md) | [EXECUTED-RUN.mp4](./runs/memdump-raw-2014/EXECUTED-RUN.mp4) (63s) | ✅ SIMULATED demo |
| Challenge "Notch It Up" | MANUAL | [EXECUTED-RUN.md](./runs/challenge-notchitup/EXECUTED-RUN.md) | [EXECUTED-RUN.mp4](./runs/challenge-notchitup/EXECUTED-RUN.mp4) (50.6s) | ✅ SIMULATED demo |
| VANKO — "Abducted Zebrafish" | activation only (steps 0–5) | [EXECUTED-RUN.md](./runs/vanko-abducted-zebrafish/EXECUTED-RUN.md) | — | — (full sealed report: [`docs/12-CASES-REPORTS/vanko-report/`](../docs/12-CASES-REPORTS/vanko-report/)) |

The per-case **report** (comprehensive + exec one-pager) is in the table just below. *(The VANKO run captured **activation only** — `case_init`→`get_image_info`, no analysis/approval; its full 10-confirmed-finding investigation is the sealed report under `docs/12-CASES-REPORTS/vanko-report/`, not a recorded activation video.)*

**Outstanding multi-audience reports.** Beyond the three focused tiers, each run also ships a **comprehensive report** — one big document fusing an executive dashboard (KPI tiles, risk matrix), full forensic sections (IOC catalogue, host/network artefacts, malware + MITRE ATT&CK, process tree, timeline), and coverage attestation — plus a **1-page executive summary**, both grounded in the case's real data and rendered with diagrams:

| Case | Comprehensive (super-report) | Exec one-pager |
|---|---|---|
| CTF "Contact Me" | [comprehensive.md](./runs/contact-me-memory/reports/comprehensive.md) · [.pdf](./runs/contact-me-memory/reports/comprehensive.pdf) | [.md](./runs/contact-me-memory/reports/executive-onepager.md) · [.pdf](./runs/contact-me-memory/reports/executive-onepager.pdf) |
| AMF Windows sample001 | [comprehensive.md](./runs/amf-win-sample001/reports/comprehensive.md) · [.pdf](./runs/amf-win-sample001/reports/comprehensive.pdf) | [.md](./runs/amf-win-sample001/reports/executive-onepager.md) · [.pdf](./runs/amf-win-sample001/reports/executive-onepager.pdf) |
| memdump (raw 2014) | [comprehensive.md](./runs/memdump-raw-2014/reports/comprehensive.md) · [.pdf](./runs/memdump-raw-2014/reports/comprehensive.pdf) | [.md](./runs/memdump-raw-2014/reports/executive-onepager.md) · [.pdf](./runs/memdump-raw-2014/reports/executive-onepager.pdf) |
| Challenge "Notch It Up" | [comprehensive.md](./runs/challenge-notchitup/reports/comprehensive.md) · [.pdf](./runs/challenge-notchitup/reports/comprehensive.pdf) | [.md](./runs/challenge-notchitup/reports/executive-onepager.md) · [.pdf](./runs/challenge-notchitup/reports/executive-onepager.pdf) |

The transcript captures the real tool responses/exits step by step. Each recorded run now completes the **full human-approval → sealed-report loop**: at least one finding moves DRAFT → APPROVED and `report_generate` returns `approved_finding_count >= 1` with a sealed report. **The approval was SIMULATED for the demo** — driven by Playwright against the Examiner Portal, **not** performed by a human; a real case requires a human examiner's HMAC sign-off. The **demo credentials** (examiner ID + approver password) live in [approval-portal.md](../docs/05-safety-forensics/approval-portal.md). The MCP host is shown as `<TAILNET-HOST>`; no token is reproduced.

---

*SIFT MCP surface: 71 tools / 16 wrappers / 4464 tests (`/home/admin2/docu_agentro/.crew/facts.md`). Evidence licensing where applicable (e.g. AMF: CC-BY-NC-SA 3.0) is noted in the individual guides. Approval remains a human hard-stop in every workflow.*
