# Case Activation Guides

This folder holds the **per-case Activation Guides** for every evidence set under `/cases/*` on the SIFT workstation —
fourteen cases in total (5 disk, 6 memory, 3 mixed multi-host). Each guide instantiates the same 8-step activation
template (pick evidence → `case_init` → `case_status` → `evidence_register` → analyze → `record_finding` → approve →
`report_generate`) with that case's **real values**: on-disk evidence paths, byte-exact sizes, acquisition hashes
(MD5/SHA-1 from `ewfinfo` or the imager log), the recommended tool chain for that evidence type, and the case-specific
GOTCHAs an operator will actually hit. Profiling in every guide was **metadata-only** (`ls`/`file`/`du`/`ewfinfo`) —
no forensic tool was run against evidence content to write a guide.

Every guide is dual-audience: each step shows the exact 🖥️ command or MCP call next to the 💬 plain-language prompt a
non-technical user can paste into a Claude session with the Agentropix MCP attached — both routes hit the same
deterministic tool. The MCP endpoint always appears as a placeholder (`http://<TAILNET-HOST>:8765/mcp`); no bearer
token or raw internal IP is reproduced. Most guides offer two execution lanes: a **Manual** numbered prompt sequence
(you drive each step) and an **Autonomous** sequence (a detached driver runs `case_init` → analysis → `record_finding`
to DRAFT, checkpointing `SUMMARY.json`, then stops).

The approval step is **always a human hard-stop**: an agent can only stage findings as DRAFT; promotion to APPROVED
requires an examiner's HMAC sign-off in the portal. Where a recorded demo run completes the loop, the approval was
**SIMULATED (demo only)** — driven by Playwright, not a human — and is labelled as such.

## File-by-file

### [INDEX.md](INDEX.md)
The master index. Routes by evidence type (disk / memory / mixed tables with file, size, and guide link), documents
the 9 `/cases/*` folders that were **skipped or classified as duplicates** (e.g. `cfreds-fresh1` is the CFReDS E01
missing its `.E02` segment; `security data` is a byte-identical copy of the Jimmy Wilson exam), and carries the
recorded-runs table with transcript/video/sealed-report links plus the multi-tier comprehensive reports per executed
run.

### [cfreds-hacking-case-4dell.md](cfreds-hacking-case-4dell.md)
NIST CFReDS "Hacking Case" — Greg Schardt / "Mr. Evil", a seized Dell Latitude CPi running Windows XP. Evidence:
`/cases/cfreds-fresh/4Dell-Latitude-CPi.E01`+`.E02` (EnCase 4 EWF, ~1.1 G on disk, 4.5 GiB decoded media, MD5
`aee4fcd9301c03b3b054623ca261959a` stored == computed). Distinctive: the NTFS partition starts at **sector 63** — the
guide's GOTCHA B2 makes that offset load-bearing for every filesystem tool. XP specifics are spelled out:
`get_amcache` is Win7+ (skip), and event logs are XP `.evt` (`get_evt`, not `get_evtx`).

### [techhive-chad-lt-laptop.md](techhive-chad-lt-laptop.md)
TheTechHive Chad_LT — a **Windows-on-ARM** Dell Inspiron 14 3420, the only ARM case in the corpus. Evidence:
`/cases/nist3/TheTechHiveScenario/TheTechHiveScenario/Chad_LT.E01` (86 G container, 465 GiB media, TX1 21.3.0
write-blocked acquisition). Load-bearing caveat: the primary OS volume (GPT partition 7) is **BitLocker-encrypted**,
and the 72-tool MCP surface includes **no BitLocker decryption wrapper** — the operator must unlock it out-of-band
(e.g. `dislocker` with the in-folder recovery key) first; until then triage is limited to the plaintext NTFS
partitions 8 and 9. ARM prefetch may be absent (tool self-skips).

### [jimmy-wilson-study-case.md](jimmy-wilson-study-case.md)
The Jimmy Wilson 25-question forensics exam: a 2017 FTK Imager acquisition (`/cases/study case/2020JimmyWilson.E01`,
296 M container, 850 MiB media, MD5 `b267fb0cd94645425eee00258d3a9b58`). Distinctive: a **GPT-partitioned disk
containing a nested `System.vhd`** whose "J. Wilson" partition must itself be examined, plus `.eml` email, Run-key,
browser-history and encryption-tool artifacts. The exam (`forensics-exam.md`) is the ground-truth question set
steering the tool chain; the source folder name has a space, so the slug `STUDY-CASE-JWILSON` is mandatory.

### [dfrws-2005-rodeo-usb.md](dfrws-2005-rodeo-usb.md)
DFRWS 2005 Forensics Rodeo — a seized FAT16 USB thumb drive as a **raw `dd`** image
(`/cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd`, 248 MB / 259,506,176 B). Distinctive: **no partition table** — `fls` runs
at offset 0, and a `get_partitions`/`mmls` error is the documented single-volume signal, not a failure (the CFReDS
sector-63 GOTCHA explicitly does not apply). Companion `rhino*.log` files are actually **pcap captures**, out of scope
for the SIFT disk chain; the published 34-page answer-key PDF is the ground truth.

### [vanko-abducted-zebrafish.md](vanko-abducted-zebrafish.md)
VANKO "The Case of the Abducted Zebrafish" (SANS FOR500) — insider IP-theft from a Microsoft Surface 3, **not a
malware intrusion** (valid credentials, a masquerade account, USB + cloud exfil). Evidence:
`/cases/vanko/surface_physical.E01`–`.E21`, a **21-segment EWF set** (~42 G on disk, 116 GiB media, MD5
`4032d556cc866c23f1e797410e95603c` matching the FTK Imager log). Distinctive: **Volume Shadow Copy recovery is the
load-bearing step** — SDelete wiped the originals but the 2016 VSS snapshots preserved them; GOTCHA B2 here warns
*don't assume* sector 63. The sealed report lives in [../docs/12-CASES-REPORTS/](../docs/12-CASES-REPORTS/).

### [amf-memory-samples.md](amf-memory-samples.md)
The *Art of Memory Forensics* training corpus: 19 raw `.bin` RAM dumps (9 Windows, 6 Linux, 4 Mac) under
`/cases/AMF_MemorySamples/`, 13 G total, CC-BY-NC-SA 3.0 licensed. Distinctive: a verified platform constraint — the
`run_volatility` allowlist contains **only `windows.*` plugins**, so the 9 Windows samples get the full memory chain
while Linux/Mac samples are **register-and-custody-only** through the MCP. The guide prescribes per-sample activation
(one case per dump, deterministic slug table) because there is exactly one active case at a time.

### [challenge-notch-it-up.md](challenge-notch-it-up.md)
CTF-style challenge "Notch It Up": a single raw Windows RAM capture, `/cases/Challenge_NotchItUp/Challenge.raw` (1.5
GiB, 1,610,547,200 B). Distinctive caveat: `file(1)` **misreports it as `Windows Event Trace Log`** — a wrong magic;
trust size + provenance. It shares its exact byte size with a MemLabs Lab6 dump but is treated as an independent
single-evidence case; no readme/ground-truth ships in the folder, so everything must be derived from the image.

### [contact-me-memory.md](contact-me-memory.md)
CTF "Contact Me": a 1.0 GiB (exactly 1,073,741,824 B) raw RAM dump with **no file extension** at
`/cases/contact_me/contact_me` (`file` → `data`). OS unknown at registration — the guide leans on Volatility3's
profile-less design: the kernel symbol table is auto-detected on the first `windows.*` plugin (`get_pslist`); there is
no separate info/banners step in the allowlist. This case has a full recorded activation run with video (see runs/).

### [memdump-mem.md](memdump-mem.md)
A generic, unattributed 512 MiB raw memory image (`/cases/memdump/memdump.mem`, 536,870,912 B exactly, file-dated
2014-01-08) with **no scenario metadata at all**. Distinctive: the guide treats every count as *discovered, not
expected*, and documents the honest-negative rule — if plugins return empty with `kernel.symbol_table_name`
unresolved, no Windows profile matched, and that result is recorded as-is. It also explains why `get_image_info` is
omitted (EWF-only; empty on a flat `.mem`).

### [memlabs-dumps.md](memlabs-dumps.md)
The MemLabs CTF corpus under `/cases/nist4/`: six independent Windows scenarios (`MemoryDump_Lab1..6.raw`, 1.0–1.5 GiB
each, 8.8 G folder total) plus a `procee` tar that extracts the Lab 3 `Challenge.raw`. Each Lab gets its own slug and
scenario summary (Lab1 "Beginner's Luck" through Lab6 "The Reckoning", a C2 hunt). GOTCHAs: these are raw dumps, so
`ewfverify`/`ewfinfo` do not apply — integrity anchors on the `evidence_register` SHA-256 cross-checked against the
MemLabs README MD5s; bare middle plugin forms (`windows.cmdline`) are rejected and there is **no `hashdump`** in the
allowlist.

### [win-xp-laptop-2005.md](win-xp-laptop-2005.md)
A 512 MiB raw `.img` dated 2005-06-25 (`/cases/win-xp-laptop-2005-06-25.img/win-xp-laptop-2005-06-25.img`).
Distinctive: the folder labels it a **disk**, but the metadata-only byte profile shows a **Windows XP RAM capture** —
no `55 AA` MBR signature, a real-mode interrupt-vector table at offset 0, and strings dominated by process environment
blocks and loaded-module paths. The guide therefore routes the **memory chain as primary** with the disk chain (`mmls`
→ `fls`) kept as an explicit fallback should a filesystem be confirmed later.

### [srl-2015-apt-enterprise.md](srl-2015-apt-enterprise.md)
SRL-2015 — the SANS FOR508 Stark Research Labs APT intrusion: **4 Windows hosts** (XP workstation, Win7 x86, Win7 x64,
Win2008R2 domain controller on `10.3.58.0/24`), each with a C-drive E01 (15–31 GiB media, per-image stored MD5s)
**and** a 2.0–2.5 G raw `.001` memory dump; 56 G total under `/cases/SRL-2015/`. Distinctive: a strict do-not-register
list — `.mans` Mandiant Redline collections, `baseline-memory/` clean images, and the SANS `precooked/` reference
answers are present in-folder and must never be registered as evidence. GOTCHAs from the validated run cover the
mmls-derived `fls` offset (B2) and scoping `get_image_info` to the 4 disk E01s only.

### [srl-2018-compromised-enterprise.md](srl-2018-compromised-enterprise.md)
SRL-2018 — the **largest case in the corpus at 198 GiB**: 7 host E01s (DC, file server, terminal servers,
workstations, DMZ-FTP; FTK Imager via F-Response, examiner "Clint Barton", Sept 2018) plus **22 raw `.img` memory
dumps** with `dc3dd` `.md5` sidecars. The investigative point is cross-host correlation of a cascading C2 backbone
(hypothesis IOC `42.112.153.164:8080`, treated as a bias-check to prove live, not a conclusion). Honest caveat kept in
the guide: the memory-case sequences are authored but **not yet live-validated**; several `.img` files trip the same
`Windows Event Trace Log` magic false-positive.

### [rocba-hackathon-2026.md](rocba-hackathon-2026.md)
ROCBA Hackathon 2026 — a mixed single-host case: `/cases/rocba/rocba-cdrive.e01` (23 GB container, 81 GiB media,
Windows 10 build 19042, acquired with X-Ways XWF 20.1) plus `/cases/rocba/Rocba-Memory/Rocba-Memory.raw` (18 GB raw
memory). Distinctive: the disk is a **whole-disk, single-volume NTFS capture with no MBR partition table** — `fls`
uses offset 0, explicitly contrasted with CFReDS; the `.raw`'s `Windows Event Trace Log` magic is documented as a
coincidence. Scenario hypotheses (external RDP brute-force T1110.003, ~15,048 `4625` failures; user-execution malware
T1204.002) are framed as claims to prove, and the prior derived output under `_work/`/`_archive/` is flagged
do-not-register.

### [runs/](runs/) — executed captures
See [runs/README.md](runs/README.md). Every folder there is a real captured execution: four full-loop MCP activation
recordings with video (Contact Me, AMF sample001, memdump, Notch It Up — each ending in a **SIMULATED examiner
approval**, labelled as demo-only), two activation-only captures (SRL-2018, VANKO — their full investigations live in
the sealed case reports), and three `agentropix-sift` **engine** triage PoCs with sealed `report.json` records (Jimmy
Wilson: 129 findings / 86 tool calls; DFRWS Rodeo: 9 findings / 68 tool calls, an honest-negatives case; plus the
first engine smoke run). Two newer runs add the **Find Evil! requirement-8 agent-execution-log** evidence:
[rocba/](runs/rocba/) is a real live-MCP triage of the ROCBA Hackathon 2026 Windows-10 insider-IP-theft case (31 MCP
requests, an RDP brute-force DRAFT finding, and the honest negatives kept on record — a carve param-bug, a DRAFT-only
`report_generate case_not_found` gotcha, and a memory-init timeout), bundled with its server HTTP/thymus audit logs;
[WINXP-LAPTOP-2005/](runs/WINXP-LAPTOP-2005/) is a sibling agent-execution-log run for the 2005 Windows XP laptop case.
Raw `step*.json` tool outputs are committed unedited.

## How to use

1. Pick your case in [INDEX.md](INDEX.md) (disk / memory / mixed tables).
2. Open its Activation Guide and follow ONE lane per step: the **Manual** numbered sequence
   (🖥️ command or 💬 prompt — you drive and verify each step), or the **Autonomous** sequence
   (detached driver runs to DRAFT findings, then stops).
3. Approval is the human hard-stop: an examiner approves findings in the portal before
   `report_generate` will seal anything.

Sealed, human-approved case reports (SRL-2015, SRL-2018, VANKO) live in
[../docs/12-CASES-REPORTS/](../docs/12-CASES-REPORTS/); executed transcripts and videos live under [runs/](runs/).
