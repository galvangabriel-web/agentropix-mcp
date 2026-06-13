# Evidence Datasets — Corpus Inventory & Provenance

> **What this page is.** The complete inventory of the forensic evidence corpus the Agentropix-SIFT
> recall and case-report claims are measured against: per-case provenance, evidence types
> (disk / memory / network), sizes, and — where the agent has investigated the case — a link to the
> in-repo case report. Provenance is stated **only** where it could be verified from acquisition
> metadata (`ewfinfo` case numbers, shipped license files, scenario documents) or the per-case
> [activation guides](../../case-activation/INDEX.md); anything else is marked **provenance: unverified**.
>
> Local case labels below are workspace directory names (no absolute paths). Raw images are **not**
> in this repo — to reproduce, obtain each dataset from its public source (SANS course media,
> NIST CFReDS portal, MemLabs GitHub, DFRWS archives, Volatility Foundation).

## 1. Per-case inventory

Survey method: read-only `ls` / `du -sh` / `find` / sampled `file(1)` over the operator evidence
store (2026-06-12). Total corpus: **~545 GB across 22 directories** (20 case dirs + 2 non-evidence).

| Case label | Public source / provenance | Size | Evidence types | Network capture? | What the agent found (in-repo) |
|---|---|---|---|---|---|
| `SRL-2015` | **SANS FOR508 "Stark Research Labs Data Breach Intrusion" (2015)** — verified via `ewfinfo` case number in every E01, examiner `SANS`. Obtain from SANS course media. | 56G | 4× disk E01 (per-host C-drives: nromanoff, nfury, tdungan, win2008R2 DC), 4× raw memory dumps, Mandiant `.mans` triage, acquisition logs | No (see §2) | [Sealed report — 2,233 raw → 17 approved findings, 21 malware samples](../12-CASES-REPORTS/srl-2015-report/README.md) |
| `SRL-2018` | **SANS FOR508-style SRL-2018 enterprise corpus** — verified via `ewfinfo` (examiner Clint Barton, case `20180905-001`, F-Response network acquisition, Sept 2018). Obtain from SANS course media. | 198G | 7× disk E01 (`base-*` hosts), 22× raw memory `.img` (+ snapshot images, 21 `.md5` sidecars), carve output | No (see §2) | [Sealed forensic report + Wazuh IOC gallery](../12-CASES-REPORTS/srl-2018-report/README.md) · [recall run-summary 49/49](recall-ground-truth/run-summary-FULL-CASE-20260505T004738Z.md) |
| `srl-2018` (lowercase) | Stale empty duplicate of `SRL-2018` — no evidence. | 8K | Empty `extracted/` dir only | No | — (skipped, [duplicates table](../../case-activation/INDEX.md)) |
| `case-A` | **NIST CFReDS "Hacking Case"** (Greg Schardt / "Mr. Evil", Dell Latitude CPi) — duplicate workspace of `cfreds-fresh`; E01 byte-identical. Obtain from NIST CFReDS portal. | 5.6G | E01 pair + raw split-dd `SCHARDT.001–.008` of the same disk, acquisition log, hash manifest | No (see §2) | — (covered by `cfreds-fresh` guide) |
| `nist2` | CSV network-attack log dataset (Kaggle-style `cybersecurity_attacks_data.csv`) — **provenance: unverified**. Tabular telemetry, not an image. | 17M | 17 MB CSV traffic-log data + saved HTML page | No (CSV logs only, **not** a pcap) | — (skipped: not a forensic image) |
| `nist3` | **NIST CFReDS "The TechHive Scenario"** — verified via TX1 acquisition logs + BitLocker recovery key. Obtain from NIST CFReDS portal. | 86G | `Chad_LT.E01` (Windows-on-ARM laptop, 465 GiB media), TX1 acquisition logs | No | [Activation guide](../../case-activation/techhive-chad-lt-laptop.md) |
| `nist4` | **MemLabs CTF Labs 1–6** (stuxnet999/MemLabs, GitHub) — verified via lab archives. | 8.8G | 6× Windows memory dumps `MemoryDump_Lab1..6.raw` + source `.7z`, `procee` memory sample | No | [Activation guide](../../case-activation/memlabs-dumps.md) |
| `nist5` | **DFRWS 2005 Memory Analysis Challenge / Forensics Rodeo ("RODEO")** — verified via challenge files + published answers PDF. Obtain from DFRWS archives. | 253M | `RHINOUSB.dd` FAT16 USB image + challenge files + three acquired scenario pcaps (`rhino*.log`) | **Yes — 3 acquired pcaps** (`rhino.log` / `rhino2.log` / `rhino3.log`, pcap v2.4 Ethernet, mislabeled `.log`; see §2a). SIFT chain does **not** parse pcap. | [Activation guide](../../case-activation/dfrws-2005-rodeo-usb.md) |
| `rocba` | **ROCBA Hackathon 2026 scenario** (private hackathon; background PPTX + questions ship with it) — not a public dataset. | 92G | `rocba-cdrive.e01` (23.7 GB E01) + `Rocba-Memory.raw` (18 GB) + archives | No | [Activation guide](../../case-activation/rocba-hackathon-2026.md) |
| `vanko` | **SANS FOR500 "The Case of the Abducted Zebrafish"** (VANKO insider IP-theft scenario) — verified via scenario `.docx` + AccessData acquisition artifacts. Obtain from SANS course media. | 82G | `surface_physical.E01–.E17` multi-segment E01 (~36 GB), master archive, acquisition logs | **Yes — 2 pcaps on the suspect disk** (`testpcap.pcap`, `starbucks pcap.pcap`; 802.11 + radiotap Wi-Fi captures residing in the image, surface on extraction; see §2a). SIFT chain does **not** parse pcap. | [Sealed report — 10 confirmed findings](../12-CASES-REPORTS/vanko-report/README.md) · [recorded activation run](../../case-activation/runs/vanko-abducted-zebrafish/EXECUTED-RUN.md) |
| `memdump` | Unattributed 512 MB raw memory dump (file dated 2014) — **provenance: unverified**. | 513M | `memdump.mem` raw memory | No | [Recorded run + reports](../../case-activation/runs/memdump-raw-2014/EXECUTED-RUN.md) |
| `cfreds-fresh` | **NIST CFReDS "Hacking Case"** (fresh re-download, chain-of-custody `CHAIN.md` present). Obtain from NIST CFReDS portal. | 1.1G | `4Dell-Latitude-CPi.E01/.E02` + corrupt-set backup | No | [Activation guide](../../case-activation/cfreds-hacking-case-4dell.md) |
| `cfreds-fresh1` | NIST CFReDS Hacking Case — incomplete duplicate (E01 only, missing `.E02`). | 641M | Single E01 segment | No | — (duplicate of `cfreds-fresh`) |
| `AMF_MemorySamples` | **Volatility Foundation OpenCourseWare / "Art of Memory Forensics" samples** — verified via shipped `COURSE_LICENSE_TERMS.txt` + `CC-BY-NC-SA-3.0.txt` (**CC-BY-NC-SA 3.0**, non-commercial training corpus). | 13G | 9 Windows + 6 Linux + 4 Mac raw memory dumps | No | [Recorded run (Windows sample001) + reports](../../case-activation/runs/amf-win-sample001/EXECUTED-RUN.md) |
| `Challenge_NotchItUp` | CTF "Notch It Up" memory challenge (2019) — **provenance: unverified** (no readme/solution ships with the image). | 1.5G | `Challenge.raw` 1.6 GB Windows memory image (`file(1)` magic misreports as ETL) | No | [Recorded run + reports](../../case-activation/runs/challenge-notchitup/EXECUTED-RUN.md) |
| `contact_me` | Unattributed CTF memory challenge — **provenance: unverified**. | 1.1G | 1 GiB raw memory image (no extension, `file` = data) | No | [Recorded run + reports](../../case-activation/runs/contact-me-memory/EXECUTED-RUN.md) |
| `Sierra_10.12.6_16G23a` | Volatility macOS Sierra kernel symbols/vtypes — tooling support, **not evidence**. | 4.5M | `kernel.symbol.dsymutil`, `kernel.vtypes` | No | — (skipped: analysis-support files) |
| `auto` | Agentropix-SIFT correlation proof-run **output** over SRL-2018 — generated, **not raw evidence**. | 5.7M | JSON tool outputs (process tree, timeline, IOC pivot) + reports | No | — (is itself agent output) |
| `security data` | Byte-identical duplicate of `study case` (Jimmy Wilson exam). | 296M | Same E01 + exam PDF/md | No | — (duplicate) |
| `study case` | "2020 Jimmy Wilson" forensic-exam case study (training/exam material) — **provenance: unverified** beyond the shipped exam PDF. | 296M | `2020JimmyWilson.E01` (310 MB) + case-study PDF + exam md | No | [Full engine triage run — sealed `report.json`, 129 findings / 86 tool calls](../../case-activation/runs/jimmy-wilson-poc/EXECUTED-RUN.md) |
| `win-xp-laptop-2005-06-25.img` | **Volatility Foundation public Windows XP laptop memory sample (2005)** — well-known public training image. | 512M | Single 512 MB raw memory dump | No | [Activation guide](../../case-activation/win-xp-laptop-2005.md) |
| `yara-rules` | Local YARA rules — tooling, **not evidence**. | 12K | Rules dir | No | — (skipped) |

Sampled `file(1)` verification: the Hacking Case E01 → EWF/EnCase image; `SCHARDT.001` → DOS/MBR boot
sector with XP partition table (raw dd); `Challenge.raw` → Windows ETL magic (actually a RAM dump);
`memdump.mem`, `contact_me`, the XP laptop `.img`, and AMF `sample001.bin` → raw `data` (memory dumps).

## 2. Network captures — the honest story

> **Full proof package:** [`network-evidence-verification/`](network-evidence-verification/) —
> verified inventory, raw `file(1)`/`xxd`/SHA-256 capture for all 11 pcaps, and the claim-by-claim
> reconciliation table. Includes the methodology post-mortem on why an extension-only search
> initially (and wrongly) reported zero acquired captures — a self-caught, documented correction.

**The corpus does contain acquired network captures — five of them — plus six carved-from-disk
pcaps.** A magic-byte sweep (matching the pcap signature `d4 c3 b2 a1`, not just file extensions) of
every `/cases` path and the extraction working dirs found **11 pcap-magic files** total. An earlier
extension-only `find … -iname "*.pcap*"` missed the acquired captures because three of them are
named `*.log` and the other two surface only inside an extracted disk tree.

### 2a. Acquired captures (5)

These are **real wire captures** — primary evidence, not derived artifacts. All confirmed via
`file(1)` and `xxd` (pcap magic `d4 c3 b2 a1`).

| Acquired pcap | Size | `file(1)` magic | Provenance |
|---|---|---|---|
| `/cases/nist5/DFRWS2005-RODEO/rhino.log` | ~3.0 MB (3,187,907 B) | pcap v2.4, Ethernet, μs ts, snaplen 65000 | DFRWS 2005 Rodeo scenario capture, mislabeled `.log` |
| `/cases/nist5/DFRWS2005-RODEO/rhino2.log` | ~286 KB (292,604 B) | pcap v2.4, Ethernet, μs ts, snaplen 65000 | DFRWS 2005 Rodeo scenario capture, `.log` name |
| `/cases/nist5/DFRWS2005-RODEO/rhino3.log` | ~221 KB (226,094 B) | pcap v2.4, Ethernet, μs ts, snaplen 65000 | DFRWS 2005 Rodeo scenario capture, `.log` name |
| `testpcap.pcap` (Vanko disk) | ~144 KB (147,899 B) | pcap v2.4, 802.11 + radiotap, μs ts, snaplen 65535 | Wi-Fi capture residing **on** the Vanko suspect disk image (`/cases/vanko` `surface_physical.E01`); surfaces under the extraction working dir, no loose copy under `/cases` |
| `starbucks pcap.pcap` (Vanko disk) | ~191 KB (195,688 B) | pcap v2.4, 802.11 + radiotap, μs ts, snaplen 65535 | Wi-Fi capture from the Vanko suspect disk image; same extraction provenance |

So the three DFRWS `rhino*.log` files are scenario network traffic, and the two Vanko Wi-Fi captures
are evidence that *resided on* a suspect disk — not captured by the lab. None of the **primary
SRL-2015 / SRL-2018 / NIST disk-image cases** ship acquired captures of their own.

### 2b. Carved-from-disk pcaps (6)

Six small `packets.pcap` files were **carved by `bulk_extractor` from disk and memory evidence**
during analysis runs. These are *derived artifacts* (network fragments recovered from disk/RAM
residue), **not** wire captures, and they live in ephemeral analysis working directories — they
should be regenerated deterministically (re-run `bulk_extractor` over the same image) rather than
treated as primary evidence:

| Carved pcap | Size | Derived from (bulk_extractor input) |
|---|---|---|
| SRL-2015 controller run | 34 KB | SRL-2015 win2008R2 controller C-drive E01 |
| SRL-2018 run | 62 KB | SRL-2018 evidence |
| Hacking Case run 1 (`case-A`) | 295 KB | NIST CFReDS Hacking Case disk |
| Hacking Case run 3 | 295 KB | Same disk — identical size to run 1 (deterministic) |
| Validation re-run | 295 KB | Same disk — matches runs 1/3 |
| Ad-hoc bulk run (2026-06-08) | 943 KB | Ad-hoc `bulk_extractor` run |

All six verified via `file(1)`: *pcap capture file v2.4, Ethernet, microsecond timestamps*. The
three identical-size (301,634 B) Hacking Case carves are themselves a small reproducibility data
point: the same image yields the same carved capture across independent runs.

### 2c. Capability boundary — the SIFT tool chain does not parse pcap

The acquired captures exist in the corpus, but **the Agentropix SIFT tool chain does not parse
pcap.** No finding in any case report is derived from packet analysis. Network visibility in
Agentropix findings comes entirely from **disk and memory artifacts**: EVTX network events
(logon `4624` / explicit-credential `4648`, firewall, share events), SRUM network-usage tables
(per-app byte counters), the registry, and memory `netscan` (Volatility) for memory-resident socket
data — plus the `nist2` CSV telemetry. So any statement about "network analysis" refers to those
disk/memory-derived sources, **not** to packet-capture analysis of the acquired `rhino*.log` or
Vanko `.pcap` files (those remain out of scope for the SIFT disk/memory chain; register for custody
if needed, analyze with a separate pcap workflow).

## 3. What this inventory does and does not substantiate

Backed **by this page** (verifiable corpus composition):

- **11 disk E01s across SRL-2015 + SRL-2018** — 4 (`SRL-2015`) + 7 (`SRL-2018` `base-*-cdrive`). ✔
- **Memory dumps across SRL-2015 + SRL-2018: 26** — 4 (`SRL-2015` raw `.001`) + 22 (`SRL-2018` `.img`).
  ⚠ Note: [dataset-recall.md](../07-sdlc-ops/dataset-recall.md) says "25 memory dumps"; the live
  inventory counts **26**. The discrepancy (likely the `base-wkstn-01-mem.img` second capture or a
  snapshot image counted differently) should be reconciled in that page.
- **Acquired network captures: 5** (§2a) — three DFRWS `rhino*.log` scenario pcaps + two Vanko
  Wi-Fi `.pcap` files that resided on a suspect disk. The SIFT tool chain does **not** parse pcap,
  so no finding derives from them; this constrains how "cross-modal" / "network analysis" claims may
  be read (network visibility comes from EVTX/SRUM/registry/memory `netscan`, not packets).

**Not** substantiated here (still requires committed run artifacts — see the recall pages' own caveats):

- The **3,710 findings** and **~1,069 inferred IOCs** figures (counted outputs of analysis runs, not
  corpus properties).
- The **72/72 tactic-hit**, **108/118 memory**, **107/107 per-IOC memory**, and **83/83 cross-modal**
  recall slices. The only recall slice with a committed artifact is the
  **49/49 disk per-IOC re-score** — see
  [recall-ground-truth/run-summary-FULL-CASE-20260505T004738Z.md](recall-ground-truth/run-summary-FULL-CASE-20260505T004738Z.md).
- The **29 ground-truth YAML** count (4 of 29 committed — see
  [recall-ground-truth/README.md](recall-ground-truth/README.md)).

## 4. Reproducing the corpus

1. **SANS scenarios** (SRL-2015, SRL-2018, VANKO/FOR500): distributed with SANS FOR508/FOR500 course
   media — obtain through SANS.
2. **NIST CFReDS** (Hacking Case, TechHive): download from the NIST CFReDS portal; verify against the
   shipped hash manifests.
3. **MemLabs**: stuxnet999/MemLabs on GitHub.
4. **DFRWS 2005 Rodeo**: DFRWS challenge archives.
5. **Volatility Foundation samples** (AMF corpus, XP laptop 2005): Volatility Foundation
   OpenCourseWare — respect the CC-BY-NC-SA 3.0 license.
6. **Carved pcaps**: re-derive with `bulk_extractor -o <outdir> <image>`; the `packets.pcap` output is
   deterministic for a given image (§2).

CTF/unattributed images (`memdump`, `contact_me`, Notch It Up, Jimmy Wilson, ROCBA) have no verified
public source; treat results on them as illustrative, not benchmark evidence.
