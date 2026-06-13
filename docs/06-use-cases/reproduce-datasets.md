# Reproduce: get the evidence datasets

> **Who this page is for:** judges, reviewers, and practitioners who want to **acquire the same
> evidence images** the Agentropix-SIFT cases use and re-run the pipeline themselves.
> For each **publicly available** dataset it gives the real upstream download location, the
> provenance recorded in the matching [Case Activation Guide](../../case-activation/INDEX.md),
> and an integrity anchor you can check after download. Datasets that **cannot be redistributed**
> (SANS course media, private hackathon evidence) are listed honestly as operator-host-only.

## How to read this page

- **Every URL below was verified live (HTTP 200) on 2026-06-10.** Only verified landing /
  archive pages are cited — no guessed deep links. If an upstream page moves, the dataset
  name + publisher is enough to re-find it.
- **Integrity anchors are upstream-published or acquisition-embedded values** (EWF stored
  MD5s, challenge-README MD5s, published answer keys) — they let you confirm your download
  matches the evidence the activation guides were written against.
- **Local paths** are shown as the `/cases/*` slugs used throughout the portal (e.g. in
  [case-runbook-srl-2018.md](case-runbook-srl-2018.md)). On your own host, put the images
  wherever your MCP allowlist points and adjust the `evidence_register` path accordingly.
- Per-case activation procedure (the 8-step `case_init → … → report` sequence with that
  case's real values) lives in [`case-activation/INDEX.md`](../../case-activation/INDEX.md).

---

## 1 · Publicly downloadable datasets

### 1.1 CFReDS "Hacking Case" (Greg Schardt / "Mr. Evil") — NIST

| Field | Value |
|---|---|
| Publisher | NIST — Computer Forensic Reference Data Sets (CFReDS) |
| Landing page | <https://cfreds.nist.gov/all/NIST/HackingCase> |
| Download page (archive host) | <https://cfreds-archive.nist.gov/Hacking_Case.html> — hosts `images/4Dell Latitude CPi.E01`/`.E02`, the raw split `images/hacking-dd/SCHARDT.001`–`.008`, and `images/TestAnswers.pdf` |
| What it is | Windows XP disk image (Dell Latitude CPi) — hacking-tools / insider-misuse training scenario, acquired 2004 |
| Local case | `/cases/cfreds-fresh/4Dell-Latitude-CPi.E01`+`.E02` → guide [cfreds-hacking-case-4dell.md](../../case-activation/cfreds-hacking-case-4dell.md) |
| Integrity anchor | EWF stored MD5 == computed MD5 == `aee4fcd9301c03b3b054623ca261959a` (verified locally with `ewfverify`; recorded in the activation guide). **Upstream publishes only E01+E02** — E03–E08 return 404; the same disk is also available as the SCHARDT.001–.008 raw split-dd. |
| License | NIST public reference data |
| Backs | The CFReDS activation guide and its example run; the disk-triage use case family |

### 1.2 DFRWS 2005 Forensics Rodeo (RHINOUSB) — NIST CFReDS hosting

| Field | Value |
|---|---|
| Publisher | DFRWS (2005 Forensics Rodeo), hosted by NIST CFReDS as "Rhino Hunt" |
| Landing page | <https://cfreds.nist.gov/all/NIST/RhinoHunt> |
| Download page (archive host) | <https://cfreds-archive.nist.gov/dfrws/Rhino_Hunt.html> — evidence links are `DFRWS2005-RODEO.zip` and `DFRWS2005-answers.pdf` |
| What it is | Seized FAT16 USB thumb-drive image (`RHINOUSB.dd`, raw dd, 259,506,176 bytes, no partition table) plus scenario pcaps and the published 34-page answer key |
| Local case | `/cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd` → guide [dfrws-2005-rodeo-usb.md](../../case-activation/dfrws-2005-rodeo-usb.md) |
| Integrity anchor | The published answer key `DFRWS2005-answers.pdf` is the scenario ground truth; image size 259,506,176 bytes matches the local copy. |
| License | Public challenge data (DFRWS / NIST hosting) |
| Backs | The Rodeo activation guide (partitionless-FAT16 `fls` offset-0 path) |

> **Disambiguation (avoid a wrong download):** `dfrws.org/forensic-challenges/` is the
> original publisher but blocks automated fetches (Cloudflare 403) — cite it as secondary.
> The GitHub repo `dfrws/dfrws2005-challenge` is the **separate DFRWS 2005 *memory*
> challenge** ("Professor Goatboy"), **not** the Rodeo USB dataset.

### 1.3 MemLabs CTF memory dumps — stuxnet999

| Field | Value |
|---|---|
| Publisher | *stuxnet999* — MemLabs (six Windows memory-forensics CTF labs) |
| Landing page | <https://github.com/stuxnet999/MemLabs> |
| Download links | Each `Lab N/README.md` in the repo carries that lab's **challenge-file download link and the dump MD5** — use the per-lab README links verbatim (they point to external file hosting; not reproduced here so they can't drift). |
| What it is | Six independent Windows raw memory dumps (`MemoryDump_Lab1..6.raw`, ~1.0–1.5 GiB each), one scenario per lab |
| Local case | `/cases/nist4/MemLabs-Lab1..6/` → guide [memlabs-dumps.md](../../case-activation/memlabs-dumps.md) |
| Integrity anchor | Per-lab MD5s in the upstream READMEs. Cross-checked: Lab 1 README dump MD5 `b9fec1a443907d870cb32b048bda9380` matches the local copy verbatim (activation guide, evidence-register step). |
| License | Public CTF challenge (see upstream repo) |
| Backs | The MemLabs activation guide (Volatility memory chain, one case per lab) |

### 1.4 AMF memory samples — *The Art of Memory Forensics* corpus

| Field | Value |
|---|---|
| Publisher | Volatility Foundation — *The Art of Memory Forensics* OpenCourseWare |
| Landing page | <https://memoryanalysis.net/amf> — links the downloads host (`downloads.artofmemoryforensics.com`), including the corpus license files `COURSE_LICENSE_TERMS.txt` and `CC-BY-NC-SA-3.0.txt` |
| Secondary index | <https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples> |
| What it is | 9 Windows + 6 Linux + 4 Mac raw RAM captures (`.bin`, ~13 GB total) used to teach Volatility |
| Local case | `/cases/AMF_MemorySamples/` → guide [amf-memory-samples.md](../../case-activation/amf-memory-samples.md) |
| Integrity anchor | The same two license files published upstream are present in the local corpus (recorded in the activation guide) — sample-level verification is via your own `evidence_register` SHA-256 at registration time (raw `.bin`, no EWF hash to compare). |
| License | **CC-BY-NC-SA 3.0** (Volatility Foundation OpenCourseWare) — training use, **non-commercial** |
| Backs | The AMF activation guide and the recorded `amf-win-sample001` run ([transcript](../../case-activation/runs/amf-win-sample001/EXECUTED-RUN.md)) |

---

## 2 · Not publicly redistributable (operator-host-only)

These cases are real and fully documented in the activation guides, but **no download link
can be provided** — the evidence is licensed course media or private case data. Stating this
plainly is part of the portal's honest-negatives discipline.

| Case | Provenance (from the activation guide) | Why it cannot be linked |
|---|---|---|
| **SRL-2015** | SANS FOR508 — "Stark Research Labs Data Breach Intrusion" (every E01's `ewfinfo` case number; examiner name in the images: `SANS`) → [srl-2015-apt-enterprise.md](../../case-activation/srl-2015-apt-enterprise.md) | SANS course media, licensed to course students — not redistributable |
| **SRL-2018** | SANS FOR508-style SRL-2018 corpus, case number `20180905-001`, acquired Sept 2018 via F-Response → [srl-2018-compromised-enterprise.md](../../case-activation/srl-2018-compromised-enterprise.md) | SANS course media — not redistributable |
| **VANKO** | SANS FOR500 — "The Case of the Abducted Zebrafish" (insider IP-theft scenario) → [vanko-abducted-zebrafish.md](../../case-activation/vanko-abducted-zebrafish.md) | SANS course media — not redistributable |
| **ROCBA** | Private Hackathon 2026 evidence set (1 EWF disk + 1 raw memory image) → [rocba-hackathon-2026.md](../../case-activation/rocba-hackathon-2026.md) | Private event evidence, no public source exists |

**Consequence for reproducibility:** the headline recall corpora — **72/72 (100 %)** disk and
**108/118 (91.5 %)** memory ([canonical-facts.md](../08-reference/canonical-facts.md)) — were
measured against the SRL-2018 corpus, so they are **re-runnable only by SANS license-holders**
who hold the same course media. For everyone else, the published recall evidence is the sealed
run artifacts and methodology: see [dataset-recall.md](../07-sdlc-ops/dataset-recall.md). The
sealed case reports for SRL-2018 and VANKO are published under
[docs/12-CASES-REPORTS/](../12-CASES-REPORTS/).

---

## 3 · Provenance not yet traced (honest gap)

The remaining small CTF/training images in the corpus are documented and analyzable
([activation guides exist](../../case-activation/INDEX.md)), but their **upstream origin has
not been verified** — rather than guess URLs, they are listed here without links:

- TheTechHive — `Chad_LT.E01` ([guide](../../case-activation/techhive-chad-lt-laptop.md))
- Jimmy Wilson study case — `2020JimmyWilson.E01` ([guide](../../case-activation/jimmy-wilson-study-case.md))
- CTF "Contact Me" — raw memory dump ([guide](../../case-activation/contact-me-memory.md))
- Challenge "Notch It Up" — `Challenge.raw` ([guide](../../case-activation/challenge-notch-it-up.md))
- memdump (generic 2014 RAM image) — `memdump.mem` ([guide](../../case-activation/memdump-mem.md))
- Windows XP laptop 2005 — `win-xp-laptop-2005-06-25.img` ([guide](../../case-activation/win-xp-laptop-2005.md)) — plausibly a public memory-forensics sample, but **not verified**, so no source is claimed

If you can pin an upstream source for any of these, it belongs in this table with the same
URL + integrity-anchor treatment as §1.

---

## Related

- [`case-activation/INDEX.md`](../../case-activation/INDEX.md) — master index of all 14 activation guides + recorded runs
- [case-hypotheses.md](case-hypotheses.md) — per-case attack-chain hypotheses (what to look for once you have the image)
- [dataset-recall.md](../07-sdlc-ops/dataset-recall.md) — the recall methodology and sealed-run evidence for the non-redistributable corpora
- [canonical-facts.md](../08-reference/canonical-facts.md) — governing numbers (72 tools / 16 wrappers / 4687 tests / 72-72 / 108-118)
