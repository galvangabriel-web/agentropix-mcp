# SRL-2015-APT-ENTERPRISE — Deliverable Index

**Case:** SRL-2015-APT-ENTERPRISE
**Generated:** 2026-06-10 (real Agentropix-SIFT pipeline run)
**Evidence cluster:** `https://<WAZUH-INDEXER>:9200` (index `agentropix-iocs-*`, `case_id=SRL-2015-APT-ENTERPRISE`)
**Source artifacts:** `Reports_results/SRL2015-PIPELINE-V2/` (per-host `disk.json`/`memory.json`, `enrichment/ti-report.json`, `screenshots-reconcile/*.png`)

---

## Headline numbers

| Metric | Value | Source |
|---|---|---|
| Raw findings | **2,233** | full/executive report (case pipeline) |
| Evidence docs live on Wazuh | **~2,874** | full/executive report |
| Approved findings (report snapshot) | 17 (14 high, 2 medium, 1 critical) | `exec_report.json` |
| Total IOCs exported | **91** | `exports/iocs.json` |
| **Malicious IOCs** | **12** | `exports/iocs.json` tally (clean 37, unknown 42, suspicious 0) |
| Executable inventory (EAR) | 17 entries, **1 suspect** (`femc.exe`) | `exports/ear.json` |
| **Carved binaries quarantined** | **21 file copies (16 disk + 5 memory) / 9 distinct malicious hashes** | `quarantine/MANIFEST.csv` (all verified Y, 0 mismatches) |
| STIX bundle objects | 92 | `exports/iocs-stix.json` |

The 4 distinct carved hashes: `usboesrv.exe` (USB-over-Ethernet trojan, controller x2),
`a.exe` (dropper, x6), `spinlock.exe` (System32 implant, x3),
`svchost.exe` (masquerading svchost, x3).
**Memory-injection payloads (T1055, malfind).** Five of the TI-only malicious hashes are 8192-byte
in-RAM injected code regions (no on-disk file) recovered with Volatility 3 `windows.malfind` from the
`*-memory-raw.001` dumps: four from the `win2008R2-controller` dump (pids 23476, 26340, 145896, and
151132 — the latter the `femc.exe` process, EAR's single suspect) and one from `win7-64-nfury`
(pid 328). Each region's SHA-256 was re-computed after dump and matched its expected IOC hash
(`verified=Y`, entries 17–21 in `quarantine/MANIFEST.csv`). The remaining on-disk TI hashes were
carved from the E01 images; nothing is fabricated (see `quarantine/README.txt`).

---

## Files

### `reports/`
- **`SRL-2015-full-report.pdf`** — complete forensic report: per-host findings, timeline, IOC table,
  MITRE ATT&CK mapping, Wazuh reconciliation, methodology.
- **`SRL-2015-executive-summary.pdf`** — condensed leadership summary: scope, headline counts,
  malicious IOCs, recommended actions.

### `exports/`
- **`iocs.csv`** / **`iocs.json`** — 91 IOCs with verdicts (12 malicious). JSON carries case metadata,
  ES source index, and per-verdict tally.
- **`iocs-stix.json`** — STIX 2.x bundle (92 objects) for SIEM/TIP ingestion.
- **`ear.csv`** / **`ear.json`** — Executable Attribution Report: 17 executables, 1 flagged suspect
  (`femc.exe`, controller RAM malfind payload). Derived from per-host disk/memory findings.

### `quarantine/`
- **`srl2015-samples.zip`** — password-protected archive of all 21 carved malware samples
  (16 disk-carved + 5 memory malfind payloads, mode 0600).
  **ARCHIVE PASSWORD: `infected`** (industry-standard malware-sharing password). LIVE MALWARE —
  open only in an isolated, network-less analysis VM.
- **`MANIFEST.csv`** — one row per carved sample: in-zip name, original on-disk path, host,
  expected IOC hash, re-computed carved SHA-256, verified flag, size.
- **`README.txt`** — handling warnings, password note, carve provenance (read-only ewfmount of
  per-host `*-c-drive.E01`), and the documented list of not-carved memory-resident targets.

---

## Provenance

This deliverable is the output of a real 2026-06-10 Agentropix-SIFT run against the live evidence
cluster `https://<WAZUH-INDEXER>:9200`. IOC verdicts come from the case's threat-intelligence enrichment;
carved samples were copied (copy-only, no execution) from read-only NTFS mounts of the per-host E01
disk images, and every carved SHA-256 was re-verified against its expected IOC hash (all `verified=Y`).

---

## Integrity — SHA-256

```
781663b86fdcf8208ba0c48914e185fcc96f397f29b78340450c4e6b3ff02433  reports/SRL-2015-full-report.pdf
43f461d66ac168bda59a45ef1028487fef4b089a75dfcdd46eef69b161961019  reports/SRL-2015-executive-summary.pdf
155b2a83e1ef64e9b26df66a421b12d5a4d3ff1c6656dcfcc6a88845cefaf2d7  exports/iocs.csv
1bafbce22a986ae00df735cba6752763ec1a2c6faaaff4b8a1d616a24f459eb8  exports/iocs.json
0c7fcb74b296d3ba5907f9338e28d396a9bf178d8f97e7720f0e3e77c97b8f55  exports/iocs-stix.json
6b95785d819951db5ff82439b13bcb07c5e803854fd0bdf6f7673515330c5ebd  exports/ear.csv
b06a917e7968a708db88e70bbe02f69d2b959a4f250f568aedd93e2470e8b57c  exports/ear.json
7c4e6dd1a01e713adc6768eadcb73c9976057ebc1514c007bb3be815e9e371d0  quarantine/srl2015-samples.zip
a00ef77360fe2b3ce6fcb536cce1e76904b82fe10c3337c8df46ca15cb673c0c  quarantine/MANIFEST.csv
aebb1d195db3e86c53bfe5b7a6feb056a4bfa8573b4d8ba12c2463007fe2fa64  quarantine/README.txt
```
