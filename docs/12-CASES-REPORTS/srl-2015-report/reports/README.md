# reports/ — human-readable case reports

The narrative deliverables for SRL-2015, in both a full technical and an executive form, each as
HTML (browser-viewable) and PDF (portable/print).

| File | Audience | Pages | Notes |
|---|---|---|---|
| `SRL-2015-full-report.pdf` | analyst / examiner | 12 | complete: 4 hosts, all findings + MITRE, IOC table w/ VT/OTX verdicts, the 12 malicious, Wazuh push status, embedded screenshots |
| `SRL-2015-full-report.html` | analyst / examiner | — | same content, browser-rendered (re-rendered from the IP-scrubbed source) |
| `SRL-2015-executive-summary.pdf` | decision-maker | 4 | case summary, key findings, the 12 malicious IOCs, verdict, recommended actions |
| `SRL-2015-executive-summary.html` | decision-maker | — | browser-rendered executive form |

## What the reports cover (headline numbers)
- **4 hosts** processed (nromanoff, tdungan, nfury, win2008R2-controller) → **2,233 findings**;
  **2,874** indexed live to Wazuh.
- **12 malicious IOCs** (10 file-hash + 1 IP + 1 domain), 21 malware samples recovered.
- Threat-intel: VirusTotal + OTX verdicts on 67 distinct IOCs.

## How to read
Start with the **executive summary** for the verdict and headline IOCs; drop into the **full report**
for per-host detail and the MITRE mapping. The structured data behind the prose lives in
[`../exports/`](../exports/) (IOCs/STIX/EAR); the deep malware RE is in
[`../deep-analysis/`](../deep-analysis/); the sample catalogue is in
[`../quarantine/`](../quarantine/); a walkthrough video is in [`../video/`](../video/).

## Provenance
Numbers in these reports are reconciled against the live Wazuh indices and the structured exports;
the full evidence→finding→IOC→verdict chain is in the [case provenance map](../README.md).
Related cases: [SRL-2018](../../srl-2018-report/) · [VANKO](../../vanko-report/).
