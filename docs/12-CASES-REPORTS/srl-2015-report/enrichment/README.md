# SRL-2015 — threat-intel enrichment (raw TI report)

> The raw VirusTotal + OTX enrichment report the pipeline produced over the SRL-2015 IOC set.
> It is the **upstream source** of the published [`../exports/iocs.json`](../exports/iocs.json) /
> `iocs.csv` / `iocs-stix.json` derivatives. Published here so the IOC verdicts are traceable to
> the raw enrichment.

## File

| File | What it is |
|---|---|
| [`ti-report.json`](ti-report.json) | Per-IOC VirusTotal/OTX verdicts, scores, providers, and the enrichment tool's own notes (including which private RFC1918 IPs it deliberately did **not** egress) |

Verdict tally (verdict field): **12 malicious / 37 clean** + unknowns — the 12 malicious match the
case headline and the `verdict=malicious` rows in [`../exports/iocs.json`](../exports/iocs.json).

## Sanitization

Two infrastructure identifiers were replaced with placeholders (the **only** edits; matches the
case-wide convention in [`../README.md`](../README.md) §3.4):

| Original (withheld) | Published placeholder |
|---|---|
| the Wazuh indexer endpoint `https://<ip>:9200` | `https://<WAZUH-INDEXER>:9200` |
| the absolute local pipeline working-set path | `<PIPELINE-WORKSET>` |

Everything else is unmodified, including the **forensic** IP indicators (attacker C2 and the
fictional SHIELD/Stark `10.3.58.x` network) — those are evidence and are meant to be public. The
`private_rfc1918_ips_not_egressed` list is the TI tool's honest record of case-data IPs it withheld
from VirusTotal/OTX for privacy; it is evidence-side, not analysis infrastructure.
