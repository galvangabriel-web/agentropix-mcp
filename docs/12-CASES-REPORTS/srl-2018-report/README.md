# SRL-2018 — network-wide APT / C2 deployment (case report)

SANS-derived multi-host APT scenario: initial access → credential theft → lateral movement →
Cobalt Strike / Empire C2 → collection & exfiltration across a segmented enterprise (incl. a DMZ).
This folder is the evaluator-facing case report for SRL-2018.

## How to read this case
1. **[SRL-2018-FORENSIC-REPORT.md](SRL-2018-FORENSIC-REPORT.md)** — the narrative: what happened,
   per-host, mapped to MITRE ATT&CK.
2. **[TECHNICAL-APPENDIX.md](TECHNICAL-APPENDIX.md)** — the supporting detail (artifacts, queries,
   evidence references).
3. **[WAZUH-IOC-GALLERY.md](WAZUH-IOC-GALLERY.md)** — the indicators and how they surface in Wazuh.

## Folder map
| Path | Contents |
|---|---|
| [`diagrams/`](diagrams/) | attack-chain / topology diagrams (Mermaid sources + rendered) |
| [`wazuh/`](wazuh/) | dashboard evidence gallery — screenshot proof findings/IOCs are indexed (see its [README](wazuh/README.md)) |
| `training-session-paged.mp4` | recorded analyst walkthrough of the case |
| `training-session-poster.png` | poster frame for the video (GitHub can't inline-play repo MP4s — ▶ open the file to download) |

## Indicators & infrastructure
SRL-2018 evidence references scenario addresses (`192.168.30.x`, `172.16.x`) and APT tooling
(Cobalt Strike, Empire). These are **case IOCs**, not lab infrastructure.

## Provenance
Findings/IOCs were indexed to the live Wazuh cluster; the dashboard gallery in
[`wazuh/`](wazuh/) is the visual proof, cross-referenced from the report + appendix.

## Related cases (correlate)
- [SRL-2015 — multi-host APT (Stark Research Labs)](../srl-2015-report/)
- [VANKO — insider exfiltration](../vanko-report/)
- [↑ all cases index](../README.md)
