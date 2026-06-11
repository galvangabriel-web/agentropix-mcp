# wazuh/ — Wazuh dashboard evidence gallery (SRL-2018)

Screenshot proof that the SRL-2018 findings and IOCs were indexed into the live Wazuh/OpenSearch
dashboard, one capture per major detection plus the CDB IOC lists. These are the visual chain-of-
custody for "the findings are actually in the SIEM".

| File | What it proves |
|---|---|
| `00-login.png` | authenticated dashboard session (access proof) |
| `01-overview-all-findings.png` | all SRL-2018 findings indexed (overview / counts) |
| `02-srl2018-c2-implant-001.png` | C2 implant detection |
| `03-srl2018-empire-c2-002.png` | Empire C2 channel |
| `04-srl2018-initial-access-003.png` | initial access |
| `05-srl2018-credtheft-sam-004.png` | credential theft (SAM) |
| `06-srl2018-bruteforce-005.png` | brute-force activity |
| `07-srl2018-persistence-006.png` | persistence mechanism |
| `08-srl2018-lateral-007.png` | lateral movement |
| `09-srl2018-timestomp-008.png` | timestomping / anti-forensics |
| `10-srl2018-psexec-dmz-009.png` | PsExec execution into the DMZ |
| `11-srl2018-collection-exfil-010.png` | collection & exfiltration |
| `12-wazuh-cdb-ioc-lists.png` | IOCs published to Wazuh CDB lists |

## How to read
Each numbered capture maps to a finding/technique in the
[forensic report](../SRL-2018-FORENSIC-REPORT.md) and
[technical appendix](../TECHNICAL-APPENDIX.md); the IOC-list view (`12-…`) corresponds to the
indicators in [`../WAZUH-IOC-GALLERY.md`](../WAZUH-IOC-GALLERY.md). The attack chain these captures
walk through is drawn in [`../diagrams/`](../diagrams/).

> Note: dashboard captures show **SRL-2018 scenario** host addresses (e.g. `192.168.30.x`,
> `172.16.x`) — these are case evidence/IOCs, not lab infrastructure.

Related cases: [SRL-2015](../../srl-2015-report/) · [VANKO](../../vanko-report/).
