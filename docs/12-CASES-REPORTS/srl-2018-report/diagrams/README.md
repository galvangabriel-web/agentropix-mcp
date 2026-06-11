# SRL-2018 — report diagrams

The five rendered diagrams embedded by [`../SRL-2018-FORENSIC-REPORT.md`](../SRL-2018-FORENSIC-REPORT.md)
(case `SRL-2018-COMPROMISED-ENTERPRISE` — Stark Research Labs intrusion, 2018‑08‑16 → 09‑05 UTC).
Each PNG is a pre-rendered Mermaid diagram so the report displays without client-side JavaScript.

> All host names, accounts and RFC1918 addresses visible in these diagrams come from the
> **SRL-2018 training evidence set** (the fictional `shieldbase.lan` estate), not from any live network.
> Per publication policy, the external attacker source pair is shown below as
> `<ATTACKER-IP-1>/<ATTACKER-IP-2>`; the literal values appear in the rendered PNGs and in the
> report's IOC table ([`../SRL-2018-FORENSIC-REPORT.md`](../SRL-2018-FORENSIC-REPORT.md)).

| File | Type | Size | What it is |
|---|---|---|---|
| `d1.png` | PNG 586×1416 | 103 KB | Attack-lifecycle flowchart — the 8 MITRE ATT&CK phases, Initial Access → Objective |
| `d2.png` | PNG 784×836 | 72 KB | Lateral-movement & C2 architecture graph — implanted hosts, pivot hub, beacons, exfil path |
| `d3.png` | PNG 784×246 | 29 KB | Campaign timeline 2018‑08‑16 → 09‑05 (7 dated milestones, UTC) |
| `d4.png` | PNG 784×413 | 40 KB | IOC mindmap — Accounts / C2 / Files / Hosts branches |
| `d5.png` | PNG 784×127 | 16 KB | Findings approval flow — DRAFT → examiner-signed APPROVED → report |

## d1.png — attack lifecycle (MITRE ATT&CK)

Vertical flowchart; node text (transcribed):

```text
Initial Access (T1133)  nfury RDP from EXTERNAL <ATTACKER-IP-1>/<ATTACKER-IP-2> → BASE-WKSTN-05 · Aug 17
  ↓
Execution / C2          Metasploit p.exe + PowerShell Empire
  ↓                                         ↘ (dashed)
Persistence (T1543.003) perfmonsvc64.exe     Defense Evasion  csrss.exe timestomp (T1070.006)
  'Perf Monitor' service + PsExec (T1569.002)  UPX pack · AMSI bypass · secure-delete
  ↓
Credential Access       T1110 brute-force tdungan (692 fails → ok) · T1003.002 SAM from DC VSS
  ↓
Lateral Movement        WinRM 5985 / RDP / SMB · RD-01 ⇄ FILE hub (spsql, rsydow-a admin)
  ↓
Collection (T1560/T1005) Rar.exe + 7za.exe — nfury 'Carbonadium' project
  ↓
Exfiltration            DMZ-FTP (C$ staging)
  ↓
OBJECTIVE               IP theft: Carbonadium
```

Full image: [d1.png](d1.png)

## d2.png — lateral-movement & C2 architecture

Node/edge graph; key elements (transcribed):

```text
EXTERNAL <ATTACKER-IP-1>/<ATTACKER-IP-2> + DESKTOP-NBTIQJ9  --RDP nfury-->  BASE-RD-01 172.16.6.11 (implant + pivot hub)
BASE-DC 172.16.4.4  ··· "SAM via VSS stolen" ···>  (credential theft edge)

[ p.exe / Empire implanted hosts ]
  BASE-RD-01 172.16.6.11 (implant + pivot hub)   BASE-FILE 172.16.4.5 (implant + collection)
  BASE-WKSTN-05 (foothold)                       BASE-WKSTN-01

BASE-FILE   --SMB C$-->        DMZ-FTP (exfil)
BASE-FILE   --rubyw STOMP-->   10.10.254.1:61613
WKSTN-05 / WKSTN-01 / RD-01  ··beacon··>  Internal C2 hub 172.16.4.10:8080
BASE-RD-01  --RDP spsql-->     BASE-RD-02
BASE-RD-01  ··DNS tunnel··>    Empire C2 squirreldirectory.com
RD-05 / RD-06  --net-->        BASE-RD-01
```

Full image: [d2.png](d2.png) — the report adds a caveat that the `BASE-HUNT/HUNT-02/HUNT-03/BASE-ADMIN`
IR hosts are defenders, **not** attacker activity.

## d3.png — campaign timeline (UTC)

```text
SRL-2018 campaign 2018-08-16 → 09-05
2018-08-16    Early recon (172.16.5.26 → dmz-ftp, DC → wkstn-05)
2018-08-17    EXTERNAL RDP <ATTACKER-IP-1>/<ATTACKER-IP-2> → wkstn-05 (nfury) — initial access
2018-08-23..31 Internal staging into wkstn-05 : PowerShell Empire stagers (squirreldirectory.com)
2018-08-31    perfmonsvc64.exe service persistence installed (wkstn-05) ·
              SAM stolen from DC VSS (@GMT-2018.08.31)
2018-09-04    PsExec → dmz-ftp (PSEXESVC)
2018-09-05    Spread (RD-01 → rd-02, → rd-01) · FILE → dmz-ftp C$ (exfil staging)
2018-09-06/07 Memory + disk acquisition (dc3dd / FTK Imager, F-Response)
```

Full image: [d3.png](d3.png)

## d4.png — IOC mindmap

```text
SRL-2018 IOCs
├── Accounts: patient-zero · brute-forced · lateral · admin abuse
├── C2
│   ├── Metasploit: "\\.\pipe\MSSE--server" · internal hub 172.16.4.10:8080 · STOMP
│   └── Empire: /a, /download/n.ps1 · http://127.0.0.1:/ agents · Install-Persistence
├── Files: msadvapi2 · p.exe, csrss.exe, b.log, PerfSvc.exe, n.ps1
└── Hosts: attacker box · EXTERNAL <ATTACKER-IP-1>/<ATTACKER-IP-2>
```

Full image: [d4.png](d4.png)

## d5.png — findings approval flow

```text
[ DRAFT: 10 findings staged, HMAC-SHA256 sealed ]
   --examiner victor.galvan · DRAFT → APPROVED-->
[ APPROVED: 10 findings signed, hash-chained ]  -->  [ APPROVED-only report ]
```

Full image: [d5.png](d5.png)
