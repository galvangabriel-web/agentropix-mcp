# SRL-2018 — Digital Forensic & Incident Response Report

| | |
|---|---|
| **Case ID** | `SRL-2018-COMPROMISED-ENTERPRISE` |
| **Examiner** | victor.galvan |
| **Evidence** | `/cases/SRL-2018` — 7 disk (E01) + 22 memory (raw) images, 198 GB |
| **Estate** | Stark Research Labs (`shieldbase.lan`) — DC, file, mail, RD farm, workstations, DMZ-FTP |
| **Incident window** | **2018‑08‑16 → 2018‑09‑05 UTC** |
| **Classification** | Targeted intrusion / APT — **intellectual-property theft** |
| **Status** | 10 findings **APPROVED** (examiner-signed, HMAC chain) |

> **Evaluation note.** The IP `42.112.153.164` was **operator-injected to test the system** and is **NOT** a real indicator — it has **zero evidentiary presence**. Disregard it in any tasking.

---

## 1. Executive summary

A targeted intrusion against the Stark Research Labs network, conducted with a **dual offensive
framework — Metasploit/Meterpreter + PowerShell Empire** — culminating in the **theft of the
"Carbonadium" research project** belonging to user `nfury`. The actor gained an external **RDP**
foothold on a workstation, deployed a DNS‑tunnelling implant (`p.exe`) and Empire agents across four
hosts, **stole credentials** (NTLM brute‑force + SAM‑from‑VSS), moved laterally via **WinRM/RDP/SMB**
through an **RD‑01 ⇄ FILE** hub, **collected** the target IP with `Rar`/`7‑Zip`, and **exfiltrated via
the DMZ‑FTP** server — covering tracks with a custom **timestomping** tool and thorough secure
deletion.

**The malware is fully recovered and hashed; the credential theft, lateral path, and objective are
all evidenced.**

---

## 2. Attack lifecycle (MITRE ATT&CK)

```mermaid
flowchart TD
    IA["🌐 Initial Access (T1133)<br/>nfury RDP from EXTERNAL 192.168.30.10/.11<br/>→ BASE-WKSTN-05 · Aug 17"]
    EX["⚙️ Execution / C2<br/>Metasploit p.exe + PowerShell Empire"]
    PE["🔒 Persistence (T1543.003)<br/>perfmonsvc64.exe 'Perf Monitor' service<br/>+ PsExec (T1569.002)"]
    CR["🔑 Credential Access<br/>T1110 brute-force tdungan (692 fails→ok)<br/>T1003.002 SAM from DC VSS"]
    LM["↔️ Lateral Movement<br/>WinRM 5985 / RDP / SMB · RD-01 ⇄ FILE hub<br/>(spsql, rsydow-a admin)"]
    DE["🥷 Defense Evasion<br/>csrss.exe timestomp (T1070.006)<br/>UPX pack · AMSI bypass · secure-delete"]
    CO["📦 Collection (T1560/T1005)<br/>Rar.exe + 7za.exe<br/>nfury 'Carbonadium' project"]
    EXF["⬆️ Exfiltration<br/>DMZ-FTP (C$ staging)"]
    OBJ((("🎯 OBJECTIVE<br/>IP theft:<br/>Carbonadium")))
    IA --> EX --> PE --> CR --> LM --> CO --> EXF --> OBJ
    EX -.-> DE
    LM -.-> CR
    classDef a fill:#ffc9c9,stroke:#e03131,color:#5c1a1a
    classDef b fill:#ffd8a8,stroke:#e8590c,color:#5c2e0a
    classDef o fill:#b2f2bb,stroke:#2f9e44,color:#15391f
    class IA,CR a
    class EX,PE,LM,DE,CO,EXF b
    class OBJ o
```

---

## 3. Lateral-movement & C2 architecture

```mermaid
flowchart LR
    EXT(("EXTERNAL<br/>192.168.30.10/.11<br/>+ DESKTOP-NBTIQJ9")) -->|RDP nfury| WK05["BASE-WKSTN-05<br/>(foothold)"]
    subgraph IMPLANT["p.exe / Empire implanted hosts"]
        RD01["BASE-RD-01<br/>172.16.6.11<br/>(implant + pivot hub)"]
        FILE["BASE-FILE<br/>172.16.4.5<br/>(implant + collection)"]
        WK01["BASE-WKSTN-01"]
        WK05
    end
    RD01 <-->|net/SMB| FILE
    RD01 -->|RDP spsql| RD02["BASE-RD-02"]
    RD01 -->|RDP nfury| WK05
    FILE -->|SMB C$| DMZ["DMZ-FTP<br/>(exfil)"]
    RD05["RD-05 / RD-06"] -->|net| RD01
    DC["BASE-DC<br/>172.16.4.4"] -.SAM via VSS stolen.-> FILE
    RD01 & FILE & WK01 & WK05 -. beacon .-> HUB(("Internal C2 hub<br/>172.16.4.10:8080"))
    FILE -. "rubyw STOMP" .-> MQ(("10.10.254.1:61613"))
    RD01 -. "DNS tunnel" .-> DNS(("Empire C2<br/>squirreldirectory.com"))
    classDef e fill:#ffc9c9,stroke:#e03131
    classDef i fill:#ffd8a8,stroke:#e8590c
    classDef c fill:#ffec99,stroke:#f08c00
    classDef t fill:#a5d8ff,stroke:#1971c2
    class EXT e
    class RD01,FILE,WK01,WK05 i
    class HUB,MQ,DNS c
    class DC,RD02,DMZ,RD05 t
```

> **Defenders excluded:** `BASE-HUNT / HUNT-02 / HUNT-03` (172.16.5.25/.27/.28) and `BASE-ADMIN`
> (172.16.5.26) are the **IR / threat-hunting** hosts (analyst `cbarton` = the acquisition examiner
> Clint Barton). Their fan-out logons are legitimate IR sweeps and are **not** attacker activity.

---

## 4. Timeline (UTC)

```mermaid
timeline
    title SRL-2018 campaign 2018-08-16 → 09-05
    2018-08-16 : Early recon (172.16.5.26→dmz-ftp, DC→wkstn-05)
    2018-08-17 : EXTERNAL RDP 192.168.30.10/.11 → wkstn-05 (nfury) — initial access
    2018-08-23..31 : Internal staging into wkstn-05 ; PowerShell Empire stagers (squirreldirectory.com)
    2018-08-31 : perfmonsvc64.exe service persistence installed (wkstn-05) ; SAM stolen from DC VSS (@GMT-2018.08.31)
    2018-09-04 : PsExec → dmz-ftp (PSEXESVC)
    2018-09-05 : Spread (RD-01→rd-02, →rd-01) ; FILE → dmz-ftp C$ (exfil staging)
    2018-09-06/07 : Memory + disk acquisition (dc3dd / FTK Imager, F-Response)
```

---

## 5. Recovered malware toolkit

All samples recovered, hashed, and quarantined (defanged) at `/home/admin2/srl-2018-malware-samples/`.

| File | SHA-256 | Role | ATT&CK |
|---|---|---|---|
| `p.exe` (packed) | `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c` | **Metasploit/Meterpreter** implant — DNS tunnel + `\\.\pipe\MSSE-<N>-server`; UPX | T1071.004, T1055, T1572 |
| `p.exe` (unpacked) | `d391ede758b6c769f89addb35ee9ec74eb0ae3a23831dbd6f7d932851265eee7` | UPX‑decompressed (reveals MSSE pipe) | — |
| `perfmonsvc64.exe` | `42477dd9317c739043d4516e04221743e00b737d1234f914a0e7608202758972` | service persistence loader ("Perf Monitor") | T1543.003 |
| `csrss.exe` | `027fef173a71142cf1616e32290b9c52cbb425bfdeac1babd2a57e260c27c70e` | **timestomping** tool (masquerades as csrss) | T1070.006, T1036 |
| `b.log` | `0a040d6f452063f5bef500972f83429f3654ada88eff13c2883e8eb06b519e05` | **BrowserHistoryView** dump of `nfury` → objective | T1217, T1005 |
| `install_msadvapi2_32.exe` | `ebb75bbae3e1298cecbed3c5b1b0ca0a2a8d4d17836f672546218bc47da8dc03` | backdoor installer ("install_wormhole") | T1105 |
| `install_msadvapi2_64.exe` | `27d4968716a095a15956f1fb9e247b32dd7765b2e67149e17469908750280568` | same (64‑bit) — **identical hash on FILE + WKSTN-05** | T1105 |
| `7za.exe` | `b3a70d388488c34dd5c767692eccc9effed36b8e7c1ee03ace1bd27123a2e6d6` | exfil archiver | T1560.001 |
| `PerfSvc.exe` | `e722dd429510c83485bb276c559015df9bd4931e7e4339eb90683cc3efd9beaa` | rundll32 loader | T1218.011 |

> **Anti-forensics.** `p.exe` survived only on **RD-01**; on file/wkstn-01/wkstn-05 it was **deleted and
> overwritten** (full raw-image scans after `ewfmount` = 0 matches; MFT entries **purged**) — a clean
> T1070.004, consistent with the `csrss.exe` timestomper.

---

## 6. Indicators of Compromise (IOCs)

### Network / behavioural
```mermaid
mindmap
  root((SRL-2018 IOCs))
    C2
      Metasploit
        "\\.\pipe\MSSE-<N>-server"
        rubyw.exe → 10.10.254.1:61613 (STOMP)
        internal hub 172.16.4.10:8080
      Empire
        squirreldirectory.com (/a, /download/n.ps1)
        http://127.0.0.1:<port>/ agents
        Install-Persistence
    Hosts
      EXTERNAL 192.168.30.10/.11
      DESKTOP-NBTIQJ9 (attacker box)
    Files
      C:\Windows\Temp\perfmon\ (p.exe, csrss.exe, b.log, PerfSvc.exe, n.ps1)
      C:\ProgramData\staging\install_wormhole\ (msadvapi2)
    Accounts
      nfury (patient-zero)
      tdungan (brute-forced)
      spsql (lateral)
      rsydow-a (admin abuse)
```

### Accounts
| Account | Role in intrusion |
|---|---|
| `nfury` | **patient-zero** — external RDP foothold; the IP-theft victim (Carbonadium) |
| `tdungan` | **brute-forced** — 692 failed NTLM from RD-01 then success |
| `spsql` | SQL service acct used for RD-01 → RD-02 RDP lateral + DC staging |
| `rsydow-a` | **abused admin** creds — WinRM/RDP to DC, FILE, DMZ-FTP |

---

## 7. Approved findings (examiner-signed)

```mermaid
graph LR
    subgraph DRAFT
      D[10 findings staged<br/>HMAC-SHA256 sealed]
    end
    subgraph APPROVED
      A[10 findings signed<br/>hash-chained]
    end
    D -->|examiner victor.galvan<br/>DRAFT→APPROVED| A --> R[APPROVED-only report]
    classDef d fill:#ffec99,stroke:#f08c00
    classDef a fill:#b2f2bb,stroke:#2f9e44
    class D d
    class A,R a
```

| ID | Sev | ATT&CK | Finding |
|---|---|---|---|
| `srl2018-c2-implant-001` | high | T1071.004/T1055 | Metasploit/Meterpreter DNS-tunnel implant `p.exe` (MSSE pipe) on rd-01/file/wkstn-01/05 |
| `srl2018-empire-c2-002` | high | T1071.001 | PowerShell Empire C2 `squirreldirectory.com` + localhost agents |
| `srl2018-initial-access-003` | high | T1133 | `nfury` external RDP from `192.168.30.10/.11` → wkstn-05 |
| `srl2018-credtheft-sam-004` | high | T1003.002 | SAM hive stolen from DC Volume Shadow Copy |
| `srl2018-bruteforce-005` | high | T1110 | 692 failed NTLM brute-force of `tdungan` from rd-01 |
| `srl2018-persistence-006` | high | T1543.003 | Service persistence `perfmonsvc64.exe` |
| `srl2018-lateral-007` | high | T1021.001/.002/.006 | RD-01 ⇄ FILE lateral hub (WinRM/RDP/SMB) |
| `srl2018-timestomp-008` | med | T1070.006 | Timestomping tool `csrss.exe` |
| `srl2018-psexec-dmz-009` | med | T1569.002 | PsExec → dmz-ftp |
| `srl2018-collection-exfil-010` | high | T1560.001/T1005 | Rar/7za archiving of `nfury` Carbonadium IP → DMZ-FTP exfil |

---

## 8. Methodology, integrity & honest caveats

**Approach.** Agentropix-SIFT MCP toolset (68/72 tools exercised) over the SRL-2018 evidence:
`get_malfind`/YARA recovered the in-memory implant; `ewfmount`+`ntfs-3g` mounting recovered on-disk
binaries; PowerShell **4104** script-block logs yielded the attacker commands; DC **Kerberos/NTLM**
(4768/4769/4776) + **RDP operational** (21/25/1149) logs built the lateral graph; prefetch confirmed
execution.

**Integrity.** Each finding is **HMAC-SHA256 sealed** (12/12) and the approvals are **hash-chained**
(`DRAFT→APPROVED`, examiner-signed). `inference_constraint: high` — the LLM orchestrated; facts come
from deterministic SIFT tools.

**Caveats (stated plainly).**
- The eval IP `42.112.153.164` is a **synthetic test injection**, not a real lead.
- **5 of 6 memory images are smeared** (non-atomic live `dc3dd`/F-Response acquisition → corrupted
  `ActiveProcessLinks`) — `malfind`/`svcscan` returned 0 on those; **YARA signature scanning** (smear-
  immune) recovered the implant where memory-list-walking failed.
- `n.ps1`'s full body is **not recoverable** (Empire patches AMSI / disables script-block logging
  post-stage); only the cradle one-liners were logged.
- Deleted `p.exe` copies are **unrecoverable** (content overwritten + MFT entries purged).
- evtx pulls were **capped** (8k–25k/host) — the graphs are representative, not exhaustive.
- The MCP report engine emits no single report-level seal; tamper-evidence is at the **finding** level.

---

*Full chain of custody: `docs/06-use-cases/assets/srl-2018-training-session/session-actions.log`
(252 steps). Samples: `/home/admin2/srl-2018-malware-samples/`. Tier reports (analyst/executive/
business × md/pdf/html): this directory.*
