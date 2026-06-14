# CFReDS "Hacking Case" — Attack Execution Graph
Case `CFREDS-HACKING-CASE-4DELL` · Host **MR-EVIL** (N-1A9ODN6ZXK4LQ, Dell Latitude CPi, WinXP) · Actor **Greg Schardt / "Mr. Evil"**

```mermaid
flowchart TD
  %% ===== ACTOR / IDENTITY =====
  subgraph ID["🧑 Actor / Identity (one person)"]
    A1["Greg Schardt<br/>(XP RegisteredOwner; Look@LAN Nome)"]
    A2["local admin acct 'Mr. Evil' RID 1003"]
    A3["IRC: mrevilrulez / ident Mrevil"]
    A4["mail: whoknowsme@sbcglobal.net"]
    A1 --- A2 --- A3 --- A4
  end

  %% ===== ENTRY / SETUP =====
  subgraph ENTRY["① Point of Entry / Setup  (2004-08-19..20)"]
    E1["Physical access to laptop<br/>local console logon (admin)"]
    E2["CD 'Jul 28 2004' (serial 1A3AD55E)<br/>+ Desktop downloads"]
    E3["IE browsing: netstumbler.com,<br/>wardriving.com, 2600.com, elitehackers.com"]
  end

  %% ===== CAPABILITY (tools/hw) =====
  subgraph CAP["② Capability — installed tools (exe) & hardware"]
    HW["📶 Compaq WL110 ORiNOCO<br/>802.11b PCMCIA card (wlluc48)"]
    T_CAIN["Cain.exe (32/76 VT)"]
    T_ETH["ethereal.exe"]
    T_NS["NetStumbler.exe"]
    T_LAL["LookAtLan.exe / LookAtHost.exe"]
    T_WHO["whois.exe"]
    T_MIRC["mirc.exe (30/75 VT)"]
    T_WASP["123WASP (pwd stealer)"]
  end

  %% ===== SERVICES / DRIVERS =====
  subgraph SVC["③ Services / Drivers registered"]
    S_NPF["NPF (WinPcap pkt-capture driver)"]
    S_RPC["rpcapd (remote capture daemon)"]
    S_WL["wlluc48.sys (wireless)"]
  end

  %% ===== DISCOVERY =====
  subgraph DISC["④ Discovery / Wardriving"]
    D1["NetStumbler — 802.11 AP discovery"]
    D2["Look@LAN / Whois — host enum"]
  end

  %% ===== COLLECTION / INTERCEPTION =====
  subgraph COL["⑤ Collection — wireless MITM (2004-08-27 15:36)"]
    C1["Ethereal + WinPcap + Cain<br/>sniff local WLAN (gw 192.168.254.254)"]
    VIC["🎯 VICTIM: neighbor Pocket PC<br/>(WinCE 4.20 / PXA255)"]
    C2["capture file 'interception' (173 KB)<br/>saved to Mr. Evil profile"]
  end

  %% ===== COMPROMISE / THEFT =====
  subgraph THEFT["⑥ Credential / Data theft"]
    K1["MSN/Hotmail session (mobile.msn.com)"]
    K2["🔑 .NET Passport cookies<br/>MSPAuth / MSPProf (cleartext)"]
    K3["remote SMB \\4.12.220.254\Temp (m1200)<br/>keys.txt / channels.txt / yng13.bmp"]
  end

  %% ===== ANTI-FORENSICS =====
  subgraph AF["⑦ Anti-forensics / evasion"]
    F1["Anonymizer.dll + GhostWare"]
    F2["RECYCLER Dc1-4.exe<br/>(deleted toolkit installers)"]
  end

  %% ===== EGRESS / COMMS =====
  subgraph NET["Network comms"]
    N1["IRC Undernet/EFnet<br/>#Elite.Hackers #evilfork #ISO-WAREZ #ushells"]
    N2["SBC mail/news<br/>pop/smtp/news.dallas.sbcglobal.net"]
    N3["mIRC DCC fileserver C:\\Temp"]
  end

  %% ---- EDGES ----
  ID --> ENTRY
  E1 --> CAP
  E2 --> CAP
  E3 --> CAP
  HW --> S_WL
  T_CAIN --> S_NPF
  T_ETH --> S_NPF
  S_NPF --> S_RPC
  CAP --> DISC
  S_WL --> DISC
  D1 --> COL
  D2 --> COL
  C1 --> VIC
  VIC --> C2
  C2 --> THEFT
  K1 --> K2
  CAP --> THEFT
  COL --> N1
  ID --> N1
  ID --> N2
  T_MIRC --> N3
  THEFT --> AF
  CAP --> AF
  ID --> NET

  %% ---- styling ----
  classDef actor fill:#e8d5ff,stroke:#7b2cbf,color:#000;
  classDef tool fill:#ffe5b4,stroke:#d97706,color:#000;
  classDef svc fill:#cfe8ff,stroke:#1d6fb8,color:#000;
  classDef victim fill:#ffd6d6,stroke:#c0392b,color:#000;
  classDef theft fill:#ffb3b3,stroke:#a30000,color:#000;
  classDef af fill:#d9d9d9,stroke:#555,color:#000;
  class A1,A2,A3,A4 actor;
  class T_CAIN,T_ETH,T_NS,T_LAL,T_WHO,T_MIRC,T_WASP,HW tool;
  class S_NPF,S_RPC,S_WL svc;
  class VIC,K1 victim;
  class K2,K3 theft;
  class F1,F2 af;
```

## Legend / element inventory
| Type | Elements |
|---|---|
| **Entry** | local admin console logon; CD `1A3AD55E`; Desktop installers; hacker-site browsing |
| **Executables** | Cain.exe, ethereal.exe, NetStumbler.exe, LookAtLan/LookAtHost.exe, whois.exe, mirc.exe, 123WASP |
| **Services/drivers** | NPF (WinPcap), rpcapd, wlluc48.sys |
| **Hardware** | Compaq WL110 ORiNOCO 802.11b PCMCIA |
| **Captured/compromised files** | `interception` (pcap); MSPAuth/MSPProf cookies; remote `keys.txt`,`channels.txt`,`yng13.bmp` |
| **Victim** | neighbor Pocket PC (WinCE/PXA255) via gw 192.168.254.254 |
| **Anti-forensics** | Anonymizer.dll, GhostWare, deleted RECYCLER Dc1-4 installers |
| **MITRE** | T1078.003 · T1588.002 · T1592.001 · T1016/T1018 · T1040 · T1557 · T1539 · T1021.002 · T1070.004 |
