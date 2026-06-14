# Executive Summary — CFREDS-HACKING-CASE-4DELL

## Key Performance Indicators

| Metric | Value |
| --- | --- |
| Approved findings | 35 |
| Critical | 2 |
| High | 15 |
| Affected hosts | MR-EVIL (N-1A9ODN6ZXK4LQ) |
| Suspect | Greg Schardt ("Mr. Evil") |
| Offense | Unauthorized wireless interception of a third party's web-mail session + credentials |

## Verdict
The standalone Windows XP laptop of **Greg Schardt** (alias **"Mr. Evil"**, local admin RID 1003) was used to conduct **unauthorized wireless interception**. Using a Compaq WL110 ORiNOCO 802.11b card with WinPcap + Ethereal + Cain & Abel, and NetStumbler/Look@LAN for discovery, the actor captured a neighboring **Pocket PC's MSN/Hotmail session** including cleartext **.NET Passport `MSPAuth`/`MSPProf`** authentication cookies (2004-08-27 15:36 GMT). Identity is corroborated across the local admin account, the Outlook Express mailbox `whoknowsme@sbcglobal.net`, the IRC persona `mrevilrulez`, and a Look@LAN registry value recording the real name "Greg Schardt". Anti-forensic tooling (Anonymizer, GhostWare) and deleted toolkit installers were also recovered.

## Critical & High Findings
- **CFREDS-EXT-15** (critical) — SMOKING GUN: Ethereal 'interception' capture contains a third party's Pocket PC MSN/Hotmail session + captured .NET Passport auth cookies
- **CFREDS-EXT-21** (critical) — CAPSTONE: full correlation — identity chain + attack chain for Greg Schardt / Mr. Evil
- **CFREDS-001** (high) — Hacking toolkit installed/executed (Cain, Ethereal, NetStumbler, Look@LAN, Whois, 123WASP, mIRC)
- **CFREDS-002** (high) — Network sniffing + wireless wardriving capability (WinPcap+Ethereal+Cain+NetStumbler)
- **CFREDS-EXT-01** (high) — Suspect real identity: Greg Schardt behind alias 'Mr. Evil'
- **CFREDS-EXT-02** (high) — Suspect Outlook Express email: whoknowsme@sbcglobal.net
- **CFREDS-EXT-04** (high) — Removable optical CD 'Jul 28 2004' (serial 1A3AD55E) carried anonymizer + GhostWare + installers
- **CFREDS-EXT-05** (high) — Access to remote SMB share \\4.12.220.254\Temp (host 'm1200')
- **CFREDS-EXT-06** (high) — Hashes of recovered hacking-tool binaries (Cain/Ethereal/NetStumbler/Whois)
- **CFREDS-EXT-07** (high) — Packet-capture & wireless services registered (NPF / rpcapd / wlluc48)
- **CFREDS-EXT-08** (high) — UserAssist/prefetch prove execution of sniffing/cracking tools
- **CFREDS-EXT-10** (high) — Ethereal packet capture 'interception' saved to Mr. Evil profile
- **CFREDS-EXT-11** (high) — Extensive secondary hacking-tool archive (John the Ripper, pwdump, netcat, NetBus, NAT)
- **CFREDS-EXT-20** (high) — OE account binds whoknowsme@sbcglobal.net to the Mr. Evil profile (SBC/Dallas TX)
- **CFREDS-EXT-25** (high) — IE browsing history: wardriving/sniffing/hacker sites & download sources
- **CFREDS-EXT-29** (high) — Wardriving hardware: Compaq WL110 (ORiNOCO/Agere 802.11b) PCMCIA card
- **CFREDS-EXT-31** (high) — Network activity & lateral-movement summary (adapters, DHCP, SMB, capture services)

_Full detail in CFREDS-analyst.md and CFREDS-report.html. All 35 findings + 24 timeline events APPROVED by examiner victor.galvan, 2026-06-14._
