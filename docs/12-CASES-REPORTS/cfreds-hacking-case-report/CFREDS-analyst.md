# Analyst / Technical Report — CFREDS-HACKING-CASE-4DELL

**Case:** CFReDS "Hacking Case" (Greg Schardt / Mr. Evil) · **Host:** MR-EVIL (N-1A9ODN6ZXK4LQ, Dell Latitude CPi, WinXP)
**Examiner:** victor.galvan · **Evidence:** /cases/cfreds-fresh/4Dell-Latitude-CPi.E01 (MD5 aee4fcd9301c03b3b054623ca261959a)
**Status:** 35 findings + 24 timeline events APPROVED (2026-06-14)

## Findings (35, all APPROVED)
| ID | Severity | Title |
|---|---|---|
| CFREDS-001 | high | Hacking toolkit installed/executed (Cain, Ethereal, NetStumbler, Look@LAN, Whois, 123WASP, mIRC) |
| CFREDS-002 | high | Network sniffing + wireless wardriving capability (WinPcap+Ethereal+Cain+NetStumbler) |
| CFREDS-003 | medium | Suspect admin account 'Mr. Evil' + anonymizer + suspicious batch file |
| CFREDS-004 | info | Bulk-extractor IOC carve summary |
| CFREDS-EXT-01 | high | Suspect real identity: Greg Schardt behind alias 'Mr. Evil' |
| CFREDS-EXT-02 | high | Suspect OE email whoknowsme@sbcglobal.net (display 'Mr Evil') |
| CFREDS-EXT-03 | medium | IRC identity ties persona to Undernet |
| CFREDS-EXT-04 | high | Removable CD 'Jul 28 2004' (1A3AD55E) carried anonymizer+GhostWare+installers |
| CFREDS-EXT-05 | high | Access to remote SMB share \\4.12.220.254\Temp (host 'm1200') |
| CFREDS-EXT-06 | high | Hashes of recovered hacking-tool binaries |
| CFREDS-EXT-07 | high | Packet-capture & wireless services (NPF / rpcapd / wlluc48) |
| CFREDS-EXT-08 | high | UserAssist/Prefetch prove execution of sniffing/cracking tools |
| CFREDS-EXT-09 | medium | TypedURLs show wardriving & 2600 intent |
| CFREDS-EXT-10 | high | Ethereal capture 'interception' saved to Mr. Evil profile |
| CFREDS-EXT-11 | high | Secondary toolkit (John the Ripper, pwdump, netcat, NetBus, NAT, ToneLoc) |
| CFREDS-EXT-12 | medium | Subscribed hacking/phreaking newsgroups (alt.2600, alt.binaries.hacking) |
| CFREDS-EXT-13 | info | Host config: ComputerName N-1A9ODN6ZXK4LQ, Central TZ |
| CFREDS-EXT-14 | low | RECYCLER held deleted executables (Dc1-Dc4.exe) |
| CFREDS-EXT-15 | critical | SMOKING GUN: capture contains third-party Pocket PC MSN/Hotmail session + .NET Passport cookies |
| CFREDS-EXT-16 | medium | mIRC config confirms Undernet IRC identity (mrevilrulez/Mrevil) |
| CFREDS-EXT-17 | medium | Look@LAN install log records real name 'Greg Schardt' in registry |
| CFREDS-EXT-18 | info | Inbox.dbx = only default OE welcome message (no user mail) |
| CFREDS-EXT-19 | medium | alt.hacking posts: BIOS password hacking & stealing monster.com logins |
| CFREDS-EXT-20 | high | OE account binds whoknowsme@sbcglobal.net to profile (SBC/Dallas TX) |
| CFREDS-EXT-21 | critical | CAPSTONE: full identity + attack-chain correlation |
| CFREDS-EXT-22 | medium | VT/OTX: Cain.exe confirmed malicious hacktool (32/76) |
| CFREDS-EXT-23 | medium | Hash + VT/OTX of remaining tool binaries & RECYCLER Dc#.exe |
| CFREDS-EXT-24 | medium | mIRC chat logs: hacking/warez/shell channels as mrevilrulez |
| CFREDS-EXT-25 | high | IE history: wardriving/sniffing/hacker sites & download sources |
| CFREDS-EXT-26 | medium | Anti-forensic/anonymity tooling: Anonymizer + GhostWare |
| CFREDS-EXT-27 | medium | Dc1-4 = deleted toolkit installers (via INFO2) |
| CFREDS-EXT-28 | low | Look@LAN saved no scan results; extra warez/MP3/shell IRC |
| CFREDS-EXT-29 | high | Wardriving hardware: Compaq WL110 (ORiNOCO 802.11b) PCMCIA card |
| CFREDS-EXT-30 | low | VT/OTX of new browsing domains + wireless driver |
| CFREDS-EXT-31 | high | Network activity & lateral-movement summary |

## Kill-chain timeline (2004, 24 events — APPROVED)
| Timestamp (UTC) | Event |
|---|---|
| 2004-08-19 22:20 | Machine renamed N-1A9ODN6ZXK4LQ (EventLog EID 6011) |
| 2004-08-19 22:48 | Windows XP installed; RegisteredOwner 'Greg Schardt' |
| 2004-08-19 23:04 | Mr. Evil user profile / NTUSER.DAT created |
| 2004-08-20 10:29 | IRC activity as mrevil/mrevilrulez (#ISO-WAREZ/#evilfork/#ushells/#Elite.Hackers/#CyberCafe) |
| 2004-08-20 15:05 | Cain & Abel v2.5 beta45 installed from D:\Drivers |
| 2004-08-20 15:12 | 123 Write All Stored Passwords (123 WASP) installer run from D:\Drivers |
| 2004-08-20 15:47 | mIRC channels.txt (1.7 MB) written |
| 2004-08-20 16:13 | Outlook Express 6 first run; account whoknowsme@sbcglobal.net (display 'Mr Evil') |
| 2004-08-25 10:55 | Look@LAN installed; registry Nome='Greg Schardt' (real-name attribution) |
| 2004-08-25 15:55 | Look@LAN installer lalsetup250.exe run from Desktop; Look@LAN 2.50 installed |
| 2004-08-25 16:18 | RECYCLER bin for Mr. Evil first created (Dc1.exe staged 15:51) |
| 2004-08-26 13:49 | yng13.bmp on \\4.12.220.254\TEMP modified (LNK target time) |
| 2004-08-26 15:05 | telnet launched via Run dialog (RunMRU) |
| 2004-08-26 15:06 | Remote SMB share \\4.12.220.254\Temp (host m1200) mapped/browsed; yng13.bmp opened |
| 2004-08-27 15:12 | NetStumbler.exe executed (wireless wardriving recon) |
| 2004-08-27 15:15 | WinPcap 3.01 alpha installed; NPF driver + rpcapd remote-capture daemon registered |
| 2004-08-27 15:18 | FTP browse of mirror.sg.depaul.edu /pub security ethereal/win32 (ShellBag) |
| 2004-08-27 15:31 | Wireless LAN PC Card driver wlluc48 service registered (wardriving NIC) |
| 2004-08-27 15:33 | Cain.exe executed (credential cracking) |
| 2004-08-27 15:35 | Ethereal executed |
| 2004-08-27 15:36 | INTERCEPTION: third-party Pocket PC (WinCE/PXA255) MSN Hotmail session + .NET Passport MSPAuth/MSPProf cookies captured (gw 192.168.254.254) |
| 2004-08-27 15:41 | Ethereal capture 'interception' (173,372 bytes) written to Mr. Evil profile |
| 2004-08-27 15:44 | TypedURLs: FTP/HTTP to 4.12.220.254/temp, wardriving.com, 2600.org, ethereal.com |
| 2004-08-27 15:46 | Final clean shutdown (EventLog EID 6006); last RECYCLER activity |

## Key IOCs
- Identity: Greg Schardt; 'Mr. Evil' RID 1003; IRC mrevilrulez/Mrevil
- Email: whoknowsme@sbcglobal.net ; servers pop/smtp.sbcglobal.net, news.dallas.sbcglobal.net
- IPs: 4.12.220.254 (SMB, m1200) ; 192.168.254.254 (WLAN gw) ; MAC 00:c0:02:b9:00:78
- Captured creds: .NET Passport MSPAuth / MSPProf cookies (victim)
- Hashes: Cain.exe MD5 6767c8db317f2517dea73a00e00f0638 (VT 32/76); Cain SHA256 e2df120323e235137795a8a3240aa789ed2307ea36e3f5062139d849b81d365a; mirc.exe VT 30/75
- Domains (flagged): elitehackers.com, 2600.com (VT suspicious)
- Hardware: Compaq WL110 ORiNOCO 802.11b PCMCIA (wlluc48)
- Services: NPF (WinPcap), rpcapd (remote capture), wlluc48.sys
- Removable: CD 'Jul 28 2004' serial 1A3AD55E

## Honest negatives / scope
- Standalone WinXP workgroup host — no enterprise lateral movement (no domain/RDP/PsExec/PtH/second host).
- No memory image — Volatility N/A; all execution evidence from disk artifacts.
- XP .evt logs used (not .evtx); Security.evt empty; Amcache skipped (Win7+).
- Look@LAN saved no scan-results file; NetStumbler saved no .ns1 session.
- 93 IOCs staged; index promotion pending an evidence-gate mutation token (CLI-minted by examiner).
