# Executive Summary — CFREDS-HACKING-CASE-4DELL

## Key Performance Indicators

| Metric | Value |
| --- | --- |
| Approved findings | 35 |
| Critical | 2 |
| High | 15 |
| Affected hosts | 0 |
| Unique ATT&CK techniques | 0 |
| Dwell time (days) | n/a |

## Critical & High Findings
- **[Hacking toolkit installed and executed by user 'Mr. Evil' (Cain, Ethereal, NetStumbler, Look@LAN, Whois, 123WASP, mIRC)](#hacking-toolkit-installed-and-executed-by-user-mr-evil-cain-ethereal-netstumbler-look-lan-whois-123wasp-mirc)** (high) — Hacking toolkit installed and executed by user 'Mr. Evil' (Cain, Ethereal, NetStumbler, Look@LAN, Whois, 123WASP, mIRC) _(see analyst finding `CFREDS-001-hacking-toolkit`)_
- **[Network sniffing + wireless wardriving capability (WinPcap + Ethereal + Cain + NetStumbler)](#network-sniffing-wireless-wardriving-capability-winpcap-ethereal-cain-netstumbler)** (high) — Network sniffing + wireless wardriving capability (WinPcap + Ethereal + Cain + NetStumbler) _(see analyst finding `CFREDS-002-sniffing-wardriving`)_
- **[Suspect real identity: Greg Schardt behind alias 'Mr. Evil'](#suspect-real-identity-greg-schardt-behind-alias-mr-evil)** (high) — Suspect real identity: Greg Schardt behind alias 'Mr. Evil' _(see analyst finding `CFREDS-EXT-01-suspect-identity-greg-schardt`)_
- **[Suspect Outlook Express email: whoknowsme@sbcglobal.net (display name 'Mr Evil')](#suspect-outlook-express-email-whoknowsme-sbcglobal-net-display-name-mr-evil)** (high) — Suspect Outlook Express email: whoknowsme@sbcglobal.net (display name 'Mr Evil') _(see analyst finding `CFREDS-EXT-02-oe-email-whoknowsme`)_
- **[Removable optical CD 'Jul 28 2004' (serial 1A3AD55E) carried anonymizer + GhostWare tooling and installers](#removable-optical-cd-jul-28-2004-serial-1a3ad55e-carried-anonymizer-ghostware-tooling-and-installers)** (high) — Removable optical CD 'Jul 28 2004' (serial 1A3AD55E) carried anonymizer + GhostWare tooling and installers _(see analyst finding `CFREDS-EXT-04-removable-optical-disc-ghostware`)_
- **[Access to remote SMB share \\4.12.220.254\Temp (host 'm1200') and sensitive files](#access-to-remote-smb-share-4-12-220-254-temp-host-m1200-and-sensitive-files)** (high) — Access to remote SMB share \\4.12.220.254\Temp (host 'm1200') and sensitive files _(see analyst finding `CFREDS-EXT-05-remote-share-4-12-220-254`)_
- **[Hashes of recovered hacking-tool binaries (Cain, Ethereal, NetStumbler, Whois)](#hashes-of-recovered-hacking-tool-binaries-cain-ethereal-netstumbler-whois)** (high) — Hashes of recovered hacking-tool binaries (Cain, Ethereal, NetStumbler, Whois) _(see analyst finding `CFREDS-EXT-06-exec-hashes-toolkit`)_
- **[Packet-capture and wireless services registered (NPF / rpcapd / wlluc48)](#packet-capture-and-wireless-services-registered-npf-rpcapd-wlluc48)** (high) — Packet-capture and wireless services registered (NPF / rpcapd / wlluc48) _(see analyst finding `CFREDS-EXT-07-pcap-wireless-services`)_
- **[UserAssist/prefetch prove execution of sniffing/cracking tools](#userassist-prefetch-prove-execution-of-sniffing-cracking-tools)** (high) — UserAssist/prefetch prove execution of sniffing/cracking tools _(see analyst finding `CFREDS-EXT-08-userassist-execution`)_
- **[Ethereal packet capture 'interception' saved to Mr. Evil profile](#ethereal-packet-capture-interception-saved-to-mr-evil-profile)** (high) — Ethereal packet capture 'interception' saved to Mr. Evil profile _(see analyst finding `CFREDS-EXT-10-ethereal-interception-capture`)_
- **[Extensive secondary hacking-tool archive (John the Ripper, pwdump, netcat, NetBus, NAT, etc.)](#extensive-secondary-hacking-tool-archive-john-the-ripper-pwdump-netcat-netbus-nat-etc)** (high) — Extensive secondary hacking-tool archive (John the Ripper, pwdump, netcat, NetBus, NAT, etc.) _(see analyst finding `CFREDS-EXT-11-additional-hacking-tools`)_
- **[SMOKING GUN: Ethereal 'interception' capture contains a third party's Pocket PC MSN/Hotmail session + captured .NET Passport auth cookies](#smoking-gun-ethereal-interception-capture-contains-a-third-party-s-pocket-pc-msn-hotmail-session-captured-net-passport-auth-cookies)** (critical) — SMOKING GUN: Ethereal 'interception' capture contains a third party's Pocket PC MSN/Hotmail session + captured .NET Passport auth cookies _(see analyst finding `CFREDS-EXT-15-intercepted-pocketpc-hotmail`)_
- **[OE account config binds mailbox whoknowsme@sbcglobal.net to the Mr. Evil profile (SBC/Dallas TX)](#oe-account-config-binds-mailbox-whoknowsme-sbcglobal-net-to-the-mr-evil-profile-sbc-dallas-tx)** (high) — OE account config binds mailbox whoknowsme@sbcglobal.net to the Mr. Evil profile (SBC/Dallas TX) _(see analyst finding `CFREDS-EXT-20-oe-account-whoknowsme`)_
- **[CAPSTONE: full correlation — identity chain + attack chain for Greg Schardt / Mr. Evil](#capstone-full-correlation-identity-chain-attack-chain-for-greg-schardt-mr-evil)** (critical) — CAPSTONE: full correlation — identity chain + attack chain for Greg Schardt / Mr. Evil _(see analyst finding `CFREDS-EXT-21-master-correlation`)_
- **[IE browsing history: wardriving/sniffing/hacker sites and toolkit download sources](#ie-browsing-history-wardriving-sniffing-hacker-sites-and-toolkit-download-sources)** (high) — IE browsing history: wardriving/sniffing/hacker sites and toolkit download sources _(see analyst finding `CFREDS-EXT-25-ie-history-wardriving`)_
- **[Wardriving hardware: Compaq WL110 (ORiNOCO/Agere 802.11b) PCMCIA wireless card installed](#wardriving-hardware-compaq-wl110-orinoco-agere-802-11b-pcmcia-wireless-card-installed)** (high) — Wardriving hardware: Compaq WL110 (ORiNOCO/Agere 802.11b) PCMCIA wireless card installed _(see analyst finding `CFREDS-EXT-29-wireless-nic-wardriving-hw`)_
- **[Network activity & lateral-movement summary (adapters, DHCP, SMB reach-out, capture services)](#network-activity-lateral-movement-summary-adapters-dhcp-smb-reach-out-capture-services)** (high) — Network activity & lateral-movement summary (adapters, DHCP, SMB reach-out, capture services) _(see analyst finding `CFREDS-EXT-31-network-lateral-summary`)_
