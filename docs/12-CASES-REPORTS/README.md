# 12 · Cases Reports

Sealed DFIR case reports — for each investigated case: the full forensic analysis, the indicators of compromise, and the Wazuh evidence captures. Findings are examiner-approved and HMAC-sealed, and every report carries its own honest-caveats section (scope, acquisition limits, what is unproven).

## Read in this order

1. [srl-2018-report/SRL-2018-FORENSIC-REPORT.md](srl-2018-report/SRL-2018-FORENSIC-REPORT.md) — the full technical forensic report: attack chain, recovered malware toolkit (9 SHA-256), network/behavioural IOCs, the 12 sealed findings, ATT&CK mapping, and methodology + caveats (renders inline with diagrams).
2. [srl-2018-report/SRL-2018-FORENSIC-REPORT.pdf](srl-2018-report/SRL-2018-FORENSIC-REPORT.pdf) — the same report as a self-contained 8-page PDF (diagrams embedded; opens in GitLab's PDF viewer).
3. [srl-2018-report/WAZUH-IOC-GALLERY.md](srl-2018-report/WAZUH-IOC-GALLERY.md) — 13 Wazuh-dashboard captures of every pushed IOC (findings index in Discover + manager CDB lists).

## Cases

### SRL-2018 — Stark Research Labs "Compromised Enterprise"

External RDP foothold → dual C2 (Metasploit/Meterpreter + PowerShell Empire) → service persistence → credential theft (SAM-from-VSS, 692-NTLM brute-force) → RD-01⇄FILE lateral hub → collection of user `nfury`'s **Carbonadium** IP → DMZ-FTP exfil, with `csrss.exe` timestomping + secure deletion anti-forensics. 12 examiner-approved findings.

**Recorded analysis session** (254 agentropix MCP actions, paged for readability):

![Recorded analysis session — paged playback](srl-2018-report/training-session-paged.mp4)

> GitLab's Markdown sanitizer strips the HTML `loop`/`autoplay` attributes, so the embedded player above plays with controls but will not auto-loop in the GitLab blob view. For a continuous loop, open [the raw file](srl-2018-report/training-session-paged.mp4) in a player (browsers/VLC honour loop), or serve the case folder via GitLab Pages where a looping `<video>` works.
