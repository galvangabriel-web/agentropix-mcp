# 12 · Cases Reports

Sealed DFIR case reports — for each investigated case: the full forensic analysis, the indicators of compromise, and the Wazuh evidence captures. Findings are examiner-approved and HMAC-sealed, and every report carries its own honest-caveats section (scope, acquisition limits, what is unproven).

## Cases

### SRL-2018 — Stark Research Labs "Compromised Enterprise"

External RDP foothold → dual C2 (Metasploit/Meterpreter + PowerShell Empire) → service persistence → credential theft (SAM-from-VSS, 692-NTLM brute-force) → RD-01⇄FILE lateral hub → collection of user `nfury`'s **Carbonadium** IP → DMZ-FTP exfil, with `csrss.exe` timestomping + secure deletion anti-forensics. 12 examiner-approved findings.

**Read in this order:**

1. [srl-2018-report/SRL-2018-FORENSIC-REPORT.md](srl-2018-report/SRL-2018-FORENSIC-REPORT.md) — the full technical forensic report: attack chain, recovered malware toolkit (9 SHA-256), network/behavioural IOCs, the 12 sealed findings, ATT&CK mapping, and methodology + caveats (renders inline with diagrams).
2. [srl-2018-report/TECHNICAL-APPENDIX.md](srl-2018-report/TECHNICAL-APPENDIX.md) — machine-extracted depth: per-host network sockets (`get_netscan`), the rd-01 injected-code regions (`get_malfind`), and the evtx lateral-movement matrix.
3. [srl-2018-report/WAZUH-IOC-GALLERY.md](srl-2018-report/WAZUH-IOC-GALLERY.md) — 13 Wazuh-dashboard captures of every pushed IOC (findings index in Discover + manager CDB lists).

**Recorded analysis session** (254 agentropix MCP actions, paged for readability):

![Recorded analysis session — paged playback](srl-2018-report/training-session-paged.mp4)

> GitLab's Markdown sanitizer strips the HTML `loop`/`autoplay` attributes, so the embedded player above plays with controls but will not auto-loop in the GitLab blob view. For a continuous loop, open [the raw file](srl-2018-report/training-session-paged.mp4) in a player (browsers/VLC honour loop), or serve the case folder via GitLab Pages where a looping `<video>` works.

---

### VANKO — "The Case of the Abducted Zebrafish" (insider IP theft)

A trusted insider (Anthony Vanko, STARKSURFACE / `PC User`) copied classified zebrafish-DNA and cell-regeneration trade secrets from the StarkResearch file server → masquerade `defaultprinter` staging account → archived + disguised as `vacation photos.7z` → **dual cloud exfil** (Dropbox `984347879` + OneDrive, SRUM-confirmed) → foreign-handler coordination (Russia: Merrick→Bulgakov; China: QQ/CAS at artifact level) → SDelete anti-forensics **defeated by Volume Shadow Copies**. **Not a malware intrusion** — an authorized insider abusing valid access and signed tools. **10 examiner-approved findings** (of 19; 9 refuted by the false-positive gate); egressed to Wazuh (decision ledger seq 139).

**Read in this order:**

1. [vanko-report/VANKO-FORENSIC-REPORT.md](vanko-report/VANKO-FORENSIC-REPORT.md) — the presentation forensic report: attack lifecycle, exfil/buyer-channel architecture, and timeline **diagrams**, the weaponized signed toolchain, IOC mindmap, the 10 sealed findings, ATT&CK mapping, and methodology + honest caveats (renders inline with diagrams).
2. [vanko-report/VANKO-DFIR-REPORT.md](vanko-report/VANKO-DFIR-REPORT.md) — the full legally-defensible 7-section DFIR report: executive summary, scope/methodology, master incident timeline, technical attack narrative (MITRE-mapped), malware & artifact analysis, structured IOCs, and containment/remediation recommendations.
3. [vanko-report/WAZUH-VANKO-GALLERY.md](vanko-report/WAZUH-VANKO-GALLERY.md) — 8 Wazuh-dashboard captures of the operator-authorized egress (10 approved findings in Discover, granular finding detail, MITRE/Threat-Hunting modules, and the manager CDB IOC read-back).

**Forensic evidence presentation** (~9 min) — the 8 key facts, each shown with its cross-source correlated artifacts (proof red-boxed), the technical correlation, and what it means to the case; bookended by the architecture and timeline diagrams:

![VANKO forensic evidence presentation](vanko-report/findings-presentation.mp4)

> GitLab's Markdown sanitizer strips the HTML `loop`/`autoplay` attributes, so the embedded player plays with controls but will not auto-loop in the blob view. For a continuous loop, open [the raw file](vanko-report/findings-presentation.mp4) in a player (browsers/VLC honour loop). The raw paged action-log playback (76 MCP actions, 2:24) is also available: [training-session-paged.mp4](vanko-report/training-session-paged.mp4).
