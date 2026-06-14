# 12 · Cases Reports

Sealed DFIR case reports — for each investigated case: the full forensic analysis, the indicators of compromise, and the Wazuh evidence captures. Findings are examiner-approved and HMAC-sealed, and every report carries its own honest-caveats section (scope, acquisition limits, what is unproven).

> 🗂️ For where these case folders sit in the wider repository (and what every other file does), see the file-by-file map in [**PROJECT-STRUCTURE.md**](../../PROJECT-STRUCTURE.md).

## Cases

### SRL-2015 — Stark Research Labs "APT Enterprise" (4-host intrusion)

Four-host enterprise APT (`win2008R2-controller` DC + 3 workstations): trojanized *USB-over-Ethernet*
C2 service on the DC → explorer process injection (T1055, VB6-packed LZMA self-injecting loader) →
`spinlock.exe` / fake-`svchost.exe` implants → PsExec lateral movement → `vibranium` credential abuse →
archive staging + USB exfil, with timestomping anti-forensics. **2,233 raw findings → 17
examiner-approved** (1 critical / 14 high / 2 medium); 91 IOCs TI-enriched (VT+OTX) → **12
malicious**; **21 malware samples** recovered hash-verified (16 disk-carved + 5 Volatility `malfind`
memory payloads, 9 distinct malicious SHA-256) — samples withheld, custody proven by manifest.

**Read in this order:**

1. [srl-2015-report/README.md](srl-2015-report/README.md) — **how to read, analyze & understand this
   investigation**: per-file map, the full provenance / chain-of-custody section (evidence image →
   SHA-256 → finding → IOC → VT/OTX verdict → Wazuh doc, RAW vs SANITIZED, withheld-by-reference
   hashes), and an "analyze it yourself" guide.
2. [srl-2015-report/reports/SRL-2015-full-report.pdf](srl-2015-report/reports/SRL-2015-full-report.pdf) — the
   complete forensic report (17 approved findings, IOC table, MITRE mapping, Wazuh reconciliation);
   condensed: [executive summary](srl-2015-report/reports/SRL-2015-executive-summary.pdf).
3½. [srl-2015-report/AGENT-EXECUTION-LOGS-REPORT-SRL2015.md](srl-2015-report/AGENT-EXECUTION-LOGS-REPORT-SRL2015.md)
   — the **Agent Execution Logs** for the autonomous engine pipeline over all 4 hosts × disk+memory
   (8 sealed runs, 2,233 findings): communication chain, timestamped A2A log, 15-iteration traces,
   cross-host APT correlation, integrity ledger — 82 JSONPath-cited claims.
3. [srl-2015-report/deep-analysis/SRL-2015-memory-deep-analysis.md](srl-2015-report/deep-analysis/SRL-2015-memory-deep-analysis.md)
   — static reverse-engineering of the 5 memory-injection payloads (one VB6/LZMA loader family, two
   compiler variants, shipped [YARA rule](srl-2015-report/deep-analysis/srl2015_meminject.yar)).

**Recorded investigation replay** (~53 s, faithful command reenactment of the real 2026-06-10 run —
chapters in [video/README.md](srl-2015-report/video/README.md)):

[![SRL-2015 investigation replay (animated GIF — click for the MP4)](srl-2015-report/video/SRL-2015-investigation.gif)](https://galvangabriel-web.github.io/agentropix-mcp/docs/12-CASES-REPORTS/srl-2015-report/video/SRL-2015-investigation-web.mp4)

> ▶ The animation above is the inline GIF replay (auto-plays on GitHub). For full quality:
> **[download the MP4 (1.5 MB)](https://raw.githubusercontent.com/galvangabriel-web/agentropix-mcp/main/docs/12-CASES-REPORTS/srl-2015-report/video/SRL-2015-investigation-web.mp4)**
> and open it locally (any browser/VLC plays it). The
> [asciinema source](srl-2015-report/video/session.cast) is also included.
> *Why no inline player: GitHub's Markdown sanitizer strips `<video>` tags entirely and renders
> `![ ](*.mp4)` as a broken image — repo-committed MP4s cannot play inline on github.com.*

**More in this case folder:**

- [srl-2015-report/INDEX.md](srl-2015-report/INDEX.md) — deliverable index for the case folder (headline-numbers table, evidence cluster, source artifacts from the real 2026-06-10 pipeline run).
- [srl-2015-report/reports/README.md](srl-2015-report/reports/README.md) — the narrative case reports (full technical + executive, each as HTML and PDF).
- [srl-2015-report/deep-analysis/README.md](srl-2015-report/deep-analysis/README.md) — static reverse-engineering of the five memory-injected payloads; includes [INJECTION-ANALYSIS.md](srl-2015-report/deep-analysis/INJECTION-ANALYSIS.md) (disassembly & injection-mechanism walkthrough) and [screenshots/README.md](srl-2015-report/deep-analysis/screenshots/README.md) (three Wazuh Discover proof captures).
- [srl-2015-report/enrichment/README.md](srl-2015-report/enrichment/README.md) — the raw VirusTotal + OTX threat-intel report, the upstream source of the published IOC exports.
- [srl-2015-report/exports/README.md](srl-2015-report/exports/README.md) — machine-readable IOC & executable inventory (`iocs.csv`/`.json`/STIX, `ear.csv`/`.json`) for SIEM/TIP ingestion.
- [srl-2015-report/pipeline-findings/README.md](srl-2015-report/pipeline-findings/README.md) — the eight raw per-host/per-modality findings JSONs whose counts sum to the 2,233 headline.
- [srl-2015-report/quarantine/README.md](srl-2015-report/quarantine/README.md) — carved-malware sample catalogue/manifest (samples withheld; custody proven).
- [srl-2015-report/wazuh-push-receipts/README.md](srl-2015-report/wazuh-push-receipts/README.md) — raw Wazuh push receipts & pipeline summaries making the headline numbers independently verifiable.
- [srl-2015-report/video/diagnosis/README.md](srl-2015-report/video/diagnosis/README.md) — Playwright render-verification captures (publication-QA proof against the live blobs).
- [watch-execution-logs.html](srl-2015-report/watch-execution-logs.html) — local watch page for the animated Agent Execution Logs deck (2 min 24 s, `EXECUTION-LOGS-SRL2015-ANIMATED.mp4`).

---

### SRL-2018 — Stark Research Labs "Compromised Enterprise"

External RDP foothold → dual C2 (Metasploit/Meterpreter + PowerShell Empire) → service persistence → credential theft (SAM-from-VSS, 692-NTLM brute-force) → RD-01⇄FILE lateral hub → collection of user `nfury`'s **Carbonadium** IP → DMZ-FTP exfil, with `csrss.exe` timestomping + secure deletion anti-forensics. 12 examiner-approved findings.

**Read in this order:**

1. [srl-2018-report/SRL-2018-FORENSIC-REPORT.md](srl-2018-report/SRL-2018-FORENSIC-REPORT.md) — the full technical forensic report: attack chain, recovered malware toolkit (9 SHA-256), network/behavioural IOCs, the 12 sealed findings, ATT&CK mapping, and methodology + caveats (renders inline with diagrams).
2. [srl-2018-report/TECHNICAL-APPENDIX.md](srl-2018-report/TECHNICAL-APPENDIX.md) — machine-extracted depth: per-host network sockets (`get_netscan`), the rd-01 injected-code regions (`get_malfind`), and the evtx lateral-movement matrix.
3. [srl-2018-report/WAZUH-IOC-GALLERY.md](srl-2018-report/WAZUH-IOC-GALLERY.md) — 13 Wazuh-dashboard captures of every pushed IOC (findings index in Discover + manager CDB lists).
4. [srl-2018-report/submission/AGENT-EXECUTION-LOGS-REPORT.md](srl-2018-report/submission/AGENT-EXECUTION-LOGS-REPORT.md) — the **Agent Execution Logs gold report**: the autonomous engine run over the same DC image (22 findings · 176 tool calls) + a NotchItUp comparison run, with all 10 raw sealed evidence files (report / audit-log / session-key / live run.log / Thymus trail) committed beside it.

**Recorded analysis session** (254 agentropix MCP actions, paged for readability):

[![Recorded analysis session — poster frame (click for the MP4)](srl-2018-report/training-session-poster.png)](https://galvangabriel-web.github.io/agentropix-mcp/docs/12-CASES-REPORTS/srl-2018-report/training-session-paged.mp4)

> ▶ The image above is a poster frame.
> **[Download the full session video (MP4, 19 MB)](https://raw.githubusercontent.com/galvangabriel-web/agentropix-mcp/main/docs/12-CASES-REPORTS/srl-2018-report/training-session-paged.mp4)**
> and open it locally (any browser/VLC plays it).
> *Why no inline player: GitHub's Markdown sanitizer strips `<video>` tags entirely and renders
> `![ ](*.mp4)` as a broken image — repo-committed MP4s cannot play inline on github.com, and at
> 19 MB this file exceeds the blob-preview limit ("we can't show files that are this big").*

**Correlate:** same Stark Research Labs org as [SRL-2015](srl-2015-report/README.md) (user `nfury` appears in both) — commodity C2 frameworks here vs SRL-2015's custom in-memory loader; contrast with the malware-free insider case [VANKO](vanko-report/VANKO-FORENSIC-REPORT.md).

**More in this case folder:**

- [srl-2018-report/README.md](srl-2018-report/README.md) — per-case reader's guide for the SRL-2018 deliverable.
- [srl-2018-report/diagrams/README.md](srl-2018-report/diagrams/README.md) — the five pre-rendered Mermaid PNGs embedded by the forensic report.
- [srl-2018-report/wazuh/README.md](srl-2018-report/wazuh/README.md) — the Wazuh dashboard evidence gallery (one capture per detection + the CDB IOC lists).
- [srl-2018-report/submission/README.md](srl-2018-report/submission/README.md) — the Agent Execution Logs gold package: two real engine runs with the full evidence quintet (report / audit-log / session-key / live `run.log` / Thymus trail) per run; includes the [Visual Atlas](srl-2018-report/submission/AGENT-EXECUTION-VISUAL-ATLAS.md) (13 diagrams + animated decks) and the `EXECUTION-LOGS-ANIMATED.mp4` walkthrough.

---

### VANKO — "The Case of the Abducted Zebrafish" (insider IP theft)

A trusted insider (Anthony Vanko, STARKSURFACE / `PC User`) copied classified zebrafish-DNA and cell-regeneration trade secrets from the StarkResearch file server → masquerade `defaultprinter` staging account → archived + disguised as `vacation photos.7z` → **dual cloud exfil** (Dropbox `984347879` + OneDrive, SRUM-confirmed) → foreign-handler coordination (Russia: Merrick→Bulgakov; China: QQ/CAS at artifact level) → SDelete anti-forensics **defeated by Volume Shadow Copies**. **Not a malware intrusion** — an authorized insider abusing valid access and signed tools. **10 examiner-approved findings** (of 19; 9 refuted by the false-positive gate); egressed to Wazuh (decision ledger seq 139).

**Read in this order:**

1. [vanko-report/VANKO-FORENSIC-REPORT.md](vanko-report/VANKO-FORENSIC-REPORT.md) — the presentation forensic report: attack lifecycle, exfil/buyer-channel architecture, and timeline **diagrams**, the weaponized signed toolchain, IOC mindmap, the 10 sealed findings, ATT&CK mapping, and methodology + honest caveats (renders inline with diagrams).
2. [vanko-report/VANKO-DFIR-REPORT.md](vanko-report/VANKO-DFIR-REPORT.md) — the full legally-defensible 7-section DFIR report: executive summary, scope/methodology, master incident timeline, technical attack narrative (MITRE-mapped), malware & artifact analysis, structured IOCs, and containment/remediation recommendations.
3. [vanko-report/WAZUH-VANKO-GALLERY.md](vanko-report/WAZUH-VANKO-GALLERY.md) — 8 Wazuh-dashboard captures of the operator-authorized egress (10 approved findings in Discover, granular finding detail, MITRE/Threat-Hunting modules, and the manager CDB IOC read-back).

**Forensic evidence presentation** (~9 min) — the 8 key facts, each shown with its cross-source correlated artifacts (proof red-boxed), the technical correlation, and what it means to the case; bookended by the architecture and timeline diagrams:

[![VANKO forensic evidence presentation — poster frame (click for the MP4)](vanko-report/findings-presentation-poster.png)](https://galvangabriel-web.github.io/agentropix-mcp/docs/12-CASES-REPORTS/vanko-report/findings-presentation.mp4)

> ▶ The image above is a poster frame.
> **[Download the full presentation video (MP4, 14 MB)](https://raw.githubusercontent.com/galvangabriel-web/agentropix-mcp/main/docs/12-CASES-REPORTS/vanko-report/findings-presentation.mp4)**
> and open it locally (any browser/VLC plays it). The raw paged action-log playback (76 MCP
> actions, 2:24) is also available:
> [download training-session-paged.mp4 (8 MB)](https://raw.githubusercontent.com/galvangabriel-web/agentropix-mcp/main/docs/12-CASES-REPORTS/vanko-report/training-session-paged.mp4).
> *Why no inline player: GitHub's Markdown sanitizer strips `<video>` tags entirely and renders
> `![ ](*.mp4)` as a broken image — repo-committed MP4s cannot play inline on github.com.*

**Correlate:** the no-malware counterpoint to the two intrusion cases — staged-archive exfiltration parallels [SRL-2015](srl-2015-report/README.md) (T1560.001), and anti-forensics defeat (VSS here, timestomp detection there) parallels [SRL-2018](srl-2018-report/SRL-2018-FORENSIC-REPORT.md).

**More in this case folder:**

- [vanko-report/README.md](vanko-report/README.md) — per-case folder guide for VANKO-ABDUCTED-ZEBRAFISH.
- [vanko-report/report.md](vanko-report/report.md) — the forensic synthesis report (evidence provenance, MD5/SHA1, full toolchain).
- [vanko-report/VANKO-EXFIL-CHAIN-WORKFLOW.md](vanko-report/VANKO-EXFIL-CHAIN-WORKFLOW.md) — end-to-end exfil-chain reconstruction workflow (file server → C: → USB → `vacation photos.7z` → cloud / university share) with exact timestamps.
- [vanko-report/diagrams/README.md](vanko-report/diagrams/README.md) — the five case diagrams (Mermaid sources + committed PNG renders).
- [vanko-report/wazuh/README.md](vanko-report/wazuh/README.md) — the 8 Wazuh egress evidence captures (narrated in WAZUH-VANKO-GALLERY.md).
- [vanko-report/toptier-results/README.md](vanko-report/toptier-results/README.md) — five parallel deep-recovery streams (VSS, pagefile/hiberfil, Windows.old, chat clients, carving) plus their [SYNTHESIS.md](vanko-report/toptier-results/SYNTHESIS.md).
- [vanko-report/ost-results/README.md](vanko-report/ost-results/README.md) — Outlook OST mailbox carve output (`carve_pst_iocs`) behind finding VANKO-P3-003.
- [vanko-report/extracted/README.md](vanko-report/extracted/README.md) — the intentionally-empty extraction destination Thymus rejected (policy-enforcement provenance note).

---

### CFReDS — Hacking Case (Greg Schardt / "Mr. Evil", unauthorized wireless interception)

The standalone **Windows XP** laptop of **Greg Schardt** (alias **"Mr. Evil"**, local admin RID 1003) used for **unauthorized wireless interception**: with a Compaq WL110 ORiNOCO 802.11b card + WinPcap/Ethereal/Cain & Abel (NetStumbler/Look@LAN for discovery), the actor captured a neighboring **Pocket PC's MSN/Hotmail session** including cleartext **.NET Passport `MSPAuth`/`MSPProf`** cookies (2004-08-27 15:36 GMT). Identity is corroborated across the local admin account, the Outlook Express mailbox `whoknowsme@sbcglobal.net`, the IRC persona `mrevilrulez`, and a Look@LAN registry real-name value. **A single-host disk case** — no enterprise lateral movement, no memory image (Volatility N/A). **35 examiner-approved findings** (2 critical / 15 high), 24 timeline events, 93 IOCs staged.

**Read in this order:**

1. [cfreds-hacking-case-report/README.md](cfreds-hacking-case-report/README.md) — per-case anchor: provenance (evidence `4Dell-Latitude-CPi.E01`, MD5 `aee4fcd9301c03b3b054623ca261959a`), headline numbers, the two smoking-gun findings, subfolder guides, and honest caveats/scope.
2. [cfreds-hacking-case-report/CFREDS-executive.md](cfreds-hacking-case-report/CFREDS-executive.md) — the executive summary: KPIs, the verdict, and the 17 critical/high findings in plain language.
3. [cfreds-hacking-case-report/CFREDS-analyst.md](cfreds-hacking-case-report/CFREDS-analyst.md) — the analyst / technical report: the 35-finding table, the full reconstructed 2004 kill-chain timeline (profile creation → toolkit install → wireless recon → the 15:36 interception → clean shutdown), the Key IOCs (identity, email, IPs, captured creds, tool hashes with VT ratios, hardware, services), and the honest negatives / scope.
4. [cfreds-hacking-case-report/diagrams/attack-graph.png](cfreds-hacking-case-report/diagrams/attack-graph.png) — the attack execution graph (identity chain + kill-chain, one visual).
5. [cfreds-hacking-case-report/audit/PROJECT-agent-execution-log.md](cfreds-hacking-case-report/audit/PROJECT-agent-execution-log.md) — the **agent execution log**: token usage, the 400-call tool-execution summary, the embedded forensic sub-agents, and a step-by-step trace.

**The two smoking-gun findings:** **CFREDS-EXT-15** (the Ethereal capture of a third party's Pocket PC MSN/Hotmail session + `.NET Passport` cookies) and **CFREDS-EXT-21** (the capstone correlation joining the identity chain to the attack chain). Run: single Claude-Code agent (`claude-opus-4-8[1m]`) + one embedded multi-agent forensic workflow · 400 tool calls · sealed/approved by examiner `victor.galvan` on 2026-06-14.

**Correlate:** a single-host **disk-only** scenario (no memory, no multi-host APT) — contrast with the enterprise intrusions [SRL-2015](srl-2015-report/README.md) / [SRL-2018](srl-2018-report/SRL-2018-FORENSIC-REPORT.md) and the malware-free insider case [VANKO](vanko-report/VANKO-FORENSIC-REPORT.md).

**Recorded execution-command replay** (5 min 22 s — every one of the 400 tool calls paired with its result/exit, 68 honest errors highlighted; built by [`make_execution_replay.py`](cfreds-hacking-case-report/make_execution_replay.py) from the audit trace):

[![CFReDS execution-command replay (animated teaser — click for the full MP4)](cfreds-hacking-case-report/EXECUTION-REPLAY-teaser.gif)](https://galvangabriel-web.github.io/agentropix-mcp/docs/12-CASES-REPORTS/cfreds-hacking-case-report/EXECUTION-REPLAY.mp4)

> ▶ Inline teaser loop (auto-plays on GitHub). GitHub can't inline-play the full repo MP4 — click the
> teaser for the GitHub Pages player, or
> ***[download the MP4 (13.5 MB, 5 min 22 s)](https://raw.githubusercontent.com/galvangabriel-web/agentropix-mcp/main/docs/12-CASES-REPORTS/cfreds-hacking-case-report/EXECUTION-REPLAY.mp4)***.

**More in this case folder:**

- [cfreds-hacking-case-report/CFREDS-HACKING-CASE-4DELL-executive.md](cfreds-hacking-case-report/CFREDS-HACKING-CASE-4DELL-executive.md) / [cfreds-hacking-case-report/CFREDS-HACKING-CASE-4DELL-analyst.md](cfreds-hacking-case-report/CFREDS-HACKING-CASE-4DELL-analyst.md) — the full server-rendered tier (every finding by stable Finding-ID with likelihood/confidence/risk-score, cross-linked executive↔analyst).
- [cfreds-hacking-case-report/CFREDS-report.html](cfreds-hacking-case-report/CFREDS-report.html) — self-contained HTML report (inline vector attack graph + legend + findings + IOCs + timeline); GitHub shows `.html` as source — download and open locally for the rendered single-file report.

---

### Cross-case artifact inventory

- [srl-2018-artifact-inventory.md](srl-2018-artifact-inventory.md) — SRL-2018 forensic artifact inventory (paths sanitized) mirrored from the engine repo, summarizing the per-host disk IOC extraction across the SRL-2018 dataset.
