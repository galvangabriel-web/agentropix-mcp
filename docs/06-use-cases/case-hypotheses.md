# Per-Case Attack-Chain Hypotheses

> **Section 06 · Use Cases** — hypothesis-only scaffolds that steer tool selection for each of the
> in-scope test cases. These direct *which* MCP tools to reach for first; they are **not** findings.
> **Prove each link against live tool output before treating it as fact.**

Related: [User Guide](../01-overview/user-guide.md) (the runbook these scaffolds plug into) ·
[Disk triage](uc-disk-triage.md) · [Memory triage](uc-memory-triage.md) ·
[Wazuh push](uc-wazuh-push.md) · [Tool capability map](../04-mcp-tools/capability-map.md) ·
[`.crew/facts.md`](../../.crew/facts.md).

---

> **Read these as bias-checks, not conclusions.** Each hypothesis names a likely attack chain and the
> tools that would confirm or refute each link. Confidence is stated per case. Where a value is a
> PLACEHOLDER it is labelled — re-derive it live before quoting it.

---

## Contents — what's in this page (and what to expect)

> Jump to any case below. Each row tells you the attack-chain hypothesis and the tools it steers you toward, so you can go straight to the case you're working.

| Section | What you'll get |
|---|---|
| [Case 1 — SRL-2015 (multi-host APT, SANS FOR508)](#case-1--srl-2015-multi-host-apt-sans-for508) | The 4-host APT chain (phish → execution → persistence → LSASS → lateral → exfil) and the delivery/execution/lateral tools to confirm each link. |
| [Case 2 — SRL-2018 (network-wide APT C2 deployment)](#case-2--srl-2018-network-wide-apt-c2-deployment) | The C2-backbone cascade (DC→file→workstations→TS→DMZ-FTP), the svcsvc32 service lead, and which placeholders to re-derive live. |
| [Case 3 — cfreds-fresh (the validated example; insider misuse, Win XP)](#case-3--cfreds-fresh-the-validated-example-insider-misuse-win-xp) | The "Mr. Evil" insider-misuse chain (tooling → wireless recon → config → attribution) and the XP-aware tool picks (prefetch, no SRUM/amcache). |
| [Case 4 — rocba (insider IP theft, 2020)](#case-4--rocba-insider-ip-theft-2020) | The insider-IP-theft hypothesis with its APT-via-insider alternative, plus access/collection/USB/exfil tools and the memory scans that disambiguate. |
| [Related](#related) | Pointers to the runbook, end-to-end use cases, capability map, and canonical facts. |

---

## Case 1 — SRL-2015 (multi-host APT, SANS FOR508)

4 hosts (DC `win2008R2-controller` 10.3.58.4; workstations `win7-64-nfury`, `win7-32-nromanoff`,
`xp-tdungan`), each with C-drive E01 + memory raw + Mandiant `.mans`. Baselines for diffing:
`Win7SP1x86-baseline.img`, `XPSP3x86-baseline.img`. nromanoff has VSS (`volume-shadow.zip`).

**Chain:** spear-phish/web payload → execution (injected/RWX, prefetch/shimcache/amcache) →
persistence (Run keys/service/task) → credential access (LSASS) → lateral movement
workstation→DC → collection/exfil.

**Key tools:** delivery `run_bulk_extractor`/`analyze_maldoc`/`carve_pst_iocs`;
execution `get_malfind`/`build_process_tree`/`get_prefetch`; lateral `get_evtx` (4624 type 3/10,
4776) + `correlate_timeline` + `detect_sweep` + `pivot_on_ioc`.

*Confidence: MEDIUM on macro shape; LOW on host-of-initial-access until confirmed.* `.mans` files are
SQLite — query the **Processes** table for parent walks.

---

## Case 2 — SRL-2018 (network-wide APT C2 deployment)

Many E01s (`base-dc`, `base-file`, `base-rd-01/02`, `base-wkstn-01/05`, `dmz-ftp`) + per-host memory
`.img` (each with `.md5`).

**Backbone (MEDIUM-HIGH):** C2 IP **42.112.153.164:8080** (VT/OTX MALICIOUS); deployment window
**2018-05-03 14:22:15 → 15:15:45 UTC (~53 min)** cascading
DC→file→workstations→terminal servers→DMZ-FTP. Concrete malware lead: the **svcsvc32-class service
binary** across DC/file/rd-01/wkstn-01; typosquat delivery domain **`stark-research-labs.co`**.

**CAUTION (re-derive live):** "svchost.exe PID 1234 / parent System PID 4", service
"SuspiciousService", task `\Microsoft\Windows\Update Check` are PLACEHOLDER.

**Key tools:** `get_svcscan`+`scan_yara`(svcsvc32)+`get_malfind`; persistence `get_evtx`
(7045/4697/4698); cascade `detect_sweep`+`correlate_timeline`+`pivot_on_ioc` on the C2; intel
`threat_intel_lookup`/`wazuh_hunt_ioc`.

*Confidence: MEDIUM-HIGH on C2+cascade; LOW on exact process/service names.*

---

## Case 3 — cfreds-fresh (the validated example; insider misuse, Win XP)

Single XP disk (`4Dell-Latitude-CPi.E01` + `.E02`).

**Chain:** identity (alias "Mr. Evil" / Greg Schardt) → tooling (sniffer Ethereal/look@LAN,
wardriving NetStumbler, IRC, keyloggers) → wireless recon (NetStumbler `.ns1` logs) →
persistence/config (install locations, Run keys) → intent/attribution (emails, chat, docs tying alias
to serial `sn# VLQLW`).

**Key tools:** `get_prefetch` (XP has prefetch; NO SRUM/amcache), `get_registry`/`get_shimcache`,
`get_bstrings`+`glob_paths` for NetStumbler,
`run_bulk_extractor`/`email_header_matrix`/`carve_pst_iocs`, `get_timeline`+`get_mftecmd`.

*Confidence: MEDIUM-HIGH on scenario shape.*

---

## Case 4 — rocba (insider IP theft, 2020)

Single host: `rocba-cdrive.e01` (23.7 GB) + `Rocba-Memory.raw` (19.0 GB, zip→7z→raw wrapped); read
`ROCBA-BACKGROUND.pptx` first; case_id `ROCBA-HACKATHON-2026`. Host TZ EST5EDT — normalize to UTC.

**Leading hypothesis = insider IP theft; ALTERNATIVE = APT-via-insider — disambiguate, don't
confirm-bias.**

**Chain:** legitimate interactive logon (expect 4624 **type 2**, not external) → collection (R&D
files, archives, shares) → exfil via personal webmail (`fred.rocba@gmail.com`/`@outlook.com`), USB, or
cloud sync → optional anti-forensics → attribution.

**Key tools:** access `get_evtx`(4624 type 2)/`get_timeline`; collection
`get_mftecmd`($MFT/$J)/`get_sbecmd`(ShellBags)/`get_lecmd`; USB
`get_registry`(USBSTOR/MountedDevices); exfil
`srum_extract`(per-app net bytes)/`get_sqlecmd`(browser history)/`get_netscan`;
**disambiguation** `scan_yara`(Cobalt Strike)+`get_malfind`+`get_netscan` on memory — a C2/beacon
flips toward APT, absence supports pure insider.

*Confidence: MEDIUM on insider frame; actively test the APT alternative.*

---

> **Cross-case operator notes:** verify each E01/raw with `get_image_info`/`.md5`/`ewfverify` before
> reading; `.mans` files are SQLite, not zip; XP hosts (cfreds, xp-tdungan) have prefetch but NO
> SRUM/amcache.

---

## Related

- [User Guide](../01-overview/user-guide.md) — the 8-phase runbook these hypotheses steer.
- [Disk triage](uc-disk-triage.md) · [Memory triage](uc-memory-triage.md) — end-to-end use cases.
- [Tool capability map](../04-mcp-tools/capability-map.md) — pick tools by DFIR function.
- [`.crew/facts.md`](../../.crew/facts.md) — canonical numbers and case inventory.
