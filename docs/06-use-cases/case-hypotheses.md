# Per-Case Attack-Chain Hypotheses

> **Section 06 · Use Cases** — hypothesis-only scaffolds that steer tool selection for each of the
> in-scope test cases. These direct *which* MCP tools to reach for first; they are **not** findings.
> **Prove each link against live tool output before treating it as fact.**

Related: [User Guide](../01-overview/user-guide.md) (the runbook these scaffolds plug into) ·
[Disk triage](uc-disk-triage.md) · [Memory triage](uc-memory-triage.md) ·
[Wazuh push](uc-wazuh-push.md) · [Tool capability map](../04-mcp-tools/capability-map.md) ·
[`canonical-facts.md`](../08-reference/canonical-facts.md).

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
- [`canonical-facts.md`](../08-reference/canonical-facts.md) — canonical numbers and case inventory.

---

## Implementation proof (source)

> **Section 06 · Use Cases › Case hypotheses › Implementation proof.** For developers: this maps each
> hypothesis link above to the **real MCP tool handler and wrapper** that confirms or refutes it.
> Every symbol is verifiable in the oracle (`/home/admin2/agentropix-sift/src`). The hypotheses are
> prose-only steering; the *muscle* that actually proves a link is the MCP tool layer below.

### How the tools are wired (two layers)

Each capability is a thin **MCP handler** in
`src/agentropix_sift/mcp_server/server.py`
— decorated with `@traced("<tool>")`, named `mcp_<tool>`, returning a typed Pydantic report or a
`ToolError` — that does rate-limit + Thymus read-policy checks, then delegates to a **wrapper** under
`src/agentropix_sift/mcp_server/wrappers/` which runs the underlying forensic binary and parses it into
a typed model. The handler shape is uniform, e.g. `server.py:mcp_get_malfind` (`server.py:459`):

```python
@traced("get_malfind")
async def mcp_get_malfind(image: str) -> MalfindReport | ToolError:
    rate_err = _rate_limiter.check("get_malfind")
    if rate_err: return ToolError(tool="get_malfind", error=rate_err)
    archive_err = _reject_archive("get_malfind", image)   # W-135 short-circuit
    if archive_err: return archive_err
    violation = _policy.check_read(image)                  # Thymus read zone
    if violation: return ToolError(tool="get_malfind", error=violation)
    return await get_malfind(image)                        # → wrappers/volatility.py
```

So "Key tools: `get_malfind` …" in every case maps to `server.py:mcp_get_malfind` →
`wrappers/volatility.py:get_malfind` (`volatility.py:798`, drives `windows.malfind.Malfind`).

### The four cross-artifact correlation tools (W-150…W-153)

These are what actually let a hypothesis "chain" be **proven across hosts** — they live in
`wrappers/correlation.py`
behind handlers at `server.py:562–730`:

| Hypothesis verb | MCP handler (`server.py`) | Wrapper (`correlation.py`) | What it proves |
|---|---|---|---|
| lateral movement workstation→DC / cascade ordering | `mcp_correlate_timeline` (562) | `correlate_timeline` (211) | Concurrent `get_evtx` over N images, merge + UTC-sort + `delta_ms` annotation |
| execution / injected-process parentage | `mcp_build_process_tree` (602) | `build_process_tree` (313) | PPID forest; flags LOLBin-under-system-parent as suspicious |
| "expand the C2 IP / service name everywhere" | `mcp_pivot_on_ioc` (633) | `pivot_on_ioc` (413) | One IOC fanned across `pslist`/`netscan`/`svcscan`/`evtx` on every host |
| share-enumeration burst (sweep) | `mcp_detect_sweep` (668) | `detect_sweep` (591) | Sliding-window over EID 5140/5145 → `SweepBurst` rows |

**Process-tree suspicion** (Case 1 "injected/RWX", Case 2 svchost lead) is a literal allow-list join in
`correlation.py:_is_suspicious` (`correlation.py:162`): a process whose name is in
`_SUSPICIOUS_PROCESS_NAMES` (`{"rubyw.exe","mshta.exe","wscript.exe","cscript.exe","regsvr32.exe","rundll32.exe","powershell.exe","pwsh.exe"}`,
`correlation.py:151`) parented by one of `_SENSITIVE_PARENTS`
(`{"services.exe","svchost.exe","lsass.exe","winlogon.exe","spoolsv.exe"}`, `correlation.py:157`) is
flagged with reason `"<name> spawned by <parent>"`.

**detect_sweep** is tuned to the SRL-2018 baseline named in the docstring (`detect_sweep` defaults
`window_seconds=1.0`, `min_shares_per_window=3`, EIDs `{5140, 5145}`; `correlation.py:591–622`) — it
groups EID 5140/5145 by source IP and slides a window, exactly the Case 2 "cascade" detector.

**pivot_on_ioc** (`correlation.py:413`) imports `get_evtx` + `get_netscan`/`get_pslist`/`get_svcscan`,
runs them per image via `asyncio.gather`, and substring-matches the IOC (`_match`, lower-cased) across
each record into `IOCHit` rows — this is the engine behind "`pivot_on_ioc` on the C2"
(`42.112.153.164` in Case 2; `fred.rocba@…` / USB serials in Case 4).

**correlate_timeline** (`correlation.py:211`) is the cross-host timeline: per-image `get_evtx` via
`asyncio.gather`, optional `window_start`/`window_end` UTC filter (the Case 2 `14:22:15 → 15:15:45`
window plugs straight into these args), merge-sort, then `row.delta_ms` between adjacent events.

### Per-case step → code path

**Case 1 — SRL-2015 (multi-host APT).** delivery `run_bulk_extractor` → `server.py:mcp_run_bulk_extractor`
(2235) → `wrappers/bulk_extractor.py`; `analyze_maldoc` → `server.py:2320`; `carve_pst_iocs` →
`wrappers/pst_carve.py`. execution `get_malfind`/`build_process_tree`/`get_prefetch` →
`mcp_get_malfind`(459)/`mcp_build_process_tree`(602)/`mcp_get_prefetch`(853). lateral `get_evtx`
(4624 type 3/10, 4776) → `mcp_get_evtx`(1940) with `event_ids=[...]` + `correlate_timeline` +
`detect_sweep` + `pivot_on_ioc` as above. The hypothesis note "`.mans` are SQLite, query Processes" is
honoured by `build_process_tree`'s PPID-forest model (`ProcessTreeReport`, roots/orphans/suspicious_count).

**Case 2 — SRL-2018 (C2 cascade).** `get_svcscan` → `mcp_get_svcscan`(488) →
`wrappers/volatility.py:get_svcscan`(929, runs `windows.svcscan.SvcScan` — finds the svcsvc32-class
service even if the process exited); `scan_yara`(svcsvc32) → `mcp_scan_yara`(2171) →
`wrappers/yara.py`; persistence `get_evtx`(7045/4697/4698) → `mcp_get_evtx`(1940); cascade trio =
`detect_sweep`+`correlate_timeline`+`pivot_on_ioc` (correlation.py); intel `threat_intel_lookup`
(EGRESS-GATED) → `wrappers/threat_intel.py:threat_intel_lookup`(357) and `wazuh_hunt_ioc` →
`wrappers/wazuh_tools.py:wazuh_hunt_ioc`(219). The PLACEHOLDER caveat is consistent with the code: these
handlers return *live-parsed* typed reports — no hard-coded process/service names.

**Case 3 — cfreds-fresh (Win XP, insider misuse).** The "XP has prefetch; NO SRUM/amcache" steering is
**enforced in code**: `mcp_get_evtx`(1940) detects image class and on XP/2003 short-circuits with
`image_class_detected="winxp_or_win2003"` + `skipped_reason` + `legacy_evt_files_found` (docstring
`server.py:1968–1971`, W-139) instead of silently returning zero events — so the operator is pushed to
`get_prefetch`/`get_bstrings` rather than modern artifacts. `get_prefetch` → `mcp_get_prefetch`(853) →
`wrappers/prefetch.py:get_prefetch`(228); `get_registry`/`get_shimcache` → `server.py:828`/`1708`;
`get_bstrings`(NetStumbler `.ns1`) → `mcp_get_bstrings`(1903) + `glob_paths` → `mcp_glob_paths`(2523);
email/attribution `run_bulk_extractor`(2235)/`email_header_matrix`/`carve_pst_iocs`; timeline
`get_mftecmd` → `mcp_get_mftecmd`(1758).

**Case 4 — rocba (insider IP theft, 2020).** access `get_evtx`(4624 **type 2**) → `mcp_get_evtx`(1940)
with `event_ids=[4624]` (logon-type filtering is on the parsed `raw` payload); collection
`get_mftecmd`($MFT/$J)(1758)/`get_sbecmd`(ShellBags)(1841)/`get_lecmd`(1786); USB
`get_registry`(USBSTOR/MountedDevices)(828); exfil `srum_extract`(per-app net bytes) →
`mcp_srum_extract`(876) → `wrappers/srum.py` (table GUIDs incl. `SRUM_TABLE_NETWORK_DATA`,
`srum.py:47`), `get_sqlecmd`(browser history)(1866), `get_netscan` → `mcp_get_netscan`(429); the
**APT-vs-insider disambiguation** is exactly `scan_yara`(2171)+`get_malfind`(459)+`get_netscan`(429)
on memory — a beacon/IOC hit flips the frame, and `pivot_on_ioc`(633) expands any hit across hosts.

### Where the proven links land (case binding)

A hypothesis only becomes a *finding* once its tool output is ingested under the case. That binding is
`wrappers/case_ingest.py`:
`idx_ingest(hostname, …, case_id=…)` (`case_ingest.py:103`) resolves the active case via
`get_active_case_id()` (raising if none is active), then `_stamp_timeline_event` (`case_ingest.py:65`)
stamps each event with `provenance=MCP`, `case_id`, and `host` — so the per-host evidence in Cases 1/2
(DC vs workstation vs DMZ-FTP) stays attributed to the right host and case through the
DRAFT/provenance/findings gate.

> **Net for developers:** the hypotheses are documentation; the *enforcement* is the typed MCP handler
> layer (`server.py:mcp_*`) over forensic-tool wrappers, with the four `correlation.py` tools doing the
> cross-host chaining and `case_ingest.py` binding proven links to a case.
