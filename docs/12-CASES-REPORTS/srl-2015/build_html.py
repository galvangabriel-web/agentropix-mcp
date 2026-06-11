#!/usr/bin/env python3
"""Render full + executive HTML reports for SRL-2015-APT-ENTERPRISE from MCP report_generate payloads."""
import base64, html, json, os

BASE = "/home/admin2/agentropix-sift/Reports_results/SRL2015-DELIVERABLE"
SHOTS = "/home/admin2/agentropix-sift/Reports_results/SRL2015-PIPELINE-V2/screenshots-reconcile"

full = json.load(open(f"{BASE}/full_report.json"))
exec_ = json.load(open(f"{BASE}/exec_report.json"))

CASE = full["case_id"]


def b64img(name):
    p = f"{SHOTS}/{name}.png"
    with open(p, "rb") as f:
        return "data:image/png;base64," + base64.b64encode(f.read()).decode()


SHOT_A = b64img("a-discover-malicious-iocs")
SHOT_B = b64img("b-malicious-ioc-expanded")
SHOT_C = b64img("c-case-findings-count")

# ------- shared data -------
findings = full["sections"]["findings"]["approved_findings"]
iocs = full["sections"]["iocs"]["iocs"]
by_type = full["sections"]["iocs"]["by_type"]
sev_mix = full["sections"]["executive_summary"]["severity_mix"]
sev_map = {s["severity"]: s["count"] for s in sev_mix}


def ioc_val(x):
    return x.get("ioc") or x.get("ioc_value") or ""


malicious = [x for x in iocs if x.get("threat_intel", {}).get("verdict") == "malicious"]

# Per-host finding summary (canonical aggregation from the pipeline)
HOST_ROWS = [
    ("win7-32-nromanoff", 250, 10, 260),
    ("xp-tdungan", 339, 10, 349),
    ("win7-64-nfury", 484, 432, 916),
    ("win2008R2-controller", 196, 512, 708),
]
TOTAL_FINDINGS = 2233
WAZUH_LIVE = 2874

# MITRE rollup from approved findings
from collections import Counter, OrderedDict
mitre_counter = Counter(f.get("mitre_attack", "-") for f in findings)
MITRE_NAMES = {
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1011": "Exfiltration Over Other Network Medium",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1055": "Process Injection",
    "T1620": "Reflective Code Loading",
    "T1036.005": "Masquerading: Match Legitimate Name or Location",
    "T1070.004": "Indicator Removal: File Deletion",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1569.002": "System Services: Service Execution",
    "T1078.002": "Valid Accounts: Domain Accounts",
    "T1005": "Data from Local System",
    "T1560.001": "Archive Collected Data: Archive via Utility",
    "T1052.001": "Exfiltration over Physical Medium: USB",
    "T1091": "Replication Through Removable Media",
    "T1070.006": "Indicator Removal: Timestomp",
}

SNAP = full["snapshot_at"]
RID_FULL = full["report_id"]
RID_EXEC = exec_["report_id"]

CSS = """
<style>
@page { size: A4; margin: 18mm 14mm; }
* { box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  color: #1a1d24; font-size: 11px; line-height: 1.5; margin: 0; }
h1 { font-size: 24px; margin: 0 0 4px; color: #0b1f3a; }
h2 { font-size: 16px; margin: 22px 0 8px; color: #0b1f3a; border-bottom: 2px solid #0b1f3a;
  padding-bottom: 3px; page-break-after: avoid; }
h3 { font-size: 13px; margin: 14px 0 6px; color: #243b5e; page-break-after: avoid; }
.hdr { background: linear-gradient(90deg,#0b1f3a,#1b3a6b); color:#fff; padding: 20px 22px; border-radius: 6px; }
.hdr .sub { color:#cfe0ff; font-size: 12px; margin-top: 4px; }
.meta { display:flex; flex-wrap:wrap; gap: 6px 24px; margin: 12px 0; font-size: 10px; color:#3a4252; }
.meta b { color:#0b1f3a; }
.classif { display:inline-block; background:#b3261e; color:#fff; font-weight:700; font-size:10px;
  letter-spacing:1px; padding:3px 10px; border-radius:3px; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 10px; }
th { background:#0b1f3a; color:#fff; text-align:left; padding:6px 8px; font-weight:600; }
td { padding:5px 8px; border-bottom:1px solid #e3e7ee; vertical-align: top; }
tr:nth-child(even) td { background:#f6f8fb; }
.mono { font-family: "SFMono-Regular", Consolas, Menlo, monospace; font-size: 9px; word-break: break-all; }
.badge { display:inline-block; padding:2px 7px; border-radius:10px; font-weight:700; font-size:9px; color:#fff; }
.b-crit { background:#7c1313; } .b-high { background:#b3261e; } .b-med { background:#c77700; }
.b-low { background:#2a7d2a; }
.v-mal { background:#b3261e; color:#fff; font-weight:700; padding:2px 7px; border-radius:3px; }
.v-clean { color:#2a7d2a; font-weight:600; }
.v-unk { color:#777; }
.malrow td { background:#fdecec !important; }
.cards { display:flex; gap:10px; flex-wrap:wrap; margin: 10px 0; }
.card { flex:1; min-width:120px; background:#f1f5fb; border:1px solid #d6e0ef; border-radius:6px;
  padding:10px 12px; text-align:center; }
.card .n { font-size:22px; font-weight:800; color:#0b1f3a; }
.card .l { font-size:9px; color:#56607a; text-transform:uppercase; letter-spacing:.5px; }
.shot { width:100%; border:1px solid #c9d2e0; border-radius:5px; margin:6px 0; }
.cap { font-size:9px; color:#56607a; font-style:italic; margin:-2px 0 12px; }
.callout { border-left:4px solid #b3261e; background:#fdf2f2; padding:9px 12px; border-radius:0 5px 5px 0;
  margin:10px 0; font-size:10.5px; }
.callout.ok { border-color:#2a7d2a; background:#f0f8f0; }
.callout.warn { border-color:#c77700; background:#fff7ec; }
.pgbreak { page-break-before: always; }
.foot { margin-top:18px; padding-top:8px; border-top:1px solid #d6e0ef; font-size:8.5px; color:#7a8398; }
ul { margin:6px 0 6px 18px; padding:0; } li { margin:2px 0; }
.kv { font-size:10px; }
</style>
"""


def sev_badge(s):
    cls = {"critical": "b-crit", "high": "b-high", "medium": "b-med", "low": "b-low"}.get(s, "b-low")
    return f'<span class="badge {cls}">{html.escape(s.upper())}</span>'


def header_block(title, rid):
    return f"""
<div class="hdr">
  <div class="classif">FOR OFFICIAL USE ONLY — DFIR</div>
  <h1>{html.escape(title)}</h1>
  <div class="sub">Case <b>{html.escape(CASE)}</b> &nbsp;·&nbsp; Agentropix-SIFT Forensic Pipeline</div>
</div>
<div class="meta">
  <span><b>Case ID:</b> {html.escape(CASE)}</span>
  <span><b>Snapshot:</b> {html.escape(SNAP)}</span>
  <span><b>Report ID:</b> <span class="mono">{html.escape(rid[:24])}…</span></span>
  <span><b>Hosts:</b> 4</span>
  <span><b>Approved findings:</b> {len(findings)}</span>
  <span><b>IOCs (enriched):</b> {len(iocs)}</span>
  <span><b>Malicious IOCs:</b> {len(malicious)}</span>
</div>
"""


def host_table():
    rows = ""
    for h, d, m, t in HOST_ROWS:
        rows += f"<tr><td class='mono'>{h}</td><td>{d}</td><td>{m}</td><td><b>{t}</b></td></tr>"
    return f"""
<table>
<tr><th>Host</th><th>Disk findings</th><th>Memory findings</th><th>Total</th></tr>
{rows}
<tr><td><b>TOTAL</b></td><td><b>1,269</b></td><td><b>964</b></td><td><b>{TOTAL_FINDINGS:,}</b></td></tr>
</table>
"""


def mitre_table():
    rows = ""
    for tech, cnt in mitre_counter.most_common():
        name = MITRE_NAMES.get(tech, "")
        rows += f"<tr><td class='mono'>{html.escape(tech)}</td><td>{html.escape(name)}</td><td>{cnt}</td></tr>"
    return f"""
<table>
<tr><th>ATT&amp;CK Technique</th><th>Name</th><th>Approved findings</th></tr>
{rows}
</table>
"""


def ioc_table(only_malicious=False):
    src = malicious if only_malicious else iocs
    rows = ""
    for x in src:
        ti = x.get("threat_intel", {})
        verdict = ti.get("verdict", "unknown")
        v = ioc_val(x)
        vtm = ti.get("vt_malicious")
        vtt = ti.get("vt_total")
        vt = f"{vtm}/{vtt}" if vtt else "—"
        otx = ti.get("otx_pulses")
        otx = str(otx) if otx is not None else "—"
        if verdict == "malicious":
            vbadge = '<span class="v-mal">MALICIOUS</span>'
            cls = "malrow"
        elif verdict == "clean":
            vbadge = '<span class="v-clean">clean</span>'
            cls = ""
        else:
            vbadge = f'<span class="v-unk">{html.escape(verdict)}</span>'
            cls = ""
        rows += (f"<tr class='{cls}'><td class='mono'>{html.escape(v)}</td>"
                 f"<td>{html.escape(x.get('ioc_type','-'))}</td><td>{vbadge}</td>"
                 f"<td>{vt}</td><td>{otx}</td></tr>")
    return f"""
<table>
<tr><th>Indicator</th><th>Type</th><th>Verdict</th><th>VT (mal/total)</th><th>OTX pulses</th></tr>
{rows}
</table>
"""


def findings_table():
    rows = ""
    for f in findings:
        rows += (f"<tr><td>{sev_badge(f['severity'])}</td>"
                 f"<td class='mono'>{html.escape(f.get('mitre_attack','-'))}</td>"
                 f"<td class='mono'>{html.escape(f['host'])}</td>"
                 f"<td>{html.escape(f['title'])}<br><span style='color:#56607a'>{html.escape(f.get('description','')[:320])}</span></td>"
                 f"<td>{f.get('confidence','')}</td></tr>")
    return f"""
<table>
<tr><th>Severity</th><th>ATT&amp;CK</th><th>Host</th><th>Finding</th><th>Conf.</th></tr>
{rows}
</table>
"""


WAZUH_CALLOUT = f"""
<div class="callout warn">
<b>Wazuh push status — DRY-RUN VERIFIED, LIVE FINDINGS PUSH BLOCKED (safety hold).</b><br>
Findings: dry-run validated all <b>{TOTAL_FINDINGS:,}</b> findings successfully
(<span class="mono">dry_run_ok=true</span>). Live indexing was <b>intentionally blocked</b>:
the sanctioned <span class="mono">wazuh_index_findings</span> bulk path auto-generates
<span class="mono">_id</span> (no deterministic <span class="mono">finding_id</span> keyed mapping),
so a live re-push would <b>duplicate</b> rather than replace. The index already holds
<b>2,194</b> SRL-2015 docs (1,590 distinct, 604 dup); ~<b>{WAZUH_LIVE:,}</b> evidence docs are
live across the case. A non-destructive deterministic-_id fix is not exposed by the approved tool, and
editing the sealed orchestrator / ADR-016 is a Hard-Stop — so the run halted rather than pollute evidence.
</div>
<div class="callout ok">
<b>IOC threat-intel lists (Wazuh CDB) — LIVE and merged.</b>
SRL-2015 malicious indicators are live in the active-response CDB lists:
<span class="mono">agentropix_malware_sha256</span> (47 total · 37 SRL-2015),
<span class="mono">agentropix_c2_ips</span> (8 · 6 SRL-2015),
<span class="mono">agentropix_persistence_regkey</span> (4 · 3),
<span class="mono">agentropix_suspect_process</span> (8 · 3). Vanko-case IOCs preserved (no deletions).
</div>
"""

SHOTS_BLOCK = f"""
<h2>Wazuh Console Evidence (reconciliation screenshots)</h2>
<p>Captured from the live Wazuh / Agentropix reconciliation console for case {html.escape(CASE)}.</p>
<h3>A — Malicious IOC discovery</h3>
<img class="shot" src="{SHOT_A}">
<div class="cap">a-discover-malicious-iocs.png — discovery view surfacing the case malicious indicators.</div>
<h3>B — Malicious IOC expanded (threat-intel verdict)</h3>
<img class="shot" src="{SHOT_B}">
<div class="cap">b-malicious-ioc-expanded.png — expanded IOC detail with VT/OTX enrichment verdict.</div>
<h3>C — Case findings count</h3>
<img class="shot" src="{SHOT_C}">
<div class="cap">c-case-findings-count.png — live case findings tally in the console.</div>
"""

FOOT = f"""
<div class="foot">
Generated by Agentropix-SIFT <span class="mono">report_generate</span> (MCP) ·
Full report_id <span class="mono">{RID_FULL}</span> ·
Snapshot {SNAP} · Provenance: MCP-sealed approved findings + VirusTotal/OTX enrichment ·
FOR OFFICIAL USE ONLY.
</div>
"""

# =================== FULL REPORT ===================
full_html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>{CASE} — Full Forensic Report</title>{CSS}</head><body>
{header_block(CASE + " — Full Forensic Report", RID_FULL)}

<h2>1. Case Summary</h2>
<p>This report consolidates the reconciled, approval-gated forensic findings for the multi-host
APT intrusion tracked as <b>{CASE}</b>. The campaign spans <b>4 acquired hosts</b> (disk + memory
images) processed through the Agentropix-SIFT Trinity pipeline. Aggregate raw findings total
<b>{TOTAL_FINDINGS:,}</b>; ~<b>{WAZUH_LIVE:,}</b> evidence documents are live on Wazuh. Of those,
<b>{len(findings)}</b> high-signal findings have been reviewed and approved for this report, and
<b>{len(iocs)}</b> indicators were enriched against VirusTotal + AlienVault OTX, confirming
<b>{len(malicious)} malicious</b> indicators.</p>

<div class="cards">
  <div class="card"><div class="n">4</div><div class="l">Hosts</div></div>
  <div class="card"><div class="n">{TOTAL_FINDINGS:,}</div><div class="l">Raw findings</div></div>
  <div class="card"><div class="n">{WAZUH_LIVE:,}</div><div class="l">Live on Wazuh</div></div>
  <div class="card"><div class="n">{len(findings)}</div><div class="l">Approved</div></div>
  <div class="card"><div class="n">{len(iocs)}</div><div class="l">IOCs enriched</div></div>
  <div class="card"><div class="n" style="color:#b3261e">{len(malicious)}</div><div class="l">Malicious IOCs</div></div>
</div>

<h3>Per-host finding counts</h3>
{host_table()}

<h3>Approved-finding severity mix</h3>
<table><tr><th>Severity</th><th>Count</th></tr>
<tr><td>{sev_badge('critical')}</td><td>{sev_map.get('critical',0)}</td></tr>
<tr><td>{sev_badge('high')}</td><td>{sev_map.get('high',0)}</td></tr>
<tr><td>{sev_badge('medium')}</td><td>{sev_map.get('medium',0)}</td></tr>
</table>

<h2 class="pgbreak">2. MITRE ATT&amp;CK Technique Rollup</h2>
<p>Techniques observed across the {len(findings)} approved findings:</p>
{mitre_table()}

<h2 class="pgbreak">3. Approved Findings</h2>
{findings_table()}

<h2 class="pgbreak">4. Indicators of Compromise — Threat-Intel Enrichment</h2>
<p>All {len(iocs)} enriched indicators with VirusTotal / OTX verdicts. The
<b>{len(malicious)} malicious</b> indicators are highlighted in red.</p>
<div class="callout"><b>{len(malicious)} confirmed-malicious indicators</b> — these gate the campaign verdict
and are live in the Wazuh active-response CDB lists.</div>
<h3>Malicious indicators (highlighted)</h3>
{ioc_table(only_malicious=True)}
<h3>Full indicator set ({len(iocs)})</h3>
{ioc_table(only_malicious=False)}

<h2 class="pgbreak">5. Wazuh Push Status</h2>
{WAZUH_CALLOUT}

{SHOTS_BLOCK}

{FOOT}
</body></html>"""

with open(f"{BASE}/reports/SRL-2015-full-report.html", "w") as f:
    f.write(full_html)

# =================== EXECUTIVE SUMMARY ===================
mal_rows = ""
MAL_LABEL = {
    "5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec": "DC C2 implant usboesrv.exe (KernelPro USB-over-Ethernet)",
    "598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec": "Campaign malware binary (52/76 detections)",
    "6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead": "Campaign malware binary (41/76 detections)",
    "e4fa730d00839aaaf4ae00fef4ab0854beccabfeb2541662a5391be85c48375c": "Campaign malware binary (43/74 detections)",
    "f293fdb96e6ed7e4ede7a173e5e47dd69a30edc6216e550787e7481d2df43cef": "Campaign malware binary (56/76 detections)",
    "199.73.28.114": "C2 / attacker-controlled IP",
    "bit.ly": "URL-shortener delivery/redirect domain",
}
for x in malicious:
    ti = x["threat_intel"]
    v = ioc_val(x)
    label = MAL_LABEL.get(v, "Malware artifact (low-prevalence detection)")
    mal_rows += (f"<tr class='malrow'><td class='mono'>{html.escape(v[:46])}{'…' if len(v)>46 else ''}</td>"
                 f"<td>{html.escape(x.get('ioc_type','-'))}</td>"
                 f"<td>{ti['vt_malicious']}/{ti['vt_total']}</td>"
                 f"<td>{html.escape(label)}</td></tr>")

exec_html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>{CASE} — Executive Summary</title>{CSS}</head><body>
{header_block(CASE + " — Executive Summary", RID_EXEC)}

<h2>Verdict</h2>
<div class="callout">
<b>CONFIRMED MULTI-HOST APT INTRUSION.</b> Forensic analysis of 4 hosts (disk + memory) produced
<b>{TOTAL_FINDINGS:,}</b> findings; ~<b>{WAZUH_LIVE:,}</b> evidence records are live on Wazuh.
<b>{len(findings)}</b> findings were reviewed and approved, including <b>1 critical</b> domain-controller
command-and-control implant. Threat-intel enrichment of {len(iocs)} indicators confirmed
<b>{len(malicious)} malicious</b> IOCs (VirusTotal + AlienVault OTX), establishing active attacker
infrastructure, custom malware, lateral movement, and data exfiltration.
</div>

<div class="cards">
  <div class="card"><div class="n">4</div><div class="l">Hosts compromised</div></div>
  <div class="card"><div class="n">{sev_map.get('critical',0)}</div><div class="l">Critical findings</div></div>
  <div class="card"><div class="n">{sev_map.get('high',0)}</div><div class="l">High findings</div></div>
  <div class="card"><div class="n" style="color:#b3261e">{len(malicious)}</div><div class="l">Malicious IOCs</div></div>
</div>

<h2>Key Findings</h2>
<ul>
<li><b>Critical — DC command-and-control.</b> An auto-start C2 implant (<span class="mono">usboesrv.exe</span>,
KernelPro USB-over-Ethernet) on the domain controller (win2008R2) beacons to
<span class="mono">96.255.98.154:29932</span>; corroborated by Volatility3 + Mandiant Redline.</li>
<li><b>Exfiltration confirmed.</b> Collected R&amp;D / classified data staged and archived
(<span class="mono">system4.rar</span>, header-encrypted) and exfiltrated over a physical USB device
(HP v100w S/N AA951D0000007252) on win7-64-nfury.</li>
<li><b>Lateral movement &amp; valid accounts.</b> PsExec hub-and-spoke movement from the xp-tdungan
operator console using compromised domain account <span class="mono">SHIELDBASE\\vibranium</span> reused
across hosts.</li>
<li><b>Custom in-memory malware &amp; anti-forensics.</b> PyInstaller/Metasploit reverse-TCP loaders,
masqueraded <span class="mono">svchost.exe</span> HTTP backdoors (httppump), and timestomping /
indicator-removal across nromanoff.</li>
<li><b>{len(malicious)} malicious indicators</b> confirmed by external threat intelligence and pushed
live to Wazuh active-response CDB lists.</li>
</ul>

<h2>The {len(malicious)} Malicious Indicators</h2>
{f'<table><tr><th>Indicator</th><th>Type</th><th>VT (mal/total)</th><th>Assessment</th></tr>{mal_rows}</table>'}

<h2 class="pgbreak">Wazuh / Containment Status</h2>
{WAZUH_CALLOUT}

<h3>Console evidence</h3>
<img class="shot" src="{SHOT_A}">
<div class="cap">Live Wazuh console — malicious IOC discovery for case {html.escape(CASE)}.</div>

<h2>Recommended Actions</h2>
<ul>
<li><b>Contain now:</b> isolate all 4 affected hosts; block C2 egress to
<span class="mono">96.255.98.154</span> and <span class="mono">199.73.28.114</span> at the perimeter.</li>
<li><b>Credentials:</b> disable / rotate <span class="mono">SHIELDBASE\\vibranium</span> and all domain
accounts observed reused across hosts; force enterprise-wide password reset and audit Kerberos tickets.</li>
<li><b>Eradicate:</b> remove the <span class="mono">usboesrv</span> service and unsigned
<span class="mono">usboebusdrv/usboeloaderdrv</span> kernel drivers from the DC; hunt the
{len(malicious)} malicious hashes enterprise-wide using the live Wazuh CDB lists.</li>
<li><b>Data-loss response:</b> treat exfiltrated Vibranium/Alloy R&amp;D + classified material as breached;
engage legal/IR per disclosure obligations. Physically recover/quarantine HP v100w USB device.</li>
<li><b>Resolve Wazuh push hold:</b> add a deterministic <span class="mono">_id=finding_id</span> ingest path
(approved change) so the {TOTAL_FINDINGS:,} findings can be indexed without duplicate-evidence pollution.</li>
<li><b>Forensic preservation:</b> maintain chain-of-custody on all images; the approval-gated findings
carry HMAC seals for evidentiary integrity.</li>
</ul>

{FOOT}
</body></html>"""

with open(f"{BASE}/reports/SRL-2015-executive-summary.html", "w") as f:
    f.write(exec_html)

print("WROTE full + executive HTML")
print("malicious:", len(malicious), "approved findings:", len(findings), "iocs:", len(iocs))
