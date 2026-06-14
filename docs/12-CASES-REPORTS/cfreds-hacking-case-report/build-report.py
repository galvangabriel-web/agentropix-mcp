# Build a standalone, self-contained HTML report (inlines the SVG attack graph).
import html, datetime, pathlib

BASE = pathlib.Path(r"C:\xp\cfreds-investigation")
svg = (BASE / "attack-graph.svg").read_text(encoding="utf-8", errors="replace")
# strip XML prolog/doctype so the SVG embeds cleanly inline
i = svg.find("<svg")
if i > 0:
    svg = svg[i:]

CASE = "CFREDS-HACKING-CASE-4DELL"
HOST = "MR-EVIL (N-1A9ODN6ZXK4LQ, Dell Latitude CPi, WinXP)"
EXAMINER = "victor.galvan"
GEN = "2026-06-14"

findings = [
 ("CFREDS-001-hacking-toolkit","high","Hacking toolkit installed/executed (Cain, Ethereal, NetStumbler, Look@LAN, Whois, 123WASP, mIRC)"),
 ("CFREDS-002-sniffing-wardriving","high","Network sniffing + wireless wardriving capability (WinPcap+Ethereal+Cain+NetStumbler)"),
 ("CFREDS-003-suspect-account-evasion","medium","Suspect admin account 'Mr. Evil' + anonymizer + suspicious batch file"),
 ("CFREDS-004-ioc-carve","informational","Bulk-extractor IOC carve summary (emails/domains/URLs/IPs)"),
 ("CFREDS-EXT-01-suspect-identity-greg-schardt","high","Suspect real identity: Greg Schardt behind alias 'Mr. Evil'"),
 ("CFREDS-EXT-02-oe-email-whoknowsme","high","Suspect OE email whoknowsme@sbcglobal.net (display 'Mr Evil')"),
 ("CFREDS-EXT-03-irc-identity-undernet","medium","IRC identity ties persona to Undernet"),
 ("CFREDS-EXT-04-removable-optical-disc-ghostware","high","Removable CD 'Jul 28 2004' (1A3AD55E) carried anonymizer+GhostWare+installers"),
 ("CFREDS-EXT-05-remote-share-4-12-220-254","high","Access to remote SMB share \\\\4.12.220.254\\Temp (host 'm1200')"),
 ("CFREDS-EXT-06-exec-hashes-toolkit","high","Hashes of recovered hacking-tool binaries"),
 ("CFREDS-EXT-07-pcap-wireless-services","high","Packet-capture & wireless services (NPF / rpcapd / wlluc48)"),
 ("CFREDS-EXT-08-userassist-execution","high","UserAssist/Prefetch prove execution of sniffing/cracking tools"),
 ("CFREDS-EXT-09-wardriving-intent-typedurls","medium","TypedURLs/cache show wardriving & 2600 intent"),
 ("CFREDS-EXT-10-ethereal-interception-capture","high","Ethereal capture 'interception' saved to Mr. Evil profile"),
 ("CFREDS-EXT-11-additional-hacking-tools","high","Secondary toolkit (John the Ripper, pwdump, netcat, NetBus, NAT, ToneLoc)"),
 ("CFREDS-EXT-12-newsgroups-subscribed","medium","Subscribed to hacking/phreaking newsgroups (alt.2600, alt.binaries.hacking)"),
 ("CFREDS-EXT-13-host-config-timezone","informational","Host config: ComputerName N-1A9ODN6ZXK4LQ, Central TZ"),
 ("CFREDS-EXT-14-recycler-deleted-execs","low","RECYCLER held deleted executables (Dc1-Dc4.exe)"),
 ("CFREDS-EXT-15-intercepted-pocketpc-hotmail","critical","SMOKING GUN: capture contains a third party's Pocket PC MSN/Hotmail session + .NET Passport cookies"),
 ("CFREDS-EXT-16-mirc-undernet-identity","medium","mIRC config confirms Undernet IRC identity (mrevilrulez/Mrevil)"),
 ("CFREDS-EXT-17-lookatlan-realname","medium","Look@LAN install log records real name 'Greg Schardt' in registry"),
 ("CFREDS-EXT-18-inbox-dbx-recovery","informational","Inbox.dbx = only default OE welcome message (no user mail)"),
 ("CFREDS-EXT-19-newsgroup-content-recovered","medium","alt.hacking posts: BIOS password hacking & stealing monster.com logins"),
 ("CFREDS-EXT-20-oe-account-whoknowsme","high","OE account binds whoknowsme@sbcglobal.net to profile (SBC/Dallas TX)"),
 ("CFREDS-EXT-21-master-correlation","critical","CAPSTONE: full identity + attack-chain correlation"),
 ("CFREDS-EXT-22-threat-intel-enrichment","medium","VT/OTX: Cain.exe confirmed malicious hacktool"),
 ("CFREDS-EXT-23-toolkit-hash-enrichment","medium","Hash + VT/OTX of remaining tool binaries & RECYCLER Dc#.exe"),
 ("CFREDS-EXT-24-irc-chatlogs","medium","mIRC chat logs: hacking/warez/shell channels as mrevilrulez"),
 ("CFREDS-EXT-25-ie-history-wardriving","high","IE history: wardriving/sniffing/hacker sites & download sources"),
 ("CFREDS-EXT-26-anonymizer-ghostware","medium","Anti-forensic/anonymity tooling: Anonymizer + GhostWare"),
 ("CFREDS-EXT-27-recycler-installers-identified","medium","Dc1-4 = deleted toolkit installers (Look@LAN/NetStumbler/WinPcap/Ethereal) via INFO2"),
 ("CFREDS-EXT-28-lookatlan-noscan-extra-irc","low","Look@LAN saved no scan results; extra warez/MP3/shell IRC"),
 ("CFREDS-EXT-29-wireless-nic-wardriving-hw","high","Wardriving hardware: Compaq WL110 (ORiNOCO 802.11b) PCMCIA card"),
 ("CFREDS-EXT-30-new-ioc-enrichment","low","VT/OTX of new browsing domains + wireless driver"),
 ("CFREDS-EXT-31-network-lateral-summary","high","Network activity & lateral-movement summary (adapters, DHCP, SMB, capture services)"),
]

iocs = [
 ("Identity","Greg Schardt; 'Mr. Evil' RID 1003; IRC mrevilrulez/Mrevil"),
 ("Email","whoknowsme@sbcglobal.net"),
 ("Hosts","pop/smtp.sbcglobal.net; news.dallas.sbcglobal.net; losangeles.ca.us.undernet.org:6660"),
 ("IPs","4.12.220.254 (SMB, m1200); 192.168.254.254 (WLAN gw)"),
 ("MAC","00:c0:02:b9:00:78"),
 ("Captured creds","MSPAuth / MSPProf .NET Passport cookies (victim)"),
 ("Hashes (flagged)","Cain.exe MD5 6767c8db317f2517dea73a00e00f0638 (VT 32/76); mirc.exe (VT 30/75)"),
 ("Cain SHA256","e2df120323e235137795a8a3240aa789ed2307ea36e3f5062139d849b81d365a"),
 ("Domains (flagged)","elitehackers.com, 2600.com (VT suspicious)"),
 ("Hardware","Compaq WL110 ORiNOCO 802.11b PCMCIA (wlluc48)"),
 ("Services","NPF (WinPcap), rpcapd (remote capture), wlluc48.sys"),
 ("Removable","CD 'Jul 28 2004' serial 1A3AD55E"),
]

timeline = [
 ("2004-08-19 22:48","Windows XP installed; RegisteredOwner Greg Schardt; 'Mr. Evil' admin created"),
 ("2004-08-20 ~10:30","mIRC active (mrevilrulez) in #Elite.Hackers/#evilfork/#ISO-WAREZ/#ushells; OE account whoknowsme@sbcglobal.net"),
 ("2004-08-25 10:55","Look@LAN installed; registry Nome='Greg Schardt'"),
 ("2004-08-25..27","Toolkit installed (Cain, Ethereal, WinPcap, NetStumbler); installers later deleted to RECYCLER"),
 ("2004-08-26 15:06","Remote SMB share \\\\4.12.220.254\\Temp (m1200) browsed"),
 ("2004-08-27 15:30/15:46","Wireless DHCP leases obtained (WL110 card)"),
 ("2004-08-27 15:36","INTERCEPTION: neighbor Pocket PC MSN/Hotmail session + Passport cookies captured"),
 ("2004-08-27 15:41","Capture file 'interception' written to Mr. Evil profile"),
 ("2004-08-27 15:46","Final clean shutdown"),
]

SEV = {"critical":"#a30000","high":"#d35400","medium":"#b8860b","low":"#1d6fb8","informational":"#5b6b73","info":"#5b6b73"}

def sev_badge(s):
    c = SEV.get(s.lower(), "#666")
    return f'<span class="badge" style="background:{c}">{html.escape(s.upper())}</span>'

rows = "\n".join(
    f"<tr><td class='mono'>{html.escape(fid)}</td><td>{sev_badge(sev)}</td><td>{html.escape(title)}</td></tr>"
    for fid, sev, title in findings
)
ioc_rows = "\n".join(f"<tr><td><b>{html.escape(k)}</b></td><td class='mono'>{html.escape(v)}</td></tr>" for k,v in iocs)
tl_rows = "\n".join(f"<tr><td class='mono nowrap'>{html.escape(t)}</td><td>{html.escape(e)}</td></tr>" for t,e in timeline)

from collections import Counter
cnt = Counter(s.lower().replace("info","informational") for _,s,_ in findings)
sev_summary = " &middot; ".join(f"{sev_badge(k)} {v}" for k,v in [("critical",cnt.get("critical",0)),("high",cnt.get("high",0)),("medium",cnt.get("medium",0)),("low",cnt.get("low",0)),("informational",cnt.get("informational",0))])

doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>DFIR Report - {html.escape(CASE)}</title>
<style>
 :root{{--ink:#1a2230;--mut:#5b6b73;--line:#dfe5ec;--bg:#f6f8fb;--card:#fff;--accent:#7b2cbf}}
 *{{box-sizing:border-box}} body{{margin:0;font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:var(--ink);background:var(--bg)}}
 .wrap{{max-width:1200px;margin:0 auto;padding:28px}}
 header{{background:linear-gradient(110deg,#241a35,#3a2a52);color:#fff;border-radius:14px;padding:26px 30px;box-shadow:0 6px 24px rgba(0,0,0,.15)}}
 header h1{{margin:0 0 6px;font-size:24px}} header .sub{{opacity:.85;font-size:14px}}
 .draft{{display:inline-block;margin-top:12px;background:#ffb020;color:#3a2a00;font-weight:700;padding:4px 12px;border-radius:999px;letter-spacing:.5px;font-size:12px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin:18px 0}}
 .kpi{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}}
 .kpi .n{{font-size:26px;font-weight:700}} .kpi .l{{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.4px}}
 section{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px 22px;margin:16px 0}}
 h2{{margin:0 0 12px;font-size:18px;border-left:4px solid var(--accent);padding-left:10px}}
 table{{width:100%;border-collapse:collapse;font-size:13.5px}} th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}}
 th{{background:#f0f3f8;font-size:12px;text-transform:uppercase;letter-spacing:.4px;color:var(--mut)}}
 .mono{{font-family:ui-monospace,Consolas,Menlo,monospace;font-size:12.5px}} .nowrap{{white-space:nowrap}}
 .badge{{color:#fff;border-radius:6px;padding:1px 8px;font-size:11px;font-weight:700;letter-spacing:.3px}}
 .graphbox{{overflow:auto;border:1px solid var(--line);border-radius:10px;background:#fff;padding:8px}}
 .graphbox svg{{max-width:100%;height:auto;display:block;margin:auto}}
 .legend{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px;margin-top:14px}}
 .lg{{display:flex;gap:8px;align-items:flex-start;font-size:13px}} .sw{{width:16px;height:16px;border-radius:4px;flex:0 0 16px;margin-top:2px;border:1px solid rgba(0,0,0,.2)}}
 .callout{{background:#fff4f4;border:1px solid #f0c0c0;border-radius:10px;padding:12px 14px;margin:10px 0;font-size:13.5px}}
 footer{{color:var(--mut);font-size:12px;text-align:center;margin:22px 0}}
 .neg li{{margin:3px 0}}
</style></head>
<body><div class="wrap">
<header>
 <h1>Digital Forensic Report &mdash; CFReDS &ldquo;Hacking Case&rdquo;</h1>
 <div class="sub">Case <b>{html.escape(CASE)}</b> &nbsp;|&nbsp; Host {html.escape(HOST)} &nbsp;|&nbsp; Examiner {html.escape(EXAMINER)} &nbsp;|&nbsp; Generated {GEN}</div>
 <span class="draft">STATUS: DRAFT &mdash; PENDING HMAC EXAMINER APPROVAL</span>
</header>

<div class="grid">
 <div class="kpi"><div class="n">{len(findings)}</div><div class="l">Findings (all DRAFT)</div></div>
 <div class="kpi"><div class="n">{len(timeline)}+</div><div class="l">Timeline anchors</div></div>
 <div class="kpi"><div class="n">2</div><div class="l">Critical findings</div></div>
 <div class="kpi"><div class="n">Greg Schardt</div><div class="l">Attributed actor</div></div>
</div>

<section>
 <h2>Executive summary</h2>
 <p>The standalone Windows&nbsp;XP laptop of <b>Greg Schardt</b> (alias <b>&ldquo;Mr.&nbsp;Evil&rdquo;</b>) was used to conduct <b>unauthorized wireless interception</b>. Using a Compaq&nbsp;WL110 ORiNOCO 802.11b card with WinPcap + Ethereal + Cain&nbsp;&amp;&nbsp;Abel and NetStumbler/Look@LAN for discovery, the actor captured a neighboring <b>Pocket&nbsp;PC&rsquo;s MSN/Hotmail session</b>, including cleartext <b>.NET Passport <span class="mono">MSPAuth/MSPProf</span></b> authentication cookies (2004-08-27 15:36). Identity is corroborated across the local admin account, the Outlook&nbsp;Express mailbox <span class="mono">whoknowsme@sbcglobal.net</span>, the IRC persona <span class="mono">mrevilrulez</span>, and a Look@LAN registry value recording the real name. Anti-forensic tooling (Anonymizer, GhostWare) and deleted toolkit installers were also recovered.</p>
 <p style="margin-bottom:0">Severity mix: {sev_summary}</p>
</section>

<section>
 <h2>Attack execution graph</h2>
 <div class="graphbox">{svg}</div>
 <div class="legend">
  <div class="lg"><span class="sw" style="background:#e8d5ff"></span><div><b>Actor / Identity</b> &mdash; the single attributed person and all aliases.</div></div>
  <div class="lg"><span class="sw" style="background:#fff2cc"></span><div><b>Entry / Phase boxes</b> &mdash; numbered kill-chain stages (1 entry &rarr; 7 anti-forensics).</div></div>
  <div class="lg"><span class="sw" style="background:#ffe5b4"></span><div><b>Tools / Hardware</b> &mdash; executables and the wireless card.</div></div>
  <div class="lg"><span class="sw" style="background:#cfe8ff"></span><div><b>Services / Drivers</b> &mdash; NPF, rpcapd, wlluc48.</div></div>
  <div class="lg"><span class="sw" style="background:#ffd6d6"></span><div><b>Victim</b> &mdash; the neighboring Pocket&nbsp;PC and its session.</div></div>
  <div class="lg"><span class="sw" style="background:#ffb3b3"></span><div><b>Theft</b> &mdash; captured credentials &amp; exfiltrated/accessed files.</div></div>
  <div class="lg"><span class="sw" style="background:#d9d9d9"></span><div><b>Anti-forensics</b> &mdash; anonymity tooling &amp; deleted installers.</div></div>
 </div>
</section>

<section>
 <h2>Timeline (2004)</h2>
 <table><thead><tr><th>When (UTC)</th><th>Event</th></tr></thead><tbody>
 {tl_rows}
 </tbody></table>
</section>

<section>
 <h2>Findings ({len(findings)} &mdash; all DRAFT, 0 approved)</h2>
 <table><thead><tr><th>Finding ID</th><th>Severity</th><th>Title</th></tr></thead><tbody>
 {rows}
 </tbody></table>
</section>

<section>
 <h2>Key indicators (IOCs)</h2>
 <table><tbody>
 {ioc_rows}
 </tbody></table>
 <div class="callout"><b>Withheld from external services (by design):</b> victim&rsquo;s captured Passport cookies and the private RFC1918 IP 192.168.254.254 &mdash; not submitted to VirusTotal/OTX.</div>
</section>

<section>
 <h2>Honest negatives / scope notes</h2>
 <ul class="neg">
  <li>Standalone WinXP workgroup host &mdash; <b>no enterprise lateral movement</b> (no domain, RDP, PsExec, pass-the-hash, or second compromised host).</li>
  <li><b>No memory image</b> &mdash; Volatility N/A; all execution evidence from disk artifacts.</li>
  <li>Windows XP <b>.evt</b> logs used (not .evtx); Security.evt empty. Amcache skipped (Win7+).</li>
  <li>Look@LAN saved <b>no scan-results</b> file; NetStumbler saved <b>no .ns1</b> session.</li>
  <li>Inbox.dbx held only the default OE welcome message; toolkit-installer binaries are VT-clean/known.</li>
 </ul>
</section>

<footer>
 Reports rendered from agentropix-SIFT case data. Findings remain DRAFT pending HMAC-signed examiner approval (W-288 sidecar).<br>
 Attack graph sources: attack-graph.svg / .mmd / .dot &mdash; this page embeds the vector SVG inline (self-contained).
</footer>
</div></body></html>"""

out = BASE / "CFREDS-report.html"
out.write_text(doc, encoding="utf-8")
print("WROTE", out, len(doc), "bytes")
