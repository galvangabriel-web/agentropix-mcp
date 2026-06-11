#!/usr/bin/env bash
# Faithful REENACTMENT of the SRL-2015 investigation command timeline.
# Nothing here re-executes live ops — it replays the commands we ran and the real output we got.
set -u
PS='\033[1;32mexaminer@sift\033[0m:\033[1;34m~/agentropix-sift\033[0m$ '
T=${T:-0.7}      # base pause
banner(){ printf '\n\033[1;33m  ── %s ──\033[0m\n\n' "$1"; sleep "$T"; }
note(){ printf '\033[1;35m# %s\033[0m\n' "$1"; sleep 0.5; }
cmd(){ printf "%b" "$PS"; printf '\033[1;37m%s\033[0m\n' "$1"; sleep 0.9; }
out(){ printf '\033[2m%s\033[0m\n' "$1"; sleep 0.8; }

clear
printf '\033[1;36m'
cat <<'BANNER'
  ===========================================================
   SRL-2015-APT-ENTERPRISE  ·  Agentropix-SIFT investigation
   command replay  ·  4 hosts -> Wazuh -> VT/OTX -> deep RE
   (reenactment — no live ops re-executed)
  ===========================================================
BANNER
printf '\033[0m\n'; sleep 1.6

banner "0 · Recon & readiness"
cmd 'grep -rin "srl-2015" docs/ | head -3'
out 'docs/01-overview/user-guide.md: SRL-2015 SANS FOR508 Stark Research Labs APT (multi-host)'
cmd 'for p in 9200 55000; do (echo > /dev/tcp/<WAZUH-INDEXER>/$p) && echo "$p open"; done'
out '9200 open   55000 open      # real cluster reachable'
cmd 'bash ~/.openclaw/workspace/scripts/start-agentropix-mcp.sh status'
out 'verify: HTTP 200 on http://<MCP-HOST>:8765/mcp   tool_count=72'

banner "1 · Process 4 hosts (autonomous DFIR swarm, -n 15)"
cmd 'set -a; source .env; set +a   # AGENTROPIX_REDACTOR_HMAC_KEY (network IOCs)'
cmd 'agentropix-sift run /cases/SRL-2015/win7-32-nromanoff-c-drive/*.E01 -n 15 -o .../nromanoff/disk.json -v'
out '[swarm] memory|timeline|filesystem|artifact|discovery|hunt ... 250 findings'
cmd 'agentropix-sift run /cases/SRL-2015/xp-tdungan-c-drive/*.E01          -n 15 -o .../xp-tdungan/disk.json -v'
out '339 findings'
cmd 'agentropix-sift run /cases/SRL-2015/win7-64-nfury-c-drive/*.E01       -n 15 -o .../nfury/disk.json -v'
out '484 disk + 432 memory findings'
cmd 'agentropix-sift run /cases/SRL-2015/win2008R2-controller-c-drive/*.E01 -n 15 -o .../win2008R2/disk.json -v'
out '196 disk + 512 memory findings'
note '4/4 hosts complete = 2,233 findings'

banner "2 · Push findings to Wazuh (dry-run -> live, append/merge IOCs)"
cmd 'mcp wazuh_index_findings  --dry-run   # <WAZUH-INDEXER>:9200'
out 'dry_run_ok=true  would_index=680 new finding_ids'
cmd 'mcp wazuh_index_findings  --live'
out 'indexed 680 (additive, no duplicate _ids)'
cmd 'mcp wazuh_publish_iocs    --merge     # never remove other-case (VANKO) entries'
out 'merged into agentropix_malware_sha256   removed_other_case=false'

banner "3 · Threat-intel enrichment (VirtualTotal + AlienVault OTX)"
cmd 'set -a; source .env; set +a   # AGENTROPIX_VT_API_KEY / OTX / ALLOW_EGRESS=1'
cmd 'mcp threat_intel_lookup  --case SRL-2015-APT-ENTERPRISE   # VT 4/min paced'
out 'enriched 67 IOCs  ->  12 MALICIOUS  37 clean  42 unknown'
out 'f293fdb9 56/76 | 598e53b6 52/76 | e4fa730d 43/74 | 6eef2381 41/76 | 199.73.28.114 | bit.ly'

banner "4 · Verify live on the real cluster + screenshot"
cmd 'curl -sk -u $WAZUH_INDEXER_USER:*** "$IDX/agentropix-findings-*/_count?q=case_id:SRL-2015-APT-ENTERPRISE"'
out '{"count":2874}'
cmd 'curl -sk ... "$IDX/agentropix-iocs-*/_count" -d {verdict:malicious}'
out '{"count":12}'
cmd 'chrome --headless --screenshot   https://<WAZUH-INDEXER>:443  (Discover: agentropix-iocs-*)'
out 'saved a-discover-malicious-iocs.png  (12 hits, VT columns)'

banner "5 · Consolidated deliverable (PDF + IOC/EAR export)"
cmd 'mcp report_generate --profile full && report_generate --profile executive'
cmd 'chrome --headless --print-to-pdf  reports/SRL-2015-full-report.pdf      # 12 pages'
out 'SRL-2015-full-report.pdf  ·  SRL-2015-executive-summary.pdf (4 pages)'
cmd 'python build_exports.py   # iocs.csv / iocs.json / iocs-stix.json / ear.{csv,json}'
out '91 IOCs exported (STIX 2.1)   ·   17 EAR executables'

banner "6 · Collect + quarantine the executables (SAFE handling)"
cmd 'ewfmount /cases/SRL-2015/<host>-c-drive/*.E01 /mnt/ewf && mount -o ro,loop /mnt/ewf/ewf1 /mnt/ntfs'
out 'read-only mount  ·  carve usboesrv.exe a.exe spinlock.exe svchost.exe'
cmd 'zip -e -P infected quarantine/srl2015-samples.zip <carved>   # password-protected, exec bits stripped'
out '16 binaries carved  ·  SHA-256 manifest: 16/16 verified (0 mismatch)'

banner "7 · Recover memory-injection payloads (Volatility3 malfind)"
cmd 'vol -f /cases/SRL-2015/*-memory-raw.001 windows.malfind   # T1055 RWX VADs'
out 'pid 23476/26340/145896/151132 (controller) + 328 (nfury)  ->  5 payloads'
cmd 'sha256sum *.bin   # match vs IOCs'
out '42f33a83 73cb9ad7 e855864a dd8ac01d a8f9a210  ->  5/5 hash-verified'
cmd 'zip -e -P infected quarantine/srl2015-samples.zip *.bin   # append'
out 'quarantine now 21 entries (16 disk + 5 memory)'

banner "8 · Deep static RE of the 5 payloads (no execution)"
cmd 'unzip -P infected ... *malfind*.bin -d /tmp/inspect  &&  objdump -D -b binary -m i386 -M intel'
out '32-bit x86 VB6 loader · 8-byte len header · E9 JMP entry · API resolve-by-name'
out 'second stage = LZMA range-decoder -> in-memory unpack · 2 variants (A:17,18 / B:19,20,21)'
cmd 'yara -r srl2015_meminject.yar /tmp/inspect/   &&   rm -rf /tmp/inspect'
out 'srl2015_meminject  matches 5/5   ·   temp wiped'
cmd 'mcp wazuh_index_findings --live   # 10 deep-analysis findings'
out 'indexed 10  (source_run_id=srl2015-deep-mem-20260610, detector_source=manual.deep_re)'

banner "9 · Final deliverable"
cmd 'find Reports_results/SRL2015-DELIVERABLE -maxdepth 2 -type f | sort'
out 'reports/  SRL-2015-full-report.pdf  SRL-2015-executive-summary.pdf'
out 'exports/  iocs.csv  iocs.json  iocs-stix.json  ear.csv  ear.json'
out 'quarantine/  srl2015-samples.zip (21, pw:infected)  MANIFEST.csv  README.txt'
out 'deep-analysis/  *.pdf  srl2015_meminject.yar  disasm-variant{A,B}.txt'
out 'INDEX.md  (+ SHA-256 integrity of every file)'
printf '\n\033[1;32m  ✔ SRL-2015 investigation complete — 2233 findings · 2874 in Wazuh · 12 malicious · 21 samples\033[0m\n'
sleep 2.4
