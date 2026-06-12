#!/usr/bin/env bash
# ISOLATED OST-investigation workflow (separate context — own log, no shared _step.sh / session-actions.log).
set -uo pipefail
export MCP_URL="http://100.85.162.82:8765/mcp"
export AGENTROPIX_MCP_AUTH_TOKEN="$(grep '^AGENTROPIX_MCP_AUTH_TOKEN' /home/admin2/agentropix-sift/.env | cut -d= -f2- | tr -d '"')"
MCP="python3 /home/admin2/.openclaw/workspace/drivers/mcp_call.py"
OUT=/home/admin2/docu_agentro/docs/12-CASES-REPORTS/vanko-report
LOG="$OUT/ost-investigation.log"; RES="$OUT/ost-results"; STR=/tmp/agentropix-sift-vanko/ost-strings
mkdir -p "$RES" "$STR"
log(){ printf '%s\n' "$*" | tee -a "$LOG"; }
: > "$LOG"
log "================ OST INVESTIGATION WORKFLOW · $(date -u +%FT%TZ) ================"
log "Isolated context: own log ($LOG), own results ($RES). Does not touch session-actions.log."

# Phase 1 — ensure all OST/PST are extracted (gmail, icloud, + OneDrive-cache OD-, non-(1) variants)
mkdir -p /tmp/agentropix-sift-vanko/outlook
log "[discover] extracting any additional OST from the image (OneDrive cache / variants)..."
$MCP extract_files '{"image":"/cases/vanko/surface_physical.E01","offset":1411072,"dest":"/tmp/agentropix-sift-vanko/outlook","paths":["/Users/PC User/AppData/Local/Microsoft/Outlook/anthony.vanko@gmail.com.ost"]}' > "$RES/_extra_extract.json" 2>&1 || true

mapfile -t OSTS < <(ls /tmp/agentropix-sift-vanko/outlook/*.ost /tmp/agentropix-sift-vanko/D/*.ost 2>/dev/null | xargs -I{} sh -c 'echo "$(stat -c%s "{}") {}"' | sort -u | awk '{ $1=""; sub(/^ /,""); print }' | awk '!seen[$0]++')
log "[discover] OST files to investigate: ${#OSTS[@]}"
n=0
for O in "${OSTS[@]}"; do
  n=$((n+1)); base=$(basename "$O"); sz=$(stat -c%s "$O" 2>/dev/null)
  log ""
  log "===== [$n] OST: $base ($sz B) ====="
  log "--- carve_pst_iocs (structured) ---"
  $MCP carve_pst_iocs "{\"path\":\"$O\"}" > "$RES/${base}.carve.json" 2>&1 || true
  python3 - "$RES/${base}.carve.json" <<'PY' 2>&1 | tee -a "$LOG" || true
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    print("  ", {k:(len(v) if isinstance(v,list) else v) for k,v in d.items() if k in ('emails','urls','ips','domains','ioc_count','message_count','error','message','tool')})
except Exception as e:
    import subprocess;print("   (raw)",subprocess.run(['head','-c','180',sys.argv[1]],capture_output=True,text=True).stdout)
PY
  log "--- strings analysis ---"
  { strings -a "$O"; strings -el "$O"; } 2>/dev/null > "$STR/${base}.strings"
  log "  Chinese contacts (qq/163/126/sina/foxmail / .cn):"
  grep -oiE '[a-z0-9._%+-]+@(qq|163|126|sina|foxmail)\.com|[a-z0-9.-]*(cas\.cn|\.edu\.cn)' "$STR/${base}.strings" | sort | uniq -c | sort -rn | head | sed 's/^/    /' | tee -a "$LOG"
  log "  dropbox / cloud share links:"
  grep -oiE 'https?://[a-z0-9./_-]*(dropbox|wetransfer|mega\.nz|pan\.baidu)[a-z0-9./_?=&%#-]*' "$STR/${base}.strings" | sort -u | head | sed 's/^/    /' | tee -a "$LOG"
  log "  case keywords:"
  grep -iE 'vacation photos|zebrafish|splice|cryoDNA|level [5678]|classified|mutant genome' "$STR/${base}.strings" | sort -u | head -8 | sed 's/^/    /' | tee -a "$LOG"
  log "  top external correspondents:"
  grep -oiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.(cn|com|edu|org|net)' "$STR/${base}.strings" | grep -vi 'vanko\|noreply\|no-reply\|@microsoft\|@apple\|@icloud.com$' | sort | uniq -c | sort -rn | head -14 | sed 's/^/    /' | tee -a "$LOG"
done
log ""
log "================ OST INVESTIGATION COMPLETE · $(date -u +%FT%TZ) ================"
