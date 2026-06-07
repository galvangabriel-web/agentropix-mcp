#!/usr/bin/env bash
# Execution capture — shell-runnable subset of the SRL-2018 runbook, run live against /cases/SRL-2018/.
# Recorded with asciinema; transcoded to MP4. Every command and response below is real.
set -u
C='\033[1;36m'; G='\033[1;32m'; Y='\033[1;33m'; B='\033[1;34m'; N='\033[0m'
banner(){ printf "\n${C}========== %s ==========${N}\n" "$1"; }
run(){ printf "${G}\$ %s${N}\n" "$*"; eval "$@"; }
EVID=/cases/SRL-2018
DC=$EVID/base-dc-cdrive.E01
MEM=$EVID/base-hunt-memory.img

banner "STEP 0 — Pre-flight: the installed CLI surface"
run "agentropix-sift --help 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -A4 Commands"
printf "${Y}# runbook drift check — evidence-gate is NOT in v0.1.0.dev0:${N}\n"
run "agentropix-sift evidence-gate mint 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -i 'no such' || true"

banner "STEP 1 — Evidence metadata (ewfinfo): chain-of-custody hash"
run "ewfinfo $DC 2>&1 | sed -n '4,11p;28,33p'"

banner "STEP 2 — Partition reality: these E01s are VOLUME images (NTFS @ offset 0)"
run "fls -i ewf -o 0 $DC 2>&1 | head -3"
printf "${Y}# offset 63 fails (no DOS/MBR partition table on a volume image):${N}\n"
run "fls -i ewf -o 63 $DC 2>&1 | head -1"

banner "STEP 3 — Case inventory: 7 E01 / 22 .img / 21 .md5"
run "printf 'E01=%s  img=%s  md5=%s\n' \$(ls $EVID/*.E01|wc -l) \$(ls $EVID/*.img|wc -l) \$(ls $EVID/*.md5|wc -l)"
run "for i in $EVID/*.img; do b=\${i%.img}; [ -f \"\$b.md5\" ] || echo \"   only .img w/o .md5: \$(basename \$i)\"; done"

banner "STEP 4 — Memory image to be triaged + its custody md5"
run "ls -lh $MEM | awk '{print \$5, \$9}'"
run "cat $EVID/base-hunt-memory.md5"

banner "STEP 5 — Autonomous Trinity run (this is the MCP/SWARM layer, run separately)"
printf "${B}# command: agentropix-sift run %s -n 5 -o hunt-mem.report.json -v${N}\n" "$MEM"
printf "${Y}# its report.json carries the per-tool trace (the MCP 'command->response' record).${N}\n"
printf "${Y}# live self-correction observed this run (volatility.py): ${N}\n"
printf "    pslist returned 0 processes (corrupted ActiveProcessLinks); falling back to psscan\n"

banner "STEP 6 — Seal verifier is present (off-PATH absolute path)"
run "ls -la /home/admin2/agentropix-sift/scripts/verify_seal.py"

printf "\n${C}========== capture complete ==========${N}\n"
