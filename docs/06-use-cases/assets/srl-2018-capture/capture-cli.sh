#!/usr/bin/env bash
# Capture script — runnable shell subset of docs/06-use-cases/case-runbook-srl-2018.md
# Recorded with asciinema; rendered to GIF with agg. Each command is real and run live.
set -u
C='\033[1;36m'; G='\033[1;32m'; Y='\033[1;33m'; R='\033[1;31m'; N='\033[0m'
banner(){ printf "\n${C}== %s ==${N}\n" "$1"; }
run(){ printf "${G}\$ %s${N}\n" "$*"; eval "$@"; }
EVID=/cases/SRL-2018
DC=$EVID/base-dc-cdrive.E01

banner "0. Pre-flight: the installed CLI (run + doctor only; NO evidence-gate)"
run "agentropix-sift --help 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -A4 Commands"
printf "${Y}# the runbook flags this drift: evidence-gate mint is NOT in v0.1.0.dev0 ->${N}\n"
run "agentropix-sift evidence-gate mint 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -i 'no such' || true"

banner "1a. Evidence metadata — ewfinfo (real acquisition hash + examiner)"
run "ewfinfo $DC 2>&1 | sed -n '4,12p;28,40p'"

banner "1b. Offset proof — these E01s are VOLUME images (NTFS at offset 0, not 63)"
run "fls -i ewf -o 0 $DC 2>&1 | head -3"
printf "${Y}# offset 63 fails on these volume images:${N}\n"
run "fls -i ewf -o 63 $DC 2>&1 | head -1"

banner "1c. Image type — img_stat"
run "img_stat $DC 2>&1 | head -7"

banner "2. Inventory facts — 7 E01, 22 .img, 21 .md5 (one dupe lacks md5)"
run "printf 'E01=%s img=%s md5=%s\n' \$(ls $EVID/*.E01 | wc -l) \$(ls $EVID/*.img | wc -l) \$(ls $EVID/*.md5 | wc -l)"
printf "${Y}# the one .img with no .md5 sibling:${N}\n"
run "for i in $EVID/*.img; do b=\${i%.img}; [ -f \"\$b.md5\" ] || echo \"   NO md5: \$(basename \$i)\"; done"

banner "3. Seal verifier is present (off-PATH; runbook gives the absolute path)"
run "ls -la /home/admin2/agentropix-sift/scripts/verify_seal.py"

printf "\n${C}== capture complete — CLI subset of the SRL-2018 runbook ==${N}\n"
