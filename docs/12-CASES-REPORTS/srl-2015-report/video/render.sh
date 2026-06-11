#!/usr/bin/env bash
set -e
cd /home/admin2/agentropix-sift/Reports_results/SRL2015-DELIVERABLE/video
export TERM=xterm-256color

echo "[1/4] recording replay (asciinema)…"
asciinema rec --overwrite -c "bash playback.sh" session.cast >/dev/null 2>&1

echo "[2/4] widening cast to 132x46…"
python3 - <<'PY'
import json
lines=open('session.cast').read().splitlines()
h=json.loads(lines[0]); h['width']=132; h['height']=46
lines[0]=json.dumps(h)
open('session.cast','w').write("\n".join(lines)+"\n")
PY

echo "[3/4] rendering GIF (agg)…"
agg --theme monokai --font-size 18 --idle-time-limit 2 --speed 1.2 --fps-cap 12 \
    session.cast SRL-2015-investigation.gif

echo "[4/4] encoding MP4 (ffmpeg)…"
ffmpeg -y -loglevel error -i SRL-2015-investigation.gif \
    -movflags +faststart -pix_fmt yuv420p \
    -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" \
    SRL-2015-investigation.mp4

echo "=== output ==="
ls -la session.cast SRL-2015-investigation.gif SRL-2015-investigation.mp4
echo "duration:"; ffprobe -v error -show_entries format=duration -of default=nk=1:nw=1 SRL-2015-investigation.mp4 2>/dev/null
echo RENDER_DONE
