#!/usr/bin/env bash
# RAW renderer: jq + ImageMagick + ffmpeg only. Storyboard JSON -> presentation mp4.
set -uo pipefail
STORY="${1:?storyboard.json}"
GAL=/home/admin2/docu_agentro/docs/12-CASES-REPORTS/vanko-report
DIAG="$GAL/diagrams"; OUT="$GAL/findings-presentation.mp4"
D=/tmp/im_frames; rm -rf "$D"; mkdir -p "$D"
W=1600; H=900; MX=64; CW=$((W-2*MX)); RM=$((W-MX))
convert -size ${W}x${H} gradient:'#11213d'-'#070d18' "$D/bg.png"
esc(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
# block OUT WIDTH MARKUP [BG PAD] -> BW BH
block(){ local out=$1 w=$2 m=$3 bg=${4:-none} pad=${5:-0}
  if [ "$bg" = none ]; then convert -background none -size ${w}x pango:"$m" "$out" 2>/dev/null
  else convert -background "$bg" -size ${w}x pango:"$m" -bordercolor "$bg" -border ${pad} "$out" 2>/dev/null; fi
  read BW BH < <(identify -format '%w %h' "$out"); }
place(){ convert "$CV" "$1" -geometry +${2}+${3} -composite "$CV"; }
panel(){ convert "$CV" -fill "$3" -stroke "$4" -strokewidth 2 -draw "roundrectangle $MX,$1 $RM,$2 12,12" "$CV"
         convert "$CV" -fill "$5" -stroke "$5" -draw "roundrectangle $MX,$1 $((MX+6)),$2 4,4" "$CV"; }  # y1 y2 fill stroke accent
redbox(){ convert "$CV" -fill none -stroke '#ff3b30' -strokewidth 3 -draw "roundrectangle $1,$2 $3,$4 9,9" "$CV"; }
newcv(){ CV="$D/$1.png"; cp "$D/bg.png" "$CV"; }
LST="$D/list.txt"; : > "$LST"
add(){ printf "file '%s'\nduration %s\n" "$D/$1.png" "$2" >> "$LST"; }
KICK(){ block "$D/k.png" $CW "<span foreground=\"#e6b450\" weight=\"bold\" size=\"15000\">$1</span>"; place "$D/k.png" $MX $2; }

n=$(jq '.scenes|length' "$STORY")

# ---------- TITLE ----------
newcv title
KICK "DIGITAL FORENSIC EXAMINATION · EVIDENCE PRESENTATION" 150
block "$D/b.png" $CW "<span foreground=\"#ffffff\" weight=\"bold\" size=\"39000\">$(esc "$(jq -r .title "$STORY")")</span>"; place "$D/b.png" $MX 205; Y=$((205+BH+24))
block "$D/b.png" $CW "<span foreground=\"#9fb0c6\" size=\"21000\">$(esc "$(jq -r .subtitle "$STORY")")</span>"; place "$D/b.png" $MX $Y; Y=$((Y+BH+26))
block "$D/b.png" $CW "<span foreground=\"#e6b450\" size=\"19000\">$(esc "$(jq -r .intro_line "$STORY")")</span>"; place "$D/b.png" $MX $Y
add title 6.5

# ---------- OVERVIEW (kill chain) ----------
newcv overview
KICK "THE KILL CHAIN AT A GLANCE · 8 FORENSIC STORES CONVERGE" 40
block "$D/b.png" $CW "<span foreground=\"#ffffff\" weight=\"bold\" size=\"30000\">One deliberate sequence — setup to cover-up</span>"; place "$D/b.png" $MX 78; Y=160
while IFS= read -r step; do
  block "$D/b.png" $CW "<span foreground=\"#dce8f6\" size=\"17500\">$(esc "$step")</span>"; place "$D/b.png" $MX $Y; Y=$((Y+BH+12))
done < <(jq -r '.kill_chain_summary[]' "$STORY")
add overview 15

# ---------- ARCH diagram ----------
if [ -f "$DIAG/d2.png" ]; then
  newcv arch; KICK "EXFILTRATION & BUYER-CHANNEL ARCHITECTURE" 40
  block "$D/b.png" $CW "<span foreground=\"#ffffff\" weight=\"bold\" size=\"30000\">How the data left the building</span>"; place "$D/b.png" $MX 78
  convert "$CV" \( "$DIAG/d2.png" -resize 1440x680 \) -gravity center -geometry +0+60 -composite "$CV"
  add arch 13
fi

# ---------- SCENES ----------
for i in $(seq 0 $((n-1))); do
  s=$(jq ".scenes[$i]" "$STORY"); no=$((i+1))
  title=$(jq -r '.title' <<<"$s"); fact=$(jq -r '.key_fact' <<<"$s")
  corr=$(jq -r '.correlation' <<<"$s"); mean=$(jq -r '.what_it_means' <<<"$s")
  # ----- EVIDENCE -----
  newcv sc${no}e; KICK "KEY FACT $no OF $n · EVIDENCE" 36; Y=70
  block "$D/b.png" $CW "<span foreground=\"#ffffff\" weight=\"bold\" size=\"27000\">$(esc "$title")</span>"; place "$D/b.png" $MX $Y; Y=$((Y+BH+12))
  block "$D/b.png" $CW "<span foreground=\"#dce8f6\" size=\"18500\">$(esc "$fact")</span>"; place "$D/b.png" $MX $Y; Y=$((Y+BH+18))
  na=$(jq '.artifacts|length' <<<"$s")
  for a in $(seq 0 $((na-1))); do
    [ $a -ge 3 ] && break
    src=$(jq -r ".artifacts[$a].source" <<<"$s"); loc=$(jq -r ".artifacts[$a].locator" <<<"$s"); shw=$(jq -r ".artifacts[$a].shows" <<<"$s")
    block "$D/b.png" $CW "<span font_family=\"DejaVu Sans Mono\" foreground=\"#5fb0f2\" size=\"14000\">$(esc "$src")</span>"; place "$D/b.png" $MX $Y; Y=$((Y+BH+5))
    block "$D/b.png" $((CW-24)) "<span font_family=\"DejaVu Sans Mono\" foreground=\"#ffd9d6\" weight=\"bold\" size=\"15500\">$(esc "$loc")</span>" '#16060a' 9
    place "$D/b.png" $MX $Y; redbox $((MX-2)) $((Y-2)) $((MX+BW+2)) $((Y+BH+2)); Y=$((Y+BH+4))
    block "$D/b.png" $CW "<span foreground=\"#aebfd6\" size=\"15000\">▸ $(esc "$shw")</span>"; place "$D/b.png" $MX $Y; Y=$((Y+BH+14))
  done
  block "$D/b.png" $CW "<span foreground=\"#52c98a\" weight=\"bold\" size=\"13500\">✓ EXAMINER-SEALED · proof red-boxed</span>"; place "$D/b.png" $MX 858
  de=$(awk -v l=${#fact} 'BEGIN{d=16+l/55; if(d>26)d=26; printf "%.1f",d}')
  add sc${no}e "$de"
  # ----- ANALYSIS -----
  newcv sc${no}a; KICK "KEY FACT $no OF $n · ANALYSIS" 36; Y=70
  block "$D/b.png" $CW "<span foreground=\"#aebfd6\" weight=\"bold\" size=\"22000\">$(esc "$title")</span>"; place "$D/b.png" $MX $Y; Y=$((Y+BH+16))
  block "$D/cb.png" $((CW-44)) "<span foreground=\"#e4edf8\" size=\"18000\">$(esc "$corr")</span>"; ch=$BH
  panel $Y $((Y+ch+58)) '#0d182c' '#243a60' '#5fb0f2'
  block "$D/h.png" $CW "<span foreground=\"#5fb0f2\" weight=\"bold\" size=\"14500\">WHY IT HOLDS — CROSS-ARTIFACT CORRELATION</span>"; place "$D/h.png" $((MX+20)) $((Y+14))
  place "$D/cb.png" $((MX+20)) $((Y+44)); Y=$((Y+ch+58+16))
  block "$D/mb.png" $((CW-44)) "<span foreground=\"#dfeee6\" size=\"18000\">$(esc "$mean")</span>"; mh=$BH
  panel $Y $((Y+mh+58)) '#0c2018' '#2c6b4c' '#52c98a'
  block "$D/h.png" $CW "<span foreground=\"#52c98a\" weight=\"bold\" size=\"14500\">WHAT IT MEANS TO THE CASE</span>"; place "$D/h.png" $((MX+20)) $((Y+14))
  place "$D/mb.png" $((MX+20)) $((Y+44))
  da=$(awk -v l=$(( ${#corr}+${#mean} )) 'BEGIN{d=15+l/58; if(d>32)d=32; printf "%.1f",d}')
  add sc${no}a "$da"
  echo "scene $no rendered (ev ${de}s / an ${da}s)"
done

# ---------- TIMELINE diagram ----------
if [ -f "$DIAG/d3.png" ]; then
  newcv tl; KICK "MASTER TIMELINE (UTC)" 40
  block "$D/b.png" $CW "<span foreground=\"#ffffff\" weight=\"bold\" size=\"30000\">One deliberate sequence — June 2016</span>"; place "$D/b.png" $MX 78
  convert "$CV" \( "$DIAG/d3.png" -resize 1440x700 \) -gravity center -geometry +0+60 -composite "$CV"
  add tl 15
fi

# ---------- CLOSING ----------
newcv closing; KICK "WHAT THE EVIDENCE PROVES — TOGETHER" 40
block "$D/b.png" $CW "<span foreground=\"#ffffff\" weight=\"bold\" size=\"30000\">Eight independent stores, one conclusion</span>"; place "$D/b.png" $MX 78
cf=$(jq -r '.closing_fact' "$STORY")
block "$D/cb.png" $((CW-44)) "<span foreground=\"#dfeee6\" size=\"19000\">$(esc "$cf")</span>"; ch=$BH
panel 150 $((150+ch+40)) '#0c2018' '#2c6b4c' '#52c98a'
place "$D/cb.png" $((MX+20)) 172
block "$D/b.png" $CW "<span foreground=\"#52c98a\" weight=\"bold\" size=\"18000\">✓ 8 INDEPENDENT STORES CORRELATED · INSIDER MISUSE, NOT MALWARE</span>"; place "$D/b.png" $MX $((150+ch+70))
add closing 18

# ---------- OUTRO ----------
newcv outro
block "$D/b.png" $CW "<span foreground=\"#ffffff\" weight=\"bold\" size=\"40000\">$(esc "$(jq -r .outro_line "$STORY")")</span>"; place "$D/b.png" $MX 360
block "$D/b.png" $CW "<span foreground=\"#52c98a\" size=\"22000\">Examiner-sealed · hash-chained · fully reproducible</span>"; place "$D/b.png" $MX 520
add outro 6

tail -2 "$LST" | head -1 >> "$LST"
ffmpeg -y -f concat -safe 0 -i "$LST" -vf "fps=25,scale=trunc(iw/2)*2:trunc(ih/2)*2" -pix_fmt yuv420p -movflags +faststart "$OUT" 2>/tmp/ff_im.log
echo "ffmpeg rc=$? | frames=$(grep -c duration "$LST") | dur=$(ffprobe -v error -show_entries format=duration -of default=nw=1 "$OUT" 2>/dev/null)"
