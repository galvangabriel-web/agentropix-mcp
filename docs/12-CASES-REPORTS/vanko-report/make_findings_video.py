#!/usr/bin/env python3
import asyncio, json, os, html, subprocess, sys
GAL="/home/admin2/docu_agentro/docs/12-CASES-REPORTS/vanko-report"
FRAMES="/tmp/vanko_frames"; os.makedirs(FRAMES, exist_ok=True)
CHROME=os.path.expanduser("~/.cache/ms-playwright/chromium-1223/chrome-linux64/chrome")
W,H=1600,900
CSS="""
*{margin:0;box-sizing:border-box;font-family:ui-sans-serif,-apple-system,Segoe UI,Roboto,Arial}
body{width:1600px;height:900px;background:linear-gradient(160deg,#0e1a30,#070d18 70%);color:#e8eef7;overflow:hidden;padding:64px 80px;display:flex;flex-direction:column;justify-content:center}
.kick{color:#e6b450;font-weight:800;letter-spacing:.18em;text-transform:uppercase;font-size:18px}
.row{display:flex;align-items:center;gap:16px;margin:10px 0 6px}
.step{background:#e6b450;color:#06101e;font-weight:900;border-radius:10px;padding:6px 14px;font-size:20px}
.fid{font-family:ui-monospace,monospace;color:#9fb0c6;font-size:22px}
.badge{border:1px solid #2c5070;color:#5fb0f2;border-radius:999px;padding:4px 14px;font-size:18px;font-family:ui-monospace,monospace}
.conf{margin-left:auto;color:#52c98a;font-weight:800;font-size:18px;border:1px solid #2c6b4c;border-radius:999px;padding:4px 14px}
h1{font-size:62px;line-height:1.05;letter-spacing:-1px;margin:14px 0}
.proves{color:#cfe;font-size:30px;line-height:1.4;max-width:30ch;margin:6px 0 26px;border-left:5px solid #e6b450;padding-left:18px;font-style:italic}
.evlab{color:#92a6c0;text-transform:uppercase;letter-spacing:.1em;font-size:16px;margin-bottom:8px}
.evsrc{color:#9fb0c6;font-size:20px;margin-bottom:12px;font-family:ui-monospace,monospace}
.proofwrap{position:relative;display:inline-block;margin-top:6px}
.proof{border:4px solid #ff3b30;border-radius:12px;background:#14060a;color:#ffd9d6;font-family:ui-monospace,monospace;
  font-size:30px;font-weight:700;padding:22px 28px;box-shadow:0 0 0 7px rgba(255,59,48,.22),0 0 40px rgba(255,59,48,.45);max-width:34ch;word-break:break-word}
.tag{position:absolute;top:-18px;left:18px;background:#ff3b30;color:#fff;font-weight:900;font-size:15px;letter-spacing:.08em;
  padding:4px 12px;border-radius:7px;box-shadow:0 3px 10px rgba(0,0,0,.5)}
.foot{position:absolute;bottom:42px;left:80px;color:#52c98a;font-weight:700;font-size:18px;letter-spacing:.04em}
.cnt{position:absolute;bottom:42px;right:80px;color:#566b8c;font-family:ui-monospace,monospace;font-size:18px}
/* title/outro */
.center{align-items:center;justify-content:center;text-align:center}
.big{font-size:76px;line-height:1.05;letter-spacing:-1.5px}
.sub{color:#9fb0c6;font-size:32px;margin-top:18px;max-width:34ch}
.intro{color:#e6b450;font-size:26px;margin-top:26px}
.seal{display:inline-block;border:3px solid #52c98a;color:#52c98a;border-radius:999px;padding:12px 28px;font-weight:800;font-size:22px;letter-spacing:.05em;margin-top:30px}
"""

def card_html(c, idx, total):
    return f"""<html><head><meta charset=utf-8><style>{CSS}</style></head><body>
    <div class=kick>Evidence {idx} of {total} · Confirmed Finding</div>
    <div class=row><span class=step>STEP {c['kill_chain_step']}</span>
      <span class=fid>{html.escape(c['finding_id'])}</span>
      <span class=badge>{html.escape(c['technique'])}</span>
      <span class=conf>confidence {c['confidence']}</span></div>
    <h1>{html.escape(c['headline'])}</h1>
    <div class=proves>{html.escape(c['proves'])}</div>
    <div class=evlab>Evidence source — {html.escape(c['evidence_source'])}</div>
    <div class=proofwrap><span class=tag>📍 PROOF LOCATED HERE</span>
      <div class=proof>{html.escape(c['proof_locator'])}</div></div>
    <div class=foot>✓ EXAMINER-SEALED · HASH-CHAINED</div>
    <div class=cnt>{idx} / {total}</div>
    </body></html>"""

def title_html(s):
    return f"""<html><head><meta charset=utf-8><style>{CSS}</style></head><body class=center>
    <div class=kick>Digital Forensic Examination · Evidence Walkthrough</div>
    <h1 class=big>{html.escape(s['title'])}</h1>
    <div class=sub>{html.escape(s['subtitle'])}</div>
    <div class=intro>{html.escape(s['intro_line'])}</div>
    <div class=sub style="margin-top:22px;color:#52c98a">10 confirmed findings · each shown with its proof located in <span style="color:#ff6b63">red</span></div>
    </body></html>"""

def outro_html(s):
    return f"""<html><head><meta charset=utf-8><style>{CSS}</style></head><body class=center>
    <div class=kick>End of evidence walkthrough</div>
    <h1 class=big>{html.escape(s['outro_line'])}</h1>
    <div class=seal>✓ 10 FINDINGS · EXAMINER-SEALED · REPRODUCIBLE</div></body></html>"""

async def main():
    story=json.load(open(sys.argv[1]))
    from playwright.async_api import async_playwright
    cards=story['cards']; total=len(cards)
    frames=[("title", title_html(story), 5.0)]
    for i,c in enumerate(cards,1):
        # slower for denser 'proves' text
        dwell=7.0 + min(3.0, len(c['proves'])/55.0)
        frames.append((f"card{i:02d}", card_html(c,i,total), dwell))
    frames.append(("outro", outro_html(story), 5.0))
    async with async_playwright() as p:
        b=await p.chromium.launch(executable_path=CHROME,headless=True,args=["--no-sandbox"])
        pg=await (await b.new_context(viewport={"width":W,"height":H})).new_page()
        concat=[]
        for name,h,dwell in frames:
            f=f"{FRAMES}/{name}.html"; open(f,"w").write(h)
            await pg.goto("file://"+f); await pg.wait_for_timeout(350)
            png=f"{FRAMES}/{name}.png"; await pg.screenshot(path=png)
            concat.append((png,dwell))
        await b.close()
    # ffmpeg concat with per-frame durations -> slow, readable mp4
    lst=f"{FRAMES}/list.txt"
    with open(lst,"w") as fh:
        for png,d in concat:
            fh.write(f"file '{png}'\nduration {d}\n")
        fh.write(f"file '{concat[-1][0]}'\n")  # last frame repeat (concat demuxer quirk)
    out=f"{GAL}/findings-evidence-annotated.mp4"
    cmd=["ffmpeg","-y","-f","concat","-safe","0","-i",lst,"-vsync","vfr",
         "-pix_fmt","yuv420p","-r","25","-movflags","+faststart",
         "-vf","scale=trunc(iw/2)*2:trunc(ih/2)*2",out]
    r=subprocess.run(cmd,capture_output=True,text=True)
    print("ffmpeg rc",r.returncode)
    print("frames:",len(frames),"| total dwell:",round(sum(d for _,d in concat),1),"s")
    print("output:",out)
asyncio.run(main())
