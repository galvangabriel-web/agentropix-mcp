#!/usr/bin/env python3
import asyncio, json, os, html, subprocess, sys
GAL="/home/admin2/docu_agentro/docs/12-CASES-REPORTS/vanko-report"; DIAG=f"{GAL}/diagrams"
FR="/tmp/vanko_pres_frames"; os.makedirs(FR, exist_ok=True)
CHROME=os.path.expanduser("~/.cache/ms-playwright/chromium-1223/chrome-linux64/chrome"); W,H=1600,900
def esc(s): return html.escape(str(s))
CSS=f"""
*{{margin:0;box-sizing:border-box;font-family:ui-sans-serif,-apple-system,Segoe UI,Roboto,Arial}}
body{{width:{W}px;height:{H}px;background:linear-gradient(155deg,#0f1d36,#070d18 72%);color:#e8eef7;overflow:hidden;padding:38px 54px}}
.hd{{display:flex;align-items:center;gap:13px;margin-bottom:5px}}
.kick{{color:#e6b450;font-weight:800;letter-spacing:.15em;text-transform:uppercase;font-size:14px}}
.badge{{border:1px solid #2c5070;color:#5fb0f2;border-radius:999px;padding:3px 11px;font-size:13px;font-family:ui-monospace,monospace;max-width:760px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.cnt{{margin-left:auto;color:#566b8c;font-family:ui-monospace,monospace;font-size:14px}}
h1{{font-size:34px;line-height:1.08;letter-spacing:-.4px;margin:3px 0 8px}}
.fact{{color:#dce8f6;font-size:20px;line-height:1.4;border-left:5px solid #e6b450;padding-left:15px;margin-bottom:14px}}
.art{{background:#101c33;border:1px solid #243a60;border-radius:11px;padding:10px 13px;margin-bottom:10px}}
.art .src{{color:#5fb0f2;font-size:14px;font-family:ui-monospace,monospace;margin-bottom:7px}}
.pf{{position:relative;display:inline-block;margin:3px 0 7px}}
.pf .box{{border:3px solid #ff3b30;border-radius:8px;background:#16060a;color:#ffd9d6;font-family:ui-monospace,monospace;font-size:16px;font-weight:700;padding:9px 13px;box-shadow:0 0 0 4px rgba(255,59,48,.16),0 0 22px rgba(255,59,48,.36);max-width:1380px;word-break:break-word}}
.pf .tag{{position:absolute;top:-12px;left:11px;background:#ff3b30;color:#fff;font-weight:900;font-size:11px;letter-spacing:.05em;padding:2px 8px;border-radius:5px}}
.shows{{color:#aebfd6;font-size:15px}}
.panel{{background:#0d182c;border:1px solid #243a60;border-radius:12px;padding:15px 18px;margin-bottom:14px}}
.panel.corr{{border-left:6px solid #5fb0f2}} .panel.mean{{border-left:6px solid #52c98a;background:#0c2018}}
.panel h3{{font-size:15px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}}
.panel.corr h3{{color:#5fb0f2}} .panel.mean h3{{color:#52c98a}}
.panel p{{font-size:19px;line-height:1.45;color:#e4edf8}}
.foot{{position:absolute;bottom:22px;left:54px;color:#52c98a;font-weight:700;font-size:14px}}
.center{{display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;height:100%}}
.big{{font-size:60px;line-height:1.06;letter-spacing:-1.2px;max-width:25ch}}
.sub{{color:#9fb0c6;font-size:26px;margin-top:16px;max-width:42ch}}
.intro{{color:#e6b450;font-size:22px;margin-top:20px;max-width:50ch}}
.steps{{list-style:none;margin-top:10px;max-width:1480px}}
.steps li{{padding:7px 0;font-size:18px;line-height:1.32;border-bottom:1px dashed #243a60}}
.steps li b{{color:#e6b450;font-family:ui-monospace,monospace;margin-right:8px}}
.seal{{display:inline-block;border:3px solid #52c98a;color:#52c98a;border-radius:999px;padding:10px 24px;font-weight:800;font-size:19px;margin-top:24px}}
.imgwrap{{display:flex;flex-direction:column;height:100%}} .imgwrap img{{max-width:100%;max-height:740px;object-fit:contain;margin:auto;border:1px solid #243a60;border-radius:10px;background:#fff}}
"""
def head(): return f"<html><head><meta charset=utf-8><style>{CSS}</style></head><body>"
def art_html(a):
    return f"""<div class=art><div class=src>{esc(a['source'])}</div>
      <div class=pf><span class=tag>📍 PROOF</span><div class=box>{esc(a['locator'])}</div></div>
      <div class=shows>▸ {esc(a['shows'])}</div></div>"""
def ev_html(s,i,n):
    arts="".join(art_html(a) for a in s['artifacts'][:3])
    return head()+f"""<div class=hd><span class=kick>Key Fact {i} of {n} · Evidence</span><span class=badge>{esc(s['mitre'])}</span><span class=cnt>{i} / {n}</span></div>
    <h1>{esc(s['title'])}</h1><div class=fact>{esc(s['key_fact'])}</div>{arts}
    <div class=foot>✓ EXAMINER-SEALED · proof red-boxed</div></body></html>"""
def an_html(s,i,n):
    return head()+f"""<div class=hd><span class=kick>Key Fact {i} of {n} · Analysis</span><span class=cnt>{i} / {n}</span></div>
    <h1 style="font-size:26px;color:#aebfd6">{esc(s['title'])}</h1>
    <div class="panel corr"><h3>🔗 Why it holds — cross-artifact correlation</h3><p>{esc(s['correlation'])}</p></div>
    <div class="panel mean"><h3>⚖️ What it means to the case</h3><p>{esc(s['what_it_means'])}</p></div></body></html>"""
def title_html(s): return head()+f"""<div class=center><div class=kick>Digital Forensic Examination · Evidence Presentation</div><h1 class=big style="margin-top:10px">{esc(s['title'])}</h1><div class=sub>{esc(s['subtitle'])}</div><div class=intro>{esc(s['intro_line'])}</div></div></body></html>"""
def ov_html(s):
    steps="".join(f"<li><b>{i+1}</b>{esc(x)}</li>" for i,x in enumerate(s['kill_chain_summary']))
    return head()+f"""<div class=hd><span class=kick>The kill chain at a glance · 8 forensic stores converge</span></div><h1>One deliberate sequence — setup to cover-up</h1><ul class=steps>{steps}</ul></body></html>"""
def img_html(path,kick,title): return head()+f"""<div class=imgwrap><div class=hd><span class=kick>{esc(kick)}</span></div><h1>{esc(title)}</h1><img src="file://{path}"></div></body></html>"""
def close_html(s): return head()+f"""<div class=hd><span class=kick>What the evidence proves — together</span></div><h1 style="font-size:30px">Eight independent stores, one conclusion</h1><div class="panel mean" style="margin-top:6px"><p style="font-size:19px;line-height:1.45">{esc(s['closing_fact'])}</p></div><div style="text-align:center;margin-top:12px"><span class=seal>✓ 8 INDEPENDENT STORES CORRELATED · INSIDER MISUSE, NOT MALWARE</span></div></body></html>"""
def outro_html(s): return head()+f"""<div class=center><h1 class=big>{esc(s['outro_line'])}</h1><div class=sub style="color:#52c98a;margin-top:20px">Examiner-sealed · hash-chained · fully reproducible</div></div></body></html>"""
async def main():
    s=json.load(open(sys.argv[1])); sc=s['scenes']; n=len(sc)
    frames=[("title",title_html(s),6.5),("overview",ov_html(s),14.0)]
    if os.path.exists(f"{DIAG}/d2.png"): frames.append(("arch",img_html(f"{DIAG}/d2.png","Exfiltration & buyer-channel architecture","How the data left the building"),13.0))
    for i,x in enumerate(sc,1):
        de=15.0+min(13.0,(len(x['key_fact'])+sum(len(a['locator'])+len(a['shows']) for a in x['artifacts']))/52.0)
        da=14.0+min(18.0,(len(x['correlation'])+len(x['what_it_means']))/58.0)
        frames.append((f"sc{i:02d}e",ev_html(x,i,n),round(de,1)))
        frames.append((f"sc{i:02d}a",an_html(x,i,n),round(da,1)))
    if os.path.exists(f"{DIAG}/d3.png"): frames.append(("tl",img_html(f"{DIAG}/d3.png","Master timeline (UTC)","One deliberate sequence — June 2016"),15.0))
    frames+=[("closing",close_html(s),18.0),("outro",outro_html(s),6.0)]
    from playwright.async_api import async_playwright
    async with async_playwright() as p:
        b=await p.chromium.launch(executable_path=CHROME,headless=True,args=["--no-sandbox"])
        pg=await (await b.new_context(viewport={"width":W,"height":H})).new_page(); seq=[]
        over=[]
        for name,h,d in frames:
            f=f"{FR}/{name}.html"; open(f,"w").write(h)
            await pg.goto("file://"+f); await pg.wait_for_timeout(380)
            sh=await pg.evaluate("()=>document.body.scrollHeight"); 
            if sh>H+6: over.append((name,sh))
            png=f"{FR}/{name}.png"; await pg.screenshot(path=png); seq.append((png,d))
        await b.close()
    if over: print("WARN overflow frames:",over)
    lst=f"{FR}/list.txt"
    with open(lst,"w") as fh:
        for png,d in seq: fh.write(f"file '{png}'\nduration {d}\n")
        fh.write(f"file '{seq[-1][0]}'\n")
    out=f"{GAL}/findings-presentation.mp4"
    r=subprocess.run(["ffmpeg","-y","-f","concat","-safe","0","-i",lst,"-vf","fps=25,scale=trunc(iw/2)*2:trunc(ih/2)*2","-pix_fmt","yuv420p","-movflags","+faststart",out],capture_output=True,text=True)
    print("ffmpeg rc",r.returncode,"| frames",len(frames),"| total",round(sum(d for _,d in seq),1),"s (",round(sum(d for _,d in seq)/60,1),"min )")
    if r.returncode: print(r.stderr[-400:])
asyncio.run(main())
