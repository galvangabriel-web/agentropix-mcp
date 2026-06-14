#!/usr/bin/env python3
# Multivariate dashboard of the whole-project agent execution chain.
import json, os
from datetime import datetime, timezone
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec

AUD = r"C:\xp\cfreds-investigation\audit"
def load(p):
    out=[]
    with open(p, encoding="utf-8") as f:
        for ln in f:
            ln=ln.strip()
            if ln:
                try: out.append(json.loads(ln))
                except: pass
    return out

steps = load(os.path.join(AUD,"tool-execution-trace.jsonl"))
agents = load(os.path.join(AUD,"workflow-agents.jsonl"))

def pt(s):
    if not s: return None
    try: return datetime.fromisoformat(s.replace("Z","+00:00")).astimezone(timezone.utc)
    except: return None

for s in steps: s["dt"]=pt(s.get("ts"))
steps=[s for s in steps if s["dt"]]
steps.sort(key=lambda s:s["dt"])
t0=steps[0]["dt"]; t1=steps[-1]["dt"]
mins=lambda d:(d-t0).total_seconds()/60.0
for s in steps: s["m"]=mins(s["dt"])
dur_min=mins(t1)

calls=[s for s in steps if s["kind"]=="tool_call"]
results=[s for s in steps if s["kind"]=="tool_result"]
errors=[s for s in results if s.get("status")=="ERROR"]

# unique assistant turns (dedupe token usage)
turns={}
for s in steps:
    if s["kind"] in ("tool_call","text") and s.get("out_tokens") is not None:
        key=(round(s["m"],4), s.get("out_tokens"), s.get("in_tokens"))
        turns[key]=dict(m=s["m"], out=s.get("out_tokens",0) or 0,
                        cr=s.get("cache_read",0) or 0, cc=s.get("cache_create",0) or 0)
turns=sorted(turns.values(), key=lambda x:x["m"])
tm=np.array([x["m"] for x in turns]); tout=np.array([x["out"] for x in turns])
cum=np.cumsum(tout)

# inter-step delays
dm=np.array([s["m"] for s in steps])
delays=np.diff(dm)*60.0  # seconds
delay_t=dm[1:]

def lbl(t):
    return (t or "").replace("mcp__agentropix-sift__","").replace("mcp__","")

# tool frequency
from collections import Counter
tc=Counter(lbl(s["tool"]) for s in calls)
top=tc.most_common(20)

# result sizes
rsz=np.array([s.get("result_chars",0) or 0 for s in results])

plt.rcParams.update({"font.size":9,"axes.titlesize":11,"axes.titleweight":"bold"})
fig=plt.figure(figsize=(22,28))
gs=GridSpec(6,2,figure=fig,hspace=0.42,wspace=0.22,height_ratios=[0.5,1,1,1,1,1])

# Banner
axb=fig.add_subplot(gs[0,:]); axb.axis("off")
kpi=(f"AGENTROPIX-SIFT DFIR — WHOLE-PROJECT EXECUTION ANALYSIS\n"
     f"Window: {t0:%Y-%m-%d %H:%M} → {t1:%H:%M} UTC  ({dur_min:.0f} min)   |   "
     f"Steps: {len(steps)}   Tool calls: {len(calls)}   Results: {len(results)}   Errors: {len(errors)}\n"
     f"Output tokens (main): {int(tout.sum()):,}   |   Workflow agents: {len(agents)}   "
     f"Workflow tool calls: {sum(a['tool_calls'] for a in agents)}   Workflow out-tokens: {sum(a['out_tokens'] for a in agents):,}")
axb.text(0.5,0.5,kpi,ha="center",va="center",fontsize=13,
         bbox=dict(boxstyle="round,pad=0.8",fc="#241a35",ec="#7b2cbf"),color="white")

# 1) Activity over time (calls per 10-min bucket)
ax1=fig.add_subplot(gs[1,0])
nb=max(8,int(dur_min/10))
ax1.hist([s["m"] for s in calls],bins=nb,color="#1d6fb8",alpha=0.85)
for e in errors: ax1.axvline(e["m"],color="#c0392b",lw=0.6,alpha=0.5)
ax1.set_title("1. Tool-call activity over time (10-min bins; red = errors)")
ax1.set_xlabel("minutes from start"); ax1.set_ylabel("tool calls")

# 2) Cumulative output tokens
ax2=fig.add_subplot(gs[1,1])
ax2.plot(tm,cum,color="#7b2cbf",lw=2)
ax2.fill_between(tm,cum,alpha=0.15,color="#7b2cbf")
ax2.set_title("2. Cumulative output tokens (main agent)")
ax2.set_xlabel("minutes from start"); ax2.set_ylabel("cum output tokens")

# 3) Per-turn output tokens (where the model generated most)
ax3=fig.add_subplot(gs[2,0])
ax3.scatter(tm,tout,s=14,color="#d97706",alpha=0.6)
ax3.set_title("3. Per-turn output tokens (generation spikes)")
ax3.set_xlabel("minutes from start"); ax3.set_ylabel("output tokens / turn")

# 4) Tool frequency (top 20)
ax4=fig.add_subplot(gs[2,1])
names=[t[0] for t in top][::-1]; vals=[t[1] for t in top][::-1]
ax4.barh(names,vals,color="#16a085")
for i,v in enumerate(vals): ax4.text(v+0.3,i,str(v),va="center",fontsize=8)
ax4.set_title("4. Tool-call frequency (top 20)"); ax4.set_xlabel("calls")

# 5) Inter-step delay distribution
ax5=fig.add_subplot(gs[3,0])
d=delays[delays>0]
ax5.hist(d,bins=np.logspace(np.log10(max(d.min(),0.05)),np.log10(d.max()+1),40),color="#34495e")
ax5.set_xscale("log")
ax5.set_title(f"5. Inter-step delay distribution (median {np.median(d):.1f}s, max {d.max():.0f}s)")
ax5.set_xlabel("delay between steps (s, log)"); ax5.set_ylabel("count")

# 6) Delay over time (where slowdowns happened)
ax6=fig.add_subplot(gs[3,1])
ax6.scatter(delay_t,delays,s=12,color="#c0392b",alpha=0.5)
ax6.set_title("6. Step latency over time (spikes = slow ops / waits)")
ax6.set_xlabel("minutes from start"); ax6.set_ylabel("delay to next step (s)")

# 7) Result-size distribution
ax7=fig.add_subplot(gs[4,0])
r=rsz[rsz>0]
ax7.hist(r,bins=np.logspace(np.log10(max(r.min(),1)),np.log10(r.max()+1),40),color="#8e44ad")
ax7.set_xscale("log")
ax7.set_title("7. Tool-result size distribution (chars, log)")
ax7.set_xlabel("result size (chars)"); ax7.set_ylabel("count")

# 8) Correlation: result size vs latency-to-next-step (colored by error)
ax8=fig.add_subplot(gs[4,1])
# delay to next step, aligned per step index
next_delay=np.append(np.diff(dm)*60.0, 0.0)
rc=[]; rl=[]; rcol=[]
for i,s in enumerate(steps):
    if s["kind"]=="tool_result":
        rc.append((s.get("result_chars",0) or 0)+1)
        rl.append(max(next_delay[i],0.01))
        rcol.append("#c0392b" if s.get("status")=="ERROR" else "#2980b9")
ax8.scatter(rc,rl,s=14,c=rcol,alpha=0.5)
ax8.set_xscale("log"); ax8.set_yscale("log")
ax8.set_title("8. Result size vs. latency-to-next-step (red=error)")
ax8.set_xlabel("result size (chars, log)"); ax8.set_ylabel("latency to next step (s, log)")

# 9) Workflow agents: tool calls
ax9=fig.add_subplot(gs[5,0])
ag=sorted(agents,key=lambda a:a["tool_calls"])
anames=[a["id"][:8] for a in ag]
ax9.barh(anames,[a["tool_calls"] for a in ag],color="#2c3e50")
for i,a in enumerate(ag): ax9.text(a["tool_calls"]+0.2,i,str(a["tool_calls"]),va="center",fontsize=8)
ax9.set_title("9. Workflow subagents — tool calls (11 agents)"); ax9.set_xlabel("tool calls")

# 10) Workflow agents: output tokens
ax10=fig.add_subplot(gs[5,1])
ag2=sorted(agents,key=lambda a:a["out_tokens"])
ax10.barh([a["id"][:8] for a in ag2],[a["out_tokens"] for a in ag2],color="#d35400")
for i,a in enumerate(ag2): ax10.text(a["out_tokens"]+50,i,f"{a['out_tokens']:,}",va="center",fontsize=8)
ax10.set_title("10. Workflow subagents — output tokens"); ax10.set_xlabel("output tokens")

fig.savefig(os.path.join(AUD,"execution-dashboard.png"),dpi=110,bbox_inches="tight",facecolor="white")
fig.savefig(os.path.join(AUD,"execution-dashboard.svg"),bbox_inches="tight",facecolor="white")
print("WROTE execution-dashboard.png / .svg")
print(f"steps={len(steps)} calls={len(calls)} results={len(results)} errors={len(errors)} dur_min={dur_min:.1f}")
print(f"out_tokens_main={int(tout.sum()):,} median_delay_s={np.median(d):.2f} max_delay_s={d.max():.0f}")
