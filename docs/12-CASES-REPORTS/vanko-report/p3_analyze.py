import json,re,glob,os
BS=chr(92)
def fld(raw,n):
    m=re.search(r'Name=[\'"]'+n+r'[\'"]\s*>([^<]*)<',raw); return m.group(1) if m else ''
# --- 4648 explicit-credential targets ---
d=json.load(open('step_p1_evtx_sec.json'))
seen={}
for e in d['events']:
    if str(e.get('event_id'))!='4648': continue
    r=e.get('raw','')
    tgt=fld(r,'TargetServerName') or fld(r,'TargetInfo'); usr=fld(r,'TargetUserName')
    proc=fld(r,'ProcessName').split(BS)[-1]
    k=(tgt,usr,proc); seen[k]=seen.get(k,0)+1
print(">> 4648 explicit-credential logons (target / user / process):")
for (t,u,p),n in sorted(seen.items(),key=lambda x:-x[1])[:12]:
    if t or u: print(f"   x{n:<4} target={t[:32]:32} user={u[:18]:18} proc={p[:22]}")

# --- email IOC analysis (gmail OST carve) ---
cf=glob.glob('ost-results/anthony.vanko@gmail.com*.carve.json')
if cf:
    M=json.load(open(cf[0])).get('messages',[])
    print(f"\n>> Email forensics — {len(M)} parsed messages")
    def has(m,*subs):
        b=(str(m.get('subject',''))+' '+str(m.get('sender',''))+' '+' '.join(m.get('recipients',[]))).lower()
        return any(s in b for s in subs)
    # recruitment / phishing delivery (inbound)
    print("   -- recruitment / opportunity / phishing-delivery subjects --")
    for m in M:
        s=str(m.get('subject',''))
        if re.search(r'opportunit|recruit|proposal|offer|confidential|research paper|potential',s,re.I):
            d2=str(m.get('date',''))[:25]; snd=str(m.get('sender',''))[:38]
            print(f"     {d2:25} att={m.get('n_attachments',0)} from={snd} | {s[:42]}")
    # ReadNotify tracking (email read-receipt service)
    rn=[m for m in M if has(m,'readnotify')]
    print(f"   -- ReadNotify email-tracking messages: {len(rn)} (e.g. {rn[0].get('subject','')[:40] if rn else '-'})")
    # internal Stark spear-phishing (kylie / stark / normandy)
    print("   -- internal (Kylie Normandy / Stark) correspondence --")
    kn=0
    for m in M:
        if has(m,'normandy','kylie.normandy'):
            kn+=1
            if kn<=4: print(f"     {str(m.get('date',''))[:25]:25} from={str(m.get('sender',''))[:30]} | {str(m.get('subject',''))[:38]}")
    print(f"     (total Kylie Normandy msgs: {kn})")
