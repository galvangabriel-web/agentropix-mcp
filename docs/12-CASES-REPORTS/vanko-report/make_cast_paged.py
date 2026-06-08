import json, re
LOG="session-actions.log"
W, H = 150, 42
BODY = H-2
src=open(LOG,encoding="utf-8",errors="replace").read()
parts=re.split(r'(?=\x1b\[1;36m===== \[)', src)
blocks=[b for b in parts if '===== [' in b]
hdr={"version":2,"width":W,"height":H,"timestamp":1465000000,
     "title":"VANKO — agentropix-SIFT DFIR — paged session",
     "env":{"TERM":"xterm-256color","SHELL":"/bin/bash"}}
out=[json.dumps(hdr)]; t=0.0
def emit(s):
    global t; out.append(json.dumps([round(t,3),"o",s]))
CLR="\x1b[2J\x1b[3J\x1b[H"
BAR="\x1b[1;35m"+"="*78+"\x1b[0m\r\n"
intro=(BAR
     +"\x1b[1;37m  VANKO - The Case of the Abducted Zebrafish\x1b[0m\r\n"
     +"\x1b[1;37m  agentropix-SIFT DFIR investigation (paged playback)\x1b[0m\r\n"
     +("\x1b[0;37m  Insider IP-theft reconstruction - %d recorded actions - 5 forensic phases\x1b[0m\r\n"%len(blocks))
     +"\x1b[0;37m  10 confirmed findings (of 19) -> examiner HMAC -> Wazuh egress (ledger seq 139)\x1b[0m\r\n"
     +BAR)
emit(CLR+intro); t+=2.8
for b in blocks:
    lines=b.split("\n")
    while lines and lines[0].strip()=="": lines.pop(0)
    shown=lines[:BODY]
    extra=len(lines)-len(shown)
    page=CLR+"\r\n".join(shown)
    if extra>0:
        page+="\r\n\x1b[1;30m   ... (+%d more output lines - see transcript) ...\x1b[0m"%extra
    emit(page)
    dwell=min(2.6, 1.0 + 0.03*len(shown))
    t+=dwell
emit(CLR+("\x1b[1;32m  [ end of recorded session - %d actions - recording stopped ]\x1b[0m\r\n"%len(blocks))); t+=3.2
open("training-session-paged.cast","w").write("\n".join(out)+"\n")
print("paged cast: %d pages, %d events, ~%.0fs (%.1f min)"%(len(blocks),len(out)-1,t,t/60))
