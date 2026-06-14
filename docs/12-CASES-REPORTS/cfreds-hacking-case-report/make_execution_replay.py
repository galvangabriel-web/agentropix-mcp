#!/usr/bin/env python3
"""Paged execution-command replay for the CFReDS "Hacking Case".

Builds an asciinema v2 cast from audit/tool-execution-trace.jsonl, showing EVERY
tool call paired with its result/exit (errors highlighted), plus the agent's
reasoning lines, in a scrolling terminal with a live phase/step header bar.

Pipeline (matches the portal recorded-session recipe):
  python make_execution_replay.py
  agg --cols 150 --rows 42 --font-size 14 --fps-cap 8 --theme github-dark \
      EXECUTION-REPLAY.cast EXECUTION-REPLAY.gif
  ffmpeg -r 8 -i EXECUTION-REPLAY.gif -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" \
      -pix_fmt yuv420p -movflags +faststart EXECUTION-REPLAY.mp4
"""
import json, os

HERE = os.path.dirname(os.path.abspath(__file__))
TRACE = os.path.join(HERE, "audit", "tool-execution-trace.jsonl")
W, H = 150, 42
BODY = H - 3                      # rows reserved for the header bar
CAST = os.path.join(HERE, "EXECUTION-REPLAY.cast")

rows = [json.loads(l) for l in open(TRACE, encoding="utf-8", errors="replace") if l.strip()]

# ---- ANSI helpers ----
def c(s, code): return "\x1b[%sm%s\x1b[0m" % (code, s)
CLR = "\x1b[2J\x1b[3J\x1b[H"

def short_tool(t):
    return (t or "").replace("mcp__agentropix-sift__", "agentropix:").replace("mcp__", "")

def phase_of(tool):
    t = tool or ""
    if any(k in t for k in ("case_init", "case_activate", "evidence_register", "health", "case_status")): return "SETUP"
    if any(k in t for k in ("approve_finding", "index_findings")): return "APPROVAL"
    if "record_finding" in t or "delete_finding" in t: return "FINDINGS"
    if "record_timeline" in t: return "TIMELINE"
    if any(k in t for k in ("report_generate", "report_export")): return "REPORT"
    if any(k in t for k in ("threat_intel", "_hash", "exiftool")): return "ENRICH"
    if any(k in t for k in ("fls", "extract", "get_", "run_strings", "get_bstrings", "glob", "registry", "evtx", "evt", "shimcache")): return "COLLECT"
    return "ANALYZE"

def trunc(s, n):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"

# ---- cast assembly ----
hdr = {"version": 2, "width": W, "height": H, "timestamp": 1465000000,
       "title": "CFReDS Hacking Case — agentropix-SIFT — execution-command replay",
       "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"}}
out = [json.dumps(hdr)]
t = 0.0
def emit(s):
    global t
    out.append(json.dumps([round(t, 3), "o", s]))

n_calls = sum(1 for r in rows if r.get("kind") == "tool_call")
n_err = 0
screen = []   # rolling window of rendered lines
phase = "SETUP"
step_no = 0

def bar():
    left = c(" CFReDS · Greg Schardt / \"Mr. Evil\" ", "1;30;47")
    mid = c(" %-8s " % phase, "1;37;44")
    right = c(" call %d/%d " % (step_no, n_calls), "1;30;43")
    line = left + " " + mid + " " + right
    return line + "\r\n" + c("─" * (W - 2), "0;90") + "\r\n"

def repaint(dwell):
    global t
    win = screen[-BODY:]
    emit(CLR + bar() + "\r\n".join(win))
    t += dwell

# intro
BAR = c("═" * (W - 4), "1;35") + "\r\n"
intro = (CLR + BAR
         + c("  CFReDS \"Hacking Case\"  —  CFREDS-HACKING-CASE-4DELL", "1;37") + "\r\n"
         + c("  agentropix-SIFT autonomous DFIR — execution-command replay (every tool call + its exit)", "1;37") + "\r\n"
         + c("  Evidence: 4Dell-Latitude-CPi.E01 (MD5 aee4fcd9301c03b3b054623ca261959a)  ·  WinXP disk, no memory image", "0;37") + "\r\n"
         + c("  %d tool calls  ·  35 approved findings (2 critical / 15 high)  ·  24 timeline events  ·  examiner victor.galvan 2026-06-14" % n_calls, "0;37") + "\r\n"
         + BAR)
emit(intro); t += 3.4

i = 0
while i < len(rows):
    r = rows[i]
    k = r.get("kind")
    if k == "text":
        txt = trunc(r.get("detail", ""), W - 6)
        if txt:
            screen.append(c("  ⌁ " + txt, "0;33"))   # reasoning, dim yellow
            repaint(0.42)
        i += 1
    elif k == "tool_call":
        step_no += 1
        phase = phase_of(r.get("tool"))
        args = trunc(r.get("detail", ""), 104)
        screen.append(c("  ▸ ", "1;36") + c(short_tool(r.get("tool")), "1;37") + "  " + c(args, "0;37"))
        # pair with the next tool_result
        res = rows[i + 1] if i + 1 < len(rows) and rows[i + 1].get("kind") == "tool_result" else None
        dwell = 0.5
        if res is not None:
            status = (res.get("status") or "").lower()
            det = str(res.get("detail", ""))
            if status == "ok" and "error" not in det.lower():
                rc = res.get("result_chars", "")
                screen.append(c("      ✓ ok", "0;32") + c("  (%s chars)" % rc if rc else "", "0;90"))
            else:
                n_err += 1
                msg = trunc(det or status or "error", 120)
                screen.append(c("      ✗ " + msg, "1;31"))
                dwell = 0.95   # linger on errors / self-corrections
            i += 2
        else:
            i += 1
        repaint(dwell)
    else:
        i += 1   # stray result already consumed

# outro
screen.append("")
screen.append(c("  ✓ Investigation complete — 35 findings + 24 timeline events sealed (examiner HMAC).", "1;32"))
screen.append(c("  %d tool calls executed · %d returned an error/exit (honest negatives kept).", "0;37") % (n_calls, n_err))
repaint(0.1)
emit(CLR + bar() + "\r\n".join(screen[-BODY:]) + "\r\n" + c("  [ end of recorded execution — recording stopped ]", "1;32")); t += 3.4

open(CAST, "w").write("\n".join(out) + "\n")
print("cast: %s" % CAST)
print("pages/events: %d  ·  tool calls: %d  ·  errors shown: %d  ·  ~%.0fs (%.1f min)"
      % (len(out) - 1, n_calls, n_err, t, t / 60))
