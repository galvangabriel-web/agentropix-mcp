#!/usr/bin/env python3
# Full-project Agent Execution Log builder (mandate #8).
# Parses the main session transcript (single-agent tool execution + token usage)
# AND the multi-agent workflow subagent transcripts (per-agent tool sequences).
import json, os, glob, datetime

PROJ = r"C:\Users\admin\.claude\projects\C--xp"
SID  = "ae783592-726b-42df-aa10-d22a7fc3fca1"
MAIN = os.path.join(PROJ, SID + ".jsonl")
WFDIR = os.path.join(PROJ, SID, "subagents", "workflows", "wf_e22ed84e-e9e")
OUT  = r"C:\xp\cfreds-investigation\audit"

def short(s, n=200):
    if s is None: return ""
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[:n] + " ..."

def load(path):
    rows = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try: rows.append(json.loads(line))
            except Exception: pass
    return rows

def parse_transcript(rows):
    """Return (steps, totals) for one transcript (main or subagent)."""
    steps = []
    call_by_id = {}
    tot = dict(out=0, inp=0, cr=0, cc=0)
    sidx = 0
    for o in rows:
        t = o.get("type")
        ts = o.get("timestamp", "")
        if t == "assistant":
            msg = o.get("message", {}) or {}
            u = msg.get("usage", {}) or {}
            out = int(u.get("output_tokens", 0) or 0)
            inp = int(u.get("input_tokens", 0) or 0)
            cr  = int(u.get("cache_read_input_tokens", 0) or 0)
            cc  = int(u.get("cache_creation_input_tokens", 0) or 0)
            tot["out"] += out; tot["inp"] += inp; tot["cr"] += cr; tot["cc"] += cc
            model = msg.get("model", "")
            for c in (msg.get("content") or []):
                ct = c.get("type")
                if ct == "text" and c.get("text", "").strip():
                    sidx += 1
                    steps.append(dict(step=sidx, ts=ts, actor="assistant", kind="text",
                                      detail=short(c.get("text"), 240), out_tokens=out,
                                      in_tokens=inp, cache_read=cr, cache_create=cc, model=model))
                elif ct == "tool_use":
                    sidx += 1
                    inp_j = short(json.dumps(c.get("input", {}), ensure_ascii=False), 220)
                    call_by_id[c.get("id")] = c.get("name")
                    steps.append(dict(step=sidx, ts=ts, actor="assistant", kind="tool_call",
                                      tool=c.get("name"), detail=inp_j, out_tokens=out,
                                      in_tokens=inp, cache_read=cr, cache_create=cc, model=model))
        elif t == "user":
            msg = o.get("message", {}) or {}
            cont = msg.get("content")
            if isinstance(cont, list):
                for c in cont:
                    if isinstance(c, dict) and c.get("type") == "tool_result":
                        sidx += 1
                        body = c.get("content")
                        if isinstance(body, list):
                            txt = " ".join(b.get("text", "") for b in body if isinstance(b, dict))
                        else:
                            txt = str(body)
                        steps.append(dict(step=sidx, ts=ts, actor="tool", kind="tool_result",
                                          tool=call_by_id.get(c.get("tool_use_id"), "(unknown)"),
                                          status="ERROR" if c.get("is_error") else "ok",
                                          result_chars=len(txt), detail=short(txt, 160)))
    return steps, tot

# ---- main transcript ----
main_rows = load(MAIN)
steps, tot = parse_transcript(main_rows)
calls = [s for s in steps if s["kind"] == "tool_call"]
results = [s for s in steps if s["kind"] == "tool_result"]
errors = [s for s in results if s.get("status") == "ERROR"]
tally = {}
for s in calls: tally[s["tool"]] = tally.get(s["tool"], 0) + 1
ts_all = [s["ts"] for s in steps if s.get("ts")]
first_ts, last_ts = (ts_all[0], ts_all[-1]) if ts_all else ("", "")

# ---- workflow subagents ----
wf_agents = []
for jf in sorted(glob.glob(os.path.join(WFDIR, "agent-*.jsonl"))):
    aid = os.path.basename(jf).replace("agent-", "").replace(".jsonl", "")
    rows = load(jf)
    a_steps, a_tot = parse_transcript(rows)
    a_calls = [s for s in a_steps if s["kind"] == "tool_call"]
    a_tcall = {}
    for s in a_calls: a_tcall[s["tool"]] = a_tcall.get(s["tool"], 0) + 1
    # role = first user prompt's first line
    role = ""
    for o in rows:
        if o.get("type") == "user":
            cont = (o.get("message", {}) or {}).get("content")
            if isinstance(cont, list):
                for c in cont:
                    if isinstance(c, dict) and c.get("type") == "text":
                        role = short(c.get("text"), 130); break
            elif isinstance(cont, str):
                role = short(cont, 130)
            if role: break
    a_ts = [s["ts"] for s in a_steps if s.get("ts")]
    wf_agents.append(dict(id=aid, role=role, tool_calls=len(a_calls),
                          out_tokens=a_tot["out"], in_tokens=a_tot["inp"],
                          cache_read=a_tot["cr"], cache_create=a_tot["cc"],
                          first=a_ts[0] if a_ts else "", last=a_ts[-1] if a_ts else "",
                          top_tools=", ".join(f"{k}:{v}" for k,v in sorted(a_tcall.items(), key=lambda x:-x[1])[:6])))

wf_out = sum(a["out_tokens"] for a in wf_agents)
wf_calls = sum(a["tool_calls"] for a in wf_agents)

# ---- write JSONL traces ----
with open(os.path.join(OUT, "tool-execution-trace.jsonl"), "w", encoding="utf-8") as f:
    for s in steps: f.write(json.dumps(s, ensure_ascii=False) + "\n")
with open(os.path.join(OUT, "workflow-agents.jsonl"), "w", encoding="utf-8") as f:
    for a in wf_agents: f.write(json.dumps(a, ensure_ascii=False) + "\n")

# ---- write master markdown ----
L = []
L.append("# Project Agent Execution Log — Agentropix-SIFT DFIR session")
L.append("")
L.append("**Submission type:** Single-agent (Claude Code, `claude-opus-4-8[1m]`) + one embedded multi-agent workflow.")
L.append(f"**Session ID:** {SID}")
L.append(f"**Window (UTC):** {first_ts}  →  {last_ts}")
L.append("**Cases worked:** INC-2026-0613202023 (rocba/SRL-FORGE) ; CFREDS-HACKING-CASE-4DELL (Greg Schardt/Mr. Evil)")
L.append("")
L.append("## A. Single-agent token usage (main loop)")
L.append("")
L.append("| Metric | Tokens |")
L.append("|---|---|")
L.append(f"| Output (generated) | {tot['out']:,} |")
L.append(f"| Input (uncached) | {tot['inp']:,} |")
L.append(f"| Cache read | {tot['cr']:,} |")
L.append(f"| Cache creation | {tot['cc']:,} |")
L.append(f"| Total input (uncached+create+read) | {tot['inp']+tot['cc']+tot['cr']:,} |")
L.append("")
L.append("## B. Single-agent tool execution summary")
L.append("")
L.append(f"- Tool calls: **{len(calls)}**  ·  results: **{len(results)}**  ·  errors: **{len(errors)}**")
L.append("")
L.append("| Tool | Calls |")
L.append("|---|---|")
for k, v in sorted(tally.items(), key=lambda x: -x[1]):
    L.append(f"| {k} | {v} |")
L.append("")
L.append("## C. Multi-agent workflow (wf_e22ed84e-e9e — cfreds-exhaustive-extract)")
L.append("")
L.append(f"- Agents: **{len(wf_agents)}**  ·  combined tool calls: **{wf_calls}**  ·  combined output tokens: **{wf_out:,}**")
L.append("")
L.append("| Agent ID | Role (prompt head) | Tool calls | Out tok | Top tools | Window (UTC) |")
L.append("|---|---|---|---|---|---|")
for a in wf_agents:
    win = f"{a['first']} → {a['last']}" if a['first'] else "-"
    L.append(f"| {a['id'][:12]} | {short(a['role'],70)} | {a['tool_calls']} | {a['out_tokens']:,} | {short(a['top_tools'],60)} | {win} |")
L.append("")
L.append("## D. Full chronological single-agent trace")
L.append("")
L.append("| # | Timestamp (UTC) | Actor | Kind | Tool / Detail | out_tok | result |")
L.append("|---|---|---|---|---|---|---|")
for s in steps:
    td = (("**"+s["tool"]+"** " if s.get("tool") else "") + (s.get("detail","") or "")).replace("|", "\\|")
    ot = s.get("out_tokens","") if s["kind"]!="tool_result" else ""
    rs = (f"{s.get('result_chars','')}c/{s.get('status','')}" if s["kind"]=="tool_result" else "")
    L.append(f"| {s['step']} | {s.get('ts','')} | {s['actor']} | {s['kind']} | {td} | {ot} | {rs} |")
L.append("")
with open(os.path.join(OUT, "PROJECT-agent-execution-log.md"), "w", encoding="utf-8") as f:
    f.write("\n".join(L))

print("WROTE PROJECT-agent-execution-log.md, tool-execution-trace.jsonl, workflow-agents.jsonl")
print(f"main: steps={len(steps)} calls={len(calls)} results={len(results)} errors={len(errors)}")
print(f"main tokens: out={tot['out']:,} in={tot['inp']:,} cacheRead={tot['cr']:,} cacheCreate={tot['cc']:,}")
print(f"workflow: agents={len(wf_agents)} calls={wf_calls} out_tokens={wf_out:,}")
print(f"window: {first_ts} -> {last_ts}")
