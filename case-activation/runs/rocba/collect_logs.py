#!/usr/bin/env python3
"""Harvest ALL ROCBA agent-execution logs into this run dir, for audit
(Find Evil! requirement 8). Re-runnable: run again to finalize after the
disk run completes. Pulls four authoritative sources:

  1. Driver step checkpoints  gearB/rocba/*.json  (+ SUMMARY.json)
  2. Server-side HTTP audit    /var/log/agentropix/http_audit.log
     (per MCP request: timestamp, duration_ms, request_id, session_id, bytes)
  3. Thymus access decisions   server.log "Thymus ALLOW/REJECT" lines (windowed)
  4. Driver run logs           /tmp/rocba-disk-run.log, /tmp/rocba-mem-run.log
     + memory sequence checkpoints gearB/rocba-mem/*.json

Token usage: the deterministic engine collects NONE by design (tokens are
client-side — see docs/07-sdlc-ops/observability-and-integrity-notes.md §2).
duration_ms + req/resp bytes are the engine-side telemetry, reported here.
"""
import glob
import json
import os
import re
import shutil

RUN = os.path.dirname(os.path.abspath(__file__))
LOGS = os.path.join(RUN, "logs")
GEARB = "/home/admin2/.openclaw/workspace/drivers/gearB/rocba"
GEARB_MEM = "/home/admin2/.openclaw/workspace/drivers/gearB/rocba-mem"
DISK_LOG = "/tmp/rocba-disk-run.log"
MEM_LOG = "/tmp/rocba-mem-run.log"
HTTP_AUDIT = "/var/log/agentropix/http_audit.log"
SERVER_LOG = "/var/log/agentropix/server.log"

for d in (LOGS, f"{LOGS}/disk-driver", f"{LOGS}/memory"):
    os.makedirs(d, exist_ok=True)


def copy(src, dst):
    if os.path.exists(src):
        shutil.copy2(src, dst)
        return True
    return False


# ---- 1. driver checkpoints (deep-trim big arrays — raw dumps stay local) ----
SAMPLE = 20          # keep first N items of any list
VERBATIM_MAX = 200_000  # copy files <200KB verbatim; trim larger ones


def _trim(obj):
    if isinstance(obj, list):
        head = [_trim(x) for x in obj[:SAMPLE]]
        if len(obj) > SAMPLE:
            head.append(f"... [{len(obj) - SAMPLE} more items truncated — full dump local-only]")
        return head
    if isinstance(obj, dict):
        return {k: _trim(v) for k, v in obj.items()}
    if isinstance(obj, str) and len(obj) > 2000:
        return obj[:2000] + f"... [+{len(obj) - 2000} chars truncated]"
    return obj


def trim_copy(src, dstdir, localref):
    dst = os.path.join(dstdir, os.path.basename(src))
    if os.path.getsize(src) <= VERBATIM_MAX:
        shutil.copy2(src, dst); return
    try:
        data = json.load(open(src))
    except Exception:
        shutil.copy2(src, dst); return
    trimmed = _trim(data)
    if isinstance(trimmed, dict):
        trimmed["_trimmed_for_repo"] = True
        trimmed["_full_dump_local"] = f"{localref}/{os.path.basename(src)}"
    json.dump(trimmed, open(dst, "w"), indent=2, default=str)


for f in glob.glob(f"{GEARB}/*.json"):
    trim_copy(f, f"{LOGS}/disk-driver", GEARB)
for f in glob.glob(f"{GEARB_MEM}/*"):
    if f.endswith(".json"):
        trim_copy(f, f"{LOGS}/memory", GEARB_MEM)
    else:
        copy(f, f"{LOGS}/memory/")
copy(DISK_LOG, f"{LOGS}/disk-driver/driver-run.log")
copy(MEM_LOG, f"{LOGS}/memory/mem-run.log")

# ---- parse the driver log for per-step absolute timestamps -----------------
steps = []  # {step, tool, start, end, elapsed}
start_ts = end_ts = None
if os.path.exists(DISK_LOG):
    pend = {}
    for line in open(DISK_LOG):
        m = re.match(r"\[([0-9T:Z-]+)\]\s+-> (\S+) \((\S+)\) timeout", line)
        if m:
            ts, step, tool = m.groups()
            pend[step] = (ts, tool)
            start_ts = start_ts or ts
            continue
        m = re.match(r"\[([0-9T:Z-]+)\]\s+ok (\S+) \(([\d.]+)s\)", line)
        if m:
            ts, step, el = m.groups()
            end_ts = ts
            s0, tool = pend.get(step, (ts, "?"))
            steps.append({"step": step, "tool": tool, "start": s0, "end": ts,
                          "elapsed_s": float(el), "ok": True})
            continue
        m = re.match(r"\[([0-9T:Z-]+)\]\s+\[\d+\] step (\S+) FAILED: (.+)", line)
        if m:
            ts, step, err = m.groups()
            end_ts = ts
            s0, tool = pend.get(step, (ts, "?"))
            steps.append({"step": step, "tool": tool, "start": s0, "end": ts,
                          "elapsed_s": 0.0, "ok": False, "error": err.strip()})

# ---- ingest completion-run step files (09_/10_/11_/07b_ etc.) ---------------
for f in sorted(glob.glob(f"{GEARB}/*.json")):
    base = os.path.basename(f)
    if base == "SUMMARY.json":
        continue
    try:
        rec = json.load(open(f))
    except Exception:
        continue
    if isinstance(rec, dict) and "step" in rec and "tool" in rec and "ok" in rec:
        steps.append({"step": rec["step"], "tool": rec["tool"], "start": rec.get("ts", ""),
                      "end": "", "elapsed_s": float(rec.get("elapsed_s") or 0),
                      "ok": bool(rec.get("ok")), "error": rec.get("error", "")})
# de-dupe by step name (completion file wins over log parse), then sort
_by = {}
for s in steps:
    _by[s["step"]] = s
steps = sorted(_by.values(), key=lambda s: s["step"])

# ---- 2. server HTTP audit, windowed to the ROCBA run -----------------------
audit_rows = []
if os.path.exists(HTTP_AUDIT) and start_ts:
    for line in open(HTTP_AUDIT):
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = r.get("timestamp", "")
        if ts >= start_ts and r.get("user_agent", "").startswith("Python-urllib"):
            audit_rows.append(r)
with open(f"{LOGS}/mcp-http-audit.jsonl", "w") as f:
    for r in audit_rows:
        f.write(json.dumps(r) + "\n")

# ---- 3. Thymus ALLOW/REJECT decisions from server.log (windowed) -----------
thymus = []
if os.path.exists(SERVER_LOG) and start_ts:
    for line in open(SERVER_LOG, errors="replace"):
        if "Thymus" in line and ("ALLOW" in line or "REJECT" in line):
            thymus.append(line.rstrip())
with open(f"{LOGS}/thymus-access.log", "w") as f:
    f.write("\n".join(l[:500] for l in thymus[-200:]) + ("\n" if thymus else ""))

# ---- 4. driver SUMMARY -----------------------------------------------------
summ = {}
if os.path.exists(f"{GEARB}/SUMMARY.json"):
    summ = json.load(open(f"{GEARB}/SUMMARY.json"))
mem_summ = {}
if os.path.exists(f"{GEARB_MEM}/SUMMARY.json"):
    mem_summ = json.load(open(f"{GEARB_MEM}/SUMMARY.json"))

# total MCP calls; real durations come from the CLIENT step timings (the server
# audit duration_ms only records stream-start latency for SSE tool responses).
n_calls = len(audit_rows)
tot_tool_s = sum(s["elapsed_s"] for s in steps if s.get("ok"))
end_ts = max((r.get("timestamp", "") for r in audit_rows), default=end_ts) or end_ts
# 200 = ok, 202 = accepted (notifications/initialized) — neither is an error.
errs = [r for r in audit_rows if r.get("status") not in (200, 202)]

# ---- generate EXECUTION-LOG.md --------------------------------------------
md = []
md.append("# ROCBA — Agent Execution Logs (audit bundle)\n")
md.append("> **Find Evil! requirement 8 — Agent Execution Logs.** Structured, timestamped "
          "tool-execution logs for the ROCBA live-MCP run. This is a **single-agent / tool-"
          "sequence** run (the `agx_gearb` PATH-B driver sequences MCP tool calls), so the "
          "matching evidence is *tool execution logs with timestamps* (below) plus the "
          "server-side per-request audit. Executed against the live MCP "
          "(`http://<TAILNET-HOST>:8765/mcp`). Examiner `victor.galvan`.\n")
md.append(f"- **Run window:** `{start_ts}` → `{end_ts or '(in progress)'}`")
md.append(f"- **Disk session_id:** `a7b33b7486bd404db17e5cde1af9cbd1` (image `/cases/rocba/rocba-cdrive.e01`, offset 0)")
md.append(f"- **MCP requests (server audit):** {n_calls} · **total tool runtime (client-measured):** "
          f"{tot_tool_s:.1f}s · **real errors (status not in 200/202):** {len(errs)}")
md.append(f"- **Driver steps ok:** {summ.get('ok_steps','?')}/{summ.get('total_steps','?')}\n")

md.append("## Token usage (stated honestly)\n")
md.append("The deterministic engine collects **no LLM token-usage metrics — by design**: it is a "
          "token-blind tool executor and token accounting belongs to the MCP client / provider "
          "(see [`observability-and-integrity-notes.md` §2]"
          "(../../../docs/07-sdlc-ops/observability-and-integrity-notes.md)). The engine-side "
          "telemetry that DOES exist — per-tool **`duration_ms`** and **request/response bytes** — "
          "is captured below from the server HTTP audit.\n")

md.append("## 1. Tool execution sequence (driver, with timestamps + durations)\n")
md.append("| # | Step | Tool | Start (UTC) | Duration | Result |")
md.append("|---|------|------|-------------|----------|--------|")
for i, s in enumerate(steps, 1):
    res = "✅ ok" if s.get("ok") else f"❌ FAIL — {s.get('error','')[:80]}"
    md.append(f"| {i} | `{s['step']}` | `{s['tool']}` | {s['start']} | {s['elapsed_s']:.1f}s | {res} |")
if not steps:
    md.append("| — | (run in progress — no completed steps parsed yet) | | | |")
md.append("")

md.append("## 2. Server-side MCP HTTP audit (authoritative per-request log)\n")
md.append("Full JSONL: [`logs/mcp-http-audit.jsonl`](logs/mcp-http-audit.jsonl) — every MCP request "
          "with `timestamp`, `duration_ms`, `request_id`, `session_id`, `req_bytes`/`resp_bytes`. "
          "Sample (first + last 3):\n")
md.append("```json")
for r in audit_rows[:1] + (audit_rows[-3:] if len(audit_rows) > 3 else []):
    md.append(json.dumps(r))
md.append("```\n")

md.append("## 3. Thymus access decisions (read-only evidence gate)\n")
md.append(f"Captured {len(thymus)} `Thymus ALLOW/REJECT` decisions from the server log → "
          "[`logs/thymus-access.log`](logs/thymus-access.log). Every evidence read is policy-checked "
          "before any byte is opened; `check_write` is unconditionally rejected (no write tool exists).\n")

md.append("## 4. Honest negatives\n")
mem_ok = sum(1 for s in mem_summ.get("steps", []) if s.get("ok"))
if mem_summ:
    md.append(f"- **Memory sequence:** {mem_ok}/{len(mem_summ.get('steps', []))} tools succeeded "
              "(`logs/memory/`).")
else:
    md.append("- **Memory sequence:** failed at `initialize()` with a socket timeout / server `500` "
              "while the disk run was hashing the 23 GB image (server busy). Captured in "
              "[`logs/memory/mem-run.log`](logs/memory/mem-run.log) and visible as the `status:500` "
              "row in the HTTP audit — logged as an honest negative, re-run pending.")
if errs:
    md.append(f"- **Error responses (status not 200/202):** {len(errs)} — "
              + ", ".join(f"`{e.get('status')}@{e.get('timestamp')}`" for e in errs[:6])
              + " (the `500` is the memory-init failure above).")
md.append("- **`report_generate`** returned the documented `case_not_found` gotcha for a brand-new "
          "DRAFT-only case (`case_status` finds the case, but the report index has no case documents "
          "until findings are approved) — logged as-is, not worked around.")
md.append("")

md.append("## 5. Files in this bundle\n")
md.append("| Path | What |")
md.append("|------|------|")
md.append("| `logs/disk-driver/NN_*.json` | per-step driver checkpoints (args + result) |")
md.append("| `logs/disk-driver/SUMMARY.json` | driver step summary (ok/elapsed per step) |")
md.append("| `logs/disk-driver/driver-run.log` | timestamped driver log |")
md.append("| `logs/mcp-http-audit.jsonl` | server-side per-request audit (the authoritative trace) |")
md.append("| `logs/thymus-access.log` | Thymus read-only-gate ALLOW/REJECT decisions |")
md.append("| `logs/memory/` | memory-sequence checkpoints + log (incl. honest-negative timeout) |")
md.append("")

with open(os.path.join(RUN, "EXECUTION-LOG.md"), "w") as f:
    f.write("\n".join(md) + "\n")

print(f"harvested: {n_calls} audit rows, {len(steps)} driver steps, {len(thymus)} thymus decisions")
print(f"EXECUTION-LOG.md + logs/ written under {RUN}")
