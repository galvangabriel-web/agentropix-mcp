# Case Activation Guide — Challenge "Notch It Up"

> **LOCAL-ONLY operator runbook.** Real evidence paths and case inventory — never published.
> Gets an operator **ready to activate the case and start analysis**. It does **not** run analysis.
> Follow ONE track per step: 🖥️ the exact command an expert types, or 💬 the plain-language prompt
> a non-technical user pastes into Claude Desktop / Claude CLI (Agentropix MCP connected) for the
> same result.
> Procedure source: `/home/admin2/agentropix-sift/docs/tools/END-USER-CASE-GUIDE.md` (steps 0→8).
> Numbers cite `CANONICAL_FACTS` via `.crew/facts.md`.

---

## 1. Identification header

| Field | Value |
|---|---|
| **Case name** | Challenge — "Notch It Up" |
| **One-liner** | CTF-style memory-forensics challenge: a single standalone Windows RAM capture to triage end-to-end. |
| **Evidence type** | **Memory** (volatile RAM image) |
| **Image file** | `/cases/Challenge_NotchItUp/Challenge.raw` |
| **Format** | **Raw / flat memory dump** (`.raw`; not EWF/E01 — `ewfinfo` rejects it) |
| **Size** | **1.5 GiB on disk · `1610547200` bytes** (= 1.6 GB) |
| **`file(1)` caveat** | misreports as `Windows Event Trace Log` — that magic is **wrong**; the bytes are a RAM dump. Trust the size + provenance, not `file`. |
| **Suggested `case_id` slug** | `CHALLENGE-NOTCHITUP` (matches `^[A-Za-z0-9._-]{1,128}$`, no spaces/slashes) |
| **OS / scenario** | Windows memory image (resolve the exact build at analysis time via `get_image_info`). Standalone CTF "Notch It Up" — same byte size (`1610547200`) as a MemLabs Lab6 dump, but treated here as an independent single-evidence case. No `readme`/`ground_truth`/`solution` file ships in the folder — derive everything from the image. |

### Recommended path + tool chain (memory)

This is a **memory** image, so the **memory** branch of the swarm applies (the disk branch —
`mmls` / `fls` / `bulk_extractor` / `yara` — does **not**):

```
get_image_info        # confirm it parses as RAM + identify OS/profile  (START HERE)
   │
   ├─ get_pslist      # running processes (Volatility pslist)
   ├─ get_netscan     # network connections / sockets
   ├─ get_malfind     # injected / hidden code regions
   ├─ get_svcscan     # Windows services
   └─ run_volatility(target, plugin=…)   # escape hatch: cmdline, pstree, dlllist,
                                          # hashdump, hivelist, consoles, filescan, …
```

> `run_volatility` is the generic Volatility driver for any plugin the named wrappers don't cover.
> Total MCP surface is **71** tools ({{ref:CANONICAL_FACTS#mcp_tool_count}}); the live
> `health.tool_count` may report **72** (a reproducible +1 — see the user-guide §1.2 note).

---

## 2. Instantiated procedure (steps 0→8 with THIS case's real values)

### Step 0 — Before you start
- **Where:** any client with the `agentropix-sift` MCP bound (Claude Desktop, Claude CLI, or the
  live tailnet server at `http://<TAILNET-IP>:8765/mcp`, host `siftworkstation.taile7c9ca.ts.net`).
  These are **MCP tools, not a CLI** — there is no `agentropix-sift case init` shell command.
- **One active case at a time** (pointer `~/.agentropix/active_case`). `case_init` registers +
  activates; `case_activate` switches.
- **`examiner_id`** stamped into every record for chain-of-custody — use `victor.galvan`.

### Step 1 — Pick evidence & choose the slug
Evidence is already at `/cases/Challenge_NotchItUp/Challenge.raw`. Slug → `CHALLENGE-NOTCHITUP`.

### Step 2 — Activate (register) the case — `case_init`
```python
case_init(
  case_name     = "Challenge - Notch It Up",
  examiner_id   = "victor.galvan",
  case_id       = "CHALLENGE-NOTCHITUP",
  case_dir      = "/cases/Challenge_NotchItUp",
  description   = "CTF-style memory forensics challenge 'Notch It Up' - single 1.6GB raw Windows RAM image",
  incident_type = "dfir", severity = "medium", scope = "", team = [], tags = ["ctf","memory","notch-it-up"]
)
```
Writes the active-case pointer first (usable even if the indexer is down), then upserts into
`agentropix-cases`. **Idempotent** on the slug.

### Step 3 — Confirm it's active — `case_status`
```python
case_status()                              # resolves the active pointer
case_status(case_id="CHALLENGE-NOTCHITUP") # status for this specific case
```
Check `active: true` and `indexer_reachable: true`.

### Step 4 — Register evidence (chain-of-custody) — `evidence_register`
```python
evidence_register(
  path        = "/cases/Challenge_NotchItUp/Challenge.raw",
  description = "Notch It Up - 1.6GB raw Windows memory image (1610547200 bytes)",
  examiner_id = "victor.galvan",
  case_id     = None                       # None = active case
)
```
Hashes the file (sha256 + size) → `agentropix-evidence-YYYY.MM.DD`. Expect `size_bytes 1610547200`.

### Step 5 — Analyze the evidence (memory branch)
```python
get_image_info(image="/cases/Challenge_NotchItUp/Challenge.raw")   # confirm RAM + OS first
get_pslist(image="/cases/Challenge_NotchItUp/Challenge.raw")
get_netscan(image="/cases/Challenge_NotchItUp/Challenge.raw")
get_malfind(image="/cases/Challenge_NotchItUp/Challenge.raw")
get_svcscan(image="/cases/Challenge_NotchItUp/Challenge.raw")
# escape hatch for any other Volatility plugin:
run_volatility(target="/cases/Challenge_NotchItUp/Challenge.raw", plugin="windows.cmdline")
run_volatility(target="/cases/Challenge_NotchItUp/Challenge.raw", plugin="windows.pstree")
```

### Step 6 — Record findings — `record_finding` (DRAFT-gated)
```python
record_finding(
  finding = {"finding_id": "F-001", "title": "...", "severity": "high"},
  case_id = None,
  dry_run = True,             # DEFAULT: preview only, writes nothing
  mutation_token = None       # supply a valid token + dry_run=False to persist
)
record_timeline_event(event={...}, hostname="<host-from-image>", case_id=None)
```
Persisted findings land as **DRAFT** — they cannot self-approve.

### Step 7 — Approve (examiner gate — human-only)
HMAC challenge-response via the Examiner Portal / `approve_finding`: DRAFT → APPROVED.
**Deliberately not automated** — this is the cryptographic chain-of-custody sign-off (Hard-Stop).

### Step 8 — Report & (optional) push IOCs
```python
report_generate(profile="full", case_id=None)     # sealed SIFT report for this case
# then, if this case feeds detection:
promote_iocs(...)   # / wazuh_publish_iocs(...)
```

---

## 3. "Activate & start" prompt sequences

### A. MANUAL sequence (operator-driven, prompt-by-prompt)

Each step shows the 💬 end-user prompt and its 🖥️ command equivalent.

**1. Open/activate the case.**
💬 *"Open a new memory-forensics case called 'Challenge - Notch It Up', case id CHALLENGE-NOTCHITUP, evidence dir /cases/Challenge_NotchItUp, examiner victor.galvan."*
🖥️ `case_init(case_name="Challenge - Notch It Up", examiner_id="victor.galvan", case_id="CHALLENGE-NOTCHITUP", case_dir="/cases/Challenge_NotchItUp", incident_type="dfir", severity="medium", tags=["ctf","memory","notch-it-up"])`
**Expect:** `case_id "CHALLENGE-NOTCHITUP"`, status `active`, pointer written.

**2. Confirm it's active.**
💬 *"Is CHALLENGE-NOTCHITUP the active case and is the indexer reachable?"*
🖥️ `case_status(case_id="CHALLENGE-NOTCHITUP")`
**Expect:** `active: true`, `indexer_reachable: true`.

**3. Register the evidence (chain-of-custody hash).**
💬 *"Register the evidence /cases/Challenge_NotchItUp/Challenge.raw — it's the 1.6GB raw Windows memory image."*
🖥️ `evidence_register(path="/cases/Challenge_NotchItUp/Challenge.raw", description="Notch It Up raw memory image", examiner_id="victor.galvan")`
**Expect:** an sha256, `size_bytes 1610547200`, record under `agentropix-evidence-<today>`.

**4. Confirm the image parses as RAM and identify the OS.**
💬 *"Confirm /cases/Challenge_NotchItUp/Challenge.raw is a memory image and tell me the OS/profile."*
🖥️ `get_image_info(image="/cases/Challenge_NotchItUp/Challenge.raw")`
**Expect:** it parses as a Windows RAM dump (NOT an Event Trace Log — `file(1)` mislabels it); an OS/build is reported.

**5. List running processes.**
💬 *"Show me the process list from the Notch It Up memory image."*
🖥️ `get_pslist(image="/cases/Challenge_NotchItUp/Challenge.raw")`
**Expect:** a process table (pid/ppid/name) — your first real analysis result; you are now "started".

**6. Check network connections.**
💬 *"What network connections were in memory?"*
🖥️ `get_netscan(image="/cases/Challenge_NotchItUp/Challenge.raw")`
**Expect:** a sockets/connections table.

**7. Hunt injected code.**
💬 *"Run malfind on the image and flag any injected regions."*
🖥️ `get_malfind(image="/cases/Challenge_NotchItUp/Challenge.raw")`
**Expect:** zero or more suspicious VAD regions with disassembly.

**8. (As needed) any other Volatility plugin.**
💬 *"Show the command line for every process (Volatility cmdline)."*
🖥️ `run_volatility(target="/cases/Challenge_NotchItUp/Challenge.raw", plugin="windows.cmdline")`
**Expect:** per-process command lines; swap `plugin=` for `windows.pstree`, `windows.hashdump`, etc.

**9. Stage a finding (DRAFT, preview first).**
💬 *"Draft finding F-001 for what we found, but just preview it — don't persist yet."*
🖥️ `record_finding(finding={"finding_id":"F-001","title":"...","severity":"high"}, dry_run=True)`
**Expect:** a preview; nothing written (`dry_run=True` is the default). Persist later with `dry_run=False` + `mutation_token`.

> Stop here for "ready to analyze". Steps **Approve** (`approve_finding`, human HMAC gate) and
> **Report** (`report_generate`) follow once findings are confirmed.

### B. AUTONOMOUS sequence (launch driver → monitor → approve → report)

> The headless driver `agx_gearb.py` walks the **memory** sequence
> (`get_pslist` → `get_netscan` → `get_malfind` → `get_svcscan` → `build_process_tree`) for a
> `.raw` image, checkpoints `SUMMARY.json` per step, stages findings **DRAFT**, and **stops before
> approval**. It takes a logical **`<case_key>`** (resolved via its `cases.json`) — not a path, not
> a token. The token comes from the environment.

**1. (Recommended) smoke-test the session without creating a case.**
💬 *"Do a preflight check against the Notch It Up case — session, health, schema, image info only, no case record."*
🖥️
```bash
AGENTROPIX_MCP_AUTH_TOKEN="<BEARER_TOKEN>" \
  python3 /home/admin2/.openclaw/workspace/drivers/agx_gearb.py challenge-notchitup --preflight
```
**Expect:** session initialized, `health` OK, schema validated, `get_image_info` returns RAM/OS; **no** case written.

**2. Launch the driver DETACHED.**
💬 *"Investigate the Notch It Up memory case end to end, stage findings as DRAFT, and do not approve anything."* (interactive autonomous lane — no shell detachment needed)
🖥️
```bash
AGENTROPIX_MCP_AUTH_TOKEN="<BEARER_TOKEN>" \
  setsid nohup bash -c "python3 /home/admin2/.openclaw/workspace/drivers/agx_gearb.py challenge-notchitup > run.log 2>&1" </dev/null >/dev/null 2>&1 &
disown
```
**Expect:** the driver runs `case_init` → `case_activate` → `get_image_info` → `evidence_register` → the memory tool chain; survives shell close. (Token is read from env only — never pass it as a positional.)

**3. Monitor progress.**
💬 *"How's the investigation going — which steps are done?"*
🖥️ `tail -f run.log` and read `/home/admin2/.openclaw/workspace/drivers/gearB/challenge-notchitup/SUMMARY.json`
**Expect:** per-step `ok`/`elapsed`/`error`; the run halts cleanly at DRAFT (before the approval gate).

**4. Approve findings (human-only HMAC gate).**
💬 *"Open the Approval Portal so I can sign off the DRAFT findings for CHALLENGE-NOTCHITUP."*
🖥️ `approve_finding(...)` via the Examiner Portal (HMAC challenge-response)
**Expect:** each finding DRAFT → APPROVED, attested to `victor.galvan`. (Hard-Stop — never auto-adopted.)

**5. Generate the sealed report.**
💬 *"Generate the full sealed report for CHALLENGE-NOTCHITUP."*
🖥️ `report_generate(profile="full", case_id="CHALLENGE-NOTCHITUP")`
**Expect:** an HMAC-sealed SIFT report. (On a brand-new DRAFT-only case `report_generate` can return `case_not_found` until at least one record is indexed — see user-guide Phase 7.)

---

## Gotchas for this case

| Gotcha | Rule |
|---|---|
| `file(1)` says "Windows Event Trace Log" | **Ignore it.** The bytes are a raw RAM dump; trust size `1610547200` + provenance. Confirm with `get_image_info`. |
| Tempted to run `mmls`/`fls`/`bulk_extractor`/`yara` | **Wrong branch** — this is memory, not disk. Use the Volatility/memory tools. |
| `ewfinfo` errors out | Expected — this is **raw**, not EWF/E01. `ewfinfo` is disk/EWF only. |
| Driver fed a path or token as arg 1 | **Fail-closed.** Pass only the logical `<case_key>`; export the token via `AGENTROPIX_MCP_AUTH_TOKEN`. |
| Findings not showing | `record_finding` defaults to `dry_run=True` — persist with `dry_run=False` + `mutation_token`. |
| `case_id` with a space | Rejected (`^[A-Za-z0-9._-]{1,128}$`). Use `CHALLENGE-NOTCHITUP`. |
