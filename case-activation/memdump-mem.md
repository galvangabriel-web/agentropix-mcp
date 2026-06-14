# Case Activation Guide — `memdump` (generic 512 MiB raw memory dump)

> **LOCAL ONLY — real case inventory. Do NOT publish.** This file lives under
> `case-activation/` (gitignored). It instantiates the template procedure
> `END-USER-CASE-GUIDE.md`
> with this case's real values, in the same dual-audience (🖥️ command / 💬 prompt)
> house style as [`user-guide.md`](../docs/01-overview/user-guide.md).
> Canonical numbers cite [`.crew/facts.md`](../docs/08-reference/canonical-facts.md) (`mcp_tool_count=71`,
> 16 forensic SIFT wrappers, `test_count=4687`).

---

## 1. Identification header

| Field | Value |
|---|---|
| **Case name** | `memdump` — generic raw memory dump (single image, unattributed) |
| **One-line description** | A single 512 MiB raw physical-memory image (`memdump.mem`, file-dated **2014-01-08**) with **no embedded scenario metadata** — a clean memory-forensics activation target. |
| **Evidence type** | **Memory** (raw physical memory dump) |
| **Image file(s)** | `/cases/memdump/memdump.mem` |
| **Format** | **Raw / unstructured** — `file` reports `data` (no EWF/ELF/crash-dump header). This is a flat `.mem` capture, **not** an E01. |
| **Size** | **512 MiB** — `536870912` bytes exactly (`du -h` → `512M`). |
| **Suggested `case_id` slug** | **`MEMDUMP-RAW-2014`** (matches `^[A-Za-z0-9._-]{1,128}$`; no spaces, no slashes) |
| **OS / scenario** | **Unknown — generic, no ground-truth.** No `readme`/`ground_truth_*.yaml` ships with this image; `file` yields only `data`. The OS profile is **not declared** and must be discovered by Volatility3's auto-detect (symbol-table match), not assumed. Treat it as an unattributed Windows-or-other memory capture — the kernel profile is resolved implicitly when the first `windows.*` analysis plugin (`get_pslist`) runs. |

### Recommended path + tool chain (memory)

This is a **memory image**, so the disk path (`mmls` → `fls` → `bulk_extractor` →
`yara`) does **not** apply — there is no partition table to walk. The memory chain
is the Volatility3-backed tool set:

```
case_init → case_activate → evidence_register (SHA-256)
   → get_pslist        # processes — also auto-detects the kernel profile (see note)
   → get_netscan       # sockets / connections
   → get_malfind       # injected / RWX code
   → get_svcscan       # Windows services
   → build_process_tree  # PPID forest + LOLBin flags
   → record_finding (DRAFT) × N → approve (portal) → report_generate
```

> **Why no `get_image_info` here.** `get_image_info` drives `ewfinfo` and only
> reads **E01/EWF** acquisition metadata. A flat `.mem` has none, so on a raw memory
> dump it returns empty fields — skip it for this case.
>
> **How the OS/kernel is resolved.** Volatility3 is **profile-less**: it auto-detects
> the kernel via symbol tables on the **first `windows.*` plugin that runs** (here
> `get_pslist`). There is **no separate `windows.info`/`banners` step** — the MCP
> allowlist exposes analysis plugins only (`pslist, psscan, pstree, malfind, netscan,
> svcscan, cmdline, dlllist, handles, filescan, vadinfo, modules, …`), so an OS-info
> call would be rejected as a disallowed plugin. A successful `get_pslist` *is* the
> confirmation that a kernel symbol table matched.

> ⚠️ **Generic-image expectation.** With no scenario metadata, treat counts as
> *discovered*, not *expected*. If the analysis plugins return empty and report
> `Unable to validate the plugin requirements: kernel.symbol_table_name`, this image
> has **no matching Windows symbol table** (it may be Linux/Mac or a partial capture) —
> an honest negative, recorded as-is. A 512 MiB image is small; plugin runs are fast.

---

## 2. Instantiated procedure (template steps 0 → 8, real values)

All tools are **MCP tools, not a CLI** — call them from a client with the
`agentropix-sift` MCP bound (Claude CLI or Desktop). The live endpoint is on the
tailnet at `http://<TAILNET-HOST>:8765/mcp` (get the real host + bearer token from
Client Setup — never hard-code them here).

### Step 0 — Pre-flight (operator-local)

> **🖥️ Expert (command):**
> ```bash
> uv run agentropix-sift doctor      # confirm the 16 forensic SIFT wrappers' binaries resolve (esp. vol / Volatility3)
> file /cases/memdump/memdump.mem    # confirms: data (raw, no header)
> du -h /cases/memdump/memdump.mem   # confirms: 512M (536870912 bytes)
> ```
> **💬 End-user (prompt):** *"Check my Agentropix forensic environment is ready — is Volatility3 installed?"*
> **Expect:** `doctor`/`health` reports each backing binary `OK <path>`, ending `All tools available.`; `file` returns `data`; `du` returns `512M`. *(No `ewfverify`/`ewfinfo` for a raw `.mem` — those are E01-only.)*

### Step 1 — Pick evidence + choose the slug

Evidence is already staged at `/cases/memdump/memdump.mem`. Slug = **`MEMDUMP-RAW-2014`**.

### Step 2 — `case_init` (register + activate)

> **🖥️ Expert (MCP calls):**
> ```text
> case_init {
>   "case_name":    "memdump — generic raw memory dump (2014)",
>   "examiner_id":  "victor.galvan",
>   "case_id":      "MEMDUMP-RAW-2014",
>   "case_dir":     "/cases/memdump",
>   "description":  "Single 512 MiB raw physical-memory image; no embedded scenario metadata",
>   "incident_type":"dfir", "severity":"medium",
>   "scope":        "/cases/memdump/memdump.mem", "tags":["memory","raw","generic"]
> }
> case_activate { "case_id":"MEMDUMP-RAW-2014" }
> ```
> **💬 End-user (prompt):** *"Open a medium-severity case `MEMDUMP-RAW-2014` for the raw memory dump at `/cases/memdump/memdump.mem`, examiner victor.galvan, and make it the active case."*
> **Expect:** `case_init` returns `case_id MEMDUMP-RAW-2014`, status `active`; `case_activate` writes the pointer to `/home/admin2/.agentropix/active_case`. Idempotent on the slug.

### Step 3 — `case_status` (confirm active)

> **🖥️ Expert (MCP call):** `case_status { "case_id":"MEMDUMP-RAW-2014" }`
> **💬 End-user (prompt):** *"Is `MEMDUMP-RAW-2014` the active case and is the indexer reachable?"*
> **Expect:** `active: true` and `indexer_reachable: true` in the result.

### Step 4 — `evidence_register` (SHA-256 custody)

> **🖥️ Expert (MCP call):**
> ```text
> evidence_register {
>   "path":        "/cases/memdump/memdump.mem",
>   "description": "Raw physical-memory image (512 MiB, file-dated 2014-01-08)",
>   "examiner_id": "victor.galvan"
> }
> ```
> **💬 End-user (prompt):** *"Register `/cases/memdump/memdump.mem` as evidence in this case and give me its SHA-256 custody hash."*
> **Expect:** returns `evidence_id`, the evidence **SHA-256**, `size_bytes 536870912`, `indexed: true` under `agentropix-evidence-YYYY.MM.DD`. (Hash is computed live at register time — record it as the custody anchor.)

### Step 5 — Analyze (memory tool chain)

> **🖥️ Expert (MCP calls):**
> ```text
> get_pslist         { "image":"/cases/memdump/memdump.mem" }   # processes (auto-detects the kernel profile)
> get_netscan        { "image":"/cases/memdump/memdump.mem" }   # sockets / connections
> get_malfind        { "image":"/cases/memdump/memdump.mem" }   # injected / RWX code
> get_svcscan        { "image":"/cases/memdump/memdump.mem" }   # Windows services
> build_process_tree { "image":"/cases/memdump/memdump.mem" }   # PPID forest + LOLBin flags
> ```
> **💬 End-user (prompt):** *"Analyse this memory image: show running processes, open network connections, any injected code, the services, and the process tree."*
> **Expect:** the Volatility-backed tools return process / socket / malfind / service / PPID-tree data. The kernel profile is auto-detected on the first plugin (`get_pslist`) — a populated process list confirms the symbol-table match; if every plugin returns empty with `Unable to validate the plugin requirements: kernel.symbol_table_name`, no Windows profile resolved (honest negative). Counts are **discovered** (no ground-truth to match against).

> **Tool surface:** these are 5 of the platform's **73** MCP tools (`{{ref:CANONICAL_FACTS#mcp_tool_count}}`), driving Volatility3 — one of the **16 forensic SIFT wrappers** (cite [`.crew/facts.md`](../docs/08-reference/canonical-facts.md)). `run_volatility` is the generic escape hatch for any other plugin — call it with either a short alias (`cmdline`, `dlllist`) or a full canonical id (`windows.cmdline.CmdLine`, `windows.dlllist.DllList`); the bare middle form (`windows.cmdline`/`windows.dlllist`) is rejected. (There is **no** `hashdump` alias and no `windows.hashdump.*` exposed by this MCP — such a call would be rejected as a disallowed plugin.)

### Step 6 — `record_finding` (DRAFT-gated)

> **🖥️ Expert (MCP call):**
> ```text
> record_finding {
>   "finding": { "finding_id":"memdump-os-001", "title":"...", "severity":"medium", ... },
>   "dry_run": false, "mutation_token":"<token>"
> }
> ```
> **💬 End-user (prompt):** *"Record a finding that the memory image's OS/kernel is `<resolved build>`, as a DRAFT."*
> **Expect:** the assistant shapes a valid finding with a non-empty `finding_id` and calls `record_finding`; it lands as **DRAFT** (`indexed:false`). `dry_run=True` is the default — persisting needs `dry_run=False` + `mutation_token`. A bot **cannot** self-approve.

### Step 7 — Approve (examiner gate, human-only)

> **🖥️ Operator action:** sign off in the **Examiner Portal** at `https://<TAILNET-HOST>:8443/` (`approve_finding`, HMAC challenge-response): DRAFT → APPROVED. Demo credentials (examiner ID + approver password) live in [approval-portal.md](../docs/05-safety-forensics/approval-portal.md).
> **💬 End-user (prompt):** *"List the DRAFT findings for `MEMDUMP-RAW-2014` and their IDs."* (then approve yourself in the browser)
> **Expect:** the session lists DRAFT findings + IDs; **you** approve in the portal. There is no plain-language approval shortcut — this is the cryptographic chain-of-custody sign-off, deliberately separate.
> **⚠ SIMULATED examiner approval (demo only):** in the recorded run this sign-off was driven by **Playwright (automated), not a human** — see [runs/memdump-raw-2014/EXECUTED-RUN.md](./runs/memdump-raw-2014/EXECUTED-RUN.md). A **real case requires a human examiner** to perform the HMAC sign-off in the portal.

### Step 8 — `report_generate`

> **🖥️ Expert (MCP call):** `report_generate { "profile":"full", "case_id":"MEMDUMP-RAW-2014" }`
> **💬 End-user (prompt):** *"Generate the full SIFT report for `MEMDUMP-RAW-2014`."*
> **Expect:** returns `report_id` + section counts. `approved_finding_count` stays `0` until a finding is approved (Step 7); a DRAFT-only case can return `case_not_found` until there is indexed state. Optionally push accountable IOCs to Wazuh (`wazuh_*` / `promote_iocs`).

---

## 3. Activate & start — prompt sequences

Both lanes hit the **same deterministic MCP tools** — only who drives them differs.

### MANUAL sequence (numbered 💬 prompts; 🖥️ command shown for each)

1. 💬 *"Check my Agentropix forensic environment is ready — is Volatility3 installed?"*
   🖥️ `uv run agentropix-sift doctor`
   **Expect:** each backing binary `OK <path>`, ending `All tools available.` (Volatility3 / `vol` present).

2. 💬 *"How many Agentropix forensic tools are available right now?"*
   🖥️ call the `health` tool
   **Expect:** `status: "ok"` with a live `tool_count` (canonical **73** — trust the live number, not the banner).

3. 💬 *"Open a medium-severity case `MEMDUMP-RAW-2014` for the raw memory dump at `/cases/memdump/memdump.mem`, examiner victor.galvan, and make it active."*
   🖥️ `case_init {…case_id:"MEMDUMP-RAW-2014"…}` then `case_activate {"case_id":"MEMDUMP-RAW-2014"}`
   **Expect:** `case_id MEMDUMP-RAW-2014`, status `active`, pointer written to `/home/admin2/.agentropix/active_case`.

4. 💬 *"Is `MEMDUMP-RAW-2014` the active case and is the indexer reachable?"*
   🖥️ `case_status {"case_id":"MEMDUMP-RAW-2014"}`
   **Expect:** `active: true`, `indexer_reachable: true`.

5. 💬 *"Register `/cases/memdump/memdump.mem` as evidence and give me its SHA-256 custody hash."*
   🖥️ `evidence_register {"path":"/cases/memdump/memdump.mem","examiner_id":"victor.galvan",…}`
   **Expect:** `evidence_id`, evidence SHA-256, `size_bytes 536870912`, `indexed: true`.

6. 💬 *"List the running processes in this memory image."*
   🖥️ `get_pslist {"image":"/cases/memdump/memdump.mem"}`
   **Expect:** a process list (PID/PPID/name) — this first `windows.*` plugin also **auto-detects the kernel profile**, so a populated list confirms the symbol-table match. There is **no separate `windows.info`/`banners` step** (the MCP allowlist exposes analysis plugins only). If it returns empty with `Unable to validate the plugin requirements: kernel.symbol_table_name`, no Windows profile resolved — an honest negative. Counts are discovered (no ground-truth).

7. 💬 *"Show the open network connections / sockets."*
   🖥️ `get_netscan {"image":"/cases/memdump/memdump.mem"}`
   **Expect:** a typed TCP/UDP socket list.

8. 💬 *"Is there any injected or RWX code in this image?"*
   🖥️ `get_malfind {"image":"/cases/memdump/memdump.mem"}`
   **Expect:** malfind hits (injected/RWX VAD regions) or an empty set — both are valid for a generic image.

9. 💬 *"Enumerate the Windows services and build the process tree with LOLBin flags."*
   🖥️ `get_svcscan {"image":"…"}` then `build_process_tree {"image":"…"}`
   **Expect:** a service list and a PPID-linked process forest with any LOLBin flags.

10. 💬 *"Record a DRAFT finding for a notable observation (e.g. the recovered process list)."*
    🖥️ `record_finding {"finding":{"finding_id":"memdump-001",…},"dry_run":false,"mutation_token":"<token>"}`
    **Expect:** finding lands as **DRAFT** (`indexed:false`); `finding_id` required; bot cannot self-approve.

11. 💬 *"List the DRAFT findings and their IDs for `MEMDUMP-RAW-2014`."* (then approve yourself in the portal)
    🖥️ approve in the Examiner Portal (`approve_finding`, HMAC sign-off)
    **Expect:** DRAFT IDs listed; **you** sign off in the browser — no plain-language approval shortcut, by design.

12. 💬 *"Generate the full SIFT report for `MEMDUMP-RAW-2014`."*
    🖥️ `report_generate {"profile":"full","case_id":"MEMDUMP-RAW-2014"}`
    **Expect:** `report_id` + section counts; `approved_finding_count` reflects Step 11 (stays `0` if nothing approved yet; a DRAFT-only case may return `case_not_found` — the correct end-state when nothing was approved).

### AUTONOMOUS sequence (launch → monitor → approve → report)

1. **Launch (interactive autonomous prompt — non-expert lane).**
   💬 *"You are a DFIR analyst with the Agentropix MCP. Investigate case `MEMDUMP-RAW-2014` on the raw memory image `/cases/memdump/memdump.mem`. Run the full memory sequence (pslist → netscan → malfind → svcscan → build_process_tree — the first plugin auto-detects the kernel profile), staging findings as DRAFT. This is a raw `.mem` — there is no partition table, so do NOT run mmls/fls/bulk_extractor. Do NOT approve findings. Finish by generating the full report."*
   🖥️ same prompt works via `claude --print` for a one-shot headless run.
   **Expect:** the agent walks `case_init`→`case_activate`→`evidence_register`→`get_pslist`→`get_netscan`→`get_malfind`→`get_svcscan`→`build_process_tree`→`record_finding`×N (DRAFT)→`report_generate{profile:"full"}`, stopping before approval.

   *Expert headless-driver alternative (detached):*
   🖥️ `AGENTROPIX_MCP_AUTH_TOKEN="<BEARER>" setsid nohup bash -c "python3 /home/admin2/.openclaw/workspace/drivers/agx_gearb.py <case_key> > run.log 2>&1" </dev/null >/dev/null 2>&1 & disown`
   **Expect:** token from env (never argv); first positional is the **case key** (resolved via the driver's `cases.json`), not a path/token. The driver detects the `.mem` as a **memory** image and runs the Volatility chain (`get_pslist`/`get_netscan`/`get_malfind`/`get_svcscan`/`build_process_tree`), checkpointing `SUMMARY.json` per step. Smoke-test with `--preflight` first.

2. **Monitor.**
   💬 *"How's the investigation going — which steps are done?"*
   🖥️ `tail -f run.log` and read `/home/admin2/.openclaw/workspace/drivers/gearB/<case>/SUMMARY.json` (per-step `ok`/`elapsed`/`error`).
   **Expect:** progress narration / per-step `ok` checkpoints; findings staged DRAFT, run stops before the approval gate.

3. **Approve (human-only gate).**
   💬 *"List the staged DRAFT findings and their IDs for `MEMDUMP-RAW-2014`."*
   🖥️ approve in the Examiner Portal (`approve_finding`, HMAC, append-only).
   **Expect:** DRAFT IDs listed; the assistant will not and cannot approve on your behalf — you sign off in the browser.

4. **Report.**
   💬 *"Generate the full SIFT report for `MEMDUMP-RAW-2014`."*
   🖥️ `report_generate {"profile":"full","case_id":"MEMDUMP-RAW-2014"}`
   **Expect:** `report_id` + section counts; once findings are approved, `approved_finding_count` and the report sections populate.

---

## Gotchas specific to this case

| Gotcha | Rule |
|---|---|
| Treating `.mem` like a disk | **No partition table.** Skip `mmls`/`fls`/`run_bulk_extractor`/`scan_yara`-on-disk. Use the Volatility memory chain. |
| Assuming an OS | **No ground-truth / no profile declared.** There is no `windows.info`/`banners` call in the MCP allowlist — the kernel profile is auto-detected by Volatility3 on the first `windows.*` plugin (`get_pslist`). A populated `get_pslist` confirms the symbol-table match; empty results with `Unable to validate ... kernel.symbol_table_name` mean no Windows profile resolved. |
| Expecting `ewfinfo` output | `get_image_info`/`ewfinfo` are **E01-only**. A flat raw `.mem` returns no EWF metadata. |
| `case_id` formatting | `MEMDUMP-RAW-2014` is pre-slugged — no spaces/slashes (`^[A-Za-z0-9._-]{1,128}$`). |
| Findings not persisting | `record_finding` defaults to `dry_run=True` — pass `dry_run=False` + `mutation_token`. |
