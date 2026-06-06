# Case Activation Guide — `contact_me` (memory)

> **LOCAL-ONLY operator runbook.** Real evidence paths and case inventory — do **not** publish.
> Gets an operator **ready to activate this case and start analysis**; it does not run analysis.
> All commands/tools verified against the oracle (`/home/admin2/agentropix-sift` docs+src) and the
> canonical numbers in [`.crew/facts.md`](../.crew/facts.md) (71 MCP tools, 16 SIFT wrappers, 4464
> tests). House style + dual-audience (🖥️ command / 💬 prompt) mirrors
> [`docs/01-overview/user-guide.md`](../docs/01-overview/user-guide.md).

---

## 1. Identification header

| Field | Value |
|---|---|
| **Case name** | `contact_me` — CTF-style memory capture ("contact me") |
| **One-line description** | A single 1 GiB raw RAM image; CTF/training memory-forensics challenge. Treat as an unknown Windows memory capture; Volatility3 auto-detects the kernel profile on the first `windows.*` plugin (`get_pslist`). |
| **Evidence type** | **Memory** (raw RAM dump) |
| **Image file(s)** | `/cases/contact_me/contact_me` (no extension) |
| **Format** | Raw / dd-style RAM capture — `file(1)` = `data` (no container magic; consistent with a raw memory dump, not EWF/E01). `ewfinfo` is **N/A** here (raw, not EWF). |
| **Size** | **1073741824 bytes = 1.0 GiB** (exactly 1 GiB; `du -h` → `1.1G` on disk) |
| **Suggested `case_id` slug** | **`CTF-CONTACT-ME-MEM`** (matches `^[A-Za-z0-9._-]{1,128}$`; no spaces/slashes) |
| **OS / scenario** | Unknown at registration (CTF, no ground-truth/readme file present in `/cases/contact_me/`). Assume Windows; the kernel profile is **auto-detected by Volatility3 on the first `windows.*` plugin** (`get_pslist`) — there is no separate info/banners call in the MCP allowlist. |
| **Recommended path** | **Memory chain** — *not* the disk chain. Skip `mmls`/`fls`/`bulk_extractor`/`scan_yara` (those are for disk images). |
| **Recommended tool chain** | `get_pslist` (processes — also auto-detects the kernel profile) → `get_netscan` (sockets) → `get_malfind` (injected/RWX code) → `get_svcscan` (services) → `build_process_tree` (PPID forest + LOLBin flags) → escape hatch `run_volatility` for any other allowlisted vol3 plugin (`cmdline`, `dlllist`, `handles`, …). |

> **Why memory, not disk.** `file(1)` returns `data` with no partition/EWF magic and the image has no
> extension — there is **no MBR/GPT to `mmls`**. The Sleuth Kit / `bulk_extractor` / YARA-on-disk legs
> do not apply; the Volatility3-backed tools do. (Re-confirmed below with metadata-only commands.)

### Metadata re-confirmation (METADATA-ONLY — no forensic tool was run on the evidence)

```text
$ file /cases/contact_me/contact_me
/cases/contact_me/contact_me: data
$ ls -al /cases/contact_me/contact_me
-rw-rw-r-- 1 admin2 admin2 1073741824 May 30 18:35 /cases/contact_me/contact_me
$ du -h /cases/contact_me/contact_me
1.1G	/cases/contact_me/contact_me
# ewfinfo: N/A — raw image, not an EWF/E01 container.
# No ground-truth/readme file present in /cases/contact_me/ (CTF; scenario inferred from filename + magic).
```

---

## 2. Instantiated procedure (template steps 0 → 8, real values)

The template lives at
[`/home/admin2/agentropix-sift/docs/tools/END-USER-CASE-GUIDE.md`](/home/admin2/agentropix-sift/docs/tools/END-USER-CASE-GUIDE.md).
These are **MCP tool calls** (not a shell CLI). Run them from any client with the `agentropix-sift`
MCP bound (Claude CLI recommended; Claude Desktop via the `mcp-remote` shim). MCP endpoint:
`http://<TAILNET-HOST>:8765/mcp` (tailnet-only; get the real host + bearer token from your operator —
not reproduced here). One active case at a time (pointer `~/.agentropix/active_case`). Consistent
`examiner_id` for chain of custody: `victor.galvan`.

### Step 0 — Pre-flight (operator-local)

> **🖥️ Expert (command):**
> ```bash
> uv run agentropix-sift doctor          # expect: All tools available.  (vol/log2timeline/fls/mmls/… )
> bash /home/admin2/.openclaw/workspace/scripts/start-agentropix-mcp.sh status   # expect health: HTTP 200
> ```
> **💬 End-user (prompt):** *"Check the Agentropix forensic environment — are all tools installed and is the MCP server healthy?"*

The memory chain depends on **Volatility3** (`vol`) being `[OK …]` in `doctor`. (No `ewfverify`
integrity step here — that is EWF-only; this is a raw image.)

### Step 1 — Pick the evidence & choose the slug

- Evidence: `/cases/contact_me/contact_me` (already under `/cases/`).
- Slug: **`CTF-CONTACT-ME-MEM`** (the directory name `contact_me` is already slug-legal, but the
  explicit slug is clearer and collision-proof).

### Step 2 — Activate (register) the case — `case_init`

> **🖥️ Expert (MCP call):**
> ```text
> case_init { "case_name":"CTF contact_me (raw memory)",
>             "examiner_id":"victor.galvan",
>             "case_id":"CTF-CONTACT-ME-MEM",
>             "case_dir":"/cases/contact_me",
>             "description":"Single 1 GiB raw RAM capture; CTF-style memory challenge.",
>             "incident_type":"dfir", "severity":"medium",
>             "scope":"/cases/contact_me/contact_me", "tags":["ctf","memory"] }
> ```
> **💬 End-user (prompt):** *"Open a medium-severity DFIR case `CTF-CONTACT-ME-MEM` named 'CTF contact_me (raw memory)' for the image at `/cases/contact_me/contact_me`, examiner victor.galvan, and make it the active case."*

Writes the active-case pointer first, then upserts into `agentropix-cases`. **Idempotent on `case_id`.**

### Step 3 — Confirm it's active — `case_status`

> **🖥️ Expert (MCP call):** `case_status {}`   (or `case_status { "case_id":"CTF-CONTACT-ME-MEM" }`)
> **💬 End-user (prompt):** *"Is `CTF-CONTACT-ME-MEM` the active case and is the indexer reachable?"*

Check `active: true` and `indexer_reachable: true`.

### Step 4 — Register evidence (SHA-256 chain of custody) — `evidence_register`

> **🖥️ Expert (MCP call):**
> ```text
> evidence_register { "path":"/cases/contact_me/contact_me",
>                     "description":"Raw RAM capture (1 GiB, no extension; file(1)=data)",
>                     "examiner_id":"victor.galvan" }   # case_id omitted = active case
> ```
> **💬 End-user (prompt):** *"Register `/cases/contact_me/contact_me` as evidence in this case and give me its SHA-256 custody hash."*

Hashes the file (sha256 + size) and records it under `agentropix-evidence-YYYY.MM.DD`. Expect
`size_bytes 1073741824`. (`get_image_info`/`ewfinfo` acquisition metadata is **not applicable** — this
is a raw dump with no EWF header; rely on the SHA-256 + size as the custody anchor.)

### Step 5 — Analyze (MEMORY tools — all resolve to the active case)

The standard memory sweep (the first `windows.*` plugin auto-detects the kernel profile):

> **🖥️ Expert (MCP calls):**
> ```text
> get_pslist        { "image":"/cases/contact_me/contact_me" }     # processes (auto-detects the kernel profile)
> get_netscan       { "image":"/cases/contact_me/contact_me" }     # sockets/connections
> get_malfind       { "image":"/cases/contact_me/contact_me" }     # injected / RWX code
> get_svcscan       { "image":"/cases/contact_me/contact_me" }     # services
> build_process_tree{ "image":"/cases/contact_me/contact_me" }     # PPID forest + LOLBin flags
> # escape hatch for any other vol3 plugin (short alias or canonical id), e.g.:
> run_volatility    { "target":"/cases/contact_me/contact_me", "plugin":"cmdline" }
> run_volatility    { "target":"/cases/contact_me/contact_me", "plugin":"netstat" }
> ```
> **💬 End-user (prompt):** *"Analyse this memory image: list running processes and network connections, check for injected code, list services, and build the process tree."*

Note the parameter split: the dedicated `get_*` tools take **`image`**; `run_volatility` takes
**`target`** + **`plugin`** (short aliases like `"malfind"`/`"netscan"`/`"cmdline"` or canonical ids
like `"windows.malfind.Malfind"`) and an optional `args` dict (`{"pid":4732}` → `--pid 4732`). These
are the Volatility3-backed memory tools; the disk tools (`mmls`/`fls`/`run_bulk_extractor`/`scan_yara`)
do **not** apply to this image.

### Step 6 — Record findings (DRAFT-gated) — `record_finding`

> **🖥️ Expert (MCP call):**
> ```text
> record_finding { "finding": { "finding_id":"ctf-contactme-001", "title":"...",
>                               "severity":"medium", ... },
>                  "dry_run": false, "mutation_token":"<token>" }
> ```
> **💬 End-user (prompt):** *"Record a finding for [observation], give it a finding_id, and stage it as a draft."*

`dry_run=True` is the **default** (previews, writes nothing). To persist, pass `dry_run=False` **and**
a valid `mutation_token`. `finding` must be a dict with a non-empty `finding_id` (else `ValueError`).
Persisted findings land as **DRAFT** — they cannot self-approve. (Timeline events:
`record_timeline_event { event, hostname }`.)

### Step 7 — Approve (examiner gate — human-only)

Approval is a **human-attested HMAC challenge-response** via the Examiner Portal / `approve_finding`
(DRAFT → APPROVED). **Deliberately not automated** — this is the cryptographic chain-of-custody
sign-off. **HARD-STOP** for autonomous runs: a bot must not sign.

### Step 8 — Report (& optional IOC push)

> **🖥️ Expert (MCP call):** `report_generate { "profile":"full" }`   (case_id omitted = active case)
> **💬 End-user (prompt):** *"Generate the full report for `CTF-CONTACT-ME-MEM`."*

`approved_finding_count` stays `0` until a finding is approved (Step 7) — DRAFT findings are not
surfaced. Then optionally push accountable IOCs to Wazuh via `promote_iocs` / `wazuh_*` (operator-gated,
needs an `egt_` mutation token).

---

## 3. "Activate & start" prompt sequences

Two lanes, same deterministic MCP engine. Run top-to-bottom; check each **Expect:** before the next.

### 3A — MANUAL sequence (💬 prompts; 🖥️ command equivalent shown)

1. 💬 *"Check the Agentropix forensic environment — are all tools installed and is the MCP server healthy?"*
   🖥️ `uv run agentropix-sift doctor` ; `…/start-agentropix-mcp.sh status`
   **Expect:** `doctor` ends `All tools available.` (with `vol` present); MCP `health` returns `status:"ok"` + a live `tool_count`.

2. 💬 *"How many Agentropix forensic tools are available right now?"*
   🖥️ call the `health` tool
   **Expect:** live `tool_count` (canonical **71**; a live server may report **72** — trust the live number, not the banner).

3. 💬 *"Open a medium-severity DFIR case `CTF-CONTACT-ME-MEM` named 'CTF contact_me (raw memory)' for `/cases/contact_me/contact_me`, examiner victor.galvan, and make it active."*
   🖥️ `case_init {…case_id:"CTF-CONTACT-ME-MEM"…}` then `case_activate { "case_id":"CTF-CONTACT-ME-MEM" }`
   **Expect:** returns `case_id CTF-CONTACT-ME-MEM`, status `active`, active-case pointer written to `~/.agentropix/active_case`.

4. 💬 *"Is `CTF-CONTACT-ME-MEM` the active case and is the indexer reachable?"*
   🖥️ `case_status {}`
   **Expect:** `active: true`, `indexer_reachable: true`.

5. 💬 *"Register `/cases/contact_me/contact_me` as evidence in this case and give me its SHA-256 custody hash."*
   🖥️ `evidence_register { "path":"/cases/contact_me/contact_me", … }`
   **Expect:** returns `evidence_id` + evidence SHA-256, `size_bytes 1073741824`, bound to the active case (`indexed:true`).

6. 💬 *"List the running processes in this memory image."*
   🖥️ `get_pslist { "image":"/cases/contact_me/contact_me" }`
   **Expect:** a non-empty process list (PID/PPID/name/start-time rows). This first `windows.*` plugin **auto-detects the kernel profile** — a populated list confirms it is a valid Windows capture and the symbol table matched. There is **no separate `windows.info` step** (the MCP allowlist exposes analysis plugins only).

7. 💬 *"Show the network connections and open sockets."*
   🖥️ `get_netscan { "image":"/cases/contact_me/contact_me" }`
   **Expect:** a socket/connection table (local/remote addr, state, owning PID) — possibly empty, which is itself a finding.

8. 💬 *"Check for injected or RWX code."*
   🖥️ `get_malfind { "image":"/cases/contact_me/contact_me" }`
   **Expect:** a malfind report (suspicious RWX regions per PID, or an empty list = clean).

9. 💬 *"List the Windows services and build the process tree with LOLBin flags."*
   🖥️ `get_svcscan { "image":"…" }` then `build_process_tree { "image":"…" }`
   **Expect:** a services table and a PPID forest with any LOLBin/suspicious-parent flags surfaced.

10. 💬 *"Run the cmdline plugin to see each process's command line."*
    🖥️ `run_volatility { "target":"/cases/contact_me/contact_me", "plugin":"cmdline" }`
    **Expect:** per-PID command-line rows (vol3 JSON preserved verbatim in `rows`).

11. 💬 *"Record a finding for [your observation], give it a finding_id, and stage it as a draft."*
    🖥️ `record_finding { "finding":{ "finding_id":"ctf-contactme-001", … }, "dry_run":false, "mutation_token":"<token>" }`
    **Expect:** lands as **DRAFT** (`indexed:false`); the assistant cannot self-approve.

12. 💬 *"Which findings are waiting for my approval and what are their IDs?"*
    🖥️ (browser) Examiner Portal at `https://<TAILNET-HOST>:8443/`
    **Expect:** the DRAFT list with IDs; **you** sign off yourself in the portal (HMAC) — no plain-language approval shortcut, by design.

13. 💬 *"Generate the full report for `CTF-CONTACT-ME-MEM`."*
    🖥️ `report_generate { "profile":"full" }`
    **Expect:** a `report_id` + section counts; `approved_finding_count 0` until a finding is approved (a DRAFT-only case can return `case_not_found` until there is indexed state).

### 3B — AUTONOMOUS sequence (launch driver → monitor → approve → report)

> **Note (driver registry).** The headless driver (`agx_gearb.py`) resolves a **logical `<case_key>`**
> through `cases.json` — `contact_me` is **not yet registered** there, and memory cases are **not
> live-validated**. Two ways to run autonomously:
> **(a) Non-expert / recommended here — the interactive autonomous prompt (no driver, no `cases.json` edit).**
> **(b) Expert — add a `cases.json` entry, then launch the detached driver with `--allow-unvalidated`.**

1. 💬 **(a) Interactive autonomous prompt** — paste into a CLI session with the MCP attached:
   *"You are a DFIR analyst with the Agentropix MCP. Investigate case `CTF-CONTACT-ME-MEM` on the raw **memory** image `/cases/contact_me/contact_me`. This is a memory capture — run the memory sequence (`get_pslist` → `get_netscan` → `get_malfind` → `get_svcscan` → `build_process_tree` — the first plugin auto-detects the kernel profile — plus `run_volatility` for `cmdline`/`netstat` as warranted). Do NOT run disk tools (mmls/fls/bulk_extractor) — there is no partition table. Stage findings as DRAFT. Do NOT approve findings. Finish by generating the full report and summarising the thread chain."*
   🖥️ Same prompt works one-shot via `claude --print`.
   **Expect:** the agent runs `case_init`→`case_activate`→`evidence_register`→the memory sweep (`get_pslist`→`get_netscan`→`get_malfind`→`get_svcscan`→`build_process_tree`)→`record_finding × N` (DRAFT)→`report_generate{profile:"full"}`, staging all findings DRAFT and **stopping before approval**.

2. 🖥️ **(b) Expert — detached driver** (token from ENV, `<case_key>` positional; `--allow-unvalidated` because memory cases aren't live-validated). First add a `contact_me` entry to `/home/admin2/.openclaw/workspace/drivers/cases.json` (`kind:"memory"`, `default_image:"/cases/contact_me/contact_me"`, `validated:false`), then:
   ```bash
   AGENTROPIX_MCP_AUTH_TOKEN="<BEARER_TOKEN>" \
     setsid nohup bash -c "python3 /home/admin2/.openclaw/workspace/drivers/agx_gearb.py contact_me --allow-unvalidated > run.log 2>&1" </dev/null >/dev/null 2>&1 &
   disown
   ```
   (Smoke-test first with `--preflight` appended — session+health+schema only, no case record.) **Token is read from the environment, never an argv positional; the first positional is the `<case_key>`.**
   **Expect:** the driver holds one persistent MCP session, walks the **memory** sequence (`get_pslist`/`get_netscan`/`get_malfind`/`get_svcscan`/`build_process_tree`), and checkpoints `SUMMARY.json` after every step.

3. 🖥️ **Monitor:**
   ```bash
   tail -f run.log
   # per-step checkpoint: /home/admin2/.openclaw/workspace/drivers/gearB/contact_me/SUMMARY.json
   ```
   💬 (interactive lane) *"How's the investigation going — which steps are done?"*
   **Expect:** progress per step (`ok`/`elapsed`/`error`); the run stages findings DRAFT and **stops at the approval gate**. A killed driver is resumable — `SUMMARY.json` preserves completed steps.

4. 💬 **Approve (human-only):** *"Which findings are waiting for my approval and what are their IDs?"* then sign off in the portal.
   🖥️ Examiner Portal `https://<TAILNET-HOST>:8443/` (HMAC challenge-response, append-only).
   **Expect:** DRAFT list with IDs; you approve yourself — **HARD-STOP** for any autonomous agent (a bot must not sign chain-of-custody).

5. 💬 **Report & verify:** *"Generate the full report for `CTF-CONTACT-ME-MEM`, then verify its seal."*
   🖥️ `report_generate { "profile":"full" }` ; `uv run python scripts/verify_seal.py <report>.json`
   **Expect:** `report_id` + section counts; once findings are approved, `approved_finding_count` and report sections populate; the seal verifier confirms the report + audit log are unaltered since sealing (HMAC-SHA256, evidence-SHA-256-bound).

---

## 4. Cross-checks (oracle + canonical)

- **71** MCP tools / **16** SIFT forensic wrappers / **4464** tests — `.crew/facts.md`
  (`mcp_tool_count=71`). A live server may report `72` (reproducible +1 over canonical; trust the live
  `health.tool_count`).
- Memory tool surface verified in `src/agentropix_sift/mcp_server/fastmcp_app.py`: `get_pslist`,
  `get_netscan`, `get_malfind`, `get_svcscan`, `build_process_tree` (param `image`);
  `run_volatility(target, plugin, args?, timeout_seconds?)` is the generic vol3 escape hatch (W-098).
- `case_id` regex `^[A-Za-z0-9._-]{1,128}$` — `CTF-CONTACT-ME-MEM` complies.
- `record_finding` defaults `dry_run=True` (preview only); needs `dry_run=False` + `mutation_token` to
  persist; findings land DRAFT. Approval is the human HMAC gate (Step 7) — not auto-done.
- No secrets / no raw internal IPs: MCP endpoint shown as `http://<TAILNET-HOST>:8765/mcp`, portal as
  `https://<TAILNET-HOST>:8443/`; bearer token never reproduced.
