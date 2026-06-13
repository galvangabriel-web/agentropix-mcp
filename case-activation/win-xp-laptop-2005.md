# Case Activation Guide — `win-xp-laptop-2005`

> **LOCAL ONLY — real case inventory. Do not publish.** This file lives under
> `/home/admin2/docu_agentro/case-activation/` (gitignored). It contains real
> evidence paths for an operator on this workstation. No secrets, no raw IPs.
>
> Procedure source-of-truth: `END-USER-CASE-GUIDE.md`
> (the canonical 8-step flow). House style + dual-audience tracks + numbered Prompt
> Playbook mirror [`docs/01-overview/user-guide.md`](../docs/01-overview/user-guide.md).
> Canonical numbers cite [`.crew/facts.md`](../docs/08-reference/canonical-facts.md)
> (72 MCP tools, 16 SIFT wrappers, 4687 tests).
>
> **Goal of this guide:** get the operator *ready to activate this case and start
> analysis* — not to run analysis. Everything below was profiled **metadata-only**
> (`ls` / `file` / `du` / a read-only byte/strings peek). **No forensic tool has been
> run against the evidence.**

---

## 1. Identification header

| Field | Value |
|---|---|
| **Case name** | Windows XP laptop image — 2005-06-25 |
| **One-line description** | Single 512 MiB raw image dated 2005-06-25 from a Windows XP laptop; the folder name doubles as the filename. |
| **Suggested `case_id` slug** | **`WIN-XP-LAPTOP-2005`** (matches `^[A-Za-z0-9._-]{1,128}$`; no spaces, no slashes) |
| **Examiner** | `victor.galvan` (chain-of-custody stamp; keep it consistent) |
| **Evidence file** | `/cases/win-xp-laptop-2005-06-25.img/win-xp-laptop-2005-06-25.img` |
| **Format** | Raw image (`.img`). `file(1)` → `data`; **not** an EWF/E01 (`ewfinfo` rejects the `.img` extension — *expected*, this is not an EnCase container). |
| **Size** | **536,715,264 bytes** = exactly 512 MiB on disk (`du -h` → `512M`; `1,048,272` × 512-byte sectors). |
| **Companion files** | None — no `ewfverify`-able hash sidecar, no `.md5`, no `ground_truth_*.yaml`, no `readme`. Custody hash will be established by `evidence_register` (Phase 3). |
| **Declared OS / scenario** | Windows XP laptop, 2005-06-25 (from the profile). Confirmed: in-image strings show `OS=Windows_NT`, `windir=C:\WINDOWS`, loaded modules `ntoskrnl.exe` / `svchost.exe` / `mqsvc.exe` — a live Windows XP system. |

### ⚠️ Evidence type — read this before activating

The profile labels this `type:"disk"` and says *"treat as raw disk evidence (confirm
partition layout on activation)."* **That confirmation was performed here (metadata
only) and it changes the routing.** The bytes say this is **a memory image, not a
partitioned disk**:

- **No MBR.** Bytes 510–511 are `00 00`, not the `55 AA` boot signature; the partition-
  table region (offset 446) holds non-table garbage.
- **No filesystem boot sector.** Offset 0 is `7e af 00 f0 …` — a real-mode interrupt-
  vector-table pattern, i.e. **physical RAM page 0**, not an NTFS/FAT VBR. A first-64 MiB
  magic scan finds **no `NTFS    ` OEM string and no crashdump (`PAGEDUMP`) header**.
- **Memory-resident artifacts dominate.** Strings are full of process **environment
  blocks** (`OS=Windows_NT`, `windir=`, `SystemRoot=`, `Path=…`, `TMP=…`) repeated
  hundreds of times, plus loaded-module paths (`ntoskrnl.exe`, `svchost.exe`,
  `mqsvc.exe`) — the signature of a **raw RAM capture**, not a disk filesystem.

> **Bottom line for the operator:** the *folder name* says "laptop disk," but the
> *ground-truth bytes* say **Windows XP RAM (512 MiB, raw, no header)** — which fits a
> 2005-era XP laptop with ~512 MB RAM. Treat it as **memory evidence** and use the
> Volatility chain. If a later read confirms a filesystem after all, fall back to the
> disk chain (`mmls` → `fls`) and pass the mmls-derived offset. Below, the memory chain
> is primary; the disk fallback is given as a sidebar.

### Recommended path + tool chain

**Primary — MEMORY (raw RAM, no MBR/header):** walk the Volatility-backed memory
tools. The first `windows.*` plugin (`get_pslist`) auto-detects the kernel profile —
Volatility 3 is profile-less, so there is no separate "identify OS" step. Process list →
network → injection → services → process forest:

```
get_pslist  →  get_netscan  →  get_malfind  →  get_svcscan  →  build_process_tree
```

> `get_image_info` is **not** in this chain. It drives `ewfinfo`/EWF metadata only; on a
> raw RAM image it returns all-empty fields and cannot ID the OS/build. The kernel symbol
> table is auto-detected on the first `windows.*` plugin (`get_pslist`): a populated
> `pslist` confirms the symbol-table match; an empty result with *"Unable to validate the
> plugin requirements: kernel.symbol_table_name"* means no profile resolved (i.e. this is
> not memory — switch to the disk fallback).

`run_volatility { plugin: ... }` is the general escape hatch for any plugin the named
wrappers don't cover. Plugin names must be a **short alias** (`dlllist`, `cmdline`,
`handles`, `hivelist`) or a full **canonical id** (`windows.dlllist.DllList`,
`windows.cmdline.CmdLine`, `windows.handles.Handles`, `windows.registry.hivelist.HiveList`);
the bare middle form (`windows.dlllist`, no class suffix) is rejected. For XP/x86 images,
Volatility 3 auto-selects the symbol table — let the tool detect it on `get_pslist`; if it
cannot, that is the cue this is *not* memory and you switch to the disk fallback.

**Fallback — DISK (only if a filesystem/partition is confirmed on a deeper read):**

```
get_partitions (mmls)  →  fls (mmls offset; B2)  live + deleted_only
                        →  run_bulk_extractor (out_dir under an allowlisted prefix; B3)
                        →  scan_yara  →  extract_files → get_registry / get_shimcache / get_prefetch / get_evt
```

Note for XP specifically: it has **prefetch** but **no Amcache** (`get_amcache` is Win7+)
and uses **`.evt`** logs (**`get_evt`**), not `.evtx` (`get_evtx`).

---

## 2. Instantiated procedure (template steps 0 → 8, this case's real values)

> Steps 2–8 are **MCP tool calls** (Claude CLI / Desktop / the live server on the
> tailnet at `siftworkstation.<tailnet>.ts.net:8765/mcp`). There is no
> `agentropix-sift case init` shell command — these are MCP tools. There is exactly
> **one active case** at a time (`~/.agentropix/active_case`).

### Step 0 — Pre-flight (operator shell)

> **🖥️ Command:**
> ```bash
> uv run agentropix-sift doctor                 # expect: "All tools available."
> bash /home/admin2/.openclaw/workspace/scripts/start-agentropix-mcp.sh status   # expect health HTTP 200
> ```
> **💬 Prompt:** *"Check that my Agentropix forensic environment is ready and the MCP server is healthy."*

`ewfverify` is **N/A** here — this is a raw `.img`, not an EWF container. The byte-intact
custody anchor is established instead by the SHA-256 in Step 4 (`evidence_register`).

### Step 1 — Pick evidence & slug

Evidence is already under `/cases/`. Slug = **`WIN-XP-LAPTOP-2005`**.

### Step 2 — Activate (register) the case — `case_init`

> **🖥️ MCP call:**
> ```text
> case_init {
>   "case_name":   "Windows XP laptop image — 2005-06-25",
>   "examiner_id": "victor.galvan",
>   "case_id":     "WIN-XP-LAPTOP-2005",
>   "case_dir":    "/cases/win-xp-laptop-2005-06-25.img",
>   "description": "Single 512 MiB raw image from a Windows XP laptop, dated 2005-06-25; byte-profile indicates a raw RAM capture (no MBR/filesystem header).",
>   "incident_type": "dfir",
>   "severity":    "medium",
>   "tags":        ["win-xp","memory","2005","raw-img"]
> }
> ```
> **💬 Prompt:** *"Open a new case `WIN-XP-LAPTOP-2005` for the Windows XP laptop image at `/cases/win-xp-laptop-2005-06-25.img`, examiner victor.galvan, severity medium."*

`case_init` writes the active-case pointer first, then upserts the record. **Idempotent
on `case_id`** — re-running the same slug updates, never duplicates.

### Step 2b — Confirm active — `case_status`

> **🖥️ MCP call:** `case_status {}`  (or `case_status { "case_id":"WIN-XP-LAPTOP-2005" }`)
> **💬 Prompt:** *"Is `WIN-XP-LAPTOP-2005` the active case and is the indexer reachable?"*

Check `active: true` and `indexer_reachable: true`. (If you ran other `case_init` calls in
between, re-activate with `case_activate { "case_id":"WIN-XP-LAPTOP-2005" }`.)

### Step 3 — Register evidence (SHA-256 custody) — `evidence_register`

> **🖥️ MCP call:**
> ```text
> evidence_register {
>   "path":        "/cases/win-xp-laptop-2005-06-25.img/win-xp-laptop-2005-06-25.img",
>   "description": "Windows XP laptop raw image (512 MiB; raw RAM capture)",
>   "examiner_id": "victor.galvan"
> }
> ```
> **💬 Prompt:** *"Register the win-xp-laptop image as evidence and give me its SHA-256 custody hash."*

Returns `evidence_id`, evidence **SHA-256**, and `size_bytes 536715264` bound to the
active case. `evidence_id` is deterministic over (case_id, path, sha256).

### Step 4 — Analyze (MEMORY chain — primary)

> **🖥️ MCP calls (memory):**
> ```text
> get_pslist         { "image":"/cases/win-xp-laptop-2005-06-25.img/win-xp-laptop-2005-06-25.img" }  # first windows.* plugin — auto-detects the kernel profile
> get_netscan        { "image":"..." }
> get_malfind        { "image":"..." }
> get_svcscan        { "image":"..." }
> build_process_tree { "image":"..." }
> # general plugin escape hatch (alias or canonical id — never the bare windows.X form):
> run_volatility     { "image":"...", "plugin":"cmdline" }   # or dlllist / handles / hivelist (canonical: windows.cmdline.CmdLine / windows.dlllist.DllList / windows.handles.Handles / windows.registry.hivelist.HiveList)
> ```
> **💬 Prompt:** *"Analyse this memory image: what processes were running, what network connections were open, is there injected code, and what services and process tree look suspicious?"*

> **Disk fallback (only if a filesystem/partition is confirmed):**
> ```text
> get_partitions { "image":"...img" }                       # mmls — find the partition start sector
> fls            { "image":"...img", "offset":<sector>, "recursive":true }                 # B2: always pass mmls offset
> fls            { "image":"...img", "offset":<sector>, "recursive":true, "deleted_only":true }
> run_bulk_extractor { "target":"...img", "out_dir":"/tmp/agentropix-sift-winxp2005-be", "max_features":1000 }   # B3: allowlisted out_dir
> ```
> XP artifacts: `get_prefetch` (XP has prefetch), `get_evt` (XP `.evt`, **not** `.evtx`),
> **no** `get_amcache` (Win7+ only).

### Step 5 — Record findings (DRAFT-gated) — `record_finding`

> **🖥️ MCP call:**
> ```text
> record_finding {
>   "finding": { "finding_id":"winxp2005-mem-001", "title":"...", "severity":"medium", ... },
>   "dry_run": false,            # default is TRUE (preview only); pass false + a mutation_token to persist
>   "mutation_token": "<token>"
> }
> ```
> **💬 Prompt:** *"Record a medium-severity finding for <observation>, with a finding_id, citing the relevant artifact."*

Every finding needs a non-empty **`finding_id`** (B4). `dry_run=True` is the default and
writes nothing. Persisted findings land as **DRAFT** — they cannot self-approve. Timeline:
`record_timeline_event { event, hostname }`.

### Step 6 — Approve (examiner gate) — `approve_finding`

> **🖥️ Step:** human-only HMAC challenge-response in the Examiner Portal
> (`https://siftworkstation.<tailnet>.ts.net:8443/`) / `approve_finding`. DRAFT → APPROVED.
> **💬 Prompt:** *"Which findings are waiting for my approval, and what are their IDs?"* — then you sign off **yourself** in the browser portal.

This is the deliberate cryptographic chain-of-custody sign-off. **A bot must not sign it.**

### Step 7 — Report — `report_generate`

> **🖥️ MCP call:** `report_generate { "profile":"full", "case_id":null }`
> **💬 Prompt:** *"Generate the full report for this case."*

`approved_finding_count` stays `0` until a finding is approved (working as designed). A
brand-new DRAFT-only case can return `case_not_found` until there is indexed state.

### Step 8 — (Optional) Push IOCs to Wazuh

> **🖥️ MCP call:** `wazuh_index_findings { "dry_run":true }` first, then a live push with an `egt_` token.
> **💬 Prompt:** *"Dry-run the Wazuh push of the curated IOCs and tell me what would be indexed."*

For a 2005 image, expect 0 docs at the default Wazuh time range — widen the range on the
`@timestamp` field.

---

## 3. "Activate & start" prompt sequences

Both lanes hit the **same deterministic MCP engine** (72 tools, 16 SIFT wrappers — cite
`.crew/facts.md`). Each step shows the **💬 prompt** and its **🖥️ command/MCP-call**
equivalent, with an **Expect:** line. Run top-to-bottom; check Expect before continuing.

### Manual path (you drive each step)

1. > 💬 *"Check that my Agentropix forensic environment is ready and the MCP server is healthy."*
   > 🖥️ `uv run agentropix-sift doctor` ; `…/start-agentropix-mcp.sh status`
   **Expect:** `doctor` ends with `All tools available.`; `health` returns `status:"ok"` with a live `tool_count`.

2. > 💬 *"How many Agentropix forensic tools are available right now?"*
   > 🖥️ call `health`
   **Expect:** live `tool_count` (canonical **72**; trust the live number, not the banner).

3. > 💬 *"Open a new case `WIN-XP-LAPTOP-2005` for the Windows XP laptop image at `/cases/win-xp-laptop-2005-06-25.img`, examiner victor.galvan, severity medium, and make it the active case."*
   > 🖥️ `case_init { case_id:"WIN-XP-LAPTOP-2005", … }` then `case_activate { case_id:"WIN-XP-LAPTOP-2005" }`
   **Expect:** a `case_id` of `WIN-XP-LAPTOP-2005`, status `active`, active-case pointer written.

4. > 💬 *"Confirm `WIN-XP-LAPTOP-2005` is the active case and the indexer is reachable."*
   > 🖥️ `case_status {}`
   **Expect:** `active:true` and `indexer_reachable:true`.

5. > 💬 *"Register the win-xp-laptop image as evidence and give me its SHA-256 custody hash."*
   > 🖥️ `evidence_register { path:"/cases/win-xp-laptop-2005-06-25.img/win-xp-laptop-2005-06-25.img", … }`
   **Expect:** an `evidence_id` and evidence SHA-256, `size_bytes 536715264`, bound to the active case.

6. > 💬 *"Analyse this memory image: list the running processes and confirm the OS."*
   > 🖥️ `get_pslist { image:"…win-xp-laptop-2005-06-25.img" }`
   **Expect:** a populated XP process list — `get_pslist` is the first `windows.*` plugin, so it auto-detects the kernel symbol table (no separate OS-ID step). An empty result with a `kernel.symbol_table_name` error means no profile resolved (not memory) — switch to the disk fallback. *(`get_image_info` is EWF-only and returns empty on a raw RAM image, so it is not used here.)*

7. > 💬 *"What network connections were open, and is there any injected code?"*
   > 🖥️ `get_netscan` → `get_malfind` (image=…win-xp-laptop-2005-06-25.img)
   **Expect:** open sockets, and any RWX/injected regions from `malfind`. *(If Volatility cannot resolve a symbol table, that signals it is not memory — switch to the disk fallback: `get_partitions` → `fls` with the mmls offset.)*

8. > 💬 *"Show me the services and the full process tree, and flag anything suspicious."*
   > 🖥️ `get_svcscan` → `build_process_tree` (image=…win-xp-laptop-2005-06-25.img)
   **Expect:** the service list and a PPID forest with LOLBin flags.

9. > 💬 *"Record a medium-severity finding for <observation>, give it a finding_id, and cite the relevant artifact."*
   > 🖥️ `record_finding { finding:{ finding_id:"winxp2005-mem-001", … }, dry_run:false, mutation_token:"<token>" }`
   **Expect:** the finding persists as **DRAFT** (`indexed:false`); it cannot self-approve.

10. > 💬 *"Which findings are waiting for my approval and what are their IDs?"*
    > 🖥️ list DRAFT findings; approve in the portal `https://siftworkstation.<tailnet>.ts.net:8443/`
    **Expect:** the DRAFT finding IDs listed; **you** sign off in the browser portal (no plain-language approval shortcut, by design).

11. > 💬 *"Generate the full report for this case."*
    > 🖥️ `report_generate { profile:"full" }`
    **Expect:** a `report_id` and section counts; `approved_finding_count` stays `0` until a finding is approved.

### Autonomous path (launch driver → monitor → approve → report)

1. > 💬 *"You are a DFIR analyst with the Agentropix MCP. Investigate case `WIN-XP-LAPTOP-2005` on image `/cases/win-xp-laptop-2005-06-25.img/win-xp-laptop-2005-06-25.img`. The byte-profile indicates a raw Windows XP memory capture, so run the memory sequence (`get_pslist` → `get_netscan` → `get_malfind` → `get_svcscan` → `build_process_tree`, plus `run_volatility` with a short-alias or canonical plugin name for any extra plugin). The first `windows.*` plugin (`get_pslist`) auto-detects the kernel profile, so there is no separate `get_image_info` OS-ID step (it is EWF-only and returns empty on a raw RAM image). If a filesystem is detected instead, fall back to the disk chain using mmls-derived offsets for `fls` and an `out_dir` under `/tmp/agentropix-sift-winxp2005`. Stage findings as DRAFT. Do NOT approve. Finish by generating the full report."*
   > 🖥️ Detached headless driver (token from ENV, case_key positional — never argv):
   > ```bash
   > AGENTROPIX_MCP_AUTH_TOKEN="<BEARER_TOKEN>" \
   >   setsid nohup bash -c "python3 /home/admin2/.openclaw/workspace/drivers/agx_gearb.py win-xp-laptop-2005 > run.log 2>&1" </dev/null >/dev/null 2>&1 &
   > disown
   > ```
   > *(Smoke-test first with `--preflight` after the case key — session+health+schema only, no case record. The case key must exist in the driver's `cases.json`; add this case there before the unattended run.)*
   **Expect:** the agent walks the memory sequence end-to-end, stages findings as **DRAFT**, and **stops before approval**.

2. > 💬 *"How's the investigation going — which steps are done?"*
   > 🖥️ `tail -f run.log` ; read `/home/admin2/.openclaw/workspace/drivers/gearB/win-xp-laptop-2005/SUMMARY.json`
   **Expect:** per-step `ok`/`elapsed`/`error` checkpoints; the run survives long blocking calls because it is detached (B5) and idempotent.

3. > 💬 *"Which findings are waiting for my approval and what are their IDs?"*
   > 🖥️ list DRAFT findings; approve in the portal `https://siftworkstation.<tailnet>.ts.net:8443/`
   **Expect:** the DRAFT finding IDs listed; **you** approve in the browser portal (HMAC sign-off, append-only) — the assistant cannot approve on your behalf.

4. > 💬 *"Generate the full report for this case."*
   > 🖥️ `report_generate { profile:"full" }`
   **Expect:** a `report_id` and section counts; once findings are approved, `approved_finding_count` and the report sections populate.

5. > 💬 *"Verify the seal on this report — confirm it hasn't been tampered with since it was generated."*
   > 🖥️ `uv run python scripts/verify_seal.py <report>.json`
   **Expect:** the seal verifier confirms the report and audit log are intact and unaltered since sealing (HMAC-SHA256, evidence-SHA-256-bound).

---

## Gotchas specific to this case

| Gotcha | Why it bites here | Rule |
|---|---|---|
| Profile says `disk`, bytes say memory | No `55 AA` MBR, no NTFS boot sector, IVT at offset 0, RAM environment-block strings | Run the **memory** chain. Confirm with `get_pslist` — a populated pslist (auto-detected kernel symbols) confirms memory; an empty pslist + `kernel.symbol_table_name` error is the cue to fall back to disk (`mmls`/`fls`). `get_image_info` gives no OS signal on a raw memory image (EWF-only). |
| `ewfverify`/`ewfinfo` fail | This is a raw `.img`, not an EWF container | Skip EWF verify; establish custody via `evidence_register` SHA-256 (Step 3). |
| No companion hash/ground-truth file | Nothing to cross-check the acquisition against | The `evidence_register` SHA-256 is the custody anchor; record it. |
| `fls` without offset (disk fallback only) | If you do fall back, starting at offset 0 → `Cannot determine file system type` (B2) | Pass the mmls-derived partition `offset`. |
| `out_dir` rejected (disk fallback only) | Thymus allowlist (B3) | Write under `/tmp/agentropix-sift-*`, `/cases/`, `/mnt/`, `/media/`, `/evidence/`. |
| Findings vanish | `record_finding` defaults to `dry_run=True` | Pass `dry_run=false` + a `mutation_token`, and a non-empty `finding_id` (B4). |
| `case_id` rules | A slug with a space/slash is rejected | Use `WIN-XP-LAPTOP-2005` (`^[A-Za-z0-9._-]{1,128}$`). |
