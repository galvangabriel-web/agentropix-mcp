# Case Activation Guide — MemLabs CTF Memory Dumps (`nist4`)

> **LOCAL ONLY — real case inventory. Do not publish.** This guide instantiates the
> template procedure in
> [`/home/admin2/agentropix-sift/docs/tools/END-USER-CASE-GUIDE.md`](/home/admin2/agentropix-sift/docs/tools/END-USER-CASE-GUIDE.md)
> with the **real** evidence under `/cases/nist4`. The goal is to get an operator
> **ready to activate a case and start analysis** — not to run the analysis here.
> Dual-audience throughout: **🖥️ command** (expert CLI/MCP) and **💬 prompt**
> (plain-language to a Claude session with the Agentropix MCP attached).
>
> Canonical numbers cited from [`.crew/facts.md`](/home/admin2/docu_agentro/.crew/facts.md):
> **71 MCP tools**, **16 SIFT forensic wrappers**, **4464 tests**, memory recall
> **108/118 (91.5 %)**. MCP endpoint shape: `http://<TAILNET-HOST>:8765/mcp`
> (tailnet-only; get the real host + bearer token from Client Setup — never inlined here).

---

## 1. Identification header

| Field | Value |
|---|---|
| **Case name** | MemLabs CTF Memory Dumps (Lab 1–Lab 6, by *stuxnet999*) |
| **One-line description** | Six independent Windows memory-forensics CTF scenarios (`MemoryDump_Lab1..6.raw`) — the playable images for the MemLabs challenge READMEs in `/cases/memlabs` — plus an ancillary `procee` tar holding the Lab 3 `Challenge.raw`. |
| **Evidence type** | **Memory** (raw physical-memory dumps of Windows systems) |
| **Image file(s)** | `/cases/nist4/MemLabs-Lab1/MemoryDump_Lab1.raw` … `/cases/nist4/MemLabs-Lab6/MemoryDump_Lab6.raw` (+ `/cases/nist4/procee/procee`, a POSIX tar containing `Challenge.raw`) |
| **Format** | Raw memory dump (`vol -f` raw; no E01 wrapper, no partition table) |
| **Per-image size (confirmed `ls -la` / `du`)** | Lab1 **1,073,676,288 B** (1.0 GiB) · Lab2 **1,073,676,288 B** (1.0 GiB) · Lab3 **1,048,510,464 B** (1.0 GiB) · Lab4 **1,073,676,288 B** (1.0 GiB) · Lab5 **1,073,676,288 B** (1.0 GiB) · Lab6 **1,610,547,200 B** (1.5 GiB) · `procee` tar **1,048,512,000 B** (extracts `Challenge.raw` 1,048,510,464 B = Lab3 image) |
| **Folder total (`du -sh /cases/nist4`)** | **8.8 G** (includes the six `.7z` and one `.xz` source archives — the extracted `.raw` files are the playable evidence) |
| **Suggested `case_id` slug** | **`NEWDATA-MEMLABS-NIST4`** (matches `^[A-Za-z0-9._-]{1,128}$`; per-Lab variants below for the one-case-per-image model) |
| **OS / scenario** | **Windows** (all dumps; per MemLabs README "All the memory dumps are that of a Windows system"). Each Lab is a *separate* scenario: **Lab1** "Beginner's Luck" (Easy, 3 flags — recover files; black window executing something), **Lab2** "A New World" (Easy, 3 flags — browsers/password-managers, environmental activist), **Lab3** "The Evil's Den" (Easy–Medium, 1 flag/2 parts — malicious script encrypted a secret; needs `steghide`), **Lab4** "Obsession" (Medium, 1 flag — system compromised, deleted file to recover), **Lab5** "Black Tuesday" (Medium–Hard, 3 flags — odd alnum filenames, an app crashing — possible virus), **Lab6** "The Reckoning" (Hard, 1 flag/2 parts — gangster David Benjamin, internet C2). |

### Evidence-type → recommended path & tool chain

This is **memory** evidence, so the tool chain is the **Volatility path**, not the
disk path (no `mmls`/`fls`/partition offset; `bulk_extractor`/`yara` are optional
string/IOC passes). The per-evidence sequence the docs prescribe for a memory image:

```
case_init → case_activate → evidence_register (sha256)
  → get_pslist        (processes — first windows.* plugin auto-detects the kernel profile)
  → get_netscan       (sockets / connections)        ← Lab6 (C2) especially
  → get_malfind       (injected / RWX VAD code)
  → get_svcscan       (services / persistence)
  → build_process_tree(PPID forest, LOLBin flags)
  → run_volatility    (arbitrary Vol3 plugin: cmdline / filescan / dumpfiles /
                       printkey — alias form; the CTF-specific plugins)
  → record_finding (DRAFT) × N → approve (human) → report_generate
```

> **No `get_image_info` in the memory chain.** `get_image_info` drives `ewfinfo` and reads
> E01/EWF metadata only — on a raw memory dump it returns all-empty fields, so it is omitted
> here. The OS/kernel profile is **auto-detected by the first `windows.*` plugin** (`get_pslist`)
> via a Volatility3 symbol-table match — there is no separate "identify OS" step.

> **Why these tools.** `get_pslist`/`get_netscan`/`get_malfind`/`get_svcscan`/`build_process_tree`
> are the five first-class memory wrappers (verified in
> [`.crew/tool-list.md`](/home/admin2/docu_agentro/.crew/tool-list.md), category `memory`,
> backed by `wrappers/volatility.py` + `wrappers/correlation.py`). The CTF flags
> typically live behind *specific* Volatility plugins — reach those via **`run_volatility`**
> with a supported spelling: `cmdline` (`windows.cmdline.CmdLine`), `filescan`
> (`windows.filescan.FileScan`), `dumpfiles` (`windows.dumpfiles.DumpFiles`), `printkey`
> (`windows.registry.printkey.PrintKey`). Bare middle forms (`windows.cmdline`) are rejected,
> and there is **no `hashdump` plugin** in this MCP's allowlist. `run_volatility` (arbitrary Vol3
> plugin, `[SIFT-16]`). `get_editbox` (Vol2.6 UI-text) can recover typed text
> (handy for Lab1's "drawing"/Lab5 prompts). Disk-only tools (`mmls`, `fls`,
> `extract_files`, `get_registry`/`get_shimcache`/`get_prefetch`, `get_evtx`/`get_evt`)
> **do not apply** to a raw memory dump.

> ⚠️ **GOTCHA (no E01).** These are **raw** dumps (`file` reports `data` /
> `Windows Event Trace Log` — not an EWF container). So **`ewfverify`/`ewfinfo` do
> not apply** (they are E01-only). Integrity here is the **SHA-256 from
> `evidence_register`**, cross-checked against the MemLabs README MD5s when you want a
> second anchor (e.g. Lab1 dump MD5 `b9fec1a443907d870cb32b048bda9380`,
> Lab6 dump MD5 `405985dc8ab7651c65cdbc04cb22961c` — full set in the per-Lab READMEs
> under `/cases/memlabs/MemLabs/Lab N/README.md`). Note `get_image_info` reads E01/EWF
> metadata only and returns **all-empty fields** on a raw memory dump — it does not report
> usable size/metadata here; rely on the SHA-256 and the filesystem size (`ls -la` / `du`).

> 🔎 **One scenario per image.** MemLabs Lab1–6 are **six distinct challenges**, not
> one case. The cleanest model is **one Agentropix case per Lab** (single active
> pointer = one case at a time). Register each, then `case_activate` the Lab you're
> working. The `procee/procee` tar is an **ancillary** copy of the Lab3 image
> (`Challenge.raw`, same 1,048,510,464 B) — do **not** double-register it as new
> evidence; treat it as the source archive for Lab3.

---

## 2. Instantiated procedure (template steps 0 → 8)

Run these from any client with the `agentropix-sift` MCP bound (Claude CLI
recommended; Claude Desktop via the `mcp-remote` shim). The values below are the
**real** `nist4` specifics. The worked example uses **Lab 1**; the Lab-1 values are
swapped per-Lab in the table at the end of this section.

### Step 0 — Pre-flight (server up, client connected, tools healthy)

> **🖥️ Command:**
> ```bash
> uv run agentropix-sift doctor                 # 16 SIFT wrappers' binaries → "All tools available."
> bash /home/admin2/.openclaw/workspace/scripts/start-agentropix-mcp.sh status   # expect health: HTTP 200
> claude mcp list                               # agentropix-sift  http://<TAILNET-HOST>:8765/mcp  ✓ Connected
> # then call the health tool → { "status":"ok", "tool_count":71, ... }
> ```
> **💬 Prompt:** *"Check that my Agentropix forensic environment is ready and the MCP
> server is healthy — how many forensic tools are available?"*
> **Expect:** `doctor` ends with `All tools available.`; `health` returns
> `status: ok` with a live `tool_count` (canonical **71** — trust the live number, not
> the startup banner).

> **Note (memory case):** the disk-only integrity step (`ewfverify`) from the template's
> Phase 0.4 is **skipped** — these raw dumps have no EWF MD5 to verify. Custody is the
> `evidence_register` SHA-256 in Step 3.

### Step 1 — Pick the evidence + choose the slug

Evidence: `/cases/nist4/MemLabs-Lab1/MemoryDump_Lab1.raw`.
Slug: **`NEWDATA-MEMLABS-NIST4-LAB1`** (`^[A-Za-z0-9._-]{1,128}$`; no spaces, no slashes).

### Step 2 — `case_init` (register + activate the record)

> **🖥️ MCP call:**
> ```text
> case_init {
>   "case_name":   "MemLabs Lab 1 — Beginner's Luck (memory CTF)",
>   "examiner_id": "victor.galvan",
>   "case_id":     "NEWDATA-MEMLABS-NIST4-LAB1",
>   "case_dir":    "/cases/nist4/MemLabs-Lab1",
>   "description": "MemLabs Lab1 Windows memory dump (1.0 GiB raw); 3 flags — recover files",
>   "incident_type": "dfir/ctf-memory",
>   "severity":    "medium",
>   "scope":       "/cases/nist4/MemLabs-Lab1/MemoryDump_Lab1.raw",
>   "tags":        ["memlabs","memory","nist4","lab1"]
> }
> ```
> **💬 Prompt:** *"Open a medium-severity DFIR case `NEWDATA-MEMLABS-NIST4-LAB1` for the
> MemLabs Lab 1 memory dump at `/cases/nist4/MemLabs-Lab1/MemoryDump_Lab1.raw`, examiner
> victor.galvan, and make it the active case."*
> **Expect:** returns `case_id NEWDATA-MEMLABS-NIST4-LAB1`, status `active`, an
> `started_at` timestamp; writes the active-case pointer first (idempotent on the slug).

### Step 3 — `case_status` (confirm active)

> **🖥️ MCP call:** `case_status {}` (or `case_status {"case_id":"NEWDATA-MEMLABS-NIST4-LAB1"}`)
> **💬 Prompt:** *"Is `NEWDATA-MEMLABS-NIST4-LAB1` the active case right now?"*
> **Expect:** `active: true` and `indexer_reachable: true` in the result.

### Step 4 — `evidence_register` (SHA-256 chain of custody)

> **🖥️ MCP call:**
> ```text
> evidence_register {
>   "path":        "/cases/nist4/MemLabs-Lab1/MemoryDump_Lab1.raw",
>   "description": "MemLabs Lab1 Windows memory dump (raw, 1,073,676,288 bytes)",
>   "examiner_id": "victor.galvan"
> }
> ```
> **💬 Prompt:** *"Register the Lab 1 memory dump as evidence and give me its SHA-256
> custody hash."*
> **Expect:** an `evidence_id`, an evidence **SHA-256**, `size_bytes 1073676288`, and
> `indexed: true` → `agentropix-evidence-YYYY.MM.DD`. (Optional second anchor: the
> MemLabs README dump MD5 `b9fec1a443907d870cb32b048bda9380`.)

> **No metadata step.** `get_image_info` is EWF/E01-only and returns all-empty fields on a
> raw memory dump, so it is **not** used here — get the size from `ls -la` / `du` and integrity
> from the `evidence_register` SHA-256 above.

### Step 5 — Analyze (the **memory** tool chain)

> **🖥️ MCP calls (active case resolves automatically):**
> ```text
> get_pslist         { "image":"/cases/nist4/MemLabs-Lab1/MemoryDump_Lab1.raw" }   # processes (the "black window" exec)
> get_netscan        { "image":"...MemoryDump_Lab1.raw" }                          # sockets / connections
> get_malfind        { "image":"...MemoryDump_Lab1.raw" }                          # injected / RWX code
> get_svcscan        { "image":"...MemoryDump_Lab1.raw" }                          # services / persistence
> build_process_tree { "image":"...MemoryDump_Lab1.raw" }                          # PPID forest, LOLBin flags
> # CTF-specific plugins via the arbitrary-plugin wrapper (alias or full *.Class id; bare middle forms rejected):
> run_volatility { "image":"...MemoryDump_Lab1.raw", "plugin":"cmdline" }      # command lines (windows.cmdline.CmdLine)
> run_volatility { "image":"...MemoryDump_Lab1.raw", "plugin":"filescan" }     # find files to recover (windows.filescan.FileScan)
> run_volatility { "image":"...MemoryDump_Lab1.raw", "plugin":"dumpfiles" }    # carve recovered files (windows.dumpfiles.DumpFiles)
> ```
> **💬 Prompt:** *"Analyse the Lab 1 memory dump: what processes were running, what
> network connections were open, is there any injected code, and what files can we
> recover?"*
> **Expect:** the session runs the Volatility-backed memory tools and summarises
> processes, sockets, injected/RWX code, services, and (via `run_volatility`) the
> CTF-relevant artifacts (cmdline, hashes, recoverable files). **Scenario steer:** Lab2
> → browser/password-manager strings & `run_volatility` with a concrete registry plugin
> (`printkey` / `windows.registry.printkey.PrintKey`, `hivelist`, or `userassist`); Lab3 →
> recover the encrypted/steg artifact (`filescan`+`dumpfiles`, then `steghide` offline);
> Lab4 → deleted-file recovery (`filescan`+`dumpfiles`); Lab5 → odd alnum filenames +
> crashing app (`filescan`, `get_malfind`, `get_editbox`); Lab6 → **`get_netscan`** +
> browser/chat artifacts (internet C2). Per-case hypotheses:
> [case-hypotheses.md](/home/admin2/docu_agentro/docs/06-use-cases/case-hypotheses.md).

### Step 6 — `record_finding` (DRAFT-gated)

> **🖥️ MCP call:**
> ```text
> record_finding { "finding": {
>   "finding_id":   "memlabs-lab1-001",
>   "host":         "memlabs-lab1-win",
>   "mitre_attack": "T1059",
>   "confidence":   0.6,
>   "timestamp":    "2019-12-11T00:00:00Z",
>   "severity":     "medium",
>   "title":        "Suspicious console-launched execution in Lab1 memory",
>   "source_artifact": "/cases/nist4/MemLabs-Lab1/MemoryDump_Lab1.raw" } }
> ```
> **💬 Prompt:** *"Record a medium-severity finding for the console-launched execution
> we saw in the Lab 1 process list, mapped to MITRE T1059, citing the memory dump."*
> **Expect:** lands as **DRAFT** (`indexed:false`); requires non-empty `finding_id`
> (B4). `dry_run=True` is the default — persisting needs `dry_run=False` + a
> `mutation_token`. **Coherence:** `severity:high` needs `confidence ≥ 0.70`,
> `critical` needs `≥ 0.85`.

### Step 7 — Approve (human-only examiner gate)

> **🖥️ MCP call (human attestation in-band):**
> `approve_finding {"finding_id":"memlabs-lab1-001","approver_id":"victor.galvan","password":"<examiner pw>"}`
> **💬 Prompt:** *"Which Lab 1 findings are waiting for my approval, and what are their
> IDs?"* — then sign off **yourself** in the portal.
> Portal: **`https://siftworkstation.taile7c9ca.ts.net:8443/`** (tailnet-only) or
> `http://127.0.0.1:8800/` on the workstation. From `DRAFT` → `APPROVED`.
> **Expect:** **HARD STOP — human-only.** The assistant will not and cannot self-approve;
> this is the cryptographic (HMAC, append-only) chain-of-custody sign-off.

### Step 8 — `report_generate`

> **🖥️ MCP call:** `report_generate {"profile":"full","case_id":"NEWDATA-MEMLABS-NIST4-LAB1"}`
> **💬 Prompt:** *"Generate the full report for the Lab 1 case."*
> **Expect:** a `report_id` + section counts; `approved_finding_count` stays `0` until a
> finding is approved (Step 7). A brand-new DRAFT-only case can return `case_not_found`
> until there is indexed state (register evidence and/or approve a finding first).

### Per-Lab instantiation table (swap into Steps 1–4)

| Lab | `case_id` slug | `case_dir` / image (`scope`) | Size (bytes) | README dump MD5 (2nd anchor) | Scenario steer |
|---|---|---|---|---|---|
| 1 | `NEWDATA-MEMLABS-NIST4-LAB1` | `/cases/nist4/MemLabs-Lab1/MemoryDump_Lab1.raw` | 1,073,676,288 | `b9fec1a443907d870cb32b048bda9380` | recover files; console exec |
| 2 | `NEWDATA-MEMLABS-NIST4-LAB2` | `/cases/nist4/MemLabs-Lab2/MemoryDump_Lab2.raw` | 1,073,676,288 | `ddb337936a75153822baed718851716b` | browsers / password managers |
| 3 | `NEWDATA-MEMLABS-NIST4-LAB3` | `/cases/nist4/MemLabs-Lab3/MemoryDump_Lab3.raw` | 1,048,510,464 | `ce4e7adc4efbf719888d2c87256d1da3` | encrypted secret; `steghide` (offline) |
| 4 | `NEWDATA-MEMLABS-NIST4-LAB4` | `/cases/nist4/MemLabs-Lab4/MemoryDump_Lab4.raw` | 1,073,676,288 | `d2bc2f671bcc9281de5f73993de04df3` | deleted-file recovery |
| 5 | `NEWDATA-MEMLABS-NIST4-LAB5` | `/cases/nist4/MemLabs-Lab5/MemoryDump_Lab5.raw` | 1,073,676,288 | `9dd6cb1134c9b018020bad44f27394db` | odd alnum filenames; crashing app |
| 6 | `NEWDATA-MEMLABS-NIST4-LAB6` | `/cases/nist4/MemLabs-Lab6/MemoryDump_Lab6.raw` | 1,610,547,200 | `405985dc8ab7651c65cdbc04cb22961c` | internet C2 (netscan first) |

> **Switching Labs:** `case_activate {"case_id":"NEWDATA-MEMLABS-NIST4-LAB3"}` flips the
> single active pointer. Register each Lab once, then activate the one you're working.

---

## 3. "Activate & start" prompt sequences

Two lanes. Both reach the same sealed result; only *who drives the tool chain*
differs. Each operator action shows the **🖥️ command** equivalent and an **Expect:** line.

### Manual sequence (you drive each step — Lab 1 shown)

1. **💬** *"Check that my Agentropix forensic environment is ready and tell me how many
   forensic tools are available."*
   🖥️ `uv run agentropix-sift doctor` ; call `health`
   **Expect:** `All tools available.`; `health` → `status: ok`, live `tool_count` (canonical **71**).

2. **💬** *"Open a medium-severity DFIR case `NEWDATA-MEMLABS-NIST4-LAB1` for the MemLabs
   Lab 1 memory dump at `/cases/nist4/MemLabs-Lab1/MemoryDump_Lab1.raw`, examiner
   victor.galvan, and make it active."*
   🖥️ `case_init {…}` then `case_activate {"case_id":"NEWDATA-MEMLABS-NIST4-LAB1"}`
   **Expect:** `case_id NEWDATA-MEMLABS-NIST4-LAB1`, status `active`, pointer written.

3. **💬** *"Is that case active now?"*
   🖥️ `case_status {}`
   **Expect:** `active: true`, `indexer_reachable: true`.

4. **💬** *"Register the Lab 1 memory dump as evidence and give me its SHA-256 custody hash."*
   🖥️ `evidence_register {"path":"/cases/nist4/MemLabs-Lab1/MemoryDump_Lab1.raw", …}`
   **Expect:** `evidence_id`, evidence SHA-256, `size_bytes 1073676288`, `indexed: true`.

5. **💬** *"List the running processes in the Lab 1 memory dump."*
   🖥️ `get_pslist {"image":"…MemoryDump_Lab1.raw"}`
   **Expect:** a non-empty process list (look for the "black window" / console-launched exec).
   This first `windows.*` plugin auto-detects the kernel profile via a Volatility3 symbol-table match.

6. **💬** *"Show the open network connections and any injected code in the dump."*
   🖥️ `get_netscan {…}` then `get_malfind {…}`
   **Expect:** socket/connection list + injected/RWX VAD regions (often empty on Easy Labs — expected).

7. **💬** *"Build the process tree and list the services."*
   🖥️ `build_process_tree {…}` then `get_svcscan {…}`
   **Expect:** a PPID forest with LOLBin flags + the service list (persistence candidates).

8. **💬** *"Run the command-line Volatility plugin, then scan for files we can recover."*
   🖥️ `run_volatility {"image":"…","plugin":"cmdline"}` ;
   `… "plugin":"filescan"`
   **Expect:** command lines and a filescan offset list for the
   CTF artifacts (carve later with `dumpfiles`).

9. **💬** *"Record a medium-severity finding for the suspicious execution, mapped to
   MITRE T1059, citing the memory dump."*
   🖥️ `record_finding {"finding":{"finding_id":"memlabs-lab1-001", …}}`
   **Expect:** lands as **DRAFT** (`indexed:false`); the assistant generates a `finding_id`
   and cannot self-approve.

10. **💬** *"Which Lab 1 findings are waiting for my approval, and what are their IDs?"*
    🖥️ open the portal `https://siftworkstation.taile7c9ca.ts.net:8443/` →
    sign `DRAFT` → `APPROVED`
    **Expect:** the DRAFT list with IDs; **you** approve in the browser (human-only HMAC gate).

11. **💬** *"Generate the full report for the Lab 1 case."*
    🖥️ `report_generate {"profile":"full","case_id":"NEWDATA-MEMLABS-NIST4-LAB1"}`
    **Expect:** a `report_id` + section counts; `approved_finding_count` reflects Step 10
    (0 until approval; a DRAFT-only case can return `case_not_found` until there's indexed state).

### Autonomous sequence (launch → monitor → approve → report)

1. **💬 (launch driver / one-shot agent)** *"You are a DFIR analyst with the Agentropix
   MCP. Open and activate case `NEWDATA-MEMLABS-NIST4-LAB1` on the memory image
   `/cases/nist4/MemLabs-Lab1/MemoryDump_Lab1.raw`. Run the full memory sequence
   (`evidence_register` → `get_pslist` → `get_netscan` →
   `get_malfind` → `get_svcscan` → `build_process_tree` → relevant `run_volatility`
   plugins), staging findings as DRAFT. (`get_pslist` is the first `windows.*` plugin and
   triggers Volatility3 kernel-profile auto-detection — no separate `get_image_info` step.) Do NOT approve findings. Finish by generating
   the full report and summarising the thread chain."*
   🖥️ detached headless driver (token from ENV, **case key** positional — never the token):
   ```bash
   AGENTROPIX_MCP_AUTH_TOKEN="<BEARER_TOKEN>" \
     setsid nohup bash -c "python3 /home/admin2/.openclaw/workspace/drivers/agx_gearb.py memlabs-lab1 > run.log 2>&1" </dev/null >/dev/null 2>&1 &
   disown
   ```
   **Expect:** the agent walks the memory chain end-to-end, stages findings as **DRAFT**,
   and stops before approval (a bot must not sign chain-of-custody). Driver checkpoints
   `SUMMARY.json` per step. *(Confirm the `memlabs-lab1` case key exists in the driver's
   `cases.json`; if not, use the interactive prompt above or `--image` with the raw path.)*

2. **💬 (monitor)** *"How's the Lab 1 investigation going — which steps are done?"*
   🖥️ `tail -f run.log` ; read
   `/home/admin2/.openclaw/workspace/drivers/gearB/memlabs-lab1/SUMMARY.json`
   **Expect:** per-step `ok`/`elapsed`/`error`; the run ends with all memory steps OK and
   the final `record_finding` `indexed:false` (DRAFT).

3. **💬 (approve — human gate)** *"Which Lab 1 findings are waiting for my approval, and
   what are their IDs?"*
   🖥️ open `https://siftworkstation.taile7c9ca.ts.net:8443/` → `DRAFT` → `APPROVED`
   **Expect:** the DRAFT list with IDs; **you** approve in the portal. The assistant will
   not and cannot approve on your behalf (HMAC, append-only).

4. **💬 (report)** *"Generate the full report for the Lab 1 case."*
   🖥️ `report_generate {"profile":"full","case_id":"NEWDATA-MEMLABS-NIST4-LAB1"}`
   **Expect:** a `report_id` + section counts; once approved, `approved_finding_count` and
   the report sections populate.

5. **💬 (verify seal)** *"Verify the seal on the Lab 1 report — confirm it hasn't been
   tampered with since it was generated."*
   🖥️ `uv run python scripts/verify_seal.py <report>.json`
   **Expect:** the verifier confirms the report and audit log are intact and unaltered
   since sealing (HMAC-SHA256, `evidence_image_sha256`-bound).

> **Repeat for Lab2–Lab6:** swap the slug, `case_dir`, image path, and scenario steer
> from the per-Lab table in §2. One active case at a time — `case_activate` the Lab
> you're working before its tool calls.

---

## Memory-case gotchas (the ones that bite here)

| Gotcha | Rule |
|---|---|
| `ewfverify`/`ewfinfo` "fail" | These are **raw** dumps, not E01 — EWF tools don't apply. Use the `evidence_register` SHA-256 (cross-check the README MD5). |
| `procee/procee` looks like new evidence | It's a tar holding `Challenge.raw` = the **Lab3** image (same 1,048,510,464 B). Don't double-register; it's the Lab3 source archive. |
| Reaching for `mmls`/`fls` | Disk-only — irrelevant to memory. No partition offset, no `extract_files`. |
| Flag is behind a plugin not in the 5 wrappers | Use **`run_volatility`** with a supported spelling — alias (`cmdline` / `filescan` / `dumpfiles` / `printkey`) or full `*.Class` id (`windows.cmdline.CmdLine`, `windows.filescan.FileScan`, `windows.dumpfiles.DumpFiles`, `windows.registry.printkey.PrintKey`). Bare middle forms (`windows.cmdline`) are rejected, and `hashdump` is **not** in this MCP's allowlist. |
| `case_id` with a space | Rejected (`^[A-Za-z0-9._-]{1,128}$`). The slugs above are pre-cleaned. |
| "Activate all six Labs" | Impossible — single active pointer. Register each, activate one. |
| Finding not persisting | `record_finding` defaults to `dry_run=True` — pass `dry_run=False` + `mutation_token`. |
