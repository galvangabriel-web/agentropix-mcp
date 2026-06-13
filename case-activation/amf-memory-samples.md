# Case Activation Guide — AMF Memory Samples (Art of Memory Forensics corpus)

> **LOCAL-ONLY working doc.** Real evidence inventory + paths. Do not publish. Lives under
> `case-activation/` (gitignored). MCP endpoint shown as the tailnet hostname placeholder; no raw IPs.
> Procedure instantiated from the oracle:
> `/home/admin2/agentropix-sift/docs/tools/END-USER-CASE-GUIDE.md`.
> Canonical numbers cite [`.crew/facts.md`](../docs/08-reference/canonical-facts.md)
> (`mcp_tool_count=71`, 16 SIFT wrappers, `test_count=4687`).

---

## 1. Identification header

| Field | Value |
|---|---|
| **Case name** | AMF Memory Samples — *The Art of Memory Forensics* training corpus |
| **One-line description** | The Volatility Foundation OpenCourseWare RAM-capture corpus: **9 Windows + 6 Linux + 4 Mac** raw memory dumps used to teach Volatility3. Each OS family is a distinct training scenario. |
| **Evidence type** | **Memory** (raw RAM captures — no container/EWF header) |
| **Image files** | Windows: `/cases/AMF_MemorySamples/windows/sample001.bin … sample009.bin` (9 files) · Linux: `/cases/AMF_MemorySamples/linux/linux-sample-1.bin … -6.bin` (6 files) · Mac: `/cases/AMF_MemorySamples/mac/mac-sample-1.bin … -4.bin` (4 files) |
| **Format** | **Raw** physical-memory dumps (`.bin`). `file(1)` reports `data` (or a spurious magic match on `mac-sample-1.bin`) — expected: raw RAM has no header. **Not EWF** → there is **no `ewfinfo`/`ewfverify` step** here. |
| **Size** | **13 G total** — windows **4.5 G** (134 MiB – 1.0 GiB each), linux **3.1 G** (≈512 MiB each), mac **5.1 G** (1.0–2.0 GiB each). |
| **Suggested case_id slug** | per-sample, e.g. **`AMF-WIN-SAMPLE001`** (slug rule `^[A-Za-z0-9._-]{1,128}$` — no spaces/slashes). See §1.3 for the full slug table. |
| **OS / scenario** | Three families. Windows samples = Win Volatility training images; Linux samples ship `linux/book.zip` (profile/symbol material); Mac samples ship `mac/Mavericks_10.9.3_AMD.zip` (macOS 10.9.3 Mavericks). License: **CC-BY-NC-SA 3.0** (Volatility Foundation OpenCourseWare — `COURSE_LICENSE_TERMS.txt`, `CC-BY-NC-SA-3.0.txt` present). **Training corpus, non-commercial.** |

> ⚠️ **Metadata-only profiling (already done for this guide).** Confirmed with `ls`/`du`/`file` only —
> no forensic tool was run on the evidence. `ewfinfo` is N/A (raw, not EWF). The two `.zip` files
> (`book.zip`, `Mavericks_10.9.3_AMD.zip`) are course/profile material, **not** evidence — do not
> register them.

### 1.1 Recommended path + tool chain (memory)

This is a **memory** case, so the chain is the Volatility branch (no `mmls`/`fls`/`bulk_extractor` disk
path). The agentropix-sift memory tools that resolve to the active case:

- **No `get_image_info` here.** It drives `ewfinfo` and reads E01/EWF metadata only; on a raw `.bin`
  RAM dump every field returns empty, so it cannot provide acquisition/size sanity. Use `ls`/`du` for
  size; anchor integrity on the `evidence_register` SHA-256.
- **`get_pslist`** → processes (this first `windows.*` plugin also auto-detects the kernel symbol
  table — Volatility3 is profile-less) · **`get_netscan`** → sockets · **`get_malfind`** → injected/RWX code ·
  **`get_svcscan`** → services · **`build_process_tree`** → PPID forest + LOLBin flags.
- **`run_volatility { plugin, args }`** — the generic escape hatch for any other plugin
  (`pstree`, `cmdline`, `dlllist`, `filescan`, `hivelist`, `printkey`, `malfind`, `netscan`, …).

> 🔴 **LOAD-BEARING PLATFORM CONSTRAINT — Windows-only memory plugins.** Verified against source
> (`src/agentropix_sift/mcp_server/wrappers/volatility.py`):
> - `get_pslist`/`get_netscan`/`get_malfind`/`get_svcscan` are hardcoded to **`volatility3.windows.*`**
>   plugins (`windows.pslist.PsList`, `windows.netscan.NetScan`, `windows.malfind.Malfind`,
>   `windows.svcscan.SvcScan`).
> - `run_volatility` rejects any plugin outside `VOL3_ALLOWED_PLUGINS` — a frozenset that contains
>   **only `windows.*` plugins** (pslist/pstree/psscan/malfind/netscan/cmdline/dlllist/filescan/
>   svcscan/handles/hivelist/printkey/dumpfiles/modules/modscan/callbacks/ssdt/mutantscan/vadinfo/
>   envars/timeliner/driverscan/drivermodule/devicetree/getservicesids/userassist/sessions).
>   **There are NO `linux.*` or `mac.*` plugins in the allowlist.**
>
> **What this means for activation:**
> - **Windows samples (9):** ✅ fully supported end-to-end through the MCP memory chain below.
> - **Linux (6) + Mac (4):** the case + evidence chain-of-custody steps (`case_init`,
>   `case_activate`, `evidence_register`, `record_finding`, `approve`,
>   `report_generate`) all work, **but the Volatility analysis plugins for these OSes are not exposed
>   through the MCP.** Their `linux.*`/`mac.*` plugins must be run with raw `vol3` *outside* the MCP
>   (and those need the matching ISF symbol pack — that is what `linux/book.zip` /
>   `mac/Mavericks_10.9.3_AMD.zip` provide). Treat Linux/Mac as **register-and-custody-only** until a
>   non-Windows plugin path is exposed.
>
> **Recommendation: activate per-sample (one case per dump), starting with the Windows family** — that
> is where the platform delivers a full analysis chain. Per-sample activation also matches the corpus
> design (each dump is an independent training scenario) and keeps the single active-case pointer clean.

### 1.2 Why per-sample (single active case)

There is exactly **one active case** at a time — the pointer `~/.agentropix/active_case`. You cannot
analyse all 19 dumps at once. Register each sample as its own case, then `case_activate` the one you are
working. The slug table below gives every sample a deterministic slug so the inventory stays auditable.

### 1.3 Suggested per-sample case_id slugs

| Sample (path) | Suggested `case_id` | Platform support |
|---|---|---|
| `windows/sample001.bin` | `AMF-WIN-SAMPLE001` | ✅ full memory chain |
| `windows/sample002.bin` | `AMF-WIN-SAMPLE002` | ✅ full memory chain |
| `windows/sample003.bin` | `AMF-WIN-SAMPLE003` | ✅ full memory chain |
| `windows/sample004.bin` | `AMF-WIN-SAMPLE004` | ✅ full memory chain |
| `windows/sample005.bin` | `AMF-WIN-SAMPLE005` | ✅ full memory chain |
| `windows/sample006.bin` | `AMF-WIN-SAMPLE006` | ✅ full memory chain |
| `windows/sample007.bin` | `AMF-WIN-SAMPLE007` | ✅ full memory chain |
| `windows/sample008.bin` | `AMF-WIN-SAMPLE008` | ✅ full memory chain |
| `windows/sample009.bin` | `AMF-WIN-SAMPLE009` | ✅ full memory chain |
| `linux/linux-sample-1.bin` … `-6.bin` | `AMF-LINUX-SAMPLE1` … `-SAMPLE6` | ⚠️ custody-only (no `linux.*` MCP plugin) |
| `mac/mac-sample-1.bin` … `-4.bin` | `AMF-MAC-SAMPLE1` … `-SAMPLE4` | ⚠️ custody-only (no `mac.*` MCP plugin) |

---

## 2. Instantiated procedure (template steps 0 → 8)

Worked end-to-end for the lead Windows sample **`windows/sample001.bin`** (slug `AMF-WIN-SAMPLE001`,
examiner `victor.galvan`). Substitute the path + slug for any other sample. All calls below are **MCP
tool calls**, not a shell CLI.

### Step 0 — Pre-flight (where you run these)

The tools are served by the `agentropix-sift` MCP. Connect a client (Claude CLI recommended) to the
tailnet endpoint, then trust the live tool count.

> **🖥️ Command (operator-local, one-time wiring):**
> ```bash
> claude mcp add --transport http agentropix-sift \
>   "http://<TAILNET-HOST>:8765/mcp" --header "Authorization: Bearer <TOKEN>"
> claude mcp list        # expect: agentropix-sift ... ✓ Connected
> ```
> Then call the `health` tool — expect `{ "status":"ok", "tool_count":72, ... }`. **Trust the live
> `health.tool_count`, not the startup banner** (canonical `72` since 2026-06-11; see the user
> guide §1.2).
> **💬 Prompt:** *"Is the Agentropix MCP server up, and how many forensic tools are available right now?"*

> ⚠️ **No `ewfverify`/`ewfinfo` for this case.** Those are EWF/E01 steps. These dumps are **raw**, so
> integrity is anchored at Step 3 by the `evidence_register` SHA-256, not by a stored-vs-computed EWF MD5.

### Step 1 — Pick the evidence and choose a slug

Evidence is under `/cases/AMF_MemorySamples/`. Pick a sample; slug from §1.3 (start Windows). For the
worked example: path `/cases/AMF_MemorySamples/windows/sample001.bin`, slug `AMF-WIN-SAMPLE001`.

### Step 2 — `case_init` (register + activate the case)

> **🖥️ Command (MCP):**
> ```text
> case_init { "case_name":"AMF Windows sample001 (Art of Memory Forensics)",
>             "examiner_id":"victor.galvan",
>             "case_id":"AMF-WIN-SAMPLE001",
>             "case_dir":"/cases/AMF_MemorySamples/windows",
>             "description":"AMF OpenCourseWare Windows RAM sample 001 (raw, 511 MiB) — CC-BY-NC-SA 3.0 training corpus",
>             "incident_type":"dfir", "severity":"medium",
>             "scope":"/cases/AMF_MemorySamples/windows/sample001.bin",
>             "tags":["amf","memory","windows","volatility","training"] }
> ```
> **💬 Prompt:** *"Open a medium-severity DFIR case `AMF-WIN-SAMPLE001` for the AMF Windows memory dump
> `/cases/AMF_MemorySamples/windows/sample001.bin`, examiner victor.galvan, and make it the active case."*
>
> **Expect:** `case_init` returns `case_id AMF-WIN-SAMPLE001`, status `active`, and writes the active-case
> pointer first (idempotent on the slug — re-running updates, never duplicates).

### Step 3 — `case_status` (confirm active)

> **🖥️ Command (MCP):** `case_status {}`  (or `case_status { "case_id":"AMF-WIN-SAMPLE001" }`)
> **💬 Prompt:** *"Is AMF-WIN-SAMPLE001 the active case and is the indexer reachable?"*
>
> **Expect:** `active: true` and `indexer_reachable: true`.

### Step 4 — `evidence_register` (SHA-256 chain-of-custody)

> **🖥️ Command (MCP):**
> ```text
> evidence_register { "path":"/cases/AMF_MemorySamples/windows/sample001.bin",
>                     "description":"AMF Windows RAM sample 001 (raw physical memory)",
>                     "examiner_id":"victor.galvan" }
> ```
> **💬 Prompt:** *"Register `/cases/AMF_MemorySamples/windows/sample001.bin` as evidence in this case and
> give me its SHA-256 custody hash."*
>
> **Expect:** an `evidence_id`, the evidence **SHA-256**, `size_bytes 536330240` (≈511 MiB), and
> `indexed: true → agentropix-evidence-YYYY.MM.DD`. (This SHA-256 is the custody anchor — raw dumps have
> no EWF stored hash.) Do **not** call `get_image_info` here — on a raw memory image it returns
> all-empty (no EWF container); it is valid only for disk EWF (`.E01`/`.Exx`) cases.

### Step 5 — Analyze (the memory tool chain)

> **🖥️ Command (MCP) — the Windows memory chain:**
> ```text
> get_pslist         { "image":"/cases/AMF_MemorySamples/windows/sample001.bin" }   # processes
> get_netscan        { "image":"/cases/AMF_MemorySamples/windows/sample001.bin" }   # sockets
> get_malfind        { "image":"/cases/AMF_MemorySamples/windows/sample001.bin" }   # injected / RWX
> get_svcscan        { "image":"/cases/AMF_MemorySamples/windows/sample001.bin" }   # services
> build_process_tree { "image":"/cases/AMF_MemorySamples/windows/sample001.bin" }   # PPID forest
> # generic escape hatch for any other allowlisted windows.* plugin:
> run_volatility     { "target":"/cases/AMF_MemorySamples/windows/sample001.bin",
>                      "plugin":"cmdline" }     # alias → windows.cmdline.CmdLine
> ```
> **💬 Prompt:** *"Analyse this memory image: what processes were running, what network connections were
> open, are there any injected/RWX regions, and what services were registered?"*
>
> **Expect:** `get_pslist` returns a non-empty process row set; `get_netscan` returns sockets;
> `get_malfind` returns injected/RWX VAD hits (often empty on a clean image — that is a valid result);
> `build_process_tree` returns the PPID forest with any LOLBin flags. Analysis outputs are **not**
> auto-persisted — you shape them into a finding in Step 6.
>
> ⚠️ **Linux/Mac samples:** stop here. The MCP exposes no `linux.*`/`mac.*` plugins (see §1.1) — these
> are custody-only via Steps 2–4, 6–8; their plugin analysis is raw-`vol3`-outside-the-MCP, with the ISF
> symbols from `book.zip` / `Mavericks_10.9.3_AMD.zip`. Record a custody/scope finding and report.

### Step 6 — `record_finding` (DRAFT-gated)

> **🖥️ Command (MCP):**
> ```text
> record_finding { "finding": {
>   "finding_id":"amf-win-s001-001",
>   "host":"amf-win-sample001",
>   "mitre_attack":"T1057",                 # Process Discovery (adjust to the artifact)
>   "confidence":0.6,
>   "timestamp":"2026-06-06T00:00:00Z",     # ISO-8601 required
>   "severity":"medium",
>   "title":"Process list recovered from AMF Windows sample001",
>   "source_artifact":"/cases/AMF_MemorySamples/windows/sample001.bin" } }
> ```
> **💬 Prompt:** *"Record a medium-severity finding for the process list we recovered, mapped to MITRE
> T1057, citing the sample001 image as the source artifact."*
>
> **Expect:** `finding_id amf-win-s001-001`, lands as **DRAFT** (`indexed:false`). Required fields:
> `finding_id` (non-empty — else `ValueError`), `host`, `mitre_attack`, `confidence` (0.0–1.0),
> `timestamp`. Coherence: `severity:high` needs `confidence ≥ 0.70`; `critical` needs `≥ 0.85`.
> `record_finding` defaults to `dry_run=True` (preview only) — the agent passes `dry_run=False` +
> `mutation_token` to persist.

### Step 7 — Approve (examiner HMAC gate — HUMAN ONLY)

DRAFT → APPROVED happens **only** in the browser Approval Portal (HMAC challenge-response). The LLM
**cannot** self-approve — this is a Hard-Stop.

> **🔗 Portal:** `https://<TAILNET-HOST>:8443/` (or local `http://127.0.0.1:8800/`). Demo credentials
> (examiner ID + approver password) live in [approval-portal.md](../docs/05-safety-forensics/approval-portal.md).
> Fill Examiner ID (= `AGENTROPIX_APPROVER_USER`) + Case ID `AMF-WIN-SAMPLE001`, paste the finding ID
> `amf-win-s001-001`, set From=`DRAFT` To=`APPROVED`, enter the approver password, Sign & Submit.
> **💬 Prompt (discovery only):** *"Which findings in AMF-WIN-SAMPLE001 are waiting for my approval and
> what are their IDs?"* — then approve yourself in the portal.
>
> **Expect:** the finding moves out of DRAFT; a deterministic approval doc is written to
> `agentropix-approvals-YYYY.MM.DD` and the append-only hash chain extends. Approvals are append-only
> (correct mistakes with a `REVOKED`/`retract_approval`, never a delete).
>
> **⚠ SIMULATED examiner approval (demo only):** in the recorded run this sign-off was driven by
> **Playwright (automated), not a human** — see [runs/amf-win-sample001/EXECUTED-RUN.md](./runs/amf-win-sample001/EXECUTED-RUN.md).
> A **real case requires a human examiner** to perform the HMAC sign-off in the portal.

### Step 8 — `report_generate` (sealed report)

> **🖥️ Command (MCP):** `report_generate { "profile":"full", "case_id":"AMF-WIN-SAMPLE001" }`
> **💬 Prompt:** *"Generate the full report for AMF-WIN-SAMPLE001."*
>
> **Expect:** a `report_id`, `snapshot_at`, and section counts. `approved_finding_count` stays `0` until
> Step 7 completes. A **DRAFT-only** case can return `case_not_found: no documents for case_id …` —
> expected gating, not a failure: register evidence and/or approve a finding so there is indexed state,
> then re-generate. Optionally push curated IOCs to Wazuh (`wazuh_index_findings`, dry-run then live with
> an `egt_` token) if this case feeds detection.

---

## 3. Activate & start — prompt sequences

Both lanes hit the same deterministic MCP engine. Each operator action shows the **🖥️ command** and the
**💬 prompt**; run top-to-bottom and check each **Expect:** before the next.

### 3.A — MANUAL sequence (you drive each step, Windows sample001)

1. **Verify the MCP is up.**
   🖥️ `claude mcp list` then call `health`.
   💬 *"Is the Agentropix MCP up, and how many forensic tools are available?"*
   **Expect:** `✓ Connected`; `health` → `status:"ok"`, live `tool_count` (canonical `72`; trust the live number).

2. **Open + activate the case.**
   🖥️ `case_init { case_id:"AMF-WIN-SAMPLE001", examiner_id:"victor.galvan", scope:"/cases/AMF_MemorySamples/windows/sample001.bin", … }`
   💬 *"Open medium-severity case AMF-WIN-SAMPLE001 for `/cases/AMF_MemorySamples/windows/sample001.bin`, examiner victor.galvan, and make it active."*
   **Expect:** `case_id AMF-WIN-SAMPLE001`, status `active`, pointer written.

3. **Confirm it's active.**
   🖥️ `case_status {}`
   💬 *"Is AMF-WIN-SAMPLE001 active and is the indexer reachable?"*
   **Expect:** `active:true`, `indexer_reachable:true`.

4. **Register the evidence (custody hash).**
   🖥️ `evidence_register { path:"/cases/AMF_MemorySamples/windows/sample001.bin", examiner_id:"victor.galvan", … }`
   💬 *"Register the sample001 memory dump as evidence and give me its SHA-256."*
   **Expect:** an `evidence_id` + SHA-256, `size_bytes 536330240`, `indexed:true`.

5. **Analyse — processes / sockets / injection / services / tree.**
   🖥️ `get_pslist {…}` · `get_netscan {…}` · `get_malfind {…}` · `get_svcscan {…}` · `build_process_tree {…}`
   💬 *"Analyse this memory image: running processes, open network connections, injected code, and services."*
   **Expect:** non-empty process + socket sets; `get_malfind` hits (possibly empty = clean); process tree with PPID/LOLBin flags. (`get_pslist`, the first `windows.*` plugin, auto-detects the kernel symbol table — a populated result confirms the profile resolved.)

6. **Run an extra plugin via the escape hatch (optional).**
   🖥️ `run_volatility { target:"/cases/AMF_MemorySamples/windows/sample001.bin", plugin:"cmdline" }`
   💬 *"Show me the command lines of the running processes."*
   **Expect:** a `VolatilityReport` with `rows` from `windows.cmdline.CmdLine`. (Only `windows.*` plugins are allowlisted.)

7. **Record a finding (DRAFT).**
   🖥️ `record_finding { finding:{ finding_id:"amf-win-s001-001", host:"amf-win-sample001", mitre_attack:"T1057", confidence:0.6, timestamp:"…Z", severity:"medium", title:"…" } }`
   💬 *"Record a medium-severity finding for the recovered process list, mapped to MITRE T1057, citing the sample001 image."*
   **Expect:** `finding_id amf-win-s001-001`, DRAFT (`indexed:false`); the assistant cannot self-approve.

8. **List findings awaiting approval, then approve in the portal (human).**
   🖥️ open `https://siftworkstation.taile7c9ca.ts.net:8443/` → sign & submit DRAFT→APPROVED.
   💬 *"Which findings in AMF-WIN-SAMPLE001 are waiting for my approval and what are their IDs?"*
   **Expect:** the DRAFT id `amf-win-s001-001` listed; you sign off yourself (no plain-language approval shortcut, by design).

9. **Generate the full report.**
    🖥️ `report_generate { profile:"full", case_id:"AMF-WIN-SAMPLE001" }`
    💬 *"Generate the full report for AMF-WIN-SAMPLE001."*
    **Expect:** a `report_id` + section counts; `approved_finding_count` reflects approvals (0 until Step 8; a DRAFT-only case may return `case_not_found` until there is indexed state).

### 3.B — AUTONOMOUS sequence (launch → monitor → approve → report)

The driver runs the full sequence unattended and **stops at the approval gate** — a bot must not sign
chain-of-custody. Use Claude CLI (not Desktop).

1. **Launch the autonomous investigation (interactive prompt, B.1 lane).**
   💬 *"You are a DFIR analyst with the Agentropix MCP. Investigate case `AMF-WIN-SAMPLE001` on memory image `/cases/AMF_MemorySamples/windows/sample001.bin`. Run the full memory sequence (`case_init`→`case_activate`→`evidence_register`→`get_pslist`/`get_netscan`/`get_malfind`/`get_svcscan`/`build_process_tree`→`record_finding` as DRAFT). The first OS/profile signal comes from `get_pslist` — Volatility3 auto-detects the kernel symbol table on the first `windows.*` plugin; there is no separate image-metadata step (`get_image_info` is EWF/disk-only and returns empty on raw RAM). This is a RAW memory dump, not a disk image — do NOT run mmls/fls/bulk_extractor. Do NOT approve findings. Finish by generating the full report and summarising the thread chain."*
   🖥️ *Expert detached-driver equivalent (the validated headless pattern; token from ENV, case_key positional):*
   ```bash
   AGENTROPIX_MCP_AUTH_TOKEN="<TOKEN>" \
     setsid nohup bash -c "python3 /home/admin2/.openclaw/workspace/drivers/agx_gearb.py <case_key> > run.log 2>&1" </dev/null >/dev/null 2>&1 &
   disown
   ```
   (Add the sample to the driver's `cases.json` first; smoke-test with `--preflight` appended after `<case_key>`. The driver auto-routes a `.bin`/`.raw` to the memory branch — `get_pslist`/`get_netscan`/`get_malfind`/`get_svcscan`/`build_process_tree` — and checkpoints `SUMMARY.json` per step.)
   **Expect:** the agent stages all findings as DRAFT and stops before approval; the report shows `approved_finding_count 0`.

2. **Monitor progress.**
   🖥️ `tail -f run.log` and read `/home/admin2/.openclaw/workspace/drivers/gearB/<case>/SUMMARY.json` (per-step `ok`/`elapsed`/`error`).
   💬 *"How's the investigation going — which memory steps are done?"*
   **Expect:** steps logged as they complete; the final `record_finding` is DRAFT (`indexed:false`).

3. **Approve in the portal (human gate).**
   🖥️ open `https://siftworkstation.taile7c9ca.ts.net:8443/` → DRAFT→APPROVED, Sign & Submit.
   💬 *"Which findings are waiting for my approval and what are their IDs?"*
   **Expect:** DRAFT findings listed; the assistant will not and cannot approve on your behalf (append-only HMAC sign-off).

4. **Generate the full report.**
   🖥️ `report_generate { profile:"full", case_id:"AMF-WIN-SAMPLE001" }`
   💬 *"Generate the full report for AMF-WIN-SAMPLE001."*
   **Expect:** `report_id` + section counts; once findings are approved, `approved_finding_count` and the report sections populate.

5. **Verify the report seal.**
   🖥️ `uv run python scripts/verify_seal.py <report>.json`
   💬 *"Verify the seal on this report — confirm it hasn't been tampered with since it was generated."*
   **Expect:** the verifier confirms the report + audit log are intact (HMAC-SHA256 seal, `evidence_image_sha256`-bound).

---

## 4. Operator notes (this corpus)

- **Start with Windows.** The 9 Windows samples get the full MCP memory chain; activate them first, one
  slug per sample (§1.3).
- **Linux/Mac = custody-only today.** Register + report for chain-of-custody, but their `linux.*`/`mac.*`
  Volatility plugins are not in the MCP allowlist — analysis is raw `vol3` outside the MCP, using the ISF
  symbols in `linux/book.zip` and `mac/Mavericks_10.9.3_AMD.zip`. Do not register the `.zip` files as
  evidence.
- **Raw, not EWF.** No `ewfverify`/`ewfinfo`; the `evidence_register` SHA-256 is the custody anchor.
- **No disk tools.** This is memory — skip `mmls`/`fls`/`bulk_extractor`/`scan_yara`/registry-hive
  extraction entirely.
- **License.** CC-BY-NC-SA 3.0 (Volatility Foundation OpenCourseWare) — training/non-commercial use;
  attribute the Volatility Foundation in any derivative.
