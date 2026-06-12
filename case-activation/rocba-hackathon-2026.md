# Case Activation Guide — ROCBA Hackathon 2026

> **LOCAL-ONLY operational doc.** This file lives under `case-activation/` (gitignored) because it
> contains real case inventory, real evidence paths, and real ground-truth hashes. **Do not publish.**
> No secrets, no raw internal IPs — the MCP endpoint is shown with the tailnet hostname placeholder.
>
> **Scope of this guide:** get an operator *ready to activate the case and start analysis* — it is the
> instantiated, copy-paste runbook for **this** case. It follows the canonical 8-step end-user
> procedure (`END-USER-CASE-GUIDE.md`) and the
> portal house style / dual-audience (🖥️ command · 💬 prompt) of
> [`docs/01-overview/user-guide.md`](../docs/01-overview/user-guide.md). Canonical numbers cite
> [`.crew/facts.md`](../docs/08-reference/canonical-facts.md) (**72 MCP tools**, **16 SIFT wrappers**, **4464 tests**).

---

## 1. Case identification (read this first)

| Field | Value |
|---|---|
| **Case name** | ROCBA Hackathon 2026 |
| **One-line description** | Windows 10 host compromise / insider-IP-theft scenario — C-drive disk image **plus** a full physical-memory capture; external RDP brute-force (T1110.003) + user-execution malware (T1204.002). Briefing: `ROCBA-BACKGROUND.pptx`. |
| **Evidence type** | **mixed** — disk (EWF/E01) **+** memory (raw) |
| **Suggested `case_id` slug** | **`ROCBA-HACKATHON-2026`** (matches `^[A-Za-z0-9._-]{1,128}$`; matches the existing `_work/`/`_archive/` derived-output naming) |
| **Examiner ID** | `victor.galvan` (chain-of-custody stamp, used consistently below) |
| **Evidence folder** | `/cases/rocba/` (lowercase — `/Cases/` does not exist) |
| **Driver case key** | `rocba` (logical key, resolved via the driver's `cases.json`; `kind: multi`, requires explicit `--image`) |
| **Investigation window (ground-truth)** | 2020-11-13T22:00:00Z → 2020-11-14T04:59:59Z (host TZ `EST5EDT`, normalized UTC) |

### Evidence images (re-confirmed metadata-only on 2026-06-06)

> Re-verified with `file` / `ewfinfo` / `du` only — **no forensic tool was run on the evidence.**

| # | Image | Format | On-disk size | Logical/media size | Integrity (ground-truth) |
|---|---|---|---|---|---|
| 1 | `/cases/rocba/rocba-cdrive.e01` | EWF / EnCase 1 (no compression) | **23 GB** (`23678691658` B container) | **81 GiB** (`87431311360` B raw; `170764280` sectors × 512 B) | MD5 `5efc207c85587683e5ca5fa2d5ef1aa4` · SHA-1 `645dcd29ab039359fbdb6643961478b3d914f21d` (`ewfverify` SUCCESS) |
| 2 | `/cases/rocba/Rocba-Memory/Rocba-Memory.raw` | raw Windows physical-memory dump (Vol3-native) | **18 GB** (`19050528768` B) | n/a (flat raw) | SHA-256 `eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563` |

- **`file` on the E01** → `EWF/Expert Witness/EnCase image file format`.
- **`file` on the `.raw`** reports `Windows Event Trace Log` — this is a **magic-byte coincidence** (the
  first bytes happen to collide); the file is a **raw memory dump** (Vol3 reads it natively). Trust the
  ground-truth `MEMORY_FORMAT.txt` (`format=raw`), not `file(1)`.
- **`ewfinfo` on the E01** → OS **Win 10, Build 19042 (64-bit)**, acquired `Fri Dec 18 18:26:51 2020`
  with **XWF 20.1** (X-Ways Forensics), `512` B/sector, media `81 GiB`.

### NOT source evidence (derived — do not register, do not re-analyze)

These live under `/cases/rocba/` but are **prior derived output / IOCs**, not ground-truth source:
`_work/ROCBA-HACKATHON-2026/` (`MASTER-IOCS.json`, reports, timeline, audit, triage), `_archive/*.tar.gz`
(closed-case bundles), and the **compressed copies** of the memory dump
(`/cases/rocba/Rocba-Memory.zip`, `/cases/rocba/Rocba-Memory/Rocba-Memory.7z` — both decompress to the
same `.raw`). Register **only** the two source images in the table above.

### OS / scenario (from the ground-truth briefing + audit)

- **OS:** Windows 10, Build 19042 (Win10 20H2). This is **not** an XP image, so the Win10 artifact
  family is in scope: `.evtx` event logs (`get_evtx`, **not** `get_evt`), **Amcache** (`get_amcache`,
  Win7+), **Shimcache** (`get_shimcache`), **Prefetch** (`get_prefetch`), and **SRUM** (`srum_extract`).
- **Disk layout (ground-truth `MMLS.txt`):** `mmls_result=EMPTY` — this is a **whole-disk single-volume
  NTFS capture with no MBR partition table**. The NTFS boot sector sits at byte 3 (`NTFS` magic).
  **→ `fls` uses `offset 0`** here, *not* sector 63. (Contrast CFReDS, which has an MBR and NTFS at
  sector 63 — that case's offset does **not** apply to ROCBA.)
- **Scenario hint (briefing + Tier-1 findings):** external **RDP brute-force** (MITRE **T1110.003** —
  ~15,048 `4625` failures from external IPs) and **user-execution malware** (MITRE **T1204.002** —
  carved `Au_`-family installer artifact). Treat these as hypotheses; prove each against live tool output.

### Recommended path + tool chain for this evidence (mixed disk + memory)

Because this is a **mixed** case, run **both** sub-chains (the autonomous driver walks each image with the
right per-evidence sequence automatically):

- **Memory (`Rocba-Memory.raw`) — Volatility3 chain:**
  `get_pslist` (Volatility3 is profile-less — this **first `windows.*` plugin auto-detects the kernel
  profile**; a populated `get_pslist` is the real OS/build-confirm step for a memory image) →
  `get_netscan` → `get_malfind` → `get_svcscan` → `build_process_tree` (PPID forest / LOLBin flags) →
  `run_volatility` for any specific Win10 plugin — use the **short alias** (`cmdline`) or the **canonical
  id** (`windows.cmdline.CmdLine`); the bare middle form `windows.cmdline` is **rejected**. (Memory
  Amcache is not a valid `run_volatility` plugin — disk Amcache is covered by the `get_amcache` wrapper.)
  Note: `get_image_info` is **not** used here — it drives `ewfinfo`/EWF metadata and returns all-empty
  fields on a raw memory dump.
- **Disk (`rocba-cdrive.e01`) — TSK / EZ-Tools chain:**
  `get_partitions`/`mmls` (confirms whole-disk → **offset 0**) → `fls { offset: 0 }` live + deleted →
  `extract_files { offset: 0 }` (lift hives) → `get_registry` / `get_shimcache` / `get_amcache`
  (Win7+) / `get_prefetch` / **`srum_extract`** → `get_evtx` (Win10 `.evtx`) → `run_bulk_extractor`
  (IOC carving) → `scan_yara` (smoke-test only until a production ruleset is installed).
- **Cross-image:** `correlate_timeline` (merge memory + disk events into one UTC stream over the
  2020-11-13/14 window) and `pivot_on_ioc` (substring hunt across both images for a brute-force IP).

---

## 2. Instantiated procedure (steps 0 → 8 with this case's real values)

> Where you run these: any client with the `agentropix-sift` MCP server bound — these are **MCP tool
> calls, not a CLI**. Endpoint shape (tailnet-only): `http://<TAILNET-HOST>:8765/mcp` with a bearer
> token (get the real host + token from Client Setup; they are not reproduced here).

### Step 0 — Pre-flight (operator-local)

> **🖥️ Expert (command):**
> ```bash
> uv run agentropix-sift doctor                 # resolves the 16 SIFT backing binaries → "All tools available."
> bash /home/admin2/.openclaw/workspace/scripts/start-agentropix-mcp.sh status   # expect health: HTTP 200
> ewfverify /cases/rocba/rocba-cdrive.e01       # chain-of-custody: stored MD5 == calculated MD5
> ```
> **💬 End-user (prompt):** *"Check that my Agentropix forensic environment is ready, the MCP server is
> healthy, and verify the integrity of the ROCBA C-drive E01."*
>
> **Expect:** `doctor` ends with `All tools available.`; `health` returns `status: "ok"` with a live
> `tool_count` (canonical **72** — trust the live number, not the banner); `ewfverify` reports
> **SUCCESS** with MD5 `5efc207c85587683e5ca5fa2d5ef1aa4`.

### Step 1 — Pick evidence + choose the slug

Evidence is already under `/cases/rocba/`. Slug = **`ROCBA-HACKATHON-2026`** (no spaces, no slashes).

### Step 2 — `case_init` (register + activate)

> **🖥️ Expert (MCP call):**
> ```text
> case_init {
>   "case_name":"ROCBA Hackathon 2026",
>   "examiner_id":"victor.galvan",
>   "case_id":"ROCBA-HACKATHON-2026",
>   "case_dir":"/cases/rocba",
>   "description":"Win10 (Build 19042) host: C-drive E01 + 19GB raw memory. RDP brute-force (T1110.003) + user-exec malware (T1204.002).",
>   "incident_type":"intrusion/insider-ip-theft",
>   "severity":"high",
>   "scope":"/cases/rocba/rocba-cdrive.e01,/cases/rocba/Rocba-Memory/Rocba-Memory.raw",
>   "tags":["rocba","win10","memory","disk","hackathon-2026"]
> }
> ```
> **💬 End-user (prompt):** *"Open a new high-severity case `ROCBA-HACKATHON-2026` for the ROCBA Win10
> host (C-drive E01 + raw memory), examiner victor.galvan, and make it the active case."*
>
> **Expect:** `case_id` = `ROCBA-HACKATHON-2026`, `status active`, `started_at …`. Idempotent on the
> slug — re-running updates, won't duplicate. (`case_init` writes the active-case pointer first.)

### Step 3 — `case_status` (confirm active)

> **🖥️ Expert (MCP call):** `case_status {}` (or `case_status { "case_id":"ROCBA-HACKATHON-2026" }`)
> **💬 End-user (prompt):** *"Is `ROCBA-HACKATHON-2026` the active case and is the indexer reachable?"*
>
> **Expect:** `active: true` and `indexer_reachable: true` for `ROCBA-HACKATHON-2026`. (Single active
> pointer — `/home/admin2/.agentropix/active_case`.)

### Step 4 — `evidence_register` (SHA-256 custody, BOTH images)

> **🖥️ Expert (MCP calls):**
> ```text
> evidence_register { "path":"/cases/rocba/rocba-cdrive.e01",
>                     "description":"Windows 10 (Build 19042) system disk (EWF/E01)",
>                     "examiner_id":"victor.galvan" }
> evidence_register { "path":"/cases/rocba/Rocba-Memory/Rocba-Memory.raw",
>                     "description":"Windows 10 physical memory capture (raw, Vol3-native)",
>                     "examiner_id":"victor.galvan" }
> ```
> **💬 End-user (prompt):** *"Register both ROCBA images as evidence in this case — the C-drive E01 and
> the raw memory dump — and give me their SHA-256 custody hashes."*
>
> **Expect:** an `evidence_id` + SHA-256 per image, bound to the active case, indexed to
> `agentropix-evidence-YYYY.MM.DD`. Ground-truth pins to check against: memory SHA-256
> `eb33bdf6373085…`; E01 file-level SHA-256 `f2eb856d6fb48e…` (E01 MD5 `5efc207c…`). Optionally confirm
> with `get_image_info { "image":"/cases/rocba/rocba-cdrive.e01" }` → media `81 GiB / 87431311360`,
> OS Win 10 Build 19042. (`evidence_register` is idempotent and audited.)

### Step 5 — Analyze (mixed: disk **and** memory)

> ⚠️ **Per-case deviation — `fls`/`extract_files` use `offset 0` (whole-disk NTFS, no MBR).** Confirm
> first with `get_partitions`/`mmls` (returns empty — that's expected here), then pass `offset: 0`.
> Do **not** copy CFReDS's sector-63 offset into this case.

> ⚠️ **`run_bulk_extractor` `out_dir` must be Thymus-allowlisted** — use
> `/tmp/agentropix-sift-rocba-be` (allowed prefixes: `/tmp/agentropix-sift-*`, `/cases/`, `/mnt/`,
> `/media/`, `/evidence/`). On Desktop, mind the **1 MB** single-result cap on heavy tools (carve,
> timeline, strings) — prefer their `out_dir`/path return mode.

> **🖥️ Expert (MCP calls) — disk:**
> ```text
> get_partitions { "image":"/cases/rocba/rocba-cdrive.e01" }                        # expect EMPTY → offset 0
> fls            { "image":"/cases/rocba/rocba-cdrive.e01", "offset":0, "recursive":true }
> fls            { "image":"...e01", "offset":0, "recursive":true, "deleted_only":true }   # T1070.004
> extract_files  { "image":"...e01", "offset":0, "paths":["<hive paths>"], "dest":"/tmp/agentropix-sift-rocba-hives" }
> get_registry   { ... } ; get_shimcache { ... } ; get_amcache { ... }              # Win7+: amcache present
> get_prefetch   { ... } ; srum_extract { ... }                                     # SRUM (Win10)
> get_evtx       { "image":"...e01", "offset":0, "event_id":4625, "since":"2020-11-13T22:00:00Z" }   # RDP brute-force (T1110.003)
> run_bulk_extractor { "target":"/cases/rocba/rocba-cdrive.e01", "out_dir":"/tmp/agentropix-sift-rocba-be", "max_features":1000 }
> scan_yara      { "target":"/cases/rocba/rocba-cdrive.e01", "rules":["/cases/yara-rules/local/pf_smoketest.yar"], "max_matches":200 }
> ```
> **🖥️ Expert (MCP calls) — memory:** (no `get_image_info` — it reads EWF/E01 metadata only and returns
> all-empty on a `.raw` dump; `get_pslist`, the first `windows.*` plugin, auto-detects the Win10 profile)
> ```text
> get_pslist         { "image":"/cases/rocba/Rocba-Memory/Rocba-Memory.raw" }   # auto-detects kernel profile = OS confirm
> get_netscan        { "image":"..." }   # external C2 / RDP sockets
> get_malfind        { "image":"..." }   # injected / RWX code
> get_svcscan        { "image":"..." }
> build_process_tree { "image":"..." }   # PPID forest, LOLBin flags
> ```
> **🖥️ Expert (MCP calls) — cross-image:**
> ```text
> correlate_timeline { "images":["/cases/rocba/Rocba-Memory/Rocba-Memory.raw","/cases/rocba/rocba-cdrive.e01"] }
> pivot_on_ioc       { "ioc":"<brute-force IP>", "images":["...raw","...e01"] }
> ```
> **💬 End-user (prompt):** *"Analyze the ROCBA case end to end: on the disk, list files (live + deleted),
> pull the registry hives, and check execution/persistence and the `4625` logon-failure events around
> 2020-11-13/14; on the memory image, list processes, network connections, and any injected code; then
> correlate the two timelines."*
>
> **Expect:** non-zero `fls` live `entry_count`; carve writes `report.xml` to the allowlisted `out_dir`;
> Volatility tools return a process/socket/injection summary; `get_evtx` surfaces the `4625` brute-force
> burst. (Analysis outputs are **not** auto-persisted — Step 6 turns them into case state.)

### Step 6 — `record_finding` (DRAFT-gated)

> **🖥️ Expert (MCP call):**
> ```text
> record_finding { "finding": {
>   "finding_id":"rocba-rdp-bruteforce-001",
>   "host":"rocba-cdrive-win10",
>   "mitre_attack":"T1110.003",
>   "confidence":0.6,
>   "timestamp":"2020-11-13T22:00:00Z",
>   "severity":"medium",
>   "title":"External RDP brute-force burst (15,048 EventID 4625 failures)",
>   "ioc_value":"213.202.233.104", "ioc_type":"ipv4",
>   "source_artifact":"/cases/rocba/rocba-cdrive.e01 (Security.evtx)" } }
> ```
> **💬 End-user (prompt):** *"Record a medium-severity finding for the external RDP brute-force we found
> in the `4625` events, mapped to MITRE T1110.003, citing the Security event log."*
>
> **Expect:** `finding_id rocba-rdp-bruteforce-001`, `indexed:false` (DRAFT — intentionally not pushed
> to the index; the engine/LLM **cannot** self-approve). **Required fields:** `finding_id`, `host`,
> `mitre_attack`, `confidence`, `timestamp`. **Coherence:** `severity:high` needs `confidence ≥ 0.70`;
> `critical` needs `≥ 0.85`. Timeline events: `record_timeline_event { event, hostname, case_id }`.
> ⚠️ A missing `finding_id` → `finding must contain non-empty finding_id` (bug B4).

### Step 7 — Approve (human-only examiner gate)

> **HARD STOP — human-only cryptographic sign-off.** DRAFT → APPROVED happens only through the HMAC
> challenge-response Approval Portal — an LLM/agent cannot do this.
> **🔗 `https://siftworkstation.taile7c9ca.ts.net:8443/`** (or on the workstation `http://127.0.0.1:8800/`).
> Fill **Examiner ID** (= `AGENTROPIX_APPROVER_USER`), **Case ID** `ROCBA-HACKATHON-2026`, the DRAFT
> **Finding ID** (e.g. `rocba-rdp-bruteforce-001`), transition **From** `DRAFT` **To** `APPROVED`, enter
> the approver password, **Sign & Submit** (crypto is client-side; the password never leaves the tab).
> In-band equivalent: `approve_finding { "finding_id":"rocba-rdp-bruteforce-001", "approver_id":"victor.galvan", "password":"<pw>" }`.
> **💬 End-user (prompt):** *"Which findings are waiting for my approval and what are their IDs?"* — then
> you approve **yourself** in the portal. There is no plain-language approval shortcut, by design.
>
> **Expect:** a success writes an append-only approval doc to `agentropix-approvals-YYYY.MM.DD`, extends
> the hash chain, and moves the finding out of `DRAFT`. Approvals are append-only (correct via `REVOKED`,
> never delete).

### Step 8 — `report_generate` (+ optional Wazuh IOC push)

> **🖥️ Expert (MCP call):** `report_generate { "profile":"full", "case_id":"ROCBA-HACKATHON-2026" }`
> **💬 End-user (prompt):** *"Generate the full report for `ROCBA-HACKATHON-2026`."*
>
> **Expect:** a `report_id` + section counts. `approved_finding_count` stays `0` until Step 7 approves a
> finding (DRAFT findings are not surfaced). ⚠️ A brand-new DRAFT-only case can return `case_not_found`
> until there is indexed state (register evidence and/or approve ≥1 finding, then re-generate).
> **Profiles:** `full` / `executive` / `timeline` / `ioc` / `findings` / `status`.
> **Optional Wazuh push:** curate → mint an `egt_<ULID>` evidence-gate token (scope `index_findings`) →
> `wazuh_index_findings { dry_run:true }` then live with `mutation_token` (EXPERIMENTAL/opt-in; never
> push the raw carve).

---

## 3. "Activate & start" prompt sequences

Both lanes hit the **same deterministic MCP engine** and reach the same sealed result — only *who drives
the tool chain* differs. Run top-to-bottom; check each **Expect:** before the next.

### 3A — MANUAL sequence (💬 prompts; 🖥️ command equivalent each)

1. 💬 *"Check the Agentropix environment is ready and verify the integrity of the ROCBA C-drive E01."*
   🖥️ `uv run agentropix-sift doctor` · `ewfverify /cases/rocba/rocba-cdrive.e01`
   **Expect:** `All tools available.`; `ewfverify` **SUCCESS**, MD5 `5efc207c85587683e5ca5fa2d5ef1aa4`.

2. 💬 *"Open a new high-severity case `ROCBA-HACKATHON-2026` for the ROCBA Win10 host (C-drive E01 + raw memory), examiner victor.galvan, and make it the active case."*
   🖥️ `case_init { case_id:"ROCBA-HACKATHON-2026", … }` (Step 2)
   **Expect:** `case_id ROCBA-HACKATHON-2026`, `status active`, active-pointer written.

3. 💬 *"Is `ROCBA-HACKATHON-2026` the active case and is the indexer reachable?"*
   🖥️ `case_status {}`
   **Expect:** `active: true`, `indexer_reachable: true`.

4. 💬 *"Register both ROCBA images as evidence — the C-drive E01 and the raw memory — and give me their SHA-256 custody hashes."*
   🖥️ `evidence_register {…e01}` · `evidence_register {…raw}` (Step 4)
   **Expect:** an `evidence_id` + SHA-256 per image; memory SHA-256 matches `eb33bdf6373085…`.

5. 💬 *"What does Agentropix report about the C-drive image — media size, OS, and MD5?"*
   🖥️ `get_image_info { "image":"/cases/rocba/rocba-cdrive.e01" }`
   **Expect:** media `81 GiB (87431311360 bytes)`, OS **Win 10 Build 19042**, MD5 `5efc207c…`.

6. 💬 *"What's the partition layout of the C-drive image, and where does the NTFS volume start?"*
   🖥️ `get_partitions { "image":"/cases/rocba/rocba-cdrive.e01" }`
   **Expect:** **no partition table** (whole-disk NTFS) → `fls` will use **offset 0** (not sector 63).

7. 💬 *"List all files on the C-drive image, then show me just the deleted files."*
   🖥️ `fls { image:"…e01", offset:0, recursive:true }` · `fls { …, deleted_only:true }`
   **Expect:** non-zero live `entry_count`, plus the deleted set.

8. 💬 *"On the disk, pull the registry hives and tell me what executed, what auto-runs, and what the `4625` logon-failure events show around 2020-11-13/14."*
   🖥️ `extract_files {offset:0,…}` → `get_registry`/`get_shimcache`/`get_amcache`/`get_prefetch`/`srum_extract` · `get_evtx {event_id:4625, since:"2020-11-13T22:00:00Z"}`
   **Expect:** execution/persistence artifacts summarized; the `4625` RDP brute-force burst (T1110.003) surfaced.

9. 💬 *"Carve out the indicators — emails, domains, IPs, URLs — from the C-drive image."*
   🖥️ `run_bulk_extractor { target:"…e01", out_dir:"/tmp/agentropix-sift-rocba-be", max_features:1000 }`
   **Expect:** carve writes `report.xml` to the allowlisted `out_dir`; feature counts reported.

10. 💬 *"Analyze the memory image: what processes were running, what network connections were open, and is there any injected code?"*
    🖥️ `get_pslist` · `get_netscan` · `get_malfind` · `get_svcscan` · `build_process_tree` (image = the `.raw`)
    **Expect:** process/socket/injection summary from the Volatility-backed tools.

11. 💬 *"Correlate the disk and memory timelines, then pivot on the brute-force IP across both images."*
    🖥️ `correlate_timeline { images:["…raw","…e01"] }` · `pivot_on_ioc { ioc:"<IP>", images:[…] }`
    **Expect:** a merged UTC timeline; the IOC located across images.

12. 💬 *"Record a medium-severity finding for the external RDP brute-force, mapped to MITRE T1110.003, citing the Security event log."*
    🖥️ `record_finding { finding:{ finding_id:"rocba-rdp-bruteforce-001", … } }`
    **Expect:** `finding_id rocba-rdp-bruteforce-001`, `indexed:false` (DRAFT — cannot self-approve).

13. 💬 *"Which findings are waiting for my approval and what are their IDs?"* — then approve **yourself** in the portal.
    🖥️ portal `https://siftworkstation.taile7c9ca.ts.net:8443/` (or `approve_finding {…}` with the examiner password)
    **Expect:** the DRAFT finding listed; after sign-off it moves out of DRAFT (append-only approval doc).

14. 💬 *"Generate the full report for `ROCBA-HACKATHON-2026`."*
    🖥️ `report_generate { profile:"full", case_id:"ROCBA-HACKATHON-2026" }`
    **Expect:** `report_id` + section counts; `approved_finding_count` reflects Step 13 (0 if nothing approved; a DRAFT-only case may return `case_not_found` until indexed state exists).

### 3B — AUTONOMOUS sequence (launch → monitor → approve → report)

The driver runs the full per-image SIFT sequence (memory + disk), stages findings **DRAFT**, and **stops
at the approval gate** — a bot must not sign chain-of-custody. **Use Claude CLI** (not Desktop — the 1 MB
cap bites on the heavy tools). The reference driver is
`/home/admin2/.openclaw/workspace/drivers/agx_gearb.py`; the logical case key is **`rocba`** (resolved via
`cases.json`, `kind: multi` → pass an explicit `--image`).

1. **Launch — DETACHED** (the single most important step; token from ENV, never argv).
   🖥️ Smoke-test first, then run each image:
   ```bash
   # safe smoke test (session + health + schema + get_image_info; no case record):
   AGENTROPIX_MCP_AUTH_TOKEN="<BEARER_TOKEN>" python3 /home/admin2/.openclaw/workspace/drivers/agx_gearb.py rocba --preflight --image /cases/rocba/rocba-cdrive.e01

   # disk image, detached + survivable:
   AGENTROPIX_MCP_AUTH_TOKEN="<BEARER_TOKEN>" \
     setsid nohup bash -c "python3 /home/admin2/.openclaw/workspace/drivers/agx_gearb.py rocba --image /cases/rocba/rocba-cdrive.e01 --offset 0 > run-rocba-disk.log 2>&1" </dev/null >/dev/null 2>&1 &
   disown
   # memory image, detached (separate run):
   AGENTROPIX_MCP_AUTH_TOKEN="<BEARER_TOKEN>" \
     setsid nohup bash -c "python3 /home/admin2/.openclaw/workspace/drivers/agx_gearb.py rocba --image /cases/rocba/Rocba-Memory/Rocba-Memory.raw > run-rocba-mem.log 2>&1" </dev/null >/dev/null 2>&1 &
   disown
   ```
   💬 *Non-expert equivalent (interactive autonomous prompt — no shell detachment):* *"You are a DFIR
   analyst with the Agentropix MCP. Investigate case `ROCBA-HACKATHON-2026` on images
   `/cases/rocba/rocba-cdrive.e01` and `/cases/rocba/Rocba-Memory/Rocba-Memory.raw`. Run the full SIFT
   sequence (acquisition → examination → analysis → findings), staging findings as DRAFT. This disk is
   whole-disk NTFS — use offset 0 for `fls`. Write `bulk_extractor` `out_dir` under
   `/tmp/agentropix-sift-rocba`. Do NOT approve findings. Finish by generating the full report."*
   **Expect:** the driver/agent walks `case_init`→`case_activate`→`evidence_register`→
   (disk) `get_image_info`(E01 only — EWF metadata) → `fls`(offset 0) live+deleted →
   `extract_files`→registry/exec artifacts → carve; (memory — **no** `get_image_info`, it returns empty on
   raw memory) `get_pslist`(auto-detects the Win10 profile)/`get_netscan`/`get_malfind`/`get_svcscan`/`build_process_tree` → `record_finding`×N DRAFT
   → `report_generate{full}`, then **stops before approval**. `--preflight` returns session+health+schema
   OK with no case record. (⚠️ pass only the **case key** positional — never the token as argv.)

2. **Monitor.**
   🖥️ `tail -f run-rocba-disk.log` and read the per-step checkpoint
   `/home/admin2/.openclaw/workspace/drivers/gearB/rocba/SUMMARY.json` (per-step `ok`/`elapsed`/`error`).
   💬 *"How's the ROCBA investigation going — which steps are done?"*
   **Expect:** each step's `ok`/`elapsed` checkpointed after it completes; a death never loses prior
   progress (idempotent — an existing complete carve is detected via `<out_dir>/report.xml` and skipped).
   ⚠️ **Bug B5:** if the driver is **not** detached, a long blocking call (carve on the 23 GB E01) is
   killed at a shell boundary — `setsid`+`nohup`+`disown` makes it survivable.

3. **Approve (human-only gate).**
   🖥️ Approval Portal `https://siftworkstation.taile7c9ca.ts.net:8443/` — Case `ROCBA-HACKATHON-2026`,
   DRAFT finding ID, From `DRAFT` → To `APPROVED`, sign & submit. (In-band: `approve_finding {…}`.)
   💬 *"Which ROCBA findings are waiting for my approval and what are their IDs?"* — then approve yourself.
   **Expect:** DRAFT findings listed; the agent will **not** and **cannot** approve on your behalf.
   Sign-off extends the append-only approval hash chain.

4. **Report.**
   🖥️ `report_generate { profile:"full", case_id:"ROCBA-HACKATHON-2026" }`
   💬 *"Generate the full report for `ROCBA-HACKATHON-2026`."*
   **Expect:** `report_id` + section counts; once findings are approved, `approved_finding_count` and the
   report sections populate.

5. **Verify the seal.**
   🖥️ `uv run python scripts/verify_seal.py <report>.json`
   💬 *"Verify the seal on the ROCBA report — confirm it hasn't been tampered with since it was generated."*
   **Expect:** the seal verifier confirms the report + audit log are intact (HMAC-SHA256 seal,
   `evidence_image_sha256`-bound to the exact image).

---

## 4. Quick recap (one line per phase)

```text
0  doctor ; mcp status ; ewfverify /cases/rocba/rocba-cdrive.e01   (MD5 5efc207c…)
1  slug = ROCBA-HACKATHON-2026
2  case_init { case_id:"ROCBA-HACKATHON-2026", severity:"high", scope: both images }
3  case_status {}                                   → active:true, indexer_reachable:true
4  evidence_register e01  +  evidence_register Rocba-Memory.raw   (mem sha256 eb33bdf6…)
5  DISK: get_partitions(EMPTY)→fls offset 0 live+deleted→extract_files→registry/shimcache/amcache/prefetch/srum_extract→get_evtx(4625)→run_bulk_extractor(/tmp/agentropix-sift-rocba-be)→scan_yara
   MEM:  get_pslist→get_netscan→get_malfind→get_svcscan→build_process_tree
   X:    correlate_timeline ; pivot_on_ioc
6  record_finding { finding_id:"rocba-rdp-bruteforce-001", mitre:T1110.003 }  → DRAFT
7  approve in portal  https://siftworkstation.taile7c9ca.ts.net:8443/   (HUMAN-ONLY)
8  report_generate { profile:"full", case_id:"ROCBA-HACKATHON-2026" } ; (optional) curate→egt_ token→wazuh_index_findings
```

> **Source-of-truth note.** Tool names, signatures, gotchas (B2–B5), and the autonomous driver pattern
> are taken from [`docs/01-overview/user-guide.md`](../docs/01-overview/user-guide.md) and the canonical
> `END-USER-CASE-GUIDE.md`. The per-case
> offset-0 / Win10-artifact deviations are derived from this case's ground-truth audit
> (`/cases/rocba/_work/ROCBA-HACKATHON-2026/audit/{MMLS,IMAGE_HASH,MEMORY_FORMAT,TIMEZONE}.txt`) and
> `ewfinfo` — confirmed metadata-only on 2026-06-06. Canonical numbers: [`.crew/facts.md`](../docs/08-reference/canonical-facts.md).
