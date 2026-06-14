# Case Activation Guide — CFReDS "Hacking Case" (Greg Schardt / Mr. Evil)

> **LOCAL ONLY — real case inventory.** This file lives under
> `/home/admin2/docu_agentro/case-activation/` (gitignored). It contains real evidence paths.
> Do not publish. The MCP endpoint is shown as the tailnet placeholder
> `http://<TAILNET-IP>:8765/mcp` — never paste a raw internal IP or the bearer token here.
>
> Procedure source-of-truth: `/home/admin2/agentropix-sift/docs/tools/END-USER-CASE-GUIDE.md`
> (steps 0→8). House style + dual-audience (🖥️ command / 💬 prompt) + numbered playbooks mirror
> `/home/admin2/docu_agentro/docs/01-overview/user-guide.md`. Canonical numbers cite
> `/home/admin2/docu_agentro/.crew/facts.md` (`mcp_tool_count=71`, `test_count=4687`, 16 SIFT wrappers).

---

## 1. Identification header

| Field | Value |
|---|---|
| **Case name** | CFReDS "Hacking Case" — Dell Latitude CPi laptop |
| **One-line description** | NIST CFReDS training image of Greg Schardt / "Mr. Evil"'s seized Dell Latitude CPi — a hacking-tools / insider-misuse Windows XP disk. |
| **Evidence type** | **Disk** (physical-disk EWF acquisition) |
| **Image file(s)** | `/cases/cfreds-fresh/4Dell-Latitude-CPi.E01` (EWF, primary segment) · `/cases/cfreds-fresh/4Dell-Latitude-CPi.E02` (EWF, continuation segment) |
| **Format** | EWF / Expert Witness / EnCase image (`File format: EnCase 4`, `Software version used: 4.19a`) — verified by `file` as *EWF/Expert Witness/EnCase image file format* on both segments. |
| **Size** | E01 = 671,094,597 B (641 MiB on disk) · E02 = 419,384,951 B (400 MiB) · **case folder total ≈ 1.1 G**. Logical media (decoded disk) = **4.5 GiB / 4,871,301,120 bytes** (9,514,260 sectors × 512 B). |
| **Integrity** | EWF-verified sound. Stored MD5 == computed MD5 == `aee4fcd9301c03b3b054623ca261959a` (per `ewfinfo` + the CHAIN.md `ewfverify SUCCESS` record). E01+E02 are the only segments upstream publishes (E03–E08 return 404). |
| **Suggested `case_id` slug** | **`CFREDS-HACKING-CASE-4DELL`** (matches `^[A-Za-z0-9._-]{1,128}$`: no spaces, no slashes). Alternative used in the example run: `INC-2026-0529224443` (auto-generated). |
| **OS / scenario** | **Windows XP** (per EWF metadata). Acquired `Wed Sep 22 14:06:04 2004` by examiner **Shane Robinson**, EWF case number **Greg Schardt**, description "Dell Latitude CPi", notes `sn# VLQLW hdsn# RQQF7429`. Scenario: hacking-tool possession / wardriving / insider misuse (the "Mr. Evil" persona). |

### Recommended path + tool chain (disk evidence)

This is a **disk** image, so the **disk/artifacts** chain applies (memory plugins do **not** — there is
no `.raw`/`.img`/`.001` memory dump in this case):

1. **Pre-flight / custody** — `doctor` (binaries present) → `ewfverify` (byte-intact) → `ewfinfo` /
   `get_image_info` (acquisition metadata).
2. **Partition** — `mmls` / `get_partitions` to get the NTFS slot's **start sector (63)**. This offset is
   load-bearing for every filesystem tool (GOTCHA B2).
3. **Filesystem / MFT** — `fls` (offset 63) recursive live + `deleted_only` (T1070.004 deletion review).
4. **IOC carving** — `run_bulk_extractor` (allowlisted `out_dir`) for emails / domains / IPs / URLs — the
   high-signal step for a hacking-tools image (carves the tool-author email fingerprint).
5. **YARA** — `scan_yara` (currently only the `pf_smoketest.yar` ruleset; 0 matches is the clean success
   signature, not a failure).
6. **Registry / execution / event-log artifacts** — `extract_files` (offset 63) to lift hives → `get_registry`,
   `get_shimcache`, `get_prefetch`. **XP specifics:** `get_amcache` is **Win7+ only → skip**;
   event logs are XP `.evt` → use **`get_evt`** (NOT `get_evtx`, which is Vista+ `.evtx`).
7. **Findings → approval → report** — `record_finding` (DRAFT) → human approval in the portal →
   `report_generate`.

> **Memory chain — not applicable here.** `get_pslist` / `get_netscan` / `get_malfind` / `get_svcscan` /
> `build_process_tree` (Volatility) are for memory-image cases (SRL-2015/SRL-2018/rocba). This case has
> no memory dump, so those tools are out of scope.

---

## 2. Instantiated procedure — template steps 0→8 with this case's real values

> 🖥️ = exact command / MCP call · 💬 = plain-language prompt to a Claude session with the
> `agentropix-sift` MCP attached. Both hit the same deterministic tool.

### Step 0 — Before you start (pre-flight + custody)

> **🖥️ Expert:**
> ```bash
> uv run agentropix-sift doctor                                   # expect: All tools available.
> ewfverify /cases/cfreds-fresh/4Dell-Latitude-CPi.E01           # expect: SUCCESS, MD5 aee4fcd9…
> ewfinfo  /cases/cfreds-fresh/4Dell-Latitude-CPi.E01           # acquisition metadata
> ```
> **💬 End-user:** *"Check my Agentropix forensic environment is ready, then verify the integrity of the
> CFReDS E01 image and show me who acquired it and what OS it is."*

Expected: 16-wrapper toolchain resolves `All tools available.`; `ewfverify` → `SUCCESS` with stored MD5
== computed MD5 == `aee4fcd9301c03b3b054623ca261959a`; `ewfinfo` → case `Greg Schardt`, examiner
`Shane Robinson`, `Windows XP`, `EnCase 4`, acquired 2004-09-22. (`ewfverify` reads the whole E01+E02
chain — you point it at the `.E01` only.)

### Step 1 — Pick evidence and choose a `case_id` slug

Evidence is already under `/cases/cfreds-fresh/`. Slug: **`CFREDS-HACKING-CASE-4DELL`**.
(`_corrupt-backup/` holds the 167-byte HTML 301 failures from the original bad download — **ignore it**;
it is not evidence.)

### Step 2 — Activate (register) the case — `case_init`

> **🖥️ Expert (MCP call):**
> ```text
> case_init {
>   "case_name":     "CFReDS Hacking Case (Greg Schardt / Mr. Evil)",
>   "examiner_id":   "victor.galvan",
>   "case_id":       "CFREDS-HACKING-CASE-4DELL",
>   "case_dir":      "/cases/cfreds-fresh",
>   "description":   "NIST CFReDS Hacking Case — Dell Latitude CPi, Windows XP, hacking-tools/insider misuse",
>   "incident_type": "intrusion/hacking-tools",
>   "severity":      "high",
>   "scope":         "/cases/cfreds-fresh/4Dell-Latitude-CPi.E01",
>   "tags":          ["cfreds","hacking-case","schardt","winxp"]
> }
> ```
> **💬 End-user:** *"Open a new high-severity case `CFREDS-HACKING-CASE-4DELL` for the CFReDS hacking
> image (Greg Schardt / Mr. Evil), examiner victor.galvan, evidence in /cases/cfreds-fresh."*

`case_init` writes the active-case pointer first, then upserts the record. **Idempotent on `case_id`** —
re-running the same slug updates, never duplicates.

### Step 3 — Confirm it's active — `case_status`

> **🖥️ Expert:** `case_status { }` (active pointer) or `case_status { "case_id":"CFREDS-HACKING-CASE-4DELL" }`
> **💬 End-user:** *"Is the CFReDS hacking case active and is the indexer reachable?"*

Expected: `active: true`, `indexer_reachable: true`. If you skipped activation, pass an explicit
`case_id` to later tools (or run `case_activate { "case_id":"CFREDS-HACKING-CASE-4DELL" }`).

### Step 4 — Register evidence (SHA-256 chain of custody) — `evidence_register`

> **🖥️ Expert (MCP call):**
> ```text
> evidence_register {
>   "path":        "/cases/cfreds-fresh/4Dell-Latitude-CPi.E01",
>   "description": "Windows XP system disk — Dell Latitude CPi (EWF/E01, E02 continuation)",
>   "examiner_id": "victor.galvan"
> }
> ```
> **💬 End-user:** *"Register the CFReDS E01 image as evidence in this case and give me its SHA-256
> custody hash."*

Expected (validated example run): evidence **SHA-256 `96bebe80f00541bf28fbc2ef0b02b580082ee6ad58837e991852ae66f077ec31`**,
`size_bytes 671094597` (the on-disk EWF container, ≈640 MiB), `indexed: true`. Confirm media metadata
in-band with `get_image_info { "image":"/cases/cfreds-fresh/4Dell-Latitude-CPi.E01" }` → media_size
`4.5 GiB (4871301120 bytes)`, MD5 `aee4fcd9…`. (The two sizes differ on purpose: 671 MB = compressed
EWF container on disk; 4.5 GiB = logical decoded media.)

### Step 5 — Analyze the evidence (disk chain)

> **🖥️ Expert (MCP calls):**
> ```text
> mmls { "image":"/cases/cfreds-fresh/4Dell-Latitude-CPi.E01" }                 # NTFS @ sector 63
> fls  { "image":"...E01", "offset":63, "recursive":true }                       # live listing
> fls  { "image":"...E01", "offset":63, "recursive":true, "deleted_only":true }  # T1070.004
> run_bulk_extractor { "target":"...E01", "out_dir":"/tmp/agentropix-sift-cfreds-4dell-be", "max_features":1000 }
> scan_yara { "target":"...E01", "rules":["/cases/yara-rules/local/pf_smoketest.yar"], "max_matches":200 }
> extract_files { "image":"...E01", "offset":63, "paths":["<hive paths>"], "dest":"/tmp/agentropix-sift-cfreds-4dell-hives" }
> get_registry { ... } ; get_shimcache { ... } ; get_prefetch { ... }            # XP: NO get_amcache
> get_evt { ... }                                                                # XP .evt (NOT get_evtx)
> ```
> **💬 End-user:** *"Investigate the CFReDS disk: list the files (live and deleted), carve out all the
> indicators, run a YARA scan, then pull the registry hives and tell me what programs ran and what's set
> to auto-run. It's a Windows XP image."*

Expected: NTFS partition starts at **sector 63** (GOTCHA B2 — omit the offset and `fls` fails with
`Cannot determine file system type`). `fls` live ≈ 12,545 entries, deleted-only ≈ 365. `bulk_extractor`
carves emails/domains/IPs/URLs into an **allowlisted** `out_dir` (GOTCHA B3 — must be under
`/tmp/agentropix-sift-*`, `/cases/`, `/mnt/`, `/media/`, `/evidence/`). `scan_yara` → `match_count 0`
with `raw_stdout_sha256 e3b0c442…` (clean smoke-test, by design). The assistant auto-picks `get_evt`
(XP `.evt`) and skips Amcache (Win7+ only).

### Step 6 — Record findings — `record_finding` (DRAFT-gated)

> **🖥️ Expert (MCP call):**
> ```text
> record_finding { "finding": {
>   "finding_id":      "cfreds-4dell-acq-001",
>   "host":            "cfreds-schardt-xp",
>   "mitre_attack":    "T1588.002",
>   "confidence":      0.6,
>   "timestamp":       "2004-09-22T14:06:04Z",
>   "severity":        "medium",
>   "title":           "Hacking-tool author emails carved from disk (nmap/dsniff/ssh fingerprint)",
>   "ioc_value":       "fyodor@insecure.org",
>   "ioc_type":        "email",
>   "source_artifact": "/tmp/agentropix-sift-cfreds-4dell-be/email.txt"
> } }
> ```
> **💬 End-user:** *"Record a medium-severity finding for the hacking-tool emails we carved, mapped to
> MITRE T1588.002, citing the carved email.txt artifact."*

`record_finding` defaults to `dry_run=True` (preview only). To persist call with `dry_run=False` **and**
a valid `mutation_token`. **Required fields:** `finding_id` (non-empty — GOTCHA B4), `host`,
`mitre_attack`, `confidence` (0.0–1.0), `timestamp`. Coherence: `severity:high` needs `confidence ≥
0.70`, `critical` needs `≥ 0.85`. The finding lands **DRAFT** (`indexed:false`) — the engine/LLM cannot
self-approve.

### Step 7 — Approve (examiner gate — human-only)

> **🖥️ Expert (in-band attestation):**
> ```text
> approve_finding { "finding_id":"cfreds-4dell-acq-001", "approver_id":"victor.galvan", "password":"<examiner pw>" }
> ```
> **💬 End-user:** you do this **yourself** in the browser portal — no plain-language shortcut, by design.
> Portal: **`https://siftworkstation.taile7c9ca.ts.net:8443/`** (or local `http://127.0.0.1:8800/`).
> Set From=`DRAFT`, To=`APPROVED`, enter the approver password, Sign & Submit.

**Hard stop.** Examiner crypto sign-off is a human-only, HMAC challenge-response decision. Only the
configured `AGENTROPIX_APPROVER_USER` is accepted; approvals are append-only (correct with `REVOKED`,
never delete). DRAFT → APPROVED is what makes findings surface in the report.

### Step 8 — Report & (optional) push IOCs

> **🖥️ Expert:** `report_generate { "profile":"full", "case_id":"CFREDS-HACKING-CASE-4DELL" }`
> **💬 End-user:** *"Generate the full report for the CFReDS hacking case."*

`approved_finding_count` stays `0` until Step 7 approval (working as designed). A brand-new DRAFT-only
case can return `case_not_found` until there is indexed state (register evidence and/or approve a
finding, then re-generate). Optional Phase 8: curate IOCs → mint an `egt_` mutation token →
`wazuh_index_findings { dry_run:true }` then live. **Never push the raw 100k+ carve** — curate, dedup,
tier-tag, attach provenance first.

---

## 3. Activate & start — prompt sequences

Both lanes hit the **same 73-tool deterministic engine** (`{{ref:CANONICAL_FACTS#mcp_tool_count}}`,
backed by 4687 tests) and reach the same sealed result. Each operator action shows the 🖥️ command
equivalent.

### Manual sequence (ask one focused question per step; inspect each answer before the next)

1. 💬 *"Check my Agentropix forensic environment is ready — are all the forensic tools installed?"*
   🖥️ `uv run agentropix-sift doctor`
   **Expect:** each backing binary `OK <path>` (16 SIFT wrappers + `icat`/`strings`), ending `All tools available.`

2. 💬 *"Verify the integrity of the CFReDS E01 image — does its stored hash match?"*
   🖥️ `ewfverify /cases/cfreds-fresh/4Dell-Latitude-CPi.E01`
   **Expect:** `SUCCESS`, stored MD5 == computed MD5 == `aee4fcd9301c03b3b054623ca261959a`.

3. 💬 *"Show me the acquisition details — who acquired it, when, and what OS?"*
   🖥️ `ewfinfo /cases/cfreds-fresh/4Dell-Latitude-CPi.E01`
   **Expect:** case `Greg Schardt`, examiner `Shane Robinson`, acquired `Wed Sep 22 14:06:04 2004`, OS `Windows XP`, `EnCase 4`.

4. 💬 *"How many Agentropix forensic tools are available right now?"*
   🖥️ MCP `health`
   **Expect:** `status:"ok"` with a live `tool_count` (canonical `73`; trust the live number, not the banner).

5. 💬 *"Open a new high-severity case `CFREDS-HACKING-CASE-4DELL` for the CFReDS hacking image (Greg Schardt / Mr. Evil), examiner victor.galvan, evidence in /cases/cfreds-fresh, and make it active."*
   🖥️ MCP `case_init {…}` then `case_activate { "case_id":"CFREDS-HACKING-CASE-4DELL" }`
   **Expect:** the `case_id` echoed, status `active`, active-case pointer written.

6. 💬 *"Is the case active and is the indexer reachable?"*
   🖥️ MCP `case_status {}`
   **Expect:** `active:true`, `indexer_reachable:true`.

7. 💬 *"Register the CFReDS E01 image as evidence and give me its SHA-256 custody hash."*
   🖥️ MCP `evidence_register { "path":"/cases/cfreds-fresh/4Dell-Latitude-CPi.E01", … }`
   **Expect:** SHA-256 `96bebe80…`, `size_bytes 671094597`, `indexed:true`, bound to the active case.

8. 💬 *"What does Agentropix report about this image's media size and MD5?"*
   🖥️ MCP `get_image_info { "image":"…E01" }`
   **Expect:** media_size `4.5 GiB (4871301120 bytes)`, MD5 `aee4fcd9301c03b3b054623ca261959a`.

9. 💬 *"What's the partition layout, and where does the NTFS partition start?"*
   🖥️ MCP `get_partitions { "image":"…E01" }` (shell: `mmls …E01` — the underlying binary)
   **Expect:** NTFS partition starts at **sector 63** (carried forward as the `fls` offset — GOTCHA B2).

10. 💬 *"List all the files on the image, then show me just the deleted files."*
    🖥️ MCP `fls { offset:63, recursive:true }` then `fls { offset:63, recursive:true, deleted_only:true }`
    **Expect:** live `entry_count ≈ 12545`, deleted-only `entry_count ≈ 365`.

11. 💬 *"Carve out all the indicators — emails, domains, IPs, URLs — from the image."*
    🖥️ MCP `run_bulk_extractor { target:"…E01", out_dir:"/tmp/agentropix-sift-cfreds-4dell-be" }`
    **Expect:** ~25 feature types written to the allowlisted `out_dir` (GOTCHA B3); domain/email/url/ip dominate (counts vary run-to-run).

12. 💬 *"Run a YARA scan and tell me if anything matched."*
    🖥️ MCP `scan_yara { target:"…E01", rules:["/cases/yara-rules/local/pf_smoketest.yar"] }`
    **Expect:** `match_count 0`, `raw_stdout_sha256 e3b0c442…` — the clean-scan success signature, not a failure.

13. 💬 *"Pull the registry hives off this disk and tell me what programs ran, what auto-runs, and what the XP event logs show."*
    🖥️ MCP `extract_files { offset:63, dest:"/tmp/agentropix-sift-cfreds-4dell-hives" }` → `get_registry` / `get_shimcache` / `get_prefetch` / `get_evt`
    **Expect:** execution + persistence artifacts; the assistant uses `get_evt` (XP `.evt`) and skips Amcache (Win7+ only).

14. 💬 *"Record a medium-severity finding for the hacking-tool emails we carved, mapped to MITRE T1588.002, citing the email.txt artifact."*
    🖥️ MCP `record_finding { finding:{ finding_id:"cfreds-4dell-acq-001", … } }`
    **Expect:** a valid finding shaped (with `finding_id` — GOTCHA B4) lands `DRAFT` (`indexed:false`); cannot self-approve.

15. 💬 *"Which findings are waiting for my approval and what are their IDs?"*
    🖥️ open portal `https://siftworkstation.taile7c9ca.ts.net:8443/` → approve (or MCP `approve_finding {…}`)
    **Expect:** the DRAFT findings listed (e.g. `cfreds-4dell-acq-001`); you sign off yourself in the browser — no plain-language approval shortcut.

16. 💬 *"Generate the full report for this case, then verify its seal."*
    🖥️ MCP `report_generate { profile:"full", case_id:"CFREDS-HACKING-CASE-4DELL" }` → `uv run python scripts/verify_seal.py <out>.json`
    **Expect:** `report_id` + section counts; `approved_finding_count` reflects approvals; seal verifies intact (HMAC-SHA256, `evidence_image_sha256`-bound).

### Autonomous sequence (launch driver → monitor → approve → report)

1. 💬 *"You are a DFIR analyst with the Agentropix MCP. Investigate case `CFREDS-HACKING-CASE-4DELL` on image `/cases/cfreds-fresh/4Dell-Latitude-CPi.E01`. Run the full SIFT disk sequence (acquisition → examination → analysis → findings), staging findings as DRAFT. Use mmls-derived offsets for `fls` on this physical disk (NTFS @ sector 63). Write `bulk_extractor` `out_dir` under `/tmp/agentropix-sift-cfreds-4dell`. It's Windows XP — use `get_evt` for event logs and skip Amcache. Do NOT approve findings. Finish by generating the full report."*
   🖥️ Expert detached driver (token from ENV, case_key positional):
   ```bash
   AGENTROPIX_MCP_AUTH_TOKEN="<BEARER_TOKEN>" \
     setsid nohup bash -c "python3 /home/admin2/.openclaw/workspace/drivers/agx_gearb.py cfreds > run.log 2>&1" </dev/null >/dev/null 2>&1 &
   disown
   ```
   **Expect:** the agent walks `case_init`→`case_activate`→`evidence_register`→`get_image_info`→`fls` live+deleted→`run_bulk_extractor`→[disk registry/exec/evt artifacts]→`record_finding × N` (DRAFT)→`report_generate{full}`, stopping before approval. (Smoke-test first with `--preflight` after `cfreds`. Launch DETACHED — GOTCHA B5.)

2. 💬 *"How's the investigation going — which steps are done?"*
   🖥️ `tail -f run.log` and read `/home/admin2/.openclaw/workspace/drivers/gearB/cfreds/SUMMARY.json`
   **Expect:** per-step `ok`/`elapsed`/`error` checkpoints; the validated CFReDS run completes **10/10 steps OK**, final `record_finding` `indexed:false` (DRAFT), `full` report `approved_finding_count 0` (approval gate working as designed).

3. 💬 *"Which findings are waiting for my approval and what are their IDs?"*
   🖥️ open portal `https://siftworkstation.taile7c9ca.ts.net:8443/` (or MCP `approve_finding {…}`)
   **Expect:** the staged DRAFT findings listed (e.g. `cfreds-4dell-acq-001`); you approve yourself via HMAC sign-off (append-only) — the assistant cannot approve on your behalf.

4. 💬 *"Generate the full report for the CFReDS hacking case."*
   🖥️ MCP `report_generate { profile:"full", case_id:"CFREDS-HACKING-CASE-4DELL" }`
   **Expect:** `report_id` + section counts; once a finding is approved, `approved_finding_count` and the report sections populate (a DRAFT-only case may return `case_not_found` until there is indexed state).

5. 💬 *"Verify the seal on this report — confirm it hasn't been tampered with since it was generated."*
   🖥️ `uv run python scripts/verify_seal.py <report>.json`
   **Expect:** the seal verifier confirms the report + audit log are intact and unaltered since sealing (HMAC-SHA256, `evidence_image_sha256`-bound).

---

## Appendix — metadata-only verification (re-run before activation)

```bash
file    /cases/cfreds-fresh/4Dell-Latitude-CPi.E01 /cases/cfreds-fresh/4Dell-Latitude-CPi.E02
du -sh  /cases/cfreds-fresh/*.E0*          # E01 641M · E02 400M
du -sh  /cases/cfreds-fresh                # total ≈ 1.1G
ewfinfo /cases/cfreds-fresh/4Dell-Latitude-CPi.E01   # Greg Schardt / Win XP / EnCase 4 / 4.5 GiB / MD5 aee4fcd9…
```

Confirmed 2026-06-06: both segments are valid EWF (NOT the 167-byte HTML failures parked in
`_corrupt-backup/`, which are out of scope). CHAIN.md records the re-acquisition from
`cfreds-archive.nist.gov` (upstream publishes only E01+E02; E03–E08 → 404) and the `ewfverify SUCCESS`.
