# Case Activation Guide — TheTechHive · Chad_LT (Windows-on-ARM laptop)

> **LOCAL-ONLY operator runbook.** Lives under `case-activation/` (gitignored) because it
> contains real evidence paths, the BitLocker recovery identifier, and acquisition serials.
> Do **not** publish. This guide gets one operator **ready to activate the case and start
> analysis** — it does not run analysis. All profiling below is **metadata-only**
> (`file` / `ewfinfo` / `du` / a read of the in-folder TX1 log).
>
> Procedure source-of-truth: `END-USER-CASE-GUIDE.md`
> (8 steps). House style + dual-audience (🖥️ command / 💬 prompt) + numbered playbook follow
> [`docs/01-overview/user-guide.md`](../docs/01-overview/user-guide.md). Canonical numbers cite
> [`.crew/facts.md`](../docs/08-reference/canonical-facts.md) (**72 MCP tools**, **16 SIFT wrappers**, **4687 tests**).

---

## 1. Identification header

| Field | Value |
|---|---|
| **Case name** | TheTechHive — Chad_LT (Windows-on-ARM Dell Inspiron laptop) |
| **One-line description** | Full disk image of Chad's ARM-based Windows laptop from TheTechHive scenario; **primary OS volume is BitLocker-encrypted** (recovery key supplied in-folder). |
| **Evidence type** | **Disk** (physical-disk EWF/E01 image) |
| **Image file** | `/cases/nist3/TheTechHiveScenario/TheTechHiveScenario/Chad_LT.E01` |
| **Format** | EWF / Expert Witness / EnCase (`file` → *EWF/Expert Witness/EnCase image file format*) |
| **On-disk container size** | **86 GiB** (`du -h` = 86G; byte size 91,297,089,739) |
| **Logical media size** | **465 GiB (500,107,862,016 bytes)** — 976,773,168 × 512-byte sectors (`ewfinfo`) |
| **Acquisition MD5** | `2302bb04197384bb65c5d1b34cfb6e3f` (`ewfinfo` + TX1 log agree) |
| **Acquisition SHA-1** | `c1e2fd256b5f9d46a854c706b09b92448f706177` (`ewfinfo` + TX1 log agree) |
| **Acquired by / tool** | Examiner `Arsenal`, imager **TX1 21.3.0** (TIE 4.3.1), write-blocked (Tableau), 2026-02-02 |
| **TX1 Case ID** | `Arsenal-Windows_on_ARM-TechHive-Scenario` |
| **OS / host** | **Windows on ARM**, Dell Inspiron 14 3420, 500 GB Samsung NVMe SSD (source serial `00A2019C1114`) |
| **Suggested `case_id` slug** | **`TECHHIVE-CHAD-LT`** (matches `^[A-Za-z0-9._-]{1,128}$`; no spaces/slashes) |
| **`case_dir` pointer** | `/cases/nist3/TheTechHiveScenario/TheTechHiveScenario` |

### Supporting in-folder artifacts (metadata / custody, NOT forensic targets)

| File | Role |
|---|---|
| `Chad_LT Bitlocker Key.txt` | **BitLocker recovery key** — Identifier `48637073-594F-4370-91E6-F58E499B5AAF` matches the encrypted partition's Recovery ID in the TX1 log. Needed to unlock Partition 7. |
| `Chad_LT.log.txt` / `Chad_LT.log.html` | TX1 acquisition log (partition map, hashes, verification `Finished OK`). |
| `Chad_LT.tx1_packed_log` | TX1 packed log (binary; metadata). |

### Partition map (from the TX1 log — GPT, 9 partitions)

| # | Start sector | Size | Encryption / FS | Operator note |
|---|---|---|---|---|
| 1–6 | 2,048 … 1,095,680 | small | EFI / FAT / WinRE-class | ESP + recovery/diagnostic partitions |
| **7** | **1,357,824** | ~236 GB | **BitLocker** (Recovery ID `48637073-…`) | **The primary Windows-on-ARM OS volume — locked.** |
| **8** | **497,313,792** | ~1.3 GB NTFS | None | Readable NTFS (recovery/utility; ~640 MB in use) |
| **9** | **500,045,824** | ~244 GB NTFS | None | Readable NTFS (data; mostly empty, ~101 MB in use) |

> ⚠️ **Load-bearing caveat — BitLocker.** The platform's **72 MCP tools include no BitLocker
> decryption wrapper** (verified: no `bitlocker`/`dislocker` handler in `src/` or `TOOL-CONTRACTS.md`).
> Filesystem/registry/timeline tools (`fls`, `extract_files`, `get_registry`, …) can read the
> **plaintext** NTFS partitions (8 and 9) directly via their TSK `offset`, but they **cannot read
> the encrypted OS volume (Partition 7)** as-is. To analyse the OS, the operator must unlock it
> **out-of-band first** (e.g. `dislocker`/`libbde` with the recovery key, exposing a cleartext
> `dislocker-file`) and register that decrypted volume as additional evidence. This is an operator
> prerequisite, not an Agentropix step. Until then, profiling/triage is limited to Partitions 8 & 9.

### Recommended path + tool chain (disk evidence)

This is **disk** evidence → the **disk / artifact** chain, not the memory chain:

1. **Partition map** — `get_partitions` (mmls) / `parse_gpt` → confirm the GPT layout and the NTFS start sectors above.
2. **Filesystem** — `fls` (live + `deleted_only`) on the **plaintext** NTFS partitions using their mmls offsets (`extract_files` to lift hives).
3. **Registry / execution** — `get_registry`, `get_shimcache`, `get_amcache` (Win10/11 ARM → Amcache present), `get_prefetch` *(ARM Windows prefetch may be absent — tool self-skips if so)*, `srum_extract`.
4. **Event logs** — `get_evtx` (Vista+ `.evtx`; this is modern Windows, **not** XP `.evt`).
5. **IOC carving + YARA** — `run_bulk_extractor` (allowlisted `out_dir`), `scan_yara`.
6. **Timeline** — `get_timeline` (plaso) scoped by parsers/time window.

> Memory plugins (`get_pslist`/`get_netscan`/`get_malfind`/`run_volatility`) are **N/A** — there is
> no memory capture in this case, only the disk image.

---

## 2. Instantiated procedure (template steps 0 → 8, with this case's real values)

> Where you run these: a client with the `agentropix-sift` MCP bound (Claude CLI or Desktop), or the
> live server on the tailnet at `http://<TAILNET-HOST>:8765/mcp`. These are **MCP tools, not a CLI** —
> there is no `agentropix-sift case init` shell command. There is exactly **one active case** at a time
> (pointer `~/.agentropix/active_case`). Use a consistent `examiner_id` for chain-of-custody.

### Step 0 — Pre-flight (operator-local; metadata + integrity)

```bash
uv run agentropix-sift doctor          # expect: ... All tools available.
ewfverify /cases/nist3/TheTechHiveScenario/TheTechHiveScenario/Chad_LT.E01
ewfinfo   /cases/nist3/TheTechHiveScenario/TheTechHiveScenario/Chad_LT.E01
```
`ewfverify` must report **SUCCESS** with stored == calculated MD5 = `2302bb04197384bb65c5d1b34cfb6e3f`.
`ewfinfo` confirms media size **465 GiB / 500,107,862,016 bytes**, TX1 Case ID
`Arsenal-Windows_on_ARM-TechHive-Scenario`.

### Step 1 — Pick evidence & choose the slug

Evidence is under `/cases/nist3/…`. Slug = **`TECHHIVE-CHAD-LT`** (the folder name *TheTechHiveScenario*
has no spaces, but pick a short, descriptive slug; never use spaces/slashes).

### Step 2 — `case_init` (register + activate the record)

```text
case_init {
  "case_name":    "TheTechHive — Chad_LT (Windows-on-ARM laptop)",
  "examiner_id":  "victor.galvan",
  "case_id":      "TECHHIVE-CHAD-LT",
  "case_dir":     "/cases/nist3/TheTechHiveScenario/TheTechHiveScenario",
  "description":  "Full disk image of Chad_LT, an ARM-based Windows laptop (TheTechHive scenario). Primary OS partition BitLocker-encrypted; recovery key in-folder.",
  "incident_type": "dfir",
  "severity":     "medium",
  "tags":         ["techhive","windows-on-arm","bitlocker","disk"]
}
```
Writes the active-case pointer first, then upserts into `agentropix-cases`. **Idempotent on `case_id`.**

### Step 3 — `case_status` (confirm active)

```text
case_status {}                            # resolves the active pointer
case_status { "case_id": "TECHHIVE-CHAD-LT" }
```
Check `active: true` and `indexer_reachable: true`.

### Step 4 — `evidence_register` (SHA-256 custody anchor)

```text
evidence_register {
  "path":        "/cases/nist3/TheTechHiveScenario/TheTechHiveScenario/Chad_LT.E01",
  "description": "Chad_LT — Windows-on-ARM laptop disk image (EWF/E01, 465 GiB media); MD5 2302bb04197384bb65c5d1b34cfb6e3f",
  "examiner_id": "victor.galvan"
}
```
Returns the `evidence_id` (deterministic over case_id+path+sha256) and the evidence **SHA-256**, indexed
under `agentropix-evidence-YYYY.MM.DD`. Then confirm metadata in-band:

```text
get_image_info  { "image": "/cases/nist3/TheTechHiveScenario/TheTechHiveScenario/Chad_LT.E01" }
```

### Step 5 — Analyze (disk chain; **plaintext partitions only** until BitLocker is unlocked)

```text
get_partitions { "image": ".../Chad_LT.E01" }       # confirm GPT; NTFS at 497,313,792 & 500,045,824
fls            { "image": ".../Chad_LT.E01", "offset": 500045824, "recursive": true }
fls            { "image": ".../Chad_LT.E01", "offset": 500045824, "recursive": true, "deleted_only": true }
extract_files  { "image": ".../Chad_LT.E01", "offset": 500045824, "paths": [<hive paths>], "dest": "/tmp/agentropix-sift-techhive-hives" }
get_registry   { ... }   # RegRipper on lifted hives
get_shimcache  { ... }   # AppCompatCache execution evidence
get_amcache    { ... }   # modern Windows → present
get_evtx       { ... }   # Vista+ .evtx (NOT XP .evt)
run_bulk_extractor { "target": ".../Chad_LT.E01", "out_dir": "/tmp/agentropix-sift-techhive-be", "max_features": 1000 }
scan_yara      { "target": ".../Chad_LT.E01", "rules": ["/cases/yara-rules/local/pf_smoketest.yar"], "max_matches": 200 }
```

> ⚠️ **B2 (offset):** `fls`/`extract_files` on a physical-disk E01 must carry the mmls/`get_partitions`
> **sector offset** (`497313792` or `500045824` here) or they fail with *Cannot determine file system type*.
> ⚠️ **B3 (allowlist):** `out_dir`/`dest` must sit under `/tmp/agentropix-sift-*`, `/cases/`, `/mnt/`,
> `/media/`, or `/evidence/`.
> ⚠️ **BitLocker:** to add Partition 7 (the OS), unlock it out-of-band first, then `evidence_register`
> the decrypted volume and run the same chain against it.

### Step 6 — `record_finding` (DRAFT-gated)

```text
record_finding {
  "finding": { "finding_id": "TECHHIVE-ACQ-001", "title": "Chad_LT image verified & registered; OS volume BitLocker-encrypted", "severity": "medium" },
  "dry_run": true
}
```
**`dry_run:true` is the default → previews, writes nothing.** To persist, call `dry_run:false` **and** a
valid `mutation_token`. Persisted findings land as **DRAFT** (they cannot self-approve). `finding_id` is
mandatory (B4). Timeline events: `record_timeline_event {event, hostname}`.

### Step 7 — Approve (examiner-only HMAC gate)

Approval is the human-attested, HMAC challenge-response sign-off (DRAFT → APPROVED) via the Examiner
Portal / `approve_finding`. **Deliberately never auto-done** — this is a Hard-Stop.

### Step 8 — `report_generate` (+ optional IOC push)

```text
report_generate { "profile": "full", "case_id": "TECHHIVE-CHAD-LT" }
```
Then verify the seal (`verify_seal.py`); optionally curate IOCs and push to Wazuh
(`wazuh_index_findings` dry-run → live with an `egt_` token).

---

## 3. "Activate & start" prompt sequences

Both lanes hit the **same 72-tool deterministic MCP engine** and reach the same sealed result — only
*who drives the tool chain* differs. Run top-to-bottom; check each **Expect:** before continuing.

### 3A — MANUAL prompt sequence (💬 end-user; 🖥️ command equivalent shown per step)

1. 💬 *"Check that my Agentropix forensic environment is ready — are all the forensic tools installed?"*
   🖥️ `uv run agentropix-sift doctor`
   **Expect:** each backing binary reported `OK <path>` / `MISSING`, ending `All tools available.`

2. 💬 *"Verify the integrity of the Chad_LT E01 image — does its stored hash match?"*
   🖥️ `ewfverify /cases/nist3/TheTechHiveScenario/TheTechHiveScenario/Chad_LT.E01`
   **Expect:** `SUCCESS`, stored MD5 == calculated MD5 == `2302bb04197384bb65c5d1b34cfb6e3f`.

3. 💬 *"Show me the acquisition details of the Chad_LT image — who acquired it, when, and what OS."*
   🖥️ `ewfinfo /cases/nist3/TheTechHiveScenario/TheTechHiveScenario/Chad_LT.E01`
   **Expect:** Case ID `Arsenal-Windows_on_ARM-TechHive-Scenario`, examiner `Arsenal`, imager TX1 21.3.0, media **465 GiB**, ARM Windows laptop.

4. 💬 *"How many Agentropix forensic tools are available right now?"*
   🖥️ MCP call `health`
   **Expect:** live `tool_count` (canonical **72**; trust the live number, not the banner).

5. 💬 *"Open a new medium-severity case for the TheTechHive Chad_LT disk image (Windows-on-ARM laptop), case id TECHHIVE-CHAD-LT, examiner victor.galvan, and make it the active case."*
   🖥️ MCP `case_init {…}` then `case_activate { "case_id":"TECHHIVE-CHAD-LT" }`
   **Expect:** `case_id` `TECHHIVE-CHAD-LT`, status `active`, active-case pointer written.

6. 💬 *"Confirm this case is active and the indexer is reachable."*
   🖥️ MCP `case_status {}`
   **Expect:** `active: true`, `indexer_reachable: true`.

7. 💬 *"Register the Chad_LT E01 image as evidence in this case and give me its SHA-256 custody hash."*
   🖥️ MCP `evidence_register { "path":".../Chad_LT.E01", … }`
   **Expect:** `evidence_id` + evidence SHA-256 returned; indexed under `agentropix-evidence-YYYY.MM.DD`.

8. 💬 *"What does Agentropix report about this image's media size and MD5?"*
   🖥️ MCP `get_image_info { "image":".../Chad_LT.E01" }`
   **Expect:** media_size **465 GiB (500,107,862,016 bytes)**, MD5 `2302bb04197384bb65c5d1b34cfb6e3f`.

9. 💬 *"What's the partition layout of the Chad_LT image, and which partitions are BitLocker-encrypted?"*
   🖥️ MCP `get_partitions { "image":".../Chad_LT.E01" }`
   **Expect:** GPT with the BitLocker OS volume at sector **1,357,824** and plaintext NTFS at **497,313,792** and **500,045,824**.

10. 💬 *"List the files on the readable data partition (start sector 500045824), then show me just the deleted files."*
    🖥️ MCP `fls { "image":".../Chad_LT.E01", "offset":500045824, "recursive":true }` then with `"deleted_only":true`
    **Expect:** non-zero live `entry_count` on the plaintext partition, then the deleted-only set. (The BitLocker OS volume returns nothing until unlocked out-of-band.)

11. 💬 *"Record a medium-severity finding noting the image is verified and registered and that the OS partition is BitLocker-encrypted, finding id TECHHIVE-ACQ-001."*
    🖥️ MCP `record_finding { "finding":{ "finding_id":"TECHHIVE-ACQ-001", … }, "dry_run":true }`
    **Expect:** valid finding previewed; on persist (`dry_run:false` + `mutation_token`) it lands as **DRAFT** (`indexed:false`) — the assistant cannot self-approve.

12. 💬 *"Which findings are waiting for my approval and what are their IDs?"*
    🖥️ Examiner Portal / MCP `idx_search` over findings
    **Expect:** the DRAFT findings + IDs (e.g. `TECHHIVE-ACQ-001`); you sign off **yourself** in the browser portal — no plain-language approval shortcut, by design.

### 3B — AUTONOMOUS prompt sequence (launch → monitor → approve → report)

1. 💬 *"You are a DFIR analyst with the Agentropix MCP. Investigate case `TECHHIVE-CHAD-LT` on image `/cases/nist3/TheTechHiveScenario/TheTechHiveScenario/Chad_LT.E01`. Run the full disk SIFT sequence (acquisition → examination → analysis → findings) on the plaintext NTFS partitions, staging findings as DRAFT. Use mmls-derived offsets for `fls` (the readable NTFS partitions start at sectors 497313792 and 500045824). Note that the primary OS partition is BitLocker-encrypted and cannot be read without out-of-band unlock. Write `bulk_extractor` `out_dir` under `/tmp/agentropix-sift-techhive`. Do NOT approve findings. Finish by generating the full report."*
   🖥️ Detached driver (token from ENV, `<case_key>` positional):
   ```bash
   AGENTROPIX_MCP_AUTH_TOKEN="<BEARER_TOKEN>" \
     setsid nohup bash -c "python3 /home/admin2/.openclaw/workspace/drivers/agx_gearb.py techhive-chad-lt > run.log 2>&1" </dev/null >/dev/null 2>&1 &
   disown
   ```
   **Expect:** the agent walks `case_init`→`case_activate`→`evidence_register`→`get_image_info`→`get_partitions`→`fls` live+deleted (offset)→`extract_files`/`get_registry`/`get_shimcache`/`get_evtx`→`run_bulk_extractor`→`record_finding`×N as **DRAFT**→`report_generate{profile:"full"}`, stopping before approval.

2. 💬 *"How's the investigation going — which steps are done?"*
   🖥️ `tail -f run.log` and read `/home/admin2/.openclaw/workspace/drivers/gearB/<case>/SUMMARY.json`
   **Expect:** per-step `ok`/`elapsed`/`error` checkpoints accumulating; findings staged `indexed:false` (DRAFT) and any `full` report shows `approved_finding_count 0` (the approval gate working as designed).

3. 💬 *"Which findings are waiting for my approval and what are their IDs?"*
   🖥️ Examiner Portal (HMAC sign-off) / MCP `idx_search`
   **Expect:** the staged DRAFT findings + IDs; you approve **yourself** in the browser portal — the assistant will not and cannot approve on your behalf.

4. 💬 *"Generate the full report for this case."*
   🖥️ MCP `report_generate { "profile":"full", "case_id":"TECHHIVE-CHAD-LT" }`
   **Expect:** `report_id` + section counts; once findings are approved, `approved_finding_count` and the report sections populate. (A DRAFT-only case can return `case_not_found` until there is indexed state.)

5. 💬 *"Verify the seal on this report — confirm it hasn't been tampered with since it was generated."*
   🖥️ `uv run python scripts/verify_seal.py <report>.json`
   **Expect:** the seal verifier confirms the report + audit log are intact and unaltered since sealing (HMAC-SHA256, `evidence_image_sha256`-bound).

---

## Operator gotchas for THIS case (quick reference)

| Symptom | Cause | Fix |
|---|---|---|
| `fls`/`extract_files` → *Cannot determine file system type* | physical-disk E01, ran at offset 0 (B2) | pass the partition sector offset (`497313792` or `500045824`) |
| The OS volume reads as empty / unrecognized | **Partition 7 is BitLocker-encrypted; no MCP decryption wrapper exists** | unlock out-of-band (recovery key in-folder, Identifier `48637073-…`), then `evidence_register` the decrypted volume |
| `run_bulk_extractor` → *Thymus REJECT: path not found* | `out_dir` not allowlisted (B3) | write under `/tmp/agentropix-sift-techhive-*` etc. |
| `record_finding` → *must contain non-empty finding_id* | missing id (B4) | give every finding a `finding_id` |
| Driver dies mid-run | reaped at shell boundary (B5) | launch detached (`setsid`+`nohup`+`disown`); resumes from `SUMMARY.json` |
