# Case Activation Guide — DFRWS 2005 Forensics Rodeo (RHINOUSB)

> **LOCAL / INTERNAL ONLY** — real case inventory and on-disk paths. This directory
> (`/home/admin2/docu_agentro/case-activation/`) is gitignored; never publish it.
> **Goal of this guide:** get an operator *ready to activate the case and start analysis*.
> Profiling below was **metadata-only** (`ls` / `file` / `du` / `mmls` exit-code / PDF page
> count) — **no forensic tool was run against the evidence content.**

---

## 1. Identification header

| Field | Value |
|---|---|
| **Case name** | DFRWS 2005 Forensics Rodeo — RHINOUSB thumb drive |
| **One-line description** | DFRWS 2005 Rodeo challenge: a seized FAT16 USB thumb-drive image (`RHINOUSB.dd`) plus scenario network captures and the published answer key. |
| **Evidence type** | **disk** (raw `dd` filesystem image) |
| **Primary image** | `/cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd` |
| **Image format** | **raw `dd`** — bare **FAT16** filesystem (`mkdosfs` OEM-ID), DOS/MBR boot sector, 8 sectors/cluster, 512 root entries, 506848 sectors, FAT 16-bit, blank volume label. **No partition table** (single-volume image). |
| **Image size** | **248 MB** (`259,506,176` bytes); folder total **252 MB**. |
| **Suggested `case_id` slug** | **`DFRWS-2005-RODEO-USB`** (matches `^[A-Za-z0-9._-]{1,128}$`; no spaces/slashes) |
| **`case_dir`** | `/cases/nist5/DFRWS2005-RODEO` |
| **OS / scenario** | No host OS — this is a **removable FAT16 USB volume** from the DFRWS 2005 Forensics Rodeo. The ground-truth answer key is the 34-page PDF `/cases/nist5/DFRWS2005-answers.pdf`. |
| **Companion (out-of-scope for the SIFT disk chain)** | `rhino.log` (3.1M), `rhino2.log` (288K), `rhino3.log` (224K) — **these are pcap network captures** (`file` → `pcap capture file … version 2.4 (Ethernet)`), *not* text logs. They are scenario network traffic, not a disk/memory image; the Agentropix SIFT disk tool chain does **not** parse pcap. Register them as evidence for chain-of-custody if needed, but analyze them with a separate pcap workflow (out of scope here). |

### Recommended path + tool chain (disk → FAT16, partitionless)

This is a **disk** image, so the path is the disk/filesystem chain (NOT the memory/Volatility
path). The one load-bearing per-case specific: **`RHINOUSB.dd` has no partition table**, so
`fls` runs at **offset 0** — *do not* pass a sector offset, and *expect* `get_partitions`/`mmls`
to error (that's the documented single-volume signal, not a failure).

```text
case_init → case_activate → evidence_register → get_image_info
   → get_partitions   (EXPECT: "no partition table" → single-volume FAT16 → use fls offset 0)
   → fls offset=0 recursive            (live files)
   → fls offset=0 recursive deleted_only   (FAT16 → strong deleted-file recovery surface)
   → run_bulk_extractor (allowlisted out_dir)   (emails / URLs / domains / IPs)
   → scan_yara (optional; smoke-test ruleset only)
   → record_finding (DRAFT) → approve (human portal) → report_generate
```

> **Why offset 0 here (vs. CFReDS sector-63):** verified metadata-only — `file` reports a
> `DOS/MBR boot sector … FAT (16 bit)` with `mkdosfs` OEM-ID, and `mmls RHINOUSB.dd` exits **1**
> with no rows. The `get_partitions` tool docstring states it "Raises an actionable error when
> there is no partition table (single-volume image → try `fls` offset 0)." So the whole image
> *is* one FAT16 partition starting at byte 0. (Contrast the CFReDS NTFS image where `fls`
> needs `offset 63`; that GOTCHA B2 does **not** apply here.)
>
> **No memory/Volatility tools** (`get_pslist`/`get_netscan`/`get_malfind`/…): there is no
> memory image in this case.

> Platform facts (cite `.crew/facts.md`): **72** MCP tools, **16** forensic SIFT wrappers,
> **4687** tests. Trust the live `health.tool_count`, not any startup banner.

---

## 2. Instantiated procedure (template steps 0 → 8, filled with this case)

These are **MCP tool calls** (not a shell CLI) — run them from a Claude client with the
`agentropix-sift` MCP server connected, or via the live server on the tailnet at
`http://<TAILNET-HOST>:8765/mcp`. There is exactly **one active case** at a time.

### Step 0 — Pre-flight (operator-local)
```bash
uv run agentropix-sift doctor                 # EXPECT: every backing binary OK; "All tools available."
```
Image integrity: this is a **raw `dd`** image, so there is **no embedded EWF hash** to verify
with `ewfverify` (that's E01-only). Custody hashing happens at Step 4 (`evidence_register`
computes SHA-256). A separate `md5sum`/`sha256sum` against a known-good value can be run by the
operator if a canonical hash exists for the Rodeo image.

### Step 1 — Pick evidence + choose the slug
- Evidence: `/cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd`
- `case_id` slug: **`DFRWS-2005-RODEO-USB`**

### Step 2 — `case_init` (register + activate the record)
```python
case_init(
  case_name     = "DFRWS 2005 Forensics Rodeo — RHINOUSB thumb drive",
  examiner_id   = "victor.galvan",
  case_id       = "DFRWS-2005-RODEO-USB",
  case_dir      = "/cases/nist5/DFRWS2005-RODEO",
  description   = "DFRWS 2005 Rodeo: FAT16 USB image RHINOUSB.dd (+ rhino*.log pcaps; answers PDF ground truth)",
  incident_type = "dfir", severity = "medium", scope = "/cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd",
  tags          = ["dfrws-2005", "rodeo", "fat16", "usb"]
)
```
EXPECT: `case_id "DFRWS-2005-RODEO-USB"`, status `active`. Idempotent on the slug.

### Step 3 — `case_status` (confirm it's active)
```python
case_status()                         # EXPECT: active:true, indexer_reachable:true
case_status(case_id="DFRWS-2005-RODEO-USB")
```

### Step 4 — `evidence_register` (SHA-256 chain of custody)
```python
evidence_register(
  path        = "/cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd",
  description = "FAT16 USB thumb-drive raw dd image (mkdosfs), 248 MB",
  examiner_id = "victor.galvan"
)
```
EXPECT: an `evidence_id`, an evidence **SHA-256**, `size_bytes 259506176`, bound to the active case.

Optionally register the pcaps for custody (analysis is out-of-scope for the SIFT disk chain):
```python
evidence_register(path="/cases/nist5/DFRWS2005-RODEO/rhino.log",  description="DFRWS Rodeo network capture (pcap)", examiner_id="victor.galvan")
evidence_register(path="/cases/nist5/DFRWS2005-RODEO/rhino2.log", description="DFRWS Rodeo network capture (pcap)", examiner_id="victor.galvan")
evidence_register(path="/cases/nist5/DFRWS2005-RODEO/rhino3.log", description="DFRWS Rodeo network capture (pcap)", examiner_id="victor.galvan")
```

Confirm image metadata in-band:
```python
get_image_info(image="/cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd")
```
EXPECT: a raw-image media size; no EWF acquisition fields (it's a bare `dd`, not E01).

### Step 5 — Analyze (disk/FAT16 chain)
```python
get_partitions(image="/cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd")
# EXPECT: actionable "no partition table" error → single-volume FAT16 → use fls offset 0.

fls(image="/cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd", offset=0, recursive=True)
# EXPECT: live entry_count > 0 (no offset needed — FS starts at byte 0).

fls(image="/cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd", offset=0, recursive=True, deleted_only=True)
# EXPECT: the deleted set (FAT16 retains directory entries → recoverable deleted files; T1070.004).

run_bulk_extractor(
  target="/cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd",
  out_dir="/tmp/agentropix-sift-dfrws-rodeo-be",     # allowlisted prefix (GOTCHA B3)
  max_features=1000
)
# EXPECT: feature counts (emails / urls / domains / ips). out_dir returned, not inline.

scan_yara(
  target="/cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd",
  rules=["/cases/yara-rules/local/pf_smoketest.yar"],
  max_matches=200
)
# EXPECT: match_count 0 (clean smoke-test = success; only pf_smoketest.yar is installed).
```
> No memory tools and no E01 hive-extraction step (`extract_files`/`get_registry`/`get_evtx`)
> — this FAT16 USB volume has no Windows hives or OS artifacts; the value is **files (live +
> deleted) and carved features.**

### Step 6 — `record_finding` (DRAFT-gated)
```python
record_finding(
  finding = {
    "finding_id": "dfrws-rodeo-001",
    "host": "rhino-usb",
    "mitre_attack": "T1052.001",          # exfiltration over removable media (adjust to the actual finding)
    "confidence": 0.6,
    "timestamp": "2005-01-01T00:00:00Z",  # set to the artifact's real time
    "severity": "medium",
    "title": "…",
    "source_artifact": "/tmp/agentropix-sift-dfrws-rodeo-be/url.txt"
  },
  dry_run = True        # DEFAULT preview; to persist: dry_run=False + a valid mutation_token
)
```
EXPECT (persisted): lands as **DRAFT** (`indexed:false`). `finding_id` is required (GOTCHA B4).
`severity:high` needs `confidence ≥ 0.70`; `critical` needs `≥ 0.85`.

### Step 7 — Approve (human-only examiner gate)
HMAC challenge-response in the browser portal — **the LLM cannot self-approve** (Hard-Stop).
Portal: **`https://siftworkstation.taile7c9ca.ts.net:8443/`** (or on the box `http://127.0.0.1:8800/`).
Examiner ID = `AGENTROPIX_APPROVER_USER`; Case ID `DFRWS-2005-RODEO-USB`; Target = the DRAFT
finding ID; From `DRAFT` → To `APPROVED`; Sign & Submit.

### Step 8 — `report_generate`
```python
report_generate(profile="full", case_id="DFRWS-2005-RODEO-USB")
```
EXPECT: a `report_id`; `approved_finding_count` stays `0` until Step 7. (A brand-new DRAFT-only
case can return `case_not_found` until there is indexed state — register evidence and/or approve
one finding, then re-generate.) Optional Phase 8: curate IOCs → `wazuh_index_findings`
(dry-run, then live with an `egt_` mutation token).

---

## 3. Activate & start — prompt sequences

Two ways to drive. Each operator action shows the **💬 end-user prompt** and the **🖥️ command
equivalent**, with an **Expect:** line. Both hit the same deterministic MCP engine.

### 3A — MANUAL path (you/the assistant drive each tool; inspect before the next)

1. 💬 *"Check that my Agentropix forensic environment is ready — are all the forensic tools installed?"*
   🖥️ `uv run agentropix-sift doctor`
   **Expect:** each backing binary reported `OK <path>`, ending `All tools available.`

2. 💬 *"How many Agentropix forensic tools are available right now?"*
   🖥️ call `health`
   **Expect:** `status: "ok"` with a live `tool_count` (canonical **72**; trust the live number).

3. 💬 *"Open a new medium-severity DFIR case for the DFRWS 2005 Rodeo USB image at /cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd, slug DFRWS-2005-RODEO-USB, examiner victor.galvan, and make it the active case."*
   🖥️ `case_init {…slug "DFRWS-2005-RODEO-USB"…}` then `case_activate {case_id:"DFRWS-2005-RODEO-USB"}`
   **Expect:** `case_id DFRWS-2005-RODEO-USB`, status `active`, active-case pointer written.

4. 💬 *"Confirm this case is active and the indexer is reachable."*
   🖥️ `case_status()`
   **Expect:** `active: true`, `indexer_reachable: true`.

5. 💬 *"Register RHINOUSB.dd as evidence in this case and give me its SHA-256 custody hash."*
   🖥️ `evidence_register {path:"/cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd", …}`
   **Expect:** an `evidence_id`, evidence **SHA-256**, `size_bytes 259506176`, bound to the active case.

6. 💬 *"What does Agentropix report about this image — its media size and type?"*
   🖥️ `get_image_info {image:"…/RHINOUSB.dd"}`
   **Expect:** a raw-image media size; no EWF acquisition metadata (it's a bare `dd`).

7. 💬 *"What's the partition layout of this USB image, and where does the filesystem start?"*
   🖥️ `get_partitions {image:"…/RHINOUSB.dd"}` (or `mmls …/RHINOUSB.dd`)
   **Expect:** an actionable "no partition table" result → single-volume **FAT16** → `fls` uses **offset 0** (this is the expected signal, not an error to fix).

8. 💬 *"List all the files on the USB image, then show me just the deleted files."*
   🖥️ `fls {image:"…/RHINOUSB.dd", offset:0, recursive:true}` then the same with `deleted_only:true`
   **Expect:** a non-zero live `entry_count`, then the deleted set (FAT16 retains deleted directory entries).

9. 💬 *"Carve out all the indicators — emails, URLs, domains, IPs — from the USB image."*
   🖥️ `run_bulk_extractor {target:"…/RHINOUSB.dd", out_dir:"/tmp/agentropix-sift-dfrws-rodeo-be", max_features:1000}`
   **Expect:** per-type feature counts; results returned as the `out_dir` path (allowlisted prefix; GOTCHA B3).

10. 💬 *"Run a YARA scan over the USB image and tell me if anything matched."*
    🖥️ `scan_yara {target:"…/RHINOUSB.dd", rules:["/cases/yara-rules/local/pf_smoketest.yar"], max_matches:200}`
    **Expect:** `match_count 0` with the empty-string `raw_stdout_sha256` — the clean-scan success signature.

11. 💬 *"Record a medium-severity finding for [the artifact you identified], with a MITRE technique and the source artifact path."*
    🖥️ `record_finding {finding:{finding_id:"dfrws-rodeo-001", host:"rhino-usb", mitre_attack:"…", confidence:0.6, timestamp:"…", severity:"medium", title:"…", source_artifact:"…"}, dry_run:false, mutation_token:"…"}`
    **Expect:** lands as **DRAFT** (`indexed:false`); `finding_id` required (B4); the assistant cannot self-approve.

12. 💬 *"Which findings are waiting for my approval and what are their IDs?"*
    🖥️ list DRAFT findings; approve in the **browser portal** (no prompt shortcut, by design)
    **Expect:** the DRAFT finding IDs (e.g. `dfrws-rodeo-001`); you sign off yourself in the portal.

13. 💬 *"Generate the full report for this case."*
    🖥️ `report_generate {profile:"full", case_id:"DFRWS-2005-RODEO-USB"}`
    **Expect:** a `report_id`; `approved_finding_count 0` until a finding is approved (DRAFT-only case may return `case_not_found` until there is indexed state).

### 3B — AUTONOMOUS path (launch driver → monitor → approve → report)

1. 💬 (launch — paste to a CLI client with the MCP attached)
   *"You are a DFIR analyst with the Agentropix MCP. Investigate case `DFRWS-2005-RODEO-USB` on image `/cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd`. Run the full SIFT disk sequence (acquisition → examination → analysis → findings), staging findings as DRAFT. This is a single-volume FAT16 image with NO partition table — use `fls` offset 0 (do not pass a sector offset). Write `bulk_extractor` `out_dir` under `/tmp/agentropix-sift-dfrws-rodeo`. Do NOT approve findings. Finish by generating the full report."*
   🖥️ detached headless driver (token from ENV, **logical case key** positional — not a path/token):
   ```bash
   AGENTROPIX_MCP_AUTH_TOKEN="<BEARER_TOKEN>" \
     setsid nohup bash -c "python3 /home/admin2/.openclaw/workspace/drivers/agx_gearb.py <case_key> --image /cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd --offset 0 > run.log 2>&1" </dev/null >/dev/null 2>&1 &
   disown
   ```
   **Expect:** the agent runs `case_init→case_activate→evidence_register→get_image_info→fls (offset 0) live+deleted→run_bulk_extractor→record_finding × N (DRAFT)→report_generate{full}`, staging all findings DRAFT and **stopping before approval**. (Smoke-test the driver first with `--preflight` appended after the case key.)

2. 💬 *"How's the investigation going — which steps are done?"*
   🖥️ `tail -f run.log` and read `…/drivers/gearB/<case>/SUMMARY.json` (per-step ok/elapsed/error)
   **Expect:** incremental per-step progress; final `record_finding` `indexed:false` (DRAFT), `full` report `approved_finding_count 0` (approval gate working as designed).

3. 💬 *"Which findings are waiting for my approval and what are their IDs?"*
   🖥️ list DRAFT findings; approve in the **portal** `https://siftworkstation.taile7c9ca.ts.net:8443/`
   **Expect:** the staged DRAFT IDs; you sign off via HMAC in the browser (append-only; the assistant cannot approve for you).

4. 💬 *"Generate the full report for this case."*
   🖥️ `report_generate {profile:"full", case_id:"DFRWS-2005-RODEO-USB"}`
   **Expect:** a `report_id` and section counts; once findings are approved, `approved_finding_count` and the sections populate.

5. 💬 *"Verify the seal on this report — confirm it hasn't been tampered with since it was generated."*
   🖥️ `uv run python scripts/verify_seal.py <report>.json`
   **Expect:** the seal verifier confirms the report and audit log are intact (HMAC-SHA256, `evidence_image_sha256`-bound).

---

> **GOTCHA recap for this case:** B2 (the CFReDS "pass `offset 63`" rule) does **NOT** apply —
> `RHINOUSB.dd` is partitionless FAT16, so `fls` uses **offset 0**, and `get_partitions`/`mmls`
> legitimately report "no partition table." B3 (`out_dir` must be under an allowlisted prefix)
> and B4 (`finding_id` required) still apply. The `rhino*.log` files are **pcaps**, not disk
> evidence — analyze them with a separate network workflow.
