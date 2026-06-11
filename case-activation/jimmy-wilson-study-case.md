# Case Activation Guide — Jimmy Wilson Forensic Image Study Case

> **LOCAL-ONLY · DO NOT PUBLISH.** This file lives under `case-activation/` (gitignored) because it
> carries the real on-disk evidence inventory and absolute paths. The MCP endpoint is shown only as the
> tailnet-hostname placeholder; no token, no raw IP.
>
> **Scope of this guide:** get an operator **READY to activate the case and start analysis** — the
> activation runbook, not the answers. The 25-question exam (`forensics-exam.md`) is the *ground-truth
> question set* that defines what analysis will eventually need to answer; it is referenced here only to
> justify the recommended tool chain. Run **no forensic tool** until you reach Phase 4.
>
> Procedure source-of-truth: `/home/admin2/agentropix-sift/docs/tools/END-USER-CASE-GUIDE.md` (8 steps).
> House style + dual-audience (🖥️ command / 💬 prompt) + numbered-prompt playbook mirror
> `/home/admin2/docu_agentro/docs/01-overview/user-guide.md`. Canonical numbers: `.crew/facts.md`
> (**72 MCP tools**, 16 SIFT wrappers, 4464 tests).

---

## 1. Identification header

| Field | Value |
|---|---|
| **Case name** | Jimmy Wilson Forensic Image Study Case |
| **One-line description** | A 2017 FTK-Imager acquisition (`2020JimmyWilson.E01`) of an 850 MiB Windows disk used as a 25-question forensics exam — GPT-partitioned physical disk containing a nested `System.vhd` virtual hard drive, with email (`.eml`), registry, prefetch, browser-history, and encryption-program artifacts to recover. |
| **Evidence type** | **Disk** (physical-disk EWF/E01 image, with a nested VHD inside) |
| **Image file(s)** | `/cases/study case/2020JimmyWilson.E01` |
| **Image format** | EWF / Expert Witness (EnCase) container, **acquired by FTK Imager** (`ewfinfo` → File format: FTK Imager) |
| **On-disk size** | **296 MiB** EWF container (`du` → 296M; `ls` → 309,818,835 bytes, no-compression deflate) |
| **Logical media size** | **850 MiB = 891,289,600 bytes** (1,740,800 sectors × 512 bytes/sector; fixed disk, physical) |
| **Stored MD5** | `b267fb0cd94645425eee00258d3a9b58` |
| **Stored SHA-1** | `a1102c70a50768b588225fdcad6efa5d5d57341b` *(this is also the answer to exam Q25 — the physical-disk SHA-1)* |
| **Acquisition metadata** | Case number `1`, Description `Jimmy Wilson`, Examiner `CEDONLEY`, Evidence number `2`, Notes `2018 Recertification`, Acquisition/System date `Thu Dec 14 11:52:41 2017`, OS used `Win 201x`, Software `ADI3.4.2.6` |
| **OS / scenario** | Windows (NT-family, "Win 201x"). GPT-partitioned physical disk (exam Q9). Insider/identity-theft training scenario: user **Jimmy Wilson** with received emails, a logon Run-key program, browser searches ("how to steal identities"), encryption tooling, and a nested `System.vhd` whose `J. Wilson` partition is itself examined. |
| **Suggested `case_id` slug** | **`STUDY-CASE-JWILSON`** *(matches `^[A-Za-z0-9._-]{1,128}$` — the source folder `study case` has a space and MUST be slugged; no spaces, no slashes)* |
| **Supporting files (not the image)** | `Case Study_Forensic image Test.pdf` (144 KiB, the case brief) · `forensics-exam.md` (Q1–25 ground-truth question set) — register these as evidence too if you want them in the custody chain, but the image is the analysis target. |

### Recommended path + tool chain for this evidence

This is a **disk image**, so it follows the **disk path**, not the memory (Volatility) path:

```
mmls (partition table — confirm GPT, find offsets)
  └─> fls (offset from mmls; live + deleted_only)            file system / MFT, $recyclebin
  └─> extract_files (offset; lift hives + the nested System.vhd to an allowlisted dest)
        ├─> get_registry / get_shimcache / get_prefetch       users/RID, logon, Run-key, uptime, last-run
        └─> [nested System.vhd] re-run mmls/fls on the VHD     'J. Wilson' partition capacity, cluster size
  └─> run_bulk_extractor (allowlisted out_dir)                emails (.eml), IPs, URLs, domains
  └─> scan_yara (optional; smoke-test ruleset only)
```

> **Why this chain (steered by the ground-truth exam, not run here):** GPT layout & 2nd-partition GUID
> → `mmls`/`parse_gpt`/`get_partitions`; `J. Wilson` partition capacity + cluster size inside
> `System.vhd` → `extract_files` the VHD then `mmls`/`fls` it; `.eml` timezone/send-time/dest-IP →
> `run_bulk_extractor` + mail wrappers; RID `0x3EB`, logon times, password hint, logon Run-program →
> `get_registry`; system uptime + Windows-Mail last-run → `get_prefetch`; "how to steal identities"
> search → browser-history artifacts; Veracrypt/BCTextEncoder → installed-program/registry evidence;
> file hashes (`pdf.pdf`, `PLEAS.txt`, `AISB08.pdf`, `Card Printers.htm`) → `fls`/`icat` + hashing.
> **Volatility/`get_pslist`/`get_netscan`/`get_malfind` are NOT used** — there is no memory image in this
> case.

---

## 2. Instantiated procedure (template steps 0 → 8, real values)

The same eight steps as `END-USER-CASE-GUIDE.md`, filled in with this case's real specifics. These are
**MCP tool calls** (Claude Desktop / Claude CLI with the `agentropix-sift` MCP bound, or the live server
on the tailnet at `http://<TAILNET-HOST>:8765/mcp`) — there is no `agentropix-sift case init` shell
command.

### Step 0 — Before you start (pre-flight, operator shell)

These are **metadata / integrity** checks only — safe to run before analysis.

```bash
uv run agentropix-sift doctor                      # 16 SIFT wrappers' binaries → expect "All tools available."
bash /home/admin2/.openclaw/workspace/scripts/start-agentropix-mcp.sh status   # expect health HTTP 200
ewfverify "/cases/study case/2020JimmyWilson.E01"  # chain-of-custody: stored MD5 == calculated MD5
ewfinfo   "/cases/study case/2020JimmyWilson.E01"  # acquisition metadata (Description "Jimmy Wilson")
```
**Expect:** `ewfverify` → `SUCCESS`, calculated MD5 == stored **`b267fb0cd94645425eee00258d3a9b58`**;
`ewfinfo` → media size **850 MiB / 891,289,600 bytes**, examiner `CEDONLEY`, SHA-1
`a1102c70a50768b588225fdcad6efa5d5d57341b`.

### Step 1 — Pick the evidence + choose a slug

Evidence is at `/cases/study case/2020JimmyWilson.E01`. The folder name `study case` has a space, which
is **rejected** for a `case_id` (`^[A-Za-z0-9._-]{1,128}$`). Use slug **`STUDY-CASE-JWILSON`**.

### Step 2 — `case_init` (register + activate)

```text
case_init {
  "case_name":   "Jimmy Wilson Forensic Image Study Case",
  "examiner_id": "victor.galvan",
  "case_id":     "STUDY-CASE-JWILSON",
  "case_dir":    "/cases/study case",
  "description": "2017 FTK-Imager E01 (2020JimmyWilson.E01), 850 MiB GPT disk w/ nested System.vhd; 25-Q exam study case",
  "incident_type": "training/study-case",
  "severity":    "medium",
  "scope":       "/cases/study case/2020JimmyWilson.E01",
  "tags":        ["study-case","jimmy-wilson","disk","gpt","vhd"]
}
```
Writes the active-case pointer first, then upserts the record. Idempotent on `case_id` — re-running the
same slug updates, never duplicates. (Do **not** pass `payload` — it's wrapper-only, not exposed over MCP.)

### Step 3 — `case_status` (confirm active)

```text
case_status {}                                  # resolves the active pointer
case_status { "case_id":"STUDY-CASE-JWILSON" }  # or check this case explicitly
```
**Expect:** `active: true` and `indexer_reachable: true`.

### Step 4 — `evidence_register` (SHA-256 chain-of-custody)

```text
evidence_register {
  "path":        "/cases/study case/2020JimmyWilson.E01",
  "description": "Windows GPT physical disk, EWF/E01 (FTK Imager), Jimmy Wilson study case",
  "examiner_id": "victor.galvan"
}
```
Hashes the file (sha256 + size) under `agentropix-evidence-YYYY.MM.DD`. `evidence_id` is deterministic
over (case_id, path, sha256); idempotent and audited. Then confirm image metadata in-band:

```text
get_image_info { "image":"/cases/study case/2020JimmyWilson.E01" }
```
**Expect:** media_size **850 MiB (891,289,600 bytes)**, MD5 `b267fb0cd94645425eee00258d3a9b58`,
bytes/sector 512, sectors 1,740,800, OS `Win 201x`.

> *(Optional)* register the brief + question set into the custody chain too:
> `evidence_register { "path":"/cases/study case/Case Study_Forensic image Test.pdf", ... }` and
> `… forensics-exam.md`.

### Step 5 — Analyze (disk path; this is the first forensic-tool step)

```text
get_partitions { "image":"/cases/study case/2020JimmyWilson.E01" }     # confirm GPT, list partition offsets
# (operator-shell equivalent:  mmls "/cases/study case/2020JimmyWilson.E01" )

fls { "image":"/cases/study case/2020JimmyWilson.E01", "offset":<sectors-from-mmls>, "recursive":true }
fls { "image":"…", "offset":<sectors>, "recursive":true, "deleted_only":true }   # $recyclebin

extract_files {                                                          # lift hives + nested VHD
  "image":"/cases/study case/2020JimmyWilson.E01", "offset":<sectors>,
  "paths":["<SYSTEM/SOFTWARE/SAM hive paths>","<…/System.vhd>"],
  "dest":"/tmp/agentropix-sift-jwilson-hives"
}
get_registry  { … }    # users/RID 0x3EB, Jimmy Wilson logon time, password hint, logon Run-key program
get_shimcache { … }    # execution evidence
get_prefetch  { … }    # system uptime, Windows Mail last-run  (XP-compatible; this OS has prefetch)

# nested VHD: after extract_files lifts System.vhd, treat it as a second disk image —
get_partitions { "image":"/tmp/agentropix-sift-jwilson-hives/System.vhd" }   # 'J. Wilson' partition
fls            { "image":"…/System.vhd", "offset":<vhd-offset> }             # capacity, cluster size

run_bulk_extractor {                                                     # .eml, IPs, URLs, domains
  "target":"/cases/study case/2020JimmyWilson.E01",
  "out_dir":"/tmp/agentropix-sift-jwilson-be", "max_features":1000
}
scan_yara { "target":"…E01", "rules":["/cases/yara-rules/local/pf_smoketest.yar"], "max_matches":200 }  # optional
```

> ⚠️ **GOTCHA B2 (offset):** `fls`/`extract_files` on a physical disk **must** get the `offset` (sectors)
> from `mmls`/`get_partitions`, or they fail with `Cannot determine file system type`. This disk is GPT
> (exam Q9), so read the partition start sectors from `mmls` first.
> ⚠️ **GOTCHA B3 (allowlist):** `out_dir`/`dest` must be under `/tmp/agentropix-sift-*`, `/cases/`,
> `/mnt/`, `/media/`, or `/evidence/`, else Thymus rejects with `path not found`.
> 🔎 **YARA:** `match_count 0` with `raw_stdout_sha256 e3b0c442…` (empty-string hash) is the *success*
> signature of a clean smoke-test, not a failure (only `pf_smoketest.yar` is installed).

### Step 6 — `record_finding` (DRAFT-gated)

```text
record_finding {
  "finding": { "finding_id":"JW-001", "title":"…", "severity":"medium",
               "mitre":["T1588.002"], "artifacts":["<source>"] },
  "dry_run": true            # DEFAULT: previews, writes NOTHING
}
# to persist: dry_run=false + a valid mutation_token  → lands as DRAFT (cannot self-approve)
```
**Expect (dry_run):** a preview, `indexed:false`. **GOTCHA B4:** every finding needs a non-empty
`finding_id` or it's rejected. Timeline: `record_timeline_event { event, hostname, case_id }`.

### Step 7 — Approve (examiner gate — HARD STOP)

Human-attested **HMAC challenge-response** in the Examiner Portal (`approve_finding`): DRAFT → APPROVED.
This is the cryptographic chain-of-custody sign-off and is **deliberately NOT automated** — a bot must
not sign. Portal: `https://siftworkstation.taile7c9ca.ts.net:8443/`.

### Step 8 — Report (+ optional IOC push)

```text
report_generate { "profile":"full", "case_id":"STUDY-CASE-JWILSON" }   # SIFT report
```
`approved_finding_count` stays `0` until Step 7 approvals land (DRAFT findings aren't surfaced — working
as designed). A brand-new DRAFT-only case can return `case_not_found` until there's indexed state.
Optional Wazuh push (`wazuh_index_findings`, dry-run then live with an `egt_` token) is opt-in/guarded —
this training image has modest live-threat value, so it's usually skipped.

---

## 3. Activate & start — prompt sequences

Both lanes hit the **same deterministic MCP engine** (72 tools). Pick one. Each operator action shows
the 🖥️ command equivalent and an **Expect:** line.

### 3A — MANUAL (numbered 💬 prompts to activate + begin)

Type these into a Claude session that has the `agentropix-sift` MCP connected, top-to-bottom; check
**Expect:** before the next.

1. 💬 *"Check that my Agentropix forensic environment is ready — are all the forensic tools installed?"*
   🖥️ `uv run agentropix-sift doctor`
   **Expect:** each backing binary `OK <path>`, ending `All tools available.`

2. 💬 *"Verify the integrity of the Jimmy Wilson E01 image at `/cases/study case/2020JimmyWilson.E01` — does its stored hash match?"*
   🖥️ `ewfverify "/cases/study case/2020JimmyWilson.E01"`
   **Expect:** `SUCCESS`; calculated MD5 == stored `b267fb0cd94645425eee00258d3a9b58`.

3. 💬 *"Show me the acquisition details of the Jimmy Wilson image — examiner, date, OS, and size."*
   🖥️ `ewfinfo "/cases/study case/2020JimmyWilson.E01"`
   **Expect:** examiner `CEDONLEY`, acquired `Thu Dec 14 11:52:41 2017`, OS `Win 201x`, media **850 MiB / 891,289,600 bytes**.

4. 💬 *"How many Agentropix forensic tools are available right now?"*
   🖥️ MCP `health`
   **Expect:** `status: ok` with a live `tool_count` (canonical **72**; trust the live number, not the banner).

5. 💬 *"Open a new medium-severity study case `STUDY-CASE-JWILSON` for the Jimmy Wilson disk image at `/cases/study case/2020JimmyWilson.E01`, examiner victor.galvan, and make it the active case."*
   🖥️ MCP `case_init {…case_id:"STUDY-CASE-JWILSON"…}` → then `case_activate { case_id:"STUDY-CASE-JWILSON" }`
   **Expect:** returns `case_id STUDY-CASE-JWILSON`, status `active`, active-case pointer written.

6. 💬 *"Confirm the active case and that the indexer is reachable."*
   🖥️ MCP `case_status {}`
   **Expect:** `active: true`, `indexer_reachable: true`.

7. 💬 *"Register the Jimmy Wilson E01 image as evidence in this case and give me its SHA-256 custody hash."*
   🖥️ MCP `evidence_register { path:"/cases/study case/2020JimmyWilson.E01", examiner_id:"victor.galvan" }`
   **Expect:** an `evidence_id` + evidence SHA-256, bound to the active case (`indexed:true`).

8. 💬 *"What does Agentropix report about this image's media size and MD5?"*
   🖥️ MCP `get_image_info { image:"/cases/study case/2020JimmyWilson.E01" }`
   **Expect:** media_size **850 MiB (891,289,600 bytes)**, MD5 `b267fb0cd94645425eee00258d3a9b58`, sectors 1,740,800.

9. 💬 *"What's the partition layout of this disk, and is it GPT? Where does each partition start?"*
   🖥️ MCP `get_partitions { image:"…E01" }`  (shell: `mmls "/cases/study case/2020JimmyWilson.E01"`)
   **Expect:** GPT schema, partition start sectors reported (carried forward as `fls`/`extract_files` `offset`). *This is the first analysis step.*

10. 💬 *"List the files on this image using that offset, then show me just the deleted files (look for the recycle bin)."*
    🖥️ MCP `fls { image:"…E01", offset:<sectors>, recursive:true }` then `… deleted_only:true`
    **Expect:** a non-zero live `entry_count`, plus a deleted set including `$recyclebin` entries — you are now into live analysis.

### 3B — AUTONOMOUS (launch driver → monitor → approve → report)

The driver runs the full disk sequence unattended, stages findings as **DRAFT**, and **stops at the
approval gate**. Use **Claude CLI** (not Desktop — the heavy tools exceed Desktop's 1 MB cap).

1. 💬 *"You are a DFIR analyst with the Agentropix MCP. Investigate case `STUDY-CASE-JWILSON` on image `/cases/study case/2020JimmyWilson.E01`. Run the full SIFT disk sequence (acquisition → examination → analysis → findings), staging findings as DRAFT. Confirm the disk is GPT and use mmls-derived offsets for `fls`/`extract_files`. Also extract the nested `System.vhd` and examine its `J. Wilson` partition. Write `bulk_extractor` `out_dir` under `/tmp/agentropix-sift-jwilson`. Do NOT approve findings. Finish by generating the full report."*
   🖥️ Detached headless driver (token from ENV, case key positional — never the token):
   ```bash
   AGENTROPIX_MCP_AUTH_TOKEN="<BEARER_TOKEN>" \
     setsid nohup bash -c "python3 /home/admin2/.openclaw/workspace/drivers/agx_gearb.py study-case > run.log 2>&1" </dev/null >/dev/null 2>&1 &
   disown
   ```
   *(Smoke-test first: append `--preflight` after the case key — session+health+schema+`get_image_info`, no case record. The driver resolves a logical `<case_key>` via its `cases.json`; confirm `study case` is mapped before launch.)*
   **Expect:** the agent walks `case_init`→`case_activate`→`evidence_register`→`get_image_info`→`get_partitions/mmls`→`fls` live+deleted→`extract_files`(hives + System.vhd)→`get_registry`/`get_shimcache`/`get_prefetch`→`run_bulk_extractor`→`record_finding` × N as DRAFT→`report_generate{profile:"full"}`, stopping before approval. (No Volatility steps — disk image.)

2. 💬 *"How's the investigation going — which steps are done?"*
   🖥️ `tail -f run.log` and read `/home/admin2/.openclaw/workspace/drivers/gearB/<case>/SUMMARY.json` (per-step `ok`/`elapsed`/`error`)
   **Expect:** steps reported OK incrementally; `SUMMARY.json` checkpoints each step (survives a kill — GOTCHA B5: the driver is detached, so a long `run_bulk_extractor` call isn't reaped).

3. 💬 *"Which findings are waiting for my approval and what are their IDs?"*
   🖥️ Examiner Portal `https://siftworkstation.taile7c9ca.ts.net:8443/`
   **Expect:** the staged DRAFT findings + IDs listed; you sign off **yourself** in the browser portal (HMAC, append-only) — the assistant cannot approve on your behalf (HARD STOP).

4. 💬 *"Generate the full report for case `STUDY-CASE-JWILSON`."*
   🖥️ MCP `report_generate { profile:"full", case_id:"STUDY-CASE-JWILSON" }`
   **Expect:** a `report_id` + section counts; `approved_finding_count` populates only after Step 3 approvals (DRAFT-only → may return `case_not_found` until indexed state exists).

5. 💬 *"Verify the seal on this report — confirm it hasn't been tampered with since it was generated."*
   🖥️ `uv run python scripts/verify_seal.py <report>.json`
   **Expect:** the seal verifier confirms the report + audit log are intact (HMAC-SHA256, `evidence_image_sha256`-bound to MD5 `b267fb0cd94645425eee00258d3a9b58`).

---

## Gotchas specific to this case

| Gotcha | Rule |
|---|---|
| Folder `study case` has a space | `case_id` rejects spaces/slashes — use the slug `STUDY-CASE-JWILSON`. Quote the path everywhere (`"/cases/study case/…"`). |
| GPT, not MBR | Exam Q9 confirms GPT — use `parse_gpt`/`get_partitions`; pass mmls offsets to `fls` (B2). |
| Nested `System.vhd` | The `J. Wilson` partition lives **inside** a VHD on the disk. `extract_files` it to an allowlisted dest, then run `mmls`/`fls` on the VHD as a second image. |
| No memory image | Disk-only case — do **not** invoke Volatility tools (`get_pslist`/`get_netscan`/`get_malfind`). |
| `forensics-exam.md` is ground truth | It is the *question set*, not evidence to draw conclusions from. Prove every answer against live tool output. |
