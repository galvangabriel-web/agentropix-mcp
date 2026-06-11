# Case Activation Guide — SRL-2015 (Stark Research Labs APT, enterprise multi-host)

> **LOCAL ONLY — investigative pre-decisional.** This file lives under
> `case-activation/` (gitignored) and contains the **real on-disk inventory** for
> `/cases/SRL-2015/`. Do not publish it. The MCP endpoint is shown as the tailnet
> hostname placeholder only.
> **Goal of this guide:** get an operator *ready to activate this case and start
> analysis* — it walks the template
> `END-USER-CASE-GUIDE.md`
> (steps 0→8), instantiated with this case's real values. It does **not** run any
> forensic tool on the evidence; profiling below is metadata-only
> (`file`/`ewfinfo`/`du`).

---

## 1. Identification header

| Field | Value |
|---|---|
| **Case name** | SRL-2015 — Stark Research Labs Data Breach Intrusion (SANS FOR508 APT scenario) |
| **One-line description** | Enterprise APT intrusion across **4 Windows hosts** — each with a C-drive E01 **and** a raw memory capture; goal is cross-host correlation of the attacker's foothold → lateral movement → controller. |
| **Evidence type** | **mixed** (disk **+** memory, multi-host) |
| **Folder** | `/cases/SRL-2015/` (total **56 GB** on disk) |
| **Suggested `case_id` slug** | **`SRL-2015-APT-ENTERPRISE`** (matches `^[A-Za-z0-9._-]{1,128}$`) |
| **Examiner ID** | `victor.galvan` (chain-of-custody stamp; use consistently) |
| **Case number (from images)** | `Stark Research Labs Data Breach Intrusion` (every E01's `ewfinfo` Case number) · Examiner name in images: `SANS` |

### Evidence inventory (metadata-only, re-confirmed 2026-06-06)

**Disk images — 4× EWF/EnCase E01, all NTFS logical drives** (`file` → "EWF/Expert
Witness/EnCase image file format"; `ewfinfo` Operating system used = `Win 201x`):

| Host (role) | Image path | Media size (`ewfinfo`) | On-disk (`du`) | Stored MD5 | Host IP (image Notes) |
|---|---|---|---|---|---|
| **xp-tdungan** (Windows XP SP3, x86) | `/cases/SRL-2015/xp-tdungan-c-drive/xp-tdungan-c-drive.E01` | 15 GiB (16114483712 B), 31473601 × 512 | 6.6G | `60b778a12a4b7ad5ed5b28eb6e869b3f` | 10.3.58.7 |
| **win7-32-nromanoff** (Win7 32-bit SP1) | `/cases/SRL-2015/win7-32-nromanoff-c-drive/win7-32-nromanoff-c-drive.E01` | 24 GiB (26578255872 B), 51910656 × 512 | 9.1G | `e381e006d8b42042a3253c7e2f07ffb8` | 10.3.58.5 |
| **win7-64-nfury** (Win7 64-bit) | `/cases/SRL-2015/win7-64-nfury-c-drive/win7-64-nfury-c-drive.E01` | 28 GiB (30232543232 B), 59047936 × 512 | 12G | `a98416e60bb81f57cb99125ec41bfe4c` | 10.3.58.6 |
| **win2008R2-controller** (Win Server 2008 R2 x64) | `/cases/SRL-2015/win2008R2-controller-c-drive/win2008R2-controller-c-drive.E01` | 31 GiB (33317453824 B), 65073152 × 512 | 14G | `3a33c416f0853f2c148a173f90363104` | 10.3.58.4 |

**Memory images — 4× raw `.001`** (`file` → `data`; FTK Imager raw dumps):

| Host | Image path | Size (`du`) |
|---|---|---|
| xp-tdungan | `/cases/SRL-2015/xp-tdungan-memory/xp-tdungan-memory-raw.001` | 2.0G |
| win7-32-nromanoff | `/cases/SRL-2015/win7-32-nromanoff-memory/win7-32-nromanoff-memory-raw.001` | 2.0G |
| win7-64-nfury | `/cases/SRL-2015/win7-64-nfury-memory/win7-64-nfury-memory-raw.001` | 2.0G |
| win2008R2-controller | `/cases/SRL-2015/win2008R2-controller-memory/win2008R2-controller-memory-raw.001` | 2.5G |

**Reference / non-evidence artifacts (do NOT register as new evidence):**

- **`.mans` files** — Mandiant Redline collections, confirmed `SQLite 3.x database`
  by `file`: `xp-tdungan-memory/xp_tdungan.mans` (90M),
  `win7-64-nfury-memory/win7-nfury-memory.mans` (104M),
  `win2008R2-controller-memory/win2008DC-Memory.mans` (434M). These are *agent
  collections*, useful for cross-check, not raw memory.
- **`baseline-memory/` subdirs** — clean-baseline images for diffing, e.g.
  `xp-tdungan-memory/baseline-memory/XPSP3x86-baseline.img` (2.0G). Reference only.
- **`precooked/` subdirs** (under the c-drive folders) — SANS reference output:
  `volatility/`, `timeline/`, `shimcache/`, `redline/`, `bulk-extractor/`,
  `mbr/`, `hashes/`, `PEid-Signatues/`, plus `volume-shadow.zip`. **Reference
  answers, NOT new evidence — never register these.**
- **`*.txt` sidecars** — FTK Imager acquisition logs (the ground-truth metadata
  the table above is drawn from).

### OS / scenario

SANS FOR508 **Stark Research Labs (SRL-2015)** APT intrusion. Four enterprise
Windows hosts on the `10.3.58.0/24` subnet — an XP workstation (tdungan), two Win7
workstations (nromanoff x86, nfury x64), and a Win2008R2 domain **controller**.
The investigative arc is a classic intrusion chain: initial foothold on a
workstation → credential theft → lateral movement → reaching the controller. The
mixed disk+memory shape per host is exactly what the platform's cross-host
correlation tools (`correlate_timeline`, `pivot_on_ioc`) are built for.

### Recommended path + tool chain for THIS evidence

This is a **mixed, multi-host** case, so you run **both** chains, per host, then
correlate across hosts:

- **Disk (each `*-c-drive.E01`):** `get_partitions`/`mmls` (offset) →
  `fls` live + deleted (offset from mmls) → `run_bulk_extractor`
  (allowlisted `out_dir`) → `scan_yara` → `extract_files` (hives) →
  `get_registry` / `get_shimcache` / `get_prefetch` / `get_evtx`.
  **OS-aware:** XP (tdungan) has **prefetch but no Amcache and uses `.evt`**
  (`get_evt`, not `get_evtx`); the Win7/2008R2 hosts have **Amcache** (`get_amcache`)
  and `.evtx` (`get_evtx`).
- **Memory (each `*-memory-raw.001`):** `get_pslist` → `get_netscan` →
  `get_malfind` → `get_svcscan` → `build_process_tree` (PPID forest, LOLBin flags).
- **Cross-host (the payoff for a 4-host case):** `correlate_timeline` over the
  per-host images into one UTC stream, then `pivot_on_ioc` on any C2 indicator
  (e.g. an attacker IP/hash) to see which of the four hosts it touched.

Platform facts (cite [`.crew/facts.md`](../docs/08-reference/canonical-facts.md)):
**72** MCP tools, **16** SIFT forensic wrappers, **4464** tests. Trust the live
`health.tool_count`, not any banner.

---

## 2. Instantiated procedure (template steps 0 → 8, this case's real values)

> ⚠️ One active case at a time — `case_init` registers **and** activates (writes
> `~/.agentropix/active_case`). For a multi-host case you register **all 8 images**
> against the single case, then run the per-image tools (each tool takes an explicit
> `image=`, so the active pointer only scopes *which case* the records land in).

### Step 0 — Pre-flight (operator-local, no evidence touched)

```bash
uv run agentropix-sift doctor                                   # expect: All tools available.
bash /home/admin2/.openclaw/workspace/scripts/start-agentropix-mcp.sh start
bash /home/admin2/.openclaw/workspace/scripts/start-agentropix-mcp.sh status   # expect health: HTTP 200
# Integrity (chain of custody) — verify each E01's stored MD5 matches:
ewfverify /cases/SRL-2015/xp-tdungan-c-drive/xp-tdungan-c-drive.E01
ewfverify /cases/SRL-2015/win7-32-nromanoff-c-drive/win7-32-nromanoff-c-drive.E01
ewfverify /cases/SRL-2015/win7-64-nfury-c-drive/win7-64-nfury-c-drive.E01
ewfverify /cases/SRL-2015/win2008R2-controller-c-drive/win2008R2-controller-c-drive.E01
```

Connect the client (one-time), then call `health` and trust the live `tool_count`:

```bash
claude mcp add --transport http agentropix-sift \
  "http://siftworkstation.taile7c9ca.ts.net:8765/mcp" \
  --header "Authorization: Bearer <TOKEN>"
claude mcp list        # expect: agentropix-sift ... ✓ Connected ; then call health -> tool_count
```

### Step 1 — Pick evidence + choose slug

Evidence is already under `/cases/SRL-2015/`. Slug: **`SRL-2015-APT-ENTERPRISE`**.

### Step 2 — `case_init` (register + activate)

```text
case_init {
  "case_name":   "SRL-2015 Stark Research Labs APT (enterprise multi-host)",
  "examiner_id": "victor.galvan",
  "case_id":     "SRL-2015-APT-ENTERPRISE",
  "case_dir":    "/cases/SRL-2015",
  "description": "SANS FOR508 SRL APT — 4 Windows hosts (XP tdungan, Win7x32 nromanoff, Win7x64 nfury, Win2008R2 controller), each C-drive E01 + raw memory",
  "incident_type": "intrusion/apt",
  "severity":    "high",
  "scope":       "/cases/SRL-2015",
  "tags":        ["srl-2015","for508","apt","multi-host"]
}
```

### Step 3 — `case_status` (confirm active)

```text
case_status()                                # active pointer -> status + per-index counts
case_status { "case_id":"SRL-2015-APT-ENTERPRISE" }
```
Check `active: true` and `indexer_reachable: true`.

### Step 4 — `evidence_register` (chain-of-custody hash, ALL 8 images)

Register each disk and each memory image (the **3 `.mans`** and the `baseline-memory`
/ `precooked` references are **NOT** registered). `path` is the real image path;
`case_id=None` uses the active case.

```text
# --- 4 disk E01s ---
evidence_register { "path":"/cases/SRL-2015/xp-tdungan-c-drive/xp-tdungan-c-drive.E01",                       "description":"xp-tdungan Win XP SP3 C-drive (E01/NTFS) 10.3.58.7",       "examiner_id":"victor.galvan" }
evidence_register { "path":"/cases/SRL-2015/win7-32-nromanoff-c-drive/win7-32-nromanoff-c-drive.E01",         "description":"win7-32-nromanoff Win7 x86 C-drive (E01/NTFS) 10.3.58.5",  "examiner_id":"victor.galvan" }
evidence_register { "path":"/cases/SRL-2015/win7-64-nfury-c-drive/win7-64-nfury-c-drive.E01",                 "description":"win7-64-nfury Win7 x64 C-drive (E01/NTFS) 10.3.58.6",      "examiner_id":"victor.galvan" }
evidence_register { "path":"/cases/SRL-2015/win2008R2-controller-c-drive/win2008R2-controller-c-drive.E01",   "description":"win2008R2 controller C-drive (E01/NTFS) 10.3.58.4",        "examiner_id":"victor.galvan" }
# --- 4 raw memory .001 ---
evidence_register { "path":"/cases/SRL-2015/xp-tdungan-memory/xp-tdungan-memory-raw.001",                     "description":"xp-tdungan raw memory",         "examiner_id":"victor.galvan" }
evidence_register { "path":"/cases/SRL-2015/win7-32-nromanoff-memory/win7-32-nromanoff-memory-raw.001",       "description":"win7-32-nromanoff raw memory",  "examiner_id":"victor.galvan" }
evidence_register { "path":"/cases/SRL-2015/win7-64-nfury-memory/win7-64-nfury-memory-raw.001",               "description":"win7-64-nfury raw memory",      "examiner_id":"victor.galvan" }
evidence_register { "path":"/cases/SRL-2015/win2008R2-controller-memory/win2008R2-controller-memory-raw.001", "description":"win2008R2 controller raw memory","examiner_id":"victor.galvan" }
```
Each hashes the file (sha256 + size) into `agentropix-evidence-YYYY.MM.DD`. Idempotent.

### Step 5 — Analyze (disk-or-memory tools, per host)

**Disk (example: xp-tdungan — XP, so `get_evt`, prefetch, NO amcache):**

```text
get_partitions { "image":"/cases/SRL-2015/xp-tdungan-c-drive/xp-tdungan-c-drive.E01" }   # mmls -> NTFS offset
fls { "image":".../xp-tdungan-c-drive.E01", "offset":<from mmls>, "recursive":true }                      # live
fls { "image":".../xp-tdungan-c-drive.E01", "offset":<from mmls>, "recursive":true, "deleted_only":true } # T1070.004
run_bulk_extractor { "target":".../xp-tdungan-c-drive.E01", "out_dir":"/tmp/agentropix-sift-srl2015-xp-be", "max_features":1000 }
extract_files { "image":".../xp-tdungan-c-drive.E01", "offset":<offset>, "paths":["<hive paths>"], "dest":"/tmp/agentropix-sift-srl2015-xp-hives" }
get_registry  { ... }    # RegRipper
get_shimcache { ... }    # AppCompatCache execution evidence
get_prefetch  { ... }    # XP has prefetch
get_evt       { ... }    # XP uses .evt (NOT get_evtx)
```

**Disk (Win7/2008R2 hosts):** same chain, but `get_amcache` (Win7+) **and**
`get_evtx` (`.evtx`) instead of `get_evt`.

**Memory (each `*-memory-raw.001`):**

```text
get_pslist         { "image":"/cases/SRL-2015/xp-tdungan-memory/xp-tdungan-memory-raw.001" }   # processes
get_netscan        { "image":"...-memory-raw.001" }   # sockets
get_malfind        { "image":"...-memory-raw.001" }   # injected / RWX code
get_svcscan        { "image":"...-memory-raw.001" }   # services
build_process_tree { "image":"...-memory-raw.001" }   # PPID forest, LOLBin flags
```

**Cross-host correlation (the 4-host payoff):**

```text
correlate_timeline { "images":[
  "/cases/SRL-2015/xp-tdungan-c-drive/xp-tdungan-c-drive.E01",
  "/cases/SRL-2015/win7-32-nromanoff-c-drive/win7-32-nromanoff-c-drive.E01",
  "/cases/SRL-2015/win7-64-nfury-c-drive/win7-64-nfury-c-drive.E01",
  "/cases/SRL-2015/win2008R2-controller-c-drive/win2008R2-controller-c-drive.E01" ] }
pivot_on_ioc { "ioc":"<attacker IP / hash>", "images":[ ...the 8 images... ] }
```

> ⚠️ **GOTCHAs (from the validated run):** **B2** — `fls` needs the mmls-derived
> `offset` or it fails `Cannot determine file system type`. **B3** — `out_dir` must
> be under an allowlisted prefix (`/tmp/agentropix-sift-*`, `/cases/`, `/mnt/`,
> `/media/`, `/evidence/`). Memory `.001` images need no offset.

### Step 6 — `record_finding` (DRAFT-gated)

```text
record_finding { "finding": {
  "finding_id":   "srl2015-controller-lateral-001",
  "host":         "win2008R2-controller",
  "mitre_attack": "T1021.002",
  "confidence":   0.6,
  "timestamp":    "2012-04-09T00:00:00Z",
  "severity":     "medium",
  "title":        "Lateral movement to domain controller (SMB admin share)",
  "ioc_value":    "<value>", "ioc_type":"<type>",
  "source_artifact":"/tmp/agentropix-sift-srl2015-...." } }
```
- **`dry_run=True` is the default → previews, writes nothing.** Persist with
  `dry_run=False` **and** a valid `mutation_token`. Findings land **DRAFT**.
- Required: `finding_id`, `host`, `mitre_attack`, `confidence` (0–1), `timestamp`.
  Coherence: `severity:high` needs `confidence ≥ 0.70`; `critical` needs `≥ 0.85`.
- Timeline events: `record_timeline_event { event, hostname, case_id=None }`.

### Step 7 — Approve (examiner gate — HUMAN ONLY, hard stop)

DRAFT → APPROVED only via the HMAC challenge-response Examiner Portal. The LLM/driver
**cannot** self-approve.

- Portal: **`https://siftworkstation.taile7c9ca.ts.net:8443/`** (workstation-local:
  `http://127.0.0.1:8800/`).
- Fill Examiner ID (= `AGENTROPIX_APPROVER_USER`), Case ID `SRL-2015-APT-ENTERPRISE`,
  the DRAFT finding ID, From=`DRAFT` To=`APPROVED`, enter password, Sign & Submit.
- In-band equivalent (still human-attested):
  `approve_finding { "finding_id":"srl2015-controller-lateral-001", "approver_id":"victor.galvan", "password":"<examiner pw>" }`

### Step 8 — Report (& optional Wazuh push)

```text
report_generate { "profile":"full", "case_id":"SRL-2015-APT-ENTERPRISE" }
```
Profiles: `full` / `executive` / `timeline` / `ioc` / `findings` / `status`. A DRAFT-only
case can return `case_not_found` until there is indexed state (register evidence /
approve ≥1 finding first) — expected gating, not a failure. Optional: curate IOCs →
mint an `egt_` token → `wazuh_index_findings` (dry-run then live).

---

## 3. Activate & start — prompt sequences

Both lanes drive the **same deterministic 72-tool MCP engine** and reach the same
sealed result; only *who drives the chain* differs.

### A) MANUAL sequence (💬 prompt + 🖥️ command equivalent)

Run top-to-bottom; check each **Expect:** before the next.

1. **Pre-flight the environment.**
   💬 *"Check that my Agentropix forensic environment is ready — are all the forensic tools installed, and is the MCP server healthy?"*
   🖥️ `uv run agentropix-sift doctor` ; then call `health`
   **Expect:** `All tools available.` and `health` → `status:"ok"` with a live `tool_count` (canonical **72**; trust the live number).

2. **Verify image integrity (all 4 disks).**
   💬 *"Verify the integrity of the four SRL-2015 disk images — do their stored MD5 hashes match?"*
   🖥️ `ewfverify /cases/SRL-2015/xp-tdungan-c-drive/xp-tdungan-c-drive.E01` (repeat for the other three)
   **Expect:** each `ewfverify` → `SUCCESS`, stored MD5 == calculated (xp `60b778a1…`, win7-32 `e381e006…`, win7-64 `a98416e6…`, controller `3a33c416…`).

3. **Open and activate the case.**
   💬 *"Open a new high-severity APT case `SRL-2015-APT-ENTERPRISE` for the Stark Research Labs multi-host intrusion under /cases/SRL-2015, examiner victor.galvan, and make it the active case."*
   🖥️ `case_init {…case_id:"SRL-2015-APT-ENTERPRISE"…}` then `case_activate {case_id:"SRL-2015-APT-ENTERPRISE"}`
   **Expect:** `case_id SRL-2015-APT-ENTERPRISE`, status `active`, pointer written to `~/.agentropix/active_case`.

4. **Confirm it's active.**
   💬 *"Is SRL-2015-APT-ENTERPRISE the active case, and is the indexer reachable?"*
   🖥️ `case_status()`
   **Expect:** `active: true` and `indexer_reachable: true`.

5. **Register all 8 evidence images.**
   💬 *"Register all eight SRL-2015 images as evidence in this case — the four C-drive E01s and the four raw memory captures — and give me their SHA-256 custody hashes. Do not register the .mans, baseline-memory, or precooked files."*
   🖥️ the 8 `evidence_register` calls in §2 Step 4
   **Expect:** 8 `evidence_register` results, each with an `evidence_id`, a SHA-256, `size_bytes`, bound to the active case (indexed → `agentropix-evidence-YYYY.MM.DD`).

6. **Examine a host's disk (start with the controller).**
   💬 *"On the win2008R2 controller disk image, show the partition layout, then list the files and the deleted files."*
   🖥️ `get_partitions {image:".../win2008R2-controller-c-drive.E01"}` → `fls {…offset:<from mmls>, recursive:true}` live + `deleted_only:true`
   **Expect:** the NTFS partition offset, then a non-zero live `entry_count` and a deleted-file set (the assistant carries the mmls offset forward — GOTCHA B2).

7. **Carve IOCs from a disk.**
   💬 *"Carve the indicators — emails, domains, IPs, URLs — from the win2008R2 controller disk."*
   🖥️ `run_bulk_extractor {target:".../win2008R2-controller-c-drive.E01", out_dir:"/tmp/agentropix-sift-srl2015-ctrl-be", max_features:1000}`
   **Expect:** a feature breakdown (domains/emails/urls/ips…) written to the allowlisted `out_dir` (GOTCHA B3); counts vary run-to-run.

8. **Analyze a host's memory.**
   💬 *"Analyse the win2008R2 controller memory image: what processes were running, what network connections were open, and is there any injected code?"*
   🖥️ `get_pslist` / `get_netscan` / `get_malfind` / `get_svcscan` / `build_process_tree` on `.../win2008R2-controller-memory-raw.001`
   **Expect:** a process list, open sockets, any injected/RWX regions, services, and a PPID tree with LOLBin flags.

9. **Pull disk registry / execution / event-log artifacts (OS-aware).**
   💬 *"Pull the registry hives off the XP tdungan disk and tell me what programs ran, what auto-runs, and what the event logs show."*
   🖥️ `extract_files` (hives → allowlisted dest) → `get_registry` / `get_shimcache` / `get_prefetch` / `get_evt`
   **Expect:** execution + persistence artifacts; the assistant uses `get_evt` (XP `.evt`) and **skips Amcache** on XP, switching to `get_evtx` + `get_amcache` on the Win7/2008R2 hosts.

10. **Correlate across all four hosts and pivot.**
    💬 *"Correlate the timelines across all four SRL-2015 hosts into one UTC stream, then pivot on the attacker indicator to see which machines it touched."*
    🖥️ `correlate_timeline {images:[…4 disks…]}` then `pivot_on_ioc {ioc:"<value>", images:[…]}`
    **Expect:** a merged cross-host timeline and the set of hosts where the indicator appears.

11. **Record a finding (DRAFT).**
    💬 *"Record a medium-severity finding for the lateral movement to the domain controller, mapped to MITRE T1021.002, citing the artifact."*
    🖥️ `record_finding {finding:{finding_id:"srl2015-controller-lateral-001", host:"win2008R2-controller", mitre_attack:"T1021.002", confidence:0.6, timestamp:"2012-04-09T00:00:00Z", severity:"medium", …}}`
    **Expect:** a valid finding staged as **DRAFT** (`indexed:false`); the assistant cannot self-approve (GOTCHA B4 — `finding_id` required).

12. **List findings awaiting approval, then approve in the portal.**
    💬 *"Which findings are waiting for my approval and what are their IDs?"*
    🖥️ approve yourself at `https://siftworkstation.taile7c9ca.ts.net:8443/` (or `approve_finding {finding_id, approver_id:"victor.galvan", password:"<pw>"}`)
    **Expect:** the DRAFT finding IDs are listed; promotion to APPROVED is a **human-only** HMAC sign-off (hard stop — the assistant will not do it).

13. **Generate the report.**
    💬 *"Generate the full report for SRL-2015-APT-ENTERPRISE."*
    🖥️ `report_generate {profile:"full", case_id:"SRL-2015-APT-ENTERPRISE"}`
    **Expect:** a `report_id` and section counts; `approved_finding_count` stays `0` until a finding is approved (a DRAFT-only case may return `case_not_found` until indexed state exists).

14. **Verify the seal.**
    💬 *"Verify the seal on this report — confirm it hasn't been tampered with since it was generated."*
    🖥️ `uv run python scripts/verify_seal.py <report json>`
    **Expect:** the seal verifier confirms the report + audit log are intact (HMAC-SHA256, `evidence_image_sha256`-bound).

### B) AUTONOMOUS sequence (launch → monitor → approve → report)

The driver runs the full per-host SIFT sequence, stages findings DRAFT, and **stops
at the approval gate** — a bot must not sign chain-of-custody. Use Claude CLI
(Desktop is human-in-the-loop / 1 MB cap).

1. **Launch the detached headless driver (B-Expert).**
   🖥️ token from ENV, **case key positional** (`SRL-2015`), launched detached:
   ```bash
   AGENTROPIX_MCP_AUTH_TOKEN="<TOKEN>" \
     setsid nohup bash -c "python3 /home/admin2/.openclaw/workspace/drivers/agx_gearb.py SRL-2015 > run.log 2>&1" </dev/null >/dev/null 2>&1 &
   disown
   ```
   💬 (non-expert equivalent — interactive autonomous prompt) *"You are a DFIR analyst with the Agentropix MCP. Investigate case `SRL-2015-APT-ENTERPRISE` across all four hosts under /cases/SRL-2015 (each C-drive E01 + raw memory). Run the full SIFT sequence (acquisition → examination → analysis → findings), staging findings as DRAFT. Use mmls-derived offsets for `fls` on the disks; use `get_evt` on XP and `get_evtx`/`get_amcache` on the Win7/2008R2 hosts. Write bulk_extractor out_dir under /tmp/agentropix-sift-srl2015. Do NOT approve findings. Finish by correlating the four hosts and generating the full report."*
   **Expect:** the run starts detached (survives the shell — GOTCHA B5); the agent/driver walks `case_init`→`case_activate`→`evidence_register` (×8)→`get_image_info` (4 disk E01s only)→per-host disk+memory tools→`record_finding` ×N (DRAFT)→`report_generate`, checkpointing `SUMMARY.json` after each step. (`get_image_info` drives `ewfinfo`/EWF metadata, so it is scoped to the 4 disk E01s only — it is NOT run on the 4 raw memory `.001` images, where it returns all-empty fields. For memory the OS/kernel profile is auto-detected on the first `windows.*` plugin (`get_pslist`), not via `get_image_info`.)

2. **Monitor progress.**
   🖥️ `tail -f run.log` ; read `/home/admin2/.openclaw/workspace/drivers/gearB/SRL-2015/SUMMARY.json` (per-step `ok`/`elapsed`/`error`)
   💬 *"How's the SRL-2015 investigation going — which steps are done?"*
   **Expect:** per-step `ok`/`elapsed`; findings land `indexed:false` (DRAFT) and any report shows `approved_finding_count 0` (approval gate working as designed).

3. **Approve in the portal (human-only).**
   🖥️ open `https://siftworkstation.taile7c9ca.ts.net:8443/` and sign off
   💬 *"Which SRL-2015 findings are waiting for my approval and what are their IDs?"*
   **Expect:** the staged DRAFT findings + IDs are listed; you approve yourself (HMAC, append-only) — the assistant will not and cannot approve on your behalf.

4. **Generate the report.**
   🖥️ `report_generate {profile:"full", case_id:"SRL-2015-APT-ENTERPRISE"}`
   💬 *"Generate the full report for SRL-2015-APT-ENTERPRISE."*
   **Expect:** `report_id` + section counts; once findings are approved, `approved_finding_count` and the report sections populate.

5. **Verify the seal.**
   🖥️ `uv run python scripts/verify_seal.py <report json>`
   💬 *"Verify the seal on this report — confirm it hasn't been tampered with since it was generated."*
   **Expect:** the verifier confirms the report and audit log are intact and unaltered since sealing.

---

> **Sources / oracle:** procedure from
> `END-USER-CASE-GUIDE.md`;
> house style + dual-audience + numbered-playbook from
> [`docs/01-overview/user-guide.md`](../docs/01-overview/user-guide.md);
> canonical numbers from [`.crew/facts.md`](../docs/08-reference/canonical-facts.md)
> (72 tools / 16 wrappers / 4464 tests). Evidence inventory re-confirmed
> metadata-only (`file` / `ewfinfo` / `du`) against `/cases/SRL-2015/` on 2026-06-06.
> The `10.3.58.x` values are **evidence-host IPs embedded in the image acquisition
> metadata** (case ground-truth), not infrastructure addresses; the MCP endpoint is
> the tailnet hostname placeholder only.
