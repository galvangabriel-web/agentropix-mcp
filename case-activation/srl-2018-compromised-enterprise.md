# Case Activation Guide — SRL-2018 Compromised Enterprise Network

> **LOCAL / OPERATIONAL — DO NOT PUBLISH.** Real case inventory and host paths.
> Lives under `/home/admin2/docu_agentro/case-activation/` (gitignored). Mirrors the portal
> house style + dual-audience (🖥️ command / 💬 prompt) of
> [`docs/01-overview/user-guide.md`](../docs/01-overview/user-guide.md). Canonical numbers cite
> [`.crew/facts.md`](../docs/08-reference/canonical-facts.md) (71 MCP tools, 16 SIFT wrappers, 4464 tests).
> Procedure template: [`agentropix-sift/docs/tools/END-USER-CASE-GUIDE.md`](/home/admin2/agentropix-sift/docs/tools/END-USER-CASE-GUIDE.md).
>
> **GOAL of this guide: get the operator READY to activate the case and start analysis.** Everything
> below up to "Activate & start" is metadata-only profiling (`ls` / `file` / `ewfinfo` / `du`); no
> forensic tool has been run against the evidence.

---

## 1. Identification header

| Field | Value |
|---|---|
| **Case name** | SRL-2018 — Stark Research Labs **Compromised Enterprise Network** (network-wide APT C2 deployment) |
| **One-line** | Multi-host enterprise intrusion: a cascading C2 backbone (DC → file → workstations → terminal servers → DMZ-FTP) deployed across a Stark Research Labs estate. |
| **Scenario / source** | SANS FOR508-style **SRL-2018** corpus. Acquisition metadata (`ewfinfo`) shows Stark Research Labs examiners (e.g. **Clint Barton**), case number `20180905-001`, "Acquired over network via F-Response", acquisition dates **Sept 2018**. The `/cases/auto/` correlation proof-run was executed against **this** corpus. |
| **Evidence type** | **mixed** — disk (E01) **and** memory (`.img`) + derived/carved artifacts |
| **Total size on disk** | **198 GiB** (`du -sh /cases/SRL-2018` → `198G`) — the **largest** case in `/cases/`. |
| **Evidence directory** | `/cases/SRL-2018/` |
| **Disk images (7 × E01)** | `base-dc-cdrive.E01`, `base-file-cdrive.E01`, `base-rd-01-cdrive.E01`, `base-rd-02-cdrive.E01`, `base-wkstn-01-c-drive.E01`, `base-wkstn-05-cdrive.E01`, `dmz-ftp-cdrive.E01` — `EWF/Expert Witness/EnCase image file format`, written by **FTK Imager** (`ewfinfo` → "File format: FTK Imager"). |
| **Memory images (22 × `.img`)** | per-host RAM dumps, each with a `dc3dd` `.md5` sidecar: `base-dc`, `base-file`, `base-mail`, `base-av`, `base-sp`, `base-hunt`, `base-elf`, `base-admin`, `base-wkstn-01..06`, `base-rd01`, `base-rd-02..06`, plus `base-wkstn-01-mem.img`. **Note:** `file` reports several `.img` as `Windows Event Trace Log` — that is the raw memory header heuristic; treat them as raw memory dumps for Volatility, not as ETL. |
| **Other** | `base-file-snapshot5.img` (`data`, 2 GiB — a file-server snapshot); `_carved/base-wkstn-01-memory/be_output/` (a prior **bulk_extractor** carve: `email.txt`, `domain.txt`, `url.txt`, `ether.txt`, `report.xml`, …); `raw/` (empty); `Common` (empty marker). |
| **Suggested `case_id` slug** | **`SRL-2018-COMPROMISED-ENTERPRISE`** (matches `^[A-Za-z0-9._-]{1,128}$`; no spaces/slashes). |
| **OS** | Windows Server / Windows client estate — `ewfinfo` "Operating system used: **Win 201x**" across the E01s. |

### DC disk — verified acquisition constants (`ewfinfo base-dc-cdrive.E01`)

| Field | Value |
|---|---|
| Case number | `20180905-001` |
| Description | `base-dc C-Drive` |
| Examiner | `Clint Barton` |
| Notes | `Acquired over network via F-Response` |
| Acquisition date | `Fri Sep 7 21:13:10 2018` |
| Media size | **33 GiB (36110860288 bytes)** · sectors `70529024` · 512 B/sector · fixed disk, physical |
| **MD5** | **`e18b450127de04afb3211faa456ada27`** |
| SHA1 | `15f1215e824a3319020cb74addcbe22d90fc6c18` |

*(Each host has its own constants — re-run `ewfinfo`/`get_image_info` per image; the DC values above are the worked example.)*

### Recommended path + tool chain for this evidence

This is a **per-host, mixed-evidence** activation. Register each host's evidence, then drive the path
that matches the image type. **Activate one host at a time** (single active-case pointer; see the
template's "Switching between cases").

- **Disk (E01) →** `get_partitions` / `parse_gpt` (find the partition offset) → `fls` (live + deleted) →
  `extract_files` (lift hives to an allowlisted dir) → `get_registry` / `get_shimcache` / `get_amcache`
  (Win7+/Server) / `get_prefetch` → `get_evtx` (Security/System; **7045 / 4697 / 4698** for service +
  scheduled-task persistence; **5140 / 5145** for SMB share sweeps) → `run_bulk_extractor` (IOC carve,
  allowlisted `out_dir`) → `scan_yara`.
- **Memory (`.img`) →** `get_pslist` → `get_netscan` → `get_malfind` → `get_svcscan` →
  `build_process_tree` (PPID forest, LOLBin / DKOM-orphan flags).
- **Cross-host (the point of this case) →** `correlate_timeline` (merge per-host events into one UTC
  stream) → `pivot_on_ioc` (hunt the **C2 IP `42.112.153.164:8080`** across images) → `detect_sweep`
  (SMB-burst lateral movement) → `threat_intel_lookup` / `wazuh_hunt_ioc` for the C2 + typosquat
  delivery domain.

> **Attack-chain hypotheses (bias-checks, NOT conclusions — prove each live).** From
> [`docs/06-use-cases/case-hypotheses.md`](../docs/06-use-cases/case-hypotheses.md) §Case 2:
> C2 backbone **`42.112.153.164:8080`** (VT/OTX MALICIOUS); deployment window
> **2018-05-03 14:22:15 → 15:15:45 UTC (~53 min)** cascading DC → file → workstations → terminal
> servers → DMZ-FTP; **`svcsvc32`-class service binary** across DC/file/rd-01/wkstn-01; typosquat
> delivery domain **`stark-research-labs.co`**. The `/cases/auto/SUMMARY.md` proof-run already
> exercised process-tree (DC: 124 procs, 22 DKOM-orphans), timeline-join (DC+file, 2576 logon events),
> IOC-pivot (`subject_srv`, hits on base-admin + base-dc), and SMB-sweep (DC E01, 14128 events).

---

## 2. Instantiated procedure (template steps 0 → 8, this case's real values)

> Where you run these: any client with the `agentropix-sift` MCP server bound — Claude Desktop, Claude
> CLI, or the live server on the tailnet at **`http://<TAILNET-HOST>:8765/mcp`** (use the tailnet
> hostname; the raw IP is not reproduced here). The tools are **MCP tools, not a CLI**. There is exactly
> **one active case** at a time (`~/.agentropix/active_case`).

**Step 0 — Pre-flight & integrity (operator shell).**

```bash
uv run agentropix-sift doctor                       # expect: All tools available.
ewfverify /cases/SRL-2018/base-dc-cdrive.E01        # expect: SUCCESS; stored MD5 == e18b450127de04afb3211faa456ada27
ewfinfo  /cases/SRL-2018/base-dc-cdrive.E01         # acquisition metadata (Clint Barton / 20180905-001 / 33 GiB)
```

**Step 1 — Pick evidence + choose the slug.** Evidence is under `/cases/SRL-2018/`. Slug:
`SRL-2018-COMPROMISED-ENTERPRISE`.

**Step 2 — `case_init` (register + activate).**

```text
case_init {
  "case_name":    "SRL-2018 Compromised Enterprise Network",
  "examiner_id":  "victor.galvan",
  "case_id":      "SRL-2018-COMPROMISED-ENTERPRISE",
  "case_dir":     "/cases/SRL-2018",
  "description":  "Stark Research Labs network-wide APT C2 deployment — multi-host disk+memory estate (DC, file, mail, av, sp, hunt, elf, admin, wkstn-01..06, rd-01..06, dmz-ftp).",
  "incident_type":"intrusion/apt-c2",
  "severity":     "high",
  "scope":        "/cases/SRL-2018",
  "tags":         ["srl-2018","apt","c2","multi-host","for508"]
}
```
Idempotent on `case_id` — re-running updates, won't duplicate.

**Step 3 — `case_status` (confirm active).**

```text
case_status {}                                      # or case_status { "case_id":"SRL-2018-COMPROMISED-ENTERPRISE" }
```
Check `active: true` and `indexer_reachable: true`.

**Step 4 — `evidence_register` (SHA-256 chain-of-custody, per host).** Register each host's evidence.

```text
# Disk (start with the DC):
evidence_register { "path":"/cases/SRL-2018/base-dc-cdrive.E01",
                    "description":"SRL-2018 domain controller C-drive (EWF/E01, FTK Imager, 33 GiB)",
                    "examiner_id":"victor.galvan" }
# Memory (same host):
evidence_register { "path":"/cases/SRL-2018/base-dc-memory.img",
                    "description":"SRL-2018 domain controller RAM dump (dc3dd raw, 5 GiB)",
                    "examiner_id":"victor.galvan" }
# …repeat per host: base-file-cdrive.E01 / base-file-memory.img, base-wkstn-01-c-drive.E01 /
#   base-wkstn-01-memory.img, base-rd-01-cdrive.E01, dmz-ftp-cdrive.E01, base-mail-memory.img, etc.
get_image_info { "image":"/cases/SRL-2018/base-dc-cdrive.E01" }   # in-band ewfinfo (MD5 e18b4501…, 33 GiB)
```

**Step 5 — Analyze (pick the path per image; resolves to the active case).**

```text
# DISK (E01) — get the offset first, then walk the filesystem + artifacts:
get_partitions { "image":"/cases/SRL-2018/base-dc-cdrive.E01" }   # → start sector (MCP tool; underlying binary is `mmls`)
fls           { "image":"/cases/SRL-2018/base-dc-cdrive.E01", "offset":<start-sector>, "recursive":true }
fls           { "image":"...E01", "offset":<start-sector>, "recursive":true, "deleted_only":true }
extract_files { "image":"...E01", "offset":<start-sector>, "paths":["<hive paths>"], "dest":"/tmp/agentropix-sift-srl2018-hives" }
get_registry  { ... }   ;  get_shimcache { ... }   ;  get_amcache { ... }   ;  get_prefetch { ... }
get_evtx      { "image":"...E01", "event_ids":[7045,4697,4698,5140,5145], "...":"..." }   # persistence + SMB sweep
run_bulk_extractor { "target":"...E01", "out_dir":"/tmp/agentropix-sift-srl2018-be", "max_features":1000 }
scan_yara     { "target":"...E01", "rules":["/cases/yara-rules/local/pf_smoketest.yar"], "max_matches":200 }

# MEMORY (.img) — Volatility-backed:
get_pslist         { "image":"/cases/SRL-2018/base-dc-memory.img" }
get_netscan        { "image":"/cases/SRL-2018/base-dc-memory.img" }
get_malfind        { "image":"/cases/SRL-2018/base-dc-memory.img" }
get_svcscan        { "image":"/cases/SRL-2018/base-dc-memory.img" }   # hunt the svcsvc32-class service
build_process_tree { "image":"/cases/SRL-2018/base-dc-memory.img" }

# CROSS-HOST (the case's whole point):
correlate_timeline { "images":["/cases/SRL-2018/base-dc-cdrive.E01","/cases/SRL-2018/base-file-cdrive.E01"], "event_ids":[4624,4625,4648] }
pivot_on_ioc       { "ioc":"42.112.153.164", "images":[ ...the 7 E01s + per-host memory... ] }
detect_sweep       { "image":"/cases/SRL-2018/base-dc-cdrive.E01" }   # EID 5140/5145 SMB bursts
threat_intel_lookup{ "indicator":"42.112.153.164" }                   # then wazuh_hunt_ioc for live hunt
```

> ⚠️ **GOTCHA (B2):** `fls`/`extract_files`/`get_evtx` on a physical-disk E01 need the
> **`get_partitions`-derived `offset`** (start sector) — omit it and you get `Cannot determine file
> system type`. The assistant carries the offset forward for you when you ask it to list files.
> ⚠️ **GOTCHA (B3):** `run_bulk_extractor` `out_dir` and `extract_files` `dest` must be under a
> Thymus-allowlisted prefix — `/tmp/agentropix-sift-*`, `/cases/`, `/mnt/`, `/media/`, `/evidence/`.
> 💡 A prior carve already exists for one host at `/cases/SRL-2018/_carved/base-wkstn-01-memory/be_output/`
> (`email.txt`, `domain.txt`, `url.txt`, `report.xml`, …) — re-running for that host is idempotent.

**Step 6 — `record_finding` (DRAFT-gated).**

```text
record_finding { "finding": {
  "finding_id":"srl2018-c2-001",
  "host":"base-dc",
  "mitre_attack":"T1071.001",
  "confidence":0.7,
  "timestamp":"2018-05-03T14:22:15Z",
  "severity":"high",
  "title":"C2 backbone beacon to 42.112.153.164:8080 from domain controller",
  "ioc_value":"42.112.153.164", "ioc_type":"ipv4",
  "source_artifact":"/cases/auto/3_pivot_ioc_subject_srv.json" } }
```
- `dry_run=True` is the **default** → it previews, writes nothing. Persist with `dry_run=False` **and** a
  valid `mutation_token`. Required fields: `finding_id`, `host`, `mitre_attack`, `confidence`,
  `timestamp`. **Coherence:** `severity:high` needs `confidence ≥ 0.70`; `critical` needs `≥ 0.85`.
  Findings land **DRAFT** — they cannot self-approve. (`record_timeline_event` for timeline rows.)

**Step 7 — Approve (human-only examiner gate).** DRAFT → APPROVED only via the HMAC challenge-response
Approval Portal (**`https://siftworkstation.taile7c9ca.ts.net:8443/`**, or `http://127.0.0.1:8800/` on
the workstation). The in-band equivalent: `approve_finding { "finding_id":"srl2018-c2-001",
"approver_id":"victor.galvan", "password":"<examiner pw>" }`. **This is a Hard-Stop — never automated.**

**Step 8 — Report (+ optional IOC push).**

```text
report_generate { "profile":"full", "case_id":"SRL-2018-COMPROMISED-ENTERPRISE" }
```
`report_generate` builds from **indexed** case state; a DRAFT-only case can return `case_not_found`
until evidence is registered and/or a finding is approved. Then optionally curate + push accountable
IOCs (the C2 IP, the typosquat domain) to Wazuh via `wazuh_index_findings` (dry-run, then live with an
`egt_` mutation token).

---

## 3. "Activate & start" prompt sequences

> Two lanes. Both hit the same deterministic MCP engine. Check each **Expect:** line before moving on.
> Each operator action shows the 🖥️ command equivalent alongside the 💬 prompt.

### Manual path (numbered 💬 prompts; 🖥️ equivalent under each)

1. 💬 *"Check that my Agentropix forensic environment is ready — are all the forensic tools installed?"*
   🖥️ `uv run agentropix-sift doctor`
   **Expect:** each backing binary `OK <path>` or `MISSING`, ending `All tools available.`

2. 💬 *"Verify the integrity of the SRL-2018 domain-controller disk image — does its stored hash match?"*
   🖥️ `ewfverify /cases/SRL-2018/base-dc-cdrive.E01`
   **Expect:** `SUCCESS`, stored MD5 == calculated MD5 == `e18b450127de04afb3211faa456ada27`.

3. 💬 *"Show me the acquisition details of the DC image — who acquired it, when, and how big is it?"*
   🖥️ `ewfinfo /cases/SRL-2018/base-dc-cdrive.E01`
   **Expect:** case `20180905-001`, examiner `Clint Barton`, acquired `Fri Sep 7 2018`, media `33 GiB (36110860288 bytes)`, "Acquired over network via F-Response".

4. 💬 *"How many Agentropix forensic tools are available right now?"*
   🖥️ call the `health` tool
   **Expect:** `status: "ok"` with a live `tool_count` (canonical **71** per `.crew/facts.md`; trust the live number, not the startup banner).

5. 💬 *"Open a new high-severity case for the SRL-2018 Compromised Enterprise Network, examiner victor.galvan, case id SRL-2018-COMPROMISED-ENTERPRISE, evidence under /cases/SRL-2018, and make it the active case."*
   🖥️ `case_init { case_name:"SRL-2018 Compromised Enterprise Network", examiner_id:"victor.galvan", case_id:"SRL-2018-COMPROMISED-ENTERPRISE", case_dir:"/cases/SRL-2018", incident_type:"intrusion/apt-c2", severity:"high" }`
   **Expect:** `case_id SRL-2018-COMPROMISED-ENTERPRISE`, status `active`, pointer written to `~/.agentropix/active_case`.

6. 💬 *"Confirm SRL-2018 is the active case and the indexer is reachable."*
   🖥️ `case_status {}`
   **Expect:** `active: true`, `indexer_reachable: true`, per-index counts for the case.

7. 💬 *"Register the DC disk and the DC memory image as evidence in this case and give me their SHA-256 custody hashes."*
   🖥️ `evidence_register { path:"/cases/SRL-2018/base-dc-cdrive.E01", ... }` then `evidence_register { path:"/cases/SRL-2018/base-dc-memory.img", ... }`
   **Expect:** an `evidence_id` + SHA-256 + `size_bytes` per image, bound to the active case, `indexed:true` → `agentropix-evidence-YYYY.MM.DD`.

8. 💬 *"What does Agentropix report about the DC disk's media size and MD5?"*
   🖥️ `get_image_info { image:"/cases/SRL-2018/base-dc-cdrive.E01" }`
   **Expect:** media `33 GiB (36110860288 bytes)`, MD5 `e18b450127de04afb3211faa456ada27`, OS `Win 201x`.

9. 💬 *"What's the partition layout of the DC disk, and where does the main partition start?"*
   🖥️ `get_partitions { image:"/cases/SRL-2018/base-dc-cdrive.E01" }` (or `parse_gpt`; underlying binary is `mmls`)
   **Expect:** the partition table with the start sector, carried forward as the `offset` for `fls`/`extract_files`.

10. 💬 *"List all the files on the DC disk, then show me just the deleted files."*
    🖥️ `fls { image:"...E01", offset:<sector>, recursive:true }` then the same with `deleted_only:true`
    **Expect:** a non-zero live `entry_count`, then the deleted-only set (the assistant uses the offset from step 9).

11. 💬 *"Analyse the DC memory image: what processes were running, what network connections were open, and is there any injected code or a suspicious svcsvc32-style service?"*
    🖥️ `get_pslist` / `get_netscan` / `get_malfind` / `get_svcscan` / `build_process_tree { image:"/cases/SRL-2018/base-dc-memory.img" }`
    **Expect:** process list, sockets, malfind RWX hits, service list, and a PPID tree with LOLBin/DKOM-orphan flags (the proof-run saw 124 procs / 22 orphans on DC).

12. 💬 *"Carve the indicators — emails, domains, IPs, URLs — from the DC disk into an allowlisted folder."*
    🖥️ `run_bulk_extractor { target:"...E01", out_dir:"/tmp/agentropix-sift-srl2018-be", max_features:1000 }`
    **Expect:** a feature-type breakdown + totals; result returns the `out_dir` path (raw features exceed the Desktop 1 MB cap).

13. 💬 *"Correlate the logon timelines across the DC and file server, then pivot on the C2 IP 42.112.153.164 to see which hosts it touched."*
    🖥️ `correlate_timeline { images:[".../base-dc-cdrive.E01",".../base-file-cdrive.E01"], event_ids:[4624,4625,4648] }` then `pivot_on_ioc { ioc:"42.112.153.164", images:[...] }`
    **Expect:** one merged UTC event stream and the hosts where the C2 indicator appears (proof-run: 2576 logon events across DC+file).

14. 💬 *"Record a high-severity finding for the C2 beacon to 42.112.153.164:8080 from the domain controller, mapped to MITRE T1071.001, citing the pivot JSON."*
    🖥️ `record_finding { finding:{ finding_id:"srl2018-c2-001", host:"base-dc", mitre_attack:"T1071.001", confidence:0.7, timestamp:"2018-05-03T14:22:15Z", severity:"high", ... } }`
    **Expect:** a valid finding staged as **DRAFT** (`indexed:false`) — the assistant cannot self-approve.

15. 💬 *"Which findings are waiting for my approval and what are their IDs?"* (then approve yourself in the portal)
    🖥️ Approval Portal `https://siftworkstation.taile7c9ca.ts.net:8443/` → sign `srl2018-c2-001` DRAFT → APPROVED (HMAC, human-only)
    **Expect:** the DRAFT list with IDs; you sign off in the browser — **there is no plain-language approval shortcut (Hard-Stop).**

16. 💬 *"Generate the full report for the SRL-2018 case."*
    🖥️ `report_generate { profile:"full", case_id:"SRL-2018-COMPROMISED-ENTERPRISE" }`
    **Expect:** a `report_id` + section counts; `approved_finding_count` stays `0` until a finding is approved (a DRAFT-only case can return `case_not_found` until there is indexed state).

### Autonomous path (numbered: launch driver → monitor → approve → report)

1. 💬 *"You are a DFIR analyst with the Agentropix MCP. Investigate case SRL-2018-COMPROMISED-ENTERPRISE under /cases/SRL-2018. For each host run the full SIFT sequence — disk: mmls-offset → fls live+deleted → extract hives → registry/shimcache/prefetch → get_evtx (7045/4697/4698/5140/5145) → bulk_extractor (out_dir under /tmp/agentropix-sift-srl2018) → yara; memory: pslist/netscan/malfind/svcscan/process_tree. Then correlate timelines across hosts and pivot on the C2 IP 42.112.153.164. Stage findings as DRAFT. Do NOT approve. Finish with the full report."*
   🖥️ (B-Expert, detached driver; token from ENV, case key positional):
   ```bash
   AGENTROPIX_MCP_AUTH_TOKEN="<BEARER_TOKEN>" \
     setsid nohup bash -c "python3 /home/admin2/.openclaw/workspace/drivers/agx_gearb.py SRL-2018 > run.log 2>&1" </dev/null >/dev/null 2>&1 &
   disown
   ```
   **Expect:** the agent/driver walks `case_init → case_activate → evidence_register → get_image_info → fls (mmls offset) → run_bulk_extractor → [memory tools] → record_finding ×N (DRAFT) → report_generate{full}`, per host, staging all findings DRAFT and **stopping before approval**. (Smoke-test first with `--preflight` appended after the case key.)

2. 💬 *"How's the SRL-2018 investigation going — which hosts and steps are done?"*
   🖥️ `tail -f run.log` and read `/home/admin2/.openclaw/workspace/drivers/gearB/SRL-2018/SUMMARY.json` (per-step `ok`/`elapsed`/`error`)
   **Expect:** incremental progress; each step checkpointed to `SUMMARY.json`, findings `indexed:false` (DRAFT) and the `full` report `approved_finding_count 0` — the approval gate working as designed.

3. 💬 *"Which findings are waiting for my approval and what are their IDs?"* (then approve in the portal)
   🖥️ Approval Portal `https://siftworkstation.taile7c9ca.ts.net:8443/` → DRAFT → APPROVED (HMAC, append-only)
   **Expect:** the staged DRAFT findings + IDs; you approve **yourself** — the assistant will not and cannot approve on your behalf (Hard-Stop).

4. 💬 *"Generate the full report for the SRL-2018 case."*
   🖥️ `report_generate { profile:"full", case_id:"SRL-2018-COMPROMISED-ENTERPRISE" }`
   **Expect:** `report_id` + section counts; once findings are approved, `approved_finding_count` and the report sections populate.

5. 💬 *"Verify the seal on this report — confirm it hasn't been tampered with since it was generated."*
   🖥️ `uv run python scripts/verify_seal.py <report>.json`
   **Expect:** the seal verifier confirms the report + audit log are intact (HMAC-SHA256 seal, `evidence_image_sha256`-bound).

---

> **Honest caveats.** SRL-2018 memory-case sequences are authored but **not yet live-validated**
> end-to-end (per the user-guide "Known gaps"). The C2 IP / `svcsvc32` / typosquat-domain leads and the
> deployment window are **hypotheses** — re-derive every placeholder against live tool output before
> treating it as fact. YARA currently ships only `pf_smoketest.yar` (a clean scan returns `match_count
> 0` with the empty-string `raw_stdout_sha256` — that is success, not failure); add a production
> ruleset under an allowlisted prefix before relying on it.
