# Command Cheatsheet — Every Command Exercised in a Real Triage

> **Section 06 · Use Cases** — a one-page index of every command the use-case pages actually
> run, in execution order, with real example values from the validated runs. This is the
> *quick-reference* companion to the narrated pages; for the *why* behind each step follow the
> per-page links. Sourced verbatim from
> [uc-disk-triage.md](uc-disk-triage.md) · [uc-memory-triage.md](uc-memory-triage.md) ·
> [uc-approval-gate.md](uc-approval-gate.md) · [uc-wazuh-push.md](uc-wazuh-push.md) ·
> [demo-walkthrough.md](demo-walkthrough.md) · [case-hypotheses.md](case-hypotheses.md).

---

## The one mental model

There are **two command surfaces** — never mix them up:

| Surface | What it is | Examples |
|---|---|---|
| **CLI (shell)** | `agentropix-sift …`, `python …`, `jq`, `curl`. Used only for pre-flight, the autonomous `run`, token/gate provisioning, the sidecar, seal verification, and inspecting the sealed report. | `agentropix-sift run`, `python scripts/verify_seal.py` |
| **MCP tool call** | Every `snake_case` tool (`get_pslist`, `record_finding`, `wazuh_publish_iocs`). Issued by an MCP client (Claude Desktop / Claude Code) against the running `agentropix-sift-mcp` server — **not** from a shell. | `get_partitions { "image":"…" }` |

Every fact traces to a named deterministic tool; the LLM orchestrates but never generates facts
(`inference_constraint: high`). Each step has a **🖥️ expert** form (exact call) and a **💬 end-user**
form (a plain-language prompt that routes to the same tool) — see the source pages for both.

---

## 0. Pre-flight & gate provisioning (CLI — shell)

```bash
# Pre-flight all 16 SIFT binaries (vol, log2timeline.py, fls, icat, mmls, ewfinfo, evtx_dump.py,
# yara, bulk_extractor, rip.pl, pf, amcache_parser, shimcache_parser, exiftool, foremost, hashdeep)
agentropix-sift doctor

# Autonomous end-to-end triage (Trinity Loop), seals the report
agentropix-sift run <IMAGE> --max-iterations 5 --out report.json --verbose

# Mint a one-shot mutation token for any later live write (-> egt_<ULID>)
agentropix-sift evidence-gate mint
export AGENTROPIX_MUTATION_TOKEN=$(agentropix-sift evidence-gate mint --emit token)

# Run the HMAC approval sidecar service (human-in-the-loop)
python -m agentropix_sift.approval_sidecar

# Verify the courtroom seal (dependency-free, runs on any machine)
python scripts/verify_seal.py report.json
```

---

## 1. Disk triage — E01 image → [uc-disk-triage.md](uc-disk-triage.md)

**Autonomous (CLI):**

```bash
agentropix-sift doctor
agentropix-sift run /evidence/srl2018/base-dc-cdrive.E01 --max-iterations 5 --out report.json --verbose
```

**Granular MCP chain (in order — the offset is load-bearing):**

```text
get_image_info    { "image":"<IMAGE>" }                                              # ewfinfo metadata, acquisition MD5
get_partitions    { "image":"<IMAGE>" }                                              # CAPTURE NTFS start sector (e.g. 63)
case_init         { "case_name":"...", "examiner_id":"...", "scope":"<IMAGE>" }
evidence_register { "path":"<IMAGE>", "description":"Windows disk (EWF/E01)", "examiner_id":"..." }
fls               { "image":"<IMAGE>", "offset":63, "recursive":true, "summary_only":true }
fls               { "image":"<IMAGE>", "offset":63, "recursive":true, "deleted_only":true }   # T1070.004 surface
extract_files     { "image":"<IMAGE>", "offset":63, "paths":["<hive paths>"], "dest":"<OUT_DIR>" }
get_shimcache     { "hive":"<OUT_DIR>/SYSTEM" }
get_amcache       { "hive":"<OUT_DIR>/Amcache.hve" }   # Win7+ only (XP has none)
get_prefetch      { "target":"<OUT_DIR>/Prefetch" }    # XP-compatible
run_hashdeep      { "target":"<OUT_DIR>" }             # IOC-candidate hashes
```

> ⚠️ **Gotchas.** Pass the `get_partitions` sector as `offset` to `fls`/`extract_files` (offset 0 = MBR
> → `Cannot determine file system type`). `dest` must be under a Thymus-allowlisted prefix
> (`/tmp/agentropix-sift-*`, `/cases/`, `/mnt/`, `/media/`, `/evidence/`).

---

## 2. Memory triage — Volatility3 → [uc-memory-triage.md](uc-memory-triage.md)

**Autonomous (CLI):**

```bash
agentropix-sift run /evidence/srl2018/base-hunt-memory.raw --max-iterations 5 --out mem-report.json
```

**Granular MCP C2-hunt chain (in order):**

```text
get_pslist          { "image":"...raw" }                          # baseline PIDs (windows.pslist)
build_process_tree  { "image":"...raw" }                          # PPID links; psscan fallback; flags LOLBins/orphans
get_netscan         { "image":"...raw" }                          # TCP/UDP rows; join pid -> tree
get_malfind         { "image":"...raw" }                          # RWX / injected-code hexdump
get_svcscan         { "image":"...raw" }                          # service persistence
get_editbox         { "image":"...raw", "profile":"<vol2.6>" }    # optional, Vol2.6 typed creds
run_volatility      { "target":"...raw", "plugin":"windows.cmdline", "args":[] }   # escape hatch (any allowlisted windows.* plugin)
pivot_on_ioc        { "ioc":"<C2 IP/hash>", "images":["host-01.raw","host-02.raw"], "ioc_type":"ip" }
threat_intel_lookup { "indicator":"<IP/hash>", "indicator_type":"ip", "providers":["virustotal","otx"] }  # egress-gated
```

> ⚠️ **Gotchas.** `threat_intel_lookup` no-ops (`egress_allowed=False`) unless `AGENTROPIX_ALLOW_EGRESS=1`
> + a provider key. `get_editbox` self-skips without the Vol2.6 sandbox (`AGENTROPIX_VOL26_BIN`).
> Prefer the typed renderers (Steps 1–5) over `run_volatility` for structured rows.

---

## 3. Approval gate — DRAFT → APPROVED → sealed → [uc-approval-gate.md](uc-approval-gate.md)

**Prereqs (CLI):** mint a token (`AGENTROPIX_MUTATION_TOKEN`) and start the sidecar (see §0).

**MCP tool calls:**

```text
record_finding   (finding={...}, dry_run=true)                               # preview (no token spent)
record_finding   (finding={...}, dry_run=false, mutation_token="egt_<ULID>") # commit DRAFT
delete_finding   (finding_id, dry_run=false)                                 # DRAFT-only self-correct
case_status      ()                                                          # {DRAFT, APPROVED, REJECTED}
approve_finding  (finding_id, approver_id, password,
                  from_status="DRAFT", to_status="APPROVED", reason="...")    # examiner only, HMAC-signed
retract_approval (approval_id, approver_id, password, reason="...")           # compensating REVOKED entry
report_generate  (profile="full")                                            # APPROVED-only
report_export    (tier="analyst", fmt="md")                                  # -> courtroom.seal_report
```

**Raw two-leg sidecar handshake (keeps the password out of LLM context) — `curl`:**

```bash
curl -fsS http://127.0.0.1:8800/challenge -H 'content-type: application/json' \
  -d '{"examiner_id":"<examiner>","target_id":"F-alice-001","target_type":"finding"}'

curl -fsS http://127.0.0.1:8800/approve -H 'content-type: application/json' \
  -d '{"case_id":"INC-2026-0042","target_id":"F-alice-001","target_type":"finding",
       "from_status":"DRAFT","to_status":"APPROVED","examiner_id":"<examiner>",
       "nonce":"<nonce>","signature_hex":"<signature-hex>","reason":"verified against source artifact"}'
```

> ⚠️ The **W-286 draft-gate** strips any caller-supplied `approval.*` — the LLM cannot self-approve.
> `report_generate` on a case with zero APPROVED findings returns the executive/empty shell by design.

---

## 4. Wazuh push — experimental, opt-in → [uc-wazuh-push.md](uc-wazuh-push.md)

**Gate provisioning (CLI, once per session — never against prod):**

```bash
agentropix-sift evidence-gate mint   # -> AGENTROPIX_MUTATION_TOKEN
export WAZUH_INTEGRATION_ENABLED=true
export WAZUH_PUSH_ENABLED=true
export WAZUH_DRY_RUN_ONLY=false
export AGENTROPIX_INTEGRATION_NOT_PRODUCTION=true   # W-188 affirmation: target is NOT prod
```

**MCP tool calls (in order):**

```text
build_executable_registry (case_id, executables=[{"sha256":"...","path":"..."}], dry_run=false, case_dir="...")  # writes MASTER-IOCS.json
wazuh_index_findings      (case_id, findings=[...], dry_run=true)                              # preview
wazuh_index_findings      (case_id, findings=[...], dry_run=false, mutation_token="egt_...")   # live index as sealed alerts
wazuh_publish_iocs        (case_dir="...", dry_run=true)                                       # push plan (Tier-1/2/3)
wazuh_publish_iocs        (case_dir="...", dry_run=false, mutation_token="egt_...")            # live push: CDB lists + rules + restart + seal
wazuh_hunt_ioc            (ioc_value="203.0.113.7", ioc_type="ip", time_range_hours=2160)      # retro-hunt 90d
wazuh_check_intel         (ioc_value="evil.example.com", ioc_type="domain")                   # read-only
wazuh_vuln_query          (cve="CVE-2024-3094", time_range_hours=720)                          # read-only
```

> ⚠️ Every `dry_run=false` call **fails closed** with a structured `error` naming the switch to flip
> until **all four** kill switches are on AND a valid one-shot token is supplied. Publish is
> **idempotent** — pass the whole `case_dir` once; do **not** loop per-IOC. Tier-3 denylist hits land
> in `skipped_tier3`, not `pushed` (a safety control, not a bug).

---

## 5. Judge demo — inspect the sealed artifact → [demo-walkthrough.md](demo-walkthrough.md)

```bash
agentropix-sift run /evidence/srl2018/win2008r2-controller-memory.001 --max-iterations 5

jq -r '.completion_proofs[]' report.json                                    # which agents fired
jq '.findings[] | select(._source=="memory.injection")' report.json         # finding -> producing tool
jq '.trace.tool_calls[] | select(.args_hash=="f7e2c4d8...")' report.json     # replay linkage

python scripts/verify_seal.py report.json                                    # -> "OK Report seal verified."
jq '.findings += [{"_source":"FAKE","confidence":1.0,"description":"fabricated"}]' \
   report.json > tampered.json
python scripts/verify_seal.py tampered.json                                  # -> "X Report seal MISMATCH ..."

agentropix-sift run /evidence/srl2015/nromanoff.pst --max-iterations 5       # mail / T1566 PST carve
```

MCP tools referenced here: `record_finding`, `report_generate`, `report_export`, `get_pslist`,
`approve_finding`, `carve_pst_iocs`, `pivot_on_ioc`.

---

## 6. Per-case tool selection → [case-hypotheses.md](case-hypotheses.md)

> **Hypotheses, not findings.** These steer *which* tools to reach for first — prove each link
> against live tool output before treating it as fact.

| Case | Image(s) | Key tools to confirm/refute each link |
|---|---|---|
| **1 — SRL-2015** (multi-host APT) | 4× E01 + memory + `.mans` | delivery `run_bulk_extractor`/`analyze_maldoc`/`carve_pst_iocs`; exec `get_malfind`/`build_process_tree`/`get_prefetch`; lateral `get_evtx`(4624 t3/10, 4776)+`correlate_timeline`+`detect_sweep`+`pivot_on_ioc` |
| **2 — SRL-2018** (network C2) | many E01 + memory `.img` | `get_svcscan`+`scan_yara`(svcsvc32)+`get_malfind`; persistence `get_evtx`(7045/4697/4698); cascade `detect_sweep`+`correlate_timeline`+`pivot_on_ioc`; intel `threat_intel_lookup`/`wazuh_hunt_ioc` |
| **3 — cfreds-fresh** (XP insider) | `4Dell-Latitude-CPi.E01` | `get_prefetch` (XP: NO SRUM/amcache), `get_registry`/`get_shimcache`, `get_bstrings`+`glob_paths`, `run_bulk_extractor`/`email_header_matrix`/`carve_pst_iocs`, `get_timeline`+`get_mftecmd` |
| **4 — rocba** (insider IP theft) | `rocba-cdrive.e01` + `Rocba-Memory.raw` | access `get_evtx`(4624 t2)/`get_timeline`; collection `get_mftecmd`/`get_sbecmd`/`get_lecmd`; USB `get_registry`(USBSTOR); exfil `srum_extract`/`get_sqlecmd`/`get_netscan`; disambig `scan_yara`(Cobalt Strike)+`get_malfind`+`get_netscan` |
| cross-case | — | verify every image with `get_image_info` / `.md5` / `ewfverify` before reading; `.mans` files are SQLite, not zip |

---

## See also

- [uc-disk-triage.md](uc-disk-triage.md) · [uc-memory-triage.md](uc-memory-triage.md) ·
  [uc-approval-gate.md](uc-approval-gate.md) · [uc-wazuh-push.md](uc-wazuh-push.md) —
  the narrated walkthroughs (with the 💬 end-user prompts and validated outputs).
- [demo-walkthrough.md](demo-walkthrough.md) — the judge-facing single run, beat by beat.
- [case-hypotheses.md](case-hypotheses.md) — per-case attack-chain bias-checks.
- [`tool-list.md`](../04-mcp-tools/tool-list.md) — the full 71-tool catalogue and exact arg schemas.
