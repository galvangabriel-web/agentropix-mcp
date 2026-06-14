# MCP Tool Reference

> **The full 73-tool surface of the single FastMCP server.**
> Agentropix-SIFT exposes **73** distinct MCP tools (`mcp_tool_count = 73`, see
> [`canonical-facts.md`](../08-reference/canonical-facts.md)). Of those, **16**
> drive the underlying SIFT command-line forensic binaries (the "16 forensic wrappers"). This page is
> the master reference: a categorized index of all 71, a deeper table for the 16 forensic wrappers, and
> the discovery-vs-execution-vs-wrapper taxonomy.

Related pages: [Response envelope](response-envelope.md) · [Tools by agent](tool-by-agent.md) ·
[Tool list](tool-list.md) · [Capability map](capability-map.md) ·
[Module map](../02-architecture/module-map.md) · [Schema reference](../03-data/schema-er.md) ·
[Canonical facts](../08-reference/canonical-facts.md).

---

## Contents — what's in this page (and what to expect)

The master reference for the full 73-tool MCP surface. Jump to the section you need:

| Section | What you'll get |
|---------|-----------------|
| [How the 73 tools are registered](#how-the-73-tools-are-registered) | How every tool becomes a `@app.tool()` FastMCP route, how the 73 `@app.tool()` registrations map 1:1 to 73 distinct functions, the live `health`/`tool_count` source of truth, and the wrapper / discovery / case-state taxonomy. |
| [Auth & mutation model (applies across the catalogue)](#auth--mutation-model-applies-across-the-catalogue) | The cross-cutting access controls — bearer token, `[MUT]` mutation tokens, `[APPR]` HMAC approval, `dry_run` guards, Thymus read-only — enforced at the MCP boundary. |
| [Master categorized table (all 73 tools)](#master-categorized-table-all-73-tools) | Every tool, grouped by category, with purpose, backing module, and `[SIFT-16]`/`[MUT]`/`[APPR]` markers — plus the per-section row counts. |
| [The 16 SIFT forensic wrappers (deep table)](#the-16-sift-forensic-wrappers-deep-table) | A per-binary deep dive of the 16 forensic wrappers: inputs, parsed return types, caveats, and the W-135 degradation contract. |
| [Discovery vs execution vs derived — worked examples](#discovery-vs-execution-vs-derived--worked-examples) | Concrete examples distinguishing execution, derived, and state-mutating tools, and which agent drives each. |

---

## How the 73 tools are registered

Every tool is a `@app.tool()` route on a single FastMCP server. The server module
(`src/agentropix_sift/mcp_server/fastmcp_app.py`) declares 67 in-module routes; the remaining tools are
registered by the 5 Wazuh wrapper decorators — **74** `@app.tool()` decorator occurrences in total,
reconciling to **73 distinct tool functions** because `wazuh_hunt_ioc` is registered in two modules
(`docs/tools/_TOOL-CATALOGUE.md`). Each FastMCP route is a thin protocol surface over an inner
`mcp_*` async function in `src/agentropix_sift/mcp_server/server.py`; the Pydantic typing, Thymus
read-only policy, rate limiting, and `@traced` instrumentation already on the inner function flow
through unchanged (`fastmcp_app.py:1-35`).

> **Authoritative count.** The `health` tool returns a live `tool_count` from `app.list_tools()`
> (`fastmcp_app.py:369`, returned at `:375`) — the single source of truth that narrative docs should
> cite rather than hard-coding a catalogue size that drifts as wrappers land. When an exact number is
> load-bearing, re-query the running server's `tools/list` and cite `mcp_tool_count = 73` from
> [`canonical-facts.md`](../08-reference/canonical-facts.md).

#### Verified sample I/O — `health`

`health` is the one tool that runs **no subprocess and no Thymus check**, so its shape is deterministic
and safe to show verbatim. It is the canary the orchestrators (Trinity, Critic, `scripts/probe_mcp.py`)
probe instead of invoking a full forensic tool (`fastmcp_app.py:354-376`).

```jsonc
// health()  -> dict   (no arguments)
{
  "status": "ok",
  "server": "agentropix-sift",
  "version": "<semver>",        // _SIFT_VERSION at startup
  "uptime_seconds": 12.481,     // monotonic since process start
  "tool_count": 73              // live len(app.list_tools()) — matches mcp_tool_count = 73
}
```

The `tool_count` field is what the canonical `mcp_tool_count = 73` is reconciled against; if a live
probe ever returns a different number, the running server — not this page — is authoritative (re-derive
the catalogue and update [`canonical-facts.md`](../08-reference/canonical-facts.md)). Every other tool wraps its payload in the standard response
envelope (`tool_available`, `raw_stdout_sha256`, `skipped_reason`, …) documented on
[Response envelope](response-envelope.md); `health` is intentionally the lone exception (no
chain-of-custody fields because it touches no evidence).

### Three kinds of tool

The 73 tools fall into a useful taxonomy that explains why the swarm calls some directly and never
others:

| Class | What it does | Examples | Backing |
|-------|--------------|----------|---------|
| **Wrapper (execution) tools** | Shell out to an external forensic binary, parse its output into a typed report. The "real work." | `get_pslist`, `fls`, `get_timeline`, `scan_yara`, `run_exiftool` | `mcp_server/wrappers/*.py` driving a binary |
| **Discovery / correlation tools** | Run no external binary on their own; read prior findings off the case or Blackboard and derive structure. | `build_process_tree`, `correlate_timeline`, `detect_sweep`, `pivot_on_ioc` | `wrappers/correlation.py`, `wrappers/ioc_registry.py` |
| **Case / state / reporting tools** | Manage the case lifecycle, persist findings/IOCs, generate reports, talk to OpenSearch / Wazuh. Several are **state-mutating** and gated. | `case_init`, `record_finding`, `promote_iocs`, `report_generate`, `idx_ingest` | `wrappers/case_*.py`, `wrappers/ioc_registry.py`, `reports/`, `wazuh/` |

The HuntAgent and DiscoveryAgent, for example, run **no wrappers** at all — they consume what the
execution tools already published (see [Tools by agent](tool-by-agent.md)).

---

## Auth & mutation model (applies across the catalogue)

Before the per-tool tables, the cross-cutting access controls. These are enforced at the MCP boundary,
not in the LLM, and are what keep the surface court-defensible.

| Mechanism | Marker | Applies to | Source |
|-----------|--------|-----------|--------|
| Bearer-token middleware | (all HTTP tools) | Every HTTP-exposed tool, tailnet-only | ADR-017 |
| `mutation_token` argument | **[MUT]** | `record_finding`, `idx_ingest`, `promote_iocs`, `promote_executable_registry`, `wazuh_index_findings`, `wazuh_publish_iocs` | per-tool signature |
| `password` (HMAC approval) | **[APPR]** | `approve_finding`, `retract_approval` | approval sidecar; ADR-016/022 |
| `dry_run` guard (default `True`) | — | all promote / ingest / publish / delete tools | per-tool signature |
| Thymus read-only policy | (all read tools) | Every evidence-reading path | `mcp_server/thymus_policy.py` (S-02) |

The mutation token is a one-shot, TTL-bound capability minted by the evidence gate
(`evidence_gate/registry.py`); the HMAC approval `password` drives the PBKDF2/HMAC challenge in the
approval sidecar. Both exist so the LLM cannot self-approve or silently mutate case state — see
[Response envelope](response-envelope.md#mutation--approval-gating) and the safety-spine chapter.

---

## Master categorized table (all 73 tools)

Legend: **[SIFT-16]** = drives one of the 16 SIFT forensic binaries · **[MUT]** = state-mutating
(requires `mutation_token`) · **[APPR]** = HMAC approval-gated. Backing module shown is the wrapper or
package that implements the tool; the FastMCP route lives in `fastmcp_app.py` and dispatches through
`server.py`.

### Case & session (4)

| Tool | Purpose | Backing module |
|------|---------|----------------|
| `case_init` | Create a case context and stamp the active-case pointer | `wrappers/case_lifecycle.py` |
| `case_activate` | Set the active case | `wrappers/case_lifecycle.py` |
| `case_status` | Report case state + per-index doc counts | `wrappers/case_lifecycle.py` |
| `health` | Server health probe + live `tool_count` (no subprocess, no Thymus) | `fastmcp_app.py:354-376` |

### Evidence intake & disk imaging (10)

| Tool | Purpose | Backing module |
|------|---------|----------------|
| `evidence_register` | Register an evidence file (SHA-256, size) into the case | `wrappers/case_lifecycle.py` |
| `get_image_info` | E01/raw image metadata · **[SIFT-16]** `ewfinfo` | `wrappers/ewf.py` |
| `get_partitions` | List partitions · **[SIFT-16]** `mmls` | `wrappers/tsk.py` |
| `parse_gpt` | Parse a GUID partition table | `wrappers/gpt_parser.py` |
| `unwrap_disk_container` | Unwrap a dynamic-disk container | `wrappers/disk_container.py` |
| `extract_files` | Extract files from an image · **[SIFT-16]** `icat` | `wrappers/extract.py` |
| `extract_archive` | Safe (zip-bomb-bounded) archive extraction | `wrappers/extract_archive.py` |
| `fls` | List filesystem entries · **[SIFT-16]** `fls` (Sleuth Kit) | `wrappers/tsk.py` |
| `list_files` | List files on a mounted path | `wrappers/tsk.py` |
| `glob_paths` | Glob path matching | `wrappers/glob_paths.py` |

### Memory forensics — Volatility (7)

| Tool | Purpose | Backing module |
|------|---------|----------------|
| `run_volatility` | Run any allowlisted Volatility3 `windows.*` plugin · **[SIFT-16]** `vol` | `wrappers/volatility.py` |
| `get_pslist` | Process list · **[SIFT-16]** `vol` | `wrappers/volatility.py` |
| `build_process_tree` | Process-tree correlation (derived) | `wrappers/correlation.py` |
| `get_malfind` | Injected code / RWX VAD detection · **[SIFT-16]** `vol` | `wrappers/volatility.py` |
| `get_netscan` | Network connections (typed socket list) · **[SIFT-16]** `vol` | `wrappers/volatility.py` |
| `get_svcscan` | Service scan · **[SIFT-16]** `vol` | `wrappers/volatility.py` |
| `get_editbox` | Vol2.6 editbox (UI text) | `wrappers/editbox.py` |
| `get_memory_netconns` | Vol2.6 XP/2003 netconns recovery (`connscan`/`connections`/`sockscan`) | `wrappers/vol26_netconns.py` |

### Registry, execution & shell artifacts — EZ Tools / RegRipper (16)

| Tool | Purpose | Backing module |
|------|---------|----------------|
| `get_registry` | RegRipper hive analysis · **[SIFT-16]** `rip.pl` | `wrappers/regripper.py` |
| `get_amcache` | Amcache execution evidence · **[SIFT-16]** `amcache_parser` | `wrappers/amcache.py` |
| `get_shimcache` | Shimcache (AppCompatCache) · **[SIFT-16]** `shimcache_parser` | `wrappers/shimcache.py` |
| `get_prefetch` | Prefetch parsing · **[SIFT-16]** `pf` | `wrappers/prefetch.py` |
| `get_recmd` | RECmd (EZ Tools) batch registry | `wrappers/recmd.py` |
| `get_mftecmd` | MFTECmd NTFS `$MFT` parser | `wrappers/mftecmd.py` |
| `get_lecmd` | LECmd `.lnk` parser | `wrappers/lecmd.py` |
| `get_jlecmd` | JLECmd Jump List parser | `wrappers/jlecmd.py` |
| `get_sbecmd` | SBECmd ShellBags parser | `wrappers/sbecmd.py` |
| `get_sqlecmd` | SQLECmd SQLite parser | `wrappers/sqlecmd.py` |
| `srum_extract` | SRUM resource-usage extraction | `wrappers/srum.py` |
| `get_bstrings` | bstrings regex string extractor | `wrappers/bstrings.py` |
| `exec_registry_get` | Read the executable-artifact registry (EAR) | `wrappers/executable_registry.py` |
| `exec_registry_search` | Search the executable registry | `wrappers/executable_registry.py` |
| `build_executable_registry` | Build the executable registry (dry-runnable) | `wrappers/executable_registry.py` |
| `promote_executable_registry` **[MUT]** | Promote the executable registry | `wrappers/executable_registry.py` |

### Event logs & timeline (6)

| Tool | Purpose | Backing module |
|------|---------|----------------|
| `get_evt` | Legacy `.evt` parser | `wrappers/evt.py` |
| `get_evtx` | Windows `.evtx` parser · **[SIFT-16]** `evtx_dump.py` | `wrappers/evtx.py` |
| `get_timeline` | Plaso super timeline · **[SIFT-16]** `log2timeline.py` | `wrappers/plaso.py` |
| `correlate_timeline` | Cross-host timeline correlation (derived) | `wrappers/correlation.py` |
| `detect_sweep` | Lateral-movement sweep detection (derived) | `wrappers/correlation.py` |
| `record_timeline_event` | Append a timeline event to the case | `wrappers/case_records.py` |

### Mail / maldoc / documents (4)

| Tool | Purpose | Backing module |
|------|---------|----------------|
| `analyze_maldoc` | oletools maldoc analysis | `wrappers/maldoc.py` |
| `carve_pst_iocs` | PST carve + attachment-hash IOC index | `wrappers/pst_carve.py` |
| `email_header_matrix` | Email-header matrix across a corpus | `wrappers/email_header_matrix.py` |
| `pdf_extract_text` | PDF text extraction | `wrappers/pdf_extract_text.py` |

### File analysis & carving (6)

| Tool | Purpose | Backing module |
|------|---------|----------------|
| `run_strings` | GNU strings extraction · **[SIFT-16]** `strings` | `wrappers/strings.py` |
| `run_bulk_extractor` | bulk_extractor feature scan · **[SIFT-16]** `bulk_extractor` | `wrappers/bulk_extractor.py` |
| `run_foremost` | Foremost file carving · **[SIFT-16]** `foremost` | `wrappers/foremost.py` |
| `run_exiftool` | ExifTool metadata · **[SIFT-16]** `exiftool` | `wrappers/exiftool.py` |
| `run_hashdeep` | hashdeep hashing / audit · **[SIFT-16]** `hashdeep` | `wrappers/hashdeep.py` |
| `scan_yara` | YARA scan · **[SIFT-16]** `yara` | `wrappers/yara.py`, `yara_forge.py` |

### Findings, IOCs & reporting (7)

| Tool | Purpose | Backing module |
|------|---------|----------------|
| `record_finding` **[MUT]** | Stage a finding as DRAFT (LLM cannot self-approve) | `wrappers/case_records.py` |
| `delete_finding` | Delete a DRAFT finding (audited self-correction) | `wrappers/case_records.py` |
| `promote_iocs` **[MUT]** | Promote case IOCs into `MASTER-IOCS` | `wrappers/ioc_registry.py` |
| `pivot_on_ioc` | Pivot across images on an IOC (derived) | `wrappers/ioc_registry.py` |
| `threat_intel_lookup` | VirusTotal / OTX lookup | `wrappers/threat_intel.py` |
| `report_generate` | Generate a tiered triage report | `reports/render.py` |
| `report_export` | Export a report tier/format | `reports/export.py` |

### Approval workflow — HMAC sidecar (2)

| Tool | Purpose | Backing module |
|------|---------|----------------|
| `approve_finding` **[APPR]** | HMAC-signed examiner approval (state transition) | `approval_sidecar/` |
| `retract_approval` **[APPR]** | Compensating retraction (append-only VOID) | `approval_sidecar/` |

### Indexer — OpenSearch (5)

| Tool | Purpose | Backing module |
|------|---------|----------------|
| `idx_ingest` **[MUT]** | Ingest findings / timeline events | `wrappers/case_ingest.py` |
| `idx_search` | Search indexed case data | `wrappers/case_queries.py` |
| `idx_aggregate` | Aggregate over a field | `wrappers/case_queries.py` |
| `idx_timeline` | Time-bucketed timeline query | `wrappers/case_queries.py` |
| `idx_case_summary` | Case summary rollup | `wrappers/case_queries.py` |

### Wazuh SIEM integration (5)

| Tool | Purpose | Backing module |
|------|---------|----------------|
| `wazuh_hunt_ioc` | Hunt an IOC across Wazuh indices | `wrappers/wazuh_intel.py` / `wazuh_tools.py` |
| `wazuh_check_intel` | Check an IOC against CDB lists | `wrappers/wazuh_intel.py` |
| `wazuh_index_findings` **[MUT]** | Index findings into Wazuh | `wrappers/wazuh_tools.py` |
| `wazuh_publish_iocs` **[MUT]** | Publish IOCs to CDB lists | `wrappers/wazuh_tools.py` |
| `wazuh_vuln_query` | Query vuln / CVE data | `wrappers/wazuh_intel.py` |

**Row count:** 4 + 10 + 8 + 16 + 6 + 4 + 6 + 7 + 2 + 5 + 5 = **73 rows listed**. `wazuh_hunt_ioc` is the
double-registered tool (two modules), so **distinct tool functions = 71** — the canonical count. (74
`@app.tool()` decorator occurrences → 73 distinct functions; see `docs/tools/_TOOL-CATALOGUE.md`.)

---

## The 16 SIFT forensic wrappers (deep table)

The canonical "16 forensic wrappers" (`README.md:151`, `CHANGELOG.md:449`) are the underlying SIFT
command-line forensic binaries that the wrapper layer drives and that `agentropix-sift doctor`
pre-flights (`src/agentropix_sift/cli.py:176-196`). Each wrapper shells out, captures stdout/stderr,
SHA-256-hashes the raw stdout bytes for chain of custody (`raw_stdout_sha256`), and parses the output
into a typed Pydantic report. Every wrapper ships timeout, memory-ceiling, retry, stderr-capture, and
`@traced` tracing (`CHANGELOG.md` M4→M6.2).

| # | Binary | MCP tool(s) | Inputs (key args) | What it parses → returns | Caveats |
|---|--------|-------------|-------------------|--------------------------|---------|
| 1 | `vol` (Volatility3) | `get_pslist`, `get_malfind`, `get_netscan`, `get_svcscan`, `run_volatility` | `image`/`target`, `plugin`, `pid_filter`, `args`, `timeout_seconds` | Memory artefacts → `PsList`, `MalfindReport`, `NetscanReport`, `SvcscanReport`, `VolatilityReport` (`wrappers/volatility.py`) | Memory-image only; on a disk image the wrapper short-circuits with `tool_available=False` + `skipped_reason`/`image_class_detected` (W-135). `pslist` may fall back to `psscan` (`used_fallback=True`). |
| 2 | `log2timeline.py` (Plaso) | `get_timeline` | `image`, `parsers`, `max_events` | Super-timeline events (`wrappers/plaso.py`) | Long-running — bounded by the Plaso timeout env; `max_events` caps the row count returned. |
| 3 | `fls` (Sleuth Kit) | `fls`, `list_files` | `image`, `offset`, `inode`, `recursive`, `deleted_only`, `fstype`, `summary_only` | Filesystem entry list → `FlsReport` with `raw_stdout_sha256` (`wrappers/tsk.py:49`) | Needs a correct partition `offset` for multi-partition images; `summary_only` trims the entry list to fit the result envelope. |
| 4 | `icat` (Sleuth Kit) | `extract_files` | `image`, `paths`, `dest`, `offset`, `fstype`, `follow_reparse_points`, `expand_dirs`, `max_dir_files` | Extracted file bytes + per-file manifest (`wrappers/extract.py`) | Concurrency-capped (`AGENTROPIX_EXTRACT_CONCURRENCY`, default 4) so a slow `ifind`/`icat` can't back-pressure the server (`fastmcp_app.py:57-60`). |
| 5 | `mmls` (Sleuth Kit) | `get_partitions` | `image` | Partition table → `MmlsReport` (`wrappers/tsk.py:313`); GPT path via `parse_gpt`→`gpt_parser.py` | Partition offsets feed the other Sleuth Kit tools; GPT tables are parsed by `gpt_parser.py` rather than `mmls`. |
| 6 | `ewfinfo` (libewf) | `get_image_info` | `image` | E01 acquisition metadata (`wrappers/ewf.py`) | E01/EWF-specific; raw `dd` images yield minimal metadata. |
| 7 | `evtx_dump.py` (python-evtx) | `get_evtx` | `target`, `channels`, `event_ids`, `max_events`, `timeout_seconds` | Windows `.evtx` records → `EvtxReport` with `channels_seen`, `raw_stdout_sha256` (`wrappers/evtx.py:423`) | `channels`/`event_ids` filter post-parse; an empty `channels_seen` can mean the image genuinely lacks those channels. Honors `AGENTROPIX_EVTX_TOOL`. |
| 8 | `yara` | `scan_yara` | `target`, `rules`, `with_meta`, `with_strings`, `max_matches`, `timeout_seconds` | Rule matches → YARA report (`wrappers/yara.py`, `yara_forge.py`) | `max_matches` caps output; rules can come from vendored `detectors/yara_rules/`. |
| 9 | `bulk_extractor` | `run_bulk_extractor` | `target`, `out_dir`, `enable_scanners`, `disable_scanners`, `only_scanner`, `max_features`, `summary_only` | Feature files (emails, URLs, ccns…) (`wrappers/bulk_extractor.py`) | Writes feature files to `out_dir`; `max_features`/`summary_only` keep the in-band response bounded. |
| 10 | `rip.pl` (RegRipper) | `get_registry` | `hive`, `profile`, `plugin` | Registry-hive analysis (`wrappers/regripper.py`) | Needs the right hive type for the chosen `profile`/`plugin`. |
| 11 | `pf` | `get_prefetch` | `target` | Prefetch execution evidence (`wrappers/prefetch.py`) | Windows prefetch only; layout varies by Windows version. |
| 12 | `amcache_parser` | `get_amcache` | `hive` | Amcache execution evidence (`wrappers/amcache.py`) | EZ-Tools `AmcacheParser`; honors `AGENTROPIX_AMCACHE_TOOL`. |
| 13 | `shimcache_parser` | `get_shimcache` | `hive` | Shimcache / AppCompatCache (`wrappers/shimcache.py`) | EZ-Tools `AppCompatCacheParser`; honors `AGENTROPIX_SHIMCACHE_TOOL`. |
| 14 | `exiftool` | `run_exiftool` | `target`, `recursive`, `fast`, `max_files` | File metadata (`wrappers/exiftool.py`) | `max_files` bounds recursive runs. |
| 15 | `foremost` | `run_foremost` | `target`, `output_dir`, `config`, `types`, `quick`, `audit_only`, `max_entries` | Carved files / audit (`wrappers/foremost.py`) | `audit_only` reports without writing; `max_entries` caps the manifest. |
| 16 | `hashdeep` | `run_hashdeep` | `target`, `algos`, `recursive`, `audit`, `max_files` | Multi-algorithm hashes / audit (`wrappers/hashdeep.py`) | `audit` mode compares against a known-good set; `max_files` bounds recursive hashing. |

> **Also pre-flighted by `doctor`** but not counted in the 16: `strings`, `ssdeep`, `ifind` (Sleuth
> Kit). `run_strings` drives `strings`; `ifind` is used internally by the `icat`/`extract_files` path.
> Additional **EZ-Tools** ship as their own wrappers layered on the core 16: `RECmd`, `MFTECmd`,
> `LECmd`, `JLECmd`, `SBECmd`, `SQLECmd`, `bstrings`, `SRUM` (`recmd.py`, `mftecmd.py`, `lecmd.py`,
> `jlecmd.py`, `sbecmd.py`, `sqlecmd.py`, `bstrings.py`, `srum.py`). These are invoked via
> `dotnet <dll>` and are degraded-tolerant — a missing `dotnet` runtime surfaces as a startup banner
> warning, not a runtime crash (`fastmcp_app.py:91-120`). See
> [EZ-Tools integration](../02-architecture/ez-tools-integration.md) for the full .NET wrapper architecture.

### Degradation contract (W-135)

A wrapper never raises when its binary is missing or the input is the wrong class. Instead it returns
its typed report with `tool_available=False` and a populated `skipped_reason` (and, for memory tools,
`image_class_detected`). This keeps the swarm deterministic: an absent `vol` against a disk image is a
*signalled skip*, not a tracebacks-everywhere failure. See
[Response envelope → availability & skip signalling](response-envelope.md#availability--skip-signalling).

---

## Discovery vs execution vs derived — worked examples

- **Execution (`get_evtx`)** → shells `evtx_dump.py`, parses records, hashes raw stdout. Produces
  primary evidence.
- **Derived (`build_process_tree`)** → no new subprocess; correlates the `get_pslist` output into a
  parent/child tree (`wrappers/correlation.py`). The MemoryAgent calls `get_pslist` first, then this.
- **Derived (`detect_sweep`)** → reads timeline events and flags lateral-movement windows; the
  TimelineAgent drives it after `get_timeline`.
- **State (`record_finding` **[MUT]**)** → stages a finding as `DRAFT`; the LLM cannot self-approve via
  this surface — promotion requires the HMAC-gated `approve_finding`.

For the agent-to-tool mapping (which agent calls which of these), see
[Tools by agent](tool-by-agent.md). For the exact shape of what any of these tools returns, see
[Response envelope](response-envelope.md).

---

## Related

Sibling pages in this section (04-mcp-tools):

- [Response envelope](response-envelope.md) — the common result shape (`tool_available`,
  `raw_stdout_sha256`, `skipped_reason`, mutation/approval gating) every tool returns.
- [Tools by agent](tool-by-agent.md) — which swarm agent invokes which of these 73 tools.
- [Tool list](tool-list.md) — the flat oracle-derived enumeration of the tool surface.
- [Capability map](capability-map.md) — capabilities-to-tools view of the same surface.

Genuinely related pages elsewhere in the portal:

- [MCP server](../02-architecture/mcp-server.md) — the single FastMCP server that registers
  every `@app.tool()` route described here.
- [Module map](../02-architecture/module-map.md) — the `wrappers/*` and `reports/`/`wazuh/`
  backing modules cited per tool.
- [Agents (index)](../10-agents/README.md) · [Agents list](../10-agents/agents-list.md) — the
  swarm agents that drive the execution, discovery, and state tools.
- [Canonical facts](../08-reference/canonical-facts.md) — the authoritative `mcp_tool_count = 73`
  and `16` forensic-wrapper counts this page reconciles against.
- [Schema reference](../03-data/schema-er.md) · [Data dictionary](../03-data/data-dictionary.md) ·
  [Persisted artifacts](../03-data/persisted-artifacts.md) — the typed reports and case state the
  tools read and write.

Architecture Decision Records (11-ADR) governing the tool boundary:

- [ADR-011 — Evidence gates](../11-ADR/ADR-011-evidence-gates.md) — the `[MUT]` mutation-token model.
- [ADR-016 — Courtroom audit](../11-ADR/ADR-016-courtroom-audit.md) · [ADR-022 — Audit-log seal](../11-ADR/ADR-022-audit-log-seal.md) — the `[APPR]` HMAC approval workflow.
- [ADR-017 — Tailnet MCP exposure](../11-ADR/ADR-017-tailnet-mcp-exposure.md) — the bearer-token,
  tailnet-only middleware on every HTTP-exposed tool.

ADRs that originated specific tools / wrappers in the tables above:

- [ADR-012 — `extract_files` (raw-E01 extraction)](../11-ADR/ADR-012-extract-files.md) — the genesis of
  the `extract_files` (icat) wrapper, its typed Pydantic I/O, and Thymus validation.
- [ADR-013 — `get_evtx` (Windows Event Log wrapper)](../11-ADR/ADR-013-evtx-wrapper.md) — why `get_evtx`
  auto-detects `evtx_dump` output formats.
- [ADR-M6.3 — per-parser sampling + priority filter](../11-ADR/ADR-M6.3-event-window.md) — the Plaso
  wrapper sampling/`max_events` behavior behind `get_timeline`.
- [ADR-014 — credential-dump triage (impacket)](../11-ADR/ADR-014-W072-impacket-secretsdump.md) — the
  vol3 `>=2.27.0` pin and the impacket `secretsdump` credential-dump path.
- [ADR-018 — Wazuh IOC push](../11-ADR/ADR-018-wazuh-ioc-push.md) — the per-PUT HMAC chain-of-custody
  seal behind the `wazuh_publish_iocs` mutation.
- [ADR-024 — Multi-tier report engine](../11-ADR/ADR-024-multi-tier-report-engine.md) — the tiered
  output of `report_generate` / `report_export`.
