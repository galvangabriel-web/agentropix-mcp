# MCP Tool List (shared reference)

> The full **72** distinct MCP tools exposed by the single FastMCP server. Derived from
> `docs/tools/_TOOL-CATALOGUE.md` (live-derived) cross-checked against
> `src/agentropix_sift/mcp_server/fastmcp_app.py` and `src/agentropix_sift/mcp_server/wrappers/`.
> **72 distinct tool functions** = 72 `@app.tool()` decorator occurrences (67 in `fastmcp_app.py`
> + 5 in the wazuh wrappers — verified against oracle HEAD `88844e98` and the live `tools/list`,
> 2026-06-11). Canonical fact: `mcp_tool_count = 72`.
> The running server's `tools/list` is the authoritative arg schema.

## The 16 SIFT forensic tools (the wrapped binaries)

The canonical "**16 forensic wrappers / 16 SIFT tools**" (`README.md:151`, `CHANGELOG.md:449`)
refers to the underlying SIFT command-line forensic binaries that the wrapper layer drives and that
`agentropix-sift doctor` (`src/agentropix_sift/cli.py:176-196`) pre-flights. They are marked
**[SIFT-16]** in the tables below where the tool drives one of them. The 16 binaries:

| # | Binary | Provides | Wrapper module |
|---|--------|----------|----------------|
| 1 | `vol` (Volatility3) | Memory forensics | `wrappers/volatility.py` |
| 2 | `log2timeline.py` (Plaso) | Super timeline | `wrappers/plaso.py` |
| 3 | `fls` (Sleuth Kit) | Filesystem listing | `wrappers/tsk.py` |
| 4 | `icat` (Sleuth Kit) | File extraction | `wrappers/extract.py` |
| 5 | `mmls` (Sleuth Kit) | Partition table | `wrappers/tsk.py` / `gpt_parser.py` |
| 6 | `ewfinfo` (libewf) | E01 image metadata | `wrappers/ewf.py` |
| 7 | `evtx_dump.py` (python-evtx) | Windows `.evtx` logs | `wrappers/evtx.py` |
| 8 | `yara` | Pattern matching | `wrappers/yara.py`, `yara_forge.py` |
| 9 | `bulk_extractor` | Feature scanning | `wrappers/bulk_extractor.py` |
| 10 | `rip.pl` (RegRipper) | Registry hives | `wrappers/regripper.py` |
| 11 | `pf` | Prefetch parsing | `wrappers/prefetch.py` |
| 12 | `amcache_parser` | Amcache execution evidence | `wrappers/amcache.py` |
| 13 | `shimcache_parser` | Shimcache (AppCompatCache) | `wrappers/shimcache.py` |
| 14 | `exiftool` | File metadata | `wrappers/exiftool.py` |
| 15 | `foremost` | File carving | `wrappers/foremost.py` |
| 16 | `hashdeep` | Multi-algorithm hashing / audit | `wrappers/hashdeep.py` |

> Also pre-flighted by `doctor`: `strings`, `ssdeep`, `ifind` (Sleuth Kit). The CHANGELOG M4→M6.2
> highlight lists the 16/16 wrappers shipped with timeout/memory-ceiling/retry/stderr-capture/tracing.
> Additional EZ-Tools (`RECmd`, `MFTECmd`, `LECmd`, `JLECmd`, `SBECmd`, `SQLECmd`, `bstrings`,
> `SRUM`) ship as their own wrappers on top of the core 16.

---

## Auth / mutation model (applies across the catalogue)

| Mechanism | Applies to | Source |
|---|---|---|
| Bearer-token middleware | All HTTP-exposed tools (tailnet-only) | ADR-017 |
| `mutation_token` arg | `record_finding`, `idx_ingest`, `promote_iocs`, `promote_executable_registry`, `wazuh_index_findings`, `wazuh_publish_iocs` | per-tool signature; ADR-011 |
| `password` (HMAC approval) | `approve_finding`, `retract_approval` | approval sidecar; ADR-016/022 |
| `dry_run` guard | all promote/ingest/publish/delete tools | per-tool signature |

---

## Full categorized tool table (71)

Legend: **[SIFT-16]** = drives one of the 16 SIFT forensic binaries. **[MUT]** = state-mutating
(requires `mutation_token`). **[APPR]** = HMAC approval-gated.

### Case & session (4)
| Tool | Category | Purpose | Backing module |
|------|----------|---------|----------------|
| `case_init` | case | Create a case context | `wrappers/case_lifecycle.py` |
| `case_activate` | case | Set the active case | `wrappers/case_lifecycle.py` |
| `case_status` | case | Report case state | `wrappers/case_lifecycle.py` |
| `health` | server | Server health + tool count | `mcp_server/fastmcp_app.py` |

### Evidence intake & disk imaging (10)
| Tool | Category | Purpose | Backing module |
|------|----------|---------|----------------|
| `evidence_register` | evidence | Register evidence file in the case | `wrappers/case_lifecycle.py` |
| `get_image_info` | imaging | E01/raw image metadata · **[SIFT-16]** ewfinfo | `wrappers/ewf.py` |
| `get_partitions` | imaging | List partitions (mmls) · **[SIFT-16]** | `wrappers/tsk.py` |
| `parse_gpt` | imaging | Parse GUID partition table | `wrappers/gpt_parser.py` |
| `unwrap_disk_container` | imaging | Unwrap dynamic-disk container | `wrappers/disk_container.py` |
| `extract_files` | filesystem | Extract files from image (icat) · **[SIFT-16]** | `wrappers/extract.py` |
| `extract_archive` | filesystem | Safe archive extraction | `wrappers/extract_archive.py` + `schema/extract_archive.py` |
| `fls` | filesystem | List filesystem entries (Sleuth Kit) · **[SIFT-16]** | `wrappers/tsk.py` |
| `list_files` | filesystem | List files on a mounted path | `wrappers/tsk.py` |
| `glob_paths` | filesystem | Glob path matching | `wrappers/glob_paths.py` |

### Memory forensics — Volatility (7)
| Tool | Category | Purpose | Backing module |
|------|----------|---------|----------------|
| `run_volatility` | memory | Arbitrary Volatility3 plugin · **[SIFT-16]** | `wrappers/volatility.py` |
| `get_pslist` | memory | Process list · **[SIFT-16]** | `wrappers/volatility.py` |
| `build_process_tree` | memory | Process tree correlation | `wrappers/correlation.py` |
| `get_malfind` | memory | Injected/RWX VAD detection · **[SIFT-16]** | `wrappers/volatility.py` |
| `get_netscan` | memory | Network connections · **[SIFT-16]** | `wrappers/volatility.py` |
| `get_svcscan` | memory | Service scan · **[SIFT-16]** | `wrappers/volatility.py` |
| `get_editbox` | memory | Vol2.6 editbox (UI text) | `wrappers/editbox.py` |

### Registry, execution & shell artifacts — EZ Tools / RegRipper (16)
| Tool | Category | Purpose | Backing module |
|------|----------|---------|----------------|
| `get_registry` | registry | RegRipper hive analysis · **[SIFT-16]** rip.pl | `wrappers/regripper.py` |
| `get_amcache` | execution | Amcache execution evidence · **[SIFT-16]** | `wrappers/amcache.py` |
| `get_shimcache` | execution | Shimcache (AppCompatCache) · **[SIFT-16]** | `wrappers/shimcache.py` |
| `get_prefetch` | execution | Prefetch parsing · **[SIFT-16]** pf | `wrappers/prefetch.py` |
| `get_recmd` | registry | RECmd (EZ Tools) | `wrappers/recmd.py` |
| `get_mftecmd` | filesystem | MFTECmd NTFS artifact parser | `wrappers/mftecmd.py` |
| `get_lecmd` | artifacts | LECmd `.lnk` parser | `wrappers/lecmd.py` |
| `get_jlecmd` | artifacts | JLECmd Jump List parser | `wrappers/jlecmd.py` |
| `get_sbecmd` | artifacts | SBECmd ShellBags parser | `wrappers/sbecmd.py` |
| `get_sqlecmd` | artifacts | SQLECmd SQLite parser | `wrappers/sqlecmd.py` |
| `srum_extract` | artifacts | SRUM resource-usage extract | `wrappers/srum.py` |
| `get_bstrings` | strings | bstrings regex string extractor | `wrappers/bstrings.py` |
| `exec_registry_get` | EAR | Read executable registry | `wrappers/executable_registry.py` |
| `exec_registry_search` | EAR | Search executable registry | `wrappers/executable_registry.py` |
| `build_executable_registry` | EAR | Build executable registry (dry-runnable) | `wrappers/executable_registry.py` |
| `promote_executable_registry` **[MUT]** | EAR | Promote executable registry | `wrappers/executable_registry.py` |

### Event logs & timeline (6)
| Tool | Category | Purpose | Backing module |
|------|----------|---------|----------------|
| `get_evt` | eventlog | Legacy `.evt` parser | `wrappers/evt.py` |
| `get_evtx` | eventlog | Windows `.evtx` parser · **[SIFT-16]** evtx_dump.py | `wrappers/evtx.py` |
| `get_timeline` | timeline | Plaso super timeline · **[SIFT-16]** log2timeline.py | `wrappers/plaso.py` |
| `correlate_timeline` | timeline | Cross-host timeline correlation | `wrappers/correlation.py` |
| `detect_sweep` | timeline | Lateral-movement sweep detection | `wrappers/correlation.py` |
| `record_timeline_event` | timeline | Append a timeline event to the case | `wrappers/case_records.py` |

### Mail / maldoc / documents (4)
| Tool | Category | Purpose | Backing module |
|------|----------|---------|----------------|
| `analyze_maldoc` | maldoc | oletools maldoc analysis | `wrappers/maldoc.py` |
| `carve_pst_iocs` | mail | PST carve + attachment-hash IOC index | `wrappers/pst_carve.py` |
| `email_header_matrix` | mail | Email-header matrix across a corpus | `wrappers/email_header_matrix.py` |
| `pdf_extract_text` | documents | PDF text extraction | `wrappers/pdf_extract_text.py` + `schema/pdf_extract_text.py` |

### File analysis & carving (6)
| Tool | Category | Purpose | Backing module |
|------|----------|---------|----------------|
| `run_strings` | strings | GNU strings extraction · **[SIFT-16]** strings | `wrappers/strings.py` |
| `run_bulk_extractor` | carving | bulk_extractor feature scan · **[SIFT-16]** | `wrappers/bulk_extractor.py` |
| `run_foremost` | carving | Foremost file carving · **[SIFT-16]** | `wrappers/foremost.py` |
| `run_exiftool` | metadata | ExifTool metadata · **[SIFT-16]** | `wrappers/exiftool.py` |
| `run_hashdeep` | hashing | hashdeep hashing/audit · **[SIFT-16]** | `wrappers/hashdeep.py` |
| `scan_yara` | hunting | YARA scan · **[SIFT-16]** yara | `wrappers/yara.py` / `yara_forge.py` |

### Findings, IOCs & reporting (7)
| Tool | Category | Purpose | Backing module |
|------|----------|---------|----------------|
| `record_finding` **[MUT]** | findings | Persist a finding to the case | `wrappers/case_records.py` |
| `delete_finding` | findings | Remove a finding (audited) | `wrappers/case_records.py` |
| `promote_iocs` **[MUT]** | iocs | Promote case IOCs (MASTER-IOCS) | `wrappers/ioc_registry.py` |
| `pivot_on_ioc` | iocs | Pivot across images on an IOC | `wrappers/ioc_registry.py` |
| `threat_intel_lookup` | intel | VirusTotal / OTX lookup | `wrappers/threat_intel.py` |
| `report_generate` | reporting | Generate triage report | `reports/render.py` |
| `report_export` | reporting | Export report tier/format | `reports/export.py` |

### Approval workflow — HMAC sidecar (2)
| Tool | Category | Purpose | Backing module |
|------|----------|---------|----------------|
| `approve_finding` **[APPR]** | approval | HMAC-signed examiner approval | `approval_sidecar/` |
| `retract_approval` **[APPR]** | approval | Compensating retraction (append-only) | `approval_sidecar/` |

### Indexer — OpenSearch (5)
| Tool | Category | Purpose | Backing module |
|------|----------|---------|----------------|
| `idx_ingest` **[MUT]** | indexer | Ingest findings/timeline | `wrappers/case_ingest.py` |
| `idx_search` | indexer | Search indexed case data | `wrappers/case_queries.py` |
| `idx_aggregate` | indexer | Aggregate over a field | `wrappers/case_queries.py` |
| `idx_timeline` | indexer | Time-bucketed timeline query | `wrappers/case_queries.py` |
| `idx_case_summary` | indexer | Case summary rollup | `wrappers/case_queries.py` |

### Wazuh SIEM integration (5)
| Tool | Category | Purpose | Backing module |
|------|----------|---------|----------------|
| `wazuh_hunt_ioc` | wazuh | Hunt an IOC across Wazuh indices | `wrappers/wazuh_intel.py` / `wazuh_tools.py` |
| `wazuh_check_intel` | wazuh | Check IOC against CDB lists | `wrappers/wazuh_intel.py` |
| `wazuh_index_findings` **[MUT]** | wazuh | Index findings into Wazuh | `wrappers/wazuh_tools.py` |
| `wazuh_publish_iocs` **[MUT]** | wazuh | Publish IOCs to CDB lists | `wrappers/wazuh_tools.py` |
| `wazuh_vuln_query` | wazuh | Query vuln/CVE data | `wrappers/wazuh_intel.py` |

---

**Total: 4 + 10 + 7 + 16 + 6 + 4 + 6 + 7 + 2 + 5 + 5 = 72 rows listed; `wazuh_hunt_ioc` is the
double-registered tool, so distinct tool functions = 71.** (The catalogue notes the 74→71
reconciliation: 74 decorator occurrences, `wazuh_hunt_ioc` registered in two modules.) When an exact
count matters in a chapter, cite `mcp_tool_count = 72` from [`canonical-facts.md`](../08-reference/canonical-facts.md) and re-query the live
`tools/list`. Backing-module attributions for a few tools are best-effort from wrapper names; confirm
against `fastmcp_app.py` registration before asserting a non-obvious module in prose.

---

## Related

**Sibling 04-mcp-tools references:**

- [Tool reference](tool-reference.md) — the master per-tool reference (args, envelopes, examples).
- [Tools by agent](tool-by-agent.md) — which swarm agent invokes which of these tools.
- [Capability map](capability-map.md) — tools grouped by forensic capability.
- [Response envelope](response-envelope.md) — the common result shape every tool returns.

**Related elsewhere in the portal:**

- [MCP server architecture](../02-architecture/mcp-server.md) — the single FastMCP server that
  registers and exposes these 72 tools.
- [Swarm agents](../10-agents/README.md) · [Agents list](../10-agents/agents-list.md) — the agents
  that call these tools.
- [Canonical facts](../08-reference/canonical-facts.md) — oracle for `mcp_tool_count = 72`, the 16
  forensic wrappers, and other figures cited above.
- [Data dictionary](../03-data/data-dictionary.md) — the case artifacts the mutating tools persist.

**Relevant ADRs:**

- [ADR-017 — Tailnet MCP exposure](../11-ADR/ADR-017-tailnet-mcp-exposure.md) — bearer-token
  middleware for all HTTP-exposed tools.
- [ADR-011 — Evidence-type gate consolidation](../11-ADR/ADR-011-evidence-gates.md) — the shared
  evidence-type helper and `mutation_token` model behind the **[MUT]** tools.
- [ADR-016 — Courtroom audit](../11-ADR/ADR-016-courtroom-audit.md) · [ADR-022 — Audit-log seal](../11-ADR/ADR-022-audit-log-seal.md)
  — the HMAC approval / append-only model behind `approve_finding` and `retract_approval`.
