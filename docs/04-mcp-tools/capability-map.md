# Tool Capability Map (by DFIR function)

> **Section 04 · MCP Tools** — the 71-tool surface grouped by what an examiner is trying to *do*,
> so you can pick the right tool for a phase of an investigation rather than scanning an alphabetical list.
> The platform's **71 tools** (`mcp_tool_count = 71`, cite [`.crew/facts.md`](../../.crew/facts.md))
> group into DFIR functions below.

Related: [Tool reference](tool-reference.md) (the master 71-tool index) ·
[Tools by agent](tool-by-agent.md) · [Response envelope](response-envelope.md) ·
[User Guide](../01-overview/user-guide.md) (the end-to-end runbook this page supports) ·
[`.crew/tool-list.md`](../../.crew/tool-list.md) (the full per-tool catalogue).

---

## The capability map

The bucket counts below sum to the **62-tool** inventory enumerated in the validated 2026-05-29 run;
the current platform total is **71** (cite [`.crew/facts.md`](../../.crew/facts.md):
`mcp_tool_count = 71`). The full per-tool catalogue — with backing modules and mutation/approval
flags — is in [`.crew/tool-list.md`](../../.crew/tool-list.md) and
[Tool reference](tool-reference.md).

| DFIR function | Tools | Notes |
|---|---|---|
| **Discovery / health / meta** | `health`, `get_image_info` | `health.tool_count` is the source of truth for the live inventory; `get_image_info` = `ewfinfo` E01 metadata |
| **Disk / container / partition / path** | `parse_gpt`, `get_partitions`, `unwrap_disk_container`, `glob_paths`, `list_files` (+`get_image_info`) | `get_partitions` = `mmls`; `unwrap_disk_container` converts VHD/VMDK/QCOW2→raw with SHA-256; `glob_paths`/`list_files` Thymus-gated |
| **Memory / Volatility** | `get_pslist`, `run_volatility`, `get_netscan`, `get_malfind`, `get_svcscan`, `get_editbox`, `build_process_tree` | vol3 plugins; `build_process_tree` = PPID forest + LOLBin flags + DKOM orphans |
| **Registry & execution artifacts** | `get_registry`, `get_amcache`, `get_shimcache`, `get_recmd`, `get_sbecmd` | `get_amcache` is Win7+ only (XP has none); `get_sbecmd` = ShellBags |
| **Filesystem / MFT / TSK** | `fls`, `extract_files`, `get_mftecmd`, `get_lecmd`, `get_jlecmd` | `fls` lists deleted (T1070.004); `offset` in **sectors**; `get_mftecmd` = $MFT/$J/$I30 |
| **Timeline** | `get_timeline`, `correlate_timeline` | plaso super-timeline; `correlate_timeline` merges EVTX across hosts into one UTC stream |
| **Event logs / execution / SRUM** | `get_evtx`, `get_evt`, `get_prefetch`, `srum_extract` | `get_evtx` = `.evtx` (Vista+); legacy XP `.evt` is handled by `get_evt`; `srum_extract` = per-process net bytes (Win8+) |
| **Email / PST** | `email_header_matrix`, `carve_pst_iocs` | SPF/DKIM/DMARC matrix; PST→per-message + per-attachment IOC report |
| **YARA / carve / strings / hash / meta / maldoc / archive / PDF / SQLite** | `scan_yara`, `run_bulk_extractor`, `run_foremost`, `run_strings`, `get_bstrings`, `run_hashdeep`, `run_exiftool`, `analyze_maldoc`, `extract_archive`, `pdf_extract_text`, `get_sqlecmd` | `run_bulk_extractor` = feature carving (emails/IPs/URLs); `analyze_maldoc` = olevba/oleid/rtfobj |
| **IOC pivot / detection analytics** | `pivot_on_ioc`, `detect_sweep` | substring hunt across artifacts/hosts; SMB share-enum burst detector |
| **Threat intel (egress-gated)** | `threat_intel_lookup` | VT/OTX; needs `AGENTROPIX_ALLOW_EGRESS=1`, else no network call |
| **Wazuh** | `wazuh_check_intel`, `wazuh_hunt_ioc`, `wazuh_vuln_query`, `wazuh_publish_iocs`, `wazuh_index_findings` | last two are **mutations** (need `dry_run=False` + `egt_<ULID>` token) |
| **Case / findings / reporting / index** | `case_init`, `case_activate`, `case_status`, `evidence_register`, `record_finding`, `record_timeline_event`, `approve_finding`, `report_generate`, `idx_ingest`, `idx_search`, `idx_aggregate`, `idx_timeline`, `idx_case_summary` | case-scoped; `record_finding`/`idx_ingest` are draft-gated mutations; `approve_finding` is human-only |

---

## Cross-cutting conventions

Most subprocess tools accept `timeout_seconds` (clamped, safe to raise per-call without a server
restart). Auto-tempdir tools (`extract_files`, `extract_archive`, `run_bulk_extractor`,
`run_foremost`, `unwrap_disk_container`) create a fresh Thymus-allowed `/tmp/agentropix-sift-*` dir
when `dest`/`out_dir` is omitted. **Thymus** path policy gates every path: out-of-allowlist paths
are silently dropped, `..` is rejected, symlinks dropped unless opted in. The EZ-Tools (.NET) family
is `get_recmd`, `get_mftecmd`, `get_lecmd`, `get_jlecmd`, `get_sbecmd`, `get_sqlecmd`, `get_bstrings`.

---

## Canonical happy-path ordering

```text
case_init (or case_activate to resume)
  → evidence_register
    → [ANALYSIS primitives]
      → record_finding / idx_ingest          (stage DRAFT)
        → approve_finding                     (human, DRAFT → APPROVED)
          → wazuh_index_findings / idx_ingest(dry_run=False)
            → report_generate
```

This ordering is the spine of the [User Guide](../01-overview/user-guide.md)'s 8 phases. The analysis
primitives in the middle are case-agnostic and **not** auto-persisted — you turn an analysis result
into case state by shaping it into `record_finding`/`idx_ingest`.

---

## Related

- [Tool reference](tool-reference.md) — the master categorized index of all 71 tools.
- [Tools by agent](tool-by-agent.md) — which swarm agent invokes which tools.
- [Response envelope](response-envelope.md) — the common result shape every tool returns.
- [User Guide](../01-overview/user-guide.md) — the end-to-end operator runbook.
- [`.crew/tool-list.md`](../../.crew/tool-list.md) · [`.crew/facts.md`](../../.crew/facts.md) — oracle references.
