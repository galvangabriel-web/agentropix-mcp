# Module Map (shared reference)

> Package/module inventory under `src/agentropix_sift/`. Purpose + key files, derived by reading the
> tree and module docstrings. Use this to pick the right citation when authoring chapters.

Repo root of the package: `/home/admin2/agentropix-sift/src/agentropix_sift/`.
Python 3.12+. Console scripts (`pyproject.toml`): `agentropix-sift = agentropix_sift.cli:main`,
`agentropix-sift-mcp = agentropix_sift.mcp_server.fastmcp_app:main`.

## Top-level modules (single-file)

| Module | Purpose | Key symbols |
|--------|---------|-------------|
| `cli.py` | Typer CLI entrypoint. `run` (triage an image), `doctor` (pre-flight the 16 SIFT binaries). Seals the report on write. | `main()`, `doctor()`, `_DOCTOR_ENV_OVERRIDES` |
| `orchestrator.py` | Drives the `SWARM` over one evidence image under the Trinity Loop; rolls findings + trace into a schema-compliant `TriageReport`. | `TriageReport`, `run_triage()` |
| `courtroom.py` | Chain-of-custody crypto (ADR-016/022): `evidence_image_sha256`, HMAC-SHA256 `seal_report`/`verify_seal`, session-key write (0600), audit-log sealing + cross-binding. | `evidence_image_sha256`, `seal_report`, `verify_seal`, `write_sealed_report`, `seal_audit_log`, `write_sealed_session` |
| `secrets.py` | Secret/token loading helpers (file-pointer form preferred over inline). | secret resolution helpers |

## Packages

### `agents/` — the DFIR swarm
Eleven+ specialist `SwarmAgent` subclasses writing to a shared `Blackboard`; HuntAgent runs last to
correlate. See `.crew/agents-list.md` for the per-agent breakdown.
| Key file | Purpose |
|----------|---------|
| `__init__.py` | Defines the ordered `SWARM` tuple (13 classes) + public surface |
| `_base.py` | `Finding` (Pydantic), `SwarmAgent` ABC, per-agent finding cap (`AGENTROPIX_AGENT_FINDING_CAP`) |
| `_blackboard.py` | `Blackboard` (asyncio finding registry, quorum), `Correlation`, token extraction |
| `memory.py`/`timeline.py`/`filesystem.py`/`artifact.py`/`discovery.py`/`mail.py`/`hunt.py` | The 7 core specialist agents |
| `_enrichment.py`, `_evidence.py`, `_suspicious.py`, `_discovery_detectors.py`, `_mail_*` , `_hive_presets.py`, `_archive.py` | Shared helper logic for the agents |

### `trinity/` — Architect → Swarm → Critic loop
| Key file | Purpose |
|----------|---------|
| `architect.py` | `Architect` — deterministic planner; returns canonical `SWARM`, may prune stable agents |
| `critic.py` | `Critic` + `TrinityResult` — deterministic score (max conf + 0.25·#correlations), fixed-point fingerprint halt (default threshold 0.85, no LLM self-rating) |

### `mcp_server/` — the single FastMCP server (71 tools)
| Key file | Purpose |
|----------|---------|
| `fastmcp_app.py` | Registration site for the 67 in-module tools (+5 wazuh wrappers); `main()` server entry |
| `server.py` | Tool dispatch helpers (`mcp_get_pslist`, `mcp_fls`, …), `ToolError`, `configure_policy` |
| `thymus_policy.py` | **Thymus read-only evidence policy (S-02)** — path allowlist enforcement + audit ring at the MCP boundary |
| `config.py` | `load_config()` / `get_config()` config merge |
| `_env.py` | `AGENTROPIX_*` env-var readers with floor/ceiling clamping (`get_int`, `get_float`, …) |
| `_trace.py` | Per-tool-call trace capture (`trace_scope`, raw-output snapshots) |
| `_tool_pins.py`, `_versions.py` | Tool-pin verification; `REQUIRED_TOOLS` version checks |
| `audit_analyzer.py`, `_startup_banner.py`, `_status.py` | Audit analysis, boot banner, status taxonomy |
| `wrappers/` | ~40 forensic wrapper modules (see below) |

### `mcp_server/wrappers/` — forensic tool drivers
Thin protocol-drivers around the 16 SIFT binaries + EZ-Tools + correlation/mail. Each ships
timeout/memory-ceiling/retry/stderr-capture/tracing.
| Group | Files |
|-------|-------|
| SIFT-16 core | `volatility.py`, `plaso.py`, `tsk.py`, `extract.py`, `ewf.py`, `evtx.py`, `yara.py`, `bulk_extractor.py`, `regripper.py`, `prefetch.py`, `amcache.py`, `shimcache.py`, `exiftool.py`, `foremost.py`, `hashdeep.py`, `strings.py` |
| EZ Tools | `recmd.py`, `mftecmd.py`, `lecmd.py`, `jlecmd.py`, `sbecmd.py`, `sqlecmd.py`, `bstrings.py`, `srum.py` |
| Imaging/partition | `disk_container.py`, `gpt_parser.py`, `ewf.py` |
| Eventlog/timeline | `evt.py`, `evtx.py`, `correlation.py` |
| Mail/maldoc/docs | `maldoc.py`, `pst_carve.py`, `email_header_matrix.py`, `email_headers.py`, `pdf_extract_text.py` |
| Memory adjunct | `editbox.py`, `credentials.py` (impacket secretsdump, W-072/ADR-014) |
| Case/findings/IOC | `case_lifecycle.py`, `case_records.py`, `case_ingest.py`, `case_queries.py`, `ioc_registry.py`, `executable_registry.py`, `observations.py`, `scheduled_tasks.py`, `glob_paths.py` |
| Wazuh/intel | `wazuh_intel.py`, `wazuh_tools.py`, `threat_intel.py` |
| Internals | `_safe_tool.py`, `_subprocess.py`, `_status.py`, `_versions.py`, `_hunt_ioc_dsl.py`, `_vuln_query_dsl.py` |

### `wrappers/` (top-level, NOT `mcp_server/wrappers`)
| Key file | Purpose |
|----------|---------|
| `__main__.py` | `python -m agentropix_sift.wrappers` entrypoint |
| `email_headers.py` | Canonical email-header parser (the `mcp_server/wrappers/email_headers.py` is a shim, issue #44) |
| `master_iocs_aggregator.py` | Aggregates case IOCs into `MASTER-IOCS.json` (validates against `schema/master_iocs.schema.json`; HMAC via `AGENTROPIX_MASTER_IOCS_HMAC_KEY`) |
| `memory_mail_carve.py` | Carves email headers from memory images (MailAgent) |

### `evidence_gate/` — mutation-token regime
| Key file | Purpose |
|----------|---------|
| `registry.py` | `TokenRow` (frozen dataclass), `TokenRegistry` (SQLite mint/spend/revoke, one-shot, TTL) |
| `cli.py` | `agentropix-sift evidence-gate` token ops (`mint`, …) |
| `errors.py` | Gate error types |

### `provenance/` — chain validation
| Key file | Purpose |
|----------|---------|
| `validate.py` | `ValidateReport`, `validate_dir()`, per-row HMAC seal verification (`_verify_one_row`, `_row_canonical_sans_seal`); CLI `main()` |

### `security/` — redaction
| Key file | Purpose |
|----------|---------|
| `redact.py` | HMAC-keyed deterministic scalar redaction of findings (`redact_finding`, `RedactionError`, key from `AGENTROPIX_REDACTOR_HMAC_KEY`) |

### `audit/` — seal verification
| Key file | Purpose |
|----------|---------|
| `verify_seal.py` | Standalone verifier for report + audit-log HMAC seals |

### `memory/` — Hippocampus bridge (opt-in)
| Key file | Purpose |
|----------|---------|
| `hippocampus_bridge.py` | `ReasoningTrace` (Pydantic), `HippocampusBridge` Lamarckian recall (opt-in via `AGENTROPIX_HIPPOCAMPUS_ENABLED`, top-k `AGENTROPIX_HIPPOCAMPUS_TOP_K`) |

### `approval_sidecar/` — HMAC human-in-the-loop service
| Key file | Purpose |
|----------|---------|
| `app.py` | Starlette HMAC approval service (`__main__.py` entrypoint) |
| `models.py` | Challenge/submit request+response models; `ApprovalStatus`, `TargetType` |
| `auth.py`, `nonce.py`, `hash_chain.py`, `writer.py`, `config.py` | PBKDF2 auth, nonce TTL, append-only hash chain, OpenSearch writer, config |
| `static/` | Browser approval form assets |

### `wazuh/` — SIEM integration
| Key file | Purpose |
|----------|---------|
| `models.py` | IOC record family (`IPIOCRecord`, `SHA256IOCRecord`, …), `IOCProvenance`, `IOCInventory`, `CDBPayload`, `Decision` |
| `client.py`, `indexer_client.py` | Wazuh Manager API (`:55000`) + Indexer (`:9200`) clients |
| `orchestrator.py`, `batch_push.py`, `prioritise.py` | Push orchestration, batching, prioritisation |
| `ar_guard.py`, `denylists.py` | Active-response guard (protected CIDRs `AGENTROPIX_AR_PROTECTED_CIDRS`), denylists |
| `evidence_gate.py`, `thymus_bridge.py`, `seal.py` | Cross-binding to evidence gate / Thymus / seal |
| `finding_to_alert.py`, `tag_schema.py`, `index_templates.py`, `ism_policies.py`, `inventory.py`, `health.py`, `config.py` | Finding→alert mapping, tag schema, index templates, ISM retention, inventory, health, config |
| `dashboards/` | Wazuh dashboard definitions |

### `detectors/` — deterministic ATT&CK detector agents
| Key file | Purpose · ATT&CK |
|----------|------------------|
| `yara_hunt.py` | `YARAHuntAgent` — YARA-driven hunting (T1055 family) |
| `injection_detector.py` | `InjectionDetector` — process injection (T1055.001/.002) |
| `t1087_002_null_session_baseline.py` | `NullSessionBaselineAgent` — null-session account discovery (T1087.002) |
| `t1546_008_accessibility_ifeo_hijack.py` | `AccessibilityIfeoHijackDetector` — IFEO/accessibility hijack (T1546.008) |
| `t1059_001_iex_loopback_c2.py` | `IexLoopbackC2Detector` — PowerShell IEX loopback C2 (T1059.001) |
| `t1071_001_svchost_outbound_http.py` | `T1071SvchostOutboundHttpDetector` — svchost outbound HTTP (T1071.001) |
| `yara_rules/` | Vendored YARA rules |

### `chromosomes/` — agent presets
| Key file | Purpose |
|----------|---------|
| `senior-analyst.yaml` | Senior-analyst "chromosome" preset (agent tuning profile) |

### `imaging/` — image lifecycle
| Key file | Purpose |
|----------|---------|
| `ewf_lifecycle.py` | E01/EWF mount lifecycle (ewfmount setup/teardown, `AGENTROPIX_EWF_LIFECYCLE_*`) |

### `reports/` — report rendering
| Key file | Purpose |
|----------|---------|
| `render.py`, `markdown.py`, `export.py`, `transformers.py`, `view_models.py`, `diagrams.py` | Tiered report generation/export, view models, Mermaid diagram emission |

### `schema/` — typed result schemas + JSON Schemas
| Key file | Purpose |
|----------|---------|
| `report.schema.json` | Triage report JSON Schema (draft 2020-12) |
| `master_iocs.schema.json` | MASTER-IOCS envelope schema |
| `extract_archive.py`, `pdf_extract_text.py` | Pydantic tool-return models (`ArchiveEntry`/`ExtractArchiveManifest`, `PdfPage`/`PdfDocument`) |

### `benchmarks/`
Benchmark harness scaffolding (Theme 2 time-to-decision; mostly pending per `CANONICAL_FACTS.md`).
