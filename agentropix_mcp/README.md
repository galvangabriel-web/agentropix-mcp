# Agentropix MCP — server source

The **Agentropix-SIFT MCP server** package: the FastMCP application that exposes the
72-tool forensic surface (canonical count — the live number is reported by the `health` tool)
to any MCP client (Claude Code, Claude Desktop, or a headless JSON-RPC driver).

## Install

**From the packaged release (fastest):**

```bash
pip install https://github.com/galvangabriel-web/agentropix-mcp/releases/download/v0.2.2/agentropix_mcp-0.2.2-py3-none-any.whl
```

**From a checkout:**

```bash
pip install ./agentropix_mcp                 # core server (fastmcp, pydantic, httpx, sidecar)
pip install "./agentropix_mcp[forensics]"    # + in-process parsers (yara, pytsk3, pypff, oletools, vol3)
pip install "./agentropix_mcp[reports]"      # + report rendering (markdown, weasyprint)
```

Then run the console script (boot is **fail-closed** — it refuses to start without
`AGENTROPIX_MCP_AUTH_TOKEN` unless `AGENTROPIX_MCP_DEV_MODE=1`):

```bash
AGENTROPIX_MCP_AUTH_TOKEN="$(openssl rand -base64 32)" agentropix-mcp --transport http --port 8765
# or stdio (default) for a local Claude Desktop / Claude Code mcp.json `command` entry:
agentropix-mcp
```

The classic SIFT binaries the wrappers drive (`vol`, `fls`/`mmls`/`icat`, `ewfinfo`, `yara`,
`bulk_extractor`, `rip.pl`, Eric Zimmerman tools via `dotnet`, …) are resolved from `PATH`
at call time — they come from the SIFT Workstation itself, not from pip.

**Extras:** `pip install "agentropix-mcp[engine]"` adds the Trinity-Loop / DFIR-swarm runtime
(`trinity/`, `agents/`, `detectors/`); `[forensics]` adds the in-process parsers; `[reports]`
adds report rendering. The MCP server runs without any of these.

## What's in here

| Path | What it is |
|---|---|
| `src/agentropix_mcp/fastmcp_app.py` | The FastMCP app — `@app.tool()` registrations, stdio + streamable-HTTP (`:8765/mcp`) transports, fail-closed Bearer auth |
| `src/agentropix_mcp/server.py` | The shared tool core (`mcp_*` async functions) — the enforcement boundary |
| `src/agentropix_mcp/thymus_policy.py` | Read-only evidence allowlist checked before every tool execution |
| `src/agentropix_mcp/wrappers/` | The forensic tool wrappers (Sleuth Kit, Volatility 3, Plaso, libewf, YARA, bulk_extractor, RegRipper, Eric Zimmerman tools, …) — argv-only subprocess, never a shell |
| `src/agentropix_mcp/wazuh/` | Wazuh SIEM integration (indexer client, CDB-list publisher, kill switch, FP denylists, dashboards) |
| `src/agentropix_mcp/approval_sidecar/` | The Examiner Approval Portal (`:8800`) — the human HMAC hard-stop (PBKDF2-600k challenge-response, in-browser key derivation) |
| `src/agentropix_mcp/trinity/` | The **Trinity Loop** — deterministic `Architect` (plan) + `Critic` (score/halt). LLM-backing deferred; the optional reorder pass is default-off. |
| `src/agentropix_mcp/agents/` | The **DFIR swarm** — 13 `SwarmAgent` classes + the quorum `Blackboard` (`SWARM` run order is load-bearing; `HuntAgent` last). |
| `src/agentropix_mcp/detectors/` | 6 MITRE ATT&CK detector agents + bundled YARA rules (`detectors/yara_rules/`). |
| `src/agentropix_mcp/evidence_gate/` | Single-use `egt_` mutation-token registry (SQLite, atomic verify-and-spend) |
| `src/agentropix_mcp/reports/`, `src/agentropix_mcp/schema/` | Report generation/export (ADR-024 tiers) and the sealed-report JSON schemas |
| `src/agentropix_mcp/security/redact.py` | Fail-closed credential redaction |
| `src/agentropix_mcp/courtroom.py` | HMAC-SHA256 report sealing, audit-log cross-binding |

## Entry points

Installing this package (`pip install ./agentropix_mcp`) provides:

- **`agentropix-mcp`** — the MCP server console script (`agentropix_mcp.fastmcp_app:main`);
  `--transport stdio` (default) or `--transport http --port 8765`. Boot is **fail-closed**:
  it refuses to start without `AGENTROPIX_MCP_AUTH_TOKEN` unless `AGENTROPIX_MCP_DEV_MODE=1`.
- **`python -m agentropix_mcp.approval_sidecar`** — the Examiner Approval Portal (`:8800`).

(The full Agentropix-SIFT distribution additionally ships the `agentropix-sift` triage CLI —
Trinity Loop / DFIR swarm — which is not part of this MCP-server package.)

Client setup (Claude Code / Claude Desktop `mcp.json`, Bearer-token HTTP, the `mcp-remote`
shim for Desktop) is documented in
[docs/09-integrations/client-setup.md](../docs/09-integrations/client-setup.md).
The validated architecture (pattern, guardrails, component-to-source map) is in
[docs/02-architecture/main-architectural-agentropix-design.md](../docs/02-architecture/main-architectural-agentropix-design.md).

> Internal endpoints in code comments are shown as placeholders (`WAZUH-HOST`); configuration
> is environment-driven — no credentials live in this tree.

## Complete file index

The table above is the high-level map; this section indexes every remaining tracked file in the
package so nothing is undocumented. (The curated overview entries are not repeated here.)

### Packaging & package root

| Path | What it is |
|---|---|
| `pyproject.toml` | Hatchling build/packaging config for `agentropix-mcp` v0.3.0 — runtime deps, `[forensics]`/`[reports]`/`[engine]` extras, `requires-python >=3.12`, console scripts |
| `src/agentropix_mcp/__init__.py` | Package init/docstring — governed MCP server for DFIR; declares `__version__` |
| `src/agentropix_mcp/_env.py` | Env-var helper layer for the `AGENTROPIX_*` tuning surface — coerce/clamp ints with floor/ceiling, warn-and-default on bad values |
| `src/agentropix_mcp/_startup_banner.py` | W-088/W-089 startup banner — logs every `AGENTROPIX_*` env var's effective value at boot so tunables aren't silently hardcoded |
| `src/agentropix_mcp/_tool_pins.py` | W-136 pinned-binary integrity check — verifies SHA-256 of each external forensic binary against the pins table at startup (off/warn/strict) |
| `src/agentropix_mcp/_trace.py` | W-032/W-027 per-tool tracing — ContextVar buffer capturing tool, timestamp, duration, args_hash, exit_code for report-schema trace records |
| `src/agentropix_mcp/audit_analyzer.py` | Thymus audit-log analyzer — reads the JSONL audit log and produces summary statistics for security review and incident response |
| `src/agentropix_mcp/config.py` | Configuration loader — reads settings from file or env vars, with Thymus allowed/forbidden-path and per-tool-timeout defaults |
| `src/agentropix_mcp/secrets.py` | W-007 secret-handling — precedence-ordered Telegram-token resolver plus a logging-safe redactor that strips tokens from log records |

### `agents/` — the DFIR swarm

| Path | What it is |
|---|---|
| `agents/__init__.py` | Swarm package surface — exports `Blackboard`, `Correlation`, `Finding`, `SwarmAgent` and the specialist agent classes |
| `agents/_archive.py` | Archive-triage helper — locates the correct dump file inside an extracted evidence tree (e.g. EnCase zips) |
| `agents/_base.py` | Base contract — the `Finding` model and `SwarmAgent` abstraction; each agent investigates one evidence dimension and publishes to the Blackboard |
| `agents/_blackboard.py` | Shared Blackboard for cross-agent finding aggregation and quorum, holding the `asyncio.Lock` so agents stay lock-free |
| `agents/_discovery_detectors.py` | Pure-function Discovery-technique detectors (issue #39) — map (process, command-line) tuples to MITRE technique hits with confidence |
| `agents/_enrichment.py` | MITRE ATT&CK vocabulary enrichment (W-050) — prepends technique text to swarm findings from a stored vocabulary table |
| `agents/_evidence.py` | Evidence-type heuristics — disambiguates ambiguous `.raw` images (memory-wins rule) so disk agents stand down on memory dumps |
| `agents/_hive_presets.py` | Canonical Windows artefact paths (registry/execution hives) the ArtifactAgent uses to drive `mcp_extract_files` over an E01 |
| `agents/_mail_detectors.py` | T1566 (Phishing) detectors for the MailAgent (issue #17) — pure functions over `MailMessage`, each carrying its T1566 sub-technique |
| `agents/_mail_maldoc_chain.py` | W-226 phishing-chain integration — drives `analyze_maldoc()` over spilled attachments and turns the `MacroReport` into `Finding` rows |
| `agents/_mail_parsers.py` | Mail-format detectors/parsers (issue #17) — EML/MSG/PST/OST extraction via stdlib `email`, `extract_msg`, and `pypff` |
| `agents/_suspicious.py` | Configurable suspicious-name matching for MemoryAgent/FilesystemAgent — literal-set + regex layers from operator file / env / built-in defaults |
| `agents/artifact.py` | ArtifactAgent — chain-of-custody + registry/execution-evidence specialist; chains `extract_files` → registry wrappers on E01/EWF images |
| `agents/discovery.py` | DiscoveryAgent (issue #39) — detects MITRE Discovery techniques (T1018/T1069/T1083/T1087/T1135) from EID 4688 events on the Blackboard |
| `agents/filesystem.py` | FilesystemAgent — Sleuth Kit (`mcp_fls`) directory-walk specialist; flags deleted/known-bad entries, NTFS ADS, timestomp, prefetch |
| `agents/hunt.py` | HuntAgent — cross-source correlation specialist; promotes any token flagged by ≥2 agents into a high-confidence correlation finding |
| `agents/mail.py` | MailAgent (issue #17) — detects MITRE T1566 (Phishing) sub-techniques from PST/OST/MSG/EML mail artifacts |
| `agents/memory.py` | MemoryAgent — Volatility (`mcp_get_pslist`) volatile-evidence specialist; flags suspicious/orphan processes, optional credential triage |
| `agents/timeline.py` | TimelineAgent — Plaso (`mcp_get_timeline`) temporal-correlation specialist; flags scripting-host/LOLBin execution events |

### `detectors/` — MITRE ATT&CK detector agents

| Path | What it is |
|---|---|
| `detectors/__init__.py` | Specialist detector package surface — enumerates the YARA-hunt, injection, IEX-loopback-C2, IFEO-hijack, and svchost-outbound detectors |
| `detectors/injection_detector.py` | InjectionDetector — Volatility `windows.malfind`-driven in-memory process-injection detection (T1055.x); closes W-052-T6 |
| `detectors/t1059_001_iex_loopback_c2.py` | IexLoopbackC2Detector — flags PowerShell ScriptBlock (EID 4104) IEX + downloader + loopback-URI C2 stagers (T1059.001); closes W-205 |
| `detectors/t1071_001_svchost_outbound_http.py` | T1071SvchostOutboundHttpDetector — flags `svchost.exe` outbound HTTP to non-Microsoft public IPs (T1071.001); closes W-215 |
| `detectors/t1087_002_null_session_baseline.py` | W-207 T1087.002 null-session baseline detector — flags burst counts of EID 4624 ANONYMOUS-LOGON (S-1-5-7) / LogonType 3 records |
| `detectors/t1546_008_accessibility_ifeo_hijack.py` | T1546.008 detector — accessibility-binary IFEO `Debugger` hijack (write + exec legs); closes W-204 |
| `detectors/yara_hunt.py` | YARAHuntAgent — signature-based Cobalt Strike stager detection via cached `.yar` rule matching; closes W-052-T2 |
| `detectors/yara_rules/cobalt_strike/cobalt_strike_artifacts.yar` | YARA rule — Cobalt Strike SMB beacon default named-pipe templates |
| `detectors/yara_rules/cobalt_strike/cobalt_strike_beacon_gen3.yar` | YARA rule — Cobalt Strike Gen3 beacon (XOR-encoded config) |
| `detectors/yara_rules/cobalt_strike/cobalt_strike_beacon_gen4.yar` | YARA rule — Cobalt Strike Gen4 beacon (AES HTTPS C2) |
| `detectors/yara_rules/cobalt_strike/cobalt_strike_loader.yar` | YARA rule — Cobalt Strike loader (reflective PE injection sequence) |

### `trinity/` — the Trinity Loop

| Path | What it is |
|---|---|
| `trinity/__init__.py` | Trinity Loop surface (W-029) — Architect → Swarm → Critic feedback wrapper; exposes `Architect`, `Critic`, `TrinityResult` (deterministic, LLM-backing deferred) |
| `trinity/architect.py` | Architect — picks (and may narrow) the swarm slice for the next iteration; Reflexion-lite drops Critic-flagged `stable` agents behind a flag |
| `trinity/critic.py` | Critic — scores a Blackboard pass (top confidence + correlation count) and decides whether the loop halts |

### `evidence_gate/` — mutation-token registry

| Path | What it is |
|---|---|
| `evidence_gate/__init__.py` | Evidence-gate token regime (Step 2, SIFT-W-A11) — public `verify`/`verify_and_spend` API with atomic spend, replay protection, expiry, revocation |
| `evidence_gate/cli.py` | CLI for the Step-2 evidence gate — `mint`/`verify`/`revoke`/`revoke-by-id`/`list` (validation-plan layers L3.2/L6) |
| `evidence_gate/errors.py` | Exception hierarchy for the evidence gate — `TokenError` base + format/not-found/spent/expired/revoked variants |
| `evidence_gate/registry.py` | SQLite-backed token registry — atomic verify+spend, expiry, revocation in serialized transactions |

### `reports/` — multi-tier report engine (ADR-024)

| Path | What it is |
|---|---|
| `reports/__init__.py` | ADR-024 report-engine surface — one canonical finding set projected into analyst/executive/business tiers, rendered MD→HTML→PDF |
| `reports/diagrams.py` | ADR-024 Mermaid diagram builders (kill-chain, process tree, IOC graph) — width-constrained, text-safe fenced blocks for deterministic prerender |
| `reports/export.py` | ADR-024 Phase 5 export orchestration — projects `sections` into tier view models and renders the requested tier/format (PDF capability-gated) |
| `reports/markdown.py` | ADR-024 per-tier Markdown(+Mermaid) renderers — the single source of truth from which HTML/PDF derive; pure view-model-in, string-out |
| `reports/render.py` | ADR-024 render pipeline — Markdown source → HTML (pure-pip `markdown`) → PDF (behind a capability check) |
| `reports/transformers.py` | ADR-024 no-drift transformers — `sections` dict → three tier view models, each carrying its `analyst_finding_id`/`anchor` back-reference |
| `reports/view_models.py` | ADR-024 tier view models — presentation projections over the canonical `ReportGenerateResult.sections` (KPI rollups, risk score, back-anchors) |

### `schema/` — typed result schemas

| Path | What it is |
|---|---|
| `schema/__init__.py` | Typed result-schema package — Pydantic models for MCP tool returns that own a non-trivial schema surface |
| `schema/extract_archive.py` | W-095 typed result schema for the `extract_archive` tool — per-entry shape mirrors `ExtractedFile` for unified manifests |
| `schema/pdf_extract_text.py` | W-103 typed result schema for `pdf_extract_text` — one row per requested page plus document-level metadata + chain-of-custody anchors |
| `schema/master_iocs.schema.json` | JSON Schema for `MASTER-IOCS.json` produced by `master_iocs_aggregator` (W-203), additive over the legacy iocs-only shape |
| `schema/report.schema.json` | JSON Schema for the Agentropix-SIFT Triage Report (version/image/iterations/findings/status/trace) |

### `security/` — credential redaction

| Path | What it is |
|---|---|
| `security/__init__.py` | Security-helpers surface (W-203) — re-exports `redact_finding`, `RedactionError`, `REDACTOR_KEY_ENV` |
| `security/redact.py` | Shared credential-redaction layer (W-203) — HMAC-tagged `[REDACTED-<tag>]` over arbitrary trees with depth/size/ReDoS guards |

### `approval_sidecar/` — Examiner Approval Portal

| Path | What it is |
|---|---|
| `approval_sidecar/__init__.py` | SIFT-W-288 sidecar surface — the separate `:8800` process that alone can move a finding DRAFT → APPROVED |
| `approval_sidecar/__main__.py` | SIFT-W-294/W-295 ops launcher — `python -m agentropix_mcp.approval_sidecar` entry point with env-var validation |
| `approval_sidecar/app.py` | SIFT-W-288 Starlette routes — `/healthz`, `/challenge` (nonce), `/approve` (signed approval write) |
| `approval_sidecar/auth.py` | SIFT-W-288 PBKDF2 key derivation + HMAC-SHA256 signature primitives — mirrors the browser Web Crypto contract so server/client can't drift |
| `approval_sidecar/config.py` | SIFT-W-288 sidecar configuration — `SidecarConfig.from_env()` matching the `WazuhConfig.from_env()` pattern |
| `approval_sidecar/hash_chain.py` | SIFT-W-288 hash-chain helpers for `agentropix-approvals-*` — deterministic `approval_id` over the approval's immutable fields |
| `approval_sidecar/models.py` | SIFT-W-288 Pydantic request/response models — field shape matches the strict-dynamic approvals index template |
| `approval_sidecar/nonce.py` | SIFT-W-288 in-memory TTL nonce store — single-use `consume()` defeats challenge-response replay |
| `approval_sidecar/writer.py` | SIFT-W-294 IndexerClient-backed `ApprovalWriter` — writes `agentropix-approvals-*` docs via the dedicated approver credential + prev-hash backfill |
| `approval_sidecar/static/index.html` | SIFT-W-294 approval-portal browser UX — Web Crypto API derives the PBKDF2 key client-side from the operator's password |

### `wazuh/` — Wazuh SIEM integration

| Path | What it is |
|---|---|
| `wazuh/__init__.py` | Wazuh IOC-push package surface — discover → filter → transform → push to CDB lists + rules pack → restart → HMAC seal → audit |
| `wazuh/ar_guard.py` | W-189 active-response protected-CIDR allowlist scaffold — guards against a mis-classified IP being blocked fleet-wide |
| `wazuh/client.py` | WazuhClient — sole owner of the `httpx.AsyncClient`; `_request` enforces Thymus validation + evidence-token verify before any PUT/POST |
| `wazuh/config.py` | WazuhConfig — typed configuration reader (precedence pattern from `secrets`); read-once-at-construction, no global state |
| `wazuh/dashboards/__init__.py` | WZ-022/W-278 dashboard saved-objects surface — exposes the NDJSON bundle paths and parsed contents for shape-locking tests |
| `wazuh/dashboards/builders.py` | SIFT-W-295 programmatic dashboard builders — deterministic generators that replace the hand-authored NDJSON so the 17-object bundle can't drift |
| `wazuh/dashboards/agentropix-findings.ndjson` | Wazuh Dashboard saved-objects bundle (NDJSON) for the `agentropix-findings-*` index pattern and visualizations |
| `wazuh/denylists.py` | Hard-coded Tier-3 denylists + normalised/regex/provenance-aware IOC filters for the Wazuh push integration |
| `wazuh/evidence_gate.py` | Wazuh write-path mutation-token verification — fails closed (raises `EvidenceGateRequired`) if the verifier can't be imported |
| `wazuh/finding_to_alert.py` | Agentropix finding → Wazuh alert mapper — converts structured DFIR findings into Wazuh-native alerts for Indexer ingestion |
| `wazuh/health.py` | WLV-06 CDB-load health probe — surfaces manager warning code 7616 so a CDB-load regression is discoverable within ~30 s |
| `wazuh/index_templates.py` | WZ-022/SIFT-W-285 index-template constants — plain dicts passed verbatim to `IndexerClient.put_index_template()` |
| `wazuh/indexer_client.py` | WZ-002 Wazuh Indexer client — OpenSearch fork on :9200; foundation for retro-hunt and vuln-query tools |
| `wazuh/inventory.py` | Case-inventory loader — walks a case directory and builds typed `IOCRecord`s into an `IOCInventory` (FR-1) |
| `wazuh/ism_policies.py` | WZ-022/W-277/SIFT-W-287 Index State Management (ISM) policies for Agentropix indices (index lifecycle automation) |
| `wazuh/models.py` | Pydantic v2 data models for the Wazuh IOC push — `IPvAnyAddress` validation, discriminated-union `IOCRecord` |
| `wazuh/orchestrator.py` | Wazuh IOC-push orchestrator — main `push_iocs()` entry point implementing the full design §3 happy-path sequence |
| `wazuh/prioritise.py` | IOC priority classifier — stateless Tier-1/2/3 scoring rubric plus the Tier-3 hard exclusions |
| `wazuh/seal.py` | Courtroom seal for the Wazuh push — ADR-016 HMAC-SHA256 with a per-run session key (not plain sha256) |
| `wazuh/tag_schema.py` | IOC tag schema — canonical parser for Agentropix CDB-list entries (`<value>:<case_id>|<confidence>|<context>`) |
| `wazuh/thymus_bridge.py` | Thymus bridge — thin shim over the STRICT validator; single import point so the wazuh package avoids MCP-tree circular deps |

### `wrappers/` — forensic tool wrappers

| Path | What it is |
|---|---|
| `wrappers/__init__.py` | Wrapper package surface — subprocess, parse, return typed Pydantic per SIFT tool |
| `wrappers/_hunt_ioc_dsl.py` | WZ-001 DSL builders for `wazuh_hunt_ioc` (Step-2 retro-hunt query construction) |
| `wrappers/_mail_parsers.py` | Mail-format detectors/parsers shared by the mail wrappers (issue #17) |
| `wrappers/_safe_tool.py` | WZ-021 `_safe_tool` decorator — uniform tool-call safety wrapping |
| `wrappers/_status.py` | Uniform tool-response status taxonomy (WS-A keystone) |
| `wrappers/_subprocess.py` | Shared subprocess utilities — memory monitoring and managed (argv-only, killable) execution |
| `wrappers/_versions.py` | Tool version checking — verifies forensic-tool compatibility |
| `wrappers/_vuln_query_dsl.py` | W-186 DSL builder for `wazuh_vuln_query` |
| `wrappers/amcache.py` | Amcache.hve wrapper — execution evidence from the application cache |
| `wrappers/bstrings.py` | bstrings wrapper — Eric Zimmerman regex-backed string extractor |
| `wrappers/bulk_extractor.py` | `bulk_extractor` feature-scanner wrapper |
| `wrappers/case_ingest.py` | SIFT-W-290 `idx_ingest` — structured ingest of normalized findings + timeline events |
| `wrappers/case_lifecycle.py` | SIFT-W-289 case-lifecycle MCP wrappers (P0 tools) |
| `wrappers/case_queries.py` | SIFT-W-290 `idx_*` query MCP wrappers |
| `wrappers/case_records.py` | SIFT-W-291 wrappers — `record_finding`/`record_timeline_event`/`approve_finding`/`report_generate` |
| `wrappers/correlation.py` | Correlation tools — W-150 cross-artifact analysis layer |
| `wrappers/credentials.py` | impacket-secretsdump LOCAL wrapper — offline credential triage (W-072 / ADR-014) |
| `wrappers/disk_container.py` | W-171 dynamic-disk container unwrapper |
| `wrappers/editbox.py` | SIFT-W-209 Volatility 2.6 `editbox` plugin subprocess wrapper |
| `wrappers/email_header_matrix.py` | W-172 email-header matrix MCP wrapper (closes GH #17 MailAgent gap) |
| `wrappers/email_headers.py` | Agent-layer wrapper — EML/MSG corpus → per-message header matrix with SPF/DKIM/DMARC |
| `wrappers/evt.py` | Legacy Windows EventLog (`.evt`) parser — NIST1 RUN1 ISSUE-008 |
| `wrappers/evtx.py` | Windows Event Log (`.evtx`) parser wrapper |
| `wrappers/ewf.py` | EWF/E01 image metadata wrapper — `ewfinfo` |
| `wrappers/executable_registry.py` | Executable Artifact Registry (EAR) Phase 1 — `build_executable_registry` |
| `wrappers/exiftool.py` | ExifTool wrapper — metadata extraction from files and directories |
| `wrappers/extract.py` | TSK file-extraction wrapper — `icat`-based content retrieval |
| `wrappers/extract_archive.py` | W-095 archive-extraction wrapper for the MCP boundary |
| `wrappers/foremost.py` | `foremost` file carver wrapper |
| `wrappers/glob_paths.py` | W-084 glob-based path enumeration primitive for MCP self-enumeration |
| `wrappers/gpt_parser.py` | W-170 GPT (GUID Partition Table) parser wrapper |
| `wrappers/hashdeep.py` | hashdeep wrapper — multi-algorithm file hashing and hash-set audit |
| `wrappers/ioc_registry.py` | IOC promotion pipeline (BUG-004) — populates `agentropix-iocs-*` |
| `wrappers/jlecmd.py` | JLECmd wrapper — Eric Zimmerman Windows Jump List parser |
| `wrappers/lecmd.py` | LECmd wrapper — Eric Zimmerman `.lnk` shortcut parser (W-127) |
| `wrappers/maldoc.py` | Maldoc analysis via python-oletools |
| `wrappers/master_iocs_aggregator.py` | MASTER-IOCS aggregator (W-203) |
| `wrappers/memory_mail_carve.py` | Memory→EML carve sidecar — extracts email artifacts from memory dumps so MailAgent can run T1566 on memory-only hosts |
| `wrappers/mftecmd.py` | MFTECmd wrapper — Eric Zimmerman NTFS artifact parser (W-126) |
| `wrappers/observations.py` | WZ-021 Observation parent + discriminated-union submodels for read-back tool results |
| `wrappers/pdf_extract_text.py` | W-103 PDF text-extraction wrapper for the MCP boundary |
| `wrappers/plaso.py` | Plaso/log2timeline wrappers — super-timeline generation |
| `wrappers/prefetch.py` | Windows Prefetch parser wrapper — execution-evidence extraction |
| `wrappers/pst_carve.py` | W-210 PST carve + attachment-hash IOC index MCP wrapper |
| `wrappers/recmd.py` | RECmd wrapper — Eric Zimmerman registry hive parser (W-125) |
| `wrappers/regripper.py` | RegRipper wrapper — registry hive analysis via `rip.pl` |
| `wrappers/sbecmd.py` | SBECmd wrapper — Eric Zimmerman ShellBags Explorer |
| `wrappers/scheduled_tasks.py` | Scheduled-task (T1053.005) extractor — reads `Windows/System32/Tasks` XML |
| `wrappers/shimcache.py` | Shimcache (AppCompatCache) wrapper — execution evidence in the SYSTEM hive |
| `wrappers/sqlecmd.py` | SQLECmd wrapper — Eric Zimmerman SQLite parser |
| `wrappers/srum.py` | SRUM (System Resource Usage Monitor) parser wrapper (SIFT-W-283) |
| `wrappers/strings.py` | GNU strings wrapper — printable-sequence extraction from binaries |
| `wrappers/threat_intel.py` | Live threat-intelligence lookups via VirusTotal v3 and AlienVault OTX (W-118) |
| `wrappers/tsk.py` | Sleuth Kit (TSK) wrappers — filesystem listing via `fls` |
| `wrappers/volatility.py` | Volatility 3 wrappers — memory-forensics process listing |
| `wrappers/wazuh_intel.py` | `wazuh_check_intel` — operator-facing CDB membership check |
| `wrappers/wazuh_tools.py` | Wazuh FastMCP tool registrations — Step 1 IOC push integration |
| `wrappers/yara.py` | YARA signature-scanning wrapper |
| `wrappers/yara_forge.py` | Yara Forge bundle wrapper — vendored, content-addressed ruleset |

### `tests/` — constraint-bypass test evidence

See [`tests/README.md`](tests/README.md) for the full suite descriptions (evidence-gate policy, W-108/W-109 hardening, chaos fault-paths).

| Path | What it is |
|---|---|
| `tests/__init__.py` | Test package init |
| `tests/unit/__init__.py` | Unit-test package init |
| `tests/unit/test_thymus_policy.py` | Locks the read/write allowlist contract — reads only from evidence zones, all writes rejected, audit ring, symlink-target validation |
| `tests/unit/test_w108_w109_thymus_hardening.py` | Evidence-gate bypass attempts — encoded traversal (W-108), PATH_MAX guard (W-109), null-byte / `/proc` / `/etc/shadow` no-regression |
| `tests/chaos/__init__.py` | Chaos-test package init |
| `tests/chaos/test_fault_paths.py` | Mock-based fault injection — Plaso/bulk_extractor/extract cleanup + subprocess-kill-on-timeout paths that fixed real bugs (`pytest.mark.chaos`) |
