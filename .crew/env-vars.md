# Environment Variables (shared reference)

> Every environment variable that configures Agentropix-SIFT, from `.env.example` (documented,
> with defaults) and from code (`grep -rhoE "AGENTROPIX_[A-Z0-9_]+" src/`). Defaults are quoted from
> code where confirmed; `(unverified)` marks a default not read from source. Secrets use the
> file-pointer form (`*_FILE`) in preference to inline. `.env` is gitignored, mode 0600.

Sources: `/home/admin2/agentropix-sift/.env.example`; `src/agentropix_sift/**/*.py`.

## 1. Documented in `.env.example` (Wazuh integration, auth, approval sidecar)

### MCP server auth (W-235, W-242)
| Var | Default | Description |
|-----|---------|-------------|
| `AGENTROPIX_MCP_AUTH_TOKEN` | — (required) | Bearer token for HTTP-exposed tools; mint with `secrets.token_urlsafe(32)` |
| `AGENTROPIX_MCP_DEV_MODE` | unset | Dev-mode opt-in; NOT sufficient alone — also needs `AGENTROPIX_BUILD_PROFILE=dev` + `AGENTROPIX_HTTP_HOST=127.0.0.1`. Boots with ephemeral per-start token |
| `AGENTROPIX_BUILD_PROFILE` | unset | Intentional dev opt-in marker (`dev`) |
| `AGENTROPIX_HTTP_HOST` | unset / loopback | Loopback bind only for dev-mode (`127.0.0.1`) |

### Connectivity & Wazuh API (ADR-017 tailnet-only)
| Var | Default | Description |
|-----|---------|-------------|
| `WAZUH_MANAGER_URL` | placeholder | Wazuh Manager API base (`:55000`) |
| `WAZUH_INDEXER_URL` | placeholder | Wazuh Indexer base (`:9200`) |
| `AGENTROPIX_WAZUH_API_USER` | placeholder | Manager API user |
| `AGENTROPIX_WAZUH_API_PASSWORD_FILE` | unset | File pointer to API password (preferred) |
| `AGENTROPIX_WAZUH_API_PASSWORD` | placeholder | Inline API password (fallback only) |
| `WAZUH_INDEXER_USER` / `WAZUH_INDEXER_PASS` | placeholder | Indexer Basic Auth (separate from manager creds) |

### Wazuh kill switches & safety
| Var | Default | Description |
|-----|---------|-------------|
| `WAZUH_INTEGRATION_ENABLED` | `false` | Master enable for Wazuh integration |
| `WAZUH_PUSH_ENABLED` | `false` | Enable IOC push (write) |
| `WAZUH_DRY_RUN_ONLY` | `true` | Force dry-run for all mutations |
| `AGENTROPIX_INTEGRATION_NOT_PRODUCTION` | `false` | Operator affirmation target Wazuh is NOT prod (W-188 round-trip gate; default-deny) |
| `AGENTROPIX_AR_PROTECTED_CIDRS` | RFC-1918 + loopback/ULA/link-local | CIDRs active-response must NEVER block (extends defaults) |
| `AGENTROPIX_AR_SAFE_CIDR_ALLOWLIST` | unset | DEPRECATED alias of the above (fallback, DeprecationWarning) |

### TLS (ADR-016 S-4 / ADR-018)
| Var | Default | Description |
|-----|---------|-------------|
| `WAZUH_TLS_VERIFY` | `true` | Manager TLS verify; `false` only allowed when `AGENTROPIX_ENV=development` |
| `WAZUH_TLS_CA_BUNDLE` | unset | CA bundle path |
| `WAZUH_INDEXER_TLS_VERIFY` | unset → falls back to `WAZUH_TLS_VERIFY` | Independent indexer TLS verify (W-181) |
| `AGENTROPIX_ENV` | unset | `development` allows insecure TLS on dev workstations |

### Rate limiting / timeouts / paths / namespace (Wazuh)
| Var | Default | Description |
|-----|---------|-------------|
| `WAZUH_WRITE_RATE_PER_SEC` | `5` | Write rate cap |
| `WAZUH_RESTART_TIMEOUT_SEC` | `90` | Restart timeout |
| `WAZUH_JWT_REFRESH_AT_SEC` | `890` | JWT refresh interval |
| `WAZUH_AUDIT_LOG` | `/var/log/agentropix/wazuh-audit.jsonl` | Wazuh audit log |
| `WAZUH_DLQ_DIR` | `/var/lib/agentropix/wazuh-dlq` | Dead-letter queue dir |
| `WAZUH_LIST_NAMESPACE` | `agentropix_` | CDB list namespace prefix |
| `WAZUH_IP_ALLOWLIST` | `127.0.0.1,::1` | Allowlisted IPs |
| `WAZUH_ALLOWED_HOSTS` | empty | Allowed hosts |
| `WAZUH_SMOKE` | `0` | Smoke-test flag |

### Mutation token (evidence gate)
| Var | Default | Description |
|-----|---------|-------------|
| `AGENTROPIX_MUTATION_TOKEN` | unset | One-shot mutation token (`egt_…`); mint with `agentropix-sift evidence-gate mint`. Source from env, never CLI flag |

### W-188 round-trip / step-6 test gates
| Var | Default | Description |
|-----|---------|-------------|
| `AGENTROPIX_RUNNER_CASE_DIR` | unset | Operator case dir with `MASTER-IOCS.json` for live runner |
| `AGENTROPIX_W188_HUNT_CAP` | `5` | Cap on IOCs hunted post-push |
| `AGENTROPIX_L2_6_CHECK_CAP` | `3` | Cap on IOCs in `wazuh_check_intel` test |
| `AGENTROPIX_RUNNER_HEADLESS_CONFIRM` | unset (`YES` to confirm) | Headless confirmation for step 6 |

### Approval sidecar (SIFT-W-288/294/296)
| Var | Default | Description |
|-----|---------|-------------|
| `AGENTROPIX_APPROVER_USER` | unset | Examiner identity (must match browser form) |
| `AGENTROPIX_APPROVER_PASSWORD` | unset | PBKDF2 source key; MUST stay stable across restarts |
| `AGENTROPIX_APPROVER_SALT_HEX` | unset | Per-examiner 16-byte hex PBKDF2 salt; MUST stay stable |
| `AGENTROPIX_APPROVAL_SIDECAR_HOST` | `127.0.0.1` | Sidecar bind host (0.0.0.0 only behind TLS nginx) |
| `AGENTROPIX_APPROVAL_SIDECAR_PORT` | `8800` | Sidecar bind port |
| `AGENTROPIX_APPROVAL_SIDECAR_NONCE_TTL` | `60` | Challenge nonce TTL (s) |
| `AGENTROPIX_APPROVAL_SIDECAR_PBKDF2_ITERATIONS` | `600000` | PBKDF2 iterations |
| `AGENTROPIX_APPROVER_INDEXER_USER` / `_PASSWORD` | unset | Separate approvals-write OpenSearch role (Crew #3 dual-credential split) |
| `AGENTROPIX_APPROVAL_SIDECAR_DEV_MODE` | unset (`1`) | Dev fallback to writer creds (logged loudly) |
| `AGENTROPIX_APPROVAL_SIDECAR_URL` | `http://127.0.0.1:8800` | URL the W-295 dashboard deep-links to |

## 2. Core orchestration & Trinity (code-derived defaults)

| Var | Default | Description | Source |
|-----|---------|-------------|--------|
| `AGENTROPIX_CRITIC_HALT_THRESHOLD` | `0.85` | Critic deterministic halt score threshold | `trinity/critic.py:42` |
| `AGENTROPIX_CRITIC_MIN_ITERATIONS` | (gates early halt) | Min iterations before halt allowed | `trinity/critic.py` |
| `AGENTROPIX_TRINITY_FEEDBACK` | `0` (off) | Opt-in Reflexion-lite feedback channel | `CHANGELOG.md` / trinity |
| `AGENTROPIX_AGENT_FINDING_CAP` | `500` (floor 10, ceiling 10000) | Per-agent per-run finding cap | `agents/_base.py:37` |
| `AGENTROPIX_TOKEN_MIN_LENGTH` | `3` (floor 1, ceiling 10) | Min correlation token length | `agents/_blackboard.py` |
| `AGENTROPIX_TOKEN_ALLOWLIST` | built-in short tokens | Allowlisted short correlation tokens | `agents/_blackboard.py` |
| `AGENTROPIX_HIPPOCAMPUS_ENABLED` | `0` (off) | Opt-in Lamarckian recall | `memory/hippocampus_bridge.py` |
| `AGENTROPIX_HIPPOCAMPUS_TOP_K` | `3` (floor 1, ceiling 50) | Top-k traces recalled | `memory/hippocampus_bridge.py` |
| `AGENTROPIX_RUN_ID` | generated | Run identifier (ledger/trace) | `mcp_server` |
| `AGENTROPIX_LOG_LEVEL` | `WARNING` | Log level | `mcp_server/_env` |
| `AGENTROPIX_CONFIG` | unset | Config file path override | `mcp_server/config.py` |

## 3. Safety / courtroom / evidence

| Var | Default | Description | Source |
|-----|---------|-------------|--------|
| `AGENTROPIX_EVIDENCE_SHA256` | `""` | Operator-supplied evidence image digest when auto-hash unavailable | `courtroom.py` |
| `AGENTROPIX_TRACE_RAW_MAX_BYTES` | `4096` (4 KiB) | Bound on pre-LLM raw-output trace snapshot | `mcp_server/_trace.py` |
| `AGENTROPIX_AUDIT_LOG` / `AGENTROPIX_AUDIT_LOG_DIR` | system log dir | On-disk Thymus JSONL audit (chain of custody) | `thymus_policy.py` |
| `AGENTROPIX_THYMUS_ALLOWED_PREFIXES` | built-in READONLY_PATHS | Extra read-only path prefixes | `thymus_policy.py` |
| `AGENTROPIX_THYMUS_AUDIT_LOG_RING_SIZE` | `1000` (floor 100, ceiling 100000) | In-memory audit ring size | `thymus_policy.py` |
| `AGENTROPIX_MAX_AUTO_PREFIXES` | `50` | Cap on auto-allowed evidence-dir prefixes | `thymus_policy.py` |
| `AGENTROPIX_EVIDENCE_GATE_DB` | default path | SQLite mutation-token registry | `evidence_gate/registry.py` |
| `AGENTROPIX_REQUIRE_IOC_PROVENANCE` | unset | When set, IOC records without `IOCProvenance` raise `ProvenanceMissingError` | `wazuh/models.py:178` |
| `AGENTROPIX_REDACTOR_HMAC_KEY` | — | HMAC key for deterministic finding redaction | `security/redact.py` |
| `AGENTROPIX_MASTER_IOCS_HMAC_KEY` | — | HMAC key for MASTER-IOCS aggregation seal | `wrappers/master_iocs_aggregator.py` |
| `AGENTROPIX_VERIFY_TOOL_PINS` | unset | Verify tool binary pins on startup | `mcp_server/_tool_pins.py` |
| `AGENTROPIX_ALLOW_EGRESS` | `0` (off) | Gate for any network egress (threat-intel) | `mcp_server/_env` |

## 4. Resource ceilings (server-wide)

| Var | Default | Description |
|-----|---------|-------------|
| `AGENTROPIX_MEM_LIMIT_MB` | `""` (unset) | Per-tool memory ceiling (MB) |
| `AGENTROPIX_MAX_RETRIES` | `2` | Subprocess retry count |
| `AGENTROPIX_RATE_LIMIT` | `60` (floor 1, ceiling 10000) | Tool-call rate limit |
| `AGENTROPIX_MCP_RESULT_MAX_BYTES` | `900000` | Max tool-result payload bytes |
| `AGENTROPIX_MIN_DISK_MB` | (unverified) | Min free disk before a run |
| `AGENTROPIX_MCP_ACCESS_LOG` | (unverified) | MCP access log path |

## 5. Per-wrapper tuning (pattern catalogue)

Each forensic wrapper exposes a consistent set. Defaults are per-tool; read the wrapper for exact
values. The common patterns:

| Pattern | Example vars | Meaning |
|---------|--------------|---------|
| `AGENTROPIX_<TOOL>_TOOL` | `AGENTROPIX_FLS_TOOL`, `AGENTROPIX_EXIFTOOL_TOOL`, `AGENTROPIX_YARA_TOOL`, `AGENTROPIX_BE_TOOL`, `AGENTROPIX_VOL26_BIN`, `AGENTROPIX_SECRETSDUMP_TOOL`, `AGENTROPIX_ICAT_TOOL`, `AGENTROPIX_MMLS_TOOL`, `AGENTROPIX_FSSTAT_TOOL`, `AGENTROPIX_IFIND_TOOL`, `AGENTROPIX_ISTAT_TOOL`, `AGENTROPIX_EVTX_TOOL`, `AGENTROPIX_SRUM_TOOL`, `AGENTROPIX_FOREMOST_TOOL`, `AGENTROPIX_HASHDEEP_TOOL`, `AGENTROPIX_STRINGS_TOOL`, `AGENTROPIX_PREFETCH_TOOL`, `AGENTROPIX_AMCACHE_TOOL`, `AGENTROPIX_SHIMCACHE_TOOL`, `AGENTROPIX_EWFMOUNT_TOOL` | Override the binary path (lets `doctor`/wrapper point at a SIFT-installed binary) |
| `AGENTROPIX_<TOOL>_TIMEOUT[_S]` | `AGENTROPIX_VOL_TIMEOUT`, `AGENTROPIX_PLASO_TIMEOUT`, `AGENTROPIX_TSK_TIMEOUT`, `AGENTROPIX_YARA_TIMEOUT`, `AGENTROPIX_EVTX_TIMEOUT`, `AGENTROPIX_EXIFTOOL_TIMEOUT`, `AGENTROPIX_FOREMOST_TIMEOUT`, `AGENTROPIX_BE_TIMEOUT`, `AGENTROPIX_HASHDEEP_TIMEOUT`, `AGENTROPIX_STRINGS_TIMEOUT`, `AGENTROPIX_REGRIPPER_TIMEOUT`, `AGENTROPIX_RECMD_TIMEOUT`, `AGENTROPIX_MFTECMD_TIMEOUT`, `AGENTROPIX_GPT_TIMEOUT`, `AGENTROPIX_SRUM_TIMEOUT`, `AGENTROPIX_EDITBOX_TIMEOUT_S`, `AGENTROPIX_PDF_EXTRACT_TIMEOUT` | Subprocess timeout |
| `AGENTROPIX_<TOOL>_MAX_*` | `AGENTROPIX_YARA_MAX_FILES`, `AGENTROPIX_YARA_MAX_MATCHES`, `AGENTROPIX_BE_MAX_FEATURES`, `AGENTROPIX_EXIFTOOL_MAX_FILES`, `AGENTROPIX_HASHDEEP_MAX_FILES`, `AGENTROPIX_STRINGS_MAX_RESULTS`, `AGENTROPIX_FOREMOST_MAX_ENTRIES`, `AGENTROPIX_PLASO_MAX_EVENTS`, `AGENTROPIX_EVTX_MAX_EVENTS`, `AGENTROPIX_TIMELINE_MAX_EVENTS`, `AGENTROPIX_LIST_FILES_MAX_RESULTS`, `AGENTROPIX_ARCHIVE_MAX_BYTES`, `AGENTROPIX_EXTRACT_MAX_BYTES`, `AGENTROPIX_MEMDUMP_MAX_BYTES`, `AGENTROPIX_MALFIND_DUMP_MAX_BYTES`, `AGENTROPIX_PDF_MAX_PAGES`, `AGENTROPIX_PDF_MAX_CHARS` | Output/size caps |
| Plaso-specific | `AGENTROPIX_PLASO_PARSERS`, `AGENTROPIX_PLASO_WORKERS`, `AGENTROPIX_PLASO_PRIORITY_BUDGET`, `AGENTROPIX_PLASO_PER_PARSER_BUDGET`, `AGENTROPIX_PLASO_EXCLUDE_FAMILIES`, `AGENTROPIX_PLASO_TIMEOUT_CAP`, `AGENTROPIX_PSORT_TIMEOUT` | Timeline tuning |
| EZ-Tools `_DLL` | `AGENTROPIX_RECMD_DLL`, `AGENTROPIX_MFTECMD_DLL`, `AGENTROPIX_LECMD_DLL`, `AGENTROPIX_JLECMD_DLL`, `AGENTROPIX_SBECMD_DLL`, `AGENTROPIX_SQLECMD_MAPS_DIR`, `AGENTROPIX_BSTRINGS_DLL` | Pointers to EZ-Tools assemblies/maps |
| Agent tuning | `AGENTROPIX_MEMORY_SUSPICIOUS_PROCS`, `AGENTROPIX_MEMORY_ORPHAN_CONFIDENCE`, `AGENTROPIX_FS_SUSPICIOUS_FILENAMES`, `AGENTROPIX_TIMELINE_LOLBINS`, `AGENTROPIX_ARTIFACT_FORMATS`, `AGENTROPIX_DISC_MIN_CONFIDENCE`, `AGENTROPIX_HUNT_CONFIDENCE_BONUS`, `AGENTROPIX_MAIL_LOOKALIKE_DISTANCE`, `AGENTROPIX_NULL_SESSION_Z_THRESHOLD`, `AGENTROPIX_IEX_LOOPBACK_ALLOWLIST_PORTS`, `AGENTROPIX_T1071_SVCHOST_PORTS`, `AGENTROPIX_IFEO_CORRELATION_WINDOW_SEC` | Per-agent confidence/threshold knobs |

## 6. Threat-intel & integrations (egress-gated)

| Var | Default | Description |
|-----|---------|-------------|
| `AGENTROPIX_VT_API_KEY` | unset | VirusTotal v3 key (no key on this host → omit) |
| `AGENTROPIX_OTX_API_KEY` | unset | AlienVault OTX key |
| `AGENTROPIX_TI_PROVIDERS` | provider list | Enabled threat-intel providers |
| `AGENTROPIX_TI_TIMEOUT` | (unverified) | Threat-intel lookup timeout |
| `AGENTROPIX_TELEGRAM_BOT_TOKEN` / `_TOKEN` / `_TOKEN_FILE` | unset | Telegram notification token (file form preferred) |

## 7. OpenSearch index / ISM (case data store)

`AGENTROPIX_<KIND>_INDEX_PATTERN`, `_TEMPLATE`, `_TEMPLATE_NAME`, `_RETENTION_DAYS`,
`_ISM_POLICY_NAME`, `_ISM_RETENTION_DAYS` for `FINDINGS`, `IOCS`, `TIMELINE`, `EVIDENCE`, `CASES`,
`REPORTS`, `APPROVALS` (+ `AGENTROPIX_APPROVALS_HOT_DAYS`, `_ISM_HOT_DAYS`). Govern index naming and
ISM retention. Defaults are per-kind; read `wazuh/index_templates.py` / `wazuh/ism_policies.py`.

> The full `AGENTROPIX_*` namespace exceeds 200 vars (mostly per-wrapper timeout/cap/tool-path
> triples). This reference lists the load-bearing ones with confirmed defaults plus the naming
> patterns for the rest. When a chapter needs an exact per-wrapper default, read the wrapper module.
