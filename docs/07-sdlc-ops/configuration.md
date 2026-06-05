# Configuration — The `AGENTROPIX_*` Environment Surface

> The full environment-variable surface that configures Agentropix-SIFT, with confirmed
> defaults from code and `.env.example`. Secrets prefer the file-pointer form (`*_FILE`);
> `.env` is gitignored and mode 0600. The complete namespace exceeds 200 vars (mostly
> per-wrapper timeout/cap/tool-path triples); this chapter lists the load-bearing ones and
> the naming patterns for the rest. When you need an exact per-wrapper default, read the
> wrapper module.

All values are sourced from [env-vars](../../.crew/env-vars.md), `.env.example`, and the
source modules cited inline. `(unverified)` marks a default not confirmed from code.

---

## 1. MCP server auth & exposure (W-235, W-242)

| Var | Default | Description |
|-----|---------|-------------|
| `AGENTROPIX_MCP_AUTH_TOKEN` | — (required) | Bearer token for HTTP-exposed tools; mint with `secrets.token_urlsafe(32)` |
| `AGENTROPIX_MCP_DEV_MODE` | unset | Dev opt-in; NOT sufficient alone — also needs `AGENTROPIX_BUILD_PROFILE=dev` + loopback bind. Boots with an ephemeral per-start token |
| `AGENTROPIX_BUILD_PROFILE` | unset | Intentional dev opt-in marker (`dev`) |
| `AGENTROPIX_HTTP_HOST` | unset / loopback | Loopback bind only for dev-mode (`127.0.0.1`) |

See [security-model](security-model.md#4-server-exposure--auth) for why dev-mode requires all
three conditions.

---

## 2. Core orchestration & Trinity

| Var | Default | Description | Source |
|-----|---------|-------------|--------|
| `AGENTROPIX_CRITIC_HALT_THRESHOLD` | `0.85` | Critic deterministic halt score threshold | `trinity/critic.py:42` |
| `AGENTROPIX_CRITIC_MIN_ITERATIONS` | (gates early halt) | Min iterations before halt allowed | `trinity/critic.py` |
| `AGENTROPIX_TRINITY_FEEDBACK` | `0` (off) | Opt-in Reflexion-lite feedback channel | trinity |
| `AGENTROPIX_AGENT_FINDING_CAP` | `500` (floor 10, ceiling 10000) | Per-agent per-run finding cap | `agents/_base.py:37` |
| `AGENTROPIX_TOKEN_MIN_LENGTH` | `3` (floor 1, ceiling 10) | Min correlation token length | `agents/_blackboard.py` |
| `AGENTROPIX_TOKEN_ALLOWLIST` | built-in short tokens | Allowlisted short correlation tokens | `agents/_blackboard.py` |
| `AGENTROPIX_HIPPOCAMPUS_ENABLED` | `0` (off) | Opt-in Lamarckian recall | `memory/hippocampus_bridge.py` |
| `AGENTROPIX_HIPPOCAMPUS_TOP_K` | `3` (floor 1, ceiling 50) | Top-k traces recalled | `memory/hippocampus_bridge.py` |
| `AGENTROPIX_RUN_ID` | generated | Run identifier (ledger/trace) | `mcp_server` |
| `AGENTROPIX_LOG_LEVEL` | `WARNING` | Log level | `mcp_server/_env` |
| `AGENTROPIX_CONFIG` | unset | Config file path override | `mcp_server/config.py` |

---

## 3. Safety / courtroom / evidence

| Var | Default | Description | Source |
|-----|---------|-------------|--------|
| `AGENTROPIX_EVIDENCE_SHA256` | `""` | Operator-supplied evidence digest when auto-hash unavailable | `courtroom.py` |
| `AGENTROPIX_TRACE_RAW_MAX_BYTES` | `4096` (4 KiB) | Bound on pre-LLM raw-output trace snapshot | `mcp_server/_trace.py` |
| `AGENTROPIX_AUDIT_LOG` / `AGENTROPIX_AUDIT_LOG_DIR` | system log dir | On-disk Thymus JSONL audit (chain of custody) | `thymus_policy.py` |
| `AGENTROPIX_THYMUS_ALLOWED_PREFIXES` | built-in `READONLY_PATHS` | Extra read-only path prefixes | `thymus_policy.py` |
| `AGENTROPIX_THYMUS_AUDIT_LOG_RING_SIZE` | `1000` (floor 100, ceiling 100000) | In-memory audit ring size | `thymus_policy.py` |
| `AGENTROPIX_MAX_AUTO_PREFIXES` | `50` | Cap on auto-allowed evidence-dir prefixes | `thymus_policy.py` |
| `AGENTROPIX_EVIDENCE_GATE_DB` | default path | SQLite mutation-token registry | `evidence_gate/registry.py` |
| `AGENTROPIX_MUTATION_TOKEN` | unset | One-shot mutation token (`egt_…`); mint via `evidence-gate mint`. From env, never a CLI flag | `evidence_gate` |
| `AGENTROPIX_REQUIRE_IOC_PROVENANCE` | unset | When set, IOC records without `IOCProvenance` raise `ProvenanceMissingError` | `wazuh/models.py:178` |
| `AGENTROPIX_REDACTOR_HMAC_KEY` | — (≥32 bytes) | HMAC key for deterministic finding redaction | `security/redact.py` |
| `AGENTROPIX_MASTER_IOCS_HMAC_KEY` | — | HMAC key for MASTER-IOCS aggregation seal (separate from redactor key) | `wrappers/master_iocs_aggregator.py` |
| `AGENTROPIX_VERIFY_TOOL_PINS` | unset | Verify tool binary pins on startup | `mcp_server/_tool_pins.py` |
| `AGENTROPIX_ALLOW_EGRESS` | `0` (off) | Gate for any network egress (threat-intel) | `mcp_server/_env` |

---

## 4. Resource ceilings (server-wide)

| Var | Default | Description |
|-----|---------|-------------|
| `AGENTROPIX_MEM_LIMIT_MB` | `""` (unset → scales to image, floor 4096) | Per-tool memory ceiling (MB); `0` disables the guard |
| `AGENTROPIX_MAX_RETRIES` | `2` | Subprocess retry count |
| `AGENTROPIX_RATE_LIMIT` | `60` (floor 1, ceiling 10000) | Tool-call rate limit |
| `AGENTROPIX_MCP_RESULT_MAX_BYTES` | `900000` | Max tool-result payload bytes |
| `AGENTROPIX_MIN_DISK_MB` | (unverified) | Min free disk before a run |
| `AGENTROPIX_MCP_ACCESS_LOG` | (unverified) | MCP access log path |

Memory-limit resolution and the R4/R5 enforcement paths are covered in
[recovery-resilience](recovery-resilience.md#3-memory-ceilings--timeouts).

---

## 5. Per-wrapper tuning (pattern catalogue)

Every forensic wrapper exposes a consistent triple; defaults are per-tool — read the wrapper
for exact values.

| Pattern | Example vars | Meaning |
|---------|--------------|---------|
| `AGENTROPIX_<TOOL>_TOOL` | `AGENTROPIX_FLS_TOOL`, `AGENTROPIX_YARA_TOOL`, `AGENTROPIX_VOL26_BIN`, `AGENTROPIX_EWFMOUNT_TOOL`, … | Override the binary path (point at a SIFT-installed binary) |
| `AGENTROPIX_<TOOL>_TIMEOUT[_S]` | `AGENTROPIX_VOL_TIMEOUT`, `AGENTROPIX_PLASO_TIMEOUT`, `AGENTROPIX_YARA_TIMEOUT`, `AGENTROPIX_TSK_TIMEOUT`, … | Subprocess timeout |
| `AGENTROPIX_<TOOL>_MAX_*` | `AGENTROPIX_YARA_MAX_FILES`, `AGENTROPIX_PLASO_MAX_EVENTS`, `AGENTROPIX_BE_MAX_FEATURES`, … | Output/size caps |
| Plaso-specific | `AGENTROPIX_PLASO_PARSERS`, `AGENTROPIX_PLASO_WORKERS`, `AGENTROPIX_PLASO_PRIORITY_BUDGET`, `AGENTROPIX_PSORT_TIMEOUT`, … | Timeline tuning |
| EZ-Tools `_DLL` | `AGENTROPIX_RECMD_DLL`, `AGENTROPIX_MFTECMD_DLL`, `AGENTROPIX_SQLECMD_MAPS_DIR`, … | Pointers to EZ-Tools assemblies/maps |
| Agent tuning | `AGENTROPIX_MEMORY_SUSPICIOUS_PROCS`, `AGENTROPIX_TIMELINE_LOLBINS`, `AGENTROPIX_DISC_MIN_CONFIDENCE`, `AGENTROPIX_NULL_SESSION_Z_THRESHOLD`, `AGENTROPIX_T1071_SVCHOST_PORTS`, … | Per-agent confidence/threshold knobs |

---

## 6. Wazuh integration (kill-switches default-deny)

The Wazuh surface ships **safe by default** — disabled, dry-run-only:

| Var | Default | Description |
|-----|---------|-------------|
| `WAZUH_INTEGRATION_ENABLED` | `false` | Master enable for Wazuh integration |
| `WAZUH_PUSH_ENABLED` | `false` | Enable IOC push (write) |
| `WAZUH_DRY_RUN_ONLY` | `true` | Force dry-run for all mutations |
| `AGENTROPIX_INTEGRATION_NOT_PRODUCTION` | `false` | Operator affirmation the target is NOT prod (W-188 round-trip gate, default-deny) |
| `AGENTROPIX_AR_PROTECTED_CIDRS` | RFC-1918 + loopback/ULA/link-local | CIDRs active-response must NEVER block |
| `WAZUH_TLS_VERIFY` | `true` | Manager TLS verify; `false` only when `AGENTROPIX_ENV=development` |
| `WAZUH_WRITE_RATE_PER_SEC` | `5` | Write rate cap |

Connectivity (`WAZUH_MANAGER_URL` `:55000`, `WAZUH_INDEXER_URL` `:9200`), credentials
(prefer `AGENTROPIX_WAZUH_API_PASSWORD_FILE` over inline), index/ISM patterns, and the W-188
runner caps are enumerated in [env-vars §1, §7](../../.crew/env-vars.md). TLS verify must stay
`true` outside `AGENTROPIX_ENV=development` (ADR-016 S-4 / ADR-018).

---

## 7. Approval sidecar (SIFT-W-288/294/296)

| Var | Default | Description |
|-----|---------|-------------|
| `AGENTROPIX_APPROVER_USER` | unset | Examiner identity (must match browser form) |
| `AGENTROPIX_APPROVER_PASSWORD` | unset | PBKDF2 source key; MUST stay stable across restarts |
| `AGENTROPIX_APPROVER_SALT_HEX` | unset | Per-examiner 16-byte hex PBKDF2 salt; MUST stay stable |
| `AGENTROPIX_APPROVAL_SIDECAR_HOST` | `127.0.0.1` | Bind host (0.0.0.0 only behind TLS nginx) |
| `AGENTROPIX_APPROVAL_SIDECAR_PORT` | `8800` | Bind port |
| `AGENTROPIX_APPROVAL_SIDECAR_NONCE_TTL` | `60` | Challenge nonce TTL (s) |
| `AGENTROPIX_APPROVAL_SIDECAR_PBKDF2_ITERATIONS` | `600000` | PBKDF2 iterations |

---

## 8. Threat-intel & notifications (egress-gated)

`AGENTROPIX_ALLOW_EGRESS` gates all network egress. Threat-intel keys
(`AGENTROPIX_VT_API_KEY`, `AGENTROPIX_OTX_API_KEY`, `AGENTROPIX_TI_PROVIDERS`,
`AGENTROPIX_TI_TIMEOUT`) and the Telegram token chain
(`AGENTROPIX_TELEGRAM_TOKEN_FILE` > `AGENTROPIX_TELEGRAM_TOKEN` > `AGENTROPIX_TELEGRAM_BOT_TOKEN`)
are all optional; the file-pointer form is preferred for the token (`secrets.py`). On a
host with no API keys, omit the threat-intel keys entirely.

---

## See also

- [env-vars (full reference)](../../.crew/env-vars.md) — every confirmed var, including the Wazuh OpenSearch index/ISM matrix.
- [security-model](security-model.md) — the security-relevant knobs in context.
- [recovery-resilience](recovery-resilience.md) — the timeout/memory/retry env knobs.
- [deployment](deployment.md) — which vars you set first when standing up a host.
