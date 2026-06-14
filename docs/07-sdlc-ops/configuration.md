# Configuration — The `AGENTROPIX_*` Environment Surface

> The full environment-variable surface that configures Agentropix-SIFT, with confirmed
> defaults from code and `.env.example`. Secrets prefer the file-pointer form (`*_FILE`);
> `.env` is gitignored and mode 0600. The complete namespace exceeds 200 vars (mostly
> per-wrapper timeout/cap/tool-path triples); this chapter lists the load-bearing ones and
> the naming patterns for the rest. When you need an exact per-wrapper default, read the
> wrapper module.

All values are sourced from [env-vars](env-vars.md), `.env.example`, and the
source modules cited inline. `(unverified)` marks a default not confirmed from code.

---

## Contents — what's in this page (and what to expect)

> Jump to any section below. Each row tells you what that part gives you, so you can go straight to your point.

| Section | What you'll get |
|---|---|
| [0. How to use this page (two audiences)](#0-how-to-use-this-page-two-audiences) | The two audience tracks (🖥️ expert command vs 💬 end-user prompt) and the Execution→Output labelling, plus the env-vars-read-at-boot GOTCHA. |
| [0.1 Verifying any config change (the universal set-then-check loop)](#01-verifying-any-config-change-the-universal-set-then-check-loop) | The one set→restart→check loop that confirms *any* var took effect — re-query `health` (operator) or ask the session (end-user). |
| [1. MCP server auth & exposure (W-235, W-242)](#1-mcp-server-auth--exposure-w-235-w-242) | The bearer-token + dev-mode/build-profile/loopback vars that gate server exposure, with a tokenless-vs-authenticated proof. |
| [2. Core orchestration & Trinity](#2-core-orchestration--trinity) | The Trinity/critic, finding-cap, correlation-token, hippocampus, and run/log vars that tune the orchestration core. |
| [3. Safety / courtroom / evidence](#3-safety--courtroom--evidence) | The chain-of-custody knobs: audit-log destination, read-only path allowlist, evidence-gate/mutation tokens, HMAC keys, egress gate. |
| [4. Resource ceilings (server-wide)](#4-resource-ceilings-server-wide) | The per-tool memory ceiling, retry count, rate limit, and result-size caps — and how to verify the server reloads cleanly. |
| [5. Per-wrapper tuning (pattern catalogue)](#5-per-wrapper-tuning-pattern-catalogue) | The naming patterns for the 200+ per-wrapper vars (binary path / timeout / max-caps / agent thresholds) so you can find any one. |
| [6. Wazuh integration (kill-switches default-deny)](#6-wazuh-integration-kill-switches-default-deny) | The safe-by-default Wazuh kill-switches and the full set of flags you must flip to permit a write, plus the read-only hunt path. |
| [7. Approval sidecar (SIFT-W-288/294/296)](#7-approval-sidecar-sift-w-288294296) | The examiner-identity, PBKDF2, bind-host/port, and nonce-TTL vars for the approval sidecar. |
| [8. Threat-intel & notifications (egress-gated)](#8-threat-intel--notifications-egress-gated) | The egress gate plus the optional threat-intel keys and Telegram token chain (file-pointer form preferred). |
| [See also](#see-also) | Pointers to the full env-vars reference, security-model, recovery-resilience, and deployment pages. |

---

## 0. How to use this page (two audiences)

Configuration is an **operator** task — you export environment variables (or write them into the
gitignored `.env`) before launching the MCP server. But every setting has a visible *effect* a
non-technical user can confirm by simply asking the connected Claude session. So each procedure
below is shown two ways, side by side:

> **🖥️ Expert (command):** the exact `export …` / config command an operator runs in a shell, then
> the verify step that proves it took effect.
> **💬 End-user (prompt):** the plain-language question a non-technical user types into Claude
> Desktop / Claude CLI (with the Agentropix MCP connected). The session answers by calling a **real
> MCP tool** — almost always [`health`](../04-mcp-tools/tool-list.md) (server health + live tool count +
> profile/exposure flags) or [`case_status`](../04-mcp-tools/tool-list.md) (case + evidence/audit state).
> **A simple, focused question is enough — the session recognises it as an Agentropix capability and
> routes it to the right check.**

Command/result pairs are labelled **Execution X → Output X** so it is unambiguous what you **run**
versus what you **get back**. Paths and secrets are shown as placeholders (`<EVIDENCE-DIR>`,
`<32-BYTE-TOKEN>`); never paste a real secret into a tracked file — prefer the `*_FILE` pointer form
and keep `.env` at mode `0600`.

> **GOTCHA — env vars are read at server start.** The MCP server reads `AGENTROPIX_*` once, at boot.
> After any `export`/`.env` edit you must **restart the server** for it to take effect; the `💬`
> verify prompts (which hit the live `health`/`case_status` tools) only ever reflect the *running*
> process, so a stale answer usually means "you changed the env but didn't restart yet."

---

## 0.1 Verifying any config change (the universal set-then-check loop)

Whatever variable you set, the confirm step is the same shape: set it in the operator shell, restart
the server, then either re-query `health` (operator) or ask the session (end-user).

> **🖥️ Expert (command):**
> ```bash
> # 1. set the variable (example: raise the tool-call rate limit)
> export AGENTROPIX_RATE_LIMIT=120
> # 2. restart the MCP server so it re-reads the environment, then
> # 3. confirm the server is back up and healthy
> curl -s -H "Authorization: Bearer <32-BYTE-TOKEN>" http://127.0.0.1:<PORT>/health | jq .
> ```
> **💬 End-user (prompt):** *"Is the Agentropix MCP server running and healthy, and how many forensic
> tools are available right now?"*
> The session calls the `health` tool and tells you in plain language whether the server is up and how
> many tools it exposes — your signal that a restart succeeded after a config change.

**Execution A → Output A.**

*Execution A:* call the `health` tool (the `💬` prompt above, or the operator `curl`).

*Output A (healthy):*
```json
{ "status": "ok", "server": "agentropix-sift", "tool_count": 73, "version": "..." }
```

`status: ok` with `tool_count: 73` (the canonical figure — see [`canonical-facts.md`](../08-reference/canonical-facts.md))
confirms the restart picked up your new environment.

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

> **🖥️ Expert (command):**
> ```bash
> # mint a strong bearer token and export it (prefer the *_FILE pointer in production)
> export AGENTROPIX_MCP_AUTH_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
> # restart the server, then prove the token is enforced: a tokenless call must be rejected
> curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:<PORT>/health        # expect 401
> curl -s -H "Authorization: Bearer $AGENTROPIX_MCP_AUTH_TOKEN" \
>   http://127.0.0.1:<PORT>/health | jq .status                                  # expect "ok"
> ```
> **💬 End-user (prompt):** *"Is the Agentropix server up and reachable for me?"*
> The session calls the `health` tool *through the already-authenticated client connection*, so it
> answers "yes, healthy" only when your token is correct — a non-technical confirmation that auth is
> wired. (Minting/rotating the token itself is an operator-only `🖥️` step; the session can't set it.)

**Execution B → Output B.**

*Execution B:* tokenless `health` request, then an authenticated one.

*Output B:* `401` for the tokenless request (auth is enforced); `"ok"` for the authenticated request.

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

The two most-touched knobs here are the **audit log destination** (`AGENTROPIX_AUDIT_LOG` —
the on-disk Thymus JSONL chain of custody) and the **read-only path allowlist**
(`READONLY_PATHS` is the built-in base list in `thymus_policy.py`; extend it at runtime with
`AGENTROPIX_THYMUS_ALLOWED_PREFIXES`). Both are shown below.

### 3.1 Point the audit log at your case directory (`AGENTROPIX_AUDIT_LOG`)

> **🖥️ Expert (command):**
> ```bash
> # write the tamper-evident Thymus audit JSONL into the case dir (placeholder path)
> export AGENTROPIX_AUDIT_LOG="<EVIDENCE-DIR>/audit/thymus-audit.jsonl"
> # restart the server, then confirm the file is being appended on the next tool call
> tail -n 1 "$AGENTROPIX_AUDIT_LOG" | jq .          # one JSON record per audited action
> ```
> **💬 End-user (prompt):** *"Is Agentropix recording an audit trail for this case, and where?"*
> The session reports case state via the `case_status` tool — including whether chain-of-custody
> auditing is active — so a non-technical examiner can confirm the trail exists without reading files.

**Execution C → Output C.**

*Execution C:* set `AGENTROPIX_AUDIT_LOG`, restart, run any tool, then `tail` the file.

*Output C:* a one-line-per-action JSONL record (actor, tool, target path, decision, timestamp) appended
to `<EVIDENCE-DIR>/audit/thymus-audit.jsonl` — the on-disk half of the Thymus chain of custody.
(Source: `thymus_policy.py` reads `AGENTROPIX_AUDIT_LOG`; if unset it falls back to the system log dir
or `AGENTROPIX_AUDIT_LOG_DIR`.)

### 3.2 Allow an extra read-only evidence prefix (`READONLY_PATHS` / `AGENTROPIX_THYMUS_ALLOWED_PREFIXES`)

> **🖥️ Expert (command):**
> ```bash
> # READONLY_PATHS is the built-in base allowlist (thymus_policy.py); extend it without editing code:
> export AGENTROPIX_THYMUS_ALLOWED_PREFIXES="<EVIDENCE-DIR>:/mnt/cases"   # colon-separated prefixes
> # restart, then verify a read under the new prefix is permitted while writes stay blocked
> ```
> **💬 End-user (prompt):** *"Can Agentropix read the evidence I put under `<EVIDENCE-DIR>`?"*
> Ask the session to list or examine a file under that path — it routes to a read-only tool
> (e.g. `list_files` / `fls`) and succeeds only if the prefix is allowlisted, so a clean read **is**
> the confirmation. (Adding the prefix itself is an operator `🖥️` step.)

**Execution D → Output D.**

*Execution D:* export `AGENTROPIX_THYMUS_ALLOWED_PREFIXES`, restart, then read a file under the prefix.

*Output D:* reads under `<EVIDENCE-DIR>` and `/mnt/cases` are now permitted (the prefixes are appended
to the built-in `READONLY_PATHS` list); any **write** to those paths is still denied by Thymus.
`AGENTROPIX_MAX_AUTO_PREFIXES` (default `50`) caps how many evidence-dir prefixes auto-allowlist.

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

> **🖥️ Expert (command):**
> ```bash
> # tighten the per-tool memory ceiling and the tool-call rate limit, then restart
> export AGENTROPIX_MEM_LIMIT_MB=8192          # 0 disables the guard; floor 4096
> export AGENTROPIX_RATE_LIMIT=120             # floor 1, ceiling 10000
> # confirm the server came back healthy after the restart
> curl -s -H "Authorization: Bearer <32-BYTE-TOKEN>" http://127.0.0.1:<PORT>/health | jq .status
> ```
> **💬 End-user (prompt):** *"Is the Agentropix server healthy and ready to take requests?"*
> The session calls `health`; an `ok` status after your restart confirms the new ceilings loaded
> cleanly. (The ceilings are operator `🖥️` knobs — the session can read health, not rewrite limits.)

**Execution E → Output E.**

*Execution E:* set the two ceilings, restart, then call `health`.

*Output E:* `"status": "ok"` — the server is back up under the new ceilings. Per-tool runs that exceed
`AGENTROPIX_MEM_LIMIT_MB` are now killed and surfaced via the R4/R5 recovery path; calls beyond
`AGENTROPIX_RATE_LIMIT`/min are throttled.

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
runner caps are enumerated in [env-vars §1, §7](env-vars.md). TLS verify must stay
`true` outside `AGENTROPIX_ENV=development` ([ADR-016 §S-4](../11-ADR/ADR-016-courtroom-audit.md) /
[ADR-018](../11-ADR/ADR-018-wazuh-ioc-push.md)).

> **Why these are default-deny (ADRs).** The IOC-push gate and per-PUT HMAC chain of custody come
> from [ADR-018](../11-ADR/ADR-018-wazuh-ioc-push.md); the `AGENTROPIX_AR_PROTECTED_CIDRS`
> active-response guard and the confirmation requirement before any destructive AR come from
> [ADR-019](../11-ADR/ADR-019-ar-confirmation-gate.md) (a two-person rule was deliberately
> **deferred** — [ADR-021](../11-ADR/ADR-021-two-person-rule-defer.md)); the credential-handling
> discipline (file-pointer first, `0600`, never echoed) is
> [ADR-020](../11-ADR/ADR-020-credential-lifecycle.md).

> **🖥️ Expert (command):**
> ```bash
> # default-deny: everything below ships off / dry-run. Enabling a WRITE needs ALL of these:
> export WAZUH_INTEGRATION_ENABLED=true        # master enable (default false)
> export WAZUH_PUSH_ENABLED=true               # allow IOC push/write (default false)
> export WAZUH_DRY_RUN_ONLY=false              # lift dry-run (default true — leave true to preview)
> export AGENTROPIX_INTEGRATION_NOT_PRODUCTION=true   # affirm target is NOT prod (W-188 gate)
> # restart, then confirm the wazuh tools are live in the running server
> curl -s -H "Authorization: Bearer <32-BYTE-TOKEN>" http://127.0.0.1:<PORT>/health | jq .tool_count
> ```
> **💬 End-user (prompt):** *"Hunt this IOC across our Wazuh data: <IOC>."*
> The session routes to the read-only `wazuh_hunt_ioc` tool — which works regardless of the write
> kill-switches, so a non-technical analyst can query Wazuh safely without ever touching the push flags.
> (Flipping the write kill-switches is an operator `🖥️`-only action by design.)

**Execution F → Output F.**

*Execution F:* leave the defaults (all off / dry-run) and ask the session to hunt an IOC.

*Output F:* `wazuh_hunt_ioc` returns matches read-only; no write occurs. To enable a *write*
(`wazuh_publish_iocs` / `wazuh_index_findings`) every kill-switch above must be flipped **and**
`AGENTROPIX_INTEGRATION_NOT_PRODUCTION=true` — any one missing leaves the integration default-denied.

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

- [env-vars (full reference)](env-vars.md) — every confirmed var, including the Wazuh OpenSearch index/ISM matrix.
- [security-model](security-model.md) — the security-relevant knobs in context.
- [recovery-resilience](recovery-resilience.md) — the timeout/memory/retry env knobs.
- [deployment](deployment.md) — which vars you set first when standing up a host.
