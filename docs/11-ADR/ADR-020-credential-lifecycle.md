> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-020: Wazuh Credential Lifecycle

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-05-04 |
| **Decision Makers** | Victor Galvan (Principal Security Engineer + AI Architect) |
| **Bio-Agentic Component** | Wazuh integration — all steps |
| **Priority** | P0 — security boundary; credential leak = full Wazuh cluster compromise |
| **Preceding ADRs** | ADR-017 (tailnet exposure), ADR-018 (Wazuh IOC push) |

## Context

### Problem Statement

The Wazuh integration requires three credential types:

1. **Wazuh Manager API JWT** — obtained via `POST /security/user/authenticate`
   with a username/password; 900-second TTL; scoped to the API role created
   for Agentropix.
2. **Wazuh Indexer (OpenSearch) HTTP Basic** — independent of the Manager JWT;
   used for `GET /_search` on `wazuh-alerts-*`; separate credential set.
3. **ADR-016 HMAC session key** — per-run 32-byte random key, written to a
   `.session-key` file alongside the audit log.

The Step-1 `02_develop.md` blueprint proposed storing credentials in the repo
`.env` file. The compliance critic (04_compliance.md) and the secrets-handling
memory (`feedback_secrets_handling.md`) both flag this as a violation:
credentials must never appear in git, must never be echoed to logs, and must
live at mode 0600.

A secondary gap: the Step-1 plan had no documented rotation cadence, no
revocation procedure, and no description of what happens when the JWT expires
mid-session.

### Constraints

- The repo `.env` is already in `.gitignore`; however `.env.example` is
  tracked and must contain only placeholder strings — never real values.
- The Wazuh Manager JWT expires at 900 seconds. The adapter must refresh
  without requiring operator intervention.
- Indexer credentials are independent of the Manager JWT and must be treated
  as a separate secret.
- The ADR-016 session key is ephemeral per run; it must survive the process
  but must not outlive the audit record it seals.
- Secrets must never appear in: git history, ruff output, pytest output,
  httpx DEBUG logs, or the ADR-016 audit JSONL.

### Assumptions

- The deployment runs on a host reachable via Tailscale (ADR-017); the
  credential file is local to that host.
- The operator has write access to `~/.openclaw/credentials/`.
- Rotation tooling (`agentropix wazuh rotate-creds`) is deferred to Step-2.

## Decision Drivers

1. **Secrets discipline** — `feedback_secrets_handling.md`: flag → gitignore
   → 0600 → never echo.
2. **Blast-radius containment** — If the Manager password leaks, the attacker
   controls all CDB lists and custom rules; if the Indexer credential leaks,
   they can read all alerts. Separate secrets = separate blast radii.
3. **JWT expiry resilience** — A mid-session JWT expiry that causes a silent
   failure or an unhandled exception is a reliability bug AND a security gap
   (the retry might log the raw 401 response which may echo credential hints).
4. **Auditability** — ADR-016 session keys are evidence; their location and
   permissions are part of the courtroom-defensibility claim.

## Decision

### Rule 1 — Storage location and permissions

| Secret | Location | Mode |
|--------|----------|------|
| Manager username | `~/.openclaw/credentials/wazuh-mgr.json` | 0600 |
| Manager password | `~/.openclaw/credentials/wazuh-mgr.json` | 0600 |
| Indexer username | `~/.openclaw/credentials/wazuh-indexer.json` | 0600 |
| Indexer password | `~/.openclaw/credentials/wazuh-indexer.json` | 0600 |
| ADR-016 session key | `<audit-log-path>.session-key` | 0600 |

`WazuhConfig.from_env` reads `WAZUH_MGR_CREDS_PATH` and
`WAZUH_INDEXER_CREDS_PATH` env vars (defaulting to the paths above). The
raw username/password values are **never stored in instance attributes** — they
are read once at startup and passed directly to the `httpx.Auth` object or JWT
request. After the JWT is obtained, the password reference is released.

### Rule 2 — JWT caching and refresh

- Cache the JWT in memory (never on disk): `_jwt_cache: dict[str, tuple[str, float]]`
  keyed by `(manager_url, username)`.
- Refresh when `time.monotonic() - issued_at >= 890` (10-second headroom before
  the 900-second TTL).
- On `401 Unauthorized` from any PUT/POST: force-refresh once, retry once.
  If still `401`, raise `WazuhAuthError` — do not loop.
- JWT value is never written to logs. If httpx DEBUG logging is active,
  `WazuhClient.__init__` must install an `httpx.RequestHook` that redacts the
  `Authorization` header before the log line is emitted.

### Rule 3 — Indexer credentials

Indexer Basic Auth credentials are passed via `httpx.BasicAuth` directly —
they are never logged, never cached to disk, and the `Authorization` header
must be redacted by the same hook as the JWT.

### Rule 4 — `.env.example` discipline

`.env.example` at the repo root MUST contain only placeholder strings:

```
WAZUH_MANAGER_URL=https://wazuh-manager.tailnet.local:55000
WAZUH_MGR_CREDS_PATH=~/.openclaw/credentials/wazuh-mgr.json
WAZUH_INDEXER_URL=https://wazuh-indexer.tailnet.local:9200
WAZUH_INDEXER_CREDS_PATH=~/.openclaw/credentials/wazuh-indexer.json
WAZUH_TLS_VERIFY=true
WAZUH_TLS_CA_BUNDLE=  # path to CA bundle if using self-signed certs
AGENTROPIX_ENV=production
```

Any commit that introduces a real hostname, IP, username, or password into
`.env.example` MUST be rejected by the pre-commit hook. A `ruff` / `gitleaks`
check is added in Step-2 to enforce this.

### Rule 5 — Never echo secrets

The following are hard prohibitions, enforced by code review and CI:

- No `print(password)`, `logging.debug(jwt)`, `f"...{token}..."` in any
  `wazuh/` module.
- `WazuhConfig.__repr__` and `__str__` must redact all credential fields:
  `WazuhConfig(manager_url='https://...', mgr_user='[REDACTED]', ...)`.
- pytest fixtures must use `os.environ["WAZUH_TEST_PASSWORD"] = "fake-pw"`
  (not hardcoded strings) so that grep for common password patterns in CI
  output doesn't surface real values.

### Rule 6 — ADR-016 session key

The per-run HMAC session key:
- Generated: `os.urandom(32)` at `WazuhClient.__init__` time.
- Written to: `<audit_log_path>.session-key` at mode 0600 immediately.
- Never logged, never included in the audit JSONL body.
- Retention: 7 years alongside the audit log it seals (ADR-016 retention
  policy). The key file is the only way to verify the seals — deleting it
  voids the court-defensibility claim.

### Rule 7 — Rotation cadence (deferred to Step-2)

- Manager API user password: rotate every 90 days via
  `PUT /security/users/{user_id}`.
- Indexer password: rotate every 90 days (Wazuh dashboard or API).
- `agentropix wazuh rotate-creds` CLI command: Step-2 deliverable.
- Rotation event is sealed into the audit log with the old-key seal
  before the new key takes effect.

### Rule 8 — Revocation

If a credential is suspected compromised:
1. Immediately `PUT /security/users/{user_id}` to rotate the Manager password
   (disables all in-flight JWTs).
2. Update `~/.openclaw/credentials/wazuh-mgr.json` to the new password (0600).
3. Wipe the JWT in-memory cache by restarting the MCP server.
4. File an incident note in the courtroom audit log signed with the current
   session key.
5. Indexer credential: rotate via Wazuh Security module independently.

## Consequences

### Positive

- Zero-git-history credential exposure.
- httpx DEBUG logging cannot leak JWT or Basic Auth tokens.
- JWT expiry is handled transparently; no mid-session auth failures.
- ADR-016 session key retention is explicit — operators know not to delete it.

### Negative

- `~/.openclaw/credentials/` directory must exist on every deployment host
  before first run. Mitigation: `WazuhConfig.from_env` raises a clear
  `CredentialFileNotFound` error pointing at the setup runbook.
- Rotation is manual until Step-2. Mitigation: HEARTBEAT.md gets a
  `wazuh-cred-age-check` entry that warns when credentials are >80 days old.

### Neutral

- Two credential files (`wazuh-mgr.json`, `wazuh-indexer.json`) instead of one
  is marginally more ops overhead but correctly reflects the separate blast
  radii.

## Bio-Agentic Mapping

| Agentropix Component | This Decision's Role |
|---------------------|---------------------|
| WazuhClient | Consumes credentials per Rules 1–3; owns the JWT cache |
| HEARTBEAT.md | `wazuh-cred-age-check` entry added for 90-day rotation reminder |
| ADR-016 Courtroom Seal | Session key lifecycle governed by Rule 6 |
| Gauntlet | Rate-limits auth attempts; surfaces `WazuhAuthError` before Gauntlet retry budget is exhausted |

## Validation Criteria

Status as of 2026-05-05 (review F-5/F-7/F-8 fix patch). Items marked
`[deferred-S1.5]` slip to the Step-1.5 sprint per `INTEGRATION-PLAN`
§15.2 with the `IOCPushOutcome` / publish-ledger work.

- [x] `WazuhConfig.__repr__` redacts the `api_password` field (test:
      `tests/wazuh/unit/test_config.py::test_config_repr_redacts_password`).
- [x] `WazuhClient` installs an `httpx.AsyncClient(event_hooks={"request":
      [_redact_request_log]})` redactor that scrubs the Authorization
      header before any local logger emit. (Behavioural; redaction is
      in-flight for any DEBUG-level httpx logger consumer.)
- [x] `WazuhClient._request` refreshes JWT when age ≥ `jwt_refresh_at_sec`
      (`_ensure_jwt` honours `config.jwt_refresh_at_sec`).
- [x] On `401`: force-refresh once, retry once; second 401 raises
      `AuthError` (covered by `tests/wazuh/unit/test_client.py`).
- [x] Cred file mode check: `_load_wazuh_password` rejects files where
      `(mode & 0o077) != 0` (test: `test_password_file_with_unsafe_perms_rejected`).
- [x] `test_tls_verify_false_rejected_outside_development` passes
      (already in ADR-018 suite).
- [x] `.env.example` greps for non-placeholder patterns return zero hits.
- [x] Session key file created at mode 0600 — by `seal.generate_session_key`,
      called from `orchestrator.push_iocs` (NOT by `WazuhClient.__init__`;
      the original ADR-020 location was incorrect — corrected here).
- [x] `RuleValidationError.server_reason` no longer echoes raw response
      text (F-8 fix; structured `resp_digest=… resp_len=…` only).
- [ ] `test_jwt_refresh_on_expiry` clock-advance test — `[deferred-S1.5]`
      (mock-clock harness lands with the publish-ledger work).
- [ ] Periodic `wazuh-cred-age-check` (HEARTBEAT.md) executed against a
      real cred file in CI — `[deferred-S1.5]` (CI-side; HEARTBEAT.md
      task itself shipped 2026-05-05).

## Drift register

The following items in this ADR were misaligned with the Step-1 codebase
when first authored; the rows above were corrected on 2026-05-05:

1. "Session key file created at mode 0600 on `WazuhClient.__init__`" was
   wrong — the session key is created by `seal.generate_session_key`,
   called from the orchestrator (not the client). The check is now on
   `seal.py::generate_session_key`.
2. "`httpx.RequestHook` redacts Authorization header" originally implied
   a synchronous Python `logging` filter; the implementation uses an
   httpx `event_hooks={"request": [...]}` callback that mutates a shadow
   header for downstream filters. Functionally equivalent; named
   correctly above.
3. The Validation Criteria checklist used `[ ]` placeholders even where
   the underlying behaviour was already implemented, creating a false
   "not done" signal. All items have been re-checked against the tree.

## References

- `feedback_secrets_handling.md` (memory): flag → gitignore → 0600 → never echo
- ADR-016: Courtroom Audit (session key retention policy)
- ADR-017: Tailnet MCP exposure (outbound egress scope)
- ADR-018: Wazuh IOC Push (WazuhConfig.from_env, TLS gate)
- WAZUH-API-FEASIBILITY.md §3 (JWT 900-second TTL, Indexer Basic Auth)
- AGENTROPIX-WAZUH-INTEGRATION.md §4.3 (credential storage decision)

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-05-04 | Victor Galvan / BMad Orchestrator | Initial draft, Status: Accepted |
