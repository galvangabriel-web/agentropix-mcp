> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-018: Wazuh IOC Push Integration

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-05-04 |
| **Decision Makers** | Victor Galvan (Principal Security Engineer + AI Architect) |
| **Bio-Agentic Component** | Wazuh integration track — Step-1 IOC push |
| **Priority** | P0 — blocking for live detection capability on SRL-2018 |
| **Correct preceding ADRs** | ADR-008 (safety/Thymus), ADR-016 (courtroom seal), ADR-017 (tailnet) |
| **Misattributed ADRs fixed** | ADR-003 is state persistence (NOT FP suppression); ADR-004 is SPIFFE/SPIRE (NOT benign-tool labeling); ADR-011 is evidence file type gate (NOT mutation token regime) |

## Context

The Agentropix SIFT platform discovers IOCs during forensic investigations
(e.g. SRL-2018). Without this ADR, discovered IOCs remain in human-readable
reports but are never pushed to the active SIEM (Wazuh), so every newly-
monitored host starts with zero threat-intelligence coverage.

Step 1 closes that gap: Agentropix MCP discovers IOCs, filters them through
the Tier-1/2/3 priority taxonomy, and pushes Tier-1/2 IOCs to Wazuh as CDB
lists + a custom rules pack.

Three critic findings drove the security design of this ADR:

1. **S-2 (CRITICAL)**: The evidence gate was fail-open in the `02_develop.md`
   blueprint — any non-empty string passed. This ADR mandates fail-closed.
2. **C-4 (BLOCKING)**: The plan used plain `sha256(req || resp)` for the seal.
   ADR-016 mandates HMAC-SHA256 with a per-run session key. This ADR
   corrects the formula.
3. **S-4 (HIGH)**: `WAZUH_TLS_VERIFY=false` was unrestricted. This ADR gates
   it behind `AGENTROPIX_ENV=development`.

## Decision

### Decision 1 — HMAC-SHA256 seal (ADR-016 compliance)

The per-PUT chain-of-custody seal is computed as:

```python
seal = HMAC-SHA256(session_key, canonical_json(envelope))
```

where `envelope` is:

```json
{
  "v": "1",
  "operator": "<unix_user>",
  "case_id": "<case_id>",
  "ts": "<iso8601_utc>",
  "evidence_token_id": "<token_id_or_null>",
  "endpoint": "<wazuh_api_path>",
  "req_sha256": "<hex64>",
  "resp_sha256": "<hex64>",
  "status": <http_status>
}
```

`canonical_json` rules (per ADR-016): `sort_keys=True`, `separators=(",",":")`
(no whitespace), `ensure_ascii=True`.

The session key is generated once per push run via `os.urandom(32)` and
written to `<audit_log_stem>.session-key` at mode `0600`. The key is never
logged or embedded in the audit JSON.

**Why HMAC, not plain SHA-256**: Plain SHA-256 gives integrity only — anyone
with the audit log can recompute it and replace tampered bytes with matching
hashes. HMAC binds the seal to a secret; without the session key, a tampered
seal cannot be recomputed. ADR-016 threat model: post-hoc tampering by a
party with file-write access.

**Seal prefix**: `"hmac-sha256:<hex>"` (scheme-prefixed to distinguish from
ADR-016's report-level `report_seal` which uses the same algorithm but a
different input shape).

### Decision 2 — Evidence gate fail-closed

`evidence_gate.py` implements the mutation token gate. The gate MUST fail
closed: if `agentropix_sift.evidence_gate.verify` cannot be imported,
`EvidenceGateRequired` is raised — the gate NEVER silently passes.

Token format: `egt_<26-char-ULID>` (matches the existing evidence-gate
registry format; ULID provides sortable uniqueness).

The gate is enforced at two levels:
1. `orchestrator.push_iocs()` calls `evidence_gate.check()` before any PUT
2. `WazuhClient._request()` calls `evidence_gate.check()` on every write
   operation so no code path can bypass it

### Decision 3 — TLS verification gate

`WazuhConfig.from_env()` raises `ConfigError` if `WAZUH_TLS_VERIFY=false`
and `AGENTROPIX_ENV != "development"`. This prevents accidental TLS bypass
in production or staging environments.

### Decision 4 — IPv4-only for Step 1

`IPIOCRecord` uses `ipaddress.ip_address()` for validation. IPv6 addresses
raise `ValueError("IPv6 IOC keys deferred to Step 2")` at model construction
time. This prevents the broken regex from `02_develop.md` that admitted
expanded IPv6 loopback (`0:0:0:0:0:0:0:1`) as a valid C2 IP.

### Decision 5 — Tier-3 hard exclusions at model layer

Model-layer validators make Tier-3 IOC values unconstructible:

- `MD5IOCRecord`: rejects `54377da4ea8d4e044bc107e65cf16ef3` (Windows
  Installer Component GUID, Gap A4)
- `ProcessIOCRecord`: rejects any value whose basename starts with
  `subject_srv` (F-Response DFIR agent, Gap A5)

These hard exclusions happen at `__init__` time, before any classifier,
transformer, or write operation.

### Decision 6 — CDB value pipe separator

CDB row format: `key:case_id|confidence|context\n`

The pipe (`|`) is used as the separator within the value part to avoid
ambiguity with Wazuh's key:value split-on-first-colon parsing. Using colon
as the value separator would break `split(":", 1)` parsing.

### Decision 7 — Rule if_group per type

Per Fix 5 (W-2) from the critics:
- IP/process/registry rules: `<if_group>syslog</if_group>`
- SHA-256/MD5 rules: `<if_group>syscheck</if_group>`

### Decision 8 — Mutation token regime

Since ADR-011 covers evidence file type detection (not mutation tokens),
this ADR defines the mutation token regime for Step 1:

- Token format: `egt_<ULID>` (structurally verified; cryptographic
  verification delegated to `agentropix_sift.evidence_gate.verify`)
- Scope: `wazuh.push_iocs` (explicit operation binding)
- Fail-closed: gate unavailability = gate denied (never pass-through)
- Audit: `evidence_token_id` (the token ID, not the secret) recorded in
  every write audit event

## Architecture

```
Operator (CLI/MCP)
       |
       | evidence_token (egt_<ULID>)
       v
orchestrator.push_iocs()
  1. CaseLoader → IOCInventory
  2. PriorityClassifier → Tier-1/2 records
  3. ThymusBridge.validate_inventory()     ← ADR-008 STRICT
  4. EvidenceGate.check(token)             ← FAIL CLOSED
  5. _make_cdb_body() → CDB payloads       ← pipe separator
  6. WazuhClient.put_cdb_list()
       └── _request("PUT", ...)
             ├── thymus.validate_input()   ← ADR-008 T2 touchpoint
             └── evidence_gate.check()    ← ADR-008 DI-5
  7. WazuhClient.put_rules_xml()
  8. WazuhClient.restart_manager()        ← coalesced FR-7
  9. CourtroomSeal.bind(...)              ← ADR-016 HMAC-SHA256
 10. AuditLogger → wazuh-audit.jsonl     ← FR-10
```

## Verification

To verify a sealed audit event:

```bash
# 1. Read the seal from the audit log
SEAL=$(jq -r .seal /var/log/agentropix/wazuh-audit.jsonl | head -1)

# 2. Read the session key (written by the push run)
SESSION_KEY_PATH=/var/log/agentropix/wazuh-audit.session-key

# 3. Recompute the HMAC
python3 -c "
import hmac, hashlib, json, sys, base64, os
key = open('$SESSION_KEY_PATH', 'rb').read()
event = json.loads(open('/var/log/agentropix/wazuh-audit.jsonl').readline())
envelope = {
    'v': '1',
    'operator': event['operator'],
    'case_id': event['case_id'],
    'ts': event['ts'],
    'evidence_token_id': event.get('evidence_token_id'),
    'endpoint': event['endpoint'],
    'req_sha256': event['req_sha256'],
    'resp_sha256': event['resp_sha256'],
    'status': event['http_status'],
}
canonical = json.dumps(envelope, sort_keys=True, separators=(',',':'), ensure_ascii=True).encode()
mac = hmac.new(key, canonical, hashlib.sha256).hexdigest()
print('hmac-sha256:' + mac)
"

# 4. Compare to the seal in the audit log — must match
```

## Trade-offs considered

### Option A — Plain SHA-256 (original plan)
**Rejected.** ADR-016 compliance requires HMAC-SHA256. Plain SHA-256 provides
integrity but not authentication — any party with the audit log can forge a
matching hash for tampered bytes.

### Option B — JWS/JWT envelope per PUT
**Rejected.** Over-engineering for the post-hoc-tampering threat model.
HMAC-SHA256 over canonical JSON provides the same guarantee.

### Option C — Per-finding seal instead of per-PUT
**Rejected.** Per-PUT sealing is sufficient for the audit trail and matches
the ADR-016 pattern. Per-finding would increase seal count proportionally
to the IOC corpus size with no additional security benefit for the threat
model.

### Option D — Share the evidence-gate session with the courtroom seal
**Rejected.** ADR-003/ADR-016 separation of concerns. The evidence gate
token proves operator authorisation; the session key proves the audit record
was not tampered. They serve different verification goals and must not share
state.

## Acceptance / Implementation gates

- [x] `seal.py`: HMAC-SHA256 seal with per-run session key at mode 0600
- [x] `evidence_gate.py`: fail-closed on missing verifier module
- [x] `config.py`: TLS gate — `WAZUH_TLS_VERIFY=false` rejected outside development
- [x] `models.py`: discriminated-union IOCRecord; IPv6 rejected; Tier-3 impossible to construct
- [x] `prioritise.py`: Tier-1/2/3 classifier with infra-IP exclusions
- [x] `client.py`: thymus + evidence_gate called in `_request()` for all writes; no DELETE
- [x] `orchestrator.py`: full push pipeline; coalesced restart; audit log
- [x] `test_evidence_gate.py`: `test_missing_verifier_fails_closed` passes
- [x] `test_client.py`: `test_request_calls_thymus_and_gate` passes
- [x] `test_config.py`: `test_tls_verify_false_rejected_outside_development` passes
- [x] `test_seal.py`: HMAC vs sha256, operator binding, collision resistance

## References

- Oracle: `src/agentropix_sift/wazuh/seal.py` — HMAC-SHA256 implementation
- Oracle: `src/agentropix_sift/wazuh/evidence_gate.py` — fail-closed gate
- Oracle: `src/agentropix_sift/wazuh/client.py` — Thymus + gate on write path
- [`ADR-016-courtroom-audit.md`](ADR-016-courtroom-audit.md) — HMAC-SHA256 seal pattern
- [`ADR-008-safety-architecture.md`](ADR-008-safety-architecture.md) — Thymus STRICT
- [`ADR-017-tailnet-mcp-exposure.md`](ADR-017-tailnet-mcp-exposure.md) — tailnet enforcement
- `Plan_step1_wazuh_iocs/critics/01_security.md` — security critic findings
- `Plan_step1_wazuh_iocs/critics/04_compliance.md` — compliance/ADR correction findings
