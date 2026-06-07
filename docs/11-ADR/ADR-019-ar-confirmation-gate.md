> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-019: Active Response Confirmation Gate

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-05-04 |
| **Decision Makers** | Victor Galvan (Principal Security Engineer + AI Architect) |
| **Bio-Agentic Component** | Wazuh integration — Active Response track (Step 3+) |
| **Priority** | P0 — safety boundary for all destructive Wazuh actions |
| **Preceding ADRs** | ADR-008 (Bio-Agentic Safety / Oncologist), ADR-018 (Wazuh IOC push) |

## Context

### Problem Statement

Wazuh Active Response (AR) allows the MCP→Wazuh bridge to issue commands that
run on monitored endpoints: firewall blocks, process kills, account lockouts,
quarantine scripts. These actions are **irreversible in the short term** and
affect production hosts that may be live during an incident.

The Step-1 design flagged AR as out of scope but explicitly proposed a gating
model (AGENTROPIX-WAZUH-INTEGRATION.md §4.2; `02_develop.md` Constraint #5).
This ADR ratifies that model as a hard architectural boundary, so Step-3
implementers cannot ship AR without satisfying it.

Three threat-model entries demand a confirmation gate:

1. **LLM07 — Insecure Plugin Design (OWASP LLM Top 10):** An LLM agent
   issued `wazuh_publish_iocs(confirm=True)` autonomously is an LLM07
   violation. AR amplifies the blast radius from data mutation to
   endpoint disruption.
2. **ADR-008 Oncologist principle:** Irreversible agent actions require
   human oversight at the decision point, not just at audit time.
3. **Incident context:** During a live IR (e.g. SRL-2018), a false-positive
   AR trigger could isolate a forensic collection host (F-Response), destroying
   evidence in transit.

### Constraints

- AR commands execute on endpoints within seconds of issuance — no
  post-issuance cancel window.
- The MCP server runs headless; a TTY-based confirmation is not viable for
  all callers.
- Existing `--confirm` flag pattern (Step-1 `wazuh_publish_iocs`) is
  insufficient for AR: a boolean in the MCP call can be set by an LLM agent
  without true human intent behind it.
- Must not block legitimate operator use in time-critical containment
  scenarios.

### Assumptions

- All AR actions in scope use `PUT /active-response` on the Wazuh Manager API.
- Operators have an out-of-band channel (Telegram bot, CLI, web UI) available
  during IR.
- Step-3 AR tools will be implemented after this ADR is Accepted.

## Decision Drivers

1. **Blast-radius minimisation** — A misfire during SRL-2018 collection could
   isolate the F-Response agent on a host being imaged.
2. **LLM07 compliance** — OWASP requires human-in-the-loop for destructive
   plugin actions.
3. **ADR-008 Oncologist gate** — The Oncologist component is the designated
   arbiter for high-impact irreversible actions.
4. **Auditability** — Every AR issuance must be court-defensible (ADR-016).

## Considered Options

### Option 1: Boolean `confirm=True` in MCP tool call

**Description:** Caller passes `confirm=True` alongside the AR request. If
absent or False, the tool dry-runs.

**Pros:**
- Simple; matches Step-1 `wazuh_publish_iocs` pattern.

**Cons:**
- An LLM agent can set `confirm=True` autonomously — this is the LLM07
  failure mode. There is no proof of human intent.
- No two-person rule; no cooldown between dry-run and execution.

### Option 2: Out-of-band confirmation token (CHOSEN)

**Description:** The AR MCP tool issues a **challenge token** (32-byte random,
base64url, 5-minute TTL) and returns it to the caller without executing the
action. A separate human-facing endpoint (Telegram bot command, CLI
`agentropix wazuh ar confirm <token>`) redeems the token. Only after
redemption does the AR execute, and the redemption event is sealed into the
audit log.

**Pros:**
- Proves human intent: the operator must take a deliberate action on a
  separate channel.
- TTL prevents stale pre-approvals from being replayed.
- Audit trail includes both issuance and redemption events with separate seals.
- Compatible with automated pipelines: the pipeline stalls at the challenge
  step and awaits operator input, which is the correct behavior.

**Cons:**
- Adds ~5–30 seconds of latency to AR execution (operator round-trip).
- Requires the Telegram/CLI channel to be reachable.
- Mitigation for latency: in pre-declared **drill** or **lab** mode
  (`AGENTROPIX_ENV=lab`), tokens auto-redeem after 3 seconds for testing.

### Option 3: Two-person rule (second operator approves)

**Description:** Two distinct operator identities must each submit a
confirmation token before AR executes.

**Pros:**
- Highest assurance level.

**Cons:**
- Operationally impractical during IR when only one analyst is on call.
- Deferred to Step-4 for high-severity playbooks (e.g. domain-wide lockout).

## Decision

We will use **Option 2 — out-of-band confirmation token** for all AR actions
in Step-3 and beyond.

### Implementation Rules (normative)

1. **No AR tool may call `PUT /active-response` without a redeemed token.**
   There is no `--force` bypass. Implementers must wire `token_gate.require_ar_token(token_id)`
   inside `WazuhClient._ar_request`, paralleling the EvidenceGate pattern from
   ADR-018.

2. **Token issuance:** `wazuh_ar_prepare(action, targets)` returns a
   `WazuhARChallenge(token_id, expires_at, action_summary)`. The action
   summary is human-readable and shown to the operator for review.

3. **Token redemption:** `agentropix wazuh ar confirm <token_id>` (CLI) or
   `/wazuh ar confirm <token_id>` (Telegram bot). Redemption binds the
   operator's identity to the token.

4. **Token TTL:** 300 seconds. Expired tokens are rejected; the MCP tool must
   re-issue.

5. **Audit:** Both issuance and redemption events are sealed with HMAC-SHA256
   per ADR-016 and appended to the AR audit log
   (`/var/log/agentropix/wazuh-ar-audit.jsonl`), separate from the IOC push
   audit log.

6. **Benign-tool exclusion:** Any AR command targeting a host that is currently
   running F-Response (`subject_srv.exe` / `subject_srv.ex`) or Mnemosyne.sys
   is automatically blocked with `ARBenignToolConflict`. The operator must
   explicitly acknowledge via a secondary `--override-dfir-tool` flag (step 4+
   only).

7. **Lab/drill mode:** When `AGENTROPIX_ENV=lab`, tokens auto-redeem after
   3 seconds with a `[LAB-AUTO-CONFIRM]` audit marker. This is only permitted
   when `AGENTROPIX_ENV` is explicitly set to `lab`.

### Out of scope for this ADR (deferred)

- Two-person rule for high-severity playbooks → Step-4 ADR-021
- AR rollback/undo capability → Step-4
- Wazuh AR webhook push (replacing polling) → Step-3 implementation detail

## Consequences

### Positive

- LLM07 compliance: no autonomous destructive action path.
- Oncologist principle satisfied: human is in the loop at the irreversible
  decision point.
- ADR-016 audit trail covers both the intent (issuance) and the execution
  (redemption).
- F-Response/Mnemosyne protection prevents self-sabotage during active IR.

### Negative

- 5–30 second AR latency (operator round-trip). Mitigation: challenge summary
  includes a ready-to-paste confirm command so the operator's path is one copy-
  paste + Enter.
- Telegram/CLI channel must be reachable. Mitigation: Step-3 runbook documents
  fallback (direct Wazuh dashboard AR).

### Neutral

- This pattern is identical to production SRE change-request flows; operators
  familiar with ITSM gating will find it natural.

## Bio-Agentic Mapping

| Agentropix Component | This Decision's Role |
|---------------------|---------------------|
| Oncologist | Issues the challenge token; is the only component allowed to call `_ar_request` after redemption |
| Thymus | Validates the AR action text for prompt injection before issuance |
| Gauntlet | Rate-limits token issuance (≤3 pending tokens per operator at a time) |
| ADR-016 Courtroom Seal | Applied to both issuance and redemption events |

## Validation Criteria

- [ ] `wazuh_ar_prepare` returns a `WazuhARChallenge` and does NOT call `PUT /active-response`
- [ ] Calling `WazuhClient._ar_request` without a redeemed token raises `ARTokenRequired`
- [ ] Token TTL expiry: expired token raises `ARTokenExpired`
- [ ] F-Response conflict check: host running `subject_srv.exe` raises `ARBenignToolConflict`
- [ ] Lab mode: `AGENTROPIX_ENV=lab` auto-redeems after 3 s with `[LAB-AUTO-CONFIRM]` marker
- [ ] Audit JSONL contains both issuance and redemption events with distinct HMAC-SHA256 seals
- [ ] `test_ar_no_autonomous_confirm` passes: LLM agent cannot call `_ar_request` without a separately redeemed token

## References

- OWASP LLM Top 10 — LLM07: Insecure Plugin Design
- ADR-008: Bio-Agentic Safety (Oncologist principle)
- ADR-016: Courtroom Audit (HMAC-SHA256 seal)
- ADR-018: Wazuh IOC Push (EvidenceGate pattern this mirrors)
- AGENTROPIX-WAZUH-INTEGRATION.md §4.2 (original AR gate proposal)
- SOUL.md: Quality Over Speed

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-05-04 | Victor Galvan / BMad Orchestrator | Initial draft, Status: Accepted |
