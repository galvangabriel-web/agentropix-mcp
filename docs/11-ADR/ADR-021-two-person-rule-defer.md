> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-021: Two-Person Rule for Active Response — DEFERRED

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Deferred (formally documented; not implemented) |
| **Date** | 2026-05-05 |
| **Decision Makers** | Victor Galvan (Principal Security Engineer + AI Architect) |
| **Bio-Agentic Component** | Wazuh integration — Active Response track (Step 3+) |
| **Preceding ADRs** | ADR-008 (Bio-Agentic Safety / Oncologist), ADR-018 (Wazuh IOC push), ADR-019 (AR Confirmation Gate), ADR-020 (Credential Lifecycle) |

## Context

ADR-019 §"Out of scope for Step-1" notes that a *two-person rule* — requiring
two distinct authorised operators to co-sign a destructive Active Response
(AR) action — is desirable for production AR rollouts but is not part of
Step-1 (IOC push) or Step-2 (read-only hunt + dashboard). This ADR records
that deferral as a load-bearing architectural commitment so that future AR
work cannot ship without re-opening the question.

The single-confirmation gate in ADR-019 already covers the LLM07 / Oncologist
case (no autonomous AR; operator must press a button). The two-person rule
is an additional control layered on top of that gate, mitigating:

1. **Operator account compromise.** A single compromised operator credential
   is sufficient to trigger AR under ADR-019 alone.
2. **Insider risk.** A single malicious authorised operator can issue AR
   without any co-signer review.
3. **High-blast-radius operations.** Network-wide isolation, mass account
   lockouts, and cross-tenant rules cross a threshold where dual control is
   industry-standard (PCI-DSS 12.5.x, SOC 2 CC6.x patterns).

## Decision

**Defer two-person rule implementation to a future sprint.** Step-1 (IOC
push, this branch) and Step-2 (read-only hunt) do not invoke AR, so the
single-confirmation gate from ADR-019 is sufficient at present. When AR
ships in Step-3, the two-person rule must be re-evaluated as a P0 design
input before any AR endpoint becomes callable from the MCP wrapper layer.

This ADR establishes the **re-attempt condition** below; absence of a
documented re-attempt would risk Step-3 shipping AR with single-confirmation
only and the issue falling off the radar.

## Consequence

* No code change in Step-1. ADR-021 is a documentation-only commitment.
* ADR-019's single-confirmation gate remains the sole AR safety boundary
  until Step-3 design opens.
* The deferral is explicit and traceable; it is **not** an implicit gap.
* HEARTBEAT.md is unaffected — no monitoring task is needed for an
  unimplemented control.

## Re-attempt condition

When the Step-3 sprint kicks off (first AR endpoint design), the architect
**must** open a follow-up ADR (proposed name: `ADR-N-two-person-rule.md`)
that:

1. Either ratifies a two-person rule design (recommended scope: AR endpoints
   marked `destructive=true` in the wrapper registry), or
2. Explicitly documents why single-confirmation is sufficient for the
   specific AR scope being shipped (e.g. "Step-3 AR is restricted to
   reversible firewall blocks with auto-expiry and no account/process
   actions; single-confirmation matches blast radius").

The follow-up ADR must reference this ADR-021 in its preceding-ADRs list.

## Trade-offs considered

### Option A — Implement two-person rule now, in Step-1

Rejected. Step-1 has no AR surface; the rule would have nothing to gate.
Implementing the co-sign machinery (token issuance, second-operator session,
expiry, audit) without a callsite produces dead code and obscures the
real Step-3 design space.

### Option B — Document the deferral in ADR-019 only, no separate ADR

Rejected. ADR-019 mentions the deferral in a sub-section, but a sub-section
in a different ADR is structurally hidden from anyone reading the AR design
in isolation. A standalone ADR-021 ensures the constraint surfaces in the
ADR index and in greps for `two-person` / `dual control`.

### Option C — Defer informally (no ADR)

Rejected. Per the project's verification-before-claiming-completion habit
and the commit-as-evidence pattern, undocumented deferrals tend to become
permanent gaps. Filing ADR-021 makes the deferral auditable.

## References

* ADR-008 — Bio-Agentic Safety (Oncologist principle)
* ADR-018 — Wazuh IOC Push Integration
* ADR-019 — AR Confirmation Gate (referenced "out-of-scope" deferral)
* ADR-020 — Credential Lifecycle (single-operator credential rotation)
* OWASP LLM Top 10 — LLM07 (Insecure Plugin Design)
* PCI-DSS 12.5.x — Dual control patterns for sensitive operations
