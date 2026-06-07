> Section 11 · ADR — Architecture Decision Records | [Portal Index](../../INDEX.md)

# Section 11 — Architecture Decision Records (ADRs)

An **Architecture Decision Record** captures one significant architectural decision
together with its context, the options weighed, and the consequences. ADRs are
immutable once accepted — if a decision changes, a *new* ADR supersedes the old one
rather than editing history.

This section mirrors the canonical ADRs from the oracle repository
(`/home/admin2/agentropix-sift/docs/adr/`). Each page carries the original decision
text plus a portal breadcrumb; sibling-ADR links resolve within this section, and
references to source/tests/runbooks cite the oracle path (the oracle wins any conflict).

## How to read the status column

Statuses are grounded in each ADR's own `Status` field and reconciled against the
oracle status audit (`docs/adr/_STATUS-AUDIT.md`). Treat them literally:

- **Implemented / Accepted** — decided and in the codebase.
- **Proposed** — decided on paper but **NOT shipped**. Do not depict as live.
- **Deferred** — formally documented, deliberately not implemented (or measurement
  postponed). Code may have landed even where live measurement is deferred.

> **Reconciliation note (ADR-024).** ADR-024's own header still reads
> `Status: Proposed`, but an in-file audit banner (2026-06-05) records that the
> `report_export` MCP tool shipped (commit `3f633be3c`, "ADR-024 Phase 5"). It is
> listed below as **Proposed (audit: shipped — header pending update)** to preserve
> the literal field while flagging the discrepancy. The oracle header is the item to
> correct upstream.

## Strategic ADRs (001–008) — the eight foundational decisions

| # | Title | Status | Decision (one line) |
|---|-------|--------|---------------------|
| [001](ADR-001-sdk-selection.md) | SDK Selection (Chimera Stack) | Implemented | Adopt a multi-provider SDK stack (LangChain + LiteLLM + Instructor) to avoid vendor lock-in and keep workflows composable and observable. |
| [002](ADR-002-execution-engine.md) | Execution Engine (Ralph Orchestrator) | Implemented | Extract the proven Ralph orchestration loop as the core execution engine, with multi-provider adapters. |
| [003](ADR-003-state-persistence.md) | State Persistence (Git checkpointing) | Implemented | Persist agent state as Git checkpoints for a full audit trail, branchable exploration, and resume-from-any-point recovery. |
| [004](ADR-004-identity-system.md) | Identity System (SPIFFE/SPIRE) | Implemented | Use SPIFFE/SPIRE for zero-trust, auto-rotating, cloud-native workload identity (the MHC-token analogue). |
| [005](ADR-005-message-bus.md) | Message Bus (Redis Streams) | Implemented | Use Redis Streams as the cytokine-network message bus — simple to operate, persistent, with consumer groups. |
| [006](ADR-006-memory-system.md) | Memory System (Zep) | Implemented | Adopt Zep for semantic retrieval, automatic summarization, and purpose-built LLM memory (epigenetic memory). |
| [007](ADR-007-deployment-model.md) | Deployment Model (Kubernetes) | Implemented | Deploy on Kubernetes for scalable, cloud-agnostic operation with a rich ecosystem (the StemCell niche). |
| [008](ADR-008-safety-architecture.md) | Safety Architecture (Bio-Agentic) | Implemented | Layered defense-in-depth, fail-safe safety model ("the Oncologist") that defaults to stopping rather than continuing. |

## Capability & forensic ADRs (009–024)

| # | Title | Status | Decision (one line) |
|---|-------|--------|---------------------|
| [009](ADR-009-task-router.md) | Intelligent Task Router | ⚠️ **Proposed** (NOT shipped) | Add an intelligent task router to lift complex-task success rate and reach single-agent parity, reusing ~70% existing infrastructure. |
| [010](ADR-010-genesis-module.md) | Genesis Module Architecture | Accepted (2026-01-18) | Introduce the Genesis Module as a pure mathematical layer implementing the bio-agentic algorithms. |
| [011](ADR-011-evidence-gates.md) | Evidence-Type Gate Consolidation | Accepted | All four data-fetching agents call one shared evidence-type helper — single source of truth, no inline literals. |
| [012](ADR-012-extract-files.md) | `mcp_extract_files` (raw-E01 extraction) | Accepted | Add one schema-clean `extract_files` MCP tool with typed Pydantic I/O and defense-in-depth Thymus validation. |
| [013](ADR-013-evtx-wrapper.md) | `mcp_get_evtx` (Windows Event Log wrapper) | Accepted | Ship a dual-format `get_evtx` wrapper that auto-detects evtx_dump output formats. |
| [014](ADR-014-W072-impacket-secretsdump.md) | Credential-dump triage (impacket) | Accepted (path forward; BMAD Phase 6) | Keep the vol3 `>=2.27.0` pin; route credential-dump triage via `impacket-secretsdump.py`; W-072 → DEFERRED MEDIUM (M7+). |
| [015](ADR-015-context-engineering.md) | Context Engineering — Progressive Disclosure | Accepted | Make SIFT memory hierarchical with strict load-on-demand semantics to preserve prompt-cache stability. |
| [016](ADR-016-courtroom-audit.md) | Courtroom Audit + Cryptographic Sealing | Accepted | Enforce three court invariants (inference-constraint declaration, provenance, HMAC report seal) in `courtroom.py`. |
| [017](ADR-017-tailnet-mcp-exposure.md) | Tailnet-only HTTP MCP exposure | Accepted | FastMCP `--transport http` defaults loopback-only; tailnet exposure is explicit opt-in via `--host`. |
| [018](ADR-018-wazuh-ioc-push.md) | Wazuh IOC Push Integration | Accepted | Push IOCs to Wazuh with a per-PUT HMAC-SHA256 chain-of-custody seal behind a fail-closed evidence gate. |
| [019](ADR-019-ar-confirmation-gate.md) | Active Response Confirmation Gate | Accepted | Require an explicit human confirmation gate before any destructive Active Response (blast-radius + OWASP LLM07). |
| [020](ADR-020-credential-lifecycle.md) | Wazuh Credential Lifecycle | Accepted (review F-5) | Define a secrets-disciplined Wazuh credential lifecycle (flag → gitignore → 0600 → never echo) to contain blast radius. |
| [021](ADR-021-two-person-rule-defer.md) | Two-Person Rule for Active Response | ⚠️ **Deferred** (documented, not implemented) | Defer the two-person rule; the ADR-019 single-confirmation gate suffices while no AR is invoked. |
| [022](ADR-022-audit-log-seal.md) | Audit-Log Seal — HMAC Envelope | Accepted | Add a peer-sealed audit-log file under the same per-run session key, cross-bound into the report seal (extends ADR-016). |
| [023](ADR-023-pilot-feedback-pipeline.md) | Pilot-Feedback Pipeline | Accepted | Resurrect Sprint-18 Story-18.1 — promote the feedback script and un-ignore the survey directory (reversible). |
| [024](ADR-024-multi-tier-report-engine.md) | Multi-Tier Report Generation Engine | ⚠️ **Proposed** (audit: shipped — header pending update) | Add tiered (exec/business/technical) report generation that reuses the court-hardened data layer with provenance fidelity. |

## Milestone & defer ADRs (non-numbered)

| ADR | Title | Status | Decision (one line) |
|-----|-------|--------|---------------------|
| [M6.3-event-window](ADR-M6.3-event-window.md) | Per-parser sampling + priority filter (Plaso wrapper) | Accepted | Add per-parser sampling and a priority filter in the Plaso wrapper layer to unblock the M6.3 sprint. |
| [M6.3-residual-gap](ADR-M6.3-residual-gap.md) | Wrapper succeeds · detector emits zero findings on live DC | Accepted (documented gap) | Record the residual gap (wrapper OK, detector silent on live DC) as a documented gap, not a design change; M6.3-event-window keeps its Accepted status. |
| [W051-defer](ADR-W051-defer.md) | DEFER live recall of EventID 4624 detector | Deferred (code landed; measurement → M6.3) | Code shipped and unit-tested; defer the live-recall contribution measurement to M6.3. |
| [W052-T2-defer](ADR-W052-T2-defer.md) | DEFER Truth #2 (RUNDLL32 stager) | Deferred | Defer crediting ground-truth #2 (RUNDLL32 stager) pending stronger evidence keywords. |
| [W052-T6-defer](ADR-W052-T6-defer.md) | DEFER Truth #6 (beacon AppData injection) | Deferred | Defer crediting ground-truth #6 (beacon AppData injection) pending stronger evidence. |
| [W054-defer](ADR-W054-defer.md) | DEFER live recall of MFT timestomp detector | Deferred (code landed; measurement → M6.3) | Code shipped and unit-tested; defer the live-recall contribution measurement to M6.3. |

## Template

| Page | Purpose |
|------|---------|
| [ADR-TEMPLATE.md](ADR-TEMPLATE.md) | The standard MADR-style format every new ADR follows. |

## Status lifecycle

```
Proposed → Accepted/Implemented → [Deprecated | Superseded by ADR-XXX]
```

- **Proposed** — under review / decided on paper, open for discussion, not shipped.
- **Accepted / Implemented** — finalized and present in the codebase.
- **Deferred** — deliberately not implemented (or live measurement postponed).
- **Deprecated** — no longer relevant (technology obsolete).
- **Superseded** — replaced by a newer ADR.

## Sources

- Oracle ADR directory: `docs/adr/` in `/home/admin2/agentropix-sift`
- Oracle ADR index: `docs/adr/README.md`
- Oracle status audit: `docs/adr/_STATUS-AUDIT.md` (2026-06-03)
- ADR format references: Michael Nygard's ADR format · MADR (Markdown ADR)
