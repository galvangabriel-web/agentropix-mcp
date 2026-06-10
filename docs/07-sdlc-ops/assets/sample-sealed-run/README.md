# Sample sealed run — a real committed trace artifact

> **Section 07 · SDLC & Ops (asset).** A genuine, HMAC-sealed Agentropix-SIFT triage
> output committed so a reviewer can inspect the telemetry + tamper-evidence pipeline
> on real bytes — not just read about it.
> **Related:** [Persisted Artifacts](../../../03-data/persisted-artifacts.md) ·
> [Audit & Courtroom Seal](../../../05-safety-forensics/audit-courtroom.md) ·
> [Observability & Integrity Notes](../../observability-and-integrity-notes.md)

## What's here

| File | What it is |
|---|---|
| `report.json` | The sealed triage report (356 KB) — schema-validated, HMAC-sealed |
| `report.audit-log.json` | The cross-bound audit-log companion (the seal pair) |

Provenance: the `W-238-clean-run` run captured in the engine repo
(`Reports_results/W-238-clean-run-20260524/`), copied **byte-verbatim** — any edit
would break the seal. The per-run HMAC **session key is deliberately NOT included**
(it is the one secret in that directory); without it the seals here are inspectable
but **not independently re-verifiable** — that is expected and honest, not a defect.

## What it demonstrates (the fields a reviewer cares about)

- **`trace.tool_calls`** — **245** real tool invocations, each with timing/args/output
  provenance; `trace.counters`, `trace.total_duration_ms`, `start_time`/`end_time`.
  This is the committed evidence that the `_trace.py` telemetry pipeline runs end to end.
- **`thymus_audit`** — the read-only-policy decision log (ALLOW/REJECT per evidence access).
- **`evidence_image_sha256`** — the pre-run hash that binds this report to the image bytes
  (the courtroom binding; see the integrity note on the *post*-run re-hash being out of scope).
- **`report_seal`** + **`audit_log_seal`** — the HMAC-SHA256 seals (the audit-log seal is
  cross-bound into the report before the report is sealed, per ADR-022).
- **`iterations`**, **`critic_score`**, **`critic_feedback`**, **`completion_proofs`** — the
  Trinity-Loop control record (the deterministic Critic halt evidence).

## Honest caveats (read before judging the numbers)

- **`status: budget_exhausted`** — this run hit its iteration/budget cap; it is a real run,
  not a curated best-case, kept precisely because it shows the honest stopping behaviour.
- The audit-log companion's `metadata` reports an **empty entry set** for this run
  (`entry_count: 0` / audit-log-disabled path) — the on-disk Thymus JSONL is conditional on
  `AGENTROPIX_AUDIT_LOG`; the in-report `thymus_audit` block is the populated record. See
  [Observability & Integrity Notes](../../observability-and-integrity-notes.md).
- **No token-usage metrics** appear anywhere in this artifact — by design (the LLM is the edge
  consumer, the deterministic engine is uninstrumented for tokens). Same note documents why.
- **Blackboard / agent-to-agent telemetry** is represented *inside* `report.json`
  (`iterations[]`, `trace.tool_calls`, `findings[].agent`), not as a separate `blackboard.log`
  — there is no standalone swarm-message log to ship, and this README does not promise one.

## Flagship full-case session logs

The richest session transcripts are the committed run records:
[SRL-2018 EXECUTED-RUN](../../../../case-activation/runs/srl-2018-compromised-enterprise/EXECUTED-RUN.md)
and [VANKO EXECUTED-RUN](../../../../case-activation/runs/vanko-abducted-zebrafish/EXECUTED-RUN.md).
Their raw per-action casts / `session-actions.log` stay local by documented design (large, and
carry unscrubbed host detail) — the EXECUTED-RUN transcripts are the published, reviewable form.
