# 07 · SDLC & Operations

Building, testing, securing, configuring, deploying, evaluating, and maintaining the engine.

## Read in this order

1. [implementation.md](implementation.md) — how the codebase is organized and built (module map).
2. [testing.md](testing.md) — the test topology, the gates, and ground-truth recall (4464 tests; 72/72 disk; 108/118 memory).
3. [security-model.md](security-model.md) — the threat model: Thymus, denylists, redaction, read-only boundary.
4. [recovery-resilience.md](recovery-resilience.md) — the failure-mode catalogue and chaos/recovery classes.
5. [configuration.md](configuration.md) — the `AGENTROPIX_*` environment surface and what each var tunes (dual-audience).
6. [deployment.md](deployment.md) — install on SIFT, expose over a tailnet, and find the runbooks (dual-audience).
7. [dataset-recall.md](dataset-recall.md) — the evaluation corpus and recall methodology (how ground truth is defined).
8. [evaluation-scorecard.md](evaluation-scorecard.md) — the independent 10-persona BMAD verdict and the Devpost rubric self-grade.
9. [maintenance-dual-repo.md](maintenance-dual-repo.md) — why there are two repos/package names and how the one-way `sift` → `mcp` sync stays faithful.
10. [observability-and-integrity-notes.md](observability-and-integrity-notes.md) — honest limitations: post-run re-hash (not implemented) and token-usage metrics (uncollected by design), plus a committed [sealed-run sample](assets/sample-sealed-run/README.md).
10. [env-vars.md](env-vars.md) — *(shared reference)* the full machine-extracted `AGENTROPIX_*` environment-variable surface.

## Accuracy & honesty supplements

- [ACCURACY-REPORT.md](ACCURACY-REPORT.md) — the consolidated honesty page: the verbatim "partially curve-fit" methodology disclosure, the honest 108/118 (91.5%) combined recall with T1003.002 = 30/40 worst case, the April 1/7→7/7 gate-failure history, W-numbered false positives/hallucinations the project caught in its own output, and **§6 — the architectural (not prompt-based) evidence-integrity guarantee**.
- [evidence-integrity-visual.md](evidence-integrity-visual.md) — graphical companion to ACCURACY-REPORT §6: colour-coded architecture diagrams + real-data charts showing how the layers interconnect, how Thymus allows/denies access, architectural-vs-prompt-based guardrails, and what happens if the model ignores the restriction (8 committed PNGs, grounded in real code + real runs).
- [cross-modal-recall-summary.md](cross-modal-recall-summary.md) — mirrored 2026-05-06 primary-source snapshot (156/156 per-IOC; base-rd-01 0% coherence by design) that [dataset-recall.md](dataset-recall.md) §4 consolidates.
- [../12-CASES-REPORTS/srl-2018-artifact-inventory.md](../12-CASES-REPORTS/srl-2018-artifact-inventory.md) — the full SRL-2018 finding inventory (9,578 findings / 29 hosts) substantiating the recall denominators.

## Committed evidence artifacts

- [assets/full-run-evidence/README.md](assets/full-run-evidence/README.md) — index for the machine-readable full-run execution evidence: two sealed run reports plus the unedited session transcripts (failures committed alongside successes), with a worked finding → tool-call → seal trace.
  - [assets/full-run-evidence/report-dc.json](assets/full-run-evidence/report-dc.json) — sealed full Trinity-Loop report for the SRL-2018 `base-dc-cdrive.E01` disk image (status `complete`, 2 iterations, 275 findings, 212 timestamped tool calls).
  - [assets/full-run-evidence/report-sample.json](assets/full-run-evidence/report-sample.json) — sealed full-run report for the synthetic `samples/sample.dd` fixture, ended `budget_exhausted` (5 iterations) and kept as honest-failure evidence.
  - [assets/full-run-evidence/00-environment.txt](assets/full-run-evidence/00-environment.txt) — the Phase-2 SIFT live-fire host fingerprint at run time (kernel, uv, Python, glibc versions).
  - [assets/full-run-evidence/01-doctor.txt](assets/full-run-evidence/01-doctor.txt) — the pre-run `doctor` toolchain check: 15 forensic binaries resolved on PATH, 3 honestly reported MISSING.
  - [assets/full-run-evidence/02-sample-seal-check.txt](assets/full-run-evidence/02-sample-seal-check.txt) — the seal-verification transcript for the sample run (`verify_seal: True`, matching 3 findings / 38 tool-call counts).
- [assets/sample-sealed-run/README.md](assets/sample-sealed-run/README.md) — describes the committed real HMAC-sealed triage trace so a reviewer can inspect the telemetry/tamper-evidence pipeline on real bytes.
  - [assets/sample-sealed-run/report.json](assets/sample-sealed-run/report.json) — the committed sample sealed triage report (SRL-2018 base-dc, `budget_exhausted`, 5 iterations).
  - [assets/sample-sealed-run/report.audit-log.json](assets/sample-sealed-run/report.audit-log.json) — the companion audit-log JSON for the sample sealed run, carrying the HMAC `audit_log_seal`.
- [assets/recovery-resilience-1.svg](assets/recovery-resilience-1.svg) — full-size zoomable diagram asset for [recovery-resilience.md](recovery-resilience.md).
