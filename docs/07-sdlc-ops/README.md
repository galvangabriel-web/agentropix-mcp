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
