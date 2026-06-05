# Testing — Topology, Gates & Ground-Truth Recall

> How Agentropix-SIFT is tested: the suite layout under `tests/`, the pytest markers, the
> coverage gate, and the ground-truth end-to-end recall gate that distinguishes a real
> forensic regression from an infrastructure failure.

The suite holds **4464** collected tests (`pytest --collect-only -q`; see
[CANONICAL_FACTS](../../.crew/facts.md)). The number is forward-drift-gated: doc lines that
quote it must cite this fact file, and stale literals (`1270`, `1129`, `1084`, `1073`,
`3881`, `3899`) are actively rejected by the upstream drift check.

---

## 1. Test topology

Tests live under `tests/`, partitioned by the layer they exercise:

| Suite | Path | What it covers |
|-------|------|----------------|
| Unit | `tests/unit/` | The largest suite — agent logic, wrappers, schema, scoring, env clamping. Mock-based, fast. |
| Integration | `tests/integration/` | Real-subprocess tests requiring SIFT binaries on PATH (and, for some, a staged E01 image). |
| Chaos | `tests/chaos/` | Fault-injection / resilience-path tests (R1–R5 classes — see [recovery-resilience](recovery-resilience.md)). |
| Provenance | `tests/provenance/` | Sealed provenance-chain validation (per-row HMAC re-verification). |
| Evidence gate | `tests/evidence_gate/` | Mutation-token mint/spend/revoke, one-shot + TTL semantics. |
| Approval sidecar | `tests/approval_sidecar/` | HMAC challenge/submit, nonce TTL, PBKDF2 auth, append-only hash chain. |
| Audit | `tests/audit/` | Standalone report + audit-log seal verification. |
| Wazuh | `tests/wazuh/` | SIEM integration — IOC models, denylists, push orchestration, active-response guard. |
| Secrets gate | `tests/secrets_gate/` | Secret resolution precedence and logging-safe redaction. |

```mermaid
graph LR
    subgraph fast["Fast / always-run (mock-based)"]
        U["unit/"]
        C["chaos/"]
        P["provenance/"]
        E["evidence_gate/"]
        A["approval_sidecar/"]
        S["secrets_gate/"]
        W["wazuh/ (unit)"]
    end
    subgraph gated["Gated on host capabilities"]
        I["integration/<br/>marker: integration"]
        WL["wazuh_live<br/>needs reachable manager+indexer"]
        RC["real_corpus<br/>needs /cases/SRL-* on disk"]
    end
    fast --> CI["CI / pre-commit"]
    gated -. "skip-with-reason<br/>when host lacks the fixture" .-> CI
```

The fast suites run everywhere with no external prerequisites; the gated suites
**skip with a self-describing reason** (naming every searched path) when the host lacks the
fixture, so a missing E01 or an unreachable Wazuh never turns into a false failure.

---

## 2. Pytest markers

The markers are declared in `pyproject.toml:74-79` and select the host-dependent tiers:

| Marker | Meaning |
|--------|---------|
| `chaos` | Fault-injection / resilience-path tests (mock-based, fast). |
| `integration` | Real-subprocess tests requiring SIFT tools on PATH. |
| `wazuh_live` | Requires a reachable Wazuh manager + indexer (gated on `WAZUH_INTEGRATION_ENABLED`). |
| `real_corpus` | Requires `/cases/SRL-2015` or `/cases/SRL-2018` on disk (orthogonal to `integration`). |

`asyncio_mode = "auto"` (`pyproject.toml:72`) means async test functions are collected
without per-test `@pytest.mark.asyncio` decoration — fitting because every agent is an async
coroutine over the MCP boundary.

---

## 3. Coverage gate

The `dev` dependency group pins `pytest-cov>=7.1.0` (`pyproject.toml:99`), and the type gate
is **basedpyright in `strict` mode** (`pyproject.toml:81-83`) — strict typing is itself a
correctness gate, not just a lint. Lint is **ruff** with the `E,F,W,I,UP,B,SIM` selectors
(`pyproject.toml:68-69`). See [setup-pre-commit] guidance in
[deployment](deployment.md) for wiring these into a commit-time hook.

---

## 4. The ground-truth E2E recall gate

The deepest correctness signal is the **Trinity Loop recall gate**: it runs the full
`run_triage()` pipeline against a real SANS E01 image and scores the findings against a
hand-authored ground-truth file.

### How it scores

`tests/integration/test_e2e_dc_recall.py` runs `run_triage(e01_image, max_iterations=5)`,
then scores the report's findings against the `expected_findings` and `scoring` blocks of
`samples/ground_truth_dc.yaml`. The ground-truth YAML is the **single evaluator** — there is
no second scoring implementation that could drift. Per-finding fingerprints are
`SHA-256[:16]` of `(source, description, evidence)`, used **only** for recall scoring (this
is deliberately *not* the Critic's dedup key, which is an unhashed 4-tuple `frozenset`
element in `critic.py`). Recall is `hits / total`, compared against
`scoring.recall_threshold`.

### Canonical recall numbers

From the last full evaluation run (2026-05-05), per [CANONICAL_FACTS](../../.crew/facts.md):

| Metric | Value |
|--------|-------|
| Disk recall (regression) | **72/72 (100%)** |
| Memory recall (combined) | **108/118 (91.5%)** |

The disk-recall figure carries a methodology caveat (post-hoc ground truth: 6 of 7
`ground_truth_*.yaml` authored from run output); the blinded variant is pending Theme 4
execution. Never quote a recall number that contradicts the fact file.

### The PLASO_TIMEOUT discriminator (W-128)

Recall numerics alone are not a clean pass. The gate carries a discriminator
(`_gate_failure_message`, `test_e2e_dc_recall.py`) that fails the run when the timeline
wrapper's `wrapper_error` contains `"timed out"` — **independently of recall**. This exists
because of a real silent-failure mode: run `28T190548Z` scored 4/7 = 0.571, numerically
clearing the 0.57 floor, yet Plaso had timed out and produced zero events, so the passing
recall was drawn entirely from non-timeline agents. The discriminator catches that case:

```python
if timed_out:
    return True, f"PLASO_TIMEOUT: {base} timeline wrapper_error={we!r}"
if recall < threshold:
    return True, base
return False, ""
```

A `PLASO_TIMEOUT` failure is never overridden by a numerically passing recall — the
timeline subsystem either produced events or the run failed. Synthetic dict-payload tests
(`TestRecallGateTimeoutDiscriminator`) pin this contract on hosts without the SANS image
staged, so the regression fails fast even where the live E01 cannot run.

---

## See also

- [recovery-resilience](recovery-resilience.md) — the R1–R5 chaos classes in detail.
- [implementation](implementation.md) — the code the tests exercise.
- [security-model](security-model.md) — the Thymus / seal invariants the audit suite checks.

[setup-pre-commit]: deployment.md
