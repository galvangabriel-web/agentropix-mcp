# System Accuracy & Validation Report

> **Provenance note.** Every numeric figure in this report is sourced from a real file
> tracked in this repository (`git ls-files`) and is cited inline (file + figure). Where a
> component has **no measured ground truth in the repo**, it is explicitly labelled
> **"not benchmarked — no ground truth in repo"** — no number is invented, estimated, or
> extrapolated for it. This document is a *code/QA* audit (engine logic, thresholds, test
> coverage); it does not restate or contradict the governing
> [`docs/08-reference/canonical-facts.md`](docs/08-reference/canonical-facts.md). It is a
> **companion** to the existing [`docs/07-sdlc-ops/ACCURACY-REPORT.md`](docs/07-sdlc-ops/ACCURACY-REPORT.md)
> (the recall/scorecard report) — it does not modify it; it cross-references it.

---

## 1. Overview & Scope

**System under audit.** Agentropix-SIFT's core logic is a deterministic **Trinity loop**
(`Architect → Swarm → Critic`) driving a **swarm of forensic agents** over a shared
Blackboard, exposing **72 MCP tools** built on **16 SIFT forensic wrappers**, with
**Python 3.12+** as the runtime baseline
([`docs/08-reference/canonical-facts.md`](docs/08-reference/canonical-facts.md):
72 tools, 16 wrappers, 4464 tests, 72/72 = 100% disk recall, 108/118 = 91.5% memory recall,
Python 3.12+).

Note: the audit prompt says "7-agent swarm", but the tracked `SWARM` tuple in
[`agentropix_mcp/src/agentropix_mcp/agents/__init__.py`](agentropix_mcp/src/agentropix_mcp/agents/__init__.py):45-58
contains **13 agent classes** (HuntAgent last). The "7" appears in the engine's recall
**ground truth** as the **DC-E01 cohit≥2 ladder** (7 measured tactic hits, e.g. 7/7 = 1.000)
in [`docs/07-sdlc-ops/ACCURACY-REPORT.md`](docs/07-sdlc-ops/ACCURACY-REPORT.md):56-61 — a
recall metric, not the agent count. Both are kept distinct below.

**Intended baseline (the recall numbers the system claims to hit).** Per
canonical-facts: **72/72 (100%)** disk-recall regression, **108/118 (91.5%)** combined
memory recall (worst band T1003.002 SAM at **30/40 = 75%**), **4464** collected tests.
A second, weaker-provenance framing — **156/156 = 1.000** per-IOC across all surfaces —
lives in [`docs/07-sdlc-ops/cross-modal-recall-summary.md`](docs/07-sdlc-ops/cross-modal-recall-summary.md):7-20
(49/49 disk + 107/107 memory + 83/83 cross-modal pairs) and is **operator-attested
per-IOC**, not sealed-run; ACCURACY-REPORT.md:44 explicitly tags it
"operator-attested per-IOC 156/156" and warns the two framings use different units and
must not be added.

**Audit scope.** This audit inspects the **deterministic engine logic** (Critic scorer +
halt cascade, convergence fingerprint, Architect planner + LLM reorder, the
orchestrator iteration budget), the **static thresholds/constants** that drive halting,
and the **tracked test coverage** of all of the above. Ground truth = tracked files only.
The decisive finding (Section 4–5) is that the engine's recall is well-measured
*end-to-end*, but the **engine's control logic has zero isolated tracked test coverage**:
only **3 test files** ship in the package
([`agentropix_mcp/tests/`](agentropix_mcp/tests/): `unit/test_thymus_policy.py`,
`unit/test_w108_w109_thymus_hardening.py`, `chaos/test_fault_paths.py` —
**90 test functions total**, 61 + 15 + 14, verified by `grep -c` against the tracked
files), and **none** exercise Trinity, the agents, the wrappers, correlation, or courtroom.

---

## 2. Component Benchmark Matrix

All figures cited from tracked files. "n/b" = **not benchmarked — no ground truth in repo**.

| Component / Module | Function | Ground Truth Baseline | Measured Accuracy / Error Rate | Performance Delta |
|---|---|---|---|---|
| **Critic deterministic scorer** (`trinity/critic.py`) | `score = min(1.0, max_conf + 0.25·#corr)` over Blackboard | Intent only: formula in [trinity-loop.md](docs/02-architecture/trinity-loop.md):31 + critic.py docstring; closest proxy = DC-E01 7/7 recall (ACCURACY-REPORT.md:60-61) | **n/b** — no `test_critic` in tracked tree; the 7/7=1.000 / 6/7=0.857 figures measure whole-swarm recall, not the isolated scorer | Not computable (no isolated baseline/measured pair) |
| **Critic halt cascade** (`critic.py`) | precedence: plan_gaps→cont; <min_iter→cont; score≥0.85→HALT; no_progress→HALT; else cont | Intent: critic.py docstring 7-31 + trinity-loop.md:142-201; threshold 0.85 deliberate (critic.py:13-14) | **n/b** — no tracked test asserts precedence, `==0.85` boundary, min-iter floor, or coverage guard | Not computable |
| **Convergence fingerprint** (`critic.py`:128) | `frozenset(agent,source,description,evidence)` fixed-point → no_progress halt | Mechanism: trinity-loop.md:154,182-191; depends on agent idempotence axiom (`agents/_base.py` docstring) | **n/b** — no test feeds the same board twice; idempotence axiom itself untested | Not computable |
| **Architect planner + Reflexion-lite drop** (`trinity/architect.py`) | returns canonical SWARM order; drops Critic-flagged "stable" agents when `AGENTROPIX_TRINITY_FEEDBACK=1` (default ON) | Intent: architect.py docstring 1-32, trinity-loop.md:100-101; cited "626/0" and "1448" baselines **not in tracked tree** | **n/b** — no `test_architect`; cited baselines untraceable in tracked files | Not computable (cited baselines untraceable) |
| **Architect LLM reorder (P5, opt-in)** (`architect.py`) | haiku reorder, accepted only as strict permutation; fail-open to deterministic; LRU cache 256 | Intent: architect.py docstring 24-31 + `_remap_names_to_classes` guard | **n/b** — no test of LLM path / parser / permutation guard / cache. Host is **OAuth, no API key** (CLAUDE.md) → SDK path raises → always falls through (dead path here) | Not computable (permute-only by design; recall unaffected) |
| **Trinity orchestrator** (`run_triage`, max_iterations budget) | hash-binds image, loops 1..max_iterations (default 5), Architect→swarm→Critic, breaks on halt, emits `budget_exhausted` | Intent: trinity-loop.md:70,178-185; schema requires `max_iterations>=1` ([report.schema.json](agentropix_mcp/src/agentropix_mcp/schema/report.schema.json):5,9). **Source absent from tracked tree** | **n/b** — implementation file not tracked (only `wazuh/orchestrator.py` exists, unrelated); cannot be inspected at all | Not computable (implementation not tracked) |
| **Blackboard correlations / quorum** (`agents/_blackboard.py`) | tokens appearing in ≥`quorum_threshold` agents become correlations feeding the score | default quorum **2**, hard `ValueError` if `<2` (_blackboard.py:86,90-91,119) | **n/b** — no tracked test; only implicitly exercised by whole-engine recall | Not computable |
| **Cross-source correlation tools** (`wrappers/correlation.py`) | `correlate_timeline` / `build_process_tree` / `pivot_on_ioc` / `detect_sweep` (4 tools, lines 211/313/413/591) — HuntAgent's cohit≥2 join engine | No isolated GT; implicitly inside the 49/49 disk figure (cross-modal-recall-summary.md:17) | **n/b** — no test references `correlation`; cohit≥2 logic only implicitly covered | Not computable |
| **Courtroom seal/verify engine** (`courtroom.py`) | `seal_report`/`verify_seal`/`seal_audit_log`/`verify_audit_seal`/`evidence_image_sha256` (lines 161/173/269/284/89) | Graded qualitatively (D3 16/20, [evaluation-scorecard.md](docs/07-sdlc-ops/evaluation-scorecard.md)); sample artifact at `docs/07-sdlc-ops/assets/sample-sealed-run/` | **n/b** — no `test_courtroom`; seal/verify roundtrip has no correctness test | Not computable |
| **Detector T1087.002 null-session baseline** (`detectors/t1087_002_null_session_baseline.py`) | anomaly band `max(mean+z·stddev, ABS_FLOOR/10)` over 4624 ANONYMOUS LOGON buckets | base-rd-02 carries 6148 events / 939 hour-buckets / flat ceiling 25 / median 5 (t1087_002...py:468-496) | **n/b** as isolated detector — the figures are *fixture description in code*, not a measured precision/recall for the detector | Not computable in isolation |
| **Detector T1059.001 IEX loopback C2** (`detectors/t1059_001_iex_loopback_c2.py`) | flags Cobalt-Strike loopback stagers | SRL-2018 carries **6** loopback stagers (t1059_001...py:13) | **n/b** as isolated detector (figure is the source-signal count in code) | Not computable in isolation |
| **Whole-engine DC-E01 recall (the 7-tactic ladder)** | end-to-end swarm recall on `/cases/SRL-2018/base-rd-02-cdrive.E01` | the climb 1/7→7/7, gate 0.57 (ACCURACY-REPORT.md:48-61) | **7/7 = 1.000** (M6.12), **6/7 = 0.857** live re-run (ACCURACY-REPORT.md:60-61) | Met intended ceiling 7/7; one live-rerun regression to 6/7 (T1055 plaso non-determinism, W-071) |
| **Disk-recall regression** | full disk recall regression | 72/72 target | **72/72 (100%)** (canonical-facts.md:15) | At baseline |
| **Memory recall (combined)** | combined memory IOC recall | 108/118 target | **108/118 (91.5%)**; worst band T1003.002 **30/40 = 75%** (canonical-facts.md:18-19, ACCURACY-REPORT.md:40-41) | 10/118 missed (all in the SAM band) |
| **Cross-modal per-IOC snapshot** | per-host per-IOC across surfaces | n/a | **156/156 = 1.000** (49/49+107/107+83/83); coherence mean **18.0%**, range 0.0%–30.0%, base-rd-01 = 0.0% by design (cross-modal-recall-summary.md:7-36) | Operator-attested provenance (weaker than sealed-run) |
| **Thymus policy** (`thymus_policy.py`) | safety-gate policy | the only well-covered area | **61 + 15 = 76 tracked unit assertions** (`test_thymus_policy.py` 61, `test_w108_w109_thymus_hardening.py` 15) | The single component with real isolated coverage |
| **Fault/chaos paths** (subprocess/EWF cleanup) | tmpdir/EWF-mount teardown on timeout/failure | n/a | **14 tracked chaos tests** (`chaos/test_fault_paths.py`) | Covered for fault teardown only |

---

## 3. Deep Dive: Semantic & Execution Fidelity

### Critic deterministic scorer (`agentropix_mcp/src/agentropix_mcp/trinity/critic.py`)
- **Operational objective:** produce a deterministic, LLM-free confidence score
  `score = min(1.0, max_conf + 0.25·#correlations)` (critic.py:122) so a re-run on a
  seeded Blackboard yields an identical score and an auditable halt decision.
- **Failure modes (present in code):** empty Blackboard → `TrinityResult(0.0, ...)` and
  fingerprint reset (critic.py:115-118); score clamped at 1.0 via `min(1.0, …)` so
  unbounded correlations cannot overflow; **no guard** that `f.confidence` is numeric
  (a `None`/non-numeric confidence would break the `max()`).
- **Validation gap:** the single load-bearing scoring formula (0.25 weight, 1.0 cap, empty
  reset) is asserted only in prose (trinity-loop.md:31) and **never executed by a tracked
  test** — there is no `test_critic` in `git ls-files agentropix_mcp/tests`.

### Critic halt-decision cascade (`critic.py`)
- **Operational objective:** decide `should_halt` by fixed precedence — coverage guard
  (W-083) → min-iterations floor → `score >= 0.85` → no-progress fixed point → continue.
  This is the most defensibility-critical logic (when the autonomous loop stops).
- **Failure modes (present in code):** `planned_agents`/`iteration` default to `None`,
  preserving legacy threshold-only halt (critic.py:172-178); `plan_gaps` computed against
  the PLANNED set, not the canonical SWARM; boundary `score >= threshold` is **inclusive**,
  so exactly **0.85 halts**; if the orchestrator never passes `iteration`, the
  min-iterations floor is **silently inert**.
- **Validation gap:** no tracked test asserts precedence ordering, the `==0.85` boundary,
  the floor, or the "guards override saturated score" invariant. The orchestrator that
  feeds `iteration`/`planned_agents` is itself **not in the tracked tree** (see below), so
  the floor's actual liveness cannot be confirmed against tracked source.

### Convergence fingerprint (`critic.py`:128)
- **Operational objective:** `no_progress` halt — if the `(agent,source,description,evidence)`
  frozenset is identical to the prior pass, the swarm added nothing → halt. Depends on the
  **agent-idempotence axiom** (same seed → identical findings).
- **Failure modes (present in code):** the tuple **excludes confidence and ordering**, so a
  re-publish of identical text at higher confidence reads as "no progress" and can halt
  prematurely; conversely a **non-idempotent** agent (new evidence string each pass) never
  triggers `no_progress`, silently shifting the loop onto threshold/max_iterations alone.
- **Validation gap:** correctness rests entirely on an **unenforced, untested** idempotence
  axiom; neither the axiom nor the fingerprint-equality halt has a tracked test.

### Architect planner + Reflexion-lite drop (`trinity/architect.py`)
- **Operational objective:** return the canonical SWARM in priority order; with
  `AGENTROPIX_TRINITY_FEEDBACK=1` (**default ON**, M8.3c) drop every agent the Critic flagged
  "stable", preserving SWARM order so HuntAgent stays last.
- **Failure modes (present in code):** drop applies only when the stable set is non-empty
  AND feedback is enabled; `prior_traces` (W-017 Lamarckian) are accepted but **do not alter
  output** (stored on `self.last_prior_traces` only); the default was **flipped ON** with no
  tracked test guarding the new default's planning effect.
- **Validation gap:** a default-on production planning change whose claimed safety baselines
  ("626/0", "1448") are **absent from the tracked repo** — the safety claim is unverifiable here.

### Architect LLM reorder pass (`architect.py`, P5, opt-in)
- **Operational objective:** optionally call haiku to reorder agents, accepting the result
  **only if it is a strict permutation** of the deterministic set; any failure falls open to
  the deterministic order. LRU cache (W-094, SHA-256 key, size 256).
- **Failure modes (present in code):** lazy `anthropic` import raises on missing SDK → caught
  → `None`; `_parse_llm_order` rejects malformed JSON; `_remap_names_to_classes` rejects
  wrong-count/dup/unknown/subset; broad `except` in `plan()` and `llm_reorder()` guarantee
  the LLM never blocks an iteration. Robust by construction.
- **Validation gap:** none of these guards are exercised by a tracked test, and on this
  **OAuth-only host (no API key)** the path is dead — it would never execute as written.

### Trinity loop orchestrator (`run_triage`, max_iterations budget) — **referenced, not tracked**
- **Operational objective (documented):** hash-bind image, loop `1..max_iterations`
  (default 5), Architect→swarm→Critic, break on `should_halt`, emit `complete` /
  `budget_exhausted`. This is where the iteration budget halt and the
  `planned_agents`/`iteration`→Critic wiring actually live.
- **Failure modes:** **cannot be assessed** — the file referenced by trinity-loop.md
  (`src/agentropix_sift/orchestrator.py`) is **not in the tracked tree** (only the unrelated
  `agentropix_mcp/src/agentropix_mcp/wazuh/orchestrator.py` exists).
- **Validation gap (largest):** the actual iteration-control choke point (budget halt,
  halt-break, Critic input wiring) is documented in detail but its source ships elsewhere —
  the portal's central engine claim is **unverifiable against this repo's tracked source**.

---

## 4. Algorithmic Drift & Bottlenecks

Exact file + line references for the static thresholds/limits/membership that steer halting:

1. **`trinity/critic.py:42`** — `_DEFAULT_HALT_THRESHOLD = 0.85`. Hardcoded halt threshold.
   Operator-overridable via `AGENTROPIX_CRITIC_HALT_THRESHOLD` (clamped 0.0–1.0, critic.py:76-81).
   Boundary is **inclusive** (`score >= threshold`, critic.py:192) so exactly 0.85 halts.
   No tracked test pins the boundary; rationale is prose-only.
2. **`trinity/critic.py:43`** — `_DEFAULT_MIN_ITERATIONS = 2`. Hardcoded min-iterations floor.
   Override `AGENTROPIX_CRITIC_MIN_ITERATIONS` (clamped 1–10, critic.py:83-88). Enforced
   **only when the orchestrator passes `iteration != None`**; otherwise the defence-in-depth
   floor is **silently inert** (critic.py:176-178).
3. **`trinity/critic.py:44`** — `_CORRELATION_WEIGHT = 0.25`. Hardcoded correlation weight in
   the score formula. **NOT env-overridable** (unlike the threshold) — a fixed magic constant
   that directly drives the halt decision, with no tracked test and no config knob.
4. **`trinity/critic.py:128`** — fingerprint tuple `(agent,source,description,evidence)`.
   Fixed-point **excludes confidence and ordering**; a re-publish with identical text but
   higher confidence reads as "no progress" and can halt. Drift risk if agents are not
   strictly idempotent — the axiom this depends on is unenforced/untested.
5. **`agents/_blackboard.py:86,90-91,119`** — `quorum_threshold` default **2**, hard
   `ValueError` if `<2`; **NOT env-tunable**. Correlations feed the Critic score
   (`0.25·#corr`), so this static value is a choke point on when multi-agent agreement
   raises the score to the halt threshold.
6. **`agents/__init__.py:45-58`** — static ordered `SWARM` tuple (**13 agent classes**;
   HuntAgent must be last to consume others' findings — comment lines 14-18). Architect plan
   and Critic `plan_gaps`/coverage-guard are computed against this static tuple; adding or
   reordering agents silently changes both plan and gap behaviour **with no guarding test**.
7. **`trinity/architect.py` (M8.3c)** — `AGENTROPIX_TRINITY_FEEDBACK` **default flipped ON**;
   the LLM-reorder LRU cache is fixed at **size 256** (W-094). Default-on behaviour change
   with no tracked test; cited regression baselines ("626/0", "1448") absent from the tree.

**Bottleneck summary:** every constant that governs *when the autonomous loop halts*
(0.85 threshold, 0.25 weight, quorum 2, min-iter 2, the confidence-blind fingerprint) is a
**static value with zero isolated tracked test coverage**; two of them (0.25 weight, quorum 2)
have **no config override at all**.

---

## 5. End-User Remediation Directives

Raw, actionable findings for operator validation. Severity reflects the evidence in the repo
only — not inflated.

1. **Add isolated unit coverage for `Critic.score`** — the formula
   `min(1.0, max_conf + 0.25·#corr)` (critic.py:122), the 1.0 saturation edge, and the
   empty-board reset (critic.py:115-118) are asserted only in prose. No `test_critic` ships.
2. **Add a halt-cascade regression test** — pin the precedence (coverage guard → min-iter →
   `score>=0.85` → no_progress → continue) and the **inclusive `==0.85` boundary**
   (critic.py:192). Currently unverified.
3. **Guard the min-iterations floor liveness** — the floor (critic.py:176-178) is inert
   unless the orchestrator passes `iteration`; add a test (and/or assertion) that confirms
   the orchestrator actually wires it.
4. **Test the convergence fixed-point AND enforce the idempotence axiom** — feed the same
   Blackboard twice (`no_progress==True`) and a changed board (`==False`); the agent
   idempotence the halt depends on (agents/_base.py docstring) is itself untested.
5. **Decide whether `_CORRELATION_WEIGHT = 0.25` (critic.py:44) should be configurable** —
   it directly drives halting but has no env override (unlike the 0.85 threshold) and no test.
6. **Add a planning test for the default-ON feedback drop (M8.3c)** — a production default
   was flipped with no tracked guard; the claimed safety baselines ("626/0", "1448") are
   **not in this repo** and cannot be relied on.
7. **Resolve the orchestrator source gap** — the documented `run_triage` /
   `max_iterations=5` budget halt (trinity-loop.md:70,178-185) references
   `src/agentropix_sift/orchestrator.py`, which is **not tracked here**. Either vendor the
   source into this package or annotate the docs that the central engine ships separately,
   so the iteration-control claim is verifiable.
8. **Benchmark or annotate the four metric-bearing modules with no isolated GT:**
   `wrappers/correlation.py` (4 cohit≥2 tools), `courtroom.py` (seal/verify roundtrip),
   detectors `t1087_002` and `t1059_001`. Each is currently
   **not benchmarked — no ground truth in repo**; either add a fixture-backed test or label
   them as such in the scorecard.
9. **Flag the 156/156 provenance difference** — the headline cross-modal figure
   (cross-modal-recall-summary.md:7-20) is **operator-attested per-IOC**
   (ACCURACY-REPORT.md:44), a weaker grounding than the sealed-run 72/72 (100%) /
   108/118 (91.5%) canonical numbers. Keep it labelled and never reconcile/add the two units.
10. **Note the only well-covered area:** Thymus policy (76 unit assertions) + fault paths
    (14 chaos tests) = the 3 shipped test files (**90 functions total**). The autonomous
    *engine* logic (Trinity/agents/wrappers/correlation/courtroom) has **no isolated tracked
    test** — concentrate net-new coverage there.

> **Repeat of provenance discipline:** all numbers above are repo-sourced and cited;
> components marked **"not benchmarked — no ground truth in repo"** had no measured ground
> truth in any tracked file, and no figure was invented for them. None of these figures
> contradict [`docs/08-reference/canonical-facts.md`](docs/08-reference/canonical-facts.md).
