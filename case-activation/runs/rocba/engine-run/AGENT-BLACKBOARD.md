# ROCBA — Agent ↔ Blackboard Communication (Trinity engine run)

> **What this is.** Unlike the [tool-sequence driver run](../EXECUTION-LOG.md), this is a full **Trinity
> Loop engine** run (`agentropix-sift run`) over the ROCBA C-drive E01 — the 7-agent swarm + 6 ATT&CK
> detectors publishing findings to a shared **blackboard**, with the Architect→Critic loop pruning the
> plan across iterations. It shows **how the agents communicate in the backend**: agents talk through
> *findings on the blackboard*, not through prompts. Run **2026-06-13**, `budget_exhausted` after the
> full 5 iterations. Evidence SHA-256 `f2eb856d…` (matches ground truth). Honest negatives kept.

## Run headline

| Metric | Value |
|---|---|
| Findings | **351** | 
| Tool calls | **509** |
| Blackboard publish events | **21** (across **13 agents**) |
| Trinity iterations | **5** (`iterations_completed: 5`, `status: budget_exhausted`, `critic_score: 1.0`) |
| Evidence SHA-256 | `f2eb856d6fb48e3928e6b6d388b2f116a57b735137354a7eaddca951d81b5c67` |

Full machine-readable trace: [`report.json`](report.json) (trimmed for repo; full local) ·
agent-comms log: [`blackboard-events.jsonl`](blackboard-events.jsonl) · sealed audit:
[`report.audit-log.json`](report.audit-log.json).

## 1. Agents publishing to the blackboard

Each agent runs its forensic tools, then **publishes its findings to the shared blackboard** with a
timestamp and duration. The `agent.*` entries in the trace are those publish events
([`blackboard-events.jsonl`](blackboard-events.jsonl)):

| Agent | Findings published | Notes |
|---|---|---|
| `artifact` | **326** | the long pole — **~26.6 min** (1,597,554 ms) of Sleuth Kit `ifind`/registry/artifact lookups over the 81 GiB image |
| `hunt` | **14** | cross-source **correlations** fused from other agents' blackboard findings |
| `yara_hunt` | 2 | (YARA itself skipped — `AGENTROPIX_YARA_MOUNT_PREFIX` unset; honest negative) |
| `t1059_001_iex_loopback_c2` | 2 | ATT&CK detector (IEX loopback C2) |
| `memory` · `timeline` · `filesystem` · `null_session_baseline` · `injection_detector` · `t1546_008_accessibility_ifeo_hijack` · `t1071_001_svchost_outbound_http` | 1 each | specialists + ATT&CK detectors |
| `discovery` · `mail` | published across **all 5 iterations** | never marked *stable* → kept re-running (see §2) |

Sample publish events (the literal agent→blackboard messages):

```json
{"ts":"2026-06-13T22:55:39.614319+00:00","agent":"memory",    "event":"publish","detail":"1 finding(s)",   "duration_ms":0.14}
{"ts":"2026-06-13T22:55:58.023217+00:00","agent":"timeline",  "event":"publish","detail":"1 finding(s)",   "duration_ms":18408.87}
{"ts":"2026-06-13T22:56:58.030566+00:00","agent":"filesystem","event":"publish","detail":"1 finding(s)",   "duration_ms":60006.16}
{"ts":"2026-06-13T23:23:35.593493+00:00","agent":"artifact",  "event":"publish","detail":"326 finding(s)", "duration_ms":1597554.27}
```

A finding promoted by `hunt` is a **Correlation** — only created when enough agents corroborate the same
token (quorum). That is the cross-agent communication: `hunt` reads what `memory`/`artifact`/`timeline`
put on the blackboard and fuses it, rather than re-deriving it.

## 2. The Trinity loop — iteration-over-iteration plan shrink (self-correction)

The Architect proposes the plan; the Critic scores the blackboard and marks agents **stable**; the next
iteration **drops the stable agents and re-runs only the unstable ones** (Reflexion-lite). This is the
agent system *changing its own approach* between iterations:

| Iter | Plan (agents run) | Critic marks stable | Dropped next | Critic | Halt |
|---|---|---|---|---|---|
| 1 | **all 13 agents** | 11 | — | 1.0 | no |
| 2 | **`[discovery, mail]`** | 11 | 11 (the stable ones) | 1.0 | no |
| 3 | `[discovery, mail]` | 11 | 11 | 1.0 | no |
| 4 | `[discovery, mail]` | 11 | 11 | 1.0 | no |
| 5 | `[discovery, mail]` | 11 | 11 | 1.0 | no |

**The approach visibly changed:** 13 agents → 2 agents after iteration 1, because the Critic found 11 of
them *stable* (no new evidence). Only `discovery` and `mail` never stabilized, so they kept running —
which is also why the loop never hit the convergence fingerprint and instead ran to the **5-iteration
budget** (`budget_exhausted`). The full per-iteration records are in
[`report.json` → `iterations[]`](report.json).

## 3. Honest negatives (kept on the record)

- **`budget_exhausted`, not convergence-halt** — `discovery`/`mail` kept producing, so the loop spent its
  full 5-iteration budget rather than halting on a stable fingerprint.
- **YARA skipped** — `AGENTROPIX_YARA_MOUNT_PREFIX` was unset for the E01, so the YARA scan was skipped
  (logged, not faked). The `yara_hunt` agent still published 2 bookkeeping findings.
- **Audit log: 0 sealed entries** — no findings were examiner-approved (this is an unattended engine run;
  DRAFT→APPROVED is the human HMAC hard-stop), so the courtroom audit log is empty by design.
- **Token usage:** none collected — the engine is token-blind (deterministic); tokens are client-side.

## How this differs from the driver run

The sibling [`EXECUTION-LOG.md`](../EXECUTION-LOG.md) is a **tool-sequence driver** run (individual MCP
tool calls). *This* run is the **Trinity engine** — the multi-agent swarm + blackboard + Critic loop —
which is where the agent-to-agent (agent↔blackboard) communication actually happens. Both are real,
live-MCP captures of the same ROCBA evidence.
