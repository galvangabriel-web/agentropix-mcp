# Anti-Hallucination: How Fabricated Findings Are Prevented

> **Section 05 · Safety & Forensics** — the anti-hallucination story.
> Related: [Provenance & Grounding](provenance-grounding.md) ·
> [Audit & Courtroom Seal](audit-courtroom.md) ·
> [Human-in-the-Loop](human-in-the-loop.md)

A forensic triage engine that an examiner cannot trust is worse than no engine
at all. Agentropix-SIFT is built so that **no fact in a report can originate
from a language model**. The LLM agents (Architect, Critic) *orchestrate*;
every finding is authored by a named, deterministic MCP tool that read bytes
off evidence. This chapter explains the concrete control points that make
fabrication structurally impossible — not merely discouraged: five that gate
every tool call, plus two verification gates (a completion contract and a
documentation drift gate) that keep the run and its numbers honest.

This is the **High Inference Constraint** contract (ADR-016, BMAD-M8 Phase
M8.2), documented in the module header of `src/agentropix_sift/courtroom.py:1-10`:

> "the LLM agents (Architect, Critic) only orchestrate; every fact in the
> report originates from a named deterministic MCP tool."

### Terms used on this page

This page assumes the following vocabulary. Each term is defined where it first
does work below, and every term names a real source file or test.

| Term | One-line definition | Defined / cited at |
|------|---------------------|--------------------|
| **Grounding** | The property that a claim in a report is anchored to evidence bytes a deterministic tool actually read — not to model output | [§1](#1--deterministic-tools-only-findings-no-llm-author), [§2](#2--evidence-sovereignty) |
| **Thymus REJECT** | A typed refusal returned by the read-only evidence policy before any I/O when a path is unsafe or out of bounds | [§3](#3--the-read-only-thymus-boundary) |
| **Evidence invariant (pre/post SHA-256)** | A cryptographic pin from report to the exact evidence bytes, captured at session start and re-checkable after a run | [§4](#4--the-prepost-sha-256-evidence-invariant) |
| **Deterministic fingerprint halt** | The Trinity loop stopping rule — a `frozenset` fixed-point plus a numeric threshold, never a model self-rating | [§5](#5--the-deterministic-fingerprint-halt) |
| **Completion-promise token** | A per-agent verifiable-completion contract: a fixed string an agent only emits after it published a real finding without a tool error | [§6](#6--completion-promise-tokens-verifiable-completion) |
| **Drift gate** | A CI check that fails the build if docs cite a number that contradicts the canonical-facts table (or let a correct number decay) | [§7](#7--canonical-fact-drift-gates) |

**Grounding**, in this system, is not a soft heuristic ("the model tried to
stay close to the data"). It is the structural guarantee that every
report-bound fact traces to bytes a named deterministic tool read off
evidence. Controls 1–4 below are the mechanisms that make grounding hold;
controls 5–7 keep the loop and the documentation honest about it.

## Contents — what's in this page (and what to expect)

This page walks the seven code-enforced controls that make fabricated findings
structurally impossible, then maps where they sit along a single tool call.

| Section | What you'll get |
|---------|-----------------|
| [The control points](#the-control-points) | A one-table overview of all seven controls — what each guarantees and the source file that enforces it |
| [1 · Deterministic-tools-only findings (no LLM author)](#1--deterministic-tools-only-findings-no-llm-author) | Why every `Finding` is authored by a deterministic wrapper, and how the Critic scores without an LLM |
| [2 · Evidence sovereignty](#2--evidence-sovereignty) | How each finding carries its own provenance (wrapper, agent, byte hash) so a reviewer can re-derive it |
| [3 · The read-only Thymus boundary](#3--the-read-only-thymus-boundary) | The path-allowlist read-only policy that runs before any I/O, plus the layered rejection screens |
| [4 · The pre/post SHA-256 evidence invariant](#4--the-prepost-sha-256-evidence-invariant) | How the report is cryptographically pinned to the exact evidence bytes, and how tampering is detected |
| [5 · The deterministic fingerprint halt](#5--the-deterministic-fingerprint-halt) | The fixed-point + threshold stopping rule that never asks a model whether to halt |
| [6 · Completion-promise tokens (verifiable completion)](#6--completion-promise-tokens-verifiable-completion) | How a silent omission (a scheduled agent that never ran) is made detectable |
| [7 · Canonical-fact drift gates](#7--canonical-fact-drift-gates) | The CI check that fails the build when docs cite a number that contradicts the canonical facts |
| [Safety control points along one tool call](#safety-control-points-along-one-tool-call) | A diagram tracing the controls along a single core-loop iteration |
| [Why this is stronger than "prompt the model to be careful"](#why-this-is-stronger-than-prompt-the-model-to-be-careful) | The structure-and-cryptography argument: each control is a code path an agent cannot route around |
| [See also](#see-also) | Links to provenance, courtroom sealing, human-in-the-loop, and the canonical-facts table |

---

## The control points

The first five controls below are the original anti-fabrication core (they gate
a single tool call). Controls 6 and 7 are the *verification* layer: a
completion contract that proves scheduled work actually ran, and a CI drift
gate that keeps the documentation's numbers honest. All seven are enforced by
code, not by prompting.

| # | Control | What it guarantees | Source |
|---|---------|--------------------|--------|
| 1 | **Deterministic-tools-only findings** | No LLM-authored content reaches a report; every `Finding` is emitted by a wrapper that ran a forensic binary | `agents/_base.py`, `trinity/critic.py` |
| 2 | **Evidence sovereignty** | A finding carries its own provenance (which agent, which wrapper, which evidence digest) so it can be re-derived | `agents/_base.py:40-92` |
| 3 | **Read-only Thymus boundary** | The agent physically cannot write to evidence — no MCP tool exposes a write op; path allowlist enforced at the boundary | `mcp_server/thymus_policy.py` |
| 4 | **Pre/post SHA-256 evidence invariant** | The report is provably tied to the exact bytes that were triaged; any byte change is detectable | `courtroom.py:89-142` |
| 5 | **Deterministic fingerprint halt** | The loop stops on a reproducible fixed point — the Critic never rates its own confidence with an LLM | `trinity/critic.py:42-213` |
| 6 | **Completion-promise tokens** | A run that delivered findings but skipped a scheduled agent is detectable — the missing promise fails the contract, so a silent wrapper crash can't masquerade as "nothing to report" | `agents/_base.py:102-114`, `orchestrator.py:70-79` |
| 7 | **Canonical-fact drift gates** | Documentation can't drift away from code-verified numbers; a stale or decayed figure fails CI | `scripts/check_canonical_facts.py` |

The rest of this chapter walks each control, then shows where they sit along a
single tool call.

## 1 · Deterministic-tools-only findings (no LLM author)

The swarm agents are, by deliberate design, **pure async coroutines over the
MCP boundary with no LLM coupling**. The base-class docstring states it
plainly (`agents/_base.py:6-11`):

> "The base class deliberately exposes no LLM coupling — agents are pure async
> coroutines over the MCP boundary so they can be tested without the Trinity
> Loop wired in."

Every finding is a typed `Finding` Pydantic model (`agents/_base.py:40-92`)
whose `source` field names the **deterministic wrapper** that produced it
(`fls`, `volatility3`, `yara`, …) and whose `agent` field names the swarm agent
that emitted it (`agents/_base.py:64-71`). The `confidence` field is bounded
`0.0–1.0` by the schema (`Field(ge=0.0, le=1.0)`), and — critically — that
confidence is computed deterministically by the wrapper/agent, never asked of
an LLM.

The Critic reinforces this: its scoring is **deterministic v1 (no LLM)**
(`trinity/critic.py:4-6`). The score is a fixed arithmetic blend of the
highest per-finding confidence already on the Blackboard plus a weighted count
of cross-agent correlations (`trinity/critic.py:120-122`):

```python
max_conf = max(f.confidence for _, f in entries)
correlations = blackboard.correlations()
score = min(1.0, max_conf + _CORRELATION_WEIGHT * len(correlations))
```

There is no path by which a model invents a finding, assigns it a confidence,
and has that confidence influence the halt decision — the inputs are the
findings that wrappers already wrote.

## 2 · Evidence sovereignty

Each `Finding` is self-describing. Beyond `source`/`agent`, it can carry
`evidence` (human-readable artifact text), `evidence_dict` (typed cross-modal
keys for IOC fusion), `mitre_attack`, and an optional `file_sha256` — the
SHA-256 of the byte payload behind the finding, e.g. inode bytes for a staged
binary or dumped VAD bytes for a `malfind` RWX hit (`agents/_base.py:59-64`).
The on-the-wire serialization uses the SANS `_source` convention so a finding
dict satisfies `report.schema.json` (`agents/_base.py:43-51`).

Because a finding names its wrapper, its agent, and (where applicable) the
hash of the bytes it rests on, **a reviewer can independently re-run the same
deterministic tool against the same evidence and reproduce it**. Sovereignty
means the finding owns its lineage; it is not a claim that has to be taken on
the model's word.

## 3 · The read-only Thymus boundary

`mcp_server/thymus_policy.py` is the architectural evidence-integrity layer
(labelled **S-02** in its module docstring, lines 1-7). Its first guarantee is
structural, not procedural:

> "The agent physically cannot write to evidence because no MCP tool exposes a
> write operation." (`thymus_policy.py:60-64`)

`check_write()` exists only for defense-in-depth and audit completeness, and it
*always* rejects (`thymus_policy.py:362-369`):

```python
def check_write(self, path: str) -> str:
    """All writes are rejected — evidence integrity is architectural."""
    self._log("REJECT_WRITE", path, "all writes forbidden")
    return f"Thymus REJECT: ALL writes to evidence are forbidden. Path: {path}"
```

On the read side, `check_read()` runs **before any I/O begins** for every
evidence-touching tool. In `mcp_server/server.py` you can see the boundary
enforced uniformly — each tool calls `_policy.check_read(...)` before opening a
file (`server.py:363, 404, 449, …`), and the module header names the server as
"the enforcement boundary — Thymus policy runs here" (`server.py:7`). The
single shared policy instance is `_policy = ThymusEvidencePolicy()`
(`server.py:176-177`).

`check_read()` layers several screens, in order (`thymus_policy.py:236-360`):

| Check | Rejects | Notes |
|-------|---------|-------|
| Path length bound | paths > 4096 bytes (`_PATH_MAX_BYTES`) | typed `REJECT_PATH_TOO_LONG` before any work (SIFT-W-109) |
| Forbidden patterns on **raw** path | `..`, `~`, `/dev/`, `/proc/`, `/sys/` | runs on raw input first so traversal intent can't be hidden by normalization |
| Canonicalize | NUL/control chars, URL-encoding, double slashes, trailing `/` | normalize-only; **never adds permission** (W-097) |
| Forbidden patterns on **resolved** path | traversal that only appears post-resolution | second screen after `Path.resolve()` |
| Symlink validation | broken/circular links, targets outside the allowlist | `REJECT_SYMLINK_TARGET_OUTSIDE_ALLOWLIST` |
| Prefix allowlist | anything not under a `READONLY_PATHS` prefix | `REJECT_OUTSIDE_ALLOWLIST` |

The default read-only zones are `/cases/`, `/mnt/`, `/media/`, `/evidence/`,
`/tmp/agentropix-sift-`, and the SIFT-shipped YARA rule dirs
(`thymus_policy.py:31-44`). Operators add per-case prefixes via
`AGENTROPIX_THYMUS_ALLOWED_PREFIXES`; evidence-image parents are auto-allowed on
first access for recognized forensic extensions
(`thymus_policy.py:122-152`). Every decision — `ALLOW`, `REJECT`, `SYMLINK`,
`AUTO_ALLOW` — is appended to a bounded in-memory ring **and** the on-disk
JSONL audit log when `AGENTROPIX_AUDIT_LOG` is set (`thymus_policy.py:371-394`),
which becomes the chain-of-custody record sealed in
[Audit & Courtroom Seal](audit-courtroom.md).

## 4 · The pre/post SHA-256 evidence invariant

At session start the orchestrator hashes the evidence image with
`evidence_image_sha256(path)` (`courtroom.py:89-142`) so the report is
"provably tied to the bytes-on-disk that were triaged"
(`courtroom.py:9-12`). The hash streams the file in 1 MiB chunks and **never
raises** — it returns `str | None`, degrading gracefully when the path is
missing, is a directory, or exceeds `AGENTROPIX_HASH_MAX_BYTES` (default
50 GB) (`courtroom.py:89-142`). For containers too large to hash inline, an
operator supplies an offline digest via `AGENTROPIX_EVIDENCE_SHA256`, which is
length-validated and embedded verbatim (`courtroom.py:103-109`).

The design note is explicit that a *recorded* skip is preferable to a silent
failure (`courtroom.py:42-44`):

> "A judge values 'we tried; here is the size threshold' over a silent
> failure."

This digest is the *pre* side of the invariant: it pins the report to specific
bytes. Combined with the read-only boundary (control 3), the *post* side is
trivial to establish — because nothing in the pipeline can mutate evidence,
re-hashing the image after a run must reproduce the same digest. A mismatch
means the evidence was altered out-of-band, and the report's embedded digest
makes that detectable.

## 5 · The deterministic fingerprint halt

The Trinity loop must not spin forever, and — just as importantly — it must not
ask an LLM "are you confident enough to stop?". The Critic halts on a
**deterministic convergence fingerprint** (`trinity/critic.py:123-129`):

```python
fingerprint = frozenset(
    (agent, f.source, f.description, f.evidence) for agent, f in entries
)
no_progress = fingerprint == self._last_fingerprint
```

Because swarm agents are idempotent (`agents/_base.py` `SwarmAgent.investigate`
contract), an agent re-publishing the same finding produces an identical
fingerprint — so the loop halts the moment the swarm pass becomes a **fixed
point**. The threshold halt (`score >= halt_threshold`, default `0.85` via
`AGENTROPIX_CRITIC_HALT_THRESHOLD`, `critic.py:42-89`) and the coverage guard
(refuse to halt while any planned agent produced zero findings, W-083,
`critic.py:166-185`) are likewise pure functions of the Blackboard state. No
self-rating, no model in the halt decision. For the loop mechanics see
[the Trinity Loop chapter](../02-architecture/trinity-loop.md).

## 6 · Completion-promise tokens (verifiable completion)

A subtler failure mode than fabrication is *silent omission*: the report looks
populated and convincing, but a scheduled analysis never actually ran (the
wrapper crashed mid-pass, or a tool was disabled by an env flag). A reader has
no way to tell a clean "nothing to report" apart from a broken "we never
looked". **Completion-promise tokens** close that gap.

A *completion-promise token* is a fixed, uppercased snake-case string declared
as a class attribute on a swarm agent — for example `TIMELINE_GENERATED`,
`MEMORY_TRIAGED`, or `YARA_HUNT_COMPLETE` (`agents/_base.py:102-114`). The base
class defines the contract (`agents/_base.py:114`):

```python
completion_promise: str | None = None
```

The orchestrator appends that token to `report.completion_proofs` **only when
the agent both completed without raising AND published at least one Finding**
(`orchestrator.py:189-195`):

```python
if findings and agent.completion_promise:
    completion_proofs.add(agent.completion_promise)
```

The "≥1 finding" condition is deliberate, and the source comment spells out why
(`orchestrator.py:185-193`): an empty findings list means "ran cleanly but
nothing to report", which is *not* counted as a promise — because if it were, a
silently broken wrapper that produced zero findings would still satisfy the
contract. The token is therefore evidence that the agent did real work, not
just that it was invoked.

Downstream, the proofs are a **verifiable completion contract**: the Critic (or
any later verifier) can fail a run that delivered a populated report but is
missing a required promise — e.g. timeline analysis was scheduled but the
`timeline.plaso` wrapper crashed, so `TIMELINE_GENERATED` never appears in
`completion_proofs` (`agents/_base.py:104-110`). One agent — the Memory agent —
even *clears* its own promise on a degraded path (`memory.py:553-556`), so a
partial run cannot claim full completion. Tests pin the tokens so they can't
silently change (`tests/unit/detectors/test_injection_detector.py:338-339`,
`tests/unit/test_orchestrator.py:53-97`).

Where the deterministic-tools rule (control 1) stops the model from *inventing*
a finding, completion-promise tokens stop a broken pipeline from *hiding* a
gap — both are forms of grounding the report against what actually happened.

## 7 · Canonical-fact drift gates

The mechanisms above keep *findings* grounded. A separate gate keeps the
*documentation's numbers* grounded against the code. A **drift gate** is a CI
check that fails the build when a tracked file cites a number that contradicts
the canonical-facts table — or when a number that is currently correct silently
decays. The gate is `scripts/check_canonical_facts.py`, wired into CI via the
`canonical-facts` job in `.github/workflows/docs-validation.yml`
(`check_canonical_facts.py:1-21`).

It runs two checks (`check_canonical_facts.py:6-19`):

| Check | SIFT id | Catches | How |
|-------|---------|---------|-----|
| **Backward drift** | W-250 | Stale numbers (e.g. an old test count like `1270`) still cited in tracked `.md` files | Scans tracked Markdown for known-stale literals; a line carrying a whitelist marker (`CANONICAL_FACTS`, `{{ref:CANONICAL_FACTS`, `historical`, `stale`) silences the hit |
| **Forward drift** | W-252 | A currently-correct number that *should* appear but no longer does (e.g. a regression drops disk recall and `README.md` stops saying `72/72`) | For each row under `## Forward-drift assertions` in `CANONICAL_FACTS.md`, asserts the required literal (or the `{{ref:CANONICAL_FACTS#key}}` citation) is present in the listed file |

The gate exits `0` when both checks pass and `1` if either fails
(`check_canonical_facts.py:20`). This is why the numbers on this portal — the
72 MCP tools, the `0.85` halt threshold, the `72/72` disk recall — must all be
sourced from [`canonical-facts.md`](../08-reference/canonical-facts.md) (the portal mirror of the
upstream table): a contradicting figure is not a stylistic slip, it is a CI
failure. The drift gate makes documentation accuracy enforceable in exactly the
same spirit as the evidence invariant makes report accuracy enforceable.

## Safety control points along one tool call

```mermaid
graph TD
    A[Architect plans swarm slice<br/>LLM orchestration only] --> B[SwarmAgent.investigate<br/>pure async coroutine, no LLM]
    B --> C{Thymus check_read?<br/>thymus_policy.py}
    C -->|REJECT: traversal / outside allowlist /<br/>symlink / path-too-long| X[Typed REJECT returned<br/>+ audit-log entry]
    C -->|ALLOW: under READONLY_PATHS| D[Deterministic wrapper runs<br/>forensic binary read-only]
    D --> E[Typed Finding emitted<br/>source + agent + evidence + file_sha256]
    E --> F[Blackboard publish<br/>per-agent finding cap]
    F --> G{Critic.score<br/>deterministic blend, no LLM}
    G -->|score >= 0.85 OR fixed-point fingerprint<br/>AND coverage guard satisfied| H[HALT]
    G -->|otherwise| A
    H --> I[Report sealed<br/>evidence SHA-256 + HMAC<br/>courtroom.py]
    X --> J[(AGENTROPIX_AUDIT_LOG<br/>JSONL chain of custody)]
    C -.logs ALLOW/REJECT.-> J

    classDef actor fill:#d0bfff,stroke:#7048e8,color:#2b1a52
    classDef api fill:#a5d8ff,stroke:#1971c2,color:#0b2545
    classDef core fill:#b2f2bb,stroke:#2f9e44,color:#15391f
    classDef gov fill:#ffc9c9,stroke:#e03131,color:#5c1a1a
    classDef sink fill:#ffec99,stroke:#f08c00,color:#5c4400
    classDef ext fill:#e9ecef,stroke:#495057,color:#212529

    class A actor
    class B api
    class C gov
    class X gov
    class D core
    class E core
    class F api
    class G api
    class H core
    class I core
    class J sink
```

The diagram traces a single iteration of the core loop (controls 1–5).
**Three of the five core controls gate a single call**: the read-only Thymus
boundary (the pink decision node) sits
*before* any I/O; the deterministic wrapper is the only thing that can author a
`Finding`; and the Critic (the blue node) decides halt purely from Blackboard
state. The evidence digest (control 4) is captured once at session start and
embedded at seal time (green node), and evidence sovereignty (control 2) is the
property each emitted `Finding` carries. Every Thymus decision — and every
rejection — is written to the JSONL audit log, so even a *blocked* hallucination
attempt leaves a tamper-evident trace. There is no edge in this graph along
which a language model writes a fact, mutates evidence, or rates its own
output. Controls 6 (completion-promise tokens) and 7 (drift gates) wrap this
loop rather than sitting inside it: the promise tokens are checked once per run
after the swarm passes complete, and the drift gate runs in CI over the
documentation — neither is reachable by an agent mid-iteration.

## Why this is stronger than "prompt the model to be careful"

Each control is enforced by code paths that an agent cannot route around:

- A write tool **does not exist**, so "the agent decided to edit evidence" is
  not a reachable state (`thymus_policy.py:60-64`).
- A finding's author is a wrapper name recorded in the typed model, not a free-
  text attribution the model could fabricate (`agents/_base.py:51-71`).
- The halt condition is a `frozenset` equality and a numeric threshold, not a
  judgment call (`trinity/critic.py:120-129`).
- The evidence digest is computed by `hashlib.sha256` over real bytes, not
  asserted (`courtroom.py:131-142`).
- A scheduled agent that produces no finding emits **no** completion-promise
  token, so an omission is visible in `completion_proofs` rather than silently
  passing as "nothing to report" (`orchestrator.py:194-195`).
- A documentation number that contradicts the canonical-facts table is a CI
  failure, not an editorial judgment call (`scripts/check_canonical_facts.py`).

The result is a system whose forensic soundness rests on **structure and
cryptography**, with the LLM confined to choosing *which* deterministic tools
to run — never to authoring, scoring, or sealing what they find.

## See also

- [Provenance & Grounding](provenance-grounding.md) — provenance tiers and how
  well a claim is externally supported.
- [Audit & Courtroom Seal](audit-courtroom.md) — HMAC-SHA256 sealing of the
  report and the Thymus audit log.
- [Human-in-the-Loop](human-in-the-loop.md) — the approval sidecar that gates
  `DRAFT → APPROVED`.
- [EZ Tools / ZimmermanTools Integration](../02-architecture/ez-tools-integration.md) — the
  deterministic forensic wrappers that author every `Finding` (the "deterministic tool"
  invariant 1 relies on).
- Canonical numbers cited here (tool count 71, halt threshold 0.85) are pinned
  in [`canonical-facts.md`](../08-reference/canonical-facts.md) /
  `CANONICAL_FACTS.md` upstream.

### Decision records (why this works the way it does)

- [ADR-016 — Courtroom Audit: High Inference Constraint + Cryptographic
  Sealing](../11-ADR/ADR-016-courtroom-audit.md) — the genesis of the **High
  Inference Constraint** contract (§ intro, controls 1, 4): why "the LLM agents
  only orchestrate; every fact originates from a deterministic MCP tool", plus
  the evidence-hash and raw-output-before-summarisation invariants.
- [ADR-008 — Safety Architecture (Bio-Agentic Safety
  Model)](../11-ADR/ADR-008-safety-architecture.md) — the Oncologist/Thymus
  rationale behind the read-only evidence boundary (control 3).
- [ADR-022 — Audit-Log Seal](../11-ADR/ADR-022-audit-log-seal.md) — why the
  Thymus access trail (the JSONL written at control 3) is itself HMAC-sealed and
  cross-bound into the report seal.
