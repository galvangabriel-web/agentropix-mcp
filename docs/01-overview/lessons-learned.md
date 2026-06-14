# Lessons learned

> **Section 01 · Overview** — What building Agentropix-SIFT actually taught us: thirteen
> lessons, every one grounded in a written post-mortem — a discarded approach, an accepted
> trade-off, or a formally deferred ADR. Nothing here is retrospective folklore; each
> lesson cites the decision record it comes from.
> Related: [Design Decisions](../08-reference/design-decisions.md) ·
> [ADR Index](../08-reference/adr-index.md) ·
> [Section 11 — ADRs (full text)](../11-ADR/README.md) ·
> [Competitive positioning](competitive-positioning.md)

> **How to read this page.** This is a reference-style page (no commands to run, so no
> operator prompt-boxes). Each lesson states the mistake or tension, what it cost, what
> replaced it, and the **source citation** — the ADR or design-decision post-mortem where
> the lesson is recorded. Statuses are quoted from the live record: where a replacement is
> *Proposed* or *Deferred*, the lesson says so plainly rather than depicting it as shipped.
> Bio-agentic terms (**Trinity Loop**, **Thymus**, **Critic**, **Blackboard**) are defined
> in the [Glossary](../08-reference/glossary.md). Numeric claims follow
> [`canonical-facts.md`](../08-reference/canonical-facts.md) (73 MCP tools, 16 forensic
> wrappers, 4687 tests, 72/72 disk recall, 108/118 memory recall).

---

## Part A — What we tried and discarded

Six approaches that were attempted, proven bad, and replaced. The full file-and-line
post-mortems live in
[Design Decisions §3 — "Six tried-and-discarded approaches"](../08-reference/design-decisions.md#3-six-tried-and-discarded-approaches).

### Lesson 1 — Regex cannot decompose tasks semantically

Splitting complex tasks on conjunctions (*"and"*, *"then"*, *"also"*) into independent
subtasks looked like a cheap planner. It failed because regex cannot detect semantic
dependencies: a task like *"Write Python, Go, Rust → compare execution times → build a
matrix → save"* split into parallel subtasks with no context-passing, so later steps had
no access to earlier outputs. The replacement design is an LLM-based Task Router that
*classifies* task structure (parallel / sequential / hybrid) without letting the LLM
execute the task.

**Honest status:** the router is **Proposed, NOT shipped** — ADR-009's live status is
`Proposed`, and the design-decisions oracle-status note is explicit that it is "a
documented design, not an implemented component."

*Source:* [ADR-009 — Task Router](../11-ADR/ADR-009-task-router.md) (post-mortem at
`engine/ralph.py:702-737`); [Design Decisions §3.1](../08-reference/design-decisions.md#3-six-tried-and-discarded-approaches).

### Lesson 2 — Module-global mutable policy state breaks concurrency and test isolation

The Thymus evidence policy (the read-only gate every tool call passes through) was held
as a module-level global — `_policy = ThymusEvidencePolicy()` at `server.py:177`, with a
`configure_policy()` mutator at `server.py:180`. A module-global policy races across
concurrent triage in one process, bleeds audit state across multi-tenant MCP hosting, and
makes test isolation impossible. The **identified replacement** is `contextvar`-based
per-call policy resolution (analogous to the trace scope) — identified, not yet built.

*Source:* [Design Decisions §3.2](../08-reference/design-decisions.md#3-six-tried-and-discarded-approaches).

### Lesson 3 — Monolithic system prompts collapse cache hit-rate and drive confabulation

Early designs loaded every wrapper docstring, weakness ID, runbook, persona, and changelog
into the system prompt. The model spent most of its context window paraphrasing noise,
cache hit-rate collapsed, cost-per-token compounded across Trinity iterations, and the
relevant context got buried — which *drives* confabulation rather than preventing it. The
replacement is Progressive Disclosure: a thin `CLAUDE.md` index at boot, with skills and
domains loaded on demand.

*Source:* [ADR-015 — Context Engineering](../11-ADR/ADR-015-context-engineering.md);
[Design Decisions §3.3](../08-reference/design-decisions.md#3-six-tried-and-discarded-approaches).

### Lesson 4 — Seal everything, not just the report

ADR-016 sealed `report.json` but left the on-disk Thymus audit JSONL unsealed. A hostile
reviewer could swap the JSONL post-run: the report seal would catch a report swap, but the
JSONL swap slipped through silently — the "residual 3%" gap the 2026-05-06 SANS rubric
re-grade flagged on Forensic Soundness. The fix (ADR-022) adds an independent HMAC-SHA256
seal over the audit log under the same per-run session key and **cross-binds**
`audit_log_seal` into the report before the report seal is computed. The lesson
generalises: a chain-of-custody guarantee is only as strong as its *least*-sealed
artifact. Tracked as **W-091 RESOLVED**.

*Source:* [ADR-022 — Audit-Log Seal](../11-ADR/ADR-022-audit-log-seal.md);
[Design Decisions §3.4](../08-reference/design-decisions.md#3-six-tried-and-discarded-approaches).

### Lesson 5 — Secrets in `.env` are a trap even when gitignored

The Step-1 Wazuh blueprint proposed storing the Manager JWT + Indexer credentials in a
repo `.env`. Three risks killed it: accidental commit even when `.gitignored`, the Manager
JWT's 900-second TTL requiring automatic refresh, and secrets leaking into `httpx` DEBUG
output (**W-007**). The replacement (ADR-020) loads credentials from externalized files at
mode `0600`, refreshes the JWT on its 900-second expiry, keeps the session key ephemeral
per-run, and scrubs secrets from logs and traces. **W-007 RESOLVED**.

*Source:* [ADR-020 — Credential Lifecycle](../11-ADR/ADR-020-credential-lifecycle.md);
[Design Decisions §3.5](../08-reference/design-decisions.md#3-six-tried-and-discarded-approaches).

### Lesson 6 — Exposure burden scales faster than distribution benefit

An early design considered a wide-reach public HTTP MCP endpoint with bearer auth so
judges could query without installing a client. It needed app-layer TLS, per-IP
rate-limiting, credential rotation, and public-internet request validation — the security
burden scaled faster than the distribution benefit ever could. The replacement (ADR-017)
defaults FastMCP to loopback; the operator opts into the tailnet via `--host`, and
`--public` requires an explicit flag with a loud warning.

*Source:* [ADR-017 — Tailnet MCP Exposure](../11-ADR/ADR-017-tailnet-mcp-exposure.md);
[Design Decisions §3.6](../08-reference/design-decisions.md#3-six-tried-and-discarded-approaches).

---

## Part B — Trade-offs we accepted on purpose

Four places where a real cost was accepted, documented as such, and never papered over.
Full rationale in
[Design Decisions §2 — "Four documented hard trade-offs"](../08-reference/design-decisions.md#2-four-documented-hard-trade-offs).

### Lesson 7 — Pin upstream stability over a single feature

ADR-014 keeps Volatility 3 pinned at `>=2.27.0` even though that release **removed** the
`hashdump` / `lsadump` / `cachedump` plugins. Downgrading would have restored in-memory
credential dumping but lost the `-r csv` renderer downstream wrappers depend on, newer
Windows 10/11 + Server 2022 symbols, and two years of security fixes. The accepted
downside — no in-memory credential dumps until M7+ (post-M7, credentials come from
`impacket-secretsdump.py LOCAL` against offline-carved hives) — was judged acceptable
because, in the ADR's words, *"the SANS submission deadline (2026-06-10) is
recall-driven, not credential-driven."* **W-072 DEFERRED** via this ADR.

*Source:* [ADR-014 — W072 / impacket-secretsdump](../11-ADR/ADR-014-W072-impacket-secretsdump.md);
[Design Decisions §2, Trade-off 1](../08-reference/design-decisions.md#2-four-documented-hard-trade-offs).

### Lesson 8 — A constant `confidence=1.0` saturates any `min()`-capped score

The W-040 post-mortem is the cleanest scoring bug in the record: `ArtifactAgent` always
emitted a chain-of-custody finding at `confidence=1.0`, so the Critic's halt score —
`score = min(1.0, max_conf + 0.25·len(correlations))` — saturated at
`1.0 ≥ halt_threshold=0.85` and the Trinity Loop halted after exactly one iteration on
*any* E01. The fix lowered the chain-of-custody confidence to `0.5` via
`AGENTROPIX_ARTIFACT_COC_CONFIDENCE`, letting the loop survive past iteration 1. The
accepted residual cost — unbounded Blackboard growth and the Critic's correlation re-scan
becoming latency-bound at high finding counts — is a documented review observation, with
`AGENTROPIX_CRITIC_HALT_THRESHOLD` (default `0.85`, `trinity/critic.py`) as the
deterministic tuning surface. The lesson: any aggregate that takes a `min()` or `max()`
over per-item confidences is one constant-valued item away from being a constant itself.

*Source:* [Design Decisions §2, Trade-off 2 (W-029 / W-040)](../08-reference/design-decisions.md#2-four-documented-hard-trade-offs).

### Lesson 9 — Defer formally, never silently

ADR-021 scopes the Wazuh integration to IOC push + read-only hunt and **defers** the
two-person rule, live Active Response endpoints, and dual-control machinery — as *"a
formal `Deferred` ADR with an explicit re-attempt condition, not silent scope-cutting."*
The ADR's own consequence section captures why this matters: *"The deferral is explicit
and traceable; it is **not** an implicit gap"* — when the Step-3 sprint kicks off, the
architect *"must open a follow-up ADR … before any AR endpoint becomes callable from the
MCP wrapper layer."* Cut scope is inevitable under a deadline; *undocumented* cut scope is
how safety controls fall off the radar.

**Honest status:** ADR-021 remains **Deferred (formally documented; not implemented)** —
do not depict the two-person rule as shipped.

*Source:* [ADR-021 — Two-Person Rule (DEFERRED)](../11-ADR/ADR-021-two-person-rule-defer.md);
[Design Decisions §2, Trade-off 3](../08-reference/design-decisions.md#2-four-documented-hard-trade-offs).

### Lesson 10 — A `0600` key file is a guarantee only if operators preserve it in transit

ADR-022 stores the 32-byte per-run HMAC session key at mode `0600`. If that file becomes
world-readable, any local user can re-seal a tampered report and the chain-of-custody
guarantee collapses. The accepted friction: operators must preserve permissions in
transit (`scp -p`, `rsync -p`, or explicit `chmod 0600`) — and a first-time
copy-without-`-p` mistake silently breaks defensibility. Cryptographic controls have
operational dependencies, and those dependencies must be documented as hard operator
requirements, not assumed.

*Source:* [ADR-022 — Audit-Log Seal](../11-ADR/ADR-022-audit-log-seal.md);
[Design Decisions §2, Trade-off 4](../08-reference/design-decisions.md#2-four-documented-hard-trade-offs).

---

## Part C — What the recall sprints taught us

Three lessons from the M6.2/M6.3 deferral record — the most honest documents in the tree,
because each one writes down a *measured miss*.

### Lesson 11 — Unit-tests-green ≠ live recall

The W-051 (EventID 4624 logon detector) and W-054 (MFT timestomp detector) sprints both
landed correct, unit-tested, committed code (commit `2a2cb1c`; suite 934/0/0) — and both
contributed **0** to live recall on the DC E01 re-run. Root cause: a structural
event-windowing issue, not a detector bug — `_DEFAULT_MAX_EVENTS=500` returned the
earliest 500 datetime-sorted events (OS-install `filestat` metadata), while the attack-era
4624 and timestomp events sat thousands-to-millions of events deep and never entered the
window. W-054 added a volume kicker: the MFT parser turned a ~12 GB image into a 5 GB
`.plaso` storage file and a ~42-minute run, requiring an `AGENTROPIX_PLASO_TIMEOUT=3600`
override. Both ADRs deferred the recall contribution to M6.3 — and the consequence
section says the quiet part out loud: *"Demo headline must reflect measured 1/7 cohit≥2,
not predicted 4/7."* Passing tests prove the detector logic; only a live measured run
proves the pipeline that feeds it.

*Source:* [ADR-W051-defer](../11-ADR/ADR-W051-defer.md) ·
[ADR-W054-defer](../11-ADR/ADR-W054-defer.md).

### Lesson 12 — When live behavior contradicts the diagnosis, instrument before redesigning

M6.3 shipped the redesigned event window (priority-deque + per-parser sampler,
`_DEFAULT_MAX_EVENTS=2000`, 16 unit tests) and re-ran the live DC E01 (artifact
`M6.3-W050W051W054-cli-20260422T000337Z.json`). Result: *"The wrapper reports success.
The agent reports zero findings. There is no observable error path between them."* That
falsified the M6.2 diagnosis — the ADR records that the truncation hypothesis *"is no
longer supported"* — and instead of a third design sprint, the decision was: accept the
gap as a P0 residual, keep the commit (`03079f2` NOT reverted), leave W-050 at PARTIAL
and W-051/W-054 at DEFERRED, and open M6.4 *"with an instrumentation sprint (not another
design sprint)"* — three ordered hypotheses (H1/H2/H3) each paired with a
`trace.timeline.*` counter that would confirm or kill it. The postscript vindicated the
method within hours: H1 was confirmed (a silent `psort` failure — plaso rejected the
`--storage_file` flag form with `rc=2`, and the wrapper never checked the return code),
and the fix (commit `9d7dd89`) both corrected the invocation and made the failure class
impossible to repeat by raising `RuntimeError` on any non-zero `psort` return. Blind
retries cost wall-clock and produce the same number; instrumentation produces a verdict.

*Source:* [ADR-M6.3-residual-gap](../11-ADR/ADR-M6.3-residual-gap.md) (complements
[ADR-M6.3-event-window](../11-ADR/ADR-M6.3-event-window.md)).

### Lesson 13 — Ground-truth keywords must be evidence-recoverable, not analysis vocabulary

Two ground truths could never be hit by the evidence pipeline as scored — not because the
detectors were weak, but because the expected keywords were *analyst conclusions*, not
*artifact text*. T2 (Cobalt Strike stager) expected the keyword `stager`, which *"is
analysis vocabulary (MITRE/CS terminology) that plaso never emits for any event type."*
T6 (beacon AppData injection) expected `injection`, an analysis conclusion that appears
only in enrichment text or YARA rule names. The principled part is what was **not** done:
the keywords were not loosened to game the score, because *"Changing the GT to drop
`injection` would misrepresent the evidence (in-memory injection cannot be confirmed from
disk artifacts alone)."* Both truths were formally deferred with re-attempt conditions —
T2 awaits a YARA agent scanning Prefetch for beacon staging artifacts; T6 awaits
Volatility integration in `MemoryAgent`, after which `injection` is replaced with the
specific Volatility output token.

**Honest status:** T2 and T6 remain **MISS** in the recall gate until those re-attempt
conditions are met.

*Source:* [ADR-W052-T2-defer](../11-ADR/ADR-W052-T2-defer.md) ·
[ADR-W052-T6-defer](../11-ADR/ADR-W052-T6-defer.md).

---

## The thread through all thirteen

Every lesson above reduces to the project's design philosophy, distilled in
[Design Decisions §6](../08-reference/design-decisions.md#6-one-paragraph-summary):
trust deterministic Python and cryptography, distrust LLM judgment by default, file every
load-bearing decision as an ADR *before* code is written, and cite every claim to a file,
a line, or a test. The lessons exist as a readable page only because the failures were
written down at the moment they happened — in ADRs that record measured misses (1/7, not
4/7), refuted hypotheses, and explicit re-attempt conditions instead of quiet scope cuts.

## Related references

- [Design Decisions — Rationale & History](../08-reference/design-decisions.md) — the full
  post-mortems behind Parts A and B (§2 trade-offs, §3 discarded approaches).
- [ADR Index](../08-reference/adr-index.md) — the ADR-001..024 routing table with live
  status audit.
- [Section 11 — ADRs (in-portal copies)](../11-ADR/README.md) — complete decision text,
  including the M6.2/M6.3 deferral record cited in Part C.
- [Canonical facts](../08-reference/canonical-facts.md) — the governing numbers; no figure
  on this page contradicts it.
- [Glossary](../08-reference/glossary.md) — Trinity Loop, Thymus, Critic, Blackboard.
