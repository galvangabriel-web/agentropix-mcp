# Next steps / Roadmap

> **Section 01 · Overview** — A consolidated, fully-cited view of what comes next: every
> forward-looking commitment already on record in the Deferred ADRs and the README SWOT.
> Related: [ADR Index](../11-ADR/README.md) ·
> [Design Decisions](../08-reference/design-decisions.md) ·
> [Competitive Positioning](competitive-positioning.md) ·
> [Canonical Facts](../08-reference/canonical-facts.md)

## How to read this page

This is **a routed index of commitments already on record (Deferred ADRs + SWOT), not a
feature-promise sheet**. Every row below traces to a named source: a formal *Deferred* ADR
with a written **re-attempt condition**, an *identified replacement* line in the
[Design Decisions](../08-reference/design-decisions.md) record, or a verbatim cell of the
[README SWOT](../../README.md#swot--strategic-assessment). Statuses are quoted from the ADRs'
own `Status` fields; nothing here is invented, scheduled, or date-promised. Items fire on
**conditions** (e.g. "when the Step-3 sprint kicks off"), not dates — deferring formally with
an explicit re-attempt condition, never silently, is itself a documented project rule
([ADR-021](../11-ADR/ADR-021-two-person-rule-defer.md); see Design Decisions §2,
Trade-off 3: *"a formal `Deferred` ADR with an explicit re-attempt condition, not silent
scope-cutting"*).

---

## 1 · Deferred ADRs — re-attempt conditions

These are formal deferrals. Each carries a written trigger; when the trigger fires, the work
re-opens by architectural commitment, not by memory.

| # | Item | Source (status verbatim) | Re-attempt condition (quoted/summarized from the ADR) |
|---|------|--------------------------|--------------------------------------------------------|
| R1 | **Two-person rule for Active Response** — dual-operator co-sign before any destructive AR action | [ADR-021](../11-ADR/ADR-021-two-person-rule-defer.md) — Status: *"Deferred (formally documented; not implemented)"* | *"When the Step-3 sprint kicks off (first AR endpoint design), the architect **must** open a follow-up ADR"* that either ratifies a two-person-rule design (recommended scope: AR endpoints marked `destructive=true`) or documents why single-confirmation suffices for the specific AR scope — *"before any AR endpoint becomes callable from the MCP wrapper layer."* Until then, ADR-019's single-confirmation gate is the sole AR safety boundary. |
| R2 | **In-memory credential extraction (W-072)** — restore SAM/LSA/MSCache credential triage lost to the Volatility ≥2.27.0 pin | [ADR-014](../11-ADR/ADR-014-W072-impacket-secretsdump.md) — Status: *"Accepted (path forward; Phase 6 of BMAD-M7 sprint)"*; W-072 **DEFERRED** per [Design Decisions §2, Trade-off 1](../08-reference/design-decisions.md) | Credentials are extracted **post-M7** via `impacket-secretsdump.py LOCAL` against registry hives carved offline — keeping the Volatility upstream pin. The accepted rationale, quoted from the ADR record: *"the SANS submission deadline (2026-06-10) is recall-driven, not credential-driven."* |
| R3 | **Event-window recall — T4 (EventID 4624) and T5 (MFT timestomp)** | [ADR-W051-defer](../11-ADR/ADR-W051-defer.md) + [ADR-W054-defer](../11-ADR/ADR-W054-defer.md) — Status: *"DEFERRED (code landed, live measurement deferred to M6.3)"* — superseded in practice by [ADR-M6.3-residual-gap](../11-ADR/ADR-M6.3-residual-gap.md) | The M6.2 diagnosis (`_DEFAULT_MAX_EVENTS=500` datetime-ascending truncation) is *"no longer supported"* after the M6.3 redesign left recall unchanged — *"The wrapper reports success. The agent reports zero findings."* Decision: **M6.4 opens with an instrumentation sprint (not another design sprint)** — land `trace.timeline.jsonl_rows_read` / `priority_hits` / `detectors_fired` counters to disambiguate hypotheses H1–H3. W-050 stays **PARTIAL**; W-051/W-054 stay **DEFERRED**; commit `03079f2` is NOT reverted (`_DEFAULT_MAX_EVENTS=2000` and the per-parser sampler are retained). Post-close update: H1 (silent psort flag failure) was confirmed and fixed (commit `9d7dd89`); the instrumentation remains charted for H2/H3 disambiguation. |
| R4 | **YARA agent — promote T2 (RUNDLL32/Cobalt Strike stager) from MISS** | [ADR-W052-T2-defer](../11-ADR/ADR-W052-T2-defer.md) — Status: *"DEFERRED"* | *"Ship a YARA agent (W3 roadmap) that scans Prefetch entries for CS beacon staging artifacts. Once the YARA agent fires, restore `artifact.exe` / `stager` or replace with the YARA rule signature name."* Until then, **T2 remains MISS** in the recall gate — `stager` is analysis vocabulary plaso never emits. |
| R5 | **Volatility-backed process-injection detection in MemoryAgent — promote T6 from MISS** | [ADR-W052-T6-defer](../11-ADR/ADR-W052-T6-defer.md) — Status: *"DEFERRED"* | *"Integrate Volatility (or equivalent) into MemoryAgent. Once process injection artifacts (e.g., `UNKNOWN` VAD regions, injected PE headers) can be detected, replace `injection` with the specific Volatility output token."* The GT keyword was deliberately **not** softened: *"Changing the GT to drop `injection` would misrepresent the evidence."* **T6 remains MISS.** |
| R6 | **Plaso output-schema contract test** — pin the timestomp sentinel tokens against upstream drift | [ADR-W054-defer §Residual risk](../11-ADR/ADR-W054-defer.md) | *"If Plaso 20260119+ stops emitting these tokens (e.g., schema migration), the detector silently regresses. M6.3 should add a contract test against a synthetic MFT timestomp event to pin Plaso's output schema."* |

> **Honest recall framing (carried from the ADRs).** Per ADR-W051-defer, the live measured
> figure is **cohit≥2 = 1/7** — *"Demo headline must reflect measured 1/7 cohit≥2, not
> predicted 4/7."* The canonical headline recall figures (72/72 disk, 108/118 memory) are a
> **different framing** governed by [Canonical Facts](../08-reference/canonical-facts.md) and
> the [recall methodology](../07-sdlc-ops/dataset-recall.md); the 1/7 figure is the M6.2/M6.3
> sprint-gate cohit metric on the DC E01 ground truth, kept here verbatim as the ADRs state it.

---

## 2 · Proposed / identified — not scheduled

Design work that exists on paper with no committed sprint. Listed so readers do not mistake
documentation for shipped capability.

| # | Item | Source | Status note |
|---|------|--------|-------------|
| R7 | **LLM Task Router** — classify task structure (parallel / sequential / hybrid) without letting the LLM execute the task; replaces the discarded regex task-splitter (`engine/ralph.py:702-737`) | [ADR-009](../11-ADR/ADR-009-task-router.md) — Status: **Proposed** | Per the [Design Decisions §3](../08-reference/design-decisions.md) oracle-status note: *"ADR-009 is **Proposed — NOT shipped** … the router is a documented design, not an implemented component."* |
| R8 | **`contextvar` per-call Thymus policy** — replace the module-global `_policy = ThymusEvidencePolicy()` (`server.py:177`) / `configure_policy()` (`server.py:180`) pattern | [Design Decisions §3, discarded approach 2](../08-reference/design-decisions.md) | *"The identified replacement is a `contextvar`-based per-call policy resolution (analogous to the trace scope)"* — identified, not implemented; no ADR commits a sprint to it. |

---

## 3 · SWOT-derived improvement fronts

The [README SWOT](../../README.md#swot--strategic-assessment) names the system's own
weaknesses and opportunities; the actionable ones map onto the rows above.

- **R9 — Memory-forensics recall.** Quoted from the SWOT *Weaknesses* cell: memory recall
  (**108/118**) *"trails disk (**72/72**) and is the active improvement front."* This is the
  standing accuracy front; the canonical numbers are governed by
  [Canonical Facts](../08-reference/canonical-facts.md).
- **R10 — Promote the deferred detectors into live recall.** Quoted from the SWOT
  *Opportunities* cell: *"The ATT&CK detector lane is extensible — deferred detectors
  (W051/W052/W054) are wired and unit-tested, ready to promote into live recall."* This is
  the SWOT's own restatement of rows **R3** and **R4/R5** above — the code is committed
  (`2a2cb1c`) and unit-tested; what remains deferred is the *live recall contribution*.
- **R11 — Case-management / report UX.** Quoted from the SWOT *Weaknesses* cell: *"A
  **triage engine, not a case-management product**: no HTML report generator, no commercial
  case-file UX (vs Magnet AXIOM, CADO); output is JSON + the audit ledger."*
  > **Reconciliation note (ADR-024).** The
  > [ADR-024](../11-ADR/ADR-024-multi-tier-report-engine.md) header still reads
  > **Status: Proposed**, but the 2026-06-05 status audit (mirrored in the
  > [ADR Index](../11-ADR/README.md)) records that the `report_export` MCP tool **shipped**
  > (commit `3f633be3c`, "ADR-024 Phase 5") — the oracle wins. Multi-tier (exec / business /
  > technical) report generation is therefore **not** listed here as future work; the
  > remaining SWOT gap is the broader commercial case-file *UX*, for which no ADR commits a
  > plan.
- **R12 — Host collection / agent fleet (acknowledged out-of-scope boundary, NOT a roadmap
  item).** Quoted from the SWOT *Weaknesses* cell: *"**Read-only consumer**, no
  host-collection ecosystem (vs Velociraptor's agent fleet) — caps it at post-collection
  triage."* No ADR commits to building host collection; it is recorded here as an honest
  scope boundary, not a commitment. See
  [Competitive Positioning](competitive-positioning.md) for the full comparison.

---

## 4 · What is deliberately NOT on this roadmap

Honest negatives, so absence is read as a decision rather than an oversight:

- **No dates or version promises.** Every item above is condition-triggered (a sprint
  kick-off, an instrumentation result, a YARA-agent landing). The only date in any source is
  the SANS submission deadline (2026-06-10), which is a past constraint cited in the ADRs'
  rationale — not a schedule for the items here.
- **No host-collection / agent-fleet commitment** (R12 above) — no ADR backs it.
- **No multi-tier reporting "coming soon"** — it already shipped per the ADR-024 audit
  (reconciliation note in R11).
- **No new detectors, tools, or capabilities beyond the cited record.** If a feature does not
  appear in a Deferred ADR's re-attempt condition, the Design Decisions identified-replacement
  line, or a SWOT cell, it is not on this page.

## Related

- [ADR Index](../11-ADR/README.md) — all decision records, including the live status audit.
- [Design Decisions §2–§3](../08-reference/design-decisions.md) — the four hard trade-offs and
  six tried-and-discarded approaches behind several rows above.
- [Competitive Positioning](competitive-positioning.md) — where the system honestly loses
  today (context for R11/R12).
- [Canonical Facts](../08-reference/canonical-facts.md) — the governing numeric authority for
  every recall figure quoted here.
