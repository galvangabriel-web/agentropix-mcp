# Implementation Plan — Multi-Tier Report Engine (ADR-024)

**Status:** Accepted / Implemented — merged to `main` (PR #197 engine + PR #198 MCP tool) · **Date:** 2026-06-01 (plan) · **Updated:** 2026-06-05 (shipped-reality reconciliation) · **Owner:** forge-orchestrator
**Governing ADR:** ADR-024 (Accepted) · **Reference templates:** SIFT reports (SRL-2018 Attack Chain = Tier 1 gold standard)

> **Shipped-reality note (2026-06-05).** This plan is retained as the design record; the boxes below are reconciled against the merged code (`/home/admin2/agentropix-sift`, branch `main`). Where the shipped engine diverges from the plan, the divergence is called out inline. Notable deltas: the engine ships with **no `templates/` or `assets/` dir, no `mmdc`/SVG-prerender step, and no jinja2/pandoc in the render path** — `render.py` uses the pure-pip `markdown` library and passes Mermaid through fenced blocks, relying on headless Chromium for diagram fidelity.

> **Templates-first gate.** No rendering-engine code is written until Phase 1 mockups (3 tiers × 3 formats) are approved. Phases are sequenced so the operator sees what reports will look like before the engine exists.

---

## Goal (single sentence)

Turn one analyzed SIFT case into three audience-targeted report tiers (Analyst / Executive / Business) rendered to PDF, HTML, and Markdown-with-Mermaid, built as a presentation layer over existing finding/IOC/correlation models, sealable and offline-capable.

## Scope guardrails

- **In scope:** new `src/agentropix_sift/reports/` package, templates, a `mcp_report_export` tool, rendering deps behind a `[reports]` extra.
- **Out of scope (this feature):** changes to core data models, MCP analysis tools, the approval gate, or the seal. `mcp_report_generate` JSON contract is frozen.
- **Hard stops (escalate, do not auto-proceed):** any network egress at render time; any change to `report.schema.json` semantics; adding an external service dependency.

---

## Phase 0 — Foundations & dependency spike  *(no user-facing output)*
**Exit:** rendering toolchain proven on a throwaway sample.

- Add `[reports]` optional-dependency group: `markdown`, plus PDF engine. Do **not** add to core deps. *(Shipped: the `[reports]` extra carries the pure-pip `markdown` library and `weasyprint`; jinja2/pandoc were NOT used in the shipped render path — `render.py` builds HTML directly from a minimal shell + the `markdown` lib.)*
- Spike the **two PDF paths** on a sample MD+Mermaid doc: (a) headless Chromium, (b) WeasyPrint + mmdc-prerendered SVG. Record which becomes default vs fallback. **SHIPPED REALITY:** the mmdc SVG-prerender mitigation was **NOT carried into the shipped engine**. `render.py` (per `/home/admin2/agentropix-sift/src/agentropix_sift/reports/render.py`) has no mmdc invocation and no SVG generation; it emits Mermaid as fenced ```mermaid blocks and relies on **headless Chromium** for diagram fidelity. Consequently the **WeasyPrint TD-graph text-drop mitigation via SVG-prerender is unshipped** — under the WeasyPrint fallback, Mermaid diagrams are not pre-rendered (the docstrings still reference the mmdc path, but no code performs it).
- ~~Confirm `mermaid-cli` (mmdc) runs offline and deterministically.~~ *(Not part of the shipped toolchain — no mmdc dependency.)*
- **Decision logged (shipped):** default PDF engine = **headless Chromium**, fallback = **WeasyPrint** — selected at runtime by `detect_pdf_capability(prefer="chromium")` in `render.py`.

## Phase 1 — Template mockups  *(USER APPROVAL GATE — the deliverable you asked to see first)*
**Exit:** operator signs off on all 3 tiers × 3 formats.

- Hand-build **static mockups** (real-looking sample data from SRL-2018) for:
  - **Tier 1 Analyst** — model on SRL-2018 Attack Chain (exec stat grid, infra inventory, kill-chain timeline, raw EID evidence tables, process tree, beacon analysis, ATT&CK grid, recommendations, evidence sources).
  - **Tier 2 Executive** — 2–3 page: impact, dwell, scope, top findings, remediation priorities, KPI rollups.
  - **Tier 3 Business/Risk** — risk register (likelihood × impact), compliance mapping, remediation owners/cost, strategic recommendations.
- Each in **MD+Mermaid (source of truth), HTML, PDF**.
- Includes: confidence/likelihood legend (ICD 203 vs FIRST — operator picks scale), seal/approval footer mockup, shared CSS paged-media theme (dark technical for HTML/PDF per SRL-2018).
- **Output:** mockups under `logs/2026-06-01-report-engine-design/mockups/`. **STOP for review.**

## Phase 2 — Canonical schema extension + transformers  ✅ DONE (shipped)
**Exit:** `ReportGenerateResult.sections` projects cleanly into 3 tier view models. **Shipped & verified.**

- ✅ **Shipped:** per-finding fields all landed on `Finding` (`src/agentropix_sift/reports/view_models.py`): `business_impact`, `risk_score` (= `likelihood_weight × severity_impact_weight`, 0..25), `likelihood` (FIRST 5-tier `Literal`), `kill_chain_phase`. ATT&CK technique IDs already present.
- `view_models.py`: pydantic view models per tier (projections only — no new evidence).
- `transformers.py`: `sections` dict → analyst/executive/business view models; KPI rollups for exec; risk scoring for business; exec/business carry back-anchors to analyst sections (fidelity-preserving).
- Tests: projection correctness, no-drift invariants (every exec/business claim resolves to an analyst anchor).

## Phase 3 — Markdown + Mermaid renderer (source of truth)
**Exit:** each tier emits valid MD+Mermaid matching approved mockups.

- `markdown.py`: view model → Markdown per tier.
- `diagrams.py`: Mermaid builders. **SHIPPED:** `kill_chain_timeline`, `ioc_graph`, and `process_tree_diagram` (recursive over `ProcessNode`). Width-constrained for PDF. **Narrowing vs plan:** `process_tree_diagram` exists but is **NOT wired into any tier renderer** — the `analyst_diagrams()` convenience returns only `kill_chain` + `ioc_graph` (process-tree needs a `ProcessTreeReport`, which is not part of the view model, so a caller must build it explicitly). There is **NO ATT&CK-Navigator / ATT&CK-layer diagram** in the shipped engine.
- Provenance footnotes from `IOCProvenance` 5-tuple; confidence + likelihood phrases rendered with auto-inserted legend.
- Tests: golden-file MD per tier vs approved mockups.

## Phase 4 — HTML + PDF rendering pipeline
**Exit:** MD+Mermaid → HTML and PDF for all tiers, offline, page-breaks clean.

- `render.py` (**shipped**): MD → HTML via the pure-pip `markdown` library (extensions: tables, fenced_code, toc, attr_list) into a self-contained single-string HTML shell, then PDF via the capability-gated engine (Chromium default → WeasyPrint fallback). **NO mmdc SVG-prerender, no pandoc, no jinja2** — Mermaid is emitted as fenced ```mermaid blocks and rendered by Chromium.
- Shared CSS paged-media stylesheet is **inlined in `render.py`** (`_DEFAULT_CSS`, `break-inside: avoid` for code/tables/figures). **No `assets/` dir shipped** (no vendored fonts/logo); the inline CSS keeps it offline.
- Tests: render all tiers from SRL-2018 sample; assert no missing diagram text in PDF; assert code/table/figure not split across pages; assert zero network calls (offline harness).

## Phase 5 — MCP tool ✅ DONE · seal integration ⛔ DESCOPED (not shipped)
**Exit:** `mcp_report_export` callable. **Shipped via PR #198.**

- ✅ **Shipped:** the MCP tool `report_export{tier, fmt, case_id}` (wired in `mcp_server/server.py`, PR #198) → artifact path + MIME; internally runs `report_generate(profile="full")` → `build_tier_bundle` (no-drift validated) → render.
- ⛔ **DESCOPED / NOT SHIPPED:** seal integration. There is **no seal/approval-metadata footer embed, no `courtroom.seal_report()` call, and no `verify_seal()` round-trip in the reports package** (grep of `src/agentropix_sift/reports/` finds none). Sealing of rendered artifacts is not part of the merged engine.
- Tests: export each tier/format end-to-end (shipped). Seal-verify tests are **not present** (feature descoped).

## Phase 6 — Real-data validation + docs  ✅ DONE (merged)
**Exit:** full validation report; resolution chain driven to merged PR. **Complete.**

- Run all 3 tiers × 3 formats against the **SRL-2018 corpus**; produce a validation artifact (KPI deck style) under `logs/`.
- Dual-gate verification: `stat` each artifact + compare embedded counts vs `mcp_report_generate` JSON.
- Docs: runbook (system-binary prereqs, offline rendering, engine selection); CHANGELOG entry. ✅ **ADR-024 → Accepted on validation.**
- ✅ **Resolution chain complete:** merged in **two squash PRs on `main`** — **PR #197** (`7c07d377a feat(reports): multi-tier report engine (ADR-024)` — reports/ package) and **PR #198** (`3f633be3c feat(reports): expose report_export MCP tool (ADR-024 Phase 5)` — wires the MCP tool). (The readiness report names only #197; tool exposure landed separately as #198.)

---

## Subagent crew (per AGENTS.md dispatch policy)

| Phase | Agent | Brief (OBJECTIVE / DONE-WHEN) |
|-------|-------|-------------------------------|
| 0 | forge-dev | Prove PDF toolchain offline; DONE-WHEN both engines render the sample. *(Shipped: Chromium default + WeasyPrint fallback; SVG-prerender path NOT shipped.)* |
| 1 | forge-tech-writer + forge-patterns | 3×3 mockups from SRL-2018 data; DONE-WHEN operator approves |
| 2–3 | forge-dev | transformers + MD/Mermaid renderer; DONE-WHEN golden MD matches mockups, tests green |
| 4 | forge-dev | HTML/PDF pipeline; DONE-WHEN offline render clean, no diagram text loss |
| 5 | forge-dev + forge-architect | MCP tool ✅ shipped (PR #198); seal integration ⛔ descoped (verify_seal not shipped) |
| 6 | forge-tea + forge-tech-writer | SRL-2018 validation + docs; ✅ DONE — PRs #197 + #198 merged to main, ADR-024 Accepted |

## Quality gates (every phase transition)

```
cd /home/admin2/agentropix-sift
uv run ruff check . && uv run ruff format --check .
uv run basedpyright
uv run pytest --cov=agentropix_sift.reports --cov-fail-under=90
```

## Risks

| Risk | Mitigation |
|------|------------|
| Mermaid text-drop in PDF | *Planned:* mmdc SVG prerender. **Shipped reality:** mitigation NOT shipped — Mermaid is passed through as fenced blocks and rendered by headless Chromium (the default engine), which carries diagram fidelity. The WeasyPrint fallback does **not** pre-render diagrams, so the TD-graph text-drop risk remains under that fallback. |
| Headless Chromium container fragility | WeasyPrint fallback selected by `detect_pdf_capability` (no SVG-prerender shipped); documented runbook |
| Tier drift / exec distortion | no-drift invariant tests; exec/business back-anchor to analyst |
| Heavy deps bloat core install | `[reports]` extra, not core dependency |
| Air-gap egress leak | offline render harness asserts zero network calls |

## Open decisions for operator — RESOLVED (shipped defaults)

1. **Confidence/likelihood scale:** ✅ **RESOLVED — FIRST 5-tier shipped.** `view_models.py` ships likelihood as a FIRST 5-tier `Literal` (`almost_certain` > `highly_likely` > `likely` > `unlikely` > `remote`, `LIKELIHOOD_WEIGHT` 5..1); `likelihood_scale` defaults to `"FIRST-5"`. Confidence (LCA `high`/`moderate`/`low`) is a **separate axis**. (ICD-203 7-tier not adopted.)
2. **Default PDF engine:** ✅ **RESOLVED — headless Chromium default, WeasyPrint fallback.** Shipped in `detect_pdf_capability(prefer="chromium")` (`render.py`): probes Chromium first, falls back to WeasyPrint; raises `ToolchainUnavailable` with install hints if neither is present (never auto-installs).
3. **Tier 3 scope:** ✅ **RESOLVED — risk + compliance only.** `RiskItem` ships `compliance_refs` and `remediation_owner` (present but empty by default); no cost-modeling fields were added.
