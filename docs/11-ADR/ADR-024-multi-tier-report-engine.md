> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

<!-- AUDIT-REMEDIATION-2026-06-05 -->
> ⚠️ **AUDIT 2026-06-05.** Status *Proposed* is out of date — the `report_export` MCP tool shipped (commit `3f633be3c`, “ADR-024 Phase 5”). Update Status to Accepted/Implemented.

# ADR-024: Multi-Tier Report Generation Engine

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Proposed |
| **Date** | 2026-06-01 |
| **Decision Makers** | Victor (Principal Security Engineer + AI Architect); forge-orchestrator (architect track) |
| **Bio-Agentic Component** | Observability / Reporting (presentation layer over existing finding + IOC + correlation models) |
| **Priority** | P1 (High) |

## Context

agentropix-sift can analyze a case end-to-end (timeline correlation, process trees, IOC pivots, sweep detection, memory forensics) and **already** assembles a structured report via `mcp_report_generate()` — but the pipeline terminates at a `sections` data dict serialized as JSON. There is no human-facing rendered output. Operators currently hand-author the polished HTML/PDF reports (e.g. the SRL-2018 Attack Chain report, the SRL-2015/2018 pandoc recovery reports) outside the tool.

We want a first-class feature that turns one analyzed case into **three coordinated, audience-targeted report tiers**, each rendered to **PDF, HTML, and Markdown-with-Mermaid**.

### Problem Statement

Produce, from a single case dataset, three linked reports — (1) Analyst/Technical, (2) Executive, (3) Business/Risk — in three formats each, with court-defensible provenance, framework mapping (MITRE ATT&CK / Kill Chain / Diamond), and no fixed length cap (size scales with case complexity). The SIFT report conventions are the reference template.

### Constraints

- **Build on existing models, do not fork them.** Findings, IOC records + `IOCProvenance` 5-tuple, `TimelineReport`, `ProcessTreeReport`, `IOCPivotReport`, and the `report.schema.json` already exist. The engine is a *projection + rendering* layer.
- **Provenance and seal are mandatory.** Every rendered artifact must preserve source citations / confidence and must be sealable via the existing `courtroom.seal_report()` (ADR-016) HMAC-SHA256 envelope.
- **Approval gate respected.** Reports already filter to APPROVED findings; rendering must not bypass the EvidenceGate / approval ledger.
- **Offline-capable.** SIFT runs on isolated forensic hosts — the pipeline must not require network egress at render time (no CDN-hosted Mermaid/JS). Self-contained assets only.
- **No new external service dependencies** (per USER.md Tier-0). System binaries (headless Chromium, mermaid-cli) are packaging decisions, not network services.
- **Templates-first.** Rendered template mockups (3 tiers × 3 formats) must be reviewed and signed off **before** the rendering engine is built.

### Assumptions

- The canonical incident schema = the existing `report.schema.json` section spine, extended with a small number of per-finding fields (business-impact translation, risk score, likelihood term, kill-chain phase) rather than a parallel schema.
- Markdown+Mermaid is the single source of truth; HTML and PDF are derived from it.
- Tier differentiation is a *filter/projection* over one finding set, not three separate authoring passes (the fidelity-preserving "reference-as-appendix" pattern).

## Decision Drivers

1. **Reuse over rebuild** — the data layer is complete and court-hardened; the only gap is presentation. Minimize new surface.
2. **Provenance fidelity** — exec/business tiers must never silently drop or distort evidence; they must link back to the technical tier.
3. **Diagram fidelity in PDF** — Mermaid in PDF is the single biggest rendering risk (known WeasyPrint TD-graph text-drop bug).
4. **Offline / air-gapped operation** — forensic hosts may have no internet; assets must be vendored.
5. **Auditability** — rendered reports must remain sealable and verifiable; the render step must be deterministic where possible.

## Considered Options

### Option 1: Three independent per-tier authoring pipelines

**Description:** Generate analyst, executive, and business reports as three separate document-build paths.

**Pros:**
- Each tier fully tunable in isolation.

**Cons:**
- Triples authoring/maintenance cost.
- Drift between tiers — exec summary diverges from technical fact (the exact failure mode best-practice warns against).
- Triples template surface for the same evidence.

### Option 2: One canonical finding set → tier projections → single render pipeline (CHOSEN)

**Description:** Extend the existing report data model with per-finding tier fields. A `transformers` layer projects the canonical set into tier-specific view models (analyst = full; executive = filtered + business-impact translation + KPI rollups; business = risk-scored + compliance mapping). A single Markdown+Mermaid renderer emits the source-of-truth doc per tier; one rendering pipeline fans out to HTML and PDF.

**Pros:**
- Single evidence source → tiers cannot drift; exec/business link back to technical anchors (fidelity-preserving).
- Reuses all existing models + the `sections` aggregation in `case_records.py`.
- One rendering pipeline to maintain and seal.

**Cons:**
- Requires a disciplined projection layer and per-finding business-translation/risk fields.

### Option 3: Hand off to an external report SaaS / template service

**Description:** Push the JSON to an external reporting service.

**Pros:**
- No rendering code to maintain.

**Cons:**
- **Hard stop:** network egress of case evidence to an external destination (USER.md Tier-0). Disqualified for air-gapped forensic use.

## Decision

We will use **Option 2 — one canonical finding set, tier projections, single Markdown+Mermaid render pipeline** because it reuses the existing court-hardened data layer, structurally prevents tier drift, and keeps one sealable, offline-capable rendering path.

### Implementation Approach

New package `src/agentropix_sift/reports/` (presentation only — no changes to core models or MCP analysis tools):

```
reports/
  transformers.py   # ReportGenerateResult.sections -> tier view models (analyst|executive|business)
  view_models.py    # pydantic view models per tier (projections, not new evidence)
  markdown.py       # view model -> Markdown(+Mermaid) source-of-truth
  diagrams.py       # Mermaid builders: kill-chain timeline, process tree, IOC/lateral-movement graph, ATT&CK layer
  render.py         # MD -> SVG-prerender (mmdc) -> HTML (pandoc/jinja) + PDF (headless chromium | weasyprint+svg)
  templates/        # jinja/pandoc templates + CSS paged-media stylesheet (3 tiers)
  assets/           # vendored fonts, CSS, logo — NO network fetch at render time
```

**Rendering pipeline (the load-bearing decision):**
1. Single source = **Markdown + Mermaid** per tier.
2. **Pre-render Mermaid → SVG via `mermaid-cli` (mmdc)** as a build step — decouples diagram fidelity from the PDF engine and sidesteps the WeasyPrint TD-graph bug.
3. **HTML tier:** Markdown → HTML (pandoc or jinja), SVGs inlined; self-contained single file.
4. **PDF tier:** **headless Chromium = default** (most robust, renders diagrams + CSS paged-media faithfully); **WeasyPrint + pre-rendered SVG = lightweight pure-Python alternative** behind a config flag.
5. Shared **CSS paged-media stylesheet** (`@page`, `break-inside: avoid` on tables/code/figures, `.pagebreak` utility) — the single highest-leverage PDF-quality artifact.

**Tier model:**
- **Analyst/Technical** — full projection: timeline, IOC tables (with `IOCProvenance` footnotes + confidence), process trees, beacon/C2 analysis, ATT&CK grid, evidence sources. Structural template = SRL-2018 Attack Chain report.
- **Executive** — filtered to critical findings + business-impact translation + KPI rollups (severity/host/technique counts, dwell time); 2–3 page equivalent; links back to analyst anchors.
- **Business/Risk** — risk-scored findings (likelihood × impact), compliance/regulatory mapping, remediation owners/cost, strategic recommendations.

**Provenance / confidence:** carry per finding — linked evidence IDs + SHA-256, **likelihood term** (configurable scale: ICD 203 7-tier or FIRST 5-tier) kept **separate** from **confidence level** (LCA: High/Moderate/Low). Scale legend auto-inserted per report.

**Framework layering:** ATT&CK technique IDs = machine-readable spine (renders as ATT&CK-Navigator layer + Mermaid kill-chain diagram); Kill Chain = exec storyboard; Diamond = attribution appendix.

**Seal integration:** rendered artifacts are accompanied by the canonical report JSON; `courtroom.seal_report()` seals the JSON, and the seal/verification metadata (examiner_id, approved_at, seal hex) is embedded in the rendered doc footer for chain-of-custody visibility.

**New MCP tool:** `mcp_report_export(case_id, tier, format)` → returns artifact path + MIME type. Existing `mcp_report_generate` unchanged (still the JSON data source).

### Migration Path

No migration — additive feature. `mcp_report_generate` JSON output remains the stable contract; `mcp_report_export` is new.

## Consequences

### Positive

- Presentation-only change; core models, MCP analysis tools, and the seal stay untouched.
- Tiers structurally cannot drift from evidence.
- Offline-capable, sealable, court-defensible rendered output.
- Operators stop hand-authoring HTML/PDF.

### Negative

- Adds packaging weight: `jinja2`, `markdown`/`pandoc`, `mermaid-cli`, and a PDF engine (headless Chromium or WeasyPrint). **Mitigation:** vendor assets; make the PDF engine pluggable; document the system-binary prerequisites; gate heavy deps behind an extras group (`pip install agentropix-sift[reports]`).
- Headless Chromium in containers needs font packages / `--no-sandbox`. **Mitigation:** documented runbook + WeasyPrint fallback path.

### Neutral

- mmdc pre-render adds a build step but makes diagram rendering deterministic and engine-independent.

## Bio-Agentic Mapping

| Agentropix Component | This Decision's Role |
|---------------------|---------------------|
| Observability / Reporting | New presentation tier over existing findings + correlation output |
| Oncologist / EvidenceGate | Render path respects approval gate; only APPROVED findings surface |
| Courtroom (ADR-016 seal) | Rendered artifacts remain sealable + verifiable |
| MHC / provenance (WZ-019) | `IOCProvenance` 5-tuple surfaced as in-report citations |

## Validation Criteria

- [ ] Template mockups for all 3 tiers × 3 formats approved by operator BEFORE engine build.
- [ ] One real case (SRL-2018 corpus) renders all 3 tiers in all 3 formats with no errors.
- [ ] Mermaid diagrams render correctly in PDF (no missing text) via the SVG-prerender path.
- [ ] Rendered report's embedded provenance matches the canonical JSON; seal verifies.
- [ ] Render path performs no network egress (verified offline).
- [ ] Page breaks do not split code blocks / tables / figures.
- [ ] Quality gates green (ruff, basedpyright, pytest ≥90% on the new package).

## References

- Internal: `mcp_report_generate()` (`src/agentropix_sift/mcp_server/wrappers/case_records.py`), `report.schema.json`, `courtroom.py`, `wazuh/models.py` (`IOCProvenance`).
- Attached reference reports (operator-supplied 2026-06-01): SRL-2018 Attack Chain; SRL-2015/2018 recovery reports; phishing-chain validation deck.
- NIST SP 800-61r3, SP 800-86, IR 8387; SANS DFIR report writing; CISA Best Practices for ATT&CK Mapping; FIRST CTI Reporting (WEP/LCA); ICD 203.
- Pipeline: pandoc+mermaid, WeasyPrint SVG bug #1655, mermaid-cli, headless-Chromium PDF.
- Related ADRs: ADR-016 (courtroom audit seal), ADR-013 (evtx wrapper), ADR-018 (wazuh IOC push), ADR-019 (AR confirmation gate).

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-06-01 | forge-orchestrator (architect track) | Initial draft (Proposed) |
