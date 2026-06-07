# ADR-024: Multi-Tier Report Generation Engine

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted / Implemented |
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

> **SHIPPED REALITY (verified against `src/agentropix_sift/reports/`, branch `main`).** The
> as-built tree is leaner than this original plan. The `templates/` and `assets/` dirs were
> **NOT shipped**, and the render path uses **no jinja2 and no pandoc** — `render.py` renders
> HTML with the pure-pip `markdown` library and produces PDF via headless Chromium (default)
> or WeasyPrint, with the paged-media CSS inlined in `render.py` rather than living in a
> stylesheet file. Annotations below reflect the actual package.

```
reports/
  __init__.py       # package exports                                         [SHIPPED]
  transformers.py   # ReportGenerateResult.sections -> tier view models;      [SHIPPED]
                    #   enforces the no-drift invariant (validate_no_drift)
  view_models.py    # pydantic view models per tier (projections, not new evidence)  [SHIPPED]
  markdown.py       # view model -> Markdown(+Mermaid) source-of-truth         [SHIPPED]
  diagrams.py       # Mermaid builders: kill-chain timeline, process tree,     [SHIPPED]
                    #   IOC/lateral-movement graph, ATT&CK layer
  render.py         # MD -> HTML (pure-pip `markdown` lib) + PDF (headless     [SHIPPED — but
                    #   chromium default | weasyprint fallback). NO mmdc/SVG     simplified vs plan:
                    #   prerender, NO jinja2, NO pandoc. Paged-media CSS inlined  no jinja/pandoc/mmdc]
  export.py         # export orchestration: build_tier_bundle -> tier_markdown [SHIPPED]
                    #   -> render; returns ExportResult
  # templates/      # NOT SHIPPED — no jinja/pandoc templates; CSS is inlined in render.py
  # assets/         # NOT SHIPPED — no vendored fonts/CSS/logo dir
```

**Rendering pipeline (the load-bearing decision):**

> **SHIPPED REALITY.** The `mermaid-cli` (mmdc) SVG-prerender build step (planned step 2) was
> **NOT implemented**. As built, Mermaid is emitted as fenced ` ```mermaid ` blocks in the
> Markdown source-of-truth and **passed through to the HTML as-is** (no mmdc invocation, no
> SVG inlining) — diagrams render client-side in the consuming viewer. The steps below are
> corrected to the as-built path.

1. Single source = **Markdown + Mermaid** per tier (`markdown.py`).
2. ~~Pre-render Mermaid → SVG via `mermaid-cli` (mmdc) as a build step.~~ **DEFERRED / NOT SHIPPED.** No mmdc dependency; Mermaid stays as fenced ` ```mermaid ` source.
3. **HTML tier:** Markdown → HTML via the pure-pip **`markdown` library** (no pandoc, no jinja); fenced Mermaid blocks pass through verbatim; self-contained single file.
4. **PDF tier:** **headless Chromium = default** (renders CSS paged-media faithfully); **WeasyPrint = pure-Python fallback** selectable via `prefer="weasyprint"`. Both engines are capability-gated (`detect_pdf_capability`) and never auto-install a toolchain. (Note: because mmdc was not shipped, Mermaid does not pre-render to SVG for the WeasyPrint path.)
5. Shared **CSS paged-media rules** (`@page`, `break-inside: avoid` on `pre`/`table`/`figure`/`.mermaid`) — **inlined in `render.py`**, not a separate stylesheet file.

**Tier model:**
- **Analyst/Technical** — full projection: timeline, IOC tables (with `IOCProvenance` footnotes + confidence), process trees, beacon/C2 analysis, ATT&CK grid, evidence sources. Structural template = SRL-2018 Attack Chain report.
- **Executive** — filtered to critical findings + business-impact translation + KPI rollups (severity/host/technique counts, dwell time); 2–3 page equivalent; links back to analyst anchors.
- **Business/Risk** — risk-scored findings (likelihood × impact), compliance/regulatory mapping, remediation owners/cost, strategic recommendations.

**Provenance / confidence:** carry per finding — linked evidence IDs + SHA-256, **likelihood term** (configurable scale: ICD 203 7-tier or FIRST 5-tier) kept **separate** from **confidence level** (LCA: High/Moderate/Low). Scale legend auto-inserted per report.

**Framework layering:** ATT&CK technique IDs = machine-readable spine (renders as ATT&CK-Navigator layer + Mermaid kill-chain diagram); Kill Chain = exec storyboard; Diamond = attribution appendix.

**Seal integration:** ~~rendered artifacts are accompanied by the canonical report JSON; `courtroom.seal_report()` seals the JSON, and the seal/verification metadata (examiner_id, approved_at, seal hex) is embedded in the rendered doc footer for chain-of-custody visibility.~~

> **NOT SHIPPED.** This design item was **not implemented** in the reports package or in
> `report_export`. There is **no** `courtroom.seal_report()` call over the report JSON and **no**
> rendered-footer seal metadata (examiner_id / approved_at / seal hex) — verified: zero seal/
> courtroom references in `src/agentropix_sift/reports/` or the `report_export` tool. The only
> seal in the repo is the separate orchestrator / ADR-016 track. Rendered-artifact sealing
> remains an open follow-up, not a shipped capability of this engine.

**New MCP tool (SHIPPED):** `mcp_report_export(tier, fmt, case_id)` (PR #198). It internally runs
`report_generate(profile="full")`, projects the sections through `build_tier_bundle` (which enforces
the no-drift invariant), renders the chosen tier/format, and returns an **`ExportResult`** dict —
`{tier, fmt, mime, content, path, bytes, pdf_capability}` (not merely "artifact path + MIME type").
`content` is inline for text formats (md/html) and `None` for the binary PDF (which is written to
`path`); `pdf_capability` reports the selected engine. PDF toolchain absence returns a structured
`ToolError` with a pip/packaging install hint rather than crashing. Existing `mcp_report_generate`
is unchanged (still the JSON data source). Source: `mcp_server/server.py` `mcp_report_export`,
`reports/export.py` `export_report`/`ExportResult`.

### Migration Path

No migration — additive feature. `mcp_report_generate` JSON output remains the stable contract; `mcp_report_export` is new.

## Consequences

### Positive

- Presentation-only change; core models, MCP analysis tools, and the seal stay untouched.
- Tiers structurally cannot drift from evidence.
- Offline-capable, sealable, court-defensible rendered output.
- Operators stop hand-authoring HTML/PDF.

### Negative

- Adds packaging weight: the PDF engine (headless Chromium or WeasyPrint) plus the `[reports]` extra. **Mitigation:** make the PDF engine pluggable (capability-gated, with a structured install hint on absence); document the system-binary prerequisites; gate heavy deps behind an extras group (`pip install agentropix-sift[reports]`). *(As-built note: the originally-planned `jinja2`, `pandoc`, and `mermaid-cli` deps were **not** taken on — HTML uses the pure-pip `markdown` lib and Mermaid is passed through as fenced source.)*
- Headless Chromium in containers needs font packages / `--no-sandbox`. **Mitigation:** documented runbook + WeasyPrint fallback path.

### Neutral

- ~~mmdc pre-render adds a build step but makes diagram rendering deterministic and engine-independent.~~ *(As-built: the mmdc pre-render step was **not shipped**; Mermaid is emitted as fenced source and rendered client-side by the consuming viewer.)*

## Bio-Agentic Mapping

| Agentropix Component | This Decision's Role |
|---------------------|---------------------|
| Observability / Reporting | New presentation tier over existing findings + correlation output |
| Oncologist / EvidenceGate | Render path respects approval gate; only APPROVED findings surface |
| Courtroom (ADR-016 seal) | Rendered artifacts remain sealable + verifiable |
| MHC / provenance (WZ-019) | `IOCProvenance` 5-tuple surfaced as in-report citations |

## Validation Criteria

- [ ] Template mockups for all 3 tiers × 3 formats approved by operator BEFORE engine build. *(Templates-first step was dropped — no `templates/` dir shipped; engine built directly.)*
- [x] One real case renders all 3 tiers in all 3 formats with no errors. *(md/html/pdf paths shipped; PDF gated on a local Chromium/WeasyPrint engine.)*
- [ ] ~~Mermaid diagrams render correctly in PDF (no missing text) via the SVG-prerender path.~~ **N/A — the mmdc/SVG-prerender path was not shipped;** Mermaid is emitted as fenced source and passed through to HTML (no SVG inlining), so this PDF-via-SVG criterion does not apply as written.
- [ ] Rendered report's embedded provenance matches the canonical JSON; **seal verifies.** *(Provenance is carried through the view models; the **seal half is N/A — sealing was not shipped**, see "Seal integration" above.)*
- [x] Render path performs no network egress (verified offline). *(Pure-pip `markdown` + local Chromium/WeasyPrint; no CDN/network calls at render time.)*
- [x] Page breaks do not split code blocks / tables / figures. *(`break-inside: avoid` on `pre`/`table`/`figure`/`.mermaid` inlined in `render.py`.)*
- [x] Quality gates green (ruff, basedpyright, pytest) on the new package. *(Merged via PR #197 + #198 with gates green; the no-drift invariant is enforced at runtime by `validate_no_drift`.)*

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
| 2026-06-01 | forge-orchestrator (architect track) | **Implemented + merged to `main`.** PR #197 `7c07d377a feat(reports): multi-tier report engine (ADR-024)` (reports package); PR #198 `3f633be3c feat(reports): expose report_export MCP tool (ADR-024 Phase 5)` (MCP tool). Status → **Accepted / Implemented** (per IMPLEMENTATION-PLAN Phase 6: "ADR-024 → Accepted on validation"). |
| 2026-06-07 | doc-update pass | Reconciled doc to shipped reality: no `templates/`/`assets/` dirs, no jinja2/pandoc/mmdc; pure-pip `markdown` + Chromium/WeasyPrint render path; rendered-artifact seal **not shipped**; corrected `report_export` signature → `(tier, fmt, case_id) → ExportResult`. |
