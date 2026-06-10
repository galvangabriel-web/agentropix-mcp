"""ADR-024 — Markdown(+Mermaid) renderers: one per tier.

Markdown+Mermaid is the single source of truth (ADR-024 §Assumptions); HTML and
PDF are derived from this output (render.py). Each renderer is pure: view model
in, Markdown string out, no I/O.

The no-drift contract surfaces in the rendered text: every executive item and
risk-register row prints a back-link (``[finding](#anchor)``) to the analyst
finding it was projected from, and the analyst tier defines those anchors via
explicit ``<a id="...">`` tags so the links resolve in HTML/PDF.

A FIRST 5-tier likelihood legend and an LCA confidence legend are
auto-inserted (the two axes kept separate, per ADR-024 §Provenance).
"""

from __future__ import annotations

from agentropix_mcp.reports.diagrams import ioc_graph, kill_chain_timeline
from agentropix_mcp.reports.view_models import (
    AnalystView,
    BusinessView,
    ExecutiveView,
    Finding,
)

__all__ = [
    "CONFIDENCE_LEGEND",
    "LIKELIHOOD_LEGEND",
    "render_analyst_markdown",
    "render_business_markdown",
    "render_executive_markdown",
]


LIKELIHOOD_LEGEND = (
    "> **Likelihood scale (FIRST 5-tier):** "
    "almost_certain > highly_likely > likely > unlikely > remote. "
    "Likelihood estimates the probability of the assessed activity; it is "
    "kept separate from analytic confidence."
)

CONFIDENCE_LEGEND = (
    "> **Confidence (LCA):** high / moderate / low — the analyst's confidence "
    "in the assessment given evidence quality and corroboration. Distinct "
    "from likelihood."
)


def _legend_block() -> str:
    return f"{LIKELIHOOD_LEGEND}\n>\n{CONFIDENCE_LEGEND}"


def _esc(text: str) -> str:
    """Escape pipe chars so free text is safe inside a Markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def _evidence_cell(finding: Finding) -> str:
    if not finding.evidence_refs:
        return "—"
    parts: list[str] = []
    for ref in finding.evidence_refs:
        if ref.source_sha256:
            parts.append(f"`{ref.source_sha256[:12]}…` ({_esc(ref.extraction_tool) or 'tool'})")
        else:
            parts.append(f"`{_esc(ref.evidence_id)}`")
    return "<br>".join(parts)


def render_analyst_markdown(analyst: AnalystView) -> str:
    """Full technical tier — defines the anchors the other tiers link to."""
    out: list[str] = []
    out.append(f"# Analyst / Technical Report — {analyst.case_id or 'case'}")
    if analyst.report_id:
        out.append(
            f"\n*Report ID:* `{analyst.report_id}`  ·  *Snapshot:* {analyst.snapshot_at or 'n/a'}"
        )
    out.append("")
    out.append(_legend_block())
    out.append("")

    out.append("## Findings")
    if not analyst.findings:
        out.append("\n_No APPROVED findings in this case snapshot._")
    for f in analyst.findings:
        # Explicit anchor so exec/business back-links resolve in HTML/PDF.
        out.append(f'\n<a id="{f.anchor}"></a>')
        out.append(f"### {f.title}")
        out.append(
            f"- **Finding ID:** `{f.finding_id}`  ·  **Severity:** {f.severity}  ·  "
            f"**Likelihood:** {f.likelihood}  ·  **Confidence:** {f.confidence}  ·  "
            f"**Risk score:** {f.risk_score}"
        )
        if f.kill_chain_phase:
            out.append(f"- **Kill-chain phase:** {f.kill_chain_phase}")
        if f.mitre_techniques:
            out.append(f"- **MITRE ATT&CK:** {', '.join(f'`{t}`' for t in f.mitre_techniques)}")
        if f.technical_body:
            out.append(f"\n{f.technical_body}")
        if f.business_impact:
            out.append(f"\n_Business impact:_ {f.business_impact}")
        out.append(f"\n_Evidence:_ {_evidence_cell(f)}")

    out.append("\n## Indicators of Compromise")
    if analyst.iocs:
        out.append("\n| Value | Type | Confidence | MITRE | Provenance |")
        out.append("| --- | --- | --- | --- | --- |")
        for ioc in analyst.iocs:
            prov = (
                f"`{ioc.provenance.source_sha256[:12]}…`"
                if ioc.provenance and ioc.provenance.source_sha256
                else "—"
            )
            mitre = ", ".join(ioc.mitre_techniques) or "—"
            out.append(
                f"| `{_esc(ioc.value)}` | {_esc(ioc.ioc_type) or '—'} | "
                f"{_esc(ioc.confidence) or '—'} | {_esc(mitre)} | {prov} |"
            )
        out.append("")
        out.append(ioc_graph(analyst.iocs))
    else:
        out.append("\n_No IOCs extracted._")

    out.append("\n## Timeline")
    if analyst.timeline:
        out.append(kill_chain_timeline(analyst.timeline))
        out.append("\n| Timestamp | Host | Event | Phase | Description |")
        out.append("| --- | --- | --- | --- | --- |")
        for row in analyst.timeline:
            out.append(
                f"| {_esc(row.timestamp)} | {_esc(row.host) or '—'} | {_esc(row.event_id) or '—'} | "  # noqa: E501
                f"{_esc(row.kill_chain_phase) or '—'} | {_esc(row.description) or '—'} |"
            )
    else:
        out.append("\n_No approved timeline events._")

    return "\n".join(out).rstrip() + "\n"


def render_executive_markdown(executive: ExecutiveView) -> str:
    """2-3 page management tier — KPI rollups + critical items, back-anchored."""
    k = executive.kpis
    out: list[str] = []
    out.append(f"# Executive Summary — {executive.case_id or 'case'}")
    if executive.report_id:
        out.append(
            f"\n*Report ID:* `{executive.report_id}`  ·  *Snapshot:* {executive.snapshot_at or 'n/a'}"  # noqa: E501
        )
    out.append("")
    out.append("## Key Performance Indicators")
    out.append("\n| Metric | Value |")
    out.append("| --- | --- |")
    out.append(f"| Approved findings | {k.approved_finding_count} |")
    out.append(f"| Critical | {k.critical_count} |")
    out.append(f"| High | {k.high_count} |")
    out.append(f"| Affected hosts | {k.affected_host_count} |")
    out.append(f"| Unique ATT&CK techniques | {k.unique_technique_count} |")
    out.append(
        f"| Dwell time (days) | {k.dwell_time_days if k.dwell_time_days is not None else 'n/a'} |"
    )
    if k.top_tactics:
        out.append(f"\n**Top tactics:** {', '.join(k.top_tactics)}")

    out.append("\n## Critical & High Findings")
    if not executive.items:
        out.append("\n_No critical or high-severity findings in scope._")
    for item in executive.items:
        # Back-anchor to the analyst tier (no-drift).
        out.append(
            f"- **[{_esc(item.title)}](#{item.analyst_anchor})** "
            f"({item.severity}) — {_esc(item.business_impact)} "
            f"_(see analyst finding `{item.analyst_finding_id}`)_"
        )

    return "\n".join(out).rstrip() + "\n"


def render_business_markdown(business: BusinessView) -> str:
    """Risk/Business tier — risk register sorted by score, back-anchored."""
    out: list[str] = []
    out.append(f"# Business / Risk Report — {business.case_id or 'case'}")
    if business.report_id:
        out.append(
            f"\n*Report ID:* `{business.report_id}`  ·  *Snapshot:* {business.snapshot_at or 'n/a'}"
        )
    out.append("")
    out.append(_legend_block())
    out.append("")
    out.append("## Risk Register")
    if not business.risk_register:
        out.append("\n_No findings to score._")
        return "\n".join(out).rstrip() + "\n"

    out.append(
        "\n| Risk | Likelihood | Severity | Score | Business impact | Compliance | Owner | Analyst ref |"  # noqa: E501
    )
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for r in business.risk_register:
        compliance = ", ".join(r.compliance_refs) or "—"
        out.append(
            f"| {_esc(r.title)} | {r.likelihood} | {r.severity} | {r.risk_score} | "
            f"{_esc(r.business_impact)} | {_esc(compliance)} | {_esc(r.remediation_owner) or '—'} | "  # noqa: E501
            f"[{_esc(r.analyst_finding_id)}](#{r.analyst_anchor}) |"
        )
    return "\n".join(out).rstrip() + "\n"
