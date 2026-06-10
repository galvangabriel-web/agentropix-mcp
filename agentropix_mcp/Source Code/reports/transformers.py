"""ADR-024 — transformers: ``sections`` dict -> three tier view models.

This is the load-bearing no-drift layer. There is ONE canonical finding set
(the analyst tier, built directly from ``ReportGenerateResult.sections``).
The executive and business tiers are *projections* over that set: every
``ExecutiveItem`` / ``RiskItem`` carries the ``analyst_finding_id`` +
``analyst_anchor`` of the finding it was derived from, so a renderer (or a
test) can prove every higher-tier claim resolves back to an analyst finding.

Input shape: the ``sections`` dict from ``mcp_report_generate`` (profile
``full`` is richest; ``findings`` / ``executive`` also accepted). See
case_records.py ``_profile_full`` for the section spine:
``{executive_summary, findings:{approved_findings:[...]}, timeline, iocs}``.

Degrade gracefully: missing/typo'd fields fall back to safe defaults rather
than raising — a partial case still renders.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from agentropix_mcp.reports.view_models import (
    LIKELIHOOD_WEIGHT,
    SEVERITY_IMPACT_WEIGHT,
    AnalystView,
    BusinessView,
    Confidence,
    EvidenceRef,
    ExecutiveItem,
    ExecutiveView,
    Finding,
    IOCRow,
    KPIRollup,
    Likelihood,
    RiskItem,
    Severity,
    TierBundle,
    TimelineRow,
)

__all__ = [
    "NoDriftError",
    "build_analyst_view",
    "build_business_view",
    "build_executive_view",
    "build_tier_bundle",
    "slugify",
    "validate_no_drift",
]


class NoDriftError(ValueError):
    """A higher-tier item references an analyst finding that does not exist.

    Raised by :func:`validate_no_drift` when an ``ExecutiveItem`` or
    ``RiskItem`` carries an ``analyst_anchor`` / ``analyst_finding_id`` that is
    not in the canonical analyst finding set — i.e. a synthesized or dangling
    back-anchor. This is the enforcing no-drift invariant: a business/executive
    claim with no analyst origin is rejected rather than silently shipped.
    """


# Severities the executive tier surfaces (filtered set, ADR-024 Tier model).
_EXEC_SEVERITIES: frozenset[str] = frozenset({"critical", "high"})

_VALID_SEVERITIES: frozenset[str] = frozenset(SEVERITY_IMPACT_WEIGHT)
_VALID_LIKELIHOODS: frozenset[str] = frozenset(LIKELIHOOD_WEIGHT)
_VALID_CONFIDENCE: frozenset[str] = frozenset({"high", "moderate", "low"})

# Map the wazuh finding float-confidence band (case_records _CONFIDENCE_WORD_MAP
# range) onto the LCA 3-tier band used by the report tiers.
_CONFIDENCE_ALIASES: dict[str, str] = {
    "very_high": "high",
    "critical": "high",
    "medium": "moderate",
    "med": "moderate",
    "very_low": "low",
    "info": "low",
    "informational": "low",
}


def slugify(text: str) -> str:
    """Deterministic in-document anchor slug (for back-anchor refs)."""
    out = re.sub(r"[^a-z0-9]+", "-", str(text).strip().lower())
    return out.strip("-") or "finding"


def _coerce_severity(value: Any) -> Severity:
    s = str(value or "").strip().lower()
    if s in _VALID_SEVERITIES:
        return s  # type: ignore[return-value]
    return "info"


def _coerce_likelihood(value: Any) -> Likelihood:
    s = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
    if s in _VALID_LIKELIHOODS:
        return s  # type: ignore[return-value]
    return "unlikely"


def _coerce_confidence(value: Any) -> Confidence:
    # Accept a float in [0,1] (the wazuh finding-doc shape) or a word.
    if isinstance(value, bool):
        return "moderate"
    if isinstance(value, (int, float)):
        f = float(value)
        if f >= 0.8:
            return "high"
        if f >= 0.5:
            return "moderate"
        return "low"
    s = str(value or "").strip().lower()
    if s in _VALID_CONFIDENCE:
        return s  # type: ignore[return-value]
    if s in _CONFIDENCE_ALIASES:
        return _CONFIDENCE_ALIASES[s]  # type: ignore[return-value]
    return "moderate"


def _str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _evidence_refs(raw: dict[str, Any]) -> list[EvidenceRef]:
    """Project a finding's provenance/evidence into EvidenceRef rows."""
    refs: list[EvidenceRef] = []
    prov = raw.get("provenance")
    if isinstance(prov, dict):
        refs.append(
            EvidenceRef(
                evidence_id=str(prov.get("source_evidence_sha256", "") or "provenance"),
                source_sha256=str(prov.get("source_evidence_sha256", "")),
                extraction_tool=str(prov.get("extraction_tool", "")),
                analyst=str(prov.get("analyst", "")),
            )
        )
    for ev in _str_list(raw.get("evidence_refs")) + _str_list(raw.get("evidence_ids")):
        refs.append(EvidenceRef(evidence_id=ev))
    return refs


def _risk_score(likelihood: Likelihood, severity: Severity) -> int:
    """Risk = likelihood_weight x impact_weight (0..25)."""
    return LIKELIHOOD_WEIGHT[likelihood] * SEVERITY_IMPACT_WEIGHT[severity]


def _extract_finding_docs(sections: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull the APPROVED finding docs from any supported sections shape."""
    if not isinstance(sections, dict):
        return []
    # full profile: sections["findings"]["approved_findings"]
    fsec = sections.get("findings")
    if isinstance(fsec, dict) and isinstance(fsec.get("approved_findings"), list):
        return [d for d in fsec["approved_findings"] if isinstance(d, dict)]
    # findings profile: sections["approved_findings"]
    if isinstance(sections.get("approved_findings"), list):
        return [d for d in sections["approved_findings"] if isinstance(d, dict)]
    return []


def _extract_ioc_docs(sections: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(sections, dict):
        return []
    isec = sections.get("iocs")
    if isinstance(isec, dict) and isinstance(isec.get("iocs"), list):
        return [d for d in isec["iocs"] if isinstance(d, dict)]
    if isinstance(sections.get("iocs"), list):
        return [d for d in sections["iocs"] if isinstance(d, dict)]
    return []


def _extract_timeline_docs(sections: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(sections, dict):
        return []
    tsec = sections.get("timeline")
    if isinstance(tsec, dict) and isinstance(tsec.get("approved_timeline_events"), list):
        return [d for d in tsec["approved_timeline_events"] if isinstance(d, dict)]
    if isinstance(sections.get("approved_timeline_events"), list):
        return [d for d in sections["approved_timeline_events"] if isinstance(d, dict)]
    return []


def _finding_from_doc(raw: dict[str, Any], used_anchors: set[str]) -> Finding:
    finding_id = str(raw.get("finding_id", "") or "")
    title = str(raw.get("title") or raw.get("name") or finding_id or "untitled-finding")

    # Unique anchor: slug of title, disambiguated by finding_id on collision.
    base = slugify(title)
    anchor = base
    if anchor in used_anchors and finding_id:
        anchor = f"{base}-{slugify(finding_id)}"
    while anchor in used_anchors:
        anchor = f"{anchor}-x"
    used_anchors.add(anchor)

    severity = _coerce_severity(raw.get("severity"))
    likelihood = _coerce_likelihood(raw.get("likelihood"))
    return Finding(
        finding_id=finding_id,
        title=title,
        anchor=anchor,
        technical_body=str(raw.get("technical_body") or raw.get("description") or ""),
        business_impact=str(raw.get("business_impact") or ""),
        severity=severity,
        risk_score=_risk_score(likelihood, severity),
        likelihood=likelihood,
        confidence=_coerce_confidence(raw.get("confidence")),
        kill_chain_phase=str(raw.get("kill_chain_phase") or ""),
        mitre_techniques=_str_list(raw.get("mitre_techniques")),
        evidence_refs=_evidence_refs(raw),
    )


def build_analyst_view(
    sections: dict[str, Any], *, meta: dict[str, Any] | None = None
) -> AnalystView:
    """Build the canonical analyst tier — the source of truth for all tiers."""
    meta = meta or {}
    used_anchors: set[str] = set()
    findings = [_finding_from_doc(d, used_anchors) for d in _extract_finding_docs(sections)]

    iocs: list[IOCRow] = []
    for d in _extract_ioc_docs(sections):
        prov = d.get("provenance")
        ref = (
            EvidenceRef(
                evidence_id=str(prov.get("source_evidence_sha256", "") or "provenance"),
                source_sha256=str(prov.get("source_evidence_sha256", "")),
                extraction_tool=str(prov.get("extraction_tool", "")),
                analyst=str(prov.get("analyst", "")),
            )
            if isinstance(prov, dict)
            else None
        )
        iocs.append(
            IOCRow(
                value=str(d.get("value") or d.get("ioc_value") or ""),
                ioc_type=str(d.get("ioc_type") or d.get("kind") or ""),
                confidence=str(d.get("confidence") or ""),
                mitre_techniques=_str_list(d.get("mitre_techniques") or d.get("mitre")),
                provenance=ref,
            )
        )

    timeline: list[TimelineRow] = []
    for d in _extract_timeline_docs(sections):
        host_field = d.get("host")
        if isinstance(host_field, dict):
            host = str(host_field.get("name", "") or "")
        else:
            host = str(host_field or d.get("hostname") or "")
        timeline.append(
            TimelineRow(
                timestamp=str(d.get("timestamp") or d.get("@timestamp") or ""),
                host=host,
                event_id=str(d.get("event_id") or ""),
                description=str(d.get("description") or d.get("message") or ""),
                kill_chain_phase=str(d.get("kill_chain_phase") or ""),
            )
        )

    return AnalystView(
        case_id=str(meta.get("case_id", "") or ""),
        report_id=str(meta.get("report_id", "") or ""),
        snapshot_at=str(meta.get("snapshot_at", "") or ""),
        likelihood_scale=str(meta.get("likelihood_scale", "FIRST-5")),
        findings=findings,
        iocs=iocs,
        timeline=timeline,
    )


def _dwell_time_days(analyst: AnalystView) -> float | None:
    """Span between first and last timeline event, in days (None if <2)."""
    parsed: list[datetime] = []
    for row in analyst.timeline:
        ts = row.timestamp.strip().replace("Z", "+00:00")
        try:
            parsed.append(datetime.fromisoformat(ts))
        except (ValueError, TypeError):
            continue
    if len(parsed) < 2:
        return None
    span = max(parsed) - min(parsed)
    return round(span.total_seconds() / 86400.0, 2)


def build_executive_view(analyst: AnalystView) -> ExecutiveView:
    """Project the analyst tier into the executive tier (filtered + rollups).

    Each ExecutiveItem back-anchors to the analyst finding it came from.
    """
    hosts: set[str] = {r.host for r in analyst.timeline if r.host}
    techniques: set[str] = set()
    tactic_counts: dict[str, int] = {}
    critical = high = 0

    items: list[ExecutiveItem] = []
    for f in analyst.findings:
        techniques.update(f.mitre_techniques)
        if f.kill_chain_phase:
            tactic_counts[f.kill_chain_phase] = tactic_counts.get(f.kill_chain_phase, 0) + 1
        if f.severity == "critical":
            critical += 1
        elif f.severity == "high":
            high += 1
        if f.severity in _EXEC_SEVERITIES:
            items.append(
                ExecutiveItem(
                    title=f.title,
                    business_impact=f.business_impact or f.title,
                    severity=f.severity,
                    analyst_finding_id=f.finding_id,
                    analyst_anchor=f.anchor,
                )
            )

    top_tactics = sorted(tactic_counts, key=lambda k: (-tactic_counts[k], k))[:5]
    kpis = KPIRollup(
        approved_finding_count=len(analyst.findings),
        critical_count=critical,
        high_count=high,
        affected_host_count=len(hosts),
        unique_technique_count=len(techniques),
        top_tactics=top_tactics,
        dwell_time_days=_dwell_time_days(analyst),
    )
    return ExecutiveView(
        case_id=analyst.case_id,
        report_id=analyst.report_id,
        snapshot_at=analyst.snapshot_at,
        kpis=kpis,
        items=items,
    )


def build_business_view(analyst: AnalystView) -> BusinessView:
    """Project the analyst tier into the risk register (risk-scored).

    Each RiskItem back-anchors to the analyst finding it came from and sorts
    by descending risk score (highest risk first).
    """
    rows: list[RiskItem] = []
    for f in analyst.findings:
        rows.append(
            RiskItem(
                title=f.title,
                likelihood=f.likelihood,
                severity=f.severity,
                risk_score=f.risk_score,
                business_impact=f.business_impact or f.title,
                compliance_refs=[],
                remediation_owner="",
                analyst_finding_id=f.finding_id,
                analyst_anchor=f.anchor,
            )
        )
    rows.sort(key=lambda r: (-r.risk_score, r.title))
    return BusinessView(
        case_id=analyst.case_id,
        report_id=analyst.report_id,
        snapshot_at=analyst.snapshot_at,
        likelihood_scale=analyst.likelihood_scale,
        risk_register=rows,
    )


def validate_no_drift(
    analyst: AnalystView,
    executive: ExecutiveView,
    business: BusinessView,
) -> None:
    """Enforce the no-drift contract across the three coordinated tiers.

    Every ``ExecutiveItem`` and every ``RiskItem`` must resolve back to a real
    analyst finding: its ``analyst_anchor`` must be in the analyst finding
    anchor set AND its ``analyst_finding_id`` must be in the analyst finding-id
    set. Any higher-tier item whose anchor/id is not in the analyst finding set
    (a synthesized or dangling back-anchor) raises :class:`NoDriftError`.

    This is the runtime invariant the docstring of this module promises: the
    structural-by-construction provenance is now *proven*, not merely asserted.
    """
    valid_anchors = {f.anchor for f in analyst.findings}
    valid_ids = {f.finding_id for f in analyst.findings if f.finding_id}

    def _check(kind: str, label: str, anchor: str, finding_id: str) -> None:
        if anchor not in valid_anchors:
            raise NoDriftError(
                f"{kind} {label!r} back-anchors to {anchor!r}, which is not an "
                f"analyst finding anchor (no-drift violation)."
            )
        # An empty analyst_finding_id is tolerated only when the analyst set
        # itself has no ids; otherwise a non-resolving id is drift.
        if valid_ids and finding_id not in valid_ids:
            raise NoDriftError(
                f"{kind} {label!r} back-anchors to finding id {finding_id!r}, "
                f"which is not an analyst finding id (no-drift violation)."
            )

    for item in executive.items:
        _check("ExecutiveItem", item.title, item.analyst_anchor, item.analyst_finding_id)
    for row in business.risk_register:
        _check("RiskItem", row.title, row.analyst_anchor, row.analyst_finding_id)


def build_tier_bundle(
    sections: dict[str, Any], *, meta: dict[str, Any] | None = None
) -> TierBundle:
    """One canonical finding set -> three coordinated, no-drift tier views.

    The no-drift invariant is enforced before the bundle is returned: every
    higher-tier item must resolve back to an analyst finding, else
    :class:`NoDriftError` is raised (see :func:`validate_no_drift`).
    """
    analyst = build_analyst_view(sections, meta=meta)
    executive = build_executive_view(analyst)
    business = build_business_view(analyst)
    validate_no_drift(analyst, executive, business)
    return TierBundle(
        analyst=analyst,
        executive=executive,
        business=business,
    )
