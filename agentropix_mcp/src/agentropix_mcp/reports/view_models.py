"""ADR-024 — tier view models (presentation projections, not new evidence).

These are *projections* over the canonical ``ReportGenerateResult.sections``
dict produced by ``mcp_report_generate`` (case_records.py). They add no new
evidence: every field is either copied from the canonical finding set or
derived deterministically from it (KPI rollups, risk score, back-anchors).

Three tiers (ADR-024 Decision, Option 2):

  * ``AnalystView``    — full technical projection (one Finding per APPROVED
                         finding, IOC table, timeline, MITRE grid).
  * ``ExecutiveView``  — filtered to critical findings + business-impact
                         translation + KPI rollups; each item back-anchors to
                         an analyst section (no drift).
  * ``BusinessView``   — risk-scored findings (likelihood x impact) +
                         compliance mapping + remediation owners; each item
                         back-anchors to an analyst section (no drift).

Likelihood (FIRST 5-tier, ADR-024 §Provenance) is kept SEPARATE from
confidence (LCA High/Moderate/Low). They are different axes and must never be
collapsed into one number.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "AnalystView",
    "BusinessView",
    "Confidence",
    "EvidenceRef",
    "ExecutiveItem",
    "ExecutiveView",
    "Finding",
    "IOCRow",
    "KPIRollup",
    "Likelihood",
    "RiskItem",
    "Severity",
    "TierBundle",
    "TimelineRow",
]


# FIRST 5-tier likelihood scale (ADR-024 default; ICD-203 7-tier is the
# alternative the operator may select). Kept as a closed Literal so a typo
# cannot silently invent a sixth band.
Likelihood = Literal[
    "almost_certain",
    "highly_likely",
    "likely",
    "unlikely",
    "remote",
]

# LCA confidence band — a SEPARATE axis from likelihood (ADR-024).
Confidence = Literal["high", "moderate", "low"]

Severity = Literal["critical", "high", "medium", "low", "info"]


# Ordinal weights for the FIRST 5-tier scale, used by the business-tier risk
# score (likelihood x impact). Higher = more likely.
LIKELIHOOD_WEIGHT: dict[str, int] = {
    "almost_certain": 5,
    "highly_likely": 4,
    "likely": 3,
    "unlikely": 2,
    "remote": 1,
}

# Impact weight derived from finding severity (the "impact" half of the risk
# product). info maps to 0 so an informational finding cannot inflate risk.
SEVERITY_IMPACT_WEIGHT: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 0,
}


class EvidenceRef(BaseModel):
    """A court-defensible pointer back to primary evidence.

    Mirrors the ``IOCProvenance`` 5-tuple (wazuh/models.py) at the
    presentation layer: enough to re-derive the indicator from source.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str
    source_sha256: str = ""
    extraction_tool: str = ""
    analyst: str = ""


class IOCRow(BaseModel):
    """One row of the analyst-tier IOC table (projection of an IOC doc)."""

    model_config = ConfigDict(extra="forbid")

    value: str
    ioc_type: str = ""
    confidence: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    provenance: EvidenceRef | None = None


class TimelineRow(BaseModel):
    """One row of the analyst-tier timeline (projection of a timeline event)."""

    model_config = ConfigDict(extra="forbid")

    timestamp: str
    host: str = ""
    event_id: str = ""
    description: str = ""
    kill_chain_phase: str = ""


class Finding(BaseModel):
    """The canonical per-finding view shared by all tiers.

    The analyst tier renders the full object; exec/business tiers project a
    subset and link back to this finding's ``anchor`` (the no-drift contract).
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    title: str
    # Stable in-document anchor (#slug). Exec/business items reference this so
    # every higher-tier claim resolves to an analyst finding (no-drift).
    anchor: str
    technical_body: str = ""
    business_impact: str = ""
    severity: Severity = "info"
    # Risk score = likelihood_weight x severity_impact_weight (0..25).
    risk_score: int = 0
    likelihood: Likelihood = "unlikely"
    confidence: Confidence = "moderate"
    kill_chain_phase: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)


class KPIRollup(BaseModel):
    """Executive-tier KPI rollups derived from the canonical finding set."""

    model_config = ConfigDict(extra="forbid")

    approved_finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    affected_host_count: int = 0
    unique_technique_count: int = 0
    top_tactics: list[str] = Field(default_factory=list)
    dwell_time_days: float | None = None


class ExecutiveItem(BaseModel):
    """A single executive-tier line, back-anchored to an analyst finding."""

    model_config = ConfigDict(extra="forbid")

    title: str
    business_impact: str
    severity: Severity
    # NO-DRIFT: the analyst-finding id + anchor this item is derived from.
    analyst_finding_id: str
    analyst_anchor: str


class RiskItem(BaseModel):
    """A single business/risk-tier register row, back-anchored to analyst."""

    model_config = ConfigDict(extra="forbid")

    title: str
    likelihood: Likelihood
    severity: Severity
    risk_score: int
    business_impact: str
    compliance_refs: list[str] = Field(default_factory=list)
    remediation_owner: str = ""
    # NO-DRIFT: the analyst-finding id + anchor this row is derived from.
    analyst_finding_id: str
    analyst_anchor: str


class AnalystView(BaseModel):
    """Full technical projection — the source-of-truth tier."""

    model_config = ConfigDict(extra="forbid")

    tier: Literal["analyst"] = "analyst"
    case_id: str
    report_id: str = ""
    snapshot_at: str = ""
    likelihood_scale: str = "FIRST-5"
    findings: list[Finding] = Field(default_factory=list)
    iocs: list[IOCRow] = Field(default_factory=list)
    timeline: list[TimelineRow] = Field(default_factory=list)


class ExecutiveView(BaseModel):
    """Filtered, business-translated, KPI-rolled-up tier."""

    model_config = ConfigDict(extra="forbid")

    tier: Literal["executive"] = "executive"
    case_id: str
    report_id: str = ""
    snapshot_at: str = ""
    kpis: KPIRollup = Field(default_factory=KPIRollup)
    items: list[ExecutiveItem] = Field(default_factory=list)


class BusinessView(BaseModel):
    """Risk-scored, compliance-mapped tier."""

    model_config = ConfigDict(extra="forbid")

    tier: Literal["business"] = "business"
    case_id: str
    report_id: str = ""
    snapshot_at: str = ""
    likelihood_scale: str = "FIRST-5"
    risk_register: list[RiskItem] = Field(default_factory=list)


class TierBundle(BaseModel):
    """The three coordinated tier views projected from one finding set."""

    model_config = ConfigDict(extra="forbid")

    analyst: AnalystView
    executive: ExecutiveView
    business: BusinessView
