"""Agentropix finding → Wazuh alert mapper.

Converts structured DFIR findings (from Reports_results/*/report.json) into
Wazuh-native alert format for batch ingestion into the Wazuh manager via the
Elasticsearch/Indexer API.

Design:
  - Confidence (0.0–1.0) → Wazuh level (1–15)
  - MITRE ATT&CK technique → Wazuh rule groups + rule ID
  - Finding metadata → Agent info + DFIR provenance
  - Batch-safe: idempotent, dedupable by fingerprint

Correct ADRs: ADR-016 (audit trail), ADR-017 (tailnet-only).
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

__all__ = [
    "AgentropixFinding",
    "FindingToAlertMapper",
    "WazuhAlert",
    "WazuhAlertSource",
    "confidence_to_wazuh_level",
    "finding_fingerprint",
    "mitre_to_rule_id",
]


# ---------------------------------------------------------------------------
# Confidence → Wazuh Level Mapping
# ---------------------------------------------------------------------------


def confidence_to_wazuh_level(confidence: float) -> int:
    """
    Map Agentropix confidence (0.0–1.0) to Wazuh level (1–15).

    Mapping:
      [0.95–1.00] → 14 (Critical)
      [0.85–0.94] → 12 (High)
      [0.70–0.84] → 9  (Medium)
      [0.50–0.69] → 6  (Low)
      [0.30–0.49] → 4  (Info)
      [0.00–0.29] → 2  (Debug)

    Args:
        confidence: Float between 0.0 and 1.0

    Returns:
        Wazuh level (2–14, where 14 is highest severity)
    """
    confidence = float(confidence)
    if confidence >= 0.95:
        return 14
    elif confidence >= 0.85:
        return 12
    elif confidence >= 0.70:
        return 9
    elif confidence >= 0.50:
        return 6
    elif confidence >= 0.30:
        return 4
    else:
        return 2


# ---------------------------------------------------------------------------
# MITRE Technique → Wazuh Rule ID Mapping
# ---------------------------------------------------------------------------


def mitre_to_rule_id(mitre_technique: str | None) -> int:
    """
    Map MITRE ATT&CK technique to Wazuh custom rule ID.

    Uses hash-based namespace: base 100300 + (hash(technique) % 99)

    Args:
        mitre_technique: MITRE ID like "T1078" or None

    Returns:
        Wazuh rule ID in range [100300, 100399]
    """
    if not mitre_technique:
        return 100300

    h = hashlib.md5(mitre_technique.encode()).digest()
    return 100300 + (int.from_bytes(h[:4], "big") % 99)


# ---------------------------------------------------------------------------
# Finding Fingerprint (for Deduplication)
# ---------------------------------------------------------------------------


def finding_fingerprint(finding: dict[str, Any]) -> str:
    """
    Compute SHA256 fingerprint of a finding for deduplication.

    Fingerprint is stable across re-pushes: same finding produces same hash.
    Uses only immutable fields: _source, evidence, timestamp, mitre_attack.

    Args:
        finding: Agentropix finding dict

    Returns:
        Hex SHA256 digest
    """
    fields = [
        finding.get("_source", ""),
        finding.get("evidence", ""),
        finding.get("timestamp", ""),
        finding.get("mitre_attack", ""),
    ]
    payload = "|".join(str(f) for f in fields).encode()
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


class AgentropixFinding(BaseModel):
    """Validated Agentropix finding from report.json."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    source: str = Field(..., alias="_source", description="Tool that detected this finding")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0.0–1.0")
    description: str = Field(..., description="Human-readable finding description")
    evidence: str = Field(..., description="Raw artifact data or witness statement")
    timestamp: str = Field(..., description="ISO-8601 timestamp")
    mitre_attack: str | None = Field(None, description="MITRE ATT&CK technique ID (e.g., T1078)")
    related_findings: list[str] = Field(default_factory=list, description="Linked finding tokens")

    fingerprint: str | None = Field(
        None, description="SHA256 dedup fingerprint (computed post-init)"
    )

    def model_post_init(self, __context: Any) -> None:
        if not self.fingerprint:
            self.fingerprint = finding_fingerprint(self.model_dump(by_alias=True))


def _parse_timestamp(ts: str) -> datetime:
    """
    Parse timestamp from multiple formats.

    Tries ISO-8601 first, then falls back to other common formats.

    Args:
        ts: Timestamp string

    Returns:
        Parsed datetime (UTC)

    Raises:
        ValueError: If no format matches
    """
    # Try ISO-8601 first
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        pass

    # Try common alternative formats
    from datetime import datetime as dt_class

    formats = [
        "%a %b %d %H:%M:%S %Y",  # "Thu Sep 16 03:10:21 2021"
        "%Y-%m-%d %H:%M:%S",  # "2021-09-16 03:10:21"
        "%Y/%m/%d %H:%M:%S",  # "2021/09/16 03:10:21"
    ]

    for fmt in formats:
        try:
            dt = dt_class.strptime(ts, fmt)
            # Assume UTC if not specified
            return dt.replace(tzinfo=None).astimezone(tz=None) if dt.tzinfo is None else dt
        except ValueError:
            pass

    # Last resort: use current time (logging the error)
    logger.warning(f"Could not parse timestamp {ts!r}; using current time")
    from datetime import UTC

    return datetime.now(UTC)


class WazuhAlertSource(BaseModel):
    """_source block of a Wazuh alert."""

    model_config = ConfigDict(extra="allow")

    dfir: dict[str, Any] = Field(..., description="DFIR provenance block")
    agent: dict[str, Any] = Field(..., description="Agent metadata")
    rule: dict[str, Any] = Field(..., description="Rule metadata")
    full_log: str = Field(..., description="Full finding description")
    timestamp: str = Field(..., description="ISO-8601 or alternative format timestamp")

    @property
    def timestamp_datetime(self) -> datetime:
        """Parse timestamp as UTC datetime."""
        return _parse_timestamp(self.timestamp)


class WazuhAlert(BaseModel):
    """Complete Wazuh alert for bulk ingestion."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    index: str = Field(..., alias="_index", description="Elasticsearch index name")
    source: WazuhAlertSource = Field(..., alias="_source", description="Alert source document")

    def to_bulk_line(self) -> str:
        """Format alert as single-line JSON for bulk API ingestion."""
        action = json.dumps({"index": {"_index": self.index}})
        source_dict = json.dumps(self.source.model_dump(), default=str)
        return f"{action}\n{source_dict}"


# ---------------------------------------------------------------------------
# Mapper
# ---------------------------------------------------------------------------


class FindingToAlertMapper:
    """Convert Agentropix findings to Wazuh alerts."""

    # MITRE tactic fallback mapping (if needed)
    MITRE_TACTICS = {
        "T1078": "Credential Access / Lateral Movement",
        "T1053": "Execution / Persistence",
        "T1547": "Persistence",
        "T1566": "Initial Access",
        "T1566.002": "Initial Access",
        "T1565": "Impact",
        "T1565.001": "Impact",
    }

    # Compliance tags per technique (example; expand as needed)
    COMPLIANCE_TAGS = {
        "T1078": {"pci_dss": ["10.2.5"], "hipaa": ["164.312.b"], "gdpr": ["II_5.1.f"]},
        "T1053": {"nist_800_53": ["CM.2"]},
        "T1547": {"pci_dss": ["2.2.4"], "nist_800_53": ["CM.2"]},
    }

    def __init__(
        self,
        scenario: str = "DFIR",
        system: str = "unknown",
        agent_id: str = "999",
        agent_ip: str = "0.0.0.0",
    ):
        """
        Initialize mapper with scenario context.

        Args:
            scenario: Scenario name (e.g., "SRL-2018")
            system: System identifier (e.g., "wkstn-01")
            agent_id: Wazuh agent ID (e.g., "999")
            agent_ip: Agent IP address
        """
        self.scenario = scenario
        self.system = system
        self.agent_id = agent_id
        self.agent_ip = agent_ip

    def map_finding(self, finding: dict[str, Any]) -> WazuhAlert:
        """
        Map a single Agentropix finding to a Wazuh alert.

        Args:
            finding: Agentropix finding dict from report.json

        Returns:
            WazuhAlert ready for bulk ingestion

        Raises:
            ValueError: If finding is invalid or missing required fields
        """
        f = AgentropixFinding(**finding)

        # Compute derived values
        level = confidence_to_wazuh_level(f.confidence)
        rule_id = mitre_to_rule_id(f.mitre_attack)
        tactic = self.MITRE_TACTICS.get(f.mitre_attack, "Unknown")
        compliance = self.COMPLIANCE_TAGS.get(f.mitre_attack, {})

        # Build rule metadata
        rule = {
            "id": rule_id,
            "level": level,
            "description": f"DFIR Finding: {f.description[:200]}",
            "groups": [
                "dfir",
                "agentropix",
                f.mitre_attack.lower().replace(".", "_") if f.mitre_attack else "uncategorized",
                f.source.lower().replace(".", "_"),
            ],
            "mitre": {
                "tactic": tactic,
                "technique": [f.mitre_attack] if f.mitre_attack else [],
                "id": [f.mitre_attack] if f.mitre_attack else [],
            },
        }

        # Add compliance tags if available
        if "pci_dss" in compliance:
            rule["pci_dss"] = compliance["pci_dss"]
        if "hipaa" in compliance:
            rule["hipaa"] = compliance["hipaa"]
        if "gdpr" in compliance:
            rule["gdpr"] = compliance["gdpr"]
        if "nist_800_53" in compliance:
            rule["nist_800_53"] = compliance["nist_800_53"]

        # Build DFIR provenance block
        dfir = {
            "scenario": self.scenario,
            "system": self.system,
            "source_tool": f.source,
            "confidence": f.confidence,
            "evidence_snippet": f.evidence[:500],  # Truncate for size
            "related_findings": f.related_findings,
            "fingerprint": f.fingerprint,
        }

        # Build alert source
        alert_source = WazuhAlertSource(
            dfir=dfir,
            agent={
                "name": self.system,
                "id": self.agent_id,
                "ip": self.agent_ip,
            },
            rule=rule,
            full_log=f.description,
            timestamp=f.timestamp,
        )

        # Build alert with index name based on timestamp
        index_date = alert_source.timestamp_datetime.strftime("%Y.%m.%d")
        index_name = f"wazuh-alerts-4.x-dfir-{index_date}"

        return WazuhAlert(_index=index_name, _source=alert_source)

    def map_findings(self, findings: list[dict[str, Any]]) -> list[WazuhAlert]:
        """
        Map multiple findings to alerts.

        Args:
            findings: List of Agentropix findings

        Returns:
            List of WazuhAlerts

        Raises:
            ValueError: If any finding is invalid (partial mapping halts)
        """
        alerts = []
        for i, finding in enumerate(findings):
            try:
                alert = self.map_finding(finding)
                alerts.append(alert)
            except Exception as e:
                logger.error(f"Failed to map finding {i}: {e}")
                raise ValueError(f"Finding {i} mapping failed: {e}") from e

        return alerts
