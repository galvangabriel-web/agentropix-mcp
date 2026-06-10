"""WZ-021 (master-report §4.4 #16a, C4-SOFTENG F1): Observation parent
+ discriminated-union submodels for read-back tool results.

The legacy ``Finding`` class in ``agentropix_mcp/agents/_base.py`` is
the schema-compliant DFIR analyst-finding shape (source, confidence,
description, evidence, MITRE ID, etc.) intended for the report.json
output that SANS rubric consumes. It carries evidence-of-attack
semantics.

Per master-report C4 F1 the design correction is option (b):

  "Or (b) introduce an Observation/Telemetry parent model for read-back
   tools and reserve Finding for evidence-of-attack semantics."

This module ships that parent. New MCP read-back tools (the WZ wave —
WZ-001 hunt_ioc Step-2, WZ-006 vuln_query, WZ-009 fim_query, etc.)
return ``Observation`` subclass instances (or dicts that match an
Observation submodel's shape). The ``kind`` field is a Pydantic
``Literal`` discriminator, so consumers exhaustively switching on
``kind`` get type-safe dispatch.

Today this file ships the parent + the 9 ``kind`` literals listed in
master-report C4 F1. Per-WZ-NNN PRs that introduce new tools will land
the corresponding ``Observation*`` submodel + their fields. WZ-021
defines the contract; the per-tool submodels follow.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "OBSERVATION_KIND_LITERALS",
    "Observation",
    "ObservationAgent",
    "ObservationAlert",
    "ObservationCVE",
    "ObservationCdbMembership",
    "ObservationDlqEntry",
    "ObservationFimEvent",
    "ObservationInstalledPackage",
    "ObservationLiveProcess",
    "ObservationScaFailedCheck",
]


# Stable list of the 9 kinds from master-report C4 F1. New observations
# extend this list + add a corresponding submodel below.
OBSERVATION_KIND_LITERALS = (
    "alert",
    "cve",
    "fim_event",
    "sca_failed_check",
    "live_process",
    "installed_package",
    "agent",
    "dlq_entry",
    "cdb_membership",
)


class _ObservationBase(BaseModel):
    """Common fields for all Observation kinds.

    Distinct from ``Finding`` (which is analyst-authored evidence-of-
    attack content). Observations are TOOL OUTPUT — the raw record an
    MCP tool returns from a read-back call against Wazuh.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # Discriminator. Each subclass overrides with a Literal[<kind>].
    # Declared on the parent so static type checkers + code search
    # can always find the field.
    kind: str

    # Wazuh agent the observation was sourced from. None for Manager-
    # level observations (e.g. dlq_entry, cdb_membership).
    agent_id: str | None = None

    # Wazuh-side timestamp of the source event. ISO-8601 UTC string.
    # Optional — some observations (cdb_membership) are timeless.
    ts_utc: str | None = None

    # Free-text label for cross-modal correlation with offline Findings
    # (e.g. "vol3-malfind-rwx", "wazuh-rule-100200"). Empty when not
    # cross-correlated.
    correlation_label: str = ""


class ObservationAlert(_ObservationBase):
    """A single alert from ``wazuh-alerts-*`` index (WZ-001 output)."""

    kind: Literal["alert"] = "alert"
    rule_id: int = Field(ge=1, le=999999)
    rule_level: int = Field(ge=0, le=15)
    rule_description: str = ""
    rule_groups: tuple[str, ...] = ()
    mitre_ids: tuple[str, ...] = ()
    srcip: str | None = None
    dstip: str | None = None
    full_log: str = ""


class ObservationCVE(_ObservationBase):
    """A CVE record from ``wazuh-states-vulnerabilities-*`` (WZ-006)."""

    kind: Literal["cve"] = "cve"
    cve_id: Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,7}$")]
    severity: Literal["critical", "high", "medium", "low", "unknown"]
    package_name: str = ""
    package_version: str = ""
    fix_version: str | None = None
    cvss_v3_score: float | None = Field(default=None, ge=0.0, le=10.0)


class ObservationFimEvent(_ObservationBase):
    """A FIM (file integrity monitoring) event (WZ-009)."""

    kind: Literal["fim_event"] = "fim_event"
    path: str
    event_type: Literal["added", "modified", "deleted"]
    sha256_after: str | None = None
    md5_after: str | None = None
    size_bytes: int | None = Field(default=None, ge=0)


class ObservationScaFailedCheck(_ObservationBase):
    """An SCA (security configuration assessment) failed check (WZ-013)."""

    kind: Literal["sca_failed_check"] = "sca_failed_check"
    policy_id: str
    check_id: str
    title: str = ""
    severity: Literal["critical", "high", "medium", "low", "info"] = "info"


class ObservationLiveProcess(_ObservationBase):
    """A process row from ``/syscollector/{id}/processes`` (WZ-012)."""

    kind: Literal["live_process"] = "live_process"
    pid: int = Field(ge=0)
    name: str
    cmd: str = ""
    parent_pid: int | None = Field(default=None, ge=0)
    user: str = ""


class ObservationInstalledPackage(_ObservationBase):
    """A package from ``/syscollector/{id}/packages`` (WZ-011)."""

    kind: Literal["installed_package"] = "installed_package"
    package_name: str
    package_version: str
    architecture: str = ""
    vendor: str = ""


class ObservationAgent(_ObservationBase):
    """An agent record from ``/agents`` (WZ-008)."""

    kind: Literal["agent"] = "agent"
    name: str
    status: Literal["active", "disconnected", "pending", "never_connected"]
    ip: str | None = None
    os_platform: str = ""
    os_version: str = ""


class ObservationDlqEntry(_ObservationBase):
    """A DLQ row from ``wazuh_dlq_list`` (WZ-004)."""

    kind: Literal["dlq_entry"] = "dlq_entry"
    entry_id: str  # UUID at enqueue time per master-report §6.4 R4
    op: str  # e.g. "put.list", "put.rules", "manager.restart"
    enqueued_at_utc: str
    attempts: int = Field(ge=0)
    last_error_class: str = ""


class ObservationCdbMembership(_ObservationBase):
    """A CDB-list membership check result from ``wazuh_check_feed`` (WZ-010)."""

    kind: Literal["cdb_membership"] = "cdb_membership"
    list_name: str
    ioc_value: str
    is_member: bool
    list_size_at_check: int = Field(ge=0)


# Discriminated union — the canonical type for read-back tool returns.
# Consumers can:
#
#   def handle(obs: Observation):
#       match obs.kind:
#           case "alert":
#               ...   # type checker narrows obs to ObservationAlert
#           case "cve":
#               ...
#
# Pydantic dispatches construction by the ``kind`` field, so
# ``Observation.model_validate({"kind": "alert", ...})`` returns the
# right submodel.
Observation = Annotated[
    ObservationAlert | ObservationCVE | ObservationFimEvent | ObservationScaFailedCheck | ObservationLiveProcess | ObservationInstalledPackage | ObservationAgent | ObservationDlqEntry | ObservationCdbMembership,
    Field(discriminator="kind"),
]


def now_utc_iso() -> str:
    """Helper: ISO-8601 UTC now() — used as default for ts_utc fields."""
    return datetime.now(UTC).isoformat()
