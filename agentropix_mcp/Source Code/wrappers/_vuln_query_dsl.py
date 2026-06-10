"""W-186: DSL builder for ``wazuh_vuln_query``.

Produces OpenSearch DSL bodies for Indexer searches against
``wazuh-states-vulnerabilities-*``. Closes the F1.2 fleet-wide-CVE
visibility gap without enabling Wazuh's Vulnerability Detector wodle
- the indexer already has 73 CVE docs populated by the agent vuln
scan path.

Supported filters (all optional; combine via AND):
  - cve_id           -> term on vulnerability.id.keyword
  - agent_id         -> term on agent.id.keyword
  - severity         -> term on vulnerability.severity (case-insensitive
                        match; Wazuh capitalises: Critical/High/Medium/Low)
  - package_name     -> term on package.name.keyword
  - time_range_hours -> range clause on vulnerability.detected_at

Field-path note: the wazuh-states-vulnerabilities-* schema uses
``.keyword`` subfields for exact-match on ID-shaped values. Free-text
match on package names would tokenise on hyphens; we use ``.keyword``
to keep ``openssl-libs`` exact. ``vulnerability.severity`` is a
keyword field at the top level (no .keyword suffix needed in 4.x).
"""

from __future__ import annotations

import time
from typing import Any

__all__ = [
    "build_vuln_query",
    "supported_severities",
    "DEFAULT_TIME_RANGE_HOURS",
    "MAX_SIZE",
]


# Default lookback: 30 days. Vulnerability scans run daily in most
# Wazuh deployments, so 30d gives a reasonable rolling window without
# pulling stale entries that have since been patched.
DEFAULT_TIME_RANGE_HOURS = 24 * 30

# Capacity envelope matches WZ-001: 500 max per call.
MAX_SIZE = 500


def supported_severities() -> tuple[str, ...]:
    """Stable list of accepted ``severity`` filter values.

    Matches the Wazuh 4.x severity vocabulary. Comparison is
    case-insensitive at the wrapper layer; the canonical form is
    capitalised here for the DSL.
    """
    return ("Critical", "High", "Medium", "Low", "Untriaged")


def _now_minus_hours_ms(hours: int) -> int:
    """Epoch-millisecond timestamp for now - <hours>."""
    return int((time.time() - hours * 3600) * 1000)


def _time_range_clause(time_range_hours: int) -> dict:
    """Build the range clause for ``vulnerability.detected_at``.

    Wazuh stores detected_at as ISO-8601; ``format: epoch_millis``
    keeps the date parser predictable.
    """
    return {
        "range": {
            "vulnerability.detected_at": {
                "gte": _now_minus_hours_ms(time_range_hours),
                "format": "epoch_millis",
            }
        }
    }


def _normalize_severity(value: str) -> str | None:
    """Normalize a user-supplied severity string to Wazuh canonical case.

    Returns None if unrecognised - the wrapper layer surfaces the
    full list and rejects unknown values rather than silently swallowing.
    """
    cleaned = value.strip().lower()
    for canon in supported_severities():
        if canon.lower() == cleaned:
            return canon
    return None


def build_vuln_query(
    *,
    cve_id: str | None = None,
    agent_id: str | None = None,
    severity: str | None = None,
    package_name: str | None = None,
    time_range_hours: int = DEFAULT_TIME_RANGE_HOURS,
    size: int = 100,
) -> dict[str, Any]:
    """Build the full OpenSearch DSL body for a vuln-query search.

    All filters are optional. With no filters and a 30-day window the
    query returns the freshest 100 vulnerabilities across the fleet.

    Args:
        cve_id: exact CVE ID (e.g. "CVE-2024-1234"). Treated as opaque;
            sanitisation is the wrapper's responsibility.
        agent_id: filter to a single agent's vulns.
        severity: one of supported_severities() (case-insensitive).
            ValueError raised for unrecognised values so the wrapper
            catches at the boundary.
        package_name: filter to vulns affecting a named package.
        time_range_hours: lookback window for detected_at.
        size: max hits to return (1..MAX_SIZE).

    Returns:
        full search body suitable for IndexerClient.search().

    Raises:
        ValueError: if severity is non-empty but not in the canonical
            list.
    """
    if size > MAX_SIZE:
        size = MAX_SIZE
    if size < 1:
        size = 1
    if time_range_hours < 1:
        time_range_hours = 1

    must: list[dict] = [_time_range_clause(time_range_hours)]

    if cve_id:
        must.append({"term": {"vulnerability.id.keyword": cve_id}})
    if agent_id:
        must.append({"term": {"agent.id.keyword": agent_id}})
    if severity:
        canon = _normalize_severity(severity)
        if canon is None:
            raise ValueError(
                f"Unknown severity {severity!r}; supported: "
                f"{supported_severities()}"
            )
        must.append({"term": {"vulnerability.severity": canon}})
    if package_name:
        must.append({"term": {"package.name.keyword": package_name}})

    return {
        "query": {"bool": {"must": must}},
        "sort": [{"vulnerability.detected_at": {"order": "desc"}}],
        "size": size,
        # _source filtering — only fetch fields needed to populate
        # ObservationCVE. Caps prompt-injection surface (master-report
        # WLV-15) and keeps response payload small.
        "_source": [
            "vulnerability.detected_at",
            "vulnerability.id",
            "vulnerability.severity",
            "vulnerability.score.base",
            "package.name",
            "package.version",
            "package.condition",
            "agent.id",
            "agent.name",
        ],
    }
