"""ADR-024 — multi-tier report engine (presentation layer over case findings).

One canonical finding set (``mcp_report_generate`` sections) is projected into
three coordinated, no-drift tier view models (analyst / executive / business),
rendered to Markdown(+Mermaid) as the source of truth, then derived to HTML
(pure-pip) and PDF (behind a capability check).

See ADR-024 for the full design. This package is presentation-only — it adds
no new evidence and does not modify core models or MCP analysis tools.
"""

from __future__ import annotations

from agentropix_mcp.reports.export import (
    ExportResult,
    export_report,
    tier_markdown,
)
from agentropix_mcp.reports.transformers import (
    build_analyst_view,
    build_business_view,
    build_executive_view,
    build_tier_bundle,
)
from agentropix_mcp.reports.view_models import (
    AnalystView,
    BusinessView,
    ExecutiveView,
    Finding,
    TierBundle,
)

__all__ = [
    "AnalystView",
    "BusinessView",
    "ExecutiveView",
    "ExportResult",
    "Finding",
    "TierBundle",
    "build_analyst_view",
    "build_business_view",
    "build_executive_view",
    "build_tier_bundle",
    "export_report",
    "tier_markdown",
]
