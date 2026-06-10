"""ADR-024 Phase 5 — export orchestration for the multi-tier report engine.

Pure, MCP-agnostic glue: given the canonical ``sections`` dict (from
``mcp_report_generate``), project it into the three tier view models and render
the requested tier to the requested format (Markdown / HTML / PDF). This module
adds no new evidence and performs no network or install side effects; the PDF
path is gated by :func:`detect_pdf_capability` and raises ``ToolchainUnavailable``
(never installs) when no engine is present.
"""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel

from agentropix_mcp.reports.markdown import (
    render_analyst_markdown,
    render_business_markdown,
    render_executive_markdown,
)
from agentropix_mcp.reports.render import (
    PdfCapability,
    detect_pdf_capability,
    render_html,
    render_pdf,
)
from agentropix_mcp.reports.transformers import build_tier_bundle
from agentropix_mcp.reports.view_models import TierBundle

__all__ = [
    "FORMATS",
    "MIME",
    "TIERS",
    "ExportResult",
    "export_report",
    "tier_markdown",
]

# Canonical tier names and renderable formats (ADR-024 tier model).
TIERS: frozenset[str] = frozenset({"analyst", "executive", "business"})
FORMATS: frozenset[str] = frozenset({"md", "markdown", "html", "pdf"})

MIME: dict[str, str] = {
    "md": "text/markdown",
    "markdown": "text/markdown",
    "html": "text/html",
    "pdf": "application/pdf",
}


class ExportResult(BaseModel):
    """Outcome of a single tier+format export."""

    tier: str
    fmt: str
    mime: str
    # Inline content for text formats (md/html); None for binary (pdf).
    content: str | None = None
    # On-disk path when the artifact was written (always for pdf).
    path: str | None = None
    bytes: int = 0
    # PDF capability probe outcome (only populated for the pdf format).
    pdf_capability: dict[str, Any] | None = None


def tier_markdown(bundle: TierBundle, tier: str) -> str:
    """Render the Markdown(+Mermaid) source-of-truth for one tier."""
    if tier == "analyst":
        return render_analyst_markdown(bundle.analyst)
    if tier == "executive":
        return render_executive_markdown(bundle.executive)
    if tier == "business":
        return render_business_markdown(bundle.business)
    raise ValueError(f"unknown tier {tier!r}; expected one of {sorted(TIERS)}")


def export_report(
    sections: dict[str, Any],
    *,
    tier: str,
    fmt: str,
    output_path: str | None = None,
    meta: dict[str, Any] | None = None,
    prefer: str = "chromium",
) -> ExportResult:
    """Project ``sections`` into the requested tier and render to ``fmt``.

    ``build_tier_bundle`` enforces the no-drift invariant before rendering, so a
    drifted finding set raises ``NoDriftError`` here rather than shipping.

    - ``md``/``markdown`` -> Markdown(+Mermaid) source of truth (inline content).
    - ``html`` -> self-contained HTML (pure-pip; offline).
    - ``pdf`` -> written to ``output_path`` via the capability-gated engine;
      ``output_path`` is required and ``ToolchainUnavailable`` is raised (never
      installs) when no engine is present.

    For text formats, the artifact is also written to ``output_path`` when one
    is supplied. Returns an :class:`ExportResult`.
    """
    tier = tier.strip().lower()
    fmt = fmt.strip().lower()
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier!r}; expected one of {sorted(TIERS)}")
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r}; expected one of {sorted(FORMATS)}")

    bundle = build_tier_bundle(sections, meta=meta)
    md = tier_markdown(bundle, tier)
    title = f"SIFT Report — {tier.title()}"
    if meta and meta.get("case_id"):
        title = f"{title} ({meta['case_id']})"

    if fmt in {"md", "markdown"}:
        if output_path:
            _write_text(output_path, md)
        return ExportResult(
            tier=tier,
            fmt="md",
            mime=MIME["md"],
            content=md,
            path=output_path,
            bytes=len(md.encode("utf-8")),
        )

    if fmt == "html":
        html = render_html(md, title=title)
        if output_path:
            _write_text(output_path, html)
        return ExportResult(
            tier=tier,
            fmt="html",
            mime=MIME["html"],
            content=html,
            path=output_path,
            bytes=len(html.encode("utf-8")),
        )

    # pdf
    if not output_path:
        raise ValueError("pdf export requires output_path (binary artifact)")
    cap: PdfCapability = detect_pdf_capability(prefer=prefer)
    # render_pdf raises ToolchainUnavailable (with install_hint) if not available.
    render_pdf(md, output_path, title=title, capability=cap)
    size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
    return ExportResult(
        tier=tier,
        fmt="pdf",
        mime=MIME["pdf"],
        content=None,
        path=output_path,
        bytes=size,
        pdf_capability={
            "available": cap.available,
            "engine": cap.engine,
            "chromium_path": cap.chromium_path,
            "weasyprint_importable": cap.weasyprint_importable,
        },
    )


def _write_text(path: str, text: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
