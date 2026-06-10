"""ADR-024 — Mermaid diagram builders (kill-chain, process tree, IOC graph).

Pure string builders: each returns a fenced ```mermaid block ready to embed
in the Markdown source of truth. They are width-constrained and text-safe so
the downstream mmdc SVG prerender (render.py) is deterministic and the
WeasyPrint TD-graph text-drop bug is sidestepped (ADR-024 §3).

No network, no I/O — just structured data -> Mermaid syntax.
"""

from __future__ import annotations

from agentropix_mcp.reports.view_models import AnalystView, IOCRow, TimelineRow

__all__ = [
    "ioc_graph",
    "kill_chain_timeline",
    "mermaid_block",
    "process_tree_diagram",
    "sanitize_label",
]


def mermaid_block(body: str) -> str:
    """Wrap a Mermaid diagram body in a fenced ```mermaid block."""
    return f"```mermaid\n{body.rstrip()}\n```"


def sanitize_label(text: str) -> str:
    """Make a string safe for a Mermaid node/edge label.

    Strips characters that break Mermaid parsing (quotes, brackets, pipes,
    newlines) and caps length so a long body cannot blow up the diagram.
    """
    cleaned = (
        str(text)
        .replace('"', "'")
        .replace("[", "(")
        .replace("]", ")")
        .replace("{", "(")
        .replace("}", ")")
        .replace("|", "/")
        .replace("\n", " ")
        .replace("\r", " ")
        .replace(";", ",")
        .strip()
    )
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > 60:
        cleaned = cleaned[:57] + "..."
    return cleaned or "?"


def kill_chain_timeline(timeline: list[TimelineRow]) -> str:
    """Build a Mermaid timeline of kill-chain phases from timeline rows.

    Groups events under their kill_chain_phase (falling back to "Activity").
    Uses Mermaid ``timeline`` syntax (vertical, PDF-friendly width).
    """
    lines = ["timeline", "    title Kill-Chain Timeline"]
    if not timeline:
        lines.append("    section No timeline data")
        lines.append("        n/a : no approved timeline events")
        return mermaid_block("\n".join(lines))

    current_phase: str | None = None
    for row in timeline:
        phase = sanitize_label(row.kill_chain_phase or "Activity")
        if phase != current_phase:
            lines.append(f"    section {phase}")
            current_phase = phase
        ts = sanitize_label(row.timestamp or "?")
        desc = sanitize_label(row.description or row.event_id or row.host or "event")
        lines.append(f"        {ts} : {desc}")
    return mermaid_block("\n".join(lines))


def process_tree_diagram(process_tree: object) -> str:
    """Build a Mermaid flowchart of a process tree.

    Accepts a ``ProcessTreeReport``-shaped object (correlation.py) — anything
    exposing ``.roots`` and ``.orphans`` lists of ``ProcessNode``-shaped nodes
    (``.pid``, ``.name``, ``.children``). Degrades to an empty-state diagram
    if the shape is absent.
    """
    roots = list(getattr(process_tree, "roots", []) or [])
    orphans = list(getattr(process_tree, "orphans", []) or [])
    lines = ["flowchart TD"]
    edges: list[str] = []

    def _walk(node: object) -> None:
        pid = getattr(node, "pid", "?")
        name = sanitize_label(getattr(node, "name", "?"))
        suspicious = bool(getattr(node, "suspicious", False))
        marker = " [!]" if suspicious else ""
        lines.append(f'    p{pid}["{name} (pid {pid}){marker}"]')
        for child in getattr(node, "children", []) or []:
            cpid = getattr(child, "pid", "?")
            edges.append(f"    p{pid} --> p{cpid}")
            _walk(child)

    if not roots and not orphans:
        lines.append('    none["no process data"]')
        return mermaid_block("\n".join(lines))

    for r in roots:
        _walk(r)
    for o in orphans:
        _walk(o)
    lines.extend(edges)
    return mermaid_block("\n".join(lines))


def ioc_graph(iocs: list[IOCRow]) -> str:
    """Build a Mermaid graph linking the case to its IOCs by type.

    case node -> ioc-type node -> ioc-value node. Keeps the fan-out grouped
    so a wide IOC set stays readable in PDF.
    """
    lines = ["flowchart LR", '    case(("Case"))']
    if not iocs:
        lines.append('    none["no IOCs"]')
        lines.append("    case --> none")
        return mermaid_block("\n".join(lines))

    type_ids: dict[str, str] = {}
    for i, row in enumerate(iocs):
        ioc_type = sanitize_label(row.ioc_type or "unknown")
        if ioc_type not in type_ids:
            tid = f"t{len(type_ids)}"
            type_ids[ioc_type] = tid
            lines.append(f'    {tid}["{ioc_type}"]')
            lines.append(f"    case --> {tid}")
        vid = f"v{i}"
        val = sanitize_label(row.value or "?")
        lines.append(f'    {vid}["{val}"]')
        lines.append(f"    {type_ids[ioc_type]} --> {vid}")
    return mermaid_block("\n".join(lines))


def analyst_diagrams(analyst: AnalystView) -> dict[str, str]:
    """Convenience: the two analyst-tier diagrams driven by view-model data.

    (Process-tree diagram needs a ProcessTreeReport, which is not part of the
    view model, so it is built separately by callers that have one.)
    """
    return {
        "kill_chain": kill_chain_timeline(analyst.timeline),
        "ioc_graph": ioc_graph(analyst.iocs),
    }
