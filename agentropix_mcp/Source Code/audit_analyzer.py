"""Thymus audit log analyzer — summarize JSONL audit logs.

Reads JSONL files written by Thymus policy and produces
actionable summaries for security review and incident response.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path

logger = logging.getLogger(__name__)


def analyze_audit_log(path: str | Path) -> dict:
    """Analyze a Thymus JSONL audit log file.

    Args:
        path: Path to the JSONL audit log file.

    Returns:
        Dict with summary statistics and notable entries.

    Raises:
        FileNotFoundError: If the log file doesn't exist.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Audit log not found: {path}")

    entries: list[dict] = []
    malformed = 0
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                malformed += 1

    action_counts = Counter(e.get("action", "UNKNOWN") for e in entries)
    rejected = [e for e in entries if "REJECT" in e.get("action", "")]
    auto_allowed = [e for e in entries if e.get("action") == "AUTO_ALLOW"]
    symlinks = [e for e in entries if e.get("action") == "SYMLINK"]

    # Unique paths accessed
    unique_paths = set(e.get("path", "") for e in entries)

    # Unique rejected paths (potential attack indicators)
    rejected_paths = set(e.get("path", "") for e in rejected)

    return {
        "total_entries": len(entries),
        "malformed_lines": malformed,
        "action_counts": dict(action_counts),
        "unique_paths": len(unique_paths),
        "rejected_count": len(rejected),
        "rejected_paths": sorted(rejected_paths),
        "auto_allowed_count": len(auto_allowed),
        "symlink_count": len(symlinks),
        "first_timestamp": entries[0].get("timestamp", "") if entries else "",
        "last_timestamp": entries[-1].get("timestamp", "") if entries else "",
    }


def format_report(analysis: dict) -> str:
    """Format an analysis dict as a human-readable report."""
    lines = [
        "=== Thymus Audit Log Report ===",
        f"Period: {analysis['first_timestamp']} to {analysis['last_timestamp']}",
        f"Total events: {analysis['total_entries']}",
        f"Unique paths: {analysis['unique_paths']}",
        "",
        "Action breakdown:",
    ]
    for action, count in sorted(analysis["action_counts"].items()):
        lines.append(f"  {action}: {count}")

    if analysis["rejected_count"]:
        lines.append("")
        lines.append(f"Rejected paths ({analysis['rejected_count']}):")
        for p in analysis["rejected_paths"][:20]:
            lines.append(f"  - {p}")
        if len(analysis["rejected_paths"]) > 20:
            lines.append(f"  ... and {len(analysis['rejected_paths']) - 20} more")

    if analysis["auto_allowed_count"]:
        lines.append(f"\nAuto-detected evidence dirs: {analysis['auto_allowed_count']}")

    if analysis["symlink_count"]:
        lines.append(f"Symlinks resolved: {analysis['symlink_count']}")

    if analysis["malformed_lines"]:
        lines.append(f"\nWARNING: {analysis['malformed_lines']} malformed log lines")

    return "\n".join(lines)
