"""WZ-022 / W-278: Wazuh Dashboard (OpenSearch Dashboards) saved-objects
bundles for Agentropix-owned indices.

The bundles ship as NDJSON files (Wazuh Dashboard ``Stack Management ->
Saved Objects -> Import`` consumes them as-is). The Python helpers here
expose the bundle paths and parsed contents so tests can lock the shape
and operators can programmatically introspect the bundle without
re-implementing NDJSON parsing.
"""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

__all__ = [
    "FINDINGS_DASHBOARD_BUNDLE_NAME",
    "findings_dashboard_bundle_path",
    "load_findings_dashboard_bundle",
]


FINDINGS_DASHBOARD_BUNDLE_NAME: str = "agentropix-findings.ndjson"
"""Filename of the findings dashboard saved-objects bundle."""


def findings_dashboard_bundle_path() -> str:
    """Return the on-disk absolute path of the findings bundle.

    Useful for operators piping the file straight into ``curl`` for an
    API-driven install (``POST /api/saved_objects/_import``) or for
    referencing it from a shell snippet without re-parsing.
    """
    with resources.as_file(
        resources.files(__package__).joinpath(FINDINGS_DASHBOARD_BUNDLE_NAME)
    ) as path:
        return str(path)


def load_findings_dashboard_bundle() -> list[dict[str, Any]]:
    """Parse the bundle NDJSON into a list of saved-object dicts.

    Each line of the bundle is one saved object; blank lines are
    skipped. Use this in tests to assert the bundle shape and in
    operator tooling that needs to inspect (e.g.) the index-pattern
    title without round-tripping through Wazuh Dashboard.
    """
    text = (
        resources.files(__package__)
        .joinpath(FINDINGS_DASHBOARD_BUNDLE_NAME)
        .read_text(encoding="utf-8")
    )
    objects: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        objects.append(json.loads(line))
    return objects
