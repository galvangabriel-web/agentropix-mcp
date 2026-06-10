"""SIFT-W-295: programmatic builders for the agentropix dashboard bundle.

Replaces the hand-authored ``.ndjson`` with deterministic generators so:

  * The 17-saved-object bundle (5 W-278 originals + 12 new W-295 ones)
    stays consistent — a single edit doesn't drift one viz out of sync
    with the rest.
  * Tests pin field-by-field via the builders rather than JSON-line
    matching.
  * Future expansions add a builder + a registry entry; the .ndjson is
    regenerated from a single call.

The bundle targets **Wazuh Dashboard 2.19.5** (OSD 2.19 fork), which
is live-verified at ``https://WAZUH-HOST`` per the
``logs/2026-05-27-valhuntir-wazuh-research/SYNTHESIS.md`` poll.
Saved-object shape uses the 7.10.2 schema the W-278 bundle established
— OSD 2.19 imports 7.10.2 bundles via the saved-objects compat layer.
"""

from __future__ import annotations

import json

# Pin once — bundle and dashboard reference each other by this id.
FINDINGS_INDEX_PATTERN_ID = "agentropix-findings-pattern"
TIMELINE_INDEX_PATTERN_ID = "agentropix-timeline-pattern"

DEFAULT_SIDECAR_URL = "http://127.0.0.1:8800"

VERSION_TOKEN = "WzEsMV0="  # base64("[1,1]") — version 1, seq_no 1
PANEL_VERSION = "7.10.2"


# ----- low-level helpers --------------------------------------------- #


def _ref_index_pattern(pattern_id: str = FINDINGS_INDEX_PATTERN_ID) -> dict:
    return {
        "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
        "type": "index-pattern",
        "id": pattern_id,
    }


def _empty_search_source(pattern_id: str = FINDINGS_INDEX_PATTERN_ID) -> str:
    return json.dumps(
        {
            "query": {"query": "", "language": "kuery"},
            "filter": [],
            "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
        }
    )


def _filter_search_source(
    field: str,
    value: str,
    pattern_id: str = FINDINGS_INDEX_PATTERN_ID,
) -> str:
    """Search source that pins a single term filter (e.g. approval.status=DRAFT)."""
    return json.dumps(
        {
            "query": {"query": "", "language": "kuery"},
            "filter": [
                {
                    "meta": {
                        "alias": None,
                        "negate": False,
                        "disabled": False,
                        "type": "phrase",
                        "key": field,
                        "value": value,
                        "params": {"query": value},
                        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    },
                    "query": {
                        "match_phrase": {field: value},
                    },
                }
            ],
            "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
        }
    )


# ----- builders ------------------------------------------------------ #


def build_findings_index_pattern(
    sidecar_url: str = DEFAULT_SIDECAR_URL,
) -> dict:
    """W-278 + W-295: index-pattern for ``agentropix-findings-*``.

    SIFT-W-295 addition: ``fieldFormatMap`` turns ``finding_id`` into a
    clickable URL pointing at the approval sidecar's ``/`` page,
    pre-filled via the ``target_id`` query string. This is the
    deep-link the Findings-tab dashboard uses.
    """
    fmt_map = json.dumps(
        {
            "finding_id": {
                "id": "url",
                "params": {
                    "urlTemplate": (f"{sidecar_url.rstrip('/')}/?target_id={{{{value}}}}"),
                    "labelTemplate": "{{value}}",
                    "openLinkInCurrentTab": False,
                },
            },
        }
    )
    return {
        "attributes": {
            "title": "agentropix-findings-*",
            "timeFieldName": "@timestamp",
            "fields": "[]",
            "fieldFormatMap": fmt_map,
        },
        "id": FINDINGS_INDEX_PATTERN_ID,
        "references": [],
        "type": "index-pattern",
        "version": VERSION_TOKEN,
    }


def build_timeline_index_pattern() -> dict:
    """W-295: index-pattern for ``agentropix-timeline-*``."""
    return {
        "attributes": {
            "title": "agentropix-timeline-*",
            "timeFieldName": "@timestamp",
            "fields": "[]",
        },
        "id": TIMELINE_INDEX_PATTERN_ID,
        "references": [],
        "type": "index-pattern",
        "version": VERSION_TOKEN,
    }


def build_severity_pie() -> dict:
    """W-278: count grouped by ``severity`` (donut)."""
    vis_state = {
        "title": "Agentropix findings by severity",
        "type": "pie",
        "params": {
            "type": "pie",
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "isDonut": True,
            "labels": {
                "show": True,
                "values": True,
                "last_level": True,
                "truncate": 100,
            },
        },
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": "count",
                "schema": "metric",
                "params": {},
            },
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "schema": "segment",
                "params": {
                    "field": "severity",
                    "size": 10,
                    "order": "desc",
                    "orderBy": "1",
                    "missingBucket": False,
                    "otherBucket": False,
                },
            },
        ],
    }
    return {
        "attributes": {
            "title": "Agentropix findings by severity",
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "WZ-022 / W-278: count of Agentropix findings grouped by severity keyword.",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": _empty_search_source()},
        },
        "id": "agentropix-findings-severity-pie",
        "references": [_ref_index_pattern()],
        "type": "visualization",
        "version": VERSION_TOKEN,
    }


def build_mitre_bar() -> dict:
    """W-278: count grouped by ``mitre_techniques``."""
    vis_state = {
        "title": "Agentropix findings by MITRE technique",
        "type": "histogram",
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False},
            "categoryAxes": [
                {
                    "id": "CategoryAxis-1",
                    "type": "category",
                    "position": "bottom",
                    "show": True,
                    "scale": {"type": "linear"},
                    "labels": {"show": True, "truncate": 100},
                    "title": {},
                }
            ],
            "valueAxes": [
                {
                    "id": "ValueAxis-1",
                    "name": "LeftAxis-1",
                    "type": "value",
                    "position": "left",
                    "show": True,
                    "scale": {"type": "linear", "mode": "normal"},
                    "labels": {
                        "show": True,
                        "rotate": 0,
                        "filter": False,
                        "truncate": 100,
                    },
                    "title": {"text": "Count"},
                }
            ],
            "seriesParams": [
                {
                    "show": True,
                    "type": "histogram",
                    "mode": "stacked",
                    "data": {"label": "Count", "id": "1"},
                    "valueAxis": "ValueAxis-1",
                    "drawLinesBetweenPoints": True,
                    "showCircles": True,
                }
            ],
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False,
        },
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": "count",
                "schema": "metric",
                "params": {},
            },
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "schema": "segment",
                "params": {
                    "field": "mitre_techniques",
                    "size": 20,
                    "order": "desc",
                    "orderBy": "1",
                    "missingBucket": False,
                    "otherBucket": False,
                },
            },
        ],
    }
    return {
        "attributes": {
            "title": "Agentropix findings by MITRE technique",
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "WZ-022 / W-278: count of Agentropix findings grouped by MITRE ATT&CK technique ID.",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": _empty_search_source()},
        },
        "id": "agentropix-findings-mitre-bar",
        "references": [_ref_index_pattern()],
        "type": "visualization",
        "version": VERSION_TOKEN,
    }


def build_timeline_line() -> dict:
    """W-278: findings count over time (line)."""
    vis_state = {
        "title": "Agentropix findings timeline",
        "type": "line",
        "params": {
            "type": "line",
            "grid": {"categoryLines": False},
            "categoryAxes": [
                {
                    "id": "CategoryAxis-1",
                    "type": "category",
                    "position": "bottom",
                    "show": True,
                    "scale": {"type": "linear"},
                    "labels": {"show": True, "truncate": 100},
                    "title": {},
                }
            ],
            "valueAxes": [
                {
                    "id": "ValueAxis-1",
                    "name": "LeftAxis-1",
                    "type": "value",
                    "position": "left",
                    "show": True,
                    "scale": {"type": "linear", "mode": "normal"},
                    "labels": {
                        "show": True,
                        "rotate": 0,
                        "filter": False,
                        "truncate": 100,
                    },
                    "title": {"text": "Count"},
                }
            ],
            "seriesParams": [
                {
                    "show": True,
                    "type": "line",
                    "mode": "normal",
                    "data": {"label": "Count", "id": "1"},
                    "valueAxis": "ValueAxis-1",
                    "drawLinesBetweenPoints": True,
                    "showCircles": True,
                    "interpolate": "linear",
                    "lineWidth": 2,
                }
            ],
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False,
        },
        "aggs": [
            {
                "id": "1",
                "enabled": True,
                "type": "count",
                "schema": "metric",
                "params": {},
            },
            {
                "id": "2",
                "enabled": True,
                "type": "date_histogram",
                "schema": "segment",
                "params": {
                    "field": "@timestamp",
                    "timeRange": {"from": "now-30d", "to": "now"},
                    "useNormalizedEsInterval": True,
                    "interval": "auto",
                    "drop_partials": False,
                    "min_doc_count": 1,
                    "extended_bounds": {},
                },
            },
        ],
    }
    return {
        "attributes": {
            "title": "Agentropix findings timeline",
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "WZ-022 / W-278: Agentropix findings count over time (default last 30 days, auto interval).",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": _empty_search_source()},
        },
        "id": "agentropix-findings-timeline-line",
        "references": [_ref_index_pattern()],
        "type": "visualization",
        "version": VERSION_TOKEN,
    }


def build_overview_dashboard() -> dict:
    """W-278: original overview dashboard (severity + MITRE + timeline)."""
    panels = [
        {
            "version": PANEL_VERSION,
            "gridData": {"x": 0, "y": 0, "w": 24, "h": 15, "i": "1"},
            "panelIndex": "1",
            "embeddableConfig": {},
            "panelRefName": "panel_0",
        },
        {
            "version": PANEL_VERSION,
            "gridData": {"x": 24, "y": 0, "w": 24, "h": "15", "i": "2"},
            "panelIndex": "2",
            "embeddableConfig": {},
            "panelRefName": "panel_1",
        },
        {
            "version": PANEL_VERSION,
            "gridData": {"x": 0, "y": 15, "w": 48, "h": 15, "i": "3"},
            "panelIndex": "3",
            "embeddableConfig": {},
            "panelRefName": "panel_2",
        },
    ]
    # Fix the stray string in panel 2 grid (h must be int).
    panels[1]["gridData"]["h"] = 15
    return {
        "attributes": {
            "title": "Agentropix findings overview",
            "hits": 0,
            "description": "WZ-022 / W-278: pre-canned dashboard for the agentropix-findings-* index pattern. Three panels: severity donut, MITRE technique bar, timeline.",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "version": 1,
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-30d",
            "refreshInterval": {"pause": True, "value": 0},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {
                        "query": {"query": "", "language": "kuery"},
                        "filter": [],
                    }
                )
            },
        },
        "id": "agentropix-findings-overview",
        "references": [
            {
                "name": "panel_0",
                "type": "visualization",
                "id": "agentropix-findings-severity-pie",
            },
            {
                "name": "panel_1",
                "type": "visualization",
                "id": "agentropix-findings-mitre-bar",
            },
            {
                "name": "panel_2",
                "type": "visualization",
                "id": "agentropix-findings-timeline-line",
            },
        ],
        "type": "dashboard",
        "version": VERSION_TOKEN,
    }


# ----- SIFT-W-295 NEW builders ---------------------------------------- #


def build_findings_saved_search() -> dict:
    """W-295: saved search for Discover-style row-by-row inspection of
    findings. Sorted by @timestamp desc."""
    return {
        "attributes": {
            "title": "Agentropix findings — all",
            "description": "SIFT-W-295: discover-style saved search for findings.",
            "hits": 0,
            "columns": [
                "finding_id",
                "severity",
                "approval.status",
                "mitre_techniques",
                "host.name",
            ],
            "sort": [["@timestamp", "desc"]],
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": _empty_search_source()},
        },
        "id": "agentropix-findings-search",
        "references": [_ref_index_pattern()],
        "type": "search",
        "version": VERSION_TOKEN,
    }


def build_timeline_saved_search() -> dict:
    return {
        "attributes": {
            "title": "Agentropix timeline — all events",
            "description": "SIFT-W-295: discover-style saved search for timeline events.",
            "hits": 0,
            "columns": [
                "event_id",
                "event_type",
                "summary",
                "host",
                "linked_finding_ids",
            ],
            "sort": [["@timestamp", "asc"]],
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": _empty_search_source(TIMELINE_INDEX_PATTERN_ID)
            },
        },
        "id": "agentropix-timeline-search",
        "references": [_ref_index_pattern(TIMELINE_INDEX_PATTERN_ID)],
        "type": "search",
        "version": VERSION_TOKEN,
    }


def _metric_vis(
    title: str,
    desc: str,
    obj_id: str,
    *,
    filter_field: str | None = None,
    filter_value: str | None = None,
    pattern_id: str = FINDINGS_INDEX_PATTERN_ID,
    cardinality_field: str | None = None,
) -> dict:
    """Generic single-metric vis builder. Filters are optional —
    DRAFT/APPROVED tiles pin them; the base count leaves them empty.
    Cardinality_field swaps the metric type from count to cardinality
    for distinct-host / distinct-technique tiles."""
    if cardinality_field is not None:
        agg = {
            "id": "1",
            "enabled": True,
            "type": "cardinality",
            "schema": "metric",
            "params": {"field": cardinality_field},
        }
    else:
        agg = {
            "id": "1",
            "enabled": True,
            "type": "count",
            "schema": "metric",
            "params": {},
        }
    vis_state = {
        "title": title,
        "type": "metric",
        "params": {
            "addTooltip": True,
            "addLegend": False,
            "type": "metric",
            "metric": {
                "percentageMode": False,
                "useRanges": False,
                "colorSchema": "Green to Red",
                "metricColorMode": "None",
                "colorsRange": [{"from": 0, "to": 10000}],
                "labels": {"show": True},
                "invertColors": False,
                "style": {
                    "bgFill": "#000",
                    "bgColor": False,
                    "labelColor": False,
                    "subText": "",
                    "fontSize": 60,
                },
            },
        },
        "aggs": [agg],
    }
    if filter_field is not None and filter_value is not None:
        source = _filter_search_source(filter_field, filter_value, pattern_id)
    else:
        source = _empty_search_source(pattern_id)
    return {
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": desc,
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": source},
        },
        "id": obj_id,
        "references": [_ref_index_pattern(pattern_id)],
        "type": "visualization",
        "version": VERSION_TOKEN,
    }


def build_metric_findings_total() -> dict:
    return _metric_vis(
        "Findings — total",
        "SIFT-W-295: total Agentropix findings (all statuses).",
        "agentropix-metric-findings-total",
    )


def build_metric_findings_draft() -> dict:
    return _metric_vis(
        "Findings — DRAFT",
        "SIFT-W-295: DRAFT-status findings awaiting examiner review.",
        "agentropix-metric-findings-draft",
        filter_field="approval.status",
        filter_value="DRAFT",
    )


def build_metric_findings_approved() -> dict:
    return _metric_vis(
        "Findings — APPROVED",
        "SIFT-W-295: APPROVED-status findings ready for reports.",
        "agentropix-metric-findings-approved",
        filter_field="approval.status",
        filter_value="APPROVED",
    )


def build_metric_findings_hosts() -> dict:
    return _metric_vis(
        "Hosts (distinct)",
        "SIFT-W-295: distinct hosts represented in findings.",
        "agentropix-metric-findings-hosts",
        cardinality_field="host.name.keyword",
    )


def build_metric_findings_mitre() -> dict:
    return _metric_vis(
        "MITRE techniques (distinct)",
        "SIFT-W-295: distinct MITRE ATT&CK techniques observed.",
        "agentropix-metric-findings-mitre",
        cardinality_field="mitre_techniques",
    )


def build_metric_timeline_total() -> dict:
    return _metric_vis(
        "Timeline events — total",
        "SIFT-W-295: total agentropix-timeline-* events.",
        "agentropix-metric-timeline-total",
        pattern_id=TIMELINE_INDEX_PATTERN_ID,
    )


def build_metric_timeline_approved() -> dict:
    return _metric_vis(
        "Timeline events — APPROVED",
        "SIFT-W-295: APPROVED-status timeline events.",
        "agentropix-metric-timeline-approved",
        pattern_id=TIMELINE_INDEX_PATTERN_ID,
        filter_field="approval.status",
        filter_value="APPROVED",
    )


def build_info_markdown() -> dict:
    """W-295: informational panel with the sidecar URL + a quick
    workflow note for new examiners."""
    md = (
        "### Agentropix Findings + Timeline Dashboards\n\n"
        "Click any **finding_id** field below to open the approval "
        "sidecar's challenge-response form (server-side HMAC; your "
        "password never leaves the browser).\n\n"
        "**Workflow:** review the DRAFT count on the left → click into "
        "a finding → sign + submit in the sidecar tab → reload to see "
        "the APPROVED count climb.\n\n"
        "_Bundle generated by_ `agentropix_mcp.wazuh.dashboards.builders` "
        "(SIFT-W-295)."
    )
    vis_state = {
        "title": "Workflow notes",
        "type": "markdown",
        "params": {
            "markdown": md,
            "openLinksInNewTab": True,
            "fontSize": 12,
        },
        "aggs": [],
    }
    return {
        "attributes": {
            "title": "Agentropix workflow notes",
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "SIFT-W-295: markdown panel with sidecar deep-link + workflow note.",
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": []}
                )
            },
        },
        "id": "agentropix-info-markdown",
        "references": [],
        "type": "visualization",
        "version": VERSION_TOKEN,
    }


def _panel(x: int, y: int, w: int, h: int, idx: int, panel_ref: str) -> dict:
    return {
        "version": PANEL_VERSION,
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(idx)},
        "panelIndex": str(idx),
        "embeddableConfig": {},
        "panelRefName": panel_ref,
    }


def build_findings_tab_dashboard() -> dict:
    """W-295: dashboard that mimics the Valhuntir Examiner Portal
    Findings tab — stat tiles across the top, saved-search list on
    the left, severity + MITRE charts on the right."""
    panels = [
        # Row 1: 5 metric tiles
        _panel(0, 0, 10, 6, 1, "panel_0"),  # findings_total
        _panel(10, 0, 10, 6, 2, "panel_1"),  # findings_draft
        _panel(20, 0, 10, 6, 3, "panel_2"),  # findings_approved
        _panel(30, 0, 9, 6, 4, "panel_3"),  # hosts distinct
        _panel(39, 0, 9, 6, 5, "panel_4"),  # mitre distinct
        # Row 2: saved-search list on left, charts on right
        _panel(0, 6, 24, 24, 6, "panel_5"),  # saved search
        _panel(24, 6, 24, 12, 7, "panel_6"),  # severity pie
        _panel(24, 18, 24, 12, 8, "panel_7"),  # mitre bar
        # Row 3: workflow markdown spans full width
        _panel(0, 30, 48, 6, 9, "panel_8"),
    ]
    return {
        "attributes": {
            "title": "Agentropix Findings Tab",
            "hits": 0,
            "description": "SIFT-W-295: Findings tab dashboard (5 stat tiles + saved-search list + severity + MITRE + workflow markdown).",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "version": 1,
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-30d",
            "refreshInterval": {"pause": True, "value": 0},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": []}
                )
            },
        },
        "id": "agentropix-findings-tab",
        "references": [
            {"name": "panel_0", "type": "visualization", "id": "agentropix-metric-findings-total"},
            {"name": "panel_1", "type": "visualization", "id": "agentropix-metric-findings-draft"},
            {
                "name": "panel_2",
                "type": "visualization",
                "id": "agentropix-metric-findings-approved",
            },
            {"name": "panel_3", "type": "visualization", "id": "agentropix-metric-findings-hosts"},
            {"name": "panel_4", "type": "visualization", "id": "agentropix-metric-findings-mitre"},
            {"name": "panel_5", "type": "search", "id": "agentropix-findings-search"},
            {"name": "panel_6", "type": "visualization", "id": "agentropix-findings-severity-pie"},
            {"name": "panel_7", "type": "visualization", "id": "agentropix-findings-mitre-bar"},
            {"name": "panel_8", "type": "visualization", "id": "agentropix-info-markdown"},
        ],
        "type": "dashboard",
        "version": VERSION_TOKEN,
    }


def build_timeline_tab_dashboard() -> dict:
    """W-295: dashboard mimicking the Examiner Portal Timeline tab.

    Top: 2 metric tiles + the date-histogram timeline line.
    Body: saved-search list of timeline events sorted ascending.
    """
    panels = [
        _panel(0, 0, 16, 6, 1, "panel_0"),  # timeline_total
        _panel(16, 0, 16, 6, 2, "panel_1"),  # timeline_approved
        _panel(0, 6, 48, 12, 3, "panel_2"),  # timeline line vis
        _panel(0, 18, 48, 18, 4, "panel_3"),  # saved-search list
    ]
    return {
        "attributes": {
            "title": "Agentropix Timeline Tab",
            "hits": 0,
            "description": "SIFT-W-295: Timeline tab dashboard (2 stat tiles + timeline line + saved-search list).",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "version": 1,
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-30d",
            "refreshInterval": {"pause": True, "value": 0},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": []}
                )
            },
        },
        "id": "agentropix-timeline-tab",
        "references": [
            {"name": "panel_0", "type": "visualization", "id": "agentropix-metric-timeline-total"},
            {
                "name": "panel_1",
                "type": "visualization",
                "id": "agentropix-metric-timeline-approved",
            },
            {"name": "panel_2", "type": "visualization", "id": "agentropix-findings-timeline-line"},
            {"name": "panel_3", "type": "search", "id": "agentropix-timeline-search"},
        ],
        "type": "dashboard",
        "version": VERSION_TOKEN,
    }


# ----- bundle assembly ----------------------------------------------- #


def build_bundle(sidecar_url: str = DEFAULT_SIDECAR_URL) -> list[dict]:
    """Return the full 17-object bundle as a list of dicts.

    Ordering matches the .ndjson on disk so a regen produces a stable
    byte-equal output: index-patterns first, then visualizations, then
    saved searches, then the dashboards that aggregate them.

    Args:
        sidecar_url: base URL embedded in the ``finding_id`` URL
            formatter. Defaults to ``http://127.0.0.1:8800`` for the
            operator's same-workstation deployment; pass an explicit
            URL when generating a bundle for a remote deployment.
    """
    return [
        # Index patterns (2)
        build_findings_index_pattern(sidecar_url),
        build_timeline_index_pattern(),
        # Original W-278 visualizations (3)
        build_severity_pie(),
        build_mitre_bar(),
        build_timeline_line(),
        # W-295 metric vis (7)
        build_metric_findings_total(),
        build_metric_findings_draft(),
        build_metric_findings_approved(),
        build_metric_findings_hosts(),
        build_metric_findings_mitre(),
        build_metric_timeline_total(),
        build_metric_timeline_approved(),
        # W-295 markdown (1)
        build_info_markdown(),
        # W-295 saved searches (2)
        build_findings_saved_search(),
        build_timeline_saved_search(),
        # Dashboards: W-278 original + 2 W-295 tabs (3)
        build_overview_dashboard(),
        build_findings_tab_dashboard(),
        build_timeline_tab_dashboard(),
    ]


def render_bundle_ndjson(sidecar_url: str = DEFAULT_SIDECAR_URL) -> str:
    """Render the bundle as NDJSON ready to drop into Wazuh Dashboard's
    saved-objects import dialog. Trailing newline after the last
    object — same as Kibana exports."""
    parts = [json.dumps(o, separators=(",", ":")) for o in build_bundle(sidecar_url)]
    return "\n".join(parts) + "\n"
