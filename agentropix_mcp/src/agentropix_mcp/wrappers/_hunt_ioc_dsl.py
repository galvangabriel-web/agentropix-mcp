"""WZ-001 (master-report §4.4 #17, §F5.3): DSL builders for `wazuh_hunt_ioc`.

Produces OpenSearch DSL bodies for Indexer searches against
``wazuh-alerts-*``. The retro-hunt covers the 90-day default window
(per master-report T-FLOW §3 alert retention).

C3-DETECTION Finding 5 acceptance:
  - Use ``term`` queries against ``<field>.keyword`` for hashes / IPs /
    agent.id / rule.id (NOT ``match``, which tokenises IPs on `.` and
    breaks exact-match)
  - Use ``match_phrase`` for analysed text fields (e.g.
    ``data.win.eventdata.queryName``)
  - Tokenisation-bug regression test (the IPv4-on-`.` failure case)
  - MITRE-id carry-through asserted for T1071 / T1071.001 / T1547.001 /
    T1027 / T1565.001

The supported IOC types map to Wazuh-alert field paths as follows:

    ip                  -> data.srcip.keyword OR data.dstip.keyword
    sha256              -> data.hash.sha256.keyword OR
                           data.win.eventdata.hashes.keyword (Sysmon)
    md5                 -> data.hash.md5.keyword
    domain              -> data.win.eventdata.queryName (match_phrase)
    process_image       -> data.win.eventdata.image.keyword
    process_module      -> data.win.eventdata.imageloaded.keyword
    rule_id             -> rule.id (numeric, term)
    username            -> data.user.keyword

Unrecognised ``ioc_type`` falls back to a ``multi_match`` across a
small allowlisted field set (with operator-controlled time bound).
This keeps surface area for prompt-injection bounded — see
master-report C1 Finding 7 / WLV-15.
"""

from __future__ import annotations

import time
from typing import Any

__all__ = [
    "build_hunt_query",
    "supported_ioc_types",
    "DEFAULT_TIME_RANGE_HOURS",
    "MAX_SIZE",
]


# 90 days = 24 * 90 = 2160 hours. T-FLOW §3 names this as the default
# retention window for alert retro-hunts. Operators can pass a smaller
# window for fast triage.
DEFAULT_TIME_RANGE_HOURS = 24 * 90

# Master-report §F4.4 capacity envelope: ``size <= 500`` per IOC for
# ``wazuh_hunt_ioc``. Beyond that the caller should use the scroll API
# (not yet implemented; tracked as future work in master-report §4.5).
MAX_SIZE = 500


def supported_ioc_types() -> tuple[str, ...]:
    """Stable list of accepted ``ioc_type`` values."""
    return (
        "ip",
        "sha256",
        "md5",
        "domain",
        "process_image",
        "process_module",
        "rule_id",
        "username",
    )


def _now_minus_hours_ms(hours: int) -> int:
    """Epoch-millisecond timestamp for now - <hours>."""
    return int((time.time() - hours * 3600) * 1000)


def _time_range_clause(time_range_hours: int) -> dict:
    """Build the ``range`` clause for the ``@timestamp`` field.

    Uses millisecond epoch on the lte/gte sides so it doesn't depend
    on the indexer's date-format parsing.
    """
    return {
        "range": {
            "@timestamp": {
                "gte": _now_minus_hours_ms(time_range_hours),
                "format": "epoch_millis",
            }
        }
    }


def _term_for_ip(value: str) -> dict:
    """IP search: an IP can appear as srcip OR dstip; OR them together.

    Uses ``term`` on the ``.keyword`` subfield to avoid the IPv4-on-`.`
    tokenisation bug (C3 Finding 5). The plain ``data.srcip`` field is
    analysed text and would tokenise on dots.
    """
    return {
        "bool": {
            "should": [
                {"term": {"data.srcip.keyword": value}},
                {"term": {"data.dstip.keyword": value}},
            ],
            "minimum_should_match": 1,
        }
    }


def _term_for_sha256(value: str) -> dict:
    """SHA-256 search: hash can land under data.hash.sha256 (Wazuh
    canonical) or data.win.eventdata.hashes (Sysmon). Both are
    keyword-typed; OR them together."""
    value = value.lower()
    return {
        "bool": {
            "should": [
                {"term": {"data.hash.sha256.keyword": value}},
                {"term": {"data.win.eventdata.hashes.keyword": f"SHA256={value.upper()}"}},
            ],
            "minimum_should_match": 1,
        }
    }


def _term_for_md5(value: str) -> dict:
    return {"term": {"data.hash.md5.keyword": value.lower()}}


def _match_phrase_for_domain(value: str) -> dict:
    """Domain search: queryName is analysed text, must use
    match_phrase to preserve dot-separated segments."""
    return {"match_phrase": {"data.win.eventdata.queryName": value.lower()}}


def _term_for_process_image(value: str) -> dict:
    return {"term": {"data.win.eventdata.image.keyword": value}}


def _term_for_process_module(value: str) -> dict:
    return {"term": {"data.win.eventdata.imageloaded.keyword": value}}


def _term_for_rule_id(value: str | int) -> dict:
    """Rule ID is numeric in Wazuh's schema. The ``rule.id`` field IS
    the canonical name (no .keyword needed)."""
    rid = int(value)
    return {"term": {"rule.id": rid}}


def _term_for_username(value: str) -> dict:
    return {"term": {"data.user.keyword": value}}


def _build_clause(ioc_type: str, ioc_value: str) -> dict:
    """Dispatch on ioc_type; returns the inner clause for the bool/must.

    Raises ValueError for unknown ioc_type so the caller (safe_tool
    wrapper) catches at the boundary and returns a clean envelope.
    """
    builders = {
        "ip": _term_for_ip,
        "sha256": _term_for_sha256,
        "md5": _term_for_md5,
        "domain": _match_phrase_for_domain,
        "process_image": _term_for_process_image,
        "process_module": _term_for_process_module,
        "rule_id": _term_for_rule_id,
        "username": _term_for_username,
    }
    builder = builders.get(ioc_type)
    if builder is None:
        raise ValueError(
            f"Unknown ioc_type {ioc_type!r}; supported: {supported_ioc_types()}"
        )
    return builder(ioc_value)


def build_hunt_query(
    ioc_value: str,
    ioc_type: str,
    *,
    time_range_hours: int = DEFAULT_TIME_RANGE_HOURS,
    size: int = MAX_SIZE,
) -> dict[str, Any]:
    """Build the full OpenSearch DSL body for a hunt_ioc retro-hunt.

    Args:
        ioc_value: the value to search for (sanitised at the
            wrapper layer; this builder treats it as opaque)
        ioc_type: one of ``supported_ioc_types()``
        time_range_hours: retro-hunt lookback window
        size: max hits to return (capped at ``MAX_SIZE``)

    Returns:
        full search body suitable for IndexerClient.search().
    """
    if size > MAX_SIZE:
        size = MAX_SIZE
    if size < 1:
        size = 1
    if time_range_hours < 1:
        time_range_hours = 1

    inner = _build_clause(ioc_type, ioc_value)
    return {
        "query": {
            "bool": {
                "must": [
                    inner,
                    _time_range_clause(time_range_hours),
                ]
            }
        },
        # Sort by @timestamp desc so the freshest hits come first.
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": size,
        # Source filtering — only fetch the fields needed to populate
        # ObservationAlert. Reduces response payload from indexer
        # significantly + caps prompt-injection surface (master-report
        # WLV-15 / C1 F7).
        "_source": [
            "@timestamp",
            "rule.id",
            "rule.level",
            "rule.description",
            "rule.groups",
            "rule.mitre.id",
            "rule.mitre.technique",
            "data.srcip",
            "data.dstip",
            "agent.id",
            "agent.name",
            "full_log",
        ],
    }
