"""SIFT-W-290: idx_* query MCP wrappers (4 of the 5 in this stack).

Implements Valhuntir workflow step 5 (structured queries — ~500 tokens
each per the user's intent) and step 4 (case_summary). Every tool here
is a thin wrapper around ``IndexerClient`` query primitives,
case-scoped via the ``case_id`` keyword field added in W-285.

Sub-agent #4 critique honored: the underlying ``IndexerClient.search``
caps ``size`` at 500. ``idx_search`` here paginates via ``from`` /
``size`` rather than passing through a single large ``size`` — so a
caller asking for ``limit=2000`` gets 4 paged round-trips assembled
into one result instead of a 400 ``ValueError`` from the client.

The 4 tools:

  * ``idx_search``        — full-text + structured query, paged.
  * ``idx_aggregate``     — terms / cardinality top-N for pattern
                            analysis.
  * ``idx_timeline``      — date_histogram bucketing for "what
                            happened at time T".
  * ``idx_case_summary``  — case overview: per-index doc counts,
                            top hosts, top artifact types, time range,
                            plus a smart-hint string for the LLM's
                            next-call planning.

``idx_ingest`` lives in the sibling ``case_ingest`` module.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

from pydantic import BaseModel, Field

from agentropix_mcp.wrappers.case_lifecycle import (
    FINDINGS_INDEX_PATTERN,
    TIMELINE_INDEX_PATTERN,
    _validate_case_id,
    get_active_case_id,
)

logger = logging.getLogger(__name__)


# Hard upper bound on the assembled paged result. The underlying
# IndexerClient.search() caps per-page at 500 (capacity envelope
# §F4.4); the wrapper caps the total at 5000 ROWS. But a row cap does
# NOT bound BYTES — SIFT-W-296c (Critic E) — so the byte-budget helper
# below trims list fields until the serialized result fits under the
# 1MB MCP tool-result envelope (Claude Desktop limitation, same family
# as the W-283 critic round).
MAX_TOTAL_LIMIT = 5000
PER_PAGE = 500

# Serialized-byte ceiling for any MCP tool result. Default 900 KB
# leaves headroom under the hard 1 MB Claude Desktop cap. Override via
# env on clients without the cap.
RESULT_MAX_BYTES = max(
    50_000,
    min(
        5_000_000,
        int(os.environ.get("AGENTROPIX_MCP_RESULT_MAX_BYTES", "900000")),
    ),
)


def _result_byte_size(model: Any) -> int:
    """Serialized JSON byte size of a Pydantic result model."""
    try:
        return len(json.dumps(model.model_dump(), default=str).encode("utf-8"))
    except Exception:
        return 0


def enforce_byte_budget(
    model: Any,
    list_attrs: list[str],
    *,
    max_bytes: int | None = None,
) -> Any:
    """SIFT-W-296c: trim the named list attributes on ``model`` until the
    serialized result fits under ``max_bytes``. Sets ``model.truncated
    = True`` when anything is dropped, and (if present) records the
    final byte size in ``model.result_bytes``.

    Trims the LARGEST list first, dropping ~15% of it per pass, so a
    result with one heavy list and several small ones loses rows only
    from the heavy one. Idempotent + safe when already under budget.

    ``max_bytes`` defaults to the module-level ``RESULT_MAX_BYTES``
    resolved at CALL time (not def time), so an env override / test
    patch takes effect.
    """
    if max_bytes is None:
        max_bytes = RESULT_MAX_BYTES
    if _result_byte_size(model) <= max_bytes:
        if hasattr(model, "result_bytes"):
            model.result_bytes = _result_byte_size(model)
        return model

    guard = 0
    while _result_byte_size(model) > max_bytes and guard < 1000:
        guard += 1
        # Pick the currently-longest list attribute that still has rows.
        longest_attr = None
        longest_len = 0
        for attr in list_attrs:
            val = getattr(model, attr, None)
            if isinstance(val, list) and len(val) > longest_len:
                longest_attr, longest_len = attr, len(val)
        if longest_attr is None or longest_len == 0:
            break  # nothing left to trim
        cur = getattr(model, longest_attr)
        drop = max(1, len(cur) // 7)  # ~15% per pass
        setattr(model, longest_attr, cur[: len(cur) - drop])
        if hasattr(model, "truncated"):
            model.truncated = True

    if hasattr(model, "result_bytes"):
        model.result_bytes = _result_byte_size(model)
    return model


# --- Pydantic result models ------------------------------------------ #


class IdxSearchHit(BaseModel):
    """One hit in an idx_search result.

    Fields are deliberately trimmed — the full ``_source`` lives in
    ``source`` while the high-signal fields are surface-promoted so a
    callback LLM can scan results without descending into the nested
    dict every time.
    """

    id: str
    index: str
    score: float | None = None
    timestamp: str = ""
    case_id: str = ""
    severity: str = ""
    source: dict[str, Any] = Field(default_factory=dict)


class IdxSearchResult(BaseModel):
    case_id: str
    index_pattern: str
    total: int
    returned: int
    hits: list[IdxSearchHit] = Field(default_factory=list)
    page_count: int = 1
    # SIFT-W-296c: byte-budget transparency. truncated=True means the
    # hits list was trimmed to fit the 1MB MCP result envelope; narrow
    # the query (since/until/limit) to see the rest.
    truncated: bool = False
    result_bytes: int = 0
    error: str = ""


class IdxAggregateBucket(BaseModel):
    key: str
    doc_count: int


class IdxAggregateResult(BaseModel):
    case_id: str
    index_pattern: str
    field: str
    total_docs: int
    distinct_values: int
    buckets: list[IdxAggregateBucket] = Field(default_factory=list)
    error: str = ""


class IdxTimelineBucket(BaseModel):
    timestamp: str
    doc_count: int


class IdxTimelineResult(BaseModel):
    case_id: str
    index_pattern: str
    interval: str
    bucket_count: int
    buckets: list[IdxTimelineBucket] = Field(default_factory=list)
    error: str = ""


class IdxCaseSummaryResult(BaseModel):
    case_id: str
    per_index_counts: dict[str, int] = Field(default_factory=dict)
    top_hosts: list[IdxAggregateBucket] = Field(default_factory=list)
    top_artifact_types: list[IdxAggregateBucket] = Field(default_factory=list)
    time_range: dict[str, str] = Field(default_factory=dict)  # earliest, latest
    next_step_hints: list[str] = Field(default_factory=list)
    error: str = ""


# --- Shared helpers --------------------------------------------------- #


# SIFT-W-296d (Critic A): index_pattern is a free-text MCP parameter
# interpolated into the indexer URL path. Without an allowlist a caller
# could read non-agentropix indices (wazuh-alerts-*, *, etc.), scoped
# only by the indexer credential. Constrain every idx_* read to the
# agentropix-owned namespace.
_ALLOWED_INDEX_PREFIX = "agentropix-"


def _validate_index_pattern(index_pattern: str) -> str:
    """Reject any index pattern outside the agentropix-* namespace."""
    if not isinstance(index_pattern, str) or not index_pattern.startswith(_ALLOWED_INDEX_PREFIX):
        raise ValueError(
            f"index_pattern must start with {_ALLOWED_INDEX_PREFIX!r}; "
            f"got {index_pattern!r} (cross-index reads are not allowed)"
        )
    return index_pattern


def _resolve_case_id(case_id: str | None) -> str:
    """Resolve the active-case pointer when ``case_id`` is None, and
    validate the resulting id.

    Common precondition for every idx_* tool — keeps the LLM from
    having to thread case_id through every call when one is active.
    SIFT-W-296d (Critic A): validates the caller-supplied case_id for
    parity with case_* tools (defense in depth — it lands in a
    structured term filter, but rejecting malformed ids early keeps
    the index _id space clean).
    """
    if case_id is not None:
        _validate_case_id(case_id)
        return case_id
    active = get_active_case_id()
    if active is None:
        raise ValueError("no active case; pass case_id= or call case_activate() first")
    return active


def _case_filter(case_id: str) -> dict:
    return {"term": {"case_id": case_id}}


def _wrap_with_case_filter(query: dict, case_id: str) -> dict:
    """Compose a user-supplied query body with the case_id scope.

    Accepts either a raw clause (e.g. ``{"match": {...}}``) or a full
    body (with ``"query"`` key); always emits a ``bool.filter``
    wrapper so the case_id constraint is enforced server-side and a
    careless query string can't leak cross-case docs.
    """
    if not query:
        inner: dict = {"match_all": {}}
    elif "query" in query:
        inner = query["query"]
    else:
        inner = query
    return {
        "query": {
            "bool": {
                "filter": [_case_filter(case_id)],
                "must": [inner],
            }
        }
    }


def _extract_hit_source(hit: dict) -> IdxSearchHit:
    src = hit.get("_source") or {}
    return IdxSearchHit(
        id=hit.get("_id", ""),
        index=hit.get("_index", ""),
        score=hit.get("_score"),
        timestamp=str(src.get("@timestamp", "")),
        case_id=str(src.get("case_id", "")),
        severity=str(src.get("severity", "")),
        source=src,
    )


# --- Tool: idx_search ------------------------------------------------- #


async def idx_search(
    query: dict | None = None,
    *,
    case_id: str | None = None,
    index_pattern: str = FINDINGS_INDEX_PATTERN,
    limit: int = 50,
    offset: int = 0,
    indexer_client: Any = None,
) -> IdxSearchResult:
    """Run a case-scoped full-text + structured search.

    Pages internally over the W-274 500-row-per-call cap so a caller
    asking for ``limit=2000`` gets 4 sequential round-trips assembled
    into one result. Total hits are still capped at
    ``MAX_TOTAL_LIMIT`` to defend the MCP tool-result envelope.

    Args:
        query: bare clause or full body. ``None`` ⇒ match_all.
        case_id: optional; resolves active-case pointer when ``None``.
        index_pattern: defaults to ``agentropix-findings-*``. Pass an
            explicit pattern (e.g. ``agentropix-timeline-*``) to
            search a different sibling.
        limit: total hits to return. Capped at MAX_TOTAL_LIMIT.
        offset: pagination offset for sub-windows.
        indexer_client: injected IndexerClient. Returns a
            search-error envelope when ``None``.
    """
    resolved_case_id = _resolve_case_id(case_id)
    _validate_index_pattern(index_pattern)
    capped_limit = max(1, min(int(limit), MAX_TOTAL_LIMIT))
    safe_offset = max(0, int(offset))
    body = _wrap_with_case_filter(query or {}, resolved_case_id)
    body["sort"] = [{"@timestamp": {"order": "desc", "missing": "_last"}}]

    if indexer_client is None:
        return IdxSearchResult(
            case_id=resolved_case_id,
            index_pattern=index_pattern,
            total=0,
            returned=0,
            page_count=0,
            error="indexer_client not injected",
        )

    hits: list[IdxSearchHit] = []
    total_total = 0
    page_count = 0
    error = ""
    try:
        remaining = capped_limit
        current_offset = safe_offset
        while remaining > 0:
            page_size = min(PER_PAGE, remaining)
            page_body = dict(body)
            page_body["from"] = current_offset
            resp = await indexer_client.search(index_pattern, page_body, size=page_size)
            page_count += 1
            page_hits = ((resp.get("hits") or {}).get("hits")) or []
            total_block = (resp.get("hits") or {}).get("total") or {}
            if isinstance(total_block, dict):
                total_total = int(total_block.get("value", 0))
            else:
                total_total = int(total_block)
            for h in page_hits:
                hits.append(_extract_hit_source(h))
            if len(page_hits) < page_size:
                break  # short page → no more results upstream
            remaining -= len(page_hits)
            current_offset += len(page_hits)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        logger.warning("idx_search: indexer call failed: %s", exc)

    result = IdxSearchResult(
        case_id=resolved_case_id,
        index_pattern=index_pattern,
        total=total_total,
        returned=len(hits),
        hits=hits,
        page_count=page_count,
        error=error,
    )
    # SIFT-W-296c (Critic E): enforce the byte ceiling — a row cap does
    # not bound bytes. Trims hits + flags truncated if over 900KB.
    enforce_byte_budget(result, ["hits"])
    result.returned = len(result.hits)
    return result


# --- Tool: idx_aggregate --------------------------------------------- #


async def idx_aggregate(
    field: str,
    *,
    case_id: str | None = None,
    index_pattern: str = FINDINGS_INDEX_PATTERN,
    query: dict | None = None,
    top_n: int = 25,
    indexer_client: Any = None,
) -> IdxAggregateResult:
    """Terms aggregation: top-N values of ``field`` for the case.

    Common patterns ``mitre_techniques`` (top techniques),
    ``host.name`` (busiest hosts), ``severity`` (severity mix).
    Returns a bucketed list ready to render as a table or a chart.
    """
    if not field or not isinstance(field, str):
        raise ValueError("field must be a non-empty string")
    resolved_case_id = _resolve_case_id(case_id)
    _validate_index_pattern(index_pattern)
    capped_top_n = max(1, min(int(top_n), 1000))

    body = _wrap_with_case_filter(query or {}, resolved_case_id)
    body["aggs"] = {
        "by_field": {"terms": {"field": field, "size": capped_top_n}},
        "distinct": {"cardinality": {"field": field}},
    }
    # size=1 because we only want the aggs; non-zero is required by
    # the existing IndexerClient.search guard.
    body["size"] = 1

    if indexer_client is None:
        return IdxAggregateResult(
            case_id=resolved_case_id,
            index_pattern=index_pattern,
            field=field,
            total_docs=0,
            distinct_values=0,
            error="indexer_client not injected",
        )

    buckets: list[IdxAggregateBucket] = []
    total_docs = 0
    distinct_values = 0
    error = ""
    try:
        resp = await indexer_client.search(index_pattern, body, size=1)
        total_block = (resp.get("hits") or {}).get("total") or {}
        if isinstance(total_block, dict):
            total_docs = int(total_block.get("value", 0))
        else:
            total_docs = int(total_block)
        aggs = resp.get("aggregations") or {}
        by_field = aggs.get("by_field") or {}
        for b in by_field.get("buckets") or []:
            buckets.append(
                IdxAggregateBucket(
                    key=str(b.get("key", "")),
                    doc_count=int(b.get("doc_count", 0)),
                )
            )
        distinct = aggs.get("distinct") or {}
        distinct_values = int(distinct.get("value", 0))
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        logger.warning("idx_aggregate: indexer call failed: %s", exc)

    return IdxAggregateResult(
        case_id=resolved_case_id,
        index_pattern=index_pattern,
        field=field,
        total_docs=total_docs,
        distinct_values=distinct_values,
        buckets=buckets,
        error=error,
    )


# --- Tool: idx_timeline ---------------------------------------------- #


async def idx_timeline(
    *,
    case_id: str | None = None,
    index_pattern: str = TIMELINE_INDEX_PATTERN,
    query: dict | None = None,
    interval: str = "1h",
    time_field: str = "@timestamp",
    indexer_client: Any = None,
) -> IdxTimelineResult:
    """date_histogram bucketing for "what happened over time".

    Defaults to the timeline sibling index but accepts any pattern
    (findings + timeline aggregate together if you want a unified
    "activity over the case" curve).

    Args:
        interval: any OpenSearch fixed-interval shorthand (1m, 5m,
            1h, 1d). Calendar intervals (1w, 1M) also work.
    """
    resolved_case_id = _resolve_case_id(case_id)
    _validate_index_pattern(index_pattern)
    if not interval or not isinstance(interval, str):
        raise ValueError("interval must be a non-empty string")

    body = _wrap_with_case_filter(query or {}, resolved_case_id)
    body["aggs"] = {
        "over_time": {
            "date_histogram": {
                "field": time_field,
                "fixed_interval": interval
                if interval.endswith(("ms", "s", "m", "h", "d"))
                else None,
                "calendar_interval": interval
                if not interval.endswith(("ms", "s", "m", "h", "d"))
                else None,
                "min_doc_count": 0,
            }
        }
    }
    # Strip the None-valued interval key (OpenSearch rejects it).
    hist = body["aggs"]["over_time"]["date_histogram"]
    for k in ("fixed_interval", "calendar_interval"):
        if hist.get(k) is None:
            hist.pop(k, None)
    body["size"] = 1

    if indexer_client is None:
        return IdxTimelineResult(
            case_id=resolved_case_id,
            index_pattern=index_pattern,
            interval=interval,
            bucket_count=0,
            error="indexer_client not injected",
        )

    buckets: list[IdxTimelineBucket] = []
    error = ""
    try:
        resp = await indexer_client.search(index_pattern, body, size=1)
        aggs = resp.get("aggregations") or {}
        over_time = aggs.get("over_time") or {}
        for b in over_time.get("buckets") or []:
            buckets.append(
                IdxTimelineBucket(
                    timestamp=str(b.get("key_as_string") or b.get("key", "")),
                    doc_count=int(b.get("doc_count", 0)),
                )
            )
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        logger.warning("idx_timeline: indexer call failed: %s", exc)

    return IdxTimelineResult(
        case_id=resolved_case_id,
        index_pattern=index_pattern,
        interval=interval,
        bucket_count=len(buckets),
        buckets=buckets,
        error=error,
    )


# --- Tool: idx_case_summary ------------------------------------------ #


def _build_hints(
    counts: dict[str, int],
    top_hosts: list[IdxAggregateBucket],
    top_artifact_types: list[IdxAggregateBucket],
) -> list[str]:
    """Smart next-step hints for the LLM.

    Mirrors Valhuntir's ``idx_case_summary`` hints generator
    (architecture.md § Layer 3: Contextual Reminders). Budget-capped
    at the natural list size; no truncation needed because each hint
    is one short sentence.
    """
    hints: list[str] = []

    if not any(counts.values()):
        hints.append(
            "Case has no indexed evidence yet. Start with "
            "`evidence_register()` then `idx_ingest()` for each "
            "Windows host."
        )
        return hints

    if counts.get("findings", 0) == 0 and counts.get("timeline", 0) > 0:
        hints.append(
            "Timeline events exist but no findings yet. Run "
            "`idx_search(index_pattern='agentropix-timeline-*')` to "
            "inspect events, then `record_finding()` for any "
            "execution / persistence / lateral indicators."
        )

    if counts.get("findings", 0) > 0 and counts.get("approvals", 0) == 0:
        hints.append(
            "Findings staged as DRAFT but none APPROVED. Run "
            "`approve_finding()` per finding or open the approval "
            "sidecar UI to review."
        )

    if top_artifact_types:
        labels = ", ".join(b.key for b in top_artifact_types[:3])
        hints.append(
            f"Top artifact types: {labels}. Use "
            f"`idx_aggregate(field='mitre_techniques')` to see which "
            f"MITRE techniques dominate."
        )

    if top_hosts:
        labels = ", ".join(b.key for b in top_hosts[:3])
        hints.append(
            f"Most-active hosts: {labels}. Use "
            f"`idx_search(query={{'term': {{'host.name': '<host>'}}}})` "
            f"to scope to one."
        )

    return hints


async def idx_case_summary(
    case_id: str | None = None,
    *,
    indexer_client: Any = None,
) -> IdxCaseSummaryResult:
    """Case overview: doc counts + top hosts + top artifact types +
    time range + next-step hints.

    Mirrors Valhuntir's first-call-of-the-investigation pattern.
    The hint set decays in informativeness in the same way
    Valhuntir's does — once the case has any data the "start with
    evidence_register" line drops out automatically. But because
    this MCP server doesn't track per-call counters, every call
    returns the full hint set; the operator's LLM context window
    is responsible for deduping over a session.
    """
    resolved_case_id = _resolve_case_id(case_id)

    if indexer_client is None:
        return IdxCaseSummaryResult(
            case_id=resolved_case_id,
            error="indexer_client not injected",
        )

    case_filter_q = {"query": _case_filter(resolved_case_id)}

    async def _count(pattern: str) -> int:
        try:
            return int(await indexer_client.count(pattern, case_filter_q))
        except Exception as exc:
            logger.warning("idx_case_summary count %s failed: %s", pattern, exc)
            return -1

    async def _terms(pattern: str, field: str, size: int = 10) -> list[IdxAggregateBucket]:
        body = _wrap_with_case_filter({}, resolved_case_id)
        body["aggs"] = {"by_field": {"terms": {"field": field, "size": size}}}
        body["size"] = 1
        try:
            resp = await indexer_client.search(pattern, body, size=1)
        except Exception as exc:
            logger.warning(
                "idx_case_summary terms %s/%s failed: %s",
                pattern,
                field,
                exc,
            )
            return []
        aggs = resp.get("aggregations") or {}
        return [
            IdxAggregateBucket(
                key=str(b.get("key", "")),
                doc_count=int(b.get("doc_count", 0)),
            )
            for b in (aggs.get("by_field") or {}).get("buckets") or []
        ]

    async def _time_range(pattern: str) -> dict[str, str]:
        body = _wrap_with_case_filter({}, resolved_case_id)
        body["aggs"] = {
            "earliest": {"min": {"field": "@timestamp"}},
            "latest": {"max": {"field": "@timestamp"}},
        }
        body["size"] = 1
        try:
            resp = await indexer_client.search(pattern, body, size=1)
        except Exception as exc:
            logger.warning("idx_case_summary time_range failed: %s", exc)
            return {}
        aggs = resp.get("aggregations") or {}
        return {
            "earliest": str((aggs.get("earliest") or {}).get("value_as_string", "")),
            "latest": str((aggs.get("latest") or {}).get("value_as_string", "")),
        }

    results = await asyncio.gather(
        _count("agentropix-findings-*"),
        _count("agentropix-timeline-*"),
        _count("agentropix-evidence-*"),
        _count("agentropix-iocs-*"),
        _count("agentropix-approvals-*"),
        _terms("agentropix-findings-*", "host.name"),
        _terms("agentropix-findings-*", "payload.artifact_type"),
        _time_range("agentropix-findings-*,agentropix-timeline-*"),
    )
    counts = {
        "findings": results[0],
        "timeline": results[1],
        "evidence": results[2],
        "iocs": results[3],
        "approvals": results[4],
    }
    top_hosts: list[IdxAggregateBucket] = results[5]
    top_artifact_types: list[IdxAggregateBucket] = results[6]
    time_range = results[7]
    hints = _build_hints(counts, top_hosts, top_artifact_types)

    return IdxCaseSummaryResult(
        case_id=resolved_case_id,
        per_index_counts=counts,
        top_hosts=top_hosts,
        top_artifact_types=top_artifact_types,
        time_range=time_range,
        next_step_hints=hints,
    )
