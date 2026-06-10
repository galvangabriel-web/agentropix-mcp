"""WZ-002 (master report §4.4 #16): Wazuh Indexer client.

Foundation for WZ-001 (`wazuh_hunt_ioc` Step-2 retro-hunt over
``wazuh-alerts-*``) and WZ-006 (`wazuh_vuln_query` against
``wazuh-states-vulnerabilities-*``). Sits separately from
``WazuhClient`` because the Indexer (OpenSearch fork on :9200) has a
different host:port + Basic Auth chain than the Manager API (:55000
with JWT).

Module also exports the shared ``_wazuh_retry_policy()`` tenacity
helper used by every network-touching tool — keeping retry / backoff /
jitter consistent across the wrappers package per master-report C4
F5. Per WZ-021 (filed in §4.4 #16a, not yet shipped) the same module
will host the ``_safe_tool`` decorator + ``Finding`` discriminated-
union ADR; today this file ships the IndexerClient + retry-policy
foundation only.

The Indexer responses are JSON; this client returns parsed dicts on
2xx, raises ``IndexerError`` on non-2xx. Best-effort behavior (return
empty / raise WazuhError-style) is left to the orchestrator helpers
(see ``health.py`` for the WLV-06 best-effort pattern).
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

logger = logging.getLogger(__name__)

__all__ = [
    "IndexerClient",
    "IndexerError",
    "QueryTimeoutError",
    "TransientHTTPError",
    "wazuh_indexer_health",
]


class IndexerError(Exception):
    """Raised by IndexerClient on non-2xx responses or auth failures.

    Distinct from WazuhError (Manager API) so callers can catch
    Indexer-specific failures without false-matching Manager-API errors.
    """


class QueryTimeoutError(IndexerError):
    """Raised when a request exceeds the read/write/pool timeout.

    SIFT-W-298: a read timeout means the request reached the Indexer but
    the query ran longer than ``timeout_sec`` — retrying just re-runs the
    same expensive query and stacks N× the timeout, turning a bounded 30s
    failure into a multi-minute hang that blows past the MCP client
    ceiling and orphans the in-flight ``tool_use`` (the ``wazuh_hunt_ioc``
    4-minute hang, same defect class as BUG-003).

    Subclasses ``IndexerError`` (NOT ``TransientHTTPError``) precisely so
    the shared ``_wazuh_retry_policy`` does NOT retry it — a slow query is
    not a transient fault. The orchestrator's ``except (TransientHTTPError,
    IndexerError)`` outage handlers still catch it as a fail-soft outage,
    and on the write path it additionally prevents a retry-induced
    double-index.
    """


class TransientHTTPError(Exception):
    """Marker for retry-eligible HTTP errors (5xx, connect timeouts).

    Also used by future WZ-021 ``_safe_tool`` decorator + the rest of
    the wrappers package via the shared ``_wazuh_retry_policy``.
    Subclassing Exception (not WazuhError / IndexerError) so a single
    classifier in the retry decorator catches transient failures
    across both clients.
    """


# =============================================================================
# Shared tenacity retry policy (master-report C4 F5)
# =============================================================================
#
# Every network-touching tool in the wrappers package SHOULD reference
# this helper rather than rolling its own backoff. Centralising the
# policy keeps:
#   - jitter shape consistent (wait_exponential_jitter, initial=1s, max=30s)
#   - max attempts consistent (5)
#   - retry classifier consistent (TransientHTTPError only — never
#     application-level errors like AuthError or 4xx)
#   - log shape consistent (tenacity logs each attempt)
#
# Future migration: when WZ-021 lands its ``_safe_tool`` decorator,
# the decorator will compose this policy with the flat-error-envelope
# wrapper so callers get retry + envelope without per-tool boilerplate.


def _wazuh_retry_policy():
    """Return a tenacity retry decorator for network-touching tools.

    Use as::

        @_wazuh_retry_policy()
        async def some_indexer_call(self):
            ...

    Or apply at the call site of a one-shot helper. The decorator only
    retries on ``TransientHTTPError``; deliberate raises for
    auth failures / 4xx / Pydantic validation propagate immediately.
    """
    return retry(
        retry=retry_if_exception_type(TransientHTTPError),
        wait=wait_exponential_jitter(initial=1.0, max=30.0),
        stop=stop_after_attempt(5),
        reraise=True,
    )


def _classify_http_status(status_code: int) -> bool:
    """Return True if the status code is retry-eligible.

    Retry on 5xx (server errors that may be transient) but NOT on 4xx
    (client errors that won't change on retry).
    """
    return 500 <= status_code < 600


# =============================================================================
# IndexerClient
# =============================================================================


class IndexerClient:
    """Async client for the Wazuh Indexer (OpenSearch fork).

    Constructed with the resolved indexer URL + Basic Auth credentials
    + TLS settings from ``WazuhConfig``. Holds a long-lived
    ``httpx.AsyncClient`` so connection-pool reuse keeps p95 latency
    in the ~25-30ms range observed in T-LIVE §3.

    Lifetime:
        Construct once per orchestrator run. Call ``aclose()`` at
        end-of-run (try/finally pattern from F-11). The
        ``__aenter__`` / ``__aexit__`` methods support ``async with``.

    Errors:
        - ``IndexerError`` raised on non-2xx (with status + body fragment)
        - ``TransientHTTPError`` raised on 5xx (eligible for retry via
          ``_wazuh_retry_policy``)
        - ``httpx.ConnectError`` / ``httpx.ReadTimeout`` propagate as
          ``TransientHTTPError`` (reclassified at the boundary)
    """

    def __init__(
        self,
        *,
        indexer_url: str,
        indexer_user: str,
        indexer_password: str,
        tls_verify: bool = True,
        tls_ca_bundle: str | None = None,
        timeout_sec: float = 30.0,
    ) -> None:
        if not indexer_url:
            raise ValueError(
                "IndexerClient requires indexer_url; set WAZUH_INDEXER_URL or pass via WazuhConfig.indexer_url"
            )
        if not indexer_user or not indexer_password:
            raise ValueError(
                "IndexerClient requires indexer_user + indexer_password; "
                "set WAZUH_INDEXER_USER and WAZUH_INDEXER_PASS in env"
            )
        self._url = indexer_url.rstrip("/")
        self._auth_header = "Basic " + base64.b64encode(
            f"{indexer_user}:{indexer_password}".encode()
        ).decode("ascii")
        self._timeout_sec = timeout_sec
        verify: bool | str = tls_verify
        if tls_verify and tls_ca_bundle:
            verify = tls_ca_bundle
        self._client = httpx.AsyncClient(
            verify=verify,
            timeout=httpx.Timeout(timeout_sec),
            headers={
                "Authorization": self._auth_header,
                "Content-Type": "application/json",
            },
        )

    async def __aenter__(self) -> IndexerClient:
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying httpx client. Idempotent + best-effort."""
        try:
            await self._client.aclose()
        except Exception as exc:
            logger.debug("IndexerClient aclose suppressed exception: %s", exc)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict | None = None,
    ) -> dict:
        """Issue a request, classify errors, return parsed JSON.

        Reclassifies httpx network exceptions to TransientHTTPError so
        the shared retry policy catches them.
        """
        url = f"{self._url}{path}"
        try:
            response = await self._client.request(method=method, url=url, json=json_body)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            # Connect-leg failures are genuinely transient (service
            # restarting, brief network blip): retry-eligible.
            raise TransientHTTPError(
                f"{method} {path} network failure: {type(exc).__name__}: {exc}"
            ) from exc
        except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as exc:
            # SIFT-W-298: the request reached the Indexer but ran past the
            # timeout. NOT transient — retrying re-runs the same expensive
            # query and stacks N× the timeout (the wazuh_hunt_ioc hang).
            raise QueryTimeoutError(
                f"{method} {path} timed out after {self._timeout_sec}s: {type(exc).__name__}"
            ) from exc

        if _classify_http_status(response.status_code):
            # Retry-eligible 5xx.
            raise TransientHTTPError(
                f"{method} {path} returned {response.status_code}: {response.text[:200]}"
            )
        if response.status_code >= 400:
            # Non-retry 4xx — surface as IndexerError.
            raise IndexerError(
                f"{method} {path} returned {response.status_code}: {response.text[:200]}"
            )
        try:
            return response.json()
        except Exception as exc:
            raise IndexerError(
                f"{method} {path} returned 2xx but body is not valid JSON: {exc}"
            ) from exc

    async def cluster_health(self) -> dict:
        """GET /_cluster/health.

        Returns the raw payload — caller decides what counts as healthy.
        Per master-report §1.1 the production cluster reports
        ``status: "green"`` with ``active_shards: 35`` (35/35).
        """
        return await self._request("GET", "/_cluster/health")

    async def _request_ndjson(
        self,
        path: str,
        body_bytes: bytes,
    ) -> dict:
        """POST NDJSON to the Indexer (``_bulk`` uses application/x-ndjson).

        Mirrors ``_request`` error classification (5xx -> TransientHTTPError,
        4xx -> IndexerError) but sends a raw byte body with the bulk
        content-type so each action/doc pair is parsed correctly.
        """
        url = f"{self._url}{path}"
        try:
            response = await self._client.request(
                method="POST",
                url=url,
                content=body_bytes,
                headers={"Content-Type": "application/x-ndjson"},
            )
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            # Connect-leg failures are genuinely transient: retry-eligible.
            raise TransientHTTPError(
                f"POST {path} network failure: {type(exc).__name__}: {exc}"
            ) from exc
        except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as exc:
            # SIFT-W-298: timed out mid-flight. NOT transient — on the bulk
            # write path retrying could also double-index. Surface as a
            # non-retryable QueryTimeoutError (caught as outage upstream).
            raise QueryTimeoutError(
                f"POST {path} timed out after {self._timeout_sec}s: {type(exc).__name__}"
            ) from exc

        if _classify_http_status(response.status_code):
            raise TransientHTTPError(
                f"POST {path} returned {response.status_code}: {response.text[:200]}"
            )
        if response.status_code >= 400:
            raise IndexerError(
                f"POST {path} returned {response.status_code}: {response.text[:200]}"
            )
        try:
            return response.json()
        except Exception as exc:
            raise IndexerError(
                f"POST {path} returned 2xx but body is not valid JSON: {exc}"
            ) from exc

    async def bulk_index(
        self,
        index: str,
        docs: list[dict],
    ) -> dict:
        """POST /_bulk to index ``docs`` into ``index``.

        WZ-022 (W-274): foundation for the evidence-indexing path. Each
        doc in ``docs`` becomes an ``index`` action against ``index``;
        the Indexer auto-generates ``_id``. The response is the raw
        ``_bulk`` payload (callers can inspect per-item ``errors`` /
        ``items[*].index.status`` for fine-grained handling), but if the
        top-level ``errors`` flag is ``true`` this method raises
        ``IndexerError`` with a short summary of the first failing item
        so a fire-and-forget caller surfaces the failure immediately.

        Args:
            index: target index name (e.g. ``agentropix-findings-2026.05.25``)
                or a write alias. Must be a concrete index name — bulk
                does not accept patterns.
            docs: list of documents to index. Empty list returns an empty
                ``items: []`` shaped envelope without issuing a request
                (saves a network round-trip + a guaranteed 2xx echo).

        Raises:
            ValueError: empty ``index`` or any non-dict element in ``docs``.
            IndexerError: bulk response has ``errors: true``, or transport
                returned 4xx, or 2xx body was not valid JSON.
            TransientHTTPError: 5xx or network failure (retry-eligible via
                ``_wazuh_retry_policy``).
        """
        if not index:
            raise ValueError("bulk_index requires a non-empty index name")
        if not docs:
            return {"took": 0, "errors": False, "items": []}
        for i, doc in enumerate(docs):
            if not isinstance(doc, dict):
                raise ValueError(f"bulk_index docs[{i}] must be a dict, got {type(doc).__name__}")

        action = json.dumps({"index": {"_index": index}}, separators=(",", ":"))
        lines: list[str] = []
        for doc in docs:
            lines.append(action)
            lines.append(json.dumps(doc, separators=(",", ":")))
        body = ("\n".join(lines) + "\n").encode("utf-8")

        result = await self._request_ndjson("/_bulk", body)

        if result.get("errors"):
            first_failure_summary = "unknown"
            for item in result.get("items", []):
                op = item.get("index") or {}
                err = op.get("error")
                if err:
                    first_failure_summary = (
                        f"index={op.get('_index')} status={op.get('status')} "
                        f"type={err.get('type')} reason={err.get('reason')}"
                    )
                    break
            raise IndexerError(
                f"_bulk returned errors:true; first failure: {first_failure_summary}"
            )
        return result

    async def put_index_template(
        self,
        name: str,
        body: dict,
    ) -> dict:
        """PUT /_index_template/<name> to install or replace a template.

        WZ-022 (W-274): used to register ``AGENTROPIX_FINDINGS_TEMPLATE``
        before the first ``bulk_index`` call. Idempotent on the OpenSearch
        side: a subsequent PUT with the same body is a no-op replace.

        Args:
            name: template name (e.g. ``agentropix-findings``).
            body: full template body — see
                ``agentropix_mcp.wazuh.index_templates`` for the
                expected shape.
        """
        if not name:
            raise ValueError("put_index_template requires a non-empty name")
        if not isinstance(body, dict) or "index_patterns" not in body:
            raise ValueError("put_index_template body must be a dict containing 'index_patterns'")
        return await self._request("PUT", f"/_index_template/{name}", json_body=body)

    async def put_ism_policy(
        self,
        name: str,
        body: dict,
    ) -> dict:
        """PUT /_plugins/_ism/policies/<name> to install or replace an
        Index State Management policy.

        WZ-022 (W-277): used to register the Agentropix findings
        retention policy alongside the W-274 template install. The
        OpenSearch ISM plugin (shipped with Wazuh Dashboard) auto-binds
        the policy to matching new indices via the ``ism_template``
        block in the body.

        Args:
            name: policy name (e.g. ``agentropix-findings``).
            body: full policy body. Must contain a ``policy`` key per
                OpenSearch ISM spec.
        """
        if not name:
            raise ValueError("put_ism_policy requires a non-empty name")
        if not isinstance(body, dict) or "policy" not in body:
            raise ValueError("put_ism_policy body must be a dict containing 'policy'")
        return await self._request("PUT", f"/_plugins/_ism/policies/{name}", json_body=body)

    async def index_one(
        self,
        index: str,
        doc: dict,
        *,
        doc_id: str | None = None,
    ) -> dict:
        """SIFT-W-289: index a single document with an optional explicit ``_id``.

        Wraps ``bulk_index`` so the same error-classification +
        ndjson-framing path is reused; the only difference is the
        action line carries ``_id`` when supplied — needed for the
        ``agentropix-cases`` upsert pattern where the case_id doubles
        as the OpenSearch doc id (idempotent ``case_init``).

        Args:
            index: target concrete index name.
            doc: document body.
            doc_id: optional explicit ``_id``; when ``None`` OpenSearch
                auto-generates.

        Returns:
            The first item from the ``_bulk`` ``items`` array (the
            per-doc result) for ergonomic single-doc callers.
        """
        if not index:
            raise ValueError("index_one requires a non-empty index name")
        if not isinstance(doc, dict):
            raise ValueError(f"index_one doc must be a dict, got {type(doc).__name__}")
        action_payload: dict = {"_index": index}
        if doc_id is not None:
            if not isinstance(doc_id, str) or not doc_id:
                raise ValueError("doc_id must be a non-empty string")
            action_payload["_id"] = doc_id
        action = json.dumps({"index": action_payload}, separators=(",", ":"))
        body = (action + "\n" + json.dumps(doc, separators=(",", ":")) + "\n").encode("utf-8")
        result = await self._request_ndjson("/_bulk", body)
        if result.get("errors"):
            items = result.get("items") or []
            first = items[0] if items else {}
            op = first.get("index") or {}
            err = op.get("error") or {}
            raise IndexerError(
                f"index_one returned errors:true; status={op.get('status')} "
                f"type={err.get('type')} reason={err.get('reason')}"
            )
        items = result.get("items") or []
        return items[0] if items else {}

    async def count(
        self,
        index_pattern: str,
        query: dict | None = None,
    ) -> int:
        """SIFT-W-289: count documents matching ``query`` in ``index_pattern``.

        Used by ``case_status`` and ``idx_case_summary`` for fast
        per-index counts without paying the cost of hydrating
        document bodies. Returns ``0`` when the index doesn't exist
        yet (404) — a fresh case has no documents in any sibling
        index, and that's not an error.

        Args:
            index_pattern: e.g. ``"agentropix-findings-*"`` or a
                concrete index. Patterns are valid for ``_count``.
            query: optional ``{"query": {...}}`` body. ``None`` ⇒
                count all docs.

        Returns:
            Integer hit count.
        """
        body: dict = {}
        if query is not None:
            body = query if "query" in query else {"query": query}
        try:
            result = await self._request("POST", f"/{index_pattern}/_count", json_body=body)
        except IndexerError as exc:
            # 404 on a fresh case is benign — every sibling index gets
            # created lazily on first ingest. Surface as zero.
            # SIFT-W-296d (Critic D): match the specific "returned 404"
            # signature `_request` emits, not a bare "404" substring
            # (which would also swallow a doc-count of 404, a "404" in a
            # reason string, etc.).
            msg = str(exc)
            if "returned 404" in msg or "index_not_found_exception" in msg:
                return 0
            raise
        return int(result.get("count", 0))

    async def search(
        self,
        index_pattern: str,
        query: dict,
        *,
        size: int = 100,
    ) -> dict:
        """POST /<index_pattern>/_search with the given query body.

        WZ-001 (when it lands) wraps this with the IOC->DSL translation
        layer (term queries against keyword fields, match_phrase for
        analysed text, MITRE-id carry-through, etc.). For now this is
        the raw escape hatch.

        Args:
            index_pattern: e.g. "wazuh-alerts-*", "wazuh-states-vulnerabilities-*"
            query: full query body (will be wrapped under "query" if
                operator passes a bare clause; otherwise sent as-is)
            size: page size (capped at 500 by master-report §F4.4
                capacity envelope; future WZ-001 paginates via scroll
                for >500 hits)
        """
        if size <= 0 or size > 500:
            raise ValueError("size must be in 1..500 (capacity envelope §F4.4)")
        # Detect bare clause vs full body.
        body = query if "query" in query else {"query": query}
        body["size"] = size
        return await self._request("POST", f"/{index_pattern}/_search", json_body=body)

    async def delete_by_query(
        self,
        index_pattern: str,
        query: dict,
    ) -> int:
        """NIST1 RUN3 ISSUE-014: POST /<index_pattern>/_delete_by_query.

        Removes documents matching ``query`` and returns the number deleted.
        Used by ``delete_finding`` to let an autonomous run self-correct an
        over-count without abandoning the case. Returns 0 when the index does
        not exist yet (404) — nothing to delete is not an error.

        Args:
            index_pattern: e.g. ``"agentropix-findings-*"``.
            query: full ``{"query": {...}}`` body, or a bare clause (wrapped).

        Returns:
            Integer count of deleted documents.
        """
        body = query if "query" in query else {"query": query}
        try:
            result = await self._request(
                "POST", f"/{index_pattern}/_delete_by_query", json_body=body
            )
        except Exception as exc:
            if "404" in str(exc):
                return 0
            raise
        return int(result.get("deleted", 0))


# =============================================================================
# Health probe
# =============================================================================


async def wazuh_indexer_health(
    client: IndexerClient,
) -> dict:
    """WZ-002 health probe.

    Returns a structured dict suitable for the future WZ-003
    ``wazuh_health()`` aggregator::

        {
            "indexer_reachable": bool,
            "cluster_status": str | None,   # "green" / "yellow" / "red"
            "active_shards": int | None,
            "active_shards_percent": float | None,
            "number_of_nodes": int | None,
            "error": str | None,
        }

    Best-effort: a transient indexer failure surfaces as
    ``indexer_reachable: False`` + ``error: <type>`` rather than
    raising. The aggregator at WZ-003 layer aggregates this with the
    Manager-API health + DLQ + CDB-load probes.
    """
    try:
        payload = await client.cluster_health()
    except (IndexerError, TransientHTTPError) as exc:
        logger.warning("wazuh_indexer_health: %s: %s", type(exc).__name__, exc)
        return {
            "indexer_reachable": False,
            "cluster_status": None,
            "active_shards": None,
            "active_shards_percent": None,
            "number_of_nodes": None,
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "indexer_reachable": True,
        "cluster_status": payload.get("status"),
        "active_shards": payload.get("active_shards"),
        "active_shards_percent": payload.get("active_shards_percent_as_number"),
        "number_of_nodes": payload.get("number_of_nodes"),
        "error": None,
    }
