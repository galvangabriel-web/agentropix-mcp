"""SIFT-W-294 (Phase 2): IndexerClient-backed ApprovalWriter + prev_approval_hash backfill.

Production wiring for the sidecar's pluggable ``ApprovalWriter``. Wraps
``IndexerClient.bulk_index`` so the sidecar can write its
``agentropix-approvals-YYYY.MM.DD`` documents using the dedicated
*approver* credential — separate from the *writer* credential the
MCP server uses for findings (Crew #3's dual-credential split).

Also adds the prev_approval_hash backfill: before each /approve
write, query the approvals index for the most-recent approval
targeting the same ``target_id`` (filtered by ``case_id`` for
defence-in-depth) and compute the chain hash. The first approval
for a target gets the empty string; every subsequent one closes
the chain.
"""

from __future__ import annotations

import logging
from typing import Any

from agentropix_mcp.approval_sidecar.config import SidecarConfig
from agentropix_mcp.approval_sidecar.hash_chain import (
    compute_prev_approval_hash,
)

logger = logging.getLogger(__name__)


APPROVALS_INDEX_PATTERN = "agentropix-approvals-*"
FINDINGS_INDEX_PATTERN = "agentropix-findings-*"
TIMELINE_INDEX_PATTERN = "agentropix-timeline-*"


def _build_client(cfg: SidecarConfig):
    """Construct an IndexerClient from sidecar config (approver creds).

    Honors WAZUH_INDEXER_TLS_VERIFY like the writer path (default strict).
    Caller owns the returned client and must aclose() it.
    """
    import os

    from agentropix_mcp.wazuh.indexer_client import IndexerClient

    tls_verify_raw = os.environ.get("WAZUH_INDEXER_TLS_VERIFY", "true").strip().lower()
    tls_verify = tls_verify_raw not in {"false", "0", "no", "off"}
    return IndexerClient(
        indexer_url=cfg.indexer_url,
        indexer_user=cfg.indexer_user,
        indexer_password=cfg.indexer_password,
        tls_verify=tls_verify,
    )


def build_indexer_backed_reader(
    cfg: SidecarConfig,
    *,
    client_factory: Any = None,
):
    """Return an ``ApprovalReader`` for the BUG-001 precondition gate.

    Looks up ``(case_id, target_id)`` in the findings (or timeline) index and
    returns the record's current ``approval.status`` (e.g. ``"DRAFT"``), or
    ``None`` when the target does not exist in the case. The sidecar refuses to
    sign when this returns None (target_not_found) or a status that doesn't
    match the asserted from_status (precondition_failed).
    """

    async def _reader(case_id: str, target_id: str, target_type: str) -> str | None:
        owns_client = client_factory is None
        client = client_factory(cfg) if client_factory is not None else _build_client(cfg)
        try:
            if target_type == "approval":
                # Retraction precondition (idempotency guard): the target is an
                # approval_id, not a finding. Look it up in the approvals index.
                #   - no such approval_id            -> None (target_not_found)
                #   - a VOID (to_status=REVOKED) for this approval_id already
                #     exists                          -> "REVOKED" (so a
                #     from_status=APPROVED retraction trips precondition_failed,
                #     blocking duplicate VOIDs — the bug where re-submitting the
                #     same approval_id kept appending new REVOKED rows)
                #   - otherwise                       -> "APPROVED" (retractable)
                resp = await client.search(
                    APPROVALS_INDEX_PATTERN,
                    {"query": {"bool": {"filter": [{"term": {"approval_id": target_id}}]}}},
                    size=1,
                )
                if not (((resp or {}).get("hits") or {}).get("hits") or []):
                    return None
                void = await client.search(
                    APPROVALS_INDEX_PATTERN,
                    {
                        "query": {
                            "bool": {
                                "filter": [
                                    {"term": {"target_id": target_id}},
                                    {"term": {"to_status": "REVOKED"}},
                                ]
                            }
                        }
                    },
                    size=1,
                )
                if ((void or {}).get("hits") or {}).get("hits") or []:
                    return "REVOKED"
                return "APPROVED"
            pattern = (
                TIMELINE_INDEX_PATTERN if target_type == "timeline" else FINDINGS_INDEX_PATTERN
            )
            id_field = "event_id" if target_type == "timeline" else "finding_id"
            resp = await client.search(
                pattern,
                {
                    "query": {
                        "bool": {
                            "filter": [
                                {"term": {"case_id": case_id}},
                                {"term": {id_field: target_id}},
                            ]
                        }
                    }
                },
                size=1,
            )
            hits = ((resp or {}).get("hits") or {}).get("hits") or []
            if not hits:
                return None
            src = hits[0].get("_source") or {}
            approval = src.get("approval") or {}
            return str(approval.get("status") or src.get("approval_status") or "DRAFT")
        finally:
            if owns_client and hasattr(client, "aclose"):
                try:
                    await client.aclose()
                except Exception:
                    pass

    return _reader


def build_indexer_backed_writer(
    cfg: SidecarConfig,
    *,
    client_factory: Any = None,
):
    """Return an ``ApprovalWriter`` that writes through ``IndexerClient``.

    The factory pattern keeps unit tests cheap — they pass a stub
    factory. Production code uses the default, which constructs an
    ``IndexerClient`` from ``cfg`` with the *approver* credentials.

    The returned coroutine signature matches
    ``approval_sidecar.app.ApprovalWriter`` exactly so it slots
    into ``build_app(writer=...)``.
    """

    async def _writer(doc: dict, index: str) -> str:
        # SIFT-W-294: backfill prev_approval_hash by querying the
        # immediately-prior approval for the same target_id. The
        # client is constructed per-write so a long-lived sidecar
        # process picks up cert rotations naturally (matches the
        # orchestrator pattern in wazuh/orchestrator.py).
        # SIFT-W-296c (Critic B fix): when we construct the client
        # ourselves, we own its httpx connection pool and MUST close it
        # — the prior code leaked one pool per approval write. A
        # factory-supplied client (tests) is owned by the caller and
        # left open.
        owns_client = client_factory is None
        if client_factory is not None:
            client = client_factory(cfg)
        else:
            import os

            from agentropix_mcp.wazuh.indexer_client import IndexerClient

            # SIFT-W-296 fix: honor the existing WAZUH_INDEXER_TLS_VERIFY
            # env var the rest of the integration uses, so a
            # self-signed-cert deployment doesn't break the sidecar
            # writer with CERTIFICATE_VERIFY_FAILED. Default True so
            # production deployments stay strict by default.
            tls_verify_raw = os.environ.get("WAZUH_INDEXER_TLS_VERIFY", "true").strip().lower()
            tls_verify = tls_verify_raw not in {"false", "0", "no", "off"}
            client = IndexerClient(
                indexer_url=cfg.indexer_url,
                indexer_user=cfg.indexer_user,
                indexer_password=cfg.indexer_password,
                tls_verify=tls_verify,
            )

        try:
            # 1) Look up the most-recent prior approval for this CASE.
            # BUG-002: the chain is scoped per-case_id, NOT per-target_id.
            # The prior code filtered by (case_id, target_id), so a case with
            # N distinct findings produced N independent single-entry chains —
            # every approval was the genesis of its own chain and thus carried
            # prev_approval_hash="" (the observed symptom: all entries empty). Chaining
            # per-case links the full approval sequence so any retroactive
            # edit/removal/insert breaks the chain and is detectable.
            case_id = doc.get("case_id", "")
            target_id = doc.get("target_id", "")
            try:
                search_resp = await client.search(
                    APPROVALS_INDEX_PATTERN,
                    {
                        "query": {"bool": {"filter": [{"term": {"case_id": case_id}}]}},
                        "sort": [{"@timestamp": {"order": "desc", "missing": "_last"}}],
                    },
                    size=1,
                )
            except Exception as exc:
                # The very first approval for a fresh case lands against a 404
                # (no daily index yet). Treat as genesis; log+continue. A real
                # outage surfaces from bulk_index below, fatal for this approval.
                logger.info(
                    "ApprovalWriter prev-approval lookup miss (case=%s target=%s): %s",
                    case_id,
                    target_id,
                    exc,
                )
                search_resp = {"hits": {"hits": []}}

            prior_hits = ((search_resp.get("hits") or {}).get("hits")) or []
            if prior_hits:
                prior_src = prior_hits[0].get("_source") or {}
                doc["prev_approval_hash"] = compute_prev_approval_hash(
                    prior_src.get("approval_id", ""),
                    prior_src.get("hmac_signature", ""),
                )
            else:
                doc["prev_approval_hash"] = ""

            # 2) Write the doc. agentropix-approvals-* template is
            #    ``dynamic: strict`` (W-285), so any stray field we
            #    accidentally added would surface here as
            #    mapper_parsing_exception — defence in depth against
            #    a future bug that injects fields.
            resp = await client.bulk_index(index, [doc])
            items = (resp or {}).get("items") or []
            if not items:
                raise RuntimeError("indexer accepted bulk but returned empty items array")
            op = items[0].get("index") or {}
            if "error" in op or op.get("status", 200) >= 400:
                raise RuntimeError(
                    f"approval index write failed: status={op.get('status')} "
                    f"error={op.get('error')}"
                )
            return doc.get("approval_id", "")
        finally:
            if owns_client and hasattr(client, "aclose"):
                try:
                    await client.aclose()
                except Exception:
                    pass

    return _writer


async def verify_approval_chain(
    case_id: str,
    *,
    client: Any = None,
    cfg: SidecarConfig | None = None,
) -> dict:
    """BUG-002: walk a case's approval chain and report the first break.

    Reads every approval for ``case_id`` in chronological order and, for each
    entry after the genesis, recomputes ``compute_prev_approval_hash`` from the
    predecessor's (approval_id, hmac_signature) and compares it to the stored
    ``prev_approval_hash``. A mismatch (or a non-empty hash on the genesis, or
    an empty hash on a non-genesis entry) means a row was deleted, mutated, or
    inserted out of order.

    Returns ``{"case_id", "count", "intact": bool, "first_break": {...}|None}``.
    Caller may inject ``client`` (tests); otherwise one is built from ``cfg``.
    """
    owns_client = client is None
    if client is None:
        if cfg is None:
            cfg = SidecarConfig.from_env()
        client = _build_client(cfg)
    try:
        resp = await client.search(
            APPROVALS_INDEX_PATTERN,
            {
                "query": {"bool": {"filter": [{"term": {"case_id": case_id}}]}},
                "sort": [{"@timestamp": {"order": "asc", "missing": "_last"}}],
            },
            # IndexerClient caps size at 500 (capacity envelope §F4.4); 1000
            # raised ValueError and crashed every verify call. A single case's
            # approval count is far below 500 in practice.
            size=500,
        )
        hits = ((resp or {}).get("hits") or {}).get("hits") or []
        rows = [h.get("_source") or {} for h in hits]
        first_break = None
        for i, row in enumerate(rows):
            stored = row.get("prev_approval_hash", "")
            if i == 0:
                expected = ""
            else:
                prev = rows[i - 1]
                expected = compute_prev_approval_hash(
                    prev.get("approval_id", ""), prev.get("hmac_signature", "")
                )
            if stored != expected:
                first_break = {
                    "position": i,
                    "approval_id": row.get("approval_id", ""),
                    "target_id": row.get("target_id", ""),
                    "stored_prev_hash": stored,
                    "expected_prev_hash": expected,
                }
                break
        return {
            "case_id": case_id,
            "count": len(rows),
            "intact": first_break is None,
            "first_break": first_break,
        }
    finally:
        if owns_client and hasattr(client, "aclose"):
            try:
                await client.aclose()
            except Exception:
                pass
