"""SIFT-W-291: record_finding / record_timeline_event / approve_finding / report_generate.

Final 4 of the 13 P0 MCP tools from the Valhuntir-on-Wazuh SYNTHESIS.

  * ``record_finding``         — single-doc convenience wrapper over
                                 ``wazuh_index_findings`` (W-274 +
                                 W-286 gate). Caller passes one finding
                                 dict; wrapper routes through the gate
                                 + orchestrator unchanged.

  * ``record_timeline_event``  — single-event variant of W-290's
                                 idx_ingest timeline half.

  * ``approve_finding``        — HTTP client into the W-288 sidecar's
                                 ``/challenge`` + ``/approve`` flow.
                                 Operator supplies the approver password
                                 as a parameter (MVP); Phase 2 will
                                 replace this with a browser-launcher
                                 flow that keeps the password out of
                                 LLM context.

  * ``report_generate``        — 6 profiles (Crew #4): full, executive,
                                 timeline, ioc, findings, status. Each
                                 builds different OS queries; only
                                 APPROVED findings appear.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Literal

from pydantic import BaseModel, Field

from agentropix_mcp.wrappers.case_ingest import (
    _stamp_timeline_event,
    _today_timeline_index,
)
from agentropix_mcp.wrappers.case_lifecycle import (
    APPROVALS_INDEX_PATTERN,
    FINDINGS_INDEX_PATTERN,
    IOCS_INDEX_PATTERN,
    TIMELINE_INDEX_PATTERN,
    get_active_case_id,
)
from agentropix_mcp.wrappers.case_queries import (
    RESULT_MAX_BYTES,  # noqa: F401 — read via module attr (_self.RESULT_MAX_BYTES) + monkeypatched in tests
    _case_filter,
    _wrap_with_case_filter,
)

logger = logging.getLogger(__name__)


ReportProfile = Literal["full", "executive", "timeline", "ioc", "findings", "status"]


# --- Pydantic results ------------------------------------------------- #


class RecordFindingResult(BaseModel):
    case_id: str
    finding_id: str
    indexed: bool
    indexed_to: str = ""
    error: str = ""
    # NIST1 RUN3 ISSUE-014: True when a finding with the same
    # (case_id, finding_id) already existed and this call was suppressed
    # (no second append) — makes record_finding idempotent so re-runs don't
    # silently inflate the case finding count.
    duplicate: bool = False


class RecordTimelineResult(BaseModel):
    case_id: str
    event_id: str
    hostname: str
    indexed: bool
    indexed_to: str = ""
    error: str = ""


class ApproveFindingResult(BaseModel):
    case_id: str
    finding_id: str
    approval_id: str = ""
    to_status: str = ""
    indexed_to: str = ""
    approved_at: str = ""
    error: str = ""
    error_code: str = ""


class ReportGenerateResult(BaseModel):
    case_id: str
    profile: str
    report_id: str
    snapshot_at: str
    approved_finding_count: int = 0
    sections: dict[str, Any] = Field(default_factory=dict)
    # SIFT-W-296c: byte-budget transparency. truncated=True means heavy
    # section row-lists were trimmed to fit the 1MB MCP result envelope.
    truncated: bool = False
    result_bytes: int = 0
    error: str = ""
    # NIST1 ISSUE-009: non-empty when an approval-filtered profile returned
    # zero APPROVED findings while DRAFT findings exist (autonomous runs have
    # 0 approvals by design) — so an empty report is not misread as "found
    # nothing". Tells the caller to approve or use profile='status'.
    warning: str = ""


# --- record_finding --------------------------------------------------- #

# NIST1 RUN2 ISSUE-010: the findings index enforces field types that were
# undocumented at the tool surface — `confidence` is a float in [0,1] (see
# wazuh/finding_to_alert.py::confidence_to_wazuh_level) and `mitre_techniques`
# is a keyword[] (array of technique-id strings). Free-form findings with a
# string confidence or {id,name} technique objects were rejected only at
# index time with a raw `mapper_parsing_exception`. Coerce common shapes at
# the tool boundary so a human-natural finding indexes cleanly.
_CONFIDENCE_WORD_MAP = {
    "critical": 0.95,
    "very_high": 0.95,
    "high": 0.9,
    "medium": 0.6,
    "med": 0.6,
    "moderate": 0.6,
    "low": 0.3,
    "very_low": 0.15,
    "info": 0.1,
    "informational": 0.1,
}


def _coerce_confidence(value: object) -> float | None:
    """Coerce a confidence value to a float in [0,1].

    Accepts floats/ints (clamped), recognised words (high/medium/low/...),
    and numeric strings. Returns ``None`` when uncoercible so the caller can
    OMIT the field (letting the index default) rather than emit a mapper error.
    """
    if isinstance(value, bool):  # bool is an int subclass — reject explicitly
        return None
    if isinstance(value, (int, float)):
        return max(0.0, min(1.0, float(value)))
    if isinstance(value, str):
        key = value.strip().lower()
        if key in _CONFIDENCE_WORD_MAP:
            return _CONFIDENCE_WORD_MAP[key]
        try:
            return max(0.0, min(1.0, float(key)))
        except ValueError:
            return None
    return None


def _coerce_mitre_techniques(value: object) -> list[str]:
    """Coerce mitre_techniques to a list of technique-id keyword strings.

    Accepts ``["T1040", ...]`` (passthrough), ``[{"id"/"technique_id"/"name":...}]``
    (extract the id), or a bare string. Drops entries that yield no id.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str):
            if item.strip():
                out.append(item.strip())
        elif isinstance(item, dict):
            tid = item.get("id") or item.get("technique_id") or item.get("name")
            if isinstance(tid, str) and tid.strip():
                out.append(tid.strip())
    return out


def _normalize_finding(finding: dict) -> dict:
    """Return a COPY of ``finding`` with index-compatible field types
    (NIST1 RUN2 ISSUE-010). Non-destructive: the caller's dict is untouched.
    Only normalises fields when present; absent fields stay absent.
    """
    normalized = dict(finding)
    if "confidence" in normalized:
        coerced = _coerce_confidence(normalized["confidence"])
        if coerced is None:
            # Uncoercible → omit so the index default applies (no mapper error).
            normalized.pop("confidence", None)
        else:
            normalized["confidence"] = coerced
    if "mitre_techniques" in normalized:
        normalized["mitre_techniques"] = _coerce_mitre_techniques(normalized["mitre_techniques"])
    return normalized


async def record_finding(
    finding: dict,
    *,
    case_id: str | None = None,
    dry_run: bool = True,
    mutation_token: str | None = None,
    wazuh_index_findings_fn: Any = None,
    indexer_client: Any = None,
) -> RecordFindingResult:
    """Single-finding write API. Routes through ``wazuh_index_findings``
    so the W-286 draft-gate fires identically — the LLM cannot
    self-approve via this surface.

    NIST1 RUN3 ISSUE-014: when ``indexer_client`` is supplied, the call is
    idempotent on ``(case_id, finding_id)`` — if a finding with the same id
    already exists in the case it is NOT appended again; the result carries
    ``duplicate=True``. Without an indexer_client the legacy append behaviour
    is preserved (e.g. unit tests that inject only the gate fn)."""
    if not isinstance(finding, dict):
        raise ValueError(f"finding must be a dict, got {type(finding).__name__}")
    if not finding.get("finding_id"):
        raise ValueError("finding must contain a non-empty finding_id")

    resolved_case_id = case_id if case_id is not None else get_active_case_id()
    if resolved_case_id is None:
        raise ValueError("no active case; pass case_id= or call case_activate() first")

    finding_id = str(finding["finding_id"])

    # NIST1 RUN3 ISSUE-014: idempotency guard. record_finding appended a fresh
    # doc on every call (the index auto-generates _id), so a re-run or duplicate
    # call silently inflated counts.findings with no way to undo it. Pre-check
    # for an existing (case_id, finding_id) and suppress the second append.
    if indexer_client is not None:
        dup_query = {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"case_id": resolved_case_id}},
                        {"term": {"finding_id": finding_id}},
                    ]
                }
            }
        }
        try:
            existing = await indexer_client.count(FINDINGS_INDEX_PATTERN, dup_query)
        except Exception as exc:
            logger.warning("record_finding dedup check failed (proceeding): %s", exc)
            existing = 0
        if existing and int(existing) > 0:
            logger.info(
                "record_finding: %s already in case %s (%d) — suppressing duplicate",
                finding_id,
                resolved_case_id,
                int(existing),
            )
            return RecordFindingResult(
                case_id=resolved_case_id,
                finding_id=finding_id,
                indexed=False,
                duplicate=True,
            )

    # NIST1 RUN2 ISSUE-010: coerce confidence/mitre_techniques to the index's
    # field types at the boundary so a human-natural finding doesn't fail with
    # a raw mapper_parsing_exception at index time.
    finding = _normalize_finding(finding)

    if wazuh_index_findings_fn is None:
        return RecordFindingResult(
            case_id=resolved_case_id,
            finding_id=finding_id,
            indexed=False,
            error="wazuh_index_findings_fn not injected",
        )

    try:
        resp = await wazuh_index_findings_fn(
            findings=[finding],
            case_id=resolved_case_id,
            dry_run=dry_run,
            mutation_token=mutation_token,
        )
    except Exception as exc:
        logger.warning("record_finding: route failed: %s", exc)
        return RecordFindingResult(
            case_id=resolved_case_id,
            finding_id=finding_id,
            indexed=False,
            error=f"{type(exc).__name__}: {exc}",
        )

    if isinstance(resp, dict) and "error" in resp:
        return RecordFindingResult(
            case_id=resolved_case_id,
            finding_id=finding_id,
            indexed=False,
            error=str(resp["error"]),
        )

    indexed_to = str((resp or {}).get("index", ""))
    outcome = str((resp or {}).get("outcome", ""))
    indexed_count = int((resp or {}).get("indexed_count", 0))
    return RecordFindingResult(
        case_id=resolved_case_id,
        finding_id=finding_id,
        indexed=outcome == "indexed" and indexed_count > 0,
        indexed_to=indexed_to,
    )


# --- delete_finding (NIST1 RUN3 ISSUE-014) --------------------------- #


class DeleteFindingResult(BaseModel):
    case_id: str
    finding_id: str
    deleted: bool = False
    deleted_count: int = 0
    # True in dry_run when a DRAFT finding was found and WOULD be deleted.
    would_delete: bool = False
    found: bool = True
    # current approval status of the finding (for transparency / refusal reason).
    status: str = ""
    error: str = ""


async def delete_finding(
    finding_id: str,
    *,
    case_id: str | None = None,
    dry_run: bool = True,
    reason: str = "",
    indexer_client: Any = None,
) -> DeleteFindingResult:
    """Delete a DRAFT finding so an autonomous run can self-correct an
    over-count (NIST1 RUN3 ISSUE-014) without abandoning the case.

    Safety envelope:
      * DRAFT-only — refuses to delete an APPROVED/REJECTED/REVOKED finding
        (never an approval-workflow bypass; the examiner ledger is untouched).
      * ``dry_run=True`` by default — previews (``would_delete``) without
        mutating; a live delete requires an explicit ``dry_run=False``.
      * every deletion is logged to the audit trail with ``reason``.
    """
    if not finding_id or not isinstance(finding_id, str):
        raise ValueError("finding_id must be a non-empty string")

    resolved_case_id = case_id if case_id is not None else get_active_case_id()
    if resolved_case_id is None:
        raise ValueError("no active case; pass case_id= or call case_activate() first")

    if indexer_client is None:
        return DeleteFindingResult(
            case_id=resolved_case_id,
            finding_id=finding_id,
            deleted=False,
            error="indexer_client not injected",
        )

    scope = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"case_id": resolved_case_id}},
                    {"term": {"finding_id": finding_id}},
                ]
            }
        }
    }

    # Look up the current finding to read its approval status (DRAFT-only guard).
    try:
        hits = await indexer_client.search(FINDINGS_INDEX_PATTERN, scope, size=1)
    except Exception as exc:
        return DeleteFindingResult(
            case_id=resolved_case_id,
            finding_id=finding_id,
            deleted=False,
            error=f"lookup failed: {type(exc).__name__}: {exc}",
        )

    hit_list = (hits or {}).get("hits", {}).get("hits", [])
    if not hit_list:
        return DeleteFindingResult(
            case_id=resolved_case_id,
            finding_id=finding_id,
            deleted=False,
            found=False,
            error=f"finding {finding_id!r} not found in case {resolved_case_id}",
        )

    source = hit_list[0].get("_source", {})
    status = str((source.get("approval") or {}).get("status", "") or "")
    if status and status.upper() != "DRAFT":
        return DeleteFindingResult(
            case_id=resolved_case_id,
            finding_id=finding_id,
            deleted=False,
            status=status,
            error=(
                f"refusing to delete finding in status {status!r} — only DRAFT "
                "findings are deletable; use the examiner approval workflow for the rest"
            ),
        )

    if dry_run:
        return DeleteFindingResult(
            case_id=resolved_case_id,
            finding_id=finding_id,
            deleted=False,
            would_delete=True,
            status=status or "DRAFT",
        )

    # Live delete — scoped to this case_id + finding_id + DRAFT only.
    delete_query = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"case_id": resolved_case_id}},
                    {"term": {"finding_id": finding_id}},
                    {"term": {"approval.status": "DRAFT"}},
                ]
            }
        }
    }
    try:
        deleted = await indexer_client.delete_by_query(FINDINGS_INDEX_PATTERN, delete_query)
    except Exception as exc:
        return DeleteFindingResult(
            case_id=resolved_case_id,
            finding_id=finding_id,
            deleted=False,
            status=status or "DRAFT",
            error=f"delete failed: {type(exc).__name__}: {exc}",
        )
    logger.warning(
        "delete_finding: removed %d DRAFT doc(s) for %s in case %s (reason=%r)",
        int(deleted),
        finding_id,
        resolved_case_id,
        reason,
    )
    return DeleteFindingResult(
        case_id=resolved_case_id,
        finding_id=finding_id,
        deleted=int(deleted) > 0,
        deleted_count=int(deleted),
        status=status or "DRAFT",
    )


# --- record_timeline_event ------------------------------------------- #


async def record_timeline_event(
    event: dict,
    hostname: str,
    *,
    case_id: str | None = None,
    indexer_client: Any = None,
) -> RecordTimelineResult:
    """Single-event timeline write. Applies the same DRAFT / provenance /
    case_id stamping as ``idx_ingest`` then bulk-indexes one doc."""
    if not isinstance(event, dict):
        raise ValueError(f"event must be a dict, got {type(event).__name__}")
    if not event.get("event_id"):
        raise ValueError("event must contain a non-empty event_id")
    if not hostname or not isinstance(hostname, str):
        raise ValueError("hostname must be a non-empty string")

    resolved_case_id = case_id if case_id is not None else get_active_case_id()
    if resolved_case_id is None:
        raise ValueError("no active case; pass case_id= or call case_activate() first")

    event_id = str(event["event_id"])
    stamped = _stamp_timeline_event(event, resolved_case_id, hostname)
    indexed_to = _today_timeline_index()

    if indexer_client is None:
        return RecordTimelineResult(
            case_id=resolved_case_id,
            event_id=event_id,
            hostname=hostname,
            indexed=False,
            indexed_to=indexed_to,
            error="indexer_client not injected",
        )

    try:
        await indexer_client.bulk_index(indexed_to, [stamped])
    except Exception as exc:
        logger.warning("record_timeline_event: bulk_index failed: %s", exc)
        return RecordTimelineResult(
            case_id=resolved_case_id,
            event_id=event_id,
            hostname=hostname,
            indexed=False,
            indexed_to=indexed_to,
            error=f"{type(exc).__name__}: {exc}",
        )

    return RecordTimelineResult(
        case_id=resolved_case_id,
        event_id=event_id,
        hostname=hostname,
        indexed=True,
        indexed_to=indexed_to,
    )


# --- approve_finding ------------------------------------------------- #
#
# HTTP client into the W-288 sidecar. The MVP accepts the approver
# password as a parameter so the MCP tool can compute the PBKDF2 +
# HMAC server-side and forward the signed approval. The password is
# held transiently in process memory and dropped immediately; never
# logged. The trade-off is that the LLM's request context contains
# the password — operators uneasy with that should use the W-288
# Phase 2 browser UI instead (the MCP tool will gain a "launch_url"
# return mode then).


async def _http_post_json(
    url: str, body: dict, *, timeout_seconds: float = 30.0
) -> tuple[int, dict | None, str]:
    """Tiny httpx POST helper. Returns (status, json_or_None, raw_text)."""
    import httpx

    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        try:
            resp = await client.post(url, json=body)
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout) as exc:
            return 0, None, f"transport: {type(exc).__name__}: {exc}"
    try:
        data = resp.json()
    except Exception:
        data = None
    return resp.status_code, data, resp.text


async def approve_finding(
    finding_id: str,
    *,
    case_id: str | None = None,
    approver_id: str,
    password: str,
    to_status: Literal["APPROVED", "REJECTED", "REVOKED"] = "APPROVED",
    from_status: Literal["DRAFT", "APPROVED"] = "DRAFT",
    target_type: Literal["finding", "timeline", "approval"] = "finding",
    reason: str = "",
    sidecar_base_url: str = "http://127.0.0.1:8800",
    http_post_fn: Callable[..., Awaitable[tuple[int, dict | None, str]]] | None = None,
) -> ApproveFindingResult:
    """SIFT-W-291: HMAC-sign + submit an approval to the W-288 sidecar.

    Flow:
      1. POST /challenge → get nonce + salt + iterations.
      2. Compute PBKDF2 key locally; compute HMAC over the canonical
         message (mirrors the sidecar's ``build_signed_message``).
      3. POST /approve with the signed payload.
      4. Return the sidecar's approval_id + indexed_to.

    Password is consumed once and not stored on this side. The LLM
    context still contains it — Phase 2 fixes this by returning a
    browser launcher URL instead.

    Args:
        sidecar_base_url: defaults to ``http://127.0.0.1:8800`` for
            the same-workstation deployment (operator decision
            2026-05-27). Override via env at startup if remote.
    """
    if not finding_id or not isinstance(finding_id, str):
        raise ValueError("finding_id must be a non-empty string")
    if not approver_id or not isinstance(approver_id, str):
        raise ValueError("approver_id must be a non-empty string")
    if not password or not isinstance(password, str):
        raise ValueError("password must be a non-empty string")

    resolved_case_id = case_id if case_id is not None else get_active_case_id()
    if resolved_case_id is None:
        raise ValueError("no active case; pass case_id= or call case_activate() first")

    post = http_post_fn if http_post_fn is not None else _http_post_json

    # 1) Challenge.
    challenge_url = sidecar_base_url.rstrip("/") + "/challenge"
    status, ch_body, ch_text = await post(
        challenge_url,
        {
            "examiner_id": approver_id,
            "target_id": finding_id,
            "target_type": target_type,
        },
    )
    if status == 0 or ch_body is None:
        return ApproveFindingResult(
            case_id=resolved_case_id,
            finding_id=finding_id,
            error=f"sidecar unreachable at {challenge_url}: {ch_text[:200]}",
            error_code="sidecar_unreachable",
        )
    if status >= 400:
        return ApproveFindingResult(
            case_id=resolved_case_id,
            finding_id=finding_id,
            error=ch_body.get("error", ch_text[:200])
            if isinstance(ch_body, dict)
            else ch_text[:200],
            error_code=str(ch_body.get("code", "challenge_failed"))
            if isinstance(ch_body, dict)
            else "challenge_failed",
        )

    nonce = str(ch_body["nonce"])
    salt_hex = str(ch_body["salt_hex"])
    iterations = int(ch_body["iterations"])

    # 2) Derive key + sign. We import here so the sidecar package isn't
    #    a hard dependency of every MCP startup — only operators who
    #    actually approve pay the import cost.
    from agentropix_mcp.approval_sidecar.auth import (
        build_signed_message,
        derive_key,
        hmac_signature,
    )

    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return ApproveFindingResult(
            case_id=resolved_case_id,
            finding_id=finding_id,
            error="sidecar returned non-hex salt",
            error_code="bad_salt",
        )

    key = derive_key(password, salt, iterations=iterations)
    message = build_signed_message(
        nonce=nonce,
        target_id=finding_id,
        target_type=target_type,
        from_status=from_status,
        to_status=to_status,
        case_id=resolved_case_id,
    )
    signature_hex = hmac_signature(key, message)

    # 3) Submit approval.
    approve_url = sidecar_base_url.rstrip("/") + "/approve"
    status, ap_body, ap_text = await post(
        approve_url,
        {
            "case_id": resolved_case_id,
            "target_id": finding_id,
            "target_type": target_type,
            "from_status": from_status,
            "to_status": to_status,
            "examiner_id": approver_id,
            "nonce": nonce,
            "signature_hex": signature_hex,
            "reason": reason,
        },
    )
    if status == 0 or ap_body is None:
        return ApproveFindingResult(
            case_id=resolved_case_id,
            finding_id=finding_id,
            error=f"sidecar unreachable at {approve_url}: {ap_text[:200]}",
            error_code="sidecar_unreachable",
        )
    if status >= 400:
        msg = ap_body.get("error", ap_text[:200]) if isinstance(ap_body, dict) else ap_text[:200]
        code = (
            ap_body.get("code", "approve_failed") if isinstance(ap_body, dict) else "approve_failed"
        )
        return ApproveFindingResult(
            case_id=resolved_case_id,
            finding_id=finding_id,
            error=str(msg),
            error_code=str(code),
        )

    return ApproveFindingResult(
        case_id=resolved_case_id,
        finding_id=finding_id,
        approval_id=str(ap_body.get("approval_id", "")),
        to_status=to_status,
        indexed_to=str(ap_body.get("indexed_to", "")),
        approved_at=str(ap_body.get("approved_at", "")),
    )


# --- retract_approval (phantom / erroneous-approval reconciliation) -- #


async def retract_approval(
    approval_id: str,
    *,
    case_id: str | None = None,
    approver_id: str,
    password: str,
    reason: str,
    sidecar_base_url: str = "http://127.0.0.1:8800",
    http_post_fn: Callable[..., Awaitable[tuple[int, dict | None, str]]] | None = None,
) -> ApproveFindingResult:
    """Append a compensating VOID/REVOKED entry that retracts a prior approval.

    For an append-only, tamper-evident ledger the correct way to undo a wrong or
    phantom approval (e.g. the NIST1-F006/F007 entries signed for findings that
    never existed) is a *compensating* entry, never a hard delete — deletion is
    exactly the silent mutation the BUG-002 hash chain is meant to detect.

    This signs (target_type="approval", target_id=<approval_id>,
    from_status="APPROVED" -> to_status="REVOKED") through the same W-288 HMAC
    flow as approve_finding, so the retraction is itself a signed, chained
    ledger row referencing the approval it voids. A non-empty ``reason`` is
    required (chain-of-custody). The BUG-001 precondition reader skips
    target_type="approval" by design (an approval_id has no finding to verify).
    """
    if not approval_id or not isinstance(approval_id, str):
        raise ValueError("approval_id must be a non-empty string")
    if not reason or not isinstance(reason, str):
        raise ValueError("reason must be a non-empty string (chain-of-custody)")

    return await approve_finding(
        approval_id,
        case_id=case_id,
        approver_id=approver_id,
        password=password,
        to_status="REVOKED",
        from_status="APPROVED",
        target_type="approval",
        reason=reason,
        sidecar_base_url=sidecar_base_url,
        http_post_fn=http_post_fn,
    )


# --- report_generate ------------------------------------------------- #


def _utc_now_iso() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _approved_filter(case_id: str) -> dict:
    """Compose ``case_id == X AND approval.status == APPROVED``.

    NOTE (SIFT-W-296b): this filters on the finding doc's OWN
    ``approval.status`` field, which the sidecar does NOT mutate — the
    sidecar writes to the append-only ``agentropix-approvals-*`` ledger
    instead. Kept for callers that want the advisory finding-doc view,
    but the report profiles now use ``_reconciled_approved_query`` which
    joins against the authoritative ledger. See
    ``_approved_target_ids``.
    """
    return {
        "query": {
            "bool": {
                "filter": [
                    _case_filter(case_id),
                    {"term": {"approval.status": "APPROVED"}},
                ]
            }
        }
    }


async def _approved_target_ids(case_id: str, client: Any, target_type: str = "finding") -> set[str]:
    """SIFT-W-296b reconciliation: return the set of target_ids whose
    NET approval state is APPROVED, derived from the authoritative
    ``agentropix-approvals-*`` ledger.

    The sidecar (W-288/W-294) writes one append-only row per approval
    transition; the finding doc's own ``approval.status`` stays DRAFT
    because the sidecar uses a separate (read-only-on-findings)
    credential. So reports must JOIN against the ledger rather than
    trust the finding field. This mirrors Valhuntir's L6 control —
    the approvals ledger is the source of truth, the finding field is
    advisory.

    Walks transitions in @timestamp order; the LAST transition per
    target wins (APPROVED then REVOKED ⇒ not approved; REJECTED then
    re-APPROVED ⇒ approved).
    """
    body = {
        "query": {
            "bool": {
                "filter": [
                    _case_filter(case_id),
                    {"term": {"target_type": target_type}},
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "asc", "missing": "_last"}}],
    }
    latest: dict[str, str] = {}
    offset = 0
    PER_PAGE = 500
    while True:
        page = dict(body)
        page["from"] = offset
        try:
            resp = await client.search(APPROVALS_INDEX_PATTERN, page, size=PER_PAGE)
        except Exception as exc:
            logger.warning("_approved_target_ids search failed: %s", exc)
            break
        hits = ((resp.get("hits") or {}).get("hits")) or []
        if not hits:
            break
        for h in hits:
            src = h.get("_source") or {}
            tid = src.get("target_id")
            if tid:
                latest[str(tid)] = str(src.get("to_status", ""))
        if len(hits) < PER_PAGE:
            break
        offset += len(hits)
    return {tid for tid, st in latest.items() if st == "APPROVED"}


def _reconciled_approved_query(case_id: str, target_ids: set[str], id_field: str) -> dict:
    """Build ``case_id == X AND <id_field> IN target_ids``.

    Used by the report profiles to pull only the docs the approvals
    ledger says are APPROVED. ``id_field`` is ``finding_id`` for the
    findings index, ``event_id`` for the timeline index.
    """
    return {
        "query": {
            "bool": {
                "filter": [
                    _case_filter(case_id),
                    {"terms": {id_field: sorted(target_ids)}},
                ]
            }
        }
    }


async def _profile_status(case_id: str, client: Any) -> dict[str, Any]:
    """status profile: counts only. Bypasses APPROVED filter — returns
    DRAFT + APPROVED + REJECTED breakdown so a standup can see
    progress."""
    body = _wrap_with_case_filter({}, case_id)
    body["aggs"] = {"by_status": {"terms": {"field": "approval.status", "size": 10}}}
    body["size"] = 1
    try:
        resp = await client.search(FINDINGS_INDEX_PATTERN, body, size=1)
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    buckets = ((resp.get("aggregations") or {}).get("by_status") or {}).get("buckets") or []
    total = (resp.get("hits") or {}).get("total") or {}
    return {
        "total_findings": (int(total.get("value", 0)) if isinstance(total, dict) else int(total)),
        "by_status": {str(b.get("key", "")): int(b.get("doc_count", 0)) for b in buckets},
    }


async def _page_source_docs(
    client: Any,
    index_pattern: str,
    body: dict,
    *,
    max_total: int = 5000,
) -> list[dict]:
    """SIFT-W-296d (Critic C): the shared 500-row paging loop used by
    the findings / timeline / ioc report profiles — previously copied
    three times. Returns the list of ``_source`` dicts up to
    ``max_total``, breaking on a short page. A search exception ends
    the loop with a logged warning (partial results beat a blanked
    report; the report-level reconciliation in ``report_generate``
    surfaces section emptiness, and idx_search remains the strict path).
    """
    PER_PAGE = 500
    collected: list[dict] = []
    offset = 0
    while len(collected) < max_total:
        page_body = dict(body)
        page_body["from"] = offset
        try:
            resp = await client.search(index_pattern, page_body, size=PER_PAGE)
        except Exception as exc:
            logger.warning("_page_source_docs page failed (%s): %s", index_pattern, exc)
            break
        hits = ((resp.get("hits") or {}).get("hits")) or []
        if not hits:
            break
        for h in hits:
            collected.append(h.get("_source") or {})
        if len(hits) < PER_PAGE:
            break
        offset += len(hits)
    return collected


async def _collect_approved_findings(
    case_id: str, client: Any, *, max_total: int = 5000
) -> list[dict]:
    """Page through agentropix-findings-* pulling the docs the
    approvals ledger says are APPROVED (SIFT-W-296b reconciliation)."""
    approved = await _approved_target_ids(case_id, client, "finding")
    if not approved:
        return []
    body = _reconciled_approved_query(case_id, approved, "finding_id")
    body["sort"] = [{"@timestamp": {"order": "asc", "missing": "_last"}}]
    return await _page_source_docs(client, FINDINGS_INDEX_PATTERN, body, max_total=max_total)


async def _profile_findings(case_id: str, client: Any) -> dict[str, Any]:
    findings = await _collect_approved_findings(case_id, client)
    return {"approved_findings": findings, "count": len(findings)}


async def _profile_timeline(case_id: str, client: Any) -> dict[str, Any]:
    """Chronological narrative — pulls APPROVED timeline events
    (SIFT-W-296b reconciliation against the approvals ledger)."""
    approved = await _approved_target_ids(case_id, client, "timeline")
    if not approved:
        return {"approved_timeline_events": [], "count": 0}
    body = _reconciled_approved_query(case_id, approved, "event_id")
    body["sort"] = [{"@timestamp": {"order": "asc", "missing": "_last"}}]
    events = await _page_source_docs(client, TIMELINE_INDEX_PATTERN, body)
    return {"approved_timeline_events": events, "count": len(events)}


async def _profile_ioc(case_id: str, client: Any) -> dict[str, Any]:
    """IOC export — pull from agentropix-iocs-* with the case filter.
    No approval filter — IOCs are auto-extracted from findings and
    live in their own index."""
    body = _wrap_with_case_filter({}, case_id)
    body["size"] = 1  # using aggs only — pull IOC docs via separate call below
    try:
        agg_resp = await client.search(
            IOCS_INDEX_PATTERN,
            {
                "query": {"bool": {"filter": [_case_filter(case_id)]}},
                "aggs": {
                    "by_type": {"terms": {"field": "ioc_type", "size": 50}},
                    "by_mitre": {"terms": {"field": "mitre_techniques", "size": 50}},
                },
                "size": 0,
            },
            size=1,
        )
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    aggs = agg_resp.get("aggregations") or {}
    by_type = [
        {"ioc_type": b["key"], "count": b["doc_count"]}
        for b in (aggs.get("by_type") or {}).get("buckets") or []
    ]
    by_mitre = [
        {"technique": b["key"], "count": b["doc_count"]}
        for b in (aggs.get("by_mitre") or {}).get("buckets") or []
    ]

    # Pull the actual IOCs (capped at 5000 to defend the envelope).
    iocs = await _page_source_docs(
        client,
        IOCS_INDEX_PATTERN,
        {"query": {"bool": {"filter": [_case_filter(case_id)]}}},
    )

    return {
        "iocs": iocs,
        "count": len(iocs),
        "by_type": by_type,
        "by_mitre_technique": by_mitre,
    }


async def _profile_executive(case_id: str, client: Any) -> dict[str, Any]:
    """1-2 page management briefing: counts + top MITRE tactics +
    top hosts. Non-technical. SIFT-W-296b: aggregates over the
    ledger-reconciled APPROVED finding set, not the finding-doc
    approval.status field."""
    approved = await _approved_target_ids(case_id, client, "finding")
    if not approved:
        return {
            "approved_finding_count": 0,
            "top_tactics": [],
            "top_hosts": [],
            "severity_mix": [],
        }
    body = _reconciled_approved_query(case_id, approved, "finding_id")
    body["aggs"] = {
        "by_tactic": {"terms": {"field": "mitre_tactics", "size": 10}},
        # SIFT-W-296b: host.name dynamic-maps as text (+ .keyword
        # sub-field). Aggregations MUST target host.name.keyword;
        # raw host.name yields empty buckets. mitre_tactics is a
        # top-level keyword so it aggregates directly.
        "by_host": {"terms": {"field": "host.name.keyword", "size": 10}},
        "by_severity": {"terms": {"field": "severity", "size": 10}},
    }
    body["size"] = 0
    try:
        resp = await client.search(FINDINGS_INDEX_PATTERN, body, size=1)
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    aggs = resp.get("aggregations") or {}
    total = (resp.get("hits") or {}).get("total") or {}
    return {
        "approved_finding_count": (
            int(total.get("value", 0)) if isinstance(total, dict) else int(total)
        ),
        "top_tactics": [
            {"tactic": b["key"], "count": b["doc_count"]}
            for b in (aggs.get("by_tactic") or {}).get("buckets") or []
        ],
        "top_hosts": [
            {"host": b["key"], "count": b["doc_count"]}
            for b in (aggs.get("by_host") or {}).get("buckets") or []
        ],
        "severity_mix": [
            {"severity": b["key"], "count": b["doc_count"]}
            for b in (aggs.get("by_severity") or {}).get("buckets") or []
        ],
    }


async def _profile_full(case_id: str, client: Any) -> dict[str, Any]:
    """Comprehensive: union of findings + timeline + ioc + executive.

    SIFT-W-296d (Critic B): the four sub-profiles are independent reads,
    so run them concurrently with asyncio.gather (~4x wall-clock vs the
    prior sequential awaits on a large case). ``return_exceptions`` keeps
    one failing sub-profile from blanking the whole report — a raised
    sub-profile becomes an ``{"error": ...}`` section that
    ``report_generate`` then bubbles to the top-level error field
    (Critic D).
    """
    findings, timeline, iocs, exec_summary = await asyncio.gather(
        _profile_findings(case_id, client),
        _profile_timeline(case_id, client),
        _profile_ioc(case_id, client),
        _profile_executive(case_id, client),
        return_exceptions=True,
    )

    def _coerce(section: Any, label: str) -> dict[str, Any]:
        if isinstance(section, BaseException):
            return {"error": f"{type(section).__name__}: {section}"}
        return section

    return {
        "executive_summary": _coerce(exec_summary, "executive_summary"),
        "findings": _coerce(findings, "findings"),
        "timeline": _coerce(timeline, "timeline"),
        "iocs": _coerce(iocs, "iocs"),
    }


_PROFILE_DISPATCH: dict[str, Callable[[str, Any], Awaitable[dict[str, Any]]]] = {
    "status": _profile_status,
    "findings": _profile_findings,
    "timeline": _profile_timeline,
    "ioc": _profile_ioc,
    "executive": _profile_executive,
    "full": _profile_full,
}


async def report_generate(
    profile: ReportProfile = "full",
    *,
    case_id: str | None = None,
    indexer_client: Any = None,
) -> ReportGenerateResult:
    """Build a report-mcp-shaped payload for one of 6 profiles.

    Only APPROVED findings reach the findings/timeline/executive/full
    profiles. The ``ioc`` profile pulls from agentropix-iocs-* without
    an approval filter (IOCs are auto-extracted; their parent
    findings carry the approval state). The ``status`` profile is a
    quick standup snapshot — includes DRAFT + APPROVED + REJECTED
    breakdown.

    Returns the structured ``sections`` dict that the calling LLM
    then renders into a narrative.
    """
    if profile not in _PROFILE_DISPATCH:
        raise ValueError(
            f"unknown profile {profile!r}; expected one of {sorted(_PROFILE_DISPATCH)}"
        )

    resolved_case_id = case_id if case_id is not None else get_active_case_id()
    if resolved_case_id is None:
        raise ValueError("no active case; pass case_id= or call case_activate() first")

    snapshot_at = _utc_now_iso()
    if indexer_client is None:
        return ReportGenerateResult(
            case_id=resolved_case_id,
            profile=profile,
            report_id="",
            snapshot_at=snapshot_at,
            error="indexer_client not injected",
        )

    # BUG-003: fail fast on a non-existent case instead of running the slow
    # per-profile dispatch (which on a missing case could block for the full
    # client timeout — ~4 min observed). Mirror case_status's quick existence
    # probe: a single bounded count across the case's sibling indices. If the
    # case has zero docs anywhere, short-circuit with a structured
    # case_not_found rather than fanning out the expensive profile reads.
    try:
        present = 0
        for _pattern in (
            FINDINGS_INDEX_PATTERN,
            TIMELINE_INDEX_PATTERN,
            IOCS_INDEX_PATTERN,
        ):
            present += int(
                await indexer_client.count(
                    _pattern, {"query": {"term": {"case_id": resolved_case_id}}}
                )
            )
            if present:
                break
    except Exception as exc:
        logger.warning("report_generate existence probe failed (continuing): %s", exc)
        present = 1  # don't short-circuit on a probe error
    if present == 0:
        return ReportGenerateResult(
            case_id=resolved_case_id,
            profile=profile,
            report_id="",
            snapshot_at=snapshot_at,
            error=f"case_not_found: no documents for case_id {resolved_case_id!r}",
        )

    sections = await _PROFILE_DISPATCH[profile](resolved_case_id, indexer_client)
    error = ""
    approved_count = 0
    if isinstance(sections, dict) and "error" in sections:
        # Single-profile error (the profile itself returned an error dict).
        error = str(sections["error"])
        sections = {}
    elif isinstance(sections, dict):
        # SIFT-W-296d (Critic D): bubble nested sub-section errors (full
        # profile) to the top-level error field so a caller sees that a
        # section degraded — the report is NOT blanked (the healthy
        # sections remain), but the error surface is honest.
        nested_errors = {
            name: sec["error"]
            for name, sec in sections.items()
            if isinstance(sec, dict) and sec.get("error")
        }
        if nested_errors:
            error = "; ".join(f"{name}: {msg}" for name, msg in sorted(nested_errors.items()))

    # Deterministic report_id: sha256 over (case_id, profile,
    # snapshot_at, sorted approved finding_ids). Matches the
    # hash_chain.compute_content_hash contract used by the
    # agentropix-reports-* index.
    finding_ids: list[str] = []
    if profile == "findings":
        finding_ids = [
            str(f.get("finding_id", "")) for f in sections.get("approved_findings", []) or []
        ]
        approved_count = sections.get("count", 0)
    elif profile == "full":
        findings_section = sections.get("findings") or {}
        finding_ids = [
            str(f.get("finding_id", ""))
            for f in findings_section.get("approved_findings", []) or []
        ]
        approved_count = findings_section.get("count", 0)
    elif profile == "executive":
        approved_count = sections.get("approved_finding_count", 0)
    elif profile in ("timeline", "ioc"):
        approved_count = sections.get("count", 0)
    elif profile == "status":
        approved_count = (sections.get("by_status") or {}).get("APPROVED", 0)

    sorted_ids = sorted(finding_ids)
    payload = "\x00".join([resolved_case_id, profile, snapshot_at, "|".join(sorted_ids)])
    report_id = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    # NIST1 ISSUE-009: an approval-filtered profile that came back empty while
    # DRAFT findings exist would otherwise look like "investigation found
    # nothing" (autonomous runs hold 0 approvals by design). Surface a warning
    # rather than silently returning empty sections.
    warning = ""
    if (
        not error
        and approved_count == 0
        and profile in ("full", "findings", "executive", "timeline")
    ):
        warning = (
            f"0 APPROVED findings — profile={profile!r} includes only APPROVED findings. "
            "If DRAFT findings exist (autonomous runs hold 0 approvals by design), approve "
            "them (approve_finding) or use profile='status' to see DRAFT work."
        )

    result = ReportGenerateResult(
        case_id=resolved_case_id,
        profile=profile,
        report_id=report_id,
        snapshot_at=snapshot_at,
        approved_finding_count=approved_count,
        sections=sections,
        error=error,
        warning=warning,
    )
    # SIFT-W-296c (Critic E): bound the serialized result to the 1MB MCP
    # envelope. The heavy row-lists live nested inside `sections`, so a
    # report-specific trimmer walks the known section list-paths.
    _enforce_report_byte_budget(result)
    return result


# The nested section paths that hold the heavy row lists, longest-first
# preference handled by the trimmer.
_REPORT_LIST_PATHS: list[tuple[str, ...]] = [
    ("approved_findings",),  # findings profile
    ("approved_timeline_events",),  # timeline profile
    ("iocs",),  # ioc profile
    ("findings", "approved_findings"),  # full profile
    ("timeline", "approved_timeline_events"),
    ("iocs", "iocs"),
]


def _enforce_report_byte_budget(
    result: ReportGenerateResult,
    *,
    max_bytes: int | None = None,
) -> None:
    """SIFT-W-296c: trim nested section row-lists until the serialized
    report fits under the MCP byte ceiling. Sets ``truncated=True`` and
    records ``result_bytes``. ``max_bytes`` resolves the module-level
    constant at CALL time so env overrides / test patches apply."""
    if max_bytes is None:
        # Read the live module global (case_records re-imports the name)
        # so an env-driven change or test monkeypatch takes effect.
        import agentropix_mcp.wrappers.case_records as _self

        max_bytes = _self.RESULT_MAX_BYTES

    def _size() -> int:
        try:
            return len(json.dumps(result.model_dump(), default=str).encode("utf-8"))
        except Exception:
            return 0

    if _size() <= max_bytes:
        result.result_bytes = _size()
        return

    guard = 0
    while _size() > max_bytes and guard < 2000:
        guard += 1
        # Find the longest list among the known nested paths.
        longest_path = None
        longest_len = 0
        for path in _REPORT_LIST_PATHS:
            node: Any = result.sections
            ok = True
            for key in path:
                if isinstance(node, dict) and key in node:
                    node = node[key]
                else:
                    ok = False
                    break
            if ok and isinstance(node, list) and len(node) > longest_len:
                longest_path, longest_len = path, len(node)
        if longest_path is None or longest_len == 0:
            break
        # Walk to the parent + trim ~15%.
        parent: Any = result.sections
        for key in longest_path[:-1]:
            parent = parent[key]
        leaf = longest_path[-1]
        cur = parent[leaf]
        drop = max(1, len(cur) // 7)
        parent[leaf] = cur[: len(cur) - drop]
        # Keep the count field honest if the section carries one.
        if isinstance(parent, dict) and "count" in parent:
            parent["count"] = len(parent[leaf])
        result.truncated = True

    result.result_bytes = _size()
