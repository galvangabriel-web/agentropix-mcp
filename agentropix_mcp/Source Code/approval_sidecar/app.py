"""SIFT-W-288: Starlette approval-sidecar routes.

Phase 1 surface:

  GET  /healthz                — liveness probe (no auth).
  POST /challenge              — issue a nonce for an (examiner, target).
  POST /approve                — submit signed approval, write to
                                  ``agentropix-approvals-*``.

The ``approve_writer`` callable is dependency-injected so tests can
drop in a stub. Default writer uses ``IndexerClient`` with the
approver credentials from ``SidecarConfig``.
"""

from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path

from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route

from agentropix_mcp.approval_sidecar.auth import (
    build_signed_message,
    derive_key,
    verify_signature,
)
from agentropix_mcp.approval_sidecar.config import SidecarConfig
from agentropix_mcp.approval_sidecar.hash_chain import compute_approval_id
from agentropix_mcp.approval_sidecar.models import (
    ApprovalSubmitRequest,
    ApprovalSubmitResponse,
    ChallengeRequest,
    ChallengeResponse,
    ErrorResponse,
)
from agentropix_mcp.approval_sidecar.nonce import (
    NonceExpired,
    NonceStore,
    NonceUnknown,
)

logger = logging.getLogger(__name__)

# Writer signature: takes the assembled doc + index name, returns the
# OpenSearch _id. Phase 2 will plug IndexerClient in here; Phase 1
# default raises so tests are forced to inject.
ApprovalWriter = Callable[[dict, str], Awaitable[str]]

# BUG-001 precondition reader: given (case_id, target_id, target_type),
# returns the target finding's current approval status as a lowercased/
# uppercased string, or None if the target does not exist in the case.
# Dependency-injected so tests pass a stub and the default wires through
# IndexerClient. None (not injected) means "skip precondition" — preserves
# the legacy flow for deployments that haven't wired a reader yet.
ApprovalReader = Callable[[str, str, str], Awaitable["str | None"]]


def _utc_now_iso() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _daily_index_name(now: dt.datetime | None = None) -> str:
    n = now or dt.datetime.now(dt.UTC)
    return f"agentropix-approvals-{n:%Y.%m.%d}"


# --------------------------------------------------------------------- #
# Default no-op writer for Phase 1. Logs the call; raises so callers
# who build the app without injecting a real writer get an audible
# failure rather than a silent drop.
# --------------------------------------------------------------------- #


async def _default_writer(_doc: dict, _index: str) -> str:
    raise NotImplementedError(
        "approve_writer not injected — pass one to build_app(). Phase 2 "
        "wires the IndexerClient-backed default."
    )


# --------------------------------------------------------------------- #
# Route handlers
# --------------------------------------------------------------------- #


def _err(code: str, message: str, status: int) -> JSONResponse:
    return JSONResponse(
        ErrorResponse(error=message, code=code).model_dump(),
        status_code=status,
    )


async def _healthz(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "approval-sidecar"})


_STATIC_DIR = Path(__file__).parent / "static"


async def _index(_request: Request):
    """SIFT-W-294: serve the browser approval UI from
    ``static/index.html``. Web Crypto API does the PBKDF2 + HMAC
    derivation locally; the password never leaves the tab.

    SIFT-W-296d (Critic D): guard against a missing packaged asset —
    return a clean 503 JSON instead of letting FileResponse raise a
    bare 500 when the static file isn't present (e.g. a partial
    install)."""
    index_path = _STATIC_DIR / "index.html"
    if not index_path.is_file():
        return _err(
            "static_missing",
            f"approval UI asset not found at {index_path}; reinstall the "
            "agentropix_mcp.approval_sidecar package",
            503,
        )
    return FileResponse(
        index_path,
        media_type="text/html; charset=utf-8",
    )


def _challenge_handler(
    config: SidecarConfig,
    store: NonceStore,
) -> Callable[[Request], Awaitable[JSONResponse]]:
    async def handler(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return _err("bad_json", "request body must be JSON", 400)
        try:
            req = ChallengeRequest.model_validate(body)
        except ValidationError as exc:
            return _err("validation", str(exc), 400)

        # Phase 1: single-examiner — refuse a challenge for any examiner
        # other than the configured approver. Multi-examiner support is
        # a future API-layer expansion (no schema change, per the
        # operator decision to keep approver as polyglot keyword).
        if req.examiner_id != config.examiner_id:
            return _err(
                "unknown_examiner",
                f"examiner_id {req.examiner_id!r} not provisioned",
                403,
            )

        nonce = store.issue(req.examiner_id, req.target_id)
        resp = ChallengeResponse(
            nonce=nonce,
            salt_hex=config.approver_salt_hex,
            iterations=config.pbkdf2_iterations,
            ttl_seconds=config.nonce_ttl_seconds,
        )
        return JSONResponse(resp.model_dump())

    return handler


def _approve_handler(
    config: SidecarConfig,
    store: NonceStore,
    writer: ApprovalWriter,
    reader: ApprovalReader | None = None,
) -> Callable[[Request], Awaitable[JSONResponse]]:
    async def handler(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return _err("bad_json", "request body must be JSON", 400)
        try:
            req = ApprovalSubmitRequest.model_validate(body)
        except ValidationError as exc:
            return _err("validation", str(exc), 400)

        # Same examiner gate as /challenge.
        if req.examiner_id != config.examiner_id:
            return _err(
                "unknown_examiner",
                f"examiner_id {req.examiner_id!r} not provisioned",
                403,
            )

        # 1) Consume the nonce — single-use, target-bound, TTL-bound.
        try:
            store.consume(
                req.nonce,
                examiner_id=req.examiner_id,
                target_id=req.target_id,
            )
        except NonceExpired as exc:
            return _err("nonce_expired", str(exc), 401)
        except NonceUnknown as exc:
            return _err("nonce_unknown", str(exc), 401)

        # 2) Re-derive the HMAC key + verify the signature. The
        #    password lives on the sidecar only; the wire payload
        #    never carried it.
        try:
            salt = bytes.fromhex(config.approver_salt_hex)
        except ValueError:
            return _err("config_error", "approver salt is not hex", 500)
        key = derive_key(
            config.approver_password,
            salt,
            iterations=config.pbkdf2_iterations,
        )
        message = build_signed_message(
            nonce=req.nonce,
            target_id=req.target_id,
            target_type=req.target_type,
            from_status=req.from_status,
            to_status=req.to_status,
            case_id=req.case_id,
        )
        if not verify_signature(key, message, req.signature_hex):
            return _err("bad_signature", "HMAC verification failed", 401)

        # 2.5) BUG-001 precondition gate (defense-in-depth at the sidecar
        #      boundary). When a reader is wired, the target MUST exist in
        #      the case and MUST currently be in the asserted from_status —
        #      otherwise the ledger could attest transitions for records that
        #      were never recorded (phantom NIST1-F006/F007). The nonce is
        #      already consumed at this point; that's fine — a rejected
        #      precondition simply means the operator must re-challenge with
        #      a real, correctly-staged target. No approval doc is written.
        if reader is not None:
            try:
                current_status = await reader(req.case_id, req.target_id, req.target_type)
            except Exception as exc:
                logger.exception("approval precondition lookup failed")
                return _err(
                    "precondition_unavailable",
                    f"could not verify target: {type(exc).__name__}: {exc}",
                    502,
                )
            if current_status is None:
                return _err(
                    "target_not_found",
                    f"{req.target_type} {req.target_id!r} not found in case "
                    f"{req.case_id!r}; refusing to sign an approval for a "
                    "record that does not exist",
                    409,
                )
            if current_status.upper() != req.from_status.upper():
                return _err(
                    "precondition_failed",
                    f"{req.target_id!r} is in status {current_status!r}, not the "
                    f"asserted from_status {req.from_status!r}; refusing "
                    "(guards double-approval / stale-state races)",
                    409,
                )

        # 3) Compute deterministic approval_id. (Phase 1 does NOT yet
        #    look up prev_approval_hash from the index — that requires
        #    a read path Phase 2 wires through IndexerClient. For now
        #    we accept caller-supplied prev_approval_hash via the
        #    optional `payload.prev_approval_hash` once Phase 2 lands;
        #    Phase 1 writes `""` so the chain can be back-filled.)
        approval_id = compute_approval_id(
            case_id=req.case_id,
            target_id=req.target_id,
            target_type=req.target_type,
            from_status=req.from_status,
            to_status=req.to_status,
            approver=req.examiner_id,
            nonce=req.nonce,
        )

        approved_at = _utc_now_iso()
        doc = {
            "@timestamp": approved_at,
            "approval_id": approval_id,
            "target_id": req.target_id,
            "target_type": req.target_type,
            "from_status": req.from_status,
            "to_status": req.to_status,
            "approver": req.examiner_id,
            "reason": req.reason,
            "hmac_signature": req.signature_hex,
            "prev_approval_hash": "",  # backfilled in Phase 2
            "nonce": req.nonce,
            "case_id": req.case_id,
        }
        index = _daily_index_name()
        try:
            await writer(doc, index)
        except Exception as exc:
            logger.exception("approval indexer write failed")
            return _err(
                "indexer_outage",
                f"indexer write failed: {type(exc).__name__}: {exc}",
                502,
            )

        resp = ApprovalSubmitResponse(
            approval_id=approval_id,
            indexed_to=index,
            prev_approval_hash="",
            approved_at=approved_at,
        )
        return JSONResponse(resp.model_dump())

    return handler


# --------------------------------------------------------------------- #
# App factory + entry point
# --------------------------------------------------------------------- #


def build_app(
    config: SidecarConfig,
    *,
    writer: ApprovalWriter | None = None,
    store: NonceStore | None = None,
    reader: ApprovalReader | None = None,
) -> Starlette:
    """Build the Starlette app.

    Args:
        config: SidecarConfig (typically from env).
        writer: callable that indexes the approval doc. Pass a stub
            in tests; production wiring lands in Phase 2 with the
            IndexerClient-backed default.
        store: optional NonceStore. Defaults to an in-memory one
            sized to the config TTL.
    """
    actual_writer: ApprovalWriter = writer if writer is not None else _default_writer
    actual_store = store if store is not None else NonceStore(ttl_seconds=config.nonce_ttl_seconds)

    routes = [
        Route("/healthz", _healthz, methods=["GET"]),
        Route("/", _index, methods=["GET"]),
        Route(
            "/challenge",
            _challenge_handler(config, actual_store),
            methods=["POST"],
        ),
        Route(
            "/approve",
            _approve_handler(config, actual_store, actual_writer, reader),
            methods=["POST"],
        ),
    ]
    return Starlette(routes=routes)


def run(
    config: SidecarConfig | None = None,
    *,
    writer: ApprovalWriter | None = None,
) -> None:  # pragma: no cover — exercised by integration / e2e, not unit
    """Boot the sidecar with uvicorn. Used by an ops launcher script.

    SIFT-W-294: when ``writer`` is None and no test injection is in
    play, we default to the IndexerClient-backed writer from
    ``approval_sidecar.writer.build_indexer_backed_writer`` so the
    sidecar can run end-to-end without a manual wiring step.
    """
    import uvicorn

    cfg = config or SidecarConfig.from_env()
    if writer is None:
        from agentropix_mcp.approval_sidecar.writer import (
            build_indexer_backed_writer,
        )

        writer = build_indexer_backed_writer(cfg)
    # BUG-001: wire the precondition reader so production refuses to sign
    # approvals for non-existent / wrong-status targets.
    from agentropix_mcp.approval_sidecar.writer import build_indexer_backed_reader

    reader = build_indexer_backed_reader(cfg)
    app = build_app(cfg, writer=writer, reader=reader)
    uvicorn.run(app, host=cfg.host, port=cfg.port, log_level="info")
