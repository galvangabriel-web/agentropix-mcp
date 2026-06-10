"""SIFT-W-288: Pydantic request / response models for the approval sidecar.

Field shape matches the ``agentropix-approvals-*`` index template
(``dynamic: strict``) so what the browser sends is exactly what the
indexer accepts. Every additional field would be rejected at index
time — these models are the only safe surface.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

ApprovalStatus = Literal["DRAFT", "APPROVED", "REJECTED", "REVOKED"]
# "approval" is the retraction target: a compensating VOID/REVOKED entry that
# references a prior approval_id (phantom-approval reconciliation, append-only —
# never a hard delete). It has no finding to precondition-check, so the BUG-001
# reader skips it by design.
TargetType = Literal["finding", "timeline", "approval"]


class ChallengeRequest(BaseModel):
    """POST /challenge — issue a nonce bound to (examiner, target).

    The browser side calls this first, gets the per-examiner salt
    (Phase 2 — Phase 1 returns just nonce + PBKDF2 params and the
    examiner's password is configured server-side), and then computes
    the HMAC client-side.
    """

    examiner_id: str = Field(..., min_length=1, max_length=128)
    target_id: str = Field(..., min_length=1, max_length=128)
    target_type: TargetType


class ChallengeResponse(BaseModel):
    """Response from POST /challenge.

    ``salt`` and ``iterations`` are echoed so the browser can derive
    the key with exactly the same parameters the server will use to
    verify. Phase 1 ships them in the response; Phase 2 may move them
    to a separate ``/examiners/<id>/salt`` endpoint to keep the
    challenge response one-shot-cacheable.
    """

    nonce: str = Field(..., min_length=24)
    salt_hex: str = Field(..., min_length=2)
    iterations: int = Field(..., ge=1)
    ttl_seconds: float = Field(..., gt=0)


class ApprovalSubmitRequest(BaseModel):
    """POST /approve — submit the signed approval.

    ``signature_hex`` is computed by the browser as
    ``HMAC-SHA256(PBKDF2(password, salt, iterations), build_signed_message(...))``
    so the server never sees the password.
    """

    case_id: str = Field(..., min_length=1, max_length=128)
    target_id: str = Field(..., min_length=1, max_length=128)
    target_type: TargetType
    from_status: ApprovalStatus
    to_status: ApprovalStatus
    examiner_id: str = Field(..., min_length=1, max_length=128)
    nonce: str = Field(..., min_length=24)
    signature_hex: str = Field(..., min_length=64, max_length=64)
    reason: str = Field("", max_length=4096)

    @field_validator("signature_hex")
    @classmethod
    def _hex_lowercase(cls, v: str) -> str:
        # Enforce lowercase hex so verify_signature's compare_digest
        # never sees a case mismatch between browser and server.
        if not all(c in "0123456789abcdef" for c in v):
            raise ValueError("signature_hex must be lowercase hex")
        return v


class ApprovalSubmitResponse(BaseModel):
    """Response from POST /approve on success."""

    approval_id: str
    indexed_to: str  # the agentropix-approvals-YYYY.MM.DD index that took the doc
    prev_approval_hash: str  # empty string on the first approval for a target
    approved_at: str  # ISO-8601


class ErrorResponse(BaseModel):
    """Error envelope. Field shape mirrors the existing
    ``wazuh_index_findings`` error envelope so a future MCP wrapper
    that proxies into the sidecar can pass through without
    reshaping."""

    error: str
    code: str  # short machine-readable token: nonce_expired, bad_signature, ...
