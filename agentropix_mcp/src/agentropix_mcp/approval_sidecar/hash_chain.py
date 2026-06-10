"""SIFT-W-288: hash-chain helpers for ``agentropix-approvals-*``.

Each approval document carries:

  - ``approval_id``      = deterministic SHA-256 over the immutable
                           fields of THIS approval (case_id, target_id,
                           target_type, from_status, to_status, approver,
                           nonce). Doubles as the OpenSearch ``_id`` so
                           the same approval cannot be indexed twice
                           (idempotency under client retry).

  - ``prev_approval_hash`` = hash of the previous approval that touched
                             the same target_id (or the empty string if
                             this is the first). The reconciliation
                             routine in the future ``report_generate``
                             tool (Phase 4) walks the chain backwards
                             and rejects any approval whose
                             ``prev_approval_hash`` doesn't match the
                             actual previous hash — that's how
                             tampering is detected.

  - ``content_hash``     = report-time content fingerprint covering
                           (case_id, sorted-finding_ids, profile). Used
                           by the future ``report_generate`` flow to
                           prove idempotency. Lives in
                           ``agentropix-reports-*`` not here, but the
                           helper lives in the same module because it
                           shares the deterministic hashing pattern.
"""

from __future__ import annotations

import hashlib

__all__ = [
    "compute_approval_id",
    "compute_content_hash",
    "compute_prev_approval_hash",
]


def _sha256_hex(parts: list[str]) -> str:
    """Stable hex digest over the NUL-joined utf-8 encoded parts."""
    payload = "\x00".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def compute_approval_id(
    case_id: str,
    target_id: str,
    target_type: str,
    from_status: str,
    to_status: str,
    approver: str,
    nonce: str,
) -> str:
    """Deterministic approval document ID.

    Args are exactly the fields a malicious replay would have to forge
    end-to-end. Including the nonce means even an identical approval
    (same from/to status, same target) submitted twice produces a
    different ID — so an LLM cannot smuggle a second approval through
    by repeating the first's signed message.

    Returns:
        Lowercase 64-char hex SHA-256.
    """
    return _sha256_hex([case_id, target_id, target_type, from_status, to_status, approver, nonce])


def compute_prev_approval_hash(
    prev_approval_id: str,
    prev_hmac_signature: str,
) -> str:
    """Hash that locks each approval to its predecessor.

    Walking backwards: the reconciliation routine computes this same
    hash from the row before the current one. If it doesn't match
    the ``prev_approval_hash`` stored on the current row, the chain
    is broken — either a row was deleted, mutated, or inserted
    out-of-order. Any of these is treated as tampering at report
    time.

    Args:
        prev_approval_id: ``approval_id`` of the row immediately
            preceding the one we're about to write (empty string
            when this is the first approval for the target).
        prev_hmac_signature: HMAC signature of the previous row.
            Including it in the chain hash means a forger who only
            has read access to the approvals index still can't
            forge a new approval without the previous HMAC.

    Returns:
        Lowercase 64-char hex SHA-256, or the empty string if this
        is the genesis (no previous approval).
    """
    if not prev_approval_id:
        return ""
    return _sha256_hex([prev_approval_id, prev_hmac_signature])


def compute_content_hash(
    case_id: str,
    profile: str,
    approved_finding_ids: list[str],
) -> str:
    """Deterministic content-hash for a report snapshot.

    Used by the future ``report_generate`` flow (Crew 4 design) to
    produce idempotent ``report_id`` values — re-running the same
    profile against the same approved finding set yields the same
    ``content_hash``, so the operator can re-render without
    duplicating rows in ``agentropix-reports-*``.

    Args:
        case_id: case identifier.
        profile: one of ``{full, executive, timeline, ioc, findings,
            status}``.
        approved_finding_ids: identifiers of every APPROVED finding
            included in this report. The list is sorted internally
            so order-of-arrival doesn't affect the hash.

    Returns:
        Lowercase 64-char hex SHA-256.
    """
    sorted_ids = sorted(approved_finding_ids)
    return _sha256_hex([case_id, profile, "|".join(sorted_ids)])
