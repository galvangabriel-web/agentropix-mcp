"""Courtroom seal for the Wazuh IOC push integration.

Fix 2 (CRITICAL S-3 + ADR-016 compliance from critics/01_security.md and
critics/04_compliance.md):

ADR-016 mandates HMAC-SHA256 with a per-run session key, NOT plain sha256.
This module implements:

  seal = HMAC-SHA256(session_key, canonical_json(envelope))

where ``envelope`` is:
  {
    "v": "1",
    "operator": <unix_user>,
    "case_id": <case_id>,
    "ts": <iso8601_utc>,
    "evidence_token_id": <token_id_or_null>,
    "endpoint": <wazuh_api_path>,
    "req_sha256": <hex64>,
    "resp_sha256": <hex64>,
    "status": <http_status>
  }

The session key is generated once per push run via ``os.urandom(32)``,
written to ``<logpath>.session-key`` at mode 0600 — exactly as ADR-016
specifies for ``write_session_key``.

Verification recomputes the MAC the same way using ``hmac.compare_digest``
for constant-time comparison.

Correct ADRs: ADR-016 (courtroom seal / HMAC-SHA256), ADR-008 (safety).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path

__all__ = [
    "SealError",
    "generate_session_key",
    "compute_seal",
    "verify_seal",
    "canonical_json",
    "CourtroomSeal",
]

logger = logging.getLogger(__name__)


class SealError(Exception):
    """Raised when a seal operation fails."""


# ---------------------------------------------------------------------------
# Session key management (ADR-016 §Invariant 4)
# ---------------------------------------------------------------------------


def generate_session_key(log_path: str | Path) -> bytes:
    """Generate a 32-byte session key and write it next to the audit log.

    The key file is written at mode 0600 (user-read-write only).
    Returns the key bytes so the orchestrator can hold the key in memory
    for the duration of the push run without re-reading the file.

    Args:
        log_path: Path to the audit log file. The key is written at
            ``<stem>.session-key`` in the same directory.

    Returns:
        32 random bytes (the session key).
    """
    key = os.urandom(32)
    log_path = Path(log_path)
    key_path = log_path.parent / f"{log_path.stem}.session-key"
    key_path.write_bytes(key)
    try:
        os.chmod(key_path, 0o600)
    except OSError as exc:  # pragma: no cover — non-POSIX FS
        logger.warning("Unable to chmod 0600 on %s: %s", key_path, exc)
    logger.info("Session key written to %s (mode 0600)", key_path)
    return key


# ---------------------------------------------------------------------------
# Canonical JSON serialisation (ADR-016 §Invariant 4)
# ---------------------------------------------------------------------------


def canonical_json(data: dict) -> bytes:
    """Serialise ``data`` to canonical JSON bytes.

    Rules (mirroring ADR-016 / courtroom.py _canonical_for_seal):
    - sort_keys=True
    - separators=(",", ":") — no whitespace
    - ensure_ascii=True
    - default=str for non-serialisable values (datetime → ISO-8601 string)
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("ascii")


# ---------------------------------------------------------------------------
# Seal computation (HMAC-SHA256 per ADR-016)
# ---------------------------------------------------------------------------


def compute_seal(
    session_key: bytes,
    *,
    operator: str,
    case_id: str,
    ts: datetime | None = None,
    evidence_token_id: str | None,
    endpoint: str,
    req_sha256: str,
    resp_sha256: str,
    status: int = 0,
    run_id: str | None = None,
) -> str:
    """Compute HMAC-SHA256 seal over the canonical envelope.

    Fix 3 (S-3 + ADR-016): binds operator, case_id, timestamp,
    evidence_token_id, endpoint, and both payload hashes so the seal
    cannot be forged by replaying a different (req, resp) pair.

    F-6 (review): also binds ``run_id`` so intra-run record substitution
    is detectable. The session key already prevents cross-run swap; the
    run_id binding closes the within-run swap that is otherwise possible
    when the same operator pushes twice in a window.

    Args:
        session_key: 32-byte secret key from ``generate_session_key``.
        operator: UNIX username holding the evidence-gate token.
        case_id: Forensic case ID (e.g. SRL-2018).
        ts: UTC timestamp of the operation (defaults to now).
        evidence_token_id: The evidence gate token ID (not the secret).
        endpoint: Wazuh API path (e.g. /lists/files/agentropix_c2_ips).
        req_sha256: SHA-256 hex digest of the canonical request bytes.
        resp_sha256: SHA-256 hex digest of the raw response body.
        status: HTTP response status code.

    Returns:
        ``"hmac-sha256:<64-char-hex>"`` string (scheme-prefixed for clarity).

    Raises:
        SealError: If session_key is shorter than 32 bytes.
    """
    if len(session_key) < 32:
        raise SealError("Session key must be at least 32 bytes (ADR-016)")

    if ts is None:
        ts = datetime.now(UTC)

    envelope = {
        # Bumped to v=2 to mark the addition of run_id (F-6). Verifiers
        # must accept v=1 for legacy audit rows AND v=2 for new ones; new
        # rows always include run_id.
        "v": "2",
        "operator": operator,
        "case_id": case_id,
        "ts": ts.isoformat(),
        "evidence_token_id": evidence_token_id,
        "endpoint": endpoint,
        "req_sha256": req_sha256,
        "resp_sha256": resp_sha256,
        "status": status,
        "run_id": run_id,
    }

    payload = canonical_json(envelope)
    mac = hmac.new(session_key, payload, hashlib.sha256).hexdigest()
    return f"hmac-sha256:{mac}"


def verify_seal(
    session_key: bytes,
    expected_seal: str,
    *,
    operator: str,
    case_id: str,
    ts: datetime,
    evidence_token_id: str | None,
    endpoint: str,
    req_sha256: str,
    resp_sha256: str,
    status: int = 0,
    run_id: str | None = None,
) -> bool:
    """Constant-time verification of a previously-computed seal.

    Returns True when the recomputed HMAC matches expected_seal.
    Uses hmac.compare_digest to prevent timing side-channels.
    """
    recomputed = compute_seal(
        session_key,
        operator=operator,
        case_id=case_id,
        ts=ts,
        evidence_token_id=evidence_token_id,
        endpoint=endpoint,
        req_sha256=req_sha256,
        resp_sha256=resp_sha256,
        status=status,
        run_id=run_id,
    )
    return hmac.compare_digest(recomputed, expected_seal)


# ---------------------------------------------------------------------------
# Object-oriented interface
# ---------------------------------------------------------------------------


class CourtroomSeal:
    """Stateful seal helper that holds the session key for a push run."""

    def __init__(self, session_key: bytes) -> None:
        if len(session_key) < 32:
            raise SealError("Session key must be at least 32 bytes")
        self._key = session_key

    @classmethod
    def for_log(cls, log_path: str | Path) -> CourtroomSeal:
        """Generate a new session key and return a CourtroomSeal instance."""
        key = generate_session_key(log_path)
        return cls(key)

    def bind(
        self,
        *,
        operator: str,
        case_id: str,
        ts: datetime | None = None,
        evidence_token_id: str | None,
        endpoint: str,
        req_sha256: str,
        resp_sha256: str,
        status: int = 0,
        run_id: str | None = None,
    ) -> str:
        """Compute and return the HMAC-SHA256 seal string."""
        return compute_seal(
            self._key,
            operator=operator,
            case_id=case_id,
            ts=ts,
            evidence_token_id=evidence_token_id,
            endpoint=endpoint,
            req_sha256=req_sha256,
            resp_sha256=resp_sha256,
            status=status,
            run_id=run_id,
        )

    def verify(self, expected_seal: str, **kwargs) -> bool:  # type: ignore[override]
        """Verify an existing seal."""
        return verify_seal(self._key, expected_seal, **kwargs)
