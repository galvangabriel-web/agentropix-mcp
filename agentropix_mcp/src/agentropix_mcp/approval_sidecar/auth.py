"""SIFT-W-288: PBKDF2 key derivation + HMAC-SHA256 signature primitives.

Mirrors the contract the browser-side Web Crypto API will implement
in Phase 2 — keeping derivation parameters in one place so server
and client can never drift.

Threat model:

  - Attacker controls the wire (can inspect or replay any request).
  - Attacker does NOT have the approver password.
  - PBKDF2 iterations (default 600 000, env-tunable) make any
    offline-dictionary attack expensive even if the salt leaks.
  - HMAC-SHA256 over a server-issued nonce defeats replay.
  - The browser never sends the password; only ``HMAC-SHA256(key, msg)``.

Salt policy:

  The PBKDF2 salt is **per-examiner**, not per-request. A request-level
  salt would force the server to disclose it in the challenge response
  every time, leaking which examiner was about to act. Per-examiner
  salt is stored alongside the password hash in the sidecar config
  and shipped on the first challenge per examiner-session.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

# Defaults match Valhuntir's recorded threat model in
# ~/example/Valhuntir/docs/security.md (PBKDF2 with 600K iterations is
# the OWASP 2023 floor for SHA-256). Operators can raise via env on
# slower hardware; never lower.
DEFAULT_PBKDF2_ITERATIONS: int = 600_000
PBKDF2_DERIVED_KEY_BYTES: int = 32  # 256-bit key for HMAC-SHA256.
PBKDF2_SALT_BYTES: int = 16


def generate_salt() -> bytes:
    """Generate a fresh per-examiner salt. Operator-provisioned at
    examiner-account-create time; never rotated per-request."""
    return secrets.token_bytes(PBKDF2_SALT_BYTES)


def derive_key(
    password: str,
    salt: bytes,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
) -> bytes:
    """Derive the per-examiner HMAC key from the password + salt.

    Args:
        password: examiner password (never persisted on the sidecar
            beyond the derivation step in this very call).
        salt: per-examiner salt bytes. Must be the SAME salt the
            browser received in the challenge response.
        iterations: PBKDF2 iteration count. Sidecar default is 600 000;
            tests may use a smaller count for speed (but never default
            to it).

    Returns:
        32-byte derived key suitable for ``hmac.new(..., 'sha256')``.

    Notes:
        ``hashlib.pbkdf2_hmac`` is a C primitive — branchless on
        modern Pythons; not vulnerable to timing attacks on the key
        bytes (those are protected by the iteration count and by
        the fact that we never compare derived keys directly).
    """
    if not isinstance(password, str):
        raise TypeError("password must be str")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")
    if iterations < 1:
        raise ValueError("iterations must be >= 1")
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes(salt),
        iterations,
        dklen=PBKDF2_DERIVED_KEY_BYTES,
    )


def build_signed_message(
    nonce: str,
    target_id: str,
    target_type: str,
    from_status: str,
    to_status: str,
    case_id: str,
) -> bytes:
    """Build the canonical message that gets HMAC'd.

    Field order is fixed so the browser and the server compute the
    same byte string. Each component is utf-8 encoded and joined by
    a NUL byte (``\\x00``) — a byte that cannot legally appear inside
    any of the components (they are all keyword-typed in
    ``index_templates.py``) so concatenation is unambiguous.
    """
    parts = [nonce, target_id, target_type, from_status, to_status, case_id]
    for i, p in enumerate(parts):
        if not isinstance(p, str):
            raise TypeError(f"message component {i} must be str, got {type(p).__name__}")
        if "\x00" in p:
            raise ValueError(
                f"message component {i} contains NUL byte; rejected to "
                "prevent canonical-form ambiguity"
            )
    return b"\x00".join(p.encode("utf-8") for p in parts)


def hmac_signature(key: bytes, message: bytes) -> str:
    """Compute HMAC-SHA256 hex digest.

    Returns lowercase hex so the wire form is JSON-friendly without
    base64 padding ambiguity.
    """
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_signature(
    key: bytes,
    message: bytes,
    submitted_hex: str,
) -> bool:
    """Constant-time compare of submitted HMAC against the expected
    HMAC computed locally.

    Uses ``hmac.compare_digest`` to avoid the timing-side-channel
    that a naive ``==`` would expose (early-exit on first byte
    mismatch leaks signature length and prefix to an attacker who
    can time the response).
    """
    if not isinstance(submitted_hex, str):
        return False
    expected = hmac_signature(key, message)
    # compare_digest tolerates length differences without short-circuiting
    return hmac.compare_digest(expected, submitted_hex.lower())
