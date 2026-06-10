"""Evidence gate — mutation token verification for the Wazuh write path.

Fix 2 (CRITICAL S-2 from 01_security.md): The gate MUST fail closed.
If the verifier module cannot be imported, EvidenceGateRequired is raised —
the system never silently passes an unverified token.

The correct ADR context for this is NOT ADR-011 (which is evidence file
type detection for EWF/E01 containers). The mutation token regime is
documented in ADR-018 (Wazuh IOC push, created alongside this integration).

Design note: in Step 1, the evidence gate performs a lightweight structural
check on the token format (``egt_<ULID>`` prefix). A full cryptographic
verification against the evidence-gate registry is wired when the
``agentropix_mcp.evidence_gate`` module is available. Without it the gate
raises EvidenceGateRequired — fail closed, never silently pass.
"""

from __future__ import annotations

import logging
import re

__all__ = ["EvidenceGateRequired", "verify_evidence_token", "EvidenceGate"]

logger = logging.getLogger(__name__)

# Token format: egt_<ULID> (26-char base32 ULID)
_TOKEN_PATTERN = re.compile(r"^egt_[0-9A-Z]{26}$")


class EvidenceGateRequired(Exception):
    """Raised when the evidence gate cannot grant the mutation request.

    Raised in ALL cases where the token is missing, invalid, or the
    verifier module is unavailable (fail-closed by design).
    """


def _try_import_verifier():  # type: ignore[return]
    """Attempt to import the real evidence-gate verifier.

    Returns the verify callable or None if the module is not installed.
    CRITICAL: this function must NEVER suppress errors silently for
    security-gating purposes — the caller checks for None and raises.
    """
    try:
        from agentropix_mcp.evidence_gate import verify  # type: ignore[import-not-found]

        return verify
    except ImportError:
        return None


def verify_evidence_token(token: str | None, *, op: str = "push_iocs") -> None:
    """Verify that the evidence gate token is valid for the requested operation.

    Fail-closed semantics (Fix 2 / S-2):
    - If token is None or empty → EvidenceGateRequired
    - If token does not match the expected format → EvidenceGateRequired
    - If the verifier module is not importable → EvidenceGateRequired
      (NEVER silently pass; import failure = gate failure)
    - If the verifier module raises → EvidenceGateRequired

    Args:
        token: The evidence gate token string (``egt_<ULID>``).
        op: The operation being authorised (default: ``push_iocs``).

    Raises:
        EvidenceGateRequired: Always raised on any failure to verify.
    """
    if not token or not token.strip():
        raise EvidenceGateRequired(
            "Evidence gate token is required for mutation operations. "
            "Mint a token with: agentropix-sift evidence-gate mint"
        )

    token = token.strip()

    # Structural format check — catches obviously bogus tokens before
    # importing the verifier (cheap, no I/O)
    if not _TOKEN_PATTERN.match(token):
        raise EvidenceGateRequired(
            f"Evidence gate token {token!r} does not match expected format egt_<26-char-ULID>. Mint a fresh token."
        )

    # CRITICAL: import the verifier — fail closed if unavailable
    verifier = _try_import_verifier()
    if verifier is None:
        raise EvidenceGateRequired(
            "EvidenceGateRequired: verifier module "
            "'agentropix_mcp.evidence_gate' is unavailable. "
            "The gate refuses to pass any token when the verifier cannot be "
            "imported (fail-closed; security fix S-2). "
            "Install the evidence-gate module or check your PYTHONPATH."
        )

    # Delegate to the real verifier
    try:
        verifier(token, op=op)
    except Exception as exc:  # noqa: BLE001
        raise EvidenceGateRequired(f"Evidence gate verification failed for token {token[:12]}...: {exc}") from exc

    logger.info("Evidence gate: token %s... authorised for op=%s", token[:12], op)


class EvidenceGate:
    """Object-oriented interface around verify_evidence_token."""

    def verify(self, token: str | None, *, op: str = "push_iocs") -> None:
        """Verify the token; raises EvidenceGateRequired on failure."""
        verify_evidence_token(token, op=op)

    def check(self, token: str | None, op: str = "push_iocs") -> None:
        """Alias for verify() — used in sequence-diagram naming."""
        verify_evidence_token(token, op=op)
