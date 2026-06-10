"""Evidence-gate token regime — Step 2 (SIFT-W-A11).

Provides the cryptographic token registry the Step-1 stub deferred:
atomic verify+spend, replay protection, expiry, revocation, scoped
operations.

Public API:
  verify(token, *, op)
    Back-compat shim used by `wazuh.evidence_gate.verify_evidence_token`.
    Routes to `verify_and_spend` against the default registry. The
    `run_id` is read from the `AGENTROPIX_RUN_ID` env var if set.

  verify_and_spend(token, *, op, run_id=None, registry=None)
    Atomic verify + mark-as-spent. Raises TokenError variants on failure.

  mint(*, scope, ttl_seconds, operator=None, registry=None) -> str
    Create a new token; returns the bearer secret.

  revoke(token, *, registry=None) -> bool
    Revoke a token; returns True if the row existed.

  list_tokens(...) -> list[TokenRow]
    Inspect the registry.

Configuration:
  AGENTROPIX_EVIDENCE_GATE_DB
    SQLite path; default `~/.agentropix/evidence-gate.sqlite`
  AGENTROPIX_EVIDENCE_GATE_STEP1_STUB
    Legacy escape hatch — when "true", `verify()` falls back to the
    Step-1 structural-format-only check (no replay/expiry/revocation).
    Reserved for cases where the registry isn't writable.
  AGENTROPIX_RUN_ID
    Optional run identifier the orchestrator can set so
    verify-and-spend records which run consumed each token.

ADR-018 (Wazuh IOC push mutation token regime).
"""

from __future__ import annotations

import logging
import os
import re

from .errors import (
    RegistryUnavailable,
    TokenAlreadySpent,
    TokenError,
    TokenExpired,
    TokenFormatInvalid,
    TokenNotFound,
    TokenRevoked,
    TokenScopeMismatch,
)
from .registry import TokenRegistry, TokenRow

__all__ = [
    # API
    "verify",
    "verify_and_spend",
    "mint",
    "revoke",
    "list_tokens",
    # Types
    "TokenRegistry",
    "TokenRow",
    # Exceptions
    "TokenError",
    "TokenFormatInvalid",
    "TokenNotFound",
    "TokenExpired",
    "TokenAlreadySpent",
    "TokenRevoked",
    "TokenScopeMismatch",
    "RegistryUnavailable",
]

logger = logging.getLogger(__name__)

_TOKEN_PATTERN = re.compile(r"^egt_[0-9A-Z]{26}$")
_STUB_OPTIN_ENV = "AGENTROPIX_EVIDENCE_GATE_STEP1_STUB"


def _stub_enabled() -> bool:
    return os.environ.get(_STUB_OPTIN_ENV, "").strip().lower() in ("true", "1", "yes")


def _default_registry() -> TokenRegistry:
    return TokenRegistry()


def verify(token: str, *, op: str = "push_iocs") -> None:
    """Back-compat entry point used by wazuh.evidence_gate.verify_evidence_token.

    Behavior:
      - In Step-2 mode (default): atomic verify+spend against the registry.
      - In Step-1 stub mode (AGENTROPIX_EVIDENCE_GATE_STEP1_STUB=true):
        structural format check only; tokens are NOT consumed.

    Raises:
      ValueError on token-format problems (Step-1 fallback path).
      TokenError variants on any registry-side rejection.
      RuntimeError when neither Step-2 nor explicit Step-1 stub is enabled.
    """
    if _stub_enabled():
        if not token or not _TOKEN_PATTERN.match(token.strip()):
            raise ValueError(
                f"Token {token[:20]!r} does not match egt_<26-char-ULID> format. "
                "Mint a fresh token."
            )
        logger.warning(
            "evidence_gate.verify: STEP-1 STUB IN USE (no replay/expiry/revocation) "
            "token=%s... op=%s",
            token[:12],
            op,
        )
        return

    # Step-2 path: atomic verify+spend.
    run_id = os.environ.get("AGENTROPIX_RUN_ID") or None
    verify_and_spend(token, op=op, run_id=run_id)


def verify_and_spend(
    token: str,
    *,
    op: str,
    run_id: str | None = None,
    registry: TokenRegistry | None = None,
) -> TokenRow:
    """Atomic verify + spend; raises TokenError variants on rejection."""
    reg = registry or _default_registry()
    return reg.verify_and_spend(token, op=op, run_id=run_id)


def mint(
    *,
    scope: str,
    ttl_seconds: int,
    operator: str | None = None,
    registry: TokenRegistry | None = None,
) -> str:
    """Mint a new token; returns the bearer secret. Persist + return."""
    reg = registry or _default_registry()
    return reg.mint(scope=scope, ttl_seconds=ttl_seconds, operator=operator)


def revoke(token: str, *, registry: TokenRegistry | None = None) -> bool:
    """Revoke a token by full bearer secret; returns True if it existed."""
    reg = registry or _default_registry()
    return reg.revoke(token)


def list_tokens(
    *,
    scope: str | None = None,
    include_spent: bool = True,
    include_revoked: bool = True,
    include_expired: bool = True,
    registry: TokenRegistry | None = None,
) -> list[TokenRow]:
    reg = registry or _default_registry()
    return reg.list_tokens(
        scope=scope,
        include_spent=include_spent,
        include_revoked=include_revoked,
        include_expired=include_expired,
    )
