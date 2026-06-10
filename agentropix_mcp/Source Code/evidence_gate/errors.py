"""Exception hierarchy for the Step-2 evidence gate."""

from __future__ import annotations


class TokenError(ValueError):
    """Base class for any evidence-gate token rejection."""


class TokenFormatInvalid(TokenError):
    """Token does not match the expected `egt_<26-char-ULID>` shape."""


class TokenNotFound(TokenError):
    """Token was structurally valid but not present in the registry."""


class TokenExpired(TokenError):
    """Token's TTL window has elapsed since mint."""


class TokenAlreadySpent(TokenError):
    """Token was already verified+spent — replay rejected."""


class TokenRevoked(TokenError):
    """Token was revoked before this verify call."""


class TokenScopeMismatch(TokenError):
    """Token was minted for a different operation."""


class RegistryUnavailable(RuntimeError):
    """Step-2 registry could not be opened (no DB path, permission, etc.)."""
