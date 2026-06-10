"""Thymus bridge — thin shim over the existing Thymus STRICT validator.

Fix 1 (CRITICAL S-1 from 01_security.md): All writes MUST be validated
by Thymus STRICT. This module is the single import point so the wazuh
package never imports the MCP server module tree directly (no circular deps).

ADR-008 (safety/Thymus) governs the Thymus STRICT + Oncologist framework.
"""

from __future__ import annotations

import logging
import re

__all__ = ["ThymusReject", "validate_input", "validate_inventory", "validate_body_sample", "ThymusBridge"]

logger = logging.getLogger(__name__)


class ThymusReject(Exception):
    """Raised when Thymus STRICT detects a safety violation.

    The offending value is NEVER included in the message to prevent
    prompt-injection content from leaking into logs or error messages.
    """

    redacted: str = "***REDACTED***"

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------------------
# Injection-detection patterns (SF-001: null bytes/control chars;
# SF-002: shell metacharacters / prompt-injection in IOC values)
# ---------------------------------------------------------------------------

_SF001_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SF002_PATTERN = re.compile(
    r"(ignore previous|drop table|<script|--|;.*--|/\*|\*/|"
    r"\\x[0-9a-f]{2}|\\u[0-9a-f]{4})",
    re.IGNORECASE,
)

# Colon injection in case_id / confidence / value fields
_COLON_INJECTION = re.compile(r"[\n\r].*:")


def _validate_string(value: str, field_name: str) -> None:
    """Apply SF-001 and SF-002 guards to a single string value."""
    if _SF001_PATTERN.search(value):
        logger.error(
            "Thymus SF-001: control character detected in field %s (value redacted)",
            field_name,
        )
        raise ThymusReject(f"SF-001 control-character injection detected in {field_name}")
    if _SF002_PATTERN.search(value):
        logger.error(
            "Thymus SF-002: prompt-injection pattern detected in field %s (value redacted)",
            field_name,
        )
        raise ThymusReject(f"SF-002 prompt-injection pattern detected in {field_name}")
    if _COLON_INJECTION.search(value):
        logger.error(
            "Thymus: newline+colon injection detected in field %s (value redacted)",
            field_name,
        )
        raise ThymusReject(f"Newline+colon injection pattern detected in {field_name}")


def validate_body_sample(sample: str, field_name: str = "request_body_sample") -> None:
    """Pattern-check a multi-line structured body sample.

    Applies SF-001 (control chars) and SF-002 (injection patterns) only.
    The colon-injection guard is deliberately excluded because CDB plaintext
    format legitimately contains ``newline + key: value`` lines — applying
    it here would produce false positives on every valid CDB PUT body.
    Individual IOC values are already colon-sanitised at the T1 touchpoint
    (``validate_inventory``).

    F-2: a previous version attempted to delegate to
    ``mcp_server.thymus_policy.validate_strict`` but that symbol does not
    exist; the import always raised ImportError and fell through to these
    patterns. The dead import has been removed; the patterns below are the
    actual policy in force. SIFT-W-178 tracks wiring real STRICT.
    """
    if _SF001_PATTERN.search(sample):
        logger.error("SF-001: control character in body sample %s (value redacted)", field_name)
        raise ThymusReject(f"SF-001 control-character injection detected in {field_name}")
    if _SF002_PATTERN.search(sample):
        logger.error("SF-002: injection pattern in body sample %s (value redacted)", field_name)
        raise ThymusReject(f"SF-002 prompt-injection pattern detected in {field_name}")


def validate_input(value: str, field_name: str = "value") -> str:
    """Pattern-check a single string (T1 touchpoint).

    Applies SF-001 (control chars), SF-002 (injection patterns), and
    colon-newline guards. Returns the value unchanged on pass; raises
    ``ThymusReject`` on any violation (the value is never echoed in the
    exception message — F-13 outbound sanitisation).

    F-2: the previous fake delegation to
    ``mcp_server.thymus_policy.validate_strict`` (a non-existent symbol)
    has been removed. These regexes are the policy in force. SIFT-W-178
    tracks wiring the real STRICT engine.
    """
    _validate_string(value, field_name)
    return value


def validate_inventory(inventory: object) -> None:
    """Validate all IOC values in an IOCInventory through Thymus STRICT.

    This is the orchestrator-level T1 touchpoint: called before any CDB
    transformer runs. If any IOC fails, the entire push is aborted.

    Raises:
        ThymusReject: on the first value that fails Thymus STRICT.
    """
    records = getattr(inventory, "records", None) or getattr(inventory, "items", None) or []
    validated = 0
    for rec in records:
        value = getattr(rec, "value", "")
        kind = getattr(rec, "kind", "unknown")
        try:
            validate_input(value, field_name=f"ioc[{kind}].value")
        except ThymusReject:
            logger.error("Thymus STRICT rejected IOC in inventory (kind=%s, value redacted)", kind)
            raise
        validated += 1

    logger.debug("Thymus STRICT: validated %d IOC values in inventory", validated)


class ThymusBridge:
    """Object-oriented interface — mirrors the sequence diagram naming."""

    def validate_input(self, value: str, field_name: str = "value") -> str:
        return validate_input(value, field_name)

    def validate_inventory(self, inventory: object) -> None:
        validate_inventory(inventory)

    def validate_body_sample(self, sample: str, field_name: str = "request_body_sample") -> None:
        validate_body_sample(sample, field_name)
