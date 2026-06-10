"""W-136 §4.1 — pinned-binary integrity verification.

Verifies the SHA-256 digest of every external binary the wrappers shell
out to against the table in ``docs/EXTERNAL-TOOL-PINS.md``. Runs once at
MCP server startup so a swapped-out binary surfaces immediately rather
than producing silently-wrong forensic output.

Trust mode is controlled by ``AGENTROPIX_VERIFY_TOOL_PINS``:

- ``off``    — no check (development only)
- ``warn``   — default; log WARNING per mismatch, server starts
- ``strict`` — refuse to start; raise :class:`ToolPinMismatchError`

Pins live in :data:`_PINS`. Mirror any change with the table in
``docs/EXTERNAL-TOOL-PINS.md`` — the `update procedure` in that doc is
the source-of-truth for adding/upgrading entries.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ToolPin:
    """Single pinned binary."""

    name: str
    sha256: str
    version: str  # human-readable tag for the banner


# Source-of-truth: ``docs/EXTERNAL-TOOL-PINS.md``. Keep in sync.
_PINS: tuple[ToolPin, ...] = (
    ToolPin(
        name="evtx_dump",
        sha256="3de883ea615af3b0b595f9cb89545472329b4d7281b67e5981aa146fb7ab1aad",
        version="0.11.2",
    ),
    ToolPin(
        name="yara",
        sha256="556283bf37712ed645552d5e84330a6c0c31d9000bd799dd375528bdc51245c3",
        version="apt",
    ),
    ToolPin(
        name="bulk_extractor",
        sha256="dd326a62952214e2362a113531a8ee8cbedcdc2d0ca9c8111090803662da342d",
        version="apt",
    ),
)


class ToolPinMismatchError(RuntimeError):
    """Raised in strict mode when a binary digest doesn't match the pin."""


def _sha256_of(path: str) -> str:
    """Stream-hash a file; tolerate >GB binaries without loading into memory."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _resolve_pin_path(pin: ToolPin) -> str | None:
    """Honor the corresponding ``AGENTROPIX_*_TOOL`` env-var override.

    The wrappers all look up their binary via
    ``os.environ.get("AGENTROPIX_<NAME>_TOOL", default)`` then
    ``shutil.which``. We replay the same resolution so the digest check
    targets the same file the wrapper will actually invoke at runtime.
    """
    env_var = f"AGENTROPIX_{pin.name.upper()}_TOOL"
    name = os.environ.get(env_var) or pin.name
    return shutil.which(name)


def verify_pins() -> list[tuple[ToolPin, str, str]]:
    """Verify every pin against the resolved binary on disk.

    Returns the list of mismatches as ``(pin, resolved_path, actual_sha)``.
    Empty list means all good. Honors ``AGENTROPIX_VERIFY_TOOL_PINS``:

    - ``off`` — return ``[]`` immediately, no I/O.
    - ``warn`` — log WARNING per mismatch, return them so callers can
      surface them in the banner; server continues.
    - ``strict`` — log ERROR per mismatch and raise
      :class:`ToolPinMismatchError` after enumerating all mismatches
      (so the operator sees every divergence in one go, not just the
      first).

    A binary that's missing on PATH is *not* a pin failure — it's a
    dependency-availability concern handled by ``_check_dependencies``.
    Pins only flag *mismatched* binaries.
    """
    mode = os.environ.get("AGENTROPIX_VERIFY_TOOL_PINS", "warn").lower().strip()
    if mode == "off":
        return []
    if mode not in {"warn", "strict"}:
        logger.warning(
            "AGENTROPIX_VERIFY_TOOL_PINS=%r unrecognised; defaulting to 'warn'",
            mode,
        )
        mode = "warn"

    mismatches: list[tuple[ToolPin, str, str]] = []
    for pin in _PINS:
        resolved = _resolve_pin_path(pin)
        if resolved is None:
            # No binary to verify — that's a missing-dependency, not a
            # pin mismatch. Log INFO so the operator sees we skipped it.
            logger.info("pin SKIP   %-20s (binary not on PATH)", pin.name)
            continue
        actual = _sha256_of(resolved)
        if actual == pin.sha256:
            logger.info(
                "pin OK     %-20s -> %s (%s, %s)",
                pin.name, resolved, pin.version, pin.sha256[:12],
            )
            continue
        mismatches.append((pin, resolved, actual))
        msg = (
            f"pin MISMATCH {pin.name:<18} expected {pin.sha256[:16]}.. "
            f"got {actual[:16]}.. at {resolved}"
        )
        if mode == "strict":
            logger.error(msg)
        else:
            logger.warning(msg)

    if mismatches and mode == "strict":
        names = ", ".join(p.name for p, _, _ in mismatches)
        raise ToolPinMismatchError(
            f"{len(mismatches)} tool-pin mismatch(es): {names}. "
            "Update docs/EXTERNAL-TOOL-PINS.md and src/agentropix_mcp/"
            "mcp_server/_tool_pins.py if intentional, or restore the "
            "expected binary."
        )
    return mismatches


__all__ = [
    "ToolPin",
    "ToolPinMismatchError",
    "verify_pins",
]
