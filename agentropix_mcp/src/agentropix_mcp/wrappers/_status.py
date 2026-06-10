"""Uniform tool-response status taxonomy (QA fixing plan 2026-05-30, WS-A keystone).

The cross-cutting QA failure mode is "failures masquerading as success": a tool
runs to completion (no exception → FastMCP ``isError:false``) but produces empty,
identical, or unsupported output with no machine-readable signal. An unattended
driver then logs "clean" when the tool really meant "didn't run".

This module introduces an explicit status taxonomy that wrappers opt into:

    status: "ok" | "unsupported" | "failed" | "partial"
    reason: stable machine-readable slug ("" when status == ok)
    reason_detail: free human text (existing skipped_reason / stderr flows here)

Rollout is gated by ``AGENTROPIX_STATUS_TAXONOMY=1`` for one release so default
behaviour is unchanged until orchestrators are updated (operator decision
2026-05-30). When the flag is off, ``classify_*`` helpers still compute the
status (cheap, side-effect-free) but callers leave report fields at their
``status="ok"`` defaults — see each wrapper's opt-in.

isError reconciliation (operator decision 2026-05-30): ``failed`` ⇒ isError true
(raise ``ToolFailed`` at the MCP boundary); ``partial`` and ``unsupported`` stay
isError false so the agent keeps the (degraded/empty) payload and branches on
``reason``.
"""

from __future__ import annotations

import os
from enum import StrEnum


class ToolStatus(StrEnum):
    """Explicit outcome of a tool invocation."""

    OK = "ok"  # ran; output is trustworthy (0 results may still be OK — a true negative)
    UNSUPPORTED = "unsupported"  # wrong asset/OS/build for this tool; agent should pivot, not retry
    FAILED = "failed"  # ran or refused and produced nothing usable; isError true at the boundary
    PARTIAL = "partial"  # produced some output but a sub-step degraded (fallback, cap, write fail)


# --- stable reason slugs (machine-readable; not free text) -------------------
REASON_SYMBOL_RESOLUTION_FAILED = "symbol_resolution_failed"
REASON_EMPTY_OUTPUT = "empty_output"
REASON_PSSCAN_FALLBACK = "psscan_fallback"
REASON_UNSUPPORTED_BUILD = "unsupported_os_build"
REASON_DISK_IMAGE_INPUT = "disk_image_input"
REASON_SUBPROCESS_ERROR = "subprocess_error"
REASON_INDEXER_WRITE_FAILED = "indexer_write_failed"


class ToolFailed(Exception):
    """Raise at the MCP boundary to map status=failed → FastMCP isError:true.

    Carries the machine-readable ``reason`` slug plus human ``detail`` so the
    surfaced error envelope is structured, not a bare traceback string.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


def taxonomy_enabled() -> bool:
    """True when AGENTROPIX_STATUS_TAXONOMY opts into the new status fields.

    Matches the repo's bool-env convention (plaso.py / editbox.py).
    """
    return os.environ.get("AGENTROPIX_STATUS_TAXONOMY", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )


# vol3 emits these to stderr (or rc!=0) when a kernel symbol table / ISF pack
# cannot be resolved. In that state vol3 frequently still exits rc==0 with an
# EMPTY CSV — which the wrappers historically returned as a clean 0-result.
# Root cause behind QA issues 01/11/14/15. Markers are matched case-insensitively.
_SYMBOL_FAILURE_MARKERS: tuple[str, ...] = (
    "symbol table could not be resolved",
    "unable to validate the plugin requirements",
    "unsatisfied requirement",
    "symbolerror",
    "no suitable",  # "No suitable address space mapping found"
    "could not resolve the symbol",
)


def detect_symbol_failure(returncode: int, stdout: str, stderr: str) -> str | None:
    """Return a reason slug if a vol3 run looks like a symbol-resolution failure.

    Two signatures:
      * any symbol-failure marker present in stderr (regardless of rc), OR
      * rc != 0 with empty stdout (a hard failure that produced nothing).

    Returns ``None`` when the run looks like a genuine (possibly empty) success.
    A populated stdout with no markers is treated as success even on a non-zero
    rc (vol3 sometimes warns on stderr while still emitting rows).
    """
    blob = (stderr or "").lower()
    if any(marker in blob for marker in _SYMBOL_FAILURE_MARKERS):
        return REASON_SYMBOL_RESOLUTION_FAILED
    if returncode != 0 and not (stdout or "").strip():
        return REASON_SUBPROCESS_ERROR
    return None
