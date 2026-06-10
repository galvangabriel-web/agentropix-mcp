"""WZ-021 (master-report §4.4 #16a, C4-SOFTENG F4): the `_safe_tool` decorator.

Wraps every ``@app.tool`` async callable so exceptions never escape to
the FastMCP boundary. Returns a flat ``{"error": str, "details": dict}``
envelope instead, which:

  - keeps the agent loop's recovery path alive (a Pydantic
    ValidationError or httpx 5xx in one tool call no longer crashes the
    agent's iteration)
  - centralises the error-shape contract so every consumer can rely on
    it without reading per-tool docstrings
  - gives ops a single place to instrument + audit error rates

The decorator does NOT swallow programming bugs — ``KeyboardInterrupt``,
``SystemExit``, and ``asyncio.CancelledError`` propagate untouched.
Anything else is caught, logged, and converted to the envelope.

Composes with the WZ-002 ``_wazuh_retry_policy()`` tenacity helper:
the retry decorator is applied INSIDE ``_safe_tool`` (i.e. retry first,
then envelope the final outcome).

Usage::

    from agentropix_mcp.wazuh.indexer_client import _wazuh_retry_policy
    from agentropix_mcp.wrappers._safe_tool import safe_tool

    @app.tool()
    @safe_tool(tool_name="wazuh_hunt_ioc")
    @_wazuh_retry_policy()
    async def wazuh_hunt_ioc(ioc_value: str, ioc_type: str) -> dict:
        ...
        return {"hits": [...]}    # success: passes through unchanged
        raise WazuhError(...)     # failure: caught, returned as envelope
"""

from __future__ import annotations

import asyncio
import functools
import logging
from typing import Any, Awaitable, Callable, TypeVar

import httpx
from pydantic import ValidationError

logger = logging.getLogger(__name__)

__all__ = ["safe_tool", "ToolErrorEnvelope"]

T = TypeVar("T")


class ToolErrorEnvelope(dict):
    """Marker subclass of ``dict`` so callers can detect envelopes.

    Returned by ``safe_tool`` on any caught exception. Shape::

        {
            "error": str,                # short error class / category
            "details": {
                "exception_class": str,  # e.g. "WazuhError" / "ValidationError"
                "message": str,          # str(exc), truncated to 500 chars
                "tool": str,             # tool_name passed to safe_tool()
            }
        }

    Callers (especially the FastMCP layer) can:

      - check ``isinstance(result, ToolErrorEnvelope)`` to branch on
        success vs failure without parsing the dict shape
      - or just check ``"error" in result`` for the duck-typed path
    """


# Exceptions that MUST propagate (programming bugs / runtime control flow).
# Catching these would mask real problems.
_NEVER_CATCH = (
    KeyboardInterrupt,
    SystemExit,
    asyncio.CancelledError,
)


def _classify_exception(exc: BaseException) -> str:
    """Return a short error category for the envelope's `error` field.

    Maps known wrapper-layer exception types to stable category strings
    so consumers can branch on category without reading exception
    messages. Unknown exceptions fall through to the class name.
    """
    cls_name = type(exc).__name__
    # Pre-imported to avoid circular imports at module load.
    if isinstance(exc, ValidationError):
        return "validation_error"
    if isinstance(exc, httpx.HTTPError):
        return "http_error"
    # WazuhError / IndexerError / TransientHTTPError are caught by name
    # rather than import to avoid coupling this decorator to those
    # modules (keeps the wrappers/_safe_tool.py module self-contained
    # and importable in tests without pulling the full wazuh stack).
    if cls_name in ("WazuhError", "AuthError", "RateLimitedError"):
        return "wazuh_error"
    if cls_name in ("IndexerError", "TransientHTTPError"):
        return "indexer_error"
    return cls_name.lower()


def safe_tool(*, tool_name: str) -> Callable[
    [Callable[..., Awaitable[T]]],
    Callable[..., Awaitable[T | ToolErrorEnvelope]],
]:
    """Decorator factory for MCP tool error-envelope wrapping.

    Args:
        tool_name: short identifier for this tool, included in the
            envelope's `details.tool` field. Must match the
            ``@app.tool()`` registration name so ops can correlate.

    Returns:
        A decorator that wraps an async function. On success, returns
        the wrapped function's result unchanged. On any caught
        exception (everything except _NEVER_CATCH), returns a
        ``ToolErrorEnvelope`` dict.
    """

    def decorator(
        func: Callable[..., Awaitable[T]],
    ) -> Callable[..., Awaitable[T | ToolErrorEnvelope]]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T | ToolErrorEnvelope:
            try:
                return await func(*args, **kwargs)
            except _NEVER_CATCH:
                # Programming control flow / shutdown signals must
                # propagate. Catching these would hide real problems.
                raise
            except Exception as exc:  # noqa: BLE001
                category = _classify_exception(exc)
                # str(exc) can include sensitive arg values; truncate
                # so an oversized indexer response body or a long
                # validation message doesn't bloat the audit row.
                message = str(exc)[:500]
                logger.warning(
                    "safe_tool(%s) caught %s: %s",
                    tool_name,
                    category,
                    message,
                )
                return ToolErrorEnvelope(
                    error=category,
                    details={
                        "exception_class": type(exc).__name__,
                        "message": message,
                        "tool": tool_name,
                    },
                )

        return wrapper

    return decorator
