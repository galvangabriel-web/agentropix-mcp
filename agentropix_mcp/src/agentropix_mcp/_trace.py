"""Per-MCP-tool tracing layer (W-032, W-027).

Implements the contextvar-based design from
``docs/PHASE-1-PLUMBING-DESIGN.md`` §3.

Why a ContextVar:
    The orchestrator runs each agent in series, but agents may issue concurrent
    MCP calls inside a single agent task.  A ``ContextVar`` lets the orchestrator
    install a fresh per-agent buffer that every MCP call inherits without
    plumbing the buffer through agent / wrapper signatures.  When the agent
    finishes, the orchestrator drains the buffer and the next agent starts with
    a fresh one.

Record shape:
    Each entry matches ``report.schema.json`` ``trace.tool_calls`` items —
    ``tool``, ``timestamp``, ``duration_ms``, ``result_summary``.  The orchestrator
    keeps the existing ``agent.<name>`` rollup record AND appends the per-tool
    ``mcp.<tool>`` records the buffer collected (OI-4 b: rollups stay until the
    explicit deprecation gate).

W-027 extension: per-MCP-tool records also carry ``args_hash`` (stable
SHA-256 short-hash of the call's args+kwargs) and ``exit_code`` (0 ok,
1 ToolError return, 2 raised exception).  These two fields are required
for S-05 ("≥3 correlation discrepancies") because distinct call sites
with the same tool name need to be distinguishable in the trace, and
failed calls need to be visible without parsing the summary string.

Public surface:
    * ``trace_scope()``   — context manager: install a fresh buffer, yield it,
      tear it down on exit (caller drains before exiting).
    * ``record(tool, duration_ms, summary, *, args_hash=None, exit_code=None)``
      — push one entry into the active buffer, no-op when no scope is active.
    * ``traced(tool_name)`` — async decorator the MCP tool entries use to wrap
      a single ``try/except``: measures ``duration_ms`` to either the success
      return or the ``ToolError`` return / raised exception, builds a short
      ``result_summary``, hashes args, then pushes the record.
"""

from __future__ import annotations

import functools
import hashlib
import os
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any, TypedDict, TypeVar

_SUMMARY_MAX = 200

# Courtroom track (M8.2c). Default 4 KiB raw-output preservation per call;
# operator-tunable via ``AGENTROPIX_TRACE_RAW_MAX_BYTES``.
_DEFAULT_RAW_MAX_BYTES = 4096
_RAW_FLOOR_BYTES = 256
_RAW_CEILING_BYTES = 1024 * 1024


def _resolve_raw_max_bytes() -> int:
    raw = os.environ.get("AGENTROPIX_TRACE_RAW_MAX_BYTES")
    if not raw:
        return _DEFAULT_RAW_MAX_BYTES
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_RAW_MAX_BYTES
    return max(_RAW_FLOOR_BYTES, min(_RAW_CEILING_BYTES, value))


def _capture_raw_output(result: Any) -> tuple[str, str]:
    """Return a bounded snapshot and full-output SHA-256 of the tool return value.

    The snapshot is taken BEFORE any LLM-side summarisation so the
    courtroom track can replay deterministic tool output. Pydantic models
    serialise via ``model_dump_json``; other types fall back to ``repr``.

    Returns ``(snapshot, output_hash)`` where:
    * ``snapshot`` — text bounded by ``AGENTROPIX_TRACE_RAW_MAX_BYTES``
      (default 4 KiB).  May be truncated; the truncation marker is "…".
    * ``output_hash`` — SHA-256 hex digest of the FULL pre-truncation text
      (P3 / ADR-016: proves the snapshot was derived from the unmodified
      output even when the snapshot was truncated).

    A best-effort, never-raise function — failure returns ("", "").
    """
    cap = _resolve_raw_max_bytes()
    try:
        if hasattr(result, "model_dump_json"):
            text = result.model_dump_json()  # type: ignore[no-untyped-call]
        else:
            text = repr(result)
    except Exception:  # noqa: BLE001 — capture must never raise into the trace
        return "", ""
    output_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    if len(text) <= cap:
        return text, output_hash
    return text[: cap - 1] + "…", output_hash

# Exit-code semantics (span-status-like tri-state):
EXIT_OK = 0
EXIT_TOOL_ERROR = 1
EXIT_EXCEPTION = 2


class ToolCallRecord(TypedDict, total=False):
    """Schema-compliant ``trace.tool_calls`` item.

    Required: ``tool``, ``timestamp``, ``duration_ms``.
    W-032 added: ``result_summary`` (always populated by ``record``).
    W-027 added: ``args_hash`` (optional, present on ``mcp.*`` records via
    ``@traced``) and ``exit_code`` (optional, present on ``mcp.*`` records).
    W-060 added: ``counters`` (optional dict of dataflow counters —
    populated by instrumentation records like ``trace.timeline.counters``
    so the report carries structured per-layer counts rather than
    free-form summary strings).  See
    ``docs/adr/ADR-M6.3-residual-gap.md`` H1/H2/H3 for the motivating
    dataflow gap.
    """

    tool: str
    timestamp: str
    duration_ms: float
    result_summary: str
    args_hash: str
    exit_code: int
    counters: dict
    # Courtroom track (M8.2c, ADR-016): preserve a bounded slice of the raw
    # tool return value PRE-LLM-summarisation so a defense expert can replay
    # the deterministic step. Cap defaults to 4 KiB; tunable via
    # ``AGENTROPIX_TRACE_RAW_MAX_BYTES`` (floor 256 B, ceiling 1 MiB).
    raw_output: str
    # P3 (ADR-016): SHA-256 of the FULL pre-truncation output text.  Proves
    # the snapshot was derived from the unmodified tool output even when the
    # snapshot itself was capped.  Empty string when capture fails.
    output_hash: str


_current_trace: ContextVar[list[ToolCallRecord] | None] = ContextVar(
    "agentropix_trace", default=None
)


def _truncate(summary: str) -> str:
    if len(summary) <= _SUMMARY_MAX:
        return summary
    return summary[: _SUMMARY_MAX - 1] + "…"


def _summarise_result(result: Any) -> str:
    """Build a ≤200-char summary string for any tool return value.

    Three-state semantics:

    * ``ToolError`` (duck-typed: ``tool`` + ``error`` attrs) → ``ERROR: <msg>``
      (``exit_code=1``).
    * ``tool_available=False`` sentinel on the report → ``skipped: <reason>``
      (``exit_code=0``).  Emitted by wrappers whose backing binary is
      absent (M6.4 graceful-skip: amcache_parser, shimcache_parser).
    * otherwise → ``ok``.
    """
    if hasattr(result, "error") and hasattr(result, "tool"):
        err = getattr(result, "error", "")
        return _truncate(f"ERROR: {err}")
    if getattr(result, "tool_available", True) is False:
        reason = getattr(result, "skip_reason", "") or "tool unavailable"
        return _truncate(f"skipped: {reason}")
    return "ok"


def _is_tool_error(result: Any) -> bool:
    """Duck-typed ToolError detection mirroring ``_summarise_result``."""
    return hasattr(result, "error") and hasattr(result, "tool")


def hash_args(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    """Stable SHA-256-short hash of a call's args+kwargs (W-027).

    The hash is intentionally coarse: ``repr()`` of each argument in
    positional order plus kwargs sorted by key.  Two calls that pass the
    same ``Path`` objects, the same ``dict`` values, and the same
    keyword-only options end up with the same ``args_hash`` — which is
    exactly the discrimination we need to spot "tool X called twice with
    different target paths" in a trace without emitting the full target
    path (privacy / size).
    """
    try:
        parts = [repr(a) for a in args]
        parts.extend(f"{k}={v!r}" for k, v in sorted(kwargs.items()))
        payload = "|".join(parts)
    except Exception:  # noqa: BLE001 — never let repr raise into the trace
        payload = f"unhashable:{len(args)}:{sorted(kwargs)}"
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]


@contextmanager
def trace_scope() -> Iterator[list[ToolCallRecord]]:
    """Install a fresh per-agent buffer, yield it, tear it down on exit."""
    buf: list[ToolCallRecord] = []
    token = _current_trace.set(buf)
    try:
        yield buf
    finally:
        _current_trace.reset(token)


def record(
    tool: str,
    duration_ms: float,
    summary: str,
    *,
    args_hash: str | None = None,
    exit_code: int | None = None,
    counters: dict | None = None,
    raw_output: str | None = None,
    output_hash: str | None = None,
) -> None:
    """Append a record to the active buffer; no-op when no scope is active.

    W-027: ``args_hash`` and ``exit_code`` are optional so agent rollups
    (which are pushed by the orchestrator, not by ``@traced``) can omit
    them.  The schema declares both as optional.

    W-060: ``counters`` is an optional structured dict of dataflow
    counters (e.g. ``jsonl_rows_read``, ``priority_hits_by_family``).
    Schema ``report.schema.json`` declares it as an optional object.

    M8.2c (ADR-016): ``raw_output`` is the courtroom-track raw tool
    return snapshot, captured PRE-LLM-summarisation. Bounded by
    ``AGENTROPIX_TRACE_RAW_MAX_BYTES`` (default 4 KiB).

    P3 (ADR-016): ``output_hash`` is the SHA-256 of the full pre-truncation
    output text.  Proves the snapshot is derived from the unmodified output.
    """
    buf = _current_trace.get()
    if buf is None:
        return
    entry: ToolCallRecord = {
        "tool": tool,
        "timestamp": datetime.now(UTC).isoformat(),
        "duration_ms": round(duration_ms, 2),
        "result_summary": _truncate(summary),
    }
    if args_hash is not None:
        entry["args_hash"] = args_hash
    if exit_code is not None:
        entry["exit_code"] = exit_code
    if counters is not None:
        entry["counters"] = dict(counters)
    if raw_output is not None and raw_output != "":
        entry["raw_output"] = raw_output
    if output_hash is not None and output_hash != "":
        entry["output_hash"] = output_hash
    buf.append(entry)


F = TypeVar("F", bound=Callable[..., Awaitable[Any]])


def traced(tool_name: str) -> Callable[[F], F]:
    """Decorator: record ``mcp.<tool_name>`` entry on every invocation.

    Records on success (``exit_code=0``), on ``ToolError`` return
    (``exit_code=1``), and on raised exception (``exit_code=2``).  The
    raised exception is re-raised after the record is pushed.
    ``duration_ms`` is measured to the failure point.  ``args_hash`` is a
    stable SHA-256 short-hash over the call's positional + keyword
    arguments (W-027).
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            t0 = time.monotonic()
            call_hash = hash_args(args, kwargs)
            try:
                result = await func(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 — record then re-raise
                elapsed_ms = (time.monotonic() - t0) * 1000
                record(
                    f"mcp.{tool_name}",
                    elapsed_ms,
                    _truncate(f"ERROR: {exc!s}"),
                    args_hash=call_hash,
                    exit_code=EXIT_EXCEPTION,
                )
                raise
            elapsed_ms = (time.monotonic() - t0) * 1000
            exit_code = EXIT_TOOL_ERROR if _is_tool_error(result) else EXIT_OK
            raw_snapshot, out_hash = _capture_raw_output(result)
            record(
                f"mcp.{tool_name}",
                elapsed_ms,
                _summarise_result(result),
                args_hash=call_hash,
                exit_code=exit_code,
                raw_output=raw_snapshot,
                output_hash=out_hash,
            )
            return result

        return wrapper  # type: ignore[return-value]

    return decorator


__all__ = [
    "EXIT_EXCEPTION",
    "EXIT_OK",
    "EXIT_TOOL_ERROR",
    "ToolCallRecord",
    "hash_args",
    "record",
    "trace_scope",
    "traced",
]
