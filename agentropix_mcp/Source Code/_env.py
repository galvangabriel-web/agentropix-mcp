"""Env-var helpers for the AGENTROPIX_* runtime tuning surface.

Established pattern (from ``feedback_env_var_pattern.md``): every runtime
knob that the operator may want to override at start time is read via
``AGENTROPIX_<DOMAIN>_<KEY>`` with a floor and a ceiling.  Out-of-range or
malformed values fall back to the documented default and emit a WARNING log
line, matching ``_subprocess.py`` and ``volatility.py``.

This module is import-cheap (stdlib + logging only) so wrappers and agents
can read tunables in their hot paths without dragging in the MCP surface.
"""

from __future__ import annotations

import logging
import os
from typing import overload

logger = logging.getLogger(__name__)


_SENTINEL = object()


def _coerce_int(name: str, raw: str) -> int | object:
    try:
        return int(raw)
    except (TypeError, ValueError):
        logger.warning("Invalid %s=%r (expected int); using default", name, raw)
        return _SENTINEL


def _coerce_float(name: str, raw: str) -> float | object:
    try:
        return float(raw)
    except (TypeError, ValueError):
        logger.warning("Invalid %s=%r (expected float); using default", name, raw)
        return _SENTINEL


def _clamp_int(name: str, value: int, floor: int | None, ceiling: int | None) -> int:
    if floor is not None and value < floor:
        logger.warning("%s=%s below floor %s; clamping to floor", name, value, floor)
        return floor
    if ceiling is not None and value > ceiling:
        logger.warning("%s=%s above ceiling %s; clamping to ceiling", name, value, ceiling)
        return ceiling
    return value


def _clamp_float(name: str, value: float, floor: float | None, ceiling: float | None) -> float:
    if floor is not None and value < floor:
        logger.warning("%s=%s below floor %s; clamping to floor", name, value, floor)
        return floor
    if ceiling is not None and value > ceiling:
        logger.warning("%s=%s above ceiling %s; clamping to ceiling", name, value, ceiling)
        return ceiling
    return value


def get_int(
    name: str,
    default: int,
    *,
    floor: int | None = None,
    ceiling: int | None = None,
) -> int:
    """Read ``AGENTROPIX_*`` int with floor/ceiling clamping.

    Unset env returns ``default`` unchanged.  Malformed input logs a warning
    and returns ``default`` (not clamped — defaults are trusted).
    """
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    value = _coerce_int(name, raw)
    if value is _SENTINEL:
        return default
    assert isinstance(value, int)
    return _clamp_int(name, value, floor, ceiling)


def get_float(
    name: str,
    default: float,
    *,
    floor: float | None = None,
    ceiling: float | None = None,
) -> float:
    """Read ``AGENTROPIX_*`` float with floor/ceiling clamping."""
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    value = _coerce_float(name, raw)
    if value is _SENTINEL:
        return default
    assert isinstance(value, float)
    return _clamp_float(name, value, floor, ceiling)


def clamp_float(
    name: str,
    value: float,
    *,
    floor: float | None = None,
    ceiling: float | None = None,
) -> float:
    """Clamp a caller-supplied float to ``[floor, ceiling]``.

    Mirrors the bounds enforcement applied to ``AGENTROPIX_*`` env-var
    reads in :func:`get_float`.  Use this when an MCP-tool caller may
    pass an explicit override that must respect the same documented
    bounds as the env-var fallback (e.g. a per-call ``timeout_seconds``
    override on ``scan_yara`` or ``get_evtx``).  Out-of-range values
    log a WARNING and are clamped to the nearer bound rather than
    rejected — the caller asked for "as long as possible" and we honor
    that within policy.
    """
    return _clamp_float(name, value, floor, ceiling)


def clamp_int(
    name: str,
    value: int,
    *,
    floor: int | None = None,
    ceiling: int | None = None,
) -> int:
    """Clamp an explicit int to ``[floor, ceiling]``, logging on out-of-range."""
    return _clamp_int(name, value, floor, ceiling)


def get_str_set(
    name: str,
    default: set[str],
    *,
    min_size: int = 1,
    max_size: int = 256,
) -> set[str]:
    """Read a comma-separated ``AGENTROPIX_*`` set of lowercase tokens.

    Unset / empty / whitespace-only env returns ``default`` unchanged.  Sets
    smaller than ``min_size`` or larger than ``max_size`` log a WARNING and
    fall back to ``default`` (clamping a set is meaningless — operator
    intent is unclear, so we honor the documented baseline).
    """
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return set(default)
    tokens = {t.strip().lower() for t in raw.split(",") if t.strip()}
    if len(tokens) < min_size:
        logger.warning(
            "%s parsed to %d token(s); below min_size %d, using default",
            name,
            len(tokens),
            min_size,
        )
        return set(default)
    if len(tokens) > max_size:
        logger.warning(
            "%s parsed to %d token(s); above max_size %d, using default",
            name,
            len(tokens),
            max_size,
        )
        return set(default)
    return tokens


def get_int_set(
    name: str,
    default: set[int],
    *,
    min_size: int = 0,
    max_size: int = 256,
) -> set[int]:
    """Read a comma-separated ``AGENTROPIX_*`` set of ints.

    Same semantics as ``get_str_set`` but coerces to ``int``.  Any
    non-integer token poisons the whole set → fall back to default.
    """
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return set(default)
    tokens_raw = [t.strip() for t in raw.split(",") if t.strip()]
    tokens: set[int] = set()
    for t in tokens_raw:
        try:
            tokens.add(int(t))
        except ValueError:
            logger.warning("Invalid %s token %r (expected int); using default", name, t)
            return set(default)
    if len(tokens) < min_size or len(tokens) > max_size:
        logger.warning(
            "%s size %d out of [%d, %d]; using default",
            name,
            len(tokens),
            min_size,
            max_size,
        )
        return set(default)
    return tokens


__all__ = [
    "clamp_float",
    "clamp_int",
    "get_float",
    "get_int",
    "get_int_set",
    "get_str_set",
]
