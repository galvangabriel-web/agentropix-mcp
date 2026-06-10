"""Glob-based path enumeration primitive for MCP self-enumeration (W-084).

Operators previously had to feed paths to the agent out-of-band because
no MCP tool let an agent enumerate files matching a glob pattern. The
SRL-2018 triage processed 34,928 mitre-cti files via 450 individual
calls because this primitive did not exist. This wrapper closes that
gap.

Pattern handling:

    glob_paths("/cases/*/raw/*.E01")
        → ["/cases/SRL-2018/raw/disk-01.E01", ...]

The longest non-glob prefix of the pattern (``/cases/`` in the example)
is checked against the Thymus read zone before any expansion happens.
After expansion every individual result is re-checked with
``_policy.check_read``; results outside the allowlist are silently
dropped (``rejected_count`` surfaces the count). Patterns containing
``..`` are rejected up front without touching the policy at all.

The wrapper is intentionally subprocess-free (pure ``pathlib.Path.glob``)
to keep it deterministic and hermetic — no external binary surface.
"""

from __future__ import annotations

import logging
from pathlib import Path

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Glob meta-characters used to find the longest non-glob prefix.  Square
# brackets are included because ``Path.glob`` treats ``[abc]`` as a
# character class.
_GLOB_META = frozenset("*?[")


class GlobPathsResult(BaseModel):
    """Result of a ``glob_paths`` enumeration."""

    paths: list[str] = Field(default_factory=list)
    truncated: bool = False
    rejected_count: int = 0
    tool_available: bool = True
    error: str | None = None


def _longest_non_glob_prefix(pattern: str) -> str:
    """Return the longest leading path component(s) free of glob meta.

    For ``/cases/SRL-2018/raw/*/*.E01`` returns ``/cases/SRL-2018/raw/``.
    For an absolute pattern with no glob chars returns the pattern as-is.
    For a relative pattern returns ``"."``.
    """
    parts = Path(pattern).parts
    if not parts:
        return "."
    prefix_parts: list[str] = []
    for part in parts:
        if any(ch in _GLOB_META for ch in part):
            break
        prefix_parts.append(part)
    if not prefix_parts:
        return "."
    prefix = str(Path(*prefix_parts))
    # Preserve trailing slash so prefix-style policy matching is clean.
    if not prefix.endswith("/"):
        prefix = prefix + "/"
    return prefix


def run_glob_paths(
    pattern: str,
    max_results: int = 1000,
    follow_symlinks: bool = False,
) -> GlobPathsResult:
    """Enumerate filesystem paths matching ``pattern`` under Thymus zones.

    Args:
        pattern: Glob pattern (e.g. ``/cases/*/raw/*.E01``). May contain
            ``*``, ``?``, and character classes. ``..`` traversal is
            rejected outright.
        max_results: Cap on returned paths. ``truncated=True`` when hit.
        follow_symlinks: When True, ``Path.resolve()`` is applied to each
            result so symlinks are followed and the policy check runs
            against the resolved target. Default False — symlinks in the
            result set are dropped (their resolution would bypass Thymus).

    Returns:
        GlobPathsResult with ``paths``, ``truncated``, ``rejected_count``,
        ``tool_available=True`` (always — pure pathlib, no binary), and
        ``error`` populated only on traversal rejection.
    """
    # Lazy import to avoid a circular: wrappers/* should not import
    # mcp_server.server at module load time. The policy is a module
    # attribute on server.py and may be reconfigured at runtime via
    # ``configure_policy``.
    from agentropix_mcp import server as _inner

    if ".." in pattern:
        return GlobPathsResult(
            paths=[],
            truncated=False,
            rejected_count=0,
            tool_available=True,
            error="pattern contains forbidden traversal sequence '..'",
        )

    has_glob_meta = any(ch in _GLOB_META for ch in pattern)
    prefix = _longest_non_glob_prefix(pattern)
    prefix_violation = _inner._policy.check_read(prefix)
    if prefix_violation:
        return GlobPathsResult(
            paths=[],
            truncated=False,
            rejected_count=0,
            tool_available=True,
            error=prefix_violation,
        )

    if not has_glob_meta:
        # Pattern had no glob chars — treat as an identity check on
        # ``pattern`` itself. If it exists and passes Thymus, return it;
        # otherwise return empty.
        candidate = Path(pattern)
        if candidate.exists():
            return GlobPathsResult(
                paths=[str(candidate)],
                truncated=False,
                rejected_count=0,
                tool_available=True,
            )
        return GlobPathsResult(
            paths=[],
            truncated=False,
            rejected_count=0,
            tool_available=True,
        )

    # Split the pattern into a base directory and the relative glob the
    # base must be expanded against. ``Path.glob`` operates on a base
    # directory + relative pattern; passing an absolute pattern to
    # ``Path.glob`` raises NotImplementedError on Python <3.13.
    base_path = Path(prefix)
    relative_pattern = pattern[len(prefix):] if pattern.startswith(prefix) else pattern

    paths: list[str] = []
    rejected_count = 0
    truncated = False

    try:
        iterator = base_path.glob(relative_pattern)
    except (OSError, ValueError) as exc:
        return GlobPathsResult(
            paths=[],
            truncated=False,
            rejected_count=0,
            tool_available=True,
            error=f"glob expansion failed: {exc}",
        )

    for match in iterator:
        if len(paths) >= max_results:
            truncated = True
            break
        # Hidden-file exclusion: drop ``.foo`` style names. Python's
        # ``Path.glob`` *does* return these for ``*`` patterns (contrary
        # to shell-glob convention); we filter explicitly so the wrapper
        # contract is consistent across platforms and Python versions.
        if match.name.startswith("."):
            continue
        # Symlink handling: when follow_symlinks=False (default), drop
        # symlink results entirely — resolving them would let an agent
        # peer outside the Thymus zone via a planted link.
        try:
            is_symlink = match.is_symlink()
        except OSError:
            is_symlink = False
        if is_symlink and not follow_symlinks:
            rejected_count += 1
            continue

        if follow_symlinks:
            try:
                candidate = match.resolve()
            except OSError:
                rejected_count += 1
                continue
        else:
            candidate = match

        violation = _inner._policy.check_read(str(candidate))
        if violation:
            rejected_count += 1
            continue
        paths.append(str(candidate))

    return GlobPathsResult(
        paths=paths,
        truncated=truncated,
        rejected_count=rejected_count,
        tool_available=True,
    )
