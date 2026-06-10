"""Shared subprocess utilities — memory monitoring and managed execution."""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Callable, Awaitable
from pathlib import Path

logger = logging.getLogger(__name__)

# Floor: 4096 MB. Small images stay capped here as a safety net against
# runaway plaso/vol3 on tiny inputs. Larger images get proportional
# headroom via _auto_mem_limit_mb() (W-162 — 7-agent SWARM on the
# 11.5 GB SRL-2018 DC E01 OOM'd at the static 4096 cap).
# Operators can still override via AGENTROPIX_MEM_LIMIT_MB (env wins);
# AGENTROPIX_MEM_LIMIT_MB=0 disables the guard entirely.
_DEFAULT_MEM_LIMIT_MB = 4096

# W-162 auto-scale slope: MB of cap per GB of evidence. W-NEW-1 final
# (2026-05-12) bumped 700→730 so the 11.5 GB DC E01 auto-scales to
# 11.5*730 = 8395 MB, exceeding the proven cron override
# AGENTROPIX_MEM_LIMIT_MB=8192 and letting the override be removed.
# Floor (and thus the cap) stays at 4096 MB for anything ≤5.61 GB.
_MEM_LIMIT_MB_PER_GB = 730

# Per-tool peak RSS tracking for observability
_peak_rss: dict[str, float] = {}


def get_peak_rss() -> dict[str, float]:
    """Return peak RSS (MB) per tool name. For monitoring dashboards."""
    return dict(_peak_rss)


def reset_peak_rss() -> None:
    """Reset peak RSS tracking. Useful between test runs."""
    _peak_rss.clear()


def _get_mem_limit_mb() -> int:
    """Resolve memory limit from env var AGENTROPIX_MEM_LIMIT_MB.

    No env var    → default floor (4096 MB).
    Env var = 0   → 0 (explicitly disabled by operator).
    Env var < 0   → 0 (treated as explicit disable).
    Env var > 0   → that value.
    Invalid str   → default with a warning.

    Note: callers that have an evidence path in scope should prefer
    ``_resolve_mem_limit_mb(image_path)`` so that the W-162 auto-scale
    kicks in when no env override is set.
    """
    raw = os.environ.get("AGENTROPIX_MEM_LIMIT_MB", "")
    if not raw:
        return _DEFAULT_MEM_LIMIT_MB
    try:
        limit = int(raw)
        if limit <= 0:
            return 0  # explicit opt-out — operator wants no RSS guard
        return limit
    except ValueError:
        logger.warning("Invalid AGENTROPIX_MEM_LIMIT_MB=%r, using default %d MB", raw, _DEFAULT_MEM_LIMIT_MB)
        return _DEFAULT_MEM_LIMIT_MB


def _auto_mem_limit_mb(image_path: Path | None) -> int:
    """W-162: scale the memory cap to the evidence size.

    Returns ``max(_DEFAULT_MEM_LIMIT_MB, image_size_GB * _MEM_LIMIT_MB_PER_GB)``
    when ``image_path`` is set and points to a readable file. Falls back
    to the floor (4096 MB) when the path is None, missing, or unreadable.
    The cap is a runtime ceiling, not a guarantee — the env override
    AGENTROPIX_MEM_LIMIT_MB still wins (resolved in
    ``_resolve_mem_limit_mb``).
    """
    if image_path is None:
        return _DEFAULT_MEM_LIMIT_MB
    try:
        size_bytes = Path(image_path).stat().st_size
    except (OSError, ValueError):
        return _DEFAULT_MEM_LIMIT_MB
    size_gb = size_bytes / (1024 ** 3)
    scaled = int(size_gb * _MEM_LIMIT_MB_PER_GB)
    return max(_DEFAULT_MEM_LIMIT_MB, scaled)


def _resolve_mem_limit_mb(image_path: Path | None = None) -> int:
    """Resolve the effective memory cap for a wrapper invocation.

    Priority (highest first):
      1. Env override ``AGENTROPIX_MEM_LIMIT_MB`` (any value, incl. 0).
      2. Auto-scale per evidence size when ``image_path`` is in scope.
      3. Static floor (``_DEFAULT_MEM_LIMIT_MB``) when no path is given.
    """
    raw = os.environ.get("AGENTROPIX_MEM_LIMIT_MB", "")
    if raw:
        return _get_mem_limit_mb()
    return _auto_mem_limit_mb(image_path)


def _tree_rss_mb(ps_proc: "psutil.Process") -> float:  # type: ignore[name-defined]
    """W-131: sum RSS (MB) across ps_proc and every descendant.

    Plaso's log2timeline.py is a thin coordinator that forks workers
    (default cpu_count - 1, capped to AGENTROPIX_PLASO_WORKERS via the
    plaso wrapper). The parent's own RSS is ~50 MiB while each worker
    holds 1-3 GiB resident. Without tree-walk the monitor would see
    only the parent and never trip the limit, while the host OOMs in
    the meantime — which is exactly what happened on 2026-04-30 DC
    triage. Catches NoSuchProcess / AccessDenied per-child so a
    transient race during fork/exit doesn't blank the whole reading.
    """
    import psutil

    rss_bytes = 0
    try:
        rss_bytes = ps_proc.memory_info().rss
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    try:
        children = ps_proc.children(recursive=True)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        children = []
    for child in children:
        try:
            rss_bytes += child.memory_info().rss
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return rss_bytes / (1024 * 1024)


async def _monitor_memory(
    proc: asyncio.subprocess.Process,
    limit_mb: int,
    tool_name: str,
    poll_interval: float = 0.5,
) -> None:
    """Poll subprocess RSS (whole tree) and kill if it exceeds limit_mb.

    Runs as a background task alongside proc.communicate().
    Silently exits when the process terminates.

    W-131: the RSS reading sums across the whole descendant tree (see
    ``_tree_rss_mb``). On a kill, we SIGKILL the process group, not
    just ``proc.kill()``, so worker subprocesses started under
    ``start_new_session=True`` are reaped together with the parent.
    """
    try:
        import psutil
    except ImportError:
        logger.warning("psutil not available — memory monitoring disabled for %s", tool_name)
        return

    pid = proc.pid
    if pid is None:
        return

    try:
        ps_proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return

    logger.info("Memory monitor active for %s (pid=%d, limit=%d MB, tree-walk)", tool_name, pid, limit_mb)
    peak_mb = 0.0

    while proc.returncode is None:
        try:
            mem_mb = _tree_rss_mb(ps_proc)
            peak_mb = max(peak_mb, mem_mb)
            if mem_mb > limit_mb:
                logger.error(
                    "%s tree (pid=%d) exceeded memory limit: %.0f MB > %d MB — killing",
                    tool_name, pid, mem_mb, limit_mb,
                )
                # W-131: when the proc was started with
                # ``start_new_session=True`` (Plaso log2timeline / psort)
                # it has its own pgid; killpg reaps the whole worker
                # tree. When it shares the parent's pgid (callers that
                # don't isolate, e.g. the test fixtures in
                # test_p2_hardening), killpg would SIGKILL the parent
                # too — guard with a same-pgid check and fall back to
                # ``proc.kill()`` (parent-only) in that case.
                try:
                    proc_pgid = os.getpgid(pid)
                    own_pgid = os.getpgid(0)
                    if proc_pgid != own_pgid:
                        os.killpg(proc_pgid, 9)  # SIGKILL the worker tree
                    else:
                        proc.kill()
                except (ProcessLookupError, OSError):
                    proc.kill()
                return
        except psutil.NoSuchProcess:
            break
        except Exception as e:
            logger.debug("Memory monitor error for %s: %s", tool_name, e)
            break
        await asyncio.sleep(poll_interval)

    # Track peak RSS for observability
    _peak_rss[tool_name] = max(_peak_rss.get(tool_name, 0.0), peak_mb)
    logger.info("Memory monitor done for %s: peak RSS %.0f MB (limit %d MB)", tool_name, peak_mb, limit_mb)


async def run_with_memory_limit(
    proc: asyncio.subprocess.Process,
    timeout: float,
    tool_name: str,
    *,
    image_path: Path | None = None,
) -> tuple[bytes, bytes]:
    """Run proc.communicate() with optional memory monitoring.

    Resolution order for the cap (see ``_resolve_mem_limit_mb``):
      1. ``AGENTROPIX_MEM_LIMIT_MB`` env var (any value, incl. 0=disable).
      2. W-162 auto-scale ``max(4096, image_size_GB * 700)`` when
         ``image_path`` points to a readable file.
      3. Static floor 4096 MB.

    If the resolved cap is >0, spawns a background task that polls RSS
    and kills the process if it exceeds the limit.

    Args:
        proc: The subprocess to monitor.
        timeout: Timeout in seconds for communicate().
        tool_name: Name for logging (e.g., "log2timeline", "vol").
        image_path: Optional path to the evidence image driving this
            invocation. Enables W-162 per-image auto-scale of the cap
            when no env override is set.

    Returns:
        (stdout_bytes, stderr_bytes) from proc.communicate().

    Raises:
        TimeoutError: If the process exceeds the timeout.
        MemoryError: If the process exceeds the memory limit.
    """
    limit_mb = _resolve_mem_limit_mb(image_path)

    if limit_mb > 0:
        logger.info("Starting memory-monitored execution for %s (limit=%d MB)", tool_name, limit_mb)
        monitor_task = asyncio.create_task(
            _monitor_memory(proc, limit_mb, tool_name)
        )
    else:
        monitor_task = None

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        if monitor_task and not monitor_task.done():
            monitor_task.cancel()
        raise TimeoutError(f"{tool_name} timed out after {timeout}s")
    finally:
        if monitor_task and not monitor_task.done():
            monitor_task.cancel()

    # If the process was killed by the memory monitor, raise MemoryError
    if proc.returncode == -9 and limit_mb > 0:
        raise MemoryError(
            f"{tool_name} killed: exceeded memory limit of {limit_mb} MB"
        )

    return stdout, stderr


async def run_with_retry(
    create_and_run: Callable[[], Awaitable[tuple[bytes, bytes]]],
    *,
    max_retries: int | None = None,
) -> tuple[bytes, bytes]:
    """Retry an async subprocess callable on TimeoutError with exponential backoff.

    Args:
        create_and_run: An async callable (no args) that creates a subprocess,
            runs it via run_with_memory_limit, and returns (stdout, stderr).
        max_retries: Maximum number of retries. Defaults to AGENTROPIX_MAX_RETRIES
            env var, or 2 if unset.

    Returns:
        (stdout_bytes, stderr_bytes) from the successful attempt.

    Raises:
        TimeoutError: If all attempts (initial + retries) fail with TimeoutError.
        Exception: Any non-TimeoutError is re-raised immediately.
    """
    if max_retries is None:
        raw = os.environ.get("AGENTROPIX_MAX_RETRIES", "2")
        try:
            max_retries = max(0, int(raw))
        except ValueError:
            logger.warning("Invalid AGENTROPIX_MAX_RETRIES=%r, defaulting to 2", raw)
            max_retries = 2

    last_error: TimeoutError | None = None
    for attempt in range(max_retries + 1):
        try:
            return await create_and_run()
        except TimeoutError as exc:
            last_error = exc
            if attempt < max_retries:
                delay = 2 ** attempt
                logger.warning(
                    "Attempt %d/%d timed out, retrying in %ds: %s",
                    attempt + 1,
                    max_retries + 1,
                    delay,
                    exc,
                )
                await asyncio.sleep(delay)
            else:
                logger.error(
                    "All %d attempts exhausted after TimeoutError: %s",
                    max_retries + 1,
                    exc,
                )

    # Should only reach here after all retries exhausted
    raise last_error  # type: ignore[misc]
