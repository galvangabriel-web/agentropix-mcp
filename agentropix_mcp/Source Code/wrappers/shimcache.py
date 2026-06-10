"""Shimcache (AppCompatCache) wrapper — execution evidence in SYSTEM hive.

Shimcache lives at ``SYSTEM\\CurrentControlSet\\Control\\Session
Manager\\AppCompatCache``. Each entry records a binary's path, the
file's last-modified timestamp, and (Win7-) an "executed" flag. The
flag is best-effort on later Windows versions, so the wrapper exposes
it but doesn't lean on it for severity scoring.

The wrapper targets a generic ``shimcache_parser`` binary (override
with ``AGENTROPIX_SHIMCACHE_TOOL``); SANS SIFT typically ships
Mandiant's ``ShimCacheParser.py`` or Eric Zimmerman's
``AppCompatCacheParser`` under Wine.
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import logging
import os
import re
import shutil
from pathlib import Path

from pydantic import BaseModel, Field

from agentropix_mcp._env import get_float

logger = logging.getLogger(__name__)

DEFAULT_TOOL_NAME = "shimcache_parser"

_TRUE_TOKENS = {"true", "yes", "1", "y", "executed"}
_FALSE_TOKENS = {"false", "no", "0", "n", "n/a", ""}


def _resolve_tool() -> str:
    return os.environ.get("AGENTROPIX_SHIMCACHE_TOOL", DEFAULT_TOOL_NAME)


def _coerce_bool(value: str) -> bool:
    v = value.strip().lower()
    if v in _TRUE_TOKENS:
        return True
    if v in _FALSE_TOKENS:
        return False
    return False


class ShimcacheEntry(BaseModel):
    """One AppCompatCache record."""

    path: str
    last_modified: str = ""
    executed: bool = False
    raw: str = ""


class ShimcacheReport(BaseModel):
    """Parsed Shimcache content.

    When the parser binary is not installed, the wrapper returns a
    sentinel report with ``tool_available=False`` and a human-readable
    ``skip_reason`` instead of raising ``FileNotFoundError``.  This lets
    the calling agent degrade gracefully (no finding emitted, no false
    ``ERROR:`` entry in the trace) while still leaving an observable
    signal (M6.4 graceful-skip).
    """

    image_path: str
    entry_count: int = 0
    entries: list[ShimcacheEntry] = Field(default_factory=list)
    tool: str = "shimcache.parser"
    raw_stderr: str = ""
    tool_available: bool = True
    skip_reason: str = ""
    # SIFT-W-082: SHA-256 of the parser's raw stdout bytes.
    raw_stdout_sha256: str = ""


# Mandiant ShimCacheParser CSV header is "Last Modified,Last Update,Path,File Size,Exec Flag".
# Tabular text dialect uses key:value lines per entry.
# NOTE: post-colon whitespace is restricted to spaces/tabs so an empty
# value line can't accidentally consume the next field.
_TEXT_PATH = re.compile(r"^Path[ \t]*:[ \t]*(.+)$", re.IGNORECASE | re.MULTILINE)
_TEXT_LASTMOD = re.compile(r"^Last[ _]?Modified[ \t]*:[ \t]*(.+)$",
                           re.IGNORECASE | re.MULTILINE)
_TEXT_EXEC = re.compile(r"^Exec(?:uted|[ \t]*Flag)?[ \t]*:[ \t]*(.+)$",
                        re.IGNORECASE | re.MULTILINE)


def _looks_like_csv(output: str) -> bool:
    first = next((ln for ln in output.splitlines() if ln.strip()), "")
    if "," not in first:
        return False
    lower = first.lower()
    return "path" in lower and ("modified" in lower or "exec" in lower)


def _parse_shimcache_csv(output: str) -> list[ShimcacheEntry]:
    reader = csv.DictReader(io.StringIO(output))
    entries: list[ShimcacheEntry] = []
    for row in reader:
        norm = {k.lower().strip(): (v or "").strip() for k, v in row.items() if k}
        path = norm.get("path", "")
        if not path:
            continue
        entries.append(
            ShimcacheEntry(
                path=path,
                last_modified=norm.get("last modified") or norm.get("last_modified", ""),
                executed=_coerce_bool(
                    norm.get("exec flag")
                    or norm.get("executed")
                    or norm.get("exec", "")
                ),
                raw=str(row)[:2000],
            )
        )
    return entries


def _parse_shimcache_text(output: str) -> list[ShimcacheEntry]:
    headers = list(_TEXT_PATH.finditer(output))
    entries: list[ShimcacheEntry] = []
    for idx, m in enumerate(headers):
        path = m.group(1).strip()
        start = m.start()
        end = headers[idx + 1].start() if idx + 1 < len(headers) else len(output)
        body = output[start:end]
        lm_m = _TEXT_LASTMOD.search(body)
        exec_m = _TEXT_EXEC.search(body)
        entries.append(
            ShimcacheEntry(
                path=path,
                last_modified=lm_m.group(1).strip() if lm_m else "",
                executed=_coerce_bool(exec_m.group(1)) if exec_m else False,
                raw=body[:2000],
            )
        )
    return entries


def _parse_shimcache_output(output: str) -> list[ShimcacheEntry]:
    if not output.strip():
        return []
    if _looks_like_csv(output):
        return _parse_shimcache_csv(output)
    return _parse_shimcache_text(output)


async def get_shimcache(
    hive: str | Path,
    *,
    timeout: float | None = None,
) -> ShimcacheReport:
    """Parse a SYSTEM hive for AppCompatCache (Shimcache) entries.

    Args:
        hive: Path to a SYSTEM hive.
        timeout: Max seconds to wait for the parser.

    Raises:
        FileNotFoundError: hive missing.
        TimeoutError: parser exceeds timeout.
        RuntimeError: parser returns non-zero with empty stdout.

    Graceful degrade:
        When the parser binary is not on PATH the function does NOT
        raise — it returns a ``ShimcacheReport`` with
        ``tool_available=False`` and a populated ``skip_reason``.
        Callers should check ``tool_available`` before treating the
        report as authoritative.
    """
    hive_path = Path(hive)
    if not hive_path.exists():
        raise FileNotFoundError(f"SYSTEM hive not found: {hive_path}")

    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_SHIMCACHE_TIMEOUT", 60.0, floor=5.0, ceiling=3600.0
        )

    tool_name = _resolve_tool()
    tool_path = shutil.which(tool_name)
    if not tool_path:
        reason = (
            f"{tool_name} not found on PATH; "
            "install a Shimcache parser or set AGENTROPIX_SHIMCACHE_TOOL"
        )
        logger.info("shimcache parser unavailable — %s", reason)
        return ShimcacheReport(
            image_path=str(hive_path),
            tool_available=False,
            skip_reason=reason,
        )

    cmd = [tool_path, str(hive_path)]
    logger.info("Running: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        raise TimeoutError(f"{tool_name} timed out after {timeout}s")

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")

    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError(
            f"{tool_name} failed (rc={proc.returncode}): {stderr[:500]}"
        )

    entries = _parse_shimcache_output(stdout)
    return ShimcacheReport(
        image_path=str(hive_path),
        entry_count=len(entries),
        entries=entries,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
    )
