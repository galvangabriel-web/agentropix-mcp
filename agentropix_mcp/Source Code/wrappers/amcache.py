"""Amcache.hve wrapper — execution evidence from the application cache.

Amcache.hve (``%SystemRoot%\\AppCompat\\Programs\\Amcache.hve``) records
metadata about every binary the OS has compiled compatibility info for:
SHA1, file size, product name, publisher, install date, and the
binary's last-modified timestamp. It survives anti-forensics that wipe
prefetch.

The wrapper targets a generic ``amcache_parser`` binary (override with
``AGENTROPIX_AMCACHE_TOOL``); SANS SIFT typically ships a Python parser
or Eric Zimmerman's ``AmcacheParser`` under Wine. Output is parsed
loosely: we recognise both CSV and key-value text dialects.
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

DEFAULT_TOOL_NAME = "amcache_parser"


def _resolve_tool() -> str:
    return os.environ.get("AGENTROPIX_AMCACHE_TOOL", DEFAULT_TOOL_NAME)


class AmcacheEntry(BaseModel):
    """One Amcache.hve record."""

    path: str
    sha1: str = ""
    size: int = 0
    product_name: str = ""
    publisher: str = ""
    install_date: str = ""
    last_modified: str = ""
    raw: str = ""


class AmcacheReport(BaseModel):
    """Parsed Amcache.hve content.

    When the parser binary is not installed, the wrapper returns a
    sentinel report with ``tool_available=False`` and a human-readable
    ``skip_reason`` instead of raising ``FileNotFoundError``.  This lets
    the calling agent degrade gracefully (no finding emitted, no false
    ``ERROR:`` entry in the trace) while still leaving an observable
    signal (M6.4 graceful-skip).
    """

    image_path: str
    entry_count: int = 0
    entries: list[AmcacheEntry] = Field(default_factory=list)
    tool: str = "amcache.parser"
    raw_stderr: str = ""
    tool_available: bool = True
    skip_reason: str = ""
    # SIFT-W-082: SHA-256 of the parser's raw stdout bytes — chain-of-custody
    # fingerprint proving the parsed entries derived from exactly these bytes.
    raw_stdout_sha256: str = ""


# NOTE: trailing `\s*` after the colon must NOT match newlines, or an
# empty value line (`Publisher:`) would slurp the next field's value.
# Using [ \t]* keeps the match confined to the current line.
_KEY_VALUE_HEADER = re.compile(r"^(?:Path|Filename|Full[ _]?Path)[ \t]*:[ \t]*(.+)$",
                               re.IGNORECASE | re.MULTILINE)
_SHA1 = re.compile(r"^SHA1[ \t]*:[ \t]*([0-9a-fA-F]+)", re.IGNORECASE | re.MULTILINE)
_SIZE = re.compile(r"^(?:File[ \t]+)?Size[ \t]*:[ \t]*(\d+)", re.IGNORECASE | re.MULTILINE)
_PRODUCT = re.compile(r"^Product[ _]?Name[ \t]*:[ \t]*(.+)$", re.IGNORECASE | re.MULTILINE)
_PUBLISHER = re.compile(r"^Publisher[ \t]*:[ \t]*(.+)$", re.IGNORECASE | re.MULTILINE)
_INSTALL = re.compile(r"^Install(?:[ \t]+Date|ed)[ \t]*:[ \t]*(.+)$", re.IGNORECASE | re.MULTILINE)
_LAST_MOD = re.compile(r"^Last[ _]?Modified[ \t]*:[ \t]*(.+)$", re.IGNORECASE | re.MULTILINE)


def _looks_like_csv(output: str) -> bool:
    first = next((ln for ln in output.splitlines() if ln.strip()), "")
    if "," not in first:
        return False
    lower = first.lower()
    return ("path" in lower or "filename" in lower) and "sha1" in lower


def _parse_amcache_csv(output: str) -> list[AmcacheEntry]:
    reader = csv.DictReader(io.StringIO(output))
    entries: list[AmcacheEntry] = []
    for row in reader:
        # Normalize keys to lowercase for tolerant lookup.
        norm = {k.lower().strip(): (v or "").strip() for k, v in row.items() if k}
        path = (
            norm.get("path")
            or norm.get("filename")
            or norm.get("full path")
            or norm.get("fullpath", "")
        )
        if not path:
            continue
        size_raw = norm.get("size") or norm.get("file size") or "0"
        try:
            size = int(size_raw)
        except ValueError:
            size = 0
        entries.append(
            AmcacheEntry(
                path=path,
                sha1=norm.get("sha1", ""),
                size=size,
                product_name=(
                    norm.get("product name")
                    or norm.get("product_name")
                    or norm.get("productname", "")
                ),
                publisher=norm.get("publisher", ""),
                install_date=(
                    norm.get("install date")
                    or norm.get("installed")
                    or norm.get("filekeylastwritetimestamp", "")
                ),
                last_modified=(
                    norm.get("last modified")
                    or norm.get("last_modified")
                    or norm.get("linkdate", "")
                ),
                raw=str(row)[:2000],
            )
        )
    return entries


def _parse_amcache_text(output: str) -> list[AmcacheEntry]:
    headers = list(_KEY_VALUE_HEADER.finditer(output))
    entries: list[AmcacheEntry] = []
    for idx, m in enumerate(headers):
        path = m.group(1).strip()
        start = m.start()
        end = headers[idx + 1].start() if idx + 1 < len(headers) else len(output)
        body = output[start:end]
        size_m = _SIZE.search(body)
        size = int(size_m.group(1)) if size_m else 0
        entries.append(
            AmcacheEntry(
                path=path,
                sha1=(_SHA1.search(body).group(1) if _SHA1.search(body) else "").lower(),
                size=size,
                product_name=(_PRODUCT.search(body).group(1).strip() if _PRODUCT.search(body) else ""),
                publisher=(_PUBLISHER.search(body).group(1).strip() if _PUBLISHER.search(body) else ""),
                install_date=(_INSTALL.search(body).group(1).strip() if _INSTALL.search(body) else ""),
                last_modified=(_LAST_MOD.search(body).group(1).strip() if _LAST_MOD.search(body) else ""),
                raw=body[:2000],
            )
        )
    return entries


def _parse_amcache_output(output: str) -> list[AmcacheEntry]:
    if not output.strip():
        return []
    if _looks_like_csv(output):
        return _parse_amcache_csv(output)
    return _parse_amcache_text(output)


async def get_amcache(
    hive: str | Path,
    *,
    timeout: float | None = None,
) -> AmcacheReport:
    """Parse an Amcache.hve hive into typed entries.

    Args:
        hive: Path to ``Amcache.hve``.
        timeout: Max seconds to wait for the parser.

    Raises:
        FileNotFoundError: hive missing.
        TimeoutError: parser exceeds timeout.
        RuntimeError: parser returns non-zero with empty stdout.

    Graceful degrade:
        When the parser binary is not on PATH the function does NOT
        raise — it returns an ``AmcacheReport`` with ``tool_available=False``
        and a populated ``skip_reason``.  Callers should check
        ``tool_available`` before treating the report as authoritative.
    """
    hive_path = Path(hive)
    if not hive_path.exists():
        raise FileNotFoundError(f"Amcache hive not found: {hive_path}")

    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_AMCACHE_TIMEOUT", 60.0, floor=5.0, ceiling=3600.0
        )

    tool_name = _resolve_tool()
    tool_path = shutil.which(tool_name)
    if not tool_path:
        reason = (
            f"{tool_name} not found on PATH; "
            "install an Amcache parser or set AGENTROPIX_AMCACHE_TOOL"
        )
        logger.info("amcache parser unavailable — %s", reason)
        return AmcacheReport(
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

    entries = _parse_amcache_output(stdout)
    return AmcacheReport(
        image_path=str(hive_path),
        entry_count=len(entries),
        entries=entries,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
    )
