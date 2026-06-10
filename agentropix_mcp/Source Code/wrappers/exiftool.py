"""ExifTool wrapper — metadata extraction from files and directories.

Drives ``exiftool -json [-r] [-fast] [-q] target`` and parses the
resulting JSON array into typed ``ExifEntry`` records.  Each record
preserves the full metadata dict alongside the promoted common fields
(SourceFile, FileType, MIMEType, FileSize, FileModifyDate) so callers
can branch on type/MIME without iterating the raw dict.

The full metadata dict is kept verbatim because ExifTool field names
are tool-version and file-type dependent (EXIF tags differ from XMP/
IPTC/PDF metadata).  Promoting every possible tag would require a
massive schema; instead callers access unusual fields via
``entry.metadata["GPSLatitude"]`` etc.

Unbounded output is possible when ``-r`` recurses a large directory.
``max_files`` caps the list after JSON parse.  For large recursive runs
the timeout is the primary guard — ExifTool is fast (Perl, not compiled)
but a 12 GB image extraction directory can have thousands of artefacts.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from agentropix_mcp._env import get_float, get_int

logger = logging.getLogger(__name__)

DEFAULT_TOOL_NAME = "exiftool"


def _resolve_tool() -> str:
    return os.environ.get("AGENTROPIX_EXIFTOOL_TOOL", DEFAULT_TOOL_NAME)


class ExifEntry(BaseModel):
    """Metadata for one file as returned by ExifTool."""

    source_file: str
    file_type: str = ""
    mime_type: str = ""
    file_size: str = ""
    file_modify_date: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExiftoolReport(BaseModel):
    """Parsed output of an ``exiftool -json`` run."""

    target: str
    recursive: bool = False
    fast: bool = False
    entry_count: int = 0
    truncated: bool = False
    entries: list[ExifEntry] = Field(default_factory=list)
    tool: str = "exiftool"
    raw_stderr: str = ""
    # SIFT-W-082: SHA-256 of exiftool's raw stdout bytes.
    raw_stdout_sha256: str = ""


def _parse_exiftool_output(
    stdout: str, *, max_files: int | None = None
) -> tuple[list[ExifEntry], bool]:
    """Parse ExifTool JSON array into ExifEntry list.

    Returns (entries, truncated).  Invalid JSON or an empty/whitespace
    stdout yields an empty list without raising.
    """
    stdout = stdout.strip()
    if not stdout:
        return [], False

    try:
        raw: list[dict[str, Any]] = json.loads(stdout)
    except json.JSONDecodeError:
        logger.warning("exiftool produced non-JSON stdout: %s…", stdout[:200])
        return [], False

    if not isinstance(raw, list):
        return [], False

    entries: list[ExifEntry] = []
    truncated = False

    for item in raw:
        if not isinstance(item, dict):
            continue
        entry = ExifEntry(
            source_file=str(item.get("SourceFile", "")),
            file_type=str(item.get("FileType", "")),
            mime_type=str(item.get("MIMEType", "")),
            file_size=str(item.get("FileSize", "")),
            file_modify_date=str(item.get("FileModifyDate", "")),
            metadata={k: v for k, v in item.items()},
        )
        entries.append(entry)
        if max_files is not None and len(entries) >= max_files:
            truncated = True
            break

    return entries, truncated


async def run_exiftool(
    target: str | Path,
    *,
    recursive: bool = False,
    fast: bool = False,
    max_files: int | None = None,
    timeout: float | None = None,
) -> ExiftoolReport:
    """Extract metadata from ``target`` using ExifTool.

    Args:
        target: File or directory to inspect.
        recursive: Pass ``-r`` to recurse into subdirectories.
        fast: Pass ``-fast`` to skip slow metadata (e.g. embedded
            thumbnails, MakerNotes). Faster but less complete.
        max_files: Cap on returned entries; entries beyond the cap are
            dropped and ``truncated`` is set.
        timeout: Max seconds to wait for exiftool.

    Returns:
        ExiftoolReport with per-file metadata entries.

    Raises:
        FileNotFoundError: target or exiftool binary not found.
        TimeoutError: exiftool exceeds timeout.
        RuntimeError: exiftool exits non-zero with empty stdout.
    """
    target_path = Path(target)
    if not target_path.exists():
        raise FileNotFoundError(f"ExifTool target not found: {target_path}")

    if max_files is None:
        max_files = get_int(
            "AGENTROPIX_EXIFTOOL_MAX_FILES", 2000, floor=1, ceiling=200_000
        )

    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_EXIFTOOL_TIMEOUT", 120.0, floor=5.0, ceiling=3600.0
        )

    tool_name = _resolve_tool()
    tool_path = shutil.which(tool_name)
    if not tool_path:
        raise FileNotFoundError(
            f"{tool_name} not found on PATH — install exiftool "
            "or set AGENTROPIX_EXIFTOOL_TOOL"
        )

    cmd: list[str] = [tool_path, "-json", "-q"]
    if recursive:
        cmd.append("-r")
    if fast:
        cmd.append("-fast")
    cmd.append(str(target_path))

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
        await proc.wait()
        raise TimeoutError(f"{tool_name} timed out after {timeout}s")

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")

    if proc.returncode not in (0, None) and not stdout.strip():
        raise RuntimeError(
            f"{tool_name} failed (rc={proc.returncode}): {stderr[:500]}"
        )

    entries, truncated = _parse_exiftool_output(stdout, max_files=max_files)

    return ExiftoolReport(
        target=str(target_path),
        recursive=recursive,
        fast=fast,
        entry_count=len(entries),
        truncated=truncated,
        entries=entries,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
    )
