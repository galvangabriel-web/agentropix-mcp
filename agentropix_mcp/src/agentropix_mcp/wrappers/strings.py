"""GNU strings wrapper — printable-sequence extraction from binaries.

Targets GNU binutils ``strings`` (override via ``AGENTROPIX_STRINGS_TOOL``
for hosts that ship it as ``gstrings`` or a custom build). The wrapper
runs with ``-a`` (whole file, not just initialized/loaded sections) and
``-t d`` (decimal byte offsets) so every string line is shaped
``<offset> <text>`` and the parser can key on offsets for dedup.

Unbounded output is the main operational risk — running strings on a
multi-GB disk image can emit gigabytes of text. The wrapper streams
stdout line by line and early-exits once ``max_results`` entries are
captured, killing the subprocess to reclaim I/O. Tool timeout is the
secondary guard.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import shutil
from pathlib import Path

from pydantic import BaseModel, Field

from agentropix_mcp._env import get_float, get_int

logger = logging.getLogger(__name__)

DEFAULT_TOOL_NAME = "strings"

# GNU strings ``-e`` encoding selectors. Single-char values matching what
# the binary expects: s=7-bit single, S=8-bit single, b/l=16-bit BE/LE,
# B/L=32-bit BE/LE. Anything else is rejected at the MCP boundary so we
# don't shell a malformed flag.
_VALID_ENCODINGS = frozenset({"s", "S", "b", "l", "B", "L"})

# Output shape with ``-t d``: leading whitespace, decimal offset, single
# run of whitespace, then the string (which itself may contain spaces).
_LINE_RE = re.compile(r"^\s*(\d+)\s(.*)$")

# Per-entry text cap — pathological binaries can emit multi-KB "strings"
# (certificates, embedded blobs). Truncate individual entries so one
# oversized line can't dominate the returned report.
_MAX_TEXT_CHARS = 4096


def _resolve_tool() -> str:
    """Resolve the strings binary, honoring AGENTROPIX_STRINGS_TOOL."""
    return os.environ.get("AGENTROPIX_STRINGS_TOOL", DEFAULT_TOOL_NAME)


class StringEntry(BaseModel):
    """One printable sequence recovered from the target."""

    offset: int
    text: str


class StringsReport(BaseModel):
    """Parsed output of a ``strings`` run."""

    image_path: str
    min_length: int
    encoding: str
    entry_count: int = 0
    truncated: bool = False
    entries: list[StringEntry] = Field(default_factory=list)
    tool: str = "binutils.strings"
    raw_stderr: str = ""
    # SIFT-W-082: SHA-256 of the bytes the streaming reader actually
    # consumed.  When ``truncated`` fires we stop reading after the
    # ``max_results`` cap, so the hash covers the same prefix the parser
    # saw — not the (potentially much larger) full ``strings`` output.
    raw_stdout_sha256: str = ""


async def run_strings(
    target: str | Path,
    *,
    min_length: int | None = None,
    encoding: str = "s",
    max_results: int | None = None,
    timeout: float | None = None,
) -> StringsReport:
    """Extract printable character sequences from a binary target.

    Args:
        target: Path to the binary (disk image, executable, memory dump, …).
        min_length: Minimum sequence length (``strings -n N``). Defaults to
            ``AGENTROPIX_STRINGS_MIN_LENGTH`` or 4.
        encoding: One of ``s|S|b|l|B|L`` (see ``strings --help``). Defaults
            to ``s`` (7-bit single). Invalid values raise ``ValueError`` so
            a malformed flag is never shell-exec'd.
        max_results: Cap on returned entries; the subprocess is killed
            once the cap is reached. Defaults to
            ``AGENTROPIX_STRINGS_MAX_RESULTS`` or 1000.
        timeout: Max seconds to wait for strings.

    Returns:
        StringsReport with per-string entries and a ``truncated`` flag
        indicating whether the ``max_results`` cap fired.

    Raises:
        FileNotFoundError: target missing or strings binary not on PATH.
        ValueError: unknown encoding selector.
        TimeoutError: strings exceeds timeout.
        RuntimeError: strings returns non-zero with empty stdout.
    """
    target_path = Path(target)
    if not target_path.exists():
        raise FileNotFoundError(f"Strings target not found: {target_path}")

    if encoding not in _VALID_ENCODINGS:
        raise ValueError(
            f"Invalid strings encoding {encoding!r}; "
            f"expected one of {sorted(_VALID_ENCODINGS)}"
        )

    if min_length is None:
        min_length = get_int(
            "AGENTROPIX_STRINGS_MIN_LENGTH", 4, floor=1, ceiling=1024
        )
    if min_length < 1:
        raise ValueError(f"min_length must be ≥1, got {min_length}")

    if max_results is None:
        max_results = get_int(
            "AGENTROPIX_STRINGS_MAX_RESULTS", 1000, floor=1, ceiling=1_000_000
        )

    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_STRINGS_TIMEOUT", 120.0, floor=5.0, ceiling=3600.0
        )

    tool_name = _resolve_tool()
    tool_path = shutil.which(tool_name)
    if not tool_path:
        raise FileNotFoundError(
            f"{tool_name} not found on PATH — install GNU binutils "
            "or set AGENTROPIX_STRINGS_TOOL"
        )

    cmd = [
        tool_path,
        "-a",
        "-t", "d",
        "-n", str(min_length),
        "-e", encoding,
        str(target_path),
    ]
    logger.info("Running: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    entries: list[StringEntry] = []
    truncated = False
    assert proc.stdout is not None
    digest = hashlib.sha256()

    async def _reader() -> None:
        nonlocal truncated
        while len(entries) < max_results:
            line_bytes = await proc.stdout.readline()
            if not line_bytes:
                return
            digest.update(line_bytes)
            line = line_bytes.decode(errors="replace").rstrip("\r\n")
            match = _LINE_RE.match(line)
            if not match:
                continue
            offset = int(match.group(1))
            text = match.group(2)
            if len(text) > _MAX_TEXT_CHARS:
                text = text[:_MAX_TEXT_CHARS]
            entries.append(StringEntry(offset=offset, text=text))
        truncated = True

    try:
        await asyncio.wait_for(_reader(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"{tool_name} timed out after {timeout}s")

    if truncated:
        proc.kill()

    # Drain remaining output + stderr so we can shape the report without
    # leaving a zombie. ``wait`` is safe after kill().
    try:
        stderr_bytes = await asyncio.wait_for(proc.stderr.read(), timeout=5.0)
    except (asyncio.TimeoutError, Exception):
        stderr_bytes = b""
    await proc.wait()

    stderr = stderr_bytes.decode(errors="replace")

    if proc.returncode not in (0, None) and not entries and not truncated:
        raise RuntimeError(
            f"{tool_name} failed (rc={proc.returncode}): {stderr[:500]}"
        )

    return StringsReport(
        image_path=str(target_path),
        min_length=min_length,
        encoding=encoding,
        entry_count=len(entries),
        truncated=truncated,
        entries=entries,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=digest.hexdigest(),
    )
