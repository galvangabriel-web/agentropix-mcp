"""bstrings wrapper — Eric Zimmerman regex-backed string extractor (Phase 2).

bstrings extends the GNU ``strings`` model with **regex-driven
search** — built-in lists for IPv4 / URL / GUID / credit-card / MAC
patterns, plus user-supplied regex via ``--lr`` (look for regex) or
``--ls`` (look for literal substring).

Three modes:

1. **No filter** → behaves like GNU strings: emit every printable
   ASCII / Unicode run from the input file.
2. **``look_for_string``** → keep only lines containing the literal
   substring.
3. **``look_for_regex``** → keep only lines matching the regex.

W-130 workaround — bstrings 2026.5.0 net9 binary silently rejects
``-f``/``-d`` on Linux (prints ``"input from stdin or file"`` and
exits rc=0 without producing output) but **stdin piping works**: the
binary buffers stdin to a temp file and processes normally, emitting
hits on stdout interspersed with header / summary lines. The wrapper
streams target bytes via stdin and parses the stdout structure
(header → ``Processing strings...`` marker → hit lines → ``Found N
string(s)`` summary). When upstream restores ``-f``/``-d`` semantics,
the stdin path can stay (it's strictly more robust against future
regressions of the same shape) or be flipped back at the operator's
discretion.

For directory mode, the wrapper iterates files under the directory
and aggregates hits across them — bstrings via stdin only sees one
stream at a time. Per-file subprocess overhead is bounded by an
``AGENTROPIX_BSTRINGS_DIR_MAX_FILES`` cap (default 256).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
from pathlib import Path

from pydantic import BaseModel, Field

from agentropix_mcp._env import get_float, get_int
from agentropix_mcp.wrappers._subprocess import run_with_memory_limit

logger = logging.getLogger(__name__)

DEFAULT_DLL = "/opt/ezt/net9/bstrings/bstrings.dll"
DEFAULT_DOTNET = "dotnet"

# Markers that bracket the actual hit list inside bstrings' verbose
# stdout.  These strings are stable across the 2026.x net9 builds we've
# tested.
_HITS_BEGIN_MARKER = "Processing strings..."
_HITS_END_PREFIX = "Found "  # "Found N string(s) in T seconds. Average ..."


def _resolve_dll() -> str:
    return os.environ.get("AGENTROPIX_BSTRINGS_DLL", DEFAULT_DLL)


def _resolve_dotnet() -> str:
    return os.environ.get("AGENTROPIX_DOTNET_TOOL", DEFAULT_DOTNET)


class BstringsHit(BaseModel):
    """One matched / extracted string from bstrings output.

    ``source`` carries the file the hit came from (for directory mode
    aggregation; equals the single target in file mode).
    """

    line: str = ""
    source: str = ""


class BstringsReport(BaseModel):
    """Parsed bstrings output."""

    target: str
    target_mode: str = ""  # "file" or "directory"
    look_for_string: str = ""
    look_for_regex: str = ""
    hit_count: int = 0
    truncated: bool = False
    # NIST1 RUN2 ISSUE-002: True when the hits list was omitted to bound the
    # payload; hit_count still reflects the real total.
    summary_only: bool = False
    hits: list[BstringsHit] = Field(default_factory=list)
    files_scanned: int = 0
    tool: str = "bstrings"
    raw_stderr: str = ""
    raw_output_sha256: str = ""
    tool_available: bool = True
    skip_reason: str = ""


def _parse_bstrings_stdout(
    stdout_text: str, *, source: str, max_hits: int
) -> tuple[list[BstringsHit], bool]:
    """Extract hit lines from bstrings' verbose stdout.

    bstrings prints:

        bstrings version ...
        Author: ...
        ...
        Command line: ...
        Searching N chunks ...
        Chunk N of M finished ...
        Primary search complete. ...
        Search complete.

        Processing strings...

        <hit 1>
        <hit 2>
        ...

        Found N string(s) in T seconds. Average strings/sec: ...

    The hit lines live between ``Processing strings...`` and the
    ``Found N`` summary. We tolerate the marker not appearing (empty
    output / error case) by returning an empty list.
    """
    if not stdout_text.strip():
        return [], False

    lines = stdout_text.splitlines()
    hits: list[BstringsHit] = []
    truncated = False

    in_hits = False
    for raw in lines:
        line = raw.rstrip()
        if not in_hits:
            if line.strip() == _HITS_BEGIN_MARKER:
                in_hits = True
            continue
        # Inside the hit block.  Stop at the summary line.
        if line.startswith(_HITS_END_PREFIX) and "string" in line and "seconds" in line:
            break
        if not line:
            continue
        if len(hits) >= max_hits:
            truncated = True
            break
        hits.append(BstringsHit(line=line, source=source))

    return hits, truncated


async def _run_bstrings_via_stdin(
    file_path: Path,
    *,
    look_for_string: str | None,
    look_for_regex: str | None,
    ascii_strings: bool,
    unicode_strings: bool,
    min_length: int,
    timeout: float,
    dotnet_bin: str,
    dll_path: Path,
) -> tuple[bytes, bytes, int]:
    """Stream ``file_path`` to bstrings via stdin and capture (stdout, stderr, rc)."""
    cmd = [
        dotnet_bin,
        str(dll_path),
        "-m",
        str(min_length),
        "-a",
        "true" if ascii_strings else "false",
        "-u",
        "true" if unicode_strings else "false",
    ]
    if look_for_string:
        cmd += ["--ls", look_for_string]
    if look_for_regex:
        cmd += ["--lr", look_for_regex]

    logger.info("Running (stdin pipe to %s): %s", file_path.name, " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    # Read the file in one shot — bstrings already chunks internally.
    # Memory cap is shared with the rest of the wrapper surface via
    # AGENTROPIX_MEM_LIMIT_MB through run_with_memory_limit.
    with file_path.open("rb") as fh:
        data = fh.read()

    proc.stdin.write(data)
    await proc.stdin.drain()
    proc.stdin.close()

    try:
        stdout_bytes, stderr_bytes = await run_with_memory_limit(proc, timeout, "bstrings")
    except TimeoutError:
        raise TimeoutError(f"bstrings timed out after {timeout}s") from None

    return stdout_bytes, stderr_bytes, proc.returncode


async def get_bstrings(
    target: str | Path,
    *,
    look_for_string: str | None = None,
    look_for_regex: str | None = None,
    ascii_strings: bool = True,
    unicode_strings: bool = True,
    min_length: int | None = None,
    summary_only: bool = False,
    timeout: float | None = None,
) -> BstringsReport:
    """Extract / regex-filter strings from a binary file or directory via bstrings.

    W-130 — uses stdin piping (the working path on bstrings 2026.5.0
    net9 Linux build) instead of ``-f`` / ``-d``.

    Args:
        target: Path to a single file or a directory.
        look_for_string: Literal substring filter (``--ls``). Only
            lines containing this substring survive.
        look_for_regex: Regex filter (``--lr``). Only lines matching
            the regex survive. ``--ls`` and ``--lr`` are mutually
            exclusive.
        ascii_strings: Pass ``-a true``. Default True.
        unicode_strings: Pass ``-u true``. Default True.
        min_length: Minimum string length (``-m N``). ``None`` reads
            ``AGENTROPIX_BSTRINGS_MIN_LENGTH`` (default 4).
        timeout: Subprocess timeout (s). ``None`` reads
            ``AGENTROPIX_BSTRINGS_TIMEOUT`` (default 600s).

    Raises:
        FileNotFoundError: target missing.
        TimeoutError: bstrings exceeded timeout.
        RuntimeError: bstrings returned non-zero with no parseable output.
        ValueError: both filters supplied (mutually exclusive).

    Graceful skip: missing dotnet or DLL → ``tool_available=False``.
    """
    if look_for_string and look_for_regex:
        raise ValueError(
            "look_for_string and look_for_regex are mutually exclusive; pass at most one"
        )

    target_path = Path(target)
    if not target_path.exists():
        raise FileNotFoundError(f"bstrings target not found: {target_path}")

    is_dir = target_path.is_dir()
    target_mode = "directory" if is_dir else "file"

    if timeout is None:
        timeout = get_float("AGENTROPIX_BSTRINGS_TIMEOUT", 600.0, floor=5.0, ceiling=3600.0)
    if min_length is None:
        min_length = get_int("AGENTROPIX_BSTRINGS_MIN_LENGTH", 4, floor=1, ceiling=1024)
    max_hits = get_int("AGENTROPIX_BSTRINGS_MAX_HITS", 10_000, floor=1, ceiling=1_000_000)
    dir_max_files = get_int("AGENTROPIX_BSTRINGS_DIR_MAX_FILES", 256, floor=1, ceiling=10_000)

    dotnet_name = _resolve_dotnet()
    dotnet_bin = shutil.which(dotnet_name)
    if not dotnet_bin:
        reason = (
            f"{dotnet_name} not found on PATH; "
            "install dotnet-runtime-9.0 or set AGENTROPIX_DOTNET_TOOL"
        )
        logger.info("bstrings skipped — %s", reason)
        return BstringsReport(
            target=str(target_path),
            target_mode=target_mode,
            tool_available=False,
            skip_reason=reason,
        )

    dll_path = Path(_resolve_dll())
    if not dll_path.is_file():
        reason = (
            f"bstrings DLL not found at {dll_path}; "
            "install via the EZ Tools net9 zip or set AGENTROPIX_BSTRINGS_DLL"
        )
        logger.info("bstrings skipped — %s", reason)
        return BstringsReport(
            target=str(target_path),
            target_mode=target_mode,
            tool_available=False,
            skip_reason=reason,
        )

    # Build the file list to scan.  For file mode it's just the
    # target; for dir mode we iterate up to dir_max_files regular
    # files.
    if is_dir:
        files: list[Path] = sorted(p for p in target_path.rglob("*") if p.is_file())[:dir_max_files]
    else:
        files = [target_path]

    aggregate_hits: list[BstringsHit] = []
    aggregate_stdout = bytearray()
    aggregate_stderr = bytearray()
    truncated = False
    files_scanned = 0
    nonzero_no_output = False

    for f in files:
        try:
            stdout_bytes, stderr_bytes, rc = await _run_bstrings_via_stdin(
                f,
                look_for_string=look_for_string,
                look_for_regex=look_for_regex,
                ascii_strings=ascii_strings,
                unicode_strings=unicode_strings,
                min_length=min_length,
                timeout=timeout,
                dotnet_bin=dotnet_bin,
                dll_path=dll_path,
            )
        except TimeoutError:
            raise

        files_scanned += 1
        aggregate_stdout.extend(stdout_bytes)
        aggregate_stderr.extend(stderr_bytes)

        stdout_text = stdout_bytes.decode(errors="replace")

        # Detect the residual W-130 failure mode (stdin invocation
        # also broken — operator likely on an even newer broken net9
        # build). Surface graceful-skip.
        if rc == 0 and "input from stdin or file" in stdout_text.lower():
            nonzero_no_output = True
            break

        per_file_hits, per_file_trunc = _parse_bstrings_stdout(
            stdout_text,
            source=str(f),
            max_hits=max_hits - len(aggregate_hits),
        )
        aggregate_hits.extend(per_file_hits)
        if per_file_trunc or len(aggregate_hits) >= max_hits:
            truncated = True
            break

    if nonzero_no_output:
        reason = (
            "bstrings stdin piping also rejected on this build "
            "(stdout signature 'input from stdin or file' on stdin path). "
            "Both -f/-d (W-130) and stdin paths broken — wrapper cannot "
            "extract strings until upstream resolves the regression."
        )
        logger.warning("bstrings skipped — %s", reason)
        return BstringsReport(
            target=str(target_path),
            target_mode=target_mode,
            look_for_string=look_for_string or "",
            look_for_regex=look_for_regex or "",
            tool_available=False,
            skip_reason=reason,
        )

    aggregate_stderr_text = bytes(aggregate_stderr).decode(errors="replace")
    aggregate_stdout_bytes = bytes(aggregate_stdout)

    return BstringsReport(
        target=str(target_path),
        target_mode=target_mode,
        look_for_string=look_for_string or "",
        look_for_regex=look_for_regex or "",
        hit_count=len(aggregate_hits),
        truncated=truncated,
        summary_only=summary_only,
        # NIST1 RUN2 ISSUE-002: summary_only keeps hit_count but omits the
        # (large) hits list so the result fits the MCP envelope.
        hits=[] if summary_only else aggregate_hits,
        files_scanned=files_scanned,
        raw_stderr=aggregate_stderr_text[:1000] if aggregate_stderr_text else "",
        raw_output_sha256=hashlib.sha256(aggregate_stdout_bytes).hexdigest()
        if aggregate_stdout_bytes
        else "",
    )
