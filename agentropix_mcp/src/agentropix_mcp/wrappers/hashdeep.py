"""hashdeep wrapper — multi-algorithm file hashing and hash-set audit.

hashdeep (part of md5deep) computes MD5, SHA-1, SHA-256, Tiger, and
Whirlpool digests.  Output is a CSV file whose column order is declared
in the ``%%%%`` header lines, so the parser resolves column positions
dynamically rather than hard-coding an offset.

Output shape::

    %%%% HASHDEEP-1.0
    %%%% size,md5,sha256,filename
    ## Invoked from: /evidence
    ## $ hashdeep -c sha256,md5 -r /evidence/extract
    ##
    13,d6eb32...,a1fff0...,/evidence/extract/cmd.exe

Audit mode (``-a -k known.txt``) produces match/mismatch lines instead
of hash lines.  The wrapper captures audit output verbatim in
``audit_output`` and sets ``audit_mode=True`` on the report so callers
can branch on it.
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

DEFAULT_TOOL_NAME = "hashdeep"

_VALID_ALGOS = frozenset({"md5", "sha1", "sha256", "tiger", "whirlpool"})

# %%%% size,algo1,algo2,...,filename
_COLUMN_RE = re.compile(r"^%%%%\s+(\S.*)$")
# Data line: no leading %% or ##
_DATA_RE = re.compile(r"^[^%#\s]")


class HashEntry(BaseModel):
    """One file's digest set as emitted by hashdeep."""

    filename: str
    size: int = 0
    hashes: dict[str, str] = Field(default_factory=dict)


class HashdeepReport(BaseModel):
    """Parsed output of a ``hashdeep`` run."""

    target: str
    algos: list[str] = Field(default_factory=list)
    recursive: bool = False
    entry_count: int = 0
    truncated: bool = False
    entries: list[HashEntry] = Field(default_factory=list)
    audit_mode: bool = False
    audit_output: str = ""
    tool: str = "hashdeep"
    raw_stderr: str = ""
    # SIFT-W-082: SHA-256 of hashdeep's raw stdout bytes.
    raw_stdout_sha256: str = ""


def _resolve_tool() -> str:
    return os.environ.get("AGENTROPIX_HASHDEEP_TOOL", DEFAULT_TOOL_NAME)


def _validate_algos(algos: list[str]) -> None:
    bad = [a for a in algos if a not in _VALID_ALGOS]
    if bad:
        raise ValueError(
            f"Invalid hashdeep algorithm(s) {bad!r}; "
            f"expected subset of {sorted(_VALID_ALGOS)}"
        )


def _parse_columns(header_line: str) -> list[str]:
    """Extract column names from a ``%%%% size,algo,...,filename`` line."""
    return [c.strip() for c in header_line.split(",")]


def _parse_hashdeep_output(
    stdout: str, *, max_files: int | None = None
) -> tuple[list[str], list[HashEntry], bool]:
    """Parse hashdeep stdout into (columns, entries, truncated).

    Columns are discovered from the ``%%%%`` header so the parser is
    robust to any ``-c`` combination the caller chose.
    """
    columns: list[str] = []
    entries: list[HashEntry] = []
    truncated = False

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        # Header: %%%% HASHDEEP-1.0  (skip version line)
        # Header: %%%% size,md5,sha256,filename  (column declaration)
        if line.startswith("%%%%"):
            m = _COLUMN_RE.match(line)
            if m:
                cols = _parse_columns(m.group(1))
                # Only treat as column header if it has "size" + "filename"
                if "size" in cols and "filename" in cols:
                    columns = cols
            continue

        if line.startswith("##"):
            continue

        if not _DATA_RE.match(line):
            continue

        if not columns:
            continue

        # CSV split — filename may contain commas, so split on len(columns)-1
        parts = line.split(",", len(columns) - 1)
        if len(parts) != len(columns):
            continue

        row = dict(zip(columns, parts))
        try:
            size = int(row.get("size", 0))
        except ValueError:
            size = 0

        filename = row.get("filename", "")
        hashes = {
            col: row[col]
            for col in columns
            if col not in ("size", "filename") and col in row
        }
        entries.append(HashEntry(filename=filename, size=size, hashes=hashes))

        if max_files is not None and len(entries) >= max_files:
            truncated = True
            break

    return columns, entries, truncated


async def run_hashdeep(
    target: str | Path,
    *,
    algos: list[str] | None = None,
    recursive: bool = False,
    known: str | Path | None = None,
    audit: bool = False,
    max_files: int | None = None,
    timeout: float | None = None,
) -> HashdeepReport:
    """Hash files under ``target`` using hashdeep.

    Args:
        target: File or directory to hash.
        algos: Algorithm list (subset of md5/sha1/sha256/tiger/whirlpool).
            Defaults to ``AGENTROPIX_HASHDEEP_ALGOS`` or ``["sha256","md5"]``.
        recursive: Pass ``-r`` to traverse subdirectories.
        known: Path to a hashdeep-format known-hash file; enables ``-k``.
        audit: When ``True`` (requires ``known``), pass ``-a`` for audit mode.
        max_files: Cap on returned entries. Entries beyond the cap are dropped
            and ``truncated`` is set on the report.
        timeout: Max seconds to wait.

    Returns:
        HashdeepReport with per-file entries.

    Raises:
        FileNotFoundError: target or hashdeep binary missing.
        ValueError: invalid algorithm.
        TimeoutError: hashdeep exceeds timeout.
        RuntimeError: non-zero exit with empty stdout.
    """
    target_path = Path(target)
    if not target_path.exists():
        raise FileNotFoundError(f"hashdeep target not found: {target_path}")

    if algos is None:
        env_algos = os.environ.get("AGENTROPIX_HASHDEEP_ALGOS", "sha256,md5")
        algos = [a.strip() for a in env_algos.split(",") if a.strip()]

    _validate_algos(algos)

    if max_files is None:
        max_files = get_int(
            "AGENTROPIX_HASHDEEP_MAX_FILES", 5000, floor=1, ceiling=500_000
        )

    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_HASHDEEP_TIMEOUT", 300.0, floor=5.0, ceiling=3600.0
        )

    if audit and known is None:
        raise ValueError("audit=True requires a known-hash file (known=)")

    tool_name = _resolve_tool()
    tool_path = shutil.which(tool_name)
    if not tool_path:
        raise FileNotFoundError(
            f"{tool_name} not found on PATH — install hashdeep (md5deep) "
            "or set AGENTROPIX_HASHDEEP_TOOL"
        )

    cmd: list[str] = [tool_path, "-c", ",".join(algos)]
    if recursive:
        cmd.append("-r")
    if known is not None:
        cmd.extend(["-k", str(known)])
    if audit:
        cmd.append("-a")
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

    raw_stdout_sha256 = hashlib.sha256(stdout_bytes).hexdigest()

    if audit:
        return HashdeepReport(
            target=str(target_path),
            algos=algos,
            recursive=recursive,
            audit_mode=True,
            audit_output=stdout[:8000],
            raw_stderr=stderr[:1000] if stderr else "",
            raw_stdout_sha256=raw_stdout_sha256,
        )

    columns, entries, truncated = _parse_hashdeep_output(stdout, max_files=max_files)
    algo_cols = [c for c in columns if c not in ("size", "filename")]

    return HashdeepReport(
        target=str(target_path),
        algos=algo_cols or algos,
        recursive=recursive,
        entry_count=len(entries),
        truncated=truncated,
        entries=entries,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=raw_stdout_sha256,
    )
