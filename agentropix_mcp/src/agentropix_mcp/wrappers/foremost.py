"""``foremost`` file carver wrapper.

Drives the system ``foremost`` binary (Kornblum/Kendall/Mikus) against a
disk image, memory dump, or other raw file to carve out files by magic
signature. Output goes to a caller-chosen output directory — one
subdirectory per file type plus a single ``audit.txt`` summarising the
run.

Invocation shape::

    foremost [-q] [-a] [-t <types>] -i <input> -o <outdir>

``-o <outdir>`` is mandatory and the directory must NOT exist unless
``zap=True`` (emits ``rm -rf`` on the directory before invoking
foremost; foremost itself aborts otherwise).

``audit.txt`` shape is stable across 1.5.x releases::

    Foremost version 1.5.7 by ...
    Audit File
    Foremost started at Tue Apr 21 05:25:16 2026
    Invocation: foremost -t jpg -i <input> -o <outdir>
    Output directory: <outdir>
    Configuration file: /etc/foremost.conf
    ------------------------------------------------------------------
    File: <input>
    Start: Tue Apr 21 05:25:16 2026
    Length: 26 B (26 bytes)

    Num   Name (bs=512)           Size       File Offset     Comment
    0:    00000000.jpg            4096 B     0
    1:    00000008.jpg            8192 B     4096            (extension)

    Finish: Tue Apr 21 05:25:16 2026
    N FILES EXTRACTED

Data rows are tab-separated under the header ``Num Name (bs=512) Size
File Offset Comment``. When no files are carved, the summary line reads
``0 FILES EXTRACTED`` and the audit.txt contains only the header frame.
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

DEFAULT_TOOL_NAME = "foremost"

# Header marking the start of the per-file data rows in audit.txt.
# foremost emits this line verbatim before every carved-file table.
_HEADER_RE = re.compile(r"^\s*Num\s+Name\s*\(bs=\d+\)\s+Size\s+File Offset\s+Comment", re.IGNORECASE)

# Line summarising the run: "N FILES EXTRACTED".
_SUMMARY_RE = re.compile(r"^\s*(\d+)\s+FILES EXTRACTED", re.IGNORECASE)

# One carved-file row: leading digits + colon, then whitespace-separated
# fields.  foremost uses literal tabs between columns; fall back to any
# run of whitespace so slightly-different builds still parse.
_ROW_RE = re.compile(
    r"^\s*(?P<num>\d+):\s+"
    r"(?P<name>\S+)\s+"
    r"(?P<size>\d+\s*(?:B|KB|MB|GB))\s+"
    r"(?P<offset>\d+)"
    r"(?:\s+(?P<comment>.*))?$",
    re.IGNORECASE,
)


def _resolve_tool() -> str:
    """Resolve the foremost binary, honouring AGENTROPIX_FOREMOST_TOOL."""
    return os.environ.get("AGENTROPIX_FOREMOST_TOOL", DEFAULT_TOOL_NAME)


class ForemostEntry(BaseModel):
    """One carved file row parsed out of audit.txt."""

    num: int
    name: str
    size: str
    file_offset: int
    comment: str = ""


class ForemostReport(BaseModel):
    """Aggregated output of a foremost run."""

    target: str
    output_dir: str
    entry_count: int = 0
    extracted_files_declared: int = 0
    types: list[str] = Field(default_factory=list)
    entries: list[ForemostEntry] = Field(default_factory=list)
    truncated: bool = False
    tool: str = "foremost"
    audit_text: str = ""
    raw_stderr: str = ""
    # SIFT-W-082: SHA-256 of foremost's raw stdout bytes — chain-of-custody fingerprint.
    raw_stdout_sha256: str = ""


def _parse_audit(
    audit_text: str,
    *,
    max_entries: int,
) -> tuple[list[ForemostEntry], int, bool]:
    """Parse audit.txt into typed entries + declared total + truncation flag.

    Entries beyond ``max_entries`` are dropped; ``truncated`` is set when
    the declared total or parsed row count exceeds the cap.  The declared
    total is the integer from the ``N FILES EXTRACTED`` summary, which
    foremost prints regardless of whether it actually wrote the files.
    """
    entries: list[ForemostEntry] = []
    declared = 0
    in_data_block = False

    for raw in audit_text.splitlines():
        line = raw.rstrip("\r\n")

        summary = _SUMMARY_RE.match(line)
        if summary:
            # Sum across per-file blocks if foremost ever emits more than
            # one (multi-input or chained runs).  Single-input runs hit
            # this once.
            declared += int(summary.group(1))
            in_data_block = False
            continue

        if _HEADER_RE.match(line):
            in_data_block = True
            continue

        if not in_data_block:
            continue

        stripped = line.strip()
        if not stripped:
            # Blank line separates the row block from the Finish line.
            # Keep in_data_block True — rows usually come right after
            # the header and blank rows inside are rare, but we bail
            # out cleanly on "Finish:" below.
            continue

        if stripped.startswith("Finish:"):
            in_data_block = False
            continue

        m = _ROW_RE.match(line)
        if not m:
            continue

        if len(entries) >= max_entries:
            # Keep counting via declared, but stop materialising.
            continue

        entries.append(
            ForemostEntry(
                num=int(m.group("num")),
                name=m.group("name"),
                size=m.group("size").strip(),
                file_offset=int(m.group("offset")),
                comment=(m.group("comment") or "").strip(),
            )
        )

    truncated = declared > len(entries) or (
        declared == 0 and len(entries) >= max_entries
    )
    return entries, declared, truncated


async def run_foremost(
    image: str | Path,
    output_dir: str | Path,
    *,
    config: str | Path | None = None,
    types: list[str] | None = None,
    quick: bool = False,
    audit_only: bool = False,
    all_headers: bool = False,
    zap: bool = False,
    max_entries: int | None = None,
    timeout: float | None = None,
) -> ForemostReport:
    """Run ``foremost`` against ``image`` and parse the audit manifest.

    Args:
        image: Path to the raw disk image / memory dump / file to carve.
        output_dir: Output directory foremost will populate.  Must NOT
            exist unless ``zap=True`` (foremost refuses to overwrite).
        config: Optional custom ``foremost.conf``. When None, foremost
            uses its system default (``/etc/foremost.conf``).
        types: Optional list of file-type tokens (``jpg``, ``pdf``, ``exe``
            etc.) passed via ``-t``.  When None, foremost carves the
            full default type set.
        quick: Pass ``-q`` (search on 512-byte boundaries; faster but
            misses unaligned signatures).
        audit_only: Pass ``-w`` — write audit.txt but do NOT write
            carved files to disk.  Halves disk usage and lets the
            caller gate writes upstream.
        all_headers: Pass ``-a`` (accept all headers, no error
            detection; matches more signatures, more false positives).
        zap: ``shutil.rmtree(output_dir, ignore_errors=True)`` before
            running foremost.  Without this, foremost aborts with
            ``ERROR: /foo already exists``.
        max_entries: Cap on materialised audit entries in the report.
            Defaults to ``AGENTROPIX_FOREMOST_MAX_ENTRIES``.
        timeout: Wrapper-level subprocess timeout. Defaults to
            ``AGENTROPIX_FOREMOST_TIMEOUT``.

    Raises:
        FileNotFoundError: image missing or foremost binary not on PATH.
        RuntimeError: foremost exits non-zero.
        TimeoutError: subprocess exceeds ``timeout``.
    """
    image_path = Path(image)
    if not image_path.exists():
        raise FileNotFoundError(f"foremost input not found: {image_path}")

    output_path = Path(output_dir)

    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_FOREMOST_TIMEOUT",
            300.0,
            floor=5.0,
            ceiling=86_400.0,
        )
    if max_entries is None:
        max_entries = get_int(
            "AGENTROPIX_FOREMOST_MAX_ENTRIES",
            5000,
            floor=1,
            ceiling=1_000_000,
        )

    tool_name = _resolve_tool()
    tool_path = shutil.which(tool_name)
    if tool_path is None:
        raise FileNotFoundError(
            f"{tool_name} not found on PATH — install foremost "
            "or set AGENTROPIX_FOREMOST_TOOL"
        )

    if zap and output_path.exists():
        shutil.rmtree(output_path, ignore_errors=True)

    cmd: list[str] = [tool_path]
    if quick:
        cmd.append("-q")
    if audit_only:
        cmd.append("-w")
    if all_headers:
        cmd.append("-a")
    if types:
        cmd.extend(["-t", ",".join(types)])
    if config is not None:
        cmd.extend(["-c", str(config)])
    cmd.extend(["-i", str(image_path), "-o", str(output_path)])

    logger.info("Running: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"{tool_name} timed out after {timeout}s") from None

    stderr = stderr_bytes.decode(errors="replace")

    if proc.returncode not in (0, None):
        raise RuntimeError(f"{tool_name} failed (rc={proc.returncode}): {stderr[:500]}")

    audit_path = output_path / "audit.txt"
    if not audit_path.exists():
        # foremost normally always produces audit.txt; if it's missing
        # the run failed in an unusual way (kernel killed, OOM, etc.).
        raise RuntimeError(
            f"{tool_name} produced no audit.txt under {output_path} — "
            "run may have been killed externally"
        )
    try:
        audit_text = audit_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise RuntimeError(f"could not read {audit_path}: {exc}") from exc

    entries, declared, truncated = _parse_audit(audit_text, max_entries=max_entries)

    return ForemostReport(
        target=str(image_path),
        output_dir=str(output_path),
        entry_count=len(entries),
        extracted_files_declared=declared,
        types=list(types) if types else [],
        entries=entries,
        truncated=truncated,
        audit_text=audit_text[:8000],
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
    )
