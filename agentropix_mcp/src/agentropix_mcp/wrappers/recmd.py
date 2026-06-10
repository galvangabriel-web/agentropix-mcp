"""RECmd wrapper — Eric Zimmerman registry hive parser (W-125).

RECmd parses a Windows registry hive (SYSTEM, SOFTWARE, SAM, NTUSER.DAT,
USRCLASS.DAT) by replaying a "batch" file (`.reb`) full of key/value
audit rules. The shipped ``Kroll_Batch.reb`` covers the persistence and
execution-evidence keys most relevant to T1547 / T1053 / T1078 hunts.

Invocation differs from the amcache/shimcache wrappers in three ways:

1. RECmd is a .NET tool. We invoke ``dotnet <dll>`` rather than a
   binary on PATH. The dotnet runtime is itself a graceful-skip
   prerequisite.
2. RECmd writes a CSV to a directory via ``--csv <outdir>`` instead of
   to stdout. We pin the filename via ``--csvf`` and read it back from
   a per-call tempdir so concurrent calls don't collide.
3. The batch-file argument resolves against
   ``AGENTROPIX_RECMD_BATCH_DIR`` (default ``BatchExamples/`` shipped
   with the tool) so operators can swap batch sets without touching
   code.

Graceful skip is the M6.4 contract: if dotnet, the DLL, or the batch
file is missing, we return a sentinel report with
``tool_available=False`` and a populated ``skip_reason`` rather than
raising. The calling agent treats this as a soft "skipped" trace
record, not an error.
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import logging
import os
import shutil
import tempfile
from pathlib import Path

from pydantic import BaseModel, Field

from agentropix_mcp._env import get_float, get_int

logger = logging.getLogger(__name__)

DEFAULT_DLL = "/opt/ezt/net9/RECmd/RECmd.dll"
DEFAULT_BATCH_DIR = "/opt/ezt/net9/RECmd/BatchExamples"
DEFAULT_BATCH = "Kroll_Batch.reb"
DEFAULT_DOTNET = "dotnet"

# RECmd composes its own output filename when --csvf is omitted
# (timestamp-prefixed). Pinning it via --csvf gives us a deterministic
# read-back path without globbing.
_OUTPUT_CSV_NAME = "RECmd_output.csv"


def _resolve_dll() -> str:
    return os.environ.get("AGENTROPIX_RECMD_DLL", DEFAULT_DLL)


def _resolve_dotnet() -> str:
    return os.environ.get("AGENTROPIX_DOTNET_TOOL", DEFAULT_DOTNET)


def _resolve_batch_dir() -> str:
    return os.environ.get("AGENTROPIX_RECMD_BATCH_DIR", DEFAULT_BATCH_DIR)


def _resolve_default_batch() -> str:
    return os.environ.get("AGENTROPIX_RECMD_BATCH", DEFAULT_BATCH)


def _resolve_batch_path(batch_arg: str | None) -> Path:
    """Resolve a user-supplied batch name to an absolute path.

    Absolute paths pass through unchanged. Bare filenames resolve under
    ``AGENTROPIX_RECMD_BATCH_DIR``. ``None`` falls back to the default
    batch (``Kroll_Batch.reb``) under the same directory.
    """
    name = batch_arg if batch_arg else _resolve_default_batch()
    candidate = Path(name)
    if candidate.is_absolute():
        return candidate
    return Path(_resolve_batch_dir()) / name


class RECmdEntry(BaseModel):
    """One row from RECmd's batch-output CSV."""

    hive_path: str = ""
    hive_type: str = ""
    key_path: str = ""
    value_name: str = ""
    value_type: str = ""
    value_data: str = ""
    last_write: str = ""
    batch_section: str = ""
    deleted: bool = False
    recursive: bool = False
    comment: str = ""


class RECmdReport(BaseModel):
    """Parsed RECmd batch output.

    Mirrors AmcacheReport / ShimcacheReport in shape: the graceful-skip
    sentinel (``tool_available`` + ``skip_reason``) lets the calling
    agent record a "skipped" trace rather than an "ERROR" when any of
    dotnet / DLL / batch file is missing. ``raw_stdout_sha256`` covers
    chain-of-custody — but here it's hashed over the *CSV file bytes*
    we read back, since RECmd doesn't speak through stdout.
    """

    hive_path: str
    batch_file: str = ""
    entry_count: int = 0
    parsed_count: int = 0
    error_count: int = 0
    truncated: bool = False
    entries: list[RECmdEntry] = Field(default_factory=list)
    tool: str = "recmd"
    raw_stderr: str = ""
    raw_stdout_sha256: str = ""
    tool_available: bool = True
    skip_reason: str = ""


def _parse_recmd_csv(content: str, *, max_entries: int) -> tuple[list[RECmdEntry], int, bool]:
    """Parse RECmd's batch-output CSV.

    Returns ``(entries, error_count, truncated)``. Rows that are missing
    a key path are counted toward ``error_count`` rather than dropped
    silently — RECmd should never emit such rows from a healthy batch
    file, so the count is a useful soft-warning signal.
    """
    if not content.strip():
        return [], 0, False

    # RECmd (like the rest of the EZ Tools suite) writes UTF-8 BOM at
    # the start of its CSV files. Today RECmd doesn't bite us (the
    # required-field lookup happens to be 'keypath', a non-first column
    # that has no BOM), but stripping up-front future-proofs the parser
    # against batch-file changes that might reorder columns.
    content = content.lstrip("﻿")
    reader = csv.DictReader(io.StringIO(content))
    entries: list[RECmdEntry] = []
    errors = 0
    truncated = False
    for row in reader:
        norm = {k.lower().strip(): (v or "").strip() for k, v in row.items() if k}
        key_path = norm.get("keypath") or norm.get("key path") or ""
        if not key_path:
            errors += 1
            continue
        if len(entries) >= max_entries:
            truncated = True
            break
        entries.append(
            RECmdEntry(
                hive_path=norm.get("hivepath") or norm.get("hive path", ""),
                hive_type=norm.get("hivetype") or norm.get("hive type", ""),
                key_path=key_path,
                value_name=norm.get("valuename") or norm.get("value name", ""),
                value_type=norm.get("valuetype") or norm.get("value type", ""),
                value_data=norm.get("valuedata") or norm.get("value data", ""),
                last_write=(
                    norm.get("lastwritetimestamp")
                    or norm.get("last write timestamp")
                    or norm.get("lastwrite", "")
                ),
                batch_section=(
                    norm.get("batchsection")
                    or norm.get("plugindetailfile")
                    or norm.get("plugin detail file", "")
                ),
                deleted=norm.get("deleted", "false").lower() == "true",
                recursive=norm.get("recursive", "false").lower() == "true",
                comment=norm.get("comment", ""),
            )
        )
    return entries, errors, truncated


async def get_recmd(
    hive: str | Path,
    *,
    batch_file: str | None = None,
    timeout: float | None = None,
) -> RECmdReport:
    """Parse a Windows registry hive via RECmd (Eric Zimmerman, .NET).

    Args:
        hive: Path to a registry hive (SYSTEM, SOFTWARE, SAM, NTUSER.DAT, …).
        batch_file: Batch filename (resolved under
            ``AGENTROPIX_RECMD_BATCH_DIR``) or absolute path to a
            ``.reb`` file. ``None`` selects ``AGENTROPIX_RECMD_BATCH``
            (default ``Kroll_Batch.reb``).
        timeout: Subprocess timeout in seconds.
            ``None`` reads ``AGENTROPIX_RECMD_TIMEOUT`` (default 120,
            floor 5, ceiling 3600).

    Raises:
        FileNotFoundError: hive missing.
        TimeoutError: RECmd exceeds timeout.
        RuntimeError: RECmd returns non-zero with no parseable output.

    Graceful skip:
        Missing dotnet, missing DLL, or missing batch file → returns a
        report with ``tool_available=False`` + ``skip_reason``.
    """
    hive_path = Path(hive)
    if not hive_path.exists():
        raise FileNotFoundError(f"Registry hive not found: {hive_path}")

    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_RECMD_TIMEOUT", 120.0, floor=5.0, ceiling=3600.0
        )
    max_entries = get_int(
        "AGENTROPIX_RECMD_MAX_ENTRIES", 10_000, floor=1, ceiling=1_000_000
    )

    dotnet_name = _resolve_dotnet()
    dotnet_path = shutil.which(dotnet_name)
    if not dotnet_path:
        reason = (
            f"{dotnet_name} not found on PATH; "
            "install dotnet-runtime-9.0 or set AGENTROPIX_DOTNET_TOOL"
        )
        logger.info("RECmd skipped — %s", reason)
        return RECmdReport(
            hive_path=str(hive_path), tool_available=False, skip_reason=reason
        )

    dll_path = Path(_resolve_dll())
    if not dll_path.is_file():
        reason = (
            f"RECmd DLL not found at {dll_path}; "
            "install via the EZ Tools net9 zip or set AGENTROPIX_RECMD_DLL"
        )
        logger.info("RECmd skipped — %s", reason)
        return RECmdReport(
            hive_path=str(hive_path), tool_available=False, skip_reason=reason
        )

    resolved_batch = _resolve_batch_path(batch_file)
    if not resolved_batch.is_file():
        reason = (
            f"RECmd batch file not found at {resolved_batch}; "
            "install BatchExamples/ or set AGENTROPIX_RECMD_BATCH_DIR / "
            "AGENTROPIX_RECMD_BATCH"
        )
        logger.info("RECmd skipped — %s", reason)
        return RECmdReport(
            hive_path=str(hive_path),
            batch_file=str(resolved_batch),
            tool_available=False,
            skip_reason=reason,
        )

    with tempfile.TemporaryDirectory(prefix="agentropix-recmd-") as tmpdir:
        cmd = [
            dotnet_path,
            str(dll_path),
            "-f",
            str(hive_path),
            "--bn",
            str(resolved_batch),
            "--csv",
            tmpdir,
            "--csvf",
            _OUTPUT_CSV_NAME,
            "--nl",  # tolerate missing transaction logs (typical for hive copies)
        ]
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
            raise TimeoutError(f"RECmd timed out after {timeout}s")

        stderr = stderr_bytes.decode(errors="replace")
        out_csv = Path(tmpdir) / _OUTPUT_CSV_NAME
        csv_bytes = out_csv.read_bytes() if out_csv.is_file() else b""

        if proc.returncode != 0 and not csv_bytes:
            raise RuntimeError(
                f"RECmd failed (rc={proc.returncode}): "
                f"{stderr[:500] or stdout_bytes.decode(errors='replace')[:500]}"
            )

        csv_text = csv_bytes.decode(errors="replace") if csv_bytes else ""
        entries, error_count, truncated = _parse_recmd_csv(
            csv_text, max_entries=max_entries
        )
        return RECmdReport(
            hive_path=str(hive_path),
            batch_file=str(resolved_batch),
            entry_count=len(entries),
            parsed_count=len(entries),
            error_count=error_count,
            truncated=truncated,
            entries=entries,
            raw_stderr=stderr[:1000] if stderr else "",
            raw_stdout_sha256=hashlib.sha256(csv_bytes).hexdigest() if csv_bytes else "",
        )
