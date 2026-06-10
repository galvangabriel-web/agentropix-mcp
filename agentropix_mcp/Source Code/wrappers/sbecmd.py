"""SBECmd wrapper — Eric Zimmerman ShellBags Explorer (Phase 2).

ShellBags are NTUSER.DAT / UsrClass.dat registry artefacts that record
folder-navigation history per user. They preserve evidence of:

- Folders the user opened in Explorer (including external/USB paths).
- Network shares accessed (UNC paths cached in ShellBags).
- Deleted directories the user once visited.

SBECmd takes a *directory* of registry hive files and emits one or
more CSVs containing the parsed bag entries. Unlike RECmd / MFTECmd,
SBECmd is **directory-only** (no ``-f`` single-file mode) — it
expects a folder containing ``NTUSER.DAT`` / ``UsrClass.dat`` files
(typically from the same user, but can be batch from many users).

Pattern: ``-d <hivedir> --csv <outdir> --csvf <pinned>`` plus M6.4
graceful skip on missing dotnet / DLL.
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
from agentropix_mcp.wrappers._subprocess import run_with_memory_limit

logger = logging.getLogger(__name__)

DEFAULT_DLL = "/opt/ezt/net9/SBECmd/SBECmd.dll"
DEFAULT_DOTNET = "dotnet"
_OUTPUT_CSV_NAME = "SBECmd_output.csv"


def _resolve_dll() -> str:
    return os.environ.get("AGENTROPIX_SBECMD_DLL", DEFAULT_DLL)


def _resolve_dotnet() -> str:
    return os.environ.get("AGENTROPIX_DOTNET_TOOL", DEFAULT_DOTNET)


class SBECmdEntry(BaseModel):
    """One ShellBag row from a parsed NTUSER.DAT / UsrClass.dat hive.

    Forensically salient fields are ``absolute_path`` (the recorded
    directory the user navigated to), ``last_interacted`` (when the
    user last touched the folder), and ``shell_type`` (drive letter,
    UNC, virtual folder, etc.).
    """

    bag_path: str = ""
    slot: str = ""
    node_slot: str = ""
    mru_position: str = ""
    absolute_path: str = ""
    shell_type: str = ""
    value: str = ""
    child_bags: str = ""
    created_on: str = ""
    modified_on: str = ""
    accessed_on: str = ""
    last_write_time: str = ""
    miscellaneous: str = ""
    hive_path: str = ""


class SBECmdReport(BaseModel):
    """Parsed SBECmd output (ShellBag rows aggregated across hives)."""

    hive_dir: str
    entry_count: int = 0
    parsed_count: int = 0
    error_count: int = 0
    truncated: bool = False
    entries: list[SBECmdEntry] = Field(default_factory=list)
    tool: str = "sbecmd"
    raw_stderr: str = ""
    raw_csv_sha256: str = ""
    tool_available: bool = True
    skip_reason: str = ""


def _parse_sbecmd_csv(
    content: str, *, max_entries: int
) -> tuple[list[SBECmdEntry], int, bool]:
    if not content.strip():
        return [], 0, False

    content = content.lstrip("﻿")
    reader = csv.DictReader(io.StringIO(content))
    entries: list[SBECmdEntry] = []
    errors = 0
    truncated = False

    for row in reader:
        norm = {
            k.lower().replace(" ", "").strip(): (v or "").strip()
            for k, v in row.items()
            if k
        }
        absolute_path = norm.get("absolutepath", "")
        if not absolute_path:
            errors += 1
            continue

        if len(entries) >= max_entries:
            truncated = True
            break

        entries.append(
            SBECmdEntry(
                bag_path=norm.get("bagpath", ""),
                slot=norm.get("slot", ""),
                node_slot=norm.get("nodeslot", ""),
                mru_position=norm.get("mruposition", ""),
                absolute_path=absolute_path,
                shell_type=norm.get("shelltype", ""),
                value=norm.get("value", ""),
                child_bags=norm.get("childbags", ""),
                created_on=norm.get("createdon", ""),
                modified_on=norm.get("modifiedon", ""),
                accessed_on=norm.get("accessedon", ""),
                last_write_time=norm.get("lastwritetime", ""),
                miscellaneous=norm.get("miscellaneous", ""),
                hive_path=norm.get("hivepath", ""),
            )
        )
    return entries, errors, truncated


async def get_sbecmd(
    hive_dir: str | Path,
    *,
    timeout: float | None = None,
) -> SBECmdReport:
    """Parse ShellBags from registry hives via SBECmd (Eric Zimmerman, .NET).

    Args:
        hive_dir: Directory containing one or more ``NTUSER.DAT`` /
            ``UsrClass.dat`` files. SBECmd is directory-only by design
            (it batches all hives in the dir).
        timeout: Subprocess timeout (s). ``None`` reads
            ``AGENTROPIX_SBECMD_TIMEOUT`` (default 180s, floor 5,
            ceiling 3600).

    Raises:
        FileNotFoundError: hive_dir missing or not a directory.
        TimeoutError: SBECmd exceeded timeout.
        RuntimeError: SBECmd returned non-zero with no parseable CSV.

    Graceful skip: missing dotnet or DLL → ``tool_available=False``.
    """
    dir_path = Path(hive_dir)
    if not dir_path.exists():
        raise FileNotFoundError(f"ShellBag hive directory not found: {dir_path}")
    if not dir_path.is_dir():
        raise FileNotFoundError(
            f"SBECmd requires a directory of hives, got file: {dir_path}"
        )

    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_SBECMD_TIMEOUT", 180.0, floor=5.0, ceiling=3600.0
        )
    max_entries = get_int(
        "AGENTROPIX_SBECMD_MAX_ENTRIES", 50_000, floor=1, ceiling=5_000_000
    )

    dotnet_name = _resolve_dotnet()
    dotnet_bin = shutil.which(dotnet_name)
    if not dotnet_bin:
        reason = (
            f"{dotnet_name} not found on PATH; "
            "install dotnet-runtime-9.0 or set AGENTROPIX_DOTNET_TOOL"
        )
        logger.info("SBECmd skipped — %s", reason)
        return SBECmdReport(
            hive_dir=str(dir_path), tool_available=False, skip_reason=reason
        )

    dll_path = Path(_resolve_dll())
    if not dll_path.is_file():
        reason = (
            f"SBECmd DLL not found at {dll_path}; "
            "install via the EZ Tools net9 zip or set AGENTROPIX_SBECMD_DLL"
        )
        logger.info("SBECmd skipped — %s", reason)
        return SBECmdReport(
            hive_dir=str(dir_path), tool_available=False, skip_reason=reason
        )

    with tempfile.TemporaryDirectory(prefix="agentropix-sbecmd-") as tmpdir:
        cmd = [
            dotnet_bin,
            str(dll_path),
            "-d",
            str(dir_path),
            "--csv",
            tmpdir,
            "--csvf",
            _OUTPUT_CSV_NAME,
        ]
        logger.info("Running: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr_bytes = await run_with_memory_limit(proc, timeout, "sbecmd")
        except TimeoutError:
            raise TimeoutError(f"SBECmd timed out after {timeout}s") from None

        stderr = stderr_bytes.decode(errors="replace")
        out_csv = Path(tmpdir) / _OUTPUT_CSV_NAME
        if not out_csv.is_file():
            candidates = [
                p for p in Path(tmpdir).iterdir()
                if p.is_file() and p.suffix.lower() == ".csv"
            ]
            if candidates:
                out_csv = candidates[0]

        csv_bytes = out_csv.read_bytes() if out_csv.is_file() else b""
        if proc.returncode != 0 and not csv_bytes:
            raise RuntimeError(
                f"SBECmd failed (rc={proc.returncode}): {stderr[:500]}"
            )

        csv_text = csv_bytes.decode(errors="replace") if csv_bytes else ""
        entries, error_count, truncated = _parse_sbecmd_csv(
            csv_text, max_entries=max_entries
        )
        return SBECmdReport(
            hive_dir=str(dir_path),
            entry_count=len(entries),
            parsed_count=len(entries),
            error_count=error_count,
            truncated=truncated,
            entries=entries,
            raw_stderr=stderr[:1000] if stderr else "",
            raw_csv_sha256=hashlib.sha256(csv_bytes).hexdigest() if csv_bytes else "",
        )
