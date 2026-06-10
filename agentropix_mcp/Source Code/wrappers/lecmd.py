"""LECmd wrapper — Eric Zimmerman .lnk shortcut parser (W-127).

LECmd parses Windows Shell Link (.lnk) files — the shortcut format that
records target path, arguments, working directory, icon location, and
four timestamps (SourceCreated/Modified/Accessed, TargetModified).

Two invocation modes, auto-selected from ``target``:

- **File mode** (``-f``): target is a single .lnk file.
- **Directory mode** (``-d``): target is a directory; LECmd recurses
  and collects all ``*.lnk`` matches by default, or all files when
  ``all_files=True`` (passes ``--all``).

Like RECmd / MFTECmd, LECmd writes CSV to ``--csv <outdir> --csvf
<pinned-name>`` so concurrent calls never collide. We pass ``-q`` to
suppress per-file detail dumps on stdout (we only read the CSV).

Graceful skip (M6.4) returns ``tool_available=False`` + ``skip_reason``
when dotnet or the DLL is absent, so the calling agent emits a
"skipped" trace rather than an error.
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

DEFAULT_DLL = "/opt/ezt/net9/LECmd/LECmd.dll"
DEFAULT_DOTNET = "dotnet"
_OUTPUT_CSV_NAME = "LECmd_output.csv"


def _resolve_dll() -> str:
    return os.environ.get("AGENTROPIX_LECMD_DLL", DEFAULT_DLL)


def _resolve_dotnet() -> str:
    return os.environ.get("AGENTROPIX_DOTNET_TOOL", DEFAULT_DOTNET)


class LECmdEntry(BaseModel):
    """One row from LECmd's CSV output.

    Fields cover the metadata forensically most relevant to T1547
    persistence chains: target paths, arguments, timestamps, and the
    drive/network location that identifies the stager origin.
    """

    source_file: str = ""
    source_created: str = ""
    source_modified: str = ""
    source_accessed: str = ""
    target_created: str = ""
    target_modified: str = ""
    target_accessed: str = ""
    file_size: int = 0
    relative_path: str = ""
    working_directory: str = ""
    arguments: str = ""
    icon_location: str = ""
    description: str = ""
    hot_key: str = ""
    local_path: str = ""
    network_path: str = ""
    common_path: str = ""
    drive_type: str = ""
    volume_serial: str = ""
    volume_label: str = ""
    file_attributes: str = ""
    is_unicode: bool = False
    has_arguments: bool = False
    has_icon_location: bool = False


class LECmdReport(BaseModel):
    """Parsed LECmd output.

    Mirrors RECmdReport / MFTECmdReport in shape. ``target_mode`` is
    either ``"file"`` or ``"directory"`` indicating which LECmd flag
    was used. ``raw_csv_sha256`` covers chain-of-custody over the CSV
    bytes before parsing.
    """

    target: str
    target_mode: str = ""
    entry_count: int = 0
    parsed_count: int = 0
    error_count: int = 0
    truncated: bool = False
    entries: list[LECmdEntry] = Field(default_factory=list)
    tool: str = "lecmd"
    raw_stderr: str = ""
    raw_csv_sha256: str = ""
    tool_available: bool = True
    skip_reason: str = ""


def _safe_int(value: str) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


def _safe_bool(value: str) -> bool:
    return value.lower().strip() == "true"


def _parse_lecmd_csv(
    content: str, *, max_entries: int
) -> tuple[list[LECmdEntry], int, bool]:
    """Parse LECmd's CSV output.

    Column names use PascalCase. After lowercasing, lookups handle both
    space-separated ("Source File") and concatenated ("SourceFile")
    forms that vary across LECmd minor versions. Returns
    ``(entries, error_count, truncated)``.
    """
    if not content.strip():
        return [], 0, False

    # LECmd (like the rest of the EZ Tools suite) writes UTF-8 BOM at
    # the start of its CSV files; without stripping it, the first-
    # column key ('SourceFile') normalises to '﻿sourcefile' and the
    # required-field gate rejects every row.
    content = content.lstrip("﻿")
    reader = csv.DictReader(io.StringIO(content))
    entries: list[LECmdEntry] = []
    errors = 0
    truncated = False

    for row in reader:
        # Normalise: lowercase, strip spaces from keys, strip values.
        norm = {
            k.lower().replace(" ", "").strip(): (v or "").strip()
            for k, v in row.items()
            if k
        }

        source_file = norm.get("sourcefile", "")
        if not source_file:
            errors += 1
            continue

        if len(entries) >= max_entries:
            truncated = True
            break

        entries.append(
            LECmdEntry(
                source_file=source_file,
                source_created=norm.get("sourcecreated", ""),
                source_modified=norm.get("sourcemodified", ""),
                source_accessed=norm.get("sourceaccessed", ""),
                target_created=norm.get("targetcreated", ""),
                target_modified=norm.get("targetmodified", ""),
                target_accessed=norm.get("targetaccessed", ""),
                file_size=_safe_int(norm.get("filesize", "0")),
                relative_path=norm.get("relativepath", ""),
                working_directory=norm.get("workingdirectory", ""),
                arguments=norm.get("arguments", ""),
                icon_location=norm.get("iconlocation", ""),
                description=norm.get("description", ""),
                hot_key=norm.get("hotkey", ""),
                local_path=norm.get("localpath", ""),
                network_path=norm.get("networkpath", ""),
                common_path=norm.get("commonpath", ""),
                drive_type=norm.get("drivetype", ""),
                volume_serial=norm.get("volumeserialnumber", "")
                or norm.get("driveserailnumber", ""),
                volume_label=norm.get("volumelabel", ""),
                file_attributes=norm.get("fileattributes", ""),
                is_unicode=_safe_bool(norm.get("isunicode", "false")),
                has_arguments=_safe_bool(norm.get("hasarguments", "false")),
                has_icon_location=_safe_bool(norm.get("hasiconlocation", "false")),
            )
        )

    return entries, errors, truncated


async def get_lecmd(
    target: str | Path,
    *,
    all_files: bool = False,
    timeout: float | None = None,
) -> LECmdReport:
    """Parse Windows .lnk shortcut files via LECmd (Eric Zimmerman, .NET).

    Args:
        target: Path to a single .lnk file or a directory containing
            .lnk files. Directories are processed with ``-d`` (LECmd
            recurses automatically); files use ``-f``.
        all_files: When ``target`` is a directory, pass ``--all`` to
            process every file rather than only ``*.lnk`` matches.
            Ignored if ``target`` is a file.
        timeout: Subprocess timeout in seconds.
            ``None`` reads ``AGENTROPIX_LECMD_TIMEOUT`` (default 120,
            floor 5, ceiling 3600).

    Raises:
        FileNotFoundError: target path does not exist.
        TimeoutError: LECmd exceeds timeout.
        RuntimeError: LECmd returns non-zero with no parseable output.

    Graceful skip:
        Missing dotnet or missing DLL → returns a report with
        ``tool_available=False`` + ``skip_reason``.
    """
    target_path = Path(target)
    if not target_path.exists():
        raise FileNotFoundError(f".lnk target not found: {target_path}")

    is_dir = target_path.is_dir()
    target_mode = "directory" if is_dir else "file"

    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_LECMD_TIMEOUT", 120.0, floor=5.0, ceiling=3600.0
        )
    max_entries = get_int(
        "AGENTROPIX_LECMD_MAX_ENTRIES", 10_000, floor=1, ceiling=1_000_000
    )

    dotnet_name = _resolve_dotnet()
    dotnet_bin = shutil.which(dotnet_name)
    if not dotnet_bin:
        reason = (
            f"{dotnet_name} not found on PATH; "
            "install dotnet-runtime-9.0 or set AGENTROPIX_DOTNET_TOOL"
        )
        logger.info("LECmd skipped — %s", reason)
        return LECmdReport(
            target=str(target_path),
            target_mode=target_mode,
            tool_available=False,
            skip_reason=reason,
        )

    dll_path = Path(_resolve_dll())
    if not dll_path.is_file():
        reason = (
            f"LECmd DLL not found at {dll_path}; "
            "install via the EZ Tools net9 zip or set AGENTROPIX_LECMD_DLL"
        )
        logger.info("LECmd skipped — %s", reason)
        return LECmdReport(
            target=str(target_path),
            target_mode=target_mode,
            tool_available=False,
            skip_reason=reason,
        )

    with tempfile.TemporaryDirectory(prefix="agentropix-lecmd-") as tmpdir:
        if is_dir:
            input_flag = ["-d", str(target_path)]
        else:
            input_flag = ["-f", str(target_path)]

        cmd = [
            dotnet_bin,
            str(dll_path),
            *input_flag,
            "-q",
            "--csv",
            tmpdir,
            "--csvf",
            _OUTPUT_CSV_NAME,
        ]
        if is_dir and all_files:
            cmd.append("--all")

        logger.info("Running: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            raise TimeoutError(f"LECmd timed out after {timeout}s")

        stderr = stderr_bytes.decode(errors="replace")
        out_csv = Path(tmpdir) / _OUTPUT_CSV_NAME
        csv_bytes = out_csv.read_bytes() if out_csv.is_file() else b""

        if proc.returncode != 0 and not csv_bytes:
            raise RuntimeError(
                f"LECmd failed (rc={proc.returncode}): {stderr[:500]}"
            )

        csv_text = csv_bytes.decode(errors="replace") if csv_bytes else ""
        entries, error_count, truncated = _parse_lecmd_csv(
            csv_text, max_entries=max_entries
        )
        return LECmdReport(
            target=str(target_path),
            target_mode=target_mode,
            entry_count=len(entries),
            parsed_count=len(entries),
            error_count=error_count,
            truncated=truncated,
            entries=entries,
            raw_stderr=stderr[:1000] if stderr else "",
            raw_csv_sha256=hashlib.sha256(csv_bytes).hexdigest() if csv_bytes else "",
        )
