"""MFTECmd wrapper — Eric Zimmerman NTFS artifact parser (W-126).

MFTECmd parses key NTFS forensic artifacts:
- ``$MFT``        Master File Table — file system metadata for all files.
- ``$J``          USN journal ($UsnJrnl:$J) — file activity change log.
- ``$I30``        Directory index — per-directory listing (incl. deleted).
- ``$Boot``       Volume boot record.
- ``$Secure_$SDS`` Security descriptor data stream.

For the two most forensically valuable artifact types ($MFT, $J), the
wrapper parses the emitted CSV and surfaces a normalised
``MFTECmdEntry`` list. Other artifact types pass through the subprocess
and return an empty-entries report with the CSV SHA-256 for custody.

When ``artifact`` points to a ``$J`` file, an optional ``mft``
companion path can be supplied. MFTECmd passes it via ``-m`` to resolve
parent directory paths in the USN journal output — otherwise parent
path is empty.

Invocation pattern mirrors RECmd (W-125): ``dotnet <dll>`` with
``--csv <outdir> --csvf <pinned-name>`` so concurrent calls don't
collide. Graceful skip (M6.4) returns ``tool_available=False`` +
``skip_reason`` when dotnet or the DLL is absent.
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

DEFAULT_DLL = "/opt/ezt/net9/MFTECmd/MFTECmd.dll"
DEFAULT_DOTNET = "dotnet"
_OUTPUT_CSV_NAME = "MFTECmd_output.csv"


def _resolve_dll() -> str:
    return os.environ.get("AGENTROPIX_MFTECMD_DLL", DEFAULT_DLL)


def _resolve_dotnet() -> str:
    return os.environ.get("AGENTROPIX_DOTNET_TOOL", DEFAULT_DOTNET)


def _detect_artifact_type(path: Path) -> str:
    """Classify an NTFS artifact file by name stem.

    Returns one of: ``mft``, ``journal``, ``index``, ``boot``,
    ``secure``, ``unknown``.
    """
    stem = path.name.lstrip("$").lower()
    if stem == "mft":
        return "mft"
    if stem in ("j", "usnjrnl"):
        return "journal"
    if stem.startswith("i30"):
        return "index"
    if stem == "boot":
        return "boot"
    if "sds" in stem or "secure" in stem:
        return "secure"
    return "unknown"


def _safe_int(value: str) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


class MFTECmdEntry(BaseModel):
    """One row from MFTECmd CSV output (normalised across artifact types)."""

    entry_number: int = 0
    sequence_number: int = 0
    parent_entry_number: int = 0
    parent_path: str = ""
    file_name: str = ""
    extension: str = ""
    file_size: int = 0
    is_directory: bool = False
    is_deleted: bool = False
    has_ads: bool = False
    created: str = ""
    last_modified: str = ""    # Created0x10 ($MFT) or UpdateTimestamp ($J)
    last_access: str = ""
    last_record_change: str = ""
    update_reasons: str = ""   # $J only
    zone_id: str = ""          # ZoneIdContents ($MFT only)


class MFTECmdReport(BaseModel):
    """Parsed MFTECmd output.

    Mirrors RECmdReport in shape. ``artifact_type`` is auto-detected from
    the filename. ``mft_path`` records the optional $MFT companion used
    for journal parent-path resolution.
    """

    artifact_path: str
    artifact_type: str = ""
    mft_path: str = ""
    entry_count: int = 0
    parsed_count: int = 0
    error_count: int = 0
    truncated: bool = False
    entries: list[MFTECmdEntry] = Field(default_factory=list)
    tool: str = "mftecmd"
    raw_stderr: str = ""
    raw_csv_sha256: str = ""
    tool_available: bool = True
    skip_reason: str = ""


def _parse_mftecmd_csv(
    content: str, *, max_entries: int
) -> tuple[list[MFTECmdEntry], int, bool]:
    """Parse MFTECmd's CSV output, tolerating both $MFT and $J column schemas.

    Column names differ by artifact type but both use PascalCase without
    spaces. After lowercasing, lookups are unambiguous. Returns
    ``(entries, error_count, truncated)``.
    """
    if not content.strip():
        return [], 0, False

    # MFTECmd writes UTF-8 BOM at the start of its CSV files; without
    # stripping it, the first-column key ('EntryNumber') normalises to
    # '﻿entrynumber' instead of 'entrynumber' and every row reads
    # as 0 for entry_number. Strip BOM up front.
    content = content.lstrip("﻿")
    reader = csv.DictReader(io.StringIO(content))
    entries: list[MFTECmdEntry] = []
    errors = 0
    truncated = False

    for row in reader:
        norm = {k.lower().strip(): (v or "").strip() for k, v in row.items() if k}

        # FileName ($MFT) vs Name ($J)
        file_name = norm.get("filename") or norm.get("name") or ""
        if not file_name:
            errors += 1
            continue

        if len(entries) >= max_entries:
            truncated = True
            break

        entries.append(
            MFTECmdEntry(
                entry_number=_safe_int(norm.get("entrynumber", "0")),
                sequence_number=_safe_int(norm.get("sequencenumber", "0")),
                parent_entry_number=_safe_int(norm.get("parententrynumber", "0")),
                parent_path=norm.get("parentpath", ""),
                file_name=file_name,
                extension=norm.get("extension", ""),
                file_size=_safe_int(norm.get("filesize", "0")),
                is_directory=norm.get("isdirectory", "false").lower() == "true",
                is_deleted=norm.get("isdeleted", "false").lower() == "true",
                has_ads=norm.get("hasads", "false").lower() == "true",
                created=norm.get("created0x10", ""),
                last_modified=(
                    norm.get("lastmodified0x10")
                    or norm.get("updatetimestamp", "")
                ),
                last_access=norm.get("lastaccess0x10", ""),
                last_record_change=norm.get("lastrecordchange0x10", ""),
                update_reasons=norm.get("updatereasons", ""),
                zone_id=norm.get("zoneidcontents", ""),
            )
        )

    return entries, errors, truncated


async def get_mftecmd(
    artifact: str | Path,
    *,
    mft: str | Path | None = None,
    timeout: float | None = None,
) -> MFTECmdReport:
    """Parse an NTFS forensic artifact via MFTECmd (Eric Zimmerman, .NET).

    Args:
        artifact: Path to the NTFS artifact ($MFT, $J, $I30, $Boot, …).
        mft: Optional path to a $MFT file. Passed via ``-m`` when
            ``artifact`` is a ``$J`` file so MFTECmd can resolve parent
            directory paths in USN journal output.
        timeout: Subprocess timeout in seconds.
            ``None`` reads ``AGENTROPIX_MFTECMD_TIMEOUT`` (default 180,
            floor 5, ceiling 3600).

    Raises:
        FileNotFoundError: artifact (or supplied mft companion) missing.
        TimeoutError: MFTECmd exceeds timeout.
        RuntimeError: MFTECmd returns non-zero with no parseable output.

    Graceful skip:
        Missing dotnet or missing DLL → returns a report with
        ``tool_available=False`` + ``skip_reason``.
    """
    artifact_path = Path(artifact)
    if not artifact_path.exists():
        raise FileNotFoundError(f"NTFS artifact not found: {artifact_path}")

    mft_path: Path | None = None
    if mft is not None:
        mft_path = Path(mft)
        if not mft_path.exists():
            raise FileNotFoundError(f"$MFT companion not found: {mft_path}")

    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_MFTECMD_TIMEOUT", 180.0, floor=5.0, ceiling=3600.0
        )
    max_mft_entries = get_int(
        "AGENTROPIX_MFTECMD_MAX_MFT_ENTRIES", 100_000, floor=1, ceiling=10_000_000
    )
    max_journal_entries = get_int(
        "AGENTROPIX_MFTECMD_MAX_JOURNAL_ENTRIES", 50_000, floor=1, ceiling=5_000_000
    )

    artifact_type = _detect_artifact_type(artifact_path)
    max_entries = (
        max_journal_entries if artifact_type == "journal" else max_mft_entries
    )

    dotnet_name = _resolve_dotnet()
    dotnet_bin = shutil.which(dotnet_name)
    if not dotnet_bin:
        reason = (
            f"{dotnet_name} not found on PATH; "
            "install dotnet-runtime-9.0 or set AGENTROPIX_DOTNET_TOOL"
        )
        logger.info("MFTECmd skipped — %s", reason)
        return MFTECmdReport(
            artifact_path=str(artifact_path),
            artifact_type=artifact_type,
            tool_available=False,
            skip_reason=reason,
        )

    dll_path = Path(_resolve_dll())
    if not dll_path.is_file():
        reason = (
            f"MFTECmd DLL not found at {dll_path}; "
            "install via the EZ Tools net9 zip or set AGENTROPIX_MFTECMD_DLL"
        )
        logger.info("MFTECmd skipped — %s", reason)
        return MFTECmdReport(
            artifact_path=str(artifact_path),
            artifact_type=artifact_type,
            tool_available=False,
            skip_reason=reason,
        )

    with tempfile.TemporaryDirectory(prefix="agentropix-mftecmd-") as tmpdir:
        cmd = [
            dotnet_bin,
            str(dll_path),
            "-f",
            str(artifact_path),
            "--csv",
            tmpdir,
            "--csvf",
            _OUTPUT_CSV_NAME,
        ]
        if mft_path is not None:
            cmd += ["-m", str(mft_path)]

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
            raise TimeoutError(f"MFTECmd timed out after {timeout}s")

        stderr = stderr_bytes.decode(errors="replace")
        out_csv = Path(tmpdir) / _OUTPUT_CSV_NAME
        csv_bytes = out_csv.read_bytes() if out_csv.is_file() else b""

        if proc.returncode != 0 and not csv_bytes:
            raise RuntimeError(
                f"MFTECmd failed (rc={proc.returncode}): {stderr[:500]}"
            )

        csv_text = csv_bytes.decode(errors="replace") if csv_bytes else ""
        entries, error_count, truncated = _parse_mftecmd_csv(
            csv_text, max_entries=max_entries
        )
        return MFTECmdReport(
            artifact_path=str(artifact_path),
            artifact_type=artifact_type,
            mft_path=str(mft_path) if mft_path else "",
            entry_count=len(entries),
            parsed_count=len(entries),
            error_count=error_count,
            truncated=truncated,
            entries=entries,
            raw_stderr=stderr[:1000] if stderr else "",
            raw_csv_sha256=hashlib.sha256(csv_bytes).hexdigest() if csv_bytes else "",
        )
