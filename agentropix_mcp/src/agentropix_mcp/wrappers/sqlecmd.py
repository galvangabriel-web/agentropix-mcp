"""SQLECmd wrapper — Eric Zimmerman SQLite parser (Phase 2).

SQLECmd parses SQLite databases against a library of forensic "maps"
(``.smap`` files) that describe how to extract evidence from known
schemas. Stock maps cover browser history (Chrome / Firefox /
Edge), Windows AppCompat / Notification Database, Skype / Slack /
Teams databases, Android contacts/SMS/calls, plus 80+ more.

Unlike RECmd / MFTECmd / LECmd, SQLECmd emits **one CSV per detected
SQLite schema** — a single SQLite file may produce multiple CSVs (e.g.
Chrome's ``History`` produces both `Chrome_DownloadList.csv` and
`Chrome_VisitedSites.csv`). The wrapper aggregates row counts across
every CSV produced and surfaces a per-schema breakdown plus a flat
sample of rows to the caller.

Pattern: ``-f`` file or ``-d`` dir, ``--csv <outdir>``, ``--maps
<dir>`` to point at the SQL maps directory (defaults to the bundled
``Maps/`` next to the DLL). M6.4 graceful skip on missing dotnet,
DLL, or maps dir.
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

DEFAULT_DLL = "/opt/ezt/net9/SQLECmd/SQLECmd.dll"
DEFAULT_MAPS_DIR = "/opt/ezt/net9/SQLECmd/Maps"
DEFAULT_DOTNET = "dotnet"


def _resolve_dll() -> str:
    return os.environ.get("AGENTROPIX_SQLECMD_DLL", DEFAULT_DLL)


def _resolve_dotnet() -> str:
    return os.environ.get("AGENTROPIX_DOTNET_TOOL", DEFAULT_DOTNET)


def _resolve_maps_dir() -> str:
    return os.environ.get("AGENTROPIX_SQLECMD_MAPS_DIR", DEFAULT_MAPS_DIR)


class SQLECmdSchemaSummary(BaseModel):
    """Per-schema row tally for one CSV produced by SQLECmd."""

    schema_name: str = ""  # e.g. "Chrome_DownloadList"
    csv_file: str = ""     # filename written by SQLECmd
    row_count: int = 0


class SQLECmdRow(BaseModel):
    """One sampled row from any SQLECmd CSV.

    Generic shape: ``schema`` identifies which map produced the row;
    ``data`` holds the row's columns as a flat dict so plugin-specific
    fields flow through verbatim (caller correlates by ``schema``).
    """

    schema_name: str = ""
    data: dict[str, str] = Field(default_factory=dict)


class SQLECmdReport(BaseModel):
    """Parsed SQLECmd output (aggregated across produced CSVs)."""

    target: str
    target_mode: str = ""  # "file" or "directory"
    maps_dir: str = ""
    schemas_produced: int = 0
    total_row_count: int = 0
    truncated: bool = False
    schemas: list[SQLECmdSchemaSummary] = Field(default_factory=list)
    sampled_rows: list[SQLECmdRow] = Field(default_factory=list)
    tool: str = "sqlecmd"
    raw_stderr: str = ""
    raw_csv_sha256: str = ""  # roll-up across produced CSVs
    tool_available: bool = True
    skip_reason: str = ""


def _parse_one_csv(content: str, schema_name: str) -> tuple[int, list[SQLECmdRow]]:
    """Parse a single SQLECmd-produced CSV.

    Returns ``(row_count, rows_as_typed)``. The full row list flows
    verbatim — caller decides what to keep (we sample at the wrapper
    level to bound memory under busy databases).
    """
    if not content.strip():
        return 0, []
    content = content.lstrip("﻿")
    reader = csv.DictReader(io.StringIO(content))
    rows: list[SQLECmdRow] = []
    for row in reader:
        norm = {(k or "").strip(): (v or "").strip() for k, v in row.items() if k}
        if not norm:
            continue
        rows.append(SQLECmdRow(schema_name=schema_name, data=norm))
    return len(rows), rows


async def get_sqlecmd(
    target: str | Path,
    *,
    hunt: bool = False,
    no_blob: bool = True,
    sample_per_schema: int | None = None,
    timeout: float | None = None,
) -> SQLECmdReport:
    """Parse SQLite databases against EZ Tools SQL maps via SQLECmd.

    Args:
        target: Path to a single SQLite file OR a directory of SQLite
            files (recursive). Auto-detected.
        hunt: When ``True`` and ``target`` is a directory, pass
            ``--hunt`` so SQLECmd uses SQLite-header sniffing instead
            of filename matching (useful when DBs have non-standard
            extensions). Ignored in file mode.
        no_blob: When ``True`` (default), pass ``--noblob`` so blob
            payloads are dropped from CSV output. Disable to capture
            attachment-style columns at the cost of much larger CSVs.
        sample_per_schema: Maximum rows kept per produced CSV in
            ``sampled_rows``. ``None`` reads
            ``AGENTROPIX_SQLECMD_SAMPLE_PER_SCHEMA`` (default 100).
        timeout: Subprocess timeout (s). ``None`` reads
            ``AGENTROPIX_SQLECMD_TIMEOUT`` (default 600s, floor 5,
            ceiling 3600).

    Raises:
        FileNotFoundError: target path missing.
        TimeoutError: SQLECmd exceeded timeout.
        RuntimeError: SQLECmd returned non-zero with no CSVs produced.

    Graceful skip: missing dotnet, DLL, or maps dir → ``tool_available=False``.
    """
    target_path = Path(target)
    if not target_path.exists():
        raise FileNotFoundError(f"SQLECmd target not found: {target_path}")

    is_dir = target_path.is_dir()
    target_mode = "directory" if is_dir else "file"

    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_SQLECMD_TIMEOUT", 600.0, floor=5.0, ceiling=3600.0
        )
    if sample_per_schema is None:
        sample_per_schema = get_int(
            "AGENTROPIX_SQLECMD_SAMPLE_PER_SCHEMA", 100, floor=1, ceiling=100_000
        )

    dotnet_name = _resolve_dotnet()
    dotnet_bin = shutil.which(dotnet_name)
    if not dotnet_bin:
        reason = (
            f"{dotnet_name} not found on PATH; "
            "install dotnet-runtime-9.0 or set AGENTROPIX_DOTNET_TOOL"
        )
        logger.info("SQLECmd skipped — %s", reason)
        return SQLECmdReport(
            target=str(target_path),
            target_mode=target_mode,
            tool_available=False,
            skip_reason=reason,
        )

    dll_path = Path(_resolve_dll())
    if not dll_path.is_file():
        reason = (
            f"SQLECmd DLL not found at {dll_path}; "
            "install via the EZ Tools net9 zip or set AGENTROPIX_SQLECMD_DLL"
        )
        logger.info("SQLECmd skipped — %s", reason)
        return SQLECmdReport(
            target=str(target_path),
            target_mode=target_mode,
            tool_available=False,
            skip_reason=reason,
        )

    maps_dir = Path(_resolve_maps_dir())
    if not maps_dir.is_dir():
        reason = (
            f"SQLECmd Maps directory not found at {maps_dir}; "
            "install via the EZ Tools net9 zip or set "
            "AGENTROPIX_SQLECMD_MAPS_DIR"
        )
        logger.info("SQLECmd skipped — %s", reason)
        return SQLECmdReport(
            target=str(target_path),
            target_mode=target_mode,
            maps_dir=str(maps_dir),
            tool_available=False,
            skip_reason=reason,
        )

    with tempfile.TemporaryDirectory(prefix="agentropix-sqlecmd-") as tmpdir:
        input_flag = ["-d", str(target_path)] if is_dir else ["-f", str(target_path)]
        cmd = [
            dotnet_bin,
            str(dll_path),
            *input_flag,
            "--csv",
            tmpdir,
            "--maps",
            str(maps_dir),
        ]
        if no_blob:
            cmd.append("--noblob")
        if is_dir and hunt:
            cmd.append("--hunt")

        logger.info("Running: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr_bytes = await run_with_memory_limit(proc, timeout, "sqlecmd")
        except TimeoutError:
            raise TimeoutError(f"SQLECmd timed out after {timeout}s") from None

        stderr = stderr_bytes.decode(errors="replace")

        # SQLECmd writes one CSV per detected schema. Walk the tmpdir
        # recursively (some maps use sub-directories per app).
        produced_csvs: list[Path] = sorted(
            p for p in Path(tmpdir).rglob("*.csv") if p.is_file()
        )

        if proc.returncode != 0 and not produced_csvs:
            raise RuntimeError(
                f"SQLECmd failed (rc={proc.returncode}): {stderr[:500]}"
            )

        schemas: list[SQLECmdSchemaSummary] = []
        sampled_rows: list[SQLECmdRow] = []
        total_rows = 0
        roll_up = hashlib.sha256()

        for csv_path in produced_csvs:
            schema_name = csv_path.stem
            content_bytes = csv_path.read_bytes()
            roll_up.update(content_bytes)
            content = content_bytes.decode(errors="replace")
            row_count, rows = _parse_one_csv(content, schema_name=schema_name)
            schemas.append(
                SQLECmdSchemaSummary(
                    schema_name=schema_name,
                    csv_file=csv_path.name,
                    row_count=row_count,
                )
            )
            total_rows += row_count
            sampled_rows.extend(rows[:sample_per_schema])

        return SQLECmdReport(
            target=str(target_path),
            target_mode=target_mode,
            maps_dir=str(maps_dir),
            schemas_produced=len(schemas),
            total_row_count=total_rows,
            truncated=any(s.row_count > sample_per_schema for s in schemas),
            schemas=schemas,
            sampled_rows=sampled_rows,
            raw_stderr=stderr[:1000] if stderr else "",
            raw_csv_sha256=roll_up.hexdigest() if produced_csvs else "",
        )
