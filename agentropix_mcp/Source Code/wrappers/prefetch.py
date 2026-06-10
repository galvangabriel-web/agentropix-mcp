"""Windows Prefetch parser wrapper — execution-evidence extraction.

Targets the SANS SIFT-installed `pf` parser (override with the
`AGENTROPIX_PREFETCH_TOOL` env var; some distros ship `prefetch` or
`prefetch_parser` instead). The parser is given the path to a
`Prefetch` directory (or a single `.pf` file) and emits per-executable
stanzas with run count, hash, and run-time history.

Output normalization is conservative: each `Executable:` (or
`Filename:`) header opens a new entry; lines until the next header are
scanned for run count, hash, and "Run time"/"Last run"/"Earliest run"
fields. Lines that don't match are preserved on the entry's `raw`
field so downstream agents can re-parse without losing fidelity.
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

from agentropix_mcp._env import get_float

logger = logging.getLogger(__name__)

DEFAULT_TOOL_NAME = "pf"


def _resolve_tool() -> str:
    """Resolve the prefetch parser binary, honoring AGENTROPIX_PREFETCH_TOOL."""
    return os.environ.get("AGENTROPIX_PREFETCH_TOOL", DEFAULT_TOOL_NAME)


class PrefetchEntry(BaseModel):
    """One executable's prefetch record."""

    executable: str
    hash: str = ""
    run_count: int = 0
    last_run: str = ""
    earliest_run: str = ""
    run_times: list[str] = Field(default_factory=list)
    volumes: list[str] = Field(default_factory=list)
    # SIFT-W-272: sccainfo emits volume serial + creation time alongside the
    # device path, and a per-run loaded-file (DLL/image) list -- all dropped
    # by the original wrapper. Default-empty so non-sccainfo dialects are
    # unaffected.
    volume_serial: str = ""
    volume_creation_time: str = ""
    loaded_files: list[str] = Field(default_factory=list)
    raw: str = ""


class PrefetchReport(BaseModel):
    """Parsed output of a Windows Prefetch parser run."""

    image_path: str
    entry_count: int = 0
    entries: list[PrefetchEntry] = Field(default_factory=list)
    tool: str = "prefetch.pf"
    raw_stderr: str = ""
    # SIFT-W-082: SHA-256 of the parser's raw stdout bytes.  In the
    # multi-file directory walk the bytes hashed are the concatenation
    # of per-file stdout chunks, joined with ``\n``, in the same order
    # the parser consumed them — i.e. the exact byte stream the dialect
    # detector and stanza splitter saw.
    raw_stdout_sha256: str = ""


_HEADER = re.compile(
    r"^(?:Executable|Filename|Source filename)\s*:\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)
_HASH = re.compile(r"^Hash\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_RUN_COUNT = re.compile(r"^Run\s+count\s*:\s*(\d+)", re.IGNORECASE | re.MULTILINE)
_LAST_RUN = re.compile(r"^Last\s+run(?:\s+time)?\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_EARLIEST_RUN = re.compile(r"^Earliest\s+run(?:\s+time)?\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_RUN_TIME = re.compile(r"^Run\s+time\s*\d*\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_VOLUME = re.compile(r"^Volume(?:\s+\d+)?\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


def _parse_prefetch_output(output: str) -> list[PrefetchEntry]:
    """Split prefetch parser output into per-executable PrefetchEntry stanzas."""
    if not output.strip():
        return []
    headers = list(_HEADER.finditer(output))
    entries: list[PrefetchEntry] = []
    for idx, match in enumerate(headers):
        executable = match.group(1).strip()
        start = match.start()
        end = headers[idx + 1].start() if idx + 1 < len(headers) else len(output)
        body = output[start:end]
        hash_m = _HASH.search(body)
        rc_m = _RUN_COUNT.search(body)
        last_m = _LAST_RUN.search(body)
        early_m = _EARLIEST_RUN.search(body)
        run_count = int(rc_m.group(1)) if rc_m else 0
        run_times = [m.group(1).strip() for m in _RUN_TIME.finditer(body)]
        volumes = [m.group(1).strip() for m in _VOLUME.finditer(body)]
        entries.append(
            PrefetchEntry(
                executable=executable,
                hash=hash_m.group(1).strip() if hash_m else "",
                run_count=run_count,
                last_run=last_m.group(1).strip() if last_m else "",
                earliest_run=early_m.group(1).strip() if early_m else "",
                run_times=run_times,
                volumes=volumes,
                raw=body[:2000],
            )
        )
    return entries


# --- libscca-tools / sccainfo support (SIFT-W-079) -----------------------
#
# sccainfo (from the libscca-tools deb) emits a single-file dump with a
# fixed banner and tab-indented field labels that don't match the generic
# pf-style parser above. Lines look like:
#
#   <TAB>Executable filename<TABS>: Op-EXPLORER.EXE-A80E4F97
#   <TAB>Prefetch hash<TABS>: 0x000000f5
#   <TAB>Run count<TABS>: 3
#   <TAB>Last run time: 1<TABS>: Sep 14, 2019 01:21:55.155335000 UTC
#
# It also only accepts a SINGLE .pf file per invocation (not a directory),
# so when the operator points the wrapper at a Prefetch directory we have
# to iterate ourselves and concatenate stanzas with the sccainfo banner
# as the natural separator.

_SCCAINFO_BANNER = "Windows Prefetch File (PF) information:"
_SCCAINFO_EXEC = re.compile(r"^\s*Executable filename\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_SCCAINFO_HASH = re.compile(r"^\s*Prefetch hash\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_SCCAINFO_RUN_COUNT = re.compile(r"^\s*Run count\s*:\s*(\d+)", re.IGNORECASE | re.MULTILINE)
_SCCAINFO_LAST_RUN = re.compile(
    r"^\s*Last run time:\s*\d+\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE
)
_SCCAINFO_VOLUME_DEVICE = re.compile(r"^\s*Device path\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
# SIFT-W-272: volume serial + creation time (emitted under "Volume: N
# information:" alongside Device path), and the per-run loaded-file list
# ("Filename: <N> : <path>" under "Filenames:").
_SCCAINFO_VOLUME_SERIAL = re.compile(r"^\s*Serial number\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_SCCAINFO_VOLUME_CREATION = re.compile(
    r"^\s*Creation time\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE
)
_SCCAINFO_FILENAME = re.compile(r"^\s*Filename:\s*\d+\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


def _looks_like_sccainfo(output: str) -> bool:
    return _SCCAINFO_BANNER in output[:1000]


def _parse_sccainfo_output(output: str) -> list[PrefetchEntry]:
    """Parse one or more sccainfo dumps concatenated together.

    The wrapper concatenates per-file outputs with the banner line still
    intact, so we split on the banner to recover stanzas.
    """
    if not output.strip():
        return []

    # Split into per-file stanzas. The banner appears once per .pf file.
    raw_stanzas = output.split(_SCCAINFO_BANNER)
    entries: list[PrefetchEntry] = []
    for stanza in raw_stanzas:
        if not stanza.strip():
            continue
        exe_m = _SCCAINFO_EXEC.search(stanza)
        if not exe_m:
            continue  # noise / preamble before the first banner
        hash_m = _SCCAINFO_HASH.search(stanza)
        rc_m = _SCCAINFO_RUN_COUNT.search(stanza)
        # All "Last run time: N" entries; sccainfo reports up to 8 slots
        # and emits "Not set (0)" for unused ones — drop those.
        run_times: list[str] = []
        for m in _SCCAINFO_LAST_RUN.finditer(stanza):
            v = m.group(1).strip()
            if v and "Not set" not in v:
                run_times.append(v)
        volumes = [m.group(1).strip() for m in _SCCAINFO_VOLUME_DEVICE.finditer(stanza)]
        serial_m = _SCCAINFO_VOLUME_SERIAL.search(stanza)
        creation_m = _SCCAINFO_VOLUME_CREATION.search(stanza)
        loaded_files = [m.group(1).strip() for m in _SCCAINFO_FILENAME.finditer(stanza)]
        entries.append(
            PrefetchEntry(
                executable=exe_m.group(1).strip(),
                hash=hash_m.group(1).strip() if hash_m else "",
                run_count=int(rc_m.group(1)) if rc_m else 0,
                # Slot 1 is most recent, last populated slot is earliest.
                last_run=run_times[0] if run_times else "",
                earliest_run=run_times[-1] if run_times else "",
                run_times=run_times,
                volumes=volumes,
                volume_serial=serial_m.group(1).strip() if serial_m else "",
                volume_creation_time=creation_m.group(1).strip() if creation_m else "",
                loaded_files=loaded_files,
                raw=stanza[:2000],
            )
        )
    return entries


def _tool_takes_directory(tool_name: str) -> bool:
    """sccainfo accepts a single .pf file only; other tools tend to
    walk a Prefetch directory natively. Default to True so unknown
    tools keep the legacy behaviour."""
    return Path(tool_name).name != "sccainfo"


async def get_prefetch(
    target: str | Path,
    *,
    timeout: float | None = None,
) -> PrefetchReport:
    """Run the Prefetch parser against a directory or .pf file.

    Args:
        target: Path to a Prefetch directory (e.g. ``C:/Windows/Prefetch``)
            or a single ``.pf`` file.
        timeout: Max seconds to wait for the parser.

    Returns:
        PrefetchReport with per-executable entries.

    Raises:
        FileNotFoundError: target missing or parser binary not on PATH.
        TimeoutError: parser exceeds timeout.
        RuntimeError: parser returns non-zero with empty stdout.
    """
    target_path = Path(target)
    if not target_path.exists():
        raise FileNotFoundError(f"Prefetch target not found: {target_path}")

    if timeout is None:
        timeout = get_float("AGENTROPIX_PREFETCH_TIMEOUT", 60.0, floor=5.0, ceiling=3600.0)

    tool_name = _resolve_tool()
    tool_path = shutil.which(tool_name)
    if not tool_path:
        raise FileNotFoundError(
            f"{tool_name} not found on PATH — install a Prefetch parser "
            "or set AGENTROPIX_PREFETCH_TOOL"
        )

    # Some parsers (sccainfo) only accept a single .pf file. When the
    # operator points us at a Prefetch directory and the tool can't walk
    # it natively, iterate ourselves and concatenate per-file output.
    if target_path.is_dir() and not _tool_takes_directory(tool_name):
        pf_files = sorted(target_path.glob("*.pf"))
        if not pf_files:
            return PrefetchReport(
                image_path=str(target_path),
                entry_count=0,
                entries=[],
                tool=tool_name,
                raw_stderr="",
                raw_stdout_sha256=hashlib.sha256(b"").hexdigest(),
            )
        chunks: list[str] = []
        stderr_chunks: list[str] = []
        nonzero_seen = False
        # Hash the byte-level concatenation that the parser will see
        # (chunks joined with ``\n``, same order as iteration).
        digest = hashlib.sha256()
        for idx, pf in enumerate(pf_files):
            sub_proc = await asyncio.create_subprocess_exec(
                tool_path,
                str(pf),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                sub_out, sub_err = await asyncio.wait_for(sub_proc.communicate(), timeout=timeout)
            except TimeoutError:
                sub_proc.kill()
                raise TimeoutError(f"{tool_name} timed out after {timeout}s on {pf.name}")
            if idx > 0:
                digest.update(b"\n")
            digest.update(sub_out)
            chunks.append(sub_out.decode(errors="replace"))
            if sub_err:
                stderr_chunks.append(f"{pf.name}: {sub_err.decode(errors='replace')}")
            if sub_proc.returncode not in (0, None):
                nonzero_seen = True
        stdout = "\n".join(chunks)
        stderr = "\n".join(stderr_chunks)
        raw_stdout_sha256 = digest.hexdigest()
        if nonzero_seen and not stdout.strip():
            raise RuntimeError(
                f"{tool_name} failed on every .pf in {target_path} (stderr tail: {stderr[-500:]})"
            )
    else:
        cmd = [tool_path, str(target_path)]
        logger.info("Running: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            proc.kill()
            raise TimeoutError(f"{tool_name} timed out after {timeout}s")

        stdout = stdout_bytes.decode(errors="replace")
        stderr = stderr_bytes.decode(errors="replace")
        raw_stdout_sha256 = hashlib.sha256(stdout_bytes).hexdigest()

        if proc.returncode != 0 and not stdout.strip():
            raise RuntimeError(f"{tool_name} failed (rc={proc.returncode}): {stderr[:500]}")

    # Pick parser by output content rather than tool name — keeps the
    # adapter stable if the operator ever points the env-var at a
    # different libscca-style binary.
    if _looks_like_sccainfo(stdout):
        entries = _parse_sccainfo_output(stdout)
    else:
        entries = _parse_prefetch_output(stdout)

    return PrefetchReport(
        image_path=str(target_path),
        entry_count=len(entries),
        entries=entries,
        tool=Path(tool_name).name,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=raw_stdout_sha256,
    )
