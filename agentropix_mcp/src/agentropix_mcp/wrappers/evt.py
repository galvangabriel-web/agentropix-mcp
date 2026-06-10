"""Legacy Windows EventLog (``.evt``) parser — NIST1 RUN1 ISSUE-008 (N8b).

Windows XP / 2003 store event logs as binary ``.evt`` (NOT the XML ``.evtx``
introduced in Vista). No agentropix wrapper covered ``.evt`` — ``get_evtx``
explicitly N/As on XP. This wrapper drives libevt's ``evtexport`` (the same
libyal toolchain family as ``esedbexport`` used by ``srum_extract``) to export
the allocated event records and normalises them into structured rows.

``evtexport`` writes one record block per event to stdout, e.g.::

    Event number      : 1
    Creation time     : Aug 27, 2004 ...
    Written time      : Aug 27, 2004 ...
    Event type        : Information event (0x0004)
    Event identifier  : 0x40010004
    Source name       : Application
    Computer name     : MR-EVIL
    Strings:
            mrevilrulez

Blocks are separated by blank lines. ``evtexport`` is fail-soft: it prints a
``Unable to open`` / ``unable to read file header`` diagnostic and still exits
rc=0 on a bad input, so the wrapper detects failure from the output content
(same hazard class as vol3 in the keystone work), not the return code.
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

DEFAULT_TOOL_NAME = "evtexport"

# evtexport fail-soft markers: printed (rc still 0) when the source isn't a
# valid .evt — treat as a hard failure rather than "0 events".
_FAILURE_MARKERS: tuple[str, ...] = (
    "unable to open",
    "unable to read file header",
    "export_handle_open_input",
)

# Each record block starts with an "Event number" line.
_EVENT_NUMBER = re.compile(r"^Event number\s*:\s*(\d+)", re.MULTILINE)
# "Key : value" lines inside a block (key may contain spaces).
_KV = re.compile(r"^([A-Za-z][\w ]*?)\s*:\s*(.*)$")


def _resolve_tool() -> str:
    return os.environ.get("AGENTROPIX_EVTEXPORT_TOOL", DEFAULT_TOOL_NAME)


class EvtEventRow(BaseModel):
    """One exported ``.evt`` record (normalised key fields + strings)."""

    event_number: int = 0
    written_time: str = ""
    creation_time: str = ""
    event_type: str = ""
    event_identifier: str = ""
    source_name: str = ""
    computer_name: str = ""
    strings: list[str] = Field(default_factory=list)


class EvtReport(BaseModel):
    """Parsed ``evtexport`` output for a single ``.evt`` file."""

    source: str
    event_count: int = 0
    events: list[EvtEventRow] = Field(default_factory=list)
    tool: str = "libevt.evtexport"
    truncated: bool = False
    # NIST1 RUN2 ISSUE-002 parity: omit the events list to bound the payload.
    summary_only: bool = False
    raw_stderr: str = ""
    raw_stdout_sha256: str = ""


def _parse_evtexport(stdout: str, *, max_events: int) -> tuple[list[EvtEventRow], bool]:
    """Split evtexport stdout into EvtEventRow blocks (capped at max_events)."""
    rows: list[EvtEventRow] = []
    truncated = False
    starts = [m.start() for m in _EVENT_NUMBER.finditer(stdout)]
    for idx, start in enumerate(starts):
        if len(rows) >= max_events:
            truncated = True
            break
        end = starts[idx + 1] if idx + 1 < len(starts) else len(stdout)
        block = stdout[start:end]
        fields: dict[str, str] = {}
        strings: list[str] = []
        in_strings = False
        for line in block.splitlines():
            if line.strip().rstrip(":").lower() == "strings":
                in_strings = True
                continue
            if in_strings:
                if line.strip():
                    strings.append(line.strip())
                continue
            m = _KV.match(line)
            if m:
                fields[m.group(1).strip().lower()] = m.group(2).strip()
        rows.append(
            EvtEventRow(
                event_number=int(fields.get("event number", "0") or 0),
                written_time=fields.get("written time", ""),
                creation_time=fields.get("creation time", ""),
                event_type=fields.get("event type", ""),
                event_identifier=fields.get("event identifier", ""),
                source_name=fields.get("source name", ""),
                computer_name=fields.get("computer name", ""),
                strings=strings,
            )
        )
    return rows, truncated


async def get_evt(
    source: str | Path,
    *,
    mode: str = "items",
    max_events: int | None = None,
    summary_only: bool = False,
    timeout: float | None = None,
) -> EvtReport:
    """Parse a legacy Windows ``.evt`` EventLog via libevt ``evtexport``.

    Args:
        source: Path to the ``.evt`` file (e.g. extracted
            ``WINDOWS/system32/config/SecEvent.evt``).
        mode: evtexport ``-m`` mode — ``items`` (allocated, default),
            ``recovered``, or ``all``.
        max_events: Cap on returned event rows (default
            ``AGENTROPIX_EVT_MAX_EVENTS``=5000; floor 1, ceiling 100000).
        summary_only: Return ``event_count`` but omit the events list to
            bound the payload (NIST1 RUN2 ISSUE-002 parity).
        timeout: Subprocess timeout (s). Default
            ``AGENTROPIX_EVT_TIMEOUT``=300.

    Returns:
        EvtReport with normalised event rows.

    Raises:
        FileNotFoundError: source missing or evtexport not on PATH.
        TimeoutError: evtexport exceeds timeout.
        RuntimeError: evtexport could not parse the source (fail-soft markers).
    """
    src = Path(source)
    if not src.exists():
        raise FileNotFoundError(f".evt source not found: {src}")

    if mode not in ("items", "recovered", "all"):
        raise ValueError(f"invalid mode {mode!r}; expected items|recovered|all")

    if max_events is None:
        max_events = get_int("AGENTROPIX_EVT_MAX_EVENTS", 5000, floor=1, ceiling=100000)
    if timeout is None:
        timeout = get_float("AGENTROPIX_EVT_TIMEOUT", 300.0, floor=5.0, ceiling=3600.0)

    tool = shutil.which(_resolve_tool())
    if not tool:
        raise FileNotFoundError(f"{_resolve_tool()} not found on PATH — install libevt-utils")

    cmd = [tool, "-m", mode, str(src)]
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
        raise TimeoutError(f"evtexport timed out after {timeout}s") from None

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")

    # evtexport is fail-soft (rc=0 on bad input) — detect failure from content.
    blob = (stdout + "\n" + stderr).lower()
    if any(marker in blob for marker in _FAILURE_MARKERS):
        raise RuntimeError(
            f"evtexport could not parse {src.name}: not a valid .evt EventLog "
            f"(libevt: {stderr.strip()[:200] or stdout.strip()[:200]})"
        )

    rows, truncated = _parse_evtexport(stdout, max_events=max_events)
    return EvtReport(
        source=str(src),
        event_count=len(rows),
        events=[] if summary_only else rows,
        truncated=truncated,
        summary_only=summary_only,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
    )
