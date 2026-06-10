"""Scheduled-task (T1053.005) extractor — reads Windows/System32/Tasks XML.

M6.11 W-068. Bridges the structural gap that left T1053.005 at cohit=1
across M6.7 → M6.10: plaso/winevtx does not surface schtasks events on
the DC E01, and the enrichment path for ``scheduled`` requires an
upstream finding containing ``schtasks`` that never arrives. Parsing
the Task XML files directly produces the keyword surface the GT
scorer expects (``schtasks`` + ``scheduled`` co-occurring in one
finding → cohit≥2 → HIT).

The wrapper owns two narrow ops:

* ``list_task_paths`` — ``ifind`` + ``fls -rp`` to enumerate regular
  files under ``/Windows/System32/Tasks`` in an E01/raw image.
* ``parse_task_xml`` — stdlib ``xml.etree`` parse of a single Task
  Scheduler XML document into a ``TaskSpec``.

Composition (extract → parse → Finding) is done by the ArtifactAgent
so the MCP surface stays SRP-clean.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

from pydantic import BaseModel, Field

from agentropix_mcp._env import get_float

logger = logging.getLogger(__name__)

# Task Scheduler 2.0 XML namespace. Tasks authored by schtasks.exe,
# Group Policy, or the MMC snap-in all use this NS. A handful of very
# old / broken tasks ship with no namespace at all; the parser tries
# both forms so those don't silently miss.
_TASK_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"

_TASKS_ROOT = "/Windows/System32/Tasks"

# fls -rp output line format:
#   r/r 1234-128-4: <name-or-path>
#   +* r/r 1234-128-4: <deleted>
_FLS_PATH_RE = re.compile(
    r"^(?:\+*\s*)?([rd])/([rd])\s+(\*?)\s*(\S+?):\s+(.+)$"
)


class TaskSpec(BaseModel):
    """Normalised Windows Scheduled Task (subset relevant to DFIR)."""

    container_path: str = ""
    name: str = ""
    author: str = ""
    command: str = ""
    arguments: str = ""
    triggers: list[str] = Field(default_factory=list)
    run_level: str = ""
    user_id: str = ""


def _decode_xml_bytes(data: bytes) -> str:
    """Decode raw Task XML bytes with BOM-aware fallback.

    Windows tasks are typically UTF-16 LE with BOM; schtasks-written
    variants occasionally ship as UTF-8-BOM or plain UTF-8.
    """
    if data[:2] == b"\xff\xfe":
        return data.decode("utf-16-le", errors="replace")
    if data[:2] == b"\xfe\xff":
        return data.decode("utf-16-be", errors="replace")
    if data[:3] == b"\xef\xbb\xbf":
        return data.decode("utf-8-sig", errors="replace")
    return data.decode("utf-8", errors="replace")


def _first_nonempty(*values: str | None) -> str:
    for v in values:
        if v:
            s = str(v).strip()
            if s:
                return s
    return ""


def _findtext_ns(parent: ET.Element, local_name: str) -> str:
    """findtext that tries namespaced form first, then bare."""
    return _first_nonempty(
        parent.findtext(f"{_TASK_NS}{local_name}"),
        parent.findtext(local_name),
    )


def _find_ns(parent: ET.Element, local_name: str) -> ET.Element | None:
    el = parent.find(f"{_TASK_NS}{local_name}")
    if el is not None:
        return el
    return parent.find(local_name)


def parse_task_xml(data: bytes | str) -> TaskSpec | None:
    """Parse a Windows Task XML document into a ``TaskSpec``.

    Returns ``None`` on malformed / unrecognised XML. Never raises —
    scheduled-task discovery must never crash the swarm on a corrupt
    or truncated Tasks entry.
    """
    try:
        text = _decode_xml_bytes(data) if isinstance(data, bytes) else data
        root = ET.fromstring(text)
    except (ET.ParseError, UnicodeDecodeError, ValueError) as exc:
        logger.debug("parse_task_xml failed: %s", exc)
        return None

    spec = TaskSpec(container_path="")

    reg = _find_ns(root, "RegistrationInfo")
    if reg is not None:
        spec.author = _findtext_ns(reg, "Author")
        uri = _findtext_ns(reg, "URI")
        if uri:
            last = uri.rstrip("\\/").replace("/", "\\").split("\\")[-1]
            spec.name = last

    actions = _find_ns(root, "Actions")
    if actions is not None:
        exec_el = _find_ns(actions, "Exec")
        if exec_el is not None:
            spec.command = _findtext_ns(exec_el, "Command")
            spec.arguments = _findtext_ns(exec_el, "Arguments")

    triggers = _find_ns(root, "Triggers")
    if triggers is not None:
        for child in triggers:
            tag = child.tag
            if tag.startswith(_TASK_NS):
                tag = tag[len(_TASK_NS):]
            spec.triggers.append(tag)

    principals = _find_ns(root, "Principals")
    if principals is not None:
        principal = _find_ns(principals, "Principal")
        if principal is not None:
            spec.run_level = _findtext_ns(principal, "RunLevel")
            spec.user_id = _findtext_ns(principal, "UserId")

    return spec


async def _run_ifind(
    image: Path,
    in_path: str,
    *,
    offset: int,
    fstype: str | None,
    timeout: float,
) -> str:
    tool = os.environ.get("AGENTROPIX_IFIND_TOOL", "ifind")
    binary = shutil.which(tool)
    if not binary:
        raise FileNotFoundError(f"{tool} not found on PATH — install sleuthkit")
    cmd = [binary]
    if offset:
        cmd.extend(["-o", str(offset)])
    if fstype:
        cmd.extend(["-f", fstype])
    cmd.extend(["-n", in_path, str(image)])
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise TimeoutError(f"ifind timed out on {in_path}") from None
    for line in out_bytes.decode(errors="replace").splitlines():
        cand = line.strip()
        if cand and cand[0].isdigit():
            return cand.split()[0]
    return ""


async def _run_fls_rp(
    image: Path,
    inode: str,
    *,
    offset: int,
    fstype: str | None,
    timeout: float,
) -> list[str]:
    tool = os.environ.get("AGENTROPIX_FLS_TOOL", "fls")
    binary = shutil.which(tool)
    if not binary:
        raise FileNotFoundError(f"{tool} not found on PATH — install sleuthkit")
    cmd = [binary, "-rp"]
    if offset:
        cmd.extend(["-o", str(offset)])
    if fstype:
        cmd.extend(["-f", fstype])
    cmd.extend([str(image), inode])
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise TimeoutError(f"fls timed out on inode {inode}") from None

    files: list[str] = []
    for line in out_bytes.decode(errors="replace").splitlines():
        m = _FLS_PATH_RE.match(line)
        if not m:
            continue
        _meta, kind, deleted, _inode, rest = m.groups()
        if kind != "r" or deleted == "*":
            continue
        name = rest.split("\t")[0].strip()
        if name:
            files.append(name)
    return files


async def list_task_paths(
    image: str | Path,
    *,
    offset: int = 0,
    fstype: str | None = None,
    timeout: float | None = None,
) -> list[str]:
    """Enumerate Task XML files under Windows/System32/Tasks.

    Returns a list of in-container paths (POSIX, leading slash,
    normalised) suitable for feeding directly to ``mcp_extract_files``.
    Returns ``[]`` if the Tasks directory is absent / unresolvable.
    Never raises on an empty directory — only on missing ``ifind`` /
    ``fls`` binaries or subprocess timeout.
    """
    image_path = Path(image)
    if not image_path.exists():
        raise FileNotFoundError(f"Image not found: {image_path}")
    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_TASKS_LIST_TIMEOUT",
            180.0,
            floor=5.0,
            ceiling=3600.0,
        )

    inode = await _run_ifind(
        image_path,
        _TASKS_ROOT,
        offset=offset,
        fstype=fstype,
        timeout=timeout,
    )
    if not inode:
        return []

    relative = await _run_fls_rp(
        image_path,
        inode,
        offset=offset,
        fstype=fstype,
        timeout=timeout,
    )
    out: list[str] = []
    for rel in relative:
        rel = rel.lstrip("/")
        if not rel:
            continue
        out.append(f"{_TASKS_ROOT}/{rel}")
    return out


__all__ = [
    "TaskSpec",
    "list_task_paths",
    "parse_task_xml",
]
