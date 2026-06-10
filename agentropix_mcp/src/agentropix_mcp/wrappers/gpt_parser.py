"""GPT (GUID Partition Table) parser wrapper — W-170.

Surfaces disk GUID and per-partition GUID fields that ``mmls`` omits:
Type GUID, Unique GUID, partition name (UTF-16LE in EFI namespace), and
attribute flags. Works on both raw disk images (.dd / .img) and EWF/E01
containers (mounted transparently via ewfmount).

MCP tool: ``parse_gpt``

Tunable:
* ``AGENTROPIX_GPT_TIMEOUT``  (float, default 30.0, [5.0, 300.0])
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path

from agentropix_mcp._env import get_float

logger = logging.getLogger(__name__)

TOOL_NAME = "sgdisk"

_SGDISK_PATH = shutil.which("sgdisk") or "/sbin/sgdisk"
_EWFMOUNT_PATH = shutil.which("ewfmount") or "/usr/bin/ewfmount"

_DEFAULT_TIMEOUT = 30.0
_EWF_EXTENSIONS: frozenset[str] = frozenset({".e01", ".ex01", ".lx01"})

# --- output parsers -----------------------------------------------------------

# Header section regexes (from `sgdisk --print`)
_RE_SECTOR_COUNT = re.compile(r"Disk\s+\S+:\s+(\d+)\s+sectors")
_RE_SECTOR_SIZE = re.compile(r"Sector size \(logical\):\s+(\d+)\s+bytes")
_RE_DISK_GUID = re.compile(
    r"Disk identifier \(GUID\):\s+([0-9A-Fa-f-]{36})"
)
_RE_TABLE_ENTRIES = re.compile(
    r"Partition table holds up to (\d+) entries"
)
_RE_FIRST_USABLE = re.compile(r"First usable sector is (\d+)")
_RE_LAST_USABLE = re.compile(r"last usable sector is (\d+)")

# Partition table row: "  1   2048   10239   4.0 MiB   EF00  EFI System Partition"
_RE_PART_ROW = re.compile(
    r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+\s+\S+)\s+([0-9A-Fa-f]{4})\s*(.*?)\s*$"
)

# Per-partition info: from `sgdisk --info=N`
_RE_TYPE_GUID = re.compile(
    r"Partition GUID code:\s+([0-9A-Fa-f-]{36})\s+\(([^)]+)\)"
)
_RE_UNIQUE_GUID = re.compile(
    r"Partition unique GUID:\s+([0-9A-Fa-f-]{36})"
)
_RE_ATTR_FLAGS = re.compile(r"Attribute flags:\s+([0-9A-Fa-f]+)")
_RE_PART_NAME_INFO = re.compile(r"Partition name:\s+'([^']*)'")


def _parse_print_output(text: str) -> dict:
    """Parse `sgdisk --print` output into a header dict + partition list."""
    header: dict = {}
    partitions: list[dict] = []

    for line in text.splitlines():
        if m := _RE_SECTOR_COUNT.search(line):
            header["total_sectors"] = int(m.group(1))
        if m := _RE_SECTOR_SIZE.search(line):
            header["sector_size_bytes"] = int(m.group(1))
        if m := _RE_DISK_GUID.search(line):
            header["disk_guid"] = m.group(1).upper()
        if m := _RE_TABLE_ENTRIES.search(line):
            header["table_max_entries"] = int(m.group(1))
        if m := _RE_FIRST_USABLE.search(line):
            header["first_usable_lba"] = int(m.group(1))
        if m := _RE_LAST_USABLE.search(line):
            header["last_usable_lba"] = int(m.group(1))
        if m := _RE_PART_ROW.match(line):
            partitions.append({
                "index": int(m.group(1)),
                "first_lba": int(m.group(2)),
                "last_lba": int(m.group(3)),
                "size_human": m.group(4).strip(),
                "type_code": m.group(5).upper(),
                "name": m.group(6).strip(),
                # filled in by --info pass
                "type_guid": "",
                "unique_guid": "",
                "attribute_flags": "",
            })

    return {"header": header, "partitions": partitions}


def _parse_info_output(text: str, entry: dict) -> None:
    """Merge `sgdisk --info=N` fields into an existing partition entry dict."""
    for line in text.splitlines():
        if m := _RE_TYPE_GUID.search(line):
            entry["type_guid"] = m.group(1).upper()
            entry["type_guid_description"] = m.group(2).strip()
        if m := _RE_UNIQUE_GUID.search(line):
            entry["unique_guid"] = m.group(1).upper()
        if m := _RE_ATTR_FLAGS.search(line):
            entry["attribute_flags"] = m.group(1)
        if m := _RE_PART_NAME_INFO.search(line):
            # --info gives the authoritative UTF-16LE-decoded name
            entry["name"] = m.group(1)


async def _run(cmd: list[str], timeout: float) -> tuple[str, str, int]:
    """Run a command, return (stdout, stderr, returncode)."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return "", f"timeout after {timeout}s", -1
    return (
        stdout_b.decode("utf-8", errors="replace"),
        stderr_b.decode("utf-8", errors="replace"),
        proc.returncode or 0,
    )


async def _sgdisk_on_device(
    device_path: str, timeout: float
) -> dict:
    """Run sgdisk --print + per-partition --info on a raw device path."""
    stdout, stderr, rc = await _run(
        [_SGDISK_PATH, "--print", device_path], timeout
    )
    if rc != 0 and not stdout:
        return {
            "error": f"sgdisk --print failed (rc={rc}): {stderr[:300]}",
            "partitions": [],
            "header": {},
        }

    result = _parse_print_output(stdout)
    result["raw_stdout_sha256"] = hashlib.sha256(
        stdout.encode("utf-8", errors="replace")
    ).hexdigest()

    for part in result["partitions"]:
        info_out, info_err, info_rc = await _run(
            [_SGDISK_PATH, f"--info={part['index']}", device_path],
            timeout,
        )
        if info_rc == 0:
            _parse_info_output(info_out, part)
        else:
            logger.debug(
                "sgdisk --info=%d failed (rc=%d): %s",
                part["index"], info_rc, info_err[:200],
            )

    return result


async def parse_gpt(image_path: str) -> dict:
    """Parse the GPT partition table of a disk image.

    Accepts raw disk images (.dd, .img, .raw) and EWF/E01 containers.
    EWF images are mounted transparently via ewfmount; the mountpoint is
    cleaned up before returning.

    Returns a dict with keys:
      ``header``   — disk_guid, total_sectors, sector_size_bytes,
                     table_max_entries, first_usable_lba, last_usable_lba
      ``partitions`` — list of per-partition dicts:
                     index, first_lba, last_lba, size_human, type_code,
                     type_guid, type_guid_description, unique_guid,
                     attribute_flags, name
      ``image_path``, ``is_ewf``, ``raw_stdout_sha256``

    On error returns ``{"error": "...", "partitions": [], "header": {}}``.
    """
    timeout = get_float(
        "AGENTROPIX_GPT_TIMEOUT", _DEFAULT_TIMEOUT, floor=5.0, ceiling=300.0
    )
    path = Path(image_path)
    is_ewf = path.suffix.lower() in _EWF_EXTENSIONS

    base_result: dict = {"image_path": image_path, "is_ewf": is_ewf}

    if is_ewf:
        if not shutil.which(_EWFMOUNT_PATH) and not os.path.exists(_EWFMOUNT_PATH):
            return {
                **base_result,
                "error": f"ewfmount not found at {_EWFMOUNT_PATH}",
                "partitions": [],
                "header": {},
            }
        mountdir = tempfile.mkdtemp(prefix="agentropix_gpt_ewf_")
        try:
            _, mount_err, mount_rc = await _run(
                [_EWFMOUNT_PATH, image_path, mountdir], timeout=30.0
            )
            if mount_rc != 0:
                return {
                    **base_result,
                    "error": f"ewfmount failed (rc={mount_rc}): {mount_err[:300]}",
                    "partitions": [],
                    "header": {},
                }
            device = os.path.join(mountdir, "ewf1")
            result = await _sgdisk_on_device(device, timeout)
        finally:
            # Always unmount + clean up, even on exception
            try:
                umount_cmd = shutil.which("fusermount") or "fusermount"
                proc = await asyncio.create_subprocess_exec(
                    umount_cmd, "-u", mountdir,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=10.0)
            except Exception as exc:
                logger.warning("parse_gpt: ewfmount cleanup error: %s", exc)
            try:
                os.rmdir(mountdir)
            except OSError:
                pass
    else:
        result = await _sgdisk_on_device(image_path, timeout)

    return {**base_result, **result}
