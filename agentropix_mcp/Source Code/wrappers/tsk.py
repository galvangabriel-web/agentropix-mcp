"""Sleuth Kit (TSK) wrappers — filesystem listing via fls."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import shutil
from pathlib import Path

from pydantic import BaseModel, Field

from agentropix_mcp._env import get_float, get_int

logger = logging.getLogger(__name__)

TOOL_NAME = "fls"

# Issue #10: bytes cap for inode reads. Default 50 MB matches the issue's
# "cap < 50 MB" guidance — files larger than that are skipped (returns b"")
# rather than truncated, because a partial read produces a misleading
# SHA-256 that wouldn't match VirusTotal / threat-intel pivots. Floor 1
# MB (anything smaller couldn't carry a real T1105 staged payload);
# ceiling 500 MB (caps memory pressure when the operator opts up).
_DEFAULT_TSK_MAX_READ_BYTES = 50 * 1024 * 1024


class FileEntry(BaseModel):
    """Single file/directory entry from fls output."""

    entry_type: str  # "r" (regular), "d" (directory), "l" (link), etc.
    allocated: bool = True  # False if deleted
    inode: str = ""
    name: str = ""
    full_path: str = ""
    modified_time: str = ""  # MACB: Modified
    accessed_time: str = ""  # MACB: Accessed
    size: int = 0  # File size in bytes (from fls -l output)


class FileListing(BaseModel):
    """Parsed fls (Sleuth Kit) result."""

    image_path: str
    offset: int
    entry_count: int
    entries: list[FileEntry] = Field(default_factory=list)
    tool: str = "sleuthkit.fls"
    raw_stderr: str = ""
    # SIFT-W-082: SHA-256 of fls's raw stdout bytes.
    raw_stdout_sha256: str = ""
    # NIST1 ISSUE-002: True when entries were omitted to bound the result
    # payload (summary_only). entry_count still reflects the full count.
    summary_only: bool = False


# fls -l long output format (tab-separated after inode):
#   <type>/<type> [*] <inode>:\t<name>\t<modified>\t<accessed>\t<changed>\t<created>\t<size>\t<uid>\t<gid>
# Short output format (no -l):
#   <type>/<type> [*] <inode>:\t<name>
#   or with spaces: <type>/<type> [*] <inode>:  <name>
# The header portion before the first tab (or the entire trailing string) is
# captured in group 5; tabs in that group indicate long-format extra fields.
_FLS_PATTERN = re.compile(r"^(?:\+*\s*)?([rdlvV\-])/([rdlvV\-])\s+(\*?)\s*(\S+?):\t(.+)$")


def _parse_fls_output(stdout: str, base_path: str = "/") -> list[FileEntry]:
    """Parse fls stdout into FileEntry list.

    Handles both short format (fls) and long format (fls -l) output.
    Long format has tab-separated fields after the name:
      name\\tmodified\\taccessed\\tchanged\\tcreated\\tsize\\tuid\\tgid
    """
    entries: list[FileEntry] = []
    for line in stdout.splitlines():
        line = line.rstrip("\n")
        if not line.strip():
            continue
        match = _FLS_PATTERN.match(line)
        if match:
            type_meta, type_name, deleted_marker, inode, rest = match.groups()
            # Split the remainder on tabs to handle long-listing fields
            fields = rest.split("\t")
            name = fields[0].strip()
            # Long listing: name\tmodified\taccessed\tchanged\tcreated\tsize\tuid\tgid
            modified_time = fields[1].strip() if len(fields) > 1 else ""
            accessed_time = fields[2].strip() if len(fields) > 2 else ""
            size_str = fields[5].strip() if len(fields) > 5 else "0"
            try:
                size = int(size_str)
            except ValueError:
                size = 0
            entries.append(
                FileEntry(
                    entry_type=type_name,
                    allocated=deleted_marker.strip() != "*",
                    inode=inode,
                    name=name,
                    full_path=f"{base_path.rstrip('/')}/{name}",
                    modified_time=modified_time,
                    accessed_time=accessed_time,
                    size=size,
                )
            )
        else:
            logger.debug("Unparsed fls line: %s", line)
    return entries


async def fls(
    image: str | Path,
    *,
    offset: int = 0,
    inode: str | None = None,
    recursive: bool = False,
    deleted_only: bool = False,
    fstype: str | None = None,
    summary_only: bool = False,
    timeout: float | None = None,
) -> FileListing:
    """Run TSK fls to list files in a filesystem image.

    Args:
        image: Path to disk image file.
        offset: Partition offset in sectors.
        inode: Starting inode (default: root).
        recursive: Recurse into directories (-r flag).
        deleted_only: Show only deleted entries (-d flag).
        fstype: Filesystem type override (e.g., "ntfs", "ext4").
        summary_only: NIST1 ISSUE-002 — when True, return entry_count but
            omit the (potentially multi-MB) entries list so the result fits
            the MCP envelope on large recursive listings.
        timeout: Max seconds to wait.

    Returns:
        FileListing with parsed file entries.

    Raises:
        FileNotFoundError: If image or fls binary not found.
        TimeoutError: If fls exceeds timeout.
        RuntimeError: If fls returns non-zero exit code.
    """
    image = Path(image)
    if not image.exists():
        raise FileNotFoundError(f"Disk image not found: {image}")

    if timeout is None:
        timeout = get_float("AGENTROPIX_TSK_TIMEOUT", 60.0, floor=5.0, ceiling=3600.0)

    fls_path = shutil.which(TOOL_NAME)
    if not fls_path:
        raise FileNotFoundError(f"{TOOL_NAME} not found on PATH — install sleuthkit")

    cmd = [fls_path, "-l"]  # long listing by default
    if offset:
        cmd.extend(["-o", str(offset)])
    if fstype:
        cmd.extend(["-f", fstype])
    if recursive:
        cmd.append("-r")
    if deleted_only:
        cmd.append("-d")
    cmd.append(str(image))
    if inode:
        cmd.append(inode)

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
        raise TimeoutError(f"fls timed out after {timeout}s") from None

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")

    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError(f"fls failed (rc={proc.returncode}): {stderr[:500]}")

    entries = _parse_fls_output(stdout)

    return FileListing(
        image_path=str(image),
        offset=offset,
        entry_count=len(entries),
        entries=[] if summary_only else entries,
        summary_only=summary_only,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
    )


def _read_inode(image: Path, inode: int, max_bytes: int | None = None) -> bytes:
    """Read up to ``max_bytes`` of the file backing ``inode`` from ``image``.

    Issue #10 — supplies the byte stream that FilesystemAgent hashes for
    T1105 staged-binary indicators (mobsync.exe, PsExec*.exe, etc.). Uses
    pytsk3 directly so we don't shell out to ``icat`` per finding (a
    full-case SRL-2018 walk can hit dozens of suspicious filenames).

    Args:
        image: Path to disk image (raw .dd or EWF .E01).
        inode: TSK inode number (filesystem-allocated).
        max_bytes: Cap on bytes returned. ``None`` reads from
            ``AGENTROPIX_TSK_MAX_READ_BYTES`` (default 50 MB; floor 1 MB,
            ceiling 500 MB). Files larger than the cap return ``b""``
            because a truncated payload produces a misleading SHA-256.

    Returns:
        Raw bytes, or ``b""`` if the file is empty / oversized / missing
        a default-data attribute / pytsk3 unavailable.

    Raises:
        FileNotFoundError: If ``image`` does not exist.
    """
    if not image.exists():
        raise FileNotFoundError(f"Disk image not found: {image}")

    if max_bytes is None:
        max_bytes = get_int(
            "AGENTROPIX_TSK_MAX_READ_BYTES",
            _DEFAULT_TSK_MAX_READ_BYTES,
            floor=1 * 1024 * 1024,
            ceiling=500 * 1024 * 1024,
        )

    try:
        import pytsk3  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("pytsk3 not available; cannot read inode %s from %s", inode, image)
        return b""

    try:
        img = pytsk3.Img_Info(str(image))
        fs = pytsk3.FS_Info(img)
        f = fs.open_meta(inode=inode)
    except (OSError, RuntimeError) as exc:
        logger.warning("Failed to open inode %s in %s: %s", inode, image, exc)
        return b""

    size = getattr(f.info.meta, "size", 0) or 0
    if size <= 0:
        return b""
    if size > max_bytes:
        logger.info(
            "inode %s in %s is %d bytes (> cap %d); skipping hash",
            inode,
            image,
            size,
            max_bytes,
        )
        return b""

    try:
        # Single read_random call; pytsk3 returns up to `size` bytes.
        data = f.read_random(0, size)
    except (OSError, RuntimeError) as exc:
        logger.warning("read_random failed for inode %s in %s: %s", inode, image, exc)
        return b""

    return bytes(data) if data else b""


# --------------------------------------------------------------------------- #
# NIST1 ISSUE-001 — partition enumeration (mmls)
#
# An autonomous agent had no in-band way to derive the partition offset that
# `fls`/`extract_files` need on a physical-disk image: `fls offset=0` lands on
# the MBR and fails FS detection, and no mmls/partition tool was exposed. This
# wrapper runs The Sleuth Kit `mmls` and returns the partition table plus the
# filesystem partition start-sectors to feed straight into `fls(offset=...)`.
# --------------------------------------------------------------------------- #

MMLS_TOOL_NAME = "mmls"

# mmls body row, e.g.:
#   002:  000:000   0000000063   0008385929   0008385867   NTFS / exFAT (0x07)
_MMLS_ROW = re.compile(r"^\s*\d{3}:\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$")
# Descriptions that are NOT real filesystems (table metadata / gaps).
_NON_FS_DESC = ("unallocated", "primary table", "extended", "gpt header", "safety table", "meta")
# Filesystem signatures mmls prints for allocatable partitions.
_FS_HINTS = ("ntfs", "fat", "exfat", "ext", "hfs", "apfs", "iso", "ufs", "linux", "swap")


class PartitionEntry(BaseModel):
    """One row of an mmls partition table."""

    slot: str = ""
    start: int = 0  # start sector — feed to fls(offset=...)
    end: int = 0
    length: int = 0
    description: str = ""
    is_filesystem: bool = False


class PartitionTable(BaseModel):
    """Parsed mmls output for a disk image."""

    image_path: str
    scheme: str = ""  # e.g. "DOS", "GPT", "MAC", "BSD"
    partitions: list[PartitionEntry] = Field(default_factory=list)
    # Start sectors of the filesystem partitions — the offsets to pass to
    # fls/extract_files. Empty list ⇒ no mountable FS found (caller should
    # not silently assume offset 0).
    filesystem_offsets: list[int] = Field(default_factory=list)
    tool: str = "sleuthkit.mmls"
    raw_stderr: str = ""
    raw_stdout_sha256: str = ""


def _parse_mmls_output(stdout: str) -> tuple[str, list[PartitionEntry]]:
    """Parse mmls stdout into (scheme, partitions)."""
    scheme = ""
    partitions: list[PartitionEntry] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # First non-blank line is the scheme banner, e.g. "DOS Partition Table".
        if not scheme and stripped.endswith("Partition Table"):
            scheme = stripped.rsplit(" Partition Table", 1)[0].strip()
            continue
        m = _MMLS_ROW.match(line)
        if not m:
            continue
        slot, start, end, length, desc = m.groups()
        desc_l = desc.lower()
        is_fs = any(h in desc_l for h in _FS_HINTS) and not any(n in desc_l for n in _NON_FS_DESC)
        partitions.append(
            PartitionEntry(
                slot=slot,
                start=int(start),
                end=int(end),
                length=int(length),
                description=desc,
                is_filesystem=is_fs,
            )
        )
    return scheme, partitions


async def get_partitions(
    image: str | Path,
    *,
    timeout: float | None = None,
) -> PartitionTable:
    """Enumerate the partition table of a disk image via mmls (NIST1 ISSUE-001).

    Args:
        image: Path to the disk image (raw .dd/.001 or EWF .E01).
        timeout: Max seconds to wait for mmls.

    Returns:
        PartitionTable with every partition row plus ``filesystem_offsets``
        (the start sectors to feed ``fls(offset=...)`` / ``extract_files``).

    Raises:
        FileNotFoundError: image missing or mmls not on PATH.
        TimeoutError: mmls exceeds timeout.
        RuntimeError: mmls returns non-zero with empty stdout (e.g. the input
            is a single-volume image with no partition table).
    """
    image_path = Path(image)
    if not image_path.exists():
        raise FileNotFoundError(f"Disk image not found: {image_path}")

    if timeout is None:
        timeout = get_float("AGENTROPIX_MMLS_TIMEOUT", 120.0, floor=5.0, ceiling=3600.0)

    mmls_path = shutil.which(MMLS_TOOL_NAME)
    if not mmls_path:
        raise FileNotFoundError(f"{MMLS_TOOL_NAME} not found on PATH — install sleuthkit")

    cmd = [mmls_path, str(image_path)]
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
        raise TimeoutError(f"mmls timed out after {timeout}s") from None

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")

    if proc.returncode != 0 and not stdout.strip():
        # mmls exits non-zero when there's no partition table (single-volume
        # image) — a clear, actionable error beats a silent empty result.
        detail = stderr[:500] or (
            "no partition table — image may be a single volume; try fls offset=0"
        )
        raise RuntimeError(f"mmls failed (rc={proc.returncode}): {detail}")

    scheme, partitions = _parse_mmls_output(stdout)
    fs_offsets = [p.start for p in partitions if p.is_filesystem]
    return PartitionTable(
        image_path=str(image_path),
        scheme=scheme,
        partitions=partitions,
        filesystem_offsets=fs_offsets,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
    )
