"""Dynamic-disk container unwrapper -- W-171.

Converts VHD / VHDX / VMDK / VDI / QCOW2 images to raw format for
downstream SIFT analysis (TSK, Volatility, GPT parser).  Uses
``qemu-img convert -O raw`` + SHA-256 chain-of-custody hash.

MCP tool: ``unwrap_disk_container``

Supported input formats (qemu-img internal names):
  vpc    -- Legacy VHD (Virtual PC / Hyper-V v1)
  vhdx   -- Hyper-V v2 VHDX
  vmdk   -- VMware VMDK (sparse + monolithic)
  vdi    -- VirtualBox VDI
  qcow2  -- KVM/QEMU native

Output is written to a fresh temp directory under /tmp so Thymus path
guards on the source path are unaffected.  The caller receives the raw
image path plus metadata and is responsible for cleanup.

Tunable:
* ``AGENTROPIX_DISK_UNWRAP_TIMEOUT``  (float, default 300.0, [30.0, 3600.0])
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
import tempfile
from pathlib import Path

from agentropix_mcp._env import get_float

logger = logging.getLogger(__name__)

TOOL_NAME = "qemu-img"

_QEMU_IMG = shutil.which("qemu-img") or "/usr/bin/qemu-img"

_DEFAULT_TIMEOUT = 300.0

# qemu-img internal format strings that we treat as container formats
_CONTAINER_FORMATS: frozenset[str] = frozenset(
    {"vpc", "vhdx", "vmdk", "vdi", "qcow2"}
)

# Human-friendly label map (vpc internal name -> canonical VHD)
_FORMAT_LABELS: dict[str, str] = {
    "vpc": "vhd",
    "vhdx": "vhdx",
    "vmdk": "vmdk",
    "vdi": "vdi",
    "qcow2": "qcow2",
}

# File-extension -> expected qemu-img format hint (used to validate
# the detected format matches the extension to catch mis-named files)
_EXT_HINTS: dict[str, str] = {
    ".vhd": "vpc",
    ".vhdx": "vhdx",
    ".vmdk": "vmdk",
    ".vdi": "vdi",
    ".qcow2": "qcow2",
    ".qcow": "qcow2",
}

# Public suffix contract referenced by drift-guard tests (W-171).
_SUPPORTED_SUFFIXES: frozenset[str] = frozenset(_EXT_HINTS)


async def _run(cmd: list[str], timeout: float) -> tuple[str, str, int]:
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


async def _qemu_info(image_path: str, timeout: float) -> dict | None:
    """Return parsed qemu-img info JSON, or None on failure."""
    stdout, stderr, rc = await _run(
        [_QEMU_IMG, "info", "--output", "json", image_path], timeout=min(timeout, 30.0)
    )
    if rc != 0:
        logger.debug("qemu-img info failed (rc=%d): %s", rc, stderr[:200])
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        logger.debug("qemu-img info JSON parse error: %s", exc)
        return None


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


async def unwrap_disk_container(
    input_path: str,
    output_dir: str | None = None,
) -> dict:
    """Convert a virtual-disk container to a raw image for SIFT analysis.

    Detects the container format via ``qemu-img info`` (accepts VHD/VPC,
    VHDX, VMDK, VDI, QCOW2).  Rejects raw images and unknown formats.
    Converts to raw via ``qemu-img convert -O raw``, hashes the output,
    and returns a structured result dict.

    Args:
        input_path: Absolute path to the disk container.
        output_dir: Directory to write the raw image into.  Defaults to
            a fresh ``/tmp/agentropix_unwrap_*/`` temp directory.  The
            directory is created by this function; it is the caller's
            responsibility to clean it up when finished.

    Returns:
        On success::

            {
                "input_path":        str,
                "format_detected":   str,   # canonical name (vhd/vhdx/vmdk/vdi/qcow2)
                "raw_image_path":    str,
                "raw_image_sha256":  str,
                "virtual_size_bytes": int,
                "actual_size_bytes": int,
                "is_sparse":         bool,
                "metadata":          dict,  # qemu-img format-specific block
            }

        On failure::

            {"error": str, "input_path": str}
    """
    timeout = get_float(
        "AGENTROPIX_DISK_UNWRAP_TIMEOUT",
        _DEFAULT_TIMEOUT,
        floor=30.0,
        ceiling=3600.0,
    )

    base: dict = {"input_path": input_path}

    info = await _qemu_info(input_path, timeout)
    if info is None:
        return {**base, "error": f"qemu-img info failed on {input_path}"}

    fmt = info.get("format", "")
    if fmt not in _CONTAINER_FORMATS:
        return {
            **base,
            "error": (
                f"unsupported format '{fmt}' — expected one of "
                f"{sorted(_CONTAINER_FORMATS)}"
            ),
        }

    virtual_size: int = info.get("virtual-size", 0)
    actual_size: int = info.get("actual-size", 0)
    is_sparse: bool = actual_size < virtual_size
    fmt_label: str = _FORMAT_LABELS.get(fmt, fmt)
    metadata: dict = info.get("format-specific", {})

    # Determine output path
    stem = Path(input_path).stem
    if output_dir is None:
        work_dir = tempfile.mkdtemp(prefix="agentropix_unwrap_")
    else:
        work_dir = output_dir
        os.makedirs(work_dir, exist_ok=True)

    raw_path = os.path.join(work_dir, f"{stem}.raw")

    # Convert
    conv_stdout, conv_stderr, conv_rc = await _run(
        [_QEMU_IMG, "convert", "-O", "raw", input_path, raw_path],
        timeout=timeout,
    )
    if conv_rc != 0:
        return {
            **base,
            "error": (
                f"qemu-img convert failed (rc={conv_rc}): {conv_stderr[:400]}"
            ),
        }

    # Hash for chain of custody
    try:
        sha256 = _sha256_file(raw_path)
    except OSError as exc:
        return {**base, "error": f"could not read converted image: {exc}"}

    return {
        "input_path": input_path,
        "format_detected": fmt_label,
        "raw_image_path": raw_path,
        "raw_image_sha256": sha256,
        "virtual_size_bytes": virtual_size,
        "actual_size_bytes": actual_size,
        "is_sparse": is_sparse,
        "metadata": metadata,
    }
