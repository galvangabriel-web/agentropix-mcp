"""EWF/E01 image metadata wrapper — ewfinfo."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import shutil
from pathlib import Path

from pydantic import BaseModel

from agentropix_mcp._env import get_float

logger = logging.getLogger(__name__)

TOOL_NAME = "ewfinfo"


class ImageInfo(BaseModel):
    """Metadata extracted from an E01/EWF forensic image via ewfinfo."""

    image_path: str
    case_number: str = ""
    examiner: str = ""
    acquisition_date: str = ""
    media_size: str = ""
    md5: str = ""
    sha1: str = ""
    tool: str = "ewftools.ewfinfo"
    raw_output: str = ""
    # SIFT-W-082: SHA-256 of ewfinfo's raw stdout bytes.
    raw_stdout_sha256: str = ""


# Patterns used to extract key fields from ewfinfo text output.
_FIELD_PATTERNS: dict[str, re.Pattern[str]] = {
    "case_number": re.compile(r"(?i)case\s+number\s*:\s*(.+)"),
    "examiner": re.compile(r"(?i)examiner\s+name\s*:\s*(.+)"),
    "acquisition_date": re.compile(r"(?i)acquisition\s+date\s*:\s*(.+)"),
    "media_size": re.compile(r"(?i)media\s+size\s*:\s*(.+)"),
    "md5": re.compile(r"(?i)md5(?:\s+hash)?\s*:\s*([0-9a-fA-F]+)"),
    "sha1": re.compile(r"(?i)sha1?(?:\s+hash)?\s*:\s*([0-9a-fA-F]+)"),
}


def _parse_ewfinfo_output(output: str, image_path: str) -> ImageInfo:
    """Parse ewfinfo text output into an ImageInfo model."""
    fields: dict[str, str] = {}
    for field, pattern in _FIELD_PATTERNS.items():
        m = pattern.search(output)
        if m:
            fields[field] = m.group(1).strip()
    return ImageInfo(
        image_path=image_path,
        raw_output=output[:2000],
        **fields,
    )


async def get_image_info(
    image: str | Path,
    *,
    timeout: float | None = None,
) -> ImageInfo:
    """Run ewfinfo to extract E01/EWF image metadata.

    Args:
        image: Path to the E01 (or other EWF-format) image file.
        timeout: Maximum seconds to wait for ewfinfo.

    Returns:
        ImageInfo with case metadata and hash values.

    Raises:
        FileNotFoundError: If the image file or ewfinfo binary is not found.
        TimeoutError: If ewfinfo exceeds the timeout.
        RuntimeError: If ewfinfo returns a non-zero exit code.
    """
    image = Path(image)
    if not image.exists():
        raise FileNotFoundError(f"E01 image not found: {image}")

    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_EWF_TIMEOUT", 30.0, floor=5.0, ceiling=3600.0
        )

    ewfinfo_path = shutil.which(TOOL_NAME)
    if not ewfinfo_path:
        raise FileNotFoundError(f"{TOOL_NAME} not found on PATH — install ewf-tools")

    cmd = [ewfinfo_path, str(image)]

    logger.info("Running: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        raise TimeoutError(f"ewfinfo timed out after {timeout}s")

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")

    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError(
            f"ewfinfo failed (rc={proc.returncode}): {stderr[:500]}"
        )

    info = _parse_ewfinfo_output(stdout, image_path=str(image))
    info.raw_stdout_sha256 = hashlib.sha256(stdout_bytes).hexdigest()
    return info
