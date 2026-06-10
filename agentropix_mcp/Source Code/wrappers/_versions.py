"""Tool version checking — verify forensic tool compatibility."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess

logger = logging.getLogger(__name__)

REQUIRED_TOOLS = {
    "vol": {"min_version": "2.0", "package": "volatility3"},
    "ewfinfo": {"min_version": "20140000", "package": "libewf-tools"},
    "fls": {"min_version": "4.0", "package": "sleuthkit"},
    "log2timeline.py": {"min_version": "20200000", "package": "plaso"},
}


def _extract_version(output: str) -> str:
    """Extract version string from tool output."""
    # Match patterns like "4.11.1", "20260119", "2.8.0"
    match = re.search(r"(\d+[\.\d]*)", output)
    return match.group(1) if match else ""


def check_tool(name: str) -> dict[str, str]:
    """Check if a tool is available and return version info."""
    path = shutil.which(name)
    if not path:
        return {"name": name, "status": "missing", "path": "", "version": ""}

    try:
        if name == "vol":
            result = subprocess.run([path, "--help"], capture_output=True, text=True, timeout=10)
            version = _extract_version(result.stdout + result.stderr)
        elif name == "ewfinfo":
            result = subprocess.run([path, "-V"], capture_output=True, text=True, timeout=10)
            version = _extract_version(result.stdout + result.stderr)
        elif name == "fls":
            result = subprocess.run([path, "-V"], capture_output=True, text=True, timeout=10)
            version = _extract_version(result.stdout + result.stderr)
        elif name == "log2timeline.py":
            result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10)
            version = _extract_version(result.stdout + result.stderr)
        else:
            version = ""
    except (subprocess.TimeoutExpired, OSError):
        return {"name": name, "status": "error", "path": path, "version": ""}

    return {"name": name, "status": "available", "path": path, "version": version}


def check_all_tools() -> list[dict[str, str]]:
    """Check all required forensic tools and log results."""
    results = []
    for tool_name in REQUIRED_TOOLS:
        info = check_tool(tool_name)
        results.append(info)
        if info["status"] == "missing":
            logger.warning("Required tool %s not found — install %s",
                          tool_name, REQUIRED_TOOLS[tool_name]["package"])
        elif info["status"] == "available":
            logger.info("Tool %s v%s at %s", tool_name, info["version"], info["path"])
        else:
            logger.warning("Tool %s check failed at %s", tool_name, info["path"])
    return results
