"""Configurable suspicious-name matching for MemoryAgent and FilesystemAgent.

Names are matched against process names / filenames via two layers:
1. A *literal set* — substring match (case-insensitive).
2. A *pattern list* — compiled ``re.Pattern`` objects, each checked via
   ``pattern.search(name)`` (case-insensitive).

Both layers come from the same source, selected in order:
  - Operator file (``AGENTROPIX_SUSPICIOUS_PROCS_FILE`` /
    ``AGENTROPIX_SUSPICIOUS_FILES_FILE``) — loaded when set and the
    path exists. Lines beginning with ``re:`` are compiled as patterns;
    all others are literal tokens. Blank lines and ``#``-comments are
    ignored.
  - Fallback to the inline env-var set (``AGENTROPIX_MEMORY_SUSPICIOUS_PROCS`` /
    ``AGENTROPIX_FS_SUSPICIOUS_FILENAMES``) with no regex support, then
    to the built-in defaults when the env var is also absent.
"""

from __future__ import annotations

import contextlib
import os
import re
from pathlib import Path

from agentropix_mcp._env import get_str_set

_DEFAULT_SUSPICIOUS_PROC_NAMES: set[str] = {
    "mimikatz",
    "psexec",
    "cobaltstrike",
    "beacon",
    "meterpreter",
    "lazagne",
    "rubeus",
    "bloodhound",
    "sharphound",
}

_DEFAULT_SUSPICIOUS_FILENAMES: set[str] = {
    "mimikatz",
    "psexec",
    "cobalt",
    "beacon",
    "meterpreter",
    "nc.exe",
    "ncat.exe",
    "wce.exe",
    "procdump.exe",
}


def load_names_file(path: Path) -> tuple[set[str], list[re.Pattern[str]]]:
    """Parse a suspicious-names file into (literals, patterns).

    File format:
      - Blank lines and lines starting with ``#`` are ignored.
      - Lines starting with ``re:`` (case-sensitive prefix) are compiled as
        case-insensitive ``re.Pattern`` objects.
      - All other non-blank lines are lowercased literal tokens.
    """
    literals: set[str] = set()
    patterns: list[re.Pattern[str]] = []
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("re:"):
                expr = line[3:].strip()
                if expr:
                    with contextlib.suppress(re.error):
                        patterns.append(re.compile(expr, re.IGNORECASE))
            else:
                literals.add(line.lower())
    except OSError:
        pass
    return literals, patterns


def matches_name(
    name: str,
    literals: set[str],
    patterns: list[re.Pattern[str]],
) -> bool:
    """True if ``name`` (lowercased by caller) matches any literal or pattern."""
    if any(lit in name for lit in literals):
        return True
    return any(pat.search(name) for pat in patterns)


def get_proc_matchers() -> tuple[set[str], list[re.Pattern[str]]]:
    """Return (literals, patterns) for process-name matching.

    Loads from ``AGENTROPIX_SUSPICIOUS_PROCS_FILE`` when set and the
    path exists; otherwise falls back to the inline env-var set
    ``AGENTROPIX_MEMORY_SUSPICIOUS_PROCS`` (comma-separated) or the
    built-in default list.
    """
    file_path_str = os.environ.get("AGENTROPIX_SUSPICIOUS_PROCS_FILE", "")
    if file_path_str:
        fp = Path(file_path_str)
        if fp.exists():
            return load_names_file(fp)

    literals = get_str_set(
        "AGENTROPIX_MEMORY_SUSPICIOUS_PROCS",
        _DEFAULT_SUSPICIOUS_PROC_NAMES,
    )
    return literals, []


def get_file_matchers() -> tuple[set[str], list[re.Pattern[str]]]:
    """Return (literals, patterns) for filename matching.

    Loads from ``AGENTROPIX_SUSPICIOUS_FILES_FILE`` when set and the
    path exists; otherwise falls back to the inline env-var set
    ``AGENTROPIX_FS_SUSPICIOUS_FILENAMES`` (comma-separated) or the
    built-in default list.
    """
    file_path_str = os.environ.get("AGENTROPIX_SUSPICIOUS_FILES_FILE", "")
    if file_path_str:
        fp = Path(file_path_str)
        if fp.exists():
            return load_names_file(fp)

    literals = get_str_set(
        "AGENTROPIX_FS_SUSPICIOUS_FILENAMES",
        _DEFAULT_SUSPICIOUS_FILENAMES,
    )
    return literals, []
