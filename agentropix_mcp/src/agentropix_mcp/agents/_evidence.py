"""Evidence-type heuristics shared across agents.

`.raw` is ambiguous (both dd disk images and memory dumps use it), so
the rule is: memory wins. If a name *or* suffix says memory, the
disk-side agents stand down.
"""

from __future__ import annotations

from pathlib import Path

from agentropix_mcp._env import get_str_set

_DEFAULT_MEMORY_SUFFIXES: set[str] = {
    ".mem",
    ".vmem",
    ".dmp",
    ".lime",
    ".memdump",
    ".crash",
}
_DEFAULT_DISK_SUFFIXES: set[str] = {
    ".dd",
    ".raw",
    ".img",
    ".e01",
    ".vmdk",
    ".qcow2",
    ".vhd",
    ".vhdx",
    ".aff4",
    ".vdi",
}
_MEMORY_NAME_HINTS = {"mem", "memory", "ram"}

# Back-compat aliases — existing call sites that import the private names
# directly continue to resolve to the expanded default sets.
_MEMORY_SUFFIXES = _DEFAULT_MEMORY_SUFFIXES
_DISK_SUFFIXES = _DEFAULT_DISK_SUFFIXES

# Default EWF-family suffixes; W-031 row 13 makes this overridable via
# ``AGENTROPIX_ARTIFACT_FORMATS`` (comma-separated). Operators can add
# vendor-specific containers without code changes; the helper preserves the
# four-token baseline when the env var is unset / malformed.
_DEFAULT_E01_SUFFIXES: set[str] = {".e01", ".ex01", ".lx01", ".l01"}
# Back-compat alias — Wave 1 (Implementer-2D) and existing call sites import
# ``_E01_SUFFIXES`` directly.  Resolves at import time to whatever the env
# said at first call; the live env-var read is via :func:`get_e01_suffixes`.
_E01_SUFFIXES = _DEFAULT_E01_SUFFIXES


def get_e01_suffixes() -> set[str]:
    """Read the EWF-family suffix set, env-var-overridable per W-031 row 13.

    Tokens are normalised to lowercase + leading-dot so operators may write
    ``"e01,ex01"`` or ``".e01,.ex01"`` — both resolve identically.
    """
    raw = get_str_set(
        "AGENTROPIX_ARTIFACT_FORMATS",
        _DEFAULT_E01_SUFFIXES,
        min_size=1,
        max_size=16,
    )
    return {tok if tok.startswith(".") else f".{tok}" for tok in raw}


def get_memory_suffixes() -> set[str]:
    """Read the memory-image suffix set, env-var-overridable via W-036.

    Tokens normalised to lowercase + leading-dot. Falls back to the
    six-token default when ``AGENTROPIX_MEMORY_SUFFIXES`` is unset or
    malformed (empty / > 32 tokens).
    """
    raw = get_str_set(
        "AGENTROPIX_MEMORY_SUFFIXES",
        _DEFAULT_MEMORY_SUFFIXES,
        min_size=1,
        max_size=32,
    )
    return {tok if tok.startswith(".") else f".{tok}" for tok in raw}


def get_disk_suffixes() -> set[str]:
    """Read the disk-image suffix set, env-var-overridable via W-036.

    Tokens normalised to lowercase + leading-dot. Falls back to the
    ten-token default when ``AGENTROPIX_DISK_SUFFIXES`` is unset or
    malformed (empty / > 32 tokens).
    """
    raw = get_str_set(
        "AGENTROPIX_DISK_SUFFIXES",
        _DEFAULT_DISK_SUFFIXES,
        min_size=1,
        max_size=32,
    )
    return {tok if tok.startswith(".") else f".{tok}" for tok in raw}


def looks_like_memory(image: Path) -> bool:
    name = image.name.lower()
    if image.suffix.lower() in get_memory_suffixes():
        return True
    return any(h in name for h in _MEMORY_NAME_HINTS)


def looks_like_disk(image: Path) -> bool:
    if looks_like_memory(image):
        return False
    return image.suffix.lower() in get_disk_suffixes() or "disk" in image.name.lower()


def looks_like_e01(image: Path) -> bool:
    """True if ``image`` is an EWF-family forensic container.

    Uses suffix only — EWF files do not have reliable name hints. Memory
    precedence does not apply: ``looks_like_memory`` and ``looks_like_e01``
    are independent (an ``.e01`` is never also a memory dump).

    The accepted suffix set is read live from
    ``AGENTROPIX_ARTIFACT_FORMATS`` (W-031 row 13) and falls back to the
    documented EWF-family default when the env var is unset.
    """
    return image.suffix.lower() in get_e01_suffixes()
