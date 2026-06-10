"""Canonical Windows artefact paths for ``mcp_extract_files`` chaining.

The ArtifactAgent uses these presets to drive a registry/execution
evidence extraction over a raw E01 without hard-coding the paths
inside the agent itself. Paths use POSIX separators (TSK convention).

Layout references:

* Registry hives live under ``%SystemRoot%\\System32\\config``.
* Per-user ``NTUSER.DAT`` lives under each ``C:\\Users\\<name>`` profile
  and must be discovered via ``fls`` — it is NOT in this preset.
* ``UsrClass.dat`` is similarly per-user; tracked as future work.
* Amcache lives under ``%SystemRoot%\\AppCompat\\Programs\\Amcache.hve``.
"""

from __future__ import annotations

from typing import Final

REGISTRY_HIVES: Final[tuple[str, ...]] = (
    "Windows/System32/config/SOFTWARE",
    "Windows/System32/config/SYSTEM",
    "Windows/System32/config/SAM",
    "Windows/System32/config/SECURITY",
)

AMCACHE: Final[str] = "Windows/AppCompat/Programs/Amcache.hve"

DEFAULT_ARTIFACTS: Final[tuple[str, ...]] = REGISTRY_HIVES + (AMCACHE,)


__all__ = [
    "AMCACHE",
    "DEFAULT_ARTIFACTS",
    "REGISTRY_HIVES",
]
