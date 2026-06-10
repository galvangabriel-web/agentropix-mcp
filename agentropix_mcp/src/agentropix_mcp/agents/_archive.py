"""Archive triage helpers — find the right dump file inside an extracted tree.

Promoted from ``_t3_scratch/t3_runner.py::extract_dump`` (T3 Memory Triage,
2026-04-25) per BMAD-M7 Phase 3 (W-076).

Why this exists: SRL-2015 EnCase-style zips ship a disk image and a memory
image side-by-side (e.g. ``win2008r2-controller-c-drive/`` next to
``win2008r2-controller-memory/``). A naive "largest file" or "any file
matching ext" picker selects the disk image, hands it to vol3, and vol3
fails with::

    Unable to validate the plugin requirements: plugins.<X>.kernel.layer_name

The fix: hard-skip a disk-extension allowlist, prefer files inside a
``*memory*`` subdirectory, and include ``.001`` (FTK Imager raw output)
in the memory-extension list.

The helpers consume the same ``AGENTROPIX_DISK_SUFFIXES`` /
``AGENTROPIX_MEMORY_SUFFIXES`` env vars defined in :mod:`._evidence`
so operators can extend the allowlist without code changes.
"""

from __future__ import annotations

from pathlib import Path

from agentropix_mcp.agents._evidence import (
    get_disk_suffixes,
    get_memory_suffixes,
)

_DEFAULT_MEMORY_PICKER_EXTS: list[str] = [
    ".vmem",
    ".dmp",
    ".raw",
    ".001",
    ".bin",
    ".mem",
    ".lime",
    ".core",
]


def _looks_like_disk(p: Path, disk_suffixes: set[str]) -> bool:
    return p.suffix.lower() in disk_suffixes


def _is_in_memory_dir(p: Path, base: Path) -> bool:
    """True when any path component *under base* contains 'memory' as a
    substring, excluding combined names like 'memory-c-drive' that some
    SRL archives use for hybrid disk layouts.

    ``base`` is the archive root passed to :func:`find_memory_dump`; only
    components below it are considered, so a parent directory called
    ``/home/foo/memory-runs/`` doesn't mis-flag every candidate.
    """
    try:
        rel = p.relative_to(base)
    except ValueError:
        return False
    for part in rel.parts:
        lowered = part.lower()
        if "memory" in lowered and "memory-c-drive" not in lowered:
            return True
    return False


def find_memory_dump(scratch_dir: Path) -> Path | None:
    """Locate a memory-image file under ``scratch_dir``, ignoring disk images.

    Picker logic (W-076):

    1. Walk the tree for files whose suffix matches the memory-extension
       list (default: ``.vmem .dmp .raw .001 .bin .mem .lime .core``;
       overridable via ``AGENTROPIX_MEMORY_SUFFIXES``).
    2. Reject any candidate whose suffix is on the disk-extension allowlist
       (``.e01 .dd .aff4 .vmdk .vhd .vhdx .qcow2 .ad1`` plus operator
       extensions via ``AGENTROPIX_DISK_SUFFIXES``).
    3. If any surviving candidate sits inside a ``*memory*`` directory,
       restrict the candidate set to those — handles SRL-2015's
       ``<system>-c-drive/`` + ``<system>-memory/`` sibling layout.
    4. If no memory-extension candidate survives, fall back to the
       largest non-disk file in the tree (covers archives whose memory
       dump has an unconventional or missing extension).
    5. Among the final candidates, return the largest by file size.

    Returns ``None`` when nothing qualifies (caller should treat that as
    "no memory dump in this archive").
    """
    if not scratch_dir.exists():
        return None

    disk_suffixes = get_disk_suffixes()
    memory_exts = list(get_memory_suffixes()) or _DEFAULT_MEMORY_PICKER_EXTS

    candidates: list[Path] = []
    for ext in memory_exts:
        candidates.extend(scratch_dir.rglob(f"*{ext}"))
    candidates = [
        c for c in candidates if c.is_file() and not _looks_like_disk(c, disk_suffixes)
    ]

    in_mem_dir = [c for c in candidates if _is_in_memory_dir(c, scratch_dir)]
    if in_mem_dir:
        candidates = in_mem_dir

    if not candidates:
        all_files = sorted(
            scratch_dir.rglob("*"),
            key=lambda p: p.stat().st_size if p.is_file() else 0,
            reverse=True,
        )
        all_files = [
            f for f in all_files if f.is_file() and not _looks_like_disk(f, disk_suffixes)
        ]
        if all_files:
            candidates = [all_files[0]]

    if not candidates:
        return None

    return max(candidates, key=lambda p: p.stat().st_size)
