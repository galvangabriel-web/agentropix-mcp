"""W-095 — typed result schema for the ``extract_archive`` MCP tool.

The wrapper at ``mcp_server/wrappers/extract_archive.py`` populates
these models from the post-extraction filesystem walk + the engine's
pre-flight inventory. Per-entry shape mirrors ``ExtractedFile`` so
downstream code can fan-in archive + disk-extraction results into a
unified manifest without a model adapter.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ArchiveEntry(BaseModel):
    """One row of the extraction manifest — mirrors ``ExtractedFile``."""

    path: str
    """In-archive logical path (forward-slash, root-relative). Empty
    string when the engine emits an entry with no knowable source name
    (e.g. stream-decompressed single-file archives)."""

    dest: str = ""
    """On-host absolute path the entry was written to. Empty string
    when the entry was rejected before any bytes were written
    (path-traversal, symlink-escape, per-file cap)."""

    size: int = 0
    """Bytes actually written to ``dest`` (or 0 on a rejected entry)."""

    sha256: str = ""
    """Hex SHA-256 over the on-host file contents. Empty when ``ok``
    is False or the entry is a directory / symlink we deliberately
    refused to follow."""

    ok: bool = True
    """True when the entry landed on disk and passed the post-extraction
    path-traversal + symlink-escape re-check. False when rejected."""

    error: str = ""
    """Populated when ``ok`` is False — short reason string suitable
    for surfacing to a human or LLM operator."""


class ExtractArchiveManifest(BaseModel):
    """Structured result of one ``extract_archive`` call."""

    archive_path: str
    dest: str
    """Canonical absolute path of the extraction destination directory."""

    used_engine: str
    """Engine actually invoked — ``"7z"`` or ``"tar"``."""

    detected_format: str
    """Suffix-derived format — ``".7z"``, ``".zip"``, ``".tar.gz"`` …"""

    entries: list[ArchiveEntry] = Field(default_factory=list)

    total_files: int = 0
    """Count of entries with ``ok`` True. Mirrors ``ok_count``."""

    total_bytes: int = 0
    """Sum of ``size`` over ``ok`` entries (bytes successfully written)."""

    error_count: int = 0
    """Count of entries with ``ok`` False (traversal / symlink / cap)."""

    truncated: bool = False
    """True when extraction was halted by a bomb cap
    (``AGENTROPIX_ARCHIVE_MAX_BYTES`` / ``MAX_FILES`` / ``MAX_PER_FILE_BYTES``)."""

    tool: str = "extract_archive"
    raw_stderr: str = ""
    """Engine stderr capped at 1000 chars for diagnostics."""

    raw_stdout_sha256: str = ""
    """SIFT-W-082 chain-of-custody — SHA-256 over the engine's primary
    log (``7z l -slt`` pre-flight stdout, the deterministic step)."""


__all__ = ["ArchiveEntry", "ExtractArchiveManifest"]
