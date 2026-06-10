"""W-095 — archive-extraction wrapper for the MCP boundary.

The MCP surface previously rejected compressed evidence at every entry
point (``_reject_archive`` in ``server.py``) but exposed no inverse
primitive — so operators ran ``7z x`` over SSH, breaking the audit
boundary the Thymus enforces. ``extract_archive`` is that inverse:
unpack ``.7z`` / ``.zip`` / ``.tar*`` archives into a Thymus-allowed
write zone, with archive-bomb caps + path-traversal + symlink-escape
re-check enforced at the wrapper layer.

Engine matrix (suffix → engine):
    .7z, .rar, .zip          → ``7z x``  (7-Zip 23.x handles all three;
                                          7z's ZIP implementation
                                          handles ZIP64 better than
                                          ``unzip``)
    .tar, .tgz, .tbz2, .txz  → ``tar -xf`` (auto-detects compression)
    .tar.gz, .tar.bz2,       → ``tar -xf`` (auto-detects compression)
    .tar.xz

Bomb defense pipeline:
    1. Resolve caps from env (with floor/ceiling clamps).
    2. Pre-flight ``7z l -slt`` to read the inventory WITHOUT extracting
       — refuse before touching the disk if claimed entry-count or
       total-bytes exceed caps. ``7z l`` works for tar/tgz/tbz/txz too,
       so a single pre-flight covers every supported format.
    3. Per-entry pre-validation on the inventory: any path containing
       ``..`` or starting with ``/`` is rejected before extraction
       (defense-in-depth — the post-walk check is the authoritative
       guard, but rejecting at the inventory step means we never even
       hand a bomb-shape archive to the engine).
    4. Run the extraction subprocess with a wall-clock timeout.
    5. Post-extraction walk: for every emitted file/symlink, resolve
       its absolute path and verify ``Path.resolve().relative_to(dest)``
       cleanly. Symlinks are read; if their target resolves outside
       ``dest`` they are unlinked and recorded as a rejected entry.

Chain-of-custody (SIFT-W-082):
    The pre-flight ``7z l -slt`` stdout is the deterministic step we
    can hash and replay. Per-entry SHA-256 is computed in-line during
    the post-walk so the manifest is the authoritative byte-level
    record; the engine's own progress output is not trusted.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
from pathlib import Path

from agentropix_mcp._env import get_float, get_int
from agentropix_mcp.schema.extract_archive import ArchiveEntry, ExtractArchiveManifest

logger = logging.getLogger(__name__)

DEFAULT_7Z = "7z"
DEFAULT_TAR = "tar"

# 64 KiB SHA-256 chunk — same constant ``extract.py`` uses; keeps
# digest overhead negligible relative to disk read latency.
_CHUNK = 64 * 1024

# Caps mirror the draft spec values. Floor is a sane non-zero ceiling
# to make accidental ``=0`` env settings impossible to interpret as
# "unlimited"; ceiling is set so the operator can override but a typo
# in env can't overflow ``int`` arithmetic downstream.
_DEFAULT_MAX_BYTES = 50 * 1024 * 1024 * 1024  # 50 GiB
_DEFAULT_MAX_FILES = 1_000_000
_DEFAULT_MAX_PER_FILE = 16 * 1024 * 1024 * 1024  # 16 GiB
_DEFAULT_TIMEOUT = 600.0

# 7z / tar suffix dispatch tables.
_SEVENZ_SUFFIXES = frozenset({".7z", ".rar", ".zip"})
_TAR_SINGLE_SUFFIXES = frozenset({".tar", ".tgz", ".tbz2", ".txz"})
_TAR_DOUBLE_SUFFIXES = frozenset({".tar.gz", ".tar.bz2", ".tar.xz"})


def _resolve_7z() -> str:
    return os.environ.get("AGENTROPIX_7Z_TOOL", DEFAULT_7Z)


def _resolve_tar() -> str:
    return os.environ.get("AGENTROPIX_TAR_TOOL", DEFAULT_TAR)


def _detect_format(p: Path) -> tuple[str, str]:
    """Return ``(detected_format, engine)`` for an archive path.

    Suffix-first dispatch — ambiguous cases (``.bin`` with a 7z magic
    header) would need libmagic, but the SIFT operator workflow always
    delivers archives with the canonical extension; we fail fast on
    anything unsupported so misroutes surface as a clear ValueError
    rather than a silent partial-extract.
    """
    last_two = "".join(s.lower() for s in p.suffixes[-2:])
    if last_two in _TAR_DOUBLE_SUFFIXES:
        return last_two, "tar"
    suffix = p.suffix.lower()
    if suffix in _TAR_SINGLE_SUFFIXES:
        return suffix, "tar"
    if suffix in _SEVENZ_SUFFIXES:
        return suffix, "7z"
    raise ValueError(
        f"unsupported archive format for {p.name!r} — supported: "
        f".7z .zip .rar .tar .tar.gz .tar.bz2 .tar.xz .tgz .tbz2 .txz"
    )


def _is_unsafe_path(in_archive_path: str) -> str:
    """Return a non-empty reason string when ``in_archive_path`` is unsafe.

    The pre-flight inventory check rejects entries whose logical path
    in the archive is itself crafted to escape (``../etc/passwd``,
    absolute paths, NUL bytes). Empty string means safe.
    """
    if not in_archive_path:
        return "empty path"
    if "\x00" in in_archive_path:
        return "NUL byte in path"
    # 7z's inventory output uses the archive's own native separator;
    # normalise both forms so a backslash-escape isn't a bypass.
    normalised = in_archive_path.replace("\\", "/")
    if normalised.startswith("/"):
        return "absolute path"
    for seg in normalised.split("/"):
        if seg == "..":
            return "path-traversal segment"
    return ""


def _parse_7z_inventory(stdout: str) -> list[dict[str, str]]:
    """Parse ``7z l -slt`` per-entry blocks.

    The output has a header section (archive-level metadata) followed
    by the line ``----------`` and one stanza per entry, with blank-
    line separators. Each stanza is ``key = value`` lines. Folder
    entries are filtered out by the caller via the ``Folder`` /
    ``Attributes`` keys, since archive-bomb sizing is a sum over real
    file entries.
    """
    entries: list[dict[str, str]] = []
    if "----------" not in stdout:
        return entries
    body = stdout.split("----------", 1)[1]
    for stanza in body.split("\n\n"):
        block = stanza.strip()
        if not block:
            continue
        d: dict[str, str] = {}
        for line in block.splitlines():
            if " = " not in line:
                continue
            key, value = line.split(" = ", 1)
            d[key.strip()] = value.strip()
        if "Path" in d:
            entries.append(d)
    return entries


def _is_folder_entry(d: dict[str, str]) -> bool:
    """Is this 7z inventory entry a directory rather than a file?

    7z marks folders one of two ways: ``Folder = +`` (older), or the
    ``D`` bit in ``Attributes``. Either signal is sufficient — we
    match both so we don't accidentally cap on directory-count.
    """
    if d.get("Folder", "").strip() == "+":
        return True
    attrs = d.get("Attributes", "")
    return attrs.startswith("D")


async def _kill_and_reap(proc: asyncio.subprocess.Process) -> None:
    """Kill a subprocess and reap the zombie within a bounded budget.

    Mirrors ``extract.py:_kill_and_reap``. Bug B (2026-04-25) hardening:
    a wedged engine left behind by a timeout would otherwise hold the
    asyncio transport open and amplify into a server-wide stall.
    """
    if proc.returncode is None:
        proc.kill()
    try:
        await asyncio.wait_for(proc.wait(), timeout=2.0)
    except (TimeoutError, ProcessLookupError):
        pass


async def _preflight_7z(
    archive: Path,
    *,
    max_files: int,
    max_total_bytes: int,
    max_per_file_bytes: int,
    timeout: float,
) -> tuple[list[dict[str, str]], bytes, str]:
    """Run ``7z l -slt`` and validate against caps.

    Returns ``(file_entries, raw_stdout_bytes, raw_stderr)``.

    Raises:
        ValueError: caps exceeded — extraction is refused.
        FileNotFoundError: ``7z`` not on PATH.
        RuntimeError: 7z exits non-zero with no parseable inventory
            (corrupt / encrypted / unrecognised archive).
        TimeoutError: pre-flight exceeded ``timeout``.
    """
    tool = _resolve_7z()
    binary = shutil.which(tool)
    if binary is None:
        raise FileNotFoundError(
            f"{tool} not found on PATH — install p7zip-full or set AGENTROPIX_7Z_TOOL"
        )
    cmd = [binary, "l", "-slt", "--", str(archive)]
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
    except TimeoutError:
        await _kill_and_reap(proc)
        raise TimeoutError(f"7z l pre-flight timed out after {timeout}s") from None

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")
    all_entries = _parse_7z_inventory(stdout)
    file_entries = [d for d in all_entries if not _is_folder_entry(d)]

    # 7z exit codes: 0 ok, 1 warning, 2+ fatal. Treat any fatal exit
    # without parseable inventory as a corrupt archive.
    if proc.returncode is not None and proc.returncode >= 2 and not file_entries:
        raise RuntimeError(
            f"7z l failed (rc={proc.returncode}) — archive may be "
            f"corrupt or encrypted: {stderr[:300]}"
        )

    # Cap validation — refuse before extracting a single byte.
    if len(file_entries) > max_files:
        raise ValueError(
            f"archive entry count {len(file_entries)} exceeds "
            f"AGENTROPIX_ARCHIVE_MAX_FILES={max_files}"
        )

    total_bytes = 0
    for d in file_entries:
        try:
            sz = int(d.get("Size", "0") or "0")
        except ValueError:
            sz = 0
        if sz > max_per_file_bytes:
            raise ValueError(
                f"archive entry {d.get('Path', '<?>')!r} claims "
                f"{sz} bytes, exceeds "
                f"AGENTROPIX_ARCHIVE_MAX_PER_FILE_BYTES={max_per_file_bytes}"
            )
        total_bytes += sz

    if total_bytes > max_total_bytes:
        raise ValueError(
            f"archive claims {total_bytes} uncompressed bytes, exceeds "
            f"AGENTROPIX_ARCHIVE_MAX_BYTES={max_total_bytes}"
        )

    return file_entries, stdout_bytes, stderr


async def _run_engine(
    engine: str,
    archive: Path,
    dest: Path,
    members: list[str] | None,
    *,
    timeout: float,
) -> tuple[int, str]:
    """Run the extraction subprocess. Returns ``(returncode, stderr)``."""
    if engine == "7z":
        tool_name = _resolve_7z()
        binary = shutil.which(tool_name)
        if binary is None:
            raise FileNotFoundError(
                f"{tool_name} not found on PATH — install p7zip-full"
            )
        # `-o<dest>` (no space — 7z syntax peculiarity).
        # `-y` assumes yes for any prompt (we control dest).
        # `--` terminates options so an archive starting with `-` is safe.
        cmd = [binary, "x", f"-o{dest}", "-y", "--", str(archive)]
        if members:
            cmd.extend(members)
    elif engine == "tar":
        tool_name = _resolve_tar()
        binary = shutil.which(tool_name)
        if binary is None:
            raise FileNotFoundError(
                f"{tool_name} not found on PATH — install GNU tar"
            )
        cmd = [binary, "-xf", str(archive), "-C", str(dest)]
        if members:
            cmd.extend(members)
    else:  # pragma: no cover — _detect_format rules this out
        raise ValueError(f"unsupported engine: {engine}")

    logger.info("Running: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except TimeoutError:
        await _kill_and_reap(proc)
        raise TimeoutError(
            f"{engine} extraction timed out after {timeout}s"
        ) from None
    rc = proc.returncode if proc.returncode is not None else -1
    return rc, stderr_bytes.decode(errors="replace")


def _walk_dest_for_entries(dest_dir: Path) -> list[ArchiveEntry]:
    """Walk ``dest_dir`` post-extraction and build per-entry rows.

    Each emitted file gets a SHA-256 computed in 64 KiB chunks. Symlinks
    are resolved and their target verified to stay under ``dest_dir``;
    any escape is recorded as a rejected entry AND the offending
    symlink is unlinked so the audited filesystem state matches the
    manifest. Directories are skipped — only files matter for the
    chain-of-custody surface.
    """
    dest_resolved = dest_dir.resolve()
    rows: list[ArchiveEntry] = []
    for path in sorted(dest_dir.rglob("*")):
        rel = path.relative_to(dest_dir).as_posix()
        # Symlinks first — we need to detect escape BEFORE following.
        if path.is_symlink():
            try:
                target = path.resolve()
                target.relative_to(dest_resolved)
            except (ValueError, OSError, RuntimeError):
                # Symlink escapes the dest dir (or is broken). Unlink
                # so the on-disk state matches the manifest's rejection.
                try:
                    path.unlink()
                except OSError:
                    pass
                rows.append(
                    ArchiveEntry(
                        path=rel,
                        dest="",
                        size=0,
                        sha256="",
                        ok=False,
                        error="symlink-escape: target outside dest",
                    )
                )
                continue
            # Symlink that stays inside — record it as ok with no SHA
            # (we don't double-hash the target, which gets its own row
            # via the walk).
            rows.append(
                ArchiveEntry(
                    path=rel,
                    dest=str(path),
                    size=0,
                    sha256="",
                    ok=True,
                    error="",
                )
            )
            continue

        if path.is_dir():
            continue

        # Regular file — verify the resolved path stays under dest
        # (defense-in-depth against a hardlink trick or an engine that
        # somehow honoured an absolute-path entry despite our
        # pre-flight rejection).
        try:
            resolved = path.resolve()
            resolved.relative_to(dest_resolved)
        except (ValueError, OSError):
            try:
                path.unlink()
            except OSError:
                pass
            rows.append(
                ArchiveEntry(
                    path=rel,
                    dest="",
                    size=0,
                    sha256="",
                    ok=False,
                    error="path-traversal: file resolves outside dest",
                )
            )
            continue

        digest = hashlib.sha256()
        size = 0
        try:
            with path.open("rb") as fh:
                while True:
                    chunk = fh.read(_CHUNK)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
        except OSError as exc:
            rows.append(
                ArchiveEntry(
                    path=rel,
                    dest=str(path),
                    size=0,
                    sha256="",
                    ok=False,
                    error=f"read failed: {exc}",
                )
            )
            continue
        rows.append(
            ArchiveEntry(
                path=rel,
                dest=str(path),
                size=size,
                sha256=digest.hexdigest(),
                ok=True,
                error="",
            )
        )
    return rows


async def extract_archive(
    archive: str | Path,
    dest: str | Path,
    *,
    members: list[str] | None = None,
    max_total_bytes: int | None = None,
    max_files: int | None = None,
    max_per_file_bytes: int | None = None,
    timeout: float | None = None,
    engine: str | None = None,
) -> ExtractArchiveManifest:
    """Extract ``archive`` into ``dest`` and return a typed manifest.

    Args:
        archive: Path to a ``.7z`` / ``.zip`` / ``.rar`` / ``.tar*``
            archive.
        dest: Destination directory. Must already exist.
        members: Optional include list — only these in-archive paths
            are extracted. Empty / None extracts everything.
        max_total_bytes: Override
            ``AGENTROPIX_ARCHIVE_MAX_BYTES`` (default 50 GiB).
        max_files: Override ``AGENTROPIX_ARCHIVE_MAX_FILES``
            (default 1,000,000).
        max_per_file_bytes: Override
            ``AGENTROPIX_ARCHIVE_MAX_PER_FILE_BYTES`` (default 16 GiB).
        timeout: Wall-clock seconds for the extraction subprocess.
            Defaults to ``AGENTROPIX_ARCHIVE_TIMEOUT`` (600 s, floor 30,
            ceiling 86400).
        engine: Force ``"7z"`` or ``"tar"`` instead of suffix dispatch.

    Raises:
        FileNotFoundError: archive missing or engine binary absent.
        ValueError: dest not a directory, archive format unsupported,
            or archive-bomb cap exceeded.
        RuntimeError: engine returned non-zero with empty manifest
            (corrupt archive, etc).
        TimeoutError: pre-flight or extraction exceeded budget.
    """
    archive_path = Path(archive)
    if not archive_path.exists():
        raise FileNotFoundError(f"archive not found: {archive_path}")
    if not archive_path.is_file():
        raise ValueError(f"archive is not a regular file: {archive_path}")

    dest_dir = Path(dest)
    if not dest_dir.exists() or not dest_dir.is_dir():
        raise ValueError(f"dest must be an existing directory: {dest_dir}")

    if max_total_bytes is None:
        max_total_bytes = get_int(
            "AGENTROPIX_ARCHIVE_MAX_BYTES",
            _DEFAULT_MAX_BYTES,
            floor=1024,
            ceiling=2**62,
        )
    if max_files is None:
        max_files = get_int(
            "AGENTROPIX_ARCHIVE_MAX_FILES",
            _DEFAULT_MAX_FILES,
            floor=1,
            ceiling=2**31 - 1,
        )
    if max_per_file_bytes is None:
        max_per_file_bytes = get_int(
            "AGENTROPIX_ARCHIVE_MAX_PER_FILE_BYTES",
            _DEFAULT_MAX_PER_FILE,
            floor=1024,
            ceiling=2**62,
        )
    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_ARCHIVE_TIMEOUT",
            _DEFAULT_TIMEOUT,
            floor=30.0,
            ceiling=86400.0,
        )

    detected_format, dispatched_engine = _detect_format(archive_path)
    used_engine = engine if engine in {"7z", "tar"} else dispatched_engine

    # Pre-flight via 7z (handles every supported format including tar/tgz).
    file_entries, preflight_stdout, preflight_stderr = await _preflight_7z(
        archive_path,
        max_files=max_files,
        max_total_bytes=max_total_bytes,
        max_per_file_bytes=max_per_file_bytes,
        timeout=timeout,
    )

    # Per-entry pre-validation on the inventory. Any unsafe entry
    # short-circuits the whole extraction — refusing to expose the
    # engine to a crafted archive at all is safer than relying on
    # post-walk cleanup alone.
    rejected_pre: list[ArchiveEntry] = []
    for d in file_entries:
        in_path = d.get("Path", "")
        reason = _is_unsafe_path(in_path)
        if reason:
            rejected_pre.append(
                ArchiveEntry(
                    path=in_path,
                    dest="",
                    size=0,
                    sha256="",
                    ok=False,
                    error=f"pre-flight reject: {reason}",
                )
            )

    if rejected_pre:
        # Refuse the whole archive — return a manifest documenting
        # exactly which entries triggered the refusal.
        return ExtractArchiveManifest(
            archive_path=str(archive_path),
            dest=str(dest_dir.resolve()),
            used_engine=used_engine,
            detected_format=detected_format,
            entries=rejected_pre,
            total_files=0,
            total_bytes=0,
            error_count=len(rejected_pre),
            truncated=False,
            raw_stderr=preflight_stderr[:1000],
            raw_stdout_sha256=hashlib.sha256(preflight_stdout).hexdigest(),
        )

    rc, eng_stderr = await _run_engine(
        used_engine, archive_path, dest_dir, members, timeout=timeout
    )

    rows = _walk_dest_for_entries(dest_dir)

    if rc != 0 and not rows:
        raise RuntimeError(
            f"{used_engine} failed (rc={rc}) with no extracted output: "
            f"{eng_stderr[:300]}"
        )

    ok_rows = [r for r in rows if r.ok]
    err_rows = [r for r in rows if not r.ok]
    total_bytes = sum(r.size for r in ok_rows)

    combined_stderr = (preflight_stderr + ("\n" + eng_stderr if eng_stderr else ""))[
        :1000
    ]

    return ExtractArchiveManifest(
        archive_path=str(archive_path),
        dest=str(dest_dir.resolve()),
        used_engine=used_engine,
        detected_format=detected_format,
        entries=rows,
        total_files=len(ok_rows),
        total_bytes=total_bytes,
        error_count=len(err_rows),
        truncated=False,
        raw_stderr=combined_stderr,
        raw_stdout_sha256=hashlib.sha256(preflight_stdout).hexdigest(),
    )


__all__ = ["ArchiveEntry", "ExtractArchiveManifest", "extract_archive"]
