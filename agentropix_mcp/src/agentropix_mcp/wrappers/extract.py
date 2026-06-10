"""TSK file-extraction wrapper — ``icat``-based content retrieval.

W-028 / ADR-012. The forensic wrappers that parse registry hives,
Amcache, Shimcache, and Prefetch all need a path to an *already
extracted* file on the host filesystem. E01 containers do not expose
their contents as regular paths, so the orchestrator needs a way to
ship chosen in-container paths out to a session tmpdir. This module
exposes that operation as a single wrapper so the MCP surface stays
SRP-clean and the Thymus audit trail captures every byte we pull
off evidence.

Design notes (see ADR-012):

* ``ifind -n <container-path>`` resolves an in-container path to an
  inode; ``icat <image> <inode>`` streams the inode's content. One
  extraction = 2 subprocesses per path.
* SHA-256 is computed while the bytes are written, so the returned
  manifest is the single source of truth for audit.
* Traversal / absolute-path attacks on the ``paths`` list are
  rejected before any subprocess runs.
* Truncation at ``AGENTROPIX_EXTRACT_MAX_BYTES`` prevents runaway
  extractions on a pathological hive.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import shutil
import time
from pathlib import Path

from pydantic import BaseModel, Field

from agentropix_mcp import _trace
from agentropix_mcp._env import get_float, get_int
from agentropix_mcp.wrappers.tsk import fls as _tsk_fls

logger = logging.getLogger(__name__)

DEFAULT_ICAT = "icat"
DEFAULT_IFIND = "ifind"

# Default 256 MiB — registry hives are typically < 50 MiB. A cap here
# is defense-in-depth, not a strict requirement.
_DEFAULT_MAX_BYTES = 256 * 1024 * 1024
# 64 KiB read chunk — SHA-256 update overhead is negligible at this size.
_CHUNK = 64 * 1024

# SIFT-W-255 (2026-05-25): TSK ifind -n halts at NTFS reparse-point
# boundaries. Junction inodes resolve when they're the terminal path
# segment, but any deeper path that crosses one returns "File not
# found" — confirmed live on /cases/SRL-2018/base-file-cdrive.E01:
# `/Users/Administrator/My Documents/desktop.ini` misses, the
# canonical `/Users/Administrator/Documents/desktop.ini` succeeds.
# This map covers the English Windows junction set (Vista through
# Server 2025) so we can retry a missed path with the canonical form.
# Non-English variants (e.g. Spanish `Mis documentos`) tracked in W-260.
_WINDOWS_JUNCTION_REWRITES = {
    "My Documents": "Documents",
    "My Music": "Music",
    "My Pictures": "Pictures",
    "My Videos": "Videos",
    "Application Data": "AppData/Roaming",
    "Local Settings/Application Data": "AppData/Local",
    "Local Settings/Temp": "AppData/Local/Temp",
    "Local Settings/History": "AppData/Local/Microsoft/Windows/History",
    "Local Settings": "AppData/Local",
    "Cookies": "AppData/Local/Microsoft/Windows/INetCookies",
    "Recent": "AppData/Roaming/Microsoft/Windows/Recent",
    "NetHood": "AppData/Roaming/Microsoft/Windows/Network Shortcuts",
    "PrintHood": "AppData/Roaming/Microsoft/Windows/Printer Shortcuts",
    "SendTo": "AppData/Roaming/Microsoft/Windows/SendTo",
    "Start Menu": "AppData/Roaming/Microsoft/Windows/Start Menu",
    "Templates": "AppData/Roaming/Microsoft/Windows/Templates",
    "Documents and Settings": "Users",
}


def _rewrite_reparse_segments(normalised: str) -> str | None:
    """Substitute known Windows junction segments with their canonical targets.

    Returns the rewritten path (always leading-slash form) if at least
    one substitution applied, or None if the path contained no known
    junction segment. Matches longest-key-first so multi-segment keys
    like ``Local Settings/Application Data`` win over the bare
    ``Local Settings``. Case-sensitive (NTFS junctions are created
    case-insensitive but stored with the original case at MFT-creation
    time; matching the stored case is correct).
    """
    rewritten = normalised
    changed = False
    for src in sorted(_WINDOWS_JUNCTION_REWRITES, key=len, reverse=True):
        token_mid = f"/{src}/"
        token_end = f"/{src}"
        replacement = _WINDOWS_JUNCTION_REWRITES[src]
        if token_mid in rewritten:
            rewritten = rewritten.replace(token_mid, f"/{replacement}/")
            changed = True
        elif rewritten.endswith(token_end):
            rewritten = rewritten[: -len(token_end)] + f"/{replacement}"
            changed = True
    return rewritten if changed else None


def _resolve_icat() -> str:
    return os.environ.get("AGENTROPIX_ICAT_TOOL", DEFAULT_ICAT)


def _resolve_ifind() -> str:
    return os.environ.get("AGENTROPIX_IFIND_TOOL", DEFAULT_IFIND)


class ExtractedFile(BaseModel):
    """One row of the extraction manifest."""

    src_path: str  # in-container path as requested (normalised)
    inode: str  # resolved via ifind
    dest: str  # on-host absolute path
    size: int  # bytes actually written
    sha256: str  # hex digest over ``size`` bytes
    truncated: bool = False  # True if write stopped at ``max_bytes``
    duration_ms: float = 0.0
    # W-255: original requested path, populated only when the wrapper
    # rewrote a Windows junction segment (e.g. ``My Documents`` ->
    # ``Documents``) to traverse a TSK ifind reparse-point dead-end.
    # None on the happy path. Preserves forensic provenance: the
    # canonical path is in ``src_path``; what the caller asked for is
    # in ``rewrote_from``.
    rewrote_from: str | None = None
    # W-265: True when this row was extracted by direct inode reference
    # (caller passed an int in ``paths``) rather than a container path
    # resolved through ``ifind``. ``src_path`` then reads ``<inode:N>``
    # and ``inode`` carries N. Lets auditors distinguish path-resolved
    # extractions from inode-direct ones (e.g. DPAPI master keys cited
    # by MFT entry number).
    inode_only: bool = False


class ExtractHint(BaseModel):
    """Diagnostic suggestion attached when a path missed because of a
    likely NTFS reparse-point traversal (W-255)."""

    path: str  # original requested path that missed
    reason: str  # human-readable explanation
    suggested_path: str  # canonical equivalent that may resolve


class ExtractManifest(BaseModel):
    """Structured result of a single ``extract_files`` call."""

    image_path: str
    offset: int = 0
    fstype: str = ""
    dest_dir: str
    entry_count: int
    extracted: list[ExtractedFile] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)
    rejected: list[str] = Field(default_factory=list)
    tool: str = "sleuthkit.icat"
    raw_stderr: str = ""
    # W-255: diagnostic hints for missed paths whose normalised form
    # contains a known Windows junction segment. Empty on the happy
    # path; one entry per path-that-missed-and-matched-a-junction.
    hints: list[ExtractHint] = Field(default_factory=list)


class ExtractValidationError(ValueError):
    """Raised when an in-container path fails normalisation checks."""


def _normalise_container_path(raw: str) -> str:
    """Canonicalise an in-container path for TSK consumption.

    * Rejects empty strings, ``..`` segments, and NUL bytes.
    * Converts Windows backslashes to forward slashes.
    * Strips a single leading slash (TSK treats paths as root-relative).
    * Host-absolute paths (leading ``/`` that resolves to something like
      ``/etc/passwd`` on the calling host) cannot be distinguished from
      E01-absolute paths here, but since ``ifind -n`` is scoped to the
      image being processed, the worst case is a missing-path miss.
    """
    if raw is None:
        raise ExtractValidationError("path is None")
    if "\x00" in raw:
        raise ExtractValidationError(f"NUL byte in path: {raw!r}")
    cleaned = raw.replace("\\", "/").strip()
    if not cleaned:
        raise ExtractValidationError("empty path")
    # Reject traversal in any segment (post-normalisation).
    segments = [s for s in cleaned.split("/") if s]
    if not segments:
        raise ExtractValidationError(f"path resolves to empty: {raw!r}")
    for seg in segments:
        if seg == "..":
            raise ExtractValidationError(f"path traversal not allowed: {raw!r}")
    return "/" + "/".join(segments)


def _safe_dest_path(dest_dir: Path, src: str) -> Path:
    """Build a dest file path under ``dest_dir``, guarding against escape."""
    dest_dir_resolved = dest_dir.resolve()
    candidate = (dest_dir_resolved / Path(src).name).resolve()
    try:
        candidate.relative_to(dest_dir_resolved)
    except ValueError as exc:
        raise ExtractValidationError(f"destination escapes dest_dir: {candidate}") from exc
    return candidate


async def _run_ifind(
    image: Path,
    in_path: str,
    *,
    offset: int,
    fstype: str | None,
    timeout: float,
) -> tuple[str, str]:
    """Resolve ``in_path`` to an inode via ``ifind -n``.

    Returns ``(inode, stderr)``. Raises ``FileNotFoundError`` if the
    ``ifind`` binary isn't on PATH. An empty or non-numeric inode
    result is returned as ``("", stderr)`` so the caller can record it
    in ``manifest.missing``.
    """
    tool = _resolve_ifind()
    binary = shutil.which(tool)
    if not binary:
        raise FileNotFoundError(
            f"{tool} not found on PATH — install sleuthkit or set AGENTROPIX_IFIND_TOOL"
        )
    cmd = [binary]
    if offset:
        cmd.extend(["-o", str(offset)])
    if fstype:
        cmd.extend(["-f", fstype])
    cmd.extend(["-n", in_path, str(image)])

    logger.info("Running: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        # Bug B hardening — ``communicate()`` reads stdout + stderr
        # concurrently internally, so this is fine for ifind (small
        # output). Wrapped in ``wait_for`` for a hard timeout, with a
        # bounded reap on cancellation to avoid zombies.
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        await _kill_and_reap(proc)
        raise TimeoutError(f"ifind timed out after {timeout}s on {in_path}") from None

    stdout = stdout_bytes.decode(errors="replace").strip()
    stderr = stderr_bytes.decode(errors="replace")

    if proc.returncode != 0:
        return "", stderr
    # ifind may print multiple lines; we want the last numeric token.
    token = ""
    for line in stdout.splitlines():
        candidate = line.strip()
        if candidate and candidate[0].isdigit():
            token = candidate.split()[0]
    return token, stderr


async def _kill_and_reap(proc: asyncio.subprocess.Process) -> None:
    """Kill a subprocess and reap the zombie within a bounded budget.

    Bug B hardening (2026-04-25): plain ``proc.kill()`` sends SIGKILL but
    does NOT wait for the kernel to reap the process. Without
    ``proc.wait()``, the next ``ps -ef`` shows a defunct ``<defunct>`` row
    and asyncio holds onto its transport. Cap the wait at 2 s so a wedged
    SIGKILL doesn't replace one wedge with another.
    """
    if proc.returncode is None:
        proc.kill()
    try:
        await asyncio.wait_for(proc.wait(), timeout=2.0)
    except (TimeoutError, ProcessLookupError):
        pass


DEFAULT_ISTAT = "istat"


def _resolve_istat() -> str:
    return os.environ.get("AGENTROPIX_ISTAT_TOOL", DEFAULT_ISTAT)


# SIFT-W-264 (2026-05-25): regex to extract the ``Size:`` line that
# TSK ``istat`` emits in its metadata block. Format is "Size: <int>".
# Anchored to bol to avoid matching `Resident size`/`Allocated size`
# lines that appear in NTFS-specific output sections further down.
_ISTAT_SIZE_RE = re.compile(r"^Size:\s+(\d+)\s*$", re.MULTILINE)


async def _run_istat(
    image: Path,
    inode: str,
    *,
    offset: int,
    fstype: str | None,
    timeout: float,
) -> int | None:
    """Return the expected file size in bytes for ``inode``, or None on parse-fail.

    SIFT-W-264: needed to detect silent-truncation in ``_run_icat`` —
    when icat exits early after writing some bytes (typical EWF
    corrupted-chunk pattern), `written` alone cannot tell us whether
    the result is complete. ``istat`` gives the authoritative MFT-
    recorded file size; comparing `written < expected_size` lets us
    flip ``truncated=True`` deterministically instead of trusting only
    the rc-and-max_bytes heuristic.

    Returns None (not raises) on tool-missing, parse-fail, or non-zero
    rc — the caller treats `None` as "no expected_size signal", which
    falls back to the prior heuristic-only behaviour. Adding ~30-80ms
    per extracted file is acceptable for forensic correctness; the
    existing AGENTROPIX_EXTRACT_CONCURRENCY semaphore caps blast.
    """
    tool = _resolve_istat()
    binary = shutil.which(tool)
    if not binary:
        return None
    cmd = [binary]
    if offset:
        cmd.extend(["-o", str(offset)])
    if fstype:
        cmd.extend(["-f", fstype])
    cmd.extend([str(image), inode])

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        await _kill_and_reap(proc)
        return None

    if proc.returncode != 0:
        return None
    match = _ISTAT_SIZE_RE.search(stdout_bytes.decode(errors="replace"))
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


# SIFT-W-264: TSK icat stderr patterns that indicate the read hit a
# corrupted region of the image (typical for damaged EWF chunks). We
# treat any match as a secondary signal that the extraction is
# incomplete even when istat-derived expected_size is unavailable.
_ICAT_READ_ERROR_RE = re.compile(
    r"(error reading sector|invalid chunk|read error|cannot read|short read)",
    re.IGNORECASE,
)


async def _run_icat(
    image: Path,
    inode: str,
    dest: Path,
    *,
    offset: int,
    fstype: str | None,
    max_bytes: int,
    timeout: float,
    expected_size: int | None = None,
) -> tuple[int, str, bool, str]:
    """Stream ``inode`` content from ``image`` into ``dest``.

    Returns ``(bytes_written, sha256_hex, truncated, stderr_text)``.

    Bug B hardening (2026-04-25):
      * stderr is drained CONCURRENTLY with stdout. A subprocess that
        produces noisy stderr (TSK ``icat`` is chatty on filesystem
        warnings) would otherwise fill the 64 KiB stderr pipe buffer,
        block the subprocess on its next stderr write, and deadlock the
        parent's stdout drain — classic pipe deadlock. The user's "4-min
        wedge on any path" symptom matches this pattern.
      * The post-drain ``proc.communicate()`` is replaced with a clean
        ``proc.wait()`` after the concurrent gather. ``communicate()``
        would have re-tried the already-drained stdout and could
        legitimately wedge if the subprocess emitted late stderr.
      * On timeout we invoke ``_kill_and_reap`` to ensure no zombie
        process lingers (matches the user's "leaked subprocess holding
        a lock" hypothesis).

    SIFT-W-264 (2026-05-25): silent-truncation hardening.
      * ``expected_size`` (from a prior ``_run_istat`` call) is the
        MFT-recorded file size. When provided, we flip ``truncated`` to
        True if ``written < min(expected_size, max_bytes)`` — closes the
        case where icat exits early after writing one valid chunk on a
        damaged EWF region. Without ``expected_size`` the function falls
        back to the prior heuristic-only behaviour (rc-and-max_bytes).
      * stderr is now returned to the caller (4th tuple element) so
        ``extract_files`` can fold short-read diagnostics into the
        per-row record AND raise/escalate when rc != 0 with bytes
        already written.
      * Secondary signal: if stderr matches `_ICAT_READ_ERROR_RE`,
        ``truncated`` is set regardless of byte count — belt-and-braces
        when istat returned None (tool missing, parse-fail, or non-MFT
        filesystem). istat is the primary; regex is the fallback.
    """
    tool = _resolve_icat()
    binary = shutil.which(tool)
    if not binary:
        raise FileNotFoundError(
            f"{tool} not found on PATH — install sleuthkit or set AGENTROPIX_ICAT_TOOL"
        )
    cmd = [binary]
    if offset:
        cmd.extend(["-o", str(offset)])
    if fstype:
        cmd.extend(["-f", fstype])
    cmd.extend([str(image), inode])

    logger.info("Running: %s -> %s", " ".join(cmd), dest)
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert proc.stdout is not None
    assert proc.stderr is not None

    digest = hashlib.sha256()
    written = 0
    truncated = False
    stderr_chunks: list[bytes] = []

    async def _drain_stdout() -> None:
        nonlocal written, truncated
        with dest.open("wb") as fh:
            while True:
                chunk = await proc.stdout.read(_CHUNK)  # type: ignore[union-attr]
                if not chunk:
                    return
                remaining = max_bytes - written
                if remaining <= 0:
                    truncated = True
                    return
                if len(chunk) > remaining:
                    chunk = chunk[:remaining]
                    truncated = True
                fh.write(chunk)
                digest.update(chunk)
                written += len(chunk)
                if truncated:
                    return

    async def _drain_stderr() -> None:
        # Cap stderr accumulation at 16 KiB to avoid memory blowups on a
        # pathologically chatty subprocess. The first 16 KiB is plenty for
        # diagnostic context.
        cap = 16 * 1024
        seen = 0
        while seen < cap:
            chunk = await proc.stderr.read(min(_CHUNK, cap - seen))  # type: ignore[union-attr]
            if not chunk:
                return
            stderr_chunks.append(chunk)
            seen += len(chunk)

    try:
        # Gather both drains concurrently — fixes the pipe-deadlock pattern.
        await asyncio.wait_for(
            asyncio.gather(_drain_stdout(), _drain_stderr(), return_exceptions=False),
            timeout=timeout,
        )
    except TimeoutError:
        await _kill_and_reap(proc)
        raise TimeoutError(f"icat timed out after {timeout}s on inode {inode}") from None

    # Reap the subprocess so we get returncode without re-draining the pipes.
    try:
        await asyncio.wait_for(proc.wait(), timeout=5.0)
    except TimeoutError:
        await _kill_and_reap(proc)

    stderr = b"".join(stderr_chunks).decode(errors="replace")
    # SIFT-W-264 (2026-05-25): silent-truncation detection.
    #   (a) Primary signal — istat-derived expected_size: if we got
    #       fewer bytes than the MFT records, flag the result as
    #       truncated even when icat exited cleanly. ``min(expected,
    #       max_bytes)`` accounts for caller-imposed caps.
    #   (b) Secondary signal — stderr regex: catches icat warnings
    #       like "Error reading sector" when istat was unavailable
    #       (no MFT, non-NTFS, tool missing). Treated as advisory.
    #   (c) Tightened rc-check: when icat exited non-zero with
    #       expected_size provided AND not reached, raise so the row
    #       lands in ``missing[]`` instead of a stub in ``extracted[]``.
    short_read = expected_size is not None and written < min(expected_size, max_bytes)
    if short_read or _ICAT_READ_ERROR_RE.search(stderr):
        truncated = True
    if proc.returncode not in (0, None) and (written == 0 or short_read):
        raise RuntimeError(f"icat failed (rc={proc.returncode}) for inode {inode}: {stderr[:300]}")
    return written, digest.hexdigest(), truncated, stderr


async def extract_files(
    image: str | Path,
    paths: list[str | int],
    dest: str | Path,
    *,
    offset: int = 0,
    fstype: str | None = None,
    timeout: float | None = None,
    max_bytes: int | None = None,
    follow_reparse_points: bool = True,
    expand_dirs: bool = False,
    max_dir_files: int | None = None,
) -> ExtractManifest:
    """Extract ``paths`` from ``image`` into ``dest``.

    Args:
        image: Path to disk image (E01 / raw / vmdk).
        paths: List of in-container paths to extract. Windows-style
            backslashes accepted; traversal tokens rejected. An entry
            may also be an ``int`` inode number (W-265): it is streamed
            directly via ``icat`` (no ``ifind`` path resolution), written
            to ``inode-<N>`` in ``dest``, and flagged ``inode_only`` in
            the manifest. Inodes must satisfy ``0 < N < 2**48``.
        dest: Directory to write extracted files into. Must exist and
            be a directory.
        offset: Partition offset in sectors (multi-partition images).
        fstype: Filesystem type override (e.g. ``ntfs``, ``ext4``).
        timeout: Per-file wall-clock budget (seconds).
        max_bytes: Per-file byte cap.
        follow_reparse_points: When True (default), retry an ``ifind``
            miss once with known Windows junction segments rewritten
            to their canonical equivalents (e.g. ``My Documents`` ->
            ``Documents``). Works around TSK ifind's inability to
            traverse NTFS reparse-point segments mid-path (W-255).
            Set False for byte-for-byte path fidelity in forensic
            workflows that need to record the caller's exact request.

    Raises:
        FileNotFoundError: Image missing or ``icat`` / ``ifind`` not
            on PATH.
        ValueError: ``dest`` is not an existing directory or contains
            no accepted paths. Propagates ``ExtractValidationError``
            subclasses for per-path issues only when **every** path
            was rejected.
        TimeoutError: A single extraction exceeded its budget.

    Returns:
        ExtractManifest — rows for every path: either in ``extracted``
        (bytes + sha256; ``rewrote_from`` populated when W-255 retry
        succeeded), ``missing`` (ifind miss after retry), or
        ``rejected`` (validation failure). ``hints`` carries
        diagnostic suggestions for missed paths whose normalised form
        contained a known Windows junction segment.
    """
    image_path = Path(image)
    if not image_path.exists():
        raise FileNotFoundError(f"Image not found: {image_path}")

    dest_dir = Path(dest)
    if not dest_dir.exists() or not dest_dir.is_dir():
        raise ValueError(f"dest must be an existing directory: {dest_dir}")

    if timeout is None:
        # Bug B hardening (2026-04-25): default lowered 120 → 60 s. A
        # legitimate ifind/icat against an extracted hive completes in
        # well under 1 s; the prior 120 s allowed two stacked timeouts
        # (ifind + icat) to add up to a 4-minute wedge that visibly
        # blocked judges' interactive sessions.
        timeout = get_float("AGENTROPIX_EXTRACT_TIMEOUT", 60.0, floor=5.0, ceiling=3600.0)
    if max_bytes is None:
        max_bytes = get_int(
            "AGENTROPIX_EXTRACT_MAX_BYTES",
            _DEFAULT_MAX_BYTES,
            floor=1024,
            ceiling=16 * 1024 * 1024 * 1024,  # 16 GiB hard ceiling
        )
    # NIST1 ISSUE-008 (N8a): per-directory child cap when expand_dirs is set.
    dir_cap = (
        max_dir_files
        if max_dir_files is not None
        else get_int("AGENTROPIX_EXTRACT_MAX_DIR_FILES", 512, floor=1, ceiling=10000)
    )

    if not paths:
        return ExtractManifest(
            image_path=str(image_path),
            offset=offset,
            fstype=fstype or "",
            dest_dir=str(dest_dir.resolve()),
            entry_count=0,
        )

    extracted: list[ExtractedFile] = []
    missing: list[str] = []
    rejected: list[str] = []
    hints: list[ExtractHint] = []
    stderr_accum: list[str] = []

    for raw_path in paths:
        t0 = time.monotonic()
        rewrote_from: str | None = None
        inode_only = False

        # W-265: a caller may pass an integer inode directly (e.g.
        # "extract MFT entry 12095" for a DPAPI master key the caller
        # already located) instead of a container path. TSK ``icat``
        # accepts an inode natively, so we skip ``_normalise_container_path``
        # and ``_run_ifind`` entirely and stream the inode straight out.
        if isinstance(raw_path, int):
            # Range guard: NTFS/ext inode numbers are positive and well
            # under 2**48; negative or absurd values are invalid by
            # construction. (bool is an int subclass — reject it too.)
            if isinstance(raw_path, bool) or not (0 < raw_path < 2**48):
                logger.warning("Rejecting out-of-range inode %r", raw_path)
                rejected.append(str(raw_path))
                continue
            inode = str(raw_path)
            normalised = f"<inode:{raw_path}>"
            dest_file = dest_dir / f"inode-{raw_path}"
            inode_only = True
            ifind_err = ""
        else:
            try:
                normalised = _normalise_container_path(raw_path)
            except ExtractValidationError as exc:
                logger.warning("Rejecting path %r: %s", raw_path, exc)
                rejected.append(raw_path)
                continue

            try:
                dest_file = _safe_dest_path(dest_dir, normalised)
            except ExtractValidationError as exc:
                logger.warning("Rejecting dest for path %r: %s", raw_path, exc)
                rejected.append(raw_path)
                continue

            inode, ifind_err = await _run_ifind(
                image_path,
                normalised,
                offset=offset,
                fstype=fstype,
                timeout=timeout,
            )
            if ifind_err:
                stderr_accum.append(ifind_err[:200])

        # W-255 / W-270: ifind missed. Before declaring this path lost,
        # see if the normalised form contains a known Windows junction
        # segment (e.g. "My Documents", "Local Settings") that TSK can't
        # traverse through. When ``follow_reparse_points`` is True we
        # retry once with the canonical rewrite and emit the hint ONLY
        # when that retry actually resolves to an inode — pattern-match
        # alone over-emits on XP-era images where "My Documents" is a
        # real allocated directory (not a Vista+ junction). When
        # ``follow_reparse_points`` is False (forensic-strict) no retry
        # happens, so the unconditional emit is the only signal the
        # caller gets — they explicitly opted out of canonical
        # resolution and treat the hint as advisory.
        #
        # W-265: guarded by ``if not inode`` — an inode-direct extraction
        # always has ``inode`` set here, so this whole block is a no-op
        # for it and control falls straight through to istat + icat.
        if not inode:
            suggested = _rewrite_reparse_segments(normalised)
            if suggested is not None:
                hint = ExtractHint(
                    path=normalised,
                    reason=(
                        "TSK ifind cannot traverse NTFS reparse-point "
                        "(junction) segments mid-path; this path likely "
                        "crosses a Windows compatibility junction"
                    ),
                    suggested_path=suggested,
                )
                if follow_reparse_points:
                    logger.info(
                        "W-255 retry: %r -> %r (junction rewrite)",
                        normalised,
                        suggested,
                    )
                    inode, ifind_err = await _run_ifind(
                        image_path,
                        suggested,
                        offset=offset,
                        fstype=fstype,
                        timeout=timeout,
                    )
                    if ifind_err:
                        stderr_accum.append(ifind_err[:200])
                    if inode:
                        # Retry resolved — surface the hint so the
                        # caller learns about the rewrite that worked,
                        # and preserve forensic provenance.
                        hints.append(hint)
                        rewrote_from = normalised
                        normalised = suggested
                    # else: retry also missed (XP false-positive case) —
                    # suppress the hint to avoid sending the caller
                    # down a dead-end path.
                else:
                    # Forensic-strict: no retry, so the advisory hint
                    # is the only signal we can emit.
                    hints.append(hint)

        if not inode:
            missing.append(normalised)
            _trace.record(
                "mcp.extract_files.ifind",
                (time.monotonic() - t0) * 1000,
                f"miss {normalised}",
            )
            continue

        # NIST1 ISSUE-008 (N8a): directory extraction. When ``expand_dirs`` is
        # set, fls -r the resolved inode; if it lists regular-file children the
        # path is a directory — extract each child by inode preserving the
        # relative tree, then skip the single-file icat. A plain file lists no
        # children and falls through to the normal icat path below. Unblocks
        # feeding e.g. ``C:\WINDOWS\Prefetch`` to get_prefetch in one call.
        if expand_dirs and not inode_only:
            try:
                listing = await _tsk_fls(
                    image_path,
                    offset=offset,
                    inode=inode,
                    recursive=True,
                    fstype=fstype,
                    timeout=timeout,
                )
                child_files = [e for e in listing.entries if e.entry_type == "r" and e.inode]
            except (RuntimeError, TimeoutError) as exc:
                logger.warning("expand_dirs fls failed for %s: %s", normalised, exc)
                child_files = []
            if child_files:
                for child in child_files[:dir_cap]:
                    rel = child.full_path.lstrip("/") or child.name
                    try:
                        child_dest = _safe_dest_path(dest_dir, f"{normalised}/{rel}")
                    except ExtractValidationError:
                        rejected.append(f"{normalised}/{rel}")
                        continue
                    child_dest.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        c_written, c_sha, c_trunc, _c_err = await _run_icat(
                            image_path,
                            child.inode,
                            child_dest,
                            offset=offset,
                            fstype=fstype,
                            max_bytes=max_bytes,
                            timeout=timeout,
                            expected_size=None,
                        )
                    except (RuntimeError, TimeoutError) as exc:
                        missing.append(f"{normalised}/{rel}")
                        stderr_accum.append(f"{normalised}/{rel}: {str(exc)[:200]}")
                        continue
                    extracted.append(
                        ExtractedFile(
                            src_path=f"{normalised}/{rel}",
                            inode=child.inode,
                            dest=str(child_dest),
                            size=c_written,
                            sha256=c_sha,
                            truncated=c_trunc,
                        )
                    )
                if len(child_files) > dir_cap:
                    stderr_accum.append(
                        f"{normalised}: directory truncated at {dir_cap} of {len(child_files)} files"
                    )
                continue
            # No children → treat as a regular file; fall through to icat below.

        # SIFT-W-264 (2026-05-25): derive expected_size via istat before
        # icat so we can detect silent-truncation on damaged EWF chunks.
        # Result is None on tool-missing / parse-fail / non-MFT
        # filesystem — _run_icat falls back to heuristic-only behavior
        # in that case. ~30-80ms per file; capped by the existing
        # AGENTROPIX_EXTRACT_CONCURRENCY semaphore.
        expected_size = await _run_istat(
            image_path,
            inode,
            offset=offset,
            fstype=fstype,
            timeout=timeout,
        )

        try:
            written, sha256, truncated, icat_stderr = await _run_icat(
                image_path,
                inode,
                dest_file,
                offset=offset,
                fstype=fstype,
                max_bytes=max_bytes,
                timeout=timeout,
                expected_size=expected_size,
            )
        except (RuntimeError, TimeoutError) as exc:
            logger.warning("icat failed for %s (inode %s): %s", normalised, inode, exc)
            missing.append(normalised)
            stderr_accum.append(f"{normalised}: {str(exc)[:200]}")
            _trace.record(
                "mcp.extract_files.icat",
                (time.monotonic() - t0) * 1000,
                f"ERROR: {exc}",
            )
            continue

        # SIFT-W-264: surface short-read diagnostics into the
        # manifest-level raw_stderr so callers (LLM orchestrator,
        # judges) can see why a result is truncated. Only emit when
        # we have actionable signal — keeps the field tight on the
        # happy path.
        if truncated and expected_size is not None and written < expected_size:
            stderr_accum.append(
                f"{normalised}: short read: got {written} of {expected_size} expected"
            )
        if icat_stderr.strip() and _ICAT_READ_ERROR_RE.search(icat_stderr):
            stderr_accum.append(f"{normalised}: {icat_stderr.strip()[:200]}")

        elapsed_ms = (time.monotonic() - t0) * 1000
        extracted.append(
            ExtractedFile(
                src_path=normalised,
                inode=inode,
                dest=str(dest_file),
                size=written,
                sha256=sha256,
                truncated=truncated,
                duration_ms=round(elapsed_ms, 2),
                rewrote_from=rewrote_from,
                inode_only=inode_only,
            )
        )
        _trace.record(
            "mcp.extract_files.icat",
            elapsed_ms,
            f"ok {normalised} -> {written}B sha256={sha256[:12]}",
        )

    return ExtractManifest(
        image_path=str(image_path),
        offset=offset,
        fstype=fstype or "",
        dest_dir=str(dest_dir.resolve()),
        entry_count=len(extracted),
        extracted=extracted,
        missing=missing,
        rejected=rejected,
        raw_stderr="\n".join(stderr_accum)[:1000],
        hints=hints,
    )
