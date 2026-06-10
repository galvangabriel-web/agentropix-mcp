"""``bulk_extractor`` feature-scanner wrapper.

Drives the system ``bulk_extractor`` binary (Simson Garfinkel /
forensicswiki BE 1.6.x, installed by default on SIFT Workstation)
against a disk image, mounted volume, or extracted file tree. Unlike
the other wrappers in this package, ``bulk_extractor`` writes its
output to an *output directory* rather than stdout — it produces one
"feature file" per recorder (email, url, ip, ccn, exif, etc.) plus a
``report.xml`` run summary.

The wrapper invocation is:

    bulk_extractor -o <outdir> [-E <scan>] [-x <scan>]... <target>

``-o <outdir>`` is mandatory and the directory must NOT exist — BE
refuses to overwrite. Callers that want to re-run against the same
path must pass a fresh ``out_dir`` or enable ``zap=True`` (emits
``-Z``, which instructs BE to erase the output directory before
writing).

Output feature files follow a stable shape across BE versions:

    # BANNER ...
    # BULK_EXTRACTOR-Version: <ver>
    # Feature-Recorder: <recorder>
    # Filename: <input>
    # Feature-File-Version: 1.1
    <offset>\t<feature>\t<context>

``<offset>`` is a byte offset (integer or ``page-offset`` form for
carved content). ``<feature>`` is the extracted value; ``<context>``
is a short surrounding slice with non-printable bytes rendered as
``\\xNN`` escapes. Histogram files (``*_histogram.txt``) are a
different format and are skipped by default — they are derivations
of the raw feature files.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
import tempfile
from pathlib import Path

from pydantic import BaseModel, Field

from agentropix_mcp._env import get_float, get_int

logger = logging.getLogger(__name__)

DEFAULT_TOOL_NAME = "bulk_extractor"

# Recorder output file names ending with these suffixes are *derived*
# artifacts (histograms, stoplists); skip them when aggregating raw
# features so counts reflect actual hits.
_DERIVED_SUFFIXES = ("_histogram.txt", "_stopped.txt")

# EWF/E01 container extensions that require pre-mounting before BE can
# scan them (the deb-packaged bulk_extractor is compiled without libewf).
_EWF_EXTENSIONS = frozenset({".e01", ".ewf", ".s01", ".e02"})

# W-096 + W-119: bulk_extractor scans bytes literally and cannot peer
# inside a compressed envelope. When the input is a single archive file,
# feature yield drops by orders of magnitude vs the same logical content
# as a raw image (measured on SRL-2018 DC). The detector returns a
# (label, severity, yield_ratio) triple per magic match so the wrapper
# can surface format-specific guidance to operators:
#
#   - severity="WARNING" — opaque containers (LZMA-family, bzip2, RAR,
#     LZ4, Zstandard). bulk_extractor sees zero structured content
#     inside; feature counts are effectively meaningless.
#   - severity="NOTE" — partially-transparent containers (ZIP/deflate,
#     gzip). BE recovers some plaintext from low-entropy regions of the
#     compressed stream but yield is still far below the raw-input
#     baseline.
#
# Yield ratios are the SRL-2018 DC measurements: 1 raw image = 1.748M
# features; .7z of the same image yielded fewer than 10 features
# (>175,000x reduction); .zip yielded ~3,000 features (~582x reduction).
_COMPRESSED_MAGIC: tuple[tuple[bytes, str, str, str], ...] = (
    (b"\x37\x7a\xbc\xaf\x27\x1c", "7z (LZMA2)", "WARNING", "~175,000x reduction (SRL-2018 DC)"),
    (b"\xfd7zXZ\x00", "XZ (LZMA)", "WARNING", "~100,000x reduction (LZMA-class opacity)"),
    (b"BZh", "bzip2", "WARNING", "~50,000x reduction (block-sorted opacity)"),
    (b"\x04\x22\x4d\x18", "LZ4", "WARNING", "~10,000x reduction (frame-level opacity)"),
    (b"\x28\xb5\x2f\xfd", "Zstandard", "WARNING", "~10,000x reduction (dictionary opacity)"),
    (b"Rar!\x1a\x07", "RAR", "WARNING", "~50,000x reduction (proprietary opacity)"),
    (b"PK\x03\x04", "ZIP (deflate)", "NOTE", "~582x reduction (SRL-2018 DC)"),
    (b"PK\x05\x06", "ZIP (empty archive)", "NOTE", "empty container; expect ~0 features"),
    (b"PK\x07\x08", "ZIP (split archive)", "NOTE", "~582x reduction (deflate-class)"),
    (b"\x1f\x8b", "gzip", "NOTE", "~500x reduction (deflate stream)"),
)


def _detect_compressed_input(path: Path) -> tuple[str, str, str] | None:
    """Return ``(label, severity, yield_ratio)`` if ``path`` is a
    compressed archive whose contents bulk_extractor cannot scan
    representatively, else None.

    Severity is ``"WARNING"`` for fully-opaque formats (LZMA-family,
    bzip2, RAR, LZ4, Zstandard) where feature yield collapses to
    near-zero, ``"NOTE"`` for partially-transparent formats (ZIP,
    gzip) where some plaintext leaks but yield is still far below
    raw-input baseline.

    Only fires for single files. Directories (recursive scan) and EWF
    images (transparent ewfmount handling) are explicitly skipped — for
    those, bulk_extractor sees the underlying content correctly.
    """
    try:
        if not path.is_file():
            return None
    except OSError:
        return None
    if path.suffix.lower() in _EWF_EXTENSIONS:
        return None
    try:
        with path.open("rb") as fh:
            head = fh.read(8)
    except OSError:
        return None
    for magic, label, severity, yield_ratio in _COMPRESSED_MAGIC:
        if head.startswith(magic):
            return (label, severity, yield_ratio)
    return None


def _resolve_tool() -> str:
    """Resolve the bulk_extractor binary, honouring AGENTROPIX_BE_TOOL."""
    return os.environ.get("AGENTROPIX_BE_TOOL", DEFAULT_TOOL_NAME)


def _resolve_ewfmount_tool() -> str:
    return os.environ.get("AGENTROPIX_EWFMOUNT_TOOL", "ewfmount")


def _resolve_fusermount_tool() -> str:
    return os.environ.get("AGENTROPIX_FUSERMOUNT_TOOL", "fusermount")


def _ewfmount_timeout() -> float:
    return get_float("AGENTROPIX_EWFMOUNT_TIMEOUT", 30.0, floor=5.0, ceiling=300.0)


def _fusermount_timeout() -> float:
    return get_float("AGENTROPIX_FUSERMOUNT_TIMEOUT", 10.0, floor=2.0, ceiling=60.0)


def _lazy_umount() -> bool:
    return os.environ.get("AGENTROPIX_EWFMOUNT_LAZY_UMOUNT", "true").lower() not in (
        "0",
        "false",
        "no",
    )


def _ewf_tmpdir() -> str | None:
    return os.environ.get("AGENTROPIX_EWF_TMPDIR") or None


def _is_ewf(path: Path) -> bool:
    return path.suffix.lower() in _EWF_EXTENSIONS


async def _ewf_mount(image: Path, mount_dir: Path) -> Path:
    """FUSE-mount an EWF image and return the path to the raw block device.

    Creates ``mount_dir`` and calls ``ewfmount <image> <mount_dir>``.
    The mounted raw surface appears as ``<mount_dir>/ewf1``.
    """
    mount_dir.mkdir(parents=True, exist_ok=True)
    ewfmount = _resolve_ewfmount_tool()
    proc = await asyncio.create_subprocess_exec(
        ewfmount,
        str(image),
        str(mount_dir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, err_bytes = await asyncio.wait_for(proc.communicate(), timeout=_ewfmount_timeout())
    if proc.returncode != 0:
        err = err_bytes.decode(errors="replace")[:300]
        raise RuntimeError(f"{ewfmount} failed (rc={proc.returncode}): {err}")
    raw = mount_dir / "ewf1"
    if not raw.exists():
        raise RuntimeError(
            f"{ewfmount} succeeded but {raw} not found — image may be multi-segment or corrupt"
        )
    return raw


async def _ewf_unmount(mount_dir: Path) -> None:
    """FUSE-unmount and ignore errors (called from finally blocks).

    Uses ``fusermount -uz`` (lazy) by default so a killed BE subprocess
    that still holds fds on the mount does not cause EBUSY.
    """
    fusermount = shutil.which(_resolve_fusermount_tool())
    if fusermount is None:
        return
    flags = "-uz" if _lazy_umount() else "-u"
    try:
        proc = await asyncio.create_subprocess_exec(
            fusermount,
            flags,
            str(mount_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=_fusermount_timeout())
    except Exception:
        pass


class BulkFeature(BaseModel):
    """One extracted feature row."""

    recorder: str
    offset: str
    feature: str
    context: str = ""


class BulkReport(BaseModel):
    """Aggregated output of a bulk_extractor run."""

    target: str
    out_dir: str
    feature_count: int = 0
    features: list[BulkFeature] = Field(default_factory=list)
    per_recorder_counts: dict[str, int] = Field(default_factory=dict)
    recorders: list[str] = Field(default_factory=list)
    # NIST1 ISSUE-003: recorder name → full feature-file path on disk, so an
    # agent can fetch the complete values that the inline ``features`` cap omits.
    recorder_files: dict[str, str] = Field(default_factory=dict)
    # NIST1 ISSUE-007: the path bulk_extractor actually scanned. Differs from
    # ``target`` when an EWF/E01 was transparently FUSE-mounted (e.g.
    # ``/tmp/agentropix-sift-ewf-XXXX/ewf1``) — surfaced for chain-of-custody.
    resolved_input: str = ""
    # NIST1 RUN2 ISSUE-002: True when the inline feature list was omitted to
    # bound the payload; counts + recorder_files still present.
    summary_only: bool = False
    truncated: bool = False
    tool: str = "bulk_extractor"
    raw_stderr: str = ""
    # SIFT-W-082: SHA-256 of bulk_extractor's raw stdout bytes — chain-of-custody fingerprint.
    raw_stdout_sha256: str = ""
    # W-096: human-readable warning emitted when the scanned target is a
    # compressed archive (7z/zip/gzip/xz/bz2/lz4/zstd/rar). Empty string
    # for raw / EWF / directory targets where BE sees content correctly.
    compressed_input_warning: str = ""
    # W-119: severity stamp for the warning above, lets downstream
    # consumers distinguish opaque containers (LZMA-family, bzip2, RAR,
    # LZ4, Zstandard -> "WARNING") from partially transparent ones
    # (ZIP/deflate, gzip -> "NOTE"). Empty string when no warning fires.
    compressed_input_severity: str = ""


def _parse_feature_file(
    path: Path,
    recorder: str,
    *,
    remaining: int,
) -> tuple[list[BulkFeature], int]:
    """Parse one BE feature file. Returns (rows, total_count).

    Only the first ``remaining`` rows are materialised; ``total_count``
    reflects every data line in the file regardless so callers can
    report the true number and flag truncation.
    """
    rows: list[BulkFeature] = []
    total = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line or line.startswith("#"):
                    continue
                stripped = line.rstrip("\n")
                if not stripped:
                    continue
                total += 1
                if remaining <= 0:
                    continue
                parts = stripped.split("\t")
                if len(parts) < 2:
                    # Malformed row — skip but count it toward total
                    # so downstream sees the anomaly.
                    continue
                offset = parts[0]
                feature = parts[1]
                context = parts[2] if len(parts) >= 3 else ""
                rows.append(
                    BulkFeature(
                        recorder=recorder,
                        offset=offset,
                        feature=feature,
                        context=context,
                    )
                )
                remaining -= 1
    except OSError as exc:
        logger.warning("Could not read feature file %s: %s", path, exc)
        return rows, total
    return rows, total


# NIST1 ISSUE-003: high-signal recorders an analyst almost always wants
# materialized inline (carved emails/URLs/IPs are frequently the crux of a
# case). These are read first so a tight budget can't be exhausted by a
# noisy low-signal recorder (e.g. ``domain``) before they are reached.
_HIGH_SIGNAL_RECORDERS = (
    "email",
    "rfc822",
    "url",
    "ip",
    "telephone",
    "ether",
    "ccn",
)


def _recorder_priority(recorder: str) -> int:
    """Sort key: high-signal recorders first (in listed order), then
    everything else alphabetically (stable via the name tiebreak)."""
    for idx, name in enumerate(_HIGH_SIGNAL_RECORDERS):
        if recorder == name:
            return idx
    return len(_HIGH_SIGNAL_RECORDERS)


def _collect_features(
    out_dir: Path,
    *,
    max_features: int,
) -> tuple[list[BulkFeature], dict[str, int], list[str], bool, dict[str, str]]:
    """Walk ``out_dir`` and aggregate feature rows across all recorders.

    Returns (features, per_recorder_counts, recorders, truncated,
    recorder_files). NIST1 ISSUE-003: the inline ``features`` budget is
    split FAIRLY per recorder (``max_features // n_recorders``) instead of
    first-come-first-served, so high-volume early recorders (alphabetically
    ``domain``) can no longer starve high-value ones (``email``/``url``/
    ``ip``). High-signal recorders are read first. ``per_recorder_counts``
    still reflects the full on-disk count; ``recorder_files`` maps every
    recorder to its full feature-file path so an agent can fetch the
    complete values the inline cap omits.
    """
    all_features: list[BulkFeature] = []
    per_recorder: dict[str, int] = {}
    recorders: list[str] = []
    recorder_files: dict[str, str] = {}
    truncated = False

    if not out_dir.is_dir():
        return all_features, per_recorder, recorders, truncated, recorder_files

    candidates: list[tuple[str, Path]] = []
    for child in sorted(out_dir.iterdir()):
        if not child.is_file() or not child.name.endswith(".txt"):
            continue
        if any(child.name.endswith(suffix) for suffix in _DERIVED_SUFFIXES):
            continue
        candidates.append((child.name[: -len(".txt")], child))

    if not candidates:
        return all_features, per_recorder, recorders, truncated, recorder_files

    # Fair per-recorder share; high-signal recorders read first.
    per_cap = max(1, max_features // len(candidates))
    candidates.sort(key=lambda rc: (_recorder_priority(rc[0]), rc[0]))

    for recorder, child in candidates:
        rows, total = _parse_feature_file(child, recorder, remaining=per_cap)
        if total == 0:
            continue
        recorders.append(recorder)
        per_recorder[recorder] = total
        recorder_files[recorder] = str(child)
        all_features.extend(rows)
        if total > len(rows):
            truncated = True

    return all_features, per_recorder, recorders, truncated, recorder_files


async def run_bulk_extractor(
    target: str | Path,
    out_dir: str | Path,
    *,
    enable_scanners: list[str] | None = None,
    disable_scanners: list[str] | None = None,
    only_scanner: str | None = None,
    zap: bool = False,
    max_features: int | None = None,
    timeout: float | None = None,
    recurse: bool = True,
    summary_only: bool = False,
) -> BulkReport:
    """Run ``bulk_extractor`` against ``target`` and aggregate feature output.

    Args:
        target: File (disk image, raw dump) or directory to scan.
        out_dir: Destination directory for BE output. Must not exist
            unless ``zap=True``.
        enable_scanners: Optional list of scanners to enable (``-e``).
        disable_scanners: Optional list of scanners to disable (``-x``).
        only_scanner: If set, runs BE with ``-E <name>`` (equivalent
            to ``-x all -e <name>``). Wins over the enable/disable
            lists when present.
        zap: Pass ``-Z`` so BE erases ``out_dir`` before writing.
            When False (default) BE exits with an error if ``out_dir``
            already exists.
        max_features: Cap on aggregated feature rows returned in the
            report. Defaults to ``AGENTROPIX_BE_MAX_FEATURES``
            (1000, floor 1, ceiling 1_000_000).
        timeout: Wrapper-level subprocess timeout. Defaults to
            ``AGENTROPIX_BE_TIMEOUT`` (3600 s, floor 60, ceil 86400).
        recurse: When True (default) and the resolved scan target is a
            directory, inject ``-R`` so bulk_extractor walks the entire
            tree instead of only the top level (W-085). Single-file
            targets never get ``-R`` because BE errors on it; pass
            ``recurse=False`` to suppress the flag for directories
            when intentionally scanning only the top level.

    Raises:
        FileNotFoundError: target missing or tool not on PATH.
        RuntimeError: bulk_extractor exits non-zero.
        TimeoutError: subprocess exceeds ``timeout``.
    """
    target_path = Path(target)
    if not target_path.exists():
        raise FileNotFoundError(f"target not found: {target_path}")

    # W-096 + W-119: detect compressed-archive inputs so the report can
    # warn the operator that feature counts are not representative of
    # the underlying evidence. The detector returns severity (WARNING
    # for opaque LZMA-family / bzip2 / RAR / LZ4 / Zstandard, NOTE for
    # partially-transparent ZIP / gzip) plus measured yield-reduction
    # guidance. Done before tool resolution so the warning surfaces
    # even if the scan itself fails.
    compressed_input_warning = ""
    compressed_input_severity = ""
    detected = _detect_compressed_input(target_path)
    if detected is not None:
        compressed_format, compressed_input_severity, yield_ratio = detected
        compressed_input_warning = (
            f"[{compressed_input_severity}] Input appears to be "
            f"{compressed_format}-compressed. bulk_extractor scans bytes "
            "literally and cannot read inside a compressed envelope - "
            f"expect {yield_ratio} vs raw-image baseline. Extract the "
            "archive first (e.g. via the extract_archive MCP tool, W-095) "
            "and re-scan the unpacked tree for representative results."
        )
        log_fn = logger.warning if compressed_input_severity == "WARNING" else logger.info
        log_fn(
            "bulk_extractor compressed-input %s: %s on %s (%s)",
            compressed_input_severity,
            compressed_format,
            target_path,
            yield_ratio,
        )

    out_path = Path(out_dir)

    if timeout is None:
        timeout = get_float(
            "AGENTROPIX_BE_TIMEOUT",
            3600.0,
            floor=60.0,
            ceiling=86_400.0,
        )
    if max_features is None:
        max_features = get_int(
            "AGENTROPIX_BE_MAX_FEATURES",
            1000,
            floor=1,
            ceiling=1_000_000,
        )

    tool_name = _resolve_tool()
    tool_path = shutil.which(tool_name)
    if tool_path is None:
        raise FileNotFoundError(
            f"{tool_name} not found on PATH — install bulk_extractor or set AGENTROPIX_BE_TOOL"
        )

    # EWF/E01 containers require ewfmount pre-processing because the
    # deb-packaged bulk_extractor is compiled without libewf (W-041).
    # Transparently FUSE-mount to a tmpdir and point BE at ewf1.
    # mkdtemp is inside the try so the finally always covers cleanup.
    ewf_mount_dir: Path | None = None
    scan_target = target_path
    try:
        if _is_ewf(target_path):
            ewfmount_bin = shutil.which(_resolve_ewfmount_tool())
            if ewfmount_bin is None:
                raise RuntimeError(
                    f"{target_path.name} is an EWF/E01 image but bulk_extractor on this host "
                    "was compiled without libewf and ewfmount is not available. "
                    "Options: (a) install ewf-tools and retry, "
                    "(b) pre-convert with ewfexport to a raw image, "
                    "(c) set AGENTROPIX_BE_TOOL to a libewf-enabled binary."
                )
            ewf_mount_dir = Path(tempfile.mkdtemp(prefix="agentropix-sift-ewf-", dir=_ewf_tmpdir()))
            scan_target = await _ewf_mount(target_path, ewf_mount_dir)
            logger.info("EWF mounted at %s → scanning %s", ewf_mount_dir, scan_target)

        cmd: list[str] = [tool_path, "-o", str(out_path)]
        # W-085: bulk_extractor only scans the top level of a directory
        # target unless given -R. Inject it when the resolved scan
        # target is a directory; single-file targets must not receive
        # -R because BE errors on `-R <file>`.
        if recurse and Path(scan_target).is_dir():
            cmd.append("-R")
        if zap:
            cmd.append("-Z")
        if only_scanner:
            cmd.extend(["-E", only_scanner])
        else:
            for sc in enable_scanners or []:
                cmd.extend(["-e", sc])
            for sc in disable_scanners or []:
                cmd.extend(["-x", sc])
        cmd.append(str(scan_target))

        logger.info("Running: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
        except TimeoutError:
            proc.kill()
            raise TimeoutError(f"{tool_name} timed out after {timeout}s") from None

        stderr = stderr_bytes.decode(errors="replace")

        if proc.returncode != 0:
            raise RuntimeError(f"{tool_name} failed (rc={proc.returncode}): {stderr[:500]}")

        features, per_recorder, recorders, truncated, recorder_files = _collect_features(
            out_path,
            max_features=max_features,
        )
    finally:
        if ewf_mount_dir is not None:
            await _ewf_unmount(ewf_mount_dir)
            shutil.rmtree(ewf_mount_dir, ignore_errors=True)

    return BulkReport(
        target=str(target_path),
        out_dir=str(out_path),
        feature_count=sum(per_recorder.values()),
        # NIST1 RUN2 ISSUE-002: summary_only drops the (multi-MB) inline feature
        # list to fit the result envelope; per_recorder_counts + recorder_files
        # still give the agent counts + on-disk paths to fetch full values.
        features=[] if summary_only else features,
        per_recorder_counts=per_recorder,
        recorders=recorders,
        recorder_files=recorder_files,
        resolved_input=str(scan_target),
        summary_only=summary_only,
        truncated=truncated,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
        compressed_input_warning=compressed_input_warning,
        compressed_input_severity=compressed_input_severity,
    )
