"""Volatility3 wrappers — memory forensics process listing."""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from agentropix_mcp._env import get_int
from agentropix_mcp.wrappers._status import (
    REASON_PSSCAN_FALLBACK,
    ToolStatus,
    detect_symbol_failure,
    taxonomy_enabled,
)
from agentropix_mcp.wrappers._subprocess import run_with_memory_limit

logger = logging.getLogger(__name__)

TOOL_NAME = "vol"

_DEFAULT_VOL_TIMEOUT = 120.0


def _symbol_status_kwargs(returncode: int, stdout: str, stderr: str) -> dict[str, str]:
    """Status-taxonomy kwargs for a vol3 run (QA WS-A / issues 01/11/14/15).

    When ``AGENTROPIX_STATUS_TAXONOMY`` is off, returns ``{}`` so the report keeps
    its ``status="ok"`` default and behaviour is unchanged. When on and a
    symbol-resolution / hard subprocess failure is detected (vol3 commonly exits
    rc=0 with an empty CSV in that state), returns status=failed + reason.
    """
    if not taxonomy_enabled():
        return {}
    reason = detect_symbol_failure(returncode, stdout, stderr)
    if reason:
        return {
            "status": ToolStatus.FAILED.value,
            "reason": reason,
            "reason_detail": (stderr or "")[:300],
        }
    return {}


# W-135: input-class detection for memory-only vol3 plugins.
#
# Pre-W-135, pslist / netscan / malfind / etc. forwarded any path
# vol3 was given. On a disk image (.E01) vol3 emits non-JSON output
# (a Python traceback to stderr + empty stdout) that the wrapper
# surfaces as ``vol3 emitted non-JSON output: Expecting value: line
# 2 column 1 (char 1)`` — opaque to anyone who doesn't know vol3
# internals. Pslist further produces 11 placeholder rows with PID/
# PPID=0 and ``name="unknown"`` that look like real data on cursory
# read. Both behaviours are correct vol3 (memory plugins need a
# memory layer); the wrapper just never said so.
#
# This sniff mirrors ``_is_e01_image`` in wrappers/evtx.py — kept
# local rather than shared via a util module so the only coupling
# between the two wrappers is the EWF magic constant. If it ever
# needs to grow (e.g. detect VHDX, raw NTFS partition images), it
# moves to wrappers/_imageclass.py and both call sites adopt.
_EWF_MAGIC = b"EVF"
_E01_SUFFIXES: frozenset[str] = frozenset(
    {".E01", ".e01"} | {f".{ext}{n:02d}" for ext in ("E", "e", "Ex", "ex") for n in range(1, 100)}
)
_DISK_IMAGE_SKIP_REASON = (
    "input is a disk image (E01/EWF), memory plugin requires a memory "
    "acquisition (.dmp / .vmem / .mem / .lime / raw memory dump). "
    "Acquire memory of the same host with WinPMem / DumpIt / FTK Imager "
    "and re-run the tool against the resulting dump."
)


def _is_disk_image(path: Path) -> bool:
    """W-135: True if ``path`` looks like an E01/EWF disk-image input.

    Suffix sniff first (cheap); EVF magic-byte fallback for renamed
    images. Same logic as ``wrappers.evtx._is_e01_image`` but kept
    local so the volatility module doesn't grow a cross-wrapper
    import. Returns False on OSError / missing file rather than
    raising — the upstream existence check has already happened.
    """
    if path.suffix in _E01_SUFFIXES:
        return True
    try:
        if path.stat().st_size < 1024:
            return False
        with path.open("rb") as fh:
            head = fh.read(3)
        return head == _EWF_MAGIC
    except OSError:
        return False


_VOL_TIMEOUT_DEPRECATION_LOGGED = False


def _resolve_vol_timeout(timeout: float | None) -> float:
    """Resolve volatility timeout: explicit kwarg > AGENTROPIX_VOL3_TIMEOUT
    > AGENTROPIX_VOL_TIMEOUT (deprecated) > default.

    W-142: ``AGENTROPIX_VOL_TIMEOUT`` is deprecated in favour of
    ``AGENTROPIX_VOL3_TIMEOUT`` (the same env var ``run_volatility`` reads).
    Setting the deprecated name still works but emits a one-time warning.
    """
    global _VOL_TIMEOUT_DEPRECATION_LOGGED
    if timeout is not None:
        return timeout

    env_val = os.environ.get("AGENTROPIX_VOL3_TIMEOUT")
    if env_val:
        try:
            return max(30.0, float(env_val))
        except ValueError:
            logger.warning("Invalid AGENTROPIX_VOL3_TIMEOUT=%r, falling through", env_val)

    legacy_val = os.environ.get("AGENTROPIX_VOL_TIMEOUT")
    if legacy_val:
        if not _VOL_TIMEOUT_DEPRECATION_LOGGED:
            logger.warning(
                "AGENTROPIX_VOL_TIMEOUT is deprecated (W-142); use "
                "AGENTROPIX_VOL3_TIMEOUT. Honoring legacy value for now."
            )
            _VOL_TIMEOUT_DEPRECATION_LOGGED = True
        try:
            return max(30.0, float(legacy_val))
        except ValueError:
            logger.warning("Invalid AGENTROPIX_VOL_TIMEOUT=%r, using default", legacy_val)
    return _DEFAULT_VOL_TIMEOUT


class ProcessInfo(BaseModel):
    """Single process from Volatility pslist output."""

    pid: int
    ppid: int
    name: str
    threads: int = 0
    handles: int = 0
    wow64: bool = False
    create_time: str = ""
    exit_time: str = ""
    offset: str = ""


class PsList(BaseModel):
    """Parsed Volatility pslist result.

    W-135 fields (``tool_available``, ``skipped_reason``,
    ``image_class_detected``) are populated only when the wrapper
    short-circuits without invoking vol3 (e.g. input is a disk image
    instead of a memory dump). On the normal path they keep their
    default values so existing consumers see no shape change.
    """

    image_path: str
    process_count: int
    processes: list[ProcessInfo] = Field(default_factory=list)
    tool: str = "volatility3.windows.pslist.PsList"
    raw_stderr: str = ""
    used_fallback: bool = False  # True if psscan was used due to pslist failure
    # SIFT-W-082: SHA-256 of vol3's raw stdout bytes — chain-of-custody fingerprint.
    raw_stdout_sha256: str = ""
    # W-135 input-class signalling — see class docstring.
    tool_available: bool = True
    skipped_reason: str = ""
    image_class_detected: str = ""
    # QA WS-A status taxonomy (gated by AGENTROPIX_STATUS_TAXONOMY); default ok.
    status: str = "ok"
    reason: str = ""
    reason_detail: str = ""


class PsScan(BaseModel):
    """Parsed Volatility psscan result (pool tag scanning)."""

    image_path: str
    process_count: int
    processes: list[ProcessInfo] = Field(default_factory=list)
    tool: str = "volatility3.windows.psscan.PsScan"
    raw_stderr: str = ""
    # SIFT-W-082: SHA-256 of vol3's raw stdout bytes — chain-of-custody fingerprint.
    raw_stdout_sha256: str = ""


def _safe_int(val: str | None, default: int = 0) -> int:
    """Parse an integer from Volatility CSV, treating '-' and blanks as default."""
    if not val or val.strip() == "-":
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _parse_pslist_csv(stdout: str) -> list[ProcessInfo]:
    """Parse Volatility CSV renderer output into ProcessInfo list."""
    processes: list[ProcessInfo] = []
    reader = csv.DictReader(io.StringIO(stdout))
    for row in reader:
        try:
            proc = ProcessInfo(
                pid=_safe_int(row.get("PID")),
                ppid=_safe_int(row.get("PPID")),
                name=row.get("ImageFileName", row.get("Name", "unknown")),
                threads=_safe_int(row.get("Threads")),
                handles=_safe_int(row.get("Handles")),
                wow64=row.get("Wow64", "False").lower() == "true",
                create_time=row.get("CreateTime", ""),
                exit_time=row.get("ExitTime", ""),
                offset=row.get("Offset(V)", row.get("OFFSET (V)", "")),
            )
            processes.append(proc)
        except (ValueError, KeyError) as e:
            logger.warning("Skipping malformed pslist row: %s", e)
    return processes


class MemoryInfo(BaseModel):
    """Parsed Volatility3 ``windows.info`` output (W-074).

    The single field SIFT cares about today is ``ke_number_processors``;
    a value of 0 indicates a paused-VM snapshot (KeNumberProcessors gets
    zeroed when the VM was suspended at acquisition time). On those dumps
    the list-walking plugins (``pslist``, ``modules``, ``svcscan``,
    legacy ``malfind``) silently return empty rows even when malware is
    present, so MemoryAgent must fall through to pool-scan plugins
    (``psscan``, ``modscan``, ``driverscan``, ``netscan``).
    """

    image_path: str
    ke_number_processors: int = -1
    raw_stderr: str = ""
    parse_failed: bool = False


def _parse_info_csv(stdout: str) -> int:
    """Extract ``KeNumberProcessors`` from a vol3 ``windows.info`` CSV dump.

    The CSV layout is ``Variable,Value`` with one row per kernel symbol;
    we hunt for the row whose Variable column ends with
    ``KeNumberProcessors``. Returns ``-1`` when the row is missing or
    the value can't be parsed (caller treats -1 as "unknown — don't
    branch to pool-scan").
    """
    reader = csv.DictReader(io.StringIO(stdout))
    for row in reader:
        var = (row.get("Variable") or "").strip()
        if var.endswith("KeNumberProcessors"):
            return _safe_int(row.get("Value"), default=-1)
    return -1


async def get_info(
    image: str | Path,
    *,
    timeout: float | None = None,
) -> MemoryInfo:
    """Run vol3 ``windows.info`` and surface the fields SIFT branches on.

    Used by MemoryAgent as a pre-flight: when ``ke_number_processors==0``
    the dump is a paused-VM snapshot and MemoryAgent must avoid
    list-walking plugins (W-074).
    """
    timeout = _resolve_vol_timeout(timeout)
    image = Path(image)
    if not image.exists():
        raise FileNotFoundError(f"Memory image not found: {image}")

    vol_path = shutil.which(TOOL_NAME)
    if not vol_path:
        raise FileNotFoundError(f"{TOOL_NAME} not found on PATH — install volatility3")

    cmd = [vol_path, "-f", str(image), "-r", "csv", "windows.info.Info"]
    logger.info("Running windows.info pre-flight: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout_bytes, stderr_bytes = await run_with_memory_limit(proc, timeout, "vol-info")
    except (MemoryError, TimeoutError):
        raise

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")

    if proc.returncode != 0 and not stdout.strip():
        # vol3 couldn't even read the header. Surface a degraded result;
        # let the caller decide whether to abort or fall through.
        return MemoryInfo(
            image_path=str(image),
            ke_number_processors=-1,
            raw_stderr=stderr[:1000],
            parse_failed=True,
        )

    ke = _parse_info_csv(stdout)
    return MemoryInfo(
        image_path=str(image),
        ke_number_processors=ke,
        raw_stderr=stderr[:1000] if stderr else "",
        parse_failed=False,
    )


class SocketInfo(BaseModel):
    """Single socket / connection from vol3 ``windows.netscan`` output.

    SIFT default network plugin per W-075: ``windows.netscan`` works
    without the tcpip.sys symbol pack while ``windows.netstat`` does
    not. ``netstat`` is opt-in via ``AGENTROPIX_VOL_USE_NETSTAT=1`` and
    only succeeds when symbols have been pre-fetched.
    """

    proto: str = ""
    local_addr: str = ""
    local_port: int = 0
    foreign_addr: str = ""
    foreign_port: int = 0
    state: str = ""
    pid: int = 0
    owner: str = ""
    created: str = ""
    offset: str = ""


class NetscanReport(BaseModel):
    """Parsed Volatility netscan result.

    W-135 fields populate only on the short-circuit path; see PsList
    docstring.
    """

    image_path: str
    socket_count: int
    sockets: list[SocketInfo] = Field(default_factory=list)
    tool: str = "volatility3.windows.netscan.NetScan"
    raw_stderr: str = ""
    # SIFT-W-082: SHA-256 of vol3's raw stdout bytes — chain-of-custody fingerprint.
    raw_stdout_sha256: str = ""
    # W-135 input-class signalling — see PsList docstring.
    tool_available: bool = True
    skipped_reason: str = ""
    image_class_detected: str = ""
    # QA WS-A status taxonomy (gated by AGENTROPIX_STATUS_TAXONOMY); default ok.
    status: str = "ok"
    reason: str = ""
    reason_detail: str = ""


def _parse_netscan_csv(stdout: str) -> list[SocketInfo]:
    """Parse vol3 ``windows.netscan -r csv`` output into SocketInfo list.

    The CSV header set is wider than ``netstat``: vol3 emits
    ``Offset,Proto,LocalAddr,LocalPort,ForeignAddr,ForeignPort,State,PID,Owner,Created``.
    Missing columns parse as empty/0. Rows that don't even have ``Proto``
    are silently dropped.
    """
    sockets: list[SocketInfo] = []
    reader = csv.DictReader(io.StringIO(stdout))
    for row in reader:
        proto = (row.get("Proto") or "").strip()
        if not proto:
            continue
        try:
            sock = SocketInfo(
                proto=proto,
                local_addr=row.get("LocalAddr", "") or "",
                local_port=_safe_int(row.get("LocalPort")),
                foreign_addr=row.get("ForeignAddr", "") or "",
                foreign_port=_safe_int(row.get("ForeignPort")),
                state=(row.get("State") or "").strip(),
                pid=_safe_int(row.get("PID")),
                owner=(row.get("Owner") or "").strip(),
                created=(row.get("Created") or "").strip(),
                offset=(row.get("Offset") or "").strip(),
            )
            sockets.append(sock)
        except (ValueError, KeyError) as exc:
            logger.warning("Skipping malformed netscan row: %s", exc)
    return sockets


async def get_netscan(
    image: str | Path,
    *,
    timeout: float | None = None,
) -> NetscanReport:
    """Run vol3 ``windows.netscan`` on a memory image (W-075 default).

    Prefer this over ``windows.netstat``: netscan is pool-tag-driven and
    works without the per-build tcpip.sys symbol pack, while netstat
    requires the pack and fails noisily when it is not pre-fetched.

    Raises:
        FileNotFoundError: image or vol binary missing.
        TimeoutError: vol exceeded timeout.
        RuntimeError: vol returned non-zero rc with empty stdout.
    """
    timeout = _resolve_vol_timeout(timeout)
    image = Path(image)
    if not image.exists():
        raise FileNotFoundError(f"Memory image not found: {image}")

    # W-135: see get_pslist for the rationale.
    if _is_disk_image(image):
        logger.info(
            "get_netscan: short-circuiting disk-image input %s — memory plugin not applicable",
            image,
        )
        return NetscanReport(
            image_path=str(image),
            socket_count=0,
            tool_available=False,
            skipped_reason=_DISK_IMAGE_SKIP_REASON,
            image_class_detected="ewf-disk",
        )

    vol_path = shutil.which(TOOL_NAME)
    if not vol_path:
        raise FileNotFoundError(f"{TOOL_NAME} not found on PATH — install volatility3")

    cmd = [vol_path, "-f", str(image), "-r", "csv", "windows.netscan.NetScan"]
    logger.info("Running netscan (W-075 default): %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await run_with_memory_limit(proc, timeout, "vol-netscan")
    except (MemoryError, TimeoutError):
        raise

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")

    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError(f"Volatility netscan failed (rc={proc.returncode}): {stderr[:500]}")

    sockets = _parse_netscan_csv(stdout)
    return NetscanReport(
        image_path=str(image),
        socket_count=len(sockets),
        sockets=sockets,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
        **_symbol_status_kwargs(proc.returncode, stdout, stderr),
    )


def should_use_netstat() -> bool:
    """W-075 policy gate. Returns True only when the operator has
    explicitly opted in via ``AGENTROPIX_VOL_USE_NETSTAT=1`` AND the
    tcpip.sys symbol pack is known to be locally available
    (``AGENTROPIX_VOL_TCPIP_SYMBOLS_OK=1``). Defaulting to netscan is
    correct on any image where the symbol pack hasn't been pre-fetched.
    """
    use = os.environ.get("AGENTROPIX_VOL_USE_NETSTAT", "0").strip().lower()
    if use not in {"1", "true", "yes", "on"}:
        return False
    pack = os.environ.get("AGENTROPIX_VOL_TCPIP_SYMBOLS_OK", "0").strip().lower()
    return pack in {"1", "true", "yes", "on"}


def is_snapshot_paused(info: MemoryInfo) -> bool:
    """W-074: KeNumberProcessors==0 → paused-VM snapshot.

    -1 (unknown / parse failed) is NOT treated as paused — we don't want
    a transient symbol-fetch failure to silently force pool-scan mode.
    """
    return info.ke_number_processors == 0


# --------------------------------------------------------------------------- #
# W-071 — native wrappers around top-5 vol3 plugins (BMAD-M7 Phase 7)
#
# These mirror the artifact.py::_task_finding pattern: each wrapper
# returns a typed Pydantic report; MemoryAgent converts each row into a
# Finding with the structured evidence_dict from W-073, populating
# MITRE tags so the cohit≥2 scorer can credit memory-side detections.
# --------------------------------------------------------------------------- #


class MalfindHit(BaseModel):
    """Single ``windows.malfind`` hit — injected/RWX VAD region.

    Issue #11 enrichment fields (``payload_sha256``, ``payload_bytes``,
    ``payload_strings``) populate when ``get_malfind`` chained a
    ``windows.vadinfo.VadInfo --dump`` against the hit and recovered
    bytes. They stay at their defaults when the dump was skipped (per-
    host cap reached) or failed (subprocess error, missing dump file,
    oversize VAD). Downstream emitters use a non-empty
    ``payload_sha256`` as the trigger to add the payload Finding so
    flag findings remain unaffected by dump failures.
    """

    pid: int = 0
    process: str = ""
    address: str = ""
    vad_tag: str = ""
    protection: str = ""
    commit_charge: int = 0
    private_memory: bool = False
    hexdump_head: str = ""
    # Issue #11 — VAD dump enrichment.
    payload_sha256: str = ""
    payload_bytes: int = 0
    payload_strings: list[str] = Field(default_factory=list)


class MalfindReport(BaseModel):
    """W-135 fields populate only on the short-circuit path; see PsList docstring."""

    image_path: str
    hit_count: int
    hits: list[MalfindHit] = Field(default_factory=list)
    tool: str = "volatility3.windows.malfind.Malfind"
    raw_stderr: str = ""
    # SIFT-W-082: SHA-256 of vol3's raw stdout bytes — chain-of-custody fingerprint.
    raw_stdout_sha256: str = ""
    # W-135 input-class signalling — see PsList docstring.
    tool_available: bool = True
    skipped_reason: str = ""
    image_class_detected: str = ""
    # QA WS-A status taxonomy (gated by AGENTROPIX_STATUS_TAXONOMY); default ok.
    status: str = "ok"
    reason: str = ""
    reason_detail: str = ""


def _parse_malfind_csv(stdout: str) -> list[MalfindHit]:
    """Parse vol3 ``windows.malfind -r csv`` output.

    Header: ``PID,Process,Start VPN,End VPN,Tag,Protection,CommitCharge,
    PrivateMemory,File output,Notes,Hexdump,Disasm``.
    The Hexdump column is multi-line in the pretty renderer; vol3 csv
    flattens it to a single quoted cell. We keep the first ~120 chars
    as ``hexdump_head`` (covers the first 16 bytes / 4 lines, enough
    for an analyst to spot common shellcode prefixes).
    """
    hits: list[MalfindHit] = []
    reader = csv.DictReader(io.StringIO(stdout))
    for row in reader:
        pid = _safe_int(row.get("PID"))
        if pid == 0 and not row.get("Process"):
            continue
        try:
            hits.append(
                MalfindHit(
                    pid=pid,
                    process=(row.get("Process") or "").strip(),
                    address=(row.get("Start VPN") or row.get("Start") or "").strip(),
                    vad_tag=(row.get("Tag") or "").strip(),
                    protection=(row.get("Protection") or "").strip(),
                    commit_charge=_safe_int(row.get("CommitCharge")),
                    private_memory=(row.get("PrivateMemory") or "").lower() == "true",
                    hexdump_head=((row.get("Hexdump") or "")[:120]).replace("\n", " "),
                )
            )
        except (ValueError, KeyError) as exc:
            logger.warning("Skipping malformed malfind row: %s", exc)
    return hits


# --- Issue #11 — RWX VAD dump enrichment ----------------------------------- #
# Default 4 MiB cap covers typical injected payloads (Cobalt Strike beacon
# stages run ~250 KiB–2 MiB). Floor 1 MiB rules out trivially-small caps that
# would skip everything; ceiling 32 MiB rules out runaway dumps that would
# exhaust /tmp on a high-hit host (worst-case 100 hits * 32 MiB = 3.2 GiB).
_MALFIND_DUMP_BYTES_DEFAULT = 4 * 1024 * 1024
_MALFIND_DUMP_BYTES_FLOOR = 1 * 1024 * 1024
_MALFIND_DUMP_BYTES_CEILING = 32 * 1024 * 1024

# Default min_len=4 matches `strings(1)` defaults — short enough to catch
# 4-char API names ("LoadLibraryA" -> "Load"), long enough to suppress most
# binary noise. Floor/ceiling clamp operator overrides into a sane range.
_MALFIND_STRING_MIN_LEN_DEFAULT = 4
_MALFIND_STRING_MIN_LEN_FLOOR = 4
_MALFIND_STRING_MIN_LEN_CEILING = 32

# Per-host cap on dump attempts. 100 covers the worst observed wargame host
# (DC with 92 RWX hits) with headroom; floor 10 prevents accidentally
# silencing the feature; ceiling 1000 caps disk usage at a hard ~32 GiB
# even at the 32 MiB byte ceiling.
_MALFIND_DUMP_MAX_PER_HOST_DEFAULT = 100
_MALFIND_DUMP_MAX_PER_HOST_FLOOR = 10
_MALFIND_DUMP_MAX_PER_HOST_CEILING = 1000

# Cap on returned strings list. Sorted by length DESC and truncated; long
# strings are higher signal (URLs, base64 blobs, file paths) than short
# fragments. 50 keeps the report readable while preserving most IOCs.
_MALFIND_STRING_SAMPLE_CAP = 50

# ASCII printable run (space through tilde). Tabs/newlines deliberately
# excluded — embedded whitespace in shellcode strings is too noisy.
_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]+")


def _extract_strings(
    data: bytes,
    *,
    min_len: int | None = None,
    max_results: int = _MALFIND_STRING_SAMPLE_CAP,
) -> list[str]:
    """Find printable-ASCII runs of length >= ``min_len`` in ``data``.

    Returns the top ``max_results`` longest runs (length DESC) so an
    operator skimming the report sees URL / file-path / API-name hits
    before short alphabet noise. ``min_len`` defaults to
    ``AGENTROPIX_MALFIND_STRING_MIN_LEN`` (default 4; floor 4, ceiling
    32). Empty input → empty list. Decode failures on a candidate run
    skip that run rather than erroring (the regex already restricted
    to ASCII printable so this only fires on adversarial bytes).
    """
    if not data:
        return []
    if min_len is None:
        min_len = get_int(
            "AGENTROPIX_MALFIND_STRING_MIN_LEN",
            _MALFIND_STRING_MIN_LEN_DEFAULT,
            floor=_MALFIND_STRING_MIN_LEN_FLOOR,
            ceiling=_MALFIND_STRING_MIN_LEN_CEILING,
        )
    found: list[str] = []
    for match in _PRINTABLE_RUN.finditer(data):
        run = match.group()
        if len(run) >= min_len:
            try:
                found.append(run.decode("ascii"))
            except UnicodeDecodeError:
                continue
    found.sort(key=len, reverse=True)
    return found[:max_results]


async def _dump_vad(
    image: Path,
    pid: int,
    addr: str,
    *,
    max_bytes: int | None = None,
    timeout: float | None = None,
) -> bytes:
    """Dump a single VAD region from a memory image and return its bytes.

    Shells out to ``vol -f <image> -o <tmpdir> windows.vadinfo.VadInfo
    --pid <pid> --address <addr> --dump`` and reads the resulting
    ``.dmp`` file. Returns ``b""`` on any failure (missing image,
    missing vol binary, subprocess error, missing dump file, oversize
    VAD). Oversize VADs return ``b""`` rather than truncating so a
    partial SHA-256 never reaches a Finding (would mismatch VT lookups).

    The cap defaults to ``AGENTROPIX_MALFIND_DUMP_MAX_BYTES`` (default
    4 MiB; floor 1 MiB, ceiling 32 MiB). The vol3 plugin is
    deliberately ``windows.vadinfo.VadInfo`` (not ``Memmap``) because
    VadInfo's ``--address`` filter dumps only the matching VAD; Memmap
    would dump the entire process memory map and blow the byte cap on
    nearly every hit.
    """
    if max_bytes is None:
        max_bytes = get_int(
            "AGENTROPIX_MALFIND_DUMP_MAX_BYTES",
            _MALFIND_DUMP_BYTES_DEFAULT,
            floor=_MALFIND_DUMP_BYTES_FLOOR,
            ceiling=_MALFIND_DUMP_BYTES_CEILING,
        )
    timeout = _resolve_vol_timeout(timeout)
    if not image.exists():
        return b""
    vol_path = shutil.which(TOOL_NAME)
    if not vol_path:
        return b""

    with tempfile.TemporaryDirectory(prefix="sift-vaddump-") as tmpdir:
        cmd = [
            vol_path,
            "-f",
            str(image),
            "-o",
            tmpdir,
            "windows.vadinfo.VadInfo",
            "--pid",
            str(pid),
            "--address",
            str(addr),
            "--dump",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await run_with_memory_limit(proc, timeout, "vol-vaddump")
        except (TimeoutError, MemoryError, OSError) as exc:
            logger.warning("vaddump subprocess failed for pid=%s addr=%s: %s", pid, addr, exc)
            return b""

        if proc.returncode != 0:
            logger.warning(
                "vaddump rc=%d pid=%s addr=%s stderr=%s",
                proc.returncode,
                pid,
                addr,
                stderr_bytes[:200].decode(errors="replace"),
            )
            return b""

        dump_files = sorted(Path(tmpdir).glob("*.dmp"))
        if not dump_files:
            return b""
        dump_path = dump_files[0]
        try:
            size = dump_path.stat().st_size
        except OSError:
            return b""
        if size == 0:
            return b""
        if size > max_bytes:
            logger.warning(
                "vaddump pid=%s addr=%s size=%d exceeds cap %d — skipping payload",
                pid,
                addr,
                size,
                max_bytes,
            )
            return b""
        try:
            return dump_path.read_bytes()
        except OSError:
            return b""


async def _enrich_hits_with_payloads(
    hits: list[MalfindHit],
    image: Path,
    *,
    timeout: float | None = None,
) -> None:
    """Mutate ``hits`` in place, populating Issue-#11 payload fields.

    Stops after ``AGENTROPIX_MALFIND_DUMP_MAX_PER_HOST`` successful
    *attempts* (default 100; floor 10, ceiling 1000) to keep disk and
    runtime bounded on hosts with hundreds of RWX VADs. Hits beyond the
    cap retain their default empty payload fields so the downstream
    emitter simply doesn't add a payload Finding for them; the original
    flag Finding is unaffected. Dump failures (subprocess error,
    oversize, missing file) leave the hit's payload fields empty too.
    """
    cap = get_int(
        "AGENTROPIX_MALFIND_DUMP_MAX_PER_HOST",
        _MALFIND_DUMP_MAX_PER_HOST_DEFAULT,
        floor=_MALFIND_DUMP_MAX_PER_HOST_FLOOR,
        ceiling=_MALFIND_DUMP_MAX_PER_HOST_CEILING,
    )
    attempts = 0
    for hit in hits:
        if attempts >= cap:
            logger.info(
                "malfind dump cap reached (%d attempts); remaining %d hits will not be dumped this run",
                cap,
                len(hits) - attempts,
            )
            break
        attempts += 1
        try:
            data = await _dump_vad(image, hit.pid, hit.address, timeout=timeout)
        except (RuntimeError, OSError) as exc:
            logger.warning(
                "vaddump unexpected error for pid=%s addr=%s: %s",
                hit.pid,
                hit.address,
                exc,
            )
            continue
        if not data:
            continue
        hit.payload_sha256 = hashlib.sha256(data).hexdigest()
        hit.payload_bytes = len(data)
        hit.payload_strings = _extract_strings(data)


async def get_malfind(
    image: str | Path,
    *,
    timeout: float | None = None,
) -> MalfindReport:
    """Run vol3 ``windows.malfind`` — flags RWX VAD regions / injected code.

    Issue #11: after parsing the malfind hits, attempts to chain
    ``windows.vadinfo.VadInfo --dump`` against each hit (capped per-host
    by ``AGENTROPIX_MALFIND_DUMP_MAX_PER_HOST``) and populates the
    ``payload_sha256`` / ``payload_bytes`` / ``payload_strings`` fields
    on each MalfindHit when a dump succeeded. Dump failures are non-
    fatal — the malfind report is still returned with the flag rows
    intact; only the payload-enrichment fields stay empty for the
    failing hits.
    """
    timeout = _resolve_vol_timeout(timeout)
    image = Path(image)
    if not image.exists():
        raise FileNotFoundError(f"Memory image not found: {image}")

    # W-135: see get_pslist for the rationale.
    if _is_disk_image(image):
        logger.info(
            "get_malfind: short-circuiting disk-image input %s — memory plugin not applicable",
            image,
        )
        return MalfindReport(
            image_path=str(image),
            hit_count=0,
            tool_available=False,
            skipped_reason=_DISK_IMAGE_SKIP_REASON,
            image_class_detected="ewf-disk",
        )

    vol_path = shutil.which(TOOL_NAME)
    if not vol_path:
        raise FileNotFoundError(f"{TOOL_NAME} not found on PATH — install volatility3")

    cmd = [vol_path, "-f", str(image), "-r", "csv", "windows.malfind.Malfind"]
    logger.info("Running malfind: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await run_with_memory_limit(proc, timeout, "vol-malfind")
    except (MemoryError, TimeoutError):
        raise

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")
    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError(f"Volatility malfind failed (rc={proc.returncode}): {stderr[:500]}")

    hits = _parse_malfind_csv(stdout)
    # Issue #11: dump+hash+strings each RWX VAD (best-effort, capped).
    await _enrich_hits_with_payloads(hits, image, timeout=timeout)
    return MalfindReport(
        image_path=str(image),
        hit_count=len(hits),
        hits=hits,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
        **_symbol_status_kwargs(proc.returncode, stdout, stderr),
    )


class ServiceInfo(BaseModel):
    """Single ``windows.svcscan`` row."""

    pid: int = 0
    name: str = ""
    display: str = ""
    state: str = ""
    start: str = ""
    type: str = ""
    binary: str = ""
    dll: str = ""


class SvcscanReport(BaseModel):
    """W-135 fields populate only on the short-circuit path; see PsList docstring."""

    image_path: str
    service_count: int
    services: list[ServiceInfo] = Field(default_factory=list)
    tool: str = "volatility3.windows.svcscan.SvcScan"
    raw_stderr: str = ""
    # SIFT-W-082: SHA-256 of vol3's raw stdout bytes — chain-of-custody fingerprint.
    raw_stdout_sha256: str = ""
    # W-135 input-class signalling — see PsList docstring.
    tool_available: bool = True
    skipped_reason: str = ""
    image_class_detected: str = ""
    # QA WS-A status taxonomy (gated by AGENTROPIX_STATUS_TAXONOMY); default ok.
    status: str = "ok"
    reason: str = ""
    reason_detail: str = ""


def _parse_svcscan_csv(stdout: str) -> list[ServiceInfo]:
    """Parse vol3 ``windows.svcscan -r csv``.

    Header (vol3 ≥ 2.7): ``PID,Offset,Order,Start,State,Type,Name,Display,Binary,Binary (services.exe),Dll``.
    """
    services: list[ServiceInfo] = []
    reader = csv.DictReader(io.StringIO(stdout))
    for row in reader:
        name = (row.get("Name") or "").strip()
        if not name:
            continue
        try:
            services.append(
                ServiceInfo(
                    pid=_safe_int(row.get("PID")),
                    name=name,
                    display=(row.get("Display") or "").strip(),
                    state=(row.get("State") or "").strip(),
                    start=(row.get("Start") or "").strip(),
                    type=(row.get("Type") or "").strip(),
                    binary=(row.get("Binary") or row.get("Binary (services.exe)") or "").strip(),
                    dll=(row.get("Dll") or "").strip(),
                )
            )
        except (ValueError, KeyError) as exc:
            logger.warning("Skipping malformed svcscan row: %s", exc)
    return services


async def get_svcscan(
    image: str | Path,
    *,
    timeout: float | None = None,
) -> SvcscanReport:
    """Run vol3 ``windows.svcscan`` — Service Control Manager enumeration."""
    timeout = _resolve_vol_timeout(timeout)
    image = Path(image)
    if not image.exists():
        raise FileNotFoundError(f"Memory image not found: {image}")

    # W-135: see get_pslist for the rationale.
    if _is_disk_image(image):
        logger.info(
            "get_svcscan: short-circuiting disk-image input %s — memory plugin not applicable",
            image,
        )
        return SvcscanReport(
            image_path=str(image),
            service_count=0,
            tool_available=False,
            skipped_reason=_DISK_IMAGE_SKIP_REASON,
            image_class_detected="ewf-disk",
        )

    vol_path = shutil.which(TOOL_NAME)
    if not vol_path:
        raise FileNotFoundError(f"{TOOL_NAME} not found on PATH — install volatility3")

    cmd = [vol_path, "-f", str(image), "-r", "csv", "windows.svcscan.SvcScan"]
    logger.info("Running svcscan: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await run_with_memory_limit(proc, timeout, "vol-svcscan")
    except (MemoryError, TimeoutError):
        raise

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")
    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError(f"Volatility svcscan failed (rc={proc.returncode}): {stderr[:500]}")

    services = _parse_svcscan_csv(stdout)
    return SvcscanReport(
        image_path=str(image),
        service_count=len(services),
        services=services,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
        **_symbol_status_kwargs(proc.returncode, stdout, stderr),
    )


_SYSTEM_BINARY_PREFIXES: tuple[str, ...] = (
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\servicing\\",
    "%systemroot%\\system32\\",
    "%systemroot%\\syswow64\\",
    "\\systemroot\\system32\\",
    "\\??\\c:\\windows\\system32\\",
)


def is_service_binary_outside_system32(svc: ServiceInfo) -> bool:
    """W-071: T1543.003 heuristic — a service whose binary lives outside
    the standard Windows service directories is high-signal for
    persistence via service installation. Whitelist the prefixes; if the
    binary is empty or starts with one, it's NOT flagged.

    The check is case-insensitive and tolerant of the various path
    layouts vol3 emits across Win 7 / 10 / Server builds.
    """
    binary = (svc.binary or "").strip().lower()
    if not binary:
        return False
    # Strip surrounding quotes and any trailing args for argv0.
    if binary.startswith('"'):
        end = binary.find('"', 1)
        if end > 0:
            binary = binary[1:end]
    else:
        binary = binary.split(" ", 1)[0]
    return not any(binary.startswith(prefix) for prefix in _SYSTEM_BINARY_PREFIXES)


class RegistryRunEntry(BaseModel):
    """Persistence row from ``windows.registry.printkey --key Run`` or
    ``windows.registry.userassist``.

    The two plugins share the same downstream Finding shape (T1547.001)
    so SIFT collapses them into a single typed model.
    """

    hive: str = ""
    key: str = ""
    value: str = ""
    data: str = ""
    last_write: str = ""
    source_plugin: str = ""  # "printkey" | "userassist"


class RegistryPersistenceReport(BaseModel):
    image_path: str
    entry_count: int
    entries: list[RegistryRunEntry] = Field(default_factory=list)
    raw_stderr: str = ""
    # SIFT-W-082: SHA-256 of vol3's raw stdout bytes — chain-of-custody fingerprint.
    raw_stdout_sha256: str = ""


def _parse_printkey_csv(stdout: str, source_plugin: str = "printkey") -> list[RegistryRunEntry]:
    """Parse vol3 ``windows.registry.printkey -r csv`` output.

    Header: ``Last Write Time,Hive Offset,Type,Key,Name,Data,Volatile``.
    Skips rows whose Type is REG_NONE / blank (those are header/key rows
    rather than value rows).
    """
    entries: list[RegistryRunEntry] = []
    reader = csv.DictReader(io.StringIO(stdout))
    for row in reader:
        type_ = (row.get("Type") or "").strip()
        name = (row.get("Name") or "").strip()
        if not name and type_ in {"", "REG_NONE", "Key"}:
            continue
        entries.append(
            RegistryRunEntry(
                hive=(row.get("Hive Offset") or row.get("Hive") or "").strip(),
                key=(row.get("Key") or "").strip(),
                value=name,
                data=(row.get("Data") or "").strip(),
                last_write=(row.get("Last Write Time") or "").strip(),
                source_plugin=source_plugin,
            )
        )
    return entries


def _parse_userassist_csv(stdout: str) -> list[RegistryRunEntry]:
    """Parse vol3 ``windows.registry.userassist -r csv``.

    Header: ``Hive Offset,Hive Name,Path,Last Write Time,Type,Name,ID,Count,
    Focus Count,Time Focused,Last Updated,Raw Data``.
    Only rows with a non-empty Name are emitted; the `data` column for
    these is the human-readable run count + last-updated stamp so
    operators can see which apps the user actually launched.
    """
    entries: list[RegistryRunEntry] = []
    reader = csv.DictReader(io.StringIO(stdout))
    for row in reader:
        name = (row.get("Name") or "").strip()
        if not name:
            continue
        count = (row.get("Count") or "0").strip()
        last_updated = (row.get("Last Updated") or "").strip()
        entries.append(
            RegistryRunEntry(
                hive=(row.get("Hive Name") or row.get("Hive Offset") or "").strip(),
                key=(row.get("Path") or "").strip(),
                value=name,
                data=f"count={count} last_updated={last_updated}",
                last_write=(row.get("Last Write Time") or "").strip(),
                source_plugin="userassist",
            )
        )
    return entries


async def _run_vol_csv(
    image: Path,
    plugin: str,
    label: str,
    timeout: float,
    extra_args: list[str] | None = None,
) -> tuple[str, str, int, str]:
    """Shared runner for the registry helpers below.

    Returns (stdout, stderr, returncode, raw_stdout_sha256).
    """
    vol_path = shutil.which(TOOL_NAME)
    if not vol_path:
        raise FileNotFoundError(f"{TOOL_NAME} not found on PATH — install volatility3")
    cmd = [vol_path, "-f", str(image), "-r", "csv", plugin]
    if extra_args:
        cmd.extend(extra_args)
    logger.info("Running %s: %s", plugin, " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_bytes, stderr_bytes = await run_with_memory_limit(proc, timeout, label)
    sha256 = hashlib.sha256(stdout_bytes).hexdigest()
    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")
    return stdout, stderr, proc.returncode, sha256


async def get_registry_run_keys(
    image: str | Path,
    *,
    key: str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    timeout: float | None = None,
) -> RegistryPersistenceReport:
    """Run vol3 ``windows.registry.printkey --key <key>`` and emit
    typed Run-key persistence rows (T1547.001)."""
    timeout = _resolve_vol_timeout(timeout)
    image = Path(image)
    if not image.exists():
        raise FileNotFoundError(f"Memory image not found: {image}")

    stdout, stderr, rc, sha256 = await _run_vol_csv(
        image,
        "windows.registry.printkey.PrintKey",
        "vol-printkey-run",
        timeout,
        extra_args=["--key", key],
    )
    if rc != 0 and not stdout.strip():
        raise RuntimeError(f"Volatility printkey failed (rc={rc}): {stderr[:500]}")

    entries = _parse_printkey_csv(stdout, source_plugin="printkey")
    return RegistryPersistenceReport(
        image_path=str(image),
        entry_count=len(entries),
        entries=entries,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=sha256,
    )


async def get_userassist(
    image: str | Path,
    *,
    timeout: float | None = None,
) -> RegistryPersistenceReport:
    """Run vol3 ``windows.registry.userassist`` and emit typed entries
    describing app-launch persistence signals (T1547.001 adjacent —
    UserAssist tracks GUI-shell launches and surfaces malware that ran
    interactively even after the live process exited)."""
    timeout = _resolve_vol_timeout(timeout)
    image = Path(image)
    if not image.exists():
        raise FileNotFoundError(f"Memory image not found: {image}")

    stdout, stderr, rc, sha256 = await _run_vol_csv(
        image,
        "windows.registry.userassist.UserAssist",
        "vol-userassist",
        timeout,
    )
    if rc != 0 and not stdout.strip():
        raise RuntimeError(f"Volatility userassist failed (rc={rc}): {stderr[:500]}")

    entries = _parse_userassist_csv(stdout)
    return RegistryPersistenceReport(
        image_path=str(image),
        entry_count=len(entries),
        entries=entries,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=sha256,
    )


async def _get_psscan(
    image: str | Path,
    timeout: float | None = None,
) -> PsScan:
    """Run Volatility3 psscan on a memory image (pool tag scanning).

    Psscan is more robust than pslist when the ActiveProcessLinks list
    is corrupted or smeared. It finds processes by scanning for pool
    headers rather than following linked lists.

    Args:
        image: Path to memory dump file.
        timeout: Max seconds to wait for Volatility.

    Returns:
        PsScan with parsed process information.

    Raises:
        FileNotFoundError: If image or vol binary not found.
        TimeoutError: If Volatility exceeds timeout.
        RuntimeError: If Volatility returns non-zero exit code.
    """
    timeout = _resolve_vol_timeout(timeout)
    image = Path(image)
    if not image.exists():
        raise FileNotFoundError(f"Memory image not found: {image}")

    vol_path = shutil.which(TOOL_NAME)
    if not vol_path:
        raise FileNotFoundError(f"{TOOL_NAME} not found on PATH — install volatility3")

    cmd = [vol_path, "-f", str(image), "-r", "csv", "windows.psscan.PsScan"]

    logger.info("Running psscan fallback: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout_bytes, stderr_bytes = await run_with_memory_limit(proc, timeout, "vol-psscan")
    except (MemoryError, TimeoutError):
        raise

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")

    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError(f"Volatility psscan failed (rc={proc.returncode}): {stderr[:500]}")

    processes = _parse_pslist_csv(stdout)

    return PsScan(
        image_path=str(image),
        process_count=len(processes),
        processes=processes,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
    )


async def get_pslist(
    image: str | Path,
    *,
    pid_filter: list[int] | None = None,
    timeout: float | None = None,
) -> PsList:
    """Run Volatility3 pslist on a memory image.

    If the ActiveProcessLinks list is corrupted (process_count == 0),
    automatically falls back to psscan (pool tag scanning).

    Args:
        image: Path to memory dump file.
        pid_filter: Optional list of PIDs to include (pslist only).
        timeout: Max seconds to wait for Volatility.

    Returns:
        PsList with parsed process information. On disk-image inputs
        (W-135) the report has ``tool_available=False`` and a populated
        ``skipped_reason`` instead of vol3 output; ``processes=[]`` and
        ``process_count=0``.

    Raises:
        FileNotFoundError: If image or vol binary not found.
        TimeoutError: If Volatility exceeds timeout.
        RuntimeError: If Volatility returns non-zero exit code.
    """
    timeout = _resolve_vol_timeout(timeout)
    image = Path(image)
    if not image.exists():
        raise FileNotFoundError(f"Memory image not found: {image}")

    # W-135: short-circuit on disk-image inputs. Pre-fix, vol3 produced
    # 11 placeholder rows with PID/PPID=0, name="unknown" — looked like
    # real data on cursory read. See module-level _DISK_IMAGE_SKIP_REASON.
    if _is_disk_image(image):
        logger.info(
            "get_pslist: short-circuiting disk-image input %s — memory plugin not applicable",
            image,
        )
        return PsList(
            image_path=str(image),
            process_count=0,
            tool_available=False,
            skipped_reason=_DISK_IMAGE_SKIP_REASON,
            image_class_detected="ewf-disk",
        )

    vol_path = shutil.which(TOOL_NAME)
    if not vol_path:
        raise FileNotFoundError(f"{TOOL_NAME} not found on PATH — install volatility3")

    cmd = [vol_path, "-f", str(image), "-r", "csv", "windows.pslist.PsList"]
    if pid_filter:
        cmd.extend(["--pid"] + [str(p) for p in pid_filter])

    logger.info("Running: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout_bytes, stderr_bytes = await run_with_memory_limit(proc, timeout, "vol-pslist")
    except (MemoryError, TimeoutError):
        raise

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")

    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError(f"Volatility pslist failed (rc={proc.returncode}): {stderr[:500]}")

    processes = _parse_pslist_csv(stdout)

    # If pslist returned 0 processes, the ActiveProcessLinks list is likely
    # corrupted or smeared. Fall back to psscan (pool tag scanning).
    if len(processes) == 0:
        logger.warning(
            "pslist returned 0 processes (corrupted ActiveProcessLinks); falling back to psscan (pool tag scanning)"
        )
        pslist_sha256 = hashlib.sha256(stdout_bytes).hexdigest()
        try:
            psscan_result = await _get_psscan(image, timeout=timeout)
            return PsList(
                image_path=str(image),
                process_count=psscan_result.process_count,
                processes=psscan_result.processes,
                tool="volatility3.windows.pslist.PsList",  # Keep tool name for backwards compat
                raw_stderr=f"pslist returned 0 processes; used psscan fallback. {stderr[:500]}",
                used_fallback=True,
                raw_stdout_sha256=pslist_sha256,
                **(
                    {"status": ToolStatus.PARTIAL.value, "reason": REASON_PSSCAN_FALLBACK}
                    if taxonomy_enabled()
                    else {}
                ),
            )
        except Exception as e:
            logger.error("psscan fallback failed: %s", e)
            # Return empty pslist if psscan also fails
            return PsList(
                image_path=str(image),
                process_count=0,
                processes=[],
                raw_stderr=f"pslist failed and psscan fallback error: {str(e)[:500]}",
                used_fallback=False,
                raw_stdout_sha256=pslist_sha256,
                **(
                    {
                        "status": ToolStatus.FAILED.value,
                        "reason": "psscan_also_failed",
                        "reason_detail": str(e)[:300],
                    }
                    if taxonomy_enabled()
                    else {}
                ),
            )

    return PsList(
        image_path=str(image),
        process_count=len(processes),
        processes=processes,
        raw_stderr=stderr[:1000] if stderr else "",
        used_fallback=False,
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
        **_symbol_status_kwargs(proc.returncode, stdout, stderr),
    )


# --------------------------------------------------------------------------- #
# W-098 — generic run_volatility() escape hatch
#
# Exposes a curated allowlist of windows.* plugins through a single MCP tool
# instead of one tool per plugin. Each call still passes through the same
# Thymus / archive-rejection / rate-limit checks at the MCP boundary; the
# wrapper itself is the thin subprocess shim. The plugin name is gated by an
# allowlist so an LLM can't smuggle ``windows.evil.Evil`` past the boundary.
#
# Output schema is intentionally generic: vol3's JSON renderer emits a list
# of plugin-specific row dicts, and this wrapper preserves them verbatim
# under ``rows`` so a single caller-side parser can handle every plugin.
# --------------------------------------------------------------------------- #


# Top-20 plugins from the W-098 ledger entry. Short alias → canonical
# vol3 plugin name. The keys are what an LLM is most likely to type;
# the values are what vol3 actually expects on the command line.
VOL3_PLUGIN_ALIASES: dict[str, str] = {
    "pslist": "windows.pslist.PsList",
    "pstree": "windows.pstree.PsTree",
    "psscan": "windows.psscan.PsScan",
    "malfind": "windows.malfind.Malfind",
    "netscan": "windows.netscan.NetScan",
    "netstat": "windows.netstat.NetStat",
    "cmdline": "windows.cmdline.CmdLine",
    "dlllist": "windows.dlllist.DllList",
    "filescan": "windows.filescan.FileScan",
    "svcscan": "windows.svcscan.SvcScan",
    "handles": "windows.handles.Handles",
    "hivelist": "windows.registry.hivelist.HiveList",
    "printkey": "windows.registry.printkey.PrintKey",
    "dumpfiles": "windows.dumpfiles.DumpFiles",
    "modules": "windows.modules.Modules",
    "modscan": "windows.modscan.ModScan",
    "callbacks": "windows.callbacks.Callbacks",
    "ssdt": "windows.ssdt.SSDT",
    "mutantscan": "windows.mutantscan.MutantScan",
    "vadinfo": "windows.vadinfo.VadInfo",
    "envars": "windows.envars.Envars",
    # W-117: documented-but-disabled plugins promoted to the allowlist.
    # Credential-extraction plugins (hashdump/lsadump/cachedump) intentionally
    # excluded — removed in vol3 2.27.0 and tracked under W-072.
    "timeliner": "windows.timeliner.Timeliner",
    "driverscan": "windows.driverscan.DriverScan",
    "drivermodule": "windows.drivermodule.DriverModule",
    "devicetree": "windows.devicetree.DeviceTree",
    "getservicesids": "windows.getservicesids.GetServiceSIDs",
    "userassist": "windows.registry.userassist.UserAssist",
    "sessions": "windows.sessions.Sessions",
}

# Canonical plugin names derived from the alias table — this is the
# allowlist. Anything outside this set is rejected before the subprocess
# is spawned.
VOL3_ALLOWED_PLUGINS: frozenset[str] = frozenset(VOL3_PLUGIN_ALIASES.values())


# --- Timeout knobs --------------------------------------------------------- #
# AGENTROPIX_VOL3_TIMEOUT controls the default per-call timeout for
# run_volatility(). Floor 5s (vol3 startup is ~3s; anything tighter is
# pointless), ceiling 3600s (an hour — the agent should chunk work
# rather than block longer). Default 600s (10 min) covers typical
# 8–16 GiB Win10 dumps for the heavier plugins (malfind, dlllist).
_VOL3_TIMEOUT_FLOOR = 5
_VOL3_TIMEOUT_CEILING = 3600
_VOL3_TIMEOUT_DEFAULT = 600


def _resolve_run_vol_timeout(explicit: int | None) -> int:
    """Resolve the run_volatility timeout precedence: explicit > env > default."""
    if explicit is not None:
        if explicit < _VOL3_TIMEOUT_FLOOR:
            logger.warning(
                "timeout_seconds=%d below floor %d; clamping",
                explicit,
                _VOL3_TIMEOUT_FLOOR,
            )
            return _VOL3_TIMEOUT_FLOOR
        if explicit > _VOL3_TIMEOUT_CEILING:
            logger.warning(
                "timeout_seconds=%d above ceiling %d; clamping",
                explicit,
                _VOL3_TIMEOUT_CEILING,
            )
            return _VOL3_TIMEOUT_CEILING
        return explicit
    return get_int(
        "AGENTROPIX_VOL3_TIMEOUT",
        _VOL3_TIMEOUT_DEFAULT,
        floor=_VOL3_TIMEOUT_FLOOR,
        ceiling=_VOL3_TIMEOUT_CEILING,
    )


class VolatilityReport(BaseModel):
    """Generic typed result of any allowlisted vol3 plugin run.

    ``rows`` preserves the raw JSON dicts emitted by vol3's JSON renderer
    so plugin-specific keys flow through verbatim. Callers who need
    typed shapes should use the per-plugin wrappers (``get_pslist``,
    ``get_malfind`` …) instead.

    W-135 fields populate only on the short-circuit path; see PsList
    docstring.
    """

    image_path: str
    plugin: str  # canonical name, e.g. "windows.malfind.Malfind"
    row_count: int
    rows: list[dict[str, Any]] = Field(default_factory=list)
    raw_stderr: str = ""
    # SIFT-W-082 chain-of-custody fingerprint — SHA-256 of vol3's raw
    # stdout bytes (pre-decode), NOT of the parsed rows.
    raw_stdout_sha256: str = ""
    # W-135 input-class signalling — see PsList docstring.
    tool_available: bool = True
    skipped_reason: str = ""
    image_class_detected: str = ""
    # QA WS-A status taxonomy (gated by AGENTROPIX_STATUS_TAXONOMY); default ok.
    status: str = "ok"
    reason: str = ""
    reason_detail: str = ""


class VolatilityPluginError(ValueError):
    """Raised when ``plugin`` is unknown or outside the allowlist.

    Subclass of ``ValueError`` so existing ``except (..., ValueError)``
    branches in ``server.py`` catch it without code change.
    """


def resolve_vol3_plugin(plugin: str) -> str:
    """Resolve a short alias or canonical name to a vetted vol3 plugin id.

    Raises ``VolatilityPluginError`` when the input matches neither an
    alias nor an entry in the canonical allowlist.
    """
    if not plugin or not isinstance(plugin, str):
        raise VolatilityPluginError(
            "plugin must be a non-empty string (alias or canonical 'windows.*' name)"
        )
    candidate = plugin.strip()
    if not candidate:
        raise VolatilityPluginError("plugin must not be blank")
    # Aliases are case-insensitive on the alias side only; canonical
    # plugin ids are exact (vol3 itself is case-sensitive).
    alias_hit = VOL3_PLUGIN_ALIASES.get(candidate.lower())
    if alias_hit is not None:
        return alias_hit
    if candidate in VOL3_ALLOWED_PLUGINS:
        return candidate
    raise VolatilityPluginError(
        f"Unknown or disallowed plugin: {plugin!r}. "
        f"Allowed aliases: {sorted(VOL3_PLUGIN_ALIASES)}; "
        f"canonical names: {sorted(VOL3_ALLOWED_PLUGINS)}"
    )


def _flatten_args(args: dict[str, Any] | None) -> list[str]:
    """Convert a key=value dict into vol3 CLI flags.

    Rules (deliberately conservative — vol3's CLI is plugin-specific):
      * key gets ``--`` prefix unless the caller already provided one.
      * underscores in the key become dashes (``pid_filter`` → ``--pid-filter``).
      * bool ``True`` emits a bare flag (``--dump``); bool ``False`` is dropped.
      * list / tuple values emit ``--key v1 v2 ...``.
      * scalar values stringify as ``--key value``.
      * ``None`` values are dropped (treated as "don't pass this flag").
    """
    if not args:
        return []
    flat: list[str] = []
    for raw_key, value in args.items():
        if value is None:
            continue
        if not isinstance(raw_key, str) or not raw_key:
            raise VolatilityPluginError(f"argument key must be a non-empty string, got {raw_key!r}")
        key = raw_key
        if not key.startswith("-"):
            key = "--" + key.replace("_", "-")
        if isinstance(value, bool):
            if value:
                flat.append(key)
            # False → flag suppressed entirely
            continue
        if isinstance(value, (list, tuple)):
            if not value:
                continue
            flat.append(key)
            flat.extend(str(v) for v in value)
            continue
        flat.append(key)
        flat.append(str(value))
    return flat


def _parse_vol3_json(stdout: str) -> list[dict[str, Any]]:
    """Parse vol3's ``-r json`` output into a list of row dicts.

    vol3 emits a JSON list of objects when given ``-r json``. Empty
    stdout / whitespace returns an empty list. Anything that doesn't
    decode to a list-of-dicts is treated as malformed and surfaced as a
    RuntimeError so the caller can include the upstream stderr in the
    diagnostic.
    """
    if not stdout.strip():
        return []
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"vol3 emitted non-JSON output: {exc}") from exc
    if isinstance(parsed, dict):
        # Some plugins may emit a single top-level dict — wrap.
        return [parsed]
    if not isinstance(parsed, list):
        raise RuntimeError(f"vol3 JSON output was {type(parsed).__name__}, expected list")
    rows: list[dict[str, Any]] = []
    for entry in parsed:
        if isinstance(entry, dict):
            rows.append(entry)
        else:
            logger.warning("Skipping non-dict vol3 row: %r", entry)
    return rows


async def run_volatility(
    target: str | Path,
    plugin: str,
    args: dict[str, Any] | None = None,
    *,
    timeout_seconds: int | None = None,
) -> VolatilityReport:
    """Run any allowlisted Volatility3 plugin against ``target``.

    Args:
        target: Path to the memory image.
        plugin: Short alias (``"malfind"``) or canonical id
            (``"windows.malfind.Malfind"``). Must be on the allowlist.
        args: Optional dict of plugin-specific kwargs flattened to
            ``--key value`` flags. ``True`` emits a bare flag, ``False``
            and ``None`` drop the flag, lists emit space-separated
            values.
        timeout_seconds: Per-call timeout override; otherwise resolved
            from ``AGENTROPIX_VOL3_TIMEOUT`` (default 600s, floor 5,
            ceiling 3600).

    Returns:
        VolatilityReport with rows preserved verbatim from vol3 JSON.

    Raises:
        VolatilityPluginError: plugin unknown / disallowed / blank arg key.
        FileNotFoundError: target image missing or vol binary missing.
        TimeoutError: vol exceeded the resolved timeout.
        RuntimeError: vol returned non-zero rc with empty stdout, or
            stdout did not parse as JSON.
    """
    canonical = resolve_vol3_plugin(plugin)
    timeout = float(_resolve_run_vol_timeout(timeout_seconds))

    image = Path(target)
    if not image.exists():
        raise FileNotFoundError(f"Memory image not found: {image}")

    # W-135: every allowlisted plugin in VOL3_ALLOWED_PLUGINS today is
    # memory-only — pslist, psscan, modules, modscan, driverscan,
    # netscan, malfind, svcscan, ldrmodules, hivelist, printkey,
    # userassist all need a memory layer. If new disk-aware plugins are
    # added later, gate this short-circuit by canonical name.
    if _is_disk_image(image):
        logger.info(
            "run_volatility(%s): short-circuiting disk-image input %s — memory plugin not applicable",
            canonical,
            image,
        )
        return VolatilityReport(
            image_path=str(image),
            plugin=canonical,
            row_count=0,
            tool_available=False,
            skipped_reason=_DISK_IMAGE_SKIP_REASON,
            image_class_detected="ewf-disk",
        )

    vol_path = shutil.which(TOOL_NAME)
    if not vol_path:
        raise FileNotFoundError(f"{TOOL_NAME} not found on PATH — install volatility3")

    extra = _flatten_args(args)
    cmd = [vol_path, "-f", str(image), "-r", "json", canonical, *extra]
    logger.info("run_volatility: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_bytes, stderr_bytes = await run_with_memory_limit(
        proc, timeout, f"vol-{canonical.split('.')[-1].lower()}"
    )

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")
    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError(f"Volatility {canonical} failed (rc={proc.returncode}): {stderr[:500]}")

    rows = _parse_vol3_json(stdout)
    return VolatilityReport(
        image_path=str(image),
        plugin=canonical,
        row_count=len(rows),
        rows=rows,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
    )


# --------------------------------------------------------------------------- #
# Issue #12 — credential-dump plugin wrappers                                 #
#                                                                             #
# Five thin wrappers around vol3's T1003 / T1059.003 plugins. Each follows    #
# the get_malfind shape (Pydantic Report model -> _parse_*_csv helper ->      #
# async subprocess + run_with_memory_limit) but without payload enrichment.   #
#                                                                             #
# The credential plugins' CSV layouts are not as stable across vol3 releases  #
# as pslist / netscan / malfind. Each parser therefore keeps the raw row in   #
# ``row`` on every entry so downstream Findings always have something to      #
# show even when canonical field names shift; the canonical fields are best- #
# effort and resolve case-insensitively.                                      #
# --------------------------------------------------------------------------- #


class HashdumpEntry(BaseModel):
    """Single ``windows.hashdump`` row — SAM NTLM hash (T1003.002)."""

    user: str = ""
    rid: int = 0
    lm_hash: str = ""
    nt_hash: str = ""
    row: dict[str, str] = Field(default_factory=dict)


class HashdumpReport(BaseModel):
    """Parsed Volatility hashdump result.

    W-135 fields populate only on the short-circuit path; see PsList docstring.
    """

    image_path: str
    entry_count: int
    entries: list[HashdumpEntry] = Field(default_factory=list)
    tool: str = "volatility3.windows.hashdump.Hashdump"
    raw_stderr: str = ""
    raw_stdout_sha256: str = ""
    tool_available: bool = True
    skipped_reason: str = ""
    image_class_detected: str = ""


def _parse_hashdump_csv(stdout: str) -> list[HashdumpEntry]:
    """Parse vol3 ``windows.hashdump -r csv`` into HashdumpEntry list.

    Header (vol3 ≥ 2.x): ``User,rid,lmhash,nthash``. Field names are
    matched case-insensitively because vol3 has historically toggled
    between PascalCase and lowercase across point releases. Rows whose
    User field is blank are silently dropped.
    """
    entries: list[HashdumpEntry] = []
    reader = csv.DictReader(io.StringIO(stdout))
    for row in reader:
        lc = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items() if k}
        user = lc.get("user", "")
        if not user:
            continue
        try:
            entries.append(
                HashdumpEntry(
                    user=user,
                    rid=_safe_int(lc.get("rid")),
                    lm_hash=lc.get("lmhash", "") or lc.get("lm_hash", ""),
                    nt_hash=lc.get("nthash", "") or lc.get("nt_hash", ""),
                    row={k: v for k, v in lc.items() if v},
                )
            )
        except (ValueError, KeyError) as exc:
            logger.warning("Skipping malformed hashdump row: %s", exc)
    return entries


async def get_hashdump(
    image: str | Path,
    *,
    timeout: float | None = None,
) -> HashdumpReport:
    """Run vol3 ``windows.hashdump`` — SAM NTLM hash extraction (T1003.002).

    Raises:
        FileNotFoundError: image or vol binary missing.
        TimeoutError: vol exceeded timeout.
        RuntimeError: vol returned non-zero rc with empty stdout.
    """
    timeout = _resolve_vol_timeout(timeout)
    image = Path(image)
    if not image.exists():
        raise FileNotFoundError(f"Memory image not found: {image}")

    if _is_disk_image(image):
        logger.info(
            "get_hashdump: short-circuiting disk-image input %s — memory plugin not applicable",
            image,
        )
        return HashdumpReport(
            image_path=str(image),
            entry_count=0,
            tool_available=False,
            skipped_reason=_DISK_IMAGE_SKIP_REASON,
            image_class_detected="ewf-disk",
        )

    vol_path = shutil.which(TOOL_NAME)
    if not vol_path:
        raise FileNotFoundError(f"{TOOL_NAME} not found on PATH — install volatility3")

    cmd = [vol_path, "-f", str(image), "-r", "csv", "windows.hashdump.Hashdump"]
    logger.info("Running hashdump: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await run_with_memory_limit(proc, timeout, "vol-hashdump")
    except (MemoryError, TimeoutError):
        raise

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")
    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError(f"Volatility hashdump failed (rc={proc.returncode}): {stderr[:500]}")

    entries = _parse_hashdump_csv(stdout)
    return HashdumpReport(
        image_path=str(image),
        entry_count=len(entries),
        entries=entries,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
    )


# Cap on how much LSA secret value gets surfaced into the Finding evidence
# string. The full hex blob lives on the structured ``value_hex`` field
# (and in the report's row dict); the truncation only affects the human-
# readable ``evidence`` string. 64 chars is enough to spot common DPAPI
# secret prefixes / well-known service-account boundaries without leaking
# entire hashes into report previews.
_LSADUMP_VALUE_PREVIEW_CHARS = 64


class LsadumpEntry(BaseModel):
    """Single ``windows.lsadump`` row — LSA secret (T1003.004)."""

    name: str = ""
    value: str = ""
    value_hex: str = ""
    row: dict[str, str] = Field(default_factory=dict)


class LsadumpReport(BaseModel):
    """Parsed Volatility lsadump result.

    W-135 fields populate only on the short-circuit path; see PsList docstring.
    """

    image_path: str
    entry_count: int
    entries: list[LsadumpEntry] = Field(default_factory=list)
    tool: str = "volatility3.windows.lsadump.Lsadump"
    raw_stderr: str = ""
    raw_stdout_sha256: str = ""
    tool_available: bool = True
    skipped_reason: str = ""
    image_class_detected: str = ""


def _parse_lsadump_csv(stdout: str) -> list[LsadumpEntry]:
    """Parse vol3 ``windows.lsadump -r csv`` into LsadumpEntry list.

    The header set has shifted across vol3 releases: ``Key,Secret,Hex``
    on some builds, ``Name,Value`` on others. We hunt for the secret
    name in (``key``, ``name``, ``secret_name``) and the value in
    (``secret``, ``value``); the hex blob in (``hex``, ``value_hex``).
    Blank-name rows are dropped.
    """
    entries: list[LsadumpEntry] = []
    reader = csv.DictReader(io.StringIO(stdout))
    for row in reader:
        lc = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items() if k}
        name = lc.get("key") or lc.get("name") or lc.get("secret_name") or ""
        if not name:
            continue
        value = lc.get("secret") or lc.get("value") or ""
        value_hex = lc.get("hex") or lc.get("value_hex") or ""
        try:
            entries.append(
                LsadumpEntry(
                    name=name,
                    value=value,
                    value_hex=value_hex,
                    row={k: v for k, v in lc.items() if v},
                )
            )
        except (ValueError, KeyError) as exc:
            logger.warning("Skipping malformed lsadump row: %s", exc)
    return entries


async def get_lsadump(
    image: str | Path,
    *,
    timeout: float | None = None,
) -> LsadumpReport:
    """Run vol3 ``windows.lsadump`` — LSA secrets extraction (T1003.004).

    Raises:
        FileNotFoundError: image or vol binary missing.
        TimeoutError: vol exceeded timeout.
        RuntimeError: vol returned non-zero rc with empty stdout.
    """
    timeout = _resolve_vol_timeout(timeout)
    image = Path(image)
    if not image.exists():
        raise FileNotFoundError(f"Memory image not found: {image}")

    if _is_disk_image(image):
        logger.info(
            "get_lsadump: short-circuiting disk-image input %s — memory plugin not applicable",
            image,
        )
        return LsadumpReport(
            image_path=str(image),
            entry_count=0,
            tool_available=False,
            skipped_reason=_DISK_IMAGE_SKIP_REASON,
            image_class_detected="ewf-disk",
        )

    vol_path = shutil.which(TOOL_NAME)
    if not vol_path:
        raise FileNotFoundError(f"{TOOL_NAME} not found on PATH — install volatility3")

    cmd = [vol_path, "-f", str(image), "-r", "csv", "windows.lsadump.Lsadump"]
    logger.info("Running lsadump: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await run_with_memory_limit(proc, timeout, "vol-lsadump")
    except (MemoryError, TimeoutError):
        raise

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")
    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError(f"Volatility lsadump failed (rc={proc.returncode}): {stderr[:500]}")

    entries = _parse_lsadump_csv(stdout)
    return LsadumpReport(
        image_path=str(image),
        entry_count=len(entries),
        entries=entries,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
    )


# Per-plugin truncation cap for the human-readable evidence string.
# Mirrors _LSADUMP_VALUE_PREVIEW_CHARS — the structured evidence_dict
# carries metadata only (lengths, names) so the wire-format report
# never serialises full credential material.
_CACHEDUMP_HASH_PREVIEW_CHARS = 16


class CachedumpEntry(BaseModel):
    """Single ``windows.cachedump`` row — cached domain credential (T1003.005)."""

    user: str = ""
    domain: str = ""
    mscache_hash: str = ""
    row: dict[str, str] = Field(default_factory=dict)


class CachedumpReport(BaseModel):
    """Parsed Volatility cachedump result.

    W-135 fields populate only on the short-circuit path; see PsList docstring.
    """

    image_path: str
    entry_count: int
    entries: list[CachedumpEntry] = Field(default_factory=list)
    tool: str = "volatility3.windows.cachedump.Cachedump"
    raw_stderr: str = ""
    raw_stdout_sha256: str = ""
    tool_available: bool = True
    skipped_reason: str = ""
    image_class_detected: str = ""


def _parse_cachedump_csv(stdout: str) -> list[CachedumpEntry]:
    """Parse vol3 ``windows.cachedump -r csv`` into CachedumpEntry list.

    The header set has shifted across vol3 releases. Canonical fields:
    ``Username,Domain,Hash`` (or lowercase variants); some builds emit
    ``User``/``MSCacheHash``. We hunt all known variants case-insensitively.
    Blank-username rows are dropped.
    """
    entries: list[CachedumpEntry] = []
    reader = csv.DictReader(io.StringIO(stdout))
    for row in reader:
        lc = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items() if k}
        user = lc.get("username") or lc.get("user") or ""
        if not user:
            continue
        domain = lc.get("domain") or lc.get("domain_name") or ""
        mscache_hash = (
            lc.get("hash")
            or lc.get("mscachehash")
            or lc.get("mscache_hash")
            or lc.get("dcc2_hash")
            or ""
        )
        try:
            entries.append(
                CachedumpEntry(
                    user=user,
                    domain=domain,
                    mscache_hash=mscache_hash,
                    row={k: v for k, v in lc.items() if v},
                )
            )
        except (ValueError, KeyError) as exc:
            logger.warning("Skipping malformed cachedump row: %s", exc)
    return entries


async def get_cachedump(
    image: str | Path,
    *,
    timeout: float | None = None,
) -> CachedumpReport:
    """Run vol3 ``windows.cachedump`` — cached domain credentials (T1003.005).

    Raises:
        FileNotFoundError: image or vol binary missing.
        TimeoutError: vol exceeded timeout.
        RuntimeError: vol returned non-zero rc with empty stdout.
    """
    timeout = _resolve_vol_timeout(timeout)
    image = Path(image)
    if not image.exists():
        raise FileNotFoundError(f"Memory image not found: {image}")

    if _is_disk_image(image):
        logger.info(
            "get_cachedump: short-circuiting disk-image input %s — memory plugin not applicable",
            image,
        )
        return CachedumpReport(
            image_path=str(image),
            entry_count=0,
            tool_available=False,
            skipped_reason=_DISK_IMAGE_SKIP_REASON,
            image_class_detected="ewf-disk",
        )

    vol_path = shutil.which(TOOL_NAME)
    if not vol_path:
        raise FileNotFoundError(f"{TOOL_NAME} not found on PATH — install volatility3")

    cmd = [vol_path, "-f", str(image), "-r", "csv", "windows.cachedump.Cachedump"]
    logger.info("Running cachedump: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await run_with_memory_limit(proc, timeout, "vol-cachedump")
    except (MemoryError, TimeoutError):
        raise

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")
    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError(f"Volatility cachedump failed (rc={proc.returncode}): {stderr[:500]}")

    entries = _parse_cachedump_csv(stdout)
    return CachedumpReport(
        image_path=str(image),
        entry_count=len(entries),
        entries=entries,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
    )


# Per-plugin truncation cap for the human-readable evidence string.
# cmdscan rows surface the recovered console command line, which can
# be very long (operator pipelines, base64-encoded payloads). The
# structured evidence_dict carries metadata only (lengths, pid, process)
# so the wire-format report never serialises the full command line.
_CMDSCAN_LINE_PREVIEW_CHARS = 200


class CmdscanEntry(BaseModel):
    """Single ``windows.cmdscan`` row — recovered console command (T1059.003)."""

    pid: int = 0
    process: str = ""
    command_line: str = ""
    row: dict[str, str] = Field(default_factory=dict)


class CmdscanReport(BaseModel):
    """Parsed Volatility cmdscan result.

    W-135 fields populate only on the short-circuit path; see PsList docstring.
    """

    image_path: str
    entry_count: int
    entries: list[CmdscanEntry] = Field(default_factory=list)
    tool: str = "volatility3.windows.cmdscan.CmdScan"
    raw_stderr: str = ""
    raw_stdout_sha256: str = ""
    tool_available: bool = True
    skipped_reason: str = ""
    image_class_detected: str = ""


def _parse_cmdscan_csv(stdout: str) -> list[CmdscanEntry]:
    """Parse vol3 ``windows.cmdscan -r csv`` into CmdscanEntry list.

    Confirmed live on vol3 2.28.0: real headers are
    ``TreeDepth,PID,Process,ConsoleInfo,Property,Address,Data`` — vol3
    emits one row per (console, Property) pair where Property is
    categorical (e.g. ``History``, ``Title``, ``ScreenBuffer``) and
    ``Data`` carries the value. We hunt the value under ``data`` first
    (matches real vol3 output) and fall back to legacy / non-standard
    builds (``command`` / ``commandline`` / ``cmd`` / ``text``). Rows
    with no value are dropped.
    """
    entries: list[CmdscanEntry] = []
    reader = csv.DictReader(io.StringIO(stdout))
    for row in reader:
        lc = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items() if k}
        command_line = (
            lc.get("data")
            or lc.get("command")
            or lc.get("commandline")
            or lc.get("cmd")
            or lc.get("text")
            or ""
        )
        if not command_line:
            continue
        process = lc.get("process") or lc.get("processname") or ""
        pid_raw = lc.get("pid") or "0"
        try:
            pid = int(pid_raw) if pid_raw.isdigit() else 0
            entries.append(
                CmdscanEntry(
                    pid=pid,
                    process=process,
                    command_line=command_line,
                    row={k: v for k, v in lc.items() if v},
                )
            )
        except (ValueError, KeyError) as exc:
            logger.warning("Skipping malformed cmdscan row: %s", exc)
    return entries


async def get_cmdscan(
    image: str | Path,
    *,
    timeout: float | None = None,
) -> CmdscanReport:
    """Run vol3 ``windows.cmdscan`` — recovered console commands (T1059.003).

    Raises:
        FileNotFoundError: image or vol binary missing.
        TimeoutError: vol exceeded timeout.
        RuntimeError: vol returned non-zero rc with empty stdout.
    """
    timeout = _resolve_vol_timeout(timeout)
    image = Path(image)
    if not image.exists():
        raise FileNotFoundError(f"Memory image not found: {image}")

    if _is_disk_image(image):
        logger.info(
            "get_cmdscan: short-circuiting disk-image input %s — memory plugin not applicable",
            image,
        )
        return CmdscanReport(
            image_path=str(image),
            entry_count=0,
            tool_available=False,
            skipped_reason=_DISK_IMAGE_SKIP_REASON,
            image_class_detected="ewf-disk",
        )

    vol_path = shutil.which(TOOL_NAME)
    if not vol_path:
        raise FileNotFoundError(f"{TOOL_NAME} not found on PATH — install volatility3")

    cmd = [vol_path, "-f", str(image), "-r", "csv", "windows.cmdscan.CmdScan"]
    logger.info("Running cmdscan: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await run_with_memory_limit(proc, timeout, "vol-cmdscan")
    except (MemoryError, TimeoutError):
        raise

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")
    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError(f"Volatility cmdscan failed (rc={proc.returncode}): {stderr[:500]}")

    entries = _parse_cmdscan_csv(stdout)
    return CmdscanReport(
        image_path=str(image),
        entry_count=len(entries),
        entries=entries,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
    )


# Per-plugin truncation cap for the human-readable evidence string.
# consoles surfaces the recovered console buffer which is typically
# multi-line (recent commands plus their output). Wider cap than
# cmdscan because the buffer carries useful surrounding context.
_CONSOLES_BUFFER_PREVIEW_CHARS = 400


class ConsolesEntry(BaseModel):
    """Single ``windows.consoles`` row — recovered console buffer (T1059.003)."""

    pid: int = 0
    process: str = ""
    console_buffer: str = ""
    row: dict[str, str] = Field(default_factory=dict)


class ConsolesReport(BaseModel):
    """Parsed Volatility consoles result.

    W-135 fields populate only on the short-circuit path; see PsList docstring.
    """

    image_path: str
    entry_count: int
    entries: list[ConsolesEntry] = Field(default_factory=list)
    tool: str = "volatility3.windows.consoles.Consoles"
    raw_stderr: str = ""
    raw_stdout_sha256: str = ""
    tool_available: bool = True
    skipped_reason: str = ""
    image_class_detected: str = ""


def _parse_consoles_csv(stdout: str) -> list[ConsolesEntry]:
    """Parse vol3 ``windows.consoles -r csv`` into ConsolesEntry list.

    Confirmed live on vol3 2.28.0: real headers are
    ``TreeDepth,PID,Process,ConsoleInfo,Property,Address,Data`` — same
    structure as cmdscan, one row per (console, Property) pair with
    the value in ``Data``. We hunt the value under ``data`` first and
    fall back to legacy variants (``buffer`` / ``consolebuffer`` /
    ``text`` / ``output``). Rows with no value are dropped.
    """
    entries: list[ConsolesEntry] = []
    reader = csv.DictReader(io.StringIO(stdout))
    for row in reader:
        lc = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items() if k}
        console_buffer = (
            lc.get("data")
            or lc.get("buffer")
            or lc.get("consolebuffer")
            or lc.get("text")
            or lc.get("output")
            or ""
        )
        if not console_buffer:
            continue
        process = lc.get("process") or lc.get("processname") or ""
        pid_raw = lc.get("pid") or "0"
        try:
            pid = int(pid_raw) if pid_raw.isdigit() else 0
            entries.append(
                ConsolesEntry(
                    pid=pid,
                    process=process,
                    console_buffer=console_buffer,
                    row={k: v for k, v in lc.items() if v},
                )
            )
        except (ValueError, KeyError) as exc:
            logger.warning("Skipping malformed consoles row: %s", exc)
    return entries


async def get_consoles(
    image: str | Path,
    *,
    timeout: float | None = None,
) -> ConsolesReport:
    """Run vol3 ``windows.consoles`` — recovered console buffers (T1059.003).

    Raises:
        FileNotFoundError: image or vol binary missing.
        TimeoutError: vol exceeded timeout.
        RuntimeError: vol returned non-zero rc with empty stdout.
    """
    timeout = _resolve_vol_timeout(timeout)
    image = Path(image)
    if not image.exists():
        raise FileNotFoundError(f"Memory image not found: {image}")

    if _is_disk_image(image):
        logger.info(
            "get_consoles: short-circuiting disk-image input %s — memory plugin not applicable",
            image,
        )
        return ConsolesReport(
            image_path=str(image),
            entry_count=0,
            tool_available=False,
            skipped_reason=_DISK_IMAGE_SKIP_REASON,
            image_class_detected="ewf-disk",
        )

    vol_path = shutil.which(TOOL_NAME)
    if not vol_path:
        raise FileNotFoundError(f"{TOOL_NAME} not found on PATH — install volatility3")

    cmd = [vol_path, "-f", str(image), "-r", "csv", "windows.consoles.Consoles"]
    logger.info("Running consoles: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await run_with_memory_limit(proc, timeout, "vol-consoles")
    except (MemoryError, TimeoutError):
        raise

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")
    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError(f"Volatility consoles failed (rc={proc.returncode}): {stderr[:500]}")

    entries = _parse_consoles_csv(stdout)
    return ConsolesReport(
        image_path=str(image),
        entry_count=len(entries),
        entries=entries,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
    )


# --------------------------------------------------------------------------- #
# W-216: dumpfiles NULL-trim MD5
# --------------------------------------------------------------------------- #
#
# vol3's ``windows.dumpfiles.DumpFiles`` carves files from the OS file cache.
# Cache pages are page-aligned (typically 4 KiB) so the carved output often
# carries trailing NUL bytes that were not part of the original file. The
# platform-expected MD5 is computed against the *trimmed* content (TeamSpy
# Q11: ``2c51251c…`` padded vs ``00e41368…`` trimmed — see
# logs/2026-05-16-cyberdefenders-teamspy-analysis/REPORT.md Step 11).
#
# This block exposes the contract a future dumpfiles wrapper (or a downstream
# agent calling vol3 directly) should emit per carved file. The model and
# helper are unit-tested in isolation; wiring into a full ``get_dumpfiles``
# wrapper is deferred to a follow-up ticket.


class DumpFilesEntry(BaseModel):
    """One carved file from vol3 ``windows.dumpfiles.DumpFiles``.

    ``md5_raw`` / ``size_raw`` are computed on the bytes vol3 wrote.
    ``md5_trimmed`` / ``size_trimmed`` strip trailing NUL bytes from EOF
    so the hash matches the platform-expected value when the original
    file ended before its cache page did. See module-level note.
    """

    path: str
    md5_raw: str
    md5_trimmed: str
    size_raw: int
    size_trimmed: int


def _trim_trailing_nuls(path: Path) -> tuple[str, int]:
    """Return ``(md5_hex, size)`` for ``path`` with trailing NULs stripped.

    Mirrors the manual hex-trim that analysts perform on
    ``windows.dumpfiles`` output. The hash is MD5 because that is what
    the CyberDefenders / SANS submission platforms expect for carved
    artefact identity; this is fingerprint matching, not cryptographic
    integrity (``usedforsecurity=False``).
    """
    raw = path.read_bytes()
    trimmed = raw.rstrip(b"\x00")
    return hashlib.md5(trimmed, usedforsecurity=False).hexdigest(), len(trimmed)


# --------------------------------------------------------------------------- #
# W-225: per-object PST/OST carve via vol3 windows.dumpfiles --filter
# --------------------------------------------------------------------------- #
#
# Foremost-style bulk carving fails on PST/OST containers because the recovery
# window is byte-pattern-only and size-capped — the carved file has the !BDN
# magic but no valid page tree, so pypff sees an unsupported content_type
# code and bails out. vol3's ``windows.dumpfiles`` walks the file-cache
# _SECTION_OBJECT_POINTERS for each _FILE_OBJECT it identifies, so the
# resulting carve is a single contiguous object with header + pages intact.
#
# W-225 wraps that path for the specific case of mail containers (.pst /
# .ost) and pairs every carve with the W-216 trim helper so the analyst
# gets both raw and trimmed MD5 out-of-the-box.


# Hard default of 30 min for dumpfiles — the plugin enumerates the kernel
# file-cache tree before carving anything, which is genuinely slow on a
# 16+ GiB image. Caller can override per-call.
_W225_DEFAULT_TIMEOUT = 1800.0

# Regex passed to vol3 --filter. Vol3's filter is applied to the file-name
# leaf of the _FILE_OBJECT path; case is handled by --ignore-case.
_W225_PST_FILTER = r"\.(pst|ost)$"


async def carve_pst_objects(
    image: str | Path,
    *,
    output_dir: str | Path,
    timeout: float | None = None,
) -> list[DumpFilesEntry]:
    """Carve every PST/OST _FILE_OBJECT from a memory image.

    Runs vol3 ``windows.dumpfiles.DumpFiles --filter '\\.(pst|ost)$'``
    against ``image``, writing carved files to ``output_dir`` and
    returning one ``DumpFilesEntry`` per carved file. ``output_dir``
    must exist on entry (vol3 refuses to create it).

    Each entry's ``md5_raw`` / ``size_raw`` reflect the bytes vol3
    wrote; ``md5_trimmed`` / ``size_trimmed`` strip trailing NUL pad
    bytes per W-216 so the hash matches the platform-expected value.

    Returns an empty list when vol3 found no matching objects; raises
    when vol3 itself failed (missing binary, timeout, non-zero rc with
    empty output dir).
    """
    image = Path(image)
    if not image.exists():
        raise FileNotFoundError(f"Memory image not found: {image}")

    if _is_disk_image(image):
        logger.info(
            "carve_pst_objects: skipping disk-image input %s — memory plugin not applicable",
            image,
        )
        return []

    output_dir = Path(output_dir)
    if not output_dir.is_dir():
        raise FileNotFoundError(
            f"output_dir does not exist: {output_dir} (vol3 will not create it)"
        )

    vol_path = shutil.which(TOOL_NAME)
    if not vol_path:
        raise FileNotFoundError(f"{TOOL_NAME} not found on PATH — install volatility3")

    eff_timeout = timeout if timeout is not None else _W225_DEFAULT_TIMEOUT

    cmd = [
        vol_path,
        "-f",
        str(image),
        "-o",
        str(output_dir),
        "--parallelism",
        "off",
        "-r",
        "csv",
        "windows.dumpfiles.DumpFiles",
        "--filter",
        _W225_PST_FILTER,
        "--ignore-case",
    ]
    logger.info("Running W-225 PST carve: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await run_with_memory_limit(
            proc, eff_timeout, "vol-dumpfiles-pst"
        )
    except (MemoryError, TimeoutError):
        raise

    stderr = stderr_bytes.decode(errors="replace")
    carved = sorted(p for p in output_dir.iterdir() if p.is_file())
    if proc.returncode != 0 and not carved:
        raise RuntimeError(f"vol3 dumpfiles failed (rc={proc.returncode}): {stderr[:500]}")

    entries: list[DumpFilesEntry] = []
    for p in carved:
        try:
            raw = p.read_bytes()
        except OSError as exc:
            logger.warning("W-225: failed to read carved file %s: %s", p, exc)
            continue
        md5_raw = hashlib.md5(raw, usedforsecurity=False).hexdigest()
        md5_trimmed, size_trimmed = _trim_trailing_nuls(p)
        entries.append(
            DumpFilesEntry(
                path=str(p),
                md5_raw=md5_raw,
                md5_trimmed=md5_trimmed,
                size_raw=len(raw),
                size_trimmed=size_trimmed,
            )
        )
    return entries


# --------------------------------------------------------------------------- #
# SIFT-W-208 — process memdump + strings + grep chain
# --------------------------------------------------------------------------- #
# CyberDefenders "TeamSpy" / SANS Find Evil!-style memory forensics: carve a
# single process's address space, then mine the dump with strings + grep for
# C2 URLs, credentials, command-line args, mail headers, etc.
#
# vol2 workflow (from the TeamSpy writeup):
#   volatility -f mem.img --profile=Win7SP1x64 memdump -p 1364 -D out/
#   strings out/1364.dmp | grep teamview
#   strings -e l out/3056.dmp | grep -i password   # UTF-16LE for cmdline args
#
# vol3 equivalent:
#   vol -f mem.img -o out/ windows.memmap.Memmap --pid 1364 --dump
#   # produces out/pid.1364.dmp
#
# The wrapper composes three primitives the TeamSpy chain depends on:
#   get_memdump()          — vol3 memmap --dump → MemdumpResult
#   memdump_strings_grep() — memdump → strings → re.search → MemdumpGrepReport
#
# Bytes-on-disk is deliberate: process dumps can run to ~1 GiB and we don't
# want them in Python memory. The chain function streams the dump through
# the existing strings.run_strings wrapper (which itself streams + caps).


# Process dumps are larger than VAD dumps (one VAD vs whole address space).
# Default 4 GiB covers ~95% of modern Windows user processes (Outlook with
# 1-10 GB mailbox = 200 MiB - 1.5 GiB; Chrome renderer high-mem tab =
# 500 MiB - 2 GiB; MsMpEng Defender = 500 MiB - 2 GiB; Cobalt Strike
# svchost injection = parent + payload, often > 1 GiB). The original
# 1 GiB default truncated common IR targets on Win10/11.
# Floor 64 MiB rules out trivially-small caps that would skip every
# realistic process; ceiling 16 GiB allows enterprise apps (SQL Server,
# Java -Xmx8g, Vmware host) on workstations with adequate /tmp budget.
_MEMDUMP_MAX_BYTES_DEFAULT = 4 * 1024 * 1024 * 1024  # 4 GiB
_MEMDUMP_MAX_BYTES_FLOOR = 64 * 1024 * 1024  # 64 MiB
_MEMDUMP_MAX_BYTES_CEILING = 16 * 1024 * 1024 * 1024  # 16 GiB

# Cap on grep hits returned per chain call. 200 covers a noisy URL grep
# (one process dump can produce dozens of HTTP strings). Floor 10 prevents
# accidentally silencing the chain; ceiling 10000 prevents an over-broad
# pattern from drowning a Finding payload.
_MEMDUMP_GREP_MAX_HITS_DEFAULT = 200
_MEMDUMP_GREP_MAX_HITS_FLOOR = 10
_MEMDUMP_GREP_MAX_HITS_CEILING = 10000

# vol3 memmap.Memmap emits the dump under the -o output dir as
# `pid.<PID>.dmp`. The vol2 equivalent was `<PID>.dmp`. We sort all .dmp
# files and pick the one matching the PID to be robust against vol3
# renaming the convention.
_VOL3_MEMDUMP_FILENAME_PATTERNS = (
    "pid.{pid}.dmp",
    "{pid}.dmp",
)


class MemdumpResult(BaseModel):
    """Output of one ``windows.memmap.Memmap --pid <N> --dump`` invocation.

    ``dump_path`` references a file inside the tmpdir the wrapper created.
    The file is cleaned up by ``get_memdump``'s context manager on return,
    so callers cannot reopen the path. Use ``memdump_strings_grep`` for
    in-line mining; use ``get_memdump`` only when the caller manages its
    own ``output_dir`` and needs the dump bytes for further processing.
    """

    image_path: str
    pid: int
    dump_path: str = ""
    dump_size_bytes: int = 0
    # SIFT-W-082: SHA-256 of the .dmp bytes — chain-of-custody fingerprint.
    dump_sha256: str = ""
    tool: str = "volatility3.windows.memmap.Memmap"
    raw_stderr: str = ""
    # W-135 input-class signalling — see PsList docstring.
    tool_available: bool = True
    skipped_reason: str = ""
    image_class_detected: str = ""
    # QA WS-A status taxonomy (gated by AGENTROPIX_STATUS_TAXONOMY); default ok.
    status: str = "ok"
    reason: str = ""
    reason_detail: str = ""


class MemdumpGrepHit(BaseModel):
    """One ``strings | grep`` hit inside a process memdump."""

    pid: int
    encoding: str = "s"
    offset: int = 0
    text: str = ""


class MemdumpGrepReport(BaseModel):
    """memdump → strings → grep chain result.

    ``hits`` is sorted by offset ascending (positional reproducibility).
    ``truncated`` is True iff the ``max_hits`` cap fired. ``dump_sha256``
    is the SHA-256 of the .dmp bytes the grep ran against — same value
    that would appear on a ``MemdumpResult`` for the same image+pid.
    """

    image_path: str
    pid: int
    pattern: str
    encoding: str = "s"
    hit_count: int = 0
    hits: list[MemdumpGrepHit] = Field(default_factory=list)
    truncated: bool = False
    dump_size_bytes: int = 0
    dump_sha256: str = ""
    tool: str = "volatility3.memmap + binutils.strings + python.re"
    raw_stderr: str = ""
    # W-135 input-class signalling — see PsList docstring.
    tool_available: bool = True
    skipped_reason: str = ""
    image_class_detected: str = ""
    # QA WS-A status taxonomy (gated by AGENTROPIX_STATUS_TAXONOMY); default ok.
    status: str = "ok"
    reason: str = ""
    reason_detail: str = ""


def _find_memdump_file(tmpdir: Path, pid: int) -> Path | None:
    """Locate the .dmp vol3 emitted for ``pid`` in ``tmpdir``.

    vol3's memmap renames have flipped between releases (``pid.<N>.dmp``
    vs ``<N>.dmp``). Try the known patterns first, then fall back to any
    .dmp whose basename contains the PID.
    """
    for pattern in _VOL3_MEMDUMP_FILENAME_PATTERNS:
        candidate = tmpdir / pattern.format(pid=pid)
        if candidate.exists():
            return candidate
    pid_marker = str(pid)
    for p in sorted(tmpdir.glob("*.dmp")):
        if pid_marker in p.name:
            return p
    return None


async def _run_vol_memdump(
    image: Path,
    pid: int,
    tmpdir: Path,
    *,
    timeout: float,
) -> tuple[int, bytes]:
    """Invoke ``vol -f <image> -o <tmpdir> windows.memmap.Memmap --pid <N> --dump``.

    Returns ``(returncode, stderr_bytes)``. The dump file lands in
    ``tmpdir`` under one of ``_VOL3_MEMDUMP_FILENAME_PATTERNS``; the
    caller resolves it with ``_find_memdump_file``. Subprocess errors
    (timeout, OSError, MemoryError) return ``(-1, str(exc).encode())``.
    """
    vol_path = shutil.which(TOOL_NAME)
    if not vol_path:
        return -1, b"vol binary not on PATH"
    cmd = [
        vol_path,
        "-f",
        str(image),
        "-o",
        str(tmpdir),
        "windows.memmap.Memmap",
        "--pid",
        str(pid),
        "--dump",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _stdout, stderr_bytes = await run_with_memory_limit(proc, timeout, "vol-memdump")
        return proc.returncode, stderr_bytes
    except (TimeoutError, MemoryError, OSError) as exc:
        logger.warning("memdump subprocess failed for pid=%s: %s", pid, exc)
        return -1, str(exc).encode()


async def get_memdump(
    image: Path,
    pid: int,
    *,
    output_dir: Path | None = None,
    max_bytes: int | None = None,
    timeout: float | None = None,
) -> MemdumpResult:
    """Carve one process's address space to a .dmp file.

    Wraps vol3 ``windows.memmap.Memmap --pid <N> --dump``. Replaces the
    vol2 workflow ``volatility -f <img> memdump -p <pid> -D <out>`` used
    in CyberDefenders TeamSpy / SANS Find Evil! style challenges.

    When ``output_dir`` is None, the dump lands in a tempdir that is
    cleaned up before return; ``dump_path`` will reference the
    now-deleted file. Use ``memdump_strings_grep`` for the inline-mine
    flow. When ``output_dir`` is provided, the dump persists and the
    caller owns the file's lifecycle.

    On any failure (missing image, disk image input per W-135, missing
    vol, oversize dump, subprocess error), returns a result with
    ``dump_size_bytes=0`` and ``skipped_reason`` populated — never
    raises.
    """
    if max_bytes is None:
        max_bytes = get_int(
            "AGENTROPIX_MEMDUMP_MAX_BYTES",
            _MEMDUMP_MAX_BYTES_DEFAULT,
            floor=_MEMDUMP_MAX_BYTES_FLOOR,
            ceiling=_MEMDUMP_MAX_BYTES_CEILING,
        )
    timeout = _resolve_vol_timeout(timeout)
    result = MemdumpResult(image_path=str(image), pid=pid)

    if not image.exists():
        result.tool_available = False
        result.skipped_reason = f"image not found: {image}"
        return result

    if _is_disk_image(image):
        result.image_class_detected = "E01/EWF disk image"
        result.skipped_reason = _DISK_IMAGE_SKIP_REASON
        return result

    if shutil.which(TOOL_NAME) is None:
        result.tool_available = False
        result.skipped_reason = f"{TOOL_NAME} binary not on PATH"
        return result

    # When caller-managed output_dir is provided, dump persists; otherwise
    # use a tempdir that we clean up on return.
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        rc, stderr_bytes = await _run_vol_memdump(image, pid, output_dir, timeout=timeout)
        result.raw_stderr = stderr_bytes[:1024].decode(errors="replace")
        if rc != 0:
            result.skipped_reason = f"vol memdump rc={rc}"
            return result
        dump_file = _find_memdump_file(output_dir, pid)
        if dump_file is None:
            result.skipped_reason = "vol produced no .dmp for pid"
            return result
        size = dump_file.stat().st_size
        if size > max_bytes:
            result.skipped_reason = f"dump size {size} exceeds cap {max_bytes}"
            return result
        result.dump_path = str(dump_file)
        result.dump_size_bytes = size
        result.dump_sha256 = _sha256_file(dump_file)
        return result

    with tempfile.TemporaryDirectory(prefix="sift-memdump-") as tmpdir_str:
        tmpdir = Path(tmpdir_str)
        rc, stderr_bytes = await _run_vol_memdump(image, pid, tmpdir, timeout=timeout)
        result.raw_stderr = stderr_bytes[:1024].decode(errors="replace")
        if rc != 0:
            result.skipped_reason = f"vol memdump rc={rc}"
            return result
        dump_file = _find_memdump_file(tmpdir, pid)
        if dump_file is None:
            result.skipped_reason = "vol produced no .dmp for pid"
            return result
        size = dump_file.stat().st_size
        if size > max_bytes:
            result.skipped_reason = f"dump size {size} exceeds cap {max_bytes}"
            return result
        result.dump_path = str(dump_file)
        result.dump_size_bytes = size
        result.dump_sha256 = _sha256_file(dump_file)
        # tmpdir cleanup happens on context exit; dump_path becomes stale.
        return result


def _sha256_file(path: Path) -> str:
    """Stream-hash a file; returns empty string on read error."""
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError as exc:
        logger.warning("memdump sha256 read failed for %s: %s", path, exc)
        return ""
    return h.hexdigest()


async def memdump_strings_grep(
    image: Path,
    pid: int,
    pattern: str,
    *,
    encoding: str = "s",
    min_length: int | None = None,
    max_hits: int | None = None,
    max_bytes: int | None = None,
    case_insensitive: bool = False,
    timeout: float | None = None,
) -> MemdumpGrepReport:
    """memdump → strings → grep chain (TeamSpy workflow).

    1. Carve the process address space via ``windows.memmap.Memmap --dump``
    2. Run ``strings -a -t d -e <encoding>`` over the resulting .dmp via
       the existing ``run_strings`` wrapper (streamed; honors max_results)
    3. Filter strings matching ``pattern`` via ``re.search``
    4. Return up to ``max_hits`` matches with byte offset + matched text

    The dump file lives in a tempdir that is cleaned up before return —
    no file persists on disk.

    Args:
        image: Path to memory acquisition (.dmp / .vmem / .mem / .lime).
        pid: Target process PID.
        pattern: Python regex (passed to ``re.compile``).
        encoding: GNU strings ``-e`` selector. ``s`` = 7-bit ASCII
            (default), ``l`` = UTF-16LE (covers Windows wide-char
            cmdline args — the case that motivated W-208's wide-char
            requirement).
        min_length: Min string length (``strings -n``). Defaults to
            ``AGENTROPIX_STRINGS_MIN_LENGTH`` or 4.
        max_hits: Cap on returned hits. Defaults to
            ``AGENTROPIX_MEMDUMP_GREP_MAX_HITS`` (default 200).
        max_bytes: Cap on dump size. Defaults to
            ``AGENTROPIX_MEMDUMP_MAX_BYTES`` (default 4 GiB; floor
            64 MiB, ceiling 16 GiB — modern Windows IR targets
            including Outlook with large mailboxes, Chrome
            renderers, MsMpEng/Defender, and Cobalt-injected
            svchost commonly exceed 1 GiB).
        case_insensitive: If True, compile pattern with ``re.IGNORECASE``.
        timeout: Per-subprocess timeout (vol3 + strings each).

    Returns:
        MemdumpGrepReport. On any failure: empty hits + populated
        ``skipped_reason``. Never raises (callers wire this into
        agent Findings — exceptions must not poison the iteration).
    """
    # Defer the strings import to runtime to avoid a circular wrapper
    # dependency at module load (strings.py itself does not depend on
    # volatility.py, but keeping the import lazy means a strings.py
    # refactor never needs a volatility.py reload).
    from agentropix_mcp.wrappers.strings import run_strings

    if max_hits is None:
        max_hits = get_int(
            "AGENTROPIX_MEMDUMP_GREP_MAX_HITS",
            _MEMDUMP_GREP_MAX_HITS_DEFAULT,
            floor=_MEMDUMP_GREP_MAX_HITS_FLOOR,
            ceiling=_MEMDUMP_GREP_MAX_HITS_CEILING,
        )

    report = MemdumpGrepReport(
        image_path=str(image),
        pid=pid,
        pattern=pattern,
        encoding=encoding,
    )

    # Compile the pattern up-front — a bad regex is a caller error and
    # ValueError is the appropriate failure mode (unlike subprocess
    # errors which we swallow into skipped_reason for agent safety).
    flags = re.IGNORECASE if case_insensitive else 0
    try:
        regex = re.compile(pattern, flags)
    except re.error as exc:
        raise ValueError(f"invalid pattern {pattern!r}: {exc}") from exc

    with tempfile.TemporaryDirectory(prefix="sift-memdump-grep-") as tmpdir_str:
        tmpdir = Path(tmpdir_str)
        dump_result = await get_memdump(
            image, pid, output_dir=tmpdir, max_bytes=max_bytes, timeout=timeout
        )
        # Propagate short-circuit reasons (disk image, missing vol, etc.).
        if not dump_result.dump_path or dump_result.dump_size_bytes == 0:
            report.tool_available = dump_result.tool_available
            report.skipped_reason = dump_result.skipped_reason
            report.image_class_detected = dump_result.image_class_detected
            report.raw_stderr = dump_result.raw_stderr
            return report

        report.dump_size_bytes = dump_result.dump_size_bytes
        report.dump_sha256 = dump_result.dump_sha256

        # Pull strings over a high cap — we filter to ``max_hits`` after
        # regex; the underlying strings pass needs to see enough volume
        # that a sparse pattern still finds candidates. Floor at 4× the
        # grep hit cap so a perfectly-matching corpus still has room.
        strings_max = max(_MEMDUMP_GREP_MAX_HITS_CEILING, max_hits * 50)
        try:
            strings_report = await run_strings(
                Path(dump_result.dump_path),
                min_length=min_length,
                encoding=encoding,
                max_results=strings_max,
                timeout=timeout,
            )
        except (FileNotFoundError, ValueError, RuntimeError, TimeoutError) as exc:
            report.skipped_reason = f"strings invocation failed: {exc}"
            return report

        hits: list[MemdumpGrepHit] = []
        truncated = False
        for entry in strings_report.entries:
            if regex.search(entry.text) is None:
                continue
            if len(hits) >= max_hits:
                truncated = True
                break
            hits.append(
                MemdumpGrepHit(
                    pid=pid,
                    encoding=encoding,
                    offset=entry.offset,
                    text=entry.text,
                )
            )

        # Sort by offset ascending for reproducibility (strings already
        # emits in scan order, but explicit sort guards against future
        # changes to the underlying wrapper).
        hits.sort(key=lambda h: h.offset)

        report.hits = hits
        report.hit_count = len(hits)
        report.truncated = truncated
        return report
