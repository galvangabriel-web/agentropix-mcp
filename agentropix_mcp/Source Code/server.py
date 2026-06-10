"""FastMCP server exposing SIFT tools as typed functions.

W1: 4 tools (pslist, plaso timeline, tsk_fls, ewf image_info).
W3: 8 tools (+ regripper, prefetch, amcache, shimcache).
Target: ≥15 by end of M3.

The MCP server is the enforcement boundary — Thymus policy runs here,
not in the agent. The agent literally has no tool to write evidence.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import defaultdict
from pathlib import Path

from pydantic import BaseModel

from agentropix_mcp._env import clamp_int, get_int
from agentropix_mcp._trace import traced
from agentropix_mcp.reports.export import ExportResult, export_report
from agentropix_mcp.reports.render import ToolchainUnavailable
from agentropix_mcp.thymus_policy import ThymusEvidencePolicy
from agentropix_mcp.wrappers.amcache import AmcacheReport, get_amcache
from agentropix_mcp.wrappers.bstrings import BstringsReport, get_bstrings
from agentropix_mcp.wrappers.bulk_extractor import BulkReport, run_bulk_extractor
from agentropix_mcp.wrappers.case_ingest import (
    IngestOutcome,
)
from agentropix_mcp.wrappers.case_ingest import (
    idx_ingest as _idx_ingest_impl,
)
from agentropix_mcp.wrappers.case_lifecycle import (
    CaseRecord,
    CaseStatusReport,
    EvidenceRegisterResult,
)
from agentropix_mcp.wrappers.case_lifecycle import (
    case_activate as _case_activate_impl,
)
from agentropix_mcp.wrappers.case_lifecycle import (
    case_init as _case_init_impl,
)
from agentropix_mcp.wrappers.case_lifecycle import (
    case_status as _case_status_impl,
)
from agentropix_mcp.wrappers.case_lifecycle import (
    evidence_register as _evidence_register_impl,
)
from agentropix_mcp.wrappers.case_queries import (
    IdxAggregateResult,
    IdxCaseSummaryResult,
    IdxSearchResult,
    IdxTimelineResult,
)
from agentropix_mcp.wrappers.case_queries import (
    idx_aggregate as _idx_aggregate_impl,
)
from agentropix_mcp.wrappers.case_queries import (
    idx_case_summary as _idx_case_summary_impl,
)
from agentropix_mcp.wrappers.case_queries import (
    idx_search as _idx_search_impl,
)
from agentropix_mcp.wrappers.case_queries import (
    idx_timeline as _idx_timeline_impl,
)
from agentropix_mcp.wrappers.case_records import (
    ApproveFindingResult,
    DeleteFindingResult,
    RecordFindingResult,
    RecordTimelineResult,
    ReportGenerateResult,
)
from agentropix_mcp.wrappers.case_records import (
    approve_finding as _approve_finding_impl,
)
from agentropix_mcp.wrappers.case_records import (
    delete_finding as _delete_finding_impl,
)
from agentropix_mcp.wrappers.case_records import (
    record_finding as _record_finding_impl,
)
from agentropix_mcp.wrappers.case_records import (
    record_timeline_event as _record_timeline_impl,
)
from agentropix_mcp.wrappers.case_records import (
    report_generate as _report_generate_impl,
)
from agentropix_mcp.wrappers.case_records import (
    retract_approval as _retract_approval_impl,
)
from agentropix_mcp.wrappers.correlation import (
    IOCPivotReport,
    ProcessTreeReport,
    SweepReport,
    TimelineReport,
    build_process_tree,
    correlate_timeline,
    detect_sweep,
    pivot_on_ioc,
)
from agentropix_mcp.wrappers.editbox import EditBoxResult, get_editbox
from agentropix_mcp.wrappers.evt import EvtReport
from agentropix_mcp.wrappers.evt import get_evt as evt_get_evt
from agentropix_mcp.wrappers.evtx import EvtxReport, get_evtx
from agentropix_mcp.wrappers.ewf import ImageInfo, get_image_info
from agentropix_mcp.wrappers.executable_registry import (
    ExecRegistryQueryResult,
    ExecutableRegistry,
    PromoteResult,
)
from agentropix_mcp.wrappers.executable_registry import (
    build_executable_registry as _build_ear_impl,
)
from agentropix_mcp.wrappers.executable_registry import (
    exec_registry_get as _exec_get_impl,
)
from agentropix_mcp.wrappers.executable_registry import (
    exec_registry_search as _exec_search_impl,
)
from agentropix_mcp.wrappers.executable_registry import (
    promote_executable_registry as _promote_ear_impl,
)
from agentropix_mcp.wrappers.exiftool import ExiftoolReport, run_exiftool
from agentropix_mcp.wrappers.extract import ExtractManifest, extract_files
from agentropix_mcp.wrappers.extract_archive import (
    ExtractArchiveManifest,
    extract_archive,
)
from agentropix_mcp.wrappers.foremost import ForemostReport, run_foremost
from agentropix_mcp.wrappers.glob_paths import GlobPathsResult, run_glob_paths
from agentropix_mcp.wrappers.hashdeep import HashdeepReport, run_hashdeep
from agentropix_mcp.wrappers.ioc_registry import PromoteIOCsResult
from agentropix_mcp.wrappers.ioc_registry import promote_iocs as _promote_iocs_impl
from agentropix_mcp.wrappers.jlecmd import JLECmdReport, get_jlecmd
from agentropix_mcp.wrappers.lecmd import LECmdReport, get_lecmd
from agentropix_mcp.wrappers.maldoc import MacroReport, analyze_maldoc
from agentropix_mcp.wrappers.mftecmd import MFTECmdReport, get_mftecmd
from agentropix_mcp.wrappers.pdf_extract_text import (
    PdfDocument,
    pdf_extract_text,
)
from agentropix_mcp.wrappers.plaso import TimelineEvents, get_timeline
from agentropix_mcp.wrappers.prefetch import PrefetchReport, get_prefetch
from agentropix_mcp.wrappers.recmd import RECmdReport, get_recmd
from agentropix_mcp.wrappers.regripper import RegistryReport, get_registry
from agentropix_mcp.wrappers.sbecmd import SBECmdReport, get_sbecmd
from agentropix_mcp.wrappers.shimcache import ShimcacheReport, get_shimcache
from agentropix_mcp.wrappers.sqlecmd import SQLECmdReport, get_sqlecmd
from agentropix_mcp.wrappers.srum import SrumExtractResult, srum_extract
from agentropix_mcp.wrappers.strings import StringsReport, run_strings
from agentropix_mcp.wrappers.tsk import FileListing, PartitionTable
from agentropix_mcp.wrappers.tsk import fls as tsk_fls
from agentropix_mcp.wrappers.tsk import get_partitions as tsk_get_partitions
from agentropix_mcp.wrappers.volatility import (
    MalfindReport,
    NetscanReport,
    PsList,
    SvcscanReport,
    VolatilityPluginError,
    VolatilityReport,
    get_malfind,
    get_netscan,
    get_pslist,
    get_svcscan,
    run_volatility,
)
from agentropix_mcp.wrappers.yara import YaraReport, scan_yara

logger = logging.getLogger(__name__)

# Thymus read-only policy — enforced at MCP boundary
_policy = ThymusEvidencePolicy()


def configure_policy(extra_allowed: list[str] | None = None) -> None:
    """Reconfigure Thymus policy with additional allowed paths."""
    global _policy
    _policy = ThymusEvidencePolicy(extra_allowed=extra_allowed)


class ToolError(BaseModel):
    """Structured error response from a tool call."""

    tool: str
    error: str
    suggestion: str = ""


class _RateLimiter:
    """Simple per-tool rate limiter (sliding-window).

    W-092: ``check`` performs a read-filter-write sequence on
    ``self._calls[tool_name]``. Under FastMCP HTTP transport's worker
    pool, multiple threads (or asyncio tasks dispatched on different
    threads) can race the sequence: two callers may both observe
    ``len(window) < limit`` before either appends, blowing past the
    cap; or one caller's filter can drop entries the other just
    appended. A ``threading.Lock`` around the critical section makes
    the limit deterministic. asyncio coroutines on a single thread
    cannot preempt each other inside the lock since the section is
    non-blocking, so a single threading.Lock covers both transports.

    W-120: Rate limit is now per-tool-overridable via env var
    ``AGENTROPIX_RATE_LIMIT_<TOOL_NAME>``. Bursty tools (e.g.
    ``extract_files`` iterating over thousands of files in a single
    investigation) need a higher ceiling than the global 60/minute
    default, while interactive tools stay capped at the safe default.
    Resolution is per-call (cheap env lookup) so operators can adjust
    a single tool's ceiling without restarting the server.
    """

    def __init__(self, calls_per_minute: int = 60) -> None:
        self._limit = calls_per_minute
        self._calls: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def _resolve_limit(self, tool_name: str) -> int:
        """Return the per-tool calls/minute cap.

        Honors ``AGENTROPIX_RATE_LIMIT_<TOOL_NAME>`` env override
        (uppercased, dots/dashes → underscores) before falling back
        to the global default. Bounded [1, 10000] to prevent
        accidental disable.
        """
        env_key = f"AGENTROPIX_RATE_LIMIT_{tool_name.upper().replace('.', '_').replace('-', '_')}"
        raw = os.environ.get(env_key, "")
        if raw:
            try:
                value = int(raw)
                if 1 <= value <= 10_000:
                    return value
            except ValueError:
                pass
        return self._limit

    def check(self, tool_name: str) -> str | None:
        """Return error string if rate limited, None if allowed."""
        now = time.monotonic()
        limit = self._resolve_limit(tool_name)
        with self._lock:
            window = [t for t in self._calls[tool_name] if now - t < 60.0]
            self._calls[tool_name] = window
            if len(window) >= limit:
                return f"Rate limited: {tool_name} exceeded {limit} calls/minute"
            self._calls[tool_name].append(now)
            return None


_rate_limiter = _RateLimiter(
    calls_per_minute=get_int("AGENTROPIX_RATE_LIMIT", 60, floor=1, ceiling=10000)
)


# W-101: when ``mcp_scan_yara`` is given a bare rule name (e.g.
# ``"malware"``) instead of an absolute path, resolve it against the
# configured YARA rules directory so Thymus sees a real path. Without
# this, the operator gets a confusing REJECT (the bare name is not
# under any allowed prefix). Tries ``<dir>/<name>``,
# ``<dir>/<name>.yar``, then ``<dir>/<name>.yara`` in order; the first
# existing file wins. Returns the original input unchanged when the
# input already looks like an absolute path or no rules-dir is set.
_DEFAULT_YARA_RULES_DIR = "/usr/share/yara/rules/"
_YARA_RULE_SUFFIXES = ("", ".yar", ".yara")


def _resolve_yara_rule(rule: str) -> str:
    if rule.startswith("/"):
        return rule
    rules_dir = os.environ.get("AGENTROPIX_YARA_RULES_DIR", _DEFAULT_YARA_RULES_DIR).strip()
    if not rules_dir:
        return rule
    base = Path(rules_dir)
    for suffix in _YARA_RULE_SUFFIXES:
        candidate = base / f"{rule}{suffix}"
        if candidate.is_file():
            return str(candidate)
    # No file matched any extension. Return the bare-name + first-suffix
    # variant under the rules dir so Thymus rejects with a meaningful
    # path (operator sees where the lookup happened) rather than the
    # raw bare name.
    return str(base / f"{rule}.yar")


# Archive suffixes the analyzer can't read directly (vol3 silently emits
# ghost processes when handed a .7z; ewfinfo / TSK ifind also fail with
# unhelpful errors). Surface the real problem at the MCP boundary instead.
_ARCHIVE_SUFFIXES = frozenset(
    {".7z", ".zip", ".rar", ".tar", ".tgz", ".tbz2", ".txz", ".gz", ".bz2", ".xz"}
)
_DOUBLE_ARCHIVE_SUFFIXES = frozenset({".tar.gz", ".tar.bz2", ".tar.xz"})


def _reject_archive(tool: str, path: str) -> ToolError | None:
    """Refuse to operate on a compressed archive (Bug 1, 2026-04-25).

    Volatility 3's typical failure mode when handed a `.7z` or `.zip`
    is silently emitting ghost processes (PID 0, name 'unknown') with
    a stderr line ``Unable to validate the plugin requirements:
    ['plugins.PsList.kernel.layer_name', ...]``. The agent then tries
    to reason over typed garbage. Catch the archive at the MCP
    boundary and return a clear ToolError pointing at the W-076
    archive picker (``agents/_archive.py::find_memory_dump``) for the
    canonical extract-then-analyze flow.
    """
    from pathlib import Path

    p = Path(path)
    suffix = p.suffix.lower()
    last_two = "".join(s.lower() for s in p.suffixes[-2:])
    if suffix in _ARCHIVE_SUFFIXES or last_two in _DOUBLE_ARCHIVE_SUFFIXES:
        return ToolError(
            tool=tool,
            error=(
                f"Refusing to run on a compressed archive: {path}. "
                f"Volatility/most analyzers can't read archives directly; "
                f"vol3 silently returns ghost processes when handed one."
            ),
            suggestion=(
                f"Call the extract_archive MCP tool first, then re-call. "
                f"Example:\n"
                f'  extract_archive(archive="{path}", '
                f'dest="/tmp/agentropix-sift-extract-<session>/")\n'
                f"and pass the extracted memory dump path back into the "
                f"analyzer. The W-076 archive picker at "
                f"`agents/_archive.py::find_memory_dump` is the canonical "
                f"helper for selecting the memory image out of the "
                f"extract_archive result."
            ),
        )
    return None


@traced("get_pslist")
async def mcp_get_pslist(
    image: str,
    pid_filter: list[int] | None = None,
) -> PsList | ToolError:
    """List processes from a Windows memory image.

    Uses Volatility3 windows.pslist.PsList plugin.
    Read-only: no writes to the image file.

    W-135: when ``image`` is an E01/EWF disk image (the wrong asset
    class for memory plugins), the call short-circuits before invoking
    vol3 and returns a ``PsList`` with ``tool_available=False``,
    ``image_class_detected="ewf-disk"``, and a populated
    ``skipped_reason``. Acquire memory of the same host (.dmp /
    .vmem / .mem) and re-run.
    """
    rate_err = _rate_limiter.check("get_pslist")
    if rate_err:
        return ToolError(tool="get_pslist", error=rate_err)

    archive_err = _reject_archive("get_pslist", image)
    if archive_err:
        return archive_err

    violation = _policy.check_read(image)
    if violation:
        return ToolError(tool="get_pslist", error=violation)

    try:
        return await get_pslist(image, pid_filter=pid_filter)
    except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as e:
        return ToolError(tool="get_pslist", error=str(e))


@traced("run_volatility")
async def mcp_run_volatility(
    target: str,
    plugin: str,
    args: dict[str, object] | None = None,
    timeout_seconds: int | None = None,
) -> VolatilityReport | ToolError:
    """Run any allowlisted Volatility3 ``windows.*`` plugin (W-098).

    A single generic escape hatch that exposes the top-20 vol3 plugins
    through one MCP tool instead of forcing one tool per plugin. The
    ``plugin`` argument accepts either the short alias (``"malfind"``)
    or the canonical id (``"windows.malfind.Malfind"``) and is checked
    against an allowlist before any subprocess spawn. ``args`` becomes
    plugin-specific CLI flags.

    W-135: when ``target`` is an E01/EWF disk image, the call
    short-circuits before invoking vol3 and returns a
    ``VolatilityReport`` with ``tool_available=False``,
    ``image_class_detected="ewf-disk"``, and a populated
    ``skipped_reason``. The current allowlist is entirely memory-only
    plugins, so this guards every supported plugin.
    """
    rate_err = _rate_limiter.check("run_volatility")
    if rate_err:
        return ToolError(tool="run_volatility", error=rate_err)

    archive_err = _reject_archive("run_volatility", target)
    if archive_err:
        return archive_err

    violation = _policy.check_read(target)
    if violation:
        return ToolError(tool="run_volatility", error=violation)

    try:
        return await run_volatility(
            target,
            plugin,
            args,
            timeout_seconds=timeout_seconds,
        )
    except VolatilityPluginError as e:
        # Allowlist / alias-resolution failure — distinct from a crash.
        return ToolError(
            tool="run_volatility",
            error=str(e),
            suggestion=(
                "Pass a short alias (e.g. 'malfind') or a canonical id from the "
                "VOL3_ALLOWED_PLUGINS allowlist; arbitrary plugin names are not exposed."
            ),
        )
    except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as e:
        return ToolError(tool="run_volatility", error=str(e))


@traced("get_netscan")
async def mcp_get_netscan(image: str) -> NetscanReport | ToolError:
    """List open TCP/UDP sockets from a Windows memory image (W-140).

    Uses Volatility3 windows.netscan.NetScan with the -r csv renderer,
    which is more reliable than -r json for netscan on all tested images.
    Returns a typed NetscanReport with SocketInfo rows instead of raw
    dict rows from the generic run_volatility path.

    W-135: when image is an E01/EWF disk image the call short-circuits
    and returns NetscanReport with tool_available=False.
    """
    rate_err = _rate_limiter.check("get_netscan")
    if rate_err:
        return ToolError(tool="get_netscan", error=rate_err)

    archive_err = _reject_archive("get_netscan", image)
    if archive_err:
        return archive_err

    violation = _policy.check_read(image)
    if violation:
        return ToolError(tool="get_netscan", error=violation)

    try:
        return await get_netscan(image)
    except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as e:
        return ToolError(tool="get_netscan", error=str(e))


@traced("get_malfind")
async def mcp_get_malfind(image: str) -> MalfindReport | ToolError:
    """Detect injected code / RWX VAD regions in a Windows memory image (W-140).

    Uses Volatility3 windows.malfind.Malfind with the -r csv renderer.
    Returns a typed MalfindReport with MalfindHit rows including PID,
    process name, address, VAD tag, protection flags, and hexdump head.

    W-135: when image is an E01/EWF disk image the call short-circuits
    and returns MalfindReport with tool_available=False.
    """
    rate_err = _rate_limiter.check("get_malfind")
    if rate_err:
        return ToolError(tool="get_malfind", error=rate_err)

    archive_err = _reject_archive("get_malfind", image)
    if archive_err:
        return archive_err

    violation = _policy.check_read(image)
    if violation:
        return ToolError(tool="get_malfind", error=violation)

    try:
        return await get_malfind(image)
    except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as e:
        return ToolError(tool="get_malfind", error=str(e))


@traced("get_svcscan")
async def mcp_get_svcscan(image: str) -> SvcscanReport | ToolError:
    """Enumerate Windows services from a memory image via pool-tag scanning (W-140).

    Uses Volatility3 windows.svcscan.SvcScan with the -r csv renderer.
    Returns a typed SvcscanReport with ServiceInfo rows including PID,
    service name, display name, state, start type, and binary path.
    Unlike pslist-based approaches, svcscan finds services whose SCM
    entries are still in pool memory even if the process has terminated.

    W-135: when image is an E01/EWF disk image the call short-circuits
    and returns SvcscanReport with tool_available=False.
    """
    rate_err = _rate_limiter.check("get_svcscan")
    if rate_err:
        return ToolError(tool="get_svcscan", error=rate_err)

    archive_err = _reject_archive("get_svcscan", image)
    if archive_err:
        return archive_err

    violation = _policy.check_read(image)
    if violation:
        return ToolError(tool="get_svcscan", error=violation)

    try:
        return await get_svcscan(image)
    except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as e:
        return ToolError(tool="get_svcscan", error=str(e))


@traced("get_editbox")
async def mcp_get_editbox(
    image: str,
    profile: str | None = None,
    timeout_seconds: float | None = None,
    max_records: int | None = None,
) -> EditBoxResult | ToolError:
    """Recover Edit-control widget contents via Vol2.6 `editbox` (W-209).

    Vol3 has no `editbox` plugin; this wrapper drives the legacy Vol2.6.1
    plugin out-of-process for TeamSpy-class credential recovery. The
    Vol2.6 sandbox (Python 2.7 venv + vol.py) must be installed per
    docs/runbooks/vol26-install.md; the wrapper raises FileNotFoundError
    pointing at that runbook when the sandbox is absent.

    Read-only: no writes to the image file. `profile` is validated against
    [A-Za-z0-9_]+ as an argv-injection guard; `imageinfo` autodetects
    when omitted (result cached on image SHA-256 per process).
    """
    rate_err = _rate_limiter.check("get_editbox")
    if rate_err:
        return ToolError(tool="get_editbox", error=rate_err)

    violation = _policy.check_read(image)
    if violation:
        return ToolError(tool="get_editbox", error=violation)

    try:
        return await get_editbox(
            image,
            profile=profile,
            timeout=timeout_seconds,
            max_records=max_records,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError, ValueError) as e:
        return ToolError(tool="get_editbox", error=str(e))


# --------------------------------------------------------------------------- #
# W-150: Correlation layer — four cross-artifact analysis tools                #
# --------------------------------------------------------------------------- #


@traced("correlate_timeline")
async def mcp_correlate_timeline(
    images: list[str],
    channels: list[str] | None = None,
    event_ids: list[int] | None = None,
    window_start: str | None = None,
    window_end: str | None = None,
    max_events_per_host: int = 5000,
) -> TimelineReport | ToolError:
    """Join EVTX events from multiple hosts into a single sorted timeline (W-150).

    Fetches Security/System events from every image concurrently, merges
    and sorts by UTC timestamp, and annotates each event with the
    inter-event delta_ms. Useful for reconstructing lateral movement
    sequences where a single host's log is insufficient.

    All images are Thymus-policy-checked before any I/O begins.
    """
    rate_err = _rate_limiter.check("correlate_timeline")
    if rate_err:
        return ToolError(tool="correlate_timeline", error=rate_err)

    for img in images:
        violation = _policy.check_read(img)
        if violation:
            return ToolError(tool="correlate_timeline", error=violation)

    try:
        return await correlate_timeline(
            images,
            channels=channels,
            event_ids=event_ids,
            window_start=window_start,
            window_end=window_end,
            max_events_per_host=max_events_per_host,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as e:
        return ToolError(tool="correlate_timeline", error=str(e))


@traced("build_process_tree")
async def mcp_build_process_tree(
    image: str,
) -> ProcessTreeReport | ToolError:
    """Build a PPID-linked process forest from a memory image (W-151).

    Calls get_pslist() (with psscan fallback on paused-VM images) and
    constructs a parent-child tree by PPID. Annotates LOLBins spawned
    by sensitive parents (services.exe, lsass.exe, etc.) as suspicious.

    Returns roots (well-parented trees), orphans (broken PPID = DKOM
    indicator), and a suspicious_count for triage prioritization.
    """
    rate_err = _rate_limiter.check("build_process_tree")
    if rate_err:
        return ToolError(tool="build_process_tree", error=rate_err)

    archive_err = _reject_archive("build_process_tree", image)
    if archive_err:
        return archive_err

    violation = _policy.check_read(image)
    if violation:
        return ToolError(tool="build_process_tree", error=violation)

    try:
        return await build_process_tree(image)
    except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as e:
        return ToolError(tool="build_process_tree", error=str(e))


@traced("pivot_on_ioc")
async def mcp_pivot_on_ioc(
    ioc: str,
    images: list[str],
    artifact_types: list[str] | None = None,
    ioc_type: str = "string",
) -> IOCPivotReport | ToolError:
    """Expand a single IOC across all artifact types and hosts (W-152).

    Searches get_pslist, get_netscan, get_svcscan, and get_evtx results
    for every image for the IOC value (case-insensitive substring). Returns
    every matching record with full field context and a per-host hit count.

    Example IOCs: "10.10.254.1", "rubyw.exe", "spsql", "MSSQLServerMSRS12".
    """
    rate_err = _rate_limiter.check("pivot_on_ioc")
    if rate_err:
        return ToolError(tool="pivot_on_ioc", error=rate_err)

    for img in images:
        violation = _policy.check_read(img)
        if violation:
            return ToolError(tool="pivot_on_ioc", error=violation)

    try:
        return await pivot_on_ioc(
            ioc,
            images,
            artifact_types=artifact_types,
            ioc_type=ioc_type,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as e:
        return ToolError(tool="pivot_on_ioc", error=str(e))


@traced("detect_sweep")
async def mcp_detect_sweep(
    image: str,
    window_seconds: float = 1.0,
    min_shares_per_window: int = 3,
    event_ids: list[int] | None = None,
) -> SweepReport | ToolError:
    """Detect SMB share enumeration bursts from Security Event Log (W-153).

    Fetches EID 5140/5145 events and applies a sliding-window algorithm:
    if >= min_shares_per_window unique shares are accessed from the same
    source IP within window_seconds, the burst is flagged as a sweep.

    SRL-2018 baseline: spsql accessed 20,013 shares across 37 hosts.
    Default thresholds (3 shares / 1 second) are tuned to detect this
    pattern with zero false positives on the SRL-2018 Security log.
    """
    rate_err = _rate_limiter.check("detect_sweep")
    if rate_err:
        return ToolError(tool="detect_sweep", error=rate_err)

    violation = _policy.check_read(image)
    if violation:
        return ToolError(tool="detect_sweep", error=violation)

    try:
        return await detect_sweep(
            image,
            window_seconds=window_seconds,
            min_shares_per_window=min_shares_per_window,
            event_ids=event_ids,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as e:
        return ToolError(tool="detect_sweep", error=str(e))


@traced("get_timeline")
async def mcp_get_timeline(
    image: str,
    parsers: str | None = None,
    max_events: int = 2000,
) -> TimelineEvents | ToolError:
    """Generate a super timeline from a disk image.

    Uses Plaso log2timeline.py + psort.py pipeline.
    Read-only: no writes to the image file.
    """
    rate_err = _rate_limiter.check("get_timeline")
    if rate_err:
        return ToolError(tool="get_timeline", error=rate_err)

    violation = _policy.check_read(image)
    if violation:
        return ToolError(tool="get_timeline", error=violation)

    try:
        return await get_timeline(image, parsers=parsers, max_events=max_events)
    except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as e:
        return ToolError(tool="get_timeline", error=str(e))


@traced("fls")
async def mcp_fls(
    image: str,
    offset: int = 0,
    inode: str | None = None,
    recursive: bool = False,
    deleted_only: bool = False,
    fstype: str | None = None,
    summary_only: bool = False,
) -> FileListing | ToolError:
    """List files in a disk image filesystem.

    Uses Sleuth Kit fls command.
    Read-only: no writes to the image file.

    Args:
        image: Path to disk image.
        offset: Partition offset in sectors (for multi-partition images).
        inode: Starting inode (default: root).
        recursive: Recurse into all directories.
        deleted_only: Show only deleted entries.
        fstype: Filesystem type override (e.g., "ntfs", "ext4").
    """
    rate_err = _rate_limiter.check("fls")
    if rate_err:
        return ToolError(tool="fls", error=rate_err)

    violation = _policy.check_read(image)
    if violation:
        return ToolError(tool="fls", error=violation)

    try:
        return await tsk_fls(
            image,
            offset=offset,
            inode=inode,
            recursive=recursive,
            deleted_only=deleted_only,
            fstype=fstype,
            summary_only=summary_only,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError) as e:
        return ToolError(tool="fls", error=str(e))


async def mcp_get_partitions(image: str) -> PartitionTable | ToolError:
    """Enumerate a disk image's partition table via Sleuth Kit mmls (NIST1 ISSUE-001).

    Read-only. Returns the partition rows plus ``filesystem_offsets`` — the
    start sectors to pass to ``fls(offset=...)`` / ``extract_files`` so an
    autonomous agent need not guess offset 0 (which lands on the MBR).

    Args:
        image: Path to the disk image (raw .dd/.001 or EWF .E01).
    """
    rate_err = _rate_limiter.check("get_partitions")
    if rate_err:
        return ToolError(tool="get_partitions", error=rate_err)

    violation = _policy.check_read(image)
    if violation:
        return ToolError(tool="get_partitions", error=violation)

    try:
        return await tsk_get_partitions(image)
    except (FileNotFoundError, RuntimeError, TimeoutError) as e:
        return ToolError(tool="get_partitions", error=str(e))


async def mcp_get_evt(
    source: str,
    mode: str = "items",
    max_events: int | None = None,
    summary_only: bool = False,
) -> EvtReport | ToolError:
    """Parse a legacy Windows ``.evt`` EventLog (XP/2003) via libevt evtexport
    (NIST1 ISSUE-008). Read-only. ``.evtx`` is handled by get_evtx; this covers
    the binary ``.evt`` that get_evtx N/As on. Returns normalised event rows.

    Args:
        source: Path to the extracted ``.evt`` file.
        mode: ``items`` (allocated, default), ``recovered``, or ``all``.
        max_events: Cap on returned rows (default 5000).
        summary_only: Return event_count but omit the events list.
    """
    rate_err = _rate_limiter.check("get_evt")
    if rate_err:
        return ToolError(tool="get_evt", error=rate_err)

    violation = _policy.check_read(source)
    if violation:
        return ToolError(tool="get_evt", error=violation)

    try:
        return await evt_get_evt(
            source, mode=mode, max_events=max_events, summary_only=summary_only
        )
    except (FileNotFoundError, RuntimeError, TimeoutError, ValueError) as e:
        return ToolError(tool="get_evt", error=str(e))


@traced("get_registry")
async def mcp_get_registry(
    hive: str,
    profile: str | None = None,
    plugin: str | None = None,
) -> RegistryReport | ToolError:
    """Run RegRipper plugins against a Windows registry hive.

    Uses regripper rip.pl with either a profile (-f) or a single plugin (-p).
    Read-only: no writes to the hive file.
    """
    rate_err = _rate_limiter.check("get_registry")
    if rate_err:
        return ToolError(tool="get_registry", error=rate_err)

    violation = _policy.check_read(hive)
    if violation:
        return ToolError(tool="get_registry", error=violation)

    try:
        return await get_registry(hive, profile=profile, plugin=plugin)
    except (FileNotFoundError, RuntimeError, TimeoutError, ValueError) as e:
        return ToolError(tool="get_registry", error=str(e))


@traced("get_prefetch")
async def mcp_get_prefetch(
    target: str,
) -> PrefetchReport | ToolError:
    """Parse Windows Prefetch artifacts under `target`.

    `target` can be a Prefetch directory (extracted from the disk image)
    or a single .pf file. Read-only: no writes to the target.
    """
    rate_err = _rate_limiter.check("get_prefetch")
    if rate_err:
        return ToolError(tool="get_prefetch", error=rate_err)

    violation = _policy.check_read(target)
    if violation:
        return ToolError(tool="get_prefetch", error=violation)

    try:
        return await get_prefetch(target)
    except (FileNotFoundError, RuntimeError, TimeoutError) as e:
        return ToolError(tool="get_prefetch", error=str(e))


@traced("srum_extract")
async def mcp_srum_extract(
    srudb_path: str,
    tables: list[str] | None = None,
    since_iso: str | None = None,
    limit: int = 1000,
    include_idmap: bool = False,
    timeout_seconds: float | None = None,
) -> SrumExtractResult | ToolError:
    """Parse a ``SRUDB.dat`` ESE database into per-table forensic records.

    Read-only: never writes to the SRUDB. esedbexport materializes
    per-table TSV in a process-private tempdir which is removed before
    the call returns.
    """
    rate_err = _rate_limiter.check("srum_extract")
    if rate_err:
        return ToolError(tool="srum_extract", error=rate_err)

    violation = _policy.check_read(srudb_path)
    if violation:
        return ToolError(tool="srum_extract", error=violation)

    try:
        return await srum_extract(
            srudb_path,
            tables=tables,
            since_iso=since_iso,
            limit=limit,
            include_idmap=include_idmap,
            timeout=timeout_seconds,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError, ValueError) as e:
        return ToolError(tool="srum_extract", error=str(e))


# =============================================================================
# SIFT-W-289: case-lifecycle MCP tools (4 of the 13 P0 from the Valhuntir
# SYNTHESIS). Indexer wiring lives in agentropix_mcp.wazuh.client; the
# inner wrappers in wrappers/case_lifecycle.py accept an injected client
# so tests stub at the boundary.
# =============================================================================


# SIFT-W-296c (Critic B fix): process-wide singleton IndexerClient.
# ``IndexerClient.__init__`` eagerly opens an ``httpx.AsyncClient`` (a
# connection pool) that must be reused, not reconstructed per call —
# the prior code built + abandoned one on every case_*/idx_*/record_*/
# report_* MCP call, leaking sockets in the long-lived server process.
# httpx.AsyncClient is explicitly designed to be long-lived and shared,
# so a single cached instance is the correct pattern. The OS reclaims
# the pool at process exit; no per-call leak. Config changes are picked
# up on server restart (same lifecycle the orchestrator's own client
# assumes).
_INDEXER_CLIENT_SINGLETON: object | None = None
_INDEXER_CLIENT_LOCK = threading.Lock()


def _get_indexer_client() -> object | None:
    """Resolve a shared IndexerClient from WazuhConfig. Returns ``None``
    if the Wazuh integration is disabled or the indexer isn't configured
    — in which case the case-lifecycle tools degrade to pointer-only
    (case_init still updates the active-case file; case_status returns
    indexer_reachable=False without raising).

    Returns a cached singleton so the underlying httpx connection pool
    is reused across calls (SIFT-W-296c — Critic B resource-leak fix).
    Construction mirrors ``orchestrator.index_findings()`` TLS-verify +
    auth semantics.
    """
    global _INDEXER_CLIENT_SINGLETON
    if _INDEXER_CLIENT_SINGLETON is not None:
        return _INDEXER_CLIENT_SINGLETON
    try:
        from agentropix_mcp.wazuh.config import WazuhConfig
        from agentropix_mcp.wazuh.indexer_client import IndexerClient

        cfg = WazuhConfig.from_env()
        if not cfg.integration_enabled or not cfg.indexer_url:
            return None
        if not cfg.indexer_user or not cfg.indexer_password:
            return None
        with _INDEXER_CLIENT_LOCK:
            if _INDEXER_CLIENT_SINGLETON is None:
                _INDEXER_CLIENT_SINGLETON = IndexerClient(
                    indexer_url=cfg.indexer_url,
                    indexer_user=cfg.indexer_user,
                    indexer_password=cfg.indexer_password,
                    tls_verify=getattr(cfg, "indexer_tls_verify", True),
                    tls_ca_bundle=getattr(cfg, "tls_ca_bundle", None),
                )
        return _INDEXER_CLIENT_SINGLETON
    except Exception:
        return None


async def reset_indexer_client_singleton() -> None:
    """Close + clear the cached IndexerClient. For graceful shutdown
    hooks + tests that need a clean slate. Safe to call when no client
    was ever constructed."""
    global _INDEXER_CLIENT_SINGLETON
    client = _INDEXER_CLIENT_SINGLETON
    _INDEXER_CLIENT_SINGLETON = None
    if client is not None and hasattr(client, "aclose"):
        try:
            await client.aclose()
        except Exception:
            pass


@traced("case_init")
async def mcp_case_init(
    case_name: str,
    examiner_id: str,
    case_id: str | None = None,
    description: str = "",
    incident_type: str = "",
    severity: str = "",
    scope: str = "",
    team: list[str] | None = None,
    tags: list[str] | None = None,
    case_dir: str = "",
    payload: dict | None = None,
) -> CaseRecord | ToolError:
    """Create a new case + update the active-case pointer.

    Indexes one document into ``agentropix-cases`` (single-doc index
    keyed by ``case_id``; re-running with the same id upserts). Falls
    back to pointer-only when the indexer is unreachable.
    """
    rate_err = _rate_limiter.check("case_init")
    if rate_err:
        return ToolError(tool="case_init", error=rate_err)
    client = _get_indexer_client()
    try:
        return await _case_init_impl(
            case_name=case_name,
            case_id=case_id,
            description=description,
            examiner_id=examiner_id,
            incident_type=incident_type,
            severity=severity,
            scope=scope,
            team=team,
            tags=tags,
            case_dir=case_dir,
            payload=payload,
            indexer_client=client,
        )
    except (ValueError, FileNotFoundError) as exc:
        return ToolError(tool="case_init", error=str(exc))


@traced("case_activate")
async def mcp_case_activate(case_id: str) -> dict | ToolError:
    """Switch the active-case pointer at ``~/.agentropix/active_case``."""
    rate_err = _rate_limiter.check("case_activate")
    if rate_err:
        return ToolError(tool="case_activate", error=rate_err)
    try:
        return await _case_activate_impl(case_id)
    except ValueError as exc:
        return ToolError(tool="case_activate", error=str(exc))


@traced("case_status")
async def mcp_case_status(
    case_id: str | None = None,
) -> CaseStatusReport | ToolError:
    """Aggregate the agentropix-cases row + per-sibling-index doc counts."""
    rate_err = _rate_limiter.check("case_status")
    if rate_err:
        return ToolError(tool="case_status", error=rate_err)
    client = _get_indexer_client()
    try:
        return await _case_status_impl(case_id, indexer_client=client)
    except ValueError as exc:
        return ToolError(tool="case_status", error=str(exc))


@traced("evidence_register")
async def mcp_evidence_register(
    path: str,
    description: str,
    examiner_id: str,
    case_id: str | None = None,
    payload: dict | None = None,
) -> EvidenceRegisterResult | ToolError:
    """SHA-256 hash an evidence file and register it under the active case."""
    rate_err = _rate_limiter.check("evidence_register")
    if rate_err:
        return ToolError(tool="evidence_register", error=rate_err)
    violation = _policy.check_read(path)
    if violation:
        return ToolError(tool="evidence_register", error=violation)
    client = _get_indexer_client()
    try:
        return await _evidence_register_impl(
            path=path,
            description=description,
            case_id=case_id,
            examiner_id=examiner_id,
            payload=payload,
            indexer_client=client,
        )
    except (ValueError, FileNotFoundError) as exc:
        return ToolError(tool="evidence_register", error=str(exc))


# =============================================================================
# SIFT-W-290: idx_* query + ingest MCP tools (5 of the 13 P0 from the
# Valhuntir SYNTHESIS). All share _get_indexer_client() defined above
# (degraded mode on indexer outage). idx_ingest's findings half routes
# through the W-286 draft-gate via the wazuh_index_findings FastMCP
# tool wired in mcp_idx_ingest_findings_half below.
# =============================================================================


@traced("idx_search")
async def mcp_idx_search(
    query: dict | None = None,
    case_id: str | None = None,
    index_pattern: str = "agentropix-findings-*",
    limit: int = 50,
    offset: int = 0,
) -> IdxSearchResult | ToolError:
    """Case-scoped full-text + structured search, paged."""
    rate_err = _rate_limiter.check("idx_search")
    if rate_err:
        return ToolError(tool="idx_search", error=rate_err)
    client = _get_indexer_client()
    try:
        return await _idx_search_impl(
            query=query,
            case_id=case_id,
            index_pattern=index_pattern,
            limit=limit,
            offset=offset,
            indexer_client=client,
        )
    except ValueError as exc:
        return ToolError(tool="idx_search", error=str(exc))


@traced("idx_aggregate")
async def mcp_idx_aggregate(
    field: str,
    case_id: str | None = None,
    index_pattern: str = "agentropix-findings-*",
    query: dict | None = None,
    top_n: int = 25,
) -> IdxAggregateResult | ToolError:
    """Top-N terms / cardinality aggregation on a case-scoped index."""
    rate_err = _rate_limiter.check("idx_aggregate")
    if rate_err:
        return ToolError(tool="idx_aggregate", error=rate_err)
    client = _get_indexer_client()
    try:
        return await _idx_aggregate_impl(
            field=field,
            case_id=case_id,
            index_pattern=index_pattern,
            query=query,
            top_n=top_n,
            indexer_client=client,
        )
    except ValueError as exc:
        return ToolError(tool="idx_aggregate", error=str(exc))


@traced("idx_timeline")
async def mcp_idx_timeline(
    case_id: str | None = None,
    index_pattern: str = "agentropix-timeline-*",
    query: dict | None = None,
    interval: str = "1h",
    time_field: str = "@timestamp",
) -> IdxTimelineResult | ToolError:
    """date_histogram bucketing across the case-scoped index."""
    rate_err = _rate_limiter.check("idx_timeline")
    if rate_err:
        return ToolError(tool="idx_timeline", error=rate_err)
    client = _get_indexer_client()
    try:
        return await _idx_timeline_impl(
            case_id=case_id,
            index_pattern=index_pattern,
            query=query,
            interval=interval,
            time_field=time_field,
            indexer_client=client,
        )
    except ValueError as exc:
        return ToolError(tool="idx_timeline", error=str(exc))


@traced("idx_case_summary")
async def mcp_idx_case_summary(
    case_id: str | None = None,
) -> IdxCaseSummaryResult | ToolError:
    """Case overview: counts + top hosts + top artifact types + time
    range + next-step hints."""
    rate_err = _rate_limiter.check("idx_case_summary")
    if rate_err:
        return ToolError(tool="idx_case_summary", error=rate_err)
    client = _get_indexer_client()
    try:
        return await _idx_case_summary_impl(case_id=case_id, indexer_client=client)
    except ValueError as exc:
        return ToolError(tool="idx_case_summary", error=str(exc))


@traced("idx_ingest")
async def mcp_idx_ingest(
    hostname: str,
    case_id: str | None = None,
    findings: list[dict] | None = None,
    timeline_events: list[dict] | None = None,
    dry_run: bool = True,
    mutation_token: str | None = None,
) -> IngestOutcome | ToolError:
    """Structured ingest: route normalized findings + timeline events
    into the agentropix-* indices.

    Findings flow through the same W-286 draft-gate that the
    standalone wazuh_index_findings uses, so the LLM cannot
    self-approve via this surface. Timeline events get an analogous
    DRAFT + provenance + case_id stamp before bulk_index.
    """
    rate_err = _rate_limiter.check("idx_ingest")
    if rate_err:
        return ToolError(tool="idx_ingest", error=rate_err)
    client = _get_indexer_client()

    # SIFT-W-291 refactor: reuse the module-scope
    # _findings_route_via_gate so the W-286 draft-gate logic lives in
    # one place. record_finding (W-291) and idx_ingest (W-290) both
    # route through it; any future tool that writes findings should
    # do the same.
    try:
        return await _idx_ingest_impl(
            hostname=hostname,
            case_id=case_id,
            findings=findings,
            timeline_events=timeline_events,
            dry_run=dry_run,
            mutation_token=mutation_token,
            indexer_client=client,
            wazuh_index_findings_fn=_findings_route_via_gate,
        )
    except ValueError as exc:
        return ToolError(tool="idx_ingest", error=str(exc))


# =============================================================================
# SIFT-W-291: record / approve / report MCP tools (final 4 of 13 P0).
# =============================================================================


async def _findings_route_via_gate(
    findings: list[dict],
    case_id: str,
    dry_run: bool,
    mutation_token: str | None = None,
) -> dict:
    """Shared findings-route used by ``record_finding`` (W-291) and
    ``idx_ingest`` (W-290). Applies the W-286 draft-gate, then calls
    the orchestrator. Defined at module scope so both wrappers share
    one code path."""
    from agentropix_mcp.wazuh.config import WazuhConfig
    from agentropix_mcp.wazuh.orchestrator import index_findings
    from agentropix_mcp.wrappers.wazuh_tools import (
        _apply_draft_gate,
    )

    try:
        cfg = WazuhConfig.from_env()
    except Exception as exc:
        return {
            "error": f"Wazuh configuration error: {exc}",
            "case_id": case_id,
            "dry_run": dry_run,
        }
    if not cfg.integration_enabled:
        return {
            "error": ("Wazuh integration is disabled; set WAZUH_INTEGRATION_ENABLED=true"),
            "case_id": case_id,
            "dry_run": dry_run,
        }
    gated, strip_events = _apply_draft_gate(findings, case_id)
    for event in strip_events:
        logger.warning(
            "SIFT-W-286 draft-gate (via record_finding/idx_ingest): %s",
            event,
        )
    result = await index_findings(
        gated,
        config=cfg,
        case_id=case_id,
        evidence_token=mutation_token,
        dry_run=dry_run,
        index=None,
    )
    return result.model_dump()


@traced("record_finding")
async def mcp_record_finding(
    finding: dict,
    case_id: str | None = None,
    dry_run: bool = True,
    mutation_token: str | None = None,
) -> RecordFindingResult | ToolError:
    """Stage a single finding as DRAFT. Routes through the W-286
    draft-gate identically to wazuh_index_findings; the LLM cannot
    self-approve via this surface."""
    rate_err = _rate_limiter.check("record_finding")
    if rate_err:
        return ToolError(tool="record_finding", error=rate_err)
    try:
        return await _record_finding_impl(
            finding,
            case_id=case_id,
            dry_run=dry_run,
            mutation_token=mutation_token,
            wazuh_index_findings_fn=_findings_route_via_gate,
            # NIST1 RUN3 ISSUE-014: enables the (case_id, finding_id) dedup guard.
            indexer_client=_get_indexer_client(),
        )
    except ValueError as exc:
        return ToolError(tool="record_finding", error=str(exc))


@traced("delete_finding")
async def mcp_delete_finding(
    finding_id: str,
    case_id: str | None = None,
    dry_run: bool = True,
    reason: str = "",
) -> DeleteFindingResult | ToolError:
    """Delete a DRAFT finding (NIST1 RUN3 ISSUE-014) so a run can self-correct
    an over-count. DRAFT-only (refuses APPROVED/REJECTED); ``dry_run=True`` by
    default previews — a live delete needs ``dry_run=False``. Never bypasses the
    examiner approval workflow."""
    rate_err = _rate_limiter.check("delete_finding")
    if rate_err:
        return ToolError(tool="delete_finding", error=rate_err)
    try:
        return await _delete_finding_impl(
            finding_id,
            case_id=case_id,
            dry_run=dry_run,
            reason=reason,
            indexer_client=_get_indexer_client(),
        )
    except ValueError as exc:
        return ToolError(tool="delete_finding", error=str(exc))


@traced("record_timeline_event")
async def mcp_record_timeline_event(
    event: dict,
    hostname: str,
    case_id: str | None = None,
) -> RecordTimelineResult | ToolError:
    """Stage a single timeline event as DRAFT."""
    rate_err = _rate_limiter.check("record_timeline_event")
    if rate_err:
        return ToolError(tool="record_timeline_event", error=rate_err)
    client = _get_indexer_client()
    try:
        return await _record_timeline_impl(
            event,
            hostname,
            case_id=case_id,
            indexer_client=client,
        )
    except ValueError as exc:
        return ToolError(tool="record_timeline_event", error=str(exc))


@traced("build_executable_registry")
async def mcp_build_executable_registry(
    case_id: str,
    executables: list[dict],
    host: str = "",
    image: str = "",
    image_md5: str = "",
    partition_offset_sectors: int = 0,
    case_dir: str = "",
    dry_run: bool = True,
) -> ExecutableRegistry | ToolError:
    """Build a case's Executable Artifact Registry (EAR Phase 1).

    Normalises + dedupes collected executable signals (shimcache / fls ->
    extract -> hashdeep) into one canonical DRAFT ``MASTER-IOCS.json`` with a
    recovered-vs-referenced_only split, idempotent on (case_id, sha256) /
    (case_id, image_path). DRAFT-only: no examiner approval, no chain-of-custody
    signing, no live index write (promotion is a separate gated step).
    ``dry_run=True`` (default) previews without writing; a live write needs
    ``dry_run=False`` + a ``case_dir`` under the Thymus-allowed prefix.
    """
    rate_err = _rate_limiter.check("build_executable_registry")
    if rate_err:
        return ToolError(tool="build_executable_registry", error=rate_err)
    if case_dir and not dry_run:
        violation = _policy.check_read(case_dir)
        if violation:
            return ToolError(
                tool="build_executable_registry",
                error=violation,
                suggestion="Choose a case_dir under /tmp/agentropix-sift-* or another Thymus-allowed prefix.",  # noqa: E501
            )
    try:
        return await _build_ear_impl(
            case_id,
            executables,
            host=host,
            image=image,
            image_md5=image_md5,
            partition_offset_sectors=partition_offset_sectors,
            case_dir=case_dir or None,
            dry_run=dry_run,
        )
    except (ValueError, OSError) as exc:
        return ToolError(tool="build_executable_registry", error=str(exc))


@traced("promote_executable_registry")
async def mcp_promote_executable_registry(
    case_id: str,
    executables: list[dict],
    host: str = "",
    image: str = "",
    image_md5: str = "",
    offset: int = 0,
    dry_run: bool = True,
    mutation_token: str | None = None,
) -> PromoteResult | ToolError:
    """Promote a case's executable registry into agentropix-executables-* (EAR
    Phase 2). dry_run=True (default) previews. A live write (dry_run=False) is
    EvidenceGate-gated and requires a valid mutation_token; docs ship DRAFT
    (indexes for retrieval, does not apply examiner approval)."""
    rate_err = _rate_limiter.check("promote_executable_registry")
    if rate_err:
        return ToolError(tool="promote_executable_registry", error=rate_err)
    try:
        return await _promote_ear_impl(
            case_id,
            executables,
            host=host,
            image=image,
            image_md5=image_md5,
            offset=offset,
            dry_run=dry_run,
            mutation_token=mutation_token,
            indexer_client=_get_indexer_client(),
            evidence_gate=None,
        )
    except ValueError as exc:
        return ToolError(tool="promote_executable_registry", error=str(exc))


@traced("promote_iocs")
async def mcp_promote_iocs(
    case_id: str,
    dry_run: bool = True,
    mutation_token: str | None = None,
) -> PromoteIOCsResult | ToolError:
    """Project a case's APPROVED-finding IOCs into agentropix-iocs-* (BUG-004).

    Reads APPROVED findings, flattens + dedupes their iocs[] on
    (ioc_type, ioc_value), and upserts by deterministic _id so the ioc report
    profile has a populated source. dry_run=True (default) previews the count;
    a live write (dry_run=False) is EvidenceGate-gated and needs a mutation_token.
    """
    rate_err = _rate_limiter.check("promote_iocs")
    if rate_err:
        return ToolError(tool="promote_iocs", error=rate_err)
    try:
        return await _promote_iocs_impl(
            case_id,
            dry_run=dry_run,
            mutation_token=mutation_token,
            indexer_client=_get_indexer_client(),
            evidence_gate=None,
        )
    except ValueError as exc:
        return ToolError(tool="promote_iocs", error=str(exc))


@traced("exec_registry_get")
async def mcp_exec_registry_get(
    case_id: str,
    size: int = 500,
) -> ExecRegistryQueryResult | ToolError:
    """Return a case's full promoted executable inventory in one call (EAR)."""
    rate_err = _rate_limiter.check("exec_registry_get")
    if rate_err:
        return ToolError(tool="exec_registry_get", error=rate_err)
    try:
        return await _exec_get_impl(case_id, indexer_client=_get_indexer_client(), size=size)
    except ValueError as exc:
        return ToolError(tool="exec_registry_get", error=str(exc))


@traced("exec_registry_search")
async def mcp_exec_registry_search(
    sha256: str | None = None,
    name: str | None = None,
    category: str | None = None,
    size: int = 100,
) -> ExecRegistryQueryResult | ToolError:
    """Cross-case executable pivot on hash / name / category (EAR campaign linking)."""
    rate_err = _rate_limiter.check("exec_registry_search")
    if rate_err:
        return ToolError(tool="exec_registry_search", error=rate_err)
    try:
        return await _exec_search_impl(
            sha256=sha256,
            name=name,
            category=category,
            indexer_client=_get_indexer_client(),
            size=size,
        )
    except ValueError as exc:
        return ToolError(tool="exec_registry_search", error=str(exc))


@traced("approve_finding")
async def mcp_approve_finding(
    finding_id: str,
    approver_id: str,
    password: str,
    case_id: str | None = None,
    to_status: str = "APPROVED",
    from_status: str = "DRAFT",
    target_type: str = "finding",
    reason: str = "",
) -> ApproveFindingResult | ToolError:
    """POST a HMAC-signed approval into the W-288 sidecar.

    Operator-supplied ``password`` is consumed once and dropped
    immediately. The LLM's request context still contains the
    password — operators uneasy with that should use the W-288
    Phase 2 browser UI instead.

    Sidecar URL via env ``AGENTROPIX_APPROVAL_SIDECAR_URL``,
    default ``http://127.0.0.1:8800`` (same-workstation).
    """
    rate_err = _rate_limiter.check("approve_finding")
    if rate_err:
        return ToolError(tool="approve_finding", error=rate_err)
    sidecar_url = os.environ.get("AGENTROPIX_APPROVAL_SIDECAR_URL", "http://127.0.0.1:8800")
    try:
        return await _approve_finding_impl(
            finding_id,
            case_id=case_id,
            approver_id=approver_id,
            password=password,
            to_status=to_status,  # type: ignore[arg-type]
            from_status=from_status,  # type: ignore[arg-type]
            target_type=target_type,  # type: ignore[arg-type]
            reason=reason,
            sidecar_base_url=sidecar_url,
        )
    except ValueError as exc:
        return ToolError(tool="approve_finding", error=str(exc))


@traced("retract_approval")
async def mcp_retract_approval(
    approval_id: str,
    approver_id: str,
    password: str,
    reason: str,
    case_id: str | None = None,
) -> ApproveFindingResult | ToolError:
    """Append a compensating VOID/REVOKED entry retracting a prior approval.

    The append-only, tamper-evident way to undo a wrong/phantom approval (e.g.
    NIST1-F006/F007 signed for findings that never existed) — never a hard
    delete. Signs (target_type=approval, from=APPROVED -> to=REVOKED) through
    the same W-288 HMAC flow, producing a signed, chained ledger row that
    references the voided approval_id. A non-empty reason is required.
    """
    rate_err = _rate_limiter.check("retract_approval")
    if rate_err:
        return ToolError(tool="retract_approval", error=rate_err)
    sidecar_url = os.environ.get("AGENTROPIX_APPROVAL_SIDECAR_URL", "http://127.0.0.1:8800")
    try:
        return await _retract_approval_impl(
            approval_id,
            case_id=case_id,
            approver_id=approver_id,
            password=password,
            reason=reason,
            sidecar_base_url=sidecar_url,
        )
    except ValueError as exc:
        return ToolError(tool="retract_approval", error=str(exc))


@traced("report_generate")
async def mcp_report_generate(
    profile: str = "full",
    case_id: str | None = None,
) -> ReportGenerateResult | ToolError:
    """Build report-mcp-shaped JSON for one of 6 profiles
    (full / executive / timeline / ioc / findings / status).

    Only APPROVED findings reach the findings/timeline/executive/full
    profiles. status returns the full DRAFT/APPROVED/REJECTED breakdown
    for standups.
    """
    rate_err = _rate_limiter.check("report_generate")
    if rate_err:
        return ToolError(tool="report_generate", error=rate_err)
    client = _get_indexer_client()
    try:
        return await _report_generate_impl(
            profile=profile,  # type: ignore[arg-type]
            case_id=case_id,
            indexer_client=client,
        )
    except ValueError as exc:
        return ToolError(tool="report_generate", error=str(exc))


def _report_output_dir() -> str:
    """Resolve the directory rendered report artifacts are written to.

    Honors ``AGENTROPIX_REPORT_OUTPUT_DIR``; otherwise a stable temp subdir.
    No network, local writes only.
    """
    import tempfile

    base = os.environ.get("AGENTROPIX_REPORT_OUTPUT_DIR") or os.path.join(
        tempfile.gettempdir(), "agentropix-reports"
    )
    os.makedirs(base, exist_ok=True)
    return base


@traced("report_export")
async def mcp_report_export(
    tier: str = "analyst",
    fmt: str = "md",
    case_id: str | None = None,
) -> ExportResult | ToolError:
    """Render a case report TIER to a FORMAT (ADR-024 Phase 5).

    Projects the canonical ``report_generate`` sections into one of three
    audience tiers (``analyst`` / ``executive`` / ``business``) and renders it
    to ``md`` (Markdown+Mermaid, source of truth), ``html`` (self-contained,
    offline), or ``pdf`` (capability-gated; never installs a toolchain).

    The no-drift invariant is enforced during projection: a higher-tier claim
    with no analyst origin raises rather than ships. PDF requires a local
    Chromium or WeasyPrint engine; if absent the tool returns a structured
    error carrying the pip/packaging install hint instead of crashing.
    """
    rate_err = _rate_limiter.check("report_export")
    if rate_err:
        return ToolError(tool="report_export", error=rate_err)

    tier_n = tier.strip().lower()
    fmt_n = fmt.strip().lower()
    ext = "pdf" if fmt_n == "pdf" else ("html" if fmt_n == "html" else "md")

    client = _get_indexer_client()
    try:
        generated = await _report_generate_impl(
            profile="full",
            case_id=case_id,
            indexer_client=client,
        )
    except ValueError as exc:
        return ToolError(tool="report_export", error=str(exc))

    safe_case = (generated.case_id or case_id or "case").replace("/", "_")
    out_path = os.path.join(_report_output_dir(), f"{safe_case}-{tier_n}.{ext}")

    try:
        return export_report(
            generated.sections,
            tier=tier_n,
            fmt=fmt_n,
            output_path=out_path,
            meta={"case_id": generated.case_id or case_id},
        )
    except ToolchainUnavailable as exc:
        hint = f" {exc.install_hint}" if exc.install_hint else ""
        return ToolError(tool="report_export", error=f"{exc}.{hint}".strip())
    except ValueError as exc:
        return ToolError(tool="report_export", error=str(exc))


@traced("get_amcache")
async def mcp_get_amcache(
    hive: str,
) -> AmcacheReport | ToolError:
    """Parse an Amcache.hve hive into typed execution-evidence entries.

    Read-only: no writes to the hive file.
    """
    rate_err = _rate_limiter.check("get_amcache")
    if rate_err:
        return ToolError(tool="get_amcache", error=rate_err)

    violation = _policy.check_read(hive)
    if violation:
        return ToolError(tool="get_amcache", error=violation)

    try:
        return await get_amcache(hive)
    except (FileNotFoundError, RuntimeError, TimeoutError) as e:
        return ToolError(tool="get_amcache", error=str(e))


@traced("get_shimcache")
async def mcp_get_shimcache(
    hive: str,
) -> ShimcacheReport | ToolError:
    """Parse AppCompatCache (Shimcache) entries from a SYSTEM hive.

    Read-only: no writes to the hive file.
    """
    rate_err = _rate_limiter.check("get_shimcache")
    if rate_err:
        return ToolError(tool="get_shimcache", error=rate_err)

    violation = _policy.check_read(hive)
    if violation:
        return ToolError(tool="get_shimcache", error=violation)

    try:
        return await get_shimcache(hive)
    except (FileNotFoundError, RuntimeError, TimeoutError) as e:
        return ToolError(tool="get_shimcache", error=str(e))


@traced("get_recmd")
async def mcp_get_recmd(
    hive: str,
    batch_file: str | None = None,
    timeout_seconds: float | None = None,
) -> RECmdReport | ToolError:
    """Parse a Windows registry hive via RECmd batch-file rules (W-125).

    Complements ``get_registry`` (regripper, Perl) with Eric Zimmerman's
    .NET parser: faster on large hives and driven by the shipped
    ``Kroll_Batch.reb`` audit set covering T1547 / T1053 / T1078 keys.
    Read-only: writes a transient CSV to a process-private tempdir; the
    hive file itself is never touched.
    """
    rate_err = _rate_limiter.check("get_recmd")
    if rate_err:
        return ToolError(tool="get_recmd", error=rate_err)

    violation = _policy.check_read(hive)
    if violation:
        return ToolError(tool="get_recmd", error=violation)

    try:
        return await get_recmd(hive, batch_file=batch_file, timeout=timeout_seconds)
    except (FileNotFoundError, RuntimeError, TimeoutError) as e:
        return ToolError(tool="get_recmd", error=str(e))


@traced("get_mftecmd")
async def mcp_get_mftecmd(
    artifact: str,
    mft: str | None = None,
    timeout_seconds: float | None = None,
) -> MFTECmdReport | ToolError:
    """Parse an NTFS forensic artifact via MFTECmd (W-126).

    Supports $MFT (master file table), $J (USN journal), $I30
    (directory index), $Boot, and $Secure_$SDS. For $J files, pass
    ``mft`` to supply the companion $MFT file so MFTECmd can resolve
    parent directory paths. Read-only: writes a transient CSV to a
    process-private tempdir; the artifact is never modified.
    """
    rate_err = _rate_limiter.check("get_mftecmd")
    if rate_err:
        return ToolError(tool="get_mftecmd", error=rate_err)

    violation = _policy.check_read(artifact)
    if violation:
        return ToolError(tool="get_mftecmd", error=violation)

    try:
        return await get_mftecmd(artifact, mft=mft, timeout=timeout_seconds)
    except (FileNotFoundError, RuntimeError, TimeoutError) as e:
        return ToolError(tool="get_mftecmd", error=str(e))


@traced("get_lecmd")
async def mcp_get_lecmd(
    target: str,
    all_files: bool = False,
    timeout_seconds: float | None = None,
) -> LECmdReport | ToolError:
    """Parse Windows .lnk shortcut files via LECmd (W-127).

    ``target`` is a single .lnk file (``-f``) or a directory (``-d``).
    For directory mode, ``all_files=True`` adds ``--all`` to process
    every file rather than only ``*.lnk`` matches. Read-only: writes a
    transient CSV to a process-private tempdir; the .lnk is never
    modified.
    """
    rate_err = _rate_limiter.check("get_lecmd")
    if rate_err:
        return ToolError(tool="get_lecmd", error=rate_err)

    violation = _policy.check_read(target)
    if violation:
        return ToolError(tool="get_lecmd", error=violation)

    try:
        return await get_lecmd(target, all_files=all_files, timeout=timeout_seconds)
    except (FileNotFoundError, RuntimeError, TimeoutError) as e:
        return ToolError(tool="get_lecmd", error=str(e))


@traced("get_jlecmd")
async def mcp_get_jlecmd(
    target: str,
    all_files: bool = False,
    timeout_seconds: float | None = None,
) -> JLECmdReport | ToolError:
    """Parse Windows Jump List files via JLECmd (Phase 2).

    Auto file (-f) vs directory (-d) mode based on ``target``;
    ``all_files`` adds ``--all`` in directory mode to widen beyond
    the default ``*.automaticDestinations-ms`` /
    ``*.customDestinations-ms`` extensions. Read-only.
    """
    rate_err = _rate_limiter.check("get_jlecmd")
    if rate_err:
        return ToolError(tool="get_jlecmd", error=rate_err)

    violation = _policy.check_read(target)
    if violation:
        return ToolError(tool="get_jlecmd", error=violation)

    try:
        return await get_jlecmd(target, all_files=all_files, timeout=timeout_seconds)
    except (FileNotFoundError, RuntimeError, TimeoutError) as e:
        return ToolError(tool="get_jlecmd", error=str(e))


@traced("get_sbecmd")
async def mcp_get_sbecmd(
    hive_dir: str,
    timeout_seconds: float | None = None,
) -> SBECmdReport | ToolError:
    """Parse ShellBags from registry hives via SBECmd (Phase 2).

    SBECmd is directory-only by design — point ``hive_dir`` at a
    folder containing one or more ``NTUSER.DAT`` / ``UsrClass.dat``
    files. Read-only.
    """
    rate_err = _rate_limiter.check("get_sbecmd")
    if rate_err:
        return ToolError(tool="get_sbecmd", error=rate_err)

    violation = _policy.check_read(hive_dir)
    if violation:
        return ToolError(tool="get_sbecmd", error=violation)

    try:
        return await get_sbecmd(hive_dir, timeout=timeout_seconds)
    except (FileNotFoundError, RuntimeError, TimeoutError) as e:
        return ToolError(tool="get_sbecmd", error=str(e))


@traced("get_sqlecmd")
async def mcp_get_sqlecmd(
    target: str,
    hunt: bool = False,
    no_blob: bool = True,
    sample_per_schema: int | None = None,
    timeout_seconds: float | None = None,
) -> SQLECmdReport | ToolError:
    """Parse SQLite databases against EZ Tools maps via SQLECmd (Phase 2).

    Auto file (-f) vs directory (-d) mode. ``hunt=True`` enables
    SQLite-header sniffing for non-standard extensions (directory
    mode only). ``no_blob=True`` (default) drops blob payloads from
    the parsed output — flip to capture attachment columns at the
    cost of much larger CSVs. ``sample_per_schema`` caps rows kept
    per produced schema in ``sampled_rows``. Read-only.
    """
    rate_err = _rate_limiter.check("get_sqlecmd")
    if rate_err:
        return ToolError(tool="get_sqlecmd", error=rate_err)

    violation = _policy.check_read(target)
    if violation:
        return ToolError(tool="get_sqlecmd", error=violation)

    try:
        return await get_sqlecmd(
            target,
            hunt=hunt,
            no_blob=no_blob,
            sample_per_schema=sample_per_schema,
            timeout=timeout_seconds,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError) as e:
        return ToolError(tool="get_sqlecmd", error=str(e))


@traced("get_bstrings")
async def mcp_get_bstrings(
    target: str,
    look_for_string: str | None = None,
    look_for_regex: str | None = None,
    min_length: int | None = None,
    summary_only: bool = False,
    timeout_seconds: float | None = None,
) -> BstringsReport | ToolError:
    """Regex-backed string extraction via bstrings (Phase 2).

    Auto file (-f) vs directory (-d) mode. ``look_for_string`` /
    ``look_for_regex`` are mutually exclusive — pass at most one. No
    filter = behaves like GNU strings. ``min_length`` floor 1, ceiling
    1024. Read-only.
    """
    rate_err = _rate_limiter.check("get_bstrings")
    if rate_err:
        return ToolError(tool="get_bstrings", error=rate_err)

    violation = _policy.check_read(target)
    if violation:
        return ToolError(tool="get_bstrings", error=violation)

    try:
        return await get_bstrings(
            target,
            look_for_string=look_for_string,
            look_for_regex=look_for_regex,
            min_length=min_length,
            summary_only=summary_only,
            timeout=timeout_seconds,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError, ValueError) as e:
        return ToolError(tool="get_bstrings", error=str(e))


@traced("get_evtx")
async def mcp_get_evtx(
    target: str,
    channels: list[str] | None = None,
    event_ids: list[int] | None = None,
    max_events: int | None = None,
    timeout_seconds: float | None = None,
    tail: bool = True,
    record_id_min: int | None = None,
    record_id_max: int | None = None,
) -> EvtxReport | ToolError:
    """Parse Windows ``.evtx`` event logs into typed event records.

    Two input modes (W-133):

    * **E01 image** — ``target`` is a raw EWF/.E01 forensic image. The
      wrapper enumerates ``Windows/System32/winevt/Logs/`` via
      ``mcp_extract_files`` (W-028 ifind+icat) into a per-call tempdir
      and runs the parser on each requested channel. If ``channels``
      is omitted, the default DC-triage set is used: ``Security``,
      ``System``, ``Application``,
      ``Microsoft-Windows-PowerShell/Operational``,
      ``Microsoft-Windows-TaskScheduler/Operational``,
      ``Microsoft-Windows-Sysmon/Operational``. The response carries
      ``evtx_files_requested`` (filenames the wrapper asked for; W-139,
      renamed from ``evtx_files_discovered``), ``evtx_files_extracted``
      (subset that icat actually pulled; W-139), ``channels_extracted``
      (channels that produced events), and ``image_class_detected``
      (``"modern"`` or ``"winxp_or_win2003"``). On XP/2003-class images
      the wrapper short-circuits and returns ``skipped_reason`` plus
      ``legacy_evt_files_found`` rather than silently zero events
      (W-139).

    * **Single ``.evtx`` file** — legacy mode unchanged. Use this when
      you've already extracted the file (e.g. via ``mcp_extract_files``)
      and just want the parser. The W-133/W-139 E01-only fields stay
      at their default empty / ``None`` values in this mode.

    Optional ``channels`` and ``event_ids`` apply caller-driven
    filters. ``timeout_seconds`` overrides the parser timeout for this
    call only — defaults to ``AGENTROPIX_EVTX_TIMEOUT`` (180s, floor 5s,
    ceiling 3600s); per-call override is clamped to the same bounds.
    Read-only: no writes to the target.

    W-137 — recent-window semantics:

    * ``tail`` (default ``True``) returns the LAST ``max_events``
      matching records the parser sees rather than the first. evtx_dump
      emits records oldest-first; ``tail=True`` surfaces the recent
      attack window for multi-million-record Security logs. Set
      ``tail=False`` to restore pre-W-137 oldest-first truncation
      semantics.
    * ``record_id_min`` / ``record_id_max`` are inclusive bounds on
      ``EventRecordID``, useful for re-scoping a known attack window
      without re-parsing the whole file.

    The default ``max_events`` was raised from 1000 to 5000 (W-137).
    """
    rate_err = _rate_limiter.check("get_evtx")
    if rate_err:
        return ToolError(tool="get_evtx", error=rate_err)

    violation = _policy.check_read(target)
    if violation:
        return ToolError(tool="get_evtx", error=violation)

    try:
        return await get_evtx(
            target,
            channels=channels,
            event_ids=event_ids,
            max_events=max_events,
            timeout=timeout_seconds,
            tail=tail,
            record_id_min=record_id_min,
            record_id_max=record_id_max,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError) as e:
        return ToolError(tool="get_evtx", error=str(e))


@traced("extract_files")
async def mcp_extract_files(
    image: str,
    paths: list[str | int],
    dest: str,
    offset: int = 0,
    fstype: str | None = None,
    follow_reparse_points: bool = True,
    expand_dirs: bool = False,
    max_dir_files: int | None = None,
) -> ExtractManifest | ToolError:
    """Extract in-container paths from an image into a session tmpdir.

    Uses TSK ``ifind`` + ``icat``. Enforces Thymus read-zone check on
    the image AND on the destination directory — writes land under an
    allowed read zone (session tmpdir prefix), which keeps the
    evidence-write invariant architecturally intact.

    W-255: ``follow_reparse_points`` (default True) controls whether an
    ``ifind`` miss on a path containing a known Windows junction
    segment (``My Documents``, ``Local Settings``, etc.) is retried
    with the canonical equivalent. Forensic-strict callers can pass
    False to preserve byte-for-byte path fidelity; the diagnostic
    ``hints`` field on the manifest still flags the likely cause.
    """
    rate_err = _rate_limiter.check("extract_files")
    if rate_err:
        return ToolError(tool="extract_files", error=rate_err)

    image_violation = _policy.check_read(image)
    if image_violation:
        return ToolError(tool="extract_files", error=image_violation)

    dest_violation = _policy.check_read(dest)
    if dest_violation:
        return ToolError(
            tool="extract_files",
            error=dest_violation,
            suggestion="Choose a dest under /tmp/agentropix-sift-* or another Thymus-allowed prefix.",  # noqa: E501
        )

    try:
        return await extract_files(
            image,
            paths,
            dest,
            offset=offset,
            fstype=fstype,
            follow_reparse_points=follow_reparse_points,
            expand_dirs=expand_dirs,
            max_dir_files=max_dir_files,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError, ValueError) as exc:
        return ToolError(tool="extract_files", error=str(exc))


@traced("extract_archive")
async def mcp_extract_archive(
    archive: str,
    dest: str,
    members: list[str] | None = None,
    max_total_bytes: int | None = None,
    max_files: int | None = None,
    max_per_file_bytes: int | None = None,
    timeout: float | None = None,
    engine: str | None = None,
) -> ExtractArchiveManifest | ToolError:
    """W-095 — unpack a ``.7z`` / ``.zip`` / ``.tar*`` archive into ``dest``.

    Closes the operator's manual-SSH gap that 22 FA-B reports flagged
    on the ``_reject_archive`` boundary. Drives ``7z x`` for
    7z/zip/rar and ``tar -xf`` for tar/tgz/tbz/txz, with a ``7z l``
    pre-flight check that refuses bombs (entry-count cap, total-bytes
    cap, per-file size cap) before extracting a single byte. Both
    ``archive`` and ``dest`` go through Thymus; ``dest`` must live
    under a Thymus-allowed prefix (typical ``/tmp/agentropix-sift-*``).

    Caps are tunable via:
      * ``AGENTROPIX_ARCHIVE_MAX_BYTES``     (default 50 GiB)
      * ``AGENTROPIX_ARCHIVE_MAX_FILES``     (default 1,000,000)
      * ``AGENTROPIX_ARCHIVE_MAX_PER_FILE_BYTES`` (default 16 GiB)
      * ``AGENTROPIX_ARCHIVE_TIMEOUT``       (default 600 s)

    Per-entry path-traversal and symlink-escape are re-checked AFTER
    extraction; offending entries are unlinked and surface in the
    manifest with ``ok=False``.
    """
    rate_err = _rate_limiter.check("extract_archive")
    if rate_err:
        return ToolError(tool="extract_archive", error=rate_err)

    archive_violation = _policy.check_read(archive)
    if archive_violation:
        return ToolError(tool="extract_archive", error=archive_violation)

    dest_violation = _policy.check_read(dest)
    if dest_violation:
        return ToolError(
            tool="extract_archive",
            error=dest_violation,
            suggestion=(
                "Choose a dest under /tmp/agentropix-sift-* or another Thymus-allowed prefix."
            ),
        )

    try:
        return await extract_archive(
            archive,
            dest,
            members=members,
            max_total_bytes=max_total_bytes,
            max_files=max_files,
            max_per_file_bytes=max_per_file_bytes,
            timeout=timeout,
            engine=engine,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError, ValueError) as exc:
        return ToolError(tool="extract_archive", error=str(exc))


@traced("get_image_info")
async def mcp_get_image_info(
    image: str,
) -> ImageInfo | ToolError:
    """Extract E01/EWF image metadata (case number, examiner, hashes).

    Uses ewftools ewfinfo to read forensic image metadata.
    Read-only: no writes to the image file.

    Args:
        image: Path to E01 or EWF-format image file.

    Returns:
        ImageInfo with case metadata and cryptographic hashes.
    """
    rate_err = _rate_limiter.check("get_image_info")
    if rate_err:
        return ToolError(tool="get_image_info", error=rate_err)

    violation = _policy.check_read(image)
    if violation:
        return ToolError(tool="get_image_info", error=violation)

    try:
        return await get_image_info(image)
    except (FileNotFoundError, RuntimeError, TimeoutError) as e:
        return ToolError(tool="get_image_info", error=str(e))


@traced("scan_yara")
async def mcp_scan_yara(
    target: str,
    rules: list[str],
    with_meta: bool = True,
    with_strings: bool = False,
    max_matches: int | None = None,
    timeout_seconds: float | None = None,
) -> YaraReport | ToolError:
    """Scan ``target`` with one or more YARA rulesets.

    Drives the system ``yara`` binary (VirusTotal YARA 4.x). ``target``
    must be a file or directory already extracted from evidence (drive
    the extraction with ``mcp_extract_files`` on raw E01 evidence, then
    feed the result here). ``rules`` is a list of ``.yar`` / ``.yara``
    / ``.yarc`` paths; each is checked against the Thymus read zone
    (rulesets live on disk just like evidence). Read-only: no writes
    to target or rules.

    ``timeout_seconds`` is a per-call override for the wrapper-level
    subprocess timeout. ``None`` (default) reads
    ``AGENTROPIX_YARA_TIMEOUT`` (300 s, floor 5, ceil 3600). An explicit
    value is clamped to the same ``[5, 3600]`` window — SIFT-W-099.
    """
    rate_err = _rate_limiter.check("scan_yara")
    if rate_err:
        return ToolError(tool="scan_yara", error=rate_err)

    violation = _policy.check_read(target)
    if violation:
        return ToolError(tool="scan_yara", error=violation)

    if not rules:
        return ToolError(
            tool="scan_yara",
            error="at least one YARA rules file is required",
        )
    # W-101: rule strings that don't look like absolute paths are
    # resolved against AGENTROPIX_YARA_RULES_DIR (default
    # /usr/share/yara/rules/) before the Thymus check, so an operator
    # passing "malware" instead of "/usr/share/yara/rules/malware.yar"
    # gets the rule from the configured directory rather than a
    # confusing "REJECT: not under allowed prefix" error.
    resolved_rules: list[str] = []
    for rule in rules:
        resolved = _resolve_yara_rule(rule)
        rule_violation = _policy.check_read(resolved)
        if rule_violation:
            return ToolError(tool="scan_yara", error=rule_violation)
        resolved_rules.append(resolved)

    try:
        return await scan_yara(
            target,
            resolved_rules,
            with_meta=with_meta,
            with_strings=with_strings,
            max_matches=max_matches,
            timeout=timeout_seconds,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError, ValueError) as e:
        return ToolError(tool="scan_yara", error=str(e))


@traced("run_bulk_extractor")
async def mcp_run_bulk_extractor(
    target: str,
    out_dir: str,
    enable_scanners: list[str] | None = None,
    disable_scanners: list[str] | None = None,
    only_scanner: str | None = None,
    zap: bool = False,
    max_features: int | None = None,
    summary_only: bool = False,
) -> BulkReport | ToolError:
    """Run ``bulk_extractor`` against ``target`` and aggregate features.

    Drives the system ``bulk_extractor`` binary. ``target`` may be a
    raw disk image, an extracted file, or a directory tree. ``out_dir``
    is where BE writes its per-recorder feature files — it is checked
    against the Thymus read zone because it lives on host disk just
    like evidence; the write itself is performed by BE, not us. Pass
    ``zap=True`` if you need to overwrite an existing ``out_dir``.
    """
    rate_err = _rate_limiter.check("run_bulk_extractor")
    if rate_err:
        return ToolError(tool="run_bulk_extractor", error=rate_err)

    target_violation = _policy.check_read(target)
    if target_violation:
        return ToolError(tool="run_bulk_extractor", error=target_violation)

    out_violation = _policy.check_read(out_dir)
    if out_violation:
        return ToolError(
            tool="run_bulk_extractor",
            error=out_violation,
            suggestion="Choose an out_dir under /tmp/agentropix-sift-* or another Thymus-allowed prefix.",  # noqa: E501
        )

    try:
        return await run_bulk_extractor(
            target,
            out_dir,
            enable_scanners=enable_scanners,
            disable_scanners=disable_scanners,
            only_scanner=only_scanner,
            zap=zap,
            max_features=max_features,
            summary_only=summary_only,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError, ValueError) as e:
        return ToolError(tool="run_bulk_extractor", error=str(e))


@traced("run_strings")
async def mcp_run_strings(
    target: str,
    min_length: int | None = None,
    encoding: str = "s",
    max_results: int | None = None,
) -> StringsReport | ToolError:
    """Extract printable character sequences from ``target`` via GNU strings.

    ``target`` may be a disk image, extracted file, memory dump, or any
    binary blob Thymus permits. The wrapper caps output via
    ``max_results`` and kills the subprocess once the cap is reached,
    so running against large images is bounded. Read-only: no writes
    to the target.
    """
    rate_err = _rate_limiter.check("run_strings")
    if rate_err:
        return ToolError(tool="run_strings", error=rate_err)

    violation = _policy.check_read(target)
    if violation:
        return ToolError(tool="run_strings", error=violation)

    try:
        return await run_strings(
            target,
            min_length=min_length,
            encoding=encoding,
            max_results=max_results,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError, ValueError) as e:
        return ToolError(tool="run_strings", error=str(e))


@traced("analyze_maldoc")
async def mcp_analyze_maldoc(
    target: str,
    timeout: float | None = None,
) -> MacroReport | ToolError:
    """W-221: olevba/oleid/rtfobj analysis on one Office/RTF document.

    Returns a ``MacroReport`` with macros, IOCs, obfuscation hints, and
    RTF embedded-object metadata. Designed for the mail-agent chain:
    once a PST/MSG attachment is spilled to disk, the agent calls this
    against the resulting path. Read-only: no writes to ``target``.
    """
    rate_err = _rate_limiter.check("analyze_maldoc")
    if rate_err:
        return ToolError(tool="analyze_maldoc", error=rate_err)

    violation = _policy.check_read(target)
    if violation:
        return ToolError(tool="analyze_maldoc", error=violation)

    try:
        # asyncio.TimeoutError is an alias of built-in TimeoutError in Py 3.11+
        return await analyze_maldoc(target, timeout=timeout)
    except (FileNotFoundError, ValueError, TimeoutError) as e:
        return ToolError(tool="analyze_maldoc", error=str(e))


@traced("run_hashdeep")
async def mcp_run_hashdeep(
    target: str,
    algos: list[str] | None = None,
    recursive: bool = False,
    known: str | None = None,
    audit: bool = False,
    max_files: int | None = None,
) -> HashdeepReport | ToolError:
    """Hash files under ``target`` via hashdeep.

    ``algos`` is a subset of md5/sha1/sha256/tiger/whirlpool.  When
    ``known`` and ``audit=True`` are supplied the wrapper runs in audit
    mode and returns the raw audit output.  Read-only: no writes to
    target.
    """
    rate_err = _rate_limiter.check("run_hashdeep")
    if rate_err:
        return ToolError(tool="run_hashdeep", error=rate_err)

    violation = _policy.check_read(target)
    if violation:
        return ToolError(tool="run_hashdeep", error=violation)

    if known is not None:
        kv = _policy.check_read(known)
        if kv:
            return ToolError(tool="run_hashdeep", error=kv)

    try:
        return await run_hashdeep(
            target,
            algos=algos,
            recursive=recursive,
            known=known,
            audit=audit,
            max_files=max_files,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError, ValueError) as e:
        return ToolError(tool="run_hashdeep", error=str(e))


@traced("run_foremost")
async def mcp_run_foremost(
    image: str,
    output_dir: str,
    config: str | None = None,
    types: list[str] | None = None,
    quick: bool = False,
    audit_only: bool = False,
    all_headers: bool = False,
    zap: bool = False,
    max_entries: int | None = None,
) -> ForemostReport | ToolError:
    """Run ``foremost`` file carver against ``image`` and parse audit.txt.

    Drives the system ``foremost`` binary (1.5.x).  ``image`` is the raw
    disk image, memory dump, or any file to carve; ``output_dir`` is the
    per-run output tree foremost will populate (must NOT exist unless
    ``zap=True``).  ``output_dir`` is checked against the Thymus read
    zone because it lives on host disk like evidence; the write itself
    is performed by foremost, not us.
    """
    rate_err = _rate_limiter.check("run_foremost")
    if rate_err:
        return ToolError(tool="run_foremost", error=rate_err)

    image_violation = _policy.check_read(image)
    if image_violation:
        return ToolError(tool="run_foremost", error=image_violation)

    out_violation = _policy.check_read(output_dir)
    if out_violation:
        return ToolError(
            tool="run_foremost",
            error=out_violation,
            suggestion="Choose an output_dir under /tmp/agentropix-sift-* or another Thymus-allowed prefix.",  # noqa: E501
        )

    if config is not None:
        cfg_violation = _policy.check_read(config)
        if cfg_violation:
            return ToolError(tool="run_foremost", error=cfg_violation)

    try:
        return await run_foremost(
            image,
            output_dir,
            config=config,
            types=types,
            quick=quick,
            audit_only=audit_only,
            all_headers=all_headers,
            zap=zap,
            max_entries=max_entries,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError, ValueError) as e:
        return ToolError(tool="run_foremost", error=str(e))


@traced("run_exiftool")
async def mcp_run_exiftool(
    target: str,
    recursive: bool = False,
    fast: bool = False,
    max_files: int | None = None,
) -> ExiftoolReport | ToolError:
    """Extract metadata from ``target`` via ExifTool.

    Returns one ``ExifEntry`` per file with promoted common fields
    (FileType, MIMEType, FileSize, FileModifyDate) plus the full
    raw metadata dict. Read-only: no writes to target.
    """
    rate_err = _rate_limiter.check("run_exiftool")
    if rate_err:
        return ToolError(tool="run_exiftool", error=rate_err)

    violation = _policy.check_read(target)
    if violation:
        return ToolError(tool="run_exiftool", error=violation)

    try:
        return await run_exiftool(
            target,
            recursive=recursive,
            fast=fast,
            max_files=max_files,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError) as e:
        return ToolError(tool="run_exiftool", error=str(e))


@traced("pdf_extract_text")
async def mcp_pdf_extract_text(
    target: str,
    pages: str | None = None,
    max_pages: int | None = None,
    max_chars: int | None = None,
    timeout_seconds: float | None = None,
) -> PdfDocument | ToolError:
    """Extract per-page text + metadata from a PDF (W-103).

    Drives ``pdftotext`` (poppler-utils) per page and ``pdfinfo`` once
    for document metadata. ``target`` must be a single PDF file already
    extracted from evidence (drive the extraction with
    ``mcp_extract_files`` on raw E01 evidence, then feed the result
    here, or feed a corpus PDF directly).

    ``pages`` accepts a ``"1-5,12,20-"`` page-range spec; ``None`` (the
    default) extracts every page subject to the ``AGENTROPIX_PDF_MAX_PAGES``
    cap (default 1000). ``max_chars`` caps per-page text length
    (default ``AGENTROPIX_PDF_MAX_CHARS`` 200_000). Per-call
    ``timeout_seconds`` overrides ``AGENTROPIX_PDF_EXTRACT_TIMEOUT``
    (default 180s, floor 5s, ceiling 3600s); explicit overrides are
    clamped to the same window. Read-only: no writes to target.
    """
    rate_err = _rate_limiter.check("pdf_extract_text")
    if rate_err:
        return ToolError(tool="pdf_extract_text", error=rate_err)

    violation = _policy.check_read(target)
    if violation:
        return ToolError(tool="pdf_extract_text", error=violation)

    try:
        return await pdf_extract_text(
            target,
            pages=pages,
            max_pages=max_pages,
            max_chars=max_chars,
            timeout=timeout_seconds,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError, ValueError) as exc:
        return ToolError(tool="pdf_extract_text", error=str(exc))


@traced("glob_paths")
async def mcp_glob_paths(
    pattern: str,
    max_results: int = 1000,
    follow_symlinks: bool = False,
) -> GlobPathsResult | ToolError:
    """Enumerate filesystem paths matching ``pattern`` (W-084).

    The longest non-glob prefix of ``pattern`` is checked against the
    Thymus read zone before any expansion happens.  After expansion every
    individual result is re-checked with the policy; results outside the
    allowlist are silently dropped (``rejected_count`` surfaces the
    count).  Patterns containing ``..`` are rejected outright without
    touching the policy.

    ``max_results`` caps the returned list (``truncated=True`` when hit).
    ``follow_symlinks=False`` (default) drops symlink results entirely;
    ``True`` resolves them and re-checks the resolved target.  Read-only:
    pure ``pathlib.Path.glob``, no subprocess.
    """
    rate_err = _rate_limiter.check("glob_paths")
    if rate_err:
        return ToolError(tool="glob_paths", error=rate_err)

    result = run_glob_paths(
        pattern,
        max_results=max_results,
        follow_symlinks=follow_symlinks,
    )
    if result.error:
        return ToolError(tool="glob_paths", error=result.error)
    return result


def _compose_list_files_glob(path: str, recursive: bool, pattern: str) -> str:
    """Compose a single glob from ``path`` + ``pattern`` honoring ``recursive``.

    Strips a leading ``**/`` from ``pattern`` (so the default
    ``"**/*"`` works for both shapes) then re-prepends it only when
    ``recursive=True``. Empty leaf collapses to ``*``.
    """
    leaf = pattern
    while leaf.startswith("**/"):
        leaf = leaf[3:]
    if not leaf:
        leaf = "*"
    base = path.rstrip("/") if path != "/" else ""
    if recursive:
        return f"{base}/**/{leaf}"
    return f"{base}/{leaf}"


@traced("list_files")
async def mcp_list_files(
    path: str,
    recursive: bool = True,
    pattern: str = "**/*",
    max_results: int | None = None,
) -> GlobPathsResult | ToolError:
    """Directory enumeration convenience over ``glob_paths`` (W-100).

    Closes the gap that operators were abusing ``run_exiftool`` /
    ``run_hashdeep`` as directory listers because there was no
    first-class enumeration tool other than the glob-pattern API.
    Composes a glob from ``path`` + ``pattern`` (with ``**/`` injected
    when ``recursive=True``) and delegates to :func:`run_glob_paths`,
    so Thymus enforcement, symlink-drop, and truncation semantics are
    inherited unchanged — no duplicate walking logic.

    ``max_results`` defaults to ``AGENTROPIX_LIST_FILES_MAX_RESULTS``
    (10000, floor 1, ceiling 1_000_000); per-call overrides are clamped
    to the same bounds.
    """
    rate_err = _rate_limiter.check("list_files")
    if rate_err:
        return ToolError(tool="list_files", error=rate_err)

    if max_results is None:
        effective_max = get_int(
            "AGENTROPIX_LIST_FILES_MAX_RESULTS",
            10000,
            floor=1,
            ceiling=1_000_000,
        )
    else:
        effective_max = clamp_int(
            "AGENTROPIX_LIST_FILES_MAX_RESULTS",
            max_results,
            floor=1,
            ceiling=1_000_000,
        )

    composed = _compose_list_files_glob(path, recursive, pattern)
    result = run_glob_paths(
        composed,
        max_results=effective_max,
        follow_symlinks=False,
    )
    if result.error:
        return ToolError(tool="list_files", error=result.error)
    return result
