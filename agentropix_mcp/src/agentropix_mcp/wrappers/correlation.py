"""Correlation tools — W-150 cross-artifact analysis layer.

Four deterministic algorithms that operate on structured data already
extracted by other wrappers (get_evtx, get_pslist, get_netscan, get_svcscan).
Unlike subprocess wrappers, these functions contain no external process
invocations — they are pure Python computation that call other async
wrappers internally, then apply graph/window/search algorithms.

    correlate_timeline  — join EVTX events from N hosts by UTC window
    build_process_tree  — PPID-linked forest from pslist/psscan rows
    pivot_on_ioc        — cross-artifact expansion of a single IOC value
    detect_sweep        — sliding-window burst detection for 5140/5145 events
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Data models                                                                  #
# --------------------------------------------------------------------------- #


class TimelineEventRow(BaseModel):
    """One event in a unified multi-host timeline."""

    host: str
    timestamp: str  # ISO-8601 UTC from EvtxEvent
    event_id: int
    channel: str
    provider: str = ""
    computer: str = ""
    level: str = ""
    delta_ms: float = 0.0  # ms since the previous event in the unified stream
    raw: dict[str, Any] = Field(default_factory=dict)


class TimelineReport(BaseModel):
    """Result of correlate_timeline: sorted, cross-host event stream."""

    host_count: int
    event_count: int
    hosts: list[str] = Field(default_factory=list)
    window_start: str = ""
    window_end: str = ""
    events: list[TimelineEventRow] = Field(default_factory=list)
    tool: str = "correlation.correlate_timeline"
    warnings: list[str] = Field(default_factory=list)


class ProcessNode(BaseModel):
    """One node in a PPID-linked process tree."""

    pid: int
    ppid: int
    name: str
    create_time: str = ""
    threads: int = 0
    wow64: bool = False
    depth: int = 0
    suspicious: bool = False
    suspicious_reason: str = ""
    children: list[ProcessNode] = Field(default_factory=list)


ProcessNode.model_rebuild()


class ProcessTreeReport(BaseModel):
    """Result of build_process_tree: PPID-linked forest."""

    image_path: str
    process_count: int
    root_count: int
    orphan_count: int
    suspicious_count: int
    roots: list[ProcessNode] = Field(default_factory=list)
    orphans: list[ProcessNode] = Field(default_factory=list)
    tool: str = "correlation.build_process_tree"
    warnings: list[str] = Field(default_factory=list)


class IOCHit(BaseModel):
    """Single hit from a cross-artifact IOC pivot."""

    artifact_type: str  # "pslist", "netscan", "svcscan", "evtx"
    host: str
    image_path: str
    timestamp: str = ""
    field_name: str  # which field matched
    matched_value: str
    context: dict[str, Any] = Field(default_factory=dict)


class IOCPivotReport(BaseModel):
    """Result of pivot_on_ioc: all hits for one IOC across all artifacts."""

    ioc_value: str
    ioc_type: str  # "ip", "process", "service", "username", "string"
    total_hits: int
    host_count: int
    hosts_hit: list[str] = Field(default_factory=list)
    artifact_types_searched: list[str] = Field(default_factory=list)
    hits: list[IOCHit] = Field(default_factory=list)
    tool: str = "correlation.pivot_on_ioc"
    warnings: list[str] = Field(default_factory=list)


class SweepBurst(BaseModel):
    """One detected SMB share enumeration burst."""

    src_ip: str = ""
    src_host: str = ""
    window_start: str
    window_end: str
    target_shares: list[str] = Field(default_factory=list)
    event_count: int
    events_per_second: float
    event_ids_seen: list[int] = Field(default_factory=list)


class SweepReport(BaseModel):
    """Result of detect_sweep: SMB share enumeration bursts."""

    image_path: str
    burst_count: int
    threshold_per_window: int
    window_size_seconds: float
    events_analyzed: int
    bursts: list[SweepBurst] = Field(default_factory=list)
    tool: str = "correlation.detect_sweep"
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Shared helpers                                                               #
# --------------------------------------------------------------------------- #

_SUSPICIOUS_PROCESS_NAMES = frozenset({
    "rubyw.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    "regsvr32.exe", "rundll32.exe", "powershell.exe", "pwsh.exe",
})

# Processes that legitimately parent system services but not arbitrary binaries
_SENSITIVE_PARENTS = frozenset({
    "services.exe", "svchost.exe", "lsass.exe", "winlogon.exe", "spoolsv.exe",
})


def _is_suspicious(name: str, ppid: int, pid_to_name: dict[int, str]) -> tuple[bool, str]:
    parent_name = pid_to_name.get(ppid, "").lower()
    if name.lower() in _SUSPICIOUS_PROCESS_NAMES and parent_name in _SENSITIVE_PARENTS:
        return True, f"{name} spawned by {parent_name}"
    return False, ""


def _parse_ts(ts: str) -> datetime | None:
    """Parse ISO-8601 UTC timestamp. Returns None on failure."""
    if not ts:
        return None
    ts = ts.strip().replace(" ", "T").rstrip("Z")
    if "." not in ts:
        ts += ".0"
    try:
        return datetime.fromisoformat(ts).replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return None


def _parse_raw(raw: Any) -> dict[str, Any]:
    """Coerce EvtxEvent.raw (str or dict) to a plain dict.

    EvtxEvent.raw is typed as str (JSON-serialised) by the evtx wrapper.
    Some test fixtures may pass a dict directly; handle both silently.
    """
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, ValueError):
            return {}
    return {}


def _host_from_image(image: str) -> str:
    """Derive a short host label from an evidence image path."""
    stem = Path(image).stem
    stem = re.sub(r"[-_](memory|mem|snapshot\d+|cdrive|c[_-]drive)$", "", stem, flags=re.IGNORECASE)
    return stem


# --------------------------------------------------------------------------- #
# Tool 1: correlate_timeline                                                   #
# --------------------------------------------------------------------------- #


async def correlate_timeline(
    images: list[str | Path],
    *,
    channels: list[str] | None = None,
    event_ids: list[int] | None = None,
    window_start: str | None = None,
    window_end: str | None = None,
    max_events_per_host: int = 5000,
    timeout: float | None = None,
) -> TimelineReport:
    """Join EVTX events from multiple hosts into a single sorted timeline.

    Calls get_evtx() for each image concurrently via asyncio.gather,
    merges all events, applies an optional UTC time-window filter, and
    annotates each event with the delta_ms from the previous event.

    Args:
        images: Evidence image paths (memory or E01 disk images).
        channels: EVTX channel filter passed to get_evtx.
        event_ids: EID filter applied after merge.
        window_start: ISO-8601 UTC lower bound (inclusive).
        window_end: ISO-8601 UTC upper bound (inclusive).
        max_events_per_host: Cap per get_evtx call.
        timeout: Per-get_evtx timeout in seconds.

    Returns:
        TimelineReport with unified, sorted, delta-annotated event list.
    """
    from agentropix_mcp.wrappers.evtx import get_evtx

    str_images = [str(img) for img in images]
    warnings: list[str] = []

    async def _fetch(img: str) -> tuple[str, list]:
        host = _host_from_image(img)
        try:
            report = await get_evtx(
                img,
                channels=channels,
                event_ids=set(event_ids) if event_ids else None,
                max_events=max_events_per_host,
                timeout=timeout,
            )
            return host, report.events
        except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as exc:
            warnings.append(f"{host}: get_evtx failed — {exc}")
            return host, []

    results = await asyncio.gather(*(_fetch(img) for img in str_images))

    ws_dt = _parse_ts(window_start) if window_start else None
    we_dt = _parse_ts(window_end) if window_end else None

    all_rows: list[TimelineEventRow] = []
    hosts_seen: list[str] = []

    for host, events in results:
        hosts_seen.append(host)
        for ev in events:
            ts_dt = _parse_ts(ev.timestamp)
            if ts_dt is None:
                continue
            if ws_dt and ts_dt < ws_dt:
                continue
            if we_dt and ts_dt > we_dt:
                continue
            all_rows.append(TimelineEventRow(
                host=host,
                timestamp=ev.timestamp,
                event_id=ev.event_id,
                channel=ev.channel,
                provider=ev.provider,
                computer=ev.computer,
                level=str(ev.level),
                raw=_parse_raw(ev.raw),
            ))

    all_rows.sort(key=lambda r: r.timestamp)

    prev_ts: datetime | None = None
    for row in all_rows:
        cur_ts = _parse_ts(row.timestamp)
        if cur_ts and prev_ts:
            row.delta_ms = (cur_ts - prev_ts).total_seconds() * 1000.0
        prev_ts = cur_ts

    return TimelineReport(
        host_count=len(str_images),
        event_count=len(all_rows),
        hosts=hosts_seen,
        window_start=window_start or (all_rows[0].timestamp if all_rows else ""),
        window_end=window_end or (all_rows[-1].timestamp if all_rows else ""),
        events=all_rows,
        warnings=warnings,
    )


# --------------------------------------------------------------------------- #
# Tool 2: build_process_tree                                                   #
# --------------------------------------------------------------------------- #


async def build_process_tree(
    image: str | Path,
    *,
    timeout: float | None = None,
) -> ProcessTreeReport:
    """Build a PPID-linked process forest from a memory image.

    Calls get_pslist() (which falls back to psscan on paused-VM images),
    constructs parent-child links by PPID, annotates suspicious nodes
    (LOLBin spawned by sensitive parent), and returns a rooted forest.

    Roots: processes whose PPID is 0, 4, or absent from the process list.
    Orphans: processes with a non-system PPID not found in the list (DKOM).

    Args:
        image: Path to memory image.
        timeout: Timeout for the underlying get_pslist call.

    Returns:
        ProcessTreeReport with roots forest, orphans list, suspicious count.
    """
    from agentropix_mcp.wrappers.volatility import get_pslist

    str_image = str(image)
    warnings: list[str] = []

    try:
        pslist = await get_pslist(str_image, timeout=timeout)
    except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as exc:
        return ProcessTreeReport(
            image_path=str_image,
            process_count=0,
            root_count=0,
            orphan_count=0,
            suspicious_count=0,
            warnings=[str(exc)],
        )

    processes = pslist.processes
    pid_to_name: dict[int, str] = {p.pid: p.name for p in processes}
    pid_set: set[int] = {p.pid for p in processes}

    nodes: dict[int, ProcessNode] = {}
    for p in processes:
        susp, reason = _is_suspicious(p.name, p.ppid, pid_to_name)
        nodes[p.pid] = ProcessNode(
            pid=p.pid,
            ppid=p.ppid,
            name=p.name,
            create_time=p.create_time,
            threads=p.threads,
            wow64=p.wow64,
            suspicious=susp,
            suspicious_reason=reason,
        )

    _SYSTEM_PIDS = {0, 4}

    def _attach(node: ProcessNode, depth: int, visited: set[int]) -> None:
        node.depth = depth
        visited.add(node.pid)
        for p in processes:
            if p.ppid == node.pid and p.pid not in visited:
                child = nodes.get(p.pid)
                if child is not None:
                    node.children.append(child)
                    _attach(child, depth + 1, visited)

    roots: list[ProcessNode] = []
    orphans: list[ProcessNode] = []

    for _pid, node in nodes.items():
        if node.ppid in _SYSTEM_PIDS or node.ppid not in pid_set:
            if node.ppid not in _SYSTEM_PIDS and node.ppid != 0:
                orphans.append(node)
            else:
                roots.append(node)
            _attach(node, 0, set())

    suspicious_count = sum(1 for n in nodes.values() if n.suspicious)

    return ProcessTreeReport(
        image_path=str_image,
        process_count=len(processes),
        root_count=len(roots),
        orphan_count=len(orphans),
        suspicious_count=suspicious_count,
        roots=sorted(roots, key=lambda n: n.pid),
        orphans=sorted(orphans, key=lambda n: n.pid),
        warnings=warnings,
    )


# --------------------------------------------------------------------------- #
# Tool 3: pivot_on_ioc                                                         #
# --------------------------------------------------------------------------- #

_DEFAULT_ARTIFACT_TYPES: tuple[str, ...] = ("pslist", "netscan", "svcscan", "evtx")


async def pivot_on_ioc(
    ioc: str,
    images: list[str | Path],
    *,
    artifact_types: list[str] | None = None,
    ioc_type: str = "string",
    timeout: float | None = None,
) -> IOCPivotReport:
    """Find all occurrences of an IOC across multiple artifact types and hosts.

    Runs get_pslist, get_netscan, get_svcscan, and get_evtx concurrently
    for each image, then searches every record for the IOC value via
    case-insensitive substring match. Returns all hits with full context.

    Args:
        ioc: The IOC value to search for (IP, process name, username, etc.).
        images: Evidence image paths.
        artifact_types: Subset of ("pslist", "netscan", "svcscan", "evtx").
                        Defaults to all four.
        ioc_type: Semantic label for the IOC ("ip", "process", "service",
                  "username", "hash", "string").
        timeout: Per-wrapper call timeout in seconds.

    Returns:
        IOCPivotReport with all hits sorted by host then timestamp.
    """
    from agentropix_mcp.wrappers.evtx import get_evtx
    from agentropix_mcp.wrappers.volatility import (
        get_netscan,
        get_pslist,
        get_svcscan,
    )

    str_images = [str(img) for img in images]
    types_to_search = set(artifact_types or _DEFAULT_ARTIFACT_TYPES)
    all_hits: list[IOCHit] = []
    warnings: list[str] = []
    ioc_lower = ioc.lower()

    def _match(value: Any) -> bool:
        return ioc_lower in str(value).lower()

    async def _search_image(img: str) -> list[IOCHit]:
        host = _host_from_image(img)
        img_hits: list[IOCHit] = []

        coros: list[Any] = []
        labels: list[str] = []
        if "pslist" in types_to_search:
            coros.append(get_pslist(img, timeout=timeout))
            labels.append("pslist")
        if "netscan" in types_to_search:
            coros.append(get_netscan(img, timeout=timeout))
            labels.append("netscan")
        if "svcscan" in types_to_search:
            coros.append(get_svcscan(img, timeout=timeout))
            labels.append("svcscan")
        if "evtx" in types_to_search:
            coros.append(get_evtx(img, timeout=timeout))
            labels.append("evtx")

        results = await asyncio.gather(*coros, return_exceptions=True)

        for label, result in zip(labels, results, strict=False):
            if isinstance(result, Exception):
                warnings.append(f"{host}/{label}: {result}")
                continue

            if label == "pslist":
                for proc in result.processes:
                    row = {"name": proc.name, "pid": proc.pid, "ppid": proc.ppid}
                    for fname, fval in row.items():
                        if _match(fval):
                            img_hits.append(IOCHit(
                                artifact_type="pslist",
                                host=host,
                                image_path=img,
                                timestamp=proc.create_time,
                                field_name=fname,
                                matched_value=str(fval),
                                context=proc.model_dump(),
                            ))
                            break

            elif label == "netscan":
                for sock in result.sockets:
                    row = {
                        "owner": sock.owner,
                        "local_addr": sock.local_addr,
                        "foreign_addr": sock.foreign_addr,
                        "state": sock.state,
                        "pid": sock.pid,
                    }
                    for fname, fval in row.items():
                        if _match(fval):
                            img_hits.append(IOCHit(
                                artifact_type="netscan",
                                host=host,
                                image_path=img,
                                timestamp=sock.created,
                                field_name=fname,
                                matched_value=str(fval),
                                context=sock.model_dump(),
                            ))
                            break

            elif label == "svcscan":
                for svc in result.services:
                    row = {
                        "name": svc.name,
                        "display": svc.display,
                        "binary": svc.binary,
                        "state": svc.state,
                    }
                    for fname, fval in row.items():
                        if _match(fval):
                            img_hits.append(IOCHit(
                                artifact_type="svcscan",
                                host=host,
                                image_path=img,
                                timestamp="",
                                field_name=fname,
                                matched_value=str(fval),
                                context=svc.model_dump(),
                            ))
                            break

            elif label == "evtx":
                for ev in result.events:
                    raw = _parse_raw(ev.raw)
                    for fname, fval in raw.items():
                        if _match(fval):
                            img_hits.append(IOCHit(
                                artifact_type="evtx",
                                host=host,
                                image_path=img,
                                timestamp=ev.timestamp,
                                field_name=fname,
                                matched_value=str(fval),
                                context={
                                    "event_id": ev.event_id,
                                    "channel": ev.channel,
                                    "raw": raw,
                                },
                            ))
                            break

        return img_hits

    per_image = await asyncio.gather(
        *(_search_image(img) for img in str_images),
        return_exceptions=True,
    )
    for item in per_image:
        if isinstance(item, list):
            all_hits.extend(item)
        elif isinstance(item, Exception):
            warnings.append(str(item))

    hosts_hit = sorted({h.host for h in all_hits})

    return IOCPivotReport(
        ioc_value=ioc,
        ioc_type=ioc_type,
        total_hits=len(all_hits),
        host_count=len(hosts_hit),
        hosts_hit=hosts_hit,
        artifact_types_searched=sorted(types_to_search),
        hits=all_hits,
        warnings=warnings,
    )


# --------------------------------------------------------------------------- #
# Tool 4: detect_sweep                                                         #
# --------------------------------------------------------------------------- #


async def detect_sweep(
    image: str | Path,
    *,
    window_seconds: float = 1.0,
    min_shares_per_window: int = 3,
    event_ids: list[int] | None = None,
    timeout: float | None = None,
) -> SweepReport:
    """Detect SMB share enumeration bursts from Security Event Log.

    Fetches EID 5140 (share object accessed) and 5145 (share object
    access-checked) events, groups by source IP, and applies a sliding
    window: if >= min_shares_per_window unique shares are accessed from
    the same IP within window_seconds, flags it as a sweep burst.

    SRL-2018 baseline: spsql authenticated to 37 hosts and accessed
    20,013 shares in a 4-hour window — the canonical sweep signature.

    Args:
        image: Path to E01 disk image (Security.evtx source) or memory image.
        window_seconds: Sliding window width in seconds (default: 1.0).
        min_shares_per_window: Minimum unique shares to trigger a flag (default: 3).
        event_ids: Override the default {5140, 5145} filter.
        timeout: Timeout for the underlying get_evtx call.

    Returns:
        SweepReport listing every detected burst with timing and share list.
    """
    from agentropix_mcp.wrappers.evtx import get_evtx

    str_image = str(image)
    target_eids = set(event_ids or [5140, 5145])
    warnings: list[str] = []

    try:
        report = await get_evtx(
            str_image,
            event_ids=target_eids,
            max_events=100_000,
            timeout=timeout,
        )
    except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as exc:
        return SweepReport(
            image_path=str_image,
            burst_count=0,
            threshold_per_window=min_shares_per_window,
            window_size_seconds=window_seconds,
            events_analyzed=0,
            warnings=[str(exc)],
        )

    if report.truncated:
        warnings.append(
            f"Event stream truncated at {len(report.events)} events — "
            "sweep results may be incomplete; raise max_events or narrow the window"
        )

    # Group by source IP: list of (timestamp_dt, share_name, event_id, src_host)
    ip_events: dict[str, list[tuple[datetime, str, int, str]]] = defaultdict(list)

    for ev in report.events:
        raw = _parse_raw(ev.raw)
        src_ip = str(raw.get("IpAddress") or raw.get("SubjectLogonId") or "")
        share_name = str(raw.get("ShareName") or raw.get("ObjectType") or "")
        src_host = str(raw.get("SubjectUserName") or "")

        ts_dt = _parse_ts(ev.timestamp)
        if ts_dt is None:
            continue

        # Skip loopback / local accesses — not lateral movement
        if not src_ip or src_ip in {"-", "LOCAL", "::1", "127.0.0.1", "local"}:
            src_ip = src_host or "unknown"

        ip_events[src_ip].append((ts_dt, share_name, ev.event_id, src_host))

    bursts: list[SweepBurst] = []

    for src_ip, ev_list in ip_events.items():
        ev_list.sort(key=lambda x: x[0])
        n = len(ev_list)
        i = 0
        while i < n:
            win_start_dt = ev_list[i][0]
            window: list[tuple[datetime, str, int, str]] = []
            j = i
            while j < n and (ev_list[j][0] - win_start_dt).total_seconds() <= window_seconds:
                window.append(ev_list[j])
                j += 1

            unique_shares = {s for _, s, _, _ in window if s}
            if len(unique_shares) >= min_shares_per_window:
                last_dt = window[-1][0]
                elapsed = (last_dt - win_start_dt).total_seconds()
                eids_seen = sorted({e for _, _, e, _ in window})
                src_host = window[0][3]
                bursts.append(SweepBurst(
                    src_ip=src_ip,
                    src_host=src_host,
                    window_start=win_start_dt.isoformat(),
                    window_end=last_dt.isoformat(),
                    target_shares=sorted(unique_shares),
                    event_count=len(window),
                    events_per_second=len(window) / max(elapsed, 0.001),
                    event_ids_seen=eids_seen,
                ))
                i = j  # advance past this burst
            else:
                i += 1

    return SweepReport(
        image_path=str_image,
        burst_count=len(bursts),
        threshold_per_window=min_shares_per_window,
        window_size_seconds=window_seconds,
        events_analyzed=len(report.events),
        bursts=bursts,
        warnings=warnings,
    )
