"""Plaso/log2timeline wrappers — super timeline generation.

M6.3 W-050 event-window redesign (supersedes the simple "first-N lines"
sampler that truncated attack-era events on multi-year NTFS images):

``_parse_jsonl_events`` now streams the entire psort JSONL and applies
a two-pass bucket-sampling strategy so high-signal events (winevtx 4624,
winreg Run-key, MFT timestomp, LOLBINs across any parser) reach the
downstream ``TimelineAgent`` even when they sit millions of datetime-
ascending lines deep:

* A bounded **priority deque** admits any event matching a high-signal
  predicate — its ``maxlen`` is tunable via
  ``AGENTROPIX_PLASO_PRIORITY_BUDGET`` (default 200, floor 0, ceiling
  10000).  Setting the budget to 0 disables the priority path entirely.
* Per-parser bounded deques retain the MOST RECENT N events per parser
  family.  On a datetime-ascending stream this naturally preserves
  attack-era events over OS-install noise.  Per-parser budget is tunable
  via ``AGENTROPIX_PLASO_PER_PARSER_BUDGET`` (default 150, floor 1,
  ceiling 10000).
* Assembly drains the priority deque first (dedup'd against the parser
  deques by ``(parser, message)`` identity) and then round-robins across
  parsers until the ``max_events`` hard cap is reached.

The output still satisfies ``len(events) <= max_events``.  Priority
predicates live in ``_PRIORITY_PREDICATES`` and are intentionally
conservative — they mirror the detectors in ``agents/timeline.py`` so
this wrapper surfaces precisely the signals the agent needs.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import shutil
import signal
import tempfile
import uuid
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from agentropix_mcp._env import get_float, get_int, get_str_set
from agentropix_mcp.wrappers._subprocess import run_with_memory_limit

logger = logging.getLogger(__name__)


def _isoformat_from_microseconds(ts_us: object) -> str:
    """W-190: convert plaso's ``timestamp`` field (microseconds since UNIX
    epoch) to an ISO-8601 string. Returns ``""`` on non-int input, overflow,
    or other failure modes so the caller can fall through to the existing
    string-fallback chain without raising.

    psort ``-o json_line`` (see ``_parse_jsonl_events``) emits an integer
    ``timestamp`` field but no string ``datetime`` field. ARTIFACT-INVENTORY
    Gap A1 documented the resulting symptom: every timeline.plaso finding
    had ``datetime=`` empty across all 9,578 SRL-2018 findings.
    """
    if not isinstance(ts_us, int) or isinstance(ts_us, bool):
        return ""
    try:
        seconds, remainder_us = divmod(ts_us, 1_000_000)
        dt = datetime.fromtimestamp(seconds, tz=UTC).replace(microsecond=remainder_us)
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


class TimelineEvent(BaseModel):
    """Single timeline event from Plaso output."""

    datetime: str = ""
    timestamp_desc: str = ""
    source: str = ""
    source_long: str = ""
    message: str = ""
    parser: str = ""
    display_name: str = ""
    tag: str = ""


class TimelineEvents(BaseModel):
    """Parsed Plaso timeline result.

    M6.4 W-060 instrumentation: ``counters`` captures dataflow signals at
    the psort→sampler→agent boundary so operators can isolate where a live
    DC run loses priority events (H1 psort empty, H2 predicates miss, H3
    agent detectors skip — see ``docs/adr/ADR-M6.3-residual-gap.md``).

    Fields (all optional, zero-filled):
      * ``jsonl_rows_read``         — rows psort produced (non-blank lines).
      * ``priority_hits_by_family`` — {family: count} across all predicates.
      * ``parser_deque_sizes``      — {family: fill count at drain time}.

    M6.4 W-060 persistence: ``wrapper_error`` is the soft-failure channel.
    When psort times out we still return a ``TimelineEvents`` (with
    ``events=[]`` and the sampler counters zero-filled) rather than
    raising — otherwise the exception path would strip whatever dataflow
    signal had been collected and ``trace.counters`` would never reach
    ``report.json``.  Callers that want the hard-failure semantics can
    inspect ``wrapper_error`` explicitly.
    """

    image_path: str
    event_count: int
    events: list[TimelineEvent] = Field(default_factory=list)
    tool: str = "plaso.log2timeline"
    storage_file: str = ""
    raw_stderr: str = ""
    # W-060 instrumentation — see class docstring.
    jsonl_rows_read: int = 0
    priority_hits_by_family: dict[str, int] = Field(default_factory=dict)
    parser_deque_sizes: dict[str, int] = Field(default_factory=dict)
    # W-060 persistence — soft-failure tag so psort timeouts carry
    # counters through to the trace instead of being dropped by the
    # exception path.  Empty string means "no wrapper-level failure".
    wrapper_error: str = ""
    # SIFT-W-082: SHA-256 of psort's raw stdout bytes — chain-of-custody fingerprint.
    # psort writes output to a file; stdout is typically empty or progress lines.
    raw_stdout_sha256: str = ""


# --- M6.3 event-window constants ------------------------------------------

# Per-parser budget when no per-parser override is supplied.  Ceilinged
# below get_int's generic ceiling so a 10-parser set can't blow past the
# default max_events (500) — but still leaves 150 slots per parser which
# is more than enough to carry any single-artefact cohit evidence.
_DEFAULT_PRIORITY_BUDGET = 200
_DEFAULT_PER_PARSER_BUDGET = 150
_DEFAULT_MAX_PER_EID = 200  # W-A08: allocate 200 events per unique Event ID
_PRIORITY_BUDGET_FLOOR = 0
_PRIORITY_BUDGET_CEILING = 10000
_PER_PARSER_BUDGET_FLOOR = 1
_PER_PARSER_BUDGET_CEILING = 10000
_MAX_PER_EID_FLOOR = 1
_MAX_PER_EID_CEILING = 10000

# W-131: bound log2timeline.py worker count. Plaso's default is
# ``cpu_count() - 1`` which on a 16-vCPU host is 15+1 = 16 forks; each
# parser-loaded worker holds 1-3 GiB resident, so aggregate RSS scales
# linearly with worker count and overran 41 GiB on the 2026-04-30 DC
# triage (OOM-killed the MCP host). Default 4 keeps aggregate ≤ ~6 GiB
# on typical parser sets while still giving meaningful parallelism;
# operators on bigger hosts can raise via AGENTROPIX_PLASO_WORKERS.
# Floor 1 (single-worker still produces output, just slower); ceiling 32
# is a defence-in-depth guard against any upstream change to the env
# parsing default.
_DEFAULT_PLASO_WORKERS = 6  # W-136 §3 row 4: raised 4 -> 6 after W-131/W-132 reaping landed
_PLASO_WORKERS_FLOOR = 1
_PLASO_WORKERS_CEILING = 32


def _resolve_plaso_workers() -> int:
    """W-131: return a bounded worker count for log2timeline.py --workers.

    Bounded by ``min(cpu_count - 1, AGENTROPIX_PLASO_WORKERS)`` so a
    misconfigured env can't overshoot host capacity. ``cpu_count - 1``
    leaves one core for the wrapper / asyncio loop / monitor task.
    """
    cap = get_int(
        "AGENTROPIX_PLASO_WORKERS",
        _DEFAULT_PLASO_WORKERS,
        floor=_PLASO_WORKERS_FLOOR,
        ceiling=_PLASO_WORKERS_CEILING,
    )
    cpu = max(1, (os.cpu_count() or 1) - 1)
    return min(cpu, cap)


def _reap_proc_group(proc: asyncio.subprocess.Process | None) -> None:
    """W-132: idempotent SIGKILL on a process group started with start_new_session=True.

    Safe to call multiple times — silent no-op if proc is None, already
    dead, or its session has already been reaped. Used from every
    exception path AND from the wrapper's finally-block so a Plaso tree
    cannot survive an abnormal wrapper exit (TimeoutError, MemoryError,
    asyncio.CancelledError, generic Exception).
    """
    if proc is None or proc.returncode is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass


# LOLBINs mirror ``TimelineAgent._DEFAULT_LOLBIN_KEYWORDS`` — duplicated here
# deliberately so the wrapper stays self-contained (no cross-module import)
# and so the priority layer doesn't shift when operators tune the agent's
# LOLBIN allowlist mid-run.
_LOLBIN_KEYWORDS: tuple[str, ...] = (
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "mshta",
    "regsvr32",
    "rundll32",
    "certutil",
    "bitsadmin",
    "schtasks",
)

_WINREG_RUN_TOKENS: tuple[str, ...] = (
    "\\run\\",
    "\\runonce\\",
    "currentversion\\run",
)

# W-105: AppData-staging predicate constants. Mirror the agent-side
# detector at agents/timeline.py:78 so the priority layer surfaces
# precisely the events the W-067 detector consumes. Duplicated rather
# than imported because the wrapper stays self-contained (see
# _LOLBIN_KEYWORDS comment above for the same convention).
_STAGING_EXTENSIONS: tuple[str, ...] = (".exe", ".dll", ".bin", ".ps1", ".bat")
_USER_PATH_TOKENS: tuple[str, ...] = ("\\users\\", "/users/")
_APPDATA_TOKEN: str = "appdata"
_BENIGN_APPDATA_FRAGMENTS: tuple[str, ...] = (
    "lastalive",
    "system32",
    "windows\\assembly",
    "windows\\fonts",
    "microsoft\\windows\\recent",
    "microsoft\\windows\\start menu",
    "notificationstation",
    "connecteddevices",
)


def _is_4624(event: dict) -> bool:
    parser = (event.get("parser") or "").lower()
    if not parser.startswith("winevtx"):
        return False
    return "4624" in (event.get("message") or "")


def _is_winreg_run(event: dict) -> bool:
    parser = (event.get("parser") or "").lower()
    if not parser.startswith("winreg"):
        return False
    msg = (event.get("message") or "").lower()
    return any(tok in msg for tok in _WINREG_RUN_TOKENS)


def _is_mft_timestomp(event: dict) -> bool:
    parser = (event.get("parser") or "").lower()
    if not parser.startswith("mft"):
        return False
    msg = (event.get("message") or "").lower()
    # W-066 (M6.8): plaso's MFT parser stores the modified-time signal in
    # the l2tcsv ``type`` column (→ ``timestamp_desc``), not the ``desc``
    # column (→ ``message``).  P0-3.4 trace.counters showed 0 predicate
    # matches across 13.8M rows despite 150 MFT events reaching the
    # per-parser deque.  Mirror the detector fix in ``agents/timeline.py``.
    ts_desc = (event.get("timestamp_desc") or "").lower()
    return (
        "timestomp" in msg
        or "modified" in msg
        or "modified" in ts_desc
        or "modification" in ts_desc
    )


def _is_lolbin(event: dict) -> bool:
    msg = (event.get("message") or "").lower()
    display = (event.get("display_name") or "").lower()
    haystack = msg + " " + display
    return any(kw in haystack for kw in _LOLBIN_KEYWORDS)


def _is_appdata_staging(event: dict) -> bool:
    """W-105: MFT events for executables under ``\\Users\\*\\AppData\\*``
    are T1055 staging candidates. Without priority promotion these lose
    to the high-volume ``_is_mft_timestomp`` events in the per-parser MFT
    deque (cap 150) on a multi-year disk, so the W-067 staging detector
    in :mod:`agents.timeline` never sees the attack-era beacon entry.

    Predicate is intentionally narrow: the same path-token + extension
    + benign-fragment shape the agent's detector uses, mirrored here so
    the wrapper surfaces precisely what the agent will promote. Benign
    paths (``\\Windows\\ServiceProfiles\\...\\AppData\\Local\\lastalive*``)
    are filtered out wrapper-side too, keeping the priority deque from
    burning a slot on entries the agent would discard anyway.
    """
    parser = (event.get("parser") or "").lower()
    if not parser.startswith("mft"):
        return False
    msg = (event.get("message") or "").lower()
    if not any(tok in msg for tok in _USER_PATH_TOKENS):
        return False
    if _APPDATA_TOKEN not in msg:
        return False
    if not any(ext in msg for ext in _STAGING_EXTENSIONS):
        return False
    return not any(frag in msg for frag in _BENIGN_APPDATA_FRAGMENTS)


# Ordered predicates — first match wins for classification but all events
# matching ANY predicate flow into the priority bucket.
_PRIORITY_PREDICATES: tuple[Callable[[dict], bool], ...] = (
    _is_4624,
    _is_winreg_run,
    _is_mft_timestomp,
    _is_lolbin,
    _is_appdata_staging,
)

# W-060 instrumentation — predicate family labels for
# ``priority_hits_by_family``.  Order matches ``_PRIORITY_PREDICATES``.
_PRIORITY_FAMILY_LABELS: tuple[str, ...] = (
    "4624",
    "winreg_run",
    "mft_timestomp",
    "lolbin",
    "appdata_staging",
)


def _parser_family(parser: str) -> str:
    """Normalise plaso parser ids to their family name.

    plaso emits parser ids like ``winreg/windows_run_key`` or
    ``winevtx`` — we bucket on the family prefix so a single
    ``AGENTROPIX_PLASO_PER_PARSER_BUDGET`` applies consistently across
    plugin variants.
    """
    raw = (parser or "").lower().strip()
    if not raw:
        return "unknown"
    return raw.split("/", 1)[0]


def _extract_eid(message: str) -> str:
    """Extract Windows Event ID from plaso message strings.

    W-A08: per-EID budgeting requires identifying the event type.
    Plaso winevtx messages include patterns like:
      "[4624 / 0x1234] message text..."  (most common)
      "Event ID: 4624 / ..."  (alternate)
      "4624:" (prefix)
    """
    import re

    if not message:
        return "unknown"
    # Match patterns like "[4624 / 0x..." or "Event ID: 4624" or "4624:" etc.
    m = re.search(r"\[(\d{4})\s*[/\]]|Event ID[:\s]+(\d{4})|^(\d{4}):", message)
    if m:
        eid = m.group(1) or m.group(2) or m.group(3)
        return eid if eid else "unknown"
    return "unknown"


def _is_priority(event: dict) -> bool:
    return any(pred(event) for pred in _PRIORITY_PREDICATES)


# --- M6.5 W-061 l2tcsv fallback helpers ------------------------------------

# plaso l2tcsv ``format`` column uses abbreviated source names like
# ``WinEvtx`` / ``WinReg`` / ``MFT``.  Detectors in ``agents/timeline.py``
# check the parser field with ``startswith("winevtx")`` etc, so we must
# normalise the CSV format column to the same identifiers json_line
# emits in ``parser``.
_L2TCSV_PARSER_MAP: dict[str, str] = {
    "winevtx": "winevtx",
    "winreg": "winreg",
    "mft": "mft",
    "prefetch": "prefetch",
    "file": "filestat",
    "filestat": "filestat",
    "lnk": "lnk",
    "pe": "pe",
}


def _normalize_l2tcsv_parser(format_col: str) -> str:
    """Map an l2tcsv ``format`` column value to the canonical parser id.

    ``format`` may include a plugin suffix (``winreg/windows_run_key``) —
    strip it and lowercase before looking up so ``WinReg/...`` becomes
    ``winreg``.  Unknown values pass through (lowercased) so the agent
    can still see them in traces.
    """
    raw = format_col.lower().strip().split("/", 1)[0]
    return _L2TCSV_PARSER_MAP.get(raw, raw)


def _normalize_l2tcsv_parser_full(format_col: str) -> str:
    """Like _normalize_l2tcsv_parser but preserves the plugin suffix.

    ``WinReg/windows_run_key`` → ``winreg/windows_run_key``.
    Used as the per-plugin deque bucket key (M6.9 W-067) so that
    high-volume plugins like ``winreg/userassist`` cannot evict
    low-volume priority plugins like ``winreg/windows_run_key``.
    """
    raw = format_col.lower().strip()
    parts = raw.split("/", 1)
    family = _L2TCSV_PARSER_MAP.get(parts[0], parts[0])
    if len(parts) > 1:
        return f"{family}/{parts[1]}"
    return family


def _make_priority_buckets(priority_budget: int) -> dict[str, deque]:
    """Return per-family priority sub-deques (M6.9 W-067).

    Splits the flat priority_budget across all predicate families so
    a high-volume family (4624: 1.4M hits/run) cannot evict a low-volume
    priority family (winreg_run: ~24 hits/run).  Each family gets an
    equal share; minimum 1 slot per family when budget is small.
    """
    per_family = (
        max(1, priority_budget // len(_PRIORITY_FAMILY_LABELS)) if priority_budget > 0 else 0
    )
    return {label: deque(maxlen=per_family) for label in _PRIORITY_FAMILY_LABELS}


def _parse_l2tcsv_events(
    csv_path: Path,
    *,
    max_events: int = 500,
    counters: dict | None = None,
) -> list[TimelineEvent]:
    """Parse Plaso ``l2tcsv`` output into a size-capped ``TimelineEvent`` list.

    M6.5 W-061 fallback for the ``_parse_jsonl_events`` path when psort
    ``json_line`` returns rc!=0 (``TypeError: Object of type bytes is
    not JSON serializable`` in ``_ExportEvents`` on Windows EVTX).

    l2tcsv columns (0-based, comma-separated with header row):
      date,time,timezone,MACB,source,sourcetype,type,user,host,
      short,desc,version,filename,inode,notes,format,extra

    Uses the same two-pass priority-bucket + per-parser-deque sampling
    as ``_parse_jsonl_events`` so the priority predicates (4624,
    winreg_run, mft_timestomp, lolbin) and the per-parser budgets work
    identically regardless of route.
    """
    import csv as _csv
    import sys as _sys

    # W-064 (M6.7): Python stdlib csv defaults ``field_size_limit`` to
    # 131072 bytes. Plaso's l2tcsv ``desc`` column embeds full Windows
    # event XML / registry value blobs that routinely exceed 128 KiB on
    # real images — the reader then raises ``csv.Error: field larger
    # than field limit (131072)`` mid-iteration, and because the counter
    # writes live AFTER the loop the entire dataflow signal is lost
    # (observed live in M6.6-W063-cli: ``trace.counters: {}``, agent
    # crashed with exit_code=2). Lift the limit so one oversized row
    # cannot sink the fallback path; ``sys.maxsize`` is clamped per the
    # stdlib ``OverflowError`` contract on 32-bit hosts.
    try:
        _csv.field_size_limit(_sys.maxsize)
    except OverflowError:
        _csv.field_size_limit(2**31 - 1)

    if counters is not None:
        counters.setdefault("jsonl_rows_read", 0)
        counters.setdefault(
            "priority_hits_by_family",
            {label: 0 for label in _PRIORITY_FAMILY_LABELS},
        )
        counters.setdefault("parser_deque_sizes", {})

    if not csv_path.exists():
        return []

    priority_budget = get_int(
        "AGENTROPIX_PLASO_PRIORITY_BUDGET",
        _DEFAULT_PRIORITY_BUDGET,
        floor=_PRIORITY_BUDGET_FLOOR,
        ceiling=_PRIORITY_BUDGET_CEILING,
    )
    per_parser_budget = get_int(
        "AGENTROPIX_PLASO_PER_PARSER_BUDGET",
        _DEFAULT_PER_PARSER_BUDGET,
        floor=_PER_PARSER_BUDGET_FLOOR,
        ceiling=_PER_PARSER_BUDGET_CEILING,
    )

    # W-067 (M6.9): per-family priority sub-deques prevent high-volume
    # families (4624: 1.4M hits/run) from evicting low-volume priority
    # families (winreg_run: ~24 hits/run) via deque rotation.
    priority_buckets: dict[str, deque[TimelineEvent]] = _make_priority_buckets(priority_budget)
    parser_buckets: dict[str, deque[TimelineEvent]] = {}

    # l2tcsv column indices
    _L2T_IDX_DATE = 0
    _L2T_IDX_TIME = 1
    _L2T_IDX_TYPE = 6
    _L2T_IDX_DESC = 10
    _L2T_IDX_FILENAME = 12
    _L2T_IDX_FORMAT = 15
    _L2T_MIN_COLS = 16

    malformed = 0
    rows_read = 0
    priority_hits = {label: 0 for label in _PRIORITY_FAMILY_LABELS}

    with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = _csv.reader(fh, skipinitialspace=True)
        # W-064 (M6.7): iterate manually so a per-row ``csv.Error``
        # (e.g. unterminated quote) skips that one row instead of
        # aborting the scan. The field_size_limit bump above is the
        # primary fix for the DC E01 failure; this is defence-in-depth.
        i = -1
        while True:
            i += 1
            try:
                row = next(reader)
            except StopIteration:
                break
            except _csv.Error as e:
                malformed += 1
                if malformed <= 5:
                    logger.warning("Skipping broken l2tcsv row %d: %s", i, e)
                continue
            if i == 0:
                # skip header
                continue
            if len(row) < _L2T_MIN_COLS:
                malformed += 1
                if malformed <= 5:
                    logger.warning("Skipping malformed l2tcsv row %d (cols=%d)", i, len(row))
                continue
            rows_read += 1

            parser = _normalize_l2tcsv_parser(row[_L2T_IDX_FORMAT])
            # W-067 (M6.9): preserve plugin suffix for per-plugin deque key
            # so winreg/windows_run_key is not evicted by winreg/userassist.
            parser_full = _normalize_l2tcsv_parser_full(row[_L2T_IDX_FORMAT])
            msg = row[_L2T_IDX_DESC]
            display = row[_L2T_IDX_FILENAME]
            dt = f"{row[_L2T_IDX_DATE]} {row[_L2T_IDX_TIME]}".strip()
            ts_desc = row[_L2T_IDX_TYPE]

            try:
                event = TimelineEvent(
                    datetime=dt,
                    timestamp_desc=ts_desc,
                    source="",
                    source_long="",
                    message=msg,
                    parser=parser,
                    display_name=display,
                    tag="",
                )
            except Exception as e:
                malformed += 1
                if malformed <= 5:
                    logger.warning("Dropping uncoercible l2tcsv row %d: %s", i, e)
                continue

            # Build a plain dict matching the json_line predicate interface.
            # W-066: include ``timestamp_desc`` so the MFT predicate can
            # see the modified-time signal plaso stores in l2tcsv col 6.
            event_dict = {
                "parser": parser,
                "message": msg,
                "display_name": display,
                "timestamp_desc": ts_desc,
            }

            for label, pred in zip(_PRIORITY_FAMILY_LABELS, _PRIORITY_PREDICATES, strict=True):
                if pred(event_dict):
                    priority_hits[label] += 1
                    if priority_budget > 0:
                        priority_buckets[label].append(event)

            # W-067: bucket by full plugin path, not family, so per-plugin
            # deques are isolated (winreg/windows_run_key ≠ winreg/userassist).
            bucket = parser_buckets.get(parser_full)
            if bucket is None:
                bucket = deque(maxlen=per_parser_budget)
                parser_buckets[parser_full] = bucket
            bucket.append(event)

    if malformed > 5:
        logger.warning(
            "l2tcsv had %d additional malformed rows (suppressed)",
            malformed - 5,
        )

    if counters is not None:
        counters["jsonl_rows_read"] = rows_read
        counters["priority_hits_by_family"] = dict(priority_hits)
        counters["parser_deque_sizes"] = {k: len(b) for k, b in parser_buckets.items()}

    # Assembly — priority first (per-family sub-deques), then per-parser
    # round-robin (newest-first), mirroring ``_parse_jsonl_events`` Pass 2.
    output: list[TimelineEvent] = []
    seen: set[tuple[str, str, str]] = set()

    def _maybe_add(event: TimelineEvent) -> bool:
        if len(output) >= max_events:
            return False
        # W-A08: include EID in dedup key so all Event IDs are represented,
        # not just the first message seen for each parser. Use FULL message
        # (not truncated) to preserve event distinguishability — truncating
        # to msg[:80] caused recall regression (273 -> 199 findings).
        eid = _extract_eid(event.message)
        key = (event.datetime, event.parser, eid, event.message)
        if key in seen:
            return False
        seen.add(key)
        output.append(event)
        return True

    for pbucket in priority_buckets.values():
        for event in pbucket:
            if not _maybe_add(event) and len(output) >= max_events:
                return output

    bucket_iters = {k: iter(list(reversed(b))) for k, b in parser_buckets.items()}
    while bucket_iters and len(output) < max_events:
        exhausted: list[str] = []
        for family, it in bucket_iters.items():
            try:
                event = next(it)
            except StopIteration:
                exhausted.append(family)
                continue
            _maybe_add(event)
            if len(output) >= max_events:
                break
        for family in exhausted:
            bucket_iters.pop(family, None)

    return output


def _parse_jsonl_events(
    jsonl_path: Path,
    *,
    max_events: int = 500,
    counters: dict | None = None,
) -> list[TimelineEvent]:
    """Parse Plaso JSON-line output into a size-capped TimelineEvent list.

    Two-pass bucket-sampling:

    Pass 1 — stream the entire JSONL.  For each valid event:
      * If it matches any priority predicate, append to the priority
        deque (bounded by ``AGENTROPIX_PLASO_PRIORITY_BUDGET``).
      * Always append to its parser-family deque (bounded by
        ``AGENTROPIX_PLASO_PER_PARSER_BUDGET``).

    Pass 2 — assemble the output list:
      * Start with priority events (in stream order).
      * Round-robin across parser deques for remaining slots.
      * Dedupe by ``(parser, message)`` identity so a priority event
        that's also in its parser deque doesn't appear twice.
      * Hard-cap at ``max_events``.

    W-060 instrumentation: if ``counters`` is a mutable mapping, populate
    it in-place with
      * ``jsonl_rows_read``          (int)
      * ``priority_hits_by_family``  (dict[str, int])
      * ``parser_deque_sizes``       (dict[str, int])
    """
    # Pre-populate with zeroed sub-counters so downstream always sees a
    # stable shape even when the JSONL is absent or empty.
    if counters is not None:
        counters.setdefault("jsonl_rows_read", 0)
        counters.setdefault(
            "priority_hits_by_family",
            {label: 0 for label in _PRIORITY_FAMILY_LABELS},
        )
        counters.setdefault("parser_deque_sizes", {})

    if not jsonl_path.exists():
        return []

    priority_budget = get_int(
        "AGENTROPIX_PLASO_PRIORITY_BUDGET",
        _DEFAULT_PRIORITY_BUDGET,
        floor=_PRIORITY_BUDGET_FLOOR,
        ceiling=_PRIORITY_BUDGET_CEILING,
    )
    per_parser_budget = get_int(
        "AGENTROPIX_PLASO_PER_PARSER_BUDGET",
        _DEFAULT_PER_PARSER_BUDGET,
        floor=_PER_PARSER_BUDGET_FLOOR,
        ceiling=_PER_PARSER_BUDGET_CEILING,
    )

    # W-067 (M6.9): per-family priority sub-deques prevent high-volume
    # families (4624: 1.4M hits/run) from evicting low-volume priority
    # families (winreg_run: ~24 hits/run) via deque rotation.
    priority_buckets: dict[str, deque[TimelineEvent]] = _make_priority_buckets(priority_budget)
    parser_buckets: dict[str, deque[TimelineEvent]] = {}

    malformed = 0
    rows_read = 0
    priority_hits = {label: 0 for label in _PRIORITY_FAMILY_LABELS}
    with open(jsonl_path) as fh:
        for i, raw_line in enumerate(fh):
            line = raw_line.strip()
            if not line:
                continue
            rows_read += 1
            try:
                data = json.loads(line)
            except (json.JSONDecodeError, KeyError) as e:
                malformed += 1
                if malformed <= 5:
                    logger.warning("Skipping malformed Plaso event at line %d: %s", i, e)
                continue

            try:
                # Coerce None → "" because some plaso plugins emit JSON
                # ``null`` for unset fields, and TimelineEvent's str-typed
                # fields would otherwise reject the event as malformed.
                event = TimelineEvent(
                    datetime=(
                        # W-190 / Gap A1: prefer string ``datetime`` when an
                        # upstream tool supplied one, then derive from int
                        # ``timestamp`` (psort json_line's canonical form —
                        # microseconds since epoch), then fall through to the
                        # existing string-only fallbacks for legacy paths.
                        data.get("datetime")
                        or _isoformat_from_microseconds(data.get("timestamp"))
                        or data.get("timestamp_desc")
                        or data.get("display_name")
                        or ""
                    ),
                    timestamp_desc=data.get("timestamp_desc") or "",
                    source=data.get("source_short") or "",
                    source_long=data.get("source_long") or "",
                    message=data.get("message") or "",
                    parser=data.get("parser") or "",
                    display_name=data.get("display_name") or "",
                    tag=data.get("tag") or "",
                )
            except Exception as e:
                malformed += 1
                if malformed <= 5:
                    logger.warning("Dropping uncoercible Plaso event at line %d: %s", i, e)
                continue

            # W-060: count priority hits per family even when the budget
            # is 0 — the counter is informational; admitting into the
            # deque is still gated by ``priority_budget > 0``.
            for label, pred in zip(_PRIORITY_FAMILY_LABELS, _PRIORITY_PREDICATES, strict=True):
                if pred(data):
                    priority_hits[label] += 1
                    if priority_budget > 0:
                        priority_buckets[label].append(event)

            # W-067: bucket by full plugin path (event.parser already carries
            # the full path from plaso JSON, e.g. ``winreg/windows_run_key``).
            plugin_key = event.parser or "unknown"
            bucket = parser_buckets.get(plugin_key)
            if bucket is None:
                bucket = deque(maxlen=per_parser_budget)
                parser_buckets[plugin_key] = bucket
            bucket.append(event)

    if malformed > 5:
        logger.warning(
            "Plaso JSONL had %d additional malformed lines (suppressed)",
            malformed - 5,
        )

    # W-060 instrumentation — capture deque fills BEFORE the drain pass
    # mutates bucket_iters so the sizes reflect the stage where the
    # sampler is about to hand events to the agent.
    if counters is not None:
        counters["jsonl_rows_read"] = rows_read
        counters["priority_hits_by_family"] = dict(priority_hits)
        counters["parser_deque_sizes"] = {k: len(b) for k, b in parser_buckets.items()}

    # Assembly — priority first (per-family sub-deques), then per-parser
    # round-robin (newest-first).  The dedup key carries ``datetime`` so
    # priority and parser-bucket copies of the SAME event collapse, while
    # distinct events with an identical message do not.
    output: list[TimelineEvent] = []
    seen: set[tuple[str, str, str]] = set()

    def _maybe_add(event: TimelineEvent) -> bool:
        if len(output) >= max_events:
            return False
        # W-A08: include EID in dedup key so all Event IDs are represented,
        # not just the first message seen for each parser. Use FULL message
        # (not truncated) to preserve event distinguishability — truncating
        # to msg[:80] caused recall regression (273 -> 199 findings).
        eid = _extract_eid(event.message)
        key = (event.datetime, event.parser, eid, event.message)
        if key in seen:
            return False
        seen.add(key)
        output.append(event)
        return True

    for pbucket in priority_buckets.values():
        for event in pbucket:
            if not _maybe_add(event) and len(output) >= max_events:
                return output

    # Round-robin: iterate each parser-bucket newest-first (the tail of the
    # deque is the latest event, which on an ascending-datetime stream is
    # attack-era on a multi-year image).  Stop when all buckets are drained
    # or max_events is hit.
    bucket_iters = {k: iter(list(reversed(b))) for k, b in parser_buckets.items()}
    while bucket_iters and len(output) < max_events:
        exhausted: list[str] = []
        for plugin_key, it in bucket_iters.items():
            try:
                event = next(it)
            except StopIteration:
                exhausted.append(plugin_key)
                continue
            _maybe_add(event)
            if len(output) >= max_events:
                break
        for plugin_key in exhausted:
            bucket_iters.pop(plugin_key, None)

    return output


# --- SIFT-W-282: mount-based fallback for tail-truncated EWF ---------------
#
# dfvfs's SourceScanner unconditionally opens a VShadow volume system
# before honouring any --vss flag.  On a tail-truncated EWF (e.g.
# rocba-cdrive.e01) libvshadow reads past the missing tail and aborts the
# whole scan, so log2timeline.py never writes a storage file.  Padding /
# synthesising the NTFS backup boot sector does NOT help — libvshadow keeps
# parsing beyond the OEM ID.
#
# The fallback (gated by AGENTROPIX_PLASO_TAIL_PAD=1) sidesteps the
# volume-system scan entirely: expose the EWF as a raw surface with
# ewfmount, loop-mount the NTFS volume read-only with a sizelimit clamped
# to the EWF media size (so the kernel loop device stops at the last valid
# byte and dfvfs never reaches the truncated tail), then point
# log2timeline.py at the MOUNTED DIRECTORY instead of the raw image.
#
# Trade-off: pointing log2timeline at a directory makes dfvfs treat it as
# an OS file source, so it runs no volume/partition scan — file-carving
# and unallocated-space parsers do NOT run.  For file-resident artefacts
# (winevtx / amcache / mft) the parser output is identical to a raw-image
# scan, which is the recall surface this fallback exists to protect.

_MOUNT_OP_TIMEOUT_S = 120


def _tail_pad_fallback_enabled() -> bool:
    """SIFT-W-282: gate the ewfmount + loop-mount fallback on
    ``AGENTROPIX_PLASO_TAIL_PAD`` (accepts ``1``/``true``/``yes``)."""
    return os.environ.get("AGENTROPIX_PLASO_TAIL_PAD", "").strip().lower() in ("1", "true", "yes")


_DM_NAME_PREFIX = "agentropix-w282-"


async def _run_priv(argv: list[str], *, stdin: str | None = None) -> tuple[int, str, str]:
    """SIFT-W-282: run a privileged mount/device command via ``sudo -n``.

    losetup / dmsetup are not SUID (unlike mount), so the whole tail-pad
    chain goes through passwordless sudo. Returns (rc, stdout, stderr) as
    decoded strings. ``stdin`` (the dmsetup table) is piped when provided.
    """
    sudo = shutil.which("sudo") or "sudo"
    proc = await asyncio.create_subprocess_exec(
        sudo,
        "-n",
        *argv,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out_bytes, err_bytes = await asyncio.wait_for(
        proc.communicate(input=stdin.encode() if stdin is not None else None),
        timeout=_MOUNT_OP_TIMEOUT_S,
    )
    return (
        proc.returncode or 0,
        out_bytes.decode(errors="replace"),
        err_bytes.decode(errors="replace"),
    )


async def _ewfmount_to_dir(ewf_path: Path, tmpdir: Path) -> Path:
    """SIFT-W-282: expose ``ewf_path`` as a raw surface via ewfmount.

    Runs ``ewfmount -X allow_root <ewf_path> <tmpdir>/ewf`` and returns the
    path to the exposed raw file ``<tmpdir>/ewf/ewf1``.  ``-X allow_root`` is
    REQUIRED: the downstream losetup/mount run as root (sudo) and a default
    FUSE mount is owner-only, so without it root gets EACCES on ``ewf1``
    (needs ``user_allow_other`` in ``/etc/fuse.conf``).  Raises
    ``RuntimeError`` on non-zero exit so the caller never proceeds against a
    surface that was never created.
    """
    ewf_dir = tmpdir / "ewf"
    ewf_dir.mkdir(parents=True, exist_ok=True)
    ewfmount = shutil.which("ewfmount") or "ewfmount"
    argv = [ewfmount, "-X", "allow_root", str(ewf_path), str(ewf_dir)]
    logger.info("SIFT-W-282 ewfmount: %s", " ".join(argv))
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=_MOUNT_OP_TIMEOUT_S)
    if proc.returncode != 0:
        err = stderr_bytes.decode(errors="replace").strip()
        raise RuntimeError(f"ewfmount failed (rc={proc.returncode}): {err[:300] or '<no stderr>'}")
    return ewf_dir / "ewf1"


def _read_ntfs_total_sectors(raw_path: Path) -> tuple[int, int]:
    """SIFT-W-282: read the NTFS $Boot at offset 0 of ``raw_path``.

    Returns ``(total_sectors, bytes_per_sector)``.  ``total_sectors`` is the
    $Boot TotalSectors field (0x28, 8 bytes LE); the volume spans that many
    sectors and ntfs-3g insists on reading the backup boot sector at the last
    index, so a tail-truncated EWF whose media size is short of
    ``total_sectors * bps`` cannot satisfy that read without padding.
    Raises ``RuntimeError`` when the OEM ID is not ``NTFS``.
    """
    with open(raw_path, "rb") as fh:
        boot = fh.read(512)
    if boot[3:11] != b"NTFS    ":
        raise RuntimeError(f"not an NTFS volume (OEM ID {boot[3:11]!r} != b'NTFS    ')")
    bps = int.from_bytes(boot[11:13], "little") or 512
    total_sectors = int.from_bytes(boot[0x28:0x30], "little")
    return total_sectors, bps


async def _loop_mount_ntfs_ro(raw_path: Path, tmpdir: Path) -> tuple[Path, str, str]:
    """SIFT-W-282: read-only NTFS mount of a possibly tail-truncated surface.

    ewfmount exposes only the bytes that exist in the EWF.  On a tail-
    truncated acquisition that is SHORT of the NTFS $Boot-claimed volume size,
    so a plain ``mount -o loop`` aborts with ``Failed to read last sector``
    (ntfs-3g must read the backup boot sector that lives in the missing tail).
    Clamping the loop ``sizelimit`` DOWN cannot fix this — the tail must be
    zero-padded UP to the claimed size.

    Build a device exactly the NTFS-claimed size by concatenating the real
    read-only loop device with a device-mapper ``zero`` target for the missing
    tail sectors, then ntfs-3g mount that.  The zero tail satisfies ntfs-3g's
    backup-boot read without touching evidence (read-only loop + zero target).

    Returns ``(ntfs_dir, dm_name, loop_dev)`` so the caller tears down in
    order: umount -> dmsetup remove -> losetup -d -> fusermount -u.
    """
    total_sectors, bps = _read_ntfs_total_sectors(raw_path)
    avail_sectors = raw_path.stat().st_size // bps
    pad_sectors = max(0, total_sectors - avail_sectors)

    rc, out, err = await _run_priv(["losetup", "--find", "--show", "--read-only", str(raw_path)])
    if rc != 0 or not out.strip():
        raise RuntimeError(f"losetup failed (rc={rc}): {err[:300] or '<no stderr>'}")
    loop_dev = out.strip()

    dm_name = f"{_DM_NAME_PREFIX}{uuid.uuid4().hex[:12]}"
    try:
        if pad_sectors > 0:
            table = f"0 {avail_sectors} linear {loop_dev} 0\n{avail_sectors} {pad_sectors} zero\n"
            logger.info(
                "SIFT-W-282 dm zero-pad: %d real + %d zero sectors "
                "(NTFS $Boot claims %d; EWF media is short by %d sectors)",
                avail_sectors,
                pad_sectors,
                total_sectors,
                pad_sectors,
            )
        else:
            table = f"0 {avail_sectors} linear {loop_dev} 0\n"
            logger.info("SIFT-W-282 dm linear (no tail truncation): %d sectors", avail_sectors)

        rc, out, err = await _run_priv(["dmsetup", "create", dm_name], stdin=table)
        if rc != 0:
            raise RuntimeError(f"dmsetup create failed (rc={rc}): {err[:300] or '<no stderr>'}")

        ntfs_dir = tmpdir / "ntfs"
        ntfs_dir.mkdir(parents=True, exist_ok=True)
        dm_dev = f"/dev/mapper/{dm_name}"
        rc, out, err = await _run_priv(
            ["mount", "-t", "ntfs-3g", "-o", "ro", dm_dev, str(ntfs_dir)]
        )
        if rc != 0:
            raise RuntimeError(f"ntfs-3g mount failed (rc={rc}): {err[:300] or '<no stderr>'}")
        return ntfs_dir, dm_name, loop_dev
    except Exception:
        # Unwind partial setup so the error path never leaks a dm device or
        # loop device (the FUSE surface is torn down by the get_timeline finally).
        await _run_priv(["dmsetup", "remove", dm_name])
        await _run_priv(["losetup", "-d", loop_dev])
        raise


async def _dm_remove_quiet(dm_name: str) -> bool:
    """SIFT-W-282: best-effort ``dmsetup remove <dm_name>``; never raises."""
    rc, _out, err = await _run_priv(["dmsetup", "remove", dm_name])
    if rc != 0:
        logger.error(
            "SIFT-W-282 dmsetup remove %s rc=%d (device left LIVE): %s", dm_name, rc, err[:200]
        )
        return False
    return True


async def _losetup_detach_quiet(loop_dev: str) -> bool:
    """SIFT-W-282: best-effort ``losetup -d <loop_dev>``; never raises."""
    rc, _out, err = await _run_priv(["losetup", "-d", loop_dev])
    if rc != 0:
        logger.error("SIFT-W-282 losetup -d %s rc=%d (loop left LIVE): %s", loop_dev, rc, err[:200])
        return False
    return True


async def _umount_quiet(mount_dir: Path) -> bool:
    """SIFT-W-282: best-effort ``umount <mount_dir>``; never raises.

    Cleanup helper for the tail-pad finally-block — a failed unmount logs an
    ERROR (the mount is left LIVE, which the caller must surface before
    ``rmtree`` so the operator can reclaim the loop device) but must not mask
    the wrapper's primary exception. Returns ``True`` only on a confirmed
    clean unmount. Goes through ``sudo`` because the mount was created as root.
    """
    try:
        rc, _out, err = await _run_priv(["umount", str(mount_dir)])
        if rc != 0:
            logger.error(
                "SIFT-W-282 umount %s rc=%d (mount left LIVE): %s",
                mount_dir,
                rc,
                err[:200],
            )
            return False
        return True
    except (OSError, TimeoutError) as exc:
        logger.error("SIFT-W-282 umount %s failed (mount left LIVE): %s", mount_dir, exc)
        return False


async def _fusermount_unmount_quiet(ewf_dir: Path) -> bool:
    """SIFT-W-282: best-effort ``fusermount -u <ewf_dir>``; never raises.

    Returns ``True`` only on a confirmed clean unmount; a failure logs an
    ERROR (the FUSE surface is left LIVE) so the caller can warn before
    removing the mountpoint.
    """
    fusermount_bin = shutil.which("fusermount") or "fusermount"
    try:
        proc = await asyncio.create_subprocess_exec(
            fusermount_bin,
            "-u",
            str(ewf_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=_MOUNT_OP_TIMEOUT_S)
        if proc.returncode != 0:
            logger.error(
                "SIFT-W-282 fusermount -u %s rc=%d (FUSE surface left LIVE): %s",
                ewf_dir,
                proc.returncode,
                stderr_bytes.decode(errors="replace")[:200],
            )
            return False
        return True
    except (OSError, TimeoutError) as exc:
        logger.error(
            "SIFT-W-282 fusermount -u %s failed (FUSE surface left LIVE): %s", ewf_dir, exc
        )
        return False


async def get_timeline(
    image: str | Path,
    *,
    parsers: str | None = None,
    partitions: str = "all",
    timeout: float | None = None,
    max_events: int | None = None,
) -> TimelineEvents:
    """Run log2timeline.py to generate a super timeline from a disk image.

    Args:
        image: Path to disk image file.
        parsers: Plaso parser filter expression (e.g., "winreg,prefetch").
        partitions: Partition selection ("all" by default).
        timeout: Max seconds to wait (auto-scaled by image size if None).
        max_events: Max events to return (context-window protection).

    Returns:
        TimelineEvents with parsed event data.

    Raises:
        FileNotFoundError: If image or log2timeline.py not found.
        TimeoutError: If plaso exceeds timeout.
        RuntimeError: If plaso returns non-zero exit code.
    """
    image = Path(image)
    if not image.exists():
        raise FileNotFoundError(f"Disk image not found: {image}")

    if max_events is None:
        max_events = get_int("AGENTROPIX_PLASO_MAX_EVENTS", 500, floor=1, ceiling=100000)

    # Check disk space before running plaso (needs ~2x image size for processing)
    stat = shutil.disk_usage("/tmp/")  # plaso uses /tmp for storage
    min_free_mb = int(os.environ.get("AGENTROPIX_MIN_DISK_MB", "500"))
    free_mb = stat.free // (1024 * 1024)
    if free_mb < min_free_mb:
        raise RuntimeError(
            f"Insufficient disk space: {free_mb} MB free, need {min_free_mb} MB minimum"
        )

    # Resolve timeout: explicit kwarg > env var > auto-scale formula
    if timeout is None:
        env_timeout = os.environ.get("AGENTROPIX_PLASO_TIMEOUT")
        if env_timeout:
            try:
                timeout = max(30, float(env_timeout))
                logger.info("Using AGENTROPIX_PLASO_TIMEOUT=%s", timeout)
            except ValueError:
                logger.warning(
                    "Invalid AGENTROPIX_PLASO_TIMEOUT=%r, falling back to auto-scale", env_timeout
                )
                env_timeout = None
        if env_timeout is None:
            timeout_cap = get_int("AGENTROPIX_PLASO_TIMEOUT_CAP", 7200, floor=30, ceiling=7200)
            size_gb = image.stat().st_size / (1024**3)
            # W-NEW-1 final (2026-05-12): retune — 475 s/GB slope, 1800 s floor,
            # default cap 7200.  Bumped from 450 to 475 s/GB so the 11.5 GB DC
            # E01 budget (11.5*475 = 5462 s) exceeds the proven cron override
            # AGENTROPIX_PLASO_TIMEOUT=5400; this lets the override be removed.
            # Slope/cap history: 180→300→450→475 s/GB (W-049 → W-104 → W-128 →
            # W-NEW-1-final); cap 600→3600→5400→7200 (W-049 → W-104 → W-128 →
            # W-NEW-1 PR #89).
            timeout = min(timeout_cap, max(1800, int(size_gb * 475)))
            logger.info("Auto-scaled plaso timeout to %ss for %.1f GB image", timeout, size_gb)

    if parsers is None and os.environ.get("AGENTROPIX_PLASO_PARSERS"):
        env_parsers = get_str_set("AGENTROPIX_PLASO_PARSERS", {"winevtx", "mft"})
        parsers = ",".join(sorted(env_parsers))

    l2t_path = shutil.which("log2timeline.py")
    if not l2t_path:
        raise FileNotFoundError("log2timeline.py not found on PATH — install plaso")

    psort_path = shutil.which("psort.py")

    tmpdir_path = Path(tempfile.mkdtemp(prefix="agentropix-sift-"))
    # SIFT-W-282: tracked across the try/finally so cleanup can unmount even
    # when log2timeline raises mid-scan.  None until the tail-pad fallback
    # actually mounts something, so the finally is a no-op on the normal path.
    ntfs_dir_to_unmount: Path | None = None
    ewf_dir_to_unmount: Path | None = None
    dm_name_to_remove: str | None = None
    loop_dev_to_detach: str | None = None
    try:
        storage_file = tmpdir_path / "timeline.plaso"
        output_file = tmpdir_path / "timeline.jsonl"

        # W-131: cap worker count so aggregate RSS is bounded.  Plaso's
        # default cpu_count-1 produced 16 forks holding 41 GiB on the
        # 2026-04-30 DC triage and OOM-killed the MCP host.  Resolved
        # value goes both onto the command line AND into the log so
        # operators can verify the cap fired without re-deriving it.
        workers = _resolve_plaso_workers()

        # SIFT-W-282: on a tail-truncated EWF, scan a mounted NTFS directory
        # instead of the raw image so dfvfs never opens the VShadow volume
        # system (which reads past the truncated tail and aborts the run).
        l2t_target: Path = image
        if _tail_pad_fallback_enabled():
            raw_surface = await _ewfmount_to_dir(image, tmpdir_path)
            ewf_dir_to_unmount = raw_surface.parent
            ntfs_dir, dm_name, loop_dev = await _loop_mount_ntfs_ro(raw_surface, tmpdir_path)
            ntfs_dir_to_unmount = ntfs_dir
            dm_name_to_remove = dm_name
            loop_dev_to_detach = loop_dev
            l2t_target = ntfs_dir
            logger.info(
                "SIFT-W-282 tail-pad fallback active: scanning mounted NTFS %s"
                " (file-level scan; carving / unallocated parsers will not run)",
                ntfs_dir,
            )

        l2t_cmd = [
            l2t_path,
            "--workers",
            str(workers),
            "--storage_file",
            str(storage_file),
            "--partitions",
            partitions,
            "--vss_stores=1",  # W-053-final: VSS=1 avoids interactive prompt + gets event logs (4624 for T1078 logon detection)
            "--status_view",
            "none",
        ]
        if parsers:
            l2t_cmd.extend(["--parsers", parsers])
        l2t_cmd.append(str(l2t_target))

        logger.info("Running log2timeline (workers=%d): %s", workers, " ".join(l2t_cmd))
        proc = await asyncio.create_subprocess_exec(
            *l2t_cmd,
            stdin=asyncio.subprocess.DEVNULL,  # suppress interactive VSS/partition prompts
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # own process group so we can kill all children
        )

        # W-132: guarantee the process group is reaped on EVERY abnormal
        # exit path (TimeoutError, MemoryError, CancelledError, generic
        # Exception). The inner except clauses still log their own
        # cause-specific WARNING; the outer finally is idempotent
        # belt-and-braces — _reap_proc_group is a no-op once the proc
        # has exited normally.
        try:
            try:
                _, stderr_bytes = await run_with_memory_limit(
                    proc, timeout, "log2timeline", image_path=image
                )
            except TimeoutError:
                _reap_proc_group(proc)
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except TimeoutError:
                    pass
                # W-049: emit WARNING (not INFO) so operators see WRAPPER_TIMEOUT
                logger.warning(
                    "WRAPPER_TIMEOUT: log2timeline timed out after %.0fs for image=%s"
                    " — increase AGENTROPIX_PLASO_TIMEOUT or AGENTROPIX_PLASO_TIMEOUT_CAP",
                    timeout,
                    image,
                )
                raise
            except MemoryError:
                # W-131/W-132: when the memory monitor trips we MUST kill
                # the whole process group, not just the parent — Plaso
                # workers each hold 1-3 GiB and would otherwise survive
                # as orphans parented to systemd-user (the 96-PID, 41 GiB
                # leak observed on 2026-04-30 DC triage).
                _reap_proc_group(proc)
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                logger.warning(
                    "WRAPPER_OOM: log2timeline killed by memory monitor for image=%s"
                    " — lower AGENTROPIX_PLASO_WORKERS or raise AGENTROPIX_MEM_LIMIT_MB",
                    image,
                )
                raise
        finally:
            # W-132 belt-and-braces: catch any exit path that didn't
            # already reap (e.g. asyncio.CancelledError when uvicorn is
            # tearing the task down, or an unexpected exception inside
            # run_with_memory_limit itself).
            _reap_proc_group(proc)

        stderr = stderr_bytes.decode(errors="replace")

        if proc.returncode != 0:
            raise RuntimeError(f"log2timeline failed (rc={proc.returncode}): {stderr[:500]}")

        # Phase 2: psort → JSON lines (if psort available)
        # M6.5 W-061: if json_line export fails (e.g. rc=1 from
        # ``TypeError: Object of type bytes is not JSON serializable`` in
        # plaso's ``_ExportEvents`` on Windows EVTX/registry events), fall
        # back to l2tcsv format which avoids JSON serialization entirely.
        # ``parse_path`` + ``parse_as`` are set by whichever branch wrote
        # a usable output file, and the shared assembly block below parses
        # and returns a single ``TimelineEvents`` regardless of route.
        parse_path = output_file
        parse_as = "jsonl"
        psort_stdout_bytes: bytes = b""  # W-082: captured below if psort runs
        if psort_path and storage_file.exists():
            # M6.3: psort 20260119 on this host uses a POSITIONAL path argument,
            # not ``--storage_file``.  A prior comment in this file claimed
            # ``--storage_file`` was the v20260119+ form, but ``psort.py --help``
            # on the installed build shows ``PATH`` as positional and the flag
            # form errors with ``unrecognized arguments``.  The silent rc=2
            # exit explains M6.1/M6.2/M6.3 seeing 0 timeline.plaso findings on
            # every live DC E01 run — log2timeline produced the storage file
            # but psort never wrote the JSONL, so ``_parse_jsonl_events`` saw
            # an empty window regardless of its sampling strategy.
            # M6.5: ``-u`` (unattended) suppresses any residual interactive
            # prompts from plaso plugins.
            psort_cmd = [
                psort_path,
                "-u",
                "-o",
                "json_line",
                "-w",
                str(output_file),
                str(storage_file),
            ]

            # W-060: psort gets its OWN budget (previously shared ``timeout``
            # with log2timeline, which meant a slow l2t phase silently starved
            # psort on real DC E01 images — wrapper hit
            # ``WRAPPER_TIMEOUT: psort timed out after 1800.0s`` even when the
            # caller raised ``AGENTROPIX_PLASO_TIMEOUT_CAP`` because the
            # sharing was per-stage, not a pool).
            psort_timeout = get_float(
                "AGENTROPIX_PSORT_TIMEOUT", 5400.0, floor=30.0, ceiling=7200.0
            )
            logger.info(
                "Running psort (AGENTROPIX_PSORT_TIMEOUT=%ss): %s",
                psort_timeout,
                " ".join(psort_cmd),
            )
            proc2 = await asyncio.create_subprocess_exec(
                *psort_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,  # own process group so we can kill all children
            )
            # W-132: psort doesn't fork as aggressively as log2timeline,
            # but a hung psort still holds the storage_file lock and can
            # orphan its own pgid on abnormal exit. The finally-block is
            # belt-and-braces — _reap_proc_group is a no-op once proc2
            # has exited normally.
            try:
                try:
                    psort_stdout_bytes, psort_stderr = await run_with_memory_limit(
                        proc2, psort_timeout, "psort"
                    )
                except TimeoutError:
                    _reap_proc_group(proc2)
                    with contextlib.suppress(asyncio.TimeoutError):
                        await asyncio.wait_for(proc2.wait(), timeout=5.0)
                    logger.warning(
                        "WRAPPER_TIMEOUT: psort timed out after %.0fs for image=%s — increase AGENTROPIX_PSORT_TIMEOUT",
                        psort_timeout,
                        image,
                    )
                    # W-060 persistence: do NOT raise — return a soft-failure
                    # TimelineEvents with zero-filled counters and the
                    # ``wrapper_error`` tag set.  The @traced layer and the
                    # TimelineAgent both see a normal return, so the counters
                    # pipeline is exercised even on timeout and whatever
                    # signal log2timeline collected reaches ``trace.counters``
                    # in report.json instead of being eaten by the exception.
                    soft_counters: dict = {}
                    # Populate the stable counter shape (rows_read=0,
                    # priority_hits={...}=0, parser_deque_sizes={}) without
                    # touching the filesystem — _parse_jsonl_events on a
                    # non-existent path zero-fills for free.
                    _parse_jsonl_events(output_file, max_events=max_events, counters=soft_counters)
                    return TimelineEvents(
                        image_path=str(image),
                        event_count=0,
                        events=[],
                        storage_file=str(storage_file),
                        raw_stderr=stderr[:1000] if stderr else "",
                        jsonl_rows_read=int(soft_counters.get("jsonl_rows_read", 0)),
                        priority_hits_by_family=dict(
                            soft_counters.get("priority_hits_by_family", {})
                        ),
                        parser_deque_sizes=dict(soft_counters.get("parser_deque_sizes", {})),
                        wrapper_error=f"psort_timeout:{psort_timeout:.0f}s",
                        raw_stdout_sha256=hashlib.sha256(b"").hexdigest(),
                    )
                except MemoryError:
                    # W-131/W-132: same kill-process-group treatment as
                    # the log2timeline branch — psort can also hold
                    # parser-loaded RSS so we must not orphan it.
                    _reap_proc_group(proc2)
                    with contextlib.suppress(asyncio.TimeoutError):
                        await asyncio.wait_for(proc2.wait(), timeout=5.0)
                    logger.warning(
                        "WRAPPER_OOM: psort killed by memory monitor for image=%s",
                        image,
                    )
                    raise
            finally:
                _reap_proc_group(proc2)

            if proc2.returncode != 0:
                # M6.5 W-061: json_line rc!=0 on Windows EVTX/registry events
                # is almost always ``TypeError: Object of type bytes is not
                # JSON serializable`` raised inside plaso's ``_ExportEvents``.
                # Retry with ``l2tcsv`` (CSV) which bypasses JSON entirely.
                psort_stderr_str = psort_stderr.decode(errors="replace")
                logger.warning(
                    "psort json_line failed (rc=%d) — falling back to l2tcsv format",
                    proc2.returncode,
                )
                logger.debug("psort json_line stderr: %s", psort_stderr_str[:5000])

                # W-062 (M6.6): when json_line crashes mid-stream on a real
                # 12 GB DC E01, the partial ``timeline.jsonl`` can be tens of
                # gigabytes. l2tcsv then writes its own multi-GB output to a
                # sibling file, and the combined footprint hits
                # ``OSError: [Errno 28] No space left on device`` inside
                # plaso/output/text_file.py:WriteText. Unlinking the partial
                # JSONL before the retry frees that space so l2tcsv has room
                # to write a complete CSV.
                try:
                    output_file.unlink()
                    logger.info(
                        "Removed partial json_line output before l2tcsv retry: %s",
                        output_file,
                    )
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    logger.warning(
                        "Could not remove partial json_line output %s: %s",
                        output_file,
                        exc,
                    )

                l2tcsv_file = output_file.with_suffix(".l2tcsv")
                psort_csv_cmd = [
                    psort_path,
                    "-u",
                    "-o",
                    "l2tcsv",
                    "-w",
                    str(l2tcsv_file),
                    str(storage_file),
                ]
                logger.info(
                    "Running psort l2tcsv fallback: %s",
                    " ".join(psort_csv_cmd),
                )
                proc3 = await asyncio.create_subprocess_exec(
                    *psort_csv_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,
                )
                # W-132: kill-on-cleanup parity with the log2timeline +
                # psort blocks above.
                try:
                    try:
                        _, psort_csv_stderr = await run_with_memory_limit(
                            proc3, psort_timeout, "psort_l2tcsv"
                        )
                    except TimeoutError as err:
                        _reap_proc_group(proc3)
                        with contextlib.suppress(asyncio.TimeoutError):
                            await asyncio.wait_for(proc3.wait(), timeout=5.0)
                        raise RuntimeError(
                            f"psort l2tcsv fallback timed out after {psort_timeout:.0f}s"
                        ) from err
                    except MemoryError:
                        _reap_proc_group(proc3)
                        with contextlib.suppress(asyncio.TimeoutError):
                            await asyncio.wait_for(proc3.wait(), timeout=5.0)
                        logger.warning(
                            "WRAPPER_OOM: psort_l2tcsv killed by memory monitor for image=%s",
                            image,
                        )
                        raise
                finally:
                    _reap_proc_group(proc3)

                if proc3.returncode != 0:
                    psort_csv_stderr_str = psort_csv_stderr.decode(errors="replace")
                    raise RuntimeError(
                        f"psort failed (rc={proc2.returncode}) AND l2tcsv"
                        f" fallback failed (rc={proc3.returncode}):"
                        f" {psort_csv_stderr_str[:5000]}"
                    )

                # l2tcsv succeeded — switch assembly path to CSV parser.
                parse_path = l2tcsv_file
                parse_as = "l2tcsv"

        # W-060: capture sampler dataflow counters so H1/H2/H3 (see
        # ``docs/adr/ADR-M6.3-residual-gap.md``) become observable at the
        # wrapper→agent boundary without extra log scraping.
        sampler_counters: dict = {}
        if parse_as == "l2tcsv":
            events = _parse_l2tcsv_events(
                parse_path, max_events=max_events, counters=sampler_counters
            )
        else:
            events = _parse_jsonl_events(
                parse_path, max_events=max_events, counters=sampler_counters
            )

        return TimelineEvents(
            image_path=str(image),
            event_count=len(events),
            events=events,
            storage_file=str(storage_file),
            raw_stderr=stderr[:1000] if stderr else "",
            jsonl_rows_read=int(sampler_counters.get("jsonl_rows_read", 0)),
            priority_hits_by_family=dict(sampler_counters.get("priority_hits_by_family", {})),
            parser_deque_sizes=dict(sampler_counters.get("parser_deque_sizes", {})),
            raw_stdout_sha256=hashlib.sha256(psort_stdout_bytes).hexdigest(),
        )
    finally:
        # SIFT-W-282: tear the tail-pad stack down in strict reverse order —
        # umount the NTFS mount, remove the dm zero-pad device, detach the
        # read-only loop, then fusermount -u the FUSE surface.  Each layer
        # holds the one below it open, so order matters.  All four are best-
        # effort and run on EVERY exit path (including a log2timeline failure
        # mid-scan) so a stuck layer never masks the wrapper's primary
        # exception and never silently leaks a device.
        mounts_clean = True
        if ntfs_dir_to_unmount is not None:
            mounts_clean = await _umount_quiet(ntfs_dir_to_unmount) and mounts_clean
        if dm_name_to_remove is not None:
            mounts_clean = await _dm_remove_quiet(dm_name_to_remove) and mounts_clean
        if loop_dev_to_detach is not None:
            mounts_clean = await _losetup_detach_quiet(loop_dev_to_detach) and mounts_clean
        if ewf_dir_to_unmount is not None:
            mounts_clean = await _fusermount_unmount_quiet(ewf_dir_to_unmount) and mounts_clean
        # SIFT-W-282: rmtree on a still-mounted dir removes the mountpoint
        # entry but orphans the live loop/FUSE/dm stack (no path-based
        # recovery). Skip the rmtree in that case and tell the operator how to
        # reclaim it.
        if not mounts_clean:
            logger.error(
                "SIFT-W-282 leaving tmpdir %s in place — a device layer is still LIVE; "
                "reclaim with: sudo umount -l %s ; sudo dmsetup remove %s ; "
                "sudo losetup -d %s ; fusermount -u %s ; rm -rf %s",
                tmpdir_path,
                ntfs_dir_to_unmount,
                dm_name_to_remove,
                loop_dev_to_detach,
                ewf_dir_to_unmount,
                tmpdir_path,
            )
        else:
            # Force-remove tmpdir even if worker subprocesses left files behind (W-022)
            shutil.rmtree(tmpdir_path, ignore_errors=True)
