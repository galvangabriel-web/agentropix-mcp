"""Windows Event Log (``.evtx``) parser wrapper.

Dual-format aware. Parses output from either:

- ``evtx_dump.py`` — the python-evtx CLI shipped with SANS SIFT, which
  emits a multi-record XML stream (``<Events>`` wrapping per-record
  ``<Event>`` blocks, each with its own ``<?xml?>`` preamble because
  python-evtx's ``record.xml()`` adds one per record).
- ``evtx_dump`` — the omerbenamram/evtx Rust binary, which emits the
  same XML shape by default and supports ``-o jsonl`` for JSONL.

Output format is auto-detected from the first non-blank byte: ``<``
routes to the XML parser, ``{`` routes to the JSONL parser. This
keeps the wrapper working regardless of which binary the operator
points ``AGENTROPIX_EVTX_TOOL`` at, without adding a format flag.

The wrapper converts the tool output into a flat ``list[EvtxEvent]``
with the fields a DFIR analyst cares about (event id, channel,
provider, timestamp, computer, record id, level). The full per-record
XML (or serialised JSON) is preserved on ``raw`` (first 2000 chars)
so downstream agents can re-parse specific payloads (e.g. logon type,
target username, process command line) without another subprocess
round-trip.

Filtering is caller-driven:

- ``channels``: only keep events whose ``Channel`` matches one of the
  provided names (case-insensitive).
- ``event_ids``: only keep events whose ``EventID`` is in the set.
- ``record_id_min`` / ``record_id_max``: scope to a record-id window
  (inclusive); useful for re-running against a known attack window
  without re-parsing the whole file (W-137).
- ``max_events``: hard cap on the result size (default via
  ``AGENTROPIX_EVTX_MAX_EVENTS``, floor 1, ceiling 100000; W-137
  raised the default from 1000 to 5000).
- ``tail``: when True (default, W-137), return the LAST ``max_events``
  records the parser sees instead of the first. evtx_dump emits
  records oldest-first, so default-False truncation surfaces
  pre-attack baseline traffic on multi-million-record Security logs;
  default-True surfaces the recent attack window. Set ``tail=False``
  to restore pre-W-137 oldest-first semantics.

Chaining raw E01 → extracted ``.evtx`` → ``mcp_get_evtx`` is driven
by ``mcp_extract_files`` (W-028, ADR-012).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
from collections import deque
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from pydantic import BaseModel, Field

from agentropix_mcp._env import clamp_float, get_float, get_int

logger = logging.getLogger(__name__)

DEFAULT_TOOL_NAME = "evtx_dump.py"
# W-136 §3 row 1: when the Rust binary is on PATH, prefer it over the
# Python parser even without an explicit AGENTROPIX_EVTX_TOOL override.
# Avoids the W-133-class env-var-not-inherited failure where a fresh
# subprocess used the Python parser despite scripts/start-mcp.sh setting
# the override. The env var still wins when set explicitly.
_RUST_TOOL_NAME = "evtx_dump"
# W-136 §3 row 2: above this size, force the Rust binary's JSONL output
# and skip the XML regex path in ``_parse_xml`` (which scans a multi-GB
# stdout with finditer over a regex). Tunable via AGENTROPIX_EVTX_FORCE_JSONL_BYTES.
_DEFAULT_FORCE_JSONL_BYTES = 50 * 1024 * 1024


# W-133: when fed an E01 image (instead of an already-extracted .evtx)
# the wrapper enumerates ``Windows/System32/winevt/Logs`` via TSK and
# extracts a default channel set unless the caller specifies one. The
# default mirrors the SANS DC-track triage priority: authn / system /
# application / PowerShell-script / scheduled-task / Sysmon. Channels
# are MCP-style names (``Microsoft-Windows-PowerShell/Operational``);
# the on-disk file uses ``%4`` to encode ``/``.
_DEFAULT_E01_CHANNELS: tuple[str, ...] = (
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-Sysmon/Operational",
)
# W-133: in-container path the Logs/ directory always lives at on
# Windows Server 2008+ (and consistent across the SRL-2018 / SRL-2015
# fixtures that drive the live-data tests).
_WINEVT_LOGS_PREFIX = "Windows/System32/winevt/Logs"
# W-139: legacy .evt log paths used by Windows XP / 2003 / 2000. The
# wrapper probes these only when the modern winevt/Logs path returns
# nothing — the surface area is small (3 files) so the probe is cheap.
# Both casing variants are checked because case-sensitive image
# filesystems (TSK on FAT/NTFS without short-name preservation) may
# expose either form.
_LEGACY_EVT_PATHS: tuple[str, ...] = (
    "Windows/System32/config/SecEvent.Evt",
    "Windows/System32/config/SysEvent.Evt",
    "Windows/System32/config/AppEvent.Evt",
    "WINDOWS/system32/config/SecEvent.Evt",
    "WINDOWS/system32/config/SysEvent.Evt",
    "WINDOWS/system32/config/AppEvent.Evt",
)
# E01/EWF magic ("EVF") — first 3 bytes of the segment-1 header. We
# also accept any of the standard EWF suffix variants (.E01, .Ex01,
# .e01, ...) as a positive sniff so callers that hand us a renamed
# file still get the E01 path.
_EWF_MAGIC = b"EVF"
_E01_SUFFIXES: tuple[str, ...] = tuple(
    f".{ext}{n:02d}"
    for ext in ("E", "e", "Ex", "ex")
    for n in range(1, 100)
) + (".E01", ".e01")  # belt-and-braces


def _resolve_tool() -> str:
    """Resolve the evtx parser binary.

    W-136 §3 row 1 resolution order:
      1. Honor ``AGENTROPIX_EVTX_TOOL`` when set (operator override wins).
      2. Else, prefer Rust ``evtx_dump`` if on PATH (~30× faster).
      3. Else, fall back to ``evtx_dump.py`` (python-evtx, SIFT default).

    Step 2 is the W-133 root-cause fix: a fresh MCP worker that did not
    inherit ``scripts/start-mcp.sh``'s exported env still picks up the
    fast binary, instead of silently using the Python parser and timing
    out on Security.evtx.
    """
    explicit = os.environ.get("AGENTROPIX_EVTX_TOOL")
    if explicit:
        return explicit
    if shutil.which(_RUST_TOOL_NAME):
        return _RUST_TOOL_NAME
    return DEFAULT_TOOL_NAME


def _is_rust_evtx_dump(tool_name: str) -> bool:
    """Return True if ``tool_name`` resolves to the Rust ``evtx_dump`` binary.

    The Rust binary supports ``-o jsonl`` and ``--threads N``; the Python
    ``evtx_dump.py`` does not. We feature-gate JSONL forcing and the
    workers cap on this distinction so an operator pinned to the Python
    parser doesn't get an unrecognised-flag failure.
    """
    return Path(tool_name).name == _RUST_TOOL_NAME


def _evtx_workers() -> int:
    """W-136 §4.2: bounded thread/concurrency cap for evtx parsing."""
    return get_int("AGENTROPIX_EVTX_WORKERS", 6, floor=1, ceiling=12)


# --------------------------------------------------------------------------- #
# W-138: per-image extraction cache
# --------------------------------------------------------------------------- #
#
# get_evtx is called repeatedly against the same E01 across channels,
# event-id filters, and time windows. Each call previously re-ran the
# full ifind+icat extraction even when the same channel was extracted
# seconds earlier. On a 245 MB Security.evtx the icat extraction is
# 3-5 s of cold I/O — once the W-136 parser hits sub-10s, icat becomes
# the dominant per-call cost.
#
# The cache is content-addressed by ``(realpath(image), mtime_ns,
# size, channel_filename)``. mtime_ns + size catch evidence-file
# overwrites (rare but legitimate during chain-of-custody rebuilds);
# realpath catches symlink redirects. Layout::
#
#   ${AGENTROPIX_EVTX_CACHE_DIR:-~/.cache/agentropix-sift/evtx}/
#       <key>/                              # 24-char sha256[:24] of realpath|mtime|size
#           Security.evtx                   # channel filename verbatim
#           Microsoft-Windows-PowerShell%4Operational.evtx
#           ...
#
# Operations are atomic via tempfile + rename. Eviction is opportunistic
# LRU on each store; bytes-over-budget cache directories shrink to
# ``AGENTROPIX_EVTX_CACHE_MAX_BYTES`` (default 10 GiB).
#
# Thymus interaction: the cache root sits under the user's HOME by
# default and is wrapper-owned, so it is NOT under any allowed-prefix.
# Reads happen via direct file ops, never via Thymus-policed paths.

_EVTX_CACHE_KEY_LEN = 24


def _evtx_cache_root() -> Path:
    """Cache root directory; created on first access.

    Honors ``AGENTROPIX_EVTX_CACHE_DIR`` for operator override, defaults
    to ``~/.cache/agentropix-sift/evtx``.
    """
    base = os.environ.get(
        "AGENTROPIX_EVTX_CACHE_DIR",
        str(Path.home() / ".cache" / "agentropix-sift" / "evtx"),
    )
    return Path(base)


def _evtx_cache_max_bytes() -> int:
    """LRU eviction ceiling. Floor 1 GiB, ceiling 200 GiB."""
    return get_int(
        "AGENTROPIX_EVTX_CACHE_MAX_BYTES",
        10 * 1024 * 1024 * 1024,  # 10 GiB
        floor=1 * 1024 * 1024 * 1024,  # 1 GiB
        ceiling=200 * 1024 * 1024 * 1024,  # 200 GiB
    )


def _evtx_cache_enabled() -> bool:
    """Allow callers (mostly tests) to disable the cache via env var."""
    return os.environ.get("AGENTROPIX_EVTX_CACHE_DISABLE", "0").lower() not in (
        "1", "true", "yes",
    )


def _evtx_cache_key(image: Path) -> str:
    """Content-addressed key from ``(realpath, mtime_ns, size)``.

    Returns empty string on stat failure — caller treats that as
    "cache disabled for this call".
    """
    try:
        st = image.stat()
        rp = str(image.resolve(strict=False))
    except OSError:
        return ""
    blob = f"{rp}|{st.st_mtime_ns}|{st.st_size}".encode()
    return hashlib.sha256(blob).hexdigest()[:_EVTX_CACHE_KEY_LEN]


def _evtx_cache_lookup(image: Path, channel_filename: str) -> Path | None:
    """Return the cached on-disk path if a fresh entry exists, else None.

    Mtime-and-size mismatches (covered by the cache key) make a stale
    file impossible to look up: we hash the current image's stat
    metadata into the key, so a changed image yields a fresh key and
    the previous cache directory is orphaned (eventually swept by
    eviction).
    """
    if not _evtx_cache_enabled():
        return None
    key = _evtx_cache_key(image)
    if not key:
        return None
    candidate = _evtx_cache_root() / key / channel_filename
    try:
        return candidate if candidate.is_file() else None
    except OSError:
        return None


def _evtx_cache_store(image: Path, channel_filename: str, source: Path) -> None:
    """Atomically copy ``source`` into the cache. Best-effort; swallows OSError.

    Touches ``source``'s mtime onto the cached copy via ``copy2`` so
    LRU bookkeeping reflects parse-time access patterns rather than
    just creation order.
    """
    if not _evtx_cache_enabled():
        return
    key = _evtx_cache_key(image)
    if not key:
        return
    cache_dir = _evtx_cache_root() / key
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        dest = cache_dir / channel_filename
        # Write to .tmp first then atomic-rename so partial writes never
        # surface as cache hits to a concurrent reader.
        tmp = cache_dir / f"{channel_filename}.tmp.{os.getpid()}"
        shutil.copy2(source, tmp)
        os.replace(tmp, dest)
    except OSError as exc:
        logger.warning(
            "evtx cache store failed for %s under %s: %s",
            channel_filename, key, exc,
        )
    else:
        # Opportunistic LRU sweep — runs on every successful store but
        # is a no-op when total bytes are under budget.
        try:
            _evtx_cache_evict_lru(_evtx_cache_max_bytes())
        except Exception:  # noqa: BLE001
            # Eviction failures must never break the parse path.
            logger.debug("evtx cache eviction sweep failed", exc_info=True)


def _evtx_cache_evict_lru(max_bytes: int) -> int:
    """Evict oldest cache files until total bytes <= max_bytes.

    Returns the number of bytes freed. ``atime`` orders the eviction;
    when atime tracking is disabled at the FS layer, mtime is used as
    a fallback (handled by the kernel). No locking — concurrent
    sweeps can race on a single file but ``unlink`` is idempotent.
    """
    root = _evtx_cache_root()
    if not root.is_dir():
        return 0
    candidates: list[tuple[float, int, Path]] = []
    total = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        # Skip in-flight ``.tmp.<pid>`` writes to avoid evicting them
        # before the rename completes.
        if ".tmp." in p.name:
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        candidates.append((st.st_atime, st.st_size, p))
        total += st.st_size
    if total <= max_bytes:
        return 0
    candidates.sort(key=lambda row: row[0])  # oldest atime first
    freed = 0
    for _, size, path in candidates:
        if total - freed <= max_bytes:
            break
        try:
            path.unlink()
            freed += size
        except OSError:
            continue
    return freed


def _force_jsonl_threshold() -> int:
    """W-136 §3 row 2: byte threshold above which we force ``-o jsonl``."""
    return get_int(
        "AGENTROPIX_EVTX_FORCE_JSONL_BYTES",
        _DEFAULT_FORCE_JSONL_BYTES,
        floor=1024 * 1024,
        ceiling=2 * 1024 * 1024 * 1024,
    )


def _is_e01_image(target: Path) -> bool:
    """W-133: return True if ``target`` looks like an E01/EWF disk image.

    Two-step sniff: filename suffix first (cheap), magic-byte read
    second (authoritative). Rejecting on suffix alone would miss
    renamed images; reading magic bytes alone would force I/O on every
    .evtx parse. Combined, the .evtx fast path stays fast (one stat
    + suffix check) while a rare renamed-E01 still routes correctly.
    """
    if target.suffix.lower() in {s.lower() for s in _E01_SUFFIXES}:
        return True
    # Suffix didn't match — sniff the magic bytes only if the file is
    # at least a kilobyte (smaller files can't be a useful image).
    try:
        if target.stat().st_size < 1024:
            return False
        with target.open("rb") as fh:
            head = fh.read(3)
        return head == _EWF_MAGIC
    except OSError:
        return False


def _channel_to_filename(channel: str) -> str:
    """W-133: convert an MCP-style channel name to its on-disk filename.

    Windows event-log channels with a path separator
    (``Microsoft-Windows-PowerShell/Operational``) are stored under
    Logs/ with the path separator encoded as ``%4``
    (``Microsoft-Windows-PowerShell%4Operational.evtx``). Channels
    without ``/`` (Security, System, Application) map verbatim. The
    ``%4`` encoding is Windows' own — it predates URL percent-encoding
    and uses a single-digit code, not the URL-style ``%2F``.
    """
    return channel.replace("/", "%4") + ".evtx"


def _filename_to_channel(filename: str) -> str:
    """Inverse of ``_channel_to_filename`` (drops ``.evtx`` suffix and
    decodes ``%4`` back to ``/``)."""
    base = filename
    if base.endswith(".evtx"):
        base = base[: -len(".evtx")]
    return base.replace("%4", "/")


class EvtxOutputSchemaError(RuntimeError):
    """W-136 §4.3: raised when parser stdout violates the expected JSONL shape.

    Today this fires when more than ``_SCHEMA_VIOLATION_THRESHOLD`` lines
    in a row fail to decode as JSON or lack the ``Event.System`` envelope.
    Catching it surfaces upstream-binary-rename bugs (the W-123 sniff
    regression class) instead of silently returning ``event_count=0``.
    """


# A handful of malformed lines is normal (header rows, blank lines).
# More than this in a row signals a schema mismatch worth surfacing.
_SCHEMA_VIOLATION_THRESHOLD = 64


class EvtxEvent(BaseModel):
    """One parsed event record."""

    record_id: int = 0
    event_id: int = 0
    channel: str = ""
    provider: str = ""
    timestamp: str = ""
    computer: str = ""
    level: int = 0
    raw: str = ""


class EvtxReport(BaseModel):
    """Parsed output of an evtx_dump run.

    Fields with the W-133 prefix populate only on the E01-dispatch
    path. On the legacy single-file path they keep their default empty
    values so existing callers see no shape change.
    """

    image_path: str
    event_count: int = 0
    events: list[EvtxEvent] = Field(default_factory=list)
    channels_seen: list[str] = Field(default_factory=list)
    truncated: bool = False
    tool: str = "evtx.dump"
    raw_stderr: str = ""
    # SIFT-W-082: SHA-256 of evtx_dump's raw stdout bytes.
    raw_stdout_sha256: str = ""
    # W-133/W-139: filenames the wrapper *requested* from the E01 (the
    # on-disk basenames of channels in the request manifest, e.g.
    # ``Security.evtx``). Populated regardless of whether extraction
    # succeeded so an operator debugging an empty result can see the
    # request manifest. Empty on the legacy single-file path.
    # Renamed in W-139 from ``evtx_files_discovered`` because the old
    # name implied "files actually located on disk" — the value is
    # actually the request shape, not the result. Pair this with
    # :attr:`evtx_files_extracted` (W-139) to see what icat returned.
    evtx_files_requested: list[str] = Field(default_factory=list)
    # W-139: subset of ``evtx_files_requested`` that icat actually
    # pulled bytes off disk for. Empty list + non-empty
    # ``evtx_files_requested`` means the wrapper looked at the wrong
    # paths for this OS (see ``image_class_detected``) or the host
    # genuinely doesn't have those channels populated.
    evtx_files_extracted: list[str] = Field(default_factory=list)
    # W-133: subset of ``evtx_files_extracted`` for which the parser
    # ran without raising (RuntimeError / TimeoutError /
    # EvtxOutputSchemaError all exclude the channel). The list uses
    # MCP-style channel names, not filenames.
    channels_extracted: list[str] = Field(default_factory=list)
    # W-139: image OS class as detected by the wrapper. ``"modern"``
    # = Vista+/2008+ (winevt/Logs path); ``"winxp_or_win2003"`` =
    # legacy SecEvent.Evt path detected; ``None`` = wrapper didn't
    # probe (single-file path) or could not classify.
    image_class_detected: str | None = None
    # W-139: human-readable explanation when the wrapper extracted
    # nothing parseable. ``None`` on the happy path.
    skipped_reason: str | None = None
    # W-139: list of legacy ``*.Evt`` file basenames found at
    # ``Windows/System32/config/`` when the modern path was empty.
    # Surfaced so the operator sees the host *does* have logs, just
    # in a format the current parser doesn't support.
    legacy_evt_files_found: list[str] = Field(default_factory=list)


def _attr(obj: Any, attr_key: str) -> str:
    """Extract an XML-attribute value (``#attributes`` key) or text value."""
    if isinstance(obj, dict):
        attrs = obj.get("#attributes") or obj.get("@attributes") or {}
        if isinstance(attrs, dict) and attr_key in attrs:
            return str(attrs[attr_key])
    return ""


def _extract_event(payload: dict[str, Any]) -> EvtxEvent | None:
    """Convert one evtx_dump JSON object into an ``EvtxEvent``.

    evtx_dump's JSONL shape is roughly::

      {"Event": {"System": {"EventID": 4624, "Channel": "Security",
         "Provider": {"#attributes": {"Name": "...-Auditing"}},
         "TimeCreated": {"#attributes": {"SystemTime": "..."}},
         "EventRecordID": 1234, "Computer": "DC1", "Level": 0}}}
    """
    event = payload.get("Event") if isinstance(payload, dict) else None
    if not isinstance(event, dict):
        return None
    system = event.get("System") if isinstance(event.get("System"), dict) else {}

    event_id_raw = system.get("EventID", 0)
    if isinstance(event_id_raw, dict):
        event_id_raw = event_id_raw.get("#text", 0)
    try:
        event_id = int(event_id_raw)
    except (TypeError, ValueError):
        event_id = 0

    channel = str(system.get("Channel", "") or "")
    provider_node = system.get("Provider")
    provider = _attr(provider_node, "Name") if isinstance(provider_node, dict) else ""

    time_node = system.get("TimeCreated")
    timestamp = _attr(time_node, "SystemTime") if isinstance(time_node, dict) else ""

    computer = str(system.get("Computer", "") or "")
    record_id_raw = system.get("EventRecordID", 0)
    try:
        record_id = int(record_id_raw)
    except (TypeError, ValueError):
        record_id = 0

    level_raw = system.get("Level", 0)
    try:
        level = int(level_raw)
    except (TypeError, ValueError):
        level = 0

    raw_serialized = json.dumps(payload, default=str)[:2000]
    return EvtxEvent(
        record_id=record_id,
        event_id=event_id,
        channel=channel,
        provider=provider,
        timestamp=timestamp,
        computer=computer,
        level=level,
        raw=raw_serialized,
    )


def _matches(
    event: EvtxEvent,
    *,
    channels_lower: set[str] | None,
    event_ids: set[int] | None,
    record_id_min: int | None = None,
    record_id_max: int | None = None,
) -> bool:
    if channels_lower is not None and event.channel.lower() not in channels_lower:
        return False
    if event_ids is not None and event.event_id not in event_ids:
        return False
    if record_id_min is not None and event.record_id < record_id_min:
        return False
    return not (record_id_max is not None and event.record_id > record_id_max)


def _parse_jsonl(
    output: str,
    *,
    channels: set[str] | None,
    event_ids: set[int] | None,
    max_events: int,
    tail: bool = True,
    record_id_min: int | None = None,
    record_id_max: int | None = None,
) -> tuple[list[EvtxEvent], list[str], bool]:
    """Return (events, channels_seen, truncated) from JSONL output.

    W-136 §4.3 added run-length tracking for malformed JSON / missing-
    envelope lines. A short tail of bad lines is normal (header rows,
    Rust binary banner). A long run signals a schema mismatch — we
    raise :class:`EvtxOutputSchemaError` so the caller doesn't silently
    return ``event_count=0`` on a binary version bump.

    W-137: when ``tail`` is True the parser keeps the LAST
    ``max_events`` matches via a bounded deque rather than early-exiting
    after the first ``max_events``. evtx_dump emits records oldest-first,
    so tail-mode surfaces the most-recent attack window. ``truncated``
    is True iff total matches exceeded ``max_events``.
    """
    channels_seen: set[str] = set()
    channels_lower = {c.lower() for c in channels} if channels else None

    consecutive_violations = 0
    saw_any_event = False
    matched_total = 0
    # tail=True buffers the last N matches; tail=False keeps a plain list
    # and breaks early at max_events for back-compat.
    buf: deque[EvtxEvent] | list[EvtxEvent] = (
        deque(maxlen=max_events) if tail else []
    )
    truncated = False

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("{"):
            # Tolerate non-JSON banners (Rust ``Record N`` headers,
            # version strings) without counting them as violations.
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            consecutive_violations += 1
            if consecutive_violations >= _SCHEMA_VIOLATION_THRESHOLD and not saw_any_event:
                raise EvtxOutputSchemaError(
                    f"{consecutive_violations} consecutive JSON decode failures "
                    "without producing a single event — likely upstream binary "
                    "output format change (W-123/W-136 regression class)"
                ) from exc
            continue
        event = _extract_event(payload) if isinstance(payload, dict) else None
        if event is None:
            consecutive_violations += 1
            if consecutive_violations >= _SCHEMA_VIOLATION_THRESHOLD and not saw_any_event:
                raise EvtxOutputSchemaError(
                    f"{consecutive_violations} consecutive parsed-JSON lines "
                    "missing the Event.System envelope — likely upstream "
                    "schema change (W-123/W-136 regression class)"
                )
            continue
        consecutive_violations = 0
        saw_any_event = True
        if event.channel:
            channels_seen.add(event.channel)
        if not _matches(
            event,
            channels_lower=channels_lower,
            event_ids=event_ids,
            record_id_min=record_id_min,
            record_id_max=record_id_max,
        ):
            continue
        matched_total += 1
        buf.append(event)
        if not tail and len(buf) >= max_events:
            truncated = True
            break

    if tail:
        truncated = matched_total > max_events
    return list(buf), sorted(channels_seen), truncated


# Match one self-contained <Event>...</Event> block. Non-greedy inner
# body — nested <Event> tags do not occur in the EVTX XML grammar.
_EVENT_BLOCK = re.compile(r"<Event\b[^>]*>.*?</Event>", re.DOTALL)
# python-evtx emits xmlns="..." on the root Event element; strip so we
# can address children without ElementTree namespace URIs.
_NS_ATTR = re.compile(r'\s+xmlns(:\w+)?="[^"]*"')


def _int_or_zero(text: str | None) -> int:
    if not text:
        return 0
    try:
        return int(text.strip())
    except ValueError:
        return 0


def _event_from_xml(block: str) -> EvtxEvent | None:
    """Convert one ``<Event>...</Event>`` XML block into an EvtxEvent."""
    clean = _NS_ATTR.sub("", block)
    try:
        root = ET.fromstring(clean)
    except ET.ParseError:
        return None
    system = root.find("System")
    if system is None:
        return None

    event_id = _int_or_zero(system.findtext("EventID"))
    channel = (system.findtext("Channel") or "").strip()
    record_id = _int_or_zero(system.findtext("EventRecordID"))
    level = _int_or_zero(system.findtext("Level"))
    computer = (system.findtext("Computer") or "").strip()

    provider = ""
    prov = system.find("Provider")
    if prov is not None:
        provider = prov.get("Name") or ""

    timestamp = ""
    tc = system.find("TimeCreated")
    if tc is not None:
        timestamp = tc.get("SystemTime") or ""

    return EvtxEvent(
        record_id=record_id,
        event_id=event_id,
        channel=channel,
        provider=provider,
        timestamp=timestamp,
        computer=computer,
        level=level,
        raw=block[:2000],
    )


def _parse_xml(
    output: str,
    *,
    channels: set[str] | None,
    event_ids: set[int] | None,
    max_events: int,
    tail: bool = True,
    record_id_min: int | None = None,
    record_id_max: int | None = None,
) -> tuple[list[EvtxEvent], list[str], bool]:
    """Return (events, channels_seen, truncated) from the XML stream.

    W-137: ``tail`` and the record-id range filter behave as in
    :func:`_parse_jsonl`. With ``tail=True`` (default), the parser
    walks the entire document but only buffers the last ``max_events``
    matches.
    """
    channels_seen: set[str] = set()
    channels_lower = {c.lower() for c in channels} if channels else None
    matched_total = 0
    buf: deque[EvtxEvent] | list[EvtxEvent] = (
        deque(maxlen=max_events) if tail else []
    )
    truncated = False

    for match in _EVENT_BLOCK.finditer(output):
        event = _event_from_xml(match.group(0))
        if event is None:
            continue
        if event.channel:
            channels_seen.add(event.channel)
        if not _matches(
            event,
            channels_lower=channels_lower,
            event_ids=event_ids,
            record_id_min=record_id_min,
            record_id_max=record_id_max,
        ):
            continue
        matched_total += 1
        buf.append(event)
        if not tail and len(buf) >= max_events:
            truncated = True
            break

    if tail:
        truncated = matched_total > max_events
    return list(buf), sorted(channels_seen), truncated


def _sniff_format(output: str) -> str:
    """Return ``"xml"``, ``"jsonl"``, or ``"empty"`` for an output string.

    Scans line-by-line so the omerbenamram/evtx Rust binary's
    ``Record NNNN`` header line (emitted before each XML block in the
    default ``-o xml`` mode) does not mask the underlying format.
    """
    for line in output.splitlines():
        stripped = line.lstrip()
        if not stripped:
            continue
        if stripped[0] == "<":
            return "xml"
        if stripped[0] == "{":
            return "jsonl"
        # Header lines like "Record 7335997" — keep scanning.
    return "empty"


def _parse_any(
    output: str,
    *,
    channels: set[str] | None,
    event_ids: set[int] | None,
    max_events: int,
    tail: bool = True,
    record_id_min: int | None = None,
    record_id_max: int | None = None,
) -> tuple[list[EvtxEvent], list[str], bool]:
    """Dispatch to the JSONL or XML parser based on the first non-blank char."""
    fmt = _sniff_format(output)
    if fmt == "jsonl":
        return _parse_jsonl(
            output,
            channels=channels,
            event_ids=event_ids,
            max_events=max_events,
            tail=tail,
            record_id_min=record_id_min,
            record_id_max=record_id_max,
        )
    if fmt == "xml":
        return _parse_xml(
            output,
            channels=channels,
            event_ids=event_ids,
            max_events=max_events,
            tail=tail,
            record_id_min=record_id_min,
            record_id_max=record_id_max,
        )
    return [], [], False


async def _run_evtx_dump(
    target_path: Path,
    *,
    channels_set: set[str] | None,
    event_ids_set: set[int] | None,
    max_events: int,
    timeout: float,
    tail: bool = True,
    record_id_min: int | None = None,
    record_id_max: int | None = None,
) -> tuple[list[EvtxEvent], list[str], bool, bytes, str]:
    """Run the configured evtx parser binary on ONE extracted .evtx.

    Internal helper shared by the legacy single-file path and the new
    W-133 E01-dispatch path. Returns
    ``(events, channels_seen, truncated, stdout_bytes, stderr_str)``.
    Raises the same exceptions as the public wrapper used to.
    """
    tool_name = _resolve_tool()
    tool_path = shutil.which(tool_name)
    if not tool_path:
        raise FileNotFoundError(
            f"{tool_name} not found on PATH — install python-evtx (SIFT default) or set AGENTROPIX_EVTX_TOOL"
        )

    cmd = [tool_path]
    # W-136 §3 row 1 + 2: when the Rust binary is in play, force JSONL
    # on inputs above the size threshold (skips the multi-GB XML-stdout
    # regex scan in ``_parse_xml``). Pass ``--threads`` from
    # ``AGENTROPIX_EVTX_WORKERS`` so a burst of MCP calls doesn't fan
    # out 24 threads × N requests (W-131-class anti-pattern).
    if _is_rust_evtx_dump(tool_name):
        cmd.extend(["--threads", str(_evtx_workers())])
        try:
            file_size = target_path.stat().st_size
        except OSError:
            file_size = 0
        if file_size >= _force_jsonl_threshold():
            cmd.extend(["-o", "jsonl"])
            logger.debug(
                "evtx forcing -o jsonl (file=%d bytes >= threshold)",
                file_size,
            )
    cmd.append(str(target_path))
    logger.info("Running: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        raise TimeoutError(f"{tool_name} timed out after {timeout}s") from None

    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")

    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError(f"{tool_name} failed (rc={proc.returncode}): {stderr[:500]}")

    events, channels_seen, truncated = _parse_any(
        stdout,
        channels=channels_set,
        event_ids=event_ids_set,
        max_events=max_events,
        tail=tail,
        record_id_min=record_id_min,
        record_id_max=record_id_max,
    )
    return events, channels_seen, truncated, stdout_bytes, stderr


async def _probe_legacy_evt(
    image_path: Path,
    tmpdir: Path,
    *,
    timeout: float,
) -> list[str]:
    """W-139: probe an E01 for XP/2003-class legacy ``.Evt`` files.

    Returns the basenames of any ``Windows/System32/config/*.Evt``
    files icat could extract. Empty list means the image is not an
    XP/2003-class host (or the legacy hive directory is also missing,
    in which case classification is genuinely "unknown" rather than
    "modern"). Caller is responsible for cleaning up ``tmpdir`` —
    this function only extracts.

    Cost: one ifind + icat per probe path (six). On the happy
    modern-Windows path this function is *never* called — only when
    the modern winevt/Logs request returned zero extracted files.
    """
    from agentropix_mcp.wrappers.extract import extract_files

    probe_manifest = await extract_files(
        image_path,
        list(_LEGACY_EVT_PATHS),
        tmpdir,
        timeout=timeout,
    )
    found: set[str] = set()
    for entry in probe_manifest.extracted:
        found.add(Path(entry.dest).name)
    return sorted(found)


async def _get_evtx_from_e01(
    image_path: Path,
    *,
    channels: set[str] | list[str] | None,
    event_ids: set[int] | list[int] | None,
    max_events: int,
    timeout: float,
    tail: bool = True,
    record_id_min: int | None = None,
    record_id_max: int | None = None,
) -> EvtxReport:
    """W-133: enumerate + extract + parse .evtx files inside an E01 image.

    Pipeline:
      1. Resolve the channel set (default
         ``_DEFAULT_E01_CHANNELS`` if caller didn't specify) and build
         the list of in-container paths under
         ``Windows/System32/winevt/Logs/``.
      2. Hand the path list to ``extract_files`` (the W-028 / ADR-012
         ifind+icat pipeline that ``get_shimcache`` / ``get_amcache``
         already use). Per-call tempdir under
         ``/tmp/agentropix-sift-evtx-*`` is removed in finally.
      3. For each successfully-extracted file, run the configured
         evtx parser and merge its events into the aggregate report.
      4. Hard-cap at ``max_events`` across all channels combined; mark
         ``truncated=True`` when the cap binds.

    W-139: when no modern paths extract, the wrapper falls back to a
    legacy ``Windows/System32/config/*.Evt`` probe and, on hits,
    returns ``image_class_detected="winxp_or_win2003"`` plus a
    ``skipped_reason`` and ``legacy_evt_files_found`` so the operator
    sees the host has logs in an unsupported format rather than
    silently misreading "0 events" as "no auth activity".

    The wrapper does NOT pre-enumerate every .evtx on disk via
    ``fls -r`` — on a 245k-entry image that took ~42 s in the
    2026-04-30 DC triage. Instead it asks the operator (or default
    set) which channels to extract, and reports back which channels
    actually produced events. ``evtx_files_requested`` (W-139, was
    ``evtx_files_discovered``), ``evtx_files_extracted`` (W-139), and
    ``channels_extracted`` give the operator the same observability
    that an enumeration pass would (W-133 acceptance criterion 3).
    """
    # Resolve channel list + filenames.
    chan_list: list[str] = list(channels) if channels else list(_DEFAULT_E01_CHANNELS)
    in_image_paths = [
        f"{_WINEVT_LOGS_PREFIX}/{_channel_to_filename(c)}" for c in chan_list
    ]

    # Channel filter applied during PER-FILE parse: the icat-extracted
    # tempfile may technically contain events for any channel its
    # internal records reference, but practically each .evtx only
    # carries records for its own channel. Pre-loaded into a set the
    # legacy parser already understands.
    channels_set: set[str] | None = set(chan_list) if chan_list else None
    event_ids_set: set[int] | None = set(event_ids) if event_ids else None

    # Lazy-import ``extract_files`` + ``ExtractedFile`` to avoid a
    # top-level cycle: the extract module also imports trace / pydantic
    # models that reach back into the wrapper namespace at server-
    # startup time.
    from agentropix_mcp.wrappers.extract import (
        ExtractedFile,
        extract_files,
    )

    tmpdir = Path(tempfile.mkdtemp(prefix="agentropix-sift-evtx-"))
    try:
        # W-138: split the request into cache hits and misses. A hit
        # hardlinks (or copies) the cached file into ``tmpdir`` so the
        # parser sees a uniform layout regardless of source. Misses fall
        # through to ``extract_files`` and are stored in the cache after
        # extraction. Cache disabled cleanly when key derivation fails
        # (stat error) — every path becomes a miss, behaviour matches
        # pre-W-138 exactly.
        cache_synth: list[ExtractedFile] = []
        miss_paths: list[str] = []
        for in_image_path in in_image_paths:
            channel_filename = Path(in_image_path).name
            cached = _evtx_cache_lookup(image_path, channel_filename)
            if cached is None:
                miss_paths.append(in_image_path)
                continue
            dst = tmpdir / channel_filename
            try:
                # Hardlink is zero-copy when cache + tmpdir share a FS.
                # Fall back to copy2 across mount points or read-only
                # cache scenarios.
                os.link(cached, dst)
            except OSError:
                shutil.copy2(cached, dst)
            try:
                size = dst.stat().st_size
            except OSError:
                size = 0
            cache_synth.append(
                ExtractedFile(
                    src_path=in_image_path,
                    inode="<cache>",
                    dest=str(dst),
                    size=size,
                    sha256="",  # not recomputed on hit; downstream parser doesn't need it
                    truncated=False,
                    duration_ms=0.0,
                )
            )

        if miss_paths:
            manifest = await extract_files(
                image_path,
                miss_paths,
                tmpdir,
                timeout=timeout,
            )
            # Store newly-extracted files in the cache so the next call
            # against the same (image, channel) is a hit.
            for entry in manifest.extracted:
                _evtx_cache_store(
                    image_path,
                    Path(entry.dest).name,
                    Path(entry.dest),
                )
        else:
            # Synthesise an empty manifest so the rest of the pipeline
            # is unchanged. The image_path/dest_dir/entry_count fields
            # only feed the trace-level fields below; we use a real
            # ExtractManifest to keep typing consistent.
            from agentropix_mcp.wrappers.extract import (
                ExtractManifest,
            )
            manifest = ExtractManifest(
                image_path=str(image_path),
                dest_dir=str(tmpdir),
                entry_count=0,
            )

        # Merge cache hits into manifest.extracted so downstream code
        # sees one combined list. Cache hits keep their synthesised
        # ExtractedFile rows.
        manifest.extracted.extend(cache_synth)

        # W-139: requested = the on-disk filenames we attempted; the
        # operator sees the request manifest even if extraction missed
        # everything. extracted = the strict subset that surfaced via
        # icat OR the W-138 cache. Without this split it's impossible
        # to tell "wrapper looked at the wrong path" (XP-class host)
        # from "host has no Security.evtx populated" (sparse Win7
        # endpoint) — both look like ``event_count=0`` from outside.
        evtx_files_requested = sorted(
            {Path(p).name for p in in_image_paths}
        )
        evtx_files_extracted = sorted(
            {Path(e.dest).name for e in manifest.extracted}
        )

        # W-139 short-circuit: nothing extracted from the modern
        # winevt/Logs path. Probe the legacy XP/2003 location before
        # returning an empty result so the operator gets a real signal
        # instead of "0 events" with the wrong manifest. Mirrors W-135's
        # vol3 disk-image short-circuit pattern: surface the actual
        # wrapper decision rather than silently degrade.
        if not manifest.extracted:
            legacy_found = await _probe_legacy_evt(
                image_path, tmpdir, timeout=timeout,
            )
            if legacy_found:
                return EvtxReport(
                    image_path=str(image_path),
                    event_count=0,
                    truncated=False,
                    raw_stderr="",
                    raw_stdout_sha256=hashlib.sha256().hexdigest(),
                    evtx_files_requested=evtx_files_requested,
                    evtx_files_extracted=[],
                    channels_extracted=[],
                    image_class_detected="winxp_or_win2003",
                    skipped_reason=(
                        "host uses legacy .evt format at "
                        "Windows/System32/config/*.Evt; current parser "
                        "supports .evtx only (W-139)"
                    ),
                    legacy_evt_files_found=legacy_found,
                )
            # Neither modern nor legacy paths found — image_class is
            # genuinely unknown (could be a non-Windows image or a
            # partial acquisition). Fall through to the normal empty
            # response so existing callers see the same shape.

        # W-136 §3 row 3: parse every extracted channel concurrently
        # with a bounded asyncio semaphore. Cap at AGENTROPIX_EVTX_WORKERS
        # so we don't fan out N parsers × M MCP requests under burst load.
        # The combined ``max_events`` cap is enforced after-the-fact when
        # we merge results — over-collecting per-channel and slicing to
        # ``max_events`` at the end is simpler than threading a shared
        # atomic counter across asyncio tasks and the resulting events
        # list is deterministic in channel order.
        sem = asyncio.Semaphore(_evtx_workers())
        per_channel_cap = max_events  # each channel may individually fill the cap

        async def _parse_one_channel(entry):
            extracted_path = Path(entry.dest)
            channel_name = _filename_to_channel(extracted_path.name)
            async with sem:
                try:
                    return channel_name, await _run_evtx_dump(
                        extracted_path,
                        channels_set=channels_set,
                        event_ids_set=event_ids_set,
                        max_events=per_channel_cap,
                        timeout=timeout,
                        tail=tail,
                        record_id_min=record_id_min,
                        record_id_max=record_id_max,
                    )
                except (RuntimeError, TimeoutError, EvtxOutputSchemaError) as exc:
                    logger.warning(
                        "evtx parse failed for channel %r (%s): %s",
                        channel_name,
                        extracted_path.name,
                        exc,
                    )
                    return channel_name, None

        results = await asyncio.gather(
            *(_parse_one_channel(e) for e in manifest.extracted)
        )

        events_all: list[EvtxEvent] = []
        channels_seen_all: set[str] = set()
        channels_extracted_set: set[str] = set()
        truncated = False
        stderr_acc: list[str] = []
        stdout_hash = hashlib.sha256()

        for channel_name, payload in results:
            if payload is None:
                continue
            events, channels_seen, sub_truncated, stdout_bytes, stderr = payload
            stdout_hash.update(stdout_bytes)
            if stderr:
                stderr_acc.append(f"[{channel_name}] {stderr[:200]}")
            channels_seen_all.update(channels_seen)
            channels_extracted_set.add(channel_name)
            if sub_truncated:
                truncated = True
            # Merge under the combined ``max_events`` cap.
            remaining = max_events - len(events_all)
            if remaining <= 0:
                truncated = True
                break
            if len(events) > remaining:
                events_all.extend(events[:remaining])
                truncated = True
            else:
                events_all.extend(events)

        return EvtxReport(
            image_path=str(image_path),
            event_count=len(events_all),
            events=events_all,
            channels_seen=sorted(channels_seen_all),
            truncated=truncated,
            raw_stderr="\n".join(stderr_acc)[:1000],
            raw_stdout_sha256=stdout_hash.hexdigest(),
            evtx_files_requested=evtx_files_requested,
            evtx_files_extracted=evtx_files_extracted,
            channels_extracted=sorted(channels_extracted_set),
            # W-139: classify as modern only when at least one file
            # extracted from the winevt/Logs path. When both modern
            # and legacy probes came up empty (image of unknown OS,
            # partial acquisition, non-Windows volume) we leave the
            # field at None so downstream code can reason about
            # "I don't know" instead of a false "modern" claim.
            image_class_detected=(
                "modern" if evtx_files_extracted else None
            ),
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


async def get_evtx(
    target: str | Path,
    *,
    channels: set[str] | list[str] | None = None,
    event_ids: set[int] | list[int] | None = None,
    max_events: int | None = None,
    timeout: float | None = None,
    tail: bool = True,
    record_id_min: int | None = None,
    record_id_max: int | None = None,
) -> EvtxReport:
    """Parse Windows ``.evtx`` event logs into typed event records.

    Two input modes (W-133):

    * **E01 image** — when ``target`` is an EWF/.E01 disk image (suffix
      sniff or ``EVF`` magic-byte check), the wrapper enumerates
      ``Windows/System32/winevt/Logs/`` and extracts the requested
      channels via the W-028 ifind+icat pipeline into a per-call
      tempdir, then runs the configured parser on each. If
      ``channels`` is not provided, the default set
      (``_DEFAULT_E01_CHANNELS``: Security / System / Application /
      PowerShell-Operational / TaskScheduler-Operational / Sysmon-
      Operational) is extracted. Response includes
      ``evtx_files_requested`` (filenames the wrapper asked for;
      W-139, renamed from ``evtx_files_discovered``),
      ``evtx_files_extracted`` (subset icat actually pulled; W-139),
      ``channels_extracted`` (channels that produced ≥ 0 events), and
      ``image_class_detected`` (``"modern"`` /
      ``"winxp_or_win2003"``). On XP/2003 hosts the wrapper
      short-circuits and returns ``skipped_reason`` +
      ``legacy_evt_files_found`` (W-139).

    * **Single .evtx file** — legacy mode unchanged: ``target`` is an
      already-extracted ``.evtx`` (e.g. one written by
      ``mcp_extract_files``). Channel set, event-id, and max-events
      filters work identically.

    Args:
        target: Path to either an E01 image or a single ``.evtx``.
        channels: Restrict to these channel names. On the E01 path
            this also drives WHICH channels to extract (default set
            applies if None).
        event_ids: Restrict to these event-id integers (case-sensitive
            equality after parser-level coercion).
        max_events: Hard cap on result size. Defaults to
            ``AGENTROPIX_EVTX_MAX_EVENTS`` (5000, floor 1, ceiling
            100000; W-137 raised the default from 1000). Cap binds
            across all channels on the E01 path.
        timeout: Max seconds per evtx parser invocation. On the E01
            path also serves as the per-icat budget.
        tail: When True (default, W-137), return the LAST
            ``max_events`` matching records the parser sees rather
            than the first. evtx_dump emits records oldest-first;
            ``tail=True`` surfaces the recent attack window for
            multi-million-record Security logs. Set ``tail=False``
            to restore pre-W-137 oldest-first truncation semantics.
        record_id_min: Inclusive lower bound on ``EventRecordID``;
            useful for re-running against a known attack window
            without re-parsing the whole file (W-137).
        record_id_max: Inclusive upper bound on ``EventRecordID``.

    Returns:
        EvtxReport with filtered events and channel summary.

    Raises:
        FileNotFoundError: target missing or parser binary not on PATH.
        TimeoutError: parser exceeds timeout.
        RuntimeError: parser returns non-zero with empty stdout.
    """
    target_path = Path(target)
    if not target_path.exists():
        raise FileNotFoundError(f"evtx target not found: {target_path}")
    if not target_path.is_file():
        raise FileNotFoundError(f"evtx target is not a regular file: {target_path}")

    if timeout is None:
        timeout = get_float("AGENTROPIX_EVTX_TIMEOUT", 180.0, floor=5.0, ceiling=3600.0)
    else:
        # Per-call override is subject to the same floor/ceiling guards as the
        # AGENTROPIX_EVTX_TIMEOUT env-var path — without this clamp a caller
        # could request 0s (instant fail) or a multi-hour timeout that pins
        # the MCP worker.
        timeout = clamp_float("AGENTROPIX_EVTX_TIMEOUT", timeout, floor=5.0, ceiling=3600.0)
    if max_events is None:
        # W-137: default raised 1000 -> 5000 to surface enough of an
        # attack window even on multi-million-record Security logs.
        max_events = get_int("AGENTROPIX_EVTX_MAX_EVENTS", 5000, floor=1, ceiling=100_000)

    # W-133: route E01 images to the enumerate+extract+parse pipeline.
    # Single-file inputs fall through to the legacy path below
    # unchanged so existing callers see no regression.
    if _is_e01_image(target_path):
        return await _get_evtx_from_e01(
            target_path,
            channels=channels,
            event_ids=event_ids,
            max_events=max_events,
            timeout=timeout,
            tail=tail,
            record_id_min=record_id_min,
            record_id_max=record_id_max,
        )

    channels_set: set[str] | None = set(channels) if channels else None
    event_ids_set: set[int] | None = set(event_ids) if event_ids else None

    events, channels_seen, truncated, stdout_bytes, stderr = await _run_evtx_dump(
        target_path,
        channels_set=channels_set,
        event_ids_set=event_ids_set,
        max_events=max_events,
        timeout=timeout,
        tail=tail,
        record_id_min=record_id_min,
        record_id_max=record_id_max,
    )
    return EvtxReport(
        image_path=str(target_path),
        event_count=len(events),
        events=events,
        channels_seen=channels_seen,
        truncated=truncated,
        raw_stderr=stderr[:1000] if stderr else "",
        raw_stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
    )
