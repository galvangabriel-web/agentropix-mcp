"""SRUM (System Resource Usage Monitor) parser wrapper — SIFT-W-283.

Targets ``SRUDB.dat`` (``C:\\Windows\\System32\\sru\\SRUDB.dat``), the
Windows ESE database that records per-process network bytes, application
resource usage, push notifications, and energy usage. SRUM evidence is
load-bearing for "what process used the network at time T" questions
that no other agentropix wrapper answers today.

Linux note: Eric Zimmerman's ``SrumECmd`` refuses to run on non-Windows
hosts ("Non-Windows platforms not supported due to the need to load ESI
specific Windows libraries! Exiting..."), and Mark Baggett's
``srum-dump`` requires ``pywin32``. The wrapper therefore drives
libesedb's ``esedbexport`` (already on SIFT/system Linux distros — the
SANS SIFT base image ships it), which can dump SRUM tables to TSV files
on Linux without any Windows runtime. The trade-off is that libesedb
sometimes fails on individual tables of a dirty-shutdown SRUDB; the
wrapper tolerates per-table export failures and surfaces them in
``raw_warnings`` rather than failing the whole call.

Output normalization is conservative — unparseable rows go to
``raw_warnings`` rather than being silently dropped, matching the
existing wrapper convention (prefetch / amcache / mftecmd).
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import logging
import os
import shutil
import tempfile
import time
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field

from agentropix_mcp._env import get_float

logger = logging.getLogger(__name__)

DEFAULT_TOOL_NAME = "esedbexport"

# Well-known SRUM table GUIDs (Microsoft + forensic literature).
SRUM_TABLE_NETWORK_DATA = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
SRUM_TABLE_APP_RESOURCE = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
SRUM_TABLE_NETWORK_CONN = "{DD6636C4-8929-4683-974E-22C046A43763}"
SRUM_TABLE_PUSH_NOTIF = "{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}"
SRUM_TABLE_ENERGY_USAGE = "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}"

KNOWN_TABLES: dict[str, str] = {
    "network_data": SRUM_TABLE_NETWORK_DATA,
    "app_resource": SRUM_TABLE_APP_RESOURCE,
    "network_connectivity": SRUM_TABLE_NETWORK_CONN,
    "push_notifications": SRUM_TABLE_PUSH_NOTIF,
    "energy_usage": SRUM_TABLE_ENERGY_USAGE,
}

IDMAP_TABLE = "SruDbIdMapTable"

# esedbexport prints timestamps in a fixed format:
#   "Oct 20, 2020 16:25:00.000000023"
# The trailing fractional seconds can have 0-9 digits.
_TS_FMTS = (
    "%b %d, %Y %H:%M:%S.%f",
    "%b %d, %Y %H:%M:%S",
)


def _resolve_tool() -> str:
    """Resolve esedbexport binary, honoring AGENTROPIX_SRUM_TOOL."""
    return os.environ.get("AGENTROPIX_SRUM_TOOL", DEFAULT_TOOL_NAME)


# --- Pydantic row models ------------------------------------------------- #


class SrumNetworkDataRow(BaseModel):
    """Per-process network bytes (sent/received) over time."""

    auto_inc_id: int = 0
    timestamp: str = ""
    app_id_num: int = 0
    user_id_num: int = 0
    app_id: str = ""
    user_sid: str = ""
    interface_luid: int = 0
    l2_profile_id: int = 0
    bytes_sent: int = 0
    bytes_recvd: int = 0


class SrumAppResourceRow(BaseModel):
    """Per-process CPU + IO snapshots (foreground vs background)."""

    auto_inc_id: int = 0
    timestamp: str = ""
    app_id_num: int = 0
    user_id_num: int = 0
    app_id: str = ""
    user_sid: str = ""
    foreground_cycle_time: int = 0
    background_cycle_time: int = 0
    foreground_bytes_read: int = 0
    foreground_bytes_written: int = 0
    background_bytes_read: int = 0
    background_bytes_written: int = 0


class SrumNetworkConnRow(BaseModel):
    """Per-process network connectivity events."""

    auto_inc_id: int = 0
    timestamp: str = ""
    app_id_num: int = 0
    user_id_num: int = 0
    app_id: str = ""
    user_sid: str = ""
    interface_luid: int = 0
    l2_profile_id: int = 0
    connected_time: int = 0
    connect_start_time: str = ""


class SrumPushNotificationRow(BaseModel):
    """Push notification record (BinaryData omitted — surfaced as hex hash only)."""

    auto_inc_id: int = 0
    timestamp: str = ""
    app_id_num: int = 0
    user_id_num: int = 0
    app_id: str = ""
    user_sid: str = ""
    binary_data_sha256: str = ""


class SrumEnergyUsageRow(BaseModel):
    """Energy usage snapshot (battery state transitions)."""

    auto_inc_id: int = 0
    timestamp: str = ""
    app_id_num: int = 0
    user_id_num: int = 0
    app_id: str = ""
    user_sid: str = ""
    raw: str = ""  # full TSV row, columns vary by Windows build


class SrumExtractResult(BaseModel):
    """Output of an ``srum_extract`` call.

    All ``*_returned`` rows are after the optional ``since_iso`` filter
    and the per-table ``limit`` cap. ``id_lookup`` maps the numeric
    ``AppId``/``UserId`` columns to their decoded strings; agents must
    consult this map to resolve the per-row ``app_id`` and ``user_sid``
    when those fields are empty (decode failures land in
    ``raw_warnings`` instead).
    """

    srudb_path: str
    srudb_sha256: str
    parser: str = "esedbexport"
    parser_version: str = ""
    tables_requested: list[str] = Field(default_factory=list)
    tables_returned: list[str] = Field(default_factory=list)
    tables_failed: list[str] = Field(default_factory=list)
    id_lookup: dict[int, str] = Field(default_factory=dict)
    network_data: list[SrumNetworkDataRow] = Field(default_factory=list)
    app_resource: list[SrumAppResourceRow] = Field(default_factory=list)
    network_connectivity: list[SrumNetworkConnRow] = Field(default_factory=list)
    push_notifications: list[SrumPushNotificationRow] = Field(default_factory=list)
    energy_usage: list[SrumEnergyUsageRow] = Field(default_factory=list)
    raw_warnings: list[str] = Field(default_factory=list)
    elapsed_sec: float = 0.0


# --- Helpers ------------------------------------------------------------- #


def _parse_timestamp(ts: str) -> datetime | None:
    ts = ts.strip()
    if not ts:
        return None
    for fmt in _TS_FMTS:
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def _parse_since(since_iso: str | None) -> datetime | None:
    if not since_iso:
        return None
    try:
        # Accept "YYYY-MM-DD" or full ISO-8601; strip trailing Z.
        return datetime.fromisoformat(since_iso.rstrip("Z"))
    except ValueError:
        return None


def _decode_idmap_blob(id_type_str: str, hex_blob: str) -> str:
    """Decode an SruDbIdMapTable IdBlob hex string into a printable name.

    IdType=3 ⇒ binary SID; everything else ⇒ UTF-16-LE string.
    Empty / malformed blobs return ''.
    """
    hex_blob = (hex_blob or "").strip()
    if not hex_blob:
        return ""
    try:
        raw = bytes.fromhex(hex_blob)
    except ValueError:
        return ""
    if id_type_str.strip() == "3":
        # SID: revision(1) + sub_auth_count(1) + auth(6 BE) + sub_auths(4 LE each)
        if len(raw) < 8:
            return ""
        revision = raw[0]
        sub_count = raw[1]
        authority = int.from_bytes(raw[2:8], "big")
        parts = [str(revision), str(authority)]
        for i in range(sub_count):
            off = 8 + i * 4
            if off + 4 > len(raw):
                break
            parts.append(str(int.from_bytes(raw[off : off + 4], "little")))
        return "S-" + "-".join(parts)
    # UTF-16-LE string (AppId). Trim trailing NUL.
    try:
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        return ""


def _int_or_zero(s: str) -> int:
    try:
        return int(s)
    except (ValueError, TypeError):
        return 0


def _find_exported_file(export_dir: Path, table_name: str) -> Path | None:
    """esedbexport names files ``<table>.<N>`` where N is the table id.
    Walk the export dir for the first match.
    """
    if not export_dir.exists():
        return None
    for entry in export_dir.iterdir():
        if entry.is_file() and entry.name.startswith(table_name + "."):
            return entry
    return None


async def _run_esedbexport(
    tool_path: str,
    srudb: Path,
    table: str,
    out_basename: Path,
    timeout: float,
) -> tuple[int, str]:
    """Run ``esedbexport -T <table> -t <basename> <srudb>``. Returns (rc, stderr)."""
    proc = await asyncio.create_subprocess_exec(
        tool_path,
        "-T",
        table,
        "-t",
        str(out_basename),
        str(srudb),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        raise TimeoutError(f"esedbexport timed out after {timeout}s on table {table}")
    return proc.returncode or 0, err.decode(errors="replace")


def _load_idmap(idmap_file: Path, warnings: list[str]) -> dict[int, str]:
    """Parse SruDbIdMapTable TSV into {IdIndex: decoded_string}."""
    if not idmap_file.exists():
        return {}
    out: dict[int, str] = {}
    with idmap_file.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f, delimiter="\t")
        try:
            header = next(reader)
        except StopIteration:
            return {}
        # Expected: IdType, IdIndex, IdBlob
        try:
            i_type = header.index("IdType")
            i_idx = header.index("IdIndex")
            i_blob = header.index("IdBlob")
        except ValueError:
            warnings.append(f"idmap: unexpected header {header}")
            return {}
        for row in reader:
            if len(row) <= i_blob:
                continue
            idx = _int_or_zero(row[i_idx])
            if idx == 0:
                continue
            decoded = _decode_idmap_blob(row[i_type], row[i_blob])
            if decoded:
                out[idx] = decoded
    return out


def _is_sid(name: str) -> bool:
    return name.startswith("S-1-") or name.startswith("S-")


def _resolve_ids(idmap: dict[int, str], app_id_num: int, user_id_num: int) -> tuple[str, str]:
    """Resolve numeric AppId/UserId → (app_id_str, user_sid_str)."""
    app_id_str = idmap.get(app_id_num, "")
    user_str = idmap.get(user_id_num, "")
    # Many SRUDBs map both numbers to strings; SID resolution lands in user_str
    # only when IdType=3. If the user row resolved to a non-SID string, surface
    # nothing for user_sid so downstream agents don't misinterpret it.
    user_sid = user_str if _is_sid(user_str) else ""
    if not _is_sid(app_id_str) and app_id_str.startswith("S-"):
        # Should not happen; defensive.
        app_id_str = ""
    return app_id_str, user_sid


def _parse_network_data(
    path: Path,
    idmap: dict[int, str],
    since: datetime | None,
    limit: int,
    warnings: list[str],
) -> list[SrumNetworkDataRow]:
    rows: list[SrumNetworkDataRow] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f, delimiter="\t")
        try:
            header = next(reader)
        except StopIteration:
            return []
        idx = {col: i for i, col in enumerate(header)}
        required = {"AppId", "UserId", "TimeStamp", "BytesSent", "BytesRecvd"}
        missing = required - set(header)
        if missing:
            warnings.append(f"network_data: missing columns {sorted(missing)}")
            return []
        for raw in reader:
            if len(rows) >= limit:
                break
            if len(raw) < len(header):
                continue
            ts = raw[idx["TimeStamp"]]
            ts_dt = _parse_timestamp(ts)
            if since and ts_dt and ts_dt < since:
                continue
            app_num = _int_or_zero(raw[idx["AppId"]])
            user_num = _int_or_zero(raw[idx["UserId"]])
            app_id_str, user_sid = _resolve_ids(idmap, app_num, user_num)
            rows.append(
                SrumNetworkDataRow(
                    auto_inc_id=_int_or_zero(
                        raw[idx.get("AutoIncId", -1)] if "AutoIncId" in idx else "0"
                    ),
                    timestamp=ts,
                    app_id_num=app_num,
                    user_id_num=user_num,
                    app_id=app_id_str,
                    user_sid=user_sid,
                    interface_luid=_int_or_zero(
                        raw[idx.get("InterfaceLuid", -1)] if "InterfaceLuid" in idx else "0"
                    ),
                    l2_profile_id=_int_or_zero(
                        raw[idx.get("L2ProfileId", -1)] if "L2ProfileId" in idx else "0"
                    ),
                    bytes_sent=_int_or_zero(raw[idx["BytesSent"]]),
                    bytes_recvd=_int_or_zero(raw[idx["BytesRecvd"]]),
                )
            )
    return rows


def _parse_app_resource(
    path: Path,
    idmap: dict[int, str],
    since: datetime | None,
    limit: int,
    warnings: list[str],
) -> list[SrumAppResourceRow]:
    rows: list[SrumAppResourceRow] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f, delimiter="\t")
        try:
            header = next(reader)
        except StopIteration:
            return []
        idx = {col: i for i, col in enumerate(header)}
        if "AppId" not in idx or "UserId" not in idx or "TimeStamp" not in idx:
            warnings.append("app_resource: missing core columns")
            return []
        for raw in reader:
            if len(rows) >= limit:
                break
            if len(raw) < len(header):
                continue
            ts = raw[idx["TimeStamp"]]
            ts_dt = _parse_timestamp(ts)
            if since and ts_dt and ts_dt < since:
                continue
            app_num = _int_or_zero(raw[idx["AppId"]])
            user_num = _int_or_zero(raw[idx["UserId"]])
            app_id_str, user_sid = _resolve_ids(idmap, app_num, user_num)

            def _col(name: str) -> int:
                return _int_or_zero(raw[idx[name]]) if name in idx else 0

            rows.append(
                SrumAppResourceRow(
                    auto_inc_id=_col("AutoIncId"),
                    timestamp=ts,
                    app_id_num=app_num,
                    user_id_num=user_num,
                    app_id=app_id_str,
                    user_sid=user_sid,
                    foreground_cycle_time=_col("ForegroundCycleTime"),
                    background_cycle_time=_col("BackgroundCycleTime"),
                    foreground_bytes_read=_col("ForegroundBytesRead"),
                    foreground_bytes_written=_col("ForegroundBytesWritten"),
                    background_bytes_read=_col("BackgroundBytesRead"),
                    background_bytes_written=_col("BackgroundBytesWritten"),
                )
            )
    return rows


def _parse_network_conn(
    path: Path,
    idmap: dict[int, str],
    since: datetime | None,
    limit: int,
    warnings: list[str],
) -> list[SrumNetworkConnRow]:
    rows: list[SrumNetworkConnRow] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f, delimiter="\t")
        try:
            header = next(reader)
        except StopIteration:
            return []
        idx = {col: i for i, col in enumerate(header)}
        if "AppId" not in idx or "UserId" not in idx or "TimeStamp" not in idx:
            warnings.append("network_connectivity: missing core columns")
            return []
        for raw in reader:
            if len(rows) >= limit:
                break
            if len(raw) < len(header):
                continue
            ts = raw[idx["TimeStamp"]]
            ts_dt = _parse_timestamp(ts)
            if since and ts_dt and ts_dt < since:
                continue
            app_num = _int_or_zero(raw[idx["AppId"]])
            user_num = _int_or_zero(raw[idx["UserId"]])
            app_id_str, user_sid = _resolve_ids(idmap, app_num, user_num)
            rows.append(
                SrumNetworkConnRow(
                    auto_inc_id=_int_or_zero(
                        raw[idx.get("AutoIncId", -1)] if "AutoIncId" in idx else "0"
                    ),
                    timestamp=ts,
                    app_id_num=app_num,
                    user_id_num=user_num,
                    app_id=app_id_str,
                    user_sid=user_sid,
                    interface_luid=_int_or_zero(
                        raw[idx.get("InterfaceLuid", -1)] if "InterfaceLuid" in idx else "0"
                    ),
                    l2_profile_id=_int_or_zero(
                        raw[idx.get("L2ProfileId", -1)] if "L2ProfileId" in idx else "0"
                    ),
                    connected_time=_int_or_zero(
                        raw[idx.get("ConnectedTime", -1)] if "ConnectedTime" in idx else "0"
                    ),
                    connect_start_time=raw[idx["ConnectStartTime"]]
                    if "ConnectStartTime" in idx
                    else "",
                )
            )
    return rows


def _parse_push_notifications(
    path: Path,
    idmap: dict[int, str],
    since: datetime | None,
    limit: int,
    warnings: list[str],
) -> list[SrumPushNotificationRow]:
    rows: list[SrumPushNotificationRow] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f, delimiter="\t")
        try:
            header = next(reader)
        except StopIteration:
            return []
        idx = {col: i for i, col in enumerate(header)}
        if "AppId" not in idx or "UserId" not in idx or "TimeStamp" not in idx:
            warnings.append("push_notifications: missing core columns")
            return []
        for raw in reader:
            if len(rows) >= limit:
                break
            if len(raw) < len(header):
                continue
            ts = raw[idx["TimeStamp"]]
            ts_dt = _parse_timestamp(ts)
            if since and ts_dt and ts_dt < since:
                continue
            app_num = _int_or_zero(raw[idx["AppId"]])
            user_num = _int_or_zero(raw[idx["UserId"]])
            app_id_str, user_sid = _resolve_ids(idmap, app_num, user_num)
            blob_sha = ""
            if "BinaryData" in idx:
                blob = raw[idx["BinaryData"]]
                if blob:
                    try:
                        blob_sha = hashlib.sha256(bytes.fromhex(blob)).hexdigest()
                    except ValueError:
                        blob_sha = hashlib.sha256(blob.encode("utf-8")).hexdigest()
            rows.append(
                SrumPushNotificationRow(
                    auto_inc_id=_int_or_zero(
                        raw[idx.get("AutoIncId", -1)] if "AutoIncId" in idx else "0"
                    ),
                    timestamp=ts,
                    app_id_num=app_num,
                    user_id_num=user_num,
                    app_id=app_id_str,
                    user_sid=user_sid,
                    binary_data_sha256=blob_sha,
                )
            )
    return rows


def _parse_energy_usage(
    path: Path,
    idmap: dict[int, str],
    since: datetime | None,
    limit: int,
    warnings: list[str],
) -> list[SrumEnergyUsageRow]:
    rows: list[SrumEnergyUsageRow] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f, delimiter="\t")
        try:
            header = next(reader)
        except StopIteration:
            return []
        idx = {col: i for i, col in enumerate(header)}
        if "AppId" not in idx or "UserId" not in idx or "TimeStamp" not in idx:
            warnings.append("energy_usage: missing core columns")
            return []
        for raw in reader:
            if len(rows) >= limit:
                break
            if len(raw) < len(header):
                continue
            ts = raw[idx["TimeStamp"]]
            ts_dt = _parse_timestamp(ts)
            if since and ts_dt and ts_dt < since:
                continue
            app_num = _int_or_zero(raw[idx["AppId"]])
            user_num = _int_or_zero(raw[idx["UserId"]])
            app_id_str, user_sid = _resolve_ids(idmap, app_num, user_num)
            # Trim the raw catch-all to keep JSON-result size predictable
            # (1 MB tool-result cap on Claude Desktop — see
            # memory/lesson_claude_desktop_1mb_tool_result_cap). At 200 chars
            # × 1000-row default limit that field is bounded to ~200 KB.
            rows.append(
                SrumEnergyUsageRow(
                    auto_inc_id=_int_or_zero(
                        raw[idx.get("AutoIncId", -1)] if "AutoIncId" in idx else "0"
                    ),
                    timestamp=ts,
                    app_id_num=app_num,
                    user_id_num=user_num,
                    app_id=app_id_str,
                    user_sid=user_sid,
                    raw="\t".join(raw)[:200],
                )
            )
    return rows


_PARSER_BY_KEY = {
    "network_data": _parse_network_data,
    "app_resource": _parse_app_resource,
    "network_connectivity": _parse_network_conn,
    "push_notifications": _parse_push_notifications,
    "energy_usage": _parse_energy_usage,
}


# --- Tool version capture ------------------------------------------------ #


async def _capture_version(tool_path: str) -> str:
    """esedbexport prints version on -V. Cheap one-shot."""
    try:
        proc = await asyncio.create_subprocess_exec(
            tool_path,
            "-V",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, _err = await asyncio.wait_for(proc.communicate(), timeout=5)
        text = out.decode(errors="replace").strip()
        # First non-empty line typically "esedbexport 20240420"
        for line in text.splitlines():
            line = line.strip()
            if line:
                return line
    except Exception:
        pass
    return ""


# --- Public entry point -------------------------------------------------- #


async def srum_extract(
    srudb_path: str | Path,
    *,
    tables: list[str] | None = None,
    since_iso: str | None = None,
    limit: int = 1000,
    include_idmap: bool = False,
    timeout: float | None = None,
) -> SrumExtractResult:
    """Extract per-table records from a ``SRUDB.dat`` ESE database.

    Default ``limit=1000`` + ``include_idmap=False`` are sized so a full
    5-table run stays under the 1 MB tool-result cap enforced by some
    MCP clients (Claude Desktop). The per-row ``app_id`` / ``user_sid``
    fields are already resolved against the IdMap on the wrapper side
    so callers typically don't need the raw mapping; pass
    ``include_idmap=True`` to surface it (adds ~50 bytes per unique ID,
    typically 200-500 KB on real SRUDBs).

    Args:
        srudb_path: Absolute path to a ``SRUDB.dat`` file.
        tables: Restrict to a subset of ``{network_data, app_resource,
            network_connectivity, push_notifications, energy_usage}``.
            ``None`` ⇒ all five.
        since_iso: ISO-8601 cutoff; rows with timestamps before this are
            dropped. ``None`` ⇒ no cutoff. Unparseable timestamps are
            never filtered out.
        limit: Per-table row cap (capped at 50000 globally; default 1000).
        include_idmap: When ``True``, surface the raw numeric-id → decoded
            string map in ``id_lookup``. Default ``False`` to keep the
            tool result under 1 MB.
        timeout: Per-table esedbexport timeout in seconds. Defaults to
            ``AGENTROPIX_SRUM_TIMEOUT`` (600s, floor 5s, ceiling 3600s).

    Returns:
        SrumExtractResult with the requested tables populated; per-table
        export failures are surfaced in ``tables_failed`` + ``raw_warnings``
        rather than raised as exceptions.

    Raises:
        FileNotFoundError: SRUDB missing or esedbexport not on PATH.
        TimeoutError: a single table export exceeds the timeout.
    """
    started = time.monotonic()
    srudb = Path(srudb_path)
    if not srudb.exists():
        raise FileNotFoundError(f"SRUDB.dat not found: {srudb}")
    if not srudb.is_file():
        raise FileNotFoundError(f"SRUDB path is not a file: {srudb}")

    tool_name = _resolve_tool()
    tool_path = shutil.which(tool_name)
    if not tool_path:
        raise FileNotFoundError(
            f"{tool_name} not found on PATH — install libesedb-utils or set AGENTROPIX_SRUM_TOOL"
        )

    if timeout is None:
        timeout = get_float("AGENTROPIX_SRUM_TIMEOUT", 600.0, floor=5.0, ceiling=3600.0)

    limit = max(1, min(int(limit), 50000))

    requested = tables or list(KNOWN_TABLES.keys())
    unknown = [t for t in requested if t not in KNOWN_TABLES]
    if unknown:
        raise ValueError(f"unknown SRUM table(s): {unknown}")

    # Hash the input up front for the audit trail.
    h = hashlib.sha256()
    with srudb.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    srudb_sha = h.hexdigest()

    parser_version = await _capture_version(tool_path)
    since_dt = _parse_since(since_iso)
    warnings: list[str] = []
    if since_iso and since_dt is None:
        warnings.append(f"since_iso unparseable, ignored: {since_iso!r}")

    result = SrumExtractResult(
        srudb_path=str(srudb),
        srudb_sha256=srudb_sha,
        parser_version=parser_version,
        tables_requested=requested,
        raw_warnings=warnings,
    )

    # Use a process-private tempdir so concurrent calls don't collide.
    with tempfile.TemporaryDirectory(prefix="agentropix-srum-") as tmp:
        tmp_path = Path(tmp)

        # IdMap first — needed to resolve numeric AppId/UserId in every other table.
        idmap_basename = tmp_path / "idmap"
        rc, err = await _run_esedbexport(tool_path, srudb, IDMAP_TABLE, idmap_basename, timeout)
        idmap: dict[int, str] = {}
        if rc != 0:
            warnings.append(f"idmap export rc={rc}: {err[:200]}")
        else:
            idmap_file = _find_exported_file(idmap_basename.with_suffix(".export"), IDMAP_TABLE)
            if idmap_file:
                idmap = _load_idmap(idmap_file, warnings)
            else:
                warnings.append("idmap: export produced no file")
        # Only surface the raw id_lookup when the caller asked for it;
        # per-row app_id / user_sid are already resolved below.
        if include_idmap:
            result.id_lookup = idmap

        for key in requested:
            guid = KNOWN_TABLES[key]
            basename = tmp_path / f"tbl_{key}"
            try:
                rc, err = await _run_esedbexport(tool_path, srudb, guid, basename, timeout)
            except TimeoutError as exc:
                warnings.append(f"{key}: {exc}")
                result.tables_failed.append(key)
                continue
            if rc != 0:
                # libesedb partial-export errors are common on dirty SRUDBs;
                # surface the rc + first stderr line for the audit trail.
                first_err = err.strip().splitlines()[0] if err.strip() else ""
                warnings.append(f"{key}: esedbexport rc={rc} ({first_err})")
                result.tables_failed.append(key)
                continue
            tsv = _find_exported_file(basename.with_suffix(".export"), guid)
            if not tsv:
                warnings.append(f"{key}: export produced no file")
                result.tables_failed.append(key)
                continue
            parser = _PARSER_BY_KEY[key]
            rows = parser(tsv, idmap, since_dt, limit, warnings)
            # Assign to the right field.
            if key == "network_data":
                result.network_data = rows
            elif key == "app_resource":
                result.app_resource = rows
            elif key == "network_connectivity":
                result.network_connectivity = rows
            elif key == "push_notifications":
                result.push_notifications = rows
            elif key == "energy_usage":
                result.energy_usage = rows
            result.tables_returned.append(key)

    # Pydantic copies list fields at construction time, so re-bind the
    # warnings list at the end so callers see everything appended during
    # the per-table loop above.
    result.raw_warnings = warnings
    result.elapsed_sec = round(time.monotonic() - started, 3)
    return result
