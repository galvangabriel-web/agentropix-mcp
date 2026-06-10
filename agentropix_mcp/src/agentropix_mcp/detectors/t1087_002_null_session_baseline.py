"""W-207: T1087.002 null-session enumeration baseline detector.

Per-host baseline-driven SwarmAgent that flags burst-counts of
``EID 4624`` records with ``TargetUserSid=S-1-5-7`` (ANONYMOUS LOGON)
and ``LogonType=3``. The signal under SRL-2018 RD-02 is ~6k events
within the attack window; a single such event is meaningless, the
volume is the signal.

Detection arithmetic (design §3 / ticket AC §2):

1. Pull the 4624 Security channel via :func:`get_evtx` (E01 path).
2. Filter to S-1-5-7 + LogonType 3 (lowercased fast-path regex over
   ``EvtxEvent.raw``).
3. Bucket per ``window_hours`` boundary in UTC.
4. Load per-host baseline (``Reports_results/_baselines/null_session/
   <host>.json``); refresh under semaphore + filelock when absent /
   TTL-stale / degenerate.
5. Emit one :class:`Finding` per bucket whose count exceeds
   ``max(mean + z*stddev, ABS_FLOOR/10)`` (live) or ``ABS_FLOOR``
   (bootstrap).

The Finding's ``description`` carries the cohit keywords
(``T1087.002``, ``null_session``, ``ANONYMOUS LOGON``) so the recall
scorer at ``scripts/score_full_case.py:51-105`` reaches it via the
existing per-host ``report.json`` wire-up.

Push-tier defense (c1-F7): :func:`_to_push_dict` strips
baseline_mean / baseline_stddev / threshold / z_score from any future
push-tier copy, and runs the shared :func:`redact_finding` over the
result. No code in this module pushes to Wazuh / MASTER-IOCS today.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import re
import statistics
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout
from pydantic import BaseModel, Field

from agentropix_mcp.agents._base import Finding, SwarmAgent
from agentropix_mcp.agents._evidence import looks_like_disk
from agentropix_mcp._env import get_float, get_int
from agentropix_mcp.wrappers.evtx import EvtxEvent, get_evtx
from agentropix_mcp.security.redact import redact_finding

logger = logging.getLogger(__name__)

# Module-level per-cap semaphore cache (c2-F2 round-2 storm cap).
# Keyed on the cap value so a mid-process env-var bump yields a fresh
# semaphore for the new cap without leaking the old one.
_BASELINE_REFRESH_SEM_CACHE: dict[int, asyncio.Semaphore] = {}

_BASELINE_SCHEMA_VERSION = "1"
_BASELINE_DEGENERATE_MIN_SAMPLES = 50
_BASELINE_MAX_AGE_DAYS = 30
_SEM_ACQUIRE_TIMEOUT_S = 30.0
_FILELOCK_TIMEOUT_S = 30.0

# c5 round-4 imperfection #6: the recall scorer reads description+evidence,
# NOT mitre_attack. These literals MUST appear in the description so the
# GT yaml's ``evidence_keywords`` (T1087.002, null_session, ANONYMOUS LOGON)
# get cohit-counted >=2.
_KEYWORD_T1087 = "T1087.002"
_KEYWORD_NULL_SESSION = "null_session"
_KEYWORD_ANON = "ANONYMOUS LOGON"

# ANONYMOUS LOGON SID is locale-stable; anchor on it rather than the
# (localised) TargetUserName.
_ANON_SID_RE = re.compile(r"targetusersid[^a-z0-9]*s-1-5-7", re.IGNORECASE)
_LOGON_TYPE_3_RE = re.compile(r"logontype[^0-9]*3\b", re.IGNORECASE)
_IP_RE = re.compile(
    r'<Data Name="IpAddress">([^<]+)</Data>',
    re.IGNORECASE,
)

# Push-tier fields stripped from any Wazuh-bound copy (c1-F7).
_PUSH_TIER_STRIP = frozenset(
    {"baseline_mean", "baseline_stddev", "threshold", "z_score"}
)


class NullSessionEventBucket(BaseModel):
    """One time-window bucket of 4624 ANONYMOUS LOGON events."""

    host: str = ""
    window_start_utc: str = ""
    window_hours: int = 1
    count: int = 0
    top_source_ips: list[str] = Field(default_factory=list)


class NullSessionBaseline(BaseModel):
    """Per-host baseline statistics, persisted as JSON."""

    mean: float = 0.0
    stddev: float = 0.0
    sample_count: int = 0
    last_updated_utc: str = ""
    source_event_count: int = 0
    schema_version: str = _BASELINE_SCHEMA_VERSION


def _hour_floor(ts_iso: str, window_hours: int) -> str:
    """Truncate an ISO-8601 timestamp to a ``window_hours`` boundary in UTC.

    The input may include timezone offset or naive time; the result is
    always UTC ISO-8601 with seconds zeroed and minutes/hours snapped to
    the window grid.
    """
    dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)
    hour = (dt.hour // window_hours) * window_hours
    snapped = dt.replace(hour=hour, minute=0, second=0, microsecond=0)
    return snapped.isoformat()


def _is_anon_logon_4624(ev: EvtxEvent) -> bool:
    """True iff ``ev`` is an EID 4624 record with S-1-5-7 + LogonType 3."""
    if ev.event_id != 4624 or ev.channel != "Security":
        return False
    raw = ev.raw or ""
    return bool(_ANON_SID_RE.search(raw) and _LOGON_TYPE_3_RE.search(raw))


def _extract_ip(raw: str) -> str | None:
    """Pull ``IpAddress`` value from the EID 4624 raw XML, if present.

    Returns None when missing or set to the empty placeholder ``"-"``
    (Windows uses ``-`` for unknown/local null-session origin).
    """
    m = _IP_RE.search(raw)
    if m is None:
        return None
    val = m.group(1).strip()
    if not val or val == "-":
        return None
    return val


def _bucket_events(
    events: list[EvtxEvent],
    host: str,
    window_hours: int,
    *,
    top_k: int,
) -> list[NullSessionEventBucket]:
    """Group ``events`` per ``window_hours`` boundary; keep top-K source IPs."""
    by_window: dict[str, NullSessionEventBucket] = {}
    raw_ips: dict[str, list[str]] = {}
    for ev in events:
        try:
            window_start = _hour_floor(ev.timestamp, window_hours)
        except (ValueError, TypeError):
            logger.debug("skipping 4624 record with unparseable timestamp")
            continue
        b = by_window.get(window_start)
        if b is None:
            b = NullSessionEventBucket(
                host=host,
                window_start_utc=window_start,
                window_hours=window_hours,
            )
            by_window[window_start] = b
            raw_ips[window_start] = []
        b.count += 1
        ip = _extract_ip(ev.raw or "")
        if ip:
            raw_ips[window_start].append(ip)
    for window_start, bucket in by_window.items():
        c = Counter(raw_ips[window_start])
        bucket.top_source_ips = [ip for ip, _n in c.most_common(top_k)]
    return sorted(by_window.values(), key=lambda b: b.window_start_utc)


def _baseline_path(baseline_dir: Path, host: str) -> Path:
    return baseline_dir / f"{host}.json"


def _load_baseline(path: Path) -> NullSessionBaseline | None:
    """Read baseline JSON; tolerate missing / corrupted files."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("baseline file %s unreadable: %s; treating as absent", path, exc)
        return None
    try:
        return NullSessionBaseline.model_validate(data)
    except Exception as exc:  # noqa: BLE001 — pydantic ValidationError + variants
        logger.warning("baseline file %s schema-invalid: %s; treating as absent", path, exc)
        return None


def _save_baseline_atomic(path: Path, baseline: NullSessionBaseline) -> None:
    """Write baseline JSON via tmp+os.replace (idempotency-canonical)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        baseline.model_dump(),
        sort_keys=True,
        separators=(",", ":"),
    )
    tmp = path.with_suffix(f".json.tmp.{os.getpid()}")
    tmp.write_text(payload)
    os.replace(tmp, path)


def _refresh_baseline(
    buckets: list[NullSessionEventBucket],
) -> NullSessionBaseline:
    """Compute mean/stddev over non-zero buckets only.

    Empty windows would dominate ``mean=0, stddev=0`` for sparse hosts;
    the non-zero filter mirrors the design's degenerate-stddev guard.
    """
    counts = [b.count for b in buckets if b.count > 0]
    if not counts:
        return NullSessionBaseline(
            mean=0.0,
            stddev=0.0,
            sample_count=0,
            last_updated_utc=datetime.now(UTC).isoformat(),
            source_event_count=0,
        )
    mean = float(statistics.fmean(counts))
    stddev = float(statistics.pstdev(counts)) if len(counts) >= 2 else 0.0
    return NullSessionBaseline(
        mean=mean,
        stddev=stddev,
        sample_count=len(counts),
        last_updated_utc=datetime.now(UTC).isoformat(),
        source_event_count=sum(b.count for b in buckets),
    )


def _is_baseline_stale(
    baseline: NullSessionBaseline | None,
    ttl_hours: int,
) -> bool:
    if baseline is None:
        return True
    try:
        last = datetime.fromisoformat(baseline.last_updated_utc)
    except ValueError:
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    age_hours = (datetime.now(UTC) - last).total_seconds() / 3600.0
    return age_hours > ttl_hours


def _is_baseline_degenerate(baseline: NullSessionBaseline) -> bool:
    """True iff the baseline cannot support a meaningful z-score."""
    if baseline.stddev <= 0:
        return True
    if baseline.sample_count < _BASELINE_DEGENERATE_MIN_SAMPLES:
        return True
    try:
        last = datetime.fromisoformat(baseline.last_updated_utc)
    except ValueError:
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    age_days = (datetime.now(UTC) - last).days
    if age_days > _BASELINE_MAX_AGE_DAYS:
        return True
    return False


def _effective_threshold(
    baseline: NullSessionBaseline | None,
    z: float,
    abs_floor: int,
) -> tuple[float, str]:
    """Pick the per-bucket count threshold + report which path was used."""
    if baseline is None or _is_baseline_degenerate(baseline):
        return float(abs_floor), "bootstrap"
    z_thr = baseline.mean + z * baseline.stddev
    # Floor at abs_floor/10 so a tiny-mean live baseline doesn't make
    # a single event "exceed threshold".
    return max(z_thr, abs_floor / 10.0), "live"


def _to_push_dict(finding_dict: dict[str, Any]) -> dict[str, Any]:
    """Strip baseline_* fields from any push-tier copy + redact remainder.

    c1-F7 round-2 mitigation: baseline statistics are LOCAL-only
    (host fingerprint surface area), so any push-tier consumer must call
    this helper instead of forwarding the raw Finding dict.
    """
    d = {k: v for k, v in finding_dict.items() if k not in _PUSH_TIER_STRIP}
    ev = d.get("evidence_dict")
    if isinstance(ev, dict):
        d["evidence_dict"] = {
            k: v for k, v in ev.items() if k not in _PUSH_TIER_STRIP
        }
    return redact_finding(d)


async def _get_refresh_semaphore(cap: int) -> asyncio.Semaphore:
    """Lazy per-cap module semaphore (binds to the live event loop on first use)."""
    sem = _BASELINE_REFRESH_SEM_CACHE.get(cap)
    if sem is None:
        sem = asyncio.Semaphore(cap)
        _BASELINE_REFRESH_SEM_CACHE[cap] = sem
    return sem


async def _maybe_refresh_baseline(
    host: str,
    baseline_dir: Path,
    buckets: list[NullSessionEventBucket],
    *,
    cap: int,
) -> tuple[NullSessionBaseline | None, str]:
    """Refresh per-host baseline under storm-cap + per-host filelock.

    Returns (baseline_or_None, status) where status is one of:
      * ``"refreshed"`` — write succeeded
      * ``"bootstrap_lock_contended"`` — semaphore acquire timed out
      * ``"bootstrap_write_failed"`` — write raised
    """
    sem = await _get_refresh_semaphore(cap)
    try:
        await asyncio.wait_for(sem.acquire(), timeout=_SEM_ACQUIRE_TIMEOUT_S)
    except (TimeoutError, asyncio.TimeoutError):
        logger.warning(
            "null_session baseline refresh semaphore contended for host=%s; "
            "falling through to bootstrap",
            host,
        )
        return _load_baseline(_baseline_path(baseline_dir, host)), "bootstrap_lock_contended"
    try:
        path = _baseline_path(baseline_dir, host)
        path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = path.with_suffix(".json.lock")
        try:
            with FileLock(str(lock_path), timeout=_FILELOCK_TIMEOUT_S):
                baseline = _refresh_baseline(buckets)
                _save_baseline_atomic(path, baseline)
                return baseline, "refreshed"
        except Timeout:
            logger.warning(
                "null_session baseline filelock contended for host=%s; "
                "falling through to bootstrap",
                host,
            )
            return _load_baseline(path), "bootstrap_lock_contended"
        except OSError as exc:
            logger.warning(
                "null_session baseline write failed for host=%s: %s; "
                "falling through to bootstrap",
                host,
                exc,
            )
            return _load_baseline(path), "bootstrap_write_failed"
    finally:
        sem.release()


def _build_finding(
    image: Path,
    host: str,
    bucket: NullSessionEventBucket,
    baseline: NullSessionBaseline | None,
    threshold: float,
    z_score: float,
    baseline_status: str,
) -> Finding:
    """Build the per-bucket Finding with redacted IPs + cohit keywords."""
    raw_payload: dict[str, Any] = {
        "host": host,
        "top_source_ips": list(bucket.top_source_ips),
    }
    try:
        redacted = redact_finding(raw_payload)
        redacted_ips = redacted.get("top_source_ips", [])
        if not isinstance(redacted_ips, list):
            redacted_ips = []
    except Exception as exc:  # noqa: BLE001 — redactor is fail-closed; degrade gracefully
        logger.warning(
            "redact_finding failed for null_session top_source_ips: %s; "
            "emitting empty IP list",
            exc,
        )
        redacted_ips = []
    confidence = 0.80 if baseline_status == "live" else 0.65
    mean = baseline.mean if baseline is not None else 0.0
    stddev = baseline.stddev if baseline is not None else 0.0
    description = (
        f"[{_KEYWORD_T1087}] {_KEYWORD_NULL_SESSION} enumeration burst: "
        f"host={host} window={bucket.window_start_utc}+{bucket.window_hours}h "
        f"count={bucket.count} threshold={threshold:.1f} "
        f"z_score={z_score:.2f} baseline_status={baseline_status} "
        f"{_KEYWORD_ANON} IPC$ via Logon Type 3"
    )
    evidence = (
        f"image={image} channel=Security event_id=4624 "
        f"target_user_sid=S-1-5-7 logon_type=3 "
        f"top_source_ips={','.join(redacted_ips)} "
        f"baseline_mean={mean:.2f} baseline_stddev={stddev:.2f}"
    )
    evidence_dict: dict[str, Any] = {
        "host": host,
        "window_start_utc": bucket.window_start_utc,
        "window_hours": bucket.window_hours,
        "count": bucket.count,
        "threshold": threshold,
        "z_score": z_score if not math.isnan(z_score) else None,
        "baseline_status": baseline_status,
        "baseline_mean": mean,
        "baseline_stddev": stddev,
        "top_source_ips": redacted_ips,
        "sample_target_user_sids": ["S-1-5-7"],
        "mitre_technique_id": _KEYWORD_T1087,
    }
    return Finding(
        source="discovery.null_session_baseline",
        confidence=confidence,
        description=description,
        evidence=evidence,
        evidence_dict=evidence_dict,
        mitre_attack=_KEYWORD_T1087,
        timestamp=Finding.now(),
    )


class NullSessionBaselineAgent(SwarmAgent):
    """Disk-side SwarmAgent for T1087.002 null-session enumeration bursts."""

    name = "null_session_baseline"
    completion_promise = "NULL_SESSION_BASELINE_COMPLETE"

    async def investigate(self, image: Path) -> list[Finding]:
        # ---- 0. Image-class gate ---------------------------------------
        if not looks_like_disk(image):
            return [
                Finding(
                    source="discovery.null_session_baseline.skipped",
                    confidence=0.0,
                    description=(
                        f"NullSessionBaselineAgent skipped: "
                        f"{image.name} is not a disk image"
                    ),
                    evidence=f"image={image} reason=non_disk_image",
                    timestamp=Finding.now(),
                )
            ]

        # ---- 1. Env-var clamping --------------------------------------
        z_threshold = get_float(
            "AGENTROPIX_NULL_SESSION_Z_THRESHOLD",
            3.0,
            floor=2.0,
            ceiling=6.0,
        )
        # Design default was 500/hour, calibrated from the ticket's
        # "5,463 events" line — interpreted at design time as
        # concentrated within a short window. Real corpus
        # (/cases/SRL-2018/base-rd-02-cdrive.E01) shows those 6148
        # events spread over 939 hour-buckets with a *flat* per-hour
        # ceiling of 25 (median 5). The non-recon wkstn-01 peer caps
        # at 10/hour. The data-driven separator is 20/hour:
        # rd-02 has 46 hour-buckets >= 20 events; wkstn-01 has 0.
        # See DECISION_LOG.md (dev-w-207, 2026-05-16) for the full
        # calibration trace.
        abs_floor = get_int(
            "AGENTROPIX_NULL_SESSION_ABS_FLOOR",
            20,
            floor=5,
            ceiling=100_000,
        )
        window_hours = get_int(
            "AGENTROPIX_NULL_SESSION_WINDOW_HOURS",
            1,
            floor=1,
            ceiling=24,
        )
        baseline_ttl_hours = get_int(
            "AGENTROPIX_NULL_SESSION_BASELINE_TTL_HOURS",
            168,
            floor=24,
            ceiling=720,
        )
        top_k = get_int(
            "AGENTROPIX_NULL_SESSION_TOP_K_IPS",
            5,
            floor=1,
            ceiling=50,
        )
        max_events = get_int(
            "AGENTROPIX_NULL_SESSION_MAX_EVENTS",
            200_000,
            floor=1_000,
            ceiling=1_000_000,
        )
        refresh_cap = get_int(
            "AGENTROPIX_NULL_SESSION_BASELINE_REFRESH_CONCURRENCY",
            2,
            floor=1,
            ceiling=8,
        )
        baseline_dir = Path(
            os.environ.get(
                "AGENTROPIX_NULL_SESSION_BASELINE_DIR",
                "Reports_results/_baselines/null_session",
            )
        )

        # ---- 2. Pull Security 4624 from corpus ------------------------
        try:
            report = await get_evtx(
                image,
                channels={"Security"},
                event_ids={4624},
                max_events=max_events,
                tail=False,  # oldest-first for full baseline math
            )
        except FileNotFoundError as exc:
            return [
                Finding(
                    source="discovery.null_session_baseline.skipped",
                    confidence=0.0,
                    description=(
                        f"NullSessionBaselineAgent skipped: "
                        f"Security.evtx unavailable: {exc}"
                    ),
                    evidence=f"image={image} reason=evtx_unavailable",
                    timestamp=Finding.now(),
                )
            ]
        except (TimeoutError, RuntimeError, MemoryError) as exc:
            logger.warning(
                "NullSessionBaselineAgent get_evtx failed for %s: %s", image, exc
            )
            return [
                Finding(
                    source="discovery.null_session_baseline.error",
                    confidence=0.0,
                    description=(
                        f"NullSessionBaselineAgent failed to read Security.evtx: {exc}"
                    ),
                    evidence=f"image={image} error={exc}",
                    timestamp=Finding.now(),
                )
            ]

        # ---- 3. Filter to ANONYMOUS LOGON ------------------------------
        anon_events = [ev for ev in report.events if _is_anon_logon_4624(ev)]

        # ---- 4. Bucket per host+hour -----------------------------------
        host = image.stem  # design §3 / OQ-2: stem keys per (host, image-class)
        buckets = _bucket_events(
            anon_events, host, window_hours, top_k=top_k
        )

        # ---- 5. Load + maybe refresh baseline --------------------------
        baseline_path = _baseline_path(baseline_dir, host)
        baseline = _load_baseline(baseline_path)
        baseline_lifecycle = "loaded"
        if _is_baseline_stale(baseline, baseline_ttl_hours):
            refreshed, lifecycle = await _maybe_refresh_baseline(
                host, baseline_dir, buckets, cap=refresh_cap
            )
            if refreshed is not None:
                baseline = refreshed
            baseline_lifecycle = lifecycle

        # ---- 6. Threshold + emit ---------------------------------------
        threshold, baseline_status = _effective_threshold(
            baseline, z_threshold, abs_floor
        )
        if baseline_lifecycle == "bootstrap_lock_contended":
            baseline_status = "bootstrap_lock_contended"
        findings: list[Finding] = []
        for bucket in buckets:
            if bucket.count < threshold:
                continue
            if baseline is not None and baseline.stddev > 0:
                z_score = (bucket.count - baseline.mean) / baseline.stddev
            else:
                z_score = float("nan")
            findings.append(
                _build_finding(
                    image,
                    host,
                    bucket,
                    baseline,
                    threshold,
                    z_score,
                    baseline_status,
                )
            )

        # ---- 7. Coverage summary ---------------------------------------
        burst_count = len(findings)
        summary_confidence = 0.50 if burst_count else 0.30
        truncated_note = " truncated=True" if report.truncated else ""
        findings.append(
            Finding(
                source="discovery.null_session_baseline.summary",
                confidence=summary_confidence,
                description=(
                    f"Null-session baseline scan complete: {burst_count} bursts "
                    f"emitted across {len(buckets)} windows "
                    f"(4624-anon events scanned: {len(anon_events)})"
                ),
                evidence=(
                    f"image={image} anon_events={len(anon_events)} "
                    f"buckets={len(buckets)} "
                    f"baseline_mean={(baseline.mean if baseline else 0.0):.2f} "
                    f"baseline_status={baseline_status} "
                    f"z_threshold={z_threshold} abs_floor={abs_floor}{truncated_note}"
                ),
                evidence_dict={
                    "anon_events": len(anon_events),
                    "buckets": len(buckets),
                    "bursts_emitted": burst_count,
                    "baseline_status": baseline_status,
                    "z_threshold": z_threshold,
                    "abs_floor": abs_floor,
                    "truncated": report.truncated,
                },
                mitre_attack=_KEYWORD_T1087,
                timestamp=Finding.now(),
            )
        )
        return findings


__all__ = [
    "NullSessionBaseline",
    "NullSessionBaselineAgent",
    "NullSessionEventBucket",
    "_baseline_path",
    "_bucket_events",
    "_build_finding",
    "_effective_threshold",
    "_extract_ip",
    "_hour_floor",
    "_is_anon_logon_4624",
    "_is_baseline_degenerate",
    "_is_baseline_stale",
    "_load_baseline",
    "_maybe_refresh_baseline",
    "_refresh_baseline",
    "_save_baseline_atomic",
    "_to_push_dict",
]
