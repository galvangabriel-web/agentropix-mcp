"""Live threat intelligence lookups via VirusTotal v3 and AlienVault OTX (W-118).

EGRESS-GATED: all network calls require AGENTROPIX_ALLOW_EGRESS=1.  Default posture
is to register the tool but return an egress-disabled shim on every call.

Provider allowlist: AGENTROPIX_TI_PROVIDERS (comma-separated; default: virustotal,otx).
Timeout: AGENTROPIX_TI_TIMEOUT seconds (floor 30, ceiling 300, default 60).
API keys: ~/.openclaw/credentials/threat_intel.json (mode 0600) or env vars
  AGENTROPIX_VT_API_KEY / AGENTROPIX_OTX_API_KEY.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import stat
import time
from pathlib import Path
from typing import Any

from agentropix_mcp._env import clamp_float, get_float, get_str_set

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VT_BASE = "https://www.virustotal.com/api/v3"
_OTX_BASE = "https://otx.alienvault.com/api/v1"
_CREDS_FILE = Path.home() / ".openclaw" / "credentials" / "threat_intel.json"
_ALL_PROVIDERS: frozenset[str] = frozenset({"virustotal", "otx"})
_USER_AGENT = "Agentropix-SIFT-TI/1.0"

_DEFAULT_TIMEOUT_S = 60.0
_TIMEOUT_FLOOR_S = 30.0
_TIMEOUT_CEILING_S = 300.0

# ---------------------------------------------------------------------------
# Per-provider rate limiters (process-global, min inter-call interval)
# ---------------------------------------------------------------------------


class _ProviderRateLimiter:
    """Enforces a minimum interval between successive calls to one provider."""

    def __init__(self, calls_per_minute: int) -> None:
        self._min_interval = 60.0 / max(1, calls_per_minute)
        self._last_call: float = 0.0
        self._lock: asyncio.Lock | None = None

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def acquire(self) -> None:
        async with self._get_lock():
            now = time.monotonic()
            wait = self._min_interval - (now - self._last_call)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = time.monotonic()


_VT_RATE_LIMITER = _ProviderRateLimiter(4)     # VT free: 4 req/min
_OTX_RATE_LIMITER = _ProviderRateLimiter(600)  # OTX: 10K/hour ≈ 166/min

# ---------------------------------------------------------------------------
# Credential loading
# ---------------------------------------------------------------------------

_CACHED_CREDS: dict[str, Any] | None = None
_CREDS_LOAD_ERROR: str = ""


def _load_credentials() -> dict[str, Any]:
    """Load API keys from env vars then credentials file (file takes precedence)."""
    global _CACHED_CREDS, _CREDS_LOAD_ERROR
    if _CACHED_CREDS is not None:
        return _CACHED_CREDS

    creds: dict[str, Any] = {}

    # Env var baseline
    vt_key = os.environ.get("AGENTROPIX_VT_API_KEY", "")
    otx_key = os.environ.get("AGENTROPIX_OTX_API_KEY", "")
    if vt_key:
        creds["virustotal"] = vt_key
    if otx_key:
        creds["otx"] = otx_key

    # Credentials file (overrides env vars if present and mode 0600)
    if _CREDS_FILE.exists():
        try:
            mode = stat.S_IMODE(_CREDS_FILE.stat().st_mode)
            if mode != 0o600:
                _CREDS_LOAD_ERROR = (
                    f"credentials file mode {oct(mode)} != 0600; refusing to load"
                )
                logger.error("threat_intel: %s", _CREDS_LOAD_ERROR)
            else:
                file_creds: dict[str, Any] = json.loads(_CREDS_FILE.read_text())
                for key in ("virustotal", "otx", "misp"):
                    if key in file_creds:
                        creds[key] = file_creds[key]
        except Exception as exc:  # pragma: no cover
            _CREDS_LOAD_ERROR = f"failed to load credentials file: {exc}"
            logger.error("threat_intel: %s", _CREDS_LOAD_ERROR)

    _CACHED_CREDS = creds
    return creds


def _clear_credentials_cache() -> None:
    """Evict cached credentials — test helper so env-var monkeypatches take effect."""
    global _CACHED_CREDS, _CREDS_LOAD_ERROR
    _CACHED_CREDS = None
    _CREDS_LOAD_ERROR = ""


# ---------------------------------------------------------------------------
# IOC type inference
# ---------------------------------------------------------------------------

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]{2,39}$")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}$")


def _infer_ioc_type(indicator: str) -> str:
    """Infer IOC type: "md5" | "sha1" | "sha256" | "ip" | "domain".

    Raises ValueError for PII (email, URL, whitespace) or unrecognised shapes.
    """
    if not indicator or not isinstance(indicator, str):
        raise ValueError("indicator must be a non-empty string")
    if re.search(r"\s", indicator):
        raise ValueError("indicator contains whitespace; rejected (PII guard)")
    if "@" in indicator:
        raise ValueError("indicator contains '@'; rejected (email PII guard)")
    if "/" in indicator:
        raise ValueError("indicator contains '/'; rejected (URL guard — extract bare host/hash first)")

    # Hash detection: hex-only strings of known digest lengths
    if _HEX_RE.match(indicator):
        n = len(indicator)
        if n == 32:
            return "md5"
        if n == 40:
            return "sha1"
        if n == 64:
            return "sha256"

    # IPv4
    m = _IPV4_RE.match(indicator)
    if m:
        octets = [int(m.group(i)) for i in range(1, 5)]
        if all(0 <= o <= 255 for o in octets):
            return "ip"

    # IPv6 (colon separator, hex chars only)
    if ":" in indicator and _IPV6_RE.match(indicator):
        return "ip"

    # Domain
    if _DOMAIN_RE.match(indicator):
        return "domain"

    raise ValueError(f"cannot infer IOC type for indicator {indicator!r}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_vt_stats(stats: dict) -> tuple[int, int, str]:
    """Return (score, score_max, verdict) from VT last_analysis_stats dict."""
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    total = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
    if malicious > 0:
        verdict = "malicious"
    elif suspicious > 0:
        verdict = "suspicious"
    elif total > 0:
        verdict = "clean"
    else:
        verdict = "unknown"
    return malicious, total, verdict


def _unix_to_iso(ts: int | float | None) -> str:
    if not ts:
        return ""
    from datetime import datetime, timezone
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _error_result(provider: str, error: str, *, ok: bool = False) -> dict:
    return {
        "provider": provider, "found": False, "verdict": "unknown",
        "score": None, "score_max": None, "first_seen": "", "last_seen": "",
        "tags": [], "raw_excerpt": "", "error": error, "ok": ok,
    }


async def _no_key_result(provider: str) -> tuple[str, str, dict]:
    return provider, "", _error_result(provider, f"missing API key for {provider}")


# ---------------------------------------------------------------------------
# Provider query coroutines
# ---------------------------------------------------------------------------


async def _query_virustotal(
    indicator: str,
    ioc_type: str,
    api_key: str,
    client: Any,
) -> tuple[str, str, dict]:
    await _VT_RATE_LIMITER.acquire()

    if ioc_type in ("md5", "sha1", "sha256"):
        url = f"{_VT_BASE}/files/{indicator}"
    elif ioc_type == "ip":
        url = f"{_VT_BASE}/ip_addresses/{indicator}"
    else:
        url = f"{_VT_BASE}/domains/{indicator}"

    try:
        resp = await client.get(url, headers={"x-apikey": api_key, "User-Agent": _USER_AGENT})
    except Exception as exc:
        return "virustotal", "", _error_result("virustotal", f"connection error: {exc}")

    raw_text: str = resp.text

    if resp.status_code == 429:
        return "virustotal", raw_text, _error_result("virustotal", "provider rate-limited")
    if resp.status_code == 404:
        return "virustotal", raw_text, {**_error_result("virustotal", "", ok=True), "found": False}
    if resp.status_code != 200:
        err = _error_result("virustotal", f"HTTP {resp.status_code}")
        err["raw_excerpt"] = raw_text[:512]
        return "virustotal", raw_text, err

    try:
        data = resp.json()
    except Exception:
        err = _error_result("virustotal", "JSON parse error")
        err["raw_excerpt"] = raw_text[:512]
        return "virustotal", raw_text, err

    attrs = data.get("data", {}).get("attributes", {})
    score, score_max, verdict = _parse_vt_stats(attrs.get("last_analysis_stats", {}))

    first_ts = attrs.get("first_submission_date") or attrs.get("creation_date")
    last_ts = attrs.get("last_analysis_date") or attrs.get("last_modification_date")

    return "virustotal", raw_text, {
        "provider": "virustotal",
        "found": True,
        "verdict": verdict,
        "score": score,
        "score_max": score_max,
        "first_seen": _unix_to_iso(first_ts),
        "last_seen": _unix_to_iso(last_ts),
        "tags": list(attrs.get("tags") or []),
        "raw_excerpt": raw_text[:512],
        "error": "",
        "ok": True,
    }


async def _query_otx(
    indicator: str,
    ioc_type: str,
    api_key: str,
    client: Any,
) -> tuple[str, str, dict]:
    await _OTX_RATE_LIMITER.acquire()

    otx_type = (
        "file" if ioc_type in ("md5", "sha1", "sha256")
        else "IPv4" if ioc_type == "ip"
        else "domain"
    )
    url = f"{_OTX_BASE}/indicators/{otx_type}/{indicator}/general"

    try:
        resp = await client.get(url, headers={"X-OTX-API-KEY": api_key, "User-Agent": _USER_AGENT})
    except Exception as exc:
        return "otx", "", _error_result("otx", f"connection error: {exc}")

    raw_text = resp.text

    if resp.status_code == 429:
        return "otx", raw_text, _error_result("otx", "provider rate-limited")
    if resp.status_code == 404:
        return "otx", raw_text, {**_error_result("otx", "", ok=True), "found": False}
    if resp.status_code != 200:
        err = _error_result("otx", f"HTTP {resp.status_code}")
        err["raw_excerpt"] = raw_text[:512]
        return "otx", raw_text, err

    try:
        data = resp.json()
    except Exception:
        err = _error_result("otx", "JSON parse error")
        err["raw_excerpt"] = raw_text[:512]
        return "otx", raw_text, err

    pulse_info = data.get("pulse_info") or {}
    pulse_count = int(pulse_info.get("count") or 0)
    pulses = pulse_info.get("pulses") or []

    if pulse_count > 2:
        verdict = "malicious"
    elif pulse_count > 0:
        verdict = "suspicious"
    else:
        verdict = "unknown"

    tags: list[str] = []
    first_seen = ""
    if pulses:
        tags = list(pulses[0].get("tags") or [])
        first_seen = str(pulses[0].get("created") or "")

    return "otx", raw_text, {
        "provider": "otx",
        "found": pulse_count > 0,
        "verdict": verdict,
        "score": pulse_count,
        "score_max": None,
        "first_seen": first_seen,
        "last_seen": "",
        "tags": tags,
        "raw_excerpt": raw_text[:512],
        "error": "",
        "ok": True,
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def threat_intel_lookup(
    indicator: str,
    *,
    indicator_type: str | None = None,
    providers: list[str] | None = None,
    timeout: float | None = None,
) -> dict:
    """Look up an IOC against live threat intelligence providers (W-118).

    EGRESS-GATED: requires AGENTROPIX_ALLOW_EGRESS=1.  Without it the tool
    registers and responds immediately with egress_allowed=False; no network
    call is ever made.

    Args:
        indicator: MD5 / SHA1 / SHA256 hash, IPv4 address, or domain name.
            URLs, emails, and whitespace-containing strings are rejected.
        indicator_type: Explicit type override.  Inferred automatically when
            omitted.  Accepted values: "md5", "sha1", "sha256", "ip", "domain".
        providers: Subset of {"virustotal", "otx"}.  Defaults to all providers
            enabled via AGENTROPIX_TI_PROVIDERS (default: both).
        timeout: Per-call HTTP timeout in seconds.  Clamped to [30, 300];
            default 60.  Overrides AGENTROPIX_TI_TIMEOUT for this call.

    Returns:
        ThreatIntelReport dict: {indicator, indicator_type, providers_queried,
        results, aggregate_verdict, tool, egress_allowed, raw_stdout_sha256}.
        Each element of ``results`` is a ProviderResult dict: {provider, found,
        verdict, score, score_max, first_seen, last_seen, tags, raw_excerpt,
        error, ok}.
    """
    egress_allowed = os.environ.get("AGENTROPIX_ALLOW_EGRESS") == "1"

    # Resolve IOC type
    if indicator_type is None:
        ioc_type = _infer_ioc_type(indicator)
    else:
        ioc_type = indicator_type.lower().strip()
        if ioc_type not in ("md5", "sha1", "sha256", "ip", "domain"):
            raise ValueError(f"invalid indicator_type {indicator_type!r}")

    # Resolve provider set
    enabled = get_str_set(
        "AGENTROPIX_TI_PROVIDERS",
        default={"virustotal", "otx"},
        min_size=1,
        max_size=3,
    ) & _ALL_PROVIDERS
    if providers is not None:
        requested = {p.lower().strip() for p in providers} & _ALL_PROVIDERS
        active = requested & enabled
    else:
        active = enabled
    providers_list = sorted(active)

    # Egress disabled — shim response, zero network calls
    if not egress_allowed:
        results = [_error_result(p, "egress disabled") for p in providers_list]
        return {
            "indicator": indicator,
            "indicator_type": ioc_type,
            "providers_queried": providers_list,
            "results": results,
            "aggregate_verdict": "unknown",
            "tool": "threat_intel_lookup",
            "egress_allowed": False,
            "raw_stdout_sha256": "",
        }

    # Resolve timeout
    if timeout is None:
        resolved_timeout = get_float(
            "AGENTROPIX_TI_TIMEOUT",
            default=_DEFAULT_TIMEOUT_S,
            floor=_TIMEOUT_FLOOR_S,
            ceiling=_TIMEOUT_CEILING_S,
        )
    else:
        resolved_timeout = clamp_float(
            "AGENTROPIX_TI_TIMEOUT",
            float(timeout),
            floor=_TIMEOUT_FLOOR_S,
            ceiling=_TIMEOUT_CEILING_S,
        )

    creds = _load_credentials()

    import httpx  # optional dep — present at runtime, not at import time

    async with httpx.AsyncClient(
        timeout=resolved_timeout,
        follow_redirects=True,
        verify=True,
    ) as client:
        tasks = []
        for p in providers_list:
            key = creds.get(p, "")
            if not key:
                tasks.append(_no_key_result(p))
            elif p == "virustotal":
                tasks.append(_query_virustotal(indicator, ioc_type, key, client))
            elif p == "otx":
                tasks.append(_query_otx(indicator, ioc_type, key, client))

        raw = await asyncio.gather(*tasks, return_exceptions=True)

    # Unpack; replace exceptions with error results
    results: list[dict] = []
    raw_texts: list[tuple[str, str]] = []

    for i, item in enumerate(raw):
        p = providers_list[i] if i < len(providers_list) else "unknown"
        if isinstance(item, Exception):
            results.append(_error_result(p, f"internal error: {item}"))
            raw_texts.append((p, ""))
        else:
            provider_name, raw_text, result_dict = item
            results.append(result_dict)
            raw_texts.append((provider_name, raw_text))

    # raw_stdout_sha256: deterministic hash over sorted (provider, raw_text) pairs
    sorted_raw = sorted(raw_texts, key=lambda x: x[0])
    combined = "".join(f"{p}:{t}" for p, t in sorted_raw).encode()
    raw_sha256 = hashlib.sha256(combined).hexdigest()

    # Aggregate verdict
    verdicts = {r["verdict"] for r in results if r.get("ok")}
    if "malicious" in verdicts:
        aggregate = "malicious"
    elif "suspicious" in verdicts:
        aggregate = "suspicious"
    elif verdicts == {"clean"}:
        aggregate = "clean"
    else:
        aggregate = "unknown"

    return {
        "indicator": indicator,
        "indicator_type": ioc_type,
        "providers_queried": providers_list,
        "results": results,
        "aggregate_verdict": aggregate,
        "tool": "threat_intel_lookup",
        "egress_allowed": True,
        "raw_stdout_sha256": raw_sha256,
    }
