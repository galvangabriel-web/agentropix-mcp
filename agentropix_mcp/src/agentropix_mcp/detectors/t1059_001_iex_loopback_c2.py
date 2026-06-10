"""T1059.001 IEX loopback C2 detector (W-205 closure).

Detects PowerShell ScriptBlock (EID 4104) records that combine, in order,
all three of:

* an IEX / Invoke-Expression token,
* a downloader (DownloadString / DownloadFile / Invoke-WebRequest /
  Invoke-RestMethod),
* a URI literal whose host resolves to a loopback address (127.0.0.0/8,
  ``::1``, ``::ffff:127.0.0.1``, ``0.0.0.0``, bare ``0``, ``localhost``,
  or decimal / hex IP literals).

Source signal — SRL-2018 carries 6 Cobalt-Strike-family loopback stagers
across base-rd-01 / base-rd-02 / base-wkstn-05. This rule fires on the
ScriptBlockText emitted by ``Microsoft-Windows-PowerShell/Operational``.

Acceptance criteria (TICKETS/W-205-iex-loopback-c2-rule.md v2):

* AC#1 — adversary-hardened detection (URL-decode + Punycode-fold +
  decimal/hex IP literals + ``ipaddress``-driven loopback test +
  trivial concat-fold).
* AC#2 — HIGH severity for machine / SYSTEM accounts, MEDIUM otherwise.
* AC#3 — conditioned ``prerequisite_missing.scriptblock_logging`` only
  when EID 4688 PS exec >=1 AND EID 4104 = 0. Emitted to LOCAL-only
  sidecar at ``<run-dir>/_internal/prereq_gaps_<host>.json`` (round-4
  c1-F3 / r2 c1-F6 recon-leak mitigation).
* AC#4 — every ``script_block_excerpt`` passes through
  ``agentropix_mcp.security.redact.redact_finding`` before emission;
  ``script_block_sha256`` is computed on the FULL un-redacted
  ScriptBlockText.
* AC#5 — ``AGENTROPIX_IEX_LOOPBACK_ALLOWLIST_PORTS`` suppresses
  loopback:<port> tuples.
* AC#6 — AST-aware regime is documented in
  ``logs/2026-05-14-macro-detection-uplift/DOCS/PREREQUISITES.md``; this
  module ships the documented substring-with-concat-fold fallback.

The detector inherits ``SwarmAgent`` (``agents/_base.py:84``) and is
wired into ``SWARM`` in ``agents/__init__.py`` after ``InjectionDetector``
and before ``HuntAgent`` (DESIGNS/W-205-design.md §1 + §9 Q5).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel

from agentropix_mcp.agents._base import Finding, SwarmAgent
from agentropix_mcp.agents._evidence import looks_like_disk
from agentropix_mcp._env import get_float, get_int, get_int_set
from agentropix_mcp.wrappers.evtx import EvtxEvent, EvtxReport, get_evtx
from agentropix_mcp.security.redact import RedactionError, redact_finding

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Public constants (referenced by tests + downstream consumers)
# --------------------------------------------------------------------------

FINDING_TYPE: str = "t1059.001.iex_loopback_c2"
SUMMARY_FINDING_TYPE: str = "t1059.001.summary"
PREREQ_MISSING_TYPE: str = "prerequisite_missing.scriptblock_logging"
PREREQ_INDETERMINATE_PT_TYPE: str = "prerequisite_indeterminate.process_tree_data_missing"
PREREQ_INDETERMINATE_TRUNC_TYPE: str = "prerequisite_indeterminate.scriptblock_truncated"
MITRE_ID: str = "T1059.001"
SUMMARY_SOURCE: str = "detectors.t1059_001.summary"
PER_HIT_SOURCE: str = "detectors.t1059_001.iex_loopback_c2"
SKIP_SOURCE: str = "detectors.t1059_001.skipped"
ERROR_SOURCE: str = "detectors.t1059_001.error"
PREREQ_MISSING_SOURCE: str = "detectors.t1059_001.prerequisite_missing"
PREREQ_INDETERMINATE_SOURCE: str = "detectors.t1059_001.prerequisite_indeterminate"
RULE_VERSION: str = "1"

# Excerpt cap (round-4 c2-F8 — bounds redactor CPU).
SCRIPT_BLOCK_EXCERPT_MAX_CHARS: int = 512

# ``EvtxEvent.raw`` is capped at 2000 chars by the wrapper
# (mcp_server/wrappers/evtx.py:528 + :699); we mirror that here to detect
# truncation without re-importing the constant.
_EVTX_RAW_CAP: int = 2000


# --------------------------------------------------------------------------
# Token grammars (compiled once at module import)
# --------------------------------------------------------------------------

# PowerShell tolerates several dash variants (hyphen-minus, en/em dash,
# horizontal bar) in flag tokens. The character class below covers them.
_DASH = r"[-‐-―]"

_IEX_TOKEN_RE = re.compile(
    rf"\b(?P<tok>IEX|Invoke{_DASH}?Expression)\b",
    re.IGNORECASE,
)
_DOWNLOADER_TOKEN_RE = re.compile(
    rf"\b(?P<tok>DownloadString|DownloadFile|"
    rf"Invoke{_DASH}?WebRequest|Invoke{_DASH}?RestMethod)\b",
    re.IGNORECASE,
)
# Quoted URI literal. Allows percent-encoded "%2F%2F" in place of "//"
# and the schemeless ``//host/...`` form.
_URI_LITERAL_RE = re.compile(
    r"""(?P<q>['"])(?P<uri>(?:https?:)?(?:%2F%2F|//)[^'"\s]{1,2048}?)(?P=q)""",
    re.IGNORECASE,
)
# Bounded string-concatenation pair: ``'a' + 'b'`` -> single literal.
# Run iteratively to fold longer chains.
_CONCAT_RE = re.compile(
    r"""(?P<q1>['"])(?P<a>[^'"\n]{0,256})(?P=q1)\s*\+\s*"""
    r"""(?P<q2>['"])(?P<b>[^'"\n]{0,256})(?P=q2)"""
)

# Substring patterns used to spot loopback PS exec in EID 4688 raw rows.
# EID 4688 raw payload (XML or JSON) carries NewProcessName.
_PS_EXE_RE = re.compile(r"(?i)(?<![A-Za-z0-9._-])(?:powershell|pwsh)\.exe\b")
_PS_ISE_RE = re.compile(r"(?i)powershell_ise\.exe")

# UserID parse from <Security UserID="S-1-5-21-..."/> XML form.
_USERID_XML_RE = re.compile(r'<Security\s+UserID="([^"]+)"\s*/?>', re.IGNORECASE)
# JSONL form: ``"#attributes": {"UserID": "S-1-5-..."}``
_USERID_JSON_RE = re.compile(r'"UserID"\s*:\s*"([^"]+)"')

# ScriptBlockText extraction from XML form.
_SBT_XML_RE = re.compile(
    r'<Data\s+Name="ScriptBlockText">(.*?)</Data>',
    re.DOTALL | re.IGNORECASE,
)


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------


class LoopbackUriHit(BaseModel):
    """One IEX + downloader + loopback-URI match observed in a ScriptBlock."""

    record_id: int
    timestamp: str
    computer: str
    user_sid: str = ""
    iex_token: str
    downloader_token: str
    uri_raw: str
    uri_canonical: str
    uri_host_normalised: str
    uri_port: int | None = None
    address_kind: str
    severity: str
    script_block_sha256: str
    script_block_excerpt: str
    truncated_raw: bool = False


def _resolve_loopback(host: str) -> tuple[bool, str, str]:
    """Return ``(is_loopback, normalised_text, address_kind)``.

    ``address_kind`` is one of ``ipv4`` / ``ipv6`` / ``ipv6_mapped`` /
    ``localhost`` / ``decimal_int`` / ``hex_dotted`` / ``bare_zero`` /
    ``unknown``. Used for fixture audit and unit-test labelling; severity
    gating consults ``is_loopback`` only.

    Loopback predicate:
        * IPv4 in ``127.0.0.0/8`` OR ``0.0.0.0``
        * IPv6 ``::1`` (after un-mapping ``::ffff:127.0.0.1``)
        * literal ``"localhost"``
        * bare ``"0"`` (resolves to ``0.0.0.0``)
    """
    if host is None:
        return (False, "", "unknown")
    raw = host.strip().strip("[]").lower()
    if not raw:
        return (False, "", "unknown")
    if raw == "localhost":
        return (True, "localhost", "localhost")
    if raw == "0":
        return (True, "0.0.0.0", "bare_zero")

    candidate: str = raw
    kind: str = "unknown"

    # Decimal integer literal -> IPv4.
    if raw.isdigit():
        try:
            ip = ipaddress.IPv4Address(int(raw))
            return (_loopback_test_v4(ip), str(ip), "decimal_int")
        except (ValueError, ipaddress.AddressValueError):
            pass

    # 0x-prefixed single integer.
    if raw.startswith("0x"):
        try:
            ip = ipaddress.IPv4Address(int(raw, 0))
            return (_loopback_test_v4(ip), str(ip), "decimal_int")
        except (ValueError, ipaddress.AddressValueError):
            pass

    # Dotted-hex (0x7f.0x0.0x0.0x1).
    if "0x" in raw:
        parts = raw.split(".")
        if len(parts) == 4:
            try:
                octets = [int(p, 0) for p in parts]
                if all(0 <= o <= 255 for o in octets):
                    ip = ipaddress.IPv4Address(
                        (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
                    )
                    return (_loopback_test_v4(ip), str(ip), "hex_dotted")
            except ValueError:
                pass

    # Plain string parses -- try v4 then v6.
    try:
        ip4 = ipaddress.IPv4Address(candidate)
        return (_loopback_test_v4(ip4), str(ip4), "ipv4")
    except (ValueError, ipaddress.AddressValueError):
        pass
    try:
        ip6 = ipaddress.IPv6Address(candidate)
        mapped = ip6.ipv4_mapped
        if mapped is not None:
            return (_loopback_test_v4(mapped), str(mapped), "ipv6_mapped")
        kind = "ipv6"
        is_loop = ip6 == ipaddress.IPv6Address("::1")
        return (is_loop, str(ip6), kind)
    except (ValueError, ipaddress.AddressValueError):
        pass

    return (False, raw, "unknown")


def _loopback_test_v4(ip: ipaddress.IPv4Address) -> bool:
    return ip in ipaddress.IPv4Network("127.0.0.0/8") or ip == ipaddress.IPv4Address("0.0.0.0")


def _fold_concat(text: str) -> str:
    """Iteratively collapse ``'a' + 'b'`` -> ``'ab'`` until stable.

    Bounded recursion (cap at 32 passes) so an adversary crafting a
    pathological chain cannot pin the regex engine indefinitely.
    """
    out = text
    for _ in range(32):
        new_out, n = _CONCAT_RE.subn(lambda m: f"{m.group('q1')}{m.group('a')}{m.group('b')}{m.group('q1')}", out)
        if n == 0:
            return new_out
        out = new_out
    return out


def _parse_uri_host_port(uri_raw: str) -> tuple[str, int | None]:
    """Return ``(host, port)`` after URL-decoding and Punycode normalisation."""
    candidate = uri_raw.strip().strip("'\"")
    candidate = unquote(candidate)
    # ``urlsplit`` needs a scheme for ``//host/...`` to expose ``netloc``.
    if candidate.startswith("//"):
        candidate = "http:" + candidate
    parts = urlsplit(candidate)
    host = parts.hostname or ""
    try:
        host_idna = host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        host_idna = host
    host_norm = host_idna.lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    return host_norm, port


def _extract_loopback_hits_from_scriptblock(
    text: str,
) -> list[tuple[str, str, str, str, int | None, str]]:
    """Yield ``(iex_token, downloader_token, uri_raw, uri_canonical,
    port, address_kind)`` tuples for every ordered IEX -> downloader ->
    loopback-URI triple in ``text``.

    Algorithm:
      1. Concatenation-fold trivial obfuscation.
      2. Find all IEX, downloader, and URI-literal positions.
      3. For each IEX, find the first downloader > iex_pos and first URI
         > downloader_pos; resolve the URI's host to a loopback address;
         emit one hit; advance the IEX cursor past the URI.
    """
    if not text:
        return []
    folded = _fold_concat(text)

    iex_matches = list(_IEX_TOKEN_RE.finditer(folded))
    dl_matches = list(_DOWNLOADER_TOKEN_RE.finditer(folded))
    uri_matches = list(_URI_LITERAL_RE.finditer(folded))
    if not iex_matches or not dl_matches or not uri_matches:
        return []

    hits: list[tuple[str, str, str, str, int | None, str]] = []
    used_uri_starts: set[int] = set()
    for iex_m in iex_matches:
        dl_m = next((m for m in dl_matches if m.start() > iex_m.start()), None)
        if dl_m is None:
            continue
        uri_m = next(
            (m for m in uri_matches if m.start() > dl_m.start() and m.start() not in used_uri_starts),
            None,
        )
        if uri_m is None:
            continue
        uri_raw = uri_m.group("uri")
        host, port = _parse_uri_host_port(uri_raw)
        is_loop, host_norm, kind = _resolve_loopback(host)
        if not is_loop:
            continue
        used_uri_starts.add(uri_m.start())
        canonical = unquote(uri_raw).lower()
        hits.append(
            (
                iex_m.group("tok"),
                dl_m.group("tok"),
                uri_raw,
                canonical,
                port,
                kind,
            )
        )
    return hits


def extract_scriptblocktext(raw: str) -> tuple[str, bool]:
    """Pull ScriptBlockText from an ``EvtxEvent.raw`` payload.

    Returns ``(text, truncated)``. ``truncated`` is True when the raw
    bytes appear to have hit the 2000-char wrapper cap (W-205 design
    §3.2 + round-4 c4-F7). Handles both JSONL and XML evtx_dump outputs.
    """
    if not raw:
        return ("", False)
    stripped = raw.lstrip()
    if stripped.startswith("{"):
        # JSONL form. Truncation typically leaves the JSON unparseable.
        try:
            payload = json.loads(raw)
            event = payload.get("Event") if isinstance(payload, dict) else None
            event_data = event.get("EventData") if isinstance(event, dict) else None
            sbt = ""
            if isinstance(event_data, dict):
                value = event_data.get("ScriptBlockText", "")
                if isinstance(value, str):
                    sbt = value
                elif isinstance(value, dict):
                    text_val = value.get("#text", "")
                    sbt = text_val if isinstance(text_val, str) else ""
            truncated = len(raw) >= _EVTX_RAW_CAP and not raw.rstrip().endswith("}")
            return (sbt, truncated)
        except json.JSONDecodeError:
            truncated = len(raw) >= _EVTX_RAW_CAP
            m = _SBT_XML_RE.search(raw)
            return ((m.group(1) if m else ""), truncated)
    # XML form.
    truncated = len(raw) >= _EVTX_RAW_CAP and "</EventData>" not in raw
    m = _SBT_XML_RE.search(raw)
    return ((m.group(1) if m else ""), truncated)


def _parse_user_sid(raw: str) -> str:
    if not raw:
        return ""
    m = _USERID_XML_RE.search(raw)
    if m:
        return m.group(1)
    m = _USERID_JSON_RE.search(raw)
    if m:
        return m.group(1)
    return ""


def _user_is_machine_or_system(sid: str, raw: str) -> bool:
    if not sid:
        return False
    if sid in {"S-1-5-18", "S-1-5-19", "S-1-5-20"}:
        return True
    # Machine accounts end in ``$`` when serialised as ``HOST$`` -- look
    # inside the raw payload for the ``UserName`` field where evtx_dump
    # exposes it.
    if "UserName" in raw:
        m = re.search(r'"UserName"\s*:\s*"([^"]*)"|<Data\s+Name="SubjectUserName">([^<]+)</Data>', raw)
        if m:
            uname = m.group(1) or m.group(2) or ""
            if uname.endswith("$"):
                return True
    return False


def _build_excerpt(sbt: str, *, around: str, max_chars: int) -> str:
    """Return a slice of ``sbt`` of at most ``max_chars`` chars centred on
    the first occurrence of ``around`` (case-insensitive). Falls back to
    ``sbt[:max_chars]`` if the anchor isn't found."""
    if not sbt:
        return ""
    lo_sbt = sbt.lower()
    lo_anchor = around.lower()
    idx = lo_sbt.find(lo_anchor) if lo_anchor else -1
    if idx < 0:
        return sbt[:max_chars]
    half = max_chars // 2
    start = max(0, idx - half)
    end = min(len(sbt), start + max_chars)
    return sbt[start:end]


def _slugify_computer(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", (name or "unknown").strip())
    return s[:120] or "unknown"


# --------------------------------------------------------------------------
# Detector
# --------------------------------------------------------------------------


class IexLoopbackC2Detector(SwarmAgent):
    """T1059.001 IEX loopback C2 detector (W-205 closure).

    See module docstring for the AC mapping.
    """

    name = "t1059_001_iex_loopback_c2"
    completion_promise = "T1059_001_IEX_LOOPBACK_SCAN_COMPLETE"

    async def investigate(self, image: Path) -> list[Finding]:
        if not looks_like_disk(image):
            # EID 4104 is a disk-side EVTX channel; memory dumps have no
            # ScriptBlock log. Emit a coverage-signal skip Finding so
            # W-083 sees the source.
            return [
                Finding(
                    source=SKIP_SOURCE,
                    confidence=0.0,
                    description=(
                        f"T1059.001 IEX loopback C2 detector skipped: "
                        f"{image.name} is not a disk image"
                    ),
                    evidence=f"image={image} reason=non_disk_image",
                    timestamp=Finding.now(),
                )
            ]

        timeout = get_float(
            "AGENTROPIX_T1059_EVTX_TIMEOUT", 180.0, floor=5.0, ceiling=3600.0
        )
        max_events = get_int(
            "AGENTROPIX_T1059_MAX_EVENTS", 5000, floor=100, ceiling=100_000
        )
        allowlist_ports = get_int_set(
            "AGENTROPIX_IEX_LOOPBACK_ALLOWLIST_PORTS",
            default=set(),
            min_size=0,
            max_size=64,
        )

        # Step 1: extract EID 4104 PowerShell/Operational records.
        try:
            ps_op = await get_evtx(
                image,
                channels={"Microsoft-Windows-PowerShell/Operational"},
                event_ids={4104},
                max_events=max_events,
                timeout=timeout,
            )
        except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as exc:
            logger.warning("W-205 get_evtx (PS/Operational) failed: %s", exc)
            return [
                Finding(
                    source=ERROR_SOURCE,
                    confidence=0.0,
                    description=(
                        f"T1059.001 detector failed to obtain PowerShell/Operational "
                        f"records: {exc}"
                    ),
                    evidence=f"image={image} error={type(exc).__name__}: {exc}",
                    timestamp=Finding.now(),
                )
            ]

        # Legacy .evt format (winxp / win2003) is not supported by the
        # current wrapper -- emit a coverage signal so the run is
        # distinguishable from "ran with empty result".
        if ps_op.image_class_detected == "winxp_or_win2003":
            return [
                Finding(
                    source=SKIP_SOURCE,
                    confidence=0.0,
                    description=(
                        f"T1059.001 detector skipped: {image.name} is legacy .evt format"
                    ),
                    evidence=f"image={image} reason=legacy_evt_format_unsupported",
                    timestamp=Finding.now(),
                )
            ]

        # Step 2: extract EID 4688 Security records for AC#3 prereq probe.
        ps_exec_count = await self._count_ps_exec(
            image, max_events=max_events, timeout=timeout
        )

        # Step 3: per-record loopback extraction.
        hits: list[LoopbackUriHit] = []
        truncated_record_ids: list[int] = []
        per_hit_failures: int = 0
        host_seen: str = ""
        for ev in ps_op.events:
            sbt, truncated = extract_scriptblocktext(ev.raw)
            if truncated:
                truncated_record_ids.append(ev.record_id)
            if not sbt:
                continue
            sb_sha256 = hashlib.sha256(sbt.encode("utf-8", errors="replace")).hexdigest()
            user_sid = _parse_user_sid(ev.raw)
            severity_high = _user_is_machine_or_system(user_sid, ev.raw)
            extracted = _extract_loopback_hits_from_scriptblock(sbt)
            if not extracted:
                continue
            host_seen = host_seen or (ev.computer or "")
            for iex_tok, dl_tok, uri_raw, canonical, port, kind in extracted:
                if port is not None and port in allowlist_ports:
                    continue
                try:
                    excerpt_raw = _build_excerpt(
                        sbt, around=iex_tok, max_chars=SCRIPT_BLOCK_EXCERPT_MAX_CHARS
                    )
                    redacted_excerpt = self._redact_excerpt(excerpt_raw)
                except RedactionError as exc:
                    # Fail-closed (round-4 c4-F5): drop the per-hit Finding,
                    # log, increment failure counter for the summary.
                    logger.error(
                        "W-205 redactor failed on record %s: %s", ev.record_id, exc
                    )
                    per_hit_failures += 1
                    continue
                host_norm = canonical
                # ``canonical`` already includes the path; we want just the
                # host substring for the dedicated field. Re-parse.
                host_only, _ = _parse_uri_host_port(uri_raw)
                hits.append(
                    LoopbackUriHit(
                        record_id=ev.record_id,
                        timestamp=ev.timestamp,
                        computer=ev.computer,
                        user_sid=user_sid,
                        iex_token=iex_tok,
                        downloader_token=dl_tok,
                        uri_raw=uri_raw,
                        uri_canonical=canonical,
                        uri_host_normalised=host_only,
                        uri_port=port,
                        address_kind=kind,
                        severity="HIGH" if severity_high else "MEDIUM",
                        script_block_sha256=sb_sha256,
                        script_block_excerpt=redacted_excerpt,
                        truncated_raw=truncated,
                    )
                )

        # Step 4: AC#3 prereq state.
        if len(ps_op.events) == 0 and ps_exec_count >= 1:
            prereq_state = "missing"
        else:
            prereq_state = "satisfied"

        # Step 4b: c4-F7 indeterminate consult via MASTER-IOCS.
        master_iocs_path = os.environ.get("AGENTROPIX_W205_MASTER_IOCS_PATH")
        host_for_consult = host_seen or _host_from_report(ps_op)
        if master_iocs_path and host_for_consult:
            if self._host_in_process_tree_findings_skipped(master_iocs_path, host_for_consult):
                prereq_state = "indeterminate"

        # Step 5: build Findings.
        findings: list[Finding] = [self._build_per_hit_finding(image, h) for h in hits]
        if truncated_record_ids:
            findings.append(self._build_truncation_finding(image, host_for_consult, truncated_record_ids))
        findings.append(
            self._build_summary_finding(
                image=image,
                hits=len(hits),
                records_scanned=len(ps_op.events),
                sb_truncated_count=len(truncated_record_ids),
                prereq_state=prereq_state,
                redactor_failures=per_hit_failures,
            )
        )

        # Step 6: LOCAL-only sidecar (AC#3 / round-4 c1-F3 / r2 c1-F6).
        if prereq_state in ("missing", "indeterminate"):
            self._write_prereq_sidecar(
                image=image,
                host=host_for_consult,
                ps_exec_count=ps_exec_count,
                ps_op_event_count=len(ps_op.events),
                prereq_state=prereq_state,
            )

        return findings

    # ------------------------------------------------------------------
    # Helpers (instance methods so tests can monkeypatch without touching
    # module globals)
    # ------------------------------------------------------------------

    async def _count_ps_exec(
        self, image: Path, *, max_events: int, timeout: float
    ) -> int:
        try:
            sec_4688: EvtxReport = await get_evtx(
                image,
                channels={"Security"},
                event_ids={4688},
                max_events=max_events,
                timeout=timeout,
            )
        except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as exc:
            logger.warning("W-205 get_evtx (Security/4688) tolerated failure: %s", exc)
            return 0
        count = 0
        for ev in sec_4688.events:
            raw = ev.raw or ""
            if _PS_EXE_RE.search(raw) and not _PS_ISE_RE.search(raw):
                count += 1
        return count

    def _redact_excerpt(self, excerpt: str) -> str:
        out = redact_finding({"script_block_excerpt": excerpt}, version=RULE_VERSION)
        value = out.get("script_block_excerpt", "")
        return value if isinstance(value, str) else ""

    def _host_in_process_tree_findings_skipped(self, path: str, host: str) -> bool:
        try:
            with open(path, "rb") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("W-205 master_iocs consult failed (%s): %s", path, exc)
            return False
        rows = payload.get("process_tree_findings_skipped", []) if isinstance(payload, dict) else []
        skipped_hosts = {
            str(row.get("host") or row.get("computer") or "").lower()
            for row in rows
            if isinstance(row, dict)
        }
        return host.lower() in skipped_hosts

    def _build_per_hit_finding(self, image: Path, hit: LoopbackUriHit) -> Finding:
        host_norm_disp = hit.uri_host_normalised or "<unknown>"
        port_disp = f":{hit.uri_port}" if hit.uri_port else ""
        description = (
            f"T1059.001 IEX loopback C2 stager observed: {hit.iex_token} + "
            f"{hit.downloader_token} against {host_norm_disp}{port_disp}"
        )
        evidence = (
            f"host={hit.computer} record_id={hit.record_id} ts={hit.timestamp} "
            f"uri={hit.uri_canonical} severity={hit.severity} "
            f"sb_sha256={hit.script_block_sha256} mitre=t1059.001 "
            f"excerpt={hit.script_block_excerpt}"
        )
        evidence_dict: dict[str, Any] = {
            "finding_type": FINDING_TYPE,
            "computer": hit.computer,
            "record_id": hit.record_id,
            "user_sid": hit.user_sid,
            "iex_token": hit.iex_token,
            "downloader_token": hit.downloader_token,
            "uri_canonical": hit.uri_canonical,
            "uri_host_normalised": hit.uri_host_normalised,
            "uri_port": hit.uri_port,
            "address_kind": hit.address_kind,
            "severity": hit.severity,
            "script_block_sha256": hit.script_block_sha256,
            "script_block_excerpt": hit.script_block_excerpt,
            "truncated_raw": hit.truncated_raw,
            "rule_version": RULE_VERSION,
        }
        return Finding(
            source=PER_HIT_SOURCE,
            confidence=0.92,
            description=description,
            evidence=evidence,
            evidence_dict=evidence_dict,
            mitre_attack=MITRE_ID,
            timestamp=Finding.now(),
        )

    def _build_summary_finding(
        self,
        *,
        image: Path,
        hits: int,
        records_scanned: int,
        sb_truncated_count: int,
        prereq_state: str,
        redactor_failures: int,
    ) -> Finding:
        confidence = 0.30 if hits == 0 else 0.50
        description = (
            f"T1059.001 iex-loopback-c2 scan complete: {hits} hits across "
            f"{records_scanned} EID 4104 records"
        )
        evidence = (
            f"image={image} hits={hits} records_scanned={records_scanned} "
            f"sb_truncated={sb_truncated_count} prereq_state={prereq_state} "
            f"redactor_failures={redactor_failures} mitre=t1059.001"
        )
        return Finding(
            source=SUMMARY_SOURCE,
            confidence=confidence,
            description=description,
            evidence=evidence,
            evidence_dict={
                "finding_type": SUMMARY_FINDING_TYPE,
                "hits": hits,
                "records_scanned": records_scanned,
                "sb_truncated_count": sb_truncated_count,
                "prereq_state": prereq_state,
                "redactor_failures": redactor_failures,
                "rule_version": RULE_VERSION,
            },
            mitre_attack=MITRE_ID,
            timestamp=Finding.now(),
        )

    def _build_truncation_finding(
        self,
        image: Path,
        host: str,
        truncated_record_ids: list[int],
    ) -> Finding:
        return Finding(
            source=PREREQ_INDETERMINATE_SOURCE,
            confidence=0.20,
            description=(
                f"T1059.001 detection on host {host or '<unknown>'} is "
                f"evidence-quality-degraded: {len(truncated_record_ids)} "
                "EID 4104 records have truncated raw payloads (wrapper 2000-char cap)"
            ),
            evidence=(
                f"image={image} host={host} truncated_count={len(truncated_record_ids)} "
                f"first_record_ids={truncated_record_ids[:10]} mitre=t1059.001"
            ),
            evidence_dict={
                "finding_type": PREREQ_INDETERMINATE_TRUNC_TYPE,
                "computer": host,
                "truncated_record_ids": truncated_record_ids,
                "local_only": False,
                "rule_version": RULE_VERSION,
            },
            mitre_attack=MITRE_ID,
            timestamp=Finding.now(),
        )

    def _write_prereq_sidecar(
        self,
        *,
        image: Path,
        host: str,
        ps_exec_count: int,
        ps_op_event_count: int,
        prereq_state: str,
    ) -> None:
        """Write LOCAL-only prerequisite sidecar. Never raises."""
        sidecar_dir = os.environ.get("AGENTROPIX_W205_PREREQ_SIDECAR_DIR")
        if sidecar_dir:
            target_dir = Path(sidecar_dir)
        else:
            # Fallback: collocated with the image's grand-parent. Emit a
            # WARNING so the operator sees the fallback path.
            target_dir = image.parent.parent / "_internal"
            logger.warning(
                "W-205 AGENTROPIX_W205_PREREQ_SIDECAR_DIR unset; falling back to %s",
                target_dir,
            )
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning("W-205 sidecar mkdir failed (%s): %s", target_dir, exc)
            return
        host_slug = _slugify_computer(host)
        path = target_dir / f"prereq_gaps_{host_slug}.json"
        if prereq_state == "missing":
            ftype = PREREQ_MISSING_TYPE
            source = PREREQ_MISSING_SOURCE
            reason: str | None = None
        else:
            ftype = PREREQ_INDETERMINATE_PT_TYPE
            source = PREREQ_INDETERMINATE_SOURCE
            reason = "host_in_process_tree_findings_skipped"
        payload = {
            "_source": source,
            "finding_type": ftype,
            "image": str(image),
            "computer": host,
            "ps_exec_event_count": ps_exec_count,
            "scriptblock_event_count": ps_op_event_count,
            "local_only": True,
            "mitre_attack": "T1562.002" if prereq_state == "missing" else MITRE_ID,
            "rule_version": RULE_VERSION,
        }
        if reason is not None:
            payload["reason"] = reason
        try:
            path.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("W-205 sidecar write failed (%s): %s", path, exc)


def _host_from_report(report: EvtxReport) -> str:
    for ev in report.events:
        if ev.computer:
            return ev.computer
    return ""


__all__ = [
    "FINDING_TYPE",
    "SUMMARY_FINDING_TYPE",
    "PREREQ_MISSING_TYPE",
    "PREREQ_INDETERMINATE_PT_TYPE",
    "PREREQ_INDETERMINATE_TRUNC_TYPE",
    "MITRE_ID",
    "PER_HIT_SOURCE",
    "SUMMARY_SOURCE",
    "PREREQ_MISSING_SOURCE",
    "PREREQ_INDETERMINATE_SOURCE",
    "RULE_VERSION",
    "SCRIPT_BLOCK_EXCERPT_MAX_CHARS",
    "LoopbackUriHit",
    "IexLoopbackC2Detector",
    "extract_scriptblocktext",
    "_extract_loopback_hits_from_scriptblock",
    "_resolve_loopback",
    "_parse_uri_host_port",
    "_fold_concat",
    "_parse_user_sid",
    "_user_is_machine_or_system",
    "_build_excerpt",
    "_slugify_computer",
]
