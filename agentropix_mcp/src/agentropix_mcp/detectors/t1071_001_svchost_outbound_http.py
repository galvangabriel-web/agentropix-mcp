"""T1071.001 svchost-as-source HTTP detector (W-215 closure).

Flags ``svchost.exe`` processes initiating outbound TCP/80 (or 8080/8000)
connections to a public IP that is **not** in the Microsoft service-range
allowlist. This is the canonical Korplug / PlugX C2 callback shape
documented in the 2026-05-16 CyberDefenders TeamSpy capability-comparison
analysis (logs/2026-05-16-cyberdefenders-teamspy-analysis/REPORT.md §10).

Why svchost-as-source and not svchost-as-target:

``detectors/injection_detector.py:58`` already covers svchost-as-target
(an RWX VAD inside svchost — i.e. injected code). The complementary
direction — svchost initiating outbound HTTP — is not currently caught
by any detector. Genuine svchost outbound HTTP exists (BITS / WUAUCLT /
OneDrive) but always lands in well-known Microsoft service ranges, so
filtering against a CIDR allowlist keeps the false-positive surface
small while preserving the high-precision Korplug catch.

**Allowlist caveat (per plan R5):** the 52.0.0.0/8 Microsoft Azure
public block overlaps with AWS public IP space; the TeamSpy C2
``54.174.131.235`` would NOT be filtered by 52.0.0.0/8 (it lives in
54.x). This is intentional — the allowlist is sized to reject obvious
MS service traffic without swallowing Korplug-class C2 that happens
to land in EC2. A future W-215a refinement may narrow to the official
Microsoft ServiceTags JSON.

Tunables (env-var, all clamped):

* ``AGENTROPIX_T1071_SVCHOST_PORTS``       (int-set, default ``"80,8080,8000"``)
* ``AGENTROPIX_T1071_SVCHOST_CONFIDENCE``  (float,   default 0.85, [0.0, 1.0])
* ``AGENTROPIX_T1071_SVCHOST_ALLOWLIST_EXTRA`` (str, comma-separated CIDRs added to baseline)
* ``AGENTROPIX_T1071_SVCHOST_DISABLE``     (int, set to 1 to suppress all findings)
"""

from __future__ import annotations

import ipaddress
import logging
import os
from pathlib import Path

from agentropix_mcp.agents._base import Finding, SwarmAgent
from agentropix_mcp.agents._evidence import looks_like_memory
from agentropix_mcp._env import get_float, get_int_set
from agentropix_mcp.wrappers.volatility import (
    NetscanReport,
    SocketInfo,
    get_netscan,
)

logger = logging.getLogger(__name__)


MITRE_ID: str = "T1071.001"
FINDING_TYPE: str = "t1071.001.svchost_outbound_http"
SUMMARY_FINDING_TYPE: str = "t1071.001.summary"
SKIP_FINDING_TYPE: str = "t1071.001.skipped"
ERROR_FINDING_TYPE: str = "t1071.001.error"

# Baseline Microsoft service-range allowlist. Conservative — narrowed
# to ranges that overwhelmingly serve BITS / WUAUCLT / OneDrive /
# Defender telemetry. Operators can extend at runtime via
# AGENTROPIX_T1071_SVCHOST_ALLOWLIST_EXTRA.
_BASELINE_ALLOWLIST_CIDRS: tuple[str, ...] = (
    "13.107.0.0/16",   # Microsoft global services
    "20.0.0.0/8",      # Azure public (broad — accepted FP cost)
    "40.0.0.0/8",      # Azure public (broad)
    "52.0.0.0/8",      # Azure public (overlaps AWS; see plan R5)
    "104.40.0.0/13",   # Microsoft online services
    "131.107.0.0/16",  # Microsoft corp
)

# Non-routable / link-local / loopback / multicast space — auto-skipped
# regardless of allowlist config so we never noise on internal traffic.
_AUTO_IGNORE_CIDRS: tuple[str, ...] = (
    "10.0.0.0/8",       # RFC 1918
    "172.16.0.0/12",    # RFC 1918
    "192.168.0.0/16",   # RFC 1918
    "127.0.0.0/8",      # loopback
    "169.254.0.0/16",   # link-local
    "224.0.0.0/4",      # multicast
    "0.0.0.0/8",        # this network
    "::1/128",          # IPv6 loopback
    "fe80::/10",        # IPv6 link-local
    "fc00::/7",         # IPv6 unique-local
)

_DEFAULT_PORTS: frozenset[int] = frozenset({80, 8080, 8000})
_DEFAULT_CONFIDENCE: float = 0.85
_SVCHOST_NAME: str = "svchost.exe"
_ESTABLISHED_STATES: frozenset[str] = frozenset({"ESTABLISHED", "SYN_SENT"})


def _resolve_ports() -> frozenset[int]:
    """Read AGENTROPIX_T1071_SVCHOST_PORTS, fall back to default."""
    raw = get_int_set(
        "AGENTROPIX_T1071_SVCHOST_PORTS",
        set(_DEFAULT_PORTS),
        min_size=1,
        max_size=64,
    )
    # Drop out-of-range port numbers defensively.
    return frozenset(p for p in raw if 1 <= p <= 65535)


def _resolve_confidence() -> float:
    return get_float(
        "AGENTROPIX_T1071_SVCHOST_CONFIDENCE",
        _DEFAULT_CONFIDENCE,
        floor=0.0,
        ceiling=1.0,
    )


def _resolve_disabled() -> bool:
    """Honour AGENTROPIX_T1071_SVCHOST_DISABLE=1 hard off-switch."""
    return os.environ.get("AGENTROPIX_T1071_SVCHOST_DISABLE", "").strip() in {"1", "true", "yes", "on"}


def _build_allowlist_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Return parsed CIDR networks: baseline + extras + auto-ignore."""
    cidrs: list[str] = list(_BASELINE_ALLOWLIST_CIDRS) + list(_AUTO_IGNORE_CIDRS)
    extra = os.environ.get("AGENTROPIX_T1071_SVCHOST_ALLOWLIST_EXTRA", "").strip()
    if extra:
        for token in extra.split(","):
            tok = token.strip()
            if tok:
                cidrs.append(tok)
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for c in cidrs:
        try:
            out.append(ipaddress.ip_network(c, strict=False))
        except ValueError as exc:
            logger.warning("invalid CIDR %r in allowlist: %s — skipping", c, exc)
    return out


def _addr_in_networks(
    addr: str,
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    """True iff `addr` is inside any of `nets`. Invalid `addr` → False."""
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    for net in nets:
        try:
            if ip in net:
                return True
        except TypeError:
            # v4 ip vs v6 net (or vice versa) — skip
            continue
    return False


def _is_candidate(
    sock: SocketInfo,
    *,
    ports: frozenset[int],
    allowlist_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    """Return True iff `sock` matches the T1071.001 svchost shape."""
    owner = (sock.owner or "").lower()
    if owner != _SVCHOST_NAME:
        return False
    state = (sock.state or "").upper()
    if state not in _ESTABLISHED_STATES:
        return False
    if sock.foreign_port not in ports:
        return False
    if not sock.foreign_addr:
        return False
    return not _addr_in_networks(sock.foreign_addr, allowlist_nets)


def _emit_hit_finding(
    sock: SocketInfo,
    *,
    image: Path,
    confidence: float,
) -> Finding:
    return Finding(
        source="memory.t1071_001.svchost_outbound_http",
        confidence=confidence,
        description=(
            f"[T1071.001] svchost.exe (pid={sock.pid}) outbound TCP/{sock.foreign_port} "
            f"to non-Microsoft public IP {sock.foreign_addr} (state={sock.state}). "
            f"Canonical Korplug/PlugX C2 callback shape."
        ),
        evidence=(
            f"image={image} pid={sock.pid} owner={sock.owner} "
            f"local={sock.local_addr}:{sock.local_port} "
            f"foreign={sock.foreign_addr}:{sock.foreign_port} "
            f"state={sock.state} proto={sock.proto}"
        ),
        evidence_dict={
            "process_name": sock.owner,
            "process_pid": sock.pid,
            "local_addr": sock.local_addr,
            "local_port": sock.local_port,
            "foreign_addr": sock.foreign_addr,
            "foreign_port": sock.foreign_port,
            "state": sock.state,
            "proto": sock.proto,
            "finding_type": FINDING_TYPE,
        },
        mitre_attack=MITRE_ID,
        timestamp=Finding.now(),
    )


class T1071SvchostOutboundHttpDetector(SwarmAgent):
    """Detect T1071.001 svchost-as-source HTTP callbacks (W-215 closure).

    Strategy:
      1. Skip non-memory images (netscan needs the memory image).
      2. Honour the ``AGENTROPIX_T1071_SVCHOST_DISABLE`` kill switch.
      3. Call ``get_netscan`` (existing MCP wrapper).
      4. For each ``SocketInfo``:
         a. Owner == svchost.exe (case-insensitive).
         b. State in {ESTABLISHED, SYN_SENT}.
         c. foreign_port in {80, 8080, 8000} (env-tunable).
         d. foreign_addr NOT in MS allowlist + RFC 1918 / loopback /
            link-local / multicast auto-ignore.
      5. Emit one Finding per hit + a skip / error Finding for the
         coverage guard (matches injection_detector.py pattern).
    """

    name = "t1071_001_svchost_outbound_http"
    completion_promise = "T1071_001_SVCHOST_OUTBOUND_HTTP_COMPLETE"

    async def investigate(self, image: Path) -> list[Finding]:
        if _resolve_disabled():
            return [
                Finding(
                    source="memory.t1071_001.skipped",
                    confidence=0.0,
                    description=(
                        "T1071SvchostOutboundHttpDetector skipped: "
                        "AGENTROPIX_T1071_SVCHOST_DISABLE=1"
                    ),
                    evidence=f"image={image} reason=detector_disabled",
                    mitre_attack=MITRE_ID,
                    timestamp=Finding.now(),
                )
            ]

        if not looks_like_memory(image):
            return [
                Finding(
                    source="memory.t1071_001.skipped",
                    confidence=0.0,
                    description=(
                        f"T1071SvchostOutboundHttpDetector skipped: "
                        f"{image.name} is not a memory image"
                    ),
                    evidence=f"image={image} reason=non_memory_image",
                    mitre_attack=MITRE_ID,
                    timestamp=Finding.now(),
                )
            ]

        ports = _resolve_ports()
        confidence = _resolve_confidence()
        allowlist_nets = _build_allowlist_networks()

        try:
            report: NetscanReport = await get_netscan(image)
        except (RuntimeError, FileNotFoundError) as exc:
            logger.warning("get_netscan failed on %s: %s", image, exc)
            return [
                Finding(
                    source="memory.t1071_001.error",
                    confidence=0.0,
                    description=(
                        f"T1071SvchostOutboundHttpDetector error: "
                        f"get_netscan failed — {exc!s}"
                    ),
                    evidence=f"image={image} error={exc!s}",
                    mitre_attack=MITRE_ID,
                    timestamp=Finding.now(),
                )
            ]

        findings: list[Finding] = []
        for sock in report.sockets:
            if _is_candidate(sock, ports=ports, allowlist_nets=allowlist_nets):
                findings.append(
                    _emit_hit_finding(sock, image=image, confidence=confidence)
                )

        if not findings:
            # Coverage guard — emit a zero-confidence "ran-but-no-hits"
            # finding so downstream observability can distinguish this
            # from "detector never executed".
            findings.append(
                Finding(
                    source="memory.t1071_001.complete",
                    confidence=0.0,
                    description=(
                        f"T1071SvchostOutboundHttpDetector complete: "
                        f"no svchost outbound HTTP/80 hits across "
                        f"{report.socket_count} sockets"
                    ),
                    evidence=f"image={image} sockets_scanned={report.socket_count}",
                    mitre_attack=MITRE_ID,
                    timestamp=Finding.now(),
                )
            )

        return findings
