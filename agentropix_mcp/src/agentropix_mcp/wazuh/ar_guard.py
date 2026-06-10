"""W-189: active-response protected-CIDR allowlist scaffold.

The Wazuh active-response (AR) path can block an IP fleet-wide. A mis-
classified Tier-1 IP (e.g. an internal jump host, a corporate VPN gateway)
landing on a block list could take production down. This module is
scaffolding: any future call into the AR endpoint MUST validate target
IPs against ``DEFAULT_SAFE_CIDRS`` (extensible via
``AGENTROPIX_AR_PROTECTED_CIDRS``) and refuse to issue the block when
any target IP falls inside a protected network.

Not yet wired into the existing AR code paths — AR is not enabled in the
current orchestrator. Wire-up will happen at the call site when AR ships.
"""

from __future__ import annotations

import ipaddress
import os
import warnings
from collections.abc import Iterable

__all__ = [
    "ARTargetBlocked",
    "DEFAULT_PROTECTED_CIDRS",
    "DEFAULT_SAFE_CIDRS",
    "load_protected_cidrs",
    "load_safe_cidrs",
    "validate_ar_targets",
]


# RFC-1918 + IPv4 loopback + IPv6 loopback/ULA/link-local. Conservative
# default: any private space is off-limits to fleet-wide block. Operators
# MUST opt-in via env to allow blocking inside private ranges (rare;
# usually a config error).
DEFAULT_PROTECTED_CIDRS: tuple[str, ...] = (
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
)

# Deprecated alias retained for one release alongside load_safe_cidrs +
# AGENTROPIX_AR_SAFE_CIDR_ALLOWLIST env. Pin removal target: see W-189
# R6 in SIFT-WEAKNESSES.md.
DEFAULT_SAFE_CIDRS: tuple[str, ...] = DEFAULT_PROTECTED_CIDRS


class ARTargetBlocked(Exception):
    """Raised when an AR call would target an IP inside the safe-CIDR list."""


def _load_protected_cidrs_impl(
    env: dict[str, str] | None,
    *,
    warn_stacklevel: int,
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Shared implementation. ``warn_stacklevel`` lets callers pin the
    DeprecationWarning frame to the operator's code rather than to the
    public-API wrapper. (R9: alias path uses one extra frame.)
    """
    e = env if env is not None else dict(os.environ)
    raw_new = e.get("AGENTROPIX_AR_PROTECTED_CIDRS", "").strip()
    raw_old = e.get("AGENTROPIX_AR_SAFE_CIDR_ALLOWLIST", "").strip()
    if raw_new:
        raw_extra = raw_new
    elif raw_old:
        warnings.warn(
            "AGENTROPIX_AR_SAFE_CIDR_ALLOWLIST is deprecated; "
            "use AGENTROPIX_AR_PROTECTED_CIDRS instead.",
            DeprecationWarning,
            stacklevel=warn_stacklevel,
        )
        raw_extra = raw_old
    else:
        raw_extra = ""
    cidrs: list[str] = list(DEFAULT_PROTECTED_CIDRS)
    if raw_extra:
        cidrs.extend(s.strip() for s in raw_extra.split(",") if s.strip())
    return [ipaddress.ip_network(c, strict=False) for c in cidrs]


def load_protected_cidrs(env: dict[str, str] | None = None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Resolve the effective protected-CIDR list from env (or defaults).

    ``AGENTROPIX_AR_PROTECTED_CIDRS`` is a comma-separated CIDR list
    that EXTENDS the defaults — operators add to the safety net, they
    don't replace it. Invalid CIDRs raise ValueError so misconfiguration
    fails loud at startup rather than at AR-fire time.

    Back-compat: the legacy name ``AGENTROPIX_AR_SAFE_CIDR_ALLOWLIST`` is
    honored when the new name is unset, with a DeprecationWarning. If
    both are set, the new name wins.
    """
    # stacklevel=3 jumps over _load_protected_cidrs_impl + this wrapper.
    return _load_protected_cidrs_impl(env, warn_stacklevel=3)


def load_safe_cidrs(env: dict[str, str] | None = None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Deprecated alias for :func:`load_protected_cidrs`.

    Kept for back-compat of any importers. Will be removed in a future
    release once all call sites migrate to the new name.
    """
    # stacklevel=3 jumps over _load_protected_cidrs_impl + this wrapper.
    return _load_protected_cidrs_impl(env, warn_stacklevel=3)


def validate_ar_targets(
    ip_list: Iterable[str],
    protected_networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None,
    *,
    safe_networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None,
) -> None:
    """Refuse the AR call if any target IP falls inside a protected network.

    Raises:
        ARTargetBlocked: if the target list is empty, contains an
            invalid IP, or any target lies inside a protected network.

    Note:
        ``safe_networks=`` is a deprecated alias for
        ``protected_networks=`` (W-189 H2 rename). It will be removed
        in a future release; see SIFT-WEAKNESSES.md R6 for pin date.
    """
    targets = list(ip_list)
    if not targets:
        raise ARTargetBlocked("AR target list is empty; refusing no-op block")

    if protected_networks is None and safe_networks is not None:
        warnings.warn(
            "validate_ar_targets(safe_networks=...) is deprecated; "
            "use protected_networks= instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        protected_networks = safe_networks

    if protected_networks is None:
        protected_networks = load_protected_cidrs()
    nets = list(protected_networks)

    for raw in targets:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise ARTargetBlocked(f"AR target {raw!r} is not a valid IP") from exc
        for net in nets:
            if ip.version != net.version:
                continue
            if ip in net:
                raise ARTargetBlocked(
                    f"AR target {raw} falls inside safe network {net}; "
                    "refusing fleet-wide block (W-189)"
                )
