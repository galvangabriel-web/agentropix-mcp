"""Hard-coded denylists for the Wazuh IOC push integration.

These are the Tier-3 hard exclusions plus the v1.1 plan §3.3 normalised /
regex / provenance-aware filters back-merged from
``INTEGRATION-PLAN-IOC-STEP1-2026-05-04.md`` §3.3.

v1.1 changes vs original v1.0 exact-string sets (per critics S-1/D-2/D-3):

* ``F_RESPONSE_BENIGN_REGEX`` — case-insensitive regex catches
  ``subject_srv``, ``subject-srv``, ``subjectsrv``, ``subject_srv.ex``,
  ``subject_srv.exe``, etc., after ``_normalise_process`` strips path /
  whitespace / null bytes / trailing dots.
* ``is_installer_guid_path`` — provenance predicate replacing exact-hash
  set; suppresses any MD5 sighted only under
  ``HKLM\\Software\\...\\Installer\\UserData\\<SID>\\Components\\...``.
  The exact-hash set is retained as defence-in-depth (see ``MD5IOCRecord``).
* RFC1918 networks no longer hard-blocked at denylist layer — gated via
  ``accept_internal_ips`` flag and ``WAZUH_OPERATOR_TRUSTED_CIDRS`` env var.

Correct ADRs: ADR-008 (safety), ADR-016 (courtroom seal), ADR-017 (tailnet).
Note: ADR-003 is State Persistence; ADR-004 is SPIFFE/SPIRE — NOT FP gating.
"""

from __future__ import annotations

import ipaddress
import os
import re

__all__ = [
    # Legacy exact-match sets (kept for back-compat and defence-in-depth)
    "F_RESPONSE_BENIGN_DENYLIST",
    "F_RESPONSE_BASENAME_PREFIXES",
    "WINDOWS_INSTALLER_GUID_DENYLIST",
    "INFRA_IP_DENYLIST",
    # v1.1 normalised / regex / provenance helpers
    "F_RESPONSE_BENIGN_REGEX",
    "INSTALLER_GUID_PATH_REGEX",
    "OPERATOR_TRUSTED_CIDRS_ENV",
    "RFC1918_NETS",
    "_normalise_process",
    "_normalise_identifier",
    "is_f_response_benign",
    "is_installer_guid_path",
    "is_rfc1918",
    "load_operator_trusted_cidrs",
    "is_operator_trusted_ip",
]


# ---------------------------------------------------------------------------
# Legacy exact-match sets (back-compat)
# ---------------------------------------------------------------------------

F_RESPONSE_BENIGN_DENYLIST: frozenset[str] = frozenset({"subject_srv.exe"})
F_RESPONSE_BASENAME_PREFIXES: frozenset[str] = frozenset({"subject_srv"})
WINDOWS_INSTALLER_GUID_DENYLIST: frozenset[str] = frozenset(
    {"54377da4ea8d4e044bc107e65cf16ef3"}
)
INFRA_IP_DENYLIST: frozenset[str] = frozenset(
    {
        "172.16.4.4",  # Domain Controller
        "172.16.4.5",  # File server
        "172.16.5.50",  # F-Response controller
    }
)


# ---------------------------------------------------------------------------
# v1.1 normalisation helpers (plan §3.3)
# ---------------------------------------------------------------------------


def _normalise_process(value: str) -> str:
    """Strip path, lowercase, strip whitespace+null, drop trailing dot.

    Comparisons happen AFTER this normalisation step so that case variants,
    path prefixes, separators, and trailing-dot bypass attempts collapse to
    the same canonical form.
    """
    if not isinstance(value, str):
        return ""
    base = value.replace("\\", "/").rsplit("/", 1)[-1]
    base = base.strip().rstrip(".\x00 \t\r\n").lower()
    return base


def _normalise_identifier(value: str) -> str:
    """Lowercase + strip braces/whitespace for username/SID/regkey compares."""
    if not isinstance(value, str):
        return ""
    return value.strip().strip("{}").lower()


# Matches subject_srv, subjectsrv, subject-srv, subject_srv.ex, subject_srv.exe, …
# Case-insensitive; pre-normalise input via _normalise_process.
F_RESPONSE_BENIGN_REGEX: re.Pattern[str] = re.compile(
    r"^subject[_-]?srv(\.ex[e_]?)?$"
)


def is_f_response_benign(process_name: str) -> bool:
    """True if ``process_name`` matches the F-Response benign regex.

    Defence-in-depth: callers should rely on this instead of the legacy
    ``F_RESPONSE_BENIGN_DENYLIST`` exact-match set.
    """
    return bool(F_RESPONSE_BENIGN_REGEX.match(_normalise_process(process_name)))


# ---------------------------------------------------------------------------
# Installer GUID provenance check (plan §3.3 — Gap A4 is a CLASS, not a hash)
# ---------------------------------------------------------------------------

# Matches ``...\\Installer\\UserData\\<anything>\\Components\\...`` and the
# forward-slash equivalent (case-insensitive); the SID/GUID itself is opaque.
INSTALLER_GUID_PATH_REGEX: re.Pattern[str] = re.compile(
    r"[\\/]Installer[\\/]UserData[\\/][^\\/]+[\\/]Components[\\/]",
    re.IGNORECASE,
)


def is_installer_guid_path(path: str) -> bool:
    """True if ``path`` is a Windows Installer Components registry path.

    A single MD5 sighting under this path class is benign (Windows Installer
    Component GUID, not a malware hash). The plan calls for suppressing any
    MD5 whose ALL sightings match this predicate; that aggregation lives in
    the orchestrator/inventory layer when it ships in Step-1.5. This module
    exposes the per-path predicate.
    """
    if not isinstance(path, str) or not path:
        return False
    return bool(INSTALLER_GUID_PATH_REGEX.search(path))


# ---------------------------------------------------------------------------
# RFC1918 + operator-trusted CIDR gate (plan §3.3)
# ---------------------------------------------------------------------------

OPERATOR_TRUSTED_CIDRS_ENV: str = "WAZUH_OPERATOR_TRUSTED_CIDRS"

RFC1918_NETS: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
)

_RFC1918_NETWORKS = tuple(ipaddress.ip_network(c) for c in RFC1918_NETS)


def is_rfc1918(ip: str) -> bool:
    """True if ``ip`` is an IPv4 address inside any RFC1918 range."""
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    if not isinstance(addr, ipaddress.IPv4Address):
        return False
    return any(addr in net for net in _RFC1918_NETWORKS)


def load_operator_trusted_cidrs(env: dict[str, str] | None = None) -> tuple[str, ...]:
    """Read ``WAZUH_OPERATOR_TRUSTED_CIDRS`` (comma-separated) from env.

    Empty / unset returns ``()``. Whitespace around CIDRs is tolerated.
    Invalid CIDRs are dropped silently (operator misconfiguration must not
    break the IOC push pipeline; the orchestrator should surface a warning).
    """
    source = env if env is not None else os.environ
    raw = source.get(OPERATOR_TRUSTED_CIDRS_ENV, "") or ""
    out: list[str] = []
    for token in raw.split(","):
        cidr = token.strip()
        if not cidr:
            continue
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        out.append(cidr)
    return tuple(out)


def is_operator_trusted_ip(ip: str, trusted_cidrs: tuple[str, ...]) -> bool:
    """True if ``ip`` falls inside any operator-trusted CIDR."""
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    for cidr in trusted_cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False
