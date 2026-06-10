"""IOC priority classifier — Tier-1/2/3 classification.

Implements the scoring rubric from ``00_PLAN.md`` §3.2 and the hard
exclusions from §3 Tier-3. The classifier is stateless; pass the config-
supplied allowlist on construction.

Fix 6 (A-1): Tier-3 IOC construction is impossible at the model layer
(MD5IOCRecord rejects the Installer GUID; ProcessIOCRecord rejects
subject_srv.* at __init__ time). This module enforces the classifier-level
tier decision for the full IOCRecord set, adding RFC1918 infra IP exclusions
that cannot be baked into the model validators (they depend on the operator
allowlist supplied at runtime).

Correct ADRs: ADR-008 (safety/Thymus), ADR-016 (courtroom seal), ADR-017 (tailnet).
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

from agentropix_mcp.wazuh.denylists import (
    INFRA_IP_DENYLIST,
    is_installer_guid_path,
    is_operator_trusted_ip,
    load_operator_trusted_cidrs,
)

if TYPE_CHECKING:
    pass

__all__ = ["PriorityClassifier", "classify_ioc", "Decision"]


# Re-export Decision for callers that import from this module
from agentropix_mcp.wazuh.models import Decision  # noqa: E402

# ---------------------------------------------------------------------------
# Tier constants (string values matching PriorityTier / Tier)
# ---------------------------------------------------------------------------

TIER1 = "tier1"
TIER2 = "tier2"
TIER3_EXCLUDED = "tier3_excluded"
TIER4_SUGGEST = "tier4_suggest"

# Alias for test compat
EXCLUDED = TIER3_EXCLUDED


# ---------------------------------------------------------------------------
# RFC1918 + special-purpose networks (always excluded)
# ---------------------------------------------------------------------------

_ALWAYS_EXCLUDED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("240.0.0.0/4"),  # reserved
    ipaddress.ip_network("0.0.0.0/8"),  # unspecified
    ipaddress.ip_network("255.255.255.255/32"),  # broadcast
]


def _is_protected_network(addr: ipaddress.IPv4Address, extra_cidrs: list[str]) -> bool:
    """Return True if addr falls in any protected/excluded network."""
    for net in _ALWAYS_EXCLUDED_NETWORKS:
        if addr in net:
            return True
    for cidr in extra_cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


class PriorityClassifier:
    """Stateless IOC priority classifier.

    Args:
        ip_allowlist: CIDR strings from WAZUH_IP_ALLOWLIST. IPs in these
            ranges are Tier-3 excluded (self-block prevention).
    """

    def __init__(
        self,
        ip_allowlist: list[str] | None = None,
        operator_trusted_cidrs: tuple[str, ...] | None = None,
    ) -> None:
        self._ip_allowlist: list[str] = ip_allowlist or []
        # F-4 partial wiring: §3.3 operator-trusted CIDRs. When unset
        # (default), falls back to the env var so operators can opt in
        # without code changes. Empty tuple means "no extra exclusions"
        # — backwards-compatible.
        if operator_trusted_cidrs is None:
            operator_trusted_cidrs = load_operator_trusted_cidrs()
        self._operator_trusted_cidrs: tuple[str, ...] = operator_trusted_cidrs

    def classify(self, ioc: object) -> Decision:
        """Classify a single IOCRecord and return a Decision.

        The ``ioc`` argument should be one of the IOCRecord variant types.
        Because model-layer validators already reject the hardest Tier-3 cases
        (Installer GUID, F-Response), we only need to handle the infra-IP
        exclusions and the tier-promotion logic here.
        """
        kind = getattr(ioc, "kind", None)
        value = getattr(ioc, "value", "")
        confidence = getattr(ioc, "confidence", "medium")
        port = getattr(ioc, "port", None)
        connection_state = getattr(ioc, "connection_state", None)
        host_count = getattr(ioc, "host_count", 1)

        if kind == "ip":
            return self._classify_ip(value, confidence, port, connection_state, host_count)
        elif kind == "hash_sha256":
            return Decision(tier=TIER1, reason="SHA-256 hash — zero collision risk; Tier 1")
        elif kind == "hash_md5":
            # F-4 partial wiring: §3.3 Installer GUID provenance check.
            # MD5 sightings whose source_path matches the Windows
            # Installer Components registry path class are benign (Gap A4
            # is a CLASS, not a single hash); exclude as Tier-3.
            source_path = getattr(ioc, "source_path", None)
            if source_path and is_installer_guid_path(source_path):
                return Decision(
                    tier=TIER3_EXCLUDED,
                    reason=(
                        f"MD5 source_path {source_path!r} matches Windows "
                        "Installer Components path class (Gap A4); benign"
                    ),
                )
            return Decision(tier=TIER2, reason="MD5 hash — Tier 2 (lower collision resistance)")
        elif kind == "process_name":
            return Decision(
                tier=TIER2,
                reason=f"process name {value!r} — Tier 2 (names reusable by legit processes)",
            )
        elif kind == "registry_key":
            return Decision(
                tier=TIER2,
                reason="registry persistence key — Tier 2 (written by legit installers too)",
            )
        elif kind == "process_tree_event":
            evidence_kind = getattr(ioc, "evidence_kind", None)
            if evidence_kind == "suspicious":
                return Decision(
                    tier=TIER1,
                    reason="process-tree suspicious parent-child relation — Tier 1",
                )
            if evidence_kind == "orphan":
                return Decision(
                    tier=TIER2,
                    reason="process-tree orphan — Tier 2 (correlation signal)",
                )
            return Decision(
                tier=TIER2,
                reason="process-tree relation — Tier 2 (default)",
            )
        else:
            return Decision(tier=TIER3_EXCLUDED, reason=f"unknown IOC kind {kind!r}")

    def _classify_ip(
        self,
        value: str,
        confidence: str,
        port: int | None,
        connection_state: str | None,
        host_count: int,
    ) -> Decision:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return Decision(tier=TIER3_EXCLUDED, reason=f"IP {value!r} is not a valid address")

        if not isinstance(addr, ipaddress.IPv4Address):
            return Decision(
                tier=TIER3_EXCLUDED,
                reason=f"IPv6 IOC {value!r} deferred to Step 2",
            )

        # Hard exclusion: protected networks
        if _is_protected_network(addr, self._ip_allowlist):
            return Decision(
                tier=TIER3_EXCLUDED,
                reason=f"IP {value!r} is in a protected/excluded network",
            )

        # Hard exclusion: specific infra IPs (SRL-2018 specific)
        if value in INFRA_IP_DENYLIST:
            return Decision(
                tier=TIER3_EXCLUDED,
                reason=f"IP {value!r} is a known infrastructure IP (SRL-2018 inventory); "
                "pushing infra IP = self-blocking",
            )

        # F-4 partial wiring: §3.3 operator-trusted CIDR exclusion. If the
        # operator declared their own trusted networks via
        # WAZUH_OPERATOR_TRUSTED_CIDRS, refuse to push any IP inside them
        # — same self-block prevention rationale as INFRA_IP_DENYLIST.
        if self._operator_trusted_cidrs and is_operator_trusted_ip(
            value, self._operator_trusted_cidrs
        ):
            return Decision(
                tier=TIER3_EXCLUDED,
                reason=(
                    f"IP {value!r} falls inside an operator-trusted CIDR; "
                    "refusing to push (self-block prevention)"
                ),
            )

        # Tier-1 promotion: ESTABLISHED connection + multi-host OR non-standard port
        if connection_state == "ESTABLISHED":
            if host_count >= 2:
                return Decision(
                    tier=TIER1,
                    reason=(f"IP {value!r} observed ESTABLISHED on {host_count} hosts — high-confidence C2 (Tier 1)"),
                )
            if port and port not in (80, 443, 8080, 8443, 22, 25, 53, 110, 143):
                return Decision(
                    tier=TIER1,
                    reason=(f"IP {value!r} ESTABLISHED on non-standard port {port} — high-confidence C2 (Tier 1)"),
                )

        # Tier-2: private C2 with ESTABLISHED (lower confidence single-host)
        if connection_state == "ESTABLISHED":
            return Decision(
                tier=TIER2,
                reason=f"IP {value!r} ESTABLISHED single-host standard-port — Tier 2",
            )

        # Tier-2: any other non-excluded IP
        return Decision(
            tier=TIER2,
            reason=f"IP {value!r} — Tier 2 (unconfirmed; monitor-only)",
        )


def classify_ioc(ioc: object, ip_allowlist: list[str] | None = None) -> Decision:
    """Module-level convenience wrapper around PriorityClassifier."""
    return PriorityClassifier(ip_allowlist=ip_allowlist).classify(ioc)
