"""SIFT-W-288: approval sidecar configuration.

Reads from env vars at import / instantiation time. Provides
``SidecarConfig.from_env()`` matching the existing
``WazuhConfig.from_env()`` pattern used elsewhere in the wazuh
package.

Key invariant: the sidecar uses **distinct** credentials from the
existing ``WAZUH_INDEXER_USER`` / ``WAZUH_INDEXER_PASS`` writer pair.
Per Crew #3's dual-credential split (`SUBAGENT3-confirm.md` claim 4),
the writer credential should never be authorized to mutate the
approvals index — only the approver credential should be.

In dev mode (``AGENTROPIX_APPROVAL_SIDECAR_DEV_MODE=1``) the sidecar
falls back to the writer credentials with a loud warning. This is
ONLY for local development; production deployments must set both
credential pairs explicitly.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Defaults — operators override via env. Floor/ceiling guards mirror
# the existing wazuh.config conventions.
DEFAULT_PORT: int = 8800
DEFAULT_HOST: str = "127.0.0.1"  # tailnet exposure done by the reverse proxy
DEFAULT_NONCE_TTL: float = 60.0
DEFAULT_PBKDF2_ITERATIONS: int = 600_000


@dataclass
class SidecarConfig:
    host: str
    port: int
    nonce_ttl_seconds: float
    pbkdf2_iterations: int

    # Approver credentials — distinct from the indexer-writer credential
    # pair already managed by WazuhConfig.
    examiner_id: str
    approver_password: str  # held in memory; never logged
    approver_salt_hex: str

    # OpenSearch endpoint that the sidecar writes to. Defaults to the
    # same indexer the existing WazuhConfig writes findings to.
    indexer_url: str
    indexer_user: str  # approver-cred (NOT the writer-cred)
    indexer_password: str

    # Dev-mode escape valve — falls back to the writer cred. Logged loudly.
    dev_mode: bool

    def __repr__(self) -> str:  # never leak the secret into logs
        return (
            f"SidecarConfig(host={self.host!r}, port={self.port}, "
            f"nonce_ttl_seconds={self.nonce_ttl_seconds}, "
            f"pbkdf2_iterations={self.pbkdf2_iterations}, "
            f"examiner_id={self.examiner_id!r}, "
            f"approver_password='***redacted***', "
            f"approver_salt_hex='{self.approver_salt_hex[:8]}...', "
            f"indexer_url={self.indexer_url!r}, "
            f"indexer_user={self.indexer_user!r}, "
            f"indexer_password='***redacted***', "
            f"dev_mode={self.dev_mode})"
        )

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> SidecarConfig:
        """Build a SidecarConfig from the provided env dict (default
        ``os.environ``).

        Raises:
            RuntimeError: when required env vars are missing in
                production mode.
        """
        e = env if env is not None else os.environ

        host = e.get("AGENTROPIX_APPROVAL_SIDECAR_HOST", DEFAULT_HOST).strip()
        port = _bounded_int(
            e.get("AGENTROPIX_APPROVAL_SIDECAR_PORT", str(DEFAULT_PORT)),
            DEFAULT_PORT,
            floor=1024,
            ceiling=65535,
        )
        nonce_ttl = _bounded_float(
            e.get(
                "AGENTROPIX_APPROVAL_SIDECAR_NONCE_TTL",
                str(DEFAULT_NONCE_TTL),
            ),
            DEFAULT_NONCE_TTL,
            floor=5.0,
            ceiling=600.0,
        )
        pbkdf2_iter = _bounded_int(
            e.get(
                "AGENTROPIX_APPROVAL_SIDECAR_PBKDF2_ITERATIONS",
                str(DEFAULT_PBKDF2_ITERATIONS),
            ),
            DEFAULT_PBKDF2_ITERATIONS,
            floor=10_000,
            ceiling=10_000_000,
        )

        examiner_id = e.get("AGENTROPIX_APPROVER_USER", "").strip()
        approver_password = e.get("AGENTROPIX_APPROVER_PASSWORD", "").strip()
        approver_salt_hex = e.get("AGENTROPIX_APPROVER_SALT_HEX", "").strip()

        indexer_url = e.get("WAZUH_INDEXER_URL", "").strip()
        indexer_user = e.get("AGENTROPIX_APPROVER_INDEXER_USER", "").strip()
        indexer_password = e.get("AGENTROPIX_APPROVER_INDEXER_PASSWORD", "").strip()

        dev_mode = e.get("AGENTROPIX_APPROVAL_SIDECAR_DEV_MODE", "0") == "1"

        # Dev fallback: writer creds → approver creds with a loud warning.
        if dev_mode and not indexer_user:
            indexer_user = e.get("WAZUH_INDEXER_USER", "").strip()
            indexer_password = e.get("WAZUH_INDEXER_PASS", "").strip()
            logger.warning(
                "SIFT-W-288 DEV MODE: falling back to WAZUH_INDEXER_USER/PASS "
                "for approver-credential. DO NOT USE IN PRODUCTION."
            )

        # Hard requirements — without these the sidecar cannot function
        # safely. Refuse to start rather than start in a degraded mode
        # the operator might not notice.
        missing: list[str] = []
        if not examiner_id:
            missing.append("AGENTROPIX_APPROVER_USER")
        if not approver_password:
            missing.append("AGENTROPIX_APPROVER_PASSWORD")
        if not approver_salt_hex:
            missing.append("AGENTROPIX_APPROVER_SALT_HEX")
        if not indexer_url:
            missing.append("WAZUH_INDEXER_URL")
        if not indexer_user and not dev_mode:
            missing.append("AGENTROPIX_APPROVER_INDEXER_USER")
        if not indexer_password and not dev_mode:
            missing.append("AGENTROPIX_APPROVER_INDEXER_PASSWORD")
        if missing:
            raise RuntimeError(
                "Approval sidecar config missing required env vars: " + ", ".join(missing)
            )

        return cls(
            host=host,
            port=port,
            nonce_ttl_seconds=nonce_ttl,
            pbkdf2_iterations=pbkdf2_iter,
            examiner_id=examiner_id,
            approver_password=approver_password,
            approver_salt_hex=approver_salt_hex,
            indexer_url=indexer_url,
            indexer_user=indexer_user,
            indexer_password=indexer_password,
            dev_mode=dev_mode,
        )


def _bounded_int(raw: str, default: int, *, floor: int, ceiling: int) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(floor, min(ceiling, value))


def _bounded_float(raw: str, default: float, *, floor: float, ceiling: float) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return default
    return max(floor, min(ceiling, value))
