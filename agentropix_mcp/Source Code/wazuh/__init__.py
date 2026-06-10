"""Wazuh IOC push integration for Agentropix SIFT.

Step 1: Forensic IOC discovery → filter → transform → push to Wazuh as
CDB lists + custom rules pack → coalesced manager restart → HMAC-SHA256
chain-of-custody seal → audit log.

Correct ADRs:
  - ADR-008: Safety Architecture (Thymus STRICT + EvidenceGate write gate)
  - ADR-016: Courtroom Audit (HMAC-SHA256 seal with per-run session key)
  - ADR-017: Tailnet-only exposure (outbound Wazuh egress constraints)

Note: ADR-003 is State Persistence (git checkpointing) — NOT FP suppression.
Note: ADR-004 is SPIFFE/SPIRE identity — NOT benign tool labeling.
Note: ADR-011 is evidence file type detection — NOT mutation token regime.
"""

from __future__ import annotations

from agentropix_mcp.wazuh.client import WazuhClient
from agentropix_mcp.wazuh.config import WazuhConfig
from agentropix_mcp.wazuh.orchestrator import WazuhIOCPushResult, push_iocs

__all__ = [
    "WazuhClient",
    "WazuhConfig",
    "push_iocs",
    "WazuhIOCPushResult",
]
