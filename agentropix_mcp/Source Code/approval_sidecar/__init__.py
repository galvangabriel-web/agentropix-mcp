"""SIFT-W-288: FastAPI/Starlette approval sidecar — Phase 1 (HMAC API).

The agentropix MCP wrapper (W-286) forces every finding to ``DRAFT``
and strips any caller-supplied ``approval.*``. Only this sidecar — a
separate process bound to port 8800 (env-tunable via
``AGENTROPIX_APPROVAL_SIDECAR_PORT``) holding the approver credential
— can move a finding to ``APPROVED``.

Why a sidecar at all?

  Pure OpenSearch Dashboards 2.19.5 (the Wazuh fork at
  ``https://WAZUH-HOST``) cannot host the browser-side PBKDF2 +
  HMAC challenge-response flow. The 10-agent crew investigation
  (logs/2026-05-27-valhuntir-wazuh-research/SYNTHESIS.md) confirmed
  three architectural blockers in OSD: no write-back, no styled
  detail pane, no keyboard-shortcut hosting. A small Starlette app
  on the same workstation (operator decision 2026-05-27) closes all
  three for ~1 % the LoC of a custom OSD plugin.

Why HMAC challenge-response?

  The L1 invariant in Valhuntir's architecture model
  (``~/example/Valhuntir/docs/architecture.md`` § Human-in-the-Loop
  Controls) is that the LLM cannot self-approve — only a human with
  the approver password can move a finding to APPROVED. The browser
  derives the PBKDF2 key client-side from the password the operator
  typed, then computes ``HMAC-SHA256(key, nonce || target_id || ...)``
  and sends only the HMAC. The password never crosses the wire.

  The nonce is server-issued, single-use, and expires after 60 s —
  defeating replay attacks across the challenge-response.

Phase 1 (this module):

  - Starlette app + routes (``/healthz``, ``/challenge``, ``/approve``).
  - PBKDF2 key derivation + HMAC verify primitives (``auth.py``).
  - In-memory TTL nonce store (``nonce.py``).
  - Hash-chain helpers for ``prev_approval_hash`` (``hash_chain.py``).
  - Pydantic request / response models (``models.py``).
  - Config reader (``config.py``) — approver credentials live in
    ``AGENTROPIX_APPROVER_USER`` + ``AGENTROPIX_APPROVER_PASSWORD``
    env vars, distinct from the existing ``WAZUH_INDEXER_*`` writer
    credentials per Crew #3's dual-credential split.

Phase 2 (next PR): static HTML page using Web Crypto API for the
browser-side PBKDF2, dual indexer-credential split wired into
``IndexerClient``, real ``read_only`` policy applied on the indexer.

Phase 1 deliberately *does not* require a live OpenSearch indexer to
run — the routes accept a pluggable ``approve_writer`` callable so
unit tests can drop in a stub. The default writer uses
``IndexerClient`` with the approver credentials.
"""

from __future__ import annotations

from agentropix_mcp.approval_sidecar.app import build_app, run
from agentropix_mcp.approval_sidecar.auth import (
    derive_key,
    hmac_signature,
    verify_signature,
)
from agentropix_mcp.approval_sidecar.config import SidecarConfig
from agentropix_mcp.approval_sidecar.hash_chain import (
    compute_approval_id,
    compute_content_hash,
)
from agentropix_mcp.approval_sidecar.models import (
    ApprovalSubmitRequest,
    ApprovalSubmitResponse,
    ChallengeRequest,
    ChallengeResponse,
)
from agentropix_mcp.approval_sidecar.nonce import (
    NonceExpired,
    NonceStore,
    NonceUnknown,
)

__all__ = [
    "ApprovalSubmitRequest",
    "ApprovalSubmitResponse",
    "ChallengeRequest",
    "ChallengeResponse",
    "NonceExpired",
    "NonceStore",
    "NonceUnknown",
    "SidecarConfig",
    "build_app",
    "compute_approval_id",
    "compute_content_hash",
    "derive_key",
    "hmac_signature",
    "run",
    "verify_signature",
]
