"""SIFT-W-294/W-295 ops launcher.

Usage:
    PYTHONPATH=src python -m agentropix_mcp.approval_sidecar

Required env vars (config.py validates these at startup):

    AGENTROPIX_APPROVER_USER             — examiner id
    AGENTROPIX_APPROVER_PASSWORD         — password the operator will type
                                            in the browser
    AGENTROPIX_APPROVER_SALT_HEX         — per-examiner 16-byte salt (hex)
    WAZUH_INDEXER_URL                    — already set by the existing
                                            agentropix .env

For dev mode (single-host workstation; falls back to writer creds):

    AGENTROPIX_APPROVAL_SIDECAR_DEV_MODE=1

For production (dedicated approver credential):

    AGENTROPIX_APPROVER_INDEXER_USER
    AGENTROPIX_APPROVER_INDEXER_PASSWORD

Optional:

    AGENTROPIX_APPROVAL_SIDECAR_HOST     — default 127.0.0.1
    AGENTROPIX_APPROVAL_SIDECAR_PORT     — default 8800
    AGENTROPIX_APPROVAL_SIDECAR_NONCE_TTL — default 60s
"""

from __future__ import annotations

from agentropix_mcp.approval_sidecar import run

if __name__ == "__main__":
    run()
