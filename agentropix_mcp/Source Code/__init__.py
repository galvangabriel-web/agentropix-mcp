"""Agentropix MCP — a governed Model Context Protocol server for DFIR.

Exposes Volatility 3, Plaso, RegRipper, EZ Tools, YARA, and supporting
forensic utilities through a FastMCP HTTP/SSE endpoint with HMAC bearer
auth (fail-closed at boot), tamper-evident HMAC-sealed audit log, and
architectural read-only enforcement on evidence directories.
"""

from __future__ import annotations

__version__ = "0.2.2"
