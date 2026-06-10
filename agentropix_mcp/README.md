# Agentropix MCP — server source

The **Agentropix-SIFT MCP server** package: the FastMCP application that exposes the
71-tool forensic surface (canonical count — the live number is reported by the `health` tool)
to any MCP client (Claude Code, Claude Desktop, or a headless JSON-RPC driver).

## What's in here

| Path | What it is |
|---|---|
| `Source Code/fastmcp_app.py` | The FastMCP app — `@app.tool()` registrations, stdio + streamable-HTTP (`:8765/mcp`) transports, fail-closed Bearer auth |
| `Source Code/server.py` | The shared tool core (`mcp_*` async functions) — the enforcement boundary |
| `Source Code/thymus_policy.py` | Read-only evidence allowlist checked before every tool execution |
| `Source Code/wrappers/` | The forensic tool wrappers (Sleuth Kit, Volatility 3, Plaso, libewf, YARA, bulk_extractor, RegRipper, Eric Zimmerman tools, …) — argv-only subprocess, never a shell |
| `Source Code/wazuh/` | Wazuh SIEM integration (indexer client, CDB-list publisher, kill switch, FP denylists, dashboards) |
| `Source Code/approval_sidecar/` | The Examiner Approval Portal (`:8800`) — the human HMAC hard-stop (PBKDF2-600k challenge-response, in-browser key derivation) |
| `Source Code/evidence_gate/` | Single-use `egt_` mutation-token registry (SQLite, atomic verify-and-spend) |
| `Source Code/reports/`, `Source Code/schema/` | Report generation/export (ADR-024 tiers) and the sealed-report JSON schemas |
| `Source Code/security/redact.py` | Fail-closed credential redaction |
| `Source Code/courtroom.py` | HMAC-SHA256 report sealing, audit-log cross-binding |

## How it runs

The package ships two console entry points when installed as `agentropix_sift`:

- `agentropix-sift` — the triage CLI (Trinity Loop / DFIR swarm, in-process)
- `agentropix-sift-mcp` — the MCP server. Boot is **fail-closed**: it refuses to start
  without `AGENTROPIX_MCP_AUTH_TOKEN` unless `AGENTROPIX_MCP_DEV_MODE=1`.

Client setup (Claude Code / Claude Desktop `mcp.json`, Bearer-token HTTP, the `mcp-remote`
shim for Desktop) is documented in
[docs/09-integrations/client-setup.md](../docs/09-integrations/client-setup.md).
The validated architecture (pattern, guardrails, component-to-source map) is in
[docs/02-architecture/main-architectural-agentropix-design.md](../docs/02-architecture/main-architectural-agentropix-design.md).

> Internal endpoints in code comments are shown as placeholders (`WAZUH-HOST`); configuration
> is environment-driven — no credentials live in this tree.
