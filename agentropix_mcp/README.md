# Agentropix MCP — server source

The **Agentropix-SIFT MCP server** package: the FastMCP application that exposes the
71-tool forensic surface (canonical count — the live number is reported by the `health` tool)
to any MCP client (Claude Code, Claude Desktop, or a headless JSON-RPC driver).

## Install

```bash
pip install ./agentropix_mcp                 # core server (fastmcp, pydantic, httpx, sidecar)
pip install "./agentropix_mcp[forensics]"    # + in-process parsers (yara, pytsk3, pypff, oletools, vol3)
pip install "./agentropix_mcp[reports]"      # + report rendering (markdown, weasyprint)
```

Then run the console script (boot is **fail-closed** — it refuses to start without
`AGENTROPIX_MCP_AUTH_TOKEN` unless `AGENTROPIX_MCP_DEV_MODE=1`):

```bash
AGENTROPIX_MCP_AUTH_TOKEN="$(openssl rand -base64 32)" agentropix-mcp --transport http --port 8765
# or stdio (default) for a local Claude Desktop / Claude Code mcp.json `command` entry:
agentropix-mcp
```

The classic SIFT binaries the wrappers drive (`vol`, `fls`/`mmls`/`icat`, `ewfinfo`, `yara`,
`bulk_extractor`, `rip.pl`, Eric Zimmerman tools via `dotnet`, …) are resolved from `PATH`
at call time — they come from the SIFT Workstation itself, not from pip.

## What's in here

| Path | What it is |
|---|---|
| `src/agentropix_mcp/fastmcp_app.py` | The FastMCP app — `@app.tool()` registrations, stdio + streamable-HTTP (`:8765/mcp`) transports, fail-closed Bearer auth |
| `src/agentropix_mcp/server.py` | The shared tool core (`mcp_*` async functions) — the enforcement boundary |
| `src/agentropix_mcp/thymus_policy.py` | Read-only evidence allowlist checked before every tool execution |
| `src/agentropix_mcp/wrappers/` | The forensic tool wrappers (Sleuth Kit, Volatility 3, Plaso, libewf, YARA, bulk_extractor, RegRipper, Eric Zimmerman tools, …) — argv-only subprocess, never a shell |
| `src/agentropix_mcp/wazuh/` | Wazuh SIEM integration (indexer client, CDB-list publisher, kill switch, FP denylists, dashboards) |
| `src/agentropix_mcp/approval_sidecar/` | The Examiner Approval Portal (`:8800`) — the human HMAC hard-stop (PBKDF2-600k challenge-response, in-browser key derivation) |
| `src/agentropix_mcp/evidence_gate/` | Single-use `egt_` mutation-token registry (SQLite, atomic verify-and-spend) |
| `src/agentropix_mcp/reports/`, `src/agentropix_mcp/schema/` | Report generation/export (ADR-024 tiers) and the sealed-report JSON schemas |
| `src/agentropix_mcp/security/redact.py` | Fail-closed credential redaction |
| `src/agentropix_mcp/courtroom.py` | HMAC-SHA256 report sealing, audit-log cross-binding |

## Entry points

Installing this package (`pip install ./agentropix_mcp`) provides:

- **`agentropix-mcp`** — the MCP server console script (`agentropix_mcp.fastmcp_app:main`);
  `--transport stdio` (default) or `--transport http --port 8765`. Boot is **fail-closed**:
  it refuses to start without `AGENTROPIX_MCP_AUTH_TOKEN` unless `AGENTROPIX_MCP_DEV_MODE=1`.
- **`python -m agentropix_mcp.approval_sidecar`** — the Examiner Approval Portal (`:8800`).

(The full Agentropix-SIFT distribution additionally ships the `agentropix-sift` triage CLI —
Trinity Loop / DFIR swarm — which is not part of this MCP-server package.)

Client setup (Claude Code / Claude Desktop `mcp.json`, Bearer-token HTTP, the `mcp-remote`
shim for Desktop) is documented in
[docs/09-integrations/client-setup.md](../docs/09-integrations/client-setup.md).
The validated architecture (pattern, guardrails, component-to-source map) is in
[docs/02-architecture/main-architectural-agentropix-design.md](../docs/02-architecture/main-architectural-agentropix-design.md).

> Internal endpoints in code comments are shown as placeholders (`WAZUH-HOST`); configuration
> is environment-driven — no credentials live in this tree.
