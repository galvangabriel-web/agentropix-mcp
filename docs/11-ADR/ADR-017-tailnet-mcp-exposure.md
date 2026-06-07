> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-017: Tailnet-only HTTP MCP exposure for the FastMCP server

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-04-25 |
| **Decision Makers** | BMAD-M8 sprint executor (Claude), Operator (gate post-M8.6) |
| **Bio-Agentic Component** | MCP transport — Goal 1 deepening (move from in-process Python to over-the-wire MCP) |
| **Priority** | P1 — unblocks demo distribution to hackathon judges without exposing the project to the public internet |

## Context

M8.4a shipped a FastMCP stdio server (`fastmcp_app.py`) that exposes
the 16 SIFT forensic tools over the MCP protocol. The stdio transport
works for a Claude Desktop instance running on the same host — judges
would have to install Claude Desktop on the operator's laptop to test.

The hackathon goal is for **a remote judge to point their own Claude
Desktop / Claude Code at the SIFT server and run a forensic query**.
That requires an over-the-wire transport. Three options were considered
in `BMAD-M8-HACKATHON-SCORECARD.md`:

1. **Tailscale-only HTTP+SSE** — server binds the tailnet IP; only
   tailnet members can reach it.
2. **Public HTTP with bearer auth + bundled demo evidence** — wide
   reach, materially more security work.
3. **ngrok TCP tunnel** — rejected (open by default, no auth).

This ADR captures the decision to ship Path 1 first.

## Decision

**FastMCP gets a `--transport http` mode that defaults to
loopback-only (`127.0.0.1`).** The operator opts into tailnet
exposure by passing `--host <their-tailnet-ip>` (looked up via
`tailscale ip -4`). Public exposure (`0.0.0.0`) requires the explicit
`--public` flag, which logs a loud warning and is **strongly
discouraged** without the additional hardening listed in §
"Public-exposure pre-flight" below.

```python
# Three operator-visible bind modes:
agentropix-sift-mcp --transport http                                # 127.0.0.1:8765
agentropix-sift-mcp --transport http --host 100.64.5.7 --port 8765  # tailnet only
agentropix-sift-mcp --transport http --public                       # 0.0.0.0 — see warnings
```

The default transport remains `stdio` for back-compat (the M8.5b cron
verifier exercises stdio; switching default would break it).

## Threat model

### What tailnet exposure protects against
- **Public scan-and-grab.** Tailscale uses CGNAT (`100.64.0.0/10`) and
  WireGuard; the server is unreachable from the public internet.
- **Casual port scanning.** No port is open on the operator's public
  IP unless explicitly mapped.
- **TLS interception.** Tailscale handles encryption at the WireGuard
  layer; HTTP-over-tailnet is end-to-end encrypted between peers.
- **Identity confusion.** Tailnet membership is identity-bound (your
  Tailscale account + 2FA); each peer is named.

### What tailnet exposure does NOT protect against
- **Compromised tailnet member.** A malicious or compromised peer
  inside the tailnet has the same access as a judge. Mitigation:
  invite-link rotation after the hackathon; ACLs scoped to a subset
  of users where possible.
- **Server-side resource exhaustion.** Forensic tools (plaso, vol3)
  are heavy; a peer can DoS the server by hammering tools/list +
  triggering long-running plaso invocations. Existing mitigations:
  `AGENTROPIX_RATE_LIMIT` (60 calls/min), per-tool timeouts. Future:
  per-peer rate limits.
- **Path-traversal in evidence references.** Tools accept evidence
  paths as strings. Thymus' allowlist defends; tailnet exposure
  doesn't change the policy. Operators MUST ensure
  `AGENTROPIX_THYMUS_ALLOWED_PREFIXES` is tight before sharing.

### What changes vs local stdio
- Authentication. Stdio = "whoever launched the process". Tailnet HTTP
  = "any peer in the tailnet". The latter is meaningfully wider; ACLs
  inside Tailscale (or invite-only sub-groups) become the auth model.
- Side-channel surface. HTTP+SSE adds headers, request IDs, timing
  observable to peers; stdio is purely in-process.
- Court-defensibility. **The seal in ADR-016 binds to `(image_bytes,
  session_key, report_json)` regardless of transport — but the
  *narrative* changes:** "this analysis was driven by a remote agent
  via tailnet HTTP, the tools ran on the operator's machine, the
  seal was computed locally." A defense expert reading the report
  must understand the chain. The seal itself is unaffected.

## Public-exposure pre-flight (Path 2)

**Do not set `--public` without all of these in place.** This is the
"hackathon visibility outweighs forensic risk" path, and it's an
explicit operator decision.

| Hardening item | Required for `--public`? |
|---|---|
| Bearer-token auth in front of FastMCP | **YES** — minimum bar |
| Thymus locked to a `samples/` allowlist (no real evidence accessible) | **YES** |
| Per-IP rate limit (≤ 60 calls/min, ideally lower) | **YES** |
| TLS termination via Caddy / Cloudflare / Tailscale Funnel | **YES** |
| Logging of every request to a tamper-evident audit file | **YES** |
| Bundled demo evidence (`samples/sample.dd`) only — no real cases | **YES** |
| ADR-016 court-seal claim downgraded for public-server reports | **YES** (separate seal-authority story) |

The Tailscale-only path (`--host <tailnet-ip>`) deliberately does NOT
require these because the trust boundary is the tailnet membership
list. If the operator decides to go public-mode for the hackathon
demo, M8.7 (or a follow-on sprint) ships the hardening.

## Acceptance / Implementation gates

- [x] `fastmcp_app.main()` parses `--transport`, `--host`, `--port`, `--public`.
- [x] Default transport is `stdio` (M8.5b cron unaffected).
- [x] HTTP default bind is loopback (`127.0.0.1`) when no `--host` given.
- [x] `--public` logs a loud warning at startup.
- [x] 6 new CLI tests in `tests/unit/test_fastmcp_app.py::TestCliArgs`.
- [x] Operator runbook at `docs/runbooks/expose-fastmcp-tailnet.md`.
- [ ] Bearer-token middleware (deferred to M8.7 if `--public` is ever needed).
- [ ] Per-peer rate limit beyond the global one (deferred).

## Verification

A judge connecting via the tailnet path:

```bash
# 1. Operator (you) — start the server bound to the tailnet IP:
$ tailscale ip -4
100.64.5.7
$ agentropix-sift-mcp --transport http --host 100.64.5.7 --port 8765
... Starting MCP server 'agentropix-sift' with transport 'http' on http://100.64.5.7:8765/mcp

# 2. Guest (judge) — accept your tailnet invite, install Tailscale,
#    confirm reachability, add to mcp.json:
$ tailscale up
$ curl -v http://100.64.5.7:8765/mcp   # 405 Method Not Allowed = server up
$ # Claude Desktop: ~/Library/Application Support/Claude/claude_desktop_config.json:
$ #   {"mcpServers":{"agentropix-sift":{"url":"http://100.64.5.7:8765/mcp","transport":"http"}}}
$ # Claude Code (CLI): claude mcp add --transport http agentropix-sift http://100.64.5.7:8765/mcp
$ # Restart Claude Desktop / start a Claude Code session; tools/list shows 16 forensic tools.

# 3. Operator — watch the audit log for guest activity:
$ tail -f .claude/ralph.jsonl  # if Ralph hooks installed (M8.3a)
$ # AND the per-tool trace lands in the next report.json under report.thymus_audit
```

If the SSE GET hits without a network error, the tailnet path is live.
If it 404s on `/sse`, FastMCP version expects a different route — check
`fastmcp` package version and adjust the URL accordingly (the path is
controlled by FastMCP's HTTP transport implementation, not by SIFT).

## Trade-offs considered

### Option A — keep stdio-only, ship a video-only demo
**Rejected.** Goal 1 (MCP depth) judging criterion explicitly wants to
see deep MCP integration. A video doesn't let a judge poke the server.

### Option B — Tailscale (this ADR)
**Accepted.** Encrypted P2P transport, identity-bound membership,
no public-internet exposure, no auth-token to leak. Trades broad
reach for safety.

### Option C — Cloudflare Tunnel + bearer auth
**Rejected (for now).** More work than Tailscale, broader exposure,
requires a domain. Revisit if the hackathon judging panel can't
install Tailscale.

### Option D — embed a guest CLI that talks stdio to the local server
**Rejected.** Defeats the purpose. The point is for the guest's
Claude Desktop to be the MCP client — not for them to install a
custom stdio harness.

## References

- Oracle: `src/agentropix_sift/mcp_server/fastmcp_app.py` — the transport switch
- Oracle: `docs/runbooks/expose-fastmcp-tailnet.md` — operator + guest guide
- ADR-016 — courtroom audit (seal still applies; transport is orthogonal)
- BMAD-M8-HACKATHON-SCORECARD.md §Path 1 — why Tailscale was first pick
- Tailscale ACL docs — for invite-link rotation after the hackathon
