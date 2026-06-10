# Agentropix MCP — Install Quickstart (Tailscale Edition)

> **Section 09 · Integrations**
>
> **Audience:** A trusted end-user who needs to point **Claude Code CLI** or **Claude Desktop**
> at the *already-running* internal Agentropix-SIFT MCP server hosted on the operator's private
> **Tailscale** tailnet — as opposed to standing the server up yourself.
>
> **Related:** [Quickstart (self-host)](../01-overview/quickstart.md) · [Deployment (operator-side)](../07-sdlc-ops/deployment.md) · [Security Model](../07-sdlc-ops/security-model.md) · [MCP Server](../02-architecture/mcp-server.md) · [Tool list](../04-mcp-tools/tool-list.md)

**Goal:** Get Claude Desktop or Claude Code CLI talking to our internal Agentropix-SIFT MCP server in under 5 minutes.

**Server:** `http://100.85.162.82:8765/mcp` (tailnet-only — not on public internet)

The endpoint exposes the full Agentropix-SIFT forensic surface — **71 MCP tools** (canonical count; the live `health.tool_count` is authoritative) wrapping **16 SANS SIFT forensic binaries**. Authentication is a single static **bearer token** sent as `Authorization: Bearer <token>`.

---

## Step 1 — Join the tailnet (one-time)

The server is reachable only from machines on our tailnet.

### 1a. Accept the invite

Open this link in a browser and sign in with the Google / Microsoft account you want associated with your tailnet identity:

> **Tailscale invite:** https://login.tailscale.com/admin/invite/hTJEiNskHFY9qsXL2Xqx11

### 1b. Install the Tailscale client

| OS | Command / Link |
|----|----------------|
| **macOS** | `brew install --cask tailscale` &nbsp;or&nbsp; https://tailscale.com/download/mac |
| **Windows** | https://tailscale.com/download/windows (MSI installer) |
| **Linux** | `curl -fsSL https://tailscale.com/install.sh \| sh` &nbsp;then&nbsp; `sudo tailscale up` |

### 1c. Verify connectivity

```bash
# All platforms
tailscale status            # should list "siftworkstation … 100.85.162.82"
ping -c 2 100.85.162.82     # should succeed (Windows: ping 100.85.162.82)
```

**Linux / macOS** — reachability + token sanity check (one combined test):

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST http://100.85.162.82:8765/mcp \
  -H "Authorization: Bearer jlviTMFYAsAuxL1AiagDvFChIs4baYHe6OeRAdBzaLs" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1.0"}}}'
```

**Windows PowerShell:**

```powershell
$headers = @{
    "Authorization" = "Bearer jlviTMFYAsAuxL1AiagDvFChIs4baYHe6OeRAdBzaLs"
    "Accept"        = "application/json, text/event-stream"
}

$body = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1.0"}}}'

try {
    $r = Invoke-WebRequest -Uri "http://100.85.162.82:8765/mcp" -Method Post `
        -Headers $headers -ContentType "application/json" -Body $body
    $r.StatusCode
} catch {
    [int]$_.Exception.Response.StatusCode
}
```

| Response | Meaning |
|----------|---------|
| `200` | Tailnet OK + token OK — proceed to Step 2 |
| `401` | Tailnet OK but token wrong — re-paste from this doc |
| `000` / timeout | Tailscale not connected or server down — re-check Step 1a–1b |

---

## Step 2 — Pick your client

You only need ONE of these. Most people want Claude Code CLI.

### Client A — Claude Code CLI (recommended)

**One-line install** (works on macOS, Linux, Windows PowerShell, and WSL):

```bash
claude mcp add --transport http agentropix-sift \
  "http://100.85.162.82:8765/mcp" \
  --header "Authorization: Bearer jlviTMFYAsAuxL1AiagDvFChIs4baYHe6OeRAdBzaLs"
```

**Verify:**

```bash
claude mcp list
# Expected: agentropix-sift  http://100.85.162.82:8765/mcp  ✓ Connected
```

### Client B — Claude Desktop App (via the `mcp-remote` shim)

Claude Desktop speaks **stdio only**, so it bridges to the HTTP server through the `npx mcp-remote` shim.

**Prerequisite:** Node.js ≥ 18 on PATH. Check with `node --version`. If missing, install LTS from https://nodejs.org/.

**1. Find your config file:**

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

**2. Edit the file** (create it if it doesn't exist). **The `command` differs per OS** — Windows must use `npx.cmd`, macOS/Linux use bare `npx`:

**macOS / Linux:**

```json
{
  "mcpServers": {
    "agentropix-sift": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "http://100.85.162.82:8765/mcp",
        "--allow-http",
        "--header",
        "Authorization: Bearer jlviTMFYAsAuxL1AiagDvFChIs4baYHe6OeRAdBzaLs"
      ],
      "env": {}
    }
  }
}
```

**Windows** (note `npx.cmd`):

```json
{
  "mcpServers": {
    "agentropix-sift": {
      "command": "npx.cmd",
      "args": [
        "-y",
        "mcp-remote",
        "http://100.85.162.82:8765/mcp",
        "--allow-http",
        "--header",
        "Authorization: Bearer jlviTMFYAsAuxL1AiagDvFChIs4baYHe6OeRAdBzaLs"
      ],
      "env": {}
    }
  }
}
```

**3. Restart your Claude Desktop App** — fully quit (⌘Q / tray → Quit) and relaunch, not just close the window.

### Smoke-test a tool

Ask the model something like:

> *"Use the agentropix-sift MCP server. Run the `health` tool and tell me the tool_count."*

Expected: `tool_count: 72` (or whatever the live count is — that field is authoritative; this doc may lag).

---

## About the bearer token

| Property | Value |
|----------|-------|
| **Token** | `jlviTMFYAsAuxL1AiagDvFChIs4baYHe6OeRAdBzaLs` |
| **Expiration** | None — never expires |
| **TTL / refresh** | None — no JWT, no refresh flow, no re-auth |
| **Auto-rotation** | None — the server reads it once at startup and re-uses it forever |
| **Who can rotate it** | Only Victor (operator), and only by editing the server's launch wrapper + restarting |
| **What invalidates it** | Operator-initiated rotation only — there is no other code path that revokes or expires this value |

**Verified from server source:** `agentropix_mcp/fastmcp_app.py` reads `AGENTROPIX_MCP_AUTH_TOKEN` via plain `os.environ.get()` and does a plaintext constant-time compare (`secrets.compare_digest`). No TTL check, no JWT decode, no expiration logic exists.

**If you suspect the token has leaked**, contact `victor.galvan@idemia.com` → operator will rotate → new value distributed out-of-band to all clients.

---

## Troubleshooting

### `401 Unauthorized`

| Cause | Fix |
|-------|-----|
| Token has a typo (trailing newline, missing char, smart quotes) | Re-copy from this doc. Length should be **43 chars**. Verify: `echo -n "<paste>" \| wc -c` should print `43`. |
| Authorization header malformed | Must be `Authorization: Bearer <token>` — case-sensitive `Bearer`, single space, no surrounding quotes |
| Claude Desktop config not picking up env var | Desktop does **not** expand `${VAR}` — paste the literal token in the JSON |
| Operator rotated the token | Ask Victor for the current value |

### `Cannot reach 100.85.162.82` / connection timeout

| Cause | Fix |
|-------|-----|
| Tailscale not running | `sudo tailscale up` (Linux/macOS) or open the GUI client (Windows). Verify with `tailscale status` |
| Tailscale running but admin hasn't approved your device | Send your `tailscale status` output to Victor so he can approve |
| Server is down | Ping Victor — server uptime is operator-side |
| Corporate firewall blocking outbound to port 8765 | Try from a personal network to confirm. Office networks sometimes block non-standard ports |

### Claude Desktop: tools icon missing / tool list empty

| Cause | Fix |
|-------|-----|
| Closed the window but didn't quit | Fully quit (⌘Q / tray → Quit) and relaunch |
| `npx` / `npx.cmd` mismatch | Windows must use `"command": "npx.cmd"`; macOS/Linux must use `"command": "npx"` |
| Node version too old | `node --version` must be ≥ 18 |
| First `mcp-remote` invocation slow / failing | Prime the cache: `npx -y mcp-remote --help` once from a terminal, then restart Desktop |
| JSON syntax error in config | Validate: `python3 -m json.tool < claude_desktop_config.json` should print, not error |
| Tool result > 1 MB | Hard cap in Desktop. Large outputs (e.g., full plaso CSV) will fail. Prefer tools that return file paths over inline payloads. |

### Check the Claude Desktop MCP server log

```bash
# macOS
tail -f ~/Library/Logs/Claude/mcp-server-agentropix-sift.log

# Linux
tail -f ~/.config/Claude/logs/mcp-server-agentropix-sift.log
```

```powershell
# Windows
Get-Content -Wait "$env:APPDATA\Claude\logs\mcp-server-agentropix-sift.log"
```

### Slow first call, fast subsequent calls

Normal — the FastMCP `initialize` handshake costs ~1–2 s; warm tool calls run ~50–200 ms.

### Long-running tool times out mid-call

Tools like `plaso_log2timeline` on multi-GB E01s can run 30–45 min and exceed the HTTP keepalive. Run them against a smaller image first to verify wiring, then ask Victor to extend the server-side timeout if needed.

---

## Quick reference card (paste into Signal when onboarding someone)

```
Agentropix MCP — install in 3 steps
1. Tailscale invite (ping me to approve after you accept):
   https://login.tailscale.com/admin/invite/hTJEiNskHFY9qsXL2Xqx11
2. Install client:
   claude mcp add --transport http agentropix-sift \
     "http://100.85.162.82:8765/mcp" \
     --header "Authorization: Bearer jlviTMFYAsAuxL1AiagDvFChIs4baYHe6OeRAdBzaLs"
3. Verify:  claude mcp list  →  ✓ Connected
Server: 100.85.162.82:8765  Token: never expires.  Issues → me.
```

---

*Last verified: 2026-05-27 — token confirmed valid via live `tools/list` round-trip; server PID 46800 running since 2026-05-26.*
