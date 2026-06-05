# System Context & Containers

> **Section 02 · Architecture** — the bird's-eye view. Where Agentropix-SIFT sits
> relative to the examiner, the SANS SIFT Workstation it runs on, and the external
> sinks (OpenSearch, Wazuh, threat-intel). Lower-level internals are in
> [component-architecture.md](component-architecture.md); the request-level flows are in
> [sequence-diagrams.md](sequence-diagrams.md).

Agentropix-SIFT is a **local, CLI-driven bio-agentic DFIR triage engine** that runs
*on* the SANS SIFT Workstation. It never re-implements a forensic parser — it drives the
16 classical SIFT forensic binaries (Volatility3, Plaso, Sleuth Kit, RegRipper, YARA, …)
through one [FastMCP](mcp-server.md) server that exposes **71 MCP tools** (`mcp_tool_count = 71`,
[`.crew/facts.md`](../../.crew/facts.md)). A deterministic [Trinity Loop](trinity-loop.md)
(Architect → Swarm → Critic) drives those tools; the
[Thymus read-only policy](mcp-server.md#thymus-the-read-only-evidence-boundary) and the
[Courtroom HMAC-SHA256 seal](sequence-diagrams.md#3-finding--provenance--courtroom-seal)
make every run court-defensible.

---

## 1. System Context (C4 — Level 1)

```mermaid
C4Context
    title System Context — Agentropix-SIFT on the SANS SIFT Workstation

    Person(examiner, "DFIR Examiner", "Runs triage, reviews findings, signs off on approvals")

    System(agentropix, "Agentropix-SIFT", "Local bio-agentic DFIR triage engine. Trinity Loop drives 71 MCP tools over a single FastMCP server; read-only evidence policy + HMAC seal")

    System_Ext(sift, "SANS SIFT Workstation", "Host OS + 16 classical forensic binaries (vol3, plaso, fls, RegRipper, YARA, ...) on $PATH")
    System_Ext(evidence, "Evidence store", "Immutable E01 / raw / .mem images under /cases, /mnt, /media (read-only via Thymus)")
    System_Ext(opensearch, "OpenSearch indexer", "Case data store — findings, timeline, IOCs (idx_* tools)")
    System_Ext(wazuh, "Wazuh SIEM (optional)", "Single-node manager + indexer; IOC push to CDB lists (wazuh_* tools)")
    System_Ext(intel, "Threat-intel providers (optional)", "VirusTotal / OTX — egress-gated, no-key on this host")

    Rel(examiner, agentropix, "Runs CLI / connects MCP client", "agentropix-sift run · stdio / HTTPS Bearer")
    Rel(agentropix, sift, "Invokes forensic binaries", "async subprocess")
    Rel(agentropix, evidence, "Reads image bytes", "read-only, Thymus-enforced")
    Rel(agentropix, opensearch, "Ingests / queries case data", "idx_* (mutation_token)")
    Rel(agentropix, wazuh, "Pushes IOCs (dry-run by default)", "wazuh_* (mutation_token)")
    Rel(agentropix, intel, "Looks up indicators", "threat_intel_lookup (AGENTROPIX_ALLOW_EGRESS)")
    Rel(examiner, agentropix, "Approves / retracts findings", "HMAC challenge → sign (approval sidecar)")
```

**Reading the context.** The only human in the loop is the **DFIR examiner**, who either
runs the `agentropix-sift` CLI (`src/agentropix_sift/cli.py`) or connects a Model Context
Protocol client (Claude Desktop / Claude Code) to the FastMCP server. Everything to the
right is a system Agentropix-SIFT *uses* but does not own:

- **SANS SIFT Workstation** — the host. Agentropix-SIFT's value-add is "the layer between
  the agent and the binary" (`docs/MCP-REQUEST-FLOW.md`): typed I/O, evidence-policy
  enforcement, defensive subprocess handling, rate-limiting, telemetry. It *never*
  re-implements a parser.
- **Evidence store** — the immutable disk/memory images. Read access is mediated by the
  [Thymus policy](mcp-server.md#thymus-the-read-only-evidence-boundary)
  (`src/agentropix_sift/mcp_server/thymus_policy.py`); **there is no write tool**, so
  evidence integrity is architectural rather than advisory.
- **OpenSearch indexer** — the case data store behind the `idx_*` tools.
- **Wazuh SIEM (optional)** and **threat-intel providers (optional)** — both are
  default-off, gated sinks (see §3).

Every fact in a report originates from a named deterministic MCP tool
(`inference_constraint = "high"`, ADR-016; `orchestrator.py:69`). No LLM ever rates or
authors a finding — the court-defensibility argument is *"trust the trace ledger and the
report seal, because the LLM never touched them"* (`docs/ARCHITECTURE-LAYERS.md` §TL;DR).

---

## 2. Container View (C4 — Level 2)

```mermaid
C4Container
    title Container View — Agentropix-SIFT runtime

    Person(examiner, "DFIR Examiner", "")

    System_Boundary(asift, "Agentropix-SIFT") {
        Container(cli, "CLI", "Python · Typer", "agentropix-sift run / doctor. Drives one triage; seals the report on write (cli.py)")
        Container(mcp, "FastMCP server", "Python · FastMCP", "Single MCP server, 71 tools. stdio (local) or HTTP+SSE (tailnet, Bearer). fastmcp_app.py")
        Container(orch, "Orchestrator + Trinity", "Python · asyncio", "Architect -> Swarm -> Critic loop over one image. orchestrator.py, trinity/")
        Container(agents, "Swarm + Blackboard", "Python · asyncio", "7 core specialists + ATT&CK detectors; shared Blackboard correlation. agents/, detectors/")
        Container(wrappers, "Forensic wrappers", "Python", "~40 wrapper modules driving 16 SIFT binaries + EZ-Tools. mcp_server/wrappers/")
        Container(thymus, "Thymus policy", "Python", "Read-only allow-list + audit ring at the MCP boundary. thymus_policy.py")
        Container(courtroom, "Courtroom + provenance", "Python", "evidence_image_sha256, HMAC-SHA256 seal, chain validation. courtroom.py, provenance/")
        Container(approval, "Approval sidecar (optional)", "Python · Starlette", "HMAC challenge/approve human gate. approval_sidecar/")
    }

    System_Ext(sift, "SIFT forensic binaries", "vol3 · plaso · fls · RegRipper · YARA · ...")
    System_Ext(evidence, "Evidence store", "E01 / raw / .mem (read-only)")
    System_Ext(opensearch, "OpenSearch", "idx_* case store")
    System_Ext(wazuh, "Wazuh SIEM (optional)", "wazuh_* CDB lists")
    System_Ext(intel, "Threat-intel (optional)", "VT / OTX")

    Rel(examiner, cli, "agentropix-sift run", "shell")
    Rel(examiner, mcp, "MCP tools/call", "stdio / HTTPS Bearer")
    Rel(cli, orch, "run_triage(image)", "in-process")
    Rel(mcp, wrappers, "dispatch tool call", "in-process")
    Rel(mcp, thymus, "check_read(path)", "in-process")
    Rel(orch, agents, "run plan each iteration", "asyncio")
    Rel(agents, wrappers, "call mcp_* tools", "asyncio")
    Rel(wrappers, thymus, "check_read before subprocess", "in-process")
    Rel(wrappers, sift, "subprocess exec", "async")
    Rel(wrappers, evidence, "read image bytes", "read-only")
    Rel(orch, courtroom, "hash evidence + seal report", "in-process")
    Rel(approval, courtroom, "bind approval into seal", "in-process")
    Rel(mcp, opensearch, "idx_* ingest/query", "HTTP")
    Rel(mcp, wazuh, "wazuh_* push (dry-run default)", "HTTPS")
    Rel(mcp, intel, "threat_intel_lookup", "HTTPS (egress-gated)")
```

**Reading the containers.** There are two entry points and one shared engine:

| Container | Tech | Responsibility | Source |
|-----------|------|----------------|--------|
| **CLI** | Typer | `run` (triage an image), `doctor` (pre-flight the 16 SIFT binaries). Seals the report on write. | `src/agentropix_sift/cli.py` |
| **FastMCP server** | FastMCP | The single MCP protocol surface — 71 tools over **stdio** (local agents) or **HTTP+SSE** (tailnet, Bearer-token). | `mcp_server/fastmcp_app.py` |
| **Orchestrator + Trinity** | asyncio | Drives the [Trinity Loop](trinity-loop.md) over one image; rolls findings + trace into a `TriageReport`. | `orchestrator.py`, `trinity/` |
| **Swarm + Blackboard** | asyncio | The [DFIR agents](swarm-agents.md) and the cross-agent correlation Blackboard. | `agents/`, `detectors/` |
| **Forensic wrappers** | Python | Thin protocol-drivers around the 16 SIFT binaries + EZ-Tools; each ships timeout / memory-ceiling / retry / stderr-capture / tracing. | `mcp_server/wrappers/` |
| **Thymus policy** | Python | Read-only path allow-list + audit ring enforced at the MCP boundary (S-02). | `mcp_server/thymus_policy.py` |
| **Courtroom + provenance** | Python | `evidence_image_sha256`, HMAC-SHA256 report/audit seal, provenance-chain validation. | `courtroom.py`, `provenance/` |
| **Approval sidecar (optional)** | Starlette | Out-of-process HMAC challenge/approve human gate; default-off. | `approval_sidecar/` |

Both the CLI and the MCP server funnel through the **same** wrapper + Thymus + Courtroom
stack — that uniformity *is* the technical-depth claim (`docs/MCP-REQUEST-FLOW.md`,
"every tool flows through the same hardening stack"). The CLI is the deterministic,
LLM-free path; the MCP server is the LLM-driven path. Neither can mutate evidence.

---

## 3. Deployment & exposure (the tailnet boundary)

In its production topology the runtime is containerised (ADR-007, Kubernetes), but the
exposure model is what matters for the threat picture
(`docs/architecture/_C4-DEPLOYMENT.md`):

```mermaid
C4Deployment
    title Deployment — tailnet-only exposure (ADR-017)

    Deployment_Node(tailnet, "Tailnet — siftworkstation.taile7c9ca.ts.net", "WireGuard overlay; no LAN/public ingress") {
        Deployment_Node(ws, "siftworkstation (primary host)", "SANS SIFT Workstation") {
            Container(mcp2, "FastMCP server", "Bearer-token middleware", "stdio or HTTP+SSE; fail-closed if no token")
            Container(approval2, "approval_sidecar :8800", "Starlette, HMAC", "127.0.0.1 bind by default")
            Container(cases, "/cases evidence store", "read-only Thymus policy", "")
        }
    }
    Deployment_Node(gpu1, "gpu1 / 192.168.2.178 — Docker", "NOT systemd") {
        Container(wazuh2, "Wazuh single-node stack", "manager + indexer + dashboard", "")
        Container(os2, "OpenSearch indexer", "idx_* tools", "")
    }
    Deployment_Node(intelnode, "Internet (egress-gated)", "") {
        Container(intel2, "Threat-intel providers", "VT / OTX", "")
    }

    Rel(mcp2, cases, "read-only", "")
    Rel(mcp2, wazuh2, "wazuh_* push (ADR-018)", "HTTPS")
    Rel(mcp2, os2, "idx_* ingest/search", "HTTP")
    Rel(mcp2, intel2, "threat_intel_lookup", "HTTPS, AGENTROPIX_ALLOW_EGRESS")
    Rel(mcp2, approval2, "HMAC approve", "HTTP loopback")
```

**Reading the deployment.** Three exposure facts anchor the security story:

1. **Tailnet-only, Bearer-token, fail-closed.** The HTTP MCP surface is reachable only
   over the Tailscale overlay; every POST to `/mcp` requires a valid `Bearer` token
   (`AGENTROPIX_MCP_AUTH_TOKEN`, [env-vars.md](../../.crew/env-vars.md) §MCP server auth).
   `--public` exists but emits a loud warning (ADR-017; `fastmcp_app.py::parse_args`). The
   default local transport is **stdio**, which needs no network at all.
2. **Evidence is read-only by construction.** `/cases` (and `/mnt`, `/media`, `/evidence`,
   `/tmp/agentropix-sift-*`) are read-only via Thymus; there is no write tool to disable.
3. **The optional sinks are off by default.** Wazuh push is gated by
   `WAZUH_INTEGRATION_ENABLED=false`, `WAZUH_PUSH_ENABLED=false`, and
   `WAZUH_DRY_RUN_ONLY=true`; threat-intel egress is gated by `AGENTROPIX_ALLOW_EGRESS=0`
   ([env-vars.md](../../.crew/env-vars.md) §Wazuh kill switches, §Threat-intel). The Wazuh
   stack itself lives on a *separate* Docker host (gpu1), reachable only over the tailnet.

> The single-host workstation layout above is the dev/demo reality; the ADR-007 Kubernetes
> topology supersedes it in production. Neither contradicts the others — the exposure
> contract (tailnet-only, Bearer, read-only evidence) is identical in both.

---

## 4. Where to go next

- The internal package layout and the four determinism layers →
  [component-architecture.md](component-architecture.md)
- How the Architect/Swarm/Critic loop halts deterministically →
  [trinity-loop.md](trinity-loop.md)
- The agent roster and Blackboard correlation → [swarm-agents.md](swarm-agents.md)
- The FastMCP server, transports, and Thymus boundary in detail → [mcp-server.md](mcp-server.md)
- End-to-end request flows (triage, tool call, seal, approval, Wazuh) →
  [sequence-diagrams.md](sequence-diagrams.md)
