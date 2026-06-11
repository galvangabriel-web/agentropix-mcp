# Agentropix-SIFT

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#license)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![MCP tools: 71](https://img.shields.io/badge/MCP%20tools-71-green.svg)](docs/04-mcp-tools/tool-reference.md)
[![SIFT wrappers: 16](https://img.shields.io/badge/SIFT%20wrappers-16-brightgreen.svg)](docs/04-mcp-tools/tool-reference.md)
[![Tests: 4464](https://img.shields.io/badge/tests-4464-brightgreen.svg)](docs/07-sdlc-ops/testing.md)
[![Disk recall: 72/72](https://img.shields.io/badge/disk%20recall-72%2F72-success.svg)](docs/07-sdlc-ops/dataset-recall.md)

> ## Autonomous DFIR triage on the SANS SIFT Workstation — that never lets the LLM rate its own findings.
> Point it at a Windows disk or memory image. It drives **16 real SIFT forensic tools** through **one
> MCP server (71 tools)**, correlates across a **7-agent swarm** on a quorum blackboard, and emits a
> cryptographically sealed, schema-validated JSON triage report — in minutes, on the local host, with
> **no LLM ever in the halt path**. *(Source: [`what-is-agentropix.md`](docs/01-overview/what-is-agentropix.md).)*

**A local, CLI-driven, bio-agentic DFIR triage engine for the SANS SIFT Workstation.**

---

## ⚡ Connect in 60 seconds

> **🚀 Already have a SIFT host running on our tailnet? Point Claude at it right now — no install, no build.**
> One command and you're driving **71 forensic tools** from Claude. **Full guide → [docs/09-integrations/client-setup.md](docs/09-integrations/client-setup.md).**

> [!NOTE]
> **First: join the tailnet (one-time).** The server `http://100.85.162.82:8765/mcp` is **tailnet-only** — reachable through **[Tailscale](https://tailscale.com/)**, never the public internet. Before the steps below:
> 1. **Accept the invite** and sign in with your Google / Microsoft identity → **[Tailscale invite](https://login.tailscale.com/admin/invite/hTJEiNskHFY9qsXL2Xqx11)** *(then ping the operator to approve your device).*
> 2. **Install the Tailscale client** — macOS `brew install --cask tailscale` · Windows [MSI](https://tailscale.com/download/windows) · Linux `curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up`
> 3. **Verify:** `tailscale status` lists `siftworkstation … 100.85.162.82`, and `ping 100.85.162.82` succeeds.
>
> Full per-OS install + a combined token-and-reachability probe: **[Client Setup → Step 1](docs/09-integrations/client-setup.md#step-1--join-the-tailnet-one-time)**.

**You only need ONE client. Most people want the Claude Code CLI.**

### ▶ Client A — Claude Code CLI *(recommended — one line, all platforms)*

```bash
claude mcp add --transport http agentropix-sift \
  "http://100.85.162.82:8765/mcp" \
  --header "Authorization: Bearer jlviTMFYAsAuxL1AiagDvFChIs4baYHe6OeRAdBzaLs"
```

Verify:

```bash
claude mcp list
# Expected: agentropix-sift  http://100.85.162.82:8765/mcp  ✓ Connected
```

### ▶ Client B — Claude Desktop App *(via the `mcp-remote` shim)*

Claude Desktop speaks **stdio only**, so it bridges to the HTTP server through the `npx mcp-remote` shim.
**Prerequisite:** Node.js ≥ 18 on `PATH` (`node --version`); install LTS from <https://nodejs.org/> if missing.

**1. Find your config file:**

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

**2. Edit it** (create if absent). **The `command` differs per OS** — Windows uses `npx.cmd`, macOS/Linux use bare `npx`:

<table>
<tr><th>macOS / Linux</th><th>Windows</th></tr>
<tr valign="top"><td>

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

</td><td>

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

</td></tr>
</table>

**3. Restart Claude Desktop** — fully quit (⌘Q / tray → Quit) and relaunch, not just close the window.

### ✅ Smoke-test it

Ask the model:

> *"Use the agentropix-sift MCP server. Run the `health` tool and tell me the tool_count."*

Expected: `tool_count: 72` (the live count is authoritative — this number may lag).

> **First time on the tailnet, or hit a `401` / timeout?** The complete quickstart — Tailscale invite,
> per-OS install, token facts, and a full troubleshooting matrix — is in
> **[📘 Client Setup — Install Quickstart](docs/09-integrations/client-setup.md)**.

---

## Start here — pick your lane

Four audiences, four fast paths. Each row is an ordered reading trail; the full routing lives in the
[Documentation Index](INDEX.md#reading-paths-by-audience).

| You are a… | You want to… | Start here → then |
|---|---|---|
| 🧑‍💻 **Software engineer** | understand the architecture, build/test/extend it | [Implementation](docs/07-sdlc-ops/implementation.md) → [Trinity Loop](docs/02-architecture/trinity-loop.md) → [Swarm & Blackboard](docs/02-architecture/swarm-agents.md) → [FastMCP Server](docs/02-architecture/mcp-server.md) → [Testing](docs/07-sdlc-ops/testing.md) → [ADRs (decision contract)](docs/11-ADR/README.md) |
| 🛡️ **SOC analyst** | run a triage, hunt IOCs, push to the SIEM | [User Guide (runbook)](docs/01-overview/user-guide.md) → [Disk triage](docs/06-use-cases/uc-disk-triage.md) → [Memory triage](docs/06-use-cases/uc-memory-triage.md) → [Wazuh push](docs/06-use-cases/uc-wazuh-push.md) → [CLI Reference](docs/08-reference/cli-reference.md) |
| ⚖️ **Evaluator / judge** | verify the claims, soundness, chain of custody | [Canonical Facts](docs/08-reference/canonical-facts.md) → [Anti-Hallucination](docs/05-safety-forensics/anti-hallucination.md) → [Audit & Courtroom Seal](docs/05-safety-forensics/audit-courtroom.md) → [Recall methodology](docs/07-sdlc-ops/dataset-recall.md) → [Evaluation scorecard](docs/07-sdlc-ops/evaluation-scorecard.md) → [SWOT](#swot--strategic-assessment) |
| 💬 **End-user (non-technical)** | get answers by just *asking* Claude | the [Two Paths table](#two-paths-operator-expert-and-end-user) below → end-user lanes in the [User Guide](docs/01-overview/user-guide.md) → [Tool Capability Map](docs/04-mcp-tools/capability-map.md) |

> 👋 **First time?** The single best entry point is the
> **[User Guide — The Complete Operator Runbook](docs/01-overview/user-guide.md)**: one complete case,
> end-to-end (pre-flight → connect/verify the MCP → init/activate the case → register evidence → the
> investigation tool chain → record findings → approve in the portal → seal the report → optional Wazuh
> push), documenting **both** execution paths (manual · autonomous) and **both** clients (Claude CLI ·
> Claude Desktop), with the validated 2026-05-29 CFReDS run as a worked example.

---

## What it is — and why

Agentropix-SIFT turns a SIFT Workstation into an autonomous-but-accountable triage operator. A
**Trinity Loop** — an Architect that proposes which agents to run, a **7-agent Swarm** that drives
deterministic forensic tools, and a **Critic** that scores findings and halts on a *deterministic*
convergence fingerprint (with **no LLM self-rating**) — orchestrates **71 MCP tools** over a single
[FastMCP](docs/02-architecture/mcp-server.md) server. The result is a fast first pass over disk images,
memory dumps, and Windows artifacts that produces an evidence-grounded, cryptographically sealed triage
report a human examiner can trust and defend.

Its central claim is simple and load-bearing: **the LLM never touches a fact.** Every finding it records
is produced by a deterministic forensic binary, fingerprinted with SHA-256, and tagged with a provenance
tier — precisely so a human can verify it.

> **Important — this is a triage accelerator, not an oracle.**
> Agentropix-SIFT is built to be *checked*, not *believed*. The LLM proposes and narrates; it never rates
> its own work and never becomes the source of a finding. **You remain the examiner of record.** Review
> the findings, confirm the underlying artifacts, and use the optional
> [human-in-the-loop approval gate](docs/05-safety-forensics/human-in-the-loop.md) before anything is
> sealed or escalated. See [Anti-Hallucination](docs/05-safety-forensics/anti-hallucination.md).

---

## How AI drives Agentropix — the consumer model

The novel angle is *where the AI sits*. Agentropix-SIFT is **deterministic layers with the stochastic
LLM confined to the top**. The LLM is not an oracle wired into the findings — it is simply **a consumer
of the same FastMCP tool surface** that the CLI uses. From the MCP boundary down, everything is pure
Python driving classical forensic binaries: no RNG, no LLM self-rating.

You drive it **two ways from one engine**: as a plain `agentropix-sift run` command, or by talking to an
LLM (Claude Desktop / Claude Code) that has the MCP server connected. A non-technical examiner can type
*"open a case for this disk image and run the SIFT triage"* and the session routes it to the real MCP
tools; an expert calls the exact tool. *Adapt Agentropix to the user, not the user to Agentropix.*

![Diagram — rendered at high resolution](assets/readme-1.png)

<details>
<summary>Mermaid source (editable)</summary>

```mermaid
flowchart TB
    classDef stoch fill:#fff5e6,stroke:#f59f00,color:#222,stroke-width:2px
    classDef det fill:#e6ffea,stroke:#2f9e44,color:#222,stroke-width:2px
    classDef anchor fill:#eef2ff,stroke:#3b5bdb,color:#222,stroke-width:2px
    classDef leak fill:#fff0f0,stroke:#e03131,color:#222,stroke-width:2px

    LLM["<b>Consumer (LLM or CLI)</b><br/>Claude Code / Desktop / cli.py<br/><i>stochastic only when LLM-driven</i>"]:::stoch

    subgraph TR["Trinity Loop — deterministic, no LLM authoring"]
        ARCH["<b>Architect</b> · plan()<br/>order/prune SWARM<br/>trinity/architect.py"]:::det
        CRIT["<b>Critic</b> · score()/halt<br/>convergence fingerprint<br/>trinity/critic.py"]:::det
    end

    subgraph SW["Swarm — 13 SwarmAgent classes"]
        AGENTS["7 specialists + 6 ATT&CK detectors<br/>agents/ · detectors/"]:::det
        BB[("Blackboard<br/>(agent, Finding) registry<br/>correlations() at quorum")]:::anchor
    end

    subgraph MCP["MCP boundary — the enforcement spine"]
        TOOLS["71 MCP tools<br/>traced · rate-limited · Thymus-gated"]:::det
        BIN["SIFT binaries<br/>vol3 / plaso / tsk / yara / EZ-Tools"]:::leak
    end

    LLM -- "args_hash + raw_output cross the boundary" --> ARCH
    ARCH -- "ordered plan" --> AGENTS
    AGENTS -- "publish Finding" --> BB
    AGENTS -- "tools/call" --> TOOLS
    TOOLS --> BIN
    BB --> CRIT
    CRIT -- "stable_agents (next iteration)" --> ARCH
```

</details>

> 📐 Rendered as a high-resolution PNG so it displays crisply on GitHub **and** GitLab — [**Open as SVG** (vector, zoomable)](assets/readme-1.svg).

- **One tool surface, two consumers.** The same `@app.tool()` functions the swarm calls are also exposed
  to an LLM client; the server is built by `_build_app()` / `FastMCP("agentropix-sift")`
  (`mcp_server/fastmcp_app.py`). The package installs two console scripts: `agentropix-sift` (triage CLI)
  and `agentropix-sift-mcp` (the MCP server). An LLM connects to the latter; the CLI bypasses it and
  drives the engine directly. See [The FastMCP Server](docs/02-architecture/mcp-server.md).
- **Two transports.** The MCP server speaks **stdio** (default — paired with a Claude Desktop / Claude
  Code `mcp.json` entry) or **HTTP+SSE** under `/mcp` (tailnet-only, Bearer-gated, default port 8765).
  Both funnel into the **same tool core**. See [Connect a Client](docs/09-integrations/client-setup.md).
- **The LLM proposes, never authors.** The `args_hash` + bounded `raw_output` snapshot is captured **at
  the MCP boundary**, so a sealed report can prove the LLM phrased a request three ways but never authored
  — or touched — a fact. Agents are *pure async coroutines over the MCP boundary, with no LLM coupling*
  (`agents/_base.py`).

> **"Agent" means two different things here.** The **runtime DFIR swarm agent** (a `SwarmAgent` subclass
> that investigates evidence) is unrelated to the **build-time BMAD dev-crew persona**. Section 10
> disambiguates them — read [The Agentic Architecture](docs/10-agents/agentic-architecture.md) first
> whenever the word is ambiguous.

---

## What you get — capability highlights

| Capability | The one-line value | Canonical figure | Source-code home |
|---|---|---|---|
| **Trinity Loop** | Deterministic Architect → Swarm → Critic control loop; halts on a convergence fingerprint, **never on an LLM self-rating** | Critic halt default **0.85** | `trinity/architect.py`, `trinity/critic.py`, `orchestrator.py` |
| **71 MCP tools** | One FastMCP server exposes **71 distinct forensic tools** over stdio + HTTP | **71** tools | `mcp_server/fastmcp_app.py` |
| **16 SIFT wrappers** | Hardened drivers (timeout, memory ceiling, retry, stderr capture, tracing) around the 16 trusted SIFT binaries | **16** wrappers | `mcp_server/wrappers/` |
| **7-agent Swarm + ATT&CK detectors** | Memory, Timeline, Filesystem, Artifact, Discovery, Mail, Hunt specialists + 6 deterministic MITRE ATT&CK detectors | **7** specialists (**13** `SWARM` classes) | `agents/`, `detectors/` |
| **Quorum Blackboard** | An observation is promoted to a `Correlation` only when enough agents corroborate the same token | quorum default **2** | `agents/_blackboard.py` |
| **Thymus read-only policy** | Every `mcp_*` call is checked against a path allowlist *before* any subprocess spawns — evidence is structurally read-only (no write tool exists) | deny-by-default | `mcp_server/thymus_policy.py` |
| **Courtroom seal** | SHA-256 evidence byte-binding + HMAC-SHA256 report/audit-log seal → a report a judge can independently verify | mode-0600 session key | `courtroom.py` |
| **Provenance & grounding** | Every `Finding._source` names the tool that produced it; `inference_constraint = high`; per-row HMAC chain validation | 3 grounding layers | `agents/_base.py`, `provenance/validate.py` |
| **Approval sidecar (HITL)** | Optional HMAC examiner sign-off: PBKDF2 key (600k iters) + nonce + append-only approval hash chain + browser form | 2 MCP tools | `approval_sidecar/` |
| **Wazuh SIEM push** | Promote findings/IOCs into Wazuh behind **default-deny** kill switches + active-response CIDR guard | 5 Wazuh tools | `wazuh/` |
| **Chaos-tested resilience** | Fault-injection tests prove graceful degradation: a missing tool skips an agent, not the run | `chaos` test marker | `tests/chaos/` |

Full capability matrix: [What You Get](docs/01-overview/what-you-get.md).

---

## Architecture

**The shape: one deterministic loop over one tool server, with a safety spine.**

A DFIR examiner drives Agentropix-SIFT from the CLI on a local SIFT host. The engine never reaches
outside that host except for the *optional* Wazuh push of already-APPROVED findings.

![Diagram — rendered at high resolution](assets/readme-2.png)

<details>
<summary>Mermaid source (editable)</summary>

```mermaid
flowchart TB
    classDef actor fill:#d0bfff,stroke:#7048e8,color:#2b1a52,stroke-width:2px
    classDef core fill:#b2f2bb,stroke:#2f9e44,color:#15391f,stroke-width:2px
    classDef ext fill:#e9ecef,stroke:#495057,color:#212529,stroke-width:1px
    classDef sink fill:#ffec99,stroke:#f08c00,color:#5c4400,stroke-width:1.5px

    Examiner(["DFIR Examiner<br/>runs triage · reviews · approves findings"]):::actor

    subgraph Host["SANS SIFT Workstation — local host"]
        Agentropix["Agentropix-SIFT<br/>Trinity Loop engine + FastMCP server (71 tools)"]:::core
        Toolchain["SIFT Forensic Toolchain<br/>Volatility3 · Plaso · Sleuth Kit · EVTX · YARA · … (16 tools)"]:::ext
        Evidence[("Evidence Store<br/>E01 / raw / memory — read-only")]:::ext
    end

    Wazuh["Wazuh / SIEM<br/>optional alert sink for APPROVED findings"]:::sink

    Examiner -->|"agentropix-sift run / review / approve"| Agentropix
    Agentropix -->|"invokes deterministic binaries (read-only)"| Toolchain
    Agentropix -->|"reads + SHA-256 fingerprints, never mutates"| Evidence
    Agentropix -->|"pushes APPROVED findings (optional)"| Wazuh

    style Host fill:#f1f3f5,stroke:#868e96,color:#212529
```

</details>

> 📐 Rendered as a high-resolution PNG so it displays crisply on GitHub **and** GitLab — [**Open as SVG** (vector, zoomable)](assets/readme-2.svg).

Internally, the **Architect** proposes which agents to spawn (by default it returns the canonical
`SWARM` tuple in priority order; a default-on Reflexion-lite step drops agents the Critic marked
*stable*). The **7-agent Swarm** invokes the 16 wrapped SIFT forensic tools through the FastMCP server's
71-tool surface, writing `Finding`s to a shared **Blackboard**; cross-agent agreement at a **quorum** of
2 becomes a `Correlation`. The **Critic** scores the accumulated findings with a *closed-form* rule —
`score = min(1.0, max_confidence + 0.25 · len(correlations))` — and halts deterministically when the
findings stop changing (a convergence fingerprint), bounded by a hard `max_iterations` budget, **never
on an LLM's self-assessed confidence**. The **Thymus** read-only policy and the **pre/post SHA-256
evidence invariant** sit between every tool and the evidence store. Finally the **Courtroom** seals the
audit log with HMAC-SHA256 and validates the provenance chain.

### 📐 The validated architecture diagram — one page, source-verified

The complete picture lives in **[Main Architectural Agentropix Design](docs/02-architecture/main-architectural-agentropix-design.md)** —
one validated diagram covering the **agent layer → MCP server → SIFT Workstation tools → data sources →
output pipeline**, the architectural-pattern verdict (**Custom MCP Server** — and why it is *not* a
Direct Agent Extension, Multi-Agent Framework, or Agentic IDE), and the full
**ARCHITECTURAL vs PROMPT-BASED guardrail split** with every row cited to its enforcing source file.
Every component was contrasted against the oracle source code; every documentation-vs-source
disagreement is called out on the page.

> 📕 **[Full document as high-quality PDF](docs/02-architecture/assets/architecture-diagram/main-architectural-agentropix-design.pdf)**
> *(the complete design document — diagram, component narrative, pattern verdict, guardrail table)* ·
> 📄 [Diagram-only HD PDF (vector)](docs/02-architecture/assets/architecture-diagram/architecture-diagram-hd.pdf) ·
> 🖼️ [PNG](docs/02-architecture/assets/architecture-diagram/architecture-diagram.png) ·
> 🔍 [SVG](docs/02-architecture/assets/architecture-diagram/architecture-diagram.svg)

For the deeper layers: [System Context & Containers](docs/02-architecture/system-context-c4.md) ·
[Component Architecture & Layer Map](docs/02-architecture/component-architecture.md) ·
[The Trinity Loop](docs/02-architecture/trinity-loop.md) ·
[Sequence Diagrams](docs/02-architecture/sequence-diagrams.md).

### Key design decisions (the decision contract)

The architecture is contracted in immutable **Architecture Decision Records** mirrored from the oracle.
The load-bearing ones for newcomers:

| ADR | Decision |
|---|---|
| [ADR-002 — Execution engine](docs/11-ADR/ADR-002-execution-engine.md) | The deterministic Trinity Loop as the execution model. |
| [ADR-008 — Safety architecture](docs/11-ADR/ADR-008-safety-architecture.md) | The deny-by-default Thymus boundary + evidence read-only invariant. |
| [ADR-011 — Evidence gates](docs/11-ADR/ADR-011-evidence-gates.md) | Pre/post SHA-256 evidence-integrity gates. |
| [ADR-016 — Courtroom audit](docs/11-ADR/ADR-016-courtroom-audit.md) / [ADR-022 — Audit-log seal](docs/11-ADR/ADR-022-audit-log-seal.md) | HMAC-SHA256 tamper-evident chain of custody. |
| [ADR-017 — Tailnet MCP exposure](docs/11-ADR/ADR-017-tailnet-mcp-exposure.md) | HTTP transport is tailnet-only + Bearer-gated. |
| [ADR-018 — Wazuh IOC push](docs/11-ADR/ADR-018-wazuh-ioc-push.md) / [ADR-019 — AR confirmation gate](docs/11-ADR/ADR-019-ar-confirmation-gate.md) | Default-deny SIEM push + active-response confirmation. |

Read the status column literally (Proposed ⇒ not shipped; Deferred ⇒ documented, not implemented). Full
index: [ADR Index](docs/08-reference/adr-index.md) · [Section 11 — ADRs](docs/11-ADR/README.md) ·
rationale narratives in [Design Decisions](docs/08-reference/design-decisions.md).

---

## 🌈 Recommended investigation workflow

> ### 🚀 One prompt. Six guarded stages. A sealed, court-ready report.
> You don't need to memorise a single flag. Connect the Agentropix MCP to Claude, then **say what you
> want in plain English** — *"open a case for this disk image and run the full SIFT triage"* — and the
> session routes your words to real forensic tools. The six stages below run the same whether an **expert
> types the command** or a **non-technical examiner just asks**. *Adapt Agentropix to the user, not the
> user to Agentropix.*

![Stage 1 doctor](https://img.shields.io/badge/①_DOCTOR-pre--flight-8e44ad?style=for-the-badge)
![Stage 2 run](https://img.shields.io/badge/②_RUN-triage-2980b9?style=for-the-badge)
![Stage 3 review](https://img.shields.io/badge/③_REVIEW-verify-f39c12?style=for-the-badge)
![Stage 4 approve](https://img.shields.io/badge/④_APPROVE-HITL_gate-27ae60?style=for-the-badge)
![Stage 5 seal](https://img.shields.io/badge/⑤_SEAL-courtroom-c0392b?style=for-the-badge)
![Stage 6 escalate](https://img.shields.io/badge/⑥_ESCALATE-SIEM-16a085?style=for-the-badge)

![Six guarded stages of the Agentropix-SIFT investigation workflow — ① doctor (pre-flight) → ② run (triage) → ③ review (verify) → 🧑‍⚖️ human gate → ④ approve (HITL) → ⑤ seal (courtroom) → ⑥ escalate (SIEM), with a reject/re-run loop back to run](assets/readme-3.png)

> 🔍 Rendered as PNG so it shows inline on every browser — [**Open as SVG** (full size, zoomable)](assets/readme-3.svg).

The vivid lane below is the *load-bearing* part: each stage shows **both** ways to reach the same result —
the **🖥️ expert command** and the **💬 plain-language prompt** a non-technical examiner types into a Claude
session that has the Agentropix MCP connected. Every prompt maps to a **real MCP tool** (verify against the
[Tool Capability Map](docs/04-mcp-tools/capability-map.md)).

---

### 🟣 ① `doctor` — pre-flight the toolchain

> **🖥️ Expert (command):**
> ```bash
> uv run agentropix-sift doctor
> ```
> **💬 End-user (prompt):** *"Check that my Agentropix forensic environment is ready — are all the SIFT
> tools installed and on PATH?"* → routes to `doctor` / `health`.

Confirms the **16 SIFT forensic binaries** resolve before you spend time on an image. Missing tools
*degrade gracefully* (the agent is skipped, not the run) — but recall drops, so always start here.

### 🔵 ② `run` — Trinity Loop triages the image end-to-end

> **🖥️ Expert (command):**
> ```bash
> uv run agentropix-sift run /cases/INC-0605/disk.E01 -o report.json
> ```
> **💬 End-user (prompt):** *"Open a high-severity case for the image at `/cases/INC-0605/disk.E01`,
> register it as evidence, and run the full SIFT triage end-to-end — acquisition → examination → analysis
> → findings — staging everything as DRAFT."* → routes to `case_init` → `case_activate` →
> `evidence_register` → the forensic tool chain → `record_finding`.

The **Architect** proposes which agents to run → the **7-agent Swarm** drives deterministic tools →
the **Critic** scores findings and **halts on a convergence fingerprint, never on an LLM self-rating**.

### 🟠 ③ `review` — the examiner verifies every finding

> **💬 End-user (prompt):** *"Show me the findings so far, and for each one tell me which exact tool
> produced it and the artifact path / `raw_stdout_sha256` so I can verify it myself."* → routes to
> `case_status` / `record_finding` inspection.

A human reads the findings and checks them against the underlying artifacts. **The LLM proposes and
narrates — you remain the examiner of record.**

### 🟢 ④ `approve` *(optional HITL gate)* — DRAFT → APPROVED

> **🖥️ Expert (command):** promote DRAFT → APPROVED in the [Approval Portal](docs/05-safety-forensics/approval-portal.md) (HMAC examiner sign-off).
> **💬 End-user (prompt):** *"Show me the findings waiting for review so I can approve them."* → the
> approval is a **human HMAC hard-stop** (`approve_finding`); the examiner signs off in the browser form.

Findings stay in **DRAFT** until a human approves them. This is the one place a person — not a model —
must act before anything is sealed or escalated.

### 🔴 ⑤ `seal` — Courtroom emits the audit seal

> **💬 End-user (prompt):** *"Generate the full report for this case and seal it — then confirm the seal
> hasn't been tampered with."* → routes to `report_generate` → the **HMAC-SHA256** audit seal +
> provenance-chain validation (`report_export` for the shareable artifact).

A tamper-evident chain of custody a judge can independently verify.

### 🟦 ⑥ `escalate` *(optional)* — push to the SIEM

> **🖥️ Expert (command):** push **APPROVED** findings/IOCs to Wazuh behind default-deny kill switches.
> **💬 End-user (prompt):** *"Dry-run the Wazuh push of the approved IOCs and tell me what would be sent
> before anything goes out."* → routes to `wazuh_index_findings` / `wazuh_publish_iocs` (default-deny,
> dry-run first).

---

> ### 💬 Drive the *entire* investigation with a single prompt
> Paste this into a Claude Desktop / Claude CLI session that has the Agentropix MCP attached — the agent
> runs the whole sequence itself, handling OS quirks (e.g. Windows XP has no Amcache / `.evtx`):
>
> > *"You are a DFIR analyst with the Agentropix MCP. Investigate case `<case_id>` on image `<path>`.
> > Run the full SIFT sequence — acquisition → examination → analysis → findings — staging findings as
> > **DRAFT**. For memory images, pull processes, network connections, injected code and services. Do
> > **not** approve findings (a human owns that gate). Finish by generating the full report and
> > summarising the attack chain."*
>
> **🖥️ Expert note:** the same prompt works in `claude --print` for a one-shot headless run. The full
> validated end-to-end runbook — both clients (CLI · Desktop), both lanes (manual · autonomous) — is the
> [**User Guide — Complete Operator Runbook**](docs/01-overview/user-guide.md).

Each step is a worked use case: [Disk triage](docs/06-use-cases/uc-disk-triage.md) ·
[Memory triage](docs/06-use-cases/uc-memory-triage.md) ·
[Approval gate](docs/06-use-cases/uc-approval-gate.md) ·
[Wazuh push](docs/06-use-cases/uc-wazuh-push.md).

---

## Installation / Quickstart

**Path A — 60-second start (runs from this repo, today).** Install the packaged MCP server —
this repo vendors its source and wheel at [`agentropix_mcp/`](agentropix_mcp/README.md) — and
connect a Claude client:

```bash
# 1. Install the v0.2.2 MCP-server wheel  (or, from this checkout: pip install ./agentropix_mcp)
pip install https://github.com/galvangabriel-web/agentropix-mcp/releases/download/v0.2.2/agentropix_mcp-0.2.2-py3-none-any.whl

# 2. Start the server — boot is fail-closed: it refuses to start without an auth token
AGENTROPIX_MCP_AUTH_TOKEN="$(openssl rand -base64 32)" agentropix-mcp --transport http --port 8765

# 3. Point Claude Code at it (use the token from step 2)
claude mcp add --transport http agentropix-sift "http://127.0.0.1:8765/mcp" \
  --header "Authorization: Bearer <token-from-step-2>"
```

Connecting to the operator's **already-running** tailnet server instead? Skip steps 1–2 —
[Client Setup](docs/09-integrations/client-setup.md) is the 5-minute join-and-connect guide
(Claude Code CLI and Claude Desktop via the `mcp-remote` shim).

**Path B — self-host the full triage engine** (`agentropix-sift` CLI: Trinity Loop, `doctor`,
sealed runs). These commands run from a checkout of the **full `agentropix-sift` engine
distribution** — *not* from this documentation portal:

```bash
uv sync                                                          # 1. install the orchestration layer
uv run agentropix-sift doctor                                   # 2. pre-flight — all 16 SIFT tools OK
uv run agentropix-sift run "/cases/study case/2020JimmyWilson.E01" -o report.json   # 3. triage
```

This exact sequence was executed live and recorded against the **Jimmy Wilson** study case:

| Step | Result |
|---|---|
| `uv sync` | dependencies resolved |
| `doctor` | **All tools available** — the 16 SIFT binaries (vol, fls/mmls/icat, ewfinfo, evtx_dump, yara, bulk_extractor, rip.pl, EZ-Tools, …) resolve on PATH |
| `run` | **129 findings · 86 tool calls · 5 iterations**, sealed `report.json` (HMAC) + audit-log, evidence SHA-256 `6c18f662…`, status `budget_exhausted`, critic_score 1.0 |

The full proof — recorded video, sealed reports, raw logs of three reproducible runs, and the
agent-execution trace — is published at
[`case-activation/runs/jimmy-wilson-poc/`](case-activation/runs/jimmy-wilson-poc/). The wider
[`case-activation/`](case-activation/) folder holds a per-case Activation Guide for every evidence
set on this host plus the captured executed runs ([`case-activation/runs/`](case-activation/runs/)).

> **Honest scope note.** The engine repo ships the `pyproject.toml`, `uv.lock`,
> `src/agentropix_sift/`, and a synthetic `samples/sample.dd` fixture for a first smoke run
> (that earliest sealed record is also published:
> [`case-activation/runs/engine-smoke-sample-dd/`](case-activation/runs/engine-smoke-sample-dd/)).
> It is a separate, **currently private** distribution — request access from the operator. This
> docs portal intentionally vendors only the MCP-server package, so Path B does not run from this
> checkout; the case images under `/cases/` live on the operator's host.

The engine installs two console scripts — `agentropix-sift` (the triage CLI) and `agentropix-sift-mcp`
(the MCP server). The full step-by-step for both paths, including example `doctor` output, is in the
[Quickstart](docs/01-overview/quickstart.md). Every CLI command and flag is enumerated in the
[CLI Reference](docs/08-reference/cli-reference.md).

### Deployment & requirements

| Requirement | Detail |
|-------------|--------|
| **Python** | **3.12+** (`pyproject.toml`: `requires-python = ">=3.12"`). Stock SIFT ships 3.10 — provide 3.12 via `uv`, `pyenv`, or the `deadsnakes` PPA. |
| **Host** | A SANS SIFT Workstation (or Ubuntu host with the GIFT PPA toolchain). Runs **fully local** — no API keys, no cloud dependency for the forensic path. |
| **Toolchain on `PATH`** | The 16 SIFT forensic binaries: Volatility3, `log2timeline`, Sleuth Kit (`fls`/`icat`/`mmls`), `ewf-tools`, YARA, `bulk_extractor`, RegRipper, EVTX, EZ-Tools, mail parsers. Agentropix-SIFT *drives* these — it does not ship them. |
| **Degradation** | Missing tools degrade gracefully (the agent is skipped, not the run) — but recall drops, so run `doctor` first. |

See [Deployment](docs/07-sdlc-ops/deployment.md) for SIFT install + tailnet exposure, and
[Recovery & Resilience](docs/07-sdlc-ops/recovery-resilience.md) for the failure-mode catalogue.

---

## Two Paths: Operator (Expert) and End-User

The same triage capability is reachable two ways — the **expert command**, or the **plain-language
prompt** a non-technical examiner types into Claude (with the Agentropix MCP connected), which routes to
a **real MCP tool**. Every operational page in the portal documents both lanes side by side.

| | 🖥️ Operator / Expert (command) | 💬 End-user (prompt) |
|---|---|---|
| **Pre-flight** | `uv run agentropix-sift doctor` | *"Check that my SIFT forensic tools are installed and ready."* |
| **Run a triage** | `uv run agentropix-sift run /cases/INC-0605/disk.E01 -o report.json` | *"Open a case for the image at `/cases/INC-0605/disk.E01`, register it as evidence, run the full SIFT triage, and save the report."* |
| **List memory processes** | MCP tool `get_pslist` | *"List the processes in the memory image and flag anything suspicious."* |
| **Approve a finding** | promote DRAFT → APPROVED in the Approval Portal | *"Show me the findings waiting for review so I can approve them."* |

The 🖥️ `uv run agentropix-sift …` commands run from a full engine checkout (**Path B** above); the
💬 prompts need only a Claude client connected to the MCP server (**Path A** — wheel install or the
live tailnet server). End-user prompts map to real MCP tools (verify against the
[Tool Capability Map](docs/04-mcp-tools/capability-map.md)). The gold-standard treatment of both lanes —
manual ↔ autonomous × expert ↔ non-expert — is the [User Guide](docs/01-overview/user-guide.md).

---

## MCP surface

Agentropix-SIFT exposes **71 distinct MCP tools** over a single FastMCP server (verified live via
`tools/list` and `health.tool_count`; see [Canonical Facts](docs/08-reference/canonical-facts.md)). Of
these, **16 are SIFT forensic tools** — deterministic binaries wrapped under `mcp_server/wrappers/` so
each call captures the binary's raw stdout and fingerprints it with SHA-256. The remainder cover case
lifecycle, finding records, reporting, provenance, approval, executable-artifact registry, and Wazuh.

| Family | Examples | Reference |
|--------|----------|-----------|
| Forensic wrappers (16 SIFT tools) | `get_pslist`, `fls`, `get_evtx`, `yara_scan`, `get_partitions`, `get_evt` | [Tool Reference](docs/04-mcp-tools/tool-reference.md) |
| Case & finding lifecycle | `record_finding`, `delete_finding`, `case_status`, `generate_report` | [Tool Reference](docs/04-mcp-tools/tool-reference.md) |
| Provenance & approval | `retract_approval`, IOC promotion (`promote_iocs`) | [Provenance](docs/05-safety-forensics/provenance-grounding.md) |
| Executable-artifact registry | `build_executable_registry`, `promote_executable_registry`, `exec_registry_get`, `exec_registry_search` | [Tool Reference](docs/04-mcp-tools/tool-reference.md) |
| Wazuh integration | `wazuh_hunt_ioc` (+ wrappers) | [Wazuh push](docs/06-use-cases/uc-wazuh-push.md) · [Operator's guide](docs/09-integrations/wazuh-portal.md) |

Full enumeration: [MCP Tool Reference](docs/04-mcp-tools/tool-reference.md) · who calls what:
[Tools by Agent](docs/04-mcp-tools/tool-by-agent.md) · per-tool breakdown:
[Tool List](docs/04-mcp-tools/tool-list.md).

### Response envelope (example)

Every tool returns a typed Pydantic model serialized with `model_dump()` — never a free-form dict. A
successful `get_pslist` against a memory image:

```json
{
  "image_path": "/cases/INC-2026-0605/mem.raw",
  "process_count": 2,
  "processes": [
    { "pid": 4732, "ppid": 624, "name": "powershell.exe" },
    { "pid": 624,  "ppid": 4,   "name": "services.exe" }
  ],
  "tool": "volatility3.windows.pslist.PsList",
  "raw_stdout_sha256": "9f2c…<64 hex>…1ab0",
  "tool_available": true,
  "skipped_reason": "",
  "status": "ok"
}
```

The load-bearing field is **`raw_stdout_sha256`** — the SHA-256 of the binary's raw stdout bytes, the
provenance fingerprint that ties the finding back to the exact tool output. Soft failures return the same
model with `tool_available: false` and a `skipped_reason`; handled errors return a structured
`ToolError`. Full field tables: [Response Envelope](docs/04-mcp-tools/response-envelope.md).

---

## Safety & anti-hallucination

Agentropix-SIFT is engineered so that the LLM **cannot** become the source of a forensic claim:

- **Deterministic-tools-only findings** — a finding may only be recorded from the output of a
  deterministic forensic binary; the LLM narrates and proposes but never authors evidence.
- **No LLM self-rating** — the Critic halts on a deterministic *convergence fingerprint* (default
  threshold **0.85**, `trinity/critic.py`), not on a model's self-assessed confidence.
- **Pre/post SHA-256 evidence invariant** — evidence is hashed before and after every run; any mutation
  aborts the run. The engine reads but never alters the image.
- **Thymus read-only policy** — deny-by-default boundary (`mcp_server/thymus_policy.py`) blocking
  write/exec paths *before* a tool executes; no write tool exists in the surface.
- **Courtroom HMAC-SHA256 seal** — the audit log (JSONL) is sealed and the provenance chain validated
  (`courtroom.py`, `provenance/`), giving a tamper-evident chain of custody.
- **Human-in-the-loop** — the optional approval sidecar (`approval_sidecar/`) holds findings in DRAFT
  until an examiner APPROVES them.

Deep dives: [Anti-Hallucination](docs/05-safety-forensics/anti-hallucination.md) ·
[Provenance & Grounding](docs/05-safety-forensics/provenance-grounding.md) ·
[Audit & Courtroom Seal](docs/05-safety-forensics/audit-courtroom.md) ·
[Security Model](docs/07-sdlc-ops/security-model.md).

---

## Engineering & evaluation (SDLC depth)

*For the advanced engineer and the evaluator/judge.* The SDLC + quality spine: how the system is tested,
deployed, hardened, kept resilient, scored, and how its decisions are contracted. Every number tracks
[Canonical Facts](docs/08-reference/canonical-facts.md).

**Quick links:** [Testing](docs/07-sdlc-ops/testing.md) · [Recall corpus](docs/07-sdlc-ops/dataset-recall.md) ·
[Eval scorecard](docs/07-sdlc-ops/evaluation-scorecard.md) · [Security model](docs/07-sdlc-ops/security-model.md) ·
[Recovery & resilience](docs/07-sdlc-ops/recovery-resilience.md) · [Deployment](docs/07-sdlc-ops/deployment.md) ·
[Implementation](docs/07-sdlc-ops/implementation.md) · [ADR index](docs/11-ADR/README.md)

- **Testing — 4464 collected tests** (`pytest --collect-only -q`) in two tiers. *Fast / always-run*
  (mock-based, CI + pre-commit): `tests/unit/`, `chaos/`, `provenance/`, `evidence_gate/`,
  `approval_sidecar/`, `secrets_gate/`, `wazuh/`. *Host-gated* (skip-with-reason when the fixture is
  absent): `integration/` (SIFT binaries + a staged E01), `wazuh_live`, `real_corpus`. A missing E01 or
  unreachable Wazuh is a **skip naming every searched path** — never a false failure.
- **Correctness gates wired into CI:** `pytest-cov`, **basedpyright `strict`** typing as a correctness
  gate (not a lint), **ruff** selectors `E,F,W,I,UP,B,SIM`, and `asyncio_mode = "auto"` (fitting — every
  agent is an async coroutine over the MCP boundary).
- **Forward-drift gate (for evaluators):** the test count is CI-enforced — a doc quoting the count
  without citing the canonical fact file fails the build, and known-stale literals are *actively
  rejected*. See [Canonical Facts](docs/08-reference/canonical-facts.md).
- **Ground-truth recall you can audit:** **72/72 (100%)** disk recall (regression) and **108/118
  (91.5%)** combined memory recall. Methodology, including the post-hoc ground-truth caveat:
  [Dataset Recall](docs/07-sdlc-ops/dataset-recall.md) · scoring rubric:
  [Evaluation Scorecard](docs/07-sdlc-ops/evaluation-scorecard.md).

---

## SWOT — strategic assessment

A structured strategic assessment for evaluators, engineers, and adopters. Each cell is grounded in the
repository corpus (`docs/COMPETITIVE-DFIR.md` oracle, [Canonical Facts](docs/08-reference/canonical-facts.md),
[Competitive Positioning](docs/01-overview/competitive-positioning.md)).

| | **Helpful** | **Harmful** |
|---|---|---|
| **Internal** | **Strengths** — *Structural* evidence safety, not a policy promise: agents have **no write tool**; the Thymus policy refuses every write call before the subprocess spawns. Real SANS DFIR tools driven **inside** the agent loop (**16/16 wrappers**, **71 MCP tools**) — rivals explain JSON *after* collection. Deterministic, auditable execution: a fingerprint no-progress detector halts the Trinity Loop with **no LLM in the halt path**, backed by a hash-chained decision ledger. | **Weaknesses** — A **triage engine, not a case-management product**: no HTML report generator, no commercial case-file UX (vs Magnet AXIOM, CADO); output is JSON + the audit ledger. **Read-only consumer**, no host-collection ecosystem (vs Velociraptor's agent fleet) — caps it at post-collection triage. Memory-forensics recall (**108/118**) trails disk (**72/72**) and is the active improvement front. |
| **External** | **Opportunities** — The MCP consumer model means *any* MCP-speaking LLM client becomes a forensic front-end with zero retraining. Default-local, no-API-key posture fits air-gapped / sovereign SOCs. The ATT&CK detector lane is extensible — deferred detectors (W051/W052/W054) are wired and unit-tested, ready to promote into live recall. | **Threats** — Forensic admissibility scrutiny of any AI-assisted pipeline raises the documentation bar (mitigated by the courtroom seal + provenance chain). Upstream SIFT tool drift (binary flags / output format) can silently shift wrapper parsing — covered by host-gated integration tests. Commercial incumbents move fast on AI features. |

Full competitive analysis: [Competitive Positioning](docs/01-overview/competitive-positioning.md).

---

## Configuration

Behavior is tuned through the `AGENTROPIX_*` environment surface — Critic halt threshold, Blackboard
quorum, status taxonomy, tool-path overrides, and more — with safe defaults so the engine runs out of the
box. See [Configuration](docs/07-sdlc-ops/configuration.md) and the
[env-var table](docs/07-sdlc-ops/env-vars.md).

---

## Canonical facts

> **Single source of truth for every numeric claim** — never state a number that contradicts it.

| Fact | Value |
|------|-------|
| MCP tools | **71** distinct tool functions |
| SIFT forensic wrappers | **16** |
| Tests collected | **4464** |
| Disk recall (regression) | **72/72 (100%)** |
| Memory recall (combined) | **108/118 (91.5%)** |
| Core swarm specialists | **7** (Memory, Timeline, Filesystem, Artifact, Discovery, Mail, Hunt) |
| `SWARM` classes (incl. ATT&CK detectors) | **13** |
| Critic halt threshold (default) | **0.85** |
| Blackboard quorum (default) | **2** |
| Python | **3.12+** |

Full table with per-row sources and verification dates:
[Canonical Facts](docs/08-reference/canonical-facts.md).

---

## Documentation map

Start at the routed [master table of contents](INDEX.md), which maps every chapter to its audience and
the question it answers. The portal is organized into twelve numbered sections under `docs/`, plus the
`case-activation/` operational annex:

| # | Section | What it contains |
|---|---------|------------------|
| 1 | [Overview](docs/01-overview/what-is-agentropix.md) | What Agentropix-SIFT is and why, the capability matrix, the 3-command Quickstart, the complete operator User Guide, and how it compares to alternatives. |
| 2 | [Architecture](docs/02-architecture/main-architectural-agentropix-design.md) | How the engine is built — **the validated architecture diagram** (pattern + guardrails, HD PDF), system context, internal components, the Trinity Loop, the Swarm + Blackboard, the FastMCP server (and the Thymus boundary), and sequence diagrams. |
| 3 | [Data](docs/03-data/data-models.md) | The data model — case/finding/report schemas, the data dictionary, the entity-relationship view, and what gets persisted to disk. |
| 4 | [MCP Tools](docs/04-mcp-tools/tool-reference.md) | The 71-tool MCP surface — the full tool reference, the typed Response Envelope, which agent invokes which tool, and the capability map. |
| 5 | [Safety & Forensics](docs/05-safety-forensics/anti-hallucination.md) | Why you can trust the output — anti-hallucination guarantees, provenance grounding, the Courtroom audit seal, the human-in-the-loop gate, the Approval Portal, and the AI disclosure. |
| 6 | [Use Cases](docs/06-use-cases/uc-disk-triage.md) | End-to-end worked runs — disk triage, memory triage, the approval gate, the Wazuh push, a guided demo walkthrough, and per-case attack-chain hypotheses. |
| 7 | [SDLC & Operations](docs/07-sdlc-ops/implementation.md) | How to build, run, and operate it — implementation, testing, configuration, deployment, the security model, recovery/resilience, recall methodology, and the evaluation scorecard. |
| 8 | [Reference](docs/08-reference/cli-reference.md) | Look-up material — the full CLI reference, the glossary, the ADR index, and the design-decision rationale. |
| 9 | [Integrations](docs/09-integrations/wazuh-portal.md) | Connecting to external systems — the Wazuh/SOC portal operator's guide and how to connect a remote client to a live internal MCP server. |
| 10 | [Agents](docs/10-agents/agentic-architecture.md) | What "agent" means here — the agentic architecture, the build-time delegation model, the FastMCP tool-execution path, and the canonical runtime swarm roster. |
| 11 | [ADRs](docs/11-ADR/README.md) | The **decision contract** — the immutable Architecture Decision Records mirrored from the oracle (001–024 + milestone/defer records). Read the status column literally. |
| 12 | [Cases Reports](docs/12-CASES-REPORTS/README.md) | Sealed DFIR case reports — one folder per investigated case (forensic report, technical appendix, Wazuh IOC gallery, diagrams, recorded-session video). |
| — | [case-activation/](case-activation/README.md) | The operational annex — a per-case **Activation Guide** for every evidence set (real paths, sizes, custody hashes) and [`runs/`](case-activation/runs/README.md): captured executed runs (raw MCP step outputs, sealed engine PoC reports, videos). |

The portal's documentation-QA working notes (render audits, case-guide sweeps) live under
[`docs/issues/`](docs/issues/) — maintainer-facing, not reader chapters.

---

## Acknowledgments

Built on the shoulders of the open-source DFIR ecosystem: the **SANS SIFT Workstation** and the forensic
tools it bundles — **Volatility3**, **Plaso/log2timeline**, **The Sleuth Kit**, **python-evtx**,
**YARA**, **bulk_extractor**, **RegRipper**, the **EZ-Tools** family, and the mail-parsing libraries
(`libpff`, `extract-msg`). The MCP surface is served by [**FastMCP**](https://github.com/jlowin/fastmcp).

## License

Released under the **MIT License**.
