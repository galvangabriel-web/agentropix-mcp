# Agentropix-SIFT

![Agentropix-SIFT — MCP Unified Forensic Triage Architecture: 73 tools and 16 SIFT forensic wrappers behind one MCP interface; an agent swarm cuts days of disk + memory triage to minutes, with every finding deterministic and hashed](assets/hero-architecture.png)

> **Dear Evaluator,**
>
> My name is **Gabriel Galvan**, and I am proud to introduce the **Agentropix MCP** solution.
>
> This innovative solution enables the initial triage phase of modern digital forensic
> investigations. I created this repository to demonstrate how Agentropix was designed, the key
> considerations that guided its development, and the features it provides. A detailed roadmap
> outlining the project's vision, architecture, and capabilities is included at the end of this
> document.
>
> The documentation section is fully completed and contains all the information required to
> understand how the solution works. In addition, you will find case analyses, technical reports,
> specifications, and supporting documentation that demonstrate the functionality and
> effectiveness of Agentropix MCP.
>
> Thank you for taking the time to evaluate this project. I hope you find Agentropix MCP both
> innovative and valuable for modern forensic analysis workflows.
>
> — *Gabriel Galvan*

> 🧭 **Judges:** the **[Evaluation Map](EVALUATION-MAP.md)** routes each of the 8 submission
> requirements (code · demo video · architecture diagram · project story · datasets · accuracy ·
> try-it-out · execution logs) to its exact evidence in this repository — or watch the
> 🎬 **[2 min 24 s Submission Evidence Tour](https://galvangabriel-web.github.io/agentropix-mcp/assets/submission-tour/watch-tour.html)** ([build sources](assets/submission-tour/README.md))
> (auto-plays): one animated scene per requirement, each with a live-captured proof panel. And for
> the investigation flow itself, the 🎞️ **[six-stage workflow animation](#-recommended-investigation-workflow)**
> plays inline right on this page — doctor → run → review → human gate → seal → escalate — and the
> 🎞️ **[safety proof reel](#%EF%B8%8F-the-six-guarantees-proven-on-screen)** shows every anti-hallucination
> guarantee backed by real cited evidence from the sealed execution logs.

> 🎥 **Featured video — [Case Evaluation walkthrough (8 min 27 s, narrated) ▶ on Vimeo](https://vimeo.com/1201031111)**
> — the full **SRL-2015** evidence walkthrough, with every headline number re-computed **live from the
> committed raw data**: 2,233 findings · 12 malicious IOCs of 91 · 5 `malfind` payloads · 21/21
> hash-verified samples · YARA 5/5 · 17 examiner-approved findings. Local copy in-repo:
> [`Final_Video/SRL-2015-EVIDENCE-presentation.mp4`](Final_Video/SRL-2015-EVIDENCE-presentation.mp4).

> 🔎 **Audit reports** (auto-generated, repo-grounded — every figure cites its source):
> **[Evidence Dataset Documentation](EVIDENCE_DATASET_DOCS.md)** — full inventory of the case
> datasets with provenance, SHA-256 integrity, schemas, and the ingestion pipeline; and the
> **[System Accuracy & Validation Report](ACCURACY_REPORT.md)** — component benchmark matrix,
> recall metrics (72/72 disk · 108/118 memory), and algorithmic-drift findings with file:line refs.

> 🤖 **For LLMs / AI agents:** a [`llms.txt`](llms.txt) curated index (project summary, canonical
> facts, and links to every core doc) — and [`llms-full.txt`](llms-full.txt), the expanded variant
> that inlines the full content of the core docs for single-pass ingestion.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#license)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![MCP tools: 73](https://img.shields.io/badge/MCP%20tools-73-green.svg)](docs/04-mcp-tools/tool-reference.md)
[![SIFT wrappers: 16](https://img.shields.io/badge/SIFT%20wrappers-16-brightgreen.svg)](docs/04-mcp-tools/tool-reference.md)
[![Tests: 4687](https://img.shields.io/badge/tests-4687-brightgreen.svg)](docs/07-sdlc-ops/testing.md)
[![Disk recall: 72/72](https://img.shields.io/badge/disk%20recall-72%2F72-success.svg)](docs/07-sdlc-ops/dataset-recall.md)

> ## Autonomous DFIR triage on the SANS SIFT Workstation — that never lets the LLM rate its own findings.
> Point it at a Windows disk or memory image. It drives **16 real SIFT forensic tools** through **one
> MCP server (73 tools)**, correlates across a **7-agent swarm** on a quorum blackboard, and emits a
> cryptographically sealed, schema-validated JSON triage report — in minutes, on the local host, with
> **no LLM ever in the halt path**. *(Source: [`what-is-agentropix.md`](docs/01-overview/what-is-agentropix.md).)*

**A local, CLI-driven, bio-agentic DFIR triage engine for the SANS SIFT Workstation.**

> 🗺️ **Evaluators — the [Strategic Project Roadmap](docs/02-architecture/PROJECT-ROADMAP-2026-06-11.md)
> (2026-06-11)** is the "where this is, where it's going" document: the development Gantt with the
> critical path to GA, the system-lifecycle state machine (orchestration, thread taxonomy, apoptosis),
> phase milestones (Foundation → Orchestration → Scale & GA), technical specifications, and risk
> mitigation — the strategic companion to the [Architecture chapter](docs/02-architecture/README.md).

---

## 🧪 Judge / Try-it-out — run locally in 5 minutes

> **Free of charge, no signup, no account, no VPN/tailnet required.** Everything below runs on
> `127.0.0.1` using the open-source wheel vendored in this repo.

```bash
# 1. Install the MCP server (pick one)
pip install ./agentropix_mcp        # from this checkout — vendored at agentropix_mcp/
# …or the released wheel:
pip install https://github.com/galvangabriel-web/agentropix-mcp/releases/download/v0.3.0/agentropix_mcp-0.3.0-py3-none-any.whl

# 2. Generate a local auth token and start the server (boot is fail-closed without one)
export AGENTROPIX_MCP_AUTH_TOKEN="$(openssl rand -base64 32)"
agentropix-mcp --transport http --port 8765

# 3. In another terminal, point Claude Code at your local server (same token)
claude mcp add --transport http agentropix-sift "http://127.0.0.1:8765/mcp" \
  --header "Authorization: Bearer $AGENTROPIX_MCP_AUTH_TOKEN"
```

**4. Smoke-test it** — ask the model:

> *"Use the agentropix-sift MCP server. Run the `health` tool and tell me the tool_count."*

Expected: `tool_count: 73` (the live count is authoritative — this number may lag).

More detail (self-hosting the full engine, requirements table): see
[Installation / Quickstart](#installation--quickstart) below and the
[Quickstart guide](docs/01-overview/quickstart.md).

---

## 🚀 Deploy, run & extend it yourself

The 5-minute block above is the smoke test. Here is the full path from *zero* to *running the agent on
your own evidence and building on it* — each step links the complete guide (nothing duplicated):

1. **Install** the agent — [`agentropix_mcp/README.md`](agentropix_mcp/README.md) (the package ships the
   engine: `agents/`, `detectors/`, `trinity/`, `wrappers/`) · full self-host: [deployment.md](docs/07-sdlc-ops/deployment.md).
2. **Configure** your MCP client (Claude Code / Claude Desktop) — [client-setup.md](docs/09-integrations/client-setup.md).
3. **Run** it on a disk or memory image — [try-it-end-to-end.md](docs/01-overview/try-it-end-to-end.md)
   (one prompt, disk **and** memory) · the two install paths + `doctor` output: [quickstart.md](docs/01-overview/quickstart.md).
4. **Reproduce** a published case from scratch — [reproduce-datasets.md](docs/06-use-cases/reproduce-datasets.md)
   (public dataset URLs + hashes; the **CFReDS** "Hacking Case" is a fully-public end-to-end loop) ·
   compare your run against the sealed [case reports](docs/12-CASES-REPORTS/README.md).
5. **Extend** it — add your own SwarmAgent, ATT&CK detector, or tool wrapper:
   [extend-the-swarm.md](docs/10-agents/extend-the-swarm.md) (source-cited recipes + the test contract).

> **What runs today vs. what needs the engine repo:** the **vendored MCP-server wheel** (Path A,
> `pip install ./agentropix_mcp`) drives the real forensic tools against *your* image through Claude
> **right now** — install, configure, run, and extend are all reproducible from this checkout. The
> fully-autonomous **Trinity-Loop engine run** (Path B) additionally needs the engine distribution
> (currently private — request access); the honest scope note is kept throughout.

---

## ⚡ Connect to a hosted instance (author's tailnet — optional)

> **Judges / evaluators:** you do **not** need this — use the local path above
> ([Judge / Try-it-out](#-judge--try-it-out--run-locally-in-5-minutes)); this section is only for
> users invited to the author's private tailnet.

> **🚀 Already have a SIFT host running on our tailnet? Point Claude at it right now — no install, no build.**
> One command and you're driving **73 forensic tools** from Claude. **Full guide → [docs/09-integrations/client-setup.md](docs/09-integrations/client-setup.md).**

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

Expected: `tool_count: 73` (the live count is authoritative — this number may lag).

> **First time on the tailnet, or hit a `401` / timeout?** The complete quickstart — Tailscale invite,
> per-OS install, token facts, and a full troubleshooting matrix — is in
> **[📘 Client Setup — Install Quickstart](docs/09-integrations/client-setup.md)**.

---

## Start here — pick your lane

Four audiences, four fast paths. Each row is an ordered reading trail; the full routing lives in the
[Documentation Index](INDEX.md#reading-paths-by-audience).

| You are a… | You want to… | Start here → then |
|---|---|---|
| 🧑‍💻 **Software engineer** | understand the architecture, build/test/extend it | [Implementation](docs/07-sdlc-ops/implementation.md) → [Trinity Loop](docs/02-architecture/trinity-loop.md) → [Swarm & Blackboard](docs/02-architecture/swarm-agents.md) → [FastMCP Server](docs/02-architecture/mcp-server.md) → [**Extend the Swarm**](docs/10-agents/extend-the-swarm.md) → [Testing](docs/07-sdlc-ops/testing.md) → [ADRs (decision contract)](docs/11-ADR/README.md) |
| 🛡️ **SOC analyst** | run a triage, hunt IOCs, push to the SIEM | [User Guide (runbook)](docs/01-overview/user-guide.md) → [Disk triage](docs/06-use-cases/uc-disk-triage.md) → [Memory triage](docs/06-use-cases/uc-memory-triage.md) → [Wazuh push](docs/06-use-cases/uc-wazuh-push.md) → [CLI Reference](docs/08-reference/cli-reference.md) |
| ⚖️ **Evaluator / judge** | verify the claims, soundness, chain of custody | [Canonical Facts](docs/08-reference/canonical-facts.md) → [Anti-Hallucination](docs/05-safety-forensics/anti-hallucination.md) → [Audit & Courtroom Seal](docs/05-safety-forensics/audit-courtroom.md) → [Evidence integrity (visual)](docs/07-sdlc-ops/evidence-integrity-visual.md) → [Recall methodology](docs/07-sdlc-ops/dataset-recall.md) → [Evaluation scorecard](docs/07-sdlc-ops/evaluation-scorecard.md) → [SWOT](#swot--strategic-assessment) |
| 💬 **End-user (non-technical)** | get answers by just *asking* Claude | **[Try it end-to-end — one prompt](docs/01-overview/try-it-end-to-end.md)** (a single copy-paste prompt runs a whole public case) → the [Two Paths table](#two-paths-operator-expert-and-end-user) below → end-user lanes in the [User Guide](docs/01-overview/user-guide.md) → [Tool Capability Map](docs/04-mcp-tools/capability-map.md) |

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
convergence fingerprint (with **no LLM self-rating**) — orchestrates **73 MCP tools** over a single
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
        TOOLS["73 MCP tools<br/>traced · rate-limited · Thymus-gated"]:::det
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
  (`mcp_server/fastmcp_app.py`). Console scripts differ by distribution: the **vendored MCP-server wheel**
  (Path A, `pip install ./agentropix_mcp`) installs **`agentropix-mcp`** only; the **full engine**
  (Path B) installs `agentropix-sift` (triage CLI) and `agentropix-sift-mcp` (the MCP server). An LLM
  connects to the MCP-server script; the CLI bypasses it and drives the engine directly. See
  [The FastMCP Server](docs/02-architecture/mcp-server.md).
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
| **73 MCP tools** | One FastMCP server exposes **73 distinct forensic tools** over stdio + HTTP | **73** tools | `mcp_server/fastmcp_app.py` |
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
        Agentropix["Agentropix-SIFT<br/>Trinity Loop engine + FastMCP server (73 tools)"]:::core
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
73-tool surface, writing `Finding`s to a shared **Blackboard**; cross-agent agreement at a **quorum** of
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

> 📋 **Copy-paste, end-to-end:** paste **one** of the two blocks below into a Claude session with the
> Agentropix MCP connected — it runs the entire six-stage flow on a real case and returns every result,
> stopping only at the human approval gate. Full guide, step-by-step tool map, and flow diagrams:
> **[Try it end-to-end — one prompt, a full investigation](docs/01-overview/try-it-end-to-end.md)**.

<details>
<summary><b>🖴 Disk case — CFReDS "Hacking Case" (Windows XP, public NIST image)</b> · <a href="docs/01-overview/try-it-end-to-end.md#the-prompt-disk-case--paste-this-whole-block-into-claude">canonical source + flow diagram</a></summary>

```text
You are my DFIR analyst, and you have the Agentropix-SIFT MCP server connected. Investigate ONE
case end-to-end and show me every result. Work autonomously — don't ask me questions — and stop
only at the human approval gate.

THE CASE
- Name: CFReDS "Hacking Case" (Greg Schardt / "Mr. Evil")
- Case ID: CFREDS-HACKING-CASE-4DELL  (examiner: victor.galvan, severity: high)
- Evidence (disk, EWF): /cases/cfreds-fresh/4Dell-Latitude-CPi.E01   (the .E02 segment is read automatically)
- It is a Windows XP disk image. There is NO memory dump — do NOT use any memory/Volatility tools
  (no pslist / netscan / malfind / svcscan / process_tree).

PER-CASE RULES (follow exactly — they matter):
- The NTFS volume starts at sector offset 63. Pass offset 63 to file-listing and file-extraction.
  Confirm the partition layout first.
- Windows XP event logs are ".evt" → use the .evt event-log tool (get_evt), NOT the Vista+ .evtx one.
  Skip Amcache (it is Windows 7+ only).
- Put any carving output dir under /tmp/agentropix-sift-  (e.g. /tmp/agentropix-sift-cfreds-be).

DO THIS IN ORDER, AND SHOW ME EACH RESULT:
0. Pre-flight + custody: confirm the forensic environment is ready, then verify the image integrity
   and show me who acquired it and what OS it is. (Expect stored MD5 == aee4fcd9301c03b3b054623ca261959a.)
1-3. Open case CFREDS-HACKING-CASE-4DELL (high severity, examiner victor.galvan, evidence in
   /cases/cfreds-fresh), make it the active case, and confirm it's active and the indexer is reachable.
4. Register the E01 as evidence and give me its SHA-256 chain-of-custody hash.
5. Analyze the disk and report each result:
   a. Partition layout — confirm NTFS at offset 63.
   b. List all files (offset 63, recursive); then list just the deleted files.
   c. Carve indicators (emails, domains, IPs, URLs) into /tmp/agentropix-sift-cfreds-be.
   d. Run a YARA smoke-scan (0 matches is a clean pass, not a failure).
   e. Lift the registry hives (offset 63) and pull execution/persistence artifacts: registry,
      shimcache, prefetch, and the XP .evt event logs.
6. Record what you found as findings (they will be saved as DRAFT — that is expected; you cannot
   self-approve evidence).
7. STOP at the approval gate: list exactly which findings are waiting for MY approval, with their IDs,
   and tell me how to approve them (the human HMAC examiner portal). Do NOT approve them yourself.
8. Generate the case report and give me the report ID + section counts. (Approved-finding count will
   be 0 until I approve in step 7 — that is correct.)

FINALLY, give me a concise summary: the custody SHA-256, the partition offset, the file + deleted-file
counts, the IOCs carved, the artifacts found, the DRAFT findings (with IDs), and the report ID — plus
any honest negatives (tools that found nothing or were skipped, and why).
```
</details>

<details>
<summary><b>🧠 Memory case — generic raw RAM dump (Volatility chain)</b> · <a href="docs/01-overview/try-it-end-to-end.md#memory-case-variant">canonical source + flow diagram</a></summary>

```text
You are my DFIR analyst with the Agentropix-SIFT MCP connected. Investigate ONE memory case end-to-end
and show me every result. Work autonomously; stop only at the human approval gate.

THE CASE
- Case ID: MEMDUMP-2014  (examiner: victor.galvan, severity: medium)
- Evidence (raw memory dump): /cases/memdump/memdump.mem

MEMORY RULES (follow exactly):
- Do NOT run get_image_info on a raw memory dump — it reads EWF/E01 metadata and returns empty on .mem.
- get_pslist is the OS/profile confirm step: Volatility auto-detects the kernel symbol table on the first
  windows.* plugin. A populated process list confirms the profile matched; an empty list with a
  symbol-table error is an HONEST NEGATIVE (no profile resolved) — report it as such, don't invent results.
- This is memory only — do NOT use disk tools (no partitions/fls/extract_files/registry-from-disk).

DO THIS IN ORDER, AND SHOW ME EACH RESULT:
0. Confirm the environment is ready and register the dump as evidence (give me its SHA-256).
1-3. Open case MEMDUMP-2014, make it active, confirm active + indexer reachable.
4. Process list (this also confirms the OS/profile). If it's empty with a symbol-table error, tell me
   plainly that no profile resolved and stop the memory chain.
5. Network connections, injected/suspicious code, services, and the process tree (PPID forest, LOLBin flags).
6. Record what you found as DRAFT findings (you cannot self-approve).
7. STOP at the approval gate: list the DRAFT findings + IDs and how I approve them. Do NOT approve them.
8. Generate the report; give me the report ID + section counts.

FINALLY: a concise summary — custody SHA-256, process/network/injection highlights, the DRAFT findings
(with IDs), the report ID, and any honest negatives.
```
</details>

![Stage 1 doctor](https://img.shields.io/badge/①_DOCTOR-pre--flight-8e44ad?style=for-the-badge)
![Stage 2 run](https://img.shields.io/badge/②_RUN-triage-2980b9?style=for-the-badge)
![Stage 3 review](https://img.shields.io/badge/③_REVIEW-verify-f39c12?style=for-the-badge)
![Stage 4 approve](https://img.shields.io/badge/④_APPROVE-HITL_gate-27ae60?style=for-the-badge)
![Stage 5 seal](https://img.shields.io/badge/⑤_SEAL-courtroom-c0392b?style=for-the-badge)
![Stage 6 escalate](https://img.shields.io/badge/⑥_ESCALATE-SIEM-16a085?style=for-the-badge)

![Animated: the six guarded stages light up in sequence — doctor pre-flight, run triage, examiner review, the human HMAC approval gate, the courtroom seal, and the SIEM escalation — ending on “SEALED · HMAC-SHA256 · court-ready”](assets/workflow-animated.gif)

> 🎬 *The banner above is a live animation (Animotion MCP; [deck source](assets/workflow-animated-deck.html)) — watch the stages light up,
> the* ***human gate*** *hold the line, and the seal close. Want the full detail graph instead?*
> *[**Static diagram (PNG)**](assets/readme-3.png) · [**SVG** (full size, zoomable)](assets/readme-3.svg).

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
# 1. Install the v0.3.0 MCP-server wheel  (or, from this checkout: pip install ./agentropix_mcp)
pip install https://github.com/galvangabriel-web/agentropix-mcp/releases/download/v0.3.0/agentropix_mcp-0.3.0-py3-none-any.whl

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
[`case-activation/runs/jimmy-wilson-poc/`](case-activation/runs/jimmy-wilson-poc/). The
evaluator-facing **Agent Execution Logs gold report** — two further engine runs (the SRL-2018
domain controller + Challenge_NotchItUp) with timestamped agent-to-agent handoff chains, full tool
sequences, and the raw sealed evidence incl. live `run.log` + Thymus audit trails — is at
[`docs/12-CASES-REPORTS/srl-2018-report/submission/`](docs/12-CASES-REPORTS/srl-2018-report/submission/AGENT-EXECUTION-LOGS-REPORT.md),
with its 🎨 **[Visual Atlas](docs/12-CASES-REPORTS/srl-2018-report/submission/AGENT-EXECUTION-VISUAL-ATLAS.md)** —
thirteen color diagrams (agent-communication graph, end-to-end timestamp chain with a
217-microsecond correlation-burst zoom, self-correction funnels, Thymus ALLOW/REJECT pies, and the
HMAC seal cross-binding chain) generated from and verified against the raw run data — and its
🎬 **[108-second animated walkthrough](https://galvangabriel-web.github.io/agentropix-mcp/docs/12-CASES-REPORTS/srl-2018-report/submission/watch.html)**
(plays directly in your browser): the same topics in motion — the 91-minute wait drawn to scale,
the 61-shield REJECT storm, the microsecond burst, and the self-correcting plan — animated with
the Animotion MCP and rendered deterministically from the committed
[deck source](docs/12-CASES-REPORTS/srl-2018-report/submission/execution-logs-animated-deck.html).
The **multi-host edition** scales the same discipline to SRL-2015 — 4 hosts × disk+memory, **8 sealed
runs, 2,233 findings, 15-iteration loops**, and the cross-host spinlock.exe → Domain-Controller
correlation: 📄 [report](docs/12-CASES-REPORTS/srl-2015-report/AGENT-EXECUTION-LOGS-REPORT-SRL2015.md) ·
🎬 **[2 min 24 s animated walkthrough](https://galvangabriel-web.github.io/agentropix-mcp/docs/12-CASES-REPORTS/srl-2015-report/watch-execution-logs.html)** (auto-plays). The
requirement-8 bundle for the **ROCBA** Windows-10 insider-IP-theft case is a real live-MCP triage —
timestamped tool sequence, server HTTP audit, Thymus decisions, a grounded DRAFT finding, and the
honest negatives kept on record:
[`case-activation/runs/rocba/EXECUTION-LOG.md`](case-activation/runs/rocba/EXECUTION-LOG.md). The same
case's **Trinity-engine run** captures the backend **agent ↔ blackboard communication** —
**21 blackboard publishes across 13 agents** (the `hunt` agent fusing **14 cross-source correlations**),
**351 findings / 509 tool calls**, and the iteration-over-iteration **plan shrink** (13 agents → just
`[discovery, mail]` once the Critic marks 11 *stable*):
[`case-activation/runs/rocba/engine-run/AGENT-BLACKBOARD.md`](case-activation/runs/rocba/engine-run/AGENT-BLACKBOARD.md)
(+ the derived [`blackboard-events.jsonl`](case-activation/runs/rocba/engine-run/blackboard-events.jsonl)).
A sibling agent-execution-log run covers the Windows XP laptop (2005) case at
[`WINXP-LAPTOP-2005`](case-activation/runs/WINXP-LAPTOP-2005/) —
🎬 **[3 min 19 s animated walkthrough](https://galvangabriel-web.github.io/agentropix-mcp/case-activation/runs/WINXP-LAPTOP-2005/WINXP-LAPTOP-2005-video/watch.html)**
(auto-plays): a 13-scene deterministic deck correlated from its logs (297 records · 64 tool calls · 14
errors, all recovered), grounded in the
[correlation report](case-activation/runs/WINXP-LAPTOP-2005/WINXP-LAPTOP-2005-video/CORRELATION-REPORT.md).
The **CFReDS "Hacking Case"** sealed case report (**CFREDS-HACKING-CASE-4DELL** — the public NIST
single-host Windows XP disk image of Greg Schardt / "Mr. Evil", a standalone *unauthorized wireless
interception* case — **no memory image, no enterprise lateral movement**) keeps its own
[agent execution log](docs/12-CASES-REPORTS/cfreds-hacking-case-report/audit/PROJECT-agent-execution-log.md)
alongside the full report: a single Claude-Code agent (`claude-opus-4-8[1m]`) plus one embedded
multi-agent forensic workflow, **400 tool calls**, **35 examiner-approved findings** (2 critical /
15 high), **24 timeline events**, 93 IOCs staged, sealed/approved by `victor.galvan` 2026-06-14 over
`4Dell-Latitude-CPi.E01` (MD5 `aee4fcd9301c03b3b054623ca261959a`):
[`docs/12-CASES-REPORTS/cfreds-hacking-case-report/`](docs/12-CASES-REPORTS/cfreds-hacking-case-report/README.md)
([executive](docs/12-CASES-REPORTS/cfreds-hacking-case-report/CFREDS-executive.md) ·
[analyst](docs/12-CASES-REPORTS/cfreds-hacking-case-report/CFREDS-analyst.md) ·
[attack graph](docs/12-CASES-REPORTS/cfreds-hacking-case-report/diagrams/attack-graph.png)).
The wider
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

Agentropix-SIFT exposes **73 distinct MCP tools** over a single FastMCP server (verified live via
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
- **Pre/post SHA-256 evidence invariant** — evidence is hashed at session start and re-verified in
  tests; immutability is enforced *structurally* (Thymus + no write tool exists), per the 2026-06-11
  source audit below. The engine reads but never alters the image.
- **Thymus read-only policy** — deny-by-default boundary (`mcp_server/thymus_policy.py`) blocking
  write/exec paths *before* a tool executes; no write tool exists in the surface.
- **Courtroom HMAC-SHA256 seal** — the audit log (JSONL) is sealed and the provenance chain validated
  (`courtroom.py`, `provenance/`), giving a tamper-evident chain of custody.
- **Human-in-the-loop** — the optional approval sidecar (`approval_sidecar/`) holds findings in DRAFT
  until an examiner APPROVES them.

### 🎞️ The six guarantees, proven on screen

![Animated: each of the six safety guarantees with real cited proof from the sealed Agent Execution Logs — the 204,884-entry fls walk, the critic pinned at 1.0 across 10 runs, 10 distinct evidence SHA-256, the 61 Thymus REJECTs, the byte-identical seal cross-bind, and the 17+12 examiner-approved findings](assets/safety-proof-animated.gif)

> 🎬 *Auto-playing proof reel (73 s loop; [deck source](assets/safety-proof-deck.html)) — each scene shows the cited
> evidence **plus a plain-language "💡 What you're seeing" explainer**. Every value is real, from the
> [SRL-2015](docs/12-CASES-REPORTS/srl-2015-report/AGENT-EXECUTION-LOGS-REPORT-SRL2015.md) and
> [SRL-2018](docs/12-CASES-REPORTS/srl-2018-report/submission/AGENT-EXECUTION-LOGS-REPORT.md) Agent Execution Logs: the 204,884-entry `fls` walk,
> critic pinned at 1.0 across all 10 runs, 10 distinct evidence SHA-256, the 61 live `REJECT_OUTSIDE_ALLOWLIST` denials, the byte-identical
> seal cross-bind, and the 17 + 12 examiner-approved findings.*

### 🔒 Source-traced invariant audit (2026-06-11)

The six guarantees above were **audited against the source, file:line by file:line** — no prompt-only
claims accepted. Headline: **5 of 6 invariants Enforced; #3 Partially Enforced** — the literal
per-tool abort-on-delta mechanism does not exist, but the evidence-immutability goal is met by a
stronger structural design (no write tool + deny-by-default Thymus). The audit's Unified Compliance
Matrix, verbatim:

| # | Invariant | Status | Primary enforcement site(s) | Key lines |
|---|-----------|--------|------------------------------|-----------|
| 1 | Deterministic-tools-only findings | ✅ Enforced | `agents/_base.py` (Finding model + sole publish path); `orchestrator.py` (report built from Blackboard) | `_base.py:40-92, 130-149`; `orchestrator.py:69, 277-284` |
| 2 | No LLM self-rating (Critic) | ✅ Enforced | `trinity/critic.py` (arithmetic score, threshold halt) | `critic.py:120-122, 180-206`; threshold clamp `76-81` |
| 3 | Pre/post SHA-256 evidence invariant | ⚠️ Partially Enforced | `courtroom.py` (session-start hash); immutability via Thymus + no-write-tools; tested pre/post | `courtroom.py:89-142`; `orchestrator.py:292, 311`; `thymus_policy.py:362-369` — **no runtime `sys.exit()` on delta** |
| 4 | Thymus read-only policy | ✅ Enforced | `mcp_server/thymus_policy.py` (deny-by-default allowlist; writes always reject) | `thymus_policy.py:264-267, 289-308, 325-330, 362-369` |
| 5 | Courtroom HMAC-SHA256 seal | ✅ Enforced | `courtroom.py` (seal + cross-bound audit seal); `hash_chain.py` (per-entry chain); `provenance/validate.py` (external validator, non-zero exit) | `courtroom.py:161-182, 341-397`; `hash_chain.py:73-101`; `validate.py:90, 278-363` |
| 6 | Human-in-the-loop sidecar | ✅ Enforced | `approval_sidecar/` (DRAFT default, signed promotion, 409 precondition, APPROVED-only export) | `models.py:15`; `app.py:222, 225-259, 379`; `reports/transformers.py:157`, `markdown.py:82` |

Each invariant in the full document carries its implementation verification, deterministic
mechanics, an adversarial forensic test case, and the auditor's hardening recommendations (e.g. a
session-end re-hash tripwire to close #3's literal gap). **Complete text:
[SECURITY-INVARIANT-AUDIT-2026-06-11.md](docs/02-architecture/SECURITY-INVARIANT-AUDIT-2026-06-11.md).**

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

- **Testing — 4687 collected tests** (`pytest --collect-only -q`) in two tiers. *Fast / always-run*
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
| **Internal** | **Strengths** — *Structural* evidence safety, not a policy promise: agents have **no write tool**; the Thymus policy refuses every write call before the subprocess spawns. Real SANS DFIR tools driven **inside** the agent loop (**16/16 wrappers**, **73 MCP tools**) — rivals explain JSON *after* collection. Deterministic, auditable execution: a fingerprint no-progress detector halts the Trinity Loop with **no LLM in the halt path**, backed by a hash-chained decision ledger. | **Weaknesses** — A **triage engine, not a case-management product**: no HTML report generator, no commercial case-file UX (vs Magnet AXIOM, CADO); output is JSON + the audit ledger. **Read-only consumer**, no host-collection ecosystem (vs Velociraptor's agent fleet) — caps it at post-collection triage. Memory-forensics recall (**108/118**) trails disk (**72/72**) and is the active improvement front. |
| **External** | **Opportunities** — The MCP consumer model means *any* MCP-speaking LLM client becomes a forensic front-end with zero retraining. Default-local, no-API-key posture fits air-gapped / sovereign SOCs. The ATT&CK detector lane is extensible — deferred detectors (W051/W052/W054) are wired and unit-tested, ready to promote into live recall. | **Threats** — Forensic admissibility scrutiny of any AI-assisted pipeline raises the documentation bar (mitigated by the courtroom seal + provenance chain). Upstream SIFT tool drift (binary flags / output format) can silently shift wrapper parsing — covered by host-gated integration tests. Commercial incumbents move fast on AI features. |

Full competitive analysis: [Competitive Positioning](docs/01-overview/competitive-positioning.md).

---

## 🗺️ Project Roadmap

Where the project is and the concrete path to GA — the full document is
**[PROJECT-ROADMAP-2026-06-11.md](docs/02-architecture/PROJECT-ROADMAP-2026-06-11.md)**
(development Gantt, system-lifecycle state machine, milestones, technical specifications, risk register).

[![Development Gantt — release trajectory & critical path](docs/02-architecture/assets/roadmap-gantt.png)](docs/02-architecture/PROJECT-ROADMAP-2026-06-11.md)

| Phase | Status | What it delivered / delivers |
|---|---|---|
| **1 — Foundation** | ✅ Complete | The bio-agentic stack (RalphEngine substrate, StemCell lifecycle, Thymus immune gate, Metabolic Ledger, Oncologist monitor) + the 16 governed MCP forensic wrappers (timeout / memory ceiling / retry / stderr capture each). |
| **2 — Orchestration** | ✅ Complete | The Trinity Loop (Architect → Swarm → Critic → Router), the 7 forensic bio-agents, the quorum Blackboard, the Hippocampus inheritance bridge, and the deterministic Critic halt gate (`score ≥ 0.85` or idempotence). |
| **3 — Scale & GA** | 🔵 Current → Upcoming | GA hardening, not feature invention: land W-082 `raw_stdout_sha256` (tamper-evident raw tool output) and wire `gitleaks` into CI — the **critical path** — mitigate W-071 plaso ordering jitter, finish packaging (`pipx`/wheel, ADR-023/024 polish), then the GA-readiness doc + QA/Security/Product sign-offs → **v0.1.0 GA tag**. Future scale: credential lifecycle + two-person rule, SPIRE cloud identities, multi-tenant alerting, audit-log seal hardening. |

The roadmap also carries the **system-lifecycle state machine** (orchestration, thread taxonomy,
apoptosis — how a run is born, governed, and dies) and a 7-row **risk register** (R1–R7: loop
non-convergence, ATP exhaustion, plaso non-determinism, evidence mutation, secret leakage, context
bleed, doc/code drift — each with its concrete mitigation). Read it alongside the
[SWOT above](#swot--strategic-assessment) and the [Architecture chapter](docs/02-architecture/README.md).

### 🔮 The Future of Agentropix

> *(operator addition, 2026-06-11 — forward-looking, not yet scheduled)*
>
> Beyond the Scale items already on the Gantt, **three directions define the next horizon**:
>
> 1. **🛰️ Threat-intelligence platform integration (CrowdStrike + Wazuh).** Integrate commercial
>    TI platforms such as **CrowdStrike** to gather richer insight about IOCs surfaced by a triage
>    run, and complement that response with the existing open-source **Wazuh** solution —
>    *commercial enrichment and open-source response working the same indicator set*.
> 2. **🧭 Agent scheduler with auditable agent-to-agent messaging.** Optimize the Agentropix
>    engine with an **agent scheduler** that independently manages all agent-to-agent
>    communication and tracks every inter-agent message — *making the swarm's internal traffic
>    itself auditable and troubleshootable*, the same discipline the tool-call trace already
>    applies at the wrapper boundary.
> 3. **🧪 Binary-analysis pipeline with a dedicated sandbox.** Integrate a pipeline that lets
>    Agentropix analyze recovered binaries using open-source solutions and a **dedicated sandbox**
>    for detonation — *testing and analyzing behaviors safely*, then feeding the verdicts back
>    into the case's findings and IOC exports.
>
> Full context: [PROJECT-ROADMAP-2026-06-11.md → The Future of Agentropix](docs/02-architecture/PROJECT-ROADMAP-2026-06-11.md#the-future-of-agentropix-operator-addition-2026-06-11--forward-looking-not-yet-scheduled).

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
| MCP tools | **73** distinct tool functions |
| SIFT forensic wrappers | **16** |
| Tests collected | **4687** |
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
the question it answers. For a file-by-file map of the whole repository — the MCP-server package
internals, every docs section, and the case folders, each with a one-line description — see the
[**Project Structure**](#project-structure) section below. The portal is organized into twelve numbered
sections under `docs/`, plus the `case-activation/` operational annex:

| # | Section | What it contains |
|---|---------|------------------|
| 1 | [Overview](docs/01-overview/what-is-agentropix.md) | What Agentropix-SIFT is and why, the capability matrix, the 3-command Quickstart, the complete operator User Guide, and how it compares to alternatives. |
| 2 | [Architecture](docs/02-architecture/main-architectural-agentropix-design.md) | How the engine is built — **the validated architecture diagram** (pattern + guardrails, HD PDF), system context, internal components, the Trinity Loop, the Swarm + Blackboard, the FastMCP server (and the Thymus boundary), sequence diagrams, the 🗺️ **[Strategic Project Roadmap](docs/02-architecture/PROJECT-ROADMAP-2026-06-11.md)** (Gantt/critical path, lifecycle state machine, GA milestones, risks), the 🔒 **[Security Invariant Audit](docs/02-architecture/SECURITY-INVARIANT-AUDIT-2026-06-11.md)** (6 invariants source-traced), and the 🎛️ **[Tunable Features Catalog](docs/02-architecture/AGENTROPIX-TUNABLE-FEATURES-CATALOG.md)** (252 documented knobs). |
| 3 | [Data](docs/03-data/data-models.md) | The data model — case/finding/report schemas, the data dictionary, the entity-relationship view, and what gets persisted to disk. |
| 4 | [MCP Tools](docs/04-mcp-tools/tool-reference.md) | The 73-tool MCP surface — the full tool reference, the typed Response Envelope, which agent invokes which tool, and the capability map. |
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

## Project Structure

This is the reader-facing **documentation portal** for Agentropix-SIFT, packaged together with the installable **`agentropix_mcp`** MCP-server (the governed read-only DFIR engine) and a set of **sealed DFIR case reports**. The portal docs explain the system across 12 numbered sections; the `agentropix_mcp/` package is the actual shippable code (src layout, console script, wheels on GitHub releases); the case folders hold real, sealed investigations.

**How to read this tree:** top-down by area — root files first, then the MCP-server package (core modules, then each subpackage), then the `docs/` sections, then `case-activation/` runs and the sealed case reports. Each `←` comment says what the file/dir actually does; only key files per area are shown.

```text
agentropix-mcp/
│
│  ── Root files: landing, index, evaluator routing, audits, LLM context ──
├── README.md                     ← Landing page — evaluator letter, 60-sec connect, workflow
├── INDEX.md                      ← Routed master TOC — audience + question-it-answers per page
├── EVALUATION-MAP.md             ← Judge router — 8 submission requirements to evidence
├── CLAUDE.md                     ← Portal working conventions + canonical/accuracy rules
├── DOCUMENTATION-PLAN.md         ← Build plan — oracle source, portal layout, sections
├── AUDIT-COVERAGE.md             ← Per-section index-coverage audit — 0 broken/orphan links
├── ACCURACY_REPORT.md            ← Code/QA accuracy audit — benchmarks, recall, thresholds
├── EVIDENCE_DATASET_DOCS.md      ← Evidence-dataset inventory — provenance, SHA-256, ingestion
├── llms.txt                      ← Curated LLM index — one-paragraph system summary
├── llms-full.txt                 ← Expanded LLM context — inlines 19 core docs
├── LICENSE                       ← MIT License (galvangabriel-web, 2026)
├── .gitignore                    ← Excludes local-only: evaluation*/, video archives, dist
├── .nojekyll                     ← Empty marker — disables Jekyll for GitHub Pages
│
│  ── agentropix_mcp/ : the installable MCP-server PACKAGE (src layout) ──
├── agentropix_mcp/
│   ├── pyproject.toml             ← Package metadata — deps + extras [forensics]/[reports]/[engine], console script
│   ├── README.md                 ← Package README — install, MCP client config, tool surface
│   ├── dist/                      ← Built wheel + sdist (gitignored; attached to GitHub releases)
│   ├── tests/                     ← Package test suite for the MCP server surface
│   └── src/agentropix_mcp/
│       │  ── Core modules ──
│       ├── __init__.py            ← Package init — version 0.3.0, governed-DFIR-MCP summary
│       ├── fastmcp_app.py         ← FastMCP stdio surface — entrypoint main(), thin routes over server.py
│       ├── server.py              ← Inner MCP tool implementations — enforcement boundary (read-only)
│       ├── thymus_policy.py       ← Thymus read-only path policy + JSONL audit ring at MCP boundary
│       ├── courtroom.py           ← Chain-of-custody — image SHA-256 + HMAC-sealed report/audit envelopes
│       ├── config.py              ← Config loader — file/env settings, policy + tool defaults
│       ├── audit_analyzer.py      ← Summarizes Thymus JSONL audit logs for security review
│       ├── secrets.py             ← Telegram-token resolver + logging-safe secret redactor
│       ├── _env.py                ← AGENTROPIX_* env-var helpers — clamped int/float tunables
│       ├── _trace.py              ← Per-tool tracing — contextvar buffer, @traced, args_hash
│       ├── _tool_pins.py          ← Startup SHA-256 pin-check of external forensic binaries
│       ├── _startup_banner.py     ← Logs effective AGENTROPIX_* env config banner at startup
│       │
│       │  ── Subpackages ──
│       ├── agents/                ← 7-agent DFIR SwarmAgent specialists + shared blackboard
│       │   ├── _base.py           ← Base SwarmAgent contract — pure, no LLM coupling
│       │   ├── _blackboard.py     ← Shared blackboard — cross-agent aggregation + quorum
│       │   ├── hunt.py            ← HuntAgent — cross-source correlation specialist
│       │   └── memory.py          ← MemoryAgent — volatile-evidence specialist
│       │                            (also: discovery, mail, timeline, artifact, filesystem)
│       ├── wrappers/              ← Forensic tool wrappers (Volatility/TSK/YARA/Plaso/registry/case)
│       │   ├── volatility.py      ← Volatility3 memory-forensics wrappers (pslist etc.)
│       │   ├── tsk.py             ← Sleuth Kit — filesystem listing via fls
│       │   ├── correlation.py     ← W-150 deterministic cross-artifact correlation
│       │   └── _safe_tool.py      ← Decorator so tool exceptions never escape
│       ├── wazuh/                 ← Wazuh SIEM integration — IOC push, alerts, registrars
│       │   ├── client.py          ← WazuhClient — sole owner of httpx async client
│       │   ├── orchestrator.py    ← push_iocs() orchestrator — IOC-push entry point
│       │   ├── finding_to_alert.py ← Maps Agentropix findings to Wazuh alerts
│       │   ├── evidence_gate.py   ← Mutation-token verification for Wazuh writes
│       │   └── seal.py            ← Courtroom seal for the IOC-push integration
│       ├── evidence_gate/         ← Step-2 mutation-token gate — registry + CLI
│       │   ├── registry.py        ← SQLite-backed token registry
│       │   ├── cli.py             ← CLI for the Step-2 evidence gate
│       │   └── errors.py          ← Exception hierarchy for the gate
│       ├── detectors/             ← ATT&CK technique detectors (4 T-codes) + YARA hunt
│       │   ├── injection_detector.py ← Vol-driven in-memory process-injection detection
│       │   ├── yara_hunt.py       ← YARAHuntAgent — Cobalt Strike stager detection
│       │   ├── t1059_001_iex_loopback_c2.py ← T1059.001 IEX loopback-C2 detector
│       │   └── yara_rules/        ← YARA rule files used by detectors
│       ├── reports/               ← ADR-024 multi-tier report render/export/diagrams
│       │   ├── render.py          ← Render pipeline — Markdown → HTML → PDF (gated)
│       │   ├── export.py          ← Export orchestration for the three tiers
│       │   ├── diagrams.py        ← Mermaid builders — kill-chain, ptree, IOC graph
│       │   └── transformers.py    ← sections dict → three tier view models
│       ├── schema/                ← Typed tool I/O result schemas + JSON schemas
│       │   ├── report.schema.json ← JSON schema for report output structure
│       │   ├── master_iocs.schema.json ← JSON schema for the master-IOC aggregate
│       │   └── extract_archive.py ← W-095 typed result schema for extract_archive
│       ├── security/              ← Shared credential-redaction layer (W-203)
│       │   └── redact.py          ← Walks dict/list tree, redacts credential patterns
│       ├── trinity/               ← Trinity loop — Architect → Swarm → Critic engine
│       │   ├── architect.py       ← Architect — picks swarm slice for next iteration
│       │   └── critic.py          ← Critic — scores pass, decides loop halt
│       └── approval_sidecar/      ← HMAC human-approval sidecar + hash chain (Starlette)
│           ├── app.py             ← Starlette approval-sidecar routes (W-288)
│           ├── auth.py            ← PBKDF2 derivation + HMAC-SHA256 signatures
│           ├── hash_chain.py      ← Hash-chain helpers (tamper-evident approvals)
│           ├── writer.py          ← IndexerClient writer, prev-hash backfill
│           └── nonce.py           ← In-memory TTL nonce store (replay defense)
│
│  ── docs/ : the documentation portal (12 numbered sections + QA logs) ──
├── docs/
│   ├── 01-overview/               ← Start-here: what-is, quickstart, gold-standard user-guide
│   ├── 02-architecture/           ← Engine build outside-in: context → Trinity loop → swarm → MCP
│   ├── 03-data/                   ← Data model: Pydantic fields, schema-ER, persisted artifacts, datasets
│   ├── 04-mcp-tools/              ← The 73-tool MCP surface: capability map, reference, envelope
│   ├── 05-safety-forensics/       ← Safety spine: anti-hallucination, provenance, HMAC seal, approval
│   ├── 06-use-cases/              ← Worked dual-audience scenarios + demo walkthrough + hypotheses
│   ├── 07-sdlc-ops/               ← Build/test/secure/deploy/evaluate/maintain + accuracy supplements
│   ├── 08-reference/              ← CLI, glossary, ADR index, design rationale, canonical-facts authority
│   ├── 09-integrations/           ← Wazuh SOC push + remote tailnet client setup
│   ├── 10-agents/                 ← Runtime swarm vs BMAD personas; Trinity↔Swarm↔MCP model
│   ├── 11-ADR/                    ← 31 Architecture Decision Records (oracle mirror; header = index)
│   ├── 12-CASES-REPORTS/          ← Sealed DFIR case reports — one folder per case, PNG diagrams
│   │   ├── README.md              ← House-style index — one heading + read-order per case
│   │   ├── srl-2015-report/       ← SRL-2015: 4-host enterprise APT, USB-over-Ethernet C2, 17 approved
│   │   ├── srl-2018-report/       ← SRL-2018: network-wide APT / Cobalt Strike-Empire C2, multi-host
│   │   ├── vanko-report/          ← VANKO: insider IP-theft (zebrafish trade secrets), 10 approved
│   │   ├── cfreds-hacking-case-report/ ← CFReDS: Mr. Evil wireless interception, XP disk, 35 approved
│   │   └── srl-2018-artifact-inventory.md ← SRL-2018 inventory (9,578 findings, 29 hosts; oracle mirror)
│   └── issues/                    ← QA logs: diagram/case-guide audits, video-playback troubleshooting
│
│  ── case-activation/ : per-case Activation Guides + executed runs ──
├── case-activation/
│   ├── README.md                  ← Folder intro — 8-step template, dual-audience, approval hard-stop
│   ├── INDEX.md                   ← Master index — disk/memory/mixed tables, recorded-runs
│   ├── cfreds-hacking-case-4dell.md ← Guide: NIST CFReDS Hacking Case (Greg Schardt XP disk)
│   ├── techhive-chad-lt-laptop.md ← Guide: TheTechHive Chad_LT — only Windows-on-ARM disk case
│   ├── jimmy-wilson-study-case.md ← Guide: Jimmy Wilson study-case NTFS E01 disk
│   ├── dfrws-2005-rodeo-usb.md    ← Guide: DFRWS 2005 Rodeo RHINOUSB (raw FAT16 dd)
│   ├── vanko-abducted-zebrafish.md ← Guide: VANKO insider IP-theft, 21-segment EWF disk
│   ├── amf-memory-samples.md      ← Guide: Art-of-Memory-Forensics RAM dumps (Win/Linux/Mac)
│   ├── challenge-notch-it-up.md   ← Guide: Challenge "Notch It Up" raw RAM dump
│   ├── contact-me-memory.md       ← Guide: CTF contact_me raw RAM dump
│   ├── memdump-mem.md             ← Guide: generic 512 MiB raw memory dump
│   ├── memlabs-dumps.md           ← Guide: MemLabs CTF memory dumps (6 labs)
│   ├── win-xp-laptop-2005.md      ← Guide: Windows XP 2005 RAM capture (mislabeled disk)
│   ├── srl-2015-apt-enterprise.md ← Guide: SRL-2015 4-host APT (mixed disk+memory)
│   ├── srl-2018-compromised-enterprise.md ← Guide: SRL-2018 compromised enterprise (7 EWF + 22 memory)
│   ├── rocba-hackathon-2026.md    ← Guide: ROCBA 2026 Win10 insider (1 EWF + raw memory)
│   └── runs/                      ← Executed transcripts — captured MCP/engine runs + rendered MP4s
│       ├── README.md              ← Runs index — per-folder kind/evidence/headline table
│       ├── contact-me-memory/     ← MCP full-loop run+video: contact_me RAM, SIMULATED approval
│       ├── amf-win-sample001/     ← MCP full-loop run+video: AMF Windows sample (300s malfind)
│       ├── memdump-raw-2014/      ← MCP full-loop run+video: 2014 raw RAM, windows_info caveat
│       ├── challenge-notchitup/   ← MCP full-loop run+video: Notch It Up pslist/netscan/malfind
│       ├── srl-2018-compromised-enterprise/ ← MCP activation steps 1-6: SRL-2018 DC disk+memory
│       ├── vanko-abducted-zebrafish/ ← MCP activation steps 1-5: VANKO 21-segment EWF
│       ├── jimmy-wilson-poc/      ← Engine triage PoC+video+raw logs: Jimmy Wilson E01
│       ├── dfrws-rodeo-poc/       ← Engine triage PoC+log: DFRWS Rodeo USB, honest negatives
│       ├── engine-smoke-sample-dd/ ← Engine smoke run: synthetic sample.dd, first sealed record
│       ├── rocba/                 ← Live-MCP triage + req-8 agent-execution log + engine-run
│       │   ├── EXECUTION-LOG.md   ← ROCBA req-8 agent-execution-log doc (findings, honest gotchas)
│       │   └── engine-run/        ← Trinity-engine agent↔blackboard showcase (publishes + plan-shrink)
│       ├── WINXP-LAPTOP-2005/     ← Agent-execution-log run + rendered 3:19 deck video
│       │   └── WINXP-LAPTOP-2005-video/ ← Rendered execution MP4 + watch.html + correlation/storyboard
│       └── _assets/               ← Shared assets for run pages
│
│  ── Media / supporting assets ──
├── assets/                        ← Shared portal images and SVGs
└── Final_Video/                   ← Featured Case Evaluation walkthrough video(s)
```

### Legend / conventions

- **`←` comments** describe what each file/dir actually does; only key files per area are listed (subpackages list their most load-bearing modules, not every file).
- **src layout:** the package is `agentropix_mcp/src/agentropix_mcp/` with a console script `agentropix-mcp` → `fastmcp_app:main`. `fastmcp_app.py` is the thin FastMCP/stdio protocol surface; `server.py` holds the real tool logic and the Thymus read-only enforcement boundary. Underscore-prefixed modules (`_env`, `_trace`, `_tool_pins`, `_startup_banner`) are internal infra.
- **Install extras:** `[forensics]` (Volatility/TSK/YARA/Plaso runtime deps), `[reports]` (MD→HTML→PDF render stack), `[engine]` (the Trinity loop + swarm agents). Built wheels live in the gitignored `dist/` and are attached to GitHub releases.
- **Docs ↔ audience mapping:** `01-overview`/`06-use-cases` are operator/end-user oriented (dual-audience, prompt + CLI); `02-architecture`/`03-data`/`04-mcp-tools`/`10-agents` are reference/architecture; `05-safety-forensics`/`07-sdlc-ops`/`08-reference`/`09-integrations` cover the forensic/safety, SDLC-ops, lookup, and integration layers; `11-ADR` is the decision record, `12-CASES-REPORTS` the sealed investigations.
- **Canonical numbers** (73 MCP tools, 31 ADRs, per-case approval counts) come from `docs/08-reference/canonical-facts.md`; case-report diagrams are committed as **PNG** (not inline Mermaid) for reliable GitHub rendering, and recovered malware is withheld-by-reference (SHA-256 only).

---


## Acknowledgments

Built on the shoulders of the open-source DFIR ecosystem: the **SANS SIFT Workstation** and the forensic
tools it bundles — **Volatility3**, **Plaso/log2timeline**, **The Sleuth Kit**, **python-evtx**,
**YARA**, **bulk_extractor**, **RegRipper**, the **EZ-Tools** family, and the mail-parsing libraries
(`libpff`, `extract-msg`). The MCP surface is served by [**FastMCP**](https://github.com/jlowin/fastmcp).

## License

Released under the **MIT License**.
