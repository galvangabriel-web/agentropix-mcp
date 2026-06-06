# Agentropix-SIFT

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#license)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![MCP tools: 71](https://img.shields.io/badge/MCP%20tools-71-green.svg)](docs/04-mcp-tools/tool-reference.md)
[![Tests: 4464](https://img.shields.io/badge/tests-4464-brightgreen.svg)](docs/07-sdlc-ops/testing.md)

**A local, CLI-driven, bio-agentic DFIR triage engine for the SANS SIFT Workstation.**

Agentropix-SIFT turns a SIFT Workstation into an autonomous-but-accountable triage
operator. A **Trinity Loop** — an Architect that proposes which agents to run, a
**7-agent Swarm** that drives deterministic forensic tools, and a **Critic** that scores
findings and halts on a *deterministic* convergence fingerprint (with **no LLM
self-rating**) — orchestrates **71 MCP tools** over a single
[FastMCP](docs/02-architecture/mcp-server.md) server. The result is a fast first pass over
disk images, memory dumps, and Windows artifacts that produces an evidence-grounded,
cryptographically sealed triage report a human examiner can trust and defend.

> **Important — this is a triage accelerator, not an oracle.**
> Agentropix-SIFT is built to be *checked*, not *believed*. Every finding it records is
> produced by a deterministic forensic binary, fingerprinted with SHA-256, and tagged with
> a provenance tier — precisely so a human can verify it. The LLM proposes and narrates;
> it never rates its own work and never becomes the source of a finding. **You remain the
> examiner of record.** Review the findings, confirm the underlying artifacts, and use the
> optional [human-in-the-loop approval gate](docs/05-safety-forensics/human-in-the-loop.md)
> before anything is sealed or escalated. Do not blindly trust AI output — verify against
> the evidence. See [Anti-Hallucination](docs/05-safety-forensics/anti-hallucination.md).

---

## What You Get

- **Trinity Loop orchestration** — Architect → Swarm → Critic, with a deterministic halt
  condition (a stable *convergence fingerprint*, not an LLM confidence score). See
  [The Trinity Loop](docs/02-architecture/trinity-loop.md).
- **7-agent forensic Swarm** — Memory, Timeline, Filesystem, Artifact, Discovery, Mail, and
  Hunt specialists, plus deterministic ATT&CK detector agents, coordinating over a quorum
  **Blackboard**. See [The Swarm Agents & Blackboard](docs/02-architecture/swarm-agents.md).
- **71 MCP tools over one FastMCP server** — including **16 SIFT forensic tools** wrapped as
  deterministic, fingerprinted callables (Volatility3, Plaso, The Sleuth Kit, EVTX, YARA,
  bulk_extractor, RegRipper, EZ-Tools, and more). See the
  [MCP Tool Reference](docs/04-mcp-tools/tool-reference.md).
- **Evidence sovereignty** — a pre/post **SHA-256 evidence invariant** guarantees the engine
  never mutates the artifacts it reads; only *deterministic* tools may produce findings. See
  [Anti-Hallucination](docs/05-safety-forensics/anti-hallucination.md).
- **Thymus read-only policy** — a deny-by-default safety boundary
  (`mcp_server/thymus_policy.py`) that blocks any write/exec path before a tool runs. See the
  [Security Model](docs/07-sdlc-ops/security-model.md).
- **Courtroom audit seal** — an **HMAC-SHA256** seal over a JSONL chain-of-custody audit log
  (`courtroom.py`) plus [provenance-chain validation](docs/05-safety-forensics/provenance-grounding.md).
- **Optional approval sidecar** — a human gate that holds findings in DRAFT until an examiner
  APPROVES them in a browser **Approval Portal** (tailnet-only, at
  `https://siftworkstation.taile7c9ca.ts.net:8443/`), before any report is sealed. See the
  [Approval Portal walkthrough](docs/05-safety-forensics/approval-portal.md).
- **Typed, provenance-tagged responses** — every tool returns a Pydantic model carrying a
  `raw_stdout_sha256` provenance fingerprint, not a free-form dict. See the
  [Response Envelope](docs/04-mcp-tools/response-envelope.md).
- **Ground-truth recall you can audit** — **72/72 (100%)** disk recall (regression) and
  **108/118 (91.5%)** combined memory recall, with **4464** tests. See
  [Testing](docs/07-sdlc-ops/testing.md) (numbers per
  [Canonical Facts](.crew/facts.md)).

Full capability matrix: [What You Get](docs/01-overview/what-you-get.md).

---

## Recommended Investigation Workflow

```text
1. doctor      Pre-flight the SIFT toolchain on PATH.
               $ uv run agentropix-sift doctor

2. run         Trinity Loop triages the image end-to-end.
               $ uv run agentropix-sift run /cases/INC-0605/disk.E01 -o report.json
               → Architect proposes agents → Swarm runs deterministic tools
               → Critic scores findings → halt on convergence fingerprint.

3. review      A human examiner reads the findings and verifies them
               against the underlying artifacts (raw_stdout_sha256, paths).

4. approve     (optional) Promote reviewed findings DRAFT → APPROVED
               through the approval sidecar before anything is sealed.

5. seal        Courtroom emits the HMAC-SHA256 audit seal + provenance chain.

6. escalate    (optional) Push APPROVED findings to Wazuh as alerts.
```

Each step is documented as a worked use case:
[Disk triage](docs/06-use-cases/uc-disk-triage.md) ·
[Memory triage](docs/06-use-cases/uc-memory-triage.md) ·
[Approval gate](docs/06-use-cases/uc-approval-gate.md) ·
[Wazuh push](docs/06-use-cases/uc-wazuh-push.md).

---

## Architecture

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

A DFIR examiner drives Agentropix-SIFT from the CLI on a local SIFT host. The engine never
reaches outside that host except for the *optional* Wazuh push of already-APPROVED findings.
Internally, the **Architect** proposes which agents to spawn, the **Swarm** invokes the 16
wrapped SIFT forensic tools through the FastMCP server's 71-tool surface, and the **Critic**
scores the accumulated findings — halting deterministically when the findings stop changing
(a convergence fingerprint), never on an LLM's self-assessed confidence. The **Thymus**
read-only policy and the **pre/post SHA-256 evidence invariant** sit between every tool and
the evidence store, guaranteeing the artifacts are read but never altered. Finally the
**Courtroom** seals the audit log with HMAC-SHA256 and validates the provenance chain.

For the full picture: [System Context & Containers](docs/02-architecture/system-context-c4.md) ·
[Component Architecture & Layer Map](docs/02-architecture/component-architecture.md) ·
[Sequence Diagrams](docs/02-architecture/sequence-diagrams.md).

---

## Deployment & Requirements

| Requirement | Detail |
|-------------|--------|
| **Python** | **3.12+** (`pyproject.toml`: `requires-python = ">=3.12"`). Stock SIFT ships 3.10 — provide 3.12 via `uv`, `pyenv`, or the `deadsnakes` PPA. |
| **Host** | A SANS SIFT Workstation (or Ubuntu host with the GIFT PPA toolchain). Runs **fully local** — no API keys, no cloud dependency for the forensic path. |
| **Toolchain on `PATH`** | The 16 SIFT forensic binaries: Volatility3, `log2timeline`, Sleuth Kit (`fls`/`icat`/`mmls`), `ewf-tools`, YARA, `bulk_extractor`, RegRipper, EVTX, EZ-Tools, mail parsers. Agentropix-SIFT *drives* these — it does not ship them. |
| **Degradation** | Missing tools degrade gracefully (the agent is skipped, not the run) — but recall drops, so run `doctor` first. |

See [Deployment](docs/07-sdlc-ops/deployment.md) for SIFT install, tailnet exposure, and the
runbook index, and [Recovery & Resilience](docs/07-sdlc-ops/recovery-resilience.md) for the
failure-mode catalogue.

---

## Installation / Quickstart

```bash
uv sync                                                        # 1. install the orchestration layer
uv run agentropix-sift doctor                                 # 2. pre-flight the toolchain
uv run agentropix-sift run samples/sample.dd -o report.json   # 3. first triage
```

The package installs two console scripts — `agentropix-sift` (the triage CLI) and
`agentropix-sift-mcp` (the MCP server). The full step-by-step, including `pip` install and
example `doctor` output, is in the [Quickstart](docs/01-overview/quickstart.md). Every CLI
command and flag is enumerated in the [CLI Reference](docs/08-reference/cli-reference.md).

---

## MCP Tools

Agentropix-SIFT exposes **71 distinct MCP tools** over a single FastMCP server (verified live
via `tools/list` and `health.tool_count`; see [Canonical Facts](.crew/facts.md)). Of these,
**16 are SIFT forensic tools** — deterministic binaries wrapped under
`mcp_server/wrappers/` so each call captures the binary's raw stdout and fingerprints it with
SHA-256. The remainder cover case lifecycle, finding records, reporting, provenance,
approval, executable-artifact registry, and Wazuh integration.

| Family | Examples | Reference |
|--------|----------|-----------|
| Forensic wrappers (16 SIFT tools) | `get_pslist`, `fls`, `get_evtx`, `yara_scan`, `get_partitions`, `get_evt` | [Tool Reference](docs/04-mcp-tools/tool-reference.md) |
| Case & finding lifecycle | `record_finding`, `delete_finding`, `case_status`, `generate_report` | [Tool Reference](docs/04-mcp-tools/tool-reference.md) |
| Provenance & approval | `retract_approval`, provenance/IOC promotion (`promote_iocs`) | [Provenance](docs/05-safety-forensics/provenance-grounding.md) |
| Executable-artifact registry | `build_executable_registry`, `promote_executable_registry`, `exec_registry_get`, `exec_registry_search` | [Tool Reference](docs/04-mcp-tools/tool-reference.md) |
| Wazuh integration | `wazuh_hunt_ioc` (+ wrappers) | [Wazuh push](docs/06-use-cases/uc-wazuh-push.md) · [Operator's guide](docs/09-integrations/wazuh-portal.md) |

See the full enumeration in the [MCP Tool Reference](docs/04-mcp-tools/tool-reference.md), which
agent invokes which tool in [Tools by Agent](docs/04-mcp-tools/tool-by-agent.md), and the typed
return shape in the [Response Envelope](docs/04-mcp-tools/response-envelope.md).

### Response envelope (example)

Every tool returns a typed Pydantic model serialized with `model_dump()` — never a free-form
dict. A successful `get_pslist` against a memory image:

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

The load-bearing field is **`raw_stdout_sha256`** — the SHA-256 of the binary's raw stdout
bytes, the provenance fingerprint that ties the finding back to the exact tool output. Soft
failures return the same model with `tool_available: false` and a `skipped_reason`; handled
errors return a structured `ToolError`. Full field tables:
[Response Envelope](docs/04-mcp-tools/response-envelope.md).

---

## Security & Anti-Hallucination

Agentropix-SIFT is engineered so that the LLM **cannot** become the source of a forensic
claim:

- **Deterministic-tools-only findings** — a finding may only be recorded from the output of a
  deterministic forensic binary; the LLM narrates and proposes but never authors evidence.
- **No LLM self-rating** — the Critic halts on a deterministic *convergence fingerprint*
  (default threshold 0.85, `trinity/critic.py`), not on a model's self-assessed confidence.
- **Pre/post SHA-256 evidence invariant** — evidence is hashed before and after every run;
  any mutation aborts the run. The engine reads but never alters the image.
- **Thymus read-only policy** — deny-by-default boundary (`mcp_server/thymus_policy.py`)
  blocking write/exec paths before a tool executes.
- **Courtroom HMAC-SHA256 seal** — the audit log (JSONL) is sealed and the provenance chain
  validated (`courtroom.py`, `provenance/`), giving a tamper-evident chain of custody.
- **Human-in-the-loop** — the optional approval sidecar (`approval_sidecar/`) holds findings
  in DRAFT until an examiner APPROVES them.

Deep dives: [Anti-Hallucination](docs/05-safety-forensics/anti-hallucination.md) ·
[Provenance & Grounding](docs/05-safety-forensics/provenance-grounding.md) ·
[Audit & Courtroom Seal](docs/05-safety-forensics/audit-courtroom.md) ·
[Security Model](docs/07-sdlc-ops/security-model.md).

---

## Configuration

Behavior is tuned through the `AGENTROPIX_*` environment surface — Critic halt threshold,
Blackboard quorum, status taxonomy, tool-path overrides, and more — with safe defaults so the
engine runs out of the box. See [Configuration](docs/07-sdlc-ops/configuration.md) for the
full env-var table.

---

## Documentation

Start at the routed [master table of contents](INDEX.md), which maps every chapter to its
audience (operator / examiner / developer / auditor) and the question it answers. Highlights:

- **New here?** [What is Agentropix-SIFT?](docs/01-overview/what-is-agentropix.md) →
  [Quickstart](docs/01-overview/quickstart.md)
- **How it works:** [Architecture](docs/02-architecture/system-context-c4.md) ·
  [Data Models](docs/03-data/data-models.md)
- **Operate it:** [Use Cases](docs/06-use-cases/uc-disk-triage.md) ·
  [CLI Reference](docs/08-reference/cli-reference.md)
- **Trust it:** [Safety & Forensics](docs/05-safety-forensics/anti-hallucination.md)
- **Extend it:** [Implementation](docs/07-sdlc-ops/implementation.md) ·
  [ADR Index](docs/08-reference/adr-index.md) · [Glossary](docs/08-reference/glossary.md)

---

## Acknowledgments

Built on the shoulders of the open-source DFIR ecosystem: the **SANS SIFT Workstation** and
the forensic tools it bundles — **Volatility3**, **Plaso/log2timeline**, **The Sleuth Kit**,
**python-evtx**, **YARA**, **bulk_extractor**, **RegRipper**, the **EZ-Tools** family, and the
mail-parsing libraries (`libpff`, `extract-msg`). The MCP surface is served by
[**FastMCP**](https://github.com/jlowin/fastmcp). The structural model for this documentation
portal follows the Valhuntir / SIFT-MCP README.

## License

Released under the **MIT License**.
