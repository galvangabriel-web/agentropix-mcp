# 02 · Architecture

How the engine is built — from the outside-in (context → components) down to the Trinity Loop, the Swarm, the MCP server, and the tool-integration substrate.

> 🗺️ **[PROJECT-ROADMAP-2026-06-11.md](PROJECT-ROADMAP-2026-06-11.md)** — the **Strategic Project
> Roadmap**: development Gantt with the critical path to GA, the system-lifecycle state machine
> (orchestration, thread taxonomy, apoptosis), phase milestones (Foundation → Orchestration →
> Scale & GA), technical specifications & refactoring plan, and risk mitigation. Read it for
> *where the architecture below is headed*; the numbered list is *how it's built today*.

## Read in this order

1. [main-architectural-agentropix-design.md](main-architectural-agentropix-design.md) — **the one-page validated architecture diagram** (PNG/PDF deliverable): agent layer → MCP server → SIFT tools → data sources → output pipeline, the architectural-pattern verdict (Custom MCP Server), and the prompt-based vs architectural guardrail split — every box source-cited.
2. [system-context-c4.md](system-context-c4.md) — how the engine sits on the SIFT host: containers and boundaries (outside-in).
3. [component-architecture.md](component-architecture.md) — the internal components and how the code layers are organized.
4. [trinity-loop.md](trinity-loop.md) — how Architect, Swarm, and Critic interact and how the deterministic halt works (the core control loop).
5. [swarm-agents.md](swarm-agents.md) — the 7 core specialists (+ ATT&CK detectors), the quorum Blackboard, and cross-run self-correction.
6. [mcp-server.md](mcp-server.md) — how the single FastMCP server is built, its transports, and where the Thymus boundary sits.
7. [sequence-diagrams.md](sequence-diagrams.md) — each key operation step by step (full run, single tool call, seal, halt, approval, Wazuh).
8. [ez-tools-integration.md](ez-tools-integration.md) — how Eric Zimmerman's EZ Tools are wrapped as governed MCP tools (genuine `.NET` binaries vs the three Linux substitutes).
9. [module-map.md](module-map.md) — *(shared reference)* where each package and component lives in `src/` (machine-extracted).
10. [PROJECT-ROADMAP-2026-06-11.md](PROJECT-ROADMAP-2026-06-11.md) — 🗺️ *(strategic)* where it's all going: Gantt/critical path, lifecycle state machine, GA milestones, risks.

> For "how does an agent actually call a tool, station by station," continue to [docs/10-agents/fastmcp-execution.md](../10-agents/fastmcp-execution.md).
