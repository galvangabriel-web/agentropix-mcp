# 02 · Architecture

How the engine is built — from the outside-in (context → components) down to the Trinity Loop, the Swarm, the MCP server, and the tool-integration substrate.

## Read in this order

1. [architecture-diagram.md](architecture-diagram.md) — **the one-page validated architecture diagram** (PNG/PDF deliverable): agent layer → MCP server → SIFT tools → data sources → output pipeline, the architectural-pattern verdict (Custom MCP Server), and the prompt-based vs architectural guardrail split — every box source-cited.
2. [system-context-c4.md](system-context-c4.md) — how the engine sits on the SIFT host: containers and boundaries (outside-in).
3. [component-architecture.md](component-architecture.md) — the internal components and how the code layers are organized.
4. [trinity-loop.md](trinity-loop.md) — how Architect, Swarm, and Critic interact and how the deterministic halt works (the core control loop).
5. [swarm-agents.md](swarm-agents.md) — the 7 core specialists (+ ATT&CK detectors), the quorum Blackboard, and cross-run self-correction.
6. [mcp-server.md](mcp-server.md) — how the single FastMCP server is built, its transports, and where the Thymus boundary sits.
7. [sequence-diagrams.md](sequence-diagrams.md) — each key operation step by step (full run, single tool call, seal, halt, approval, Wazuh).
8. [ez-tools-integration.md](ez-tools-integration.md) — how Eric Zimmerman's EZ Tools are wrapped as governed MCP tools (genuine `.NET` binaries vs the three Linux substitutes).
9. [module-map.md](module-map.md) — *(shared reference)* where each package and component lives in `src/` (machine-extracted).

> For "how does an agent actually call a tool, station by station," continue to [docs/10-agents/fastmcp-execution.md](../10-agents/fastmcp-execution.md).
