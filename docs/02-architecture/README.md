# 02 · Architecture

How the engine is built — from the outside-in (context → components) down to the Trinity Loop, the Swarm, the MCP server, and the tool-integration substrate.

> 🗺️ **[PROJECT-ROADMAP-2026-06-11.md](PROJECT-ROADMAP-2026-06-11.md)** — the **Strategic Project
> Roadmap**: development Gantt with the critical path to GA, the system-lifecycle state machine
> (orchestration, thread taxonomy, apoptosis), phase milestones (Foundation → Orchestration →
> Scale & GA), technical specifications & refactoring plan, and risk mitigation. Read it for
> *where the architecture below is headed*; the numbered list is *how it's built today*.

## Read in this order

1. [main-architectural-agentropix-design.md](main-architectural-agentropix-design.md) — **the one-page validated architecture diagram** (PNG/PDF deliverable): agent layer → MCP server → SIFT tools → data sources → output pipeline, the architectural-pattern verdict (Custom MCP Server), and the prompt-based vs architectural guardrail split — every box source-cited.
2. [system-diagram.md](system-diagram.md) — the system-diagram index: where every rendered diagram lives, prose verification that the five rubric elements (agents · SIFT tools · MCP server · evidence · output pipeline) are all covered, and the trust boundary (transport/auth + Thymus) called out explicitly.
3. [system-context-c4.md](system-context-c4.md) — how the engine sits on the SIFT host: containers and boundaries (outside-in).
4. [architecture-layers.md](architecture-layers.md) — the four-layer determinism map: where stochasticity lives (Layer 1 only), where determinism is enforced (Layers 2–4), the L1↔L3 trust-boundary contract, and where each tracked weakness sits.
5. [component-architecture.md](component-architecture.md) — the internal components and how the code layers are organized.
6. [trinity-loop.md](trinity-loop.md) — how Architect, Swarm, and Critic interact and how the deterministic halt works (the core control loop).
7. [swarm-agents.md](swarm-agents.md) — the 7 core specialists (+ ATT&CK detectors), the quorum Blackboard, and cross-run self-correction.
8. [mcp-server.md](mcp-server.md) — how the single FastMCP server is built, its transports, and where the Thymus boundary sits.
9. [sequence-diagrams.md](sequence-diagrams.md) — each key operation step by step (full run, single tool call, seal, halt, approval, Wazuh).
10. [ez-tools-integration.md](ez-tools-integration.md) — how Eric Zimmerman's EZ Tools are wrapped as governed MCP tools (genuine `.NET` binaries vs the three Linux substitutes).
11. [module-map.md](module-map.md) — *(shared reference)* where each package and component lives in `src/` (machine-extracted).
12. [PROJECT-ROADMAP-2026-06-11.md](PROJECT-ROADMAP-2026-06-11.md) — 🗺️ *(strategic)* where it's all going: Gantt/critical path, lifecycle state machine, GA milestones, risks.
13. [SECURITY-INVARIANT-AUDIT-2026-06-11.md](SECURITY-INVARIANT-AUDIT-2026-06-11.md) — 🔒 *(audit)* the six safety/anti-hallucination invariants traced to source file:line — 5 Enforced, #3 Partially (structural, not literal) — with adversarial test cases and hardening recommendations.
14. [AGENTROPIX-TUNABLE-FEATURES-CATALOG.md](AGENTROPIX-TUNABLE-FEATURES-CATALOG.md) — 🎛️ *(reference)* the explanatory catalog of all 252 tunables: 16 feature toggles, 125 performance/scaling knobs, 18 detection thresholds, 17 security/egress gates, 54 tool paths/data sets, and the rest.

> For "how does an agent actually call a tool, station by station," continue to [docs/10-agents/fastmcp-execution.md](../10-agents/fastmcp-execution.md).
