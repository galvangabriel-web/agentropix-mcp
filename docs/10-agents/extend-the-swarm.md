# Extend the Swarm — add your own agent, detector, or tool

**Audience:** practitioners who want to *build on* Agentropix-SIFT — not just deploy it. This page is
the "add your own" recipe the architecture pages describe but don't walk through. Everything below is
grounded in the **shipped source** under [`agentropix_mcp/`](../../agentropix_mcp/) (install the engine
extra: `pip install ./agentropix_mcp[engine]`), so a contribution returns straight to the toolset.

> **See also** (the *what/why*, this page is the *how*): [swarm-agents](../02-architecture/swarm-agents.md)
> (the SwarmAgent contract + blackboard quorum), [mcp-server](../02-architecture/mcp-server.md)
> (tool registration + the live-count check), [agentic-architecture](agentic-architecture.md),
> [delegation-model](delegation-model.md), [fastmcp-execution](fastmcp-execution.md), and the
> per-module [agents-list](agents-list.md). The current surface is **73 MCP tools · 16 SIFT wrappers ·
> 4,687 tests · Python 3.12+** ([canonical-facts](../08-reference/canonical-facts.md)).

The golden rule holds for every extension: **the LLM never authors a fact.** Your agent/detector/wrapper
is deterministic code that reads bytes off evidence and returns a `Finding`; the model only orchestrates.

---

## A. Add a new SwarmAgent (or ATT&CK detector)

A detector *is* a `SwarmAgent` — the only difference is convention (one ATT&CK technique per file under
`detectors/`). Both subclass the same base.

**1. Subclass `SwarmAgent`** (`agentropix_mcp/src/agentropix_mcp/agents/_base.py:95`). Set a class-level
`name`, then implement the one abstract method, `investigate`:

```python
# agentropix_mcp/src/agentropix_mcp/detectors/t1518_security_software_discovery.py
from pathlib import Path
from agentropix_mcp.agents._base import Finding, SwarmAgent

class SecuritySoftwareDiscoveryDetector(SwarmAgent):
    name = "t1518_security_software_discovery"
    completion_promise = None  # optional: a token the Critic can require (see _base.py)

    async def investigate(self, image: Path) -> list[Finding]:
        # Drive a DETERMINISTIC wrapper/tool — never reason a fact into existence.
        # Return zero or more Finding(...). MUST be idempotent (S-08:
        # same image + same blackboard state -> identical findings).
        findings: list[Finding] = []
        # ...call a wrapper, parse its output, append Finding(...)...
        return findings
```

A `Finding` (`_base.py:40`, a Pydantic model) needs at least `_source`, `confidence` (0.0–1.0),
`description`, and — for a detector — `mitre_attack`:

```python
Finding(_source="get_pslist", confidence=0.85,
        description="…what was observed and where…", mitre_attack="T1518")
```

You do **not** call `run()` or publish yourself — the base `run()` (`_base.py:130`) wraps `investigate()`:
it applies the per-agent finding cap (`AGENTROPIX_AGENT_FINDING_CAP`, default 500), stamps
`finding.agent = self.name`, and publishes each finding to the **Blackboard** so the quorum/correlation
logic and the deterministic Critic see it. Emit `confidence=0.0` on skip/error/empty paths — a finding
on a clean image with `confidence > 0.0` will (correctly) trip the false-positive gate.

**2. Register it in the ordered run** — add the class to the `SWARM` tuple
(`agentropix_mcp/src/agentropix_mcp/agents/__init__.py:45`) and its `__all__`. **Order matters:**
`HuntAgent` **must stay last** (it consumes the findings everyone else publishes), so insert detectors
*between* the specialist agents and `HuntAgent`:

```python
SWARM: tuple[type[SwarmAgent], ...] = (
    MemoryAgent, TimelineAgent, FilesystemAgent, ArtifactAgent, DiscoveryAgent,
    NullSessionBaselineAgent, MailAgent,
    YARAHuntAgent, InjectionDetector, AccessibilityIfeoHijackDetector,
    IexLoopbackC2Detector, T1071SvchostOutboundHttpDetector,
    SecuritySoftwareDiscoveryDetector,   # <-- new detector, BEFORE HuntAgent
    HuntAgent,                            # <-- always last
)
```

Follow the shape of an existing detector for tunables and docstring discipline —
[`detectors/t1071_001_svchost_outbound_http.py`](../../agentropix_mcp/src/agentropix_mcp/detectors/t1071_001_svchost_outbound_http.py)
is a good template (env-var tunables, allowlist caveats, one technique per file).

---

## B. Add a new tool wrapper (grows the MCP surface 73 → 74)

A tool is a deterministic wrapper exposed to both the swarm and any MCP client through the same
`@app.tool()` function — *one* surface, two consumers.

**1. Write the wrapper** under `agentropix_mcp/src/agentropix_mcp/wrappers/` following an existing module
(e.g. `wrappers/volatility.py`): an `async` function that runs the binary via
`asyncio.create_subprocess_exec` with an **argv list — never a shell** (see
[`wrappers/_subprocess.py`](../../agentropix_mcp/src/agentropix_mcp/wrappers/)), and returns a typed
result carrying `raw_stdout_sha256` so every parsed value is anchored to the tool's raw bytes.

**2. Register it** with a thin `@app.tool()` caller in
[`agentropix_mcp/src/agentropix_mcp/fastmcp_app.py`](../../agentropix_mcp/src/agentropix_mcp/fastmcp_app.py).
The decorated function name **becomes the MCP tool name** — it must pass the Thymus read-only path policy
before any I/O, and (if it touches evidence) never expose a write. Adding one `@app.tool()` takes the
live count from **73 to 74**; keep the registration arithmetic and the `health()` live-count check in
sync ([mcp-server §registration](../02-architecture/mcp-server.md)).

**3. Document it** — add the new tool to [`tool-list.md`](../04-mcp-tools/tool-list.md) and
[`tool-reference.md`](../04-mcp-tools/tool-reference.md), and bump the count in
[`canonical-facts.md`](../08-reference/canonical-facts.md) (the canonical-facts CI drift gate fails the
build if the docs and the live `tools/list` disagree). If it's a `run_volatility` plugin, remember the
two accepted forms — a short alias (`pslist`) **or** a full canonical id (`windows.cmdline.CmdLine`);
the bare middle form (`windows.cmdline`) is rejected.

---

## C. The test (this is the contract, not an afterthought)

Every agent/detector ships with a unit test that proves the `investigate()` contract on a fixture, and
every wrapper proves its parse against captured tool output. The test pattern is **construct → invoke →
assert**:

```python
import pytest
from pathlib import Path
from agentropix_mcp.agents._base import Blackboard

@pytest.mark.asyncio
async def test_security_software_discovery_detector():
    bb = Blackboard()
    agent = SecuritySoftwareDiscoveryDetector(bb)
    findings = await agent.investigate(Path("tests/fixtures/<your-image-or-mock>"))
    assert all(0.0 <= f.confidence <= 1.0 for f in findings)
    assert all(f.mitre_attack == "T1518" for f in findings)   # detector tags its technique
    # idempotence (S-08): same inputs -> identical findings
    assert findings == await agent.investigate(Path("tests/fixtures/<your-image-or-mock>"))
```

Run the suite with `uv run pytest -q` (or scope it: `uv run pytest tests/ -k security_software -q`).
Two invariants your test must defend: **(1) idempotence** — same image + same blackboard → identical
findings (S-08); **(2) honest negatives** — on a clean fixture the detector returns `confidence=0.0`
(or no findings), so it never scores a confident hallucination.

---

## Where it plugs into the loop

Your new agent runs inside the deterministic **Trinity Loop**: the Architect schedules the `SWARM`
tuple, your `investigate()` publishes `Finding`s to the Blackboard, an observation becomes a
`Correlation` only when a quorum of agents corroborate the same token, and the **Critic halts on a
deterministic fingerprint** — never on a model's say-so. Nothing about extending the swarm relaxes that
boundary: you are adding another deterministic producer of provable facts.

**Then:** open a PR with the new module + its test + the doc/count updates. Because the package ships the
engine (`agents/`, `detectors/`, `wrappers/`, `trinity/`), a reviewer can `pip install ./agentropix_mcp[engine]`,
run your test, and see your finding flow through the loop — deployable *and* extensible, from this repo.
