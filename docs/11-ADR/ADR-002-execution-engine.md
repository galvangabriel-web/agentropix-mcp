> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-002: Execution Engine (Ralph Orchestrator)

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Implemented |
| **Date** | 2026-01-02 |
| **Accepted** | 2026-01-11 |
| **Implemented** | 2026-01-14 |
| **Decision Makers** | Architecture Team |
| **Bio-Agentic Component** | Core Execution Loop, Telomere Budget |
| **Priority** | P0 (Critical) |

## Context

Agentropix requires an execution engine that implements the continuous agent loop pattern - iterating until task completion while managing resources, state, and safety constraints. This is the "angular stone" of the entire system.

### Problem Statement

We need an execution engine that:
1. Runs agents iteratively until task completion
2. Manages iteration limits (Telomere Budget)
3. Tracks costs and resources (ATP Economy)
4. Persists state across iterations (LineageManager)
5. Enforces safety limits (The Oncologist)
6. Supports multiple LLM providers

### Constraints

- Must support iteration-based execution (not just single-shot)
- Must have completion detection ("done" signal)
- Must enforce budget limits (iterations, tokens, cost)
- Must persist state for recovery
- Must be extensible for new LLM providers

### Assumptions

- Iterative execution is the correct pattern for complex agent tasks
- Most tasks complete within 50-100 iterations
- State persistence is critical for long-running tasks
- Cost tracking is essential for production viability

## Decision Drivers

1. **Proven pattern** - Validated execution loop with 920+ tests
2. **Bio-agentic alignment** - Natural mapping to Agentropix components
3. **Multi-provider support** - Adapters for Claude, Gemini, local models
4. **Production ready** - Safety guards, cost tracking, checkpointing
5. **Extensibility** - Clean adapter pattern for new integrations

## Considered Options

### Option 1: Ralph Orchestrator (Adopt)

**Description:** Adopt the Ralph Orchestrator (1.6MB, 920+ tests) as the execution engine, adapting its patterns to Agentropix's bio-agentic model.

**Pros:**
- Battle-tested with 920+ unit tests
- Clean iteration loop with completion detection
- Built-in safety guards (SafetyGuard class)
- Cost tracking (CostTracker class)
- Context management (ContextManager class)
- Multi-provider adapters (Claude, Gemini, QChat, ACP)
- Checkpoint/resume capability

**Cons:**
- Large codebase (1.6MB) to understand and maintain
- Some patterns may not directly align with Agentropix
- Dual maintenance if upstream Ralph evolves

### Option 2: LangGraph Execution

**Description:** Use LangGraph's built-in execution model with state graphs.

**Pros:**
- Native LangChain integration
- Built-in persistence (checkpointing)
- Human-in-the-loop support
- Graph-based workflow definition

**Cons:**
- Graph-based model less intuitive for iteration loops
- Less direct mapping to bio-agentic components
- Vendor lock-in to LangChain ecosystem
- No explicit Telomere Budget pattern

### Option 3: Custom Execution Engine

**Description:** Build a custom execution engine from scratch.

**Pros:**
- Perfect alignment with Agentropix requirements
- No external dependencies
- Full control over implementation

**Cons:**
- Significant development time (3-6 months)
- Need to solve already-solved problems
- Testing burden (need 500+ tests for reliability)
- Risk of missing edge cases

### Option 4: CrewAI Process

**Description:** Use CrewAI's sequential/hierarchical process model.

**Pros:**
- Simple mental model
- Built-in agent collaboration

**Cons:**
- Limited iteration control
- No explicit budget management
- Less flexible than Ralph's model
- Not designed for long-running tasks

## Decision

We will **extract Ralph Orchestrator's components** ("Organ Harvesting") rather than wrapping the full orchestrator, because:

1. **Proven reliability**: 928+ tests demonstrate production-quality code for SafetyGuard, CostTracker, ContextManager
2. **Graph execution required**: Trinity Loop requires LangGraph's parallel branching, which Ralph's linear while-loop cannot provide
3. **Time savings**: Inherit tested component logic without reimplementing
4. **Feature completeness**: Safety, cost tracking, context optimization all included

### Integration Strategy: Component Extraction (Not Wrapping)

| Approach | Decision | Rationale |
|----------|----------|-----------|
| Wrap RalphOrchestrator | ❌ **Rejected** | Linear execution cannot support Trinity Loop parallelism |
| Extract Components | ✅ **Adopted** | Use proven classes inside LangGraph StateGraph |

### Ralph ↔ Agentropix Component Mapping

| Ralph Feature | Agentropix Component | Implementation |
|---------------|---------------------|----------------|
| `max_iterations` | Telomere Budget | Hard limit on agent lifespan |
| `checkpoint_interval` | LineageManager | State persistence to git/files |
| `SafetyGuard` | The Oncologist | Runaway detection, resource limits |
| `CostTracker` | ATP Economy | Token/cost budget enforcement |
| `ContextManager` | Agentic Chromosome | Context window optimization |
| `completion_promise` | The Gauntlet | Task completion detection |
| `adapters/` | Multi-Model Support | Provider abstraction |

### Implementation Approach

```python
# Agentropix wrapper around Ralph core
from ralph_orchestrator import Orchestrator, SafetyGuard, CostTracker

class AgentropixExecutor:
    """Bio-agentic execution engine powered by Ralph."""

    def __init__(self, config: ExecutorConfig):
        # Telomere Budget
        self.max_iterations = config.telomere_budget

        # ATP Economy
        self.cost_tracker = CostTracker(
            max_tokens=config.atp_budget.tokens,
            max_cost_usd=config.atp_budget.cost
        )

        # The Oncologist
        self.oncologist = SafetyGuard(
            max_iterations=self.max_iterations,
            cost_tracker=self.cost_tracker,
            runaway_detection=True
        )

        # LineageManager
        self.lineage = LineageManager(
            checkpoint_interval=config.checkpoint_interval,
            storage_backend=config.storage
        )

    async def execute(self, prompt: str) -> ExecutionResult:
        """Execute agent loop until completion or budget exhaustion."""
        iteration = 0

        while iteration < self.max_iterations:
            # Check Oncologist limits
            if self.oncologist.should_terminate():
                return ExecutionResult(
                    status="terminated",
                    reason=self.oncologist.termination_reason
                )

            # Execute one iteration
            result = await self._execute_iteration(prompt, iteration)

            # Checkpoint state (LineageManager)
            if iteration % self.lineage.checkpoint_interval == 0:
                await self.lineage.checkpoint(result)

            # Check for completion promise (The Gauntlet)
            if self._detect_completion(result):
                return ExecutionResult(status="completed", result=result)

            iteration += 1

        return ExecutionResult(status="budget_exhausted")

    def _detect_completion(self, result: IterationResult) -> bool:
        """The Gauntlet: Detect task completion signals."""
        completion_markers = [
            "TASK_COMPLETE",
            "DONE",
            "✅ Complete",
            result.tool_calls.contains("task_complete")
        ]
        return any(marker in result.output for marker in completion_markers)
```

### File Structure

```
src/agentropix/
├── executor/
│   ├── __init__.py
│   ├── core.py           # AgentropixExecutor (wraps Ralph)
│   ├── telomere.py       # Telomere Budget implementation
│   ├── oncologist.py     # Safety and limits (wraps SafetyGuard)
│   ├── atp_economy.py    # Cost tracking (wraps CostTracker)
│   └── lineage.py        # State persistence
├── adapters/
│   ├── claude.py         # Claude adapter (from Ralph)
│   ├── gemini.py         # Gemini adapter (from Ralph)
│   └── base.py           # Adapter interface
└── gauntlet/
    └── completion.py     # Completion detection
```

### Migration Path

1. **Phase 1**: Extract Ralph core patterns into `executor/`
2. **Phase 2**: Rename classes to bio-agentic terminology
3. **Phase 3**: Add Agentropix-specific extensions
4. **Phase 4**: Integrate with Chimera Stack (ADR-001)

## Consequences

### Positive

- **Immediate capability**: Execution engine available from day 1
- **Proven reliability**: 920+ tests provide confidence
- **Feature completeness**: Safety, cost, checkpointing included
- **Natural mapping**: Ralph concepts → bio-agentic components
- **Multi-provider**: Claude, Gemini, local models supported

### Negative

- **Codebase size**: 1.6MB is substantial to understand
  - *Mitigation*: Extract only needed modules, document key paths
- **Dual maintenance**: If upstream Ralph evolves
  - *Mitigation*: Fork and own the codebase, cherry-pick updates
- **Naming translation**: Team must learn Ralph → bio-agentic mapping
  - *Mitigation*: Create glossary, use Agentropix names in our code

### Neutral

- Ralph was designed for Claude Code specifically; we're generalizing it
- Some Ralph features (slash commands) won't be used initially

## Bio-Agentic Mapping

| Agentropix Component | Ralph Implementation | Location in Ralph |
|---------------------|---------------------|-------------------|
| Telomere Budget | `max_iterations` config | `orchestrator.py:~26116` |
| ATP Economy | `CostTracker` class | `safety.py` |
| The Oncologist | `SafetyGuard` class | `safety.py` |
| LineageManager | `checkpoint_*` methods | `orchestrator.py` |
| The Gauntlet | `completion_promise` detection | `orchestrator.py` |
| Agentic Chromosome | `ContextManager` class | `context.py` |

## Validation Criteria

- [x] Ralph core extracted and tests passing (RalphEngine in engine/ralph.py)
- [x] Bio-agentic class wrappers implemented (BioState, Trinity Loop)
- [x] Telomere Budget enforced (iteration limits) (max_loops in BioState)
- [x] ATP Economy tracking (token/cost) (MetabolicLedger with reserve/spend/release)
- [x] The Oncologist safety guards active (5-level escalation in safety/oncologist.py)
- [x] LineageManager checkpointing working (Phoenix Protocol resurrection)
- [x] Multi-provider execution (Claude + Gemini) (LiteLLM with Anthropic, Gemini, OpenRouter)

## Backup Plans

If Ralph adoption fails:

| Risk | Backup Plan |
|------|-------------|
| Ralph patterns don't fit | Extract core loop only, build rest custom |
| Performance issues | Profile and optimize hot paths |
| Maintenance burden | Simplify to minimal viable subset |
| Provider adapters break | Use LiteLLM (ADR-001) as abstraction |

## References

- Ralph Source: `ralph/ralph-orchestrator.txt` (line ~26116 for core loop)
- Ralph Plugin: `ralph/ralph.txt`
- Agentropix Component Design — oracle: `docs/component-fixes-plan.md`
- Related: [ADR-001: SDK Selection](ADR-001-sdk-selection.md)

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-01-02 | Claude Code | Initial draft |
