> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-009: Intelligent Task Router

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Proposed |
| **Date** | 2026-01-17 |
| **Decision Makers** | Architecture Team, BMAD Team |
| **Bio-Agentic Component** | Task Classification, Execution Routing |
| **Priority** | P0 (Critical) |
| **Related ADRs** | ADR-002 (Execution Engine) |

## Context

Agentropix's Trinity Loop architecture assumes parallel-first execution, which fails on complex multi-step tasks requiring sequential execution with context passing between steps.

### Problem Statement

When given a task like:
> "Write Python, Go, Rust code → Compare execution times → Create matrix → Save to file"

The current system:
1. Uses regex to split on conjunctions ("and", "then", "also")
2. Creates subtasks WITHOUT dependency tracking
3. Executes all subtasks in parallel with no shared context
4. Each subtask has no access to outputs from other subtasks

**Result:** Complex sequential tasks fail or produce incorrect/incomplete results.

### Root Causes

| Root Cause | Location | Impact |
|------------|----------|--------|
| Regex-based task decomposition | `engine/ralph.py:702-737` | No dependency detection |
| Context isolation | `llm/executor.py` | Subtasks can't see prior results |
| Parallel-first assumption | Architectural | No sequential execution path |
| No task type detection | Missing | All tasks treated identically |

### Constraints

- Must preserve existing Trinity Loop for parallel tasks
- Must integrate with ATP economy and bio-agentic lifecycle
- Must not regress performance on parallel-suitable tasks
- Classification must add minimal latency (<500ms)
- Must be backwards compatible with existing CLI

### Assumptions

- LLM-based classification is reliable (>95% accuracy expected)
- Most user tasks can be classified into parallel/sequential/hybrid
- Existing Swarm dependency injection can handle context passing
- Users prefer automatic classification over manual mode selection

## Decision Drivers

1. **User success rate** - Complex tasks must complete successfully
2. **Competitive parity** - Match single-agent systems on sequential tasks
3. **Leverage existing infrastructure** - 70% of required code already exists
4. **Minimal disruption** - Preserve Trinity Loop for suitable tasks
5. **Bio-agentic alignment** - Integrate with ATP economy

## Considered Options

### Option 1: LLM-Based Task Router (Recommended)

**Description:** Implement a TaskRouter component that uses LLM classification to determine execution mode and route to appropriate executor.

```
User Prompt → [TaskRouter] → Classification → Route to Executor
                   │
            ┌──────┴──────┐
            │             │
      PARALLEL      SEQUENTIAL      HYBRID
         │               │             │
   Trinity Loop    Chain Exec    DAG Execution
```

**Pros:**
- Automatic classification - users don't specify mode
- Leverages existing infrastructure (Subtask.dependencies, Swarm context injection)
- Clear separation of concerns
- Extensible for future execution modes
- Minimal code changes to existing components

**Cons:**
- Adds classification latency (~200-500ms)
- LLM classification may occasionally be wrong
- Additional complexity in execution path
- ATP cost for classification step

### Option 2: Enhanced Architect Only (Quick Win)

**Description:** Replace regex decomposition with LLM-based decomposition that populates dependencies. Use existing Swarm for all execution.

**Pros:**
- Minimal code changes (single file: architect.py)
- Faster to implement (2-3 days)
- No new components needed
- Existing Swarm handles dependency resolution

**Cons:**
- No explicit task type classification
- Pure sequential tasks still use parallel infrastructure
- Less optimal for sequential-only tasks
- No execution mode visibility to users

### Option 3: Manual Mode Selection

**Description:** Add CLI flags for users to specify execution mode: `--parallel`, `--sequential`, `--hybrid`.

**Pros:**
- No classification latency or cost
- User has full control
- Simple to implement

**Cons:**
- Poor UX - users must understand execution models
- Users often don't know which mode is appropriate
- Doesn't scale to diverse task types
- Defeats purpose of agentic automation

### Option 4: Heuristic-Based Router

**Description:** Use keyword matching and regex patterns to classify tasks without LLM.

**Pros:**
- No LLM cost for classification
- Very fast (<10ms)
- Deterministic behavior

**Cons:**
- Limited accuracy on complex/ambiguous tasks
- Brittle to prompt phrasing variations
- Requires ongoing pattern maintenance
- Can't understand semantic dependencies

## Decision

We will implement **Option 1 (LLM-Based Task Router)** in two phases:

### Phase 1: Quick Win (Option 2)
- Replace regex decomposition with LLM-based decomposition
- LLM returns subtasks WITH dependencies populated
- Existing Swarm dependency injection handles context
- **Goal:** Validate that dependency-aware decomposition fixes benchmark task

### Phase 2: Full Router (Option 1)
- Implement TaskRouter with explicit classification
- Add SequentialExecutor for pure sequential tasks
- Add HybridExecutor for mixed dependency graphs
- Add ExecutionContext for clean context management
- CLI integration with `--verbose` for classification visibility

### Rationale

1. **Quick Win validates hypothesis** before investing in full router
2. **70% infrastructure exists** - Subtask.dependencies + Swarm._inject_dependency_context()
3. **LLM classification is accurate** for structured task analysis
4. **Routing Pattern (Ch. 2)** is the correct architectural pattern per Gulli's "Agentic Design Patterns"

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         AFTER (With TaskRouter)                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   User Prompt ───► TaskRouter ─────┬───► Trinity Loop (PARALLEL)        │
│                        │           │       └── Architect → Swarm        │
│                  [LLM Classify]    │                                    │
│                        │           ├───► SequentialExecutor (SEQUENTIAL)│
│                        │           │       └── Chain with context       │
│                        ▼           │                                    │
│                   TaskPlan         └───► HybridExecutor (HYBRID)        │
│                                          └── DAG with Swarm + context   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### New Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `TaskRouter` | `orchestration/router.py` | LLM classification and routing |
| `SequentialExecutor` | `orchestration/sequential.py` | Chain execution with context |
| `HybridExecutor` | `orchestration/hybrid.py` | DAG-based mixed execution |
| `ExecutionContext` | `orchestration/context.py` | Result storage and injection |
| `TaskPlan` | `orchestration/router.py` | Classification result model |
| `ExecutionMode` | `orchestration/router.py` | Enum: PARALLEL/SEQUENTIAL/HYBRID |

### Key Interfaces

```python
class ExecutionMode(Enum):
    PARALLEL = "parallel"      # Trinity Loop
    SEQUENTIAL = "sequential"  # Chain Executor
    HYBRID = "hybrid"          # DAG Executor

@dataclass
class TaskPlan:
    execution_mode: ExecutionMode
    subtasks: list[SubtaskSpec]
    dependency_graph: dict[str, list[str]]
    reasoning: str

class TaskRouter:
    async def classify(self, prompt: str) -> TaskPlan: ...
    async def execute(self, plan: TaskPlan) -> ExecutionResult: ...
```

### Classification Prompt

```
Analyze this task and create an execution plan.

Task: {user_prompt}

Determine:
1. PARALLEL: All subtasks can run independently
2. SEQUENTIAL: Each subtask depends on previous output
3. HYBRID: Some parallel, some sequential dependencies

Output JSON with execution_mode, reasoning, and subtasks with dependencies.
```

## Consequences

### Positive

- **Sequential tasks succeed** - Context flows between dependent subtasks
- **Automatic optimization** - System chooses best execution strategy
- **Backwards compatible** - Parallel tasks still use efficient Trinity Loop
- **Extensible** - Easy to add new execution modes
- **Observable** - Classification reasoning logged for debugging
- **Bio-agentic integration** - Classification ATP cost tracked

### Negative

- **Classification latency** - Adds 200-500ms per task
  - *Mitigation*: Cache classification for repeated prompts
- **Classification errors** - LLM may misclassify occasionally
  - *Mitigation*: Add `--force-parallel` and `--force-sequential` overrides
- **Increased complexity** - More components to maintain
  - *Mitigation*: Clear separation of concerns, comprehensive tests
- **ATP cost** - Classification consumes tokens
  - *Mitigation*: Use efficient model, track in ATP budget

### Neutral

- Existing regex decomposition becomes fallback/deprecated
- Users gain visibility into execution mode (via `--verbose`)

## Validation Criteria

- [ ] Benchmark task completes successfully (Python/Go/Rust with comparison)
- [ ] Classification accuracy >95% on 50-prompt test suite
- [ ] Classification latency <500ms
- [ ] No regression in parallel task performance
- [ ] ATP economy correctly tracks classification cost
- [ ] CLI `--verbose` shows classification decision
- [ ] `--force-parallel` and `--force-sequential` work correctly
- [ ] Unit test coverage >90% on new components
- [ ] Integration tests with real LLM calls pass

## Backup Plans

| Risk | Backup Plan |
|------|-------------|
| LLM classification unreliable | Add heuristic fallback (Option 4) |
| Performance regression | Optimize with async classification |
| Context too large | Implement context summarization |
| ATP budget issues | Make classification cost configurable |
| Backwards compatibility breaks | Feature flag for gradual rollout |

## Implementation Plan

### Phase 1: Quick Win (Days 1-3)
1. Enhance `architect.py` with LLM-based decomposition
2. LLM prompt returns subtasks with dependencies
3. Test with benchmark task
4. Validate hypothesis

### Phase 2: Full Router (Days 4-14)
1. Create `orchestration/context.py` (ExecutionContext)
2. Create `orchestration/router.py` (TaskRouter, TaskPlan)
3. Create `orchestration/sequential.py` (SequentialExecutor)
4. Create `orchestration/hybrid.py` (HybridExecutor)
5. Update `cli/commands/run.py` with router integration
6. Add CLI flags and verbose output
7. Write comprehensive tests
8. Update documentation

## References

- [ADR-002: Execution Engine](ADR-002-execution-engine.md)
- Design Document: Task Router — oracle: `docs/plans/2026-01-17-task-router-design.md` (proposal-stage; ADR-009 is **Proposed**, not shipped)
- [Trinity Loop Documentation](../02-architecture/trinity-loop.md)
- Agentic Design Patterns (Antonio Gulli) - Chapters 1-6
- KI-008: Subtask Context Isolation Fix

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-01-17 | BMAD Team | Initial proposal based on research session |
