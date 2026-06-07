> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-008: Safety Architecture (Bio-Agentic Safety Model)

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Implemented |
| **Date** | 2026-01-02 |
| **Accepted** | 2026-01-11 |
| **Implemented** | 2026-01-14 |
| **Decision Makers** | Architecture Team |
| **Bio-Agentic Component** | The Oncologist (Safety Controller) |
| **Priority** | P0 (Critical) |

## Context

AI agents operating autonomously pose safety risks:
- Runaway resource consumption
- Unintended actions with real-world impact
- Context window exhaustion
- Cost explosions
- Harmful output generation

The Oncologist component (named after cancer specialists) monitors for "malignant" behavior patterns and can terminate problematic agents.

### Problem Statement

We need a comprehensive safety architecture that:
1. Prevents runaway agent execution
2. Enforces resource budgets (tokens, cost, time)
3. Detects anomalous behavior patterns
4. Provides circuit breakers for failing components
5. Enables human oversight at critical points
6. Maintains audit trails for accountability

### Constraints

- Must not significantly impact agent performance (< 5% overhead)
- Must work in distributed environments
- Must be configurable per agent/user/deployment
- Must fail-safe (if safety system fails, agents stop)
- Must support NIST AI Risk Management Framework alignment

### Assumptions

- Most agents will complete normally
- Anomalies are rare but must be caught
- Human oversight is required for high-risk operations
- Cost and time limits are acceptable

## Decision Drivers

1. **Defense in depth** - Multiple safety layers
2. **Fail-safe** - Default to stopping, not continuing
3. **Observability** - Know what agents are doing
4. **Human control** - Maintain oversight capability
5. **Bio-agentic alignment** - Match the metaphor

## Considered Options

### Option 1: Multi-Layer Bio-Agentic Safety Model

**Description:** Implement safety using the bio-agentic metaphor with multiple interconnected components.

**Pros:**
- Coherent with overall architecture metaphor
- Multiple independent safety mechanisms
- Well-defined boundaries and responsibilities
- Intuitive mental model

**Cons:**
- More complex than single safety check
- Multiple components to maintain

### Option 2: Single Safety Gate

**Description:** One centralized safety checker before each action.

**Pros:**
- Simple implementation
- Single point of control
- Easy to understand

**Cons:**
- Single point of failure
- No defense in depth
- Limited granularity

### Option 3: LangChain Guardrails Only

**Description:** Use LangChain's built-in guardrails.

**Pros:**
- Integrated with SDK (ADR-001)
- Less custom code
- Community-maintained

**Cons:**
- Limited customization
- May not cover all safety needs
- Not designed for multi-model systems

## Decision

We will implement the **Multi-Layer Bio-Agentic Safety Model** with five interconnected components:

1. **Telomere Budget** - Hard iteration limits
2. **ATP Economy** - Cost and resource budgets
3. **The Oncologist** - Anomaly detection and termination
4. **Thymus Sandbox** - Capability-based isolation
5. **The Gauntlet** - Completion validation

### Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                     Safety Architecture                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│   ┌────────────────┐    ┌────────────────┐    ┌────────────────┐ │
│   │ TELOMERE       │    │ ATP ECONOMY    │    │ THYMUS         │ │
│   │ BUDGET         │    │ (Cost Control) │    │ SANDBOX        │ │
│   │ (Iteration     │    │                │    │ (Capability    │ │
│   │  Limits)       │    │ • Token budget │    │  Isolation)    │ │
│   │                │    │ • Cost budget  │    │                │ │
│   │ • Max iters    │    │ • Time budget  │    │ • Tool perms   │ │
│   │ • Decay rate   │    │ • Rate limits  │    │ • File access  │ │
│   └───────┬────────┘    └───────┬────────┘    └───────┬────────┘ │
│           │                     │                     │           │
│           └─────────────────────┼─────────────────────┘           │
│                                 │                                  │
│                    ┌────────────▼────────────┐                    │
│                    │     THE ONCOLOGIST      │                    │
│                    │   (Central Safety)      │                    │
│                    │                         │                    │
│                    │ • Anomaly detection     │                    │
│                    │ • Pattern matching      │                    │
│                    │ • Kill decision         │                    │
│                    │ • Escalation            │                    │
│                    └────────────┬────────────┘                    │
│                                 │                                  │
│                    ┌────────────▼────────────┐                    │
│                    │     THE GAUNTLET        │                    │
│                    │   (Exit Validation)     │                    │
│                    │                         │                    │
│                    │ • Completion check      │                    │
│                    │ • Output validation     │                    │
│                    │ • Quality gates         │                    │
│                    └─────────────────────────┘                    │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
```

### Component Implementations

#### 1. Telomere Budget

```python
from dataclasses import dataclass

@dataclass
class TelomereBudget:
    """Hard limits on agent iteration count."""
    max_iterations: int = 100
    warning_threshold: float = 0.8  # 80% consumed
    decay_rate: float = 1.0  # Iterations consumed per step

class TelomereEnforcer:
    """Enforces iteration limits."""

    def __init__(self, budget: TelomereBudget):
        self.budget = budget
        self.consumed = 0

    def consume(self, amount: float = 1.0) -> bool:
        """Consume iterations. Returns False if exhausted."""
        self.consumed += amount * self.budget.decay_rate

        if self.consumed >= self.budget.max_iterations:
            return False  # Budget exhausted

        if self.remaining_ratio() <= (1 - self.budget.warning_threshold):
            self._emit_warning()

        return True

    def remaining_ratio(self) -> float:
        return 1 - (self.consumed / self.budget.max_iterations)

    def _emit_warning(self):
        # Emit to Cytokine Network
        pass
```

#### 2. ATP Economy

```python
from dataclasses import dataclass
from decimal import Decimal

@dataclass
class ATPBudget:
    """Resource budgets for agent execution."""
    max_tokens: int = 1_000_000
    max_cost_usd: Decimal = Decimal("10.00")
    max_time_seconds: int = 3600
    rate_limit_rpm: int = 60  # Requests per minute

class ATPEconomyTracker:
    """Tracks and enforces resource consumption."""

    def __init__(self, budget: ATPBudget):
        self.budget = budget
        self.tokens_consumed = 0
        self.cost_consumed = Decimal("0.00")
        self.start_time = time.time()
        self.request_times = []

    def record_usage(
        self,
        tokens: int,
        cost: Decimal,
        model: str
    ) -> bool:
        """Record usage. Returns False if any budget exceeded."""
        self.tokens_consumed += tokens
        self.cost_consumed += cost

        # Check all budgets
        if self.tokens_consumed > self.budget.max_tokens:
            return False
        if self.cost_consumed > self.budget.max_cost_usd:
            return False
        if self.elapsed_time() > self.budget.max_time_seconds:
            return False
        if not self._check_rate_limit():
            return False

        return True

    def elapsed_time(self) -> float:
        return time.time() - self.start_time

    def _check_rate_limit(self) -> bool:
        now = time.time()
        minute_ago = now - 60
        self.request_times = [t for t in self.request_times if t > minute_ago]
        self.request_times.append(now)
        return len(self.request_times) <= self.budget.rate_limit_rpm
```

#### 3. The Oncologist

```python
from enum import Enum
from dataclasses import dataclass

class AnomalyType(Enum):
    REPETITIVE_OUTPUT = "repetitive_output"
    CONTEXT_SPIRAL = "context_spiral"
    TOOL_ABUSE = "tool_abuse"
    COST_SPIKE = "cost_spike"
    TIMEOUT_PATTERN = "timeout_pattern"

@dataclass
class AnomalyDetection:
    type: AnomalyType
    severity: float  # 0-1
    evidence: str
    recommendation: str

class TheOncologist:
    """Central safety controller - detects and handles malignant behavior."""

    def __init__(
        self,
        telomere: TelomereEnforcer,
        atp: ATPEconomyTracker,
        sandbox: ThymusSandbox
    ):
        self.telomere = telomere
        self.atp = atp
        self.sandbox = sandbox
        self.history = []
        self.anomaly_detectors = [
            self._detect_repetition,
            self._detect_context_spiral,
            self._detect_tool_abuse,
            self._detect_cost_spike,
        ]

    async def evaluate(self, iteration_result: IterationResult) -> tuple[bool, str]:
        """Evaluate iteration for safety. Returns (should_continue, reason)."""
        self.history.append(iteration_result)

        # Check hard limits
        if not self.telomere.consume():
            return False, "Telomere budget exhausted"

        if not self.atp.record_usage(
            iteration_result.tokens,
            iteration_result.cost,
            iteration_result.model
        ):
            return False, "ATP budget exceeded"

        # Run anomaly detection
        for detector in self.anomaly_detectors:
            anomaly = detector(self.history)
            if anomaly and anomaly.severity > 0.8:
                return False, f"Anomaly detected: {anomaly.type.value}"

        return True, "OK"

    def _detect_repetition(self, history: list) -> AnomalyDetection | None:
        """Detect repetitive outputs (agent stuck in loop)."""
        if len(history) < 5:
            return None

        recent = [h.output[:100] for h in history[-5:]]
        unique = set(recent)

        if len(unique) <= 2:  # Only 2 unique outputs in last 5
            return AnomalyDetection(
                type=AnomalyType.REPETITIVE_OUTPUT,
                severity=0.9,
                evidence=f"Repeated outputs: {unique}",
                recommendation="Agent may be stuck in a loop"
            )
        return None

    def _detect_context_spiral(self, history: list) -> AnomalyDetection | None:
        """Detect context window spiraling out of control."""
        if len(history) < 3:
            return None

        context_sizes = [h.context_tokens for h in history[-3:]]
        if all(context_sizes[i+1] > context_sizes[i] * 1.5
               for i in range(len(context_sizes)-1)):
            # Context growing by 50%+ each iteration
            return AnomalyDetection(
                type=AnomalyType.CONTEXT_SPIRAL,
                severity=0.85,
                evidence=f"Context growth: {context_sizes}",
                recommendation="Context window growing uncontrollably"
            )
        return None

    def _detect_tool_abuse(self, history: list) -> AnomalyDetection | None:
        """Detect excessive tool calls (potential abuse)."""
        if len(history) < 3:
            return None

        recent_tool_calls = sum(len(h.tool_calls) for h in history[-3:])
        if recent_tool_calls > 30:  # More than 10 per iteration average
            return AnomalyDetection(
                type=AnomalyType.TOOL_ABUSE,
                severity=0.7,
                evidence=f"Tool calls in last 3 iterations: {recent_tool_calls}",
                recommendation="Excessive tool usage detected"
            )
        return None

    def _detect_cost_spike(self, history: list) -> AnomalyDetection | None:
        """Detect sudden cost increases."""
        if len(history) < 5:
            return None

        costs = [h.cost for h in history[-5:]]
        avg_early = sum(costs[:3]) / 3
        avg_late = sum(costs[3:]) / 2

        if avg_late > avg_early * 3:  # 3x cost increase
            return AnomalyDetection(
                type=AnomalyType.COST_SPIKE,
                severity=0.75,
                evidence=f"Cost spike: {avg_early} → {avg_late}",
                recommendation="Unusual cost increase detected"
            )
        return None
```

#### 4. Thymus Sandbox

```python
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class CapabilitySet:
    """Defines what an agent is allowed to do."""
    allowed_tools: list[str] = field(default_factory=list)
    file_read_paths: list[Path] = field(default_factory=list)
    file_write_paths: list[Path] = field(default_factory=list)
    network_allowed: bool = False
    shell_allowed: bool = False
    max_file_size_bytes: int = 10_000_000  # 10MB

class ThymusSandbox:
    """Capability-based isolation for agent actions."""

    def __init__(self, capabilities: CapabilitySet):
        self.capabilities = capabilities

    def can_use_tool(self, tool_name: str) -> bool:
        return tool_name in self.capabilities.allowed_tools

    def can_read_file(self, path: Path) -> bool:
        return any(
            path.is_relative_to(allowed)
            for allowed in self.capabilities.file_read_paths
        )

    def can_write_file(self, path: Path) -> bool:
        return any(
            path.is_relative_to(allowed)
            for allowed in self.capabilities.file_write_paths
        )

    def validate_action(self, action: AgentAction) -> tuple[bool, str]:
        """Validate if action is allowed. Returns (allowed, reason)."""
        if action.type == "tool_call":
            if not self.can_use_tool(action.tool_name):
                return False, f"Tool {action.tool_name} not in allowed list"

        elif action.type == "file_read":
            if not self.can_read_file(action.path):
                return False, f"Read access denied for {action.path}"

        elif action.type == "file_write":
            if not self.can_write_file(action.path):
                return False, f"Write access denied for {action.path}"
            if action.size > self.capabilities.max_file_size_bytes:
                return False, f"File too large: {action.size} bytes"

        elif action.type == "network":
            if not self.capabilities.network_allowed:
                return False, "Network access not allowed"

        elif action.type == "shell":
            if not self.capabilities.shell_allowed:
                return False, "Shell access not allowed"

        return True, "OK"
```

#### 5. The Gauntlet

```python
from dataclasses import dataclass

@dataclass
class CompletionCriteria:
    """Criteria for valid task completion."""
    required_markers: list[str] = field(default_factory=lambda: ["DONE", "COMPLETE"])
    min_iterations: int = 1
    max_open_questions: int = 0
    require_summary: bool = True

class TheGauntlet:
    """Exit validation - ensures completion is legitimate."""

    def __init__(self, criteria: CompletionCriteria):
        self.criteria = criteria

    def validate_completion(
        self,
        final_output: str,
        iteration_count: int,
        conversation_state: dict
    ) -> tuple[bool, str]:
        """Validate that completion claim is legitimate."""

        # Check minimum iterations
        if iteration_count < self.criteria.min_iterations:
            return False, f"Too few iterations ({iteration_count})"

        # Check for completion markers
        has_marker = any(
            marker.lower() in final_output.lower()
            for marker in self.criteria.required_markers
        )
        if not has_marker:
            return False, "No completion marker found"

        # Check for open questions
        open_questions = self._count_open_questions(conversation_state)
        if open_questions > self.criteria.max_open_questions:
            return False, f"Too many open questions ({open_questions})"

        # Check for summary if required
        if self.criteria.require_summary:
            if not self._has_summary(final_output):
                return False, "No summary provided"

        return True, "Completion validated"

    def _count_open_questions(self, state: dict) -> int:
        # Implementation
        return 0

    def _has_summary(self, output: str) -> bool:
        summary_markers = ["summary:", "in summary", "to summarize", "## Summary"]
        return any(m.lower() in output.lower() for m in summary_markers)
```

### Safety Configuration

```yaml
# safety-config.yaml
safety:
  telomere:
    default_max_iterations: 100
    warning_threshold: 0.8
    profiles:
      quick_task:
        max_iterations: 25
      long_running:
        max_iterations: 500

  atp_economy:
    default:
      max_tokens: 1000000
      max_cost_usd: 10.00
      max_time_seconds: 3600
      rate_limit_rpm: 60
    profiles:
      development:
        max_cost_usd: 1.00
      production:
        max_cost_usd: 100.00

  oncologist:
    anomaly_detection:
      enabled: true
      repetition_threshold: 0.9
      context_growth_threshold: 1.5
      tool_abuse_limit: 30

  sandbox:
    default_capabilities:
      allowed_tools:
        - read_file
        - write_file
        - search
      file_read_paths:
        - "/workspace"
      file_write_paths:
        - "/workspace/output"
      network_allowed: false
      shell_allowed: false

  gauntlet:
    required_markers:
      - "DONE"
      - "COMPLETE"
      - "TASK_FINISHED"
    min_iterations: 1
    require_summary: true
```

## Consequences

### Positive

- **Defense in depth**: Multiple independent safety layers
- **Bio-agentic coherence**: Matches overall architecture metaphor
- **Configurable**: Per-agent/environment safety profiles
- **Observable**: All safety decisions logged and auditable
- **Fail-safe**: Defaults to stopping on uncertainty

### Negative

- **Complexity**: Five components to understand and maintain
  - *Mitigation*: Clear documentation, unified configuration
- **Performance overhead**: Safety checks on each iteration
  - *Mitigation*: Keep checks lightweight (< 5ms)
- **False positives**: Legitimate agents may be stopped
  - *Mitigation*: Tune thresholds, allow override for trusted agents

### Neutral

- Safety configuration is another thing to manage
- Trade-off between safety and agent autonomy

## Bio-Agentic Mapping

| Safety Component | Biological Analogy |
|-----------------|-------------------|
| Telomere Budget | Telomere shortening limits cell division |
| ATP Economy | ATP is cellular energy currency |
| The Oncologist | Oncologists detect and treat cancer |
| Thymus Sandbox | Thymus trains immune system on self vs non-self |
| The Gauntlet | Immune checkpoint ensuring proper response |

## NIST AI RMF Alignment

| NIST Category | Agentropix Implementation |
|--------------|--------------------------|
| Govern | Safety configuration as code, version controlled |
| Map | Bio-agentic component mapping documents risks |
| Measure | Metrics from Oncologist, budgets tracked |
| Manage | Termination capabilities, human escalation |

## Validation Criteria

- [x] Runaway agent terminated within 5 iterations of budget (router apoptosis decision)
- [x] Cost limits enforced (no charges beyond budget) (ATP Ledger 2-phase commit)
- [x] Anomaly detection catching test cases (Oncologist 5-level escalation)
- [x] Sandbox preventing unauthorized tool use (Thymus security levels)
- [x] Gauntlet rejecting incomplete completions (critic_approved gate in Trinity Loop)
- [x] All safety decisions logged with evidence (structlog structured logging)

## References

- Error Handling Patterns: `docs/impl-patterns/error_handling.md`
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- Ralph Safety: `ralph/ralph-orchestrator.txt` (search: SafetyGuard)
- Related: [ADR-002: Execution Engine](ADR-002-execution-engine.md)
- Related: [ADR-004: Identity System](ADR-004-identity-system.md)

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-01-02 | Claude Code | Initial draft |
