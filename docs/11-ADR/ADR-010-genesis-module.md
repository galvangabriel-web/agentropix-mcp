> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-010: Genesis Module Architecture

## Status

**Accepted** — 2026-01-18

## Context

Agentropix implements bio-agentic algorithms (fitness landscapes, evolutionary rescue, stochastic simulation) that were previously scattered across operational components. This created several problems:

1. **Testability**: Stochastic functions were difficult to test due to non-deterministic behavior
2. **Duplication**: Mathematical formulas were hardcoded in multiple places
3. **Coupling**: Pure calculations were mixed with I/O operations
4. **Maintainability**: Changes to formulas required updating multiple files

The project needed a pure mathematical layer that:
- Implements all bio-agentic algorithms in one place
- Uses dependency injection for testable stochastic code
- Follows "Functional Core, Imperative Shell" pattern
- Has no I/O dependencies

## Decision

We introduce the **Genesis Module** as a pure mathematical layer implementing bio-agentic algorithms from `agent_ena/all_doc.MD`.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Operational Layer                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ Oncologist  │  │   Thymus    │  │   Hippocampus       │ │
│  │ (Safety)    │  │ (Trust)     │  │   (Memory)          │ │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         │                │                     │            │
│         └────────────────┼─────────────────────┘            │
│                          ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                   Genesis Module                         ││
│  │  ┌───────────┐  ┌───────────┐  ┌───────────────────┐   ││
│  │  │  fitness  │  │ stochastic│  │    protocols      │   ││
│  │  │  (core)   │  │  (SSA)    │  │  (RandomSource)   │   ││
│  │  └───────────┘  └───────────┘  └───────────────────┘   ││
│  │           Pure Functions, No I/O                        ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Pure Functions**: No side effects, same input = same output
2. **No I/O**: No file/network/database access
3. **Protocol-based**: Dependency injection via `typing.Protocol`
4. **Testable**: Each function unit-testable without mocking

### RandomSource Protocol

Injectable randomness enabling deterministic tests:

```python
@runtime_checkable
class RandomSource(Protocol):
    def uniform(self) -> float: ...

class SystemRandom:    # Production: os.urandom
class SeededRandom:    # Reproducible experiments
class FixedRandom:     # Deterministic tests
```

### Module Structure

```
agentropix/genesis/
├── __init__.py         # Module exports
├── protocols.py        # RandomSource protocol & implementations
├── core/
│   ├── fitness.py      # Fitness landscape functions
│   └── stochastic.py   # Gillespie SSA implementation
├── decay/              # (Phase 2) Exponential decay
├── evolution/          # (Phase 2) Evolutionary dynamics
└── detection/          # (Phase 2) Anomaly detection
```

## Consequences

### Positive

1. **Testability**: Stochastic algorithms now fully deterministic in tests
2. **Single Source of Truth**: All formulas in one module
3. **Decoupling**: Pure math separated from I/O operations
4. **Documentation**: Each function documents its mathematical formula
5. **Type Safety**: Full type hints with Protocol validation

### Negative

1. **Indirection**: Operational code must import from Genesis
2. **Learning Curve**: Developers must understand Protocol pattern
3. **Initial Overhead**: Setting up RandomSource in call sites

### Neutral

1. **Migration Path**: Existing code can gradually adopt Genesis functions
2. **Phase-based Implementation**: Allows incremental delivery

## Alternatives Considered

### 1. Keep Formulas Inline

**Rejected**: Leads to duplication and inconsistency.

### 2. Utility Functions Without Protocol

**Rejected**: Can't test stochastic code deterministically.

### 3. Class-based Design

**Rejected**: Adds unnecessary state; pure functions are simpler.

## Implementation Phases

| Phase | Components | Status |
|-------|------------|--------|
| Phase 1 | protocols, fitness, stochastic | ✅ Complete |
| Phase 2 | decay, rescue equations | 🔲 Planned |
| Phase 3 | evolution dynamics | 🔲 Planned |
| Phase 4 | anomaly detection | 🔲 Planned |

## Related Decisions

- **ADR-006**: Memory System (uses Genesis for fitness calculations)
- **ADR-008**: Safety Architecture (uses Genesis for threat detection)
- **ADR-009**: Task Router (will use Genesis for routing decisions)

## References

- `agent_ena/all_doc.MD` — Source mathematical specifications
- "Functional Core, Imperative Shell" — Gary Bernhardt, 2012
- Gillespie Algorithm — D.T. Gillespie, 1977

---

*Decision Record Created: 2026-01-18*
*Authors: BMAD Development Team*
