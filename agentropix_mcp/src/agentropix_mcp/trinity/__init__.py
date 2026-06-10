"""Trinity Loop — Architect → Swarm → Critic feedback wrapper.

W-029 / Phase-2 Wave-3 minimum viable Trinity per
``docs/PHASE-1-TRINITY-DESIGN.md`` Path C.

Public surface:
    Architect    — picks (and may narrow) the swarm slice for an iteration.
    Critic       — scores a Blackboard pass and decides whether to halt.
    TrinityResult — what one iteration of (Architect, Swarm pass, Critic) yields.

Everything is deterministic this iteration; LLM-backed Architect / Critic
are deferred to a future story (see sprint sift-2-7).
"""

from agentropix_mcp.trinity.architect import Architect
from agentropix_mcp.trinity.critic import Critic, TrinityResult

__all__ = ["Architect", "Critic", "TrinityResult"]
