"""Critic — scores a Blackboard pass and decides whether the Trinity loop halts.

Deterministic v1 (no LLM): the score is a simple blend of the highest
per-finding confidence on the Blackboard and the count of cross-agent
correlations the Blackboard's quorum surfaces.

Halt rule (per OI-3a): stop when ``score >= halt_threshold`` OR when the
swarm pass added no new findings since the previous iteration (no progress
→ no point in iterating again).

``halt_threshold`` reads ``AGENTROPIX_CRITIC_HALT_THRESHOLD`` via the
shared env helper so operators can tighten or loosen the bar without code
changes; the default of 0.85 was picked deliberately to halt on
high-confidence single findings or any correlated multi-agent agreement.

Coverage guard (W-083, 2026-04-26): when the orchestrator passes the
iteration's planned agent names to ``Critic.score``, the Critic refuses
to halt while any planned agent produced **zero** findings — i.e. the
plan still has unfilled gaps. This restores the M6.12 baseline behaviour
in which the loop iterated past iter-1 even when ``max_conf`` saturated
to 1.0 from a single high-confidence finding. Floor controlled by
``AGENTROPIX_CRITIC_MIN_ITERATIONS`` (default 2) provides defence in
depth so the loop never short-circuits to iter-1 in production.

Reflexion-lite seam (SIFT-W-045): the Critic also exposes a
``stable_agents`` set on every ``TrinityResult`` — agents whose published
fingerprint is non-empty and unchanged from the previous Critic pass. The
Architect (when ``AGENTROPIX_TRINITY_FEEDBACK=1``) drops those agents
from the next iteration's swarm. ``gaps`` is the canonical-SWARM coverage
view (every SwarmAgent that produced zero findings this run); the planned
gaps used by the halt guard are computed against ``planned_agents``.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import NamedTuple

from agentropix_mcp.agents import Blackboard
from agentropix_mcp._env import get_float, get_int

_DEFAULT_HALT_THRESHOLD = 0.85
_DEFAULT_MIN_ITERATIONS = 2
_CORRELATION_WEIGHT = 0.25  # each correlation adds this to the score (capped at 1.0)


class TrinityResult(NamedTuple):
    """Outcome of one Critic evaluation.

    ``stable_agents`` and ``gaps`` are the Reflexion-lite forward channel
    consumed by ``Architect.plan()`` on the next iteration. ``dropped_agents``
    is filled in by the orchestrator after the architect picks the next plan;
    Critic itself leaves it empty.
    """

    score: float
    feedback: str
    should_halt: bool
    stable_agents: frozenset[str] = frozenset()
    dropped_agents: tuple[str, ...] = ()
    gaps: frozenset[str] = frozenset()


_FindingFingerprint = frozenset[tuple[str, str, str]]


class Critic:
    """Score the Blackboard after a swarm pass; decide whether to halt."""

    def __init__(
        self,
        halt_threshold: float | None = None,
        min_iterations: int | None = None,
    ) -> None:
        if halt_threshold is None:
            halt_threshold = get_float(
                "AGENTROPIX_CRITIC_HALT_THRESHOLD",
                _DEFAULT_HALT_THRESHOLD,
                floor=0.0,
                ceiling=1.0,
            )
        if min_iterations is None:
            min_iterations = get_int(
                "AGENTROPIX_CRITIC_MIN_ITERATIONS",
                _DEFAULT_MIN_ITERATIONS,
                floor=1,
                ceiling=10,
            )
        self.halt_threshold = halt_threshold
        self.min_iterations = min_iterations
        self._last_fingerprint: frozenset[tuple[str, str, str, str]] = frozenset()
        self._last_per_agent_fingerprint: dict[str, _FindingFingerprint] = {}

    def score(
        self,
        blackboard: Blackboard,
        planned_agents: Iterable[str] | None = None,
        iteration: int | None = None,
    ) -> TrinityResult:
        """Score this pass and return a TrinityResult.

        ``planned_agents`` and ``iteration`` are the W-083 coverage-guard
        inputs. When the orchestrator passes both, the Critic blocks
        ``should_halt`` while:

        * any planned agent produced zero findings this run (unfilled
          plan gap), or
        * ``iteration < self.min_iterations`` (floor).

        Both inputs default to ``None`` so callers that don't pass them
        keep the legacy threshold-only halt semantics — that's how the
        unit tests pin the original contract.
        """
        entries = blackboard.all
        if not entries:
            self._last_fingerprint = frozenset()
            self._last_per_agent_fingerprint = {}
            return TrinityResult(0.0, "no findings on blackboard", False)

        max_conf = max(f.confidence for _, f in entries)
        correlations = blackboard.correlations()
        score = min(1.0, max_conf + _CORRELATION_WEIGHT * len(correlations))

        # "Progress" = any new (agent, source, description, evidence) tuple
        # appeared since the last call. Idempotent agents re-publishing the
        # same Finding each iteration produce no new fingerprints, so the
        # loop halts as soon as the swarm pass becomes a fixed point.
        fingerprint = frozenset((agent, f.source, f.description, f.evidence) for agent, f in entries)
        no_progress = fingerprint == self._last_fingerprint
        self._last_fingerprint = fingerprint

        # Per-agent fingerprints power the Reflexion-lite feedback channel.
        # An agent is "stable" if it has published at least one finding AND
        # that contribution set is unchanged from the previous Critic pass.
        # The idempotence axiom (agents/_base.py SwarmAgent.investigate
        # docstring) means that on iter 2, every agent that produced findings
        # at iter 1 will reproduce the same set — so the carry-over rule is
        # equivalent to "current contribution set is non-empty" once we've
        # observed it once. Architect only drops when the env flag is on.
        per_agent_now: dict[str, set[tuple[str, str, str]]] = {}
        for agent, f in entries:
            per_agent_now.setdefault(agent, set()).add((f.source, f.description, f.evidence))
        per_agent_frozen: dict[str, _FindingFingerprint] = {agent: frozenset(fp) for agent, fp in per_agent_now.items()}
        stable_agents = frozenset(
            agent
            for agent, fp in per_agent_frozen.items()
            if fp and self._last_per_agent_fingerprint.get(agent, fp) == fp
        )
        self._last_per_agent_fingerprint = per_agent_frozen

        # gaps (BMAD-M8 Phase M8.3c): names of SwarmAgents that exist in
        # the canonical SWARM but produced **zero** Findings this run.
        # The Architect can use this to either (a) re-prioritize the
        # gappy agents on the next iteration with different env-var
        # tuning, or (b) drop them as "tried, empty" alongside stable
        # agents. The signal is also exposed to the orchestrator's
        # ``iterations_log`` so judges can see the open-loop gap close
        # in the demo.
        from agentropix_mcp.agents import SWARM as _CANONICAL_SWARM

        producing_agents = {agent for agent, _f in entries}
        gaps = frozenset(
            cls.name for cls in _CANONICAL_SWARM if cls.name not in producing_agents
        )

        # W-083 coverage guard: when the orchestrator told us which agents
        # were planned this iteration, refuse to halt while any of them
        # produced zero findings — those agents need another swing under
        # a (possibly re-prioritised) plan. Computed against the *planned*
        # set, not the canonical SWARM, so feedback-driven plan shrinkage
        # does not perpetually look like a coverage gap.
        plan_set = frozenset(planned_agents) if planned_agents is not None else None
        plan_gaps: frozenset[str] = (
            frozenset(plan_set - producing_agents) if plan_set is not None else frozenset()
        )
        below_min_iter = (
            iteration is not None and iteration < self.min_iterations
        )

        if plan_gaps:
            should_halt = False
            feedback = (
                f"continue: plan gap — {len(plan_gaps)} planned agent(s) produced 0 findings "
                f"({sorted(plan_gaps)}); score {score:.2f}"
            )
        elif below_min_iter:
            should_halt = False
            feedback = (
                f"continue: iteration {iteration} < min_iterations {self.min_iterations} "
                f"(score {score:.2f})"
            )
        elif score >= self.halt_threshold:
            should_halt = True
            feedback = (
                f"halt: score {score:.2f} >= threshold {self.halt_threshold:.2f} "
                f"({len(entries)} finding(s), {len(correlations)} correlation(s))"
            )
        elif no_progress:
            should_halt = True
            feedback = f"halt: no new findings this iteration (score {score:.2f} < threshold {self.halt_threshold:.2f})"
        else:
            should_halt = False
            feedback = (
                f"continue: score {score:.2f} < threshold {self.halt_threshold:.2f} "
                f"({len(entries)} finding(s), {len(correlations)} correlation(s))"
            )
        return TrinityResult(
            score=score,
            feedback=feedback,
            should_halt=should_halt,
            stable_agents=stable_agents,
            gaps=gaps,
        )
