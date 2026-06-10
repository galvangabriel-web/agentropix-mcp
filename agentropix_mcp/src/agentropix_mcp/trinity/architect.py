"""Architect — picks the swarm slice for the next Trinity iteration.

W3 baseline (no LLM): the Architect always returned the canonical ``SWARM``
tuple in priority order; ``critic_feedback`` was an inert seam.

Reflexion-lite (SIFT-W-045, REVIEW-2026-04-20.md item #1): when
``AGENTROPIX_TRINITY_FEEDBACK=1``, the Architect now drops any agent the
Critic flagged as ``stable`` (its per-agent fingerprint is non-empty and
unchanged from the previous iteration) and returns the surviving subset
in canonical SWARM order. HuntAgent's run-last invariant is preserved
because preserving SWARM order does it for free.

Default behaviour is unchanged (flag off) so the 626/0 test baseline is
structurally untouchable until item #3 ships ``samples/ground_truth_dc.yaml``
with a recall scorer that can prove the gain on a real DC E01.

The architecture.md:780-799 reference impl shape is:

    subtasks = await architect.decompose(task)

We collapse "decompose" → "plan" because in sift the unit of work is a
SwarmAgent class, not a free-text subtask string.

P5 (sprint sift-2-7): optional LLM-backed reordering pass after the
deterministic plan. Gated by ``AGENTROPIX_ARCHITECT_LLM_REORDER`` (default
``false``). When enabled, the Architect calls Claude haiku with the
critic feedback and the deterministic order, asks for a refined sequence,
and uses it iff the LLM returns the SAME agent set (no add / no drop) in
parseable JSON. Any failure (anthropic SDK missing, network, JSON parse,
unknown agents, subset return) falls through silently to the deterministic
order — the Architect MUST NEVER block an iteration on the LLM call.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from collections import OrderedDict
from collections.abc import Iterable
from time import monotonic
from typing import TYPE_CHECKING, Any

from agentropix_mcp.agents import SWARM, SwarmAgent
from agentropix_mcp._env import get_int
from agentropix_mcp._trace import EXIT_EXCEPTION, EXIT_OK, record

if TYPE_CHECKING:
    from agentropix_mcp.memory import ReasoningTrace

logger = logging.getLogger(__name__)


_FEEDBACK_ENV = "AGENTROPIX_TRINITY_FEEDBACK"
# BMAD-M8 Phase M8.3c: flip the default to ON. The drop rule has been
# stable since W-045 (2026-04-20) and the recall arc M6.7→M6.12 was
# achieved with this rule active. Default-on closes the "Architect is
# open-loop in practice" finding from REVIEW-2026-04-20.md. Operators
# can still opt out with AGENTROPIX_TRINITY_FEEDBACK=0.
_FEEDBACK_DEFAULT = "1"

# P5: LLM-backed reordering pass. Default OFF (opt-in for the demo) so
# the existing deterministic 1448-test baseline is structurally untouched.
_LLM_REORDER_ENV = "AGENTROPIX_ARCHITECT_LLM_REORDER"
_LLM_REORDER_DEFAULT = "false"

# Cheap, fast model — appropriate for a meta-reasoning task (reorder
# 5 agent names against a critic-feedback string).
_LLM_REORDER_MODEL = "claude-haiku-4-5-20251001"

_LLM_SYSTEM_PROMPT = (
    "You are a DFIR investigation planner. Given a set of forensic agents and "
    "the gaps the critic identified after iteration N, return the agents in the "
    "order most likely to close those gaps next iteration. Output JSON: "
    '{"order": ["agent1", "agent2", ...]}. Do not add or remove agents.'
)


def _feedback_enabled() -> bool:
    """Return True iff the Reflexion-lite drop rule is enabled.

    Default is ON (M8.3c). Set ``AGENTROPIX_TRINITY_FEEDBACK=0`` to opt out.
    """
    return os.environ.get(_FEEDBACK_ENV, _FEEDBACK_DEFAULT).strip() == "1"


def _llm_reorder_enabled() -> bool:
    """Return True iff the LLM-backed reorder pass is enabled (P5).

    Binary env var (true|false). Anything other than ``true`` (case-insensitive)
    keeps the pass OFF. Default OFF preserves the deterministic baseline.
    """
    raw = os.environ.get(_LLM_REORDER_ENV, _LLM_REORDER_DEFAULT).strip().lower()
    return raw == "true"


# W-094: process-wide LRU cache for the LLM reorder result. Previously
# the cache lived on each Architect instance, and Architect was
# constructed fresh per ``run_trinity_loop`` call — so two sequential
# triages with identical (gaps_hash, agents_tuple) inputs paid for
# duplicate Anthropic API calls. Lifting the cache to module scope
# means a warm cache amortises across triages within the same MCP
# server process. Bounded LRU keyed by SHA-256 of the canonical cache
# key string; size from ``AGENTROPIX_ARCHITECT_LLM_CACHE_SIZE``
# (default 256, floor 0, ceiling 100_000). 0 disables the cache.
_PROCESS_LLM_CACHE: OrderedDict[str, list[str]] = OrderedDict()
_PROCESS_LLM_CACHE_LOCK = threading.Lock()


def _process_cache_max_size() -> int:
    return get_int(
        "AGENTROPIX_ARCHITECT_LLM_CACHE_SIZE",
        256,
        floor=0,
        ceiling=100_000,
    )


def _process_cache_get(key: str) -> list[str] | None:
    with _PROCESS_LLM_CACHE_LOCK:
        if key not in _PROCESS_LLM_CACHE:
            return None
        _PROCESS_LLM_CACHE.move_to_end(key)
        return list(_PROCESS_LLM_CACHE[key])


def _process_cache_put(key: str, value: list[str]) -> None:
    max_size = _process_cache_max_size()
    if max_size <= 0:
        return  # Cache explicitly disabled.
    with _PROCESS_LLM_CACHE_LOCK:
        _PROCESS_LLM_CACHE[key] = list(value)
        _PROCESS_LLM_CACHE.move_to_end(key)
        while len(_PROCESS_LLM_CACHE) > max_size:
            _PROCESS_LLM_CACHE.popitem(last=False)


def _process_cache_clear() -> None:
    """Test-only: drop the process-wide cache."""
    with _PROCESS_LLM_CACHE_LOCK:
        _PROCESS_LLM_CACHE.clear()


class Architect:
    """Deterministic planner: returns the canonical SWARM tuple, optionally
    pruned by the Critic's stable-agent feedback.

    P5: when ``AGENTROPIX_ARCHITECT_LLM_REORDER=true``, an optional Claude
    haiku reorder pass refines the deterministic plan based on the critic
    feedback. Failure-resistant: any LLM error falls through silently.
    """

    def __init__(self) -> None:
        # W-094: cache is process-wide (module-scope ``_PROCESS_LLM_CACHE``)
        # so two sequential triages with identical (gaps_hash, agents_tuple)
        # inputs hit the cache instead of paying for duplicate Anthropic API
        # calls. Use ``_process_cache_*`` helpers for read/write — the
        # ``self._llm_cache`` instance attribute is kept as a no-op alias for
        # any introspection code that might still reference it.
        self._llm_cache = _PROCESS_LLM_CACHE
        # Surfaced for tests / report introspection — last prior_traces
        # injection (W-017) lands here even when unused.
        self.last_prior_traces: list[ReasoningTrace] = []

    # ------------------------------------------------------------------
    # Deterministic order — extracted so tests can patch independently.
    # ------------------------------------------------------------------
    def _get_deterministic_order(
        self,
        stable_agents: Iterable[str] = (),
    ) -> tuple[type[SwarmAgent], ...]:
        """Return the canonical SWARM tuple, optionally pruned by ``stable_agents``.

        This is the W3-baseline behaviour with the W-045 Reflexion-lite drop
        applied when ``AGENTROPIX_TRINITY_FEEDBACK=1``.
        """
        stable_set = frozenset(stable_agents)
        if not stable_set or not _feedback_enabled():
            return SWARM
        plan = tuple(cls for cls in SWARM if cls.name not in stable_set)
        if logger.isEnabledFor(logging.DEBUG):
            dropped = [cls.name for cls in SWARM if cls.name in stable_set]
            logger.debug(
                "architect: dropping %d stable agent(s) %s; plan=%s",
                len(dropped),
                dropped,
                [cls.name for cls in plan],
            )
        return plan

    def plan(
        self,
        critic_feedback: str | None = None,
        stable_agents: Iterable[str] = (),
        prior_traces: list[ReasoningTrace] | None = None,
    ) -> tuple[type[SwarmAgent], ...]:
        """Pick the swarm slice for this iteration.

        ``critic_feedback`` is accepted for future LLM-backed re-ordering
        (P5 / sprint sift-2-7). When ``AGENTROPIX_ARCHITECT_LLM_REORDER=true``
        and a non-empty feedback string is supplied, the deterministic plan
        is handed to ``llm_reorder()`` for a refinement pass.

        ``stable_agents`` is the Reflexion-lite drop set (W-045) surfaced by
        the previous ``Critic.score`` call. When ``AGENTROPIX_TRINITY_FEEDBACK=1``
        every agent whose ``name`` appears in this set is removed from the
        next iteration's plan. The drop preserves canonical SWARM order, so
        HuntAgent (run-last invariant) stays last when it survives the drop.

        ``prior_traces`` is the Lamarckian-inheritance input (W-017): a list
        of ``ReasoningTrace`` from Hippocampus recall for the same goal.
        Accepted so callers can feed context in without a signature change
        later; the deterministic planner does not yet alter its output based
        on the traces — it stores the handle on ``self.last_prior_traces``
        so tests and the report can observe that injection happened.
        """
        self.last_prior_traces = list(prior_traces) if prior_traces else []
        deterministic = self._get_deterministic_order(stable_agents)

        # P5: optional LLM-backed reordering pass. Default off; only runs
        # when (a) env var is "true", (b) we have a critic_feedback string
        # to reason about, and (c) there are at least 2 agents to reorder.
        if (
            _llm_reorder_enabled()
            and critic_feedback
            and len(deterministic) >= 2
        ):
            try:
                refined_names = self.llm_reorder(deterministic, critic_feedback)
            except Exception as exc:  # noqa: BLE001 — never block on LLM
                logger.warning(
                    "architect.llm_reorder unexpected failure (%s); falling through to deterministic order",
                    exc,
                )
                refined_names = None
            if refined_names is not None:
                # Map names back to classes; any failure (unknown name,
                # subset, duplicate) → fall through.
                remapped = self._remap_names_to_classes(refined_names, deterministic)
                if remapped is not None:
                    return remapped
        return deterministic

    # ------------------------------------------------------------------
    # P5 LLM reorder — public so tests can patch / observe.
    # ------------------------------------------------------------------
    def llm_reorder(
        self,
        agents: tuple[type[SwarmAgent], ...] | list[type[SwarmAgent]] | list[str],
        critic_feedback: str,
    ) -> list[str] | None:
        """Ask Claude haiku to reorder ``agents`` to better close ``critic_feedback``.

        Returns the refined order as a list of agent name strings, or
        ``None`` on any failure (network, JSON parse, malformed response).

        Caller is responsible for validating the returned set against the
        original — ``llm_reorder`` does NOT enforce set-equality so callers
        can inspect the raw LLM output for tracing / debugging.
        """
        agent_names = self._coerce_agent_names(agents)
        cache_key = self._cache_key(critic_feedback, agent_names)
        cached = _process_cache_get(cache_key)
        if cached is not None:
            logger.debug("architect.llm_reorder cache hit (key=%s…)", cache_key[:12])
            return cached

        t0 = monotonic()
        exit_code = EXIT_OK
        result: list[str] | None = None
        try:
            raw_response = self._call_claude(agent_names, critic_feedback)
            result = self._parse_llm_order(raw_response)
            if result is not None:
                _process_cache_put(cache_key, result)
        except Exception as exc:  # noqa: BLE001 — log + return None
            logger.warning(
                "architect.llm_reorder failed (%s); deterministic order will be used",
                exc,
            )
            exit_code = EXIT_EXCEPTION
            result = None
        finally:
            elapsed_ms = (monotonic() - t0) * 1000
            args_hash = cache_key[:16]
            summary = (
                f"reordered {len(result)} agent(s)"
                if result is not None
                else "fallthrough (no refined order)"
            )
            # Best-effort trace record. ``record()`` is a no-op outside a
            # trace_scope, so this is safe to call unconditionally.
            try:
                record(
                    "agent.architect.llm_reorder",
                    elapsed_ms,
                    summary,
                    args_hash=args_hash,
                    exit_code=exit_code,
                )
            except Exception:  # noqa: BLE001 — tracing must never raise
                pass
        return result

    # ------------------------------------------------------------------
    # Internals — separated so tests can patch _call_claude in isolation.
    # ------------------------------------------------------------------
    def _call_claude(self, agent_names: list[str], critic_feedback: str) -> str:
        """Issue a single Claude haiku call and return the raw text response.

        Lazy-imports ``anthropic`` so the SDK is an OPTIONAL dep — if
        absent, raises ``RuntimeError`` which the caller catches and
        treats as a fall-through-to-deterministic signal.
        """
        try:
            from anthropic import Anthropic
        except ImportError as exc:
            raise RuntimeError(
                "anthropic SDK not installed; install agentropix-sift[llm] to enable architect reordering"
            ) from exc

        user_payload = {
            "agents": list(agent_names),
            "gaps": critic_feedback,
        }
        client = Anthropic()
        message = client.messages.create(
            model=_LLM_REORDER_MODEL,
            max_tokens=256,
            system=_LLM_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": json.dumps(user_payload),
                }
            ],
        )
        # Claude SDK returns content as a list of blocks; concatenate the
        # text blocks into a single string for the JSON parser.
        text_parts: list[str] = []
        for block in getattr(message, "content", []) or []:
            text = getattr(block, "text", None)
            if isinstance(text, str):
                text_parts.append(text)
        return "".join(text_parts).strip()

    @staticmethod
    def _parse_llm_order(raw: str) -> list[str] | None:
        """Parse a Claude reorder response. Returns list[str] or None on failure."""
        if not raw:
            return None
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            logger.warning("architect.llm_reorder: malformed JSON response (%r)", raw[:120])
            return None
        if not isinstance(payload, dict):
            return None
        order = payload.get("order")
        if not isinstance(order, list):
            return None
        if not all(isinstance(item, str) for item in order):
            return None
        return [str(item) for item in order]

    @staticmethod
    def _coerce_agent_names(
        agents: tuple[type[SwarmAgent], ...] | list[type[SwarmAgent]] | list[str] | Iterable[Any],
    ) -> list[str]:
        """Normalise agent-class tuple OR name list to a list[str]."""
        names: list[str] = []
        for item in agents:
            if isinstance(item, str):
                names.append(item)
            else:
                # SwarmAgent subclass — read the .name class attribute.
                name = getattr(item, "name", None)
                names.append(name if isinstance(name, str) else repr(item))
        return names

    @staticmethod
    def _cache_key(critic_feedback: str, agent_names: list[str]) -> str:
        """Stable key for the in-memory cache (gaps + agents tuple)."""
        payload = f"{critic_feedback}|{tuple(agent_names)!r}"
        return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()

    @staticmethod
    def _remap_names_to_classes(
        names: list[str],
        deterministic: tuple[type[SwarmAgent], ...],
    ) -> tuple[type[SwarmAgent], ...] | None:
        """Map LLM-returned name list back to ordered class tuple.

        Returns ``None`` (caller falls through) when:
        * the LLM returned any name not in the deterministic set, OR
        * the LLM omitted any agent from the deterministic set
          (subset returns are not a valid refinement — the spec says
          "do not add or remove agents"), OR
        * the LLM returned duplicates.

        This is a strict guard: a refined order must be a permutation
        of the deterministic order, nothing else.
        """
        det_by_name = {cls.name: cls for cls in deterministic}
        if len(names) != len(det_by_name):
            logger.warning(
                "architect.llm_reorder: returned %d agents but deterministic plan has %d; falling through",
                len(names),
                len(det_by_name),
            )
            return None
        if len(set(names)) != len(names):
            logger.warning("architect.llm_reorder: returned duplicate agents; falling through")
            return None
        if set(names) != set(det_by_name):
            unknown = sorted(set(names) - set(det_by_name))
            logger.warning(
                "architect.llm_reorder: returned unknown agent(s) %s; falling through",
                unknown,
            )
            return None
        return tuple(det_by_name[n] for n in names)
