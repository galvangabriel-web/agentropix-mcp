"""HuntAgent — cross-source correlation specialist.

Reads the Blackboard *after* the other four agents have published.
Promotes any token (filename, PID, hash) flagged by ≥2 agents into a
high-confidence correlation finding. Drives S-05 ("≥3 correlation
discrepancies flagged") in the W4 benchmark.

Unlike the other agents, HuntAgent does not call MCP tools; it operates
entirely on Blackboard state.
"""

from __future__ import annotations

from pathlib import Path

from agentropix_mcp.agents._base import Finding, SwarmAgent
from agentropix_mcp.agents._enrichment import enriched_finding
from agentropix_mcp._env import get_float

# Generic OS/evidence words that carry no forensic signal but appear
# in every agent's evidence strings (registry paths, diagnostic messages,
# image path components). Tokens matching this set are suppressed before
# HuntAgent creates hunt.correlate findings to avoid noise inflation.
_TOKEN_STOPWORDS: frozenset[str] = frozenset(
    {
        "accounts",
        "application",
        "autochk",
        "candidate",
        "command",
        "config",
        "data",
        "entry",
        "home",
        "image",
        "information",
        "inode",
        "manager",
        "metadata",
        "microsoft",
        "not",
        "parser",
        "path",
        "policy",
        "program",
        "s-1-5-18",
        "s-1-5-19",
        "s-1-5-20",
        "services",
        "skipped",
        "software",
        "system",
        "system32",
        "user",
        "wbem",
        "windows",
        "workspace",
    }
)


def _is_noise_token(token: str, image_frags: frozenset[str]) -> bool:
    """Return True if token should not generate a hunt.correlate finding."""
    t = token.lower()
    return len(t) < 4 or t in _TOKEN_STOPWORDS or t in image_frags


class HuntAgent(SwarmAgent):
    name = "hunt"
    completion_promise = "CROSS_AGENT_CORRELATION_DONE"  # M8.3d

    async def investigate(self, image: Path) -> list[Finding]:
        # Derive image-path fragments for noise filtering: tokens that are
        # substrings of the case image path (e.g. "analyst", "workspace",
        # "base-dc-cdrive.e01") appear in every agent's evidence and would
        # otherwise generate spurious correlations.
        _image_frags: frozenset[str] = frozenset(p.lower() for p in (*image.parts, image.stem, image.suffix))
        del image  # HuntAgent is otherwise image-independent
        confidence_cap = get_float(
            "AGENTROPIX_HUNT_CONFIDENCE_CAP",
            0.95,
            floor=0.0,
            ceiling=1.0,
        )
        confidence_bonus = get_float(
            "AGENTROPIX_HUNT_CONFIDENCE_BONUS",
            0.1,
            floor=0.0,
            ceiling=1.0,
        )
        correlations = self.blackboard.correlations()
        findings: list[Finding] = []
        for corr in correlations:
            if corr.token == "memory" or corr.token in {a for a, _ in self.blackboard.all}:
                continue  # skip the agent-name tokens themselves
            if _is_noise_token(corr.token, _image_frags):
                continue
            # A correlation whose agreeing findings are ALL zero-confidence is
            # not a real cross-source detection: it is shared text from
            # tool-error / diagnostic messages (e.g. an evtx_dump failure on a
            # non-Windows image emits the same "expected ElfFile0" vocabulary
            # from multiple detectors). Promoting it fabricates a positive
            # finding from error noise. Require at least one underlying finding
            # with real (confidence > 0) signal before promoting.
            if corr.max_confidence <= 0.0:
                continue
            raw = Finding(
                source="hunt.correlate",
                confidence=min(confidence_cap, corr.max_confidence + confidence_bonus),
                description=(
                    f"Cross-source agreement: '{corr.token}' flagged by "
                    f"{len(corr.agents)} agents ({', '.join(corr.agents)})"
                ),
                evidence=f"token={corr.token} agents={corr.agents} findings={corr.finding_count}",
                timestamp=Finding.now(),
                related_findings=corr.agents,
            )
            findings.append(enriched_finding(raw))
        return findings
