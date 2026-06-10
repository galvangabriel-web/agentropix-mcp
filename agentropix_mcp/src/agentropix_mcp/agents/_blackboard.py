"""Shared Blackboard for cross-agent finding aggregation and quorum.

Each swarm agent publishes Finding objects keyed by agent name. The
Blackboard is the only mutable state shared between agents — it carries
the asyncio.Lock, so individual agents are free to be lock-free.

Quorum: a "correlation" is raised when >=N distinct agents publish
findings whose `evidence` strings share a normalized token (filename,
PID, URL, hash). This is the W2 substrate for S-05 ("≥3 correlation
discrepancies flagged").
"""

from __future__ import annotations

import asyncio
import os
import re
from collections import defaultdict

from pydantic import BaseModel

from agentropix_mcp.agents._base import Finding
from agentropix_mcp._env import get_int


# W-018: security-relevant short tokens that must correlate regardless of
# the ``AGENTROPIX_TOKEN_MIN_LENGTH`` floor.  Default list covers common
# 2-char identifiers ("pe" = Portable Executable, "ps" = PowerShell) and
# cipher/protocol names operators routinely investigate.  Operators can
# extend or narrow via ``AGENTROPIX_TOKEN_ALLOWLIST`` (comma-separated,
# case-insensitive — empty string disables the allowlist).
_DEFAULT_SHORT_TOKEN_ALLOWLIST = "pe,ps,rc4,asm,cs,rdp,iis,ftp"


def _short_token_allowlist() -> frozenset[str]:
    """Return the configured short-token allowlist as a lowercase set."""
    raw = os.environ.get(
        "AGENTROPIX_TOKEN_ALLOWLIST", _DEFAULT_SHORT_TOKEN_ALLOWLIST
    )
    return frozenset(
        t.strip().lower() for t in raw.split(",") if t.strip()
    )


def _token_pattern() -> re.Pattern[str]:
    min_len = get_int("AGENTROPIX_TOKEN_MIN_LENGTH", 3, floor=1, ceiling=10)
    return re.compile(rf"[A-Za-z0-9_.\-]{{{min_len},}}")


def _short_token_pattern() -> re.Pattern[str] | None:
    """Return a regex that ORs together the allowlist, or None if empty.

    Built with word boundaries so ``pe`` matches ``PE.exe`` but not
    ``append`` and ``ps`` matches ``ps.exe`` but not ``perhaps``.
    """
    allowlist = _short_token_allowlist()
    if not allowlist:
        return None
    # Sort longest-first so overlapping tokens (``rc4`` vs ``rc``) match
    # greedily; escape each so any dot / hyphen is literal.
    alts = "|".join(sorted((re.escape(t) for t in allowlist), key=len, reverse=True))
    return re.compile(rf"(?<![A-Za-z0-9_])(?:{alts})(?![A-Za-z0-9_])", re.IGNORECASE)


class Correlation(BaseModel):
    """Cross-agent agreement on a single artifact token."""

    token: str
    agents: list[str]
    finding_count: int
    max_confidence: float


class Blackboard:
    """Thread-safe (asyncio) finding registry with quorum detection.

    The optional ``config`` attribute carries the per-run configuration dict
    produced by ``mcp_server.config.load_config()`` so agents can read tuning
    knobs without a new constructor parameter (W-030 plumbing). Always a
    ``dict`` — empty when no config has been loaded so call sites can use
    ``self.blackboard.config.get(...)`` unconditionally.
    """

    def __init__(
        self,
        quorum_threshold: int = 2,
        *,
        config: dict | None = None,
    ) -> None:
        if quorum_threshold < 2:
            raise ValueError("quorum_threshold must be >= 2 to mean 'multiple agents'")
        self._lock = asyncio.Lock()
        self._entries: list[tuple[str, Finding]] = []
        self._quorum_threshold = quorum_threshold
        self.config: dict = dict(config) if config else {}

    async def publish(self, agent: str, finding: Finding) -> None:
        async with self._lock:
            self._entries.append((agent, finding))

    @property
    def all(self) -> list[tuple[str, Finding]]:
        return list(self._entries)

    def by_agent(self, agent: str) -> list[Finding]:
        return [f for a, f in self._entries if a == agent]

    def correlations(self) -> list[Correlation]:
        """Return tokens that appear in evidence strings of >=quorum agents."""
        token_index: dict[str, dict[str, list[Finding]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for agent, finding in self._entries:
            for token in _extract_tokens(finding):
                token_index[token][agent].append(finding)

        correlations: list[Correlation] = []
        for token, by_agent in token_index.items():
            if len(by_agent) < self._quorum_threshold:
                continue
            all_findings = [f for fs in by_agent.values() for f in fs]
            correlations.append(
                Correlation(
                    token=token,
                    agents=sorted(by_agent.keys()),
                    finding_count=len(all_findings),
                    max_confidence=max(f.confidence for f in all_findings),
                )
            )
        correlations.sort(key=lambda c: (-c.max_confidence, c.token))
        return correlations


def _extract_tokens(finding: Finding) -> set[str]:
    """Pull substantive tokens (filenames, PIDs, hashes) out of a finding.

    W-018: also emits allowlisted short tokens (``pe``, ``ps``, ``rc4`` …)
    so correlations are not silently lost for 2-char security-relevant
    identifiers that fall below ``AGENTROPIX_TOKEN_MIN_LENGTH``.
    """
    haystack = f"{finding.evidence} {finding.description}"
    tokens = {m.group(0).lower() for m in _token_pattern().finditer(haystack)}
    short_re = _short_token_pattern()
    if short_re is not None:
        tokens.update(m.group(0).lower() for m in short_re.finditer(haystack))
    return {t for t in tokens if t != "none"}
