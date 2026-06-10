"""Base contract for the 7-agent DFIR swarm.

W2 (M2): every agent investigates a single dimension of the evidence
(memory, timeline, filesystem, artifacts) and publishes findings to a
shared Blackboard. A final HuntAgent correlates across the others.

The base class deliberately exposes no LLM coupling — agents are pure
async coroutines over the MCP boundary so they can be tested without
the Trinity Loop wired in. Trinity / Hippocampus integration lands on
top of this contract in W3.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from agentropix_mcp._env import get_int

if TYPE_CHECKING:
    from agentropix_mcp.agents._blackboard import Blackboard

logger = logging.getLogger(__name__)

# W-048: per-agent cap on the number of findings a single investigation may
# publish to the Blackboard. Prevents plaso / fls row-dumps from saturating
# the Critic's fingerprint space and bloating report JSON. The default
# (500) was chosen to stay well below 1% of observed DC-E01 emissions while
# leaving plenty of headroom for genuinely multi-hit agents (ArtifactAgent
# has its own internal per-source cap of 50, so even all three registry
# wrappers + amcache + shimcache stays under 500).
_DEFAULT_AGENT_FINDING_CAP = 500


class Finding(BaseModel):
    """A schema-compliant DFIR finding.

    Field `source` serializes to `_source` so `Finding.model_dump(by_alias=True)`
    produces a dict that satisfies report.schema.json. The leading-underscore
    name on the wire is a SANS convention (provenance fields are "private"
    metadata about the finding rather than analyst-authored content).
    """

    model_config = ConfigDict(populate_by_name=True)

    source: str = Field(alias="_source")
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    evidence: str = ""
    evidence_dict: dict[str, object] = Field(default_factory=dict)
    timestamp: str = ""
    mitre_attack: str = ""
    related_findings: list[str] = Field(default_factory=list)
    # Issue #10: optional SHA-256 of the byte payload behind this finding
    # (e.g. inode bytes for a T1105 staged-binary, dumped VAD bytes for a
    # malfind RWX hit). Lowercase hex; empty string when no payload was
    # captured. Kept off the wire when blank to preserve schema parity
    # for findings that don't carry a payload.
    file_sha256: str = ""
    # W-196: which SwarmAgent emitted this finding. Stamped by
    # SwarmAgent.run() before Blackboard publish. Empty string when the
    # finding was constructed outside the agent contract (tests, fixtures,
    # legacy report.json reloads). Enables per-agent recall measurement
    # that was previously impossible because findings only carried the
    # `source` field (which names the WRAPPER, not the AGENT).
    agent: str = ""

    def to_report_dict(self) -> dict[str, object]:
        # W-073: emit evidence_dict only when populated. Disk-side findings
        # that haven't migrated to typed evidence keep emitting only the
        # human-readable `evidence` string; memory-side wrappers (W-071)
        # populate evidence_dict for cross-modal IOC fusion. An empty dict
        # is dropped so the wire format stays clean for legacy consumers.
        d = self.model_dump(by_alias=True)
        if not d.get("evidence_dict"):
            d.pop("evidence_dict", None)
        if not d.get("file_sha256"):
            d.pop("file_sha256", None)
        # W-196: drop agent when blank to preserve wire compatibility with
        # legacy consumers / fixtures created outside the agent contract.
        if not d.get("agent"):
            d.pop("agent", None)
        return d

    @staticmethod
    def now() -> str:
        return datetime.now(UTC).isoformat()


class SwarmAgent(ABC):
    """Abstract base for a DFIR swarm agent.

    Subclasses set `name` and implement `investigate`. The base class
    handles publishing to the Blackboard so callers never see a finding
    that hasn't been recorded.

    BMAD-M8 Phase M8.3d (promise tokens): each agent declares a
    ``completion_promise`` string (e.g. ``"TIMELINE_GENERATED"``,
    ``"MEMORY_TRIAGED"``) that the orchestrator appends to
    ``report.completion_proofs`` whenever the agent's run produces ≥1
    Finding *without* a tool error. Promises serve as a verifiable
    completion contract — the Critic can fail a run that delivered a
    populated report but is missing a required promise (e.g. timeline
    analysis was scheduled but never completed). Default is ``None``
    (no promise). Subclasses opt-in by setting the class attribute.
    """

    name: str = ""
    completion_promise: str | None = None

    def __init__(self, blackboard: Blackboard) -> None:
        if not self.name:
            raise ValueError(f"{type(self).__name__} must set a class-level `name`")
        self.blackboard = blackboard

    @abstractmethod
    async def investigate(self, image: Path) -> list[Finding]:
        """Inspect the evidence and return any findings.

        Implementations must be idempotent — re-invoking on the same image
        with the same Blackboard state must produce the same findings list
        (S-08: same seed → identical trace).
        """

    async def run(self, image: Path) -> list[Finding]:
        """Investigate and publish; returns the findings for the caller.

        W-048: emissions are capped per-agent per-run via
        ``AGENTROPIX_AGENT_FINDING_CAP`` (default 500, floor 10, ceiling
        10000). When the cap is exceeded the lowest-confidence findings
        are dropped (confidence DESC order, stable by original position)
        and a WARNING is logged. The cap applies before Blackboard
        publication, so downstream trace counts and the Critic's
        fingerprint space never see the overflow.
        """
        findings = await self.investigate(image)
        findings = self._apply_finding_cap(findings)
        # W-196: stamp emitting agent so downstream report consumers can
        # compute per-agent recall (which was impossible before because
        # the `source` field names the wrapper, not the agent).
        for finding in findings:
            finding.agent = self.name
            await self.blackboard.publish(self.name, finding)
        return findings

    def _apply_finding_cap(self, findings: list[Finding]) -> list[Finding]:
        """Truncate ``findings`` to the configured per-agent cap.

        Ordering: sort by confidence DESC (stable on ties so the original
        ordering is preserved for equal-confidence items). Keep the top
        ``cap``; drop the tail. When anything is dropped, emit a WARNING
        log line naming the agent, the raw count, and the cap so operators
        running live triages see the suppression in stdout.
        """
        cap = get_int(
            "AGENTROPIX_AGENT_FINDING_CAP",
            _DEFAULT_AGENT_FINDING_CAP,
            floor=10,
            ceiling=10000,
        )
        if len(findings) <= cap:
            return findings
        # ``sorted`` is stable, so tied confidences keep their original
        # order — which preserves the investigate() narrative when the
        # agent was already emitting strongest-first.
        indexed = list(enumerate(findings))
        indexed.sort(key=lambda p: (-p[1].confidence, p[0]))
        kept = [f for _, f in indexed[:cap]]
        dropped = len(findings) - cap
        logger.warning(
            "agent %s: finding cap reached (%d kept, %d dropped via "
            "AGENTROPIX_AGENT_FINDING_CAP=%d) — lowest-confidence entries "
            "suppressed to protect Critic fingerprint space",
            self.name,
            cap,
            dropped,
            cap,
        )
        return kept
