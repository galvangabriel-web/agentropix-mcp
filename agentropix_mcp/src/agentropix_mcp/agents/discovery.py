"""DiscoveryAgent (issue #39) -- detect MITRE Discovery techniques
(T1018, T1069, T1083, T1087, T1135) from EID 4688 process-creation
events already on the Blackboard from TimelineAgent's plaso pass.

Does NOT re-run plaso. Reads self.blackboard.all for timeline.plaso
findings that embed winevtx EID 4688 evidence, then matches the Strings
array against per-technique regex patterns.

Only runs on disk images (looks_like_memory -> early return []).

Tunables:
* AGENTROPIX_DISC_MAX_EVENTS  (int, default 10000, [100, 500000])
* AGENTROPIX_DISC_MIN_CONFIDENCE (float, default 0.65, [0.3, 1.0])
"""

from __future__ import annotations

import logging
from pathlib import Path

from agentropix_mcp.agents._base import Finding, SwarmAgent
from agentropix_mcp.agents._discovery_detectors import detect_discovery, parse_4688_strings
from agentropix_mcp.agents._evidence import looks_like_memory
from agentropix_mcp._env import get_float, get_int

logger = logging.getLogger(__name__)


class DiscoveryAgent(SwarmAgent):
    name = "discovery"
    completion_promise = "DISCOVERY_ENUMERATED"  # M8.3d

    async def investigate(self, image: Path) -> list[Finding]:
        if looks_like_memory(image):
            return []

        max_events = get_int(
            "AGENTROPIX_DISC_MAX_EVENTS",
            10000,
            floor=100,
            ceiling=500000,
        )
        min_conf = get_float(
            "AGENTROPIX_DISC_MIN_CONFIDENCE",
            0.65,
            floor=0.3,
            ceiling=1.0,
        )

        # Collect EID 4688 process pairs from Blackboard timeline findings
        process_pairs: list[tuple[str, str]] = []
        for _agent_name, finding in self.blackboard.all:
            if finding.source != "timeline.plaso":
                continue
            evidence = finding.evidence or ""
            if "4688" not in evidence:
                continue
            proc, cmdline = parse_4688_strings(evidence)
            if proc:
                process_pairs.append((proc, cmdline))
            if len(process_pairs) >= max_events:
                break

        logger.debug(
            "DiscoveryAgent: scanned %d EID-4688 process pairs from Blackboard",
            len(process_pairs),
        )

        hits = detect_discovery(process_pairs)

        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for technique_id, description, confidence in hits:
            if confidence < min_conf:
                continue
            key = (technique_id, description[:80])
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    source="discovery.4688",
                    confidence=confidence,
                    description=f"[{technique_id}] {description}",
                    evidence=f"image={image} technique={technique_id}",
                    evidence_dict={"technique": technique_id, "image": str(image)},
                    mitre_attack=technique_id,
                    timestamp=Finding.now(),
                )
            )

        return findings
