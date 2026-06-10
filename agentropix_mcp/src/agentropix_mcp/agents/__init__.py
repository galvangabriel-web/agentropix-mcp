"""DFIR Swarm — eleven specialist agents writing to a shared Blackboard.

Public surface (W2 / M2 + W-052 W3 + issue #39 + W-204 + W-205):
    Blackboard, Correlation, Finding, SwarmAgent
    MemoryAgent, TimelineAgent, FilesystemAgent, ArtifactAgent
    DiscoveryAgent                                       (issue #39)
    YARAHuntAgent, InjectionDetector          (W-052-T2 / T6 closure)
    AccessibilityIfeoHijackDetector                      (W-204 T1546.008)
    IexLoopbackC2Detector                                (W-205 T1059.001)
    T1071SvchostOutboundHttpDetector                     (W-213 T1071.001)
    HuntAgent
    SWARM        -- ordered tuple of agent classes for the standard run

Run order matters: HuntAgent must execute LAST because it consumes the
findings the other agents publish. The W-052 detectors (YARAHuntAgent,
InjectionDetector) and the W-204/W-205 detectors sit between the four
MVP specialists and HuntAgent so their findings are on the Blackboard
when HuntAgent computes correlations. DiscoveryAgent (issue #39) sits
between ArtifactAgent and MailAgent so it can read EID 4688 events
already published by TimelineAgent.
"""

from agentropix_mcp.agents._base import Finding, SwarmAgent
from agentropix_mcp.agents._blackboard import Blackboard, Correlation
from agentropix_mcp.agents.artifact import ArtifactAgent
from agentropix_mcp.agents.discovery import DiscoveryAgent
from agentropix_mcp.agents.filesystem import FilesystemAgent
from agentropix_mcp.agents.hunt import HuntAgent
from agentropix_mcp.agents.mail import MailAgent
from agentropix_mcp.agents.memory import MemoryAgent
from agentropix_mcp.agents.timeline import TimelineAgent
from agentropix_mcp.detectors.injection_detector import InjectionDetector
from agentropix_mcp.detectors.t1059_001_iex_loopback_c2 import IexLoopbackC2Detector
from agentropix_mcp.detectors.t1071_001_svchost_outbound_http import (
    T1071SvchostOutboundHttpDetector,
)
from agentropix_mcp.detectors.t1546_008_accessibility_ifeo_hijack import (
    AccessibilityIfeoHijackDetector,
)
from agentropix_mcp.detectors.t1087_002_null_session_baseline import (
    NullSessionBaselineAgent,
)
from agentropix_mcp.detectors.yara_hunt import YARAHuntAgent

SWARM: tuple[type[SwarmAgent], ...] = (
    MemoryAgent,
    TimelineAgent,
    FilesystemAgent,
    ArtifactAgent,
    DiscoveryAgent,
    NullSessionBaselineAgent,
    MailAgent,
    YARAHuntAgent,
    InjectionDetector,
    AccessibilityIfeoHijackDetector,
    IexLoopbackC2Detector,
    T1071SvchostOutboundHttpDetector,
    HuntAgent,
)

__all__ = [
    "SWARM",
    "AccessibilityIfeoHijackDetector",
    "ArtifactAgent",
    "Blackboard",
    "Correlation",
    "DiscoveryAgent",
    "Finding",
    "FilesystemAgent",
    "HuntAgent",
    "IexLoopbackC2Detector",
    "InjectionDetector",
    "MailAgent",
    "MemoryAgent",
    "NullSessionBaselineAgent",
    "SwarmAgent",
    "T1071SvchostOutboundHttpDetector",
    "TimelineAgent",
    "YARAHuntAgent",
]
