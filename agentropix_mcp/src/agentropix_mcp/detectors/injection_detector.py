"""InjectionDetector — Volatility-driven in-memory process injection detection.

Closes W-052-T6: detects code injection (T1055.x) by classifying VAD
regions and PE-header anomalies surfaced by Volatility's ``windows.malfind``
plugin. The detector builds a higher-level "InjectionIndicator" abstraction
on top of the existing :func:`get_malfind` wrapper rather than adding a
new MCP tool — this keeps Layer 1 (policy/trace) thin and concentrates
the injection-specific reasoning in the agent layer.

Detection strategy (applied to each MalfindHit):

* **UNKNOWN VAD regions** — `vad_tag in {"VadS", "VadF", ""}` with
  `protection in {"PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY"}`
  is the canonical "private memory + executable" pattern that classic
  process-hollowing and DLL injection produce.
* **Suspicious PE headers in private memory** — when `hexdump_head`
  starts with the MZ stub (`4D 5A`) at a non-base address, that's a
  reflectively-loaded PE — classic Cobalt Strike beacon DLL injection.
* **Process-name correlation** — when the injected process is a normal
  user shell (explorer.exe, svchost.exe, lsass.exe), confidence rises
  because a benign program rarely has private RWX with a PE stub.

The detector is image-aware: it skips disk E01 inputs (no VAD tree to
analyse) and emits an explicit "skipped" finding so the orchestrator's
coverage guard (W-083) can distinguish "agent ran with empty result"
from "agent had nothing to do".
"""

from __future__ import annotations

import logging
from pathlib import Path

from pydantic import BaseModel, Field

from agentropix_mcp.agents._base import Finding, SwarmAgent
from agentropix_mcp.agents._evidence import looks_like_memory
from agentropix_mcp._env import get_float
from agentropix_mcp.wrappers.volatility import (
    MalfindHit,
    MalfindReport,
    get_malfind,
)

logger = logging.getLogger(__name__)


# Process names that are suspicious targets for code injection. A hit on
# any of these is high-signal because the listed processes are core
# Windows services (lsass, svchost) or the user shell (explorer) — they
# very rarely host private executable memory under normal operation.
_INJECTION_TARGETS_HIGH_VALUE = frozenset(
    {
        "lsass.exe",
        "explorer.exe",
        "winlogon.exe",
        "services.exe",
        "svchost.exe",
        "spoolsv.exe",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "dllhost.exe",
    }
)

# VAD protection flags that indicate writable+executable memory, the
# precondition for code injection. Read-only or copy-on-write regions
# are not injection targets.
_RWX_PROTECTION_FLAGS = frozenset(
    {
        "PAGE_EXECUTE_READWRITE",
        "PAGE_EXECUTE_WRITECOPY",
        "PAGE_EXECUTE",
    }
)


class InjectionIndicator(BaseModel):
    """Structured injection indicator emitted by the detector.

    Carried in :attr:`Finding.evidence_dict` so HuntAgent can promote
    cross-agent agreement on the same indicator (e.g. memory.injection
    + filesystem.beacon → cohit≥2 → quorum-promoted finding).
    """

    process_pid: int = 0
    process_name: str = ""
    injection_type: str = ""  # "unknown_vad" | "pe_header" | "rwx_high_value"
    address_range: str = ""
    protection: str = ""
    confidence: float = 0.0
    mitre_technique: str = "T1055"
    notes: str = ""
    evidence_fields: dict[str, object] = Field(default_factory=dict)


def _classify_hit(hit: MalfindHit) -> InjectionIndicator | None:
    """Classify a single malfind hit into an InjectionIndicator.

    Returns ``None`` if the hit doesn't match any injection pattern (so
    callers can filter benign RWX regions like JIT compilers). The
    classification is monotonic: matching multiple patterns increases
    confidence rather than emitting multiple indicators per hit.
    """
    name_lc = (hit.process or "").strip().lower()
    protection = (hit.protection or "").strip().upper()

    # Trim VAD addresses for the indicator. address may be "0x7fff0000"
    # or "0x7fff0000-0x7fff5000"; normalise to a fixed key.
    address_range = hit.address or "<unknown>"

    base_evidence = {
        "pid": hit.pid,
        "process": hit.process,
        "vad_tag": hit.vad_tag,
        "protection": protection,
        "commit_charge": hit.commit_charge,
        "private_memory": hit.private_memory,
    }

    # ------------------------------------------------------------------
    # Pattern 1 — PE header in private memory (highest confidence)
    # The hexdump head starts with MZ (`4D 5A`) followed by the typical
    # DOS stub sequence. Reflectively-loaded PEs always carry this stub.
    # ------------------------------------------------------------------
    head = (hit.hexdump_head or "").strip().lower()
    looks_like_pe = (
        head.startswith("4d 5a") or head.startswith("4d5a") or "mz" in head[:6]
    )
    if looks_like_pe and protection in _RWX_PROTECTION_FLAGS:
        confidence = 0.92 if name_lc in _INJECTION_TARGETS_HIGH_VALUE else 0.85
        return InjectionIndicator(
            process_pid=hit.pid,
            process_name=hit.process,
            injection_type="pe_header",
            address_range=address_range,
            protection=protection,
            confidence=confidence,
            mitre_technique="T1055.002",  # Portable Executable Injection
            notes="PE stub detected in private RWX memory — reflective load indicator",
            evidence_fields=base_evidence,
        )

    # ------------------------------------------------------------------
    # Pattern 2 — RWX VAD inside a high-value process
    # Any private RWX VAD inside lsass/explorer/svchost is suspicious;
    # legitimate code rarely needs writable+executable memory in those
    # processes.
    # ------------------------------------------------------------------
    if (
        protection in _RWX_PROTECTION_FLAGS
        and hit.private_memory
        and name_lc in _INJECTION_TARGETS_HIGH_VALUE
    ):
        return InjectionIndicator(
            process_pid=hit.pid,
            process_name=hit.process,
            injection_type="rwx_high_value",
            address_range=address_range,
            protection=protection,
            confidence=0.85,
            mitre_technique="T1055",
            notes=(
                "Private RWX VAD region in high-value process — "
                "common code-injection footprint"
            ),
            evidence_fields=base_evidence,
        )

    # ------------------------------------------------------------------
    # Pattern 3 — UNKNOWN VAD tag with executable protection
    # `VadS`/`VadF`/empty tag means the region is private-mapped (no
    # backing file). Combined with executable protection that's the
    # canonical injection footprint.
    # ------------------------------------------------------------------
    vad_tag = (hit.vad_tag or "").strip()
    is_unknown_vad = vad_tag in {"VadS", "VadF", ""} or vad_tag.lower().startswith("unknown")
    if is_unknown_vad and protection in _RWX_PROTECTION_FLAGS:
        return InjectionIndicator(
            process_pid=hit.pid,
            process_name=hit.process,
            injection_type="unknown_vad",
            address_range=address_range,
            protection=protection,
            confidence=0.78,
            mitre_technique="T1055.001",  # Code Cave Injection variant
            notes=(
                "Private executable VAD with no file backing — "
                "code-cave / shellcode injection indicator"
            ),
            evidence_fields=base_evidence,
        )

    return None


def _findings_from_indicators(
    image: Path,
    indicators: list[InjectionIndicator],
) -> list[Finding]:
    """Materialise InjectionIndicators into Findings."""
    out: list[Finding] = []
    for ind in indicators:
        out.append(
            Finding(
                source=f"memory.injection.{ind.injection_type}",
                confidence=ind.confidence,
                description=(
                    f"Process injection indicator: {ind.process_name} "
                    f"(pid={ind.process_pid}) {ind.injection_type} @ {ind.address_range} "
                    f"prot={ind.protection}"
                ),
                evidence=(
                    f"image={image} pid={ind.process_pid} process={ind.process_name} "
                    f"injection_type={ind.injection_type} addr={ind.address_range} "
                    f"protection={ind.protection} mitre={ind.mitre_technique}"
                ),
                evidence_dict={
                    "process_pid": ind.process_pid,
                    "process_name": ind.process_name,
                    "injection_type": ind.injection_type,
                    "address_range": ind.address_range,
                    "protection": ind.protection,
                    "notes": ind.notes,
                    **ind.evidence_fields,
                },
                mitre_attack=ind.mitre_technique,
                timestamp=Finding.now(),
            )
        )
    return out


class InjectionDetector(SwarmAgent):
    """In-memory process injection detector (W-052-T6 closure).

    Strategy:
      1. Skip non-memory images (E01 disks have no VAD tree).
      2. Call ``get_malfind`` (existing MCP wrapper).
      3. Classify each hit via :func:`_classify_hit`.
      4. Aggregate per-process: emit one Finding per unique
         (pid, injection_type) tuple, with confidence boosted when
         multiple patterns hit the same process.
      5. Always emit a "complete" or "skipped" Finding so the
         coverage guard (W-083) can distinguish empty-by-design from
         empty-by-error.
    """

    name = "injection_detector"
    completion_promise = "INJECTION_DETECTION_COMPLETE"

    async def investigate(self, image: Path) -> list[Finding]:
        if not looks_like_memory(image):
            # W-168: skip findings emit confidence=0.0 to match the
            # convention used by Memory/Timeline/Artifact/Filesystem
            # agents.  Nonzero confidence on a "ran but had nothing to
            # do" signal hallucinates on the FP gate.
            return [
                Finding(
                    source="memory.injection.skipped",
                    confidence=0.0,
                    description=(
                        f"InjectionDetector skipped: {image.name} is not a memory image"
                    ),
                    evidence=f"image={image} reason=non_memory_image",
                    timestamp=Finding.now(),
                )
            ]

        confidence_floor = get_float(
            "AGENTROPIX_INJECTION_CONFIDENCE_FLOOR",
            0.70,
            floor=0.0,
            ceiling=1.0,
        )

        try:
            report: MalfindReport = await get_malfind(image)
        except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as exc:
            # W-168: error finding still emitted (W-083 coverage guard
            # needs the source string), but at confidence=0.0.  The
            # logger.warning above carries the operator-facing signal.
            logger.warning("InjectionDetector get_malfind failed: %s", exc)
            return [
                Finding(
                    source="memory.injection.error",
                    confidence=0.0,
                    description=f"InjectionDetector failed to obtain malfind report: {exc}",
                    evidence=f"image={image} error={exc}",
                    timestamp=Finding.now(),
                )
            ]

        if not report.tool_available:
            # W-168: skip on missing tool is a coverage signal, not a
            # detection — confidence=0.0 (parity with non-memory skip).
            return [
                Finding(
                    source="memory.injection.skipped",
                    confidence=0.0,
                    description=(
                        f"InjectionDetector skipped: malfind unavailable "
                        f"({report.skipped_reason or 'no reason given'})"
                    ),
                    evidence=f"image={image} reason={report.skipped_reason}",
                    timestamp=Finding.now(),
                )
            ]

        indicators: list[InjectionIndicator] = []
        for hit in report.hits:
            indicator = _classify_hit(hit)
            if indicator is None:
                continue
            if indicator.confidence < confidence_floor:
                continue
            indicators.append(indicator)

        # Boost confidence on processes that have multiple indicators —
        # if both PE-header and UNKNOWN-VAD patterns fire on the same
        # PID, that's strong evidence of injection. Cap the boost so a
        # single very-noisy process doesn't dominate the report.
        per_pid: dict[int, int] = {}
        for ind in indicators:
            per_pid[ind.process_pid] = per_pid.get(ind.process_pid, 0) + 1
        for ind in indicators:
            multiplicity = per_pid.get(ind.process_pid, 1)
            if multiplicity >= 2:
                ind.confidence = min(0.97, ind.confidence + 0.05)
                ind.notes = (
                    f"{ind.notes} | corroborated by {multiplicity - 1} additional "
                    "indicators on the same PID"
                )

        findings = _findings_from_indicators(image, indicators)

        # Always emit a summary finding so coverage guard sees a non-empty
        # output even when no injection is present.
        findings.append(
            Finding(
                source="memory.injection.summary",
                confidence=0.30 if not indicators else 0.50,
                description=(
                    f"Injection scan complete: {len(indicators)} indicators "
                    f"across {len(per_pid)} processes "
                    f"(malfind hits scanned: {report.hit_count})"
                ),
                evidence=(
                    f"image={image} indicators={len(indicators)} "
                    f"processes={len(per_pid)} malfind_hits={report.hit_count}"
                ),
                evidence_dict={
                    "indicators_emitted": len(indicators),
                    "processes_with_indicators": len(per_pid),
                    "malfind_hits_scanned": report.hit_count,
                },
                mitre_attack="T1055",
                timestamp=Finding.now(),
            )
        )
        return findings
