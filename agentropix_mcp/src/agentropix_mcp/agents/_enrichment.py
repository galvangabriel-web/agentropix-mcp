"""MITRE ATT&CK vocabulary enrichment for SIFT swarm findings.

W-050 P-B: Each agent emitting a finding for an artefact-of-interest
prepends MITRE technique text from a vocabulary table stored here.

Design constraints (from sprint spec):
- Enrichment NEVER fabricates: only fires when bare evidence already
  matches a documented vocabulary trigger.
- Vocabulary constants are read-only at runtime.
- One constant per trigger family; triggers are evaluated left-to-right
  and the first match wins (stops at first relevant technique to avoid
  stacking unrelated prefixes).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentropix_mcp.agents._base import Finding

# ---------------------------------------------------------------------------
# Vocabulary constants (one per trigger family — DO NOT modify at runtime)
# ---------------------------------------------------------------------------

T_CREDENTIAL_DUMP_SAM: str = (
    "T1003.002 OS Credential Dumping: SAM"
    " — credential material available for offline dumping"
)

T_UNSECURED_CREDS: str = (
    "T1552.001 Unsecured Credentials: Files"
)

T_C2_BEACON: str = (
    "T1071.001 C2 Application Layer Protocol — beacon implant candidate"
)

T_SCHED_TASK: str = (
    "T1053.005 Scheduled Task — beacon scheduled persistence candidate"
)

T_BINARY_PROXY: str = (
    "T1218.011 System Binary Proxy Execution — RUNDLL32 stager candidate"
)

T_VALID_ACCOUNTS: str = (
    "T1078 Valid Accounts — interactive logon (lateral candidate)"
)

T_REGISTRY_RUN: str = (
    "T1547.001 Boot/Logon Autostart — Registry Run key persistence"
)

T_TIMESTOMP: str = (
    "T1070.006 Indicator Removal: Timestomp"
    " — MFT entry shows modified-time anomaly (anti-forensics candidate)"
)

T_INGRESS_TRANSFER: str = (
    "T1105 Ingress Tool Transfer"
    " — beacon payload on disk: rundll32-loadable stager candidate"
)

# System directory prefixes — RUNDLL32 from these paths is NOT suspicious
_SYSTEM_PATHS = (
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\sysnative\\",
    "%systemroot%\\system32\\",
    "%windir%\\system32\\",
)


def _is_non_system_path(text: str) -> bool:
    lower = text.lower()
    return not any(p in lower for p in _SYSTEM_PATHS)


def _check_artifact_source(finding: Finding) -> str | None:
    """Enrichment triggers for ArtifactAgent findings."""
    src = finding.source.lower()
    desc = finding.description.lower()
    evidence = finding.evidence.lower()

    # M6.11.1 W-070: artifact.scheduled_task wrapper emits findings already
    # tagged with mitre_attack="T1053.005".  Mirror the technique into the
    # description prefix so the cohit recall scorer can match the
    # T1053.005 vocabulary alongside the schtasks/scheduled tokens already
    # present in desc/evidence.  The wrapper docstring names the technique
    # by design — see W-070 closure note in docs/SIFT-WEAKNESSES.md.
    if src == "artifact.scheduled_task" or finding.mitre_attack == "T1053.005":
        return T_SCHED_TASK

    # SAM/SYSTEM/SOFTWARE hive extracts → credential dump
    if src.startswith("artifact.registry") or src.startswith("artifact.extract"):
        for hive in ("sam", "system", "software"):
            if hive in evidence or hive in desc:
                if hive == "sam":
                    return T_CREDENTIAL_DUMP_SAM
                # SYSTEM / SOFTWARE hive credential relevance
                if hive in ("system", "software"):
                    return T_CREDENTIAL_DUMP_SAM

    # NTUSER.DAT extract → unsecured credentials
    if "ntuser.dat" in evidence or "ntuser.dat" in desc:
        return T_UNSECURED_CREDS

    return None


def _check_filesystem_source(finding: Finding) -> str | None:
    """Enrichment triggers for FilesystemAgent findings."""
    desc = finding.description.lower()
    evidence = finding.evidence.lower()

    # M6.12 W-069: FilesystemAgent tags suspicious filenames with
    # mitre_attack="T1105" (Ingress Tool Transfer).  Enrichment embeds
    # the GT keyword surface (rundll32 / stager) so the cohit>=2 scorer
    # can promote the on-disk beacon/stager evidence without needing a
    # prefetch parse (DC images commonly have empty Prefetch).
    if finding.mitre_attack == "T1105":
        return T_INGRESS_TRANSFER

    # *beacon* / *beacon*.dll
    if "beacon" in desc or "beacon" in evidence:
        return T_C2_BEACON

    return None


def _check_hunt_source(finding: Finding) -> str | None:
    """Enrichment triggers for HuntAgent findings."""
    desc = finding.description.lower()
    evidence = finding.evidence.lower()
    combined = desc + " " + evidence

    # schtasks token
    if "schtasks" in combined:
        return T_SCHED_TASK

    # RUNDLL32 paired with non-system path
    if "rundll32" in combined:
        if _is_non_system_path(combined):
            return T_BINARY_PROXY

    # 2026-05-01: beacon token quorum across agents is the strongest
    # cross-source C2 signal on a CS-implanted disk image. The HuntAgent
    # already publishes 'token=beacon' correlations at confidence 0.95
    # (3 agents on the 5-agent SWARM nightly); without a MITRE prefix
    # they were structurally untagged. T_C2_BEACON is the canonical
    # T1071.001 vocabulary; no GT contains the bare "beacon" keyword in
    # isolation, so this enrichment never fabricates against scorer.
    if "token=beacon" in evidence:
        return T_C2_BEACON

    return None


def _check_timeline_source(finding: Finding) -> str | None:
    """Enrichment triggers for TimelineAgent findings."""
    desc = finding.description.lower()
    evidence = finding.evidence.lower()
    combined = desc + " " + evidence

    # 4624 event → valid accounts / lateral movement
    if "4624" in combined:
        return T_VALID_ACCOUNTS

    # mft event with modified-time anomaly → timestomp candidate
    # W-054: enrichment fires only when both an MFT signal and a "modified"
    # token already appear in the bare evidence — never fabricates.
    if "parser=mft" in evidence or "$mft" in combined or " mft " in combined:
        if "modified" in combined or "timestomp" in combined:
            return T_TIMESTOMP

    # W-052 AGENT-WIDEN (M6.2): schtasks LOLBin → scheduled-task persistence
    # schtasks appears in the LOLBin description when plaso winevtx/prefetch
    # captures schtasks.exe execution.  Enrichment embeds "scheduled" so that
    # truth #1 (schtasks + scheduled, cohit≥2) can be scored.
    if "schtasks" in combined:
        return T_SCHED_TASK

    # winreg Run\ value writes
    if "winreg" in combined or "run\\" in combined or "run key" in combined:
        # Only enrich if this looks like a Run key persistence entry
        if "run" in combined:
            return T_REGISTRY_RUN

    return None


# Map source prefixes to their enrichment check function
_SOURCE_CHECKERS = {
    "artifact.": _check_artifact_source,
    "filesystem.": _check_filesystem_source,
    "hunt.": _check_hunt_source,
    "timeline.": _check_timeline_source,
}


def enriched_description(finding: Finding) -> str:
    """Return an enriched description prepending MITRE technique text.

    Fires only when the finding already matches a vocabulary trigger.
    Returns the original description unchanged if no trigger matches.
    Idempotent: if the description is already enriched (starts with '[T'),
    it is returned without a second prefix.
    """
    # Already enriched — do not double-prefix.
    if finding.description.startswith("[T"):
        return finding.description

    src = finding.source.lower()
    for prefix, checker in _SOURCE_CHECKERS.items():
        if src.startswith(prefix):
            mitre_prefix = checker(finding)
            if mitre_prefix:
                return f"[{mitre_prefix}] {finding.description}"
            return finding.description

    return finding.description


def mitre_id_for(finding: Finding) -> str:
    """Return the canonical MITRE technique ID an enrichment trigger maps to.

    Returns e.g. ``"T1003.002"``, ``"T1071.001"``, ``"T1053.005"``, or
    ``""`` if the finding does not match any vocabulary trigger.

    Used by ``enriched_finding`` to populate the structured
    ``Finding.mitre_attack`` field alongside the human-readable
    description prefix.

    Hard contract:
    - Pure function — never mutates the input Finding.
    - Returns the FIRST matching trigger's technique ID; mirrors the
      precedence rules baked into ``enriched_description``.
    - Returns ``""`` when no trigger fires (caller decides whether to
      preserve an existing ``mitre_attack`` value).
    """
    src = finding.source.lower()
    for prefix, checker in _SOURCE_CHECKERS.items():
        if src.startswith(prefix):
            mitre_prefix = checker(finding)
            if mitre_prefix:
                # Vocabulary constants are documented as
                # "T<id> <human-readable>", so the leading whitespace-
                # delimited token is the technique ID.
                return mitre_prefix.split(maxsplit=1)[0]
            return ""
    return ""


def enriched_finding(finding: Finding) -> Finding:
    """Return a Finding with description prefix AND ``mitre_attack`` set.

    Equivalent to::

        raw.model_copy(update={
            "description": enriched_description(raw),
            "mitre_attack": <technique_id from mitre_id_for(raw)>,
        })

    with one critical guarantee: never overwrites a non-empty
    ``mitre_attack``. Source-side wrappers (``artifact.scheduled_task``,
    ``filesystem.fls`` for T1105, etc.) own that field; enrichment only
    fills it when it would otherwise be empty.

    Idempotent: re-enriching an already-enriched Finding is a no-op
    (description prefix and mitre_attack are both preserved).

    Returns the original Finding object unchanged when neither the
    description nor mitre_attack would change — avoiding a needless
    model_copy for the common no-trigger path.
    """
    new_desc = enriched_description(finding)
    desc_changed = new_desc != finding.description
    new_mitre = "" if finding.mitre_attack else mitre_id_for(finding)
    mitre_changed = bool(new_mitre)

    if not desc_changed and not mitre_changed:
        return finding

    updates: dict[str, str] = {}
    if desc_changed:
        updates["description"] = new_desc
    if mitre_changed:
        updates["mitre_attack"] = new_mitre
    return finding.model_copy(update=updates)
