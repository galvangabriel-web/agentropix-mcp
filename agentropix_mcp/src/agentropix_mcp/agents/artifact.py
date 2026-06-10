"""ArtifactAgent — chain-of-custody and registry/execution-evidence specialist.

For E01/EWF images, calls ``mcp_get_image_info`` to emit a provenance
finding and then (M4 / W-028) chains ``mcp_extract_files`` → registry
wrappers so ``regripper`` / ``amcache_parser`` / ``shimcache_parser``
can fire on raw E01 content. The agent owns the orchestration of
extract-then-parse; the MCP surface stays SRP-clean.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path

from agentropix_mcp.agents._base import Finding, SwarmAgent
from agentropix_mcp.agents._enrichment import enriched_finding
from agentropix_mcp.agents._evidence import looks_like_e01
from agentropix_mcp.agents._hive_presets import AMCACHE, REGISTRY_HIVES
from agentropix_mcp._env import get_float, get_int
from agentropix_mcp.server import (
    ToolError,
    mcp_extract_files,
    mcp_get_amcache,
    mcp_get_image_info,
    mcp_get_registry,
    mcp_get_shimcache,
)
from agentropix_mcp.wrappers.extract import ExtractManifest
from agentropix_mcp.wrappers.scheduled_tasks import (
    TaskSpec,
    list_task_paths,
    parse_task_xml,
)

logger = logging.getLogger(__name__)


def _extract_enabled() -> bool:
    raw = os.environ.get("AGENTROPIX_ARTIFACT_EXTRACT", "1").strip().lower()
    return raw in ("1", "true", "yes", "on")


def _finding_conf() -> float:
    return get_float(
        "AGENTROPIX_ARTIFACT_COC_CONFIDENCE",
        0.5,
        floor=0.0,
        ceiling=1.0,
    )


def _suspicious_conf() -> float:
    return get_float(
        "AGENTROPIX_ARTIFACT_SUSPICIOUS_CONFIDENCE",
        0.6,
        floor=0.0,
        ceiling=1.0,
    )


def _max_registry_entries() -> int:
    return get_int(
        "AGENTROPIX_ARTIFACT_MAX_ENTRIES",
        50,
        floor=1,
        ceiling=10000,
    )


def _tasks_enabled() -> bool:
    raw = os.environ.get("AGENTROPIX_ARTIFACT_TASKS_ENABLED", "1").strip().lower()
    return raw in ("1", "true", "yes", "on")


def _max_tasks() -> int:
    return get_int(
        "AGENTROPIX_ARTIFACT_MAX_TASKS",
        500,
        floor=1,
        ceiling=10000,
    )


class ArtifactAgent(SwarmAgent):
    name = "artifact"
    completion_promise = "ARTIFACTS_PARSED"  # M8.3d

    async def investigate(self, image: Path) -> list[Finding]:
        if not looks_like_e01(image):
            return []

        findings: list[Finding] = []
        findings.extend(await self._chain_of_custody(image))

        if _extract_enabled():
            findings.extend(await self._extract_and_parse(image))

        if _tasks_enabled():
            findings.extend(await self._scan_scheduled_tasks(image))

        return findings

    async def _chain_of_custody(self, image: Path) -> list[Finding]:
        result = await mcp_get_image_info(str(image))
        if isinstance(result, ToolError):
            return [
                Finding(
                    source="artifact.ewfinfo",
                    confidence=0.0,
                    description=f"ewfinfo failed: {result.error}",
                    evidence=f"image={image}",
                )
            ]
        return [
            Finding(
                source="artifact.ewfinfo",
                confidence=_finding_conf(),
                description=(f"Evidence chain: case={result.case_number} examiner={result.examiner}"),
                evidence=(f"md5={result.md5} sha1={result.sha1} acquired={result.acquisition_date}"),
                timestamp=result.acquisition_date or Finding.now(),
            )
        ]

    async def _extract_and_parse(self, image: Path) -> list[Finding]:
        """Chain ``mcp_extract_files`` → registry / amcache wrappers."""
        with tempfile.TemporaryDirectory(prefix="agentropix-sift-extract-") as td:
            tmp = Path(td)
            preset_paths = list(REGISTRY_HIVES) + [AMCACHE]

            manifest = await mcp_extract_files(
                str(image),
                preset_paths,
                str(tmp),
            )
            if isinstance(manifest, ToolError):
                logger.info("extract_files failed: %s", manifest.error)
                return [
                    Finding(
                        source="artifact.extract",
                        confidence=0.0,
                        description=f"extract_files failed: {manifest.error}",
                        evidence=f"image={image}",
                    )
                ]

            findings: list[Finding] = []
            for row in manifest.extracted:
                raw = Finding(
                    source="artifact.extract",
                    confidence=_finding_conf(),
                    description=(f"Extracted {row.src_path} ({row.size}B) from evidence"),
                    evidence=f"sha256={row.sha256} inode={row.inode} dest={row.dest}",
                )
                findings.append(enriched_finding(raw))

            findings.extend(await self._parse_extracted(manifest))
            return findings

    async def _parse_extracted(
        self,
        manifest: ExtractManifest,
    ) -> list[Finding]:
        findings: list[Finding] = []
        by_name: dict[str, str] = {Path(row.src_path).name.upper(): row.dest for row in manifest.extracted}

        # Registry hives → regripper
        for hive_name in ("SOFTWARE", "SYSTEM", "SAM", "SECURITY"):
            dest = by_name.get(hive_name)
            if not dest:
                continue
            result = await mcp_get_registry(dest)
            if isinstance(result, ToolError):
                continue
            findings.extend(self._registry_findings(hive_name, result))

        # Amcache.hve → amcache_parser.  A "tool unavailable" sentinel
        # report (``tool_available=False``) is a clean skip, not a
        # failure: no finding, no ``ERROR:`` in the trace (M6.4).
        amcache_dest = by_name.get("AMCACHE.HVE")
        if amcache_dest:
            amcache_result = await mcp_get_amcache(amcache_dest)
            if not isinstance(amcache_result, ToolError) and getattr(
                amcache_result, "tool_available", True
            ):
                findings.extend(self._amcache_findings(amcache_result))

        # Shimcache lives inside the SYSTEM hive — same skip contract
        # as amcache above.
        system_dest = by_name.get("SYSTEM")
        if system_dest:
            shim_result = await mcp_get_shimcache(system_dest)
            if not isinstance(shim_result, ToolError) and getattr(
                shim_result, "tool_available", True
            ):
                findings.extend(self._shimcache_findings(shim_result))

        return findings

    def _registry_findings(
        self,
        hive_name: str,
        result: object,
    ) -> list[Finding]:
        entries = getattr(result, "entries", []) or []
        cap = _max_registry_entries()
        findings: list[Finding] = []
        for entry in entries[:cap]:
            plugin = getattr(entry, "plugin", "")
            summary = getattr(entry, "summary", "") or getattr(entry, "raw", "")[:200]
            if not plugin:
                continue
            raw = Finding(
                source=f"artifact.registry.{plugin}",
                confidence=_finding_conf(),
                description=(f"{hive_name}: {plugin} {summary[:120]}").strip(),
                evidence=f"hive={hive_name} plugin={plugin}",
            )
            findings.append(enriched_finding(raw))
        return findings

    def _amcache_findings(self, report: object) -> list[Finding]:
        entries = getattr(report, "entries", []) or []
        cap = _max_registry_entries()
        findings: list[Finding] = []
        for entry in entries[:cap]:
            path = getattr(entry, "path", "")
            sha1 = getattr(entry, "sha1", "")
            if not path:
                continue
            findings.append(
                Finding(
                    source="artifact.amcache",
                    confidence=_finding_conf(),
                    description=f"Amcache: {path}",
                    evidence=f"sha1={sha1} last_modified={getattr(entry, 'last_modified', '')}",
                )
            )
        return findings

    def _shimcache_findings(self, report: object) -> list[Finding]:
        entries = getattr(report, "entries", []) or []
        cap = _max_registry_entries()
        findings: list[Finding] = []
        for entry in entries[:cap]:
            path = getattr(entry, "path", "")
            if not path:
                continue
            executed = getattr(entry, "executed", False)
            findings.append(
                Finding(
                    source="artifact.shimcache",
                    confidence=_suspicious_conf() if executed else _finding_conf(),
                    description=f"Shimcache: {path}" + (" (executed)" if executed else ""),
                    evidence=f"last_modified={getattr(entry, 'last_modified', '')}",
                )
            )
        return findings

    async def _scan_scheduled_tasks(self, image: Path) -> list[Finding]:
        """M6.11 W-068 — enumerate Windows/System32/Tasks XML, emit per-task Finding.

        Closes the T1053.005 structural no-fire gap that left recall
        at 5/7 through M6.10. Each finding's evidence/description
        carries ``schtasks``, ``scheduled``, task name, and command so
        the cohit≥2 scorer can promote the GT entry.
        """
        try:
            paths = await list_task_paths(image)
        except (FileNotFoundError, TimeoutError, RuntimeError) as exc:
            logger.info("Task enumeration failed: %s", exc)
            return []
        if not paths:
            return []

        paths = paths[: _max_tasks()]

        findings: list[Finding] = []
        with tempfile.TemporaryDirectory(prefix="agentropix-sift-tasks-") as td:
            tmp = Path(td)
            for src_path in paths:
                manifest = await mcp_extract_files(str(image), [src_path], str(tmp))
                if isinstance(manifest, ToolError):
                    continue
                for row in manifest.extracted:
                    try:
                        data = Path(row.dest).read_bytes()
                    except OSError:
                        continue
                    spec = parse_task_xml(data)
                    if spec is None:
                        continue
                    spec.container_path = src_path
                    findings.append(self._task_finding(spec))
                    try:
                        Path(row.dest).unlink()
                    except OSError:
                        pass
        return findings

    def _task_finding(self, spec: TaskSpec) -> Finding:
        display_name = spec.name or Path(spec.container_path.rstrip("/")).name or "(unnamed)"
        triggers_txt = ",".join(spec.triggers) if spec.triggers else "none"
        desc = (
            f"Scheduled task (schtasks) {display_name}:"
            f" command={spec.command or '(empty)'}"
            f" triggers={triggers_txt}"
        )
        evidence = (
            f"schtasks path={spec.container_path}"
            f" author={spec.author or '(none)'}"
            f" args={spec.arguments[:200]}"
            f" run_level={spec.run_level or '(none)'}"
            f" user={spec.user_id or '(none)'}"
        )
        raw = Finding(
            source="artifact.scheduled_task",
            confidence=_finding_conf(),
            description=desc,
            evidence=evidence,
            mitre_attack="T1053.005",
        )
        return enriched_finding(raw)
