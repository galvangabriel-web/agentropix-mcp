"""Case inventory loader — walks a case directory and builds typed IOCRecords.

FR-1: Enumerate all IOCs across an Agentropix case directory and produce
a typed IOCInventory.

This module reads structured JSON from the case directory but does NOT
re-run any forensic agents. It relies on previously-generated outputs.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from agentropix_mcp.wazuh.models import (
    IOCInventory,
    IOCProvenance,
    IPIOCRecord,
    MD5IOCRecord,
    ProcessImageIOCRecord,
    ProcessIOCRecord,
    ProcessModuleIOCRecord,
    ProcessTreeEventIOCRecord,
    RegistryIOCRecord,
    SHA256IOCRecord,
)


def _safe_make_provenance(data: dict[str, Any]) -> IOCProvenance | None:
    """WZ-019: build IOCProvenance from a JSON entry's `provenance` block.

    Returns None when the block is absent OR malformed (the orchestrator's
    enforcement gate will surface a ProvenanceMissingError on push when
    AGENTROPIX_REQUIRE_IOC_PROVENANCE=1 — silently dropping at load
    avoids breaking back-compat for legacy MASTER-IOCS.json files).
    """
    block = data.get("provenance")
    if not isinstance(block, dict):
        return None
    try:
        return IOCProvenance(**block)
    except Exception as exc:  # noqa: BLE001
        logger.debug(
            "Skipping malformed provenance for IOC %r: %s",
            data.get("value"),
            exc,
        )
        return None

logger = logging.getLogger(__name__)

__all__ = ["load_case_inventory", "CaseLoader"]


def _safe_make_ip(data: dict[str, Any], case_id: str) -> IPIOCRecord | None:
    try:
        return IPIOCRecord(
            case_id=case_id,
            value=data.get("value", ""),
            confidence=data.get("confidence", "medium"),
            mitre=data.get("mitre"),
            port=data.get("port"),
            connection_state=data.get("connection_state"),
            source_path=data.get("source_path"),
            host_count=data.get("host_count", 1),
            provenance=_safe_make_provenance(data),
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("Skipping IP IOC %r: %s", data.get("value"), exc)
        return None


def _safe_make_sha256(data: dict[str, Any], case_id: str) -> SHA256IOCRecord | None:
    try:
        return SHA256IOCRecord(
            case_id=case_id,
            value=data.get("value", ""),
            confidence=data.get("confidence", "high"),
            mitre=data.get("mitre"),
            filename_hint=data.get("filename_hint"),
            source_path=data.get("source_path"),
            provenance=_safe_make_provenance(data),
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("Skipping SHA256 IOC %r: %s", data.get("value"), exc)
        return None


def _safe_make_md5(data: dict[str, Any], case_id: str) -> MD5IOCRecord | None:
    try:
        return MD5IOCRecord(
            case_id=case_id,
            value=data.get("value", ""),
            confidence=data.get("confidence", "medium"),
            mitre=data.get("mitre"),
            filename_hint=data.get("filename_hint"),
            source_path=data.get("source_path"),
            provenance=_safe_make_provenance(data),
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("Skipping MD5 IOC %r: %s", data.get("value"), exc)
        return None


def _safe_make_process(data: dict[str, Any], case_id: str) -> ProcessIOCRecord | None:
    """Build a ProcessIOCRecord (legacy kind=process_name).

    Issue #60: this preserves back-compat with existing MASTER-IOCS.json
    files that use ``kind: process_name``. New pushes should use
    ``kind: process_image`` or ``kind: process_module`` to route to
    the correct CDB list. The ``_safe_make_process_image`` /
    ``_safe_make_process_module`` builders below handle those.
    """
    try:
        return ProcessIOCRecord(
            case_id=case_id,
            value=data.get("value", ""),
            confidence=data.get("confidence", "medium"),
            mitre=data.get("mitre"),
            context=data.get("context"),
            source_path=data.get("source_path"),
            provenance=_safe_make_provenance(data),
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("Skipping process IOC %r: %s", data.get("value"), exc)
        return None


def _safe_make_process_image(
    data: dict[str, Any], case_id: str
) -> ProcessImageIOCRecord | None:
    """Issue #60: explicit process_image kind (Sysmon EID 1)."""
    try:
        return ProcessImageIOCRecord(
            case_id=case_id,
            value=data.get("value", ""),
            confidence=data.get("confidence", "medium"),
            mitre=data.get("mitre"),
            context=data.get("context"),
            source_path=data.get("source_path"),
            provenance=_safe_make_provenance(data),
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("Skipping process_image IOC %r: %s", data.get("value"), exc)
        return None


def _safe_make_process_module(
    data: dict[str, Any], case_id: str
) -> ProcessModuleIOCRecord | None:
    """Issue #60: explicit process_module kind (Sysmon EID 7)."""
    try:
        return ProcessModuleIOCRecord(
            case_id=case_id,
            value=data.get("value", ""),
            confidence=data.get("confidence", "medium"),
            mitre=data.get("mitre"),
            context=data.get("context"),
            source_path=data.get("source_path"),
            provenance=_safe_make_provenance(data),
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("Skipping process_module IOC %r: %s", data.get("value"), exc)
        return None


def _safe_make_process_tree_event(
    data: dict[str, Any], case_id: str
) -> ProcessTreeEventIOCRecord | None:
    """W-203: build a process_tree_event row from MASTER-IOCS.json iocs[].

    Returns None on missing required fields so the loader skips legacy
    rows that pre-date the W-203 schema additions.
    """
    try:
        host = data.get("host", "")
        pid = data.get("pid", 0)
        parent_pid = data.get("parent_pid", 0)
        name = data.get("name", "")
        # Synthesize a CDB-safe lookup key from the four-tuple so the
        # push pipeline (_make_cdb_body) can route this row. Format:
        # host~pid~parent_pid~name with whitespace / colon / pipe in
        # textual fields replaced with `_` to clear the whitespace gate
        # at orchestrator.py:161 and survive parse_cdb_line's first-colon
        # split. The aggregator does not emit `value`; the schema marks
        # it optional and downstream lookup is by four-tuple, so this
        # synthesis is the canonical loader-side derivation.
        def _safe(s: str) -> str:
            return re.sub(r"[\s:|]+", "_", s) if s else "_"
        synth_value = f"{_safe(str(host))}~{pid}~{parent_pid}~{_safe(str(name))}"
        return ProcessTreeEventIOCRecord(
            case_id=case_id,
            value=synth_value,
            host=host,
            pid=pid,
            parent_pid=parent_pid,
            name=name,
            confidence=data.get("confidence", 0.75),
            mitre=data.get("mitre"),
            image_path_normalized=data.get("image_path_normalized"),
            image_sha256=data.get("image_sha256"),
            image_hash_source=data.get("image_hash_source"),
            command_line_redacted=data.get("command_line_redacted"),
            command_line_sha256=data.get("command_line_sha256"),
            first_seen_utc=data.get("first_seen_utc"),
            source_artifact=data.get("source_artifact"),
            source_finding_index=data.get("source_finding_index"),
            evidence_kind=data.get("evidence_kind"),
            evidence_reason=data.get("evidence_reason"),
            threads=data.get("threads"),
            wow64=data.get("wow64"),
            redacted=bool(data.get("redacted", False)),
            redactor_version=data.get("redactor_version", "1"),
            provenance=_safe_make_provenance(data),
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug(
            "Skipping process_tree_event IOC host=%r pid=%r: %s",
            data.get("host"),
            data.get("pid"),
            exc,
        )
        return None


def _safe_make_registry(data: dict[str, Any], case_id: str) -> RegistryIOCRecord | None:
    try:
        return RegistryIOCRecord(
            case_id=case_id,
            value=data.get("value", ""),
            confidence=data.get("confidence", "medium"),
            mitre=data.get("mitre"),
            persistence_type=data.get("persistence_type"),
            source_path=data.get("source_path"),
            provenance=_safe_make_provenance(data),
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("Skipping registry IOC %r: %s", data.get("value"), exc)
        return None


_KIND_BUILDERS = {
    "ip": _safe_make_ip,
    "hash_sha256": _safe_make_sha256,
    "hash_md5": _safe_make_md5,
    # Issue #60: process_name is the legacy unified kind; new pushes
    # use process_image (EID 1) / process_module (EID 7) explicitly.
    # The legacy builder routes to ProcessIOCRecord which is still
    # accepted by the orchestrator's legacy _KIND_TO_LIST entry.
    "process_name": _safe_make_process,
    "process_image": _safe_make_process_image,
    "process_module": _safe_make_process_module,
    "registry_key": _safe_make_registry,
    # W-203: aggregator emits this kind into MASTER-IOCS iocs[]. The
    # loader picks it up via the same dispatcher the other kinds use.
    "process_tree_event": _safe_make_process_tree_event,
}


def load_case_inventory(case_dir: str | Path) -> IOCInventory:
    """Load IOCInventory from a case directory.

    Looks for MASTER-IOCS.json at the case directory root. Falls back to
    an empty inventory if the file is missing (not an error — case may be
    newly initialised).
    """
    case_path = Path(case_dir)
    master_iocs = case_path / "MASTER-IOCS.json"

    # Derive case_id from directory name, uppercased
    case_id = case_path.name.upper()
    # Sanitise to match the pattern ^[A-Z0-9][A-Z0-9_-]{0,63}$
    import re

    case_id_clean = re.sub(r"[^A-Z0-9_\-]", "", case_id)[:64]
    if not case_id_clean or not case_id_clean[0].isalnum():
        case_id_clean = "UNKNOWN"

    records = []

    if master_iocs.exists():
        try:
            data = json.loads(master_iocs.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse %s: %s", master_iocs, exc)
            data = {}

        iocs_list: list[dict] = data.get("iocs", [])
        if not isinstance(iocs_list, list):
            iocs_list = []

        for entry in iocs_list:
            if not isinstance(entry, dict):
                continue
            kind = entry.get("kind", "")
            builder = _KIND_BUILDERS.get(kind)
            if builder is None:
                logger.debug("Unknown IOC kind %r — skipping", kind)
                continue
            record = builder(entry, case_id_clean)
            if record is not None:
                records.append(record)

    logger.info("Loaded %d IOC records from case %s", len(records), case_id_clean)
    return IOCInventory(
        case_id=case_id_clean,
        case_dir=str(case_path),
        records=records,
    )


class CaseLoader:
    """Object-oriented interface around load_case_inventory."""

    def load(self, case_dir: str | Path) -> IOCInventory:
        return load_case_inventory(case_dir)
