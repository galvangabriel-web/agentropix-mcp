"""Executable Artifact Registry (EAR) — Phase 1: build_executable_registry.

Turns the executable signals an analyst already collects (shimcache / fls →
extract → hashdeep) into one canonical, deduped
``agentropix.executable-registry/v1`` document (``MASTER-IOCS.json``) with a
load-bearing *recovered* vs *referenced_only* split.

Mandates: DRAFT-only (never signs chain-of-custody, never applies examiner
approval); idempotent — keyed on ``(case_id, sha256)`` for recovered entries
and ``(case_id, image_path)`` for hashless referenced_only entries so re-runs
de-duplicate instead of inflating (mirrors record_finding); additive +
allowlisted (writes ``MASTER-IOCS.json`` only under the case_dir); ASCII.

This module owns canonicalisation + persistence. Collection (the
shimcache/fls/extract/hashdeep calls) is done by the existing tools and passed
in as ``candidates``; promotion to the shared ``agentropix-executables-*`` index
is a separate, EvidenceGate-gated step (Phase 2), intentionally NOT done here.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

SCHEMA = "agentropix.executable-registry/v1"

# Lightweight category tags by filename hint — best-effort, advisory only.
_CATEGORY_HINTS: tuple[tuple[str, str], ...] = (
    ("cain", "credential-capture"),
    ("ethereal", "sniffer"),
    ("wireshark", "sniffer"),
    ("netstumbler", "network-recon"),
    ("lookatlan", "network-recon"),
    ("lookathost", "network-recon"),
    ("whois", "network-recon"),
    ("nmap", "network-recon"),
    ("winpcap", "driver-installer"),
    ("npf", "driver-installer"),
    ("mirc", "irc"),
    ("agent", "newsreader"),
)


def _categorise(name: str) -> str:
    low = name.lower()
    for needle, cat in _CATEGORY_HINTS:
        if needle in low:
            return cat
    if low.endswith((".bat", ".cmd", ".ps1")):
        return "script"
    if "setup" in low or "install" in low:
        return "installer"
    if low.endswith((".sys", ".dll")):
        return "driver-installer"
    return "executable"


def _basename(image_path: str) -> str:
    # in-image paths use backslashes; normalise for the name field.
    return image_path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


class ExecutableEntry(BaseModel):
    name: str
    image_path: str
    category: str = "executable"
    status: str = "referenced_only"  # recovered | referenced_only
    inode: str = ""
    size: int | None = None
    md5: str | None = None
    sha256: str | None = None
    shimcache_last_modified_utc: str = ""
    source_signals: list[str] = Field(default_factory=list)
    finding_refs: list[str] = Field(default_factory=list)
    notes: str = ""


class ExecutableRegistry(BaseModel):
    registry_schema: str = Field(default=SCHEMA, alias="schema")
    case_id: str
    host: str = ""
    image: str = ""
    image_md5: str = ""
    partition_offset_sectors: int = 0
    approval_status: str = "DRAFT"
    executables: list[ExecutableEntry] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    artifact_path: str = ""
    error: str = ""

    model_config = {"populate_by_name": True}


def _summarise(entries: list[ExecutableEntry]) -> dict[str, Any]:
    recovered = [e for e in entries if e.status == "recovered"]
    referenced = [e for e in entries if e.status != "recovered"]
    by_cat: dict[str, int] = {}
    for e in entries:
        by_cat[e.category] = by_cat.get(e.category, 0) + 1
    return {
        "total": len(entries),
        "recovered_hashed": len([e for e in recovered if e.sha256]),
        "referenced_only": len(referenced),
        "by_category": by_cat,
        "carve_recovery_candidates": [e.name for e in referenced],
    }


def _build_registry(
    *,
    case_id: str,
    host: str,
    image: str,
    image_md5: str,
    offset: int,
    candidates: list[dict[str, Any]],
) -> ExecutableRegistry:
    """Pure normaliser: collected per-path candidate dicts → deduped registry.

    Idempotent within a build — dedupes on sha256 (recovered) else image_path
    (referenced-only). Deterministic; no I/O. A candidate with a non-empty
    sha256 is ``recovered``; else ``referenced_only``.
    """
    by_key: dict[str, ExecutableEntry] = {}
    for c in candidates:
        image_path = str(c.get("image_path", "")).strip()
        if not image_path:
            continue
        sha256 = (c.get("sha256") or "") or None
        status = "recovered" if sha256 else "referenced_only"
        key = f"sha:{sha256}" if sha256 else f"path:{image_path.lower()}"
        name = _basename(image_path)
        entry = by_key.get(key)
        if entry is None:
            by_key[key] = ExecutableEntry(
                name=name,
                image_path=image_path,
                category=_categorise(name),
                status=status,
                inode=str(c.get("inode", "") or ""),
                size=c.get("size"),
                md5=(c.get("md5") or None),
                sha256=sha256,
                shimcache_last_modified_utc=str(c.get("shimcache_last_modified_utc", "") or ""),
                source_signals=list(c.get("source_signals", []) or []),
                finding_refs=list(c.get("finding_refs", []) or []),
                notes=str(c.get("notes", "") or ""),
            )
        else:
            # Merge signals/refs from a second sighting of the same artifact.
            for sig in c.get("source_signals", []) or []:
                if sig not in entry.source_signals:
                    entry.source_signals.append(sig)
            for ref in c.get("finding_refs", []) or []:
                if ref not in entry.finding_refs:
                    entry.finding_refs.append(ref)
            if not entry.shimcache_last_modified_utc and c.get("shimcache_last_modified_utc"):
                entry.shimcache_last_modified_utc = str(c["shimcache_last_modified_utc"])

    entries = sorted(by_key.values(), key=lambda e: (e.status != "recovered", e.name.lower()))
    return ExecutableRegistry(
        case_id=case_id,
        host=host,
        image=image,
        image_md5=image_md5,
        partition_offset_sectors=offset,
        approval_status="DRAFT",
        executables=entries,
        summary=_summarise(entries),
    )


async def build_executable_registry(
    case_id: str,
    *,
    candidates: list[dict[str, Any]],
    host: str = "",
    image: str = "",
    image_md5: str = "",
    offset: int = 0,
    case_dir: str | Path | None = None,
    dry_run: bool = True,
) -> ExecutableRegistry:
    """Build a case's Executable Artifact Registry from collected candidates.

    Phase 1 is collection-agnostic: the caller (driver / orchestrator) gathers
    the union of signals (shimcache + fls-recovered+hashed binaries +
    referenced-only deleted paths) into ``candidates`` and this assembles the
    deduped, status-split, DRAFT ``MASTER-IOCS.json``. Keeping collection out
    of this function makes it deterministic + testable.

    When ``case_dir`` is given and ``dry_run`` is False, the artifact is written
    to ``<case_dir>/MASTER-IOCS.json`` (additive, DRAFT — no index write, no
    examiner approval). ``dry_run=True`` (default) returns the registry without
    touching disk.

    Args:
        case_id: the case this registry belongs to.
        candidates: per-path candidate dicts (see ``_build_registry``).
        host / image / image_md5 / offset: evidence provenance.
        case_dir: where to write MASTER-IOCS.json (when not dry_run).
        dry_run: when True (default), do not write the artifact.

    Returns:
        ExecutableRegistry (``artifact_path`` set when written).
    """
    if not case_id or not isinstance(case_id, str):
        raise ValueError("case_id must be a non-empty string")

    registry = _build_registry(
        case_id=case_id,
        host=host,
        image=image,
        image_md5=image_md5,
        offset=offset,
        candidates=candidates or [],
    )

    if not dry_run and case_dir is not None:
        dest = Path(case_dir) / "MASTER-IOCS.json"
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            payload = registry.model_dump(by_alias=True, exclude={"artifact_path", "error"})
            dest.write_text(json.dumps(payload, indent=1, ensure_ascii=True), encoding="ascii")
            registry.artifact_path = str(dest)
            logger.info(
                "EAR: wrote %d executables (%d recovered) to %s",
                registry.summary.get("total", 0),
                registry.summary.get("recovered_hashed", 0),
                dest,
            )
        except OSError as exc:
            registry.error = f"failed to write MASTER-IOCS.json: {exc}"
            logger.warning("EAR write failed: %s", exc)

    return registry


# =============================================================================
# Phase 2 — promotion to the shared index + cross-case retrieval
# =============================================================================

EXECUTABLES_INDEX_PREFIX = "agentropix-executables-"
EXECUTABLES_INDEX_PATTERN = "agentropix-executables-*"
_PROMOTE_PURPOSE = "promote_executable_registry"


def _today_executables_index() -> str:
    return EXECUTABLES_INDEX_PREFIX + _dt.datetime.now(_dt.UTC).strftime("%Y.%m.%d")


def _doc_id(case_id: str, entry: ExecutableEntry) -> str:
    """Deterministic _id so re-promotion upserts instead of duplicating
    (mirrors the (case_id, sha256) / (case_id, image_path) idempotency)."""
    if entry.status == "recovered" and entry.sha256:
        return f"{case_id}::sha256::{entry.sha256.lower()}"
    return f"{case_id}::path::{(entry.image_path or entry.name).lower()}"


class PromoteResult(BaseModel):
    case_id: str
    index: str = ""
    promoted: int = 0
    total: int = 0
    dry_run: bool = True
    approval_status: str = "DRAFT"
    error: str = ""


class ExecRegistryQueryResult(BaseModel):
    query: dict[str, Any] = Field(default_factory=dict)
    count: int = 0
    executables: list[dict] = Field(default_factory=list)
    error: str = ""


async def promote_executable_registry(
    case_id: str,
    executables: list[dict],
    *,
    host: str = "",
    image: str = "",
    image_md5: str = "",
    offset: int = 0,
    generated_at: str = "",
    dry_run: bool = True,
    mutation_token: str | None = None,
    indexer_client: Any = None,
    evidence_gate: Any = None,
) -> PromoteResult:
    """Promote a case's executable registry into ``agentropix-executables-*``.

    Builds the deduped registry (same normaliser as build_executable_registry)
    and upserts each entry by deterministic ``_id`` so re-promotion never
    inflates. Live write is EvidenceGate-gated (S-1): ``dry_run=False`` requires
    a valid ``mutation_token`` (``egt_*``, purpose ``promote_executable_registry``).
    ``dry_run=True`` (default) returns what WOULD be promoted without writing.
    Docs ship ``approval_status=DRAFT`` — promotion indexes for retrieval, it
    does NOT apply examiner approval.
    """
    if not case_id or not isinstance(case_id, str):
        raise ValueError("case_id must be a non-empty string")

    registry = _build_registry(
        case_id=case_id,
        host=host,
        image=image,
        image_md5=image_md5,
        offset=offset,
        candidates=executables or [],
    )
    total = int(registry.summary.get("total", 0))
    index = _today_executables_index()

    if dry_run:
        return PromoteResult(case_id=case_id, index=index, promoted=0, total=total, dry_run=True)

    if evidence_gate is None:
        return PromoteResult(
            case_id=case_id,
            index=index,
            total=total,
            dry_run=False,
            error="EvidenceGate not injected; live promotion unavailable",
        )
    ok, reason = evidence_gate.verify_and_consume(mutation_token or "", purpose=_PROMOTE_PURPOSE)
    if not ok:
        return PromoteResult(
            case_id=case_id,
            index=index,
            total=total,
            dry_run=False,
            error=f"mutation_token rejected: {reason}",
        )
    if indexer_client is None:
        return PromoteResult(
            case_id=case_id,
            index=index,
            total=total,
            dry_run=False,
            error="indexer_client not injected",
        )

    promoted = 0
    for entry in registry.executables:
        doc = entry.model_dump()
        doc["case_id"] = case_id
        doc["host"] = host
        doc["image"] = image
        doc["approval_status"] = "DRAFT"
        doc["provenance"] = "MCP"
        if generated_at:
            doc["@timestamp"] = generated_at
        try:
            await indexer_client.index_one(index, doc, doc_id=_doc_id(case_id, entry))
            promoted += 1
        except Exception as exc:
            logger.warning("EAR promote: index_one failed for %s: %s", entry.name, exc)
    return PromoteResult(
        case_id=case_id, index=index, promoted=promoted, total=total, dry_run=False
    )


async def exec_registry_get(
    case_id: str,
    *,
    indexer_client: Any = None,
    size: int = 500,
) -> ExecRegistryQueryResult:
    """Return a case's full promoted executable inventory in one call."""
    if not case_id or not isinstance(case_id, str):
        raise ValueError("case_id must be a non-empty string")
    if indexer_client is None:
        return ExecRegistryQueryResult(error="indexer_client not injected")
    query = {"query": {"term": {"case_id": case_id}}}
    try:
        resp = await indexer_client.search(EXECUTABLES_INDEX_PATTERN, query, size=min(size, 500))
    except Exception as exc:
        return ExecRegistryQueryResult(
            query={"case_id": case_id}, error=f"{type(exc).__name__}: {exc}"
        )
    hits = [h.get("_source", {}) for h in (resp or {}).get("hits", {}).get("hits", [])]
    return ExecRegistryQueryResult(query={"case_id": case_id}, count=len(hits), executables=hits)


async def exec_registry_search(
    *,
    sha256: str | None = None,
    name: str | None = None,
    category: str | None = None,
    indexer_client: Any = None,
    size: int = 100,
) -> ExecRegistryQueryResult:
    """Cross-case pivot on hash / name / category (campaign linking)."""
    if indexer_client is None:
        return ExecRegistryQueryResult(error="indexer_client not injected")
    filters: list[dict] = []
    if sha256:
        filters.append({"term": {"sha256": sha256.lower()}})
    if name:
        filters.append({"term": {"name": name}})
    if category:
        filters.append({"term": {"category": category}})
    if not filters:
        raise ValueError("provide at least one of sha256 / name / category")
    query = {"query": {"bool": {"filter": filters}}}
    try:
        resp = await indexer_client.search(EXECUTABLES_INDEX_PATTERN, query, size=min(size, 500))
    except Exception as exc:
        return ExecRegistryQueryResult(query=query, error=f"{type(exc).__name__}: {exc}")
    hits = [h.get("_source", {}) for h in (resp or {}).get("hits", {}).get("hits", [])]
    return ExecRegistryQueryResult(
        query={"sha256": sha256, "name": name, "category": category},
        count=len(hits),
        executables=hits,
    )
