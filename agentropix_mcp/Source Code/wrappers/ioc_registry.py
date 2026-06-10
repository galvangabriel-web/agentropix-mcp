"""IOC promotion pipeline — BUG-004: populate ``agentropix-iocs-*``.

The ``ioc`` report profile reads ``agentropix-iocs-*`` but nothing wrote to it,
so the index was always empty even though APPROVED findings carry populated
``iocs[]`` arrays. This pipeline projects those finding IOCs into the index:
read APPROVED findings, flatten + dedupe their ``iocs[]`` on
``(ioc_type, ioc_value)``, carry MITRE technique mapping + parent finding refs,
and upsert by deterministic ``_id`` so re-promotion never inflates (mirrors the
EAR promote pattern + record_finding idempotency).

Live index write is EvidenceGate-gated (``dry_run=False`` requires a valid
``egt_*`` token, purpose ``promote_iocs``). ``dry_run=True`` (default) returns
what WOULD be promoted without writing. The pure normaliser ``_build_iocs`` is
deterministic + indexer-free so it unit-tests cheaply.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import logging
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

IOCS_INDEX_PREFIX = "agentropix-iocs-"
IOCS_INDEX_PATTERN = "agentropix-iocs-*"
FINDINGS_INDEX_PATTERN = "agentropix-findings-*"
_PROMOTE_PURPOSE = "promote_iocs"


def _today_iocs_index() -> str:
    return IOCS_INDEX_PREFIX + _dt.datetime.now(_dt.UTC).strftime("%Y.%m.%d")


def _ioc_doc_id(case_id: str, ioc_type: str, ioc_value: str) -> str:
    """Deterministic _id over (case_id, ioc_type, ioc_value) so re-promotion
    upserts in place instead of duplicating."""
    raw = f"{case_id}\x00{ioc_type.lower()}\x00{ioc_value.lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class IOCEntry(BaseModel):
    ioc_type: str
    ioc_value: str
    mitre_techniques: list[str] = Field(default_factory=list)
    finding_refs: list[str] = Field(default_factory=list)
    case_id: str = ""


class PromoteIOCsResult(BaseModel):
    case_id: str
    index: str = ""
    promoted: int = 0
    total: int = 0
    dry_run: bool = True
    error: str = ""
    # SIFT-W-299: non-fatal warning. Set when the approvals ledger HAS
    # APPROVED findings for the case but none yielded a promotable IOC —
    # kills the silent-success failure mode (promoted:0 looking like "done").
    warning: str = ""


def _coerce_ioc(raw: Any) -> tuple[str, str] | None:
    """Normalise one finding IOC entry → (ioc_type, ioc_value).

    Accepts dicts ({ioc_type|type, ioc_value|value|indicator}) or bare strings
    (typed as ``unknown``). Returns None when no value can be extracted.
    """
    if isinstance(raw, str):
        v = raw.strip()
        return ("unknown", v) if v else None
    if isinstance(raw, dict):
        ioc_type = str(raw.get("ioc_type") or raw.get("type") or "unknown").strip() or "unknown"
        value = raw.get("ioc_value") or raw.get("value") or raw.get("indicator") or ""
        value = str(value).strip()
        return (ioc_type, value) if value else None
    return None


def _build_iocs(case_id: str, findings: list[dict[str, Any]]) -> list[IOCEntry]:
    """Pure normaliser: flatten + dedupe APPROVED findings' ``iocs[]``.

    Dedupe key is ``(ioc_type, ioc_value)`` lowercased; MITRE techniques and
    parent finding_ids are merged across sightings. Deterministic; no I/O.
    """
    by_key: dict[tuple[str, str], IOCEntry] = {}
    for f in findings:
        fid = str(f.get("finding_id", "") or "")
        f_mitre = [str(m) for m in (f.get("mitre_techniques") or []) if str(m).strip()]
        for raw in f.get("iocs") or []:
            coerced = _coerce_ioc(raw)
            if coerced is None:
                continue
            ioc_type, ioc_value = coerced
            key = (ioc_type.lower(), ioc_value.lower())
            # per-IOC MITRE (if the IOC dict carried its own) else the finding's.
            ioc_mitre = (
                [str(m) for m in raw.get("mitre_techniques") or [] if str(m).strip()]
                if isinstance(raw, dict)
                else []
            ) or f_mitre
            entry = by_key.get(key)
            if entry is None:
                by_key[key] = IOCEntry(
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    mitre_techniques=list(dict.fromkeys(ioc_mitre)),
                    finding_refs=[fid] if fid else [],
                    case_id=case_id,
                )
            else:
                for m in ioc_mitre:
                    if m not in entry.mitre_techniques:
                        entry.mitre_techniques.append(m)
                if fid and fid not in entry.finding_refs:
                    entry.finding_refs.append(fid)
    return sorted(by_key.values(), key=lambda e: (e.ioc_type, e.ioc_value.lower()))


async def _approved_finding_ids(case_id: str, indexer_client: Any) -> set[str]:
    """SIFT-W-299: resolve APPROVED finding_ids from the authoritative
    append-only approvals ledger (``agentropix-approvals-*``).

    Reuses the same resolver the ``findings``/``full``/``executive`` report
    profiles use (``case_records._approved_target_ids``), which walks the
    ledger in @timestamp order and keeps the LATEST transition per target —
    so an approved-then-REVOKED or phantom approval (e.g. a ghost
    ``NIST1-F006``) is correctly EXCLUDED.

    Deferred import: ``case_records`` does not import ``ioc_registry`` at
    module load, but importing inside the function keeps the dependency
    one-directional and avoids any future import-order fragility.
    """
    from agentropix_mcp.wrappers.case_records import (
        _approved_target_ids,
    )

    return await _approved_target_ids(case_id, indexer_client, "finding")


async def _read_approved_findings(case_id: str, indexer_client: Any) -> list[dict]:
    """Fetch ledger-APPROVED findings for the case (their iocs[] are the source).

    SIFT-W-299: was a ``term`` query on the finding doc's own
    ``approval.status`` field, which the W-286 draft-gate pins to ``DRAFT``
    forever (the sidecar records approvals in the ledger, not the doc). That
    made this return [] for every validly-approved finding, silently blocking
    ALL IOC promotion. Now resolves approval from the ledger and fetches only
    those finding docs.
    """
    from agentropix_mcp.wrappers.case_records import (
        _reconciled_approved_query,
    )

    approved_ids = await _approved_finding_ids(case_id, indexer_client)
    if not approved_ids:
        return []
    body = _reconciled_approved_query(case_id, approved_ids, "finding_id")
    resp = await indexer_client.search(FINDINGS_INDEX_PATTERN, body, size=500)
    hits = ((resp or {}).get("hits") or {}).get("hits") or []
    return [h.get("_source") or {} for h in hits]


async def promote_iocs(
    case_id: str,
    *,
    findings: list[dict] | None = None,
    dry_run: bool = True,
    mutation_token: str | None = None,
    indexer_client: Any = None,
    evidence_gate: Any = None,
) -> PromoteIOCsResult:
    """Project a case's APPROVED-finding IOCs into ``agentropix-iocs-*`` (BUG-004).

    When ``findings`` is None they are read from the findings index
    (APPROVED-only) via ``indexer_client``. The flattened, deduped IOC set is
    upserted by deterministic ``_id``. Live write is EvidenceGate-gated.
    ``dry_run=True`` (default) returns the would-promote count without writing.
    """
    if not case_id or not isinstance(case_id, str):
        raise ValueError("case_id must be a non-empty string")

    index = _today_iocs_index()
    if findings is None:
        if indexer_client is None:
            return PromoteIOCsResult(
                case_id=case_id,
                index=index,
                dry_run=dry_run,
                error="indexer_client not injected (cannot read findings)",
            )
        findings = await _read_approved_findings(case_id, indexer_client)

    entries = _build_iocs(case_id, findings)
    total = len(entries)

    # SIFT-W-299: kill the silent-success failure mode. If the case HAS
    # APPROVED findings but none carry a promotable IOC, total==0 would
    # otherwise look identical to "nothing approved yet" / "already done".
    warning = ""
    if total == 0 and findings:
        warning = (
            f"{len(findings)} APPROVED finding(s) for case {case_id!r} carry no "
            f"promotable IOCs (empty iocs[]); 0 IOCs written"
        )

    if dry_run:
        return PromoteIOCsResult(
            case_id=case_id,
            index=index,
            promoted=0,
            total=total,
            dry_run=True,
            warning=warning,
        )

    if evidence_gate is None:
        return PromoteIOCsResult(
            case_id=case_id,
            index=index,
            total=total,
            dry_run=False,
            error="EvidenceGate not injected; live promotion unavailable",
        )
    # SIFT-W-299: use the established fail-closed EvidenceGate control
    # (atomic verify+spend of a one-time, op-bound ``egt_`` token) — the
    # same mutation gate wazuh_publish_iocs / wazuh_index_findings use.
    # ``.verify`` raises EvidenceGateRequired / TokenError on any rejection
    # (missing/format/expired/replayed/wrong-op); fail closed.
    try:
        evidence_gate.verify(mutation_token, op=_PROMOTE_PURPOSE)
    except Exception as exc:
        return PromoteIOCsResult(
            case_id=case_id,
            index=index,
            total=total,
            dry_run=False,
            error=f"mutation_token rejected: {exc}",
        )
    if indexer_client is None:
        return PromoteIOCsResult(
            case_id=case_id,
            index=index,
            total=total,
            dry_run=False,
            error="indexer_client not injected",
        )

    promoted = 0
    for entry in entries:
        doc = entry.model_dump()
        doc["case_id"] = case_id
        doc["@timestamp"] = _dt.datetime.now(_dt.UTC).isoformat()
        doc["provenance"] = "MCP"
        try:
            await indexer_client.index_one(
                index, doc, doc_id=_ioc_doc_id(case_id, entry.ioc_type, entry.ioc_value)
            )
            promoted += 1
        except Exception as exc:
            logger.warning("promote_iocs: index_one failed for %s: %s", entry.ioc_value, exc)
    return PromoteIOCsResult(
        case_id=case_id,
        index=index,
        promoted=promoted,
        total=total,
        dry_run=False,
        warning=warning,
    )
