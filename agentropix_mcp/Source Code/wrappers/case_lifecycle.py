"""SIFT-W-289: Case-lifecycle MCP wrappers (4 of the 13 P0 tools).

Implements the foundational Valhuntir workflow steps 1, 2 + the
case-pointer helpers (architecture.md § Case Directory Structure):

  * ``case_init``         — create a new case + agentropix-cases entry
  * ``case_status``       — read agentropix-cases + per-index counts
  * ``case_activate``     — switch the active-case pointer
  * ``evidence_register`` — SHA-256 hash + agentropix-evidence-* entry

Active-case state lives at ``~/.agentropix/active_case`` — a single
line of UTF-8 with the case_id. Every tool that needs case context
calls :func:`get_active_case_id` to resolve it. The dir is created
on first init; the file is overwritten by ``case_activate``.

This module is the **read** half of the W-289 work. The wrappers
themselves are async functions; their MCP-tool registrations live
in ``server.py`` (Thymus + rate-limiter wired in) and the
FastMCP-decorated surface in ``fastmcp_app.py``.

Indices touched (W-285 templates):

  * ``agentropix-cases``      — single-doc-per-case lifecycle.
                                _id == case_id (upsert idempotent).
  * ``agentropix-evidence-*`` — per-day evidence registry. _id auto-gen;
                                evidence_id carried inside the doc.
  * ``agentropix-findings-*`` — counted-only here.
  * ``agentropix-timeline-*`` — counted-only here.
  * ``agentropix-iocs-*``     — counted-only here.

No tool in this slice has authority to APPROVE; record_finding lives
in W-290 (next stacked PR) and goes through the W-286 draft-gate.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import logging
import os
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# --- Constants --------------------------------------------------------- #


ACTIVE_CASE_DIR_DEFAULT = "~/.agentropix"
ACTIVE_CASE_FILE_NAME = "active_case"
CASES_INDEX = "agentropix-cases"  # single-doc index per W-285
EVIDENCE_INDEX_PREFIX = "agentropix-evidence-"
FINDINGS_INDEX_PATTERN = "agentropix-findings-*"
TIMELINE_INDEX_PATTERN = "agentropix-timeline-*"
IOCS_INDEX_PATTERN = "agentropix-iocs-*"
APPROVALS_INDEX_PATTERN = "agentropix-approvals-*"

# case_id format: A-Za-z0-9._- between 1 and 128 chars. Mirrors
# Valhuntir's INC-2026-MMDD convention while accepting any operator
# slug (CFReDS-fresh, ROCBA, study-case-2). The regex protects the
# index _id space — anything else would risk collisions with the
# evidence-id / approval-id keyword fields.
_CASE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


# --- Pydantic models --------------------------------------------------- #


class CaseRecord(BaseModel):
    """One row in ``agentropix-cases``."""

    case_id: str
    case_name: str
    description: str = ""
    status: str = "active"  # active | closed | archived
    examiner_id: str
    incident_type: str = ""
    severity: str = ""
    started_at: str  # ISO-8601 UTC
    ended_at: str | None = None
    scope: str = ""
    team: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    case_dir: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)


class CaseStatusReport(BaseModel):
    """Result of ``case_status``."""

    case_id: str
    case: CaseRecord | None  # None when no agentropix-cases doc found
    active: bool
    counts: dict[str, int]  # per-sibling-index doc count
    indexer_reachable: bool
    error: str = ""


class EvidenceRecord(BaseModel):
    """One row in ``agentropix-evidence-*``."""

    evidence_id: str
    case_id: str
    path: str
    description: str
    sha256: str
    size_bytes: int
    examiner_id: str
    registered_at: str  # ISO-8601 UTC
    audit_id: str = ""  # set by server.py wrapper at MCP boundary
    payload: dict[str, Any] = Field(default_factory=dict)


class EvidenceRegisterResult(BaseModel):
    """Result of ``evidence_register``."""

    evidence: EvidenceRecord
    indexed_to: str  # agentropix-evidence-YYYY.MM.DD
    indexed: bool
    error: str = ""


# --- Helpers ----------------------------------------------------------- #


def _utc_now_iso() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _today_evidence_index() -> str:
    return EVIDENCE_INDEX_PREFIX + dt.datetime.now(dt.UTC).strftime("%Y.%m.%d")


def _active_case_path() -> Path:
    """Resolve the active-case pointer file, honoring the env override
    ``AGENTROPIX_ACTIVE_CASE_DIR`` so tests can drop in a tempdir
    without touching the operator's real ``~/.agentropix``."""
    base = os.environ.get("AGENTROPIX_ACTIVE_CASE_DIR", ACTIVE_CASE_DIR_DEFAULT)
    return Path(base).expanduser() / ACTIVE_CASE_FILE_NAME


def _validate_case_id(case_id: str) -> None:
    if not isinstance(case_id, str) or not _CASE_ID_RE.match(case_id):
        raise ValueError(f"case_id must be 1-128 chars of [A-Za-z0-9._-]; got {case_id!r}")


def _default_case_id() -> str:
    """Generate an INC-YYYY-MMDDHHMMSS slug when none is supplied.

    Matches Valhuntir's ``INC-2026-...`` convention while staying
    unambiguous within the keyword index. Uses UTC so multi-region
    examiners produce sortable, collision-resistant ids without
    coordination.
    """
    now = dt.datetime.now(dt.UTC)
    return f"INC-{now:%Y-%m%d%H%M%S}"


def get_active_case_id() -> str | None:
    """Read the active-case pointer. Returns ``None`` if unset.

    Public helper — the future record_finding / report_generate
    wrappers (W-290) call this to resolve the default ``case_id`` when
    the caller doesn't pass one explicitly.
    """
    path = _active_case_path()
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return text or None


def _set_active_case_id(case_id: str) -> Path:
    """Overwrite the active-case pointer. Creates the parent dir
    when missing (matches the Valhuntir-quickstart behavior)."""
    path = _active_case_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(case_id + "\n", encoding="utf-8")
    return path


# --- Tool: case_init --------------------------------------------------- #


async def case_init(
    case_name: str,
    *,
    case_id: str | None = None,
    description: str = "",
    examiner_id: str,
    incident_type: str = "",
    severity: str = "",
    scope: str = "",
    team: list[str] | None = None,
    tags: list[str] | None = None,
    case_dir: str = "",
    payload: dict[str, Any] | None = None,
    indexer_client: Any = None,
) -> CaseRecord:
    """SIFT-W-289: create a new case and stamp the active-case pointer.

    The agentropix-cases index uses the case_id as the document _id,
    so a second call with the same ``case_id`` upserts (idempotent
    under re-run; the new fields replace the prior ones). ``case_dir``
    is captured but never validated by this wrapper — it's an
    operator-friendly free-text path for the future Valhuntir-style
    flat-layout sibling files.

    Args:
        case_name: human-readable label.
        case_id: optional explicit slug. Auto-generated to
            ``INC-YYYY-MMDDHHMMSS`` when ``None``.
        examiner_id: required; stamped into the doc + every future
            evidence/approval record for chain-of-custody.
        indexer_client: optional injected ``IndexerClient`` (tests
            stub here; production wires the real one via the
            server.py glue).

    Returns:
        The :class:`CaseRecord` that landed in the index.
    """
    if not case_name or not isinstance(case_name, str):
        raise ValueError("case_name must be a non-empty string")
    if not examiner_id or not isinstance(examiner_id, str):
        raise ValueError("examiner_id must be a non-empty string")

    resolved_case_id = case_id if case_id is not None else _default_case_id()
    _validate_case_id(resolved_case_id)

    record = CaseRecord(
        case_id=resolved_case_id,
        case_name=case_name,
        description=description,
        status="active",
        examiner_id=examiner_id,
        incident_type=incident_type,
        severity=severity,
        started_at=_utc_now_iso(),
        ended_at=None,
        scope=scope,
        team=list(team or []),
        tags=list(tags or []),
        case_dir=case_dir,
        payload=dict(payload or {}),
    )

    # SIFT-W-296c (Critic D fix): set the active-case pointer FIRST,
    # then attempt the index write under try/except. The pointer is the
    # load-bearing LOCAL effect of case_init — it must always happen so
    # subsequent tools resolve the case, even if the indexer is down.
    # Previously the write was unguarded and ran before the pointer, so
    # an IndexerError / TransientHTTPError crashed the entry-point tool
    # AND left no active case. This now mirrors evidence_register's
    # graceful-degradation pattern.
    _set_active_case_id(resolved_case_id)
    if indexer_client is not None:
        doc = record.model_dump()
        doc["@timestamp"] = record.started_at
        try:
            await indexer_client.index_one(CASES_INDEX, doc, doc_id=resolved_case_id)
        except Exception as exc:
            logger.warning(
                "case_init: indexer write failed for %s (%s); active-case "
                "pointer still set, case usable locally: %s",
                resolved_case_id,
                case_name,
                exc,
            )
    logger.info(
        "case_init: created case %s (%s); active-case pointer updated",
        resolved_case_id,
        case_name,
    )
    return record


# --- Tool: case_activate ---------------------------------------------- #


async def case_activate(case_id: str) -> dict[str, str]:
    """Switch the active-case pointer.

    No indexer round-trip — this is a local-only state change.
    Returns the prior pointer value so the caller can audit the
    transition.
    """
    _validate_case_id(case_id)
    prior = get_active_case_id()
    _set_active_case_id(case_id)
    return {
        "case_id": case_id,
        "prior_case_id": prior or "",
        "pointer_path": str(_active_case_path()),
    }


# --- Tool: case_status ------------------------------------------------ #


async def case_status(
    case_id: str | None = None,
    *,
    indexer_client: Any = None,
) -> CaseStatusReport:
    """Aggregate case context: the agentropix-cases row + sibling counts.

    Args:
        case_id: optional case slug. ``None`` resolves the active-case
            pointer. ``ValueError`` raised if neither is set.
        indexer_client: optional injected ``IndexerClient``.

    Returns:
        :class:`CaseStatusReport`. Indexer-unreachable surfaces as
        ``indexer_reachable=False`` + ``error=...`` rather than
        raising — the active-case-pointer half of the answer is
        always reachable locally.
    """
    if case_id is None:
        case_id = get_active_case_id()
        if case_id is None:
            raise ValueError("no active case; call case_init() or case_activate() first")
    _validate_case_id(case_id)
    active = get_active_case_id() == case_id

    if indexer_client is None:
        return CaseStatusReport(
            case_id=case_id,
            case=None,
            active=active,
            counts={},
            indexer_reachable=False,
            error="indexer_client not injected",
        )

    case_record: CaseRecord | None = None
    counts: dict[str, int] = {}
    error = ""
    indexer_reachable = True
    try:
        # 1) Look up the cases doc by exact _id.
        search_resp = await indexer_client.search(
            CASES_INDEX,
            {"query": {"term": {"_id": case_id}}},
            size=1,
        )
        hits = (search_resp.get("hits") or {}).get("hits") or []
        if hits:
            src = hits[0].get("_source") or {}
            try:
                case_record = CaseRecord.model_validate(src)
            except Exception as exc:
                logger.warning(
                    "case_status: malformed agentropix-cases doc for %s: %s",
                    case_id,
                    exc,
                )

        # 2) Sibling-index counts. Run in parallel; one outage doesn't
        #    blank the whole answer.
        per_index = {
            "findings": FINDINGS_INDEX_PATTERN,
            "timeline": TIMELINE_INDEX_PATTERN,
            "evidence": EVIDENCE_INDEX_PREFIX + "*",
            "iocs": IOCS_INDEX_PATTERN,
            "approvals": APPROVALS_INDEX_PATTERN,
        }
        query_body = {"query": {"term": {"case_id": case_id}}}

        async def _one_count(label: str, pattern: str) -> tuple[str, int]:
            try:
                n = await indexer_client.count(pattern, query_body)
                return (label, int(n))
            except Exception as exc:
                logger.warning(
                    "case_status: count failed for %s (%s): %s",
                    label,
                    pattern,
                    exc,
                )
                return (label, -1)

        results = await asyncio.gather(
            *(_one_count(label, pat) for label, pat in per_index.items())
        )
        counts = {label: n for label, n in results}
    except Exception as exc:
        indexer_reachable = False
        error = f"{type(exc).__name__}: {exc}"

    return CaseStatusReport(
        case_id=case_id,
        case=case_record,
        active=active,
        counts=counts,
        indexer_reachable=indexer_reachable,
        error=error,
    )


# --- Tool: evidence_register ------------------------------------------ #


def _sha256_file(path: Path, *, chunk_size: int = 1 << 20) -> tuple[str, int]:
    """Stream the file in 1MB chunks. Returns (hex_digest, size_bytes).

    Sync read inside an async wrapper — acceptable for evidence files
    (typically MB-scale; multi-GB images already shouldn't be
    registered through this MCP path). The sub-agent #2 critique on
    SHA-256 streaming in async applies to multi-GB SRUM/EWF inputs;
    evidence registry rows are descriptive, not bulk artifacts.
    """
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


async def evidence_register(
    path: str,
    description: str,
    *,
    case_id: str | None = None,
    examiner_id: str,
    audit_id: str = "",
    payload: dict[str, Any] | None = None,
    indexer_client: Any = None,
) -> EvidenceRegisterResult:
    """SIFT-W-289: hash an evidence file and register it in the case.

    Computes SHA-256 + size, builds an :class:`EvidenceRecord`, and
    indexes it into the daily ``agentropix-evidence-YYYY.MM.DD`` index
    (per W-285 template). The evidence_id is a deterministic SHA-256
    of (case_id, path, sha256) — re-registering the same file under
    the same case is idempotent within a UTC day.

    Args:
        path: absolute path on disk.
        description: free-text examiner-supplied label.
        case_id: optional; resolves from active-case pointer when
            ``None``.
        examiner_id: required for chain-of-custody.
        audit_id: optional MCP audit_id the caller is wrapping
            around — server.py supplies it from the @traced layer.
        indexer_client: injected ``IndexerClient`` for the write.
    """
    target = Path(path).expanduser()
    if not target.exists():
        raise FileNotFoundError(f"evidence path not found: {target}")
    if not target.is_file():
        raise FileNotFoundError(f"evidence path is not a file: {target}")

    if not description or not isinstance(description, str):
        raise ValueError("description must be a non-empty string")
    if not examiner_id or not isinstance(examiner_id, str):
        raise ValueError("examiner_id must be a non-empty string")

    if case_id is None:
        case_id = get_active_case_id()
        if case_id is None:
            raise ValueError("no active case; pass case_id= or call case_activate()")
    _validate_case_id(case_id)

    digest, size = _sha256_file(target)
    evidence_id = hashlib.sha256(f"{case_id}\x00{target!s}\x00{digest}".encode()).hexdigest()
    registered_at = _utc_now_iso()

    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        path=str(target),
        description=description,
        sha256=digest,
        size_bytes=size,
        examiner_id=examiner_id,
        registered_at=registered_at,
        audit_id=audit_id,
        payload=dict(payload or {}),
    )

    indexed_to = _today_evidence_index()
    indexed = False
    error = ""
    if indexer_client is not None:
        doc = record.model_dump()
        doc["@timestamp"] = registered_at
        try:
            # BUG-005: write with a deterministic _id = evidence_id so
            # re-registering the same (case_id, path, sha256) upserts in
            # place instead of appending a duplicate row (mirrors case_init
            # idempotency). bulk_index auto-generated a fresh _id each call,
            # which is why nist1 evidence showed 4 docs for 2 artifacts.
            await indexer_client.index_one(indexed_to, doc, doc_id=evidence_id)
            indexed = True
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "evidence_register: indexer write failed for %s: %s",
                evidence_id,
                exc,
            )

    return EvidenceRegisterResult(
        evidence=record,
        indexed_to=indexed_to,
        indexed=indexed,
        error=error,
    )
