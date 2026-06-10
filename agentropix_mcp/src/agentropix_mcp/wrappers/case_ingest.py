"""SIFT-W-290: ``idx_ingest`` — structured ingest of normalized findings + timeline events.

Pragmatic MVP scope: this tool accepts **pre-shaped** finding /
timeline dicts and routes them into the appropriate W-285 indices
via the existing ``IndexerClient.bulk_index`` path. It does NOT
auto-discover artifact files on disk — that's W-292 (Valhuntir-style
"`idx_ingest(case_dir)`" KAPE-orchestration which composes the
existing get_evtx / get_amcache / get_mftecmd / get_prefetch
parsers).

This MVP is exactly what an LLM client needs to push:

  1. LLM runs e.g. ``get_evtx(...)`` to parse a security log.
  2. LLM normalizes the events into a list of finding-shaped dicts.
  3. LLM calls ``idx_ingest(findings=[...], timeline_events=[...])``.

The DRAFT-gate on findings stays intact because this wrapper routes
through ``wazuh_index_findings`` for the findings half — so any LLM
attempt to bake ``approval.*`` into a normalized payload is still
stripped + WARNING-logged (W-286). Timeline events use the same
gating helper to keep the model consistent across the two
sibling indices.
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any

from pydantic import BaseModel, Field

from agentropix_mcp.wrappers.case_lifecycle import (
    get_active_case_id,
)

logger = logging.getLogger(__name__)


# --- Pydantic result --------------------------------------------------- #


class IngestOutcome(BaseModel):
    case_id: str
    hostname: str
    findings_indexed: int = 0
    findings_failed: int = 0
    findings_index: str = ""
    timeline_indexed: int = 0
    timeline_failed: int = 0
    timeline_index: str = ""
    findings_error: str = ""
    timeline_error: str = ""
    next_steps: list[str] = Field(default_factory=list)


# --- Helpers ---------------------------------------------------------- #


def _today_timeline_index() -> str:
    return "agentropix-timeline-" + dt.datetime.now(dt.UTC).strftime("%Y.%m.%d")


def _stamp_timeline_event(event: dict, case_id: str, hostname: str) -> dict:
    """Normalize a timeline event the same way the W-286 draft-gate
    normalizes findings — strip ``approval.*``, stamp DRAFT, stamp
    ``provenance=MCP``, stamp ``case_id`` from the wrapper arg if
    missing.

    Mirrors ``wazuh_tools._apply_draft_gate`` but for the timeline
    sibling; we don't reuse that helper directly because the findings
    gate goes through ``wazuh_index_findings`` (full pipeline with
    HMAC seal + run_id + indexer-outage fallback), while timeline
    events have a simpler bulk_index path.
    """
    f = dict(event)  # shallow copy, never mutate caller input
    if "approval" in f:
        logger.warning(
            "SIFT-W-290 timeline gate: approval.* stripped from event %s",
            f.get("event_id", "<unknown>"),
        )
    f["approval"] = {
        "status": "DRAFT",
        "approver": None,
        "approved_at": None,
        "hmac_signature": None,
        "prev_doc_hash": None,
    }
    hint = f.pop("_provenance_hint", "MCP")
    if not isinstance(hint, str) or hint not in {"MCP", "HOOK", "SHELL"}:
        hint = "MCP"
    f["provenance"] = hint
    f.setdefault("case_id", case_id)
    f.setdefault("host", hostname)
    f.setdefault("@timestamp", dt.datetime.now(dt.UTC).isoformat())
    return f


# --- Tool: idx_ingest -------------------------------------------------- #


async def idx_ingest(
    hostname: str,
    *,
    case_id: str | None = None,
    findings: list[dict] | None = None,
    timeline_events: list[dict] | None = None,
    dry_run: bool = True,
    mutation_token: str | None = None,
    indexer_client: Any = None,
    wazuh_index_findings_fn: Any = None,
) -> IngestOutcome:
    """SIFT-W-290 MVP ingest: route normalized findings + timeline events.

    ``findings`` is routed through ``wazuh_index_findings`` (W-274 +
    W-286 gate) so the audit seal + HMAC envelope + DRAFT enforcement
    apply identically to the path an LLM uses today.

    ``timeline_events`` are bulk-indexed into
    ``agentropix-timeline-YYYY.MM.DD`` after the same shape-only
    DRAFT/provenance/case_id stamp the findings gate applies.

    Args:
        hostname: source host these artifacts came from. Stamped into
            every timeline event (matches the W-285 timeline template's
            ``host`` keyword field). Findings stamp host via their own
            ``host.name`` sub-doc; this wrapper doesn't override that.
        case_id: optional; resolves active-case pointer when None.
        findings: list of normalized finding dicts. Empty list ⇒ skip.
        timeline_events: list of normalized event dicts. Empty list ⇒ skip.
        dry_run: forwarded to ``wazuh_index_findings``; timeline writes
            obey the same flag (no bulk_index call when ``dry_run=True``).
        mutation_token: required by ``wazuh_index_findings`` when
            ``dry_run=False``.
        indexer_client: injected for the timeline bulk_index call;
            ``wazuh_index_findings_fn`` is a separate injection point
            for the findings half (production wires the FastMCP tool;
            tests stub).
    """
    if not hostname or not isinstance(hostname, str):
        raise ValueError("hostname must be a non-empty string")

    resolved_case_id = case_id if case_id is not None else get_active_case_id()
    if resolved_case_id is None:
        raise ValueError("no active case; pass case_id= or call case_activate() first")

    findings_list = list(findings or [])
    timeline_list = list(timeline_events or [])

    outcome = IngestOutcome(
        case_id=resolved_case_id,
        hostname=hostname,
    )

    # --- findings half (routes through wazuh_index_findings) -------- #
    if findings_list:
        if wazuh_index_findings_fn is None:
            outcome.findings_error = (
                "wazuh_index_findings_fn not injected — findings half could not run"
            )
            outcome.findings_failed = len(findings_list)
        else:
            try:
                resp = await wazuh_index_findings_fn(
                    findings=findings_list,
                    case_id=resolved_case_id,
                    dry_run=dry_run,
                    mutation_token=mutation_token,
                )
                # wazuh_index_findings returns a dict envelope on
                # success or {"error": ...} on validation/gate fail.
                if isinstance(resp, dict) and "error" in resp:
                    outcome.findings_error = resp["error"]
                    outcome.findings_failed = len(findings_list)
                else:
                    outcome.findings_indexed = int(
                        (resp or {}).get("indexed_count", len(findings_list))
                    )
                    outcome.findings_failed = int((resp or {}).get("indexed_failed_count", 0))
                    outcome.findings_index = str((resp or {}).get("index", ""))
            except Exception as exc:
                outcome.findings_error = f"{type(exc).__name__}: {exc}"
                outcome.findings_failed = len(findings_list)
                logger.warning("idx_ingest findings half failed: %s", exc)

    # --- timeline half (direct bulk_index) -------------------------- #
    if timeline_list:
        outcome.timeline_index = _today_timeline_index()
        stamped = [_stamp_timeline_event(ev, resolved_case_id, hostname) for ev in timeline_list]
        if dry_run:
            outcome.timeline_indexed = 0  # not written
            outcome.timeline_error = ""  # not an error, just dry-run
        elif indexer_client is None:
            outcome.timeline_error = "indexer_client not injected"
            outcome.timeline_failed = len(stamped)
        else:
            try:
                resp = await indexer_client.bulk_index(outcome.timeline_index, stamped)
                items = (resp or {}).get("items") or []
                # bulk_index raises on errors:true; if we got here
                # everything succeeded.
                outcome.timeline_indexed = len(items) or len(stamped)
            except Exception as exc:
                outcome.timeline_error = f"{type(exc).__name__}: {exc}"
                outcome.timeline_failed = len(stamped)
                logger.warning("idx_ingest timeline half failed: %s", exc)

    # --- next-steps hints ------------------------------------------- #
    if dry_run and (findings_list or timeline_list):
        outcome.next_steps.append(
            "dry_run=True — nothing was written. Re-run with "
            "dry_run=False + a mutation_token to commit."
        )
    if outcome.findings_indexed and outcome.findings_failed == 0 and not dry_run:
        outcome.next_steps.append(
            "Findings indexed as DRAFT. Run idx_case_summary() to "
            "review or approve_finding() per finding."
        )
    if outcome.timeline_indexed and outcome.timeline_failed == 0 and not dry_run:
        outcome.next_steps.append(
            "Timeline events landed. Use idx_timeline() to bucket "
            "them or idx_search(index_pattern='agentropix-timeline-*') "
            "to scan."
        )
    if outcome.findings_failed or outcome.timeline_failed:
        outcome.next_steps.append(
            "Some events failed to index. Check the *_error fields, "
            "fix the input, and retry. Original payloads were not "
            "mutated."
        )

    return outcome
