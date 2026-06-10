"""WZ-022 (W-274) + SIFT-W-285: Index-template constants for Agentropix-owned indices.

Constants here are passed verbatim to ``IndexerClient.put_index_template()``.
They are deliberately kept as plain dicts (not Pydantic models) so the body
matches the OpenSearch ``PUT /_index_template/<name>`` payload shape 1:1 and
the operator can diff a template change against the upstream OpenSearch
reference without an intermediate translation layer.

Design notes:

  - **Dedicated index patterns** (``agentropix-*``). Pollution of
    ``wazuh-alerts-*`` was rejected because Wazuh dashboards + the manager
    ILM policy assume Manager-shaped docs; mixing schemas breaks both.

  - **Single shard / zero replicas** to match the production single-node
    ``wazuh-cluster``. Replica count is the conservative choice for a
    single-node cluster; a future multi-node deployment can override via
    a custom template composed on top of this base.

  - **No ILM policy attached at template level.** ILM is managed
    separately via ``PUT _plugins/_ism/policies/...`` so an operator can
    swap retention without touching this constant. The approvals index
    needs an ``ism_template`` that targets a ``read_only`` action so
    historical approval rows cannot be tampered with after the hot
    window closes — that policy lives in :mod:`ism_policies` (new code,
    SIFT-W-285 follow-up).

  - **Mappings** lock the high-signal fields needed for dashboard queries
    and the new approval / case / provenance state machine introduced
    in SIFT-W-285. ``payload`` stays as a generic ``object`` so the
    finding-emitter can evolve without a template churn.

SIFT-W-285 additions (2026-05-27):

  The Valhuntir → Wazuh feasibility crew identified that the original
  W-274 findings template had no explicit fields for the DRAFT →
  APPROVED state machine, the case-scoping key, or provenance tier.
  This module now also exports per-index templates for the four sibling
  indices required by the MVP plan (timeline, evidence, iocs, cases,
  approvals, reports). The approver field is mapped as a single
  ``keyword`` per the operator decision — OpenSearch ``keyword`` is
  polyglot (accepts a single string or a list of strings without a
  reindex), so future multi-examiner support is purely an API-layer
  change, not a schema migration.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    # Original W-274 exports — kept for backward compatibility.
    "AGENTROPIX_FINDINGS_INDEX_PATTERN",
    "AGENTROPIX_FINDINGS_TEMPLATE_NAME",
    "AGENTROPIX_FINDINGS_TEMPLATE",
    # SIFT-W-285 additions.
    "AGENTROPIX_TIMELINE_INDEX_PATTERN",
    "AGENTROPIX_TIMELINE_TEMPLATE_NAME",
    "AGENTROPIX_TIMELINE_TEMPLATE",
    "AGENTROPIX_EVIDENCE_INDEX_PATTERN",
    "AGENTROPIX_EVIDENCE_TEMPLATE_NAME",
    "AGENTROPIX_EVIDENCE_TEMPLATE",
    "AGENTROPIX_IOCS_INDEX_PATTERN",
    "AGENTROPIX_IOCS_TEMPLATE_NAME",
    "AGENTROPIX_IOCS_TEMPLATE",
    "AGENTROPIX_CASES_INDEX_PATTERN",
    "AGENTROPIX_CASES_TEMPLATE_NAME",
    "AGENTROPIX_CASES_TEMPLATE",
    "AGENTROPIX_APPROVALS_INDEX_PATTERN",
    "AGENTROPIX_APPROVALS_TEMPLATE_NAME",
    "AGENTROPIX_APPROVALS_TEMPLATE",
    "AGENTROPIX_REPORTS_INDEX_PATTERN",
    "AGENTROPIX_REPORTS_TEMPLATE_NAME",
    "AGENTROPIX_REPORTS_TEMPLATE",
    "ALL_AGENTROPIX_TEMPLATES",
]


# --- Shared building blocks (SIFT-W-285) -------------------------------- #
#
# Pulled out as constants so the same approval / case / provenance
# field shape is shared across findings, timeline events, and any other
# stateful artifact. Changing the schema in one place updates every
# index that references it — and the unit tests pin the structure.


_DEFAULT_SETTINGS: dict[str, Any] = {
    "index": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "5s",
    }
}


_CASE_FIELDS: dict[str, Any] = {
    # case_id pins every document to a case. Required for cross-case
    # scoping and for the agentropix-cases index lookup. Keyword so it
    # supports both exact-term filtering and wildcard prefix queries.
    "case_id": {"type": "keyword"},
}


_PROVENANCE_FIELDS: dict[str, Any] = {
    # Mirrors Valhuntir's provenance tier (MCP > HOOK > SHELL > NONE).
    # Keyword so the report-reconciliation routine can filter
    # APPROVED-but-NONE-provenance defensively (a finding without
    # provenance must never reach an APPROVED state).
    "provenance": {"type": "keyword"},
}


_APPROVAL_FIELDS: dict[str, Any] = {
    "approval": {
        "properties": {
            # State machine: DRAFT → APPROVED | REJECTED, APPROVED → REVOKED.
            # Enum enforced at the wrapper layer in ``wazuh_index_findings``
            # (the index template is permissive so we never break ingest;
            # the wrapper rejects bad transitions).
            "status": {"type": "keyword"},
            # ``approver`` is a single ``keyword`` today (per operator
            # decision 2026-05-27). OpenSearch keyword is polyglot — when
            # multi-examiner attribution lands later, the sidecar can
            # emit a JSON array under the same field with zero reindex.
            "approver": {"type": "keyword"},
            "approved_at": {"type": "date"},
            # HMAC-SHA256 over (case_id || finding_id || prev_doc_hash
            # || approver || status || approved_at). PBKDF2-derived key
            # is browser-local; never sent over the wire. Indexed=false
            # so it doesn't pollute the keyword field-data heap; we only
            # ever retrieve it by _id.
            "hmac_signature": {"type": "keyword", "index": False},
            # prev_doc_hash links each approval-state transition to the
            # immediately-prior document state — the chain that lets the
            # report-time reconciliation routine detect tampering.
            "prev_doc_hash": {"type": "keyword", "index": False},
        }
    }
}


def _merge(*parts: dict[str, Any]) -> dict[str, Any]:
    """Shallow-merge dicts left-to-right. Later wins on key collision."""
    out: dict[str, Any] = {}
    for part in parts:
        out.update(part)
    return out


# --- findings (W-274, extended SIFT-W-285) ------------------------------ #

AGENTROPIX_FINDINGS_INDEX_PATTERN: str = "agentropix-findings-*"
"""Index pattern owned by Agentropix findings emitter. Dedicated to avoid
collision with ``wazuh-alerts-*`` / ``wazuh-states-*`` schemas."""

AGENTROPIX_FINDINGS_TEMPLATE_NAME: str = "agentropix-findings"
"""Template name used at ``PUT /_index_template/<name>``."""


AGENTROPIX_FINDINGS_TEMPLATE: dict[str, Any] = {
    "index_patterns": [AGENTROPIX_FINDINGS_INDEX_PATTERN],
    "priority": 100,
    "template": {
        "settings": _DEFAULT_SETTINGS,
        "mappings": {
            "dynamic": "true",
            "properties": _merge(
                {
                    "@timestamp": {"type": "date"},
                    "finding_id": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "mitre_techniques": {"type": "keyword"},
                    # SIFT-W-285: denorm field for executive aggregation.
                    # Tactics are derived from techniques on ingest.
                    "mitre_tactics": {"type": "keyword"},
                    "source_run_id": {"type": "keyword"},
                    "hmac_seal": {"type": "keyword", "index": False},
                    "payload": {"type": "object", "enabled": True},
                },
                _CASE_FIELDS,
                _PROVENANCE_FIELDS,
                _APPROVAL_FIELDS,
            ),
        },
    },
    "_meta": {
        "owner": "agentropix-sift",
        "ticket": "SIFT-W-274 / WZ-022 + SIFT-W-285",
    },
}


# --- timeline events (SIFT-W-285) --------------------------------------- #

AGENTROPIX_TIMELINE_INDEX_PATTERN: str = "agentropix-timeline-*"
AGENTROPIX_TIMELINE_TEMPLATE_NAME: str = "agentropix-timeline"
AGENTROPIX_TIMELINE_TEMPLATE: dict[str, Any] = {
    "index_patterns": [AGENTROPIX_TIMELINE_INDEX_PATTERN],
    "priority": 100,
    "template": {
        "settings": _DEFAULT_SETTINGS,
        "mappings": {
            "dynamic": "true",
            "properties": _merge(
                {
                    "@timestamp": {"type": "date"},
                    "event_id": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "source": {"type": "keyword"},
                    "host": {"type": "keyword"},
                    "user": {"type": "keyword"},
                    "summary": {"type": "text"},
                    "linked_finding_ids": {"type": "keyword"},
                    "evidence_audit_ids": {"type": "keyword"},
                    "hmac_seal": {"type": "keyword", "index": False},
                    "payload": {"type": "object", "enabled": True},
                },
                _CASE_FIELDS,
                _PROVENANCE_FIELDS,
                _APPROVAL_FIELDS,
            ),
        },
    },
    "_meta": {"owner": "agentropix-sift", "ticket": "SIFT-W-285"},
}


# --- evidence registry (SIFT-W-285) ------------------------------------- #

AGENTROPIX_EVIDENCE_INDEX_PATTERN: str = "agentropix-evidence-*"
AGENTROPIX_EVIDENCE_TEMPLATE_NAME: str = "agentropix-evidence"
AGENTROPIX_EVIDENCE_TEMPLATE: dict[str, Any] = {
    "index_patterns": [AGENTROPIX_EVIDENCE_INDEX_PATTERN],
    "priority": 100,
    "template": {
        "settings": _DEFAULT_SETTINGS,
        "mappings": {
            "dynamic": "true",
            "properties": _merge(
                {
                    "@timestamp": {"type": "date"},
                    "evidence_id": {"type": "keyword"},
                    "path": {"type": "keyword"},
                    "description": {"type": "text"},
                    "sha256": {"type": "keyword"},
                    "size_bytes": {"type": "long"},
                    "examiner_id": {"type": "keyword"},
                    "registered_at": {"type": "date"},
                    # Chain-of-custody pointer to actions.jsonl-equivalent.
                    "audit_id": {"type": "keyword"},
                    "hmac_seal": {"type": "keyword", "index": False},
                    "payload": {"type": "object", "enabled": True},
                },
                _CASE_FIELDS,
            ),
        },
    },
    "_meta": {"owner": "agentropix-sift", "ticket": "SIFT-W-285"},
}


# --- IOCs (SIFT-W-285) -------------------------------------------------- #
#
# Distinct from ``wazuh_publish_iocs`` which writes to the Wazuh
# **Manager** CDB list. This index is for queryable, case-scoped IOCs
# that originate inside an agentropix investigation.

AGENTROPIX_IOCS_INDEX_PATTERN: str = "agentropix-iocs-*"
AGENTROPIX_IOCS_TEMPLATE_NAME: str = "agentropix-iocs"
AGENTROPIX_IOCS_TEMPLATE: dict[str, Any] = {
    "index_patterns": [AGENTROPIX_IOCS_INDEX_PATTERN],
    "priority": 100,
    "template": {
        "settings": _DEFAULT_SETTINGS,
        "mappings": {
            "dynamic": "true",
            "properties": _merge(
                {
                    "@timestamp": {"type": "date"},
                    "ioc_id": {"type": "keyword"},
                    # Type discriminator: ipv4 / ipv6 / domain / url /
                    # sha256 / sha1 / md5 / mutex / service_name / etc.
                    "ioc_type": {"type": "keyword"},
                    "value": {"type": "keyword"},
                    # IOCs may extract from multiple findings; keep as a
                    # keyword (polyglot — accepts single or list values).
                    "linked_finding_ids": {"type": "keyword"},
                    "mitre_techniques": {"type": "keyword"},
                    "first_seen": {"type": "date"},
                    "last_seen": {"type": "date"},
                    "hmac_seal": {"type": "keyword", "index": False},
                    "payload": {"type": "object", "enabled": True},
                },
                _CASE_FIELDS,
                _PROVENANCE_FIELDS,
            ),
        },
    },
    "_meta": {"owner": "agentropix-sift", "ticket": "SIFT-W-285"},
}


# --- cases (SIFT-W-285) ------------------------------------------------- #
#
# Dedicated index (operator decision 2026-05-27) rather than a
# ``payload.case_meta.*`` sub-doc on findings. One document per case;
# updated in-place by ``case_init`` / ``case_status`` / case-close
# tooling. ``case_id`` doubles as the document _id for upsert idempotency.

AGENTROPIX_CASES_INDEX_PATTERN: str = "agentropix-cases"
AGENTROPIX_CASES_TEMPLATE_NAME: str = "agentropix-cases"
AGENTROPIX_CASES_TEMPLATE: dict[str, Any] = {
    "index_patterns": [AGENTROPIX_CASES_INDEX_PATTERN],
    "priority": 100,
    "template": {
        "settings": _DEFAULT_SETTINGS,
        "mappings": {
            "dynamic": "true",
            "properties": _merge(
                {
                    "@timestamp": {"type": "date"},
                    "case_name": {"type": "text"},
                    "description": {"type": "text"},
                    "status": {"type": "keyword"},
                    "examiner_id": {"type": "keyword"},
                    "incident_type": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "started_at": {"type": "date"},
                    "ended_at": {"type": "date"},
                    "scope": {"type": "text"},
                    "team": {"type": "keyword"},
                    "tags": {"type": "keyword"},
                    "case_dir": {"type": "keyword"},
                    "payload": {"type": "object", "enabled": True},
                },
                _CASE_FIELDS,
            ),
        },
    },
    "_meta": {"owner": "agentropix-sift", "ticket": "SIFT-W-285"},
}


# --- approvals — append-only, hash-chained (SIFT-W-285) ----------------- #
#
# One document per approval-state transition. NEVER updated in place
# (the index-level ISM policy enforces ``read_only`` after the hot
# window). The hash-chain through ``prev_approval_hash`` is what the
# report-time reconciliation routine walks to detect tampering.

AGENTROPIX_APPROVALS_INDEX_PATTERN: str = "agentropix-approvals-*"
AGENTROPIX_APPROVALS_TEMPLATE_NAME: str = "agentropix-approvals"
AGENTROPIX_APPROVALS_TEMPLATE: dict[str, Any] = {
    "index_patterns": [AGENTROPIX_APPROVALS_INDEX_PATTERN],
    "priority": 100,
    "template": {
        "settings": _DEFAULT_SETTINGS,
        "mappings": {
            "dynamic": "strict",  # approvals are append-only and
            # tightly schema'd — refuse dynamic field discovery so an
            # LLM-crafted payload can't smuggle extra fields past the
            # wrapper's validation.
            "properties": _merge(
                {
                    "@timestamp": {"type": "date"},
                    "approval_id": {"type": "keyword"},
                    # Pointer to the finding (or timeline event) this
                    # approval transitions.
                    "target_id": {"type": "keyword"},
                    "target_type": {"type": "keyword"},  # finding|timeline
                    "from_status": {"type": "keyword"},
                    "to_status": {"type": "keyword"},
                    "approver": {"type": "keyword"},
                    "reason": {"type": "text"},
                    "hmac_signature": {"type": "keyword", "index": False},
                    "prev_approval_hash": {"type": "keyword", "index": False},
                    # Server-side nonce echoed in the HMAC payload to
                    # defeat replay attacks across the challenge-response.
                    "nonce": {"type": "keyword", "index": False},
                },
                _CASE_FIELDS,
            ),
        },
    },
    "_meta": {"owner": "agentropix-sift", "ticket": "SIFT-W-285"},
}


# --- reports — HMAC-sealed mirror of findings at report time (SIFT-W-285) #

AGENTROPIX_REPORTS_INDEX_PATTERN: str = "agentropix-reports-*"
AGENTROPIX_REPORTS_TEMPLATE_NAME: str = "agentropix-reports"
AGENTROPIX_REPORTS_TEMPLATE: dict[str, Any] = {
    "index_patterns": [AGENTROPIX_REPORTS_INDEX_PATTERN],
    "priority": 100,
    "template": {
        "settings": _DEFAULT_SETTINGS,
        "mappings": {
            "dynamic": "true",
            "properties": _merge(
                {
                    "@timestamp": {"type": "date"},
                    # Deterministic id = sha256(case_id || profile ||
                    # snapshot_at) — guarantees report-generation
                    # idempotency.
                    "report_id": {"type": "keyword"},
                    "profile": {"type": "keyword"},  # full|executive|...
                    "snapshot_at": {"type": "date"},
                    "examiner_id": {"type": "keyword"},
                    # Hash of (case_id || sorted approved finding_ids
                    # || profile) — lets the reconciliation routine
                    # confirm the report is built from the exact set
                    # of approved findings it claims.
                    "content_hash": {"type": "keyword", "index": False},
                    "hmac_seal": {"type": "keyword", "index": False},
                    # Rendered JSON + (optional) rendered markdown.
                    "payload": {"type": "object", "enabled": True},
                },
                _CASE_FIELDS,
            ),
        },
    },
    "_meta": {"owner": "agentropix-sift", "ticket": "SIFT-W-285"},
}


# --- Convenience registry ---------------------------------------------- #
#
# Bulk-apply order: cases first (so other indices can validate case_id
# against it), then findings/timeline/evidence/iocs in parallel, then
# approvals (depends on findings being writeable), then reports
# (depends on approvals being queryable for reconciliation).

ALL_AGENTROPIX_TEMPLATES: list[tuple[str, dict[str, Any]]] = [
    (AGENTROPIX_CASES_TEMPLATE_NAME, AGENTROPIX_CASES_TEMPLATE),
    (AGENTROPIX_FINDINGS_TEMPLATE_NAME, AGENTROPIX_FINDINGS_TEMPLATE),
    (AGENTROPIX_TIMELINE_TEMPLATE_NAME, AGENTROPIX_TIMELINE_TEMPLATE),
    (AGENTROPIX_EVIDENCE_TEMPLATE_NAME, AGENTROPIX_EVIDENCE_TEMPLATE),
    (AGENTROPIX_IOCS_TEMPLATE_NAME, AGENTROPIX_IOCS_TEMPLATE),
    (AGENTROPIX_APPROVALS_TEMPLATE_NAME, AGENTROPIX_APPROVALS_TEMPLATE),
    (AGENTROPIX_REPORTS_TEMPLATE_NAME, AGENTROPIX_REPORTS_TEMPLATE),
]
"""Bulk-application list. ``IndexerClient.put_index_template`` can be
mapped over this in a single startup pass so a fresh deployment ends
up with all 7 templates present."""
