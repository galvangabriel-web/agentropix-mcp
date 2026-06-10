"""WZ-022 / W-277 + SIFT-W-287: Index State Management (ISM) policies
for Agentropix indices.

Wazuh ships OpenSearch, which uses the Index State Management plugin
(``/_plugins/_ism/policies/<name>``) for index lifecycle automation.

W-277 (findings policy) — retention only, no rollover:

  - ``index_findings()`` writes to date-suffixed indices
    (``agentropix-findings-YYYY.MM.DD``) — one per day — so the date
    suffix already provides natural daily "rollover". The policy only
    needs to delete indices older than
    ``AGENTROPIX_FINDINGS_RETENTION_DAYS`` days.

  - **Index-creation-age based, not @timestamp based.** ISM
    ``min_index_age`` uses the index's creation timestamp. Since each
    daily index is created at most once (when the first finding of the
    day lands), the creation-age tracks the day-of-the-data within
    UTC drift bounds.

  - **`ism_template` block** auto-binds the policy to the
    ``agentropix-findings-*`` pattern: any newly-created index matching
    that pattern picks up the policy at creation time. No per-index
    ``PUT`` required.

  - **Operator-tunable retention** via
    ``AGENTROPIX_FINDINGS_RETENTION_DAYS`` (default 90, floor 1, ceiling
    3650). Floor prevents accidental same-day-delete; ceiling caps at
    ~10 years for sanity.

SIFT-W-287 (approvals policy) — hot → read_only → delete:

  - Approvals are append-only and tamper-sensitive. After a brief hot
    window (default 7 days, tunable via
    ``AGENTROPIX_APPROVALS_HOT_DAYS``) the index transitions into a
    ``read_only`` state — the OpenSearch ISM ``read_only`` action
    flips ``index.blocks.write=true``, so no further writes can land
    on that daily index. The approver service writes go to the
    current-day index only; historical days become immutable.

  - **Read-only is a write-block, not a delete.** Queries still work,
    so the report-time HMAC reconciliation routine can walk the
    historical hash-chain. The fields hosting HMAC signatures are
    ``index:false`` at the template level, so even a compromised
    write-credential cannot mutate sealed approvals.

  - **Eventually delete.** After
    ``AGENTROPIX_APPROVALS_RETENTION_DAYS`` (default 365, floor 30,
    ceiling 3650) the index is deleted — long enough to cover a
    standard reporting cycle plus discovery, short enough that the
    cluster doesn't accumulate dead approvals indefinitely.

  - **`ism_template` block** binds the policy to
    ``agentropix-approvals-*`` at index creation time.

  - Per sub-agent #3's review of the Crew #3 design: this is **new
    code**, not an extension. The pre-W-287 file only carried delete
    + hot transitions for findings.
"""

from __future__ import annotations

import os
from typing import Any

__all__ = [
    # W-277 findings policy — kept for backward compatibility.
    "AGENTROPIX_FINDINGS_ISM_POLICY_NAME",
    "AGENTROPIX_FINDINGS_ISM_RETENTION_DAYS",
    "build_findings_ism_policy",
    # SIFT-W-287 approvals policy.
    "AGENTROPIX_APPROVALS_ISM_POLICY_NAME",
    "AGENTROPIX_APPROVALS_ISM_HOT_DAYS",
    "AGENTROPIX_APPROVALS_ISM_RETENTION_DAYS",
    "build_approvals_ism_policy",
    "ALL_AGENTROPIX_ISM_POLICIES",
]


AGENTROPIX_FINDINGS_ISM_POLICY_NAME: str = "agentropix-findings"
"""Policy name used at ``PUT /_plugins/_ism/policies/<name>``."""


def _bounded_int_from_env(var: str, default: int, *, floor: int, ceiling: int) -> int:
    """Read an integer env var with floor/ceiling guards."""
    raw = os.environ.get(var, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(floor, min(ceiling, value))


def _retention_days_from_env() -> int:
    return _bounded_int_from_env("AGENTROPIX_FINDINGS_RETENTION_DAYS", 90, floor=1, ceiling=3650)


AGENTROPIX_FINDINGS_ISM_RETENTION_DAYS: int = _retention_days_from_env()
"""Effective findings-retention in days for this process. Re-evaluated at import."""


def build_findings_ism_policy(
    retention_days: int | None = None,
) -> dict[str, Any]:
    """Build the findings ISM policy body. Factory so tests can pass an
    explicit ``retention_days`` without poking the env."""
    days = retention_days if retention_days is not None else AGENTROPIX_FINDINGS_ISM_RETENTION_DAYS
    return {
        "policy": {
            "description": (
                "Agentropix findings retention -- delete indices older "
                f"than {days}d (WZ-022 / W-277)."
            ),
            "default_state": "hot",
            "states": [
                {
                    "name": "hot",
                    "actions": [],
                    "transitions": [
                        {
                            "state_name": "delete",
                            "conditions": {"min_index_age": f"{days}d"},
                        }
                    ],
                },
                {
                    "name": "delete",
                    "actions": [{"delete": {}}],
                    "transitions": [],
                },
            ],
            "ism_template": [
                {
                    "index_patterns": ["agentropix-findings-*"],
                    "priority": 100,
                }
            ],
        }
    }


# --------------------------------------------------------------------- #
# SIFT-W-287: approvals ISM policy
# --------------------------------------------------------------------- #


AGENTROPIX_APPROVALS_ISM_POLICY_NAME: str = "agentropix-approvals"
"""Policy name used at ``PUT /_plugins/_ism/policies/<name>``."""


def _approvals_hot_days_from_env() -> int:
    return _bounded_int_from_env("AGENTROPIX_APPROVALS_HOT_DAYS", 7, floor=1, ceiling=365)


def _approvals_retention_days_from_env() -> int:
    return _bounded_int_from_env(
        "AGENTROPIX_APPROVALS_RETENTION_DAYS",
        365,
        floor=30,
        ceiling=3650,
    )


AGENTROPIX_APPROVALS_ISM_HOT_DAYS: int = _approvals_hot_days_from_env()
"""Effective hot-window days for approvals (writeable). After this the
index transitions to ``read_only``."""

AGENTROPIX_APPROVALS_ISM_RETENTION_DAYS: int = _approvals_retention_days_from_env()
"""Effective total retention in days for approvals (hot + read_only)."""


def build_approvals_ism_policy(
    hot_days: int | None = None,
    retention_days: int | None = None,
) -> dict[str, Any]:
    """Build the approvals ISM policy body.

    State machine: ``hot`` (writeable) → ``locked`` (read_only) → ``delete``.

    Args:
        hot_days: number of days an approvals daily-index stays
            writeable. Defaults to ``AGENTROPIX_APPROVALS_HOT_DAYS``
            (7d). Must be < ``retention_days``.
        retention_days: total days before delete. Defaults to
            ``AGENTROPIX_APPROVALS_RETENTION_DAYS`` (365d).

    Returns:
        Policy body suitable for
        ``IndexerClient.put_ism_policy(name, body)``.
    """
    hd = hot_days if hot_days is not None else AGENTROPIX_APPROVALS_ISM_HOT_DAYS
    rd = retention_days if retention_days is not None else AGENTROPIX_APPROVALS_ISM_RETENTION_DAYS
    # Defensive: enforce hot < retention so the transition order is
    # well-formed. A retention earlier than the hot window would mean
    # an index is deleted before it ever becomes read-only.
    if hd >= rd:
        hd = max(1, rd - 1)
    return {
        "policy": {
            "description": (
                "Agentropix approvals immutability -- writeable for "
                f"{hd}d, then read_only until {rd}d (SIFT-W-287)."
            ),
            "default_state": "hot",
            "states": [
                {
                    "name": "hot",
                    "actions": [],
                    "transitions": [
                        {
                            "state_name": "locked",
                            "conditions": {"min_index_age": f"{hd}d"},
                        }
                    ],
                },
                {
                    "name": "locked",
                    "actions": [{"read_only": {}}],
                    "transitions": [
                        {
                            "state_name": "delete",
                            "conditions": {"min_index_age": f"{rd}d"},
                        }
                    ],
                },
                {
                    "name": "delete",
                    "actions": [{"delete": {}}],
                    "transitions": [],
                },
            ],
            "ism_template": [
                {
                    "index_patterns": ["agentropix-approvals-*"],
                    "priority": 100,
                }
            ],
        }
    }


# --------------------------------------------------------------------- #
# Convenience registry
# --------------------------------------------------------------------- #


ALL_AGENTROPIX_ISM_POLICIES: list[tuple[str, dict[str, Any]]] = [
    (AGENTROPIX_FINDINGS_ISM_POLICY_NAME, build_findings_ism_policy()),
    (AGENTROPIX_APPROVALS_ISM_POLICY_NAME, build_approvals_ism_policy()),
]
"""Bulk-application list. Same pattern as
``index_templates.ALL_AGENTROPIX_TEMPLATES`` — a fresh deployment can
map ``put_ism_policy`` over this in one startup pass."""
