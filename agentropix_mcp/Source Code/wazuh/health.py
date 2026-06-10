"""WLV-06 — CDB-load health probe.

Closes §4.1 #3 of the WLV master report (`docs/WAZUH-CAPABILITY-LIVE-
VALIDATION-MASTER-REPORT-2026-05-08.md`): wire warning code 7616 from
``GET /manager/logs`` into a discoverable signal so a regression of the
DEFECT-LIVE-01 trap surfaces audibly within 30 s of any manager
restart, rather than silently disabling rules for hours.

Today this ships as a standalone coordinator function
``check_cdb_load_failures()`` that the WLV-01 reconciler-aware caller
(or an operator runbook) can poll directly. When WZ-003 lands its
``wazuh_health()`` aggregator (master report §4.4 #18), this function
becomes the building block for the ``cdb_load_failures`` field on the
aggregate health envelope.

Wazuh error 7616 surface in /manager/logs::

    WARNING: (7616): List 'etc/lists/<namespace>' could not be loaded.
    Rule '<rule_id>' will be ignored.

The probe parses each warning line, extracts the namespace from
``etc/lists/<namespace>``, and returns a deduplicated list of failing
namespaces filtered to the ``agentropix_*`` prefix (so unrelated
operator-managed lists do not pollute the SIFT signal).
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Regex against the description text emitted by wazuh-analysisd at
# startup for warning code 7616. Anchored on the parenthesised code so
# operator-localised log shapes that translate "could not be loaded"
# still match the structural pattern.
_CDB_7616_RE = re.compile(
    r"\(7616\)[^']*'etc/lists/([A-Za-z0-9_./-]+)'",
)

# Default substring filter passed to /manager/logs?search=. Matches
# the canonical English message and is robust to either side of the
# parenthesised code being localised.
_CDB_7616_SEARCH = "could not be loaded"

# Limit for the namespace-prefix filter. Operators may run other CDB
# lists outside the agentropix_* namespace; this filter keeps SIFT
# health signals scoped to what SIFT controls and doesn't false-alarm
# on third-party lists the operator broke independently.
_AGENTROPIX_PREFIX = "agentropix_"


def _parse_failures(log_entries: list[dict[str, Any]]) -> list[str]:
    """Extract failing CDB namespaces from a /manager/logs page.

    Visible for unit-testing without the network round-trip.
    """
    seen: dict[str, None] = {}  # ordered set
    for entry in log_entries:
        if not isinstance(entry, dict):
            continue
        # Only warning rows are relevant; the API may return higher
        # severities too if the operator misqueried.
        if entry.get("level") not in (None, "warning", "error", "critical"):
            # We accept None here because some Wazuh versions omit
            # ``level`` when the search filter is highly selective.
            continue
        description = entry.get("description") or ""
        match = _CDB_7616_RE.search(description)
        if not match:
            continue
        name = match.group(1)
        # Strip a trailing ``.cdb`` if the message references the
        # compiled binary path; we want the canonical source name.
        if name.endswith(".cdb"):
            name = name[: -len(".cdb")]
        # Limit signal to agentropix_* namespaces so unrelated
        # operator-managed lists don't pollute the SIFT health view.
        if not name.startswith(_AGENTROPIX_PREFIX):
            continue
        seen.setdefault(name, None)
    return list(seen.keys())


async def check_cdb_load_failures(
    client: Any,
    *,
    limit: int = 200,
) -> list[str]:
    """WLV-06 probe: return failing agentropix_* CDB namespaces (or []).

    Calls ``GET /manager/logs?level=warning&search=could+not+be+loaded``
    and parses each entry's description for the 7616 pattern. Result is
    deduplicated and prefix-filtered to ``agentropix_*``.

    Returns an empty list when:
      - the manager has no 7616 warnings (healthy),
      - the manager API is unreachable / non-200 (best-effort: the
        caller must not crash on a transiently-degraded manager;
        the empty result is intentionally indistinguishable from
        "healthy" because the canonical observability story is
        WLV-02's post-restart self-test, NOT this probe in isolation),
      - the response body is malformed.

    On a healthy cluster post-restart this returns within ~30 s of the
    restart settling (Wazuh writes the analysisd startup log entries
    synchronously before accepting API traffic). The 30 s SLO is
    documented in master report §4.1 #3.
    """
    try:
        entries = await client.get_manager_logs(
            level="warning",
            search=_CDB_7616_SEARCH,
            limit=limit,
        )
    except Exception as exc:  # noqa: BLE001
        # Best-effort. A network blip during a restart-poll window is
        # expected; surfacing it as a probe failure (rather than
        # masking) lives at the WZ-003 aggregator layer.
        logger.warning(
            "WLV-06 CDB-load probe: get_manager_logs failed (%s); "
            "returning empty result",
            exc,
        )
        return []
    return _parse_failures(entries)
