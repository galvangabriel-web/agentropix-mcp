"""wazuh_check_intel — operator-facing CDB membership check.

User-journey ``tool-A`` from the 2026-05-11 4-tools evaluation:

    "Is this hash known to Wazuh Intel?"

Distinct from ``wazuh_hunt_ioc``:

    * ``wazuh_hunt_ioc``  -> searches ``wazuh-alerts-*`` for FIRINGS
    * ``wazuh_check_intel`` -> queries CDB lists for MEMBERSHIP

A value can be on the watchlist but never have fired (no matching event
ever entered Wazuh). This tool answers the membership question without
requiring any alert traffic.

Output-sanitisation policy mirrors ``wazuh_hunt_ioc`` (master-report
WLV-15 / F-13): the raw value is never echoed back; callers receive a
SHA-256 prefix digest and the structured match metadata.

Cross-tool field naming
-----------------------
* ``value_digest`` here  == ``ioc_digest``  in ``wazuh_hunt_ioc``
* ``kind`` here          == ``ioc_type``    in ``wazuh_hunt_ioc``
* ``manager_reachable``  vs ``indexer_reachable`` — DIFFERENT (these
   tools hit the Wazuh manager API and the OpenSearch indexer
   respectively; the asymmetry is deliberate)
* ``entries`` (CDB membership rows) vs ``hits`` (alert documents) —
   DIFFERENT semantics, intentional

The first two pairs are construction-identical between the tools; the
divergent names are kept to make the per-tool field semantics explicit
to MCP callers. An ADR-style note is recorded here so future tool
authors (tool-C, tool-D in the 2026-05-11 4-tools evaluation) can
either continue this pattern or unify — but the choice is on record.
"""

from __future__ import annotations

import hashlib
import logging

from agentropix_mcp.wrappers._safe_tool import safe_tool

logger = logging.getLogger(__name__)


def register_wazuh_intel_tools(app) -> None:
    """Register ``wazuh_check_intel`` on the FastMCP app.

    Mirrors the ``register_wazuh_tools`` shape from ``wazuh_tools.py`` so
    the call-site in ``fastmcp_app.py`` is symmetric.
    """

    @app.tool()  # type: ignore[misc]
    @safe_tool(tool_name="wazuh_check_intel")
    async def wazuh_check_intel(
        value: str,
        kind: str | None = None,
        lists: list[str] | None = None,
    ) -> dict:
        """Check whether ``value`` is present in any Agentropix CDB list.

        Args:
            value: the IOC to look up (hash / ip / image / regkey / module).
                Compared case-insensitively for hex hashes, case-sensitively
                otherwise. Treated as opaque on the wire; sanitised to a
                SHA-256 prefix digest before returning (F-13).
            kind: optional hint - one of ``ip`` | ``md5`` | ``sha256`` |
                ``image`` | ``regkey`` | ``module``. When provided, only
                the matching CDB list is fetched (faster, narrower).
                When omitted, all six Agentropix CDB lists are checked.
            lists: optional explicit list of CDB list names to query.
                Overrides ``kind``. Names outside the agentropix_*
                namespace are rejected (returns warning).

        Returns:
            dict with::

                {
                    "value_digest":   str,           # 16-char SHA-256 prefix
                    "kind":           str | None,
                    "present":        bool,
                    "lists_checked":  [str],
                    "manager_reachable": bool,
                    "entries":        [
                        {
                            "list":       str,
                            "value":      str,        # the raw value (echo back is OK -
                                                      # it was already in the CDB which the
                                                      # operator can read directly; the
                                                      # F-13 sanitisation applies to the
                                                      # caller's input, not to existing
                                                      # CDB contents)
                            "case_id":    str,
                            "confidence": str,
                            "context":    str,
                        }
                    ],
                    "warning":        str | None,    # absent on success
                }

            On config error or manager unreachable, returns the same
            shape with ``manager_reachable=False`` and ``entries=[]``.
            The ``@safe_tool`` decorator converts any escaped exception
            to an ``{"error": ...}`` envelope.
        """
        from agentropix_mcp.wazuh.client import WazuhClient
        from agentropix_mcp.wazuh.config import WazuhConfig
        from agentropix_mcp.wazuh.tag_schema import (
            AGENTROPIX_CDB_LISTS,
            list_for_value_kind,
            match,
            parse_cdb_body,
        )

        value_digest = hashlib.sha256(
            value.encode("utf-8", errors="replace")
        ).hexdigest()[:16]
        safe_kind = None
        if kind is not None:
            safe_kind = "".join(
                c for c in kind if c.isalnum() or c in "_-"
            )[:16] or None

        empty_envelope = {
            "value_digest":      value_digest,
            "kind":              safe_kind,
            "present":           False,
            "lists_checked":     [],
            "manager_reachable": False,
            "entries":           [],
        }

        try:
            config = WazuhConfig.from_env()
        except Exception as exc:  # noqa: BLE001
            return {**empty_envelope, "warning": f"WazuhConfig.from_env failed: {type(exc).__name__}"}

        if not config.manager_url or not config.api_user or not config.api_password:
            return {
                **empty_envelope,
                "warning": (
                    "Manager not configured: set WAZUH_MANAGER_URL + "
                    "AGENTROPIX_WAZUH_API_USER + AGENTROPIX_WAZUH_API_PASSWORD"
                ),
            }

        # Resolve which lists to query
        if lists is not None:
            # Reject anything outside the agentropix_* namespace
            invalid = [n for n in lists if not n.startswith("agentropix_")]
            if invalid:
                return {
                    **empty_envelope,
                    "warning": f"lists outside agentropix_* namespace rejected: {invalid}",
                }
            target_lists = list(lists)
        elif safe_kind:
            mapped = list_for_value_kind(safe_kind)
            if mapped is None:
                return {
                    **empty_envelope,
                    "warning": f"unknown kind {safe_kind!r}; supported: ip|md5|sha256|image|regkey|module",
                }
            target_lists = [mapped]
        else:
            target_lists = list(AGENTROPIX_CDB_LISTS)

        # Build a read-only manager client. WazuhClient.__init__ accepts
        # thymus=None/evidence_gate=None and lazy-constructs the defaults,
        # and the _request method short-circuits both stages on GET (per
        # the test_request_calls_thymus_and_gate suite). So GET-only calls
        # are safe with no token.
        client = WazuhClient(
            config,
            operator="wazuh_check_intel",
            case_id="N/A",
        )

        entries: list[dict] = []
        lists_actually_checked: list[str] = []
        reachable = True
        last_warning: str | None = None

        try:
            for list_name in target_lists:
                try:
                    body = await client.get_cdb_list(list_name)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "wazuh_check_intel GET %s failed: %s",
                        list_name, type(exc).__name__,
                    )
                    reachable = False
                    last_warning = f"manager error on {list_name}: {type(exc).__name__}"
                    continue

                lists_actually_checked.append(list_name)
                if not body:
                    continue  # 404 / empty list -> skip

                tags = parse_cdb_body(body)
                hits = match(value, tags, kind_hint=safe_kind)
                for hit in hits:
                    entries.append({"list": list_name, **hit.as_dict()})
        finally:
            close_fn = getattr(client, "aclose", None)
            if close_fn:
                try:
                    await close_fn()
                except Exception:  # noqa: BLE001
                    pass

        result: dict = {
            "value_digest":      value_digest,
            "kind":              safe_kind,
            "present":           bool(entries),
            "lists_checked":     lists_actually_checked,
            "manager_reachable": reachable,
            "entries":           entries,
        }
        if last_warning and not reachable:
            result["warning"] = last_warning
        return result

    logger.info("Wazuh intel check tool registered (wazuh_check_intel)")
