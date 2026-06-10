"""Wazuh FastMCP tool registrations — Step 1 IOC push integration.

Exposes two FastMCP tools:
  - ``wazuh_publish_iocs``: push Tier-1/2 IOCs from a case directory to Wazuh
  - ``wazuh_hunt_ioc``: (Step 2 stub) hunt a single IOC across Wazuh alerts

Both tools route through ``orchestrator.push_iocs`` and never bypass the
Thymus STRICT + EvidenceGate write-path guards (Fix 1 / S-1).

Correct ADRs: ADR-008 (safety), ADR-016 (courtroom seal), ADR-017 (tailnet).
"""

from __future__ import annotations

import asyncio
import logging

__all__ = ["register_wazuh_tools"]

logger = logging.getLogger(__name__)


# SIFT-W-298: hard total-deadline ceiling for a single Indexer-backed tool
# call, spanning ALL retry attempts. The capacity envelope is p95 ≤ 30s
# (matches the per-request timeout), so 45s leaves headroom for one slow
# legitimate query while staying far under the ~240s MCP client ceiling
# that, when exceeded, orphans the in-flight tool_use. Bounds the worst
# case for every failure class (read-timeout, connect-retry stacking).
INDEXER_TOOL_DEADLINE_SEC = 45.0


# SIFT-W-286: provenance tiers borrowed from Valhuntir's architecture
# (MCP > HOOK > SHELL > NONE). MCP is the strongest tier — we're the
# protocol boundary itself — so a caller's hint can only DOWNGRADE.
# NONE is rejected at the gate to keep the orchestrator's invariant
# that every indexed finding has a provenance chain.
_PROVENANCE_TIERS_RANKED: tuple[str, ...] = ("MCP", "HOOK", "SHELL", "NONE")


def _apply_draft_gate(
    findings: list[dict],
    case_id: str,
) -> tuple[list[dict], list[str]]:
    """SIFT-W-286: DRAFT gate + provenance stamp + ``approval.*`` strip.

    The gate defends against LLM self-approval. The LLM cannot move
    findings out of DRAFT — only the FastAPI approval sidecar (W-285
    follow-up) is authorized to write ``approval.status="APPROVED"``,
    and it does so via an HMAC-SHA256 challenge-response on a separate
    indexer credential. Anything that arrives at this wrapper is
    forced to DRAFT regardless of what the caller said.

    Provenance is stamped server-side. The default is ``"MCP"`` —
    every finding that reaches this function has by definition crossed
    the MCP boundary. A caller may *downgrade* via a top-level
    ``"_provenance_hint"`` key (``HOOK`` or ``SHELL``); upgrades and
    garbage values fall back to ``"MCP"``. ``"NONE"`` is also silently
    upgraded because the wrapper itself is the MCP boundary, so the
    tier can never genuinely be NONE here.

    Args:
        findings: caller-supplied list of dicts. NEVER mutated in place
            — shallow copies are returned.
        case_id: wrapper-arg case identifier, applied as the default
            for any finding that didn't already carry one.

    Returns:
        ``(rewritten_findings, strip_events)``. ``strip_events`` is a
        list of human-readable strings; the caller logs each at WARNING
        so that any LLM attempt to self-approve appears in the audit
        trail rather than being silently absorbed.
    """
    strip_events: list[str] = []
    rewritten: list[dict] = []
    valid_tiers = set(_PROVENANCE_TIERS_RANKED)

    for idx, finding in enumerate(findings):
        # Shallow copy — never mutate the caller's dict. The
        # `approval` subobject is overwritten wholesale so we don't
        # need to deep-copy further.
        f = dict(finding)
        finding_id = f.get("finding_id", f"<unknown-{idx}>")

        # 1) Strip incoming approval.* — record the event for the
        #    audit trail. We log even an empty/None subobject so
        #    operators can distinguish "caller never set it" from
        #    "caller sent something we discarded".
        if "approval" in f:
            prior = f["approval"]
            shape = (
                f"{len(prior)} keys" if isinstance(prior, dict) else f"type={type(prior).__name__}"
            )
            strip_events.append(f"approval.* stripped from finding {finding_id} ({shape})")

        # 2) Stamp DRAFT. The wrapper has no authority to APPROVE;
        #    that's the sidecar's job (separate indexer credential).
        f["approval"] = {
            "status": "DRAFT",
            "approver": None,
            "approved_at": None,
            "hmac_signature": None,
            "prev_doc_hash": None,
        }

        # 3) Provenance: MCP default, accept downgrade hint, never
        #    accept an upgrade. NONE collapses to MCP because the
        #    wrapper IS the MCP boundary.
        hint = f.pop("_provenance_hint", "MCP")
        if not isinstance(hint, str) or hint not in valid_tiers or hint == "NONE":
            hint = "MCP"
        f["provenance"] = hint

        # 4) Ensure case_id is stamped. The W-285 template promotes
        #    case_id to a top-level keyword field — without it the
        #    case-scoping queries in the future report-mcp profiles
        #    silently miss the finding.
        f.setdefault("case_id", case_id)

        rewritten.append(f)

    return rewritten, strip_events


def register_wazuh_tools(app: object) -> None:  # type: ignore[type-arg]
    """Register Wazuh tools on the FastMCP app instance.

    Called from ``fastmcp_app._build_app()`` following the existing
    registration pattern for correlation wrappers.

    Args:
        app: FastMCP app instance. The tool decorator is obtained via
            ``app.tool()``.
    """
    tool = getattr(app, "tool", None)
    if tool is None:
        raise RuntimeError("register_wazuh_tools received an object without a .tool() method")

    @app.tool()  # type: ignore[misc]
    async def wazuh_publish_iocs(
        case_dir: str,
        dry_run: bool = True,
        mutation_token: str | None = None,
    ) -> dict:
        """Push Tier-1/2 IOCs from an Agentropix case directory to Wazuh.

        Performs the full Step-1 IOC push pipeline:
          1. Loads IOCInventory from case_dir (reads MASTER-IOCS.json)
          2. Classifies each IOC as Tier-1, Tier-2, or Tier-3-excluded
          3. Validates all values through Thymus STRICT (ADR-008)
          4. If dry_run=False: verifies mutation_token via EvidenceGate
          5. Transforms IOCs to CDB payloads (pipe-separated values)
          6. PUTs each CDB list + rules XML to the Wazuh Manager API
          7. Triggers one coalesced manager restart
          8. Stamps each PUT with HMAC-SHA256 seal (ADR-016)
          9. Appends structured audit events to wazuh-audit.jsonl

        Args:
            case_dir: Absolute path to the Agentropix case directory
                (must contain MASTER-IOCS.json).
            dry_run: When True (default), compute and return the push plan
                without writing to Wazuh. Set to False with a valid
                mutation_token to execute the push.
            mutation_token: EvidenceGate mutation token in ``egt_<ULID>``
                format. Required when dry_run=False. Source from the
                environment variable ``AGENTROPIX_MUTATION_TOKEN``.

        Returns:
            dict with keys: case_id, pushed, skipped_tier3,
                skipped_idempotent, failed, restart_pending, dry_run,
                seal, run_id.
        """
        from agentropix_mcp.wazuh.config import WazuhConfig
        from agentropix_mcp.wazuh.orchestrator import push_iocs

        try:
            config = WazuhConfig.from_env()
        except Exception as exc:
            return {
                "error": f"Wazuh configuration error: {exc}",
                "case_dir": case_dir,
                "dry_run": dry_run,
            }

        if not config.integration_enabled:
            logger.info("Wazuh integration disabled (WAZUH_INTEGRATION_ENABLED=false)")
            return {
                "error": "Wazuh integration is disabled; set WAZUH_INTEGRATION_ENABLED=true",
                "case_dir": case_dir,
                "dry_run": dry_run,
            }

        if not dry_run and config.dry_run_only:
            return {
                "error": (
                    "WAZUH_DRY_RUN_ONLY=true prevents --confirm pushes; set WAZUH_DRY_RUN_ONLY=false to enable writes"
                ),
                "case_dir": case_dir,
                "dry_run": dry_run,
            }

        result = await push_iocs(
            case_dir,
            config=config,
            evidence_token=mutation_token,
            dry_run=dry_run,
        )
        return result.model_dump()

    @app.tool()  # type: ignore[misc]
    async def wazuh_hunt_ioc(
        ioc_value: str,
        ioc_type: str = "ip",
        time_range_hours: int = 24 * 90,
        size: int = 100,
    ) -> dict:
        """Retro-hunt a single IOC across Wazuh alerts (WZ-001 Step 2).

        Searches the ``wazuh-alerts-*`` indices for events matching
        ``ioc_value`` of ``ioc_type`` within the last ``time_range_hours``.
        Default lookback is 90 days (T-FLOW §3 retention).

        Args:
            ioc_value: the IOC to hunt. Treated as opaque; sanitised
                only at the response boundary (master-report WLV-15
                outbound-IOC sanitisation).
            ioc_type: one of ``ip``, ``sha256``, ``md5``, ``domain``,
                ``process_image``, ``process_module``, ``rule_id``,
                ``username``. Each maps to a specific alert field path
                via ``term`` (keyword) or ``match_phrase`` (analysed
                text). C3 F5: ``term`` on ``<field>.keyword`` for hashes
                / IPs avoids the IPv4-on-`.` tokenisation bug.
            time_range_hours: retro-hunt window in hours.
                Default 2160 (90 days). Master-report §F4.4 capacity
                envelope: p95 ≤ 30s.
            size: max hits to return (1..500). Capped at 500 per
                §F4.4. For >500 hits, paginate via subsequent calls
                with narrower ``time_range_hours``.

        Returns:
            dict with::

                {
                    "ioc_digest": str,          # SHA-256 prefix (F-13 sanitisation)
                    "ioc_type": str,
                    "time_range_hours": int,
                    "indexer_reachable": bool,
                    "total_hits": int,
                    "returned_hits": int,
                    "hits": [
                        {  # ObservationAlert.model_dump() shape
                            "kind": "alert",
                            "rule_id": int,
                            "rule_level": int,
                            ...
                        }
                    ],
                    "warning": str | None,      # absent on success
                }

            On indexer error / config gap, returns the same shape with
            ``indexer_reachable=False`` and ``hits=[]``. The
            ``_safe_tool`` decorator (WZ-021) catches any escaped
            exception and converts to ``{"error": ...}`` envelope
            instead.
        """
        import hashlib

        from agentropix_mcp.wazuh.config import WazuhConfig
        from agentropix_mcp.wazuh.indexer_client import (
            IndexerClient,
            QueryTimeoutError,
            _wazuh_retry_policy,
        )
        from agentropix_mcp.wrappers._hunt_ioc_dsl import (
            build_hunt_query,
            supported_ioc_types,
        )
        from agentropix_mcp.wrappers.observations import (
            ObservationAlert,
        )

        # Sanitise outputs (master-report WLV-15) — never echo raw IOC
        # back into the LLM response surface; use a SHA-256 prefix
        # instead. Operators correlate via the prefix; the raw value
        # stays in indexer logs.
        ioc_digest = hashlib.sha256(ioc_value.encode("utf-8", errors="replace")).hexdigest()[:16]
        safe_ioc_type = "".join(c for c in ioc_type if c.isalnum() or c in "_-")[:32]

        if ioc_type not in supported_ioc_types():
            return {
                "ioc_digest": ioc_digest,
                "ioc_type": safe_ioc_type,
                "time_range_hours": int(time_range_hours),
                "indexer_reachable": False,
                "total_hits": 0,
                "returned_hits": 0,
                "hits": [],
                "warning": (
                    f"unsupported ioc_type {safe_ioc_type!r}; supported: {supported_ioc_types()}"
                ),
            }

        try:
            config = WazuhConfig.from_env()
        except Exception as exc:
            return {
                "ioc_digest": ioc_digest,
                "ioc_type": safe_ioc_type,
                "time_range_hours": int(time_range_hours),
                "indexer_reachable": False,
                "total_hits": 0,
                "returned_hits": 0,
                "hits": [],
                "warning": f"WazuhConfig.from_env failed: {type(exc).__name__}",
            }

        if not config.indexer_url or not config.indexer_user or not config.indexer_password:
            return {
                "ioc_digest": ioc_digest,
                "ioc_type": safe_ioc_type,
                "time_range_hours": int(time_range_hours),
                "indexer_reachable": False,
                "total_hits": 0,
                "returned_hits": 0,
                "hits": [],
                "warning": (
                    "Indexer not configured: set WAZUH_INDEXER_URL + WAZUH_INDEXER_USER + WAZUH_INDEXER_PASS"
                ),
            }

        # Cap size to MAX (DSL builder also clamps; double-guard).
        size = max(1, min(int(size), 500))
        body = build_hunt_query(
            ioc_value,
            ioc_type,
            time_range_hours=int(time_range_hours),
            size=size,
        )

        client = IndexerClient(
            indexer_url=config.indexer_url,
            indexer_user=config.indexer_user,
            indexer_password=config.indexer_password,
            tls_verify=config.indexer_tls_verify,
            tls_ca_bundle=config.tls_ca_bundle,
        )

        @_wazuh_retry_policy()
        async def _do_search():
            return await client.search("wazuh-alerts-*", body, size=size)

        def _degraded(warning: str) -> dict:
            return {
                "ioc_digest": ioc_digest,
                "ioc_type": safe_ioc_type,
                "time_range_hours": int(time_range_hours),
                "indexer_reachable": False,
                "total_hits": 0,
                "returned_hits": 0,
                "hits": [],
                "warning": warning,
            }

        try:
            try:
                # SIFT-W-298: hard total deadline across all retries so a
                # slow / degraded indexer can never hang past the MCP
                # client ceiling and orphan the tool_use.
                payload = await asyncio.wait_for(_do_search(), timeout=INDEXER_TOOL_DEADLINE_SEC)
            finally:
                await client.aclose()
        except (TimeoutError, QueryTimeoutError):
            logger.warning(
                "wazuh_hunt_ioc query_timeout after %ss",
                INDEXER_TOOL_DEADLINE_SEC,
            )
            return _degraded(
                f"query_timeout: indexer did not respond within {INDEXER_TOOL_DEADLINE_SEC:.0f}s"
            )
        except Exception as exc:
            logger.warning("wazuh_hunt_ioc indexer failure: %s", type(exc).__name__)
            return _degraded(f"upstream_unavailable: {type(exc).__name__}")

        # Translate indexer hits to ObservationAlert.model_dump() dicts.
        raw_hits = payload.get("hits", {}).get("hits", []) or []
        total_value = payload.get("hits", {}).get("total", {}).get("value", len(raw_hits))
        observations: list[dict] = []
        for hit in raw_hits:
            src = hit.get("_source", {})
            rule = src.get("rule", {}) or {}
            data = src.get("data", {}) or {}
            agent = src.get("agent", {}) or {}
            mitre_block = rule.get("mitre", {}) or {}
            mitre_ids_raw = mitre_block.get("id") or []
            if isinstance(mitre_ids_raw, str):
                mitre_ids_raw = [mitre_ids_raw]
            try:
                obs = ObservationAlert(
                    agent_id=str(agent.get("id", "")) or None,
                    ts_utc=src.get("@timestamp"),
                    rule_id=int(rule.get("id", 0) or 0),
                    rule_level=int(rule.get("level", 0) or 0),
                    rule_description=str(rule.get("description", ""))[:500],
                    rule_groups=tuple(rule.get("groups", []) or []),
                    mitre_ids=tuple(mitre_ids_raw),
                    srcip=data.get("srcip"),
                    dstip=data.get("dstip"),
                    full_log=str(src.get("full_log", ""))[:1000],
                )
            except Exception as exc:
                # Per-hit shape problem; log + skip rather than failing
                # the whole hunt.
                logger.debug("Skipping unparseable hit: %s", exc)
                continue
            observations.append(obs.model_dump())

        return {
            "ioc_digest": ioc_digest,
            "ioc_type": safe_ioc_type,
            "time_range_hours": int(time_range_hours),
            "indexer_reachable": True,
            "total_hits": int(total_value),
            "returned_hits": len(observations),
            "hits": observations,
            "warning": None,
        }

    @app.tool()  # type: ignore[misc]
    async def wazuh_vuln_query(
        cve_id: str | None = None,
        agent_id: str | None = None,
        severity: str | None = None,
        package_name: str | None = None,
        time_range_hours: int = 24 * 30,
        size: int = 100,
    ) -> dict:
        """Query Wazuh's vulnerability index for CVE findings (W-186).

        Reads ``wazuh-states-vulnerabilities-*`` (populated by Wazuh's
        agent-side vuln scan; no Vulnerability Detector wodle required).
        Closes the F1.2 fleet-wide-CVE visibility gap.

        All filters are optional and combine via AND. With no filters
        and a 30-day window, returns the freshest 100 vulnerabilities
        across the fleet.

        Args:
            cve_id: exact CVE ID (e.g. "CVE-2024-1234"). Treated as
                opaque; sanitised at response boundary.
            agent_id: filter to a single agent.
            severity: one of "Critical", "High", "Medium", "Low",
                "Untriaged" (case-insensitive). Unknown values produce
                a clean ``{"warning": ...}`` envelope.
            package_name: filter to vulns affecting a named package.
            time_range_hours: lookback window for vulnerability.detected_at.
                Default 720 (30 days).
            size: max hits to return (1..500). Capped at 500.

        Returns:
            dict with::

                {
                    "filters": {  # echoed back for caller convenience
                        "cve_id": str | None,
                        "agent_id": str | None,
                        "severity": str | None,
                        "package_name": str | None,
                    },
                    "time_range_hours": int,
                    "indexer_reachable": bool,
                    "total_hits": int,
                    "returned_hits": int,
                    "vulnerabilities": [
                        {  # ObservationCVE.model_dump() shape
                            "kind": "cve",
                            "cve_id": "CVE-...",
                            "severity": "high",
                            "package_name": "...",
                            "package_version": "...",
                            "fix_version": str | None,
                            "cvss_v3_score": float | None,
                            "agent_id": str | None,
                            "ts_utc": str | None,
                        }
                    ],
                    "warning": str | None,
                }
        """
        from agentropix_mcp.wazuh.config import WazuhConfig
        from agentropix_mcp.wazuh.indexer_client import (
            IndexerClient,
            QueryTimeoutError,
            _wazuh_retry_policy,
        )
        from agentropix_mcp.wrappers._vuln_query_dsl import (
            build_vuln_query,
            supported_severities,
        )
        from agentropix_mcp.wrappers.observations import (
            ObservationCVE,
        )

        # Echo filters back to caller (sanitised — strip control chars,
        # cap length; never echo raw values that could XSS log viewers).
        def _safe_str(v: str | None, maxlen: int = 128) -> str | None:
            if v is None:
                return None
            cleaned = "".join(c for c in v if c.isprintable())[:maxlen]
            return cleaned or None

        filters_echo = {
            "cve_id": _safe_str(cve_id),
            "agent_id": _safe_str(agent_id),
            "severity": _safe_str(severity),
            "package_name": _safe_str(package_name),
        }

        empty_response = {
            "filters": filters_echo,
            "time_range_hours": int(time_range_hours),
            "indexer_reachable": False,
            "total_hits": 0,
            "returned_hits": 0,
            "vulnerabilities": [],
            "warning": None,
        }

        # Validate severity upfront so we can surface a clean warning
        # rather than a raised ValueError from the DSL builder.
        if severity:
            normalised = next(
                (s for s in supported_severities() if s.lower() == severity.strip().lower()),
                None,
            )
            if normalised is None:
                empty_response["warning"] = (
                    f"unsupported severity {filters_echo['severity']!r}; supported: {supported_severities()}"
                )
                return empty_response

        try:
            config = WazuhConfig.from_env()
        except Exception as exc:
            empty_response["warning"] = f"WazuhConfig.from_env failed: {type(exc).__name__}"
            return empty_response

        if not config.indexer_url or not config.indexer_user or not config.indexer_password:
            empty_response["warning"] = (
                "Indexer not configured: set WAZUH_INDEXER_URL + WAZUH_INDEXER_USER + WAZUH_INDEXER_PASS"
            )
            return empty_response

        size_capped = max(1, min(int(size), 500))
        try:
            body = build_vuln_query(
                cve_id=cve_id,
                agent_id=agent_id,
                severity=severity,
                package_name=package_name,
                time_range_hours=int(time_range_hours),
                size=size_capped,
            )
        except ValueError as exc:
            empty_response["warning"] = str(exc)
            return empty_response

        client = IndexerClient(
            indexer_url=config.indexer_url,
            indexer_user=config.indexer_user,
            indexer_password=config.indexer_password,
            tls_verify=config.indexer_tls_verify,
            tls_ca_bundle=config.tls_ca_bundle,
        )

        @_wazuh_retry_policy()
        async def _do_search():
            return await client.search("wazuh-states-vulnerabilities-*", body, size=size_capped)

        try:
            try:
                # SIFT-W-298: hard total deadline across all retries (see
                # wazuh_hunt_ioc) so a degraded indexer can't hang past the
                # MCP client ceiling and orphan the tool_use.
                payload = await asyncio.wait_for(_do_search(), timeout=INDEXER_TOOL_DEADLINE_SEC)
            finally:
                await client.aclose()
        except (TimeoutError, QueryTimeoutError):
            logger.warning(
                "wazuh_vuln_query query_timeout after %ss",
                INDEXER_TOOL_DEADLINE_SEC,
            )
            empty_response["warning"] = (
                f"query_timeout: indexer did not respond within {INDEXER_TOOL_DEADLINE_SEC:.0f}s"
            )
            return empty_response
        except Exception as exc:
            logger.warning("wazuh_vuln_query indexer failure: %s", type(exc).__name__)
            empty_response["warning"] = f"upstream_unavailable: {type(exc).__name__}"
            return empty_response

        # Translate indexer hits to ObservationCVE.model_dump() dicts.
        raw_hits = payload.get("hits", {}).get("hits", []) or []
        total_value = payload.get("hits", {}).get("total", {}).get("value", len(raw_hits))
        vulnerabilities: list[dict] = []
        for hit in raw_hits:
            src = hit.get("_source", {})
            vuln = src.get("vulnerability", {}) or {}
            pkg = src.get("package", {}) or {}
            agent = src.get("agent", {}) or {}
            score_block = vuln.get("score", {}) or {}
            sev_raw = str(vuln.get("severity", "")).lower()
            # ObservationCVE expects {critical, high, medium, low, unknown}.
            sev_map = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
            }
            sev = sev_map.get(sev_raw, "unknown")
            try:
                obs = ObservationCVE(
                    agent_id=str(agent.get("id", "")) or None,
                    ts_utc=vuln.get("detected_at"),
                    cve_id=str(vuln.get("id", "")),
                    severity=sev,  # type: ignore[arg-type]
                    package_name=str(pkg.get("name", ""))[:200],
                    package_version=str(pkg.get("version", ""))[:100],
                    fix_version=(str(pkg.get("condition", "")) or None),
                    cvss_v3_score=(
                        float(score_block["base"])
                        if "base" in score_block
                        and isinstance(score_block.get("base"), (int, float))
                        else None
                    ),
                )
            except Exception as exc:
                # Per-hit shape problem; skip rather than failing whole query.
                logger.debug("Skipping unparseable vuln hit: %s", exc)
                continue
            vulnerabilities.append(obs.model_dump())

        return {
            "filters": filters_echo,
            "time_range_hours": int(time_range_hours),
            "indexer_reachable": True,
            "total_hits": int(total_value),
            "returned_hits": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "warning": None,
        }

    @app.tool()  # type: ignore[misc]
    async def wazuh_index_findings(
        findings: list[dict],
        case_id: str,
        index: str | None = None,
        dry_run: bool = True,
        mutation_token: str | None = None,
    ) -> dict:
        """Index Agentropix findings into the ``agentropix-findings-*`` pattern.

        WZ-022 / W-276: MCP-layer wrapper around
        ``orchestrator.index_findings()`` (W-275). Lets external callers
        (Claude Code, claude.ai, Pi agents) push ad-hoc findings without
        spinning up the full orchestrator pipeline -- useful for one-shot
        judge demos, re-indexing a single curated finding, and integration
        testing.

        Pipeline:
          1. Load WazuhConfig from env (fail-fast on bad config)
          2. Check ``WAZUH_INTEGRATION_ENABLED`` (kill switch)
          3. Check ``WAZUH_DRY_RUN_ONLY`` if dry_run=False
          4. Validate ``findings`` is a list of dicts (reject early)
          5. If dry_run=False: verify ``mutation_token`` via EvidenceGate
             (fail-closed -- no silent pass)
          6. Call ``index_findings(...)`` -- W-275 orchestrator handles
             template install + HMAC seal + batched _bulk + sealed audit
             rows + fail-soft on Indexer outage
          7. Return ``WazuhFindingsIndexResult.model_dump()``

        Args:
            findings: list of finding dicts. Each dict should contain at
                least ``finding_id``; other fields (severity,
                mitre_techniques, source_run_id, payload) flow through
                verbatim. The orchestrator stamps ``@timestamp``,
                ``source_run_id`` (if absent), and ``hmac_seal`` into
                each doc before indexing.
            case_id: case identifier for the audit-seal binding (e.g.
                ``SRL-2018``, ``CFReDS-Hacking``). Required.
            index: explicit target index name. Defaults to the
                date-suffixed template ``agentropix-findings-YYYY.MM.DD``
                (UTC) when ``None``.
            dry_run: when True (default), compute the would-be-indexed
                shape (incl. seals) but do not write to the Indexer.
                Set to False with a valid ``mutation_token`` to execute
                the index.
            mutation_token: EvidenceGate mutation token in ``egt_<ULID>``
                format. Required when ``dry_run=False``. Source from the
                env variable ``AGENTROPIX_MUTATION_TOKEN``.

        Returns:
            On success: ``WazuhFindingsIndexResult.model_dump()`` with
            keys ``indexed_count``, ``indexed_failed_count``,
            ``batch_count``, ``index_template_installed_this_run``,
            ``index``, ``dry_run``, ``run_id``, ``outcome``, and
            (when an Indexer outage degraded the run) ``error``.

            On config / gate / validation / auth failure: an envelope
            ``{"error": "...", "case_id": str, "dry_run": bool}``.
            Distinct from a successful run that returned
            ``outcome=indexer_outage`` (which still carries the full
            result shape) -- the ``error`` envelope means the call
            never reached the orchestrator.
        """
        from agentropix_mcp.wazuh.config import WazuhConfig
        from agentropix_mcp.wazuh.evidence_gate import (
            EvidenceGateRequired,
            verify_evidence_token,
        )
        from agentropix_mcp.wazuh.orchestrator import index_findings

        try:
            config = WazuhConfig.from_env()
        except Exception as exc:
            return {
                "error": f"Wazuh configuration error: {exc}",
                "case_id": case_id,
                "dry_run": dry_run,
            }

        if not config.integration_enabled:
            logger.info("Wazuh integration disabled (WAZUH_INTEGRATION_ENABLED=false)")
            return {
                "error": ("Wazuh integration is disabled; set WAZUH_INTEGRATION_ENABLED=true"),
                "case_id": case_id,
                "dry_run": dry_run,
            }

        if not dry_run and config.dry_run_only:
            return {
                "error": (
                    "WAZUH_DRY_RUN_ONLY=true prevents --confirm pushes; set WAZUH_DRY_RUN_ONLY=false to enable writes"
                ),
                "case_id": case_id,
                "dry_run": dry_run,
            }

        # Reject non-list / non-dict-element inputs early so the orchestrator
        # doesn't see malformed shapes deep in its chunking loop.
        if not isinstance(findings, list):
            return {
                "error": (f"findings must be a list, got {type(findings).__name__}"),
                "case_id": case_id,
                "dry_run": dry_run,
            }
        for i, f in enumerate(findings):
            if not isinstance(f, dict):
                return {
                    "error": (f"findings[{i}] must be a dict, got {type(f).__name__}"),
                    "case_id": case_id,
                    "dry_run": dry_run,
                }

        # SIFT-W-286: DRAFT gate. Runs AFTER input validation (so a
        # malformed payload still surfaces a clean validation error)
        # but BEFORE the EvidenceGate token check (so the strip event
        # is logged regardless of whether the live-mode token is
        # accepted). Strips caller-supplied approval.*, forces
        # status=DRAFT, stamps provenance tier + case_id.
        findings, strip_events = _apply_draft_gate(findings, case_id)
        for event in strip_events:
            logger.warning("SIFT-W-286 draft-gate: %s", event)

        if not dry_run:
            try:
                verify_evidence_token(mutation_token, op="index_findings")
            except EvidenceGateRequired as exc:
                return {
                    "error": f"EvidenceGateRequired: {exc}",
                    "case_id": case_id,
                    "dry_run": dry_run,
                }

        result = await index_findings(
            findings,
            config=config,
            case_id=case_id,
            evidence_token=mutation_token,
            dry_run=dry_run,
            index=index,
        )
        return result.model_dump()
