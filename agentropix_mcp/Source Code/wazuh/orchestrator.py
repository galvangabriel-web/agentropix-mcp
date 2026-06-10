"""Wazuh IOC push orchestrator — main entry point for push_iocs().

Implements the full happy-path sequence from 01_design.md §3:
  1. CaseLoader → IOCInventory
  2. PriorityClassifier → Tier 1+2 / excluded
  3. ThymusBridge.validate_inventory (Fix 1 / S-1)
  4. EvidenceGate.verify (Fix 1 / S-1)
  5. CDB + rules XML transformation
  6. DryRunPlanner (if dry_run)
  7. WazuhClient writes + coalesced restart (if --confirm)
  8. CourtroomSeal stamps each PUT (Fix 2 / S-3 + ADR-016 HMAC-SHA256)
  9. AuditLogger appends JSONL

Correct ADRs: ADR-008 (safety/Thymus), ADR-016 (courtroom seal HMAC-SHA256),
ADR-017 (tailnet).
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import time
from datetime import UTC, datetime
from typing import Any
from xml.etree import ElementTree as ET

# WLV-01: ossec.conf reconciler parses operator-influenced XML; defusedxml
# protects against XXE / billion-laughs at parse time. Imported at module
# load so a missing dep surfaces at startup, not at first reconciler call.
from defusedxml import ElementTree as DET

__all__ = [
    "WazuhFindingsIndexResult",
    "WazuhIOCPushResult",
    "index_findings",
    "push_iocs",
]


# WZ-022 / W-275 (orchestrator wiring): per-process template-install cache.
# Keyed by (indexer_url, template_name). Each ``index_findings()`` run
# checks the cache before issuing a redundant ``PUT /_index_template/<name>``
# (which is idempotent on the OpenSearch side but a wasted round-trip).
# Intentionally process-local, not persisted — a process restart re-PUTs the
# template, which is a no-op on the server when bytes are identical.
_FINDINGS_TEMPLATE_INSTALL_CACHE: dict[tuple[str, str], bool] = {}


# WZ-022 / W-277 (ISM): per-process ISM-policy-install cache.
# Same shape and rationale as the template cache above. Keyed by
# (indexer_url, policy_name). A process restart re-PUTs the policy,
# which is an idempotent replace on the OpenSearch ISM plugin.
_FINDINGS_ISM_INSTALL_CACHE: dict[tuple[str, str], bool] = {}

logger = logging.getLogger(__name__)


class WazuhIOCPushResult:
    """Result of a push_iocs() call.

    F-10: ``outcome`` field (string) classifies the run state into one of
    the IOCPushOutcome values below. Boolean fields are retained for
    back-compat; new callers should consume ``outcome``.
    """

    # IOCPushOutcome values (F-10).
    OUTCOME_PUSHED_AND_LOADED = "pushed_and_loaded"
    OUTCOME_PARTIAL_PUSHED_AND_LOADED = "partial_pushed_and_loaded"
    OUTCOME_PUSHED_PENDING_RESTART = "pushed_pending_restart"
    OUTCOME_FAILED_PRE_PUSH = "failed_pre_push"
    OUTCOME_FAILED_POST_PUSH = "failed_post_push"
    # WLV-02: self-test failed AFTER the restart settled. Bytes are on
    # the manager + ossec.conf is patched + restart fired clean, but
    # one or more rules failed to fire on the sentinel event. Caller
    # should investigate rule logic / decoder bridge (master report
    # §4.3 #15) — not auto-rollback (that's WLV-10's job).
    OUTCOME_PUSHED_BUT_SELF_TEST_FAILED = "pushed_but_self_test_failed"
    OUTCOME_NOTHING_PUSHED = "nothing_pushed"
    OUTCOME_DRY_RUN = "dry_run"

    def __init__(
        self,
        *,
        case_id: str,
        pushed: int = 0,
        skipped_tier3: int = 0,
        skipped_idempotent: int = 0,
        failed: int = 0,
        restart_pending: bool = False,
        dry_run: bool = True,
        seal: str | None = None,
        run_id: str = "",
        outcome: str | None = None,
        error: dict | None = None,
        self_test_results: list[dict] | None = None,
    ) -> None:
        self.case_id = case_id
        self.pushed = pushed
        self.skipped_tier3 = skipped_tier3
        self.skipped_idempotent = skipped_idempotent
        self.failed = failed
        self.restart_pending = restart_pending
        self.dry_run = dry_run
        self.seal = seal
        self.run_id = run_id
        self.outcome = outcome or (self.OUTCOME_DRY_RUN if dry_run else self.OUTCOME_NOTHING_PUSHED)
        # WLV-01 / §4.4 #19: when the pre-restart reconciler fails, the
        # orchestrator MUST NOT issue the restart and MUST surface a
        # rollback envelope so a future WLV-10 snapshot mechanism can
        # consume it. Shape: {"error": str, "details": dict,
        # "rollback_required": True}.
        self.error = error
        # WLV-02: per-rule self-test outcomes. Each entry is
        # {"rule_id": int, "passed": bool, "skipped": bool, "reason": str}
        # — empty list when no self-test ran (dry_run, restart_pending,
        # or no namespaces with landed bytes).
        self.self_test_results: list[dict] = self_test_results or []

    def model_dump(self) -> dict:
        d = {
            "case_id": self.case_id,
            "pushed": self.pushed,
            "skipped_tier3": self.skipped_tier3,
            "skipped_idempotent": self.skipped_idempotent,
            "failed": self.failed,
            "restart_pending": self.restart_pending,
            "dry_run": self.dry_run,
            "seal": self.seal,
            "run_id": self.run_id,
            "outcome": self.outcome,
            "self_test_results": list(self.self_test_results),
        }
        if self.error is not None:
            # WLV-01b (issue #50): preserve the nested envelope shape so
            # `result.model_dump()["error"]` matches `result.error`. The
            # earlier flat shape was asymmetric and would TypeError on
            # consumers doing `result.model_dump()["error"]["details"]`.
            #
            # WLV-01-review-2: deep-copy via copy.deepcopy() so callers
            # mutating the dumped envelope (e.g. for logging) do NOT
            # propagate the mutation back to self.error — a shallow
            # dict() copy leaks list/dict mutations through the shared
            # reference at `details`.
            d["error"] = copy.deepcopy(self.error)
        return d


def _make_cdb_body(
    records: list,
    list_name: str,
    kind_filter: str,
) -> bytes:
    """Build a deterministic CDB payload from a list of IOCRecords.

    CDB value format (Fix 4 / S-5): ``key:case_id|confidence|context\n``
    using pipe (|) as the separator within the value part, not colon.
    Lines are sorted ASCII-ascending by key (FR-11 determinism).
    """
    lines: dict[str, str] = {}

    for rec in records:
        if getattr(rec, "kind", None) != kind_filter:
            continue
        key = getattr(rec, "value", "")
        case_id = getattr(rec, "case_id", "")
        confidence = getattr(rec, "confidence", "medium")

        # Context: use filename_hint, persistence_type, or context field
        ctx = (
            getattr(rec, "filename_hint", None)
            or getattr(rec, "persistence_type", None)
            or getattr(rec, "context", None)
            or getattr(rec, "mitre", None)
            or "unknown"
        )
        # Wazuh CDB format requires keys with no spaces. Skip keys that
        # contain whitespace (e.g. "Windows NT" in registry paths) — they
        # cannot be looked up and would trigger Wazuh error 1800.
        if " " in key or "\t" in key:
            logger.warning(
                "CDB: skipping IOC key with whitespace (Wazuh error 1800 would reject it): %r",
                key[:80],
            )
            continue

        # Sanitise value fields — strip colon/newline/CR.
        # confidence may be a float scalar (W-203 process_tree_event uses
        # 0.75 / 0.80 numeric bands), so str-coerce all three to avoid
        # AttributeError on .replace().
        safe_case_id = str(case_id).replace(":", "_").replace("\n", "").replace("\r", "")
        safe_confidence = str(confidence).replace(":", "_").replace("\n", "").replace("\r", "")
        safe_ctx = str(ctx).replace(":", "_").replace("\n", "").replace("\r", "")

        # Pipe separator in value part (Fix 4: CDB row = key:case_id|confidence|context)
        lines[key] = f"{safe_case_id}|{safe_confidence}|{safe_ctx}"

    sorted_lines = sorted(lines.items())
    body = b"".join(f"{k}:{v}\n".encode() for k, v in sorted_lines)
    return body


# WZ-019 (master-report §4.2 #11): env gate that switches the publisher
# from advisory ("log warning when provenance is missing") to enforcing
# ("raise ProvenanceMissingError before any PUT issues"). Off-by-default
# so back-loading legacy MASTER-IOCS.json files isn't blocked while the
# operator captures retroactive provenance.
_REQUIRE_PROVENANCE_ENV = "AGENTROPIX_REQUIRE_IOC_PROVENANCE"


def _provenance_gate(pushable: list) -> tuple[list, list]:
    """WZ-019: split ``pushable`` into (with_provenance, without_provenance).

    Visible-for-testing helper. The orchestrator threads both lists into
    the audit row so operators can see at a glance how much of the run
    is court-defensible vs advisory-only.
    """
    with_p: list = []
    without_p: list = []
    for rec in pushable:
        if getattr(rec, "provenance", None) is not None:
            with_p.append(rec)
        else:
            without_p.append(rec)
    return with_p, without_p


def _write_provenance_sidecar(
    case_dir: str,
    pushable: list,
    list_name: str,
    kind_filter: str,
    *,
    seal_helper: Any,
    operator: str,
    case_id: str,
    run_id: str,
    evidence_token: str | None,
) -> str | None:
    """WZ-019 (master-report §4.2 #11): write per-list provenance.jsonl.

    Each row is one IOC with its provenance triple, HMAC-sealed via the
    same envelope as the audit log so a courtroom challenge can verify
    "this indicator was extracted from THIS evidence by THIS tool at
    THIS time by THIS analyst" without re-running the agents.

    Path: ``<case_dir>/provenance/<list_name>.provenance.jsonl``

    Returns the absolute path written, or None if no records of
    ``kind_filter`` carry provenance (no sidecar written for that list).
    """
    from pathlib import Path

    rows_payload: list[dict] = []
    for rec in pushable:
        if getattr(rec, "kind", None) != kind_filter:
            continue
        prov = getattr(rec, "provenance", None)
        if prov is None:
            continue
        # Pydantic v2: model_dump() for the nested provenance block.
        prov_dict = prov.model_dump() if hasattr(prov, "model_dump") else dict(prov)
        rows_payload.append(
            {
                "kind": kind_filter,
                "value": getattr(rec, "value", ""),
                "case_id": getattr(rec, "case_id", case_id),
                "list_name": list_name,
                "provenance": prov_dict,
            }
        )

    if not rows_payload:
        return None

    sidecar_dir = Path(case_dir) / "provenance"
    sidecar_dir.mkdir(parents=True, exist_ok=True)
    sidecar_path = sidecar_dir / f"{list_name}.provenance.jsonl"

    with sidecar_path.open("w", encoding="utf-8") as f:
        for row in rows_payload:
            # Bind via the existing CourtroomSeal idiom (W-A16): the seal
            # covers the canonical-JSON of the row + the run_id, so any
            # tampered row breaks verification under hmac.compare_digest.
            payload = json.dumps(
                row, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("ascii")
            req_sha256 = hashlib.sha256(payload).hexdigest()
            try:
                seal = seal_helper.bind(
                    operator=operator,
                    case_id=case_id,
                    evidence_token_id=evidence_token,
                    endpoint=f"/provenance/{list_name}",
                    req_sha256=req_sha256,
                    resp_sha256=hashlib.sha256(b"").hexdigest(),
                    status=0,
                    run_id=run_id,
                )
            except Exception as exc:
                # Best-effort: a seal failure here MUST NOT corrupt the
                # CDB push pipeline. Log + write the row unsealed (the
                # absence of a seal is itself the chain-of-custody flag).
                logger.warning(
                    "WZ-019 provenance seal failed for %s/%s: %s",
                    list_name,
                    row.get("value"),
                    exc,
                )
                seal = None
            row["seal"] = seal
            f.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")

    return str(sidecar_path)


_KIND_TO_LIST = {
    "ip": "agentropix_c2_ips",
    "hash_sha256": "agentropix_malware_sha256",
    "hash_md5": "agentropix_malware_md5",
    # Issue #60 / §4.2 #8: process IOC split.
    # Legacy kind=process_name retained for back-compat with existing
    # MASTER-IOCS.json files; routes to the legacy unified list. New
    # pushes should use process_image (Sysmon EID 1) or process_module
    # (Sysmon EID 7) which route to dedicated lists.
    "process_name": "agentropix_suspect_process",
    "process_image": "agentropix_suspect_image",
    "process_module": "agentropix_suspect_module",
    "registry_key": "agentropix_persistence_regkey",
    # W-203: cross-host process-tree relations dispatch to a dedicated
    # CDB list. Manager-side rule registration is operator-owned.
    "process_tree_event": "agentropix_process_tree_event",
}

_RULES_XML_TEMPLATE = """\
<group name="agentropix,srl2018,threat_intel,">
  <rule id="100200" level="12">
    <if_group>syslog</if_group>
    <list field="srcip" lookup="match_key">etc/lists/agentropix_c2_ips</list>
    <description>Agentropix: known C2 IP matched $(srcip)</description>
    <mitre><id>T1071.001</id></mitre>
    <group>c2,agentropix,</group>
  </rule>
  <rule id="100201" level="13">
    <if_group>syscheck</if_group>
    <list field="sha256_after" lookup="match_key">etc/lists/agentropix_malware_sha256</list>
    <description>Agentropix: known malware SHA-256 matched $(sha256_after)</description>
    <mitre><id>T1105</id></mitre>
    <group>malware,agentropix,</group>
  </rule>
  <rule id="100202" level="10">
    <if_group>syscheck</if_group>
    <list field="md5_after" lookup="match_key">etc/lists/agentropix_malware_md5</list>
    <description>Agentropix: known malware MD5 matched $(md5_after)</description>
    <mitre><id>T1105</id></mitre>
    <group>malware,agentropix,</group>
  </rule>
  <rule id="100203" level="8">
    <!-- Issue #60: rule split. 100203 now matches Sysmon EID 1
         (process create) against the suspect_image CDB list. -->
    <if_group>sysmon_event1</if_group>
    <list field="win.eventdata.image" lookup="match_key">etc/lists/agentropix_suspect_image</list>
    <description>Agentropix: suspect process image matched $(win.eventdata.image)</description>
    <mitre><id>T1059</id></mitre>
    <group>process,agentropix,</group>
  </rule>
  <rule id="100204" level="10">
    <if_group>syscheck</if_group>
    <list field="path" lookup="match_key">etc/lists/agentropix_persistence_regkey</list>
    <description>Agentropix: persistence registry key matched $(path)</description>
    <mitre><id>T1547.001</id></mitre>
    <group>persistence,agentropix,</group>
  </rule>
  <rule id="100208" level="10">
    <!-- Issue #60: new rule for Sysmon EID 7 (image load / DLL).
         Field is imageloaded (NOT image) per Sysmon schema. Matches
         against the suspect_module CDB list. -->
    <if_group>sysmon_event7</if_group>
    <list field="win.eventdata.imageloaded" lookup="match_key">etc/lists/agentropix_suspect_module</list>
    <description>Agentropix: suspect loaded module matched $(win.eventdata.imageloaded)</description>
    <mitre><id>T1574.002</id></mitre>
    <group>process,agentropix,</group>
  </rule>
  <rule id="100205" level="14">
    <!-- SRL-2018 GAP-14 structural fix: Wazuh CDB keys cannot contain
         spaces, so the Winlogon key (which includes "Windows NT" in the
         path) cannot be pushed via CDB (error 1800). This rule bypasses
         the CDB limitation by matching the targetObject field via pcre2
         regex. Fires on Sysmon EID 13 (RegistryValueSet) touching any
         subkey of Winlogon - covers the confirmed SRL-2018 Userinit hijack
         (T1547 on base-dc-cdrive). -->
    <if_group>sysmon_event_13</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)Winlogon</field>
    <description>Agentropix: Winlogon registry key modified - T1547 persistence ($(win.eventdata.targetObject))</description>
    <mitre><id>T1547</id></mitre>
    <group>persistence,agentropix,srl2018,</group>
  </rule>
  <rule id="100206" level="12">
    <!-- Companion to 100205: EID 12 (RegistryEvent object create/delete)
         on the Winlogon subtree - catches key creation as well as value
         set (100205). -->
    <if_group>sysmon_event_12</if_group>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)Winlogon</field>
    <description>Agentropix: Winlogon registry key created/deleted - T1547 persistence ($(win.eventdata.targetObject))</description>
    <mitre><id>T1547</id></mitre>
    <group>persistence,agentropix,srl2018,</group>
  </rule>
</group>
"""


# WLV-02 (master report §4.1 #2): post-restart self-test sentinel
# fixtures — one per agentropix_* rule. Each entry maps rule_id to
# (list_name, log_format, build_event(key)) where build_event constructs
# a synthetic event matching the rule's <list field=...> + <if_group>
# constraints. The `key` is the IOC value the orchestrator just pushed
# (or its first record); the sentinel proves end-to-end that
# bytes-on-disk + ossec.conf-declares + analysisd-loads + rule-fires.
#
# Note (master-report §1.5 + C5 Recommended Edit): the integration-test
# report's §8 payloads are free-text shapes that the syscheck decoder
# does NOT parse, so 100201/100202/100204 historically returned
# alert=false. WLV-04's decoder bridge will close that gap; until then,
# the self-test for those rules ships log_format="json" with a
# decoded-shape payload that bypasses the broken syslog/syscheck
# decoder and exercises the rule logic directly.
def _build_sentinel_for_rule_100200(key: str) -> tuple[str, str]:
    """Rule 100200: srcip lookup against agentropix_c2_ips, if_group=syslog.

    Send a JSON event with `srcip` field; logtest treats this as a
    pre-decoded log entry, hits the syslog group, and the rule fires
    when CDB lookup succeeds.
    """
    import json as _json

    return ("json", _json.dumps({"srcip": key, "agent": {"id": "000"}}))


def _build_sentinel_for_rule_100201(key: str) -> tuple[str, str]:
    """Rule 100201: sha256_after lookup against agentropix_malware_sha256,
    if_group=syscheck."""
    import json as _json

    return (
        "json",
        _json.dumps(
            {
                "sha256_after": key,
                "path": "/tmp/wlv02-sentinel.bin",
                "agent": {"id": "000"},
                "syscheck": {"event": "modified"},
            }
        ),
    )


def _build_sentinel_for_rule_100202(key: str) -> tuple[str, str]:
    """Rule 100202: md5_after lookup, if_group=syscheck."""
    import json as _json

    return (
        "json",
        _json.dumps(
            {
                "md5_after": key,
                "path": "/tmp/wlv02-sentinel.bin",
                "agent": {"id": "000"},
                "syscheck": {"event": "modified"},
            }
        ),
    )


def _build_sentinel_for_rule_100203(key: str) -> tuple[str, str]:
    """Rule 100203 (Issue #60: now Sysmon EID 1, suspect_image list).

    win.eventdata.image lookup against agentropix_suspect_image.
    """
    import json as _json

    return (
        "json",
        _json.dumps(
            {
                "win": {"eventdata": {"image": key, "event_id": 1}},
                "agent": {"id": "000"},
            }
        ),
    )


def _build_sentinel_for_rule_100204(key: str) -> tuple[str, str]:
    """Rule 100204: path lookup against agentropix_persistence_regkey,
    if_group=syscheck."""
    import json as _json

    return (
        "json",
        _json.dumps(
            {
                "path": key,
                "agent": {"id": "000"},
                "syscheck": {"event": "modified"},
            }
        ),
    )


def _build_sentinel_for_rule_100205(_key: str = "") -> tuple[str, str]:
    """Rule 100205: Sysmon EID 13 (RegistryValueSet) Winlogon regex.

    NOTE: This rule uses <if_group>sysmon_event_13</if_group>. The
    logtest JSON format bypasses the Sysmon decoder chain so the event
    never enters the sysmon_event_13 group — this sentinel will NOT fire
    rule 100205 via /logtest. The rule WILL fire correctly on real Sysmon
    agent events. Sentinel is provided for documentation; self-test
    records result="skipped:logtest_decoder_bypass".
    """
    import json as _json

    return (
        "json",
        _json.dumps(
            {
                "win": {
                    "system": {"eventID": "13"},
                    "eventdata": {
                        "eventType": "SetValue",
                        "targetObject": (
                            "HKLM\\Software\\Microsoft\\Windows NT"
                            "\\CurrentVersion\\Winlogon\\Userinit"
                        ),
                        "image": "C:\\Windows\\System32\\cmd.exe",
                    },
                },
                "agent": {"id": "000"},
            }
        ),
    )


def _build_sentinel_for_rule_100206(_key: str = "") -> tuple[str, str]:
    """Rule 100206: Sysmon EID 12 (RegistryEvent key create/delete) Winlogon.

    Same logtest limitation as 100205 — sysmon_event_12 group requires
    the Sysmon decoder chain. Fires correctly on real Sysmon agent events.
    """
    import json as _json

    return (
        "json",
        _json.dumps(
            {
                "win": {
                    "system": {"eventID": "12"},
                    "eventdata": {
                        "eventType": "CreateKey",
                        "targetObject": (
                            "HKLM\\Software\\Microsoft\\Windows NT"
                            "\\CurrentVersion\\Winlogon\\NewSubKey"
                        ),
                        "image": "C:\\Windows\\System32\\cmd.exe",
                    },
                },
                "agent": {"id": "000"},
            }
        ),
    )


def _build_sentinel_for_rule_100208(key: str) -> tuple[str, str]:
    """Issue #60: Rule 100208 — Sysmon EID 7 (image load / DLL).

    win.eventdata.imageloaded lookup against agentropix_suspect_module.
    Distinct from 100203's `image` field which is for EID 1 (process
    create).
    """
    import json as _json

    return (
        "json",
        _json.dumps(
            {
                "win": {"eventdata": {"imageloaded": key, "event_id": 7}},
                "agent": {"id": "000"},
            }
        ),
    )


# Rule IDs whose <if_group> requires a decoder chain that the logtest JSON
# format bypasses. These rules WILL fire on real agent events (syscheck FIM
# events, Sysmon EID 1/7/12/13) but CANNOT be verified via /logtest PUT
# because the JSON decoder assigns events to the generic group, not to
# syscheck or sysmon_event_* groups.
#
# When a fixture in this set returns alert=False from logtest, the self-test
# records result="logtest_decoder_bypass" (skipped=True) instead of fail —
# same treatment as list_name=None static rules. The CDB bytes still must
# have landed (list_name check still enforced) before the bypass kicks in.
#
# rule 100200 (if_group=syslog) is NOT here — syslog IS the default group
# for JSON events, so 100200 fires normally.
_LOGTEST_DECODER_BYPASS_RULES: frozenset[int] = frozenset(
    {
        100201,  # if_group=syscheck — FIM SHA-256 lookup; syscheck group not assigned by json decoder
        100202,  # if_group=syscheck — FIM MD5 lookup
        100203,  # if_group=sysmon_event1 — process create EID 1
        100204,  # if_group=syscheck — registry key CDB lookup
        100205,  # if_group=sysmon_event_13 — already handled via list_name=None
        100206,  # if_group=sysmon_event_12 — already handled via list_name=None
        100208,  # if_group=sysmon_event7 — DLL load EID 7
    }
)
# Map: (list_name, rule_id, sentinel_builder).
# Order matters: tested in this order, deterministic for audit grep.
# list_name=None marks a "static" rule (regex/inline match — not CDB-gated).
# Static rules always run; their builder accepts an ignored key argument.
# Issue #60: legacy suspect_process slot retained as a no-op fixture
# for back-compat — its sentinel still uses the EID 1 image shape, but
# the rule now points at suspect_image. New pushes should use the
# suspect_image / suspect_module entries below.
_SELF_TEST_FIXTURES: tuple[tuple[str | None, int, Any], ...] = (
    ("agentropix_c2_ips", 100200, _build_sentinel_for_rule_100200),
    ("agentropix_malware_sha256", 100201, _build_sentinel_for_rule_100201),
    ("agentropix_malware_md5", 100202, _build_sentinel_for_rule_100202),
    ("agentropix_suspect_image", 100203, _build_sentinel_for_rule_100203),
    ("agentropix_persistence_regkey", 100204, _build_sentinel_for_rule_100204),
    # Issue #60: new rule 100208 for the module/DLL split.
    ("agentropix_suspect_module", 100208, _build_sentinel_for_rule_100208),
    # GAP-14 Winlogon regex rules — static, always tested (list_name=None).
    (None, 100205, _build_sentinel_for_rule_100205),
    (None, 100206, _build_sentinel_for_rule_100206),
)


def _first_key_from_cdb_body(body: bytes) -> str | None:
    """Extract the first key from a CDB body (key:value\\n format).

    Visible-for-testing helper. Returns None on empty body.
    """
    if not body:
        return None
    # Body lines are "key:value\n"; key is everything before the first colon.
    first_line = body.split(b"\n", 1)[0]
    if not first_line:
        return None
    sep_idx = first_line.find(b":")
    if sep_idx <= 0:
        return None
    try:
        return first_line[:sep_idx].decode("utf-8")
    except UnicodeDecodeError:
        return None


def _logtest_response_alert(response: dict) -> bool:
    """Check whether a /logtest response indicates alert=True.

    Real Wazuh API shape: ``{"data": {"alert": bool, "output": {"rule": {...}}}}``.
    The ``alert`` flag is at ``data.alert`` (top level of the data envelope),
    NOT inside ``data.output.alert`` as previously documented.
    Falls back to ``data.output.alert`` for legacy test fixtures.
    Returns False on any malformed shape (best-effort).
    """
    try:
        data = response.get("data", {})
        if "alert" in data:
            return bool(data["alert"])
        return bool(data.get("output", {}).get("alert"))
    except Exception:
        return False


async def _run_post_restart_self_test(
    client: Any,
    payloads: dict[str, bytes],
    namespaces_with_landed_bytes: set[str],
    *,
    seal_helper: Any,
    operator: str,
    case_id: str,
    run_id: str,
    evidence_token: str | None,
    audit_log: str,
) -> list[dict]:
    """WLV-02: send sentinel events to /logtest for each rule whose
    namespace had bytes landed this run; assert each rule fires.

    Returns a list of per-rule result dicts:
      {"rule_id": int, "passed": bool, "skipped": bool, "reason": str}

    The caller threads this list into ``WazuhIOCPushResult.self_test_results``
    so downstream consumers (operator runbook, WLV-10 rollback decision,
    SIFT-WEAKNESSES tracking) can see at a glance which rules fired
    end-to-end.

    Failure semantics: this function records but does NOT raise. The
    orchestrator decides outcome routing based on the returned list
    (any passed=False entry escalates the run-level outcome to
    OUTCOME_PUSHED_BUT_SELF_TEST_FAILED).

    Skipping semantics: a rule whose namespace had no landed bytes
    this run is recorded as ``skipped: True`` with a reason — NOT as
    passed. Operators reading the audit log must distinguish "rule
    fired" from "rule had no chance to fire because no IOC was pushed
    for it". Conflating these two leads to false-positive green runs.
    """
    results: list[dict] = []
    for list_name, rule_id, builder in _SELF_TEST_FIXTURES:
        # Static rules (list_name=None) are regex/inline — not CDB-gated.
        # They always attempt logtest with a hardcoded sentinel path.
        # However, if_group=sysmon_event_* rules won't fire in logtest
        # because JSON format bypasses the Sysmon decoder chain. Record
        # as skipped:logtest_decoder_bypass (not a test failure — the rule
        # is confirmed loaded on the manager and will fire on real agents).
        if list_name is None:
            log_format, event = builder("")
        else:
            if list_name not in namespaces_with_landed_bytes:
                results.append(
                    {
                        "rule_id": rule_id,
                        "list_name": list_name,
                        "passed": False,
                        "skipped": True,
                        "reason": "no_landed_bytes",
                    }
                )
                continue
            body = payloads.get(list_name, b"")
            key = _first_key_from_cdb_body(body)
            if key is None:
                results.append(
                    {
                        "rule_id": rule_id,
                        "list_name": list_name,
                        "passed": False,
                        "skipped": True,
                        "reason": "empty_or_unparseable_body",
                    }
                )
                continue
            log_format, event = builder(key)
        t0 = time.monotonic()
        try:
            response = await client.run_logtest(
                event,
                log_format=log_format,
                location=f"agentropix-self-test/{run_id}",
                evidence_token=evidence_token,
            )
        except Exception as exc:
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            logger.error(
                "WLV-02 self-test for rule %d (%s) failed: %s",
                rule_id,
                list_name,
                exc,
            )
            _seal_and_audit_attempt(
                audit_log=audit_log,
                seal_helper=seal_helper,
                operator=operator,
                case_id=case_id,
                run_id=run_id,
                event="wazuh.self_test",
                op="logtest",
                endpoint="/logtest",
                evidence_token=evidence_token,
                req_body=event.encode("utf-8"),
                resp_body=b"",
                status=0,
                latency_ms=elapsed_ms,
                result="error",
                extra={"rule_id": rule_id, "list_name": list_name},
                error_class=type(exc).__name__,
            )
            results.append(
                {
                    "rule_id": rule_id,
                    "list_name": list_name,
                    "passed": False,
                    "skipped": False,
                    "reason": f"logtest_exception:{type(exc).__name__}",
                }
            )
            continue

        elapsed_ms = (time.monotonic() - t0) * 1000.0
        alerted = _logtest_response_alert(response)

        # Rules whose if_group requires a decoder chain that JSON-format logtest
        # bypasses (syscheck FIM, sysmon_event_*). These include static rules
        # (list_name=None) AND CDB-gated rules in _LOGTEST_DECODER_BYPASS_RULES.
        # The CDB bytes have already landed (enforced above); treat the logtest
        # result as skipped rather than failed — the rule will fire on real agents.
        if not alerted and (list_name is None or rule_id in _LOGTEST_DECODER_BYPASS_RULES):
            _seal_and_audit_attempt(
                audit_log=audit_log,
                seal_helper=seal_helper,
                operator=operator,
                case_id=case_id,
                run_id=run_id,
                event="wazuh.self_test",
                op="logtest",
                endpoint="/logtest",
                evidence_token=evidence_token,
                req_body=event.encode("utf-8"),
                resp_body=b"",
                status=200,
                latency_ms=elapsed_ms,
                result="skipped",
                extra={
                    "rule_id": rule_id,
                    "list_name": list_name,
                    "alert": alerted,
                    "skip_reason": "logtest_decoder_bypass",
                },
            )
            results.append(
                {
                    "rule_id": rule_id,
                    "list_name": list_name,
                    "passed": False,
                    "skipped": True,
                    "reason": "logtest_decoder_bypass",
                }
            )
            continue

        result_str = "ok" if alerted else "fail"
        _seal_and_audit_attempt(
            audit_log=audit_log,
            seal_helper=seal_helper,
            operator=operator,
            case_id=case_id,
            run_id=run_id,
            event="wazuh.self_test",
            op="logtest",
            endpoint="/logtest",
            evidence_token=evidence_token,
            req_body=event.encode("utf-8"),
            resp_body=b"",
            status=200,
            latency_ms=elapsed_ms,
            result=result_str,
            extra={
                "rule_id": rule_id,
                "list_name": list_name,
                "alert": alerted,
            },
        )
        results.append(
            {
                "rule_id": rule_id,
                "list_name": list_name,
                "passed": alerted,
                "skipped": False,
                "reason": "alert_true" if alerted else "alert_false",
            }
        )
    return results


def _append_audit(audit_log: str, event: dict) -> None:
    """Append a JSON event to the audit log (best-effort, never raises)."""
    try:
        os.makedirs(os.path.dirname(audit_log), exist_ok=True)
        with open(audit_log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, default=str) + "\n")
    except Exception as exc:
        logger.warning("Failed to write audit log %s: %s", audit_log, exc)


def _parse_cdb_keys(body: bytes) -> set[str]:
    """Extract the set of CDB keys (text before first colon) from a list body.

    CDB plaintext format is one row per line: ``key:value\\n``. Empty lines
    and comments (``#`` prefix) are ignored. Used by the F-3 pre-PUT diff
    guard to detect silent removals.
    """
    keys: set[str] = set()
    for raw in body.splitlines():
        # errors="replace" cannot raise — invalid bytes become U+FFFD.
        line = raw.decode("utf-8", errors="replace").strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        keys.add(line.split(":", 1)[0])
    return keys


def _seal_and_audit_attempt(
    *,
    audit_log: str,
    seal_helper: Any,
    operator: str,
    case_id: str,
    run_id: str,
    event: str,
    op: str,
    endpoint: str,
    evidence_token: str | None,
    req_body: bytes,
    resp_body: bytes,
    status: int,
    latency_ms: float,
    result: str,
    extra: dict | None = None,
    error_class: str | None = None,
) -> str:
    """Compute a per-attempt seal envelope and append a sealed audit row.

    Review F-1 / F-2: the original orchestrator only sealed-and-audited on
    the success path; failures (`Exception` arms, restart-poll timeout)
    silently dropped the audit trail, breaking ADR-016 court-defensibility.
    This helper guarantees that every PUT attempt and the restart attempt
    emit a sealed row regardless of HTTP outcome.

    On failure paths the caller passes `req_body=b"" / resp_body=b""` and
    `status=0`; the seal still binds endpoint + result + run_id so the
    failure is provably attributable to a specific attempt.
    """
    ts = datetime.now(UTC)
    req_sha256 = hashlib.sha256(req_body).hexdigest()
    resp_sha256 = hashlib.sha256(resp_body).hexdigest()
    try:
        seal_str = seal_helper.bind(
            operator=operator,
            case_id=case_id,
            ts=ts,
            evidence_token_id=evidence_token[:12] if evidence_token else None,
            endpoint=endpoint,
            req_sha256=req_sha256,
            resp_sha256=resp_sha256,
            status=status,
            run_id=run_id,
        )
    except Exception as exc:
        # NEW-2: seal computation failure is an integrity event — emit a
        # SEPARATE audit row marking the breach and re-raise. Writing a
        # malformed `seal=SEAL_FAILED:...` into the regular row would
        # break the schema invariant that downstream verifiers rely on.
        logger.error("Seal computation failed for %s: %s", endpoint, exc)
        _append_audit(
            audit_log,
            {
                "ts": ts.isoformat(),
                "event": "seal.failure",
                "case_id": case_id,
                "run_id": run_id,
                "endpoint": endpoint,
                "operator": operator,
                "error_class": type(exc).__name__,
                "result": "seal_failed",
            },
        )
        raise

    record = {
        "ts": ts.isoformat(),
        "event": event,
        "case_id": case_id,
        "run_id": run_id,
        "op": op,
        "endpoint": endpoint,
        "http_status": status,
        "req_sha256": req_sha256,
        "resp_sha256": resp_sha256,
        "seal": seal_str,
        "evidence_token_id": evidence_token[:12] if evidence_token else None,
        "operator": operator,
        "latency_ms": int(latency_ms),
        "dry_run": False,
        "result": result,
    }
    if error_class:
        # Class name only — never `str(exc)`, which can echo IOC content.
        record["error_class"] = error_class
    if extra:
        record.update(extra)
    _append_audit(audit_log, record)
    return seal_str


async def _reconcile_ossec_conf_lists(
    client: Any,
    namespaces_to_reconcile: tuple[str, ...],
    *,
    evidence_token: str | None = None,
) -> bool:
    """Ensure every namespace this run wrote has a <list> declaration.

    WLV-01: closes the DEFECT-LIVE-01 trap. PUT /lists/files/<name>
    writes the source bytes, but unless <ruleset> in ossec.conf names
    that list, wazuh-analysisd emits warning 7616 at restart and
    silently drops every rule referencing it.

    Steps:
      1. GET /manager/configuration  — fetch current ossec.conf XML
      2. Parse with defusedxml
      3. For each namespace in ``namespaces_to_reconcile`` not already
         declared as ``etc/lists/<name>``, append a fresh
         ``<list>etc/lists/<name></list>`` to <ruleset>
      4. PUT /manager/configuration with the patched XML

    Idempotent: if every requested namespace is already declared,
    returns False and does NOT issue the PUT. Returns True when a
    PUT was made.

    Operator note (WLV-01d.3 / issue #52): the patched ossec.conf is
    serialised via stdlib ``ElementTree.tostring``, which does NOT
    preserve XML comments, indentation, or whitespace from the source
    document. The cluster does not care about formatting, but operators
    diffing ossec.conf snapshots in version control will see large
    "noise" diffs after the FIRST reconciler PUT (subsequent PUTs are
    incremental). Comment loss is a known limitation; if comment
    preservation becomes a hard requirement, swap the serialisation
    path for ``lxml.etree`` with tail/text preservation. Until then,
    document this in the operator runbook (WLV-12).
    """
    if not namespaces_to_reconcile:
        return False

    raw = await client.get_manager_configuration()
    if not raw:
        raise RuntimeError(
            "ossec.conf reconciler: GET /manager/configuration returned "
            "empty body; refusing to PUT a derived config"
        )

    # Wazuh ossec.conf frequently contains multiple <ossec_config> root
    # elements (one per include file merged by the API). Strict XML parsers
    # reject this as "junk after document element". Wrap in a synthetic
    # <doc> root so defusedxml can parse all blocks as siblings.
    #
    # Security invariant: if the raw content contains a DOCTYPE declaration,
    # pass it to defusedxml WITHOUT wrapping — DOCTYPE placement inside a
    # <doc> wrapper is invalid XML and masks defusedxml's EntitiesForbidden
    # path. Real Wazuh ossec.conf files never contain DOCTYPE; an adversarial
    # payload that does will be correctly rejected by the unwrapped parse.
    if b"<!DOCTYPE" in raw or b"<!doctype" in raw.lower():
        doc_root = DET.fromstring(raw)  # defusedxml raises EntitiesForbidden
    else:
        # Strip any leading XML declaration — it becomes invalid when nested
        # inside <doc>. DOCTYPE is already excluded above, so this safe.
        _stripped = raw.lstrip()
        if _stripped.startswith(b"<?xml"):
            _decl_end = _stripped.find(b"?>")
            _stripped = _stripped[_decl_end + 2 :].lstrip(b"\r\n") if _decl_end != -1 else _stripped
        wrapped = b"<doc>" + _stripped + b"</doc>"
        doc_root = DET.fromstring(wrapped)

    # ossec.conf may have several <ruleset> stanzas if the operator
    # split config; pick the first one that already carries <list>
    # entries, else the first <ruleset>, else create one.
    rulesets = doc_root.findall(".//ruleset")
    if not rulesets:
        # Append to first <ossec_config> child, or to doc_root if none.
        first_cfg = doc_root.find("ossec_config")
        parent = first_cfg if first_cfg is not None else doc_root
        ruleset = ET.SubElement(parent, "ruleset")
    else:
        with_lists = [r for r in rulesets if r.findall("list")]
        ruleset = with_lists[0] if with_lists else rulesets[0]

    declared: set[str] = set()
    for el in ruleset.findall("list"):
        text = (el.text or "").strip()
        if text.startswith("etc/lists/"):
            declared.add(text[len("etc/lists/") :])

    missing = [n for n in namespaces_to_reconcile if n not in declared]
    if not missing:
        return False

    for name in missing:
        new = ET.SubElement(ruleset, "list")
        new.text = f"etc/lists/{name}"

    # Serialize each child of the synthetic <doc> root separately and
    # concatenate — this reconstructs the multi-root document without
    # the wrapper. Comments and whitespace are lost (known limitation;
    # see WLV-01d.3 / issue #52).
    patched = b"".join(
        ET.tostring(child, encoding="utf-8", xml_declaration=False) for child in doc_root
    )
    status, _resp, _latency = await client.put_manager_configuration(
        patched, evidence_token=evidence_token
    )
    if status != 200:
        raise RuntimeError(
            f"PUT /manager/configuration returned {status}; ossec.conf reconciliation failed"
        )
    return True


async def push_iocs(
    case_dir: str,
    *,
    config: Any,
    evidence_token: str | None = None,
    dry_run: bool = True,
    operator: str | None = None,
    thymus: Any | None = None,
    evidence_gate: Any | None = None,
    client: Any | None = None,
    confirm_remove: bool = False,
    clear_lists: tuple[str, ...] = (),
) -> WazuhIOCPushResult:
    """Orchestrate the full Wazuh IOC push pipeline.

    This function is the main entry point called by both the CLI and the
    FastMCP tool. It is async to support the httpx.AsyncClient write path.

    Order of operations (ADR-008 + Fix 1):
      1. ThymusBridge.validate_inventory (BEFORE any data leaves the host)
      2. EvidenceGate.verify (BEFORE any network write)
      3. Transform IOCs to CDB payloads + rules XML
      4. If dry_run: return plan without writing
      5. If not dry_run: PUT each list, PUT rules, coalesced restart
      6. CourtroomSeal stamps each PUT with HMAC-SHA256 (ADR-016)
      7. Audit log appended

    Args:
        case_dir: Path to the Agentropix case directory.
        config: WazuhConfig instance.
        evidence_token: Operator mutation token (required for dry_run=False).
        dry_run: If True, compute payloads but do not write to Wazuh.
        operator: UNIX username (defaults to os.getlogin()).
        thymus: ThymusBridge instance (injectable for testing).
        evidence_gate: EvidenceGate instance (injectable for testing).
        client: WazuhClient instance (injectable for testing).
        confirm_remove: If False (default), refuse a PUT whose new payload
            would silently REMOVE keys present in the existing list (F-3).
            Set True to authorise an explicit retraction.
        clear_lists: Tuple of CDB list names to explicitly empty (F-9 —
            explicit clear API). Each name must be in the agentropix_*
            namespace. Implied confirm_remove=True for the affected
            list(s); the empty PUT is sealed and audited as
            ``op=put.list result=ok cleared=true``.

    Returns:
        WazuhIOCPushResult with counts and seal.
    """
    import uuid

    run_id = str(uuid.uuid4())[:8]

    if operator is None:
        try:
            operator = os.getlogin()
        except OSError:
            operator = os.environ.get("USER", "agentropix-mcp")

    # --- Load inventory (FR-1) ---
    from agentropix_mcp.wazuh.inventory import load_case_inventory

    inventory = load_case_inventory(case_dir)
    case_id = inventory.case_id

    # --- W-A16: generate seal helper EARLY so Thymus reject and JWT refresh
    # rows can be HMAC-sealed (court-defensibility — closes seal-asymmetry
    # called out by critic-courtroom). Before this fix the Thymus reject
    # path used unsealed _append_audit while diff-guard refusals at a
    # later stage emitted sealed degenerate envelopes. ---
    from agentropix_mcp.wazuh.seal import CourtroomSeal, generate_session_key

    session_key = generate_session_key(config.audit_log)
    seal_helper = CourtroomSeal(session_key)

    # --- Fix 1 (S-1): Thymus STRICT validation FIRST ---
    if thymus is None:
        from agentropix_mcp.wazuh.thymus_bridge import ThymusBridge

        thymus = ThymusBridge()

    try:
        thymus.validate_inventory(inventory)
    except Exception as exc:
        from agentropix_mcp.wazuh.thymus_bridge import ThymusReject

        if isinstance(exc, ThymusReject):
            # W-A16: seal the rejection row so the chain is symmetric with
            # diff-guard refusals. Degenerate envelope (no req/resp body)
            # since Thymus rejects pre-network.
            _seal_and_audit_attempt(
                audit_log=config.audit_log,
                seal_helper=seal_helper,
                operator=operator,
                case_id=case_id,
                run_id=run_id,
                event="thymus.reject",
                op="thymus.validate_inventory",
                endpoint="(pre-network)",
                evidence_token=evidence_token,
                req_body=b"",
                resp_body=b"",
                status=0,
                latency_ms=0,
                result="reject",
                extra={"ioc_value_redacted": "***REDACTED***", "reason_class": type(exc).__name__},
                error_class="ThymusReject",
            )
        raise

    # --- Classify IOCs (FR-2, FR-3) ---
    from agentropix_mcp.wazuh.prioritise import PriorityClassifier

    classifier = PriorityClassifier(ip_allowlist=config.ip_allowlist)
    pushable = []
    excluded_count = 0

    for rec in inventory.records:
        decision = classifier.classify(rec)
        if decision.tier in ("tier1", "tier2"):
            pushable.append(rec)
        else:
            excluded_count += 1

    logger.info(
        "IOC classification: %d pushable, %d excluded (case=%s, run=%s)",
        len(pushable),
        excluded_count,
        case_id,
        run_id,
    )

    # --- Build CDB payloads (FR-4) ---
    payloads: dict[str, bytes] = {}
    for kind, list_name in _KIND_TO_LIST.items():
        body = _make_cdb_body(pushable, list_name, kind)
        payloads[list_name] = body

    rules_body = _RULES_XML_TEMPLATE.encode("utf-8")

    # --- WZ-019 (master-report §4.2 #11) provenance gate ---
    # Split pushable into with/without provenance. When the env gate is
    # set, raise ProvenanceMissingError BEFORE EvidenceGate so missing
    # metadata never reaches the wire. When the gate is off (default),
    # log a warning and continue — operators back-loading legacy corpora
    # need a graceful degradation while they capture retroactive
    # provenance.
    from agentropix_mcp.wazuh.models import ProvenanceMissingError

    with_provenance, without_provenance = _provenance_gate(pushable)
    require_provenance = os.environ.get(_REQUIRE_PROVENANCE_ENV, "").lower() in {"1", "true", "yes"}
    if without_provenance and require_provenance:
        sample = [
            {"kind": getattr(r, "kind", "?"), "value": getattr(r, "value", "?")}
            for r in without_provenance[:5]
        ]
        # Audit-row first so the rejection is recorded even if the
        # raise propagates through to the caller's error path.
        _append_audit(
            config.audit_log,
            {
                "ts": datetime.now(UTC).isoformat(),
                "event": "wazuh.provenance.gate",
                "case_id": case_id,
                "run_id": run_id,
                "result": "reject",
                "missing_count": len(without_provenance),
                "missing_sample": sample,
                "require_provenance": True,
            },
        )
        raise ProvenanceMissingError(
            f"WZ-019: {len(without_provenance)} IOC(s) lack the provenance "
            f"triple and AGENTROPIX_REQUIRE_IOC_PROVENANCE is enabled. "
            f"Missing kinds (first 5): {sample}. Capture "
            "{source_evidence_sha256, extraction_tool, extraction_args, "
            "extraction_ts_utc, analyst} in MASTER-IOCS.json under each "
            "entry's 'provenance' block."
        )
    if without_provenance and not require_provenance:
        logger.warning(
            "WZ-019: %d IOC(s) without provenance triple — proceeding in "
            "advisory mode (set AGENTROPIX_REQUIRE_IOC_PROVENANCE=1 to "
            "enforce). Court-defensibility is degraded for these entries.",
            len(without_provenance),
        )
    # Always emit the audit row for run-level visibility, even when the
    # gate is off — operators tracking SIFT-WEAKNESSES can grep it.
    _append_audit(
        config.audit_log,
        {
            "ts": datetime.now(UTC).isoformat(),
            "event": "wazuh.provenance.gate",
            "case_id": case_id,
            "run_id": run_id,
            "result": "ok" if not without_provenance else "advisory",
            "with_provenance_count": len(with_provenance),
            "without_provenance_count": len(without_provenance),
            "require_provenance": require_provenance,
        },
    )

    if dry_run:
        _append_audit(
            config.audit_log,
            {
                "ts": datetime.now(UTC).isoformat(),
                "event": "wazuh.dryrun",
                "case_id": case_id,
                "run_id": run_id,
                "dry_run": True,
                "pushable_count": len(pushable),
                "excluded_count": excluded_count,
                "result": "ok",
            },
        )
        return WazuhIOCPushResult(
            case_id=case_id,
            pushed=0,
            skipped_tier3=excluded_count,
            dry_run=True,
            run_id=run_id,
        )

    # --- Fix 1 (S-1): EvidenceGate BEFORE any write ---
    if evidence_gate is None:
        from agentropix_mcp.wazuh.evidence_gate import EvidenceGate

        evidence_gate = EvidenceGate()

    evidence_gate.check(evidence_token, op="push_iocs")

    # --- Session key + seal_helper already generated above (W-A16) ---

    # --- Create WazuhClient ---
    if client is None:
        from agentropix_mcp.wazuh.client import WazuhClient

        client = WazuhClient(
            config,
            thymus=thymus,
            evidence_gate=evidence_gate,
            session_key=session_key,
            evidence_token=evidence_token,
            operator=operator,
            case_id=case_id,
            run_id=run_id,
        )

    # --- Execute writes (FR-5, FR-6) ---
    pushed = 0
    failed = 0
    skipped_idempotent = 0
    seals = []
    # WLV-01c (issue #51): track per-namespace PUT success so the AC-d
    # reconciler is invoked with ONLY the namespaces whose source-bytes
    # actually landed on the manager. Without this filter a partial
    # PUT failure would still get a <list> declaration in ossec.conf
    # and re-introduce error 7616 for the failed namespace at restart.
    # Idempotent-skip namespaces are also included (the existing list
    # body matches what we wanted to write, so it's effectively
    # already-on-the-manager).
    namespaces_with_landed_bytes: set[str] = set()
    # WLV-02: per-rule self-test outcomes — populated after the
    # post-restart poll succeeds. Initialised empty so the result
    # constructor below always has a list to thread, even on the
    # restart-pending / pre-push-failure paths.
    self_test_results: list[dict] = []

    # Apply F-9 clear directives — when an operator asks to clear a list,
    # the payload is forced to empty regardless of any records that would
    # have been included for that kind.
    for _name in clear_lists:
        if _name in payloads:
            payloads[_name] = b""
        else:
            logger.warning("clear_lists requested unknown list %s; ignored", _name)

    # F-11: try/finally so the shared httpx.AsyncClient is closed even if
    # a mid-run raise (e.g., seal-failure path) bypasses the end-of-run
    # cleanup. SIFT-W-177 leak fix.
    try:
        for list_name, body in payloads.items():
            endpoint = f"/lists/files/{list_name}"

            # F-9: explicit clear takes precedence — operator asked to empty
            # this list. Treat as confirm_remove=True for this name only.
            list_in_clear = list_name in clear_lists
            if not body.strip() and not list_in_clear:
                logger.debug(
                    "Skipping empty CDB list %s (no IOCs and not in clear_lists)", list_name
                )
                continue
            effective_confirm_remove = confirm_remove or list_in_clear

            # F-3 + NEW-1: pre-PUT diff guard — refuse to silently REMOVE keys.
            # Fail-CLOSED on GET failure: an attacker who can cause the GET to
            # fail (network blip, JWT expiry, indexer down) MUST NOT bypass the
            # silent-removal protection. Operator can override with
            # confirm_remove=True to acknowledge the unknown prior state.
            get_failed = False
            existing_body = b""
            try:
                existing_body = await client.get_cdb_list(list_name)
            except Exception as exc:
                get_failed = True
                logger.error(
                    "get_cdb_list(%s) failed; diff guard cannot verify: %s", list_name, exc
                )

            existing_keys = _parse_cdb_keys(existing_body)
            new_keys = _parse_cdb_keys(body)
            removed = tuple(sorted(existing_keys - new_keys))

            # W-A04 idempotency: if the GET succeeded and the body bytes are
            # byte-identical to what's on the manager, skip the PUT. Suppresses
            # the "operator double-click → restart storm" failure mode. Explicit
            # clears (list_in_clear) bypass this — empty payload may legitimately
            # match an already-empty list but the operator asked to clear.
            if not get_failed and not list_in_clear and body == existing_body:
                _seal_and_audit_attempt(
                    audit_log=config.audit_log,
                    seal_helper=seal_helper,
                    operator=operator,
                    case_id=case_id,
                    run_id=run_id,
                    event="wazuh.put.list",
                    op="put.list",
                    endpoint=endpoint,
                    evidence_token=evidence_token,
                    req_body=body,
                    resp_body=b"",
                    status=0,
                    latency_ms=0,
                    result="skipped_idempotent",
                    extra={"list_name": list_name, "ioc_count": len(new_keys)},
                )
                skipped_idempotent += 1
                # WLV-01c: idempotent skip = bytes already match what we
                # wanted; treat as "landed" for reconciler purposes.
                namespaces_with_landed_bytes.add(list_name)
                continue

            if get_failed and not effective_confirm_remove:
                _seal_and_audit_attempt(
                    audit_log=config.audit_log,
                    seal_helper=seal_helper,
                    operator=operator,
                    case_id=case_id,
                    run_id=run_id,
                    event="wazuh.put.list",
                    op="put.list",
                    endpoint=endpoint,
                    evidence_token=evidence_token,
                    req_body=body,
                    resp_body=b"",
                    status=0,
                    latency_ms=0,
                    result="refused_diff_guard_unavailable",
                    extra={"list_name": list_name},
                    error_class="DiffGuardUnavailable",
                )
                failed += 1
                continue
            if removed and not effective_confirm_remove:
                from agentropix_mcp.wazuh.client import IOCRemovalRequiresConfirmation

                err = IOCRemovalRequiresConfirmation(list_name, removed)
                logger.error("Pre-PUT diff guard refused %s: %s", list_name, err)
                _seal_and_audit_attempt(
                    audit_log=config.audit_log,
                    seal_helper=seal_helper,
                    operator=operator,
                    case_id=case_id,
                    run_id=run_id,
                    event="wazuh.put.list",
                    op="put.list",
                    endpoint=endpoint,
                    evidence_token=evidence_token,
                    req_body=body,
                    resp_body=b"",
                    status=0,
                    latency_ms=0,
                    result="refused_silent_removal",
                    extra={
                        "list_name": list_name,
                        "removed_count": len(removed),
                        "removed_sample": list(removed[:5]),
                    },
                    error_class="IOCRemovalRequiresConfirmation",
                )
                failed += 1
                continue

            # F-1 / F-2: every PUT attempt emits a sealed audit row regardless
            # of outcome. Success paths bind real req/resp hashes; failure
            # paths bind a degenerate envelope (resp_sha256 over b"") so the
            # attempt is still provably attributable.
            # NEW-4: capture wall-clock latency even on failure paths so the
            # audit log preserves the timing signal for TLS / connect timeouts.
            t0 = time.monotonic()
            try:
                status, resp_body, latency_ms = await client.put_cdb_list(
                    list_name, body, evidence_token=evidence_token
                )
            except Exception as exc:
                elapsed_ms = (time.monotonic() - t0) * 1000.0
                logger.error("Failed to push CDB list %s: %s", list_name, exc)
                _seal_and_audit_attempt(
                    audit_log=config.audit_log,
                    seal_helper=seal_helper,
                    operator=operator,
                    case_id=case_id,
                    run_id=run_id,
                    event="wazuh.put.list",
                    op="put.list",
                    endpoint=endpoint,
                    evidence_token=evidence_token,
                    req_body=body,
                    resp_body=b"",
                    status=0,
                    latency_ms=elapsed_ms,
                    result="error",
                    extra={"list_name": list_name},
                    error_class=type(exc).__name__,
                )
                failed += 1
                continue

            seal_str = _seal_and_audit_attempt(
                audit_log=config.audit_log,
                seal_helper=seal_helper,
                operator=operator,
                case_id=case_id,
                run_id=run_id,
                event="wazuh.put.list",
                op="put.list",
                endpoint=endpoint,
                evidence_token=evidence_token,
                req_body=body,
                resp_body=resp_body,
                status=status,
                latency_ms=latency_ms,
                result="ok" if status == 200 else "error",
                extra={"list_name": list_name},
                # F-2 asymmetry fix: HTTP non-200 also gets an error_class so
                # downstream filters keying on error_class catch HTTP-only
                # failures alongside raised-exception failures.
                error_class=None if status == 200 else f"HTTP{status}",
            )
            seals.append(seal_str)
            # Wazuh sometimes returns HTTP 200 with total_failed_items > 0
            # when the write silently fails (e.g., missing overwrite=true).
            # Detect this and treat as a failure so pushed is not inflated.
            _resp_failed = False
            if status == 200 and resp_body:
                try:
                    _resp_json = json.loads(resp_body)
                    _resp_failed = _resp_json.get("data", {}).get("total_failed_items", 0) > 0
                    if _resp_failed:
                        logger.error(
                            "CDB PUT %s: HTTP 200 but total_failed_items > 0: %s",
                            list_name,
                            _resp_json.get("data", {}).get("failed_items", [])[:2],
                        )
                except Exception:
                    pass
            if status == 200 and not _resp_failed:
                pushed += 1
                # WLV-01c: this namespace's source bytes are now on the
                # manager. Eligible for ossec.conf <list> declaration.
                namespaces_with_landed_bytes.add(list_name)
                # WZ-019 (master-report §4.2 #11): write the per-list
                # provenance.jsonl sidecar AFTER a successful PUT so a
                # later WLV-10 rollback that discards the source bytes
                # also discards the provenance (consistent state).
                # Reverse-lookup kind from list_name via _KIND_TO_LIST.
                kind_for_list = next(
                    (k for k, v in _KIND_TO_LIST.items() if v == list_name),
                    None,
                )
                if kind_for_list is not None:
                    try:
                        sidecar = _write_provenance_sidecar(
                            inventory.case_dir,
                            pushable,
                            list_name,
                            kind_for_list,
                            seal_helper=seal_helper,
                            operator=operator,
                            case_id=case_id,
                            run_id=run_id,
                            evidence_token=evidence_token,
                        )
                        if sidecar is not None:
                            logger.info("WZ-019 provenance sidecar written: %s", sidecar)
                    except Exception as exc:
                        # Sidecar emission failure MUST NOT break the
                        # push pipeline. Log + audit, then proceed.
                        logger.warning(
                            "WZ-019 sidecar write failed for %s: %s",
                            list_name,
                            exc,
                        )
                        _append_audit(
                            config.audit_log,
                            {
                                "ts": datetime.now(UTC).isoformat(),
                                "event": "wazuh.provenance.sidecar",
                                "case_id": case_id,
                                "run_id": run_id,
                                "list_name": list_name,
                                "result": "error",
                                "error_class": type(exc).__name__,
                            },
                        )
            else:
                failed += 1

        # --- Rules XML push (FR-6) — F-1 / F-2 always-seal-the-attempt ---
        rules_filename = "agentropix_srl2018_rules.xml"
        rules_endpoint = f"/rules/files/{rules_filename}"

        # W-A04 idempotency: GET the existing rules XML; skip PUT when identical.
        # Read failure is non-fatal — fall through to the PUT path so the rules
        # always reach the manager when their state is unknown.
        try:
            existing_rules: bytes | None = await client.get_rules_file(rules_filename)
        except Exception as exc:
            logger.debug("get_rules_file(%s) failed; will PUT: %s", rules_filename, exc)
            existing_rules = None

        if existing_rules == rules_body:
            _seal_and_audit_attempt(
                audit_log=config.audit_log,
                seal_helper=seal_helper,
                operator=operator,
                case_id=case_id,
                run_id=run_id,
                event="wazuh.put.rules",
                op="put.rules",
                endpoint=rules_endpoint,
                evidence_token=evidence_token,
                req_body=rules_body,
                resp_body=b"",
                status=0,
                latency_ms=0,
                result="skipped_idempotent",
                extra={"filename": rules_filename},
            )
            skipped_idempotent += 1
        else:
            t_rules = time.monotonic()
            try:
                status, resp_body, latency_ms = await client.put_rules_xml(
                    rules_filename, rules_body, evidence_token=evidence_token
                )
            except Exception as exc:
                elapsed_ms = (time.monotonic() - t_rules) * 1000.0
                logger.error("Failed to push rules XML: %s", exc)
                _seal_and_audit_attempt(
                    audit_log=config.audit_log,
                    seal_helper=seal_helper,
                    operator=operator,
                    case_id=case_id,
                    run_id=run_id,
                    event="wazuh.put.rules",
                    op="put.rules",
                    endpoint=rules_endpoint,
                    evidence_token=evidence_token,
                    req_body=rules_body,
                    resp_body=b"",
                    status=0,
                    latency_ms=elapsed_ms,
                    result="error",
                    extra={"filename": rules_filename},
                    error_class=type(exc).__name__,
                )
                failed += 1
            else:
                seal_str = _seal_and_audit_attempt(
                    audit_log=config.audit_log,
                    seal_helper=seal_helper,
                    operator=operator,
                    case_id=case_id,
                    run_id=run_id,
                    event="wazuh.put.rules",
                    op="put.rules",
                    endpoint=rules_endpoint,
                    evidence_token=evidence_token,
                    req_body=rules_body,
                    resp_body=resp_body,
                    status=status,
                    latency_ms=latency_ms,
                    result="ok" if status == 200 else "error",
                    extra={"filename": rules_filename},
                    error_class=None if status == 200 else f"HTTP{status}",
                )
                seals.append(seal_str)
                if status == 200:
                    pushed += 1
                else:
                    failed += 1

        # --- WLV-01 AC-d: ossec.conf <ruleset> reconciliation ---
        # The PUT loop above wrote source bytes for every CDB namespace
        # this run touched. But unless ossec.conf names that namespace
        # under <ruleset>, wazuh-analysisd will emit warning 7616 at
        # restart and silently drop the rules referencing it (the
        # DEFECT-LIVE-01 trap). Reconcile BEFORE issuing the restart.
        #
        # Failure here MUST NOT issue the restart, MUST emit a sealed
        # audit row, and MUST cause push_iocs() to return the §4.4 #19
        # rollback envelope so a future WLV-10 snapshot mechanism can
        # consume it.
        reconcile_error: dict | None = None
        if pushed > 0:
            # WLV-01c (issue #51): ONLY reconcile namespaces whose source
            # bytes actually landed on the manager (or matched idempotently)
            # this run. A failed per-namespace PUT must NOT get a <list>
            # declaration in ossec.conf — declaring a namespace whose .cdb
            # cannot be compiled re-introduces error 7616 for that one
            # namespace. The set is built from successful PUTs +
            # idempotent skips in the loop above.
            #
            # Explicit clear_lists entries also reconcile: even an empty
            # CDB needs the <list> declaration to avoid 7616.
            namespaces_to_reconcile = tuple(
                sorted(namespaces_with_landed_bytes | (set(clear_lists) & set(payloads)))
            )
            t_reconcile = time.monotonic()
            try:
                reconcile_changed = await _reconcile_ossec_conf_lists(
                    client,
                    namespaces_to_reconcile,
                    evidence_token=evidence_token,
                )
            except Exception as exc:
                elapsed_ms = (time.monotonic() - t_reconcile) * 1000.0
                logger.error("ossec.conf reconciliation failed: %s", exc)
                _seal_and_audit_attempt(
                    audit_log=config.audit_log,
                    seal_helper=seal_helper,
                    operator=operator,
                    case_id=case_id,
                    run_id=run_id,
                    event="wazuh.ossec.reconcile",
                    op="manager.configuration.patch",
                    endpoint="/manager/configuration",
                    evidence_token=evidence_token,
                    req_body=b"",
                    resp_body=b"",
                    status=0,
                    latency_ms=elapsed_ms,
                    result="error",
                    extra={
                        "namespaces_to_reconcile": list(namespaces_to_reconcile),
                    },
                    error_class=type(exc).__name__,
                )
                reconcile_error = {
                    "error": "ossec_conf_reconcile_failed",
                    "details": {
                        "exception_class": type(exc).__name__,
                        "namespaces_to_reconcile": list(namespaces_to_reconcile),
                    },
                    "rollback_required": True,
                }
            else:
                elapsed_ms = (time.monotonic() - t_reconcile) * 1000.0
                _seal_and_audit_attempt(
                    audit_log=config.audit_log,
                    seal_helper=seal_helper,
                    operator=operator,
                    case_id=case_id,
                    run_id=run_id,
                    event="wazuh.ossec.reconcile",
                    op="manager.configuration.patch",
                    endpoint="/manager/configuration",
                    evidence_token=evidence_token,
                    req_body=b"",
                    resp_body=b"",
                    status=200,
                    latency_ms=elapsed_ms,
                    result="ok",
                    extra={
                        "namespaces_to_reconcile": list(namespaces_to_reconcile),
                        "config_patched": bool(reconcile_changed),
                    },
                )

        # --- Coalesced restart (FR-7) — only if something was pushed ---
        # F-1: split restart_manager() and poll_restart() into separate try
        # blocks so the partial-state path (PUT issued, manager bytes-on-disk,
        # poll timed out) emits its own sealed audit row instead of being
        # silently swallowed.
        # F-10: restart fires when ANYTHING was successfully pushed, even if
        # there were partial failures — the bytes are on disk and need to be
        # loaded. The outcome enum below captures partial-success state.
        restart_pending = False
        restart_attempted = False
        if pushed > 0 and reconcile_error is None:
            restart_attempted = True
            t_restart = time.monotonic()
            try:
                status, resp_body, latency_ms = await client.restart_manager(
                    evidence_token=evidence_token
                )
            except Exception as exc:
                elapsed_ms = (time.monotonic() - t_restart) * 1000.0
                logger.error("Manager restart issue failed: %s", exc)
                _seal_and_audit_attempt(
                    audit_log=config.audit_log,
                    seal_helper=seal_helper,
                    operator=operator,
                    case_id=case_id,
                    run_id=run_id,
                    event="wazuh.manager.restart",
                    op="manager.restart",
                    endpoint="/manager/restart",
                    evidence_token=evidence_token,
                    req_body=b"",
                    resp_body=b"",
                    status=0,
                    latency_ms=elapsed_ms,
                    result="error",
                    error_class=type(exc).__name__,
                )
                restart_pending = True
            else:
                _seal_and_audit_attempt(
                    audit_log=config.audit_log,
                    seal_helper=seal_helper,
                    operator=operator,
                    case_id=case_id,
                    run_id=run_id,
                    event="wazuh.manager.restart",
                    op="manager.restart",
                    endpoint="/manager/restart",
                    evidence_token=evidence_token,
                    req_body=b"",
                    resp_body=resp_body,
                    status=status,
                    latency_ms=latency_ms,
                    result="ok",
                )
                t_poll = time.monotonic()
                try:
                    await client.poll_restart(timeout_sec=config.restart_timeout_sec)
                except Exception as exc:
                    elapsed_ms = (time.monotonic() - t_poll) * 1000.0
                    logger.error("Manager restart poll failed: %s", exc)
                    _seal_and_audit_attempt(
                        audit_log=config.audit_log,
                        seal_helper=seal_helper,
                        operator=operator,
                        case_id=case_id,
                        run_id=run_id,
                        event="wazuh.manager.restart.poll",
                        op="manager.restart.poll",
                        endpoint="/manager/status",
                        evidence_token=evidence_token,
                        req_body=b"",
                        resp_body=b"",
                        status=0,
                        latency_ms=elapsed_ms,
                        result="timeout" if "timed out" in str(exc).lower() else "error",
                        error_class=type(exc).__name__,
                    )
                    restart_pending = True
                else:
                    elapsed_ms = (time.monotonic() - t_poll) * 1000.0
                    _seal_and_audit_attempt(
                        audit_log=config.audit_log,
                        seal_helper=seal_helper,
                        operator=operator,
                        case_id=case_id,
                        run_id=run_id,
                        event="wazuh.manager.restart.poll",
                        op="manager.restart.poll",
                        endpoint="/manager/status",
                        evidence_token=evidence_token,
                        req_body=b"",
                        resp_body=b"",
                        status=200,
                        latency_ms=elapsed_ms,
                        result="ok",
                    )

                    # --- WLV-02: post-restart self-test ---
                    # Master report §4.1 #2: send a sentinel event to
                    # /logtest for each agentropix_* rule whose namespace
                    # has a non-empty body in this run's payloads.
                    # Failure here MUST NOT raise; the orchestrator
                    # records the per-rule outcome and routes to
                    # OUTCOME_PUSHED_BUT_SELF_TEST_FAILED if any rule
                    # failed (operator/WLV-10 decides rollback).
                    # Self-test runs only on a CLEAN restart
                    # (poll_restart succeeded) so a transiently-degraded
                    # manager doesn't generate false alarms.
                    #
                    # Note: PR #49 (WLV-01c) introduces a stricter
                    # `namespaces_with_landed_bytes` set that filters
                    # out failed-PUT namespaces. When that lands in
                    # wave1 + this branch rebases, swap the derivation
                    # below for the WLV-01c set. The current proxy
                    # (non-empty payload bytes) overcounts only when
                    # a per-namespace PUT failed mid-run; the
                    # self-test then correctly reports alert_false for
                    # that namespace, which is informative not harmful.
                    namespaces_to_self_test = {name for name, body in payloads.items() if body}
                    try:
                        self_test_results = await _run_post_restart_self_test(
                            client,
                            payloads,
                            namespaces_to_self_test,
                            seal_helper=seal_helper,
                            operator=operator,
                            case_id=case_id,
                            run_id=run_id,
                            evidence_token=evidence_token,
                            audit_log=config.audit_log,
                        )
                    except Exception as exc:
                        # Defensive: the helper is already best-effort
                        # per-rule; this catch is for unexpected errors
                        # at the helper boundary itself.
                        logger.error("WLV-02 self-test orchestration failed: %s", exc)
                        self_test_results = []

        # Aggregate seal (use the last individual seal as the run-level seal)
        aggregate_seal = seals[-1] if seals else None
    finally:
        # F-11: best-effort aclose. Never propagates back over the original raise.
        aclose = getattr(client, "aclose", None)
        if aclose is not None:
            try:
                await aclose()
            except Exception as exc:
                logger.warning("WazuhClient close failed: %s", exc)

    # F-10: derive a richer outcome string. The boolean fields stay for
    # back-compat; the orchestrator-level outcome is exposed via the
    # IOCPushOutcome enum on WazuhIOCPushResult.
    #
    # WLV-02: a self-test fail (any non-skipped result with passed=False)
    # escalates the outcome to OUTCOME_PUSHED_BUT_SELF_TEST_FAILED so the
    # caller can route to investigation/rollback. Skipped entries (no
    # landed bytes for that rule) are NOT failures.
    self_test_failed = any(
        not r.get("passed", False) and not r.get("skipped", False) for r in self_test_results
    )

    if reconcile_error is not None:
        # WLV-01 AC-d: PUTs landed, reconciler failed, restart was
        # suppressed. Treat as post-push failure so callers can route
        # the rollback envelope to WLV-10's snapshot mechanism.
        outcome = WazuhIOCPushResult.OUTCOME_FAILED_POST_PUSH
    elif not restart_attempted:
        outcome = (
            WazuhIOCPushResult.OUTCOME_NOTHING_PUSHED
            if pushed == 0
            else WazuhIOCPushResult.OUTCOME_FAILED_PRE_PUSH
        )
    elif restart_pending:
        outcome = WazuhIOCPushResult.OUTCOME_PUSHED_PENDING_RESTART
    elif self_test_failed:
        outcome = WazuhIOCPushResult.OUTCOME_PUSHED_BUT_SELF_TEST_FAILED
    elif failed > 0:
        outcome = WazuhIOCPushResult.OUTCOME_PARTIAL_PUSHED_AND_LOADED
    else:
        outcome = WazuhIOCPushResult.OUTCOME_PUSHED_AND_LOADED

    return WazuhIOCPushResult(
        case_id=case_id,
        pushed=pushed,
        skipped_tier3=excluded_count,
        skipped_idempotent=skipped_idempotent,
        failed=failed,
        restart_pending=restart_pending,
        dry_run=False,
        seal=aggregate_seal,
        run_id=run_id,
        self_test_results=self_test_results,
        outcome=outcome,
        error=reconcile_error,
    )


# ===========================================================================
# WZ-022 / W-275 — Findings indexing orchestrator
# ===========================================================================
#
# Sits alongside ``push_iocs`` (Manager-API IOC push, detection content) as
# the writer-side path that lands Agentropix-derived FINDINGS into the
# dedicated ``agentropix-findings-*`` index pattern. Foundation methods on
# ``IndexerClient`` (``bulk_index`` / ``put_index_template``) shipped in
# W-274 / PR #152. This module ships the orchestration layer:
#
#   1. idempotent template install (cached per process for the
#      (indexer_url, template_name) tuple)
#   2. per-finding HMAC content seal (CourtroomSeal-derived; ADR-016 chain)
#      written into the doc as ``hmac_seal``
#   3. batched bulk_index (cap 500 docs per ``_bulk`` call — same envelope
#      as ``IndexerClient.search()`` size cap)
#   4. sealed audit row per batch (event ``findings.bulk_index``) with
#      ``indexed_count`` / ``indexed_failed_count`` / ``index_template_
#      installed_this_run`` extras
#   5. fail-soft on Indexer outage: returns
#      ``OUTCOME_INDEXER_OUTAGE`` instead of raising — Manager push is the
#      SANS-judged path, Indexer is supplementary retention
#
# Out of scope (separate tickets):
#   * MCP tool surface ``wazuh_index_findings`` (W-276)
#   * ILM policy on ``agentropix-findings-*`` (W-277)
#   * Kibana dashboard (W-278)
#   * Historical Reports_results/ backfill (W-279)


_FINDINGS_BULK_CHUNK_SIZE = 500
"""Cap per ``_bulk`` call. Mirrors the
``IndexerClient.search()`` size cap from master-report Sec F4.4 capacity
envelope. Larger batches risk Indexer-side payload limits on smaller
deployments."""


class WazuhFindingsIndexResult:
    """Result of an ``index_findings()`` call.

    Outcome values follow the IOCPushOutcome convention from
    ``WazuhIOCPushResult`` (suffix ``OUTCOME_``); a new caller should
    consume ``outcome`` rather than the boolean / count fields.
    """

    OUTCOME_INDEXED = "indexed"
    OUTCOME_PARTIAL_INDEXED = "partial_indexed"
    OUTCOME_INDEXER_OUTAGE = "indexer_outage"
    OUTCOME_DRY_RUN = "dry_run"
    OUTCOME_NOTHING_INDEXED = "nothing_indexed"

    def __init__(
        self,
        *,
        indexed_count: int = 0,
        indexed_failed_count: int = 0,
        batch_count: int = 0,
        index_template_installed_this_run: bool = False,
        ism_policy_installed_this_run: bool = False,
        index: str = "",
        dry_run: bool = True,
        run_id: str = "",
        outcome: str | None = None,
        error: dict | None = None,
    ) -> None:
        self.indexed_count = indexed_count
        self.indexed_failed_count = indexed_failed_count
        self.batch_count = batch_count
        self.index_template_installed_this_run = index_template_installed_this_run
        self.ism_policy_installed_this_run = ism_policy_installed_this_run
        self.index = index
        self.dry_run = dry_run
        self.run_id = run_id
        self.outcome = outcome or (
            self.OUTCOME_DRY_RUN if dry_run else self.OUTCOME_NOTHING_INDEXED
        )
        self.error = error

    def model_dump(self) -> dict:
        d = {
            "indexed_count": self.indexed_count,
            "indexed_failed_count": self.indexed_failed_count,
            "batch_count": self.batch_count,
            "index_template_installed_this_run": self.index_template_installed_this_run,
            "ism_policy_installed_this_run": self.ism_policy_installed_this_run,
            "index": self.index,
            "dry_run": self.dry_run,
            "run_id": self.run_id,
            "outcome": self.outcome,
        }
        if self.error is not None:
            d["error"] = copy.deepcopy(self.error)
        return d


def _default_findings_index_for_today() -> str:
    """Return the date-suffixed default index name for today's findings."""
    return f"agentropix-findings-{datetime.now(UTC):%Y.%m.%d}"


def _seal_finding_doc(
    seal_helper: Any,
    *,
    finding: dict,
    operator: str,
    case_id: str,
    run_id: str,
    evidence_token: str | None,
    index: str,
) -> dict:
    """Return a copy of ``finding`` with ``@timestamp``, ``source_run_id``,
    and ``hmac_seal`` fields stamped in.

    The HMAC content seal binds the canonical JSON serialisation of the
    finding (sort_keys=True) to the (case_id, run_id, operator, ts,
    evidence_token, index) tuple via the existing CourtroomSeal chain
    (ADR-016). The seal is a *content* seal (status=0, resp_sha256 is the
    32-byte zero placeholder) — distinct from the network seal that
    ``_seal_and_audit_attempt`` produces for the ``_bulk`` HTTP call.
    """
    doc = dict(finding)
    ts = datetime.now(UTC)
    doc.setdefault("@timestamp", ts.isoformat())
    doc.setdefault("source_run_id", run_id)
    canonical = json.dumps(doc, sort_keys=True, default=str).encode("utf-8")
    req_sha256 = hashlib.sha256(canonical).hexdigest()
    zero_resp_sha256 = hashlib.sha256(b"").hexdigest()
    finding_id = str(doc.get("finding_id", ""))
    doc["hmac_seal"] = seal_helper.bind(
        operator=operator,
        case_id=case_id,
        ts=ts,
        evidence_token_id=evidence_token[:12] if evidence_token else None,
        endpoint=f"index:{index}/{finding_id}",
        req_sha256=req_sha256,
        resp_sha256=zero_resp_sha256,
        status=0,
        run_id=run_id,
    )
    return doc


async def index_findings(
    findings: list[dict],
    *,
    config: Any,
    case_id: str,
    evidence_token: str | None = None,
    dry_run: bool = True,
    operator: str | None = None,
    indexer_client: Any | None = None,
    index: str | None = None,
    run_id: str | None = None,
) -> WazuhFindingsIndexResult:
    """Index Agentropix findings into the ``agentropix-findings-*`` pattern.

    Flow:
      1. Resolve target index (default: ``agentropix-findings-YYYY.MM.DD``).
      2. If ``dry_run``: stamp every finding with @timestamp + hmac_seal
         (so the operator can inspect the would-be-indexed shape) and
         return ``OUTCOME_DRY_RUN`` without touching the network.
      3. Install ``AGENTROPIX_FINDINGS_TEMPLATE`` via
         ``put_index_template`` if not already cached for this
         (indexer_url, template_name) tuple in this process.
      4. Chunk findings into batches of ``_FINDINGS_BULK_CHUNK_SIZE`` and
         call ``IndexerClient.bulk_index`` for each batch.
      5. Emit one sealed audit row per batch via
         ``_seal_and_audit_attempt`` with ``indexed_count`` /
         ``indexed_failed_count`` extras.
      6. On Indexer outage (TransientHTTPError or IndexerError):
         degrade to ``OUTCOME_INDEXER_OUTAGE``, emit a sealed audit row
         with ``result="indexer_outage"``, return without raising.

    Args:
        findings: list of finding dicts. Empty list returns
            ``OUTCOME_NOTHING_INDEXED`` without any network call.
        config: WazuhConfig instance (uses ``audit_log`` + the indexer_*
            attrs to construct the IndexerClient when ``indexer_client``
            is ``None``).
        case_id: case identifier for the audit-seal binding.
        evidence_token: operator mutation token (required for dry_run=False
            by the evidence_gate chain; this function does NOT itself
            invoke EvidenceGate.verify — caller is responsible. Same
            contract as push_iocs).
        dry_run: if True, compute the would-be-indexed shape (incl. seals)
            but do not write to the Indexer.
        operator: UNIX username (defaults to os.getlogin() / $USER).
        indexer_client: injectable IndexerClient (test seam). When None,
            constructed from ``config.indexer_url`` / ``config.indexer_user``
            / ``config.indexer_password``.
        index: explicit target index name; defaults to the date-suffixed
            template per ``_default_findings_index_for_today()``.
        run_id: optional pre-computed run_id (defaults to a fresh uuid4
            prefix, mirroring push_iocs).

    Returns:
        WazuhFindingsIndexResult.
    """
    import uuid

    from agentropix_mcp.wazuh.index_templates import (
        AGENTROPIX_FINDINGS_TEMPLATE,
        AGENTROPIX_FINDINGS_TEMPLATE_NAME,
    )
    from agentropix_mcp.wazuh.indexer_client import (
        IndexerClient,
        IndexerError,
        TransientHTTPError,
    )
    from agentropix_mcp.wazuh.seal import CourtroomSeal, generate_session_key

    if run_id is None:
        run_id = str(uuid.uuid4())[:8]

    if operator is None:
        try:
            operator = os.getlogin()
        except OSError:
            operator = os.environ.get("USER", "agentropix-mcp")

    target_index = index or _default_findings_index_for_today()
    session_key = generate_session_key(config.audit_log)
    seal_helper = CourtroomSeal(session_key)

    # Empty short-circuit — no network, no audit (parity with push_iocs
    # nothing-to-push path).
    if not findings:
        return WazuhFindingsIndexResult(
            indexed_count=0,
            indexed_failed_count=0,
            batch_count=0,
            index_template_installed_this_run=False,
            index=target_index,
            dry_run=dry_run,
            run_id=run_id,
            outcome=WazuhFindingsIndexResult.OUTCOME_NOTHING_INDEXED,
        )

    sealed_docs = [
        _seal_finding_doc(
            seal_helper,
            finding=f,
            operator=operator,
            case_id=case_id,
            run_id=run_id,
            evidence_token=evidence_token,
            index=target_index,
        )
        for f in findings
    ]

    if dry_run:
        # Dry-run still seals every doc so the operator can inspect the
        # would-be-indexed shape; matches push_iocs dry_run semantics
        # (compute the payload, never write).
        return WazuhFindingsIndexResult(
            indexed_count=0,
            indexed_failed_count=0,
            batch_count=0,
            index_template_installed_this_run=False,
            index=target_index,
            dry_run=True,
            run_id=run_id,
            outcome=WazuhFindingsIndexResult.OUTCOME_DRY_RUN,
        )

    owns_client = indexer_client is None
    if indexer_client is None:
        # SIFT-W-296 fix: read config.indexer_tls_verify (the indexer
        # flag) not config.tls_verify (the manager flag). Same pattern
        # as PR #158 / SIFT-W-274 — orchestrator was the lone outlier
        # the W-274 sweep missed. Memory:
        # `lesson_wazuh_indexer_tls_flag_decoupled`.
        indexer_client = IndexerClient(
            indexer_url=config.indexer_url,
            indexer_user=config.indexer_user,
            indexer_password=config.indexer_password,
            tls_verify=getattr(config, "indexer_tls_verify", True),
            tls_ca_bundle=getattr(config, "tls_ca_bundle", None),
        )

    indexed_count = 0
    indexed_failed_count = 0
    batch_count = 0
    template_installed_this_run = False
    ism_installed_this_run = False
    try:
        # Idempotent template install — only PUT if this process hasn't
        # already done so for this (indexer_url, template_name) tuple.
        cache_key = (config.indexer_url, AGENTROPIX_FINDINGS_TEMPLATE_NAME)
        if not _FINDINGS_TEMPLATE_INSTALL_CACHE.get(cache_key):
            t0 = time.time()
            try:
                template_resp = await indexer_client.put_index_template(
                    AGENTROPIX_FINDINGS_TEMPLATE_NAME,
                    AGENTROPIX_FINDINGS_TEMPLATE,
                )
                _FINDINGS_TEMPLATE_INSTALL_CACHE[cache_key] = True
                template_installed_this_run = True
                _seal_and_audit_attempt(
                    audit_log=config.audit_log,
                    seal_helper=seal_helper,
                    operator=operator,
                    case_id=case_id,
                    run_id=run_id,
                    event="findings.template_install",
                    op="put.template",
                    endpoint=f"/_index_template/{AGENTROPIX_FINDINGS_TEMPLATE_NAME}",
                    evidence_token=evidence_token,
                    req_body=json.dumps(AGENTROPIX_FINDINGS_TEMPLATE, sort_keys=True).encode(
                        "utf-8"
                    ),
                    resp_body=json.dumps(template_resp).encode("utf-8"),
                    status=200,
                    latency_ms=(time.time() - t0) * 1000.0,
                    result="ok",
                )
            except (TransientHTTPError, IndexerError) as exc:
                # Template install failed — abort before any bulk_index
                # since the index would land without the locked mapping.
                logger.warning(
                    "findings.template_install failed: %s: %s",
                    type(exc).__name__,
                    exc,
                )
                _seal_and_audit_attempt(
                    audit_log=config.audit_log,
                    seal_helper=seal_helper,
                    operator=operator,
                    case_id=case_id,
                    run_id=run_id,
                    event="findings.template_install",
                    op="put.template",
                    endpoint=f"/_index_template/{AGENTROPIX_FINDINGS_TEMPLATE_NAME}",
                    evidence_token=evidence_token,
                    req_body=b"",
                    resp_body=b"",
                    status=0,
                    latency_ms=(time.time() - t0) * 1000.0,
                    result="indexer_outage",
                    error_class=type(exc).__name__,
                )
                return WazuhFindingsIndexResult(
                    indexed_count=0,
                    indexed_failed_count=len(sealed_docs),
                    batch_count=0,
                    index_template_installed_this_run=False,
                    ism_policy_installed_this_run=False,
                    index=target_index,
                    dry_run=False,
                    run_id=run_id,
                    outcome=WazuhFindingsIndexResult.OUTCOME_INDEXER_OUTAGE,
                    error={
                        "stage": "template_install",
                        "error_class": type(exc).__name__,
                        "details": str(exc)[:200],
                    },
                )

        # WZ-022 / W-277: ISM retention policy install (non-fatal).
        # Runs after the template install. Operational hygiene only --
        # a policy install failure does NOT abort the bulk_index loop
        # (data still lands; ISM is best-effort retention enforcement).
        from agentropix_mcp.wazuh.ism_policies import (
            AGENTROPIX_FINDINGS_ISM_POLICY_NAME,
            build_findings_ism_policy,
        )

        ism_cache_key = (
            config.indexer_url,
            AGENTROPIX_FINDINGS_ISM_POLICY_NAME,
        )
        if not _FINDINGS_ISM_INSTALL_CACHE.get(ism_cache_key):
            t0 = time.time()
            ism_body = build_findings_ism_policy()
            try:
                ism_resp = await indexer_client.put_ism_policy(
                    AGENTROPIX_FINDINGS_ISM_POLICY_NAME,
                    ism_body,
                )
                _FINDINGS_ISM_INSTALL_CACHE[ism_cache_key] = True
                ism_installed_this_run = True
                _seal_and_audit_attempt(
                    audit_log=config.audit_log,
                    seal_helper=seal_helper,
                    operator=operator,
                    case_id=case_id,
                    run_id=run_id,
                    event="findings.ism_install",
                    op="put.ism_policy",
                    endpoint=(f"/_plugins/_ism/policies/{AGENTROPIX_FINDINGS_ISM_POLICY_NAME}"),
                    evidence_token=evidence_token,
                    req_body=json.dumps(ism_body, sort_keys=True).encode("utf-8"),
                    resp_body=json.dumps(ism_resp).encode("utf-8"),
                    status=200,
                    latency_ms=(time.time() - t0) * 1000.0,
                    result="ok",
                )
            except (TransientHTTPError, IndexerError) as exc:
                # Non-fatal: log + sealed audit row, but do NOT abort.
                # The findings still land in the index; retention just
                # won't auto-prune until a future run re-installs.
                logger.warning(
                    "findings.ism_install failed (non-fatal): %s: %s",
                    type(exc).__name__,
                    exc,
                )
                _seal_and_audit_attempt(
                    audit_log=config.audit_log,
                    seal_helper=seal_helper,
                    operator=operator,
                    case_id=case_id,
                    run_id=run_id,
                    event="findings.ism_install",
                    op="put.ism_policy",
                    endpoint=(f"/_plugins/_ism/policies/{AGENTROPIX_FINDINGS_ISM_POLICY_NAME}"),
                    evidence_token=evidence_token,
                    req_body=b"",
                    resp_body=b"",
                    status=0,
                    latency_ms=(time.time() - t0) * 1000.0,
                    result="indexer_outage",
                    error_class=type(exc).__name__,
                )

        for start in range(0, len(sealed_docs), _FINDINGS_BULK_CHUNK_SIZE):
            batch = sealed_docs[start : start + _FINDINGS_BULK_CHUNK_SIZE]
            batch_count += 1
            t0 = time.time()
            try:
                resp = await indexer_client.bulk_index(target_index, batch)
            except (TransientHTTPError, IndexerError) as exc:
                logger.warning(
                    "findings.bulk_index batch %d failed: %s: %s",
                    batch_count,
                    type(exc).__name__,
                    exc,
                )
                _seal_and_audit_attempt(
                    audit_log=config.audit_log,
                    seal_helper=seal_helper,
                    operator=operator,
                    case_id=case_id,
                    run_id=run_id,
                    event="findings.bulk_index",
                    op="post.bulk",
                    endpoint="/_bulk",
                    evidence_token=evidence_token,
                    req_body=b"",
                    resp_body=b"",
                    status=0,
                    latency_ms=(time.time() - t0) * 1000.0,
                    result="indexer_outage",
                    extra={
                        "index": target_index,
                        "indexed_count": 0,
                        "indexed_failed_count": len(batch),
                        "batch_index": batch_count,
                        "batch_size": len(batch),
                        "index_template_installed_this_run": (template_installed_this_run),
                    },
                    error_class=type(exc).__name__,
                )
                indexed_failed_count += len(batch)
                return WazuhFindingsIndexResult(
                    indexed_count=indexed_count,
                    indexed_failed_count=(
                        indexed_failed_count + (len(sealed_docs) - start - len(batch))
                    ),
                    batch_count=batch_count,
                    index_template_installed_this_run=template_installed_this_run,
                    ism_policy_installed_this_run=ism_installed_this_run,
                    index=target_index,
                    dry_run=False,
                    run_id=run_id,
                    outcome=WazuhFindingsIndexResult.OUTCOME_INDEXER_OUTAGE,
                    error={
                        "stage": "bulk_index",
                        "batch_index": batch_count,
                        "error_class": type(exc).__name__,
                        "details": str(exc)[:200],
                    },
                )

            batch_failed = 0
            for item in resp.get("items", []):
                op = item.get("index") or {}
                if op.get("error"):
                    batch_failed += 1
            batch_ok = len(batch) - batch_failed
            indexed_count += batch_ok
            indexed_failed_count += batch_failed

            _seal_and_audit_attempt(
                audit_log=config.audit_log,
                seal_helper=seal_helper,
                operator=operator,
                case_id=case_id,
                run_id=run_id,
                event="findings.bulk_index",
                op="post.bulk",
                endpoint="/_bulk",
                evidence_token=evidence_token,
                req_body=json.dumps(resp, sort_keys=True).encode("utf-8"),
                resp_body=json.dumps(resp).encode("utf-8"),
                status=200,
                latency_ms=(time.time() - t0) * 1000.0,
                result="ok" if batch_failed == 0 else "partial",
                extra={
                    "index": target_index,
                    "indexed_count": batch_ok,
                    "indexed_failed_count": batch_failed,
                    "batch_index": batch_count,
                    "batch_size": len(batch),
                    "index_template_installed_this_run": (template_installed_this_run),
                },
            )
    finally:
        if owns_client:
            try:
                await indexer_client.aclose()
            except Exception as exc:
                logger.warning("IndexerClient close failed: %s", exc)

    if indexed_failed_count > 0 and indexed_count == 0:
        outcome = WazuhFindingsIndexResult.OUTCOME_INDEXER_OUTAGE
    elif indexed_failed_count > 0:
        outcome = WazuhFindingsIndexResult.OUTCOME_PARTIAL_INDEXED
    else:
        outcome = WazuhFindingsIndexResult.OUTCOME_INDEXED

    return WazuhFindingsIndexResult(
        indexed_count=indexed_count,
        indexed_failed_count=indexed_failed_count,
        batch_count=batch_count,
        index_template_installed_this_run=template_installed_this_run,
        ism_policy_installed_this_run=ism_installed_this_run,
        index=target_index,
        dry_run=False,
        run_id=run_id,
        outcome=outcome,
    )
