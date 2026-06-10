"""Pydantic v2 data models for the Wazuh IOC push integration.

Design source: ``01_design.md`` §§4.1-4.10 plus critic fixes:
  - Fix 4 (S-5): IPvAnyAddress via pydantic for IP validation; IPv6 IOCs
    rejected at model layer with clear ValueError.
  - Fix 6 (A-1): Discriminated-union IOCRecord approach — each IOC kind is
    a separate concrete class with a ``Literal`` discriminator field, making
    it impossible to construct e.g. a Tier-3 (Installer GUID) IOC after the
    model-layer validators run.
  - Fix 7 (Compliance): ADR references corrected — ADR-008, ADR-016, ADR-017.

The ``IOC`` and ``Tier`` names are aliases for backwards-compatibility with
``03_test.md`` test imports (design §15.1 flag 1).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

__all__ = [
    # Enums / types
    "IOCKind",
    "PriorityTier",
    "Confidence",
    "CDBListName",
    # Discriminated-union IOCRecord hierarchy
    "IPIOCRecord",
    "SHA256IOCRecord",
    "MD5IOCRecord",
    "ProcessIOCRecord",
    # Issue #60 / §4.2 #8: split process IOCs by Sysmon event field
    "ProcessImageIOCRecord",
    "ProcessModuleIOCRecord",
    # W-203: cross-host parent/child relation lifted from memory.process_tree
    "ProcessTreeEventIOCRecord",
    "RegistryIOCRecord",
    "IOCRecord",
    # WZ-019: provenance triple
    "IOCProvenance",
    "ProvenanceMissingError",
    # Aliases for test compat
    "IOC",
    "Tier",
    "Decision",
    # Container models
    "IOCInventory",
    "CDBPayload",
    "RulesXMLPayload",
    "PushResult",
    "PushAuditEvent",
]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class IOCKind(str):
    """String constants for IOC kind (used as discriminator field value)."""

    ip = "ip"
    hash_sha256 = "hash_sha256"
    hash_md5 = "hash_md5"
    process_name = "process_name"  # legacy, deprecated; use process_image / process_module
    # Issue #60 / master report §4.2 #8: split process_name into two
    # variants so rule 100203 (Sysmon EID 1, image=) and rule 100208
    # (Sysmon EID 7, imageloaded=) can match the right field.
    process_image = "process_image"
    process_module = "process_module"
    registry_key = "registry_key"
    # W-203: parent/child process-tree relation (memory.process_tree
    # Finding) lifted into MASTER-IOCS for cross-host aggregation.
    process_tree_event = "process_tree_event"


class PriorityTier(str):
    """Priority tier classification."""

    TIER1 = "tier1"
    TIER2 = "tier2"
    TIER3_EXCLUDED = "tier3_excluded"
    TIER4_SUGGEST = "tier4_suggest"


# Alias for test compat (03_test.md imports ``Tier``)
class Tier(str):
    TIER1 = "tier1"
    TIER2 = "tier2"
    EXCLUDED = "excluded"
    SUGGESTION = "suggestion"


class Confidence(str):
    high = "high"
    medium = "medium"
    low = "low"


class CDBListName(str):
    """The CDB list names in the agentropix_* namespace.

    Issue #60: ``suspect_process`` is the legacy unified namespace
    (kept for back-compat); new pushes use ``suspect_image`` (EID 1)
    and ``suspect_module`` (EID 7).
    """

    c2_ips = "agentropix_c2_ips"
    malware_sha256 = "agentropix_malware_sha256"
    malware_md5 = "agentropix_malware_md5"
    suspect_process = "agentropix_suspect_process"  # legacy / deprecated
    # Issue #60 / §4.2 #8: process IOC split.
    suspect_image = "agentropix_suspect_image"
    suspect_module = "agentropix_suspect_module"
    persistence_regkey = "agentropix_persistence_regkey"


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")

# WLV / §4.2 #7 entropy guard — minimum number of trailing hex zeros that
# triggers rejection. A real cryptographic hash effectively never has 16+
# consecutive zero hex chars (probability ~16^-16); when it does, the
# hash is almost certainly a stub / placeholder / truncated value, not
# real evidence. Master report cited example: f8d54...0000000000000000.
# Threshold of 16 is conservative — would only false-positive on an
# attacker who deliberately ground out a hash with that suffix
# (~10^19 hashes), which itself would be evidence of forgery.
_HASH_TRAILING_ZERO_REJECT_THRESHOLD = 16

# WLV / §4.2 #7: detect a hash that is a stub. Returns None on real-looking
# hashes; returns a reason string on stubs. Exposed at module scope so
# tests + future audit tooling can apply the same check off the IOC path.
def _hash_stub_reason(value: str) -> str | None:
    """Heuristic stub detector for hex hashes.

    Today catches the most common stub class: trailing zero-pad. Future
    extensions could include leading-zero checks, low Shannon entropy,
    or known-fixture hashes from public threat-intel databases.
    """
    # Trailing-zero check.
    suffix = value.rstrip("0")
    trailing_zeros = len(value) - len(suffix)
    if trailing_zeros >= _HASH_TRAILING_ZERO_REJECT_THRESHOLD:
        return (
            f"hash has {trailing_zeros} trailing zero hex chars "
            f"(threshold {_HASH_TRAILING_ZERO_REJECT_THRESHOLD}); "
            "this is almost certainly a stub / placeholder, not real "
            "evidence. Verify the hash is the full extracted value "
            "from the source artifact."
        )
    # Identical-byte-fill check (e.g. "ffff..." or "0000..." entire string).
    if len(set(value)) == 1:
        return (
            f"hash consists of a single repeated character {value[0]!r}; "
            "this is a stub / placeholder, not a real hash."
        )
    return None
_PROC_NAME = re.compile(r"^[a-z0-9._\-]{1,64}$")
_REGKEY_PREFIX = re.compile(r"^(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\")
_CASE_ID = re.compile(r"^[A-Z0-9][A-Z0-9_\-]{0,63}$")

# ---------------------------------------------------------------------------
# Base for all IOCRecord variants
# ---------------------------------------------------------------------------


class ProvenanceMissingError(ValueError):
    """Raised by orchestrator/publisher when an IOC lacks the WZ-019
    provenance triple AND the project has been configured to enforce
    provenance (AGENTROPIX_REQUIRE_IOC_PROVENANCE=1).

    Distinct from generic ValueError so audit-log filters can isolate
    provenance gaps from other validation failures.
    """


class IOCProvenance(BaseModel):
    """WZ-019 (master report §4.2 #11) — court-defensible provenance
    triple for every IOC entering the CDB.

    Without this metadata, an audit / courtroom challenge cannot
    resolve "where did SHA X come from?" — the load-bearing question
    for any DFIR finding. WZ-019 makes the schema first-class in the
    IOC model so missing-provenance is a Pydantic ValidationError at
    inventory-load time, NOT a silent gap discovered later.

    Fields are deliberately minimal: more elaborate provenance (chain
    of custody, evidence handler, etc.) lives at the case-level
    report.json HMAC envelope (M8.2a). The triple here is the
    minimum needed to re-derive the indicator from primary evidence.

    All five fields are REQUIRED. Optional fields belong on the
    record itself (e.g., ``filename_hint`` on SHA256), not here.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # SHA-256 of the source evidence file (e.g., the disk image, the
    # memory dump, the eml file the indicator was extracted from). Hex
    # lowercase, 64 chars.
    source_evidence_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    # The tool name that extracted the indicator (e.g., "volatility3",
    # "fls", "yara", "manual-review"). Free text capped at 64 chars
    # so we can keep distinguishing tools/wrappers without bloating
    # the audit row.
    extraction_tool: Annotated[str, Field(min_length=1, max_length=64)]

    # The argv (or canonical command line) used to run the tool.
    # Operators must redact secrets BEFORE storing — the schema does
    # not auto-redact. Capped at 1024 chars; longer commands should
    # reference an external script file by SHA-256 in this field.
    extraction_args: Annotated[str, Field(min_length=1, max_length=1024)]

    # ISO-8601 UTC timestamp of the extraction run. We deliberately
    # accept a string (not a datetime) so MASTER-IOCS.json round-trips
    # cleanly through json.dumps without timezone normalisation
    # surprises. Validator below enforces parseability + UTC.
    extraction_ts_utc: str

    # Analyst identifier — UNIX username, email local-part, or any
    # short opaque identifier the operator uses for chain-of-custody.
    # Required even for automated runs (use "automation" or the
    # service account's name).
    analyst: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("extraction_ts_utc")
    @classmethod
    def _validate_ts(cls, v: str) -> str:
        """Reject strings that don't parse as ISO-8601 UTC."""
        try:
            parsed = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"extraction_ts_utc {v!r} is not ISO-8601 parseable: {exc}"
            ) from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError(
                "extraction_ts_utc must include timezone (Z or +00:00); "
                f"got {v!r}"
            )
        # Normalise non-UTC offsets to UTC equivalent on the way out
        # so downstream readers don't have to re-normalise. Keeps the
        # canonical string form stable for HMAC envelope hashing.
        if parsed.utcoffset().total_seconds() != 0:
            return parsed.astimezone(UTC).isoformat()
        return v


class _IOCBase(BaseModel):
    """Common fields for all IOC variants."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: Annotated[str, Field(pattern=r"^[A-Z0-9][A-Z0-9_\-]{0,63}$")]
    confidence: Literal["high", "medium", "low"] = "medium"
    mitre: str | None = Field(default=None, pattern=r"^T\d{4}(\.\d{3})?$")
    port: int | None = Field(default=None, ge=1, le=65535)
    connection_state: str | None = Field(
        default=None,
        pattern=(
            r"^(ESTABLISHED|CLOSE_WAIT|CLOSED|LISTEN|SYN_SENT|SYN_RECV"
            r"|TIME_WAIT|FIN_WAIT1|FIN_WAIT2|LAST_ACK|CLOSING)$"
        ),
    )
    source_path: str | None = Field(default=None, max_length=1024)
    host_count: int = Field(default=1, ge=1)
    filename_hint: str | None = Field(default=None, max_length=255)
    persistence_type: str | None = Field(default=None, max_length=64)
    # context field for test compat (03_test.md uses context= kwarg)
    context: str | None = Field(default=None, max_length=256)
    # WZ-019: court-defensible provenance triple. Optional at the
    # model layer for back-compat with existing case data; the
    # orchestrator's enforcement gate (AGENTROPIX_REQUIRE_IOC_PROVENANCE=1)
    # raises ProvenanceMissingError on push when this is None and the
    # gate is on. New corpora SHOULD always populate this; the env
    # gate exists so back-loading WZ-018 corpus data isn't blocked
    # before its provenance is captured retroactively.
    provenance: IOCProvenance | None = None


# ---------------------------------------------------------------------------
# Discriminated-union leaf classes (Fix 6 / A-1)
# ---------------------------------------------------------------------------

# Hard-exclusion constants (Tier 3)
_INSTALLER_GUID_MD5 = "54377da4ea8d4e044bc107e65cf16ef3"
_F_RESPONSE_BASENAME = "subject_srv.exe"
_PROTECTED_PREFIXES = ("subject_srv",)  # catches .bak, .tmp variants


class IPIOCRecord(_IOCBase):
    """IPv4-only IOC (Fix 4: S-5 — IPv6 deferred to Step 2)."""

    kind: Literal["ip"] = "ip"
    value: Annotated[str, Field(min_length=7, max_length=45)]

    @model_validator(mode="after")
    def _validate_ip(self) -> IPIOCRecord:
        v = self.value.strip()
        object.__setattr__(self, "value", v)
        try:
            addr = ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"invalid IP address {v!r}") from exc

        # Fix 4 (S-5): reject IPv6 at model layer
        if isinstance(addr, ipaddress.IPv6Address):
            raise ValueError("IPv6 IOC keys deferred to Step 2; use dotted-quad IPv4 for Step 1")

        # Reject loopback, link-local, multicast, unspecified
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            raise ValueError(
                f"IP {v!r} is loopback/link-local/multicast/unspecified; "
                "these are Tier-3 excluded (self-block prevention)"
            )
        return self


class SHA256IOCRecord(_IOCBase):
    """SHA-256 hash IOC (Tier 1).

    WLV / §4.2 #7: stub-hash entropy guard rejects values with ≥16
    trailing zero hex chars or single-char fills. The cluster's
    99e125b3193f4e13...0000... entry that landed in
    Reports_results/WAZUH-DRY-RUN-SRL2018/MASTER-IOCS.json on the
    push that produced T-LIVE was such a stub; this validator
    structurally prevents recurrence.
    """

    kind: Literal["hash_sha256"] = "hash_sha256"
    value: Annotated[str, Field(min_length=64, max_length=64)]

    @field_validator("value")
    @classmethod
    def _normalize(cls, v: str) -> str:
        v = v.strip().lower()
        if not _HEX64.match(v):
            raise ValueError("sha256 must be 64 lowercase hex chars")
        # WLV / §4.2 #7 entropy guard.
        stub_reason = _hash_stub_reason(v)
        if stub_reason is not None:
            raise ValueError(f"sha256 stub rejected: {stub_reason}")
        return v


class MD5IOCRecord(_IOCBase):
    """MD5 hash IOC (Tier 2).

    Fix 6 (A-1): the Windows Installer GUID MD5 is impossible to construct —
    the validator raises at model creation time.

    WLV / §4.2 #7: stub-hash entropy guard rejects MD5 values with ≥16
    trailing zero hex chars or single-char fills. The cluster's
    f8d546807e667ad40000000000000000 entry was such a stub; this
    validator prevents recurrence at model-construction time.
    """

    kind: Literal["hash_md5"] = "hash_md5"
    value: Annotated[str, Field(min_length=32, max_length=32)]

    @field_validator("value")
    @classmethod
    def _normalize_and_check(cls, v: str) -> str:
        v = v.strip().lower()
        if not _HEX32.match(v):
            raise ValueError("md5 must be 32 lowercase hex chars")
        # Hard exclusion: Windows Installer GUID (Tier 3 / Gap A4)
        if v == _INSTALLER_GUID_MD5:
            raise ValueError(
                f"MD5 {v!r} is the Windows Installer Component GUID (Gap A4); "
                "this is a known false-positive and must never be pushed as an IOC"
            )
        # WLV / §4.2 #7 entropy guard.
        stub_reason = _hash_stub_reason(v)
        if stub_reason is not None:
            raise ValueError(f"md5 stub rejected: {stub_reason}")
        return v


class ProcessIOCRecord(_IOCBase):
    """Process name IOC (Tier 2).

    Fix 6 (A-1): F-Response subject_srv.exe is impossible to construct —
    the validator raises at model creation time, including .bak/.tmp variants.
    """

    kind: Literal["process_name"] = "process_name"
    value: Annotated[str, Field(min_length=1, max_length=64)]

    @field_validator("value")
    @classmethod
    def _normalize_and_check(cls, v: str) -> str:
        # Plan v1.1 §3.3: normalise via _normalise_process before pattern check
        # so case variants / path prefixes / separators / trailing dots all
        # collapse to the canonical form before the F-Response regex runs.
        from agentropix_mcp.wazuh.denylists import (
            _normalise_process,
            is_f_response_benign,
        )

        normalised = _normalise_process(v)
        if not _PROC_NAME.match(normalised):
            raise ValueError(f"process name {v!r} must match pattern [a-z0-9._-]{{1,64}}")
        # Hard exclusion: F-Response DFIR agent (Gap A5) — regex covers
        # subject_srv / subjectsrv / subject-srv / .ex / .exe / etc.
        if is_f_response_benign(normalised):
            raise ValueError(
                f"process name {v!r} matches F-Response DFIR agent exclusion (Gap A5); "
                "this is a known benign tool and must never be pushed as an IOC"
            )
        # Defence-in-depth: legacy basename-prefix check (back-compat)
        basename = normalised.split(".")[0] if "." in normalised else normalised
        if basename in _PROTECTED_PREFIXES or normalised == _F_RESPONSE_BASENAME:
            raise ValueError(
                f"process name {v!r} matches F-Response DFIR agent exclusion (Gap A5); "
                "this is a known benign tool and must never be pushed as an IOC"
            )
        return normalised


# ---------------------------------------------------------------------------
# Issue #60 / master report §4.2 #8: process IOC split
# ---------------------------------------------------------------------------
# Background: rule 100203 looks up `data.win.eventdata.image` against
# the `agentropix_suspect_process` CDB list. But Sysmon's `image` field
# on EID 1 (process create) is the process binary path; DLLs surface on
# EID 7 (image load) with field `imageloaded`. Pushing a DLL into
# `agentropix_suspect_process` cannot match a real Sysmon EID 1 event
# (master report §3.2 #2 / C2-DFIR Finding 5).
#
# Split rationale:
#   - ProcessImageIOCRecord (kind=process_image): EXE / process-binary
#     paths. Pushed to agentropix_suspect_image. Rule 100203 matches
#     against Sysmon EID 1.
#   - ProcessModuleIOCRecord (kind=process_module): DLL / module paths.
#     Pushed to agentropix_suspect_module. New rule 100208 matches
#     against Sysmon EID 7.
#
# Both reuse ProcessIOCRecord's normalize-and-check validator (F-Response
# exclusion, _PROC_NAME pattern, basename-prefix guard) via inheritance.
# The kind discriminator is the only field that differs structurally.
#
# Migration: the legacy `ProcessIOCRecord` (kind=process_name) stays
# for back-compat with any existing MASTER-IOCS.json that still uses
# the unified kind. inventory._safe_make_process auto-routes by file
# extension (.dll → module, otherwise image). Operators may explicitly
# set `kind: "process_image"` or `"process_module"` in MASTER-IOCS.json
# to bypass the auto-routing.


class ProcessImageIOCRecord(ProcessIOCRecord):
    """Process IOC for executable images (Sysmon EID 1, field=image).

    Issue #60: split from ProcessIOCRecord. Same validators as the
    legacy class; only the discriminator differs so the orchestrator's
    _KIND_TO_LIST routes this kind to ``agentropix_suspect_image``.
    """

    kind: Literal["process_image"] = "process_image"  # type: ignore[assignment]


class ProcessModuleIOCRecord(ProcessIOCRecord):
    """Process IOC for loaded modules / DLLs (Sysmon EID 7, field=imageloaded).

    Issue #60: split from ProcessIOCRecord. Same validators as the
    legacy class; only the discriminator differs so the orchestrator's
    _KIND_TO_LIST routes this kind to ``agentropix_suspect_module``.
    """

    kind: Literal["process_module"] = "process_module"  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# W-203: process_tree_event (cross-host parent/child relation)
# ---------------------------------------------------------------------------


class ProcessTreeEventIOCRecord(_IOCBase):
    """Process-tree relation lifted from memory.process_tree Findings.

    Distinct from process_image / process_module: those name a binary
    path. ProcessTreeEvent names the *(host, pid, parent_pid, name)*
    tuple so cross-host pivots can correlate orphan / suspicious
    parent-child anomalies. See DESIGNS/W-203-design.md §2.1.

    Fields are wide so the discriminated union accepts the rows the
    aggregator emits. ``value`` is unused for routing -- the
    aggregator does not produce a per-row value string; the row is
    looked up by the four-tuple.
    """

    kind: Literal["process_tree_event"] = "process_tree_event"  # type: ignore[assignment]
    # Override base confidence band to accept the float scalar the
    # memory.process_tree emitter writes (0.75 orphan / 0.80 suspicious).
    # Legacy string bands remain accepted so cross-loader paths do not
    # break when a downstream consumer feeds back a string-banded row.
    confidence: float | Literal["high", "medium", "low"] = 0.75  # type: ignore[assignment]
    value: str | None = Field(default=None, max_length=512)
    host: Annotated[str, Field(min_length=1, max_length=255)]
    pid: Annotated[int, Field(ge=0, le=4_294_967_295)]
    parent_pid: Annotated[int, Field(ge=0, le=4_294_967_295)]
    name: Annotated[str, Field(min_length=1, max_length=255)]
    image_path_normalized: str | None = Field(default=None, max_length=1024)
    image_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    image_hash_source: str | None = Field(default=None, max_length=32)
    command_line_redacted: str | None = Field(default=None, max_length=4096)
    command_line_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    first_seen_utc: str | None = Field(default=None, max_length=64)
    source_artifact: str | None = Field(default=None, max_length=1024)
    source_finding_index: int | None = Field(default=None, ge=0)
    evidence_kind: Literal["orphan", "suspicious"] | None = None
    evidence_reason: str | None = Field(default=None, max_length=1024)
    threads: int | None = Field(default=None, ge=0)
    wow64: bool | None = None
    redacted: bool = False
    redactor_version: str = Field(default="1", max_length=32)


class RegistryIOCRecord(_IOCBase):
    """Registry key IOC (Tier 2)."""

    kind: Literal["registry_key"] = "registry_key"
    value: Annotated[str, Field(min_length=5, max_length=512)]

    @field_validator("value")
    @classmethod
    def _validate_regkey(cls, v: str) -> str:
        v = v.strip()
        if not _REGKEY_PREFIX.match(v):
            raise ValueError("registry key must start with HKEY_*/HKLM/HKCU/HKCR/HKU followed by a backslash")
        if any(c in v for c in ("\x00", "\n", "\r")):
            raise ValueError("registry key must not contain null/newline/CR bytes")
        return v


# ---------------------------------------------------------------------------
# Union type (discriminator on ``kind`` field)
# ---------------------------------------------------------------------------

IOCRecord = (
    IPIOCRecord
    | SHA256IOCRecord
    | MD5IOCRecord
    | ProcessIOCRecord
    | ProcessTreeEventIOCRecord
    | RegistryIOCRecord
)

# Alias for test compat
IOC = IOCRecord


# ---------------------------------------------------------------------------
# Decision (output of PriorityClassifier)
# ---------------------------------------------------------------------------


class Decision(BaseModel):
    """Output of ``prioritise.PriorityClassifier.classify``."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    tier: str  # PriorityTier / Tier string value
    reason: str


# ---------------------------------------------------------------------------
# IOCInventory
# ---------------------------------------------------------------------------


class IOCInventory(BaseModel):
    """Typed bag of IOCRecords produced by the case loader."""

    model_config = ConfigDict(frozen=False, extra="forbid")
    case_id: Annotated[str, Field(pattern=r"^[A-Z0-9][A-Z0-9_\-]{0,63}$")]
    case_dir: str = ""
    records: list[
        Annotated[
            IPIOCRecord
            | SHA256IOCRecord
            | MD5IOCRecord
            | ProcessIOCRecord
            | ProcessTreeEventIOCRecord
            | RegistryIOCRecord,
            Field(discriminator="kind"),
        ]
    ] = Field(default_factory=list)
    # items alias for test compat
    items: tuple[
        IPIOCRecord
        | SHA256IOCRecord
        | MD5IOCRecord
        | ProcessIOCRecord
        | ProcessTreeEventIOCRecord
        | RegistryIOCRecord,
        ...,
    ] = Field(default_factory=tuple)
    loaded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def by_kind(self, kind: str) -> list:
        return [r for r in self.records if r.kind == kind]


# ---------------------------------------------------------------------------
# CDBPayload
# ---------------------------------------------------------------------------


class CDBPayload(BaseModel):
    """One generated CDB list payload ready for PUT to Wazuh.

    Fix 4 (S-5): CDB value format uses pipe separator:
    ``key:case_id|confidence|context\n``
    """

    model_config = ConfigDict(frozen=True, extra="forbid")
    list_name: str  # one of CDBListName.*
    body: bytes
    line_count: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _check_hash(self) -> CDBPayload:
        actual = hashlib.sha256(self.body).hexdigest()
        if actual != self.sha256:
            raise ValueError(f"CDBPayload sha256 mismatch: declared={self.sha256} actual={actual}")
        return self

    @field_validator("body")
    @classmethod
    def _no_null_and_size_check(cls, v: bytes) -> bytes:
        if b"\x00" in v:
            raise ValueError("CDB body must not contain null bytes")
        if len(v) > 10 * 1024 * 1024:
            raise ValueError("CDB body exceeds Wazuh 10 MB max_upload_size limit")
        return v


# ---------------------------------------------------------------------------
# RulesXMLPayload
# ---------------------------------------------------------------------------


class RulesXMLPayload(BaseModel):
    """One generated Wazuh custom rules XML pack payload."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    filename: Annotated[str, Field(pattern=r"^agentropix_[a-z0-9_]+_rules\.xml$")]
    body: bytes
    rule_ids: tuple[int, ...]
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("rule_ids")
    @classmethod
    def _check_id_range(cls, v: tuple[int, ...]) -> tuple[int, ...]:
        for rid in v:
            if not (100200 <= rid <= 100299):
                raise ValueError(f"rule id {rid} is outside the reserved range 100200-100299")
        return v


# ---------------------------------------------------------------------------
# PushResult
# ---------------------------------------------------------------------------


class PushResult(BaseModel):
    """Outcome of a single Wazuh write operation."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    op: Literal["put.list", "put.rules", "manager.restart"]
    target: str
    http_status: int
    seal: str = Field(pattern=r"^hmac-sha256:[0-9a-f]{64}$")
    latency_ms: int = Field(ge=0)
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    response_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    error: str | None = None
    dlq_id: str | None = None


# ---------------------------------------------------------------------------
# PushAuditEvent
# ---------------------------------------------------------------------------


class PushAuditEvent(BaseModel):
    """One structured audit-log event written to wazuh-audit.jsonl."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    ts: datetime
    event: Literal[
        "wazuh.put.list",
        "wazuh.put.rules",
        "wazuh.manager.restart",
        "wazuh.dlq.write",
        "wazuh.dryrun",
        "wazuh.disabled",
        "thymus.reject",
        "manual_rollback",
    ]
    case_id: str
    actor: str = "agentropix-mcp"
    operator: str | None = None
    op: Literal["put.list", "put.rules", "manager.restart", "dryrun"] | None = None
    endpoint: str | None = None
    list_name: str | None = None
    filename: str | None = None
    rule_ids: tuple[int, ...] | None = None
    http_status: int | None = None
    jwt_age_sec: int | None = None
    req_sha256: str | None = None
    resp_sha256: str | None = None
    seal: str | None = None
    evidence_token_id: str | None = None
    dry_run: bool = False
    latency_ms: int | None = None
    result: Literal["ok", "reject", "deferred", "error"]
    ioc_value_redacted: Literal["***REDACTED***"] | None = None
    dlq_id: str | None = None
    reason: str | None = None
