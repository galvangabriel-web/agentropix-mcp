# Schema Dump (shared reference)

> Exhaustive enumeration of the Pydantic models, dataclasses, JSON Schemas, and `Literal` type
> aliases that define the Agentropix-SIFT data contract. Derived by reading the source. Code wins
> over docs. Field tables list **name · type · required? · semantics/constraint**.

Primary roots:
- `src/agentropix_sift/schema/` — typed result schemas + JSON Schemas
- `src/agentropix_sift/orchestrator.py` — `TriageReport` (Pydantic)
- `src/agentropix_sift/agents/_base.py` — `Finding`, `SwarmAgent`
- `src/agentropix_sift/agents/_blackboard.py` — `Correlation`, `Blackboard`
- `src/agentropix_sift/trinity/critic.py` — `TrinityResult`
- `src/agentropix_sift/memory/hippocampus_bridge.py` — `ReasoningTrace`
- `src/agentropix_sift/evidence_gate/registry.py` — `TokenRow`
- `src/agentropix_sift/approval_sidecar/models.py` — approval request/response models + type aliases
- `src/agentropix_sift/wazuh/models.py` — IOC record family + provenance
- `src/agentropix_sift/provenance/validate.py` — `ValidateReport`

---

## 1. Core report contract

### `report.schema.json` (JSON Schema, draft 2020-12)
Source: `src/agentropix_sift/schema/report.schema.json` — "Agentropix-SIFT Triage Report".
Required top-level: `version`, `image`, `max_iterations`, `iterations_completed`, `findings`, `status`, `trace`.

| Field | Type | Required | Semantics / constraint |
|-------|------|----------|------------------------|
| `version` | string | yes | Report schema version |
| `image` | string | yes | Path to evidence image triaged |
| `max_iterations` | integer ≥1 | yes | Trinity Loop iteration cap |
| `iterations_completed` | integer ≥0 | yes | Iterations actually run |
| `status` | string enum | yes | `complete` \| `budget_exhausted` \| `error` \| `stub` |
| `inference_constraint` | string enum | no | `high`\|`medium`\|`low`. M8.2/ADR-016 design declaration; `high` = LLM orchestrates only, every fact originates from a named deterministic MCP tool captured in `trace.tool_calls` |
| `evidence_image_sha256` | string\|null | no | SHA-256 of evidence image at session start; binds report to bytes. Null when unhashable (oversize/non-file/missing); operator may supply via `AGENTROPIX_EVIDENCE_SHA256` |
| `report_seal` | string\|null | no | HMAC-SHA256 over canonicalised report JSON. Computed by `cli.py`; verified against `<report>.session-key` (mode 0600). Null on unsealed test fixtures |
| `completion_proofs` | array<string> | no | M8.3d verifiable completion-promise tokens (e.g. `TIMELINE_GENERATED`); one per agent that published ≥1 Finding; sorted |
| `findings` | array<object> | yes | See **Finding (wire form)** below |
| `trace` | object | yes | Required keys `tool_calls`, `start_time`, `end_time`; see **trace** below |
| `thymus_audit` | array<object> | no | Items: `timestamp`, `action`, `path`, `reason` — Thymus read-only access trail |
| `critic_score` | number\|null [0,1] | no | Final Critic blend score |
| `critic_feedback` | string\|null | no | Final Critic feedback text |
| `iterations` | array<object> | no | Per-iteration TrinityResult JSON (Reflexion-lite, SIFT-W-045); items require `iteration`, `plan`, `critic_score`, `should_halt` |

**`findings[]` (wire form, required `_source`, `confidence`, `description`):**

| Field | Type | Required | Semantics / constraint |
|-------|------|----------|------------------------|
| `_source` | string | yes | Tool name that produced this finding |
| `confidence` | number [0,1] | yes | Confidence score |
| `description` | string | yes | Human-readable finding |
| `evidence` | string | no | Evidence string |
| `evidence_dict` | object (additionalProperties) | no | W-073 typed evidence container for cross-modal IOC fusion (ip, path, container_path, process, pid, ppid, hash_sha256, registry_key, registry_value, command_line) |
| `timestamp` | string | no | ISO-8601 |
| `mitre_attack` | string | no | MITRE ATT&CK technique id |
| `related_findings` | array<string> | no | Cross-refs |
| `file_sha256` | string | no | Lowercase hex SHA-256 of the byte payload behind the finding (issue #10/#11); omitted when none hashed |

**`trace`** — `tool_calls[]` each require `tool`, `timestamp`, `duration_ms`; optional `result_summary`,
`args_hash`, `exit_code`, `raw_output` (PRE-LLM-summarisation snapshot, default 4 KiB, tunable via
`AGENTROPIX_TRACE_RAW_MAX_BYTES`), `counters` (W-060 dataflow counters). `trace.counters` mirrors
per-record counters keyed by tool name; `start_time`/`end_time` required; `total_duration_ms` optional.

### `TriageReport` (Pydantic `BaseModel`)
Source: `src/agentropix_sift/orchestrator.py:33`. Validates against `report.schema.json`.

| Field | Type | Default | Semantics / constraint |
|-------|------|---------|------------------------|
| `version` | str | `"0.2.0-dev"` | Schema version |
| `image` | str | (required) | Evidence image path |
| `max_iterations` | int | (required) | Trinity cap |
| `iterations_completed` | int | `0` | Iterations run |
| `status` | str | `"complete"` | One of the schema enum values |
| `findings` | list[dict] | `[]` | Finding wire dicts |
| `trace` | dict | `{}` | Tool-call trace |
| `thymus_audit` | list[dict[str,str]] | `[]` | Thymus access trail |
| `critic_score` | float\|None | `None` | Final score |
| `critic_feedback` | str\|None | `None` | Final feedback |
| `iterations` | list[dict] | `[]` | Per-iteration TrinityResult JSON |
| `inference_constraint` | str | `"high"` | Courtroom invariant (ADR-016) |
| `evidence_image_sha256` | str\|None | `None` | Evidence binding hash |
| `report_seal` | str\|None | `None` | HMAC-SHA256 seal |
| `completion_proofs` | list[str] | `[]` | M8.3d promise tokens |

---

## 2. Finding & Blackboard

### `Finding` (Pydantic `BaseModel`)
Source: `src/agentropix_sift/agents/_base.py:40`. `model_config = populate_by_name`. `source` serialises
to `_source` so `model_dump(by_alias=True)` satisfies `report.schema.json`. `to_report_dict()` drops
empty `evidence_dict` / `file_sha256` / `agent` for wire compatibility.

| Field | Type | Required | Semantics / constraint |
|-------|------|----------|------------------------|
| `source` (alias `_source`) | str | yes | Wrapper/tool that produced the finding |
| `confidence` | float | yes | `ge=0.0, le=1.0` |
| `description` | str | yes | Finding text |
| `evidence` | str | no (`""`) | Human-readable evidence |
| `evidence_dict` | dict[str,object] | no (`{}`) | Typed evidence (W-073) |
| `timestamp` | str | no (`""`) | ISO-8601 |
| `mitre_attack` | str | no (`""`) | ATT&CK id |
| `related_findings` | list[str] | no (`[]`) | Cross-refs |
| `file_sha256` | str | no (`""`) | Lowercase hex SHA-256 of payload (issue #10) |
| `agent` | str | no (`""`) | Emitting `SwarmAgent.name`, stamped by `run()` (W-196); enables per-agent recall |

### `Correlation` (Pydantic `BaseModel`)
Source: `src/agentropix_sift/agents/_blackboard.py:65`. Cross-agent agreement on one artifact token.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `token` | str | yes | The shared artifact token |
| `agents` | list[str] | yes | Agents that agree (sorted) |
| `finding_count` | int | yes | Findings backing the token |
| `max_confidence` | float | yes | Highest confidence among them |

`Blackboard` (class, not a model) holds `(agent, Finding)` entries behind an asyncio lock; `quorum_threshold`
default 2 (must be ≥2); `correlations()` returns `Correlation` for tokens appearing in ≥quorum agents.

---

## 3. Trinity

### `TrinityResult` (`NamedTuple`)
Source: `src/agentropix_sift/trinity/critic.py:47`. What one Architect→Swarm→Critic iteration yields.

| Field | Type | Semantics |
|-------|------|-----------|
| `score` | float | Critic blend score (max confidence + 0.25·#correlations, capped at 1.0) |
| `feedback` | str | Critic feedback string |
| `should_halt` | bool | Deterministic halt decision (score ≥ threshold OR fixed-point fingerprint, gated by min-iterations and zero-finding guard) |

(Additional Reflexion-lite fields such as `stable_agents`/`dropped_agents`/`gaps` are surfaced into the
report's `iterations[]` entries — see `report.schema.json` `iterations` items.)

---

## 4. Memory / Hippocampus

### `ReasoningTrace` (Pydantic `BaseModel`)
Source: `src/agentropix_sift/memory/hippocampus_bridge.py:54`. `model_config = {"extra": "forbid"}`.
Field shape mirrors `agentropix.memory.hippocampus.ReasoningTrace` for drop-in migration.

| Field | Type | Default | Semantics |
|-------|------|---------|-----------|
| `trace_id` | str | `""` | Trace identifier |
| `iteration` | int | `0` | Trinity iteration number |
| `goal` | str | (required) | Iteration goal |
| `plan` | list[str] | `[]` | Planned steps |
| `result` | dict[str,Any] | `{}` | Iteration result |
| `critique` | str | `""` | Critic critique |
| `fitness_score` | float | `0.0` | `ge=0.0, le=1.0` |
| `created_at` | datetime | `now(UTC)` | Creation time |
| `content_hash` (property) | str | derived | SHA-256(goal:iteration:plan)[:16] for dedup |

---

## 5. Evidence gate (mutation tokens)

### `TokenRow` (`@dataclass(frozen=True)`)
Source: `src/agentropix_sift/evidence_gate/registry.py:113`. One row in the mutation-token registry.

| Field | Type | Semantics |
|-------|------|-----------|
| `token_id` | str | Token id (`egt_…`) |
| `scope` | str | Authorised mutation scope |
| `created_ts` | float | Mint time (epoch) |
| `ttl_seconds` | int | Time-to-live |
| `spent_ts` | float\|None | When consumed (one-shot) |
| `spent_run_id` | str\|None | Run that spent it |
| `revoked_ts` | float\|None | Revocation time |
| `operator` | str\|None | Minting operator |

`TokenRegistry` (class) is the SQLite-backed mint/spend/revoke store (`AGENTROPIX_EVIDENCE_GATE_DB`).

---

## 6. Approval sidecar (HMAC)

Source: `src/agentropix_sift/approval_sidecar/models.py`.

**Type aliases (`Literal`):**
- `ApprovalStatus = Literal["DRAFT", "APPROVED", "REJECTED", "REVOKED"]`
- `TargetType = Literal["finding", "timeline", "approval"]` (`approval` = compensating VOID/REVOKED retraction entry; append-only)

### `ChallengeRequest` — POST `/challenge`
| Field | Type | Required | Constraint |
|-------|------|----------|-----------|
| `examiner_id` | str | yes | min 1, max 128 |
| `target_id` | str | yes | min 1, max 128 |
| `target_type` | TargetType | yes | enum |

### `ChallengeResponse`
| Field | Type | Constraint |
|-------|------|-----------|
| `nonce` | str | min 24 |
| `salt_hex` | str | min 2 |
| `iterations` | int | ge 1 (PBKDF2 iterations) |
| `ttl_seconds` | float | gt 0 |

### `ApprovalSubmitRequest` — POST submit
| Field | Type | Required | Constraint |
|-------|------|----------|-----------|
| `case_id` | str | yes | min 1, max 128 |
| `target_id` | str | yes | min 1, max 128 |
| `target_type` | TargetType | yes | enum |
| `from_status` | ApprovalStatus | yes | enum |
| `to_status` | ApprovalStatus | yes | enum |
| `examiner_id` | str | yes | min 1, max 128 |
| `nonce` | str | yes | min 24 |
| `signature_hex` | str | yes | exactly 64 hex (HMAC) |
| `reason` | str | no (`""`) | max 4096 |

### `ApprovalSubmitResponse`
| Field | Type | Semantics |
|-------|------|-----------|
| `approval_id` | str | New approval id |
| `indexed_to` | str | `agentropix-approvals-YYYY.MM.DD` index that took the doc |
| `prev_approval_hash` | str | Hash-chain link; empty on first approval for a target |
| `approved_at` | str | ISO-8601 |

### `ErrorResponse`
| Field | Type | Semantics |
|-------|------|-----------|
| `error` | str | Human message |
| `code` | str | Machine token (`nonce_expired`, `bad_signature`, …) |

---

## 7. Wazuh IOC record family

Source: `src/agentropix_sift/wazuh/models.py`. Provenance is first-class (WZ-019).

### `IOCProvenance` (Pydantic `BaseModel`)
| Field | Type | Required | Constraint |
|-------|------|----------|-----------|
| `source_evidence_sha256` | str | yes | regex `^[0-9a-f]{64}$` |
| `extraction_tool` | str | yes | min 1, max 64 |
| `extraction_args` | str | yes | min 1, max 1024 |
| `extraction_ts_utc` | str | yes | ISO-8601 parseable (validator) |
| `analyst` | str | yes | min 1, max 128 |

### IOC record classes (all extend `_IOCBase`, carry `IOCProvenance`)
| Class | Source line | IOC carried |
|-------|-------------|-------------|
| `_IOCBase` | `:261` | Common base (value, provenance, decision) |
| `IPIOCRecord` | `:303` | IP indicator |
| `SHA256IOCRecord` | `:331` | SHA-256 hash indicator |
| `MD5IOCRecord` | `:358` | MD5 hash indicator |
| `ProcessIOCRecord` | `:392` | Process indicator |
| `ProcessImageIOCRecord` | `:463` | Process image (extends `ProcessIOCRecord`) |
| `ProcessModuleIOCRecord` | `:474` | Loaded module (extends `ProcessIOCRecord`) |
| `ProcessTreeEventIOCRecord` | `:490` | Process-tree event |
| `RegistryIOCRecord` | `:531` | Registry key/value indicator |

Supporting types: `IOCKind`, `PriorityTier`, `Tier`, `Confidence`, `CDBListName` (string-enum helpers,
`:65`–`:106`); `Decision` (`:570`), `IOCInventory` (`:583`), `CDBPayload` (`:621`),
`ProvenanceMissingError` (`:178`, raised when `AGENTROPIX_REQUIRE_IOC_PROVENANCE` is set and provenance absent).

---

## 8. Provenance validation

### `ValidateReport` (`@dataclass`)
Source: `src/agentropix_sift/provenance/validate.py:67`. Result of validating a provenance/seal chain
(`validate_dir(...)`). Carries the per-row HMAC verification outcomes (`_verify_one_row`,
`_row_canonical_sans_seal`). Used to confirm a sealed chain has not been tampered.

---

## 9. Tool-result schemas (`schema/` package)

| Model | Source | Key fields |
|-------|--------|-----------|
| `ArchiveEntry` | `schema/extract_archive.py:15` | `path`, `dest`, `size`, `ok`, `error` |
| `ExtractArchiveManifest` | `schema/extract_archive.py:45` | `archive_path`, `dest`, `used_engine`, `detected_format`, `entries: list[ArchiveEntry]`, `total_files`, `total_bytes`, `error_count`, `truncated`, `tool`, `raw_stderr` |
| `PdfPage` | `schema/pdf_extract_text.py:17` | `page`, `ok`, `error`, `text`, `char_count`, `truncated` |
| `PdfDocument` | `schema/pdf_extract_text.py:42` | `target`, `page_count`, `title`, `author`, `created`, `pages: list[PdfPage]`, `skipped_pages`, `engine`, `engine_version`, `duration_ms`, `truncated`, `tool`, `raw_stderr` |

`master_iocs.schema.json` (JSON Schema, `schema/master_iocs.schema.json`) defines the aggregated
`MASTER-IOCS.json` envelope produced by `wrappers/master_iocs_aggregator.py`.

> Many wrappers colocate their own typed return models (e.g. `ExtractManifest`, `YaraReport`,
> `EvtxReport`). New non-trivial schemas land in `schema/`; legacy ones stay in their wrapper module
> (see `schema/__init__.py` docstring). When a wrapper's exact return shape is load-bearing for a
> chapter, read that wrapper directly — the catalogue's args are the canonical *input* contract.
