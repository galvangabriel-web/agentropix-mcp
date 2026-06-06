# Data Dictionary

> **Reference of record.** Exhaustive, field-by-field dictionary for every data model in the
> Agentropix-SIFT data contract. Each entry lists *name · type · required? · default · semantics /
> constraint · source file*. Where a wire alias differs from the Python attribute name, both are
> shown. Code wins over docs; numeric claims cite [`CANONICAL_FACTS.md`](../../.crew/facts.md).

Companion chapters: [data-models.md](data-models.md) (class diagrams + invariants),
[schema-er.md](schema-er.md) (entity relationships), [persisted-artifacts.md](persisted-artifacts.md)
(on-disk lifecycle).

The data contract has two faces:

1. **The wire schema** — `report.schema.json` (JSON Schema draft 2020-12), the contract every
   persisted `report.json` MUST satisfy.
2. **The Python models** — Pydantic `BaseModel`s, `NamedTuple`s, and frozen `@dataclass`es that the
   runtime builds and that serialise *into* the wire schema.

When the two disagree, the JSON Schema is the validation gate and the Pydantic model is the producer;
they are kept in lock-step (`TriageReport` validates against `report.schema.json` —
`src/agentropix_sift/orchestrator.py:34`).

---

## Contents — what's in this page (and what to expect)

> Jump to any model below. Each row tells you what that entry gives you, so you can go straight to the field set you need.

| Section | What you'll get |
|---|---|
| [1. `TriageReport` — the top-level report contract](#1-triagereport--the-top-level-report-contract) | The full top-level `report.json` field set — wire-required keys, seals, completion proofs, and the courtroom `inference_constraint`. |
| [2. `Finding` — the wire finding object](#2-finding--the-wire-finding-object) | Every field of a DFIR finding, the `_source` wire alias, typed `evidence_dict`, and the `to_report_dict()` serialiser rules. |
| [3. `Correlation` — cross-agent agreement on one token](#3-correlation--cross-agent-agreement-on-one-token) | The quorum correlation model (token, agreeing agents, counts, max confidence) and how the Blackboard produces it. |
| [4. `iterations[]` entry — per-iteration `TrinityResult` JSON](#4-iterations-entry--per-iteration-trinityresult-json) | The Reflexion-lite per-iteration record — plan, stable/dropped agents, gaps, Critic score, and the deterministic halt fields. |
| [5. `trace` — the tool-call trace](#5-trace--the-tool-call-trace) | The deterministic MCP audit: top-level trace keys plus each `tool_calls[]` record incl. `raw_output` and dataflow counters. |
| [6. `thymus_audit[]` entry](#6-thymus_audit-entry) | The Thymus read-only access-trail item shape (timestamp/action/path/reason) and where the durable JSONL trail lives. |
| [7. `ReasoningTrace` — Hippocampus memory trace](#7-reasoningtrace--hippocampus-memory-trace) | The opt-in per-iteration reasoning trace fields, the dedup `content_hash`, and its in-memory (non-durable) persistence note. |
| [8. `TokenRow` — evidence-gate mutation token](#8-tokenrow--evidence-gate-mutation-token) | The one-shot, TTL-bounded mutation-token registry row — mint/spend/revoke timestamps and operator identity. |
| [9. Approval-sidecar models](#9-approval-sidecar-models) | The HMAC human-in-the-loop request/response models (challenge, submit, error) plus the `ApprovalStatus`/`TargetType` aliases. |
| [10. Wazuh IOC record family](#10-wazuh-ioc-record-family) | First-class `IOCProvenance`, the nine IOC record classes, and the provenance-gate that blocks un-sourced IOCs. |
| [11. Tool-result schemas (`schema/` package)](#11-tool-result-schemas-schema-package) | The typed per-tool return models — `ArchiveEntry`/`ExtractArchiveManifest` and `PdfPage`/`PdfDocument` field-by-field. |
| [12. MCP tool envelope — `ToolError`](#12-mcp-tool-envelope--toolerror) | The uniform error envelope every tool returns instead of raising, keeping the trace well-formed. |
| [13. `ValidateReport` — provenance-chain validation result](#13-validatereport--provenance-chain-validation-result) | The seal-chain validation result dataclass used by the standalone verifiers to confirm a chain is untampered. |
| [Cross-references](#cross-references) | Links to the companion data chapters (models, ER, persisted artifacts) and the canonical facts file. |

---

## 1. `TriageReport` — the top-level report contract

The complete triage report. Pydantic `BaseModel` at `src/agentropix_sift/orchestrator.py:33`; its
serialised form validates against `src/agentropix_sift/schema/report.schema.json`.

Wire-required top-level keys (`report.schema.json:5`): `version`, `image`, `max_iterations`,
`iterations_completed`, `findings`, `status`, `trace`.

| Field | Type | Required | Default | Semantics / constraint | Source |
|-------|------|----------|---------|------------------------|--------|
| `version` | string | yes (wire) | `"0.2.0-dev"` | Report schema version. | `orchestrator.py:51`; `report.schema.json:7` |
| `image` | string | yes | — | Path to the evidence image triaged. | `orchestrator.py:52`; `report.schema.json:8` |
| `max_iterations` | integer ≥ 1 | yes | — | Trinity Loop iteration cap. | `orchestrator.py:53`; `report.schema.json:9` |
| `iterations_completed` | integer ≥ 0 | yes | `0` | Iterations actually run. | `orchestrator.py:54`; `report.schema.json:10` |
| `status` | string enum | yes | `"complete"` | One of `complete` \| `budget_exhausted` \| `error` \| `stub`. | `orchestrator.py:55`; `report.schema.json:11` |
| `findings` | array&lt;Finding wire dict&gt; | yes | `[]` | The findings published this run. See [§2](#2-finding--the-wire-finding-object). | `orchestrator.py:56`; `report.schema.json:30` |
| `trace` | object | yes | `{}` | Tool-call trace. Required sub-keys `tool_calls`, `start_time`, `end_time`. See [§5](#5-trace--the-tool-call-trace). | `orchestrator.py:57`; `report.schema.json:52` |
| `thymus_audit` | array&lt;object&gt; | no | `[]` | Thymus read-only access trail; items `{timestamp, action, path, reason}`. See [§6](#6-thymus_audit-entry). | `orchestrator.py:58`; `report.schema.json:90` |
| `critic_score` | number \| null, [0,1] | no | `None` | Final Critic blend score. | `orchestrator.py:59`; `report.schema.json:102` |
| `critic_feedback` | string \| null | no | `None` | Final Critic feedback text. | `orchestrator.py:60`; `report.schema.json:103` |
| `iterations` | array&lt;object&gt; | no | `[]` | Per-iteration `TrinityResult` JSON (Reflexion-lite, SIFT-W-045). See [§4](#4-iterations-entry--per-iteration-trinityresult-json). | `orchestrator.py:67`; `report.schema.json:104` |
| `inference_constraint` | string enum | no | `"high"` | Courtroom design declaration (M8.2 / ADR-016). `high` \| `medium` \| `low`. `high` = the LLM is orchestrator only; every fact originates from a named deterministic MCP tool captured in `trace.tool_calls`. | `orchestrator.py:69`; `report.schema.json:12` |
| `evidence_image_sha256` | string \| null | no | `None` | SHA-256 hex digest of the evidence image at session start; binds the report to the bytes triaged. Null when the image is unhashable (oversize, non-file, missing); operators may supply an offline digest via `AGENTROPIX_EVIDENCE_SHA256`. | `orchestrator.py:70`; `report.schema.json:17`; `courtroom.py:89` |
| `report_seal` | string \| null | no | `None` | HMAC-SHA256 hex digest over the canonicalised report JSON. Computed at write time by `cli.py`; verified by reading `<report>.session-key` (mode 0600). Null only on unsealed test fixtures. | `orchestrator.py:71`; `report.schema.json:21`; `courtroom.py:161` |
| `completion_proofs` | array&lt;string&gt; | no | `[]` | M8.3d verifiable completion-promise tokens (e.g. `TIMELINE_GENERATED`, `MEMORY_TRIAGED`). One token per agent that published ≥ 1 Finding this run. Sorted for diff-stability. | `orchestrator.py:79`; `report.schema.json:25` |
| `audit_log_seal` | string | no (added at seal time) | — | Cross-binding field: the audit-log's own HMAC seal, copied into the report dict so `report_seal` MACs over it. Injected by `write_sealed_session`, not a model field. | `courtroom.py:387` |

**Notes.**
- `version` defaults to `"0.2.0-dev"` on the Pydantic side but is wire-required, so every serialised
  report carries it.
- `status = "stub"` marks a placeholder report produced without a real swarm pass.
- `audit_log_seal` is the only top-level key not declared on the `TriageReport` model — it is added
  during sealing (see [persisted-artifacts.md §sealed-session](persisted-artifacts.md#the-sealed-session-cross-binding)).

---

## 2. `Finding` — the wire finding object

A schema-compliant DFIR finding. Pydantic `BaseModel` at `src/agentropix_sift/agents/_base.py:40`,
`model_config = ConfigDict(populate_by_name=True)`. The attribute `source` carries the wire alias
`_source`, so `Finding.model_dump(by_alias=True)` yields a dict that satisfies the schema's
`findings[]` item (`_base.py:51`). The leading-underscore name is a SANS convention — provenance
fields are "private" metadata about the finding rather than analyst-authored content (`_base.py:46`).

Wire-required keys (`report.schema.json:34`): `_source`, `confidence`, `description`.

| Python field (wire alias) | Type | Required | Default | Semantics / constraint | Source |
|---------------------------|------|----------|---------|------------------------|--------|
| `source` (`_source`) | str | yes | — | Tool/wrapper name that produced the finding. | `_base.py:51`; `report.schema.json:36` |
| `confidence` | float | yes | — | `ge=0.0, le=1.0`. Confidence score. | `_base.py:52`; `report.schema.json:37` |
| `description` | str | yes | — | Human-readable finding text. | `_base.py:53`; `report.schema.json:38` |
| `evidence` | str | no | `""` | Human-readable evidence string. | `_base.py:54`; `report.schema.json:39` |
| `evidence_dict` | dict[str, object] | no | `{}` | W-073 typed evidence container for cross-modal IOC fusion. Common keys: `ip`, `path`, `container_path`, `process`, `pid`, `ppid`, `hash_sha256`, `registry_key`, `registry_value`, `command_line` (`additionalProperties: true`). Memory-side wrappers populate it; disk-side wrappers migrate incrementally. Dropped from the wire when empty. | `_base.py:55`; `report.schema.json:40` |
| `timestamp` | str | no | `""` | ISO-8601 timestamp. | `_base.py:56`; `report.schema.json:45` |
| `mitre_attack` | str | no | `""` | MITRE ATT&CK technique id (e.g. `T1055.001`). | `_base.py:57`; `report.schema.json:46` |
| `related_findings` | list[str] | no | `[]` | Cross-references to other findings. | `_base.py:58`; `report.schema.json:47` |
| `file_sha256` | str | no | `""` | Issue #10/#11 — lowercase hex SHA-256 of the byte payload backing this finding (inode bytes for a T1105 staged binary, dumped VAD bytes for a malfind RWX hit). Dropped from the wire when blank. | `_base.py:64`; `report.schema.json:48` |
| `agent` | str | no | `""` | W-196 — the emitting `SwarmAgent.name`, stamped by `SwarmAgent.run()` before Blackboard publish. Enables per-agent recall (distinct from `source`, which names the *wrapper*). Dropped from the wire when blank. | `_base.py:71` |

**`to_report_dict()` (`_base.py:73`)** — the wire serialiser. It calls `model_dump(by_alias=True)`
and then drops `evidence_dict`, `file_sha256`, and `agent` when each is empty/blank, preserving wire
parity for legacy consumers and fixtures.

**`Finding.now()` (`_base.py:91`)** — static helper returning `datetime.now(UTC).isoformat()` for
stamping `timestamp`.

---

## 3. `Correlation` — cross-agent agreement on one token

Pydantic `BaseModel` at `src/agentropix_sift/agents/_blackboard.py:65`. Produced by
`Blackboard.correlations()` for every token appearing in ≥ `quorum_threshold` distinct agents'
evidence (default quorum 2 — [`CANONICAL_FACTS.md`](../../.crew/facts.md), `_blackboard.py:86`).

| Field | Type | Required | Semantics / constraint | Source |
|-------|------|----------|------------------------|--------|
| `token` | str | yes | The shared artifact token (filename, hash, IP, PID, URL fragment). | `_blackboard.py:68` |
| `agents` | list[str] | yes | Names of the agents that agree, sorted. | `_blackboard.py:69`, `:125` |
| `finding_count` | int | yes | Total findings across all agreeing agents backing the token. | `_blackboard.py:70`, `:126` |
| `max_confidence` | float | yes | Highest `confidence` among the backing findings. | `_blackboard.py:71`, `:127` |

The `Blackboard` itself is a class (not a model) — an asyncio-locked `list[tuple[str, Finding]]`
behind `self._lock`, with `quorum_threshold` defaulting to 2 (`_blackboard.py:86`) and validated
`>= 2` (`_blackboard.py:90`).
Correlation results are sorted `(-max_confidence, token)` for diff-stability (`_blackboard.py:130`).

---

## 4. `iterations[]` entry — per-iteration `TrinityResult` JSON

Each Trinity iteration appends one object to `report.iterations[]` (Reflexion-lite, SIFT-W-045). The
runtime object is the `TrinityResult` `NamedTuple` (`src/agentropix_sift/trinity/critic.py:47`); the
serialised entry is constrained by `report.schema.json:104`.

**Wire item** (required keys `iteration`, `plan`, `critic_score`, `should_halt` —
`report.schema.json:109`):

| Field | Type | Required | Semantics / constraint | Source |
|-------|------|----------|------------------------|--------|
| `iteration` | integer ≥ 1 | yes | Trinity iteration number. | `report.schema.json:111` |
| `plan` | array&lt;string&gt; | yes | The swarm slice (agent names) the Architect chose. | `report.schema.json:112` |
| `stable_agents` | array&lt;string&gt; | no | Agents whose published fingerprint was non-empty and unchanged from the prior Critic pass. | `report.schema.json:113`; `critic.py:59` |
| `dropped_agents` | array&lt;string&gt; | no | Agents the Architect dropped this iteration (drives the iter-1 vs iter-2 demo beat). Filled by the orchestrator after the Architect picks the next plan; the Critic leaves it empty. | `report.schema.json:114`; `critic.py:60` |
| `gaps` | array&lt;string&gt; | no | Canonical-SWARM coverage gaps — every `SwarmAgent` that produced zero findings this run. | `report.schema.json:115`; `critic.py:61` |
| `critic_score` | number, [0,1] | yes | The iteration's Critic blend score. | `report.schema.json:116` |
| `critic_feedback` | string | no | The iteration's Critic feedback. | `report.schema.json:117` |
| `should_halt` | boolean | yes | Deterministic halt decision for this iteration. | `report.schema.json:118` |

**`TrinityResult` runtime fields** (`critic.py:47`):

| Field | Type | Default | Semantics | Source |
|-------|------|---------|-----------|--------|
| `score` | float | — | Critic blend: `max finding confidence + 0.25·#correlations`, capped at 1.0 (`_CORRELATION_WEIGHT = 0.25`). | `critic.py:56`, `:44` |
| `feedback` | str | — | Critic feedback string. | `critic.py:57` |
| `should_halt` | bool | — | Halt when `score ≥ halt_threshold` (default 0.85, `AGENTROPIX_CRITIC_HALT_THRESHOLD`) OR the per-pass fingerprint reaches a fixed point — gated by `AGENTROPIX_CRITIC_MIN_ITERATIONS` (default 2) and a refusal to halt while any planned agent produced zero findings. **No LLM self-rating.** | `critic.py:58`, `:42`, `:43` |
| `stable_agents` | frozenset[str] | `frozenset()` | Reflexion-lite forward channel consumed by `Architect.plan()` next iteration. | `critic.py:59` |
| `dropped_agents` | tuple[str, ...] | `()` | Filled by the orchestrator after the Architect picks the next plan. | `critic.py:60` |
| `gaps` | frozenset[str] | `frozenset()` | Canonical-SWARM zero-finding agents. | `critic.py:61` |

---

## 5. `trace` — the tool-call trace

`report.trace` is the deterministic audit of every MCP tool invocation. Required keys `tool_calls`,
`start_time`, `end_time` (`report.schema.json:54`). Captured by `mcp_server/_trace.py`.

**`trace` top level:**

| Field | Type | Required | Semantics / constraint | Source |
|-------|------|----------|------------------------|--------|
| `tool_calls` | array&lt;object&gt; | yes | One record per tool invocation (see below). | `report.schema.json:56` |
| `counters` | object | no | W-060 persistence — structured dataflow counters keyed by tool name (e.g. `trace.timeline.counters → {jsonl_rows_read, priority_hits_by_family, …}`). Mirrors per-record counters but indexed for cheap lookup; survives wrapper timeouts. `additionalProperties: {type: object}`. | `report.schema.json:80` |
| `start_time` | string | yes | Session start (ISO-8601). | `report.schema.json:85` |
| `end_time` | string | yes | Session end (ISO-8601). | `report.schema.json:86` |
| `total_duration_ms` | number | no | Total wall-clock for the run. | `report.schema.json:87` |

**`trace.tool_calls[]` item** (required `tool`, `timestamp`, `duration_ms` — `report.schema.json:60`):

| Field | Type | Required | Semantics / constraint | Source |
|-------|------|----------|------------------------|--------|
| `tool` | string | yes | MCP tool name invoked. | `report.schema.json:62` |
| `timestamp` | string | yes | Invocation time (ISO-8601). | `report.schema.json:63` |
| `duration_ms` | number | yes | Tool wall-clock in ms. | `report.schema.json:64` |
| `result_summary` | string | no | Short summary of the result. | `report.schema.json:65` |
| `args_hash` | string | no | Hash of the call arguments (reproducibility anchor). | `report.schema.json:66` |
| `exit_code` | integer | no | Subprocess exit code. | `report.schema.json:67` |
| `raw_output` | string | no | M8.2c / ADR-016 — bounded snapshot of the tool return value **pre-LLM-summarisation** (default 4 KiB, tunable via `AGENTROPIX_TRACE_RAW_MAX_BYTES`). Lets a defense expert replay the deterministic step. Omitted when capture failed. | `report.schema.json:68` |
| `counters` | object | no | M6.4/W-060 per-record dataflow counters (e.g. `jsonl_rows_read`, `priority_hits_by_family`, `events_received_by_agent`, `detectors_fired_by_id`). `additionalProperties: true`. | `report.schema.json:72` |

---

## 6. `thymus_audit[]` entry

The Thymus read-only access trail copied into the report. Items are
`dict[str, str]` (`orchestrator.py:58`); each entry is built by `ThymusEvidencePolicy._log`
(`mcp_server/thymus_policy.py:371`).

| Field | Type | Required | Semantics | Source |
|-------|------|----------|-----------|--------|
| `timestamp` | string | no | ISO-8601 of the access decision. | `report.schema.json:95`; `mcp_server/thymus_policy.py:373` |
| `action` | string | no | `ALLOW` or a denial action. | `report.schema.json:96`; `mcp_server/thymus_policy.py:374` |
| `path` | string | no | The evidence path that was checked. | `report.schema.json:97`; `mcp_server/thymus_policy.py:375` |
| `reason` | string | no | Why the access was allowed/denied. | `report.schema.json:98`; `mcp_server/thymus_policy.py:376` |

The same entry is appended to an in-memory ring (`AGENTROPIX_THYMUS_AUDIT_LOG_RING_SIZE`, default
1000) and, when `AGENTROPIX_AUDIT_LOG` is set, written as a JSONL line to disk — the chain-of-custody
trail of record (`mcp_server/thymus_policy.py:382`). See
[persisted-artifacts.md §thymus-jsonl](persisted-artifacts.md#thymus-jsonl-audit-log).

---

## 7. `ReasoningTrace` — Hippocampus memory trace

Pydantic `BaseModel` at `src/agentropix_sift/memory/hippocampus_bridge.py:54`,
`model_config = {"extra": "forbid"}`. One per-iteration reasoning trace, opt-in via
`AGENTROPIX_HIPPOCAMPUS_ENABLED` (default off). Field shape is a strict subset of
`agentropix.memory.hippocampus.ReasoningTrace` for drop-in migration (`hippocampus_bridge.py:57`).

| Field | Type | Required | Default | Semantics / constraint | Source |
|-------|------|----------|---------|------------------------|--------|
| `trace_id` | str | no | `""` | Trace identifier. | `hippocampus_bridge.py:62` |
| `iteration` | int | no | `0` | Trinity iteration number. | `hippocampus_bridge.py:63` |
| `goal` | str | yes | — | The iteration goal (image + "triage" today). | `hippocampus_bridge.py:64` |
| `plan` | list[str] | no | `[]` | The swarm slice the Architect chose. | `hippocampus_bridge.py:65` |
| `result` | dict[str, Any] | no | `{}` | Per-agent finding counts + overall count. | `hippocampus_bridge.py:66` |
| `critique` | str | no | `""` | The Critic's score + feedback. | `hippocampus_bridge.py:67` |
| `fitness_score` | float | no | `0.0` | `ge=0.0, le=1.0`. | `hippocampus_bridge.py:68` |
| `created_at` | datetime | no | `now(UTC)` | Creation time. | `hippocampus_bridge.py:69` |
| `content_hash` (property) | str | derived | — | `SHA-256(f"{goal}:{iteration}:{','.join(plan)}")[:16]` for dedup. `iteration` is part of the hash so iter-2 of the same (goal, plan) is not deduped against iter-1. | `hippocampus_bridge.py:74`, `:85` |

> **Persistence note.** `HippocampusBridge` uses an **in-memory list** as its backing store
> (`hippocampus_bridge.py:108`); traces do **not** survive process exit on their own. The durable
> per-iteration record is `report.iterations[]` ([§4](#4-iterations-entry--per-iteration-trinityresult-json)).
> See [persisted-artifacts.md §hippocampus](persisted-artifacts.md#hippocampus-reasoning-traces).

---

## 8. `TokenRow` — evidence-gate mutation token

Frozen dataclass `@dataclass(frozen=True)` at `src/agentropix_sift/evidence_gate/registry.py:113`.
One row in the SQLite-backed mutation-token registry (`TokenRegistry`,
`AGENTROPIX_EVIDENCE_GATE_DB`). Tokens are one-shot, TTL-bounded mint/spend/revoke records.

| Field | Type | Required | Semantics / constraint | Source |
|-------|------|----------|------------------------|--------|
| `token_id` | str | yes | Token id, prefix `egt_…`. | `registry.py:115` |
| `scope` | str | yes | Authorised mutation scope. | `registry.py` |
| `created_ts` | float | yes | Mint time (epoch seconds). | `registry.py` |
| `ttl_seconds` | int | yes | Time-to-live. | `registry.py` |
| `spent_ts` | float \| None | no | When consumed (one-shot); `None` while unspent. | `registry.py` |
| `spent_run_id` | str \| None | no | Run id that spent it. | `registry.py` |
| `revoked_ts` | float \| None | no | Revocation time; `None` while valid. | `registry.py` |
| `operator` | str \| None | no | Minting operator identity. | `registry.py` |

---

## 9. Approval-sidecar models

Source: `src/agentropix_sift/approval_sidecar/models.py`. The HMAC human-in-the-loop service.

**Type aliases (`Literal`):**

| Alias | Values | Meaning |
|-------|--------|---------|
| `ApprovalStatus` | `DRAFT` \| `APPROVED` \| `REJECTED` \| `REVOKED` | Approval lifecycle state. |
| `TargetType` | `finding` \| `timeline` \| `approval` | What is being approved. `approval` = a compensating VOID/REVOKED retraction entry (append-only). |

### `ChallengeRequest` — POST `/challenge`

| Field | Type | Required | Constraint |
|-------|------|----------|-----------|
| `examiner_id` | str | yes | min 1, max 128 |
| `target_id` | str | yes | min 1, max 128 |
| `target_type` | `TargetType` | yes | enum |

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
| `target_type` | `TargetType` | yes | enum |
| `from_status` | `ApprovalStatus` | yes | enum |
| `to_status` | `ApprovalStatus` | yes | enum |
| `examiner_id` | str | yes | min 1, max 128 |
| `nonce` | str | yes | min 24 |
| `signature_hex` | str | yes | exactly 64 hex (HMAC) |
| `reason` | str | no (`""`) | max 4096 |

### `ApprovalSubmitResponse`

| Field | Type | Semantics |
|-------|------|-----------|
| `approval_id` | str | New approval id. |
| `indexed_to` | str | `agentropix-approvals-YYYY.MM.DD` index that took the doc. |
| `prev_approval_hash` | str | Hash-chain link; empty on the first approval for a target. |
| `approved_at` | str | ISO-8601. |

### `ErrorResponse`

| Field | Type | Semantics |
|-------|------|-----------|
| `error` | str | Human-readable message. |
| `code` | str | Machine token (`nonce_expired`, `bad_signature`, …). |

---

## 10. Wazuh IOC record family

Source: `src/agentropix_sift/wazuh/models.py`. Provenance is first-class (WZ-019).

### `IOCProvenance` (Pydantic `BaseModel`)

| Field | Type | Required | Constraint |
|-------|------|----------|-----------|
| `source_evidence_sha256` | str | yes | regex `^[0-9a-f]{64}$` |
| `extraction_tool` | str | yes | min 1, max 64 |
| `extraction_args` | str | yes | min 1, max 1024 |
| `extraction_ts_utc` | str | yes | ISO-8601 parseable (validator) |
| `analyst` | str | yes | min 1, max 128 |

When `AGENTROPIX_REQUIRE_IOC_PROVENANCE` is set, an IOC record built without `IOCProvenance` raises
`ProvenanceMissingError` (the exception type is defined at `wazuh/models.py:178`; the gate that
raises it fires in `wazuh/orchestrator.py:1269`, before any OpenSearch PUT).

### IOC record classes (all extend `_IOCBase`, carry an `IOCProvenance`)

| Class | Source line | IOC carried |
|-------|-------------|-------------|
| `_IOCBase` | `:261` | Common base — value, provenance, decision. |
| `IPIOCRecord` | `:303` | IP indicator. |
| `SHA256IOCRecord` | `:331` | SHA-256 hash indicator. |
| `MD5IOCRecord` | `:358` | MD5 hash indicator. |
| `ProcessIOCRecord` | `:392` | Process indicator. |
| `ProcessImageIOCRecord` | `:463` | Process image (extends `ProcessIOCRecord`). |
| `ProcessModuleIOCRecord` | `:474` | Loaded module (extends `ProcessIOCRecord`). |
| `ProcessTreeEventIOCRecord` | `:490` | Process-tree event. |
| `RegistryIOCRecord` | `:531` | Registry key/value indicator. |

Supporting string-enum helpers: `IOCKind`, `PriorityTier`, `Tier`, `Confidence`, `CDBListName`
(`:65`–`:106`). Aggregate types: `Decision` (`:570`), `IOCInventory` (`:583`), `CDBPayload` (`:621`).

---

## 11. Tool-result schemas (`schema/` package)

Typed Pydantic return models for individual MCP tools. New non-trivial schemas land in `schema/`;
legacy ones stay colocated in their wrapper module (`schema/__init__.py`).

### `ArchiveEntry` (`schema/extract_archive.py:15`)

One row of the `extract_archive` manifest — mirrors `ExtractedFile`.

| Field | Type | Required | Default | Semantics / constraint |
|-------|------|----------|---------|------------------------|
| `path` | str | yes | — | In-archive logical path (forward-slash, root-relative). Empty when the engine emits no knowable source name. |
| `dest` | str | no | `""` | On-host absolute path written to. Empty when rejected before any bytes were written (path-traversal, symlink-escape, per-file cap). |
| `size` | int | no | `0` | Bytes actually written to `dest`. |
| `sha256` | str | no | `""` | Hex SHA-256 over on-host file contents. Empty when `ok` is False or the entry is a directory/symlink deliberately not followed. |
| `ok` | bool | no | `True` | True when the entry landed and passed the post-extraction traversal/symlink re-check. |
| `error` | str | no | `""` | Reason string when `ok` is False. |

### `ExtractArchiveManifest` (`schema/extract_archive.py:45`)

Structured result of one `extract_archive` call.

| Field | Type | Required | Default | Semantics / constraint |
|-------|------|----------|---------|------------------------|
| `archive_path` | str | yes | — | Source archive path. |
| `dest` | str | yes | — | Canonical absolute path of the extraction destination. |
| `used_engine` | str | yes | — | Engine invoked — `"7z"` or `"tar"`. |
| `detected_format` | str | yes | — | Suffix-derived format (`.7z`, `.zip`, `.tar.gz`, …). |
| `entries` | list[`ArchiveEntry`] | no | `[]` | Per-entry manifest. |
| `total_files` | int | no | `0` | Count of `ok` entries (mirrors `ok_count`). |
| `total_bytes` | int | no | `0` | Sum of `size` over `ok` entries. |
| `error_count` | int | no | `0` | Count of `ok=False` entries (traversal/symlink/cap). |
| `truncated` | bool | no | `False` | True when halted by a bomb cap (`AGENTROPIX_ARCHIVE_MAX_BYTES`/`MAX_FILES`/`MAX_PER_FILE_BYTES`). |
| `tool` | str | no | `"extract_archive"` | Tool name. |
| `raw_stderr` | str | no | `""` | Engine stderr, capped at 1000 chars. |
| `raw_stdout_sha256` | str | no | `""` | SIFT-W-082 chain-of-custody — SHA-256 over the engine's `7z l -slt` pre-flight stdout (the deterministic step). |

### `PdfPage` (`schema/pdf_extract_text.py:17`)

One row of the per-page `pdf_extract_text` manifest.

| Field | Type | Required | Default | Semantics / constraint |
|-------|------|----------|---------|------------------------|
| `page` | int | yes | — | 1-indexed page number within the source document. |
| `ok` | bool | no | `True` | True when the page extracted cleanly; the batch continues on a per-page error. |
| `error` | str | no | `""` | Populated when `ok` is False. |
| `text` | str | no | `""` | Extracted plain text; may be truncated to `AGENTROPIX_PDF_MAX_CHARS`. |
| `char_count` | int | no | `0` | Byte-count of `text` after truncation. |
| `truncated` | bool | no | `False` | True when this page's text was clipped to `max_chars`. |

### `PdfDocument` (`schema/pdf_extract_text.py:42`)

Structured result of one `pdf_extract_text` call.

| Field | Type | Required | Default | Semantics / constraint |
|-------|------|----------|---------|------------------------|
| `target` | str | yes | — | Resolved absolute path of the source PDF. |
| `sha256` | str | no | `""` | SHA-256 of the raw PDF bytes — chain-of-custody anchor (W-082). |
| `page_count` | int | no | `0` | Total pages, per `pdfinfo`. |
| `title` | str | no | `""` | Document Title from `pdfinfo`. |
| `author` | str | no | `""` | Document Author from `pdfinfo`. |
| `created` | str | no | `""` | Raw `CreationDate` string from `pdfinfo` (free-form). |
| `pages` | list[`PdfPage`] | no | `[]` | Extracted pages in source order, restricted to the caller's selector and `max_pages`. |
| `skipped_pages` | list[int] | no | `[]` | Requested page numbers trimmed by the `max_pages` cap (cap-victim list for audit). |
| `engine` | str | no | `"pdftotext"` | Engine used (currently always `pdftotext`). |
| `engine_version` | str | no | `""` | First line of `pdftotext -v`. |
| `duration_ms` | float | no | `0.0` | Wall-clock in the wrapper, including all per-page subprocess calls. |
| `truncated` | bool | no | `False` | True when any page hit `max_chars` OR `skipped_pages` is non-empty. |
| `tool` | str | no | `"pdf_extract_text"` | Tool name. |
| `raw_stderr` | str | no | `""` | Concatenated `pdftotext` stderr, capped at 1000 chars. |
| `raw_stdout_sha256` | str | no | `""` | SHA-256 over `"\n\f".join(p.text for p in pages)` — cheap reproducibility check. |

> Many wrappers colocate their own return models (`YaraReport`, `EvtxReport`, `ExtractManifest`). When
> a wrapper's exact return shape is load-bearing for a chapter, read that wrapper directly — the tool
> catalogue's args are the canonical *input* contract.

---

## 12. MCP tool envelope — `ToolError`

Every one of the [71 MCP tools](../../.crew/tool-list.md) ([`CANONICAL_FACTS.md`](../../.crew/facts.md))
returns either its own typed success payload (a Pydantic model dump or dict — e.g. `PdfDocument`,
`ExtractArchiveManifest`) **or** a structured error. The error envelope is uniform:

### `ToolError` (`src/agentropix_sift/mcp_server/server.py:186`)

| Field | Type | Required | Default | Semantics |
|-------|------|----------|---------|-----------|
| `tool` | str | yes | — | The tool that produced the error. |
| `error` | str | yes | — | Human-readable error message. |
| `suggestion` | str | no | `""` | Optional remediation hint. |

A tool returns a `ToolError` for rate-limit rejections (`server.py:1048`) and caught exceptions
(`server.py:1053`) rather than raising, so the trace/report stays well-formed. See
[data-models.md §envelope](data-models.md#5-the-mcp-tool-envelope) for the success/error dichotomy.

---

## 13. `ValidateReport` — provenance-chain validation result

`@dataclass` at `src/agentropix_sift/provenance/validate.py:67`. The result of validating a
provenance/seal chain via `validate_dir(...)`. Carries the per-row HMAC verification outcomes
(`_verify_one_row`, `_row_canonical_sans_seal`), used to confirm a sealed chain has not been tampered.
Consumed by the standalone verifiers in `audit/verify_seal.py` and `provenance/validate.py:main()`.

---

## Cross-references

- Class diagrams and invariants: [data-models.md](data-models.md)
- Entity relationships (ER): [schema-er.md](schema-er.md)
- On-disk artifacts and lifecycle: [persisted-artifacts.md](persisted-artifacts.md)
- Canonical numbers: [`.crew/facts.md`](../../.crew/facts.md)
