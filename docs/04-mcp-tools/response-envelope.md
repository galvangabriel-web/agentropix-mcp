# Tool Response Envelope

> **What a tool call actually returns.** Every one of the [72 MCP tools](tool-reference.md) returns a
> **typed Pydantic model** — not a free-form dict — and that model is serialized to the wire with
> `result.model_dump()` at the FastMCP boundary (`fastmcp_app.py:382-385`). There is no single global
> envelope class wrapping all tools; instead a recurring set of cross-cutting fields appears across the
> per-tool report models. This page documents that recurring shape from the code, with a realistic JSON
> example and a field table, and is precise about which conceptual fields exist and which do not.

Related: [Tool reference](tool-reference.md) · [Schema reference](../03-data/schema-er.md) ·
[Safety spine](../05-safety-forensics/anti-hallucination.md).

---

## Contents — what's in this page (and what to expect)

> Jump to any section below. Each row tells you what that part gives you, so you can go straight to your point.

| Section | What you'll get |
|---|---|
| [The shape, derived from code](#the-shape-derived-from-code) | The two return models (per-tool report vs `ToolError`), the outer discriminator, and the recurring cross-cutting field tables for forensic wrappers and case/reporting results. |
| [Realistic JSON example](#realistic-json-example) | Worked wire examples: a `get_pslist` success, a W-135 soft failure, a `ToolError`, and a `record_finding` mutation result. |
| [The `safe_tool` flat error envelope](#the-safe_tool-flat-error-envelope) | The second error contract used by Wazuh tools — `ToolErrorEnvelope`'s flat `{error, details}` shape, stable error categories, message truncation, and how it differs from `ToolError`. |
| [Mapping the conceptual envelope to the real fields](#mapping-the-conceptual-envelope-to-the-real-fields) | A table mapping the idealized envelope names (`success`, `data`, `caveats`, …) to the real fields the code returns, plus the hard authoring rule. |
| [Availability & skip signalling](#availability--skip-signalling) | How `tool_available=False` + `skipped_reason` make missing-binary/wrong-input cases deterministic, replayable signalled skips instead of crashes. |
| [Mutation & approval gating](#mutation--approval-gating) | How state-mutating tools enforce one-shot `mutation_token`s, default to dry-run, stage findings as DRAFT only, and report `indexed`/`indexed_to`. |
| [The report that aggregates all tool calls](#the-report-that-aggregates-all-tool-calls) | How individual envelopes roll up into the Triage Report with `trace.tool_calls[]` and the court-defensible invariants. |

---

## The shape, derived from code

Each FastMCP route awaits an inner `mcp_*` coroutine and returns its `.model_dump()`
(`fastmcp_app.py:382-385`, `414-436`). The inner function returns **one of two** Pydantic models:

1. A **per-tool success report** — e.g. `PsList`, `FlsReport`, `EvtxReport`, `RecordFindingResult`,
   `CaseStatusReport`. These carry the tool's data *plus* the recurring cross-cutting fields below.
2. A **`ToolError`** — the structured error model, returned (not raised) on a handled failure such as a
   rate-limit hit or a validation error (`mcp_server/server.py:186`).

> **Definitions used on this page.** *Envelope* = the JSON object a single tool call returns over the
> wire (one tool call ⇒ one envelope). *Report* = a per-tool success model carrying that tool's data.
> *Flat* = fields sit at the top level of the JSON object rather than nested under a `data` /
> `payload` key. *Soft (or signalled) failure* = a handled failure the tool returns as a normal value
> (a `ToolError`, a `ToolErrorEnvelope`, or `tool_available=False`) instead of raising — so the run
> stays deterministic and replayable. The architecture chapter calls these the
> [two error-envelope contracts](../02-architecture/mcp-server.md#35-the-wrapper-layer-and-the-two-error-envelope-contracts);
> this page documents the **success** shape and both **error** shapes from the code.

```python
# mcp_server/server.py:186
class ToolError(BaseModel):
    """Structured error response from a tool call."""
    tool: str
    error: str
    suggestion: str = ""
```

So the *outer discriminator* of every response is "did I get a report or a `ToolError`?" — both are
plain JSON objects after `model_dump()`. The `@traced` decorator records the call either way, tagging
`exit_code` 0 (ok), 1 (`ToolError` returned), or 2 (exception raised and re-raised)
(`mcp_server/_trace.py:260-300`).

There is one more error shape — the **`safe_tool` envelope** used by the Wazuh tools — covered in
[The `safe_tool` flat error envelope](#the-safe_tool-flat-error-envelope) below. It is the *second* of
the two error-envelope contracts; the `ToolError` model above is the first.

### Recurring cross-cutting fields (forensic wrapper reports)

The forensic wrapper reports share a stable spine, illustrated by `PsList`
(`wrappers/volatility.py:157`) and `FlsReport` (`wrappers/tsk.py:49`):

| Field | Type | Where | Semantics |
|-------|------|-------|-----------|
| `tool` | `str` | almost all wrapper reports | Canonical tool/plugin identity, e.g. `"volatility3.windows.pslist.PsList"`, `"sleuthkit.fls"`, `"evtx.dump"`. This is the closest thing to an envelope `tool` field. |
| `raw_stdout_sha256` | `str` | 22 wrapper modules | **The provenance fingerprint.** SHA-256 of the binary's raw stdout bytes — chain-of-custody (SIFT-W-082). Present in `volatility.py`, `tsk.py`, `evtx.py`, and ~19 others. |
| `raw_stderr` | `str` | most wrapper reports | Captured stderr for diagnosis (default `""`). |
| `tool_available` | `bool` | wrapper reports (W-135) | `False` when the wrapper short-circuited without invoking the binary (missing tool or wrong input class). |
| `skipped_reason` | `str` | wrapper reports (W-135) | Human reason the wrapper short-circuited; empty on the normal path. |
| `image_class_detected` | `str` | memory wrapper reports (W-135) | e.g. detected a disk image where a memory dump was required. |
| `status` / `reason` / `reason_detail` | `str` | reports under the status taxonomy | QA WS-A status taxonomy (gated by `AGENTROPIX_STATUS_TAXONOMY`); default `status="ok"`. |
| `used_fallback` | `bool` | `PsList` | `True` when `psscan` was substituted for a failed `pslist`. |

### Recurring fields (case / state / reporting results)

The case-state and reporting tools return their own result models with a different recurring spine
(`wrappers/case_records.py`, `wrappers/case_lifecycle.py`):

| Field | Type | Where | Semantics |
|-------|------|-------|-----------|
| `case_id` | `str` | every case-scoped result | The case the operation applied to. |
| `error` | `str` (default `""`) | most result models | Non-empty when the operation failed softly (e.g. indexer unreachable). |
| `indexed` / `indexed_to` | `bool` / `str` | record/ingest results | Whether the doc was written and to which dated index (`agentropix-…-YYYY.MM.DD`). |
| `audit_id` | `str` (default `""`) | `EvidenceRecord` and case records | MCP audit id stamped by the `server.py` wrapper at the boundary (`case_lifecycle.py:115`). This is the real `audit_id`. |
| `duplicate` | `bool` | `RecordFindingResult` | `True` when an idempotent `(case_id, finding_id)` re-record was suppressed (ISSUE-014). |
| `truncated` / `result_bytes` | `bool` / `int` | `ReportGenerateResult` | Byte-budget transparency — heavy section row-lists trimmed to fit the ~1 MB MCP result envelope (SIFT-W-296c). |
| `warning` | `str` | `ReportGenerateResult` | Non-empty when an approval-filtered profile returned zero APPROVED findings while DRAFTs exist (so an empty report isn't misread as "found nothing", NIST1 ISSUE-009). |

---

## Realistic JSON example

A successful `get_pslist` call against a memory image. Fields are exactly those of `PsList`
(`wrappers/volatility.py:157-182`); `processes[]` rows are `ProcessInfo`:

```json
{
  "image_path": "/cases/INC-2026-0605/mem.raw",
  "process_count": 2,
  "processes": [
    { "pid": 4732, "ppid": 624, "name": "powershell.exe" },
    { "pid": 624,  "ppid": 4,   "name": "services.exe" }
  ],
  "tool": "volatility3.windows.pslist.PsList",
  "raw_stderr": "",
  "used_fallback": false,
  "raw_stdout_sha256": "9f2c…<64 hex>…1ab0",
  "tool_available": true,
  "skipped_reason": "",
  "image_class_detected": "",
  "status": "ok",
  "reason": "",
  "reason_detail": ""
}
```

A **soft failure** for the same tool when handed a disk image instead of a memory dump (W-135):

```json
{
  "image_path": "/cases/INC-2026-0605/disk.E01",
  "process_count": 0,
  "processes": [],
  "tool": "volatility3.windows.pslist.PsList",
  "tool_available": false,
  "skipped_reason": "input is a disk image, not a memory dump",
  "image_class_detected": "disk_image",
  "raw_stdout_sha256": "",
  "status": "ok"
}
```

A **`ToolError`** (rate-limit example):

```json
{ "tool": "record_finding", "error": "rate limit exceeded (60/min)", "suggestion": "" }
```

A **state-mutating** `record_finding` success (`RecordFindingResult`, `case_records.py:66`):

```json
{
  "case_id": "INC-2026-0605",
  "finding_id": "F-0012",
  "indexed": true,
  "indexed_to": "agentropix-findings-2026.06.05",
  "error": "",
  "duplicate": false
}
```

---

## The `safe_tool` flat error envelope

The forensic dispatch core (the `mcp_*` functions in `server.py`) catches expected failures and returns
a `ToolError` Pydantic model, as shown above. The **Wazuh tools take a different route.** Each Wazuh
`@app.tool()` callable is wrapped by the `@safe_tool(tool_name=…)` decorator
(`wrappers/_safe_tool.py`), which catches *any* escaped exception — a Pydantic `ValidationError`, an
`httpx` HTTP error, a `WazuhError` from the Wazuh manager, an `IndexerError` — and returns a
**`ToolErrorEnvelope`** instead of letting it crash the agent's iteration. This is the *second* of the
[two error-envelope contracts](../02-architecture/mcp-server.md#35-the-wrapper-layer-and-the-two-error-envelope-contracts);
the `ToolError` model is the first. (`safe_tool` is applied e.g. at `wrappers/wazuh_intel.py:55` and
`wrappers/wazuh_tools.py`.)

`ToolErrorEnvelope` is a thin `dict` subclass (`_safe_tool.py:53`), so on the wire it is a plain JSON
object — **flat `{error, details}`**, with the tool's own data simply absent on the failure path:

```python
# wrappers/_safe_tool.py:53 — shape (docstring-verbatim)
class ToolErrorEnvelope(dict):
    # {
    #   "error":   str,          # short error CATEGORY, not a sentence
    #   "details": {
    #       "exception_class": str,  # e.g. "WazuhError" / "ValidationError"
    #       "message":         str,  # str(exc), truncated to 500 chars
    #       "tool":            str,  # the tool_name passed to safe_tool()
    #   },
    # }
```

A realistic `ToolErrorEnvelope` — `wazuh_check_intel` when the Wazuh manager is unreachable:

```json
{
  "error": "wazuh_error",
  "details": {
    "exception_class": "WazuhError",
    "message": "connection refused: indexer at <WAZUH-HOST>:9200",
    "tool": "wazuh_check_intel"
  }
}
```

Three details make this envelope load-bearing and worth understanding:

- **The `error` field is a stable *category*, not free text.** `_classify_exception` maps known
  exception types to fixed strings — `validation_error`, `http_error`, `wazuh_error`, `indexer_error`
  — so a consumer can branch on the category without parsing the human `message` (unknown types fall
  through to the lower-cased class name). The verbatim exception type stays in `details.exception_class`.
- **The `message` is truncated to 500 chars** because `str(exc)` can carry a multi-kilobyte indexer
  response body or sensitive argument values — bounding it keeps the audit row small and avoids leaking
  bulk data into the trace.
- **Detection is duck-typed.** A caller checks `isinstance(result, ToolErrorEnvelope)` (the marker
  subclass) or, equivalently after JSON serialization, simply `"error" in result`. The FastMCP layer
  uses this to branch success vs failure without parsing the dict shape.

`safe_tool` deliberately does **not** catch `KeyboardInterrupt`, `SystemExit`, or
`asyncio.CancelledError` (`_NEVER_CATCH`, `_safe_tool.py`) — those are control-flow/shutdown signals
that must propagate. When a Wazuh tool also uses the WZ-002 retry helper, the retry runs *inside*
`safe_tool`, so the envelope captures only the **final** outcome after retries are exhausted, never an
intermediate transient failure.

> **`ToolError` vs `ToolErrorEnvelope` — don't conflate them.** Both are flat JSON error objects, but
> they are distinct types with distinct shapes. `ToolError` is a Pydantic model with `tool` / `error` /
> `suggestion` returned by the **forensic dispatch core**. `ToolErrorEnvelope` is a `dict` subclass with
> `error` / `details{exception_class,message,tool}` returned by the **`@safe_tool`-wrapped Wazuh tools**.
> A consumer that wants one boolean "did this fail?" check can rely on the shared truth that a present,
> non-empty `error` key (top-level on both) signals failure.

---

## Mapping the conceptual envelope to the real fields

The project description names an idealized envelope (`success`, `tool`, `data`, `data_provenance`,
`audit_id`, `caveats`, `advisories`, `corroboration`, discipline reminder). For accuracy, here is how
each maps to what the code actually returns — code wins over the conceptual model:

| Conceptual field | Implemented as | Notes |
|------------------|----------------|-------|
| `success` | **Implicit** | No boolean `success` field. Success vs failure is the *type* of the returned object (`ToolError` *or* `ToolErrorEnvelope` ⇒ failure) plus `@traced` `exit_code`. Soft failures also surface via `tool_available=False` / a non-empty top-level `error` key (present on both error envelopes). |
| `tool` | **`tool`** | Real field on wrapper reports (`tool="sleuthkit.fls"` etc.) and on `ToolError.tool`. |
| `data` | **The report body itself** | Tool data is the report's own typed fields (`processes`, `entries`, `findings`, …), not nested under a `data` key. |
| `data_provenance` | **`raw_stdout_sha256`** (+ `tool`, `raw_stderr`) | Provenance is the SHA-256 of the binary's raw stdout bytes (SIFT-W-082). No field literally named `data_provenance`. |
| `audit_id` | **`audit_id`** | Real field on case/evidence records (`case_lifecycle.py:115`), stamped at the MCP boundary. Not present on stateless forensic reports. |
| `caveats` | **`skipped_reason` / `reason` / `warning`** | The "caveat" role is filled by these per-context fields. No field literally named `caveats`. |
| `advisories` | **`suggestion` (ToolError) / `warning`** | `ToolError.suggestion` and `ReportGenerateResult.warning` carry advisory text. No field literally named `advisories`. |
| `corroboration` | **`Correlation` records** (out of band) | Cross-source corroboration is modeled by `Correlation` on the Blackboard (`agents/_blackboard.py:65`) and surfaced in HuntAgent findings, **not** as a tool-response field. |
| discipline reminder | **Not a response field** | The "deterministic-tools-only / no LLM self-rating" discipline is enforced structurally (Thymus policy, `inference_constraint="high"` on the report, deterministic Critic) — it is not emitted inside individual tool envelopes. |

> **Authoring note (HARD RULE 1).** Do not assert that a tool response contains literal `success`,
> `data`, `data_provenance`, `caveats`, `advisories`, `corroboration`, or `discipline_reminder` keys —
> those names are not in the code. Describe the real fields above. The provenance hash
> (`raw_stdout_sha256`), the `tool` identity, the `audit_id`, and the `tool_available`/`skipped_reason`
> degradation signals are the load-bearing, verifiable parts of the envelope.

---

## Availability & skip signalling

Wrapper reports never raise on a missing binary or wrong input class — they return with
`tool_available=False` and a populated `skipped_reason` (W-135). This is what makes the swarm
deterministic and idempotent: an absent `vol` against a disk image is a *signalled skip*, replayable to
an identical trace, not a stochastic crash. The Critic and Architect read these signals rather than
guessing. See [Tool reference → degradation contract](tool-reference.md#degradation-contract-w-135).

## Mutation & approval gating

State-mutating tools (`record_finding`, `idx_ingest`, `promote_iocs`, `promote_executable_registry`,
`wazuh_index_findings`, `wazuh_publish_iocs`) require a one-shot, TTL-bound `mutation_token`
(`evidence_gate/registry.py`) and default to `dry_run=True`. `record_finding` only ever stages a
finding as **DRAFT** — the LLM cannot self-approve through it (`server.py:1287`). Promotion to APPROVED
runs through the HMAC-gated `approve_finding` in the approval sidecar (`approval_sidecar/`, ADR-016/022).
The response of these tools therefore reports `indexed`/`indexed_to` and (for findings) the DRAFT
`finding_id` — never an approval. See the safety-spine chapter and
[Tool reference → auth & mutation model](tool-reference.md#auth--mutation-model-applies-across-the-catalogue).

---

## The report that aggregates all tool calls

Individual tool envelopes are the leaves; the run as a whole rolls up into the **Triage Report**
(`report.schema.json`, `orchestrator.py` `TriageReport`). Every tool call is captured in
`trace.tool_calls[]` (each with `tool`, `timestamp`, `duration_ms`, `args_hash`, optional `raw_output`
snapshot and `output_hash`), and the report carries the court-defensible invariants
(`inference_constraint="high"`, `evidence_image_sha256`, HMAC `report_seal`). For the full report
contract see the [schema reference](../03-data/schema-er.md).

---

## Related

**Within this section (04 · MCP Tools)**

- [Tool reference](tool-reference.md) — the master categorized index of all 72 tools, with the
  [degradation contract (W-135)](tool-reference.md#degradation-contract-w-135) and
  [auth & mutation model](tool-reference.md#auth--mutation-model-applies-across-the-catalogue) this page cross-references.
- [Capability map](capability-map.md) — what the catalogue lets you *do*, grouped by capability.
- [Tools by agent](tool-by-agent.md) — which swarm agent invokes which tools (the callers that consume these envelopes).
- [Tool list](tool-list.md) — the flat alphabetical roster of every tool.

**Architecture & execution**

- [MCP server](../02-architecture/mcp-server.md) — the FastMCP boundary that calls `result.model_dump()`,
  and §3.5 [the wrapper layer and the two error-envelope contracts](../02-architecture/mcp-server.md#35-the-wrapper-layer-and-the-two-error-envelope-contracts).
- [FastMCP execution](../10-agents/fastmcp-execution.md) — one agent tool call, station by station, from prompt to returned envelope.
- [Agentic architecture](../10-agents/agentic-architecture.md) — the agents that read `tool_available` / `skipped_reason` and the rolled-up trace.

**Data & schema**

- [Schema / ER reference](../03-data/schema-er.md) — the full Triage Report contract these leaf envelopes roll up into.
- [Data models](../03-data/data-models.md) — the Pydantic report models (`PsList`, `FlsReport`, `RecordFindingResult`, …) serialized here.
- [Persisted artifacts](../03-data/persisted-artifacts.md) — where `audit_id`, `indexed_to` indices, and findings land on disk.

**Reference & decisions**

- [Canonical facts](../08-reference/canonical-facts.md) — oracle figures (72 tools, 16 wrappers, …) used throughout this page.
- [ADR-011 — evidence gates](../11-ADR/ADR-011-evidence-gates.md) — the `mutation_token` / dry-run gating behind the mutation fields.
- [ADR-016 — courtroom audit](../11-ADR/ADR-016-courtroom-audit.md) and [ADR-022 — audit-log seal](../11-ADR/ADR-022-audit-log-seal.md) — the `audit_id` and `report_seal` provenance chain.
- [ADR-024 — multi-tier report engine](../11-ADR/ADR-024-multi-tier-report-engine.md) — the byte-budget (`truncated` / `result_bytes`) and approval-filtered (`warning`) behavior of `ReportGenerateResult`.
