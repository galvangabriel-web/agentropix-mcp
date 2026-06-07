# Schema ER Model

> The persisted entities of Agentropix-SIFT and their relationships, drawn as a Mermaid `erDiagram`.
> Where [data-models.md](data-models.md) shows *object shape* and [data-dictionary.md](data-dictionary.md)
> shows *every field*, this chapter shows *how the records relate* once written to disk and to the
> case index. Numbers cite [`CANONICAL_FACTS.md`](../08-reference/canonical-facts.md); records cite their source files.

A triage run produces a small constellation of related records. Some are embedded in a single JSON
document (a `TriageReport` owns its `Finding`s, `ToolCall`s, and `ThymusAuditEntry`s); others are
peer files cross-bound by HMAC (the audit-log and the session key); still others are independent,
durable stores (the evidence-gate SQLite registry, the approval hash-chain, the Wazuh IOC inventory).
The ER diagram below treats each as a logical **entity** regardless of whether it is an embedded array, a
sidecar file, or a database row — the relationships are what matter for an examiner reconstructing a
case.

### How to read this page

This is a **reference** chapter, not a how-to: it has no commands or prompts, only the entity model.
Three terms recur throughout, defined once here:

- **Entity** — a logical record type (a box in the diagram). It may physically be an *embedded array
  element* inside the report JSON (e.g. a `FINDING`), a *sidecar file* written next to the report
  (e.g. the `SESSION_KEY`), or a *row* in a standalone database (e.g. a `MUTATION_TOKEN` in the
  SQLite evidence-gate registry). The ER model abstracts over the storage form.
- **Relationship** — a named, directed link between two entities (the line connecting two boxes,
  e.g. *contains*, *sealed-by*, *hash-chains-to-prev*).
- **Cardinality** — how many instances of each entity participate in a relationship, drawn with
  crow's-foot notation. The notation is defined in the legend immediately below; read it before the
  diagram so the symbols on each line are unambiguous.

### Cardinality notation (crow's-foot key)

Mermaid `erDiagram` writes cardinality as a two-character marker at *each end* of the relationship
line. The marker nearest an entity describes that entity's participation. Read a line as
`LEFT  <left-marker>--<right-marker>  RIGHT : "relationship"`.

| Marker | Reads as | Meaning |
|--------|----------|---------|
| `\|\|` | exactly one | mandatory, exactly 1 (one-and-only-one) |
| `o\|` | zero or one | optional, at most 1 |
| `}o` / `o{` | zero or more | optional, 0..* (the crow's foot = "many") |
| `}\|` / `\|{` | one or more | mandatory, 1..* |

> *(In the markers above and the patterns below, each `\|` is a single literal pipe character — the
> backslash is Markdown escaping so the table renders; in the diagram source the bars appear plain,
> e.g. `||--o{`.)*

Combining the two ends gives the full reading. The five patterns used in this diagram:

| Pattern | Reads as | Example on the diagram |
|---------|----------|------------------------|
| `\|\|--\|\|` | one-to-one (both mandatory) | `TRIAGE_REPORT \|\|--\|\| TRACE` — every report embeds exactly one trace |
| `\|\|--o{` | one-to-many | `TRIAGE_REPORT \|\|--o{ FINDING` — one report, zero-or-more findings |
| `\|\|--o\|` | one-to-zero-or-one | `FINDING \|\|--o\| EVIDENCE_PAYLOAD` — a finding optionally hashes one payload |
| `}o--o{` | many-to-many | `FINDING }o--o{ CORRELATION` — each side may relate to many of the other |
| `}o--\|\|` | many-to-one | `IOC_RECORD }o--\|\| IOC_PROVENANCE` — many IOCs could share one provenance shape; here each carries exactly one |

> **Direction note.** The verb label reads left-to-right (`A contains B`). The crow's foot is the
> "many" end; the double bar `||` is the "exactly one" end. The full cardinality of each relationship
> — with its enforcing invariant and source file — is tabulated in
> [Relationship invariants summary](#relationship-invariants-summary) at the foot of this page.

---

## Contents — what's in this page (and what to expect)

> Jump to any section below. Each row tells you what that part gives you, so you can go straight to your point.

| Section | What you'll get |
|---|---|
| [The persisted-entity ER diagram](#the-persisted-entity-er-diagram) | The full Mermaid `erDiagram` of every persisted entity, its fields, and the crow's-foot relationships between them (plus a zoomable SVG link). |
| [Entity-by-entity](#entity-by-entity) | A walkthrough of each entity — what it is, where it lives on disk, its relationships, and a jump to its field-level data-dictionary entry. |
| [Relationship invariants summary](#relationship-invariants-summary) | A table of every relationship with its cardinality, enforcing invariant, and source file. |
| [Cross-references](#cross-references) | Links to the companion data chapters (object shapes, field dictionary, on-disk artifacts). |

---

## The persisted-entity ER diagram

```mermaid
erDiagram
    TRIAGE_REPORT ||--o{ FINDING : "contains"
    TRIAGE_REPORT ||--|| TRACE : "embeds"
    TRACE ||--o{ TOOL_CALL : "records"
    TRIAGE_REPORT ||--o{ THYMUS_AUDIT_ENTRY : "embeds"
    TRIAGE_REPORT ||--o{ TRINITY_ITERATION : "embeds"
    TRIAGE_REPORT ||--|| SESSION_KEY : "sealed-by"
    TRIAGE_REPORT ||--|| AUDIT_LOG_FILE : "cross-bound-to"
    AUDIT_LOG_FILE ||--o{ THYMUS_AUDIT_ENTRY : "snapshots"
    TRIAGE_REPORT }o--|| EVIDENCE_IMAGE : "binds-to"
    FINDING }o--o{ CORRELATION : "backs"
    FINDING ||--o| EVIDENCE_PAYLOAD : "hashes"
    MUTATION_TOKEN }o--o| TRIAGE_REPORT : "authorises-run"
    IOC_RECORD }o--|| IOC_PROVENANCE : "carries"
    IOC_RECORD }o--|| EVIDENCE_IMAGE : "extracted-from"
    APPROVAL_ENTRY }o--|| FINDING : "approves"
    APPROVAL_ENTRY ||--o| APPROVAL_ENTRY : "hash-chains-to-prev"

    TRIAGE_REPORT {
        string version
        string image
        string status
        string inference_constraint
        string evidence_image_sha256
        string report_seal
        int max_iterations
        int iterations_completed
    }
    FINDING {
        string _source
        float confidence
        string description
        string mitre_attack
        string file_sha256
        string agent
    }
    TRACE {
        string start_time
        string end_time
        float total_duration_ms
    }
    TOOL_CALL {
        string tool
        string timestamp
        float duration_ms
        string args_hash
        string raw_output
    }
    THYMUS_AUDIT_ENTRY {
        string timestamp
        string action
        string path
        string reason
    }
    TRINITY_ITERATION {
        int iteration
        float critic_score
        bool should_halt
    }
    SESSION_KEY {
        bytes key "mode 0600"
        string path "report.session-key"
    }
    AUDIT_LOG_FILE {
        string audit_log_seal
        int entry_count
    }
    EVIDENCE_IMAGE {
        string path
        string sha256
    }
    CORRELATION {
        string token
        int finding_count
        float max_confidence
    }
    EVIDENCE_PAYLOAD {
        string file_sha256
    }
    MUTATION_TOKEN {
        string token_id "egt_..."
        string scope
        int ttl_seconds
        float spent_ts
    }
    IOC_RECORD {
        string value
        string kind
        string decision
    }
    IOC_PROVENANCE {
        string source_evidence_sha256
        string extraction_tool
        string analyst
    }
    APPROVAL_ENTRY {
        string approval_id
        string target_type
        string from_status
        string to_status
        string prev_approval_hash
    }
```

> 🔍 **[Open as SVG — full size, zoomable](assets/schema-er-1.svg)** (renders larger than the page column; the SVG zooms losslessly in a browser tab).

---

## Entity-by-entity

### `TRIAGE_REPORT` — the case root

The aggregate root. One JSON document per run (`src/agentropix_sift/orchestrator.py:33`). It *contains*
its findings, *embeds* its trace / Thymus-audit / Trinity-iteration arrays, is *sealed-by* a session
key, is *cross-bound-to* its audit-log file, and *binds-to* the evidence image by SHA-256. Every other
entity hangs off this root or is referenced by it. Detail:
[data-dictionary §1](data-dictionary.md#1-triagereport--the-top-level-report-contract).

### `FINDING` — contained, never standalone

A finding has no identity outside its report — it is an embedded array element
(`report.findings[]`, `_base.py:40`). Cardinality `||--o{`: a report contains zero-or-more findings.
A finding may *back* one or more `CORRELATION`s (many-to-many — one token can be backed by findings
from several agents, and one finding can contribute several tokens, `_blackboard.py:108`; quorum is
≥ 2 distinct agents per correlated token, `_blackboard.py:86`). A finding
optionally *hashes* an `EVIDENCE_PAYLOAD` via `file_sha256` (zero-or-one — present only when a byte
payload was captured, `_base.py:64`). Field detail:
[finding — data-dictionary §2](data-dictionary.md#2-finding--the-wire-finding-object);
[correlation — data-dictionary §3](data-dictionary.md#3-correlation--cross-agent-agreement-on-one-token).

### `TRACE` and `TOOL_CALL` — the deterministic-provenance record

Exactly one `TRACE` is embedded per report (`||--||`), and it *records* zero-or-more `TOOL_CALL`s
(`report.schema.json:56`). The trace is the heart of the `inference_constraint = "high"` invariant:
every fact in `findings` must trace to a named tool here, replayable via each call's `raw_output`
snapshot (default 4 KiB, `AGENTROPIX_TRACE_RAW_MAX_BYTES`). `args_hash` makes a call reproducible.
Field detail: [data-dictionary §5](data-dictionary.md#5-trace--the-tool-call-trace).

### `THYMUS_AUDIT_ENTRY` — the chain-of-custody trail

An access-decision record built by the Thymus read-only policy (`thymus_policy.py:371`). The same
entry is embedded in `report.thymus_audit[]` **and** snapshotted into the sealed `AUDIT_LOG_FILE` —
hence the two relationships in the diagram (`TRIAGE_REPORT ||--o{` and `AUDIT_LOG_FILE ||--o{`). When
`AGENTROPIX_AUDIT_LOG` is set, each entry is also appended live as a JSONL line — the trail of record
(`thymus_policy.py:382`). Field detail:
[data-dictionary §6](data-dictionary.md#6-thymus_audit-entry).

### `TRINITY_ITERATION` — the reasoning trail

One embedded entry per Trinity iteration (`report.iterations[]`, serialised `TrinityResult`,
`critic.py:47`). Records the plan, Critic score, and halt decision for each Architect → Swarm → Critic
pass — the durable form of the otherwise-ephemeral Hippocampus `ReasoningTrace`
(see [persisted-artifacts.md §hippocampus](persisted-artifacts.md#hippocampus-reasoning-traces)).
Field detail: [data-dictionary §4](data-dictionary.md#4-iterations-entry--per-iteration-trinityresult-json).

### `SESSION_KEY` and `AUDIT_LOG_FILE` — the seal cross-binding

The report is *sealed-by* exactly one `SESSION_KEY` — a per-run HMAC key written to
`<report>.session-key` at mode 0600 (`courtroom.py:185`). The report is *cross-bound-to* exactly one
`AUDIT_LOG_FILE` (`<report>.audit-log.json`): the audit log's own `audit_log_seal` is copied into the
report dict before the report seal is computed, so a post-hoc swap of either file fails verification
(`write_sealed_session`, `courtroom.py:387`). This is a `||--||` relationship in both cases — exactly
one of each per sealed report.

### `EVIDENCE_IMAGE` — the bytes under examination

The report *binds-to* one evidence image by its SHA-256 (`evidence_image_sha256`, `courtroom.py:89`).
`IOC_RECORD`s are *extracted-from* the same image, carrying its digest in their provenance — this is
how an IOC pushed to a SIEM remains traceable back to the exact evidence bytes.

### `MUTATION_TOKEN` — the optional write authorisation

A one-shot, TTL-bounded token in the SQLite evidence-gate registry (`TokenRow`, `registry.py:113`).
The relationship to a run is sparse (`}o--o|`): most runs are pure read-only triage and spend no
token; a mutating operation *authorises-run* by spending exactly one token, stamping `spent_run_id`.
Field detail: [data-dictionary §8](data-dictionary.md#8-tokenrow--evidence-gate-mutation-token).

### `IOC_RECORD` and `IOC_PROVENANCE` — the SIEM-bound intelligence

Each IOC record (the `IPIOCRecord` / `SHA256IOCRecord` / … family, `wazuh/models.py`) *carries*
exactly one `IOC_PROVENANCE` (`||`) — provenance is first-class (WZ-019). Without it, when
`AGENTROPIX_REQUIRE_IOC_PROVENANCE` is set, construction raises `ProvenanceMissingError`
(`wazuh/models.py:178`). Provenance pins `source_evidence_sha256`, `extraction_tool`, and `analyst`,
linking the IOC back to the `EVIDENCE_IMAGE`. Field detail:
[data-dictionary §10](data-dictionary.md#10-wazuh-ioc-record-family).

### `APPROVAL_ENTRY` — the human-in-the-loop hash chain

An append-only approval record written by the optional approval sidecar (`approval_sidecar/models.py`).
Each entry *approves* a target `FINDING` (or timeline, or a compensating `approval` retraction) and
*hash-chains-to* the previous approval for the same target via `prev_approval_hash` (self-referential
`||--o|`, empty on the first approval). State transitions are constrained to
`DRAFT → APPROVED → REJECTED → REVOKED` per the `ApprovalStatus` / `TargetType` enums
([data-dictionary §9](data-dictionary.md#9-approval-sidecar-models)).

---

## Relationship invariants summary

| Relationship | Cardinality | Invariant | Source |
|--------------|-------------|-----------|--------|
| report → findings | 1 : 0..* | Findings are embedded; no standalone identity. | `orchestrator.py:56` |
| report → trace | 1 : 1 | Exactly one trace; required wire key. | `report.schema.json:54` |
| report → session-key | 1 : 1 | One per sealed report, mode 0600. | `courtroom.py:185` |
| report ↔ audit-log | 1 : 1 | HMAC cross-bound; swapping either fails the seal. | `courtroom.py:387` |
| report → evidence image | * : 1 | Bound by SHA-256 at session start. | `courtroom.py:89` |
| finding ↔ correlation | 0..* : 0..* | Quorum ≥ 2 distinct agents per correlated token. | `_blackboard.py:90` |
| finding → payload hash | 1 : 0..1 | `file_sha256` present only when a payload was hashed. | `_base.py:64` |
| token → run | 0..* : 0..1 | One-shot spend; most runs spend none. | `registry.py:113` |
| IOC → provenance | * : 1 | Provenance mandatory under `AGENTROPIX_REQUIRE_IOC_PROVENANCE`. | `wazuh/models.py:178` |
| approval → prev approval | 1 : 0..1 | Hash-chained, append-only per target. | `approval_sidecar/models.py` |

---

## Cross-references

- Object shapes and class diagrams: [data-models.md](data-models.md)
- Field-by-field dictionary: [data-dictionary.md](data-dictionary.md)
- How each entity is written/read on disk: [persisted-artifacts.md](persisted-artifacts.md)
- Exhaustive model/dataclass/JSON-Schema enumeration: [schema-dump.md](schema-dump.md)
- Canonical numbers: [`canonical-facts.md`](../08-reference/canonical-facts.md)
