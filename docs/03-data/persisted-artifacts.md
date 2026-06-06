# Persisted Artifacts

> Every on-disk (and on-index) artifact a triage run produces or consumes: its **path / naming**,
> **format**, **lifecycle** (who writes it, who reads it, when), and the **integrity guarantees** that
> bind it. Where [schema-er.md](schema-er.md) shows how the records relate and
> [data-dictionary.md](data-dictionary.md) defines their fields, this chapter is the operator's map of
> what lands on the filesystem after a run. Code wins over docs; numbers cite
> [`CANONICAL_FACTS.md`](../../.crew/facts.md).

A sealed triage run writes a **trio of sibling files** plus, optionally, a JSONL audit trail and
entries in independent stores (the evidence-gate SQLite DB, the approval hash-chain, the Wazuh IOC
index). The trio is cross-bound by a single per-run HMAC key so that tampering with any one file is
detectable.

---

## Artifact overview

| Artifact | Path / naming | Format | Written by | Read by | Lifecycle |
|----------|---------------|--------|------------|---------|-----------|
| Triage report | `<report>.json` (operator-chosen) | JSON (indent=2) validating `report.schema.json` | `cli.py` via `write_sealed_session` | examiners, verifiers, `provenance/validate.py` | Per run; sealed at write time |
| Session key | `<report>.session-key` | 32 raw bytes, mode 0600 | `write_session_key` (`courtroom.py:185`) | `verify_seal`, `audit/verify_seal.py` | One per run; overwritten if re-run |
| Sealed audit log | `<report>.audit-log.json` | JSON, HMAC-sealed, cross-bound | `write_sealed_session` (`courtroom.py:394`) | `verify_audit_seal`, examiners | Per run; peer of the report |
| Thymus JSONL audit | `$AGENTROPIX_AUDIT_LOG` | JSONL (append) | `ThymusEvidencePolicy._log` (`thymus_policy.py:382`) | drained into sealed audit log; SIEM | Append-only, live during run |
| Hippocampus traces | (in-memory only) | `ReasoningTrace` objects | `HippocampusBridge.remember` | next-iteration `Architect` | Process-lifetime; not persisted standalone |
| Evidence-gate DB | `$AGENTROPIX_EVIDENCE_GATE_DB` | SQLite | `TokenRegistry` (`registry.py`) | mutating tool calls | Durable across runs |
| MASTER-IOCS | `<run-dir>/MASTER-IOCS.json` (+ `.signature` sidecar) | JSON validating `master_iocs.schema.json` | `master_iocs_aggregator.py` | Wazuh push, examiners | Per case; signed by a detached HMAC sidecar |
| Approval chain | OpenSearch `agentropix-approvals-YYYY.MM.DD` | indexed docs, hash-chained | approval sidecar `writer.py` | dashboard, examiners | Append-only |

---

## The triage report — `<report>.json`

**Path / naming.** Operator-chosen output path passed to the CLI `run` command; the session key and
audit log are derived from its stem (see below).

**Format.** A single JSON document, written with `indent=2` for human readability (the seal is
computed over the *canonical* form, so indentation does not affect verification — `courtroom.py:213`).
It validates against [`report.schema.json`](data-dictionary.md#1-triagereport--the-top-level-report-contract)
(draft 2020-12). The `TriageReport` Pydantic model is the producer (`orchestrator.py:33`).

**Lifecycle.**
1. `run_triage()` drives the SWARM under the Trinity Loop and returns a `TriageReport`
   (`orchestrator.py:82`).
2. `cli.py` serialises it and seals it on write — the report is **never written unsealed** on the CLI
   path (the `doctor`/test paths are the only unsealed cases).
3. Verifiers re-read the report alongside its session key and recompute the seal.

**Integrity.** Carries the three courtroom invariants — `evidence_image_sha256` (binds to the image
bytes), `inference_constraint = "high"` (every fact ← a named MCP tool in `trace.tool_calls`), and
`report_seal` (HMAC over the canonical JSON). See
[data-models.md §courtroom-invariant-chain](data-models.md#6-the-courtroom-invariant-chain).

---

## The session key — `<report>.session-key`

**Path / naming.** `<stem>.session-key` in the same directory as the report
(`write_session_key`, `courtroom.py:196`). For `case42.json` the key is `case42.session-key`.

**Format.** 32 raw bytes from `secrets.token_bytes(32)`, written with mode **0600** (user read/write
only). On non-POSIX filesystems where `chmod` fails, a warning is logged but the run continues
(`courtroom.py:200`). Operators are responsible for any further OS-level ACLs for evidentiary handling
(`courtroom.py:189`).

**Lifecycle.** Generated **once per run** as the very first step of sealing; if a key already exists at
the path it is overwritten — one key per run (`courtroom.py:193`). It is the *only* secret needed to
verify the report and audit-log seals, so its handling is the crux of the chain-of-custody story: a
verifier with the key can prove the report is unmodified; without it, the seals are opaque.

**Read by.** `verify_seal` (`courtroom.py:173`) and the standalone `audit/verify_seal.py` recompute
the HMAC from this key and compare in constant time.

---

## The sealed audit log — `<report>.audit-log.json`

**Path / naming.** `<stem>.audit-log.json`, peer of the report (`courtroom.py:394`).

**Format.** A JSON document with a `metadata` block (`audit_log_enabled`, `entry_count`,
`audit_log_source_path`), an `audit_entries` array (the drained Thymus access records), and its own
`audit_log_seal` HMAC field (`courtroom.py:374`).

**Lifecycle (the `write_sealed_session` flow, `courtroom.py:341`).**
1. Generate the per-run session key once via `write_session_key`.
2. Build the audit-log dict from the drained entries; compute its seal; embed it as `audit_log_seal`.
3. **Cross-bind:** copy `audit_log_seal` into the *report* dict so the report seal MACs over it.
4. Compute and embed `report_seal`; write `<report>.json`.
5. Write `<report>.audit-log.json`.

`write_sealed_session` returns `{"report": Path, "key": Path, "audit": Path}` so the CLI can echo all
three surfaces to the operator (`courtroom.py:363`).

### The sealed-session cross-binding

The cross-binding is the load-bearing integrity property: because the report seal is computed *over*
the audit log's seal, a hostile reviewer who swaps in a different `<report>.audit-log.json` — even one
with a valid internal `audit_log_seal` — produces a different cross-bound value, and the report seal
fails (`courtroom.py:385`). Neither file can be replaced in isolation. The legacy
`write_sealed_report` (`courtroom.py:205`) seals only the report and is retained for callers with no
audit entries (legacy/test paths); new code uses `write_sealed_session`.

---

## Thymus JSONL audit log

**Path / naming.** `$AGENTROPIX_AUDIT_LOG` (and dir form `$AGENTROPIX_AUDIT_LOG_DIR`). When unset, no
on-disk JSONL is written and only the in-memory ring is kept.

**Format.** One JSON object per line (JSONL). Each line is a Thymus access-decision entry:
`{timestamp, action, path, reason}` (`thymus_policy.py:372`).

**Lifecycle.** Written **live, append-only** during the run by `ThymusEvidencePolicy._log` every time
the read-only evidence policy decides an access — `ALLOW` at `logger.info`, denials at
`logger.warning` (`thymus_policy.py:379`). Parent dirs are created on demand; an `OSError` on write is
logged but non-fatal (`thymus_policy.py:389`). In parallel, every entry is appended to an in-memory
ring sized by `AGENTROPIX_THYMUS_AUDIT_LOG_RING_SIZE` (default 1000, floor 100, ceiling 100000).

**Relationship to the sealed audit log.** At session end the JSONL trail-of-record is drained
(`read_audit_log_jsonl`, `courtroom.py:290`) into the sealed `<report>.audit-log.json` so the sealed
file is a *snapshot* of the trail rather than the live file (`courtroom.py:250`). The same entries
also surface embedded in `report.thymus_audit[]`. This is why the
[ER diagram](schema-er.md#thymus_audit_entry--the-chain-of-custody-trail) shows a `THYMUS_AUDIT_ENTRY`
linked to both the report and the audit-log file.

---

## Hippocampus reasoning traces

**Path / naming.** **None — the bridge is in-memory only.** `HippocampusBridge` backs its store with
a plain Python list, not a file or database (`hippocampus_bridge.py:108`).

**Format.** `ReasoningTrace` objects ([data-dictionary §7](data-dictionary.md#7-reasoningtrace--hippocampus-memory-trace)),
opt-in via `AGENTROPIX_HIPPOCAMPUS_ENABLED` (default off).

**Lifecycle.** Iteration *N* calls `remember(trace)`; iteration *N+1*'s `Architect` receives the
top-K (`AGENTROPIX_HIPPOCAMPUS_TOP_K`, default 3) most similar prior traces as planning context —
Lamarckian inheritance within a single process (`hippocampus_bridge.py:19`). When the process exits,
the traces are gone.

> **The durable form is `report.iterations[]`.** Although the Hippocampus traces themselves are not
> persisted, the equivalent per-iteration record *is* written into the report as the serialised
> `TrinityResult` array ([data-dictionary §4](data-dictionary.md#4-iterations-entry--per-iteration-trinityresult-json)).
> The full-fat `agentropix.memory.hippocampus.HippocampusMemory` (ChromaDB-backed) is a documented
> drop-in upgrade path; the bridge's `ReasoningTrace` field shape is a strict subset of it so a future
> persistent store can replace the in-memory list without touching callers (`hippocampus_bridge.py:15`).

---

## Evidence-gate token registry (SQLite)

**Path / naming.** `$AGENTROPIX_EVIDENCE_GATE_DB` (default path resolved by `registry.py`).

**Format.** SQLite. Rows are `TokenRow` records (frozen dataclass, `registry.py:113`):
`token_id` (`egt_…`), `scope`, `created_ts`, `ttl_seconds`, `spent_ts`, `spent_run_id`, `revoked_ts`,
`operator` ([data-dictionary §8](data-dictionary.md#8-tokenrow--evidence-gate-mutation-token)).

**Lifecycle.** **Durable across runs** — this is the one store whose lifetime is decoupled from a
single triage. Operators mint a one-shot, TTL-bounded token with `agentropix-sift evidence-gate mint`;
a mutating tool call consumes it (one-shot spend, stamping `spent_run_id` and `spent_ts`); tokens can
be revoked. The token is sourced from `AGENTROPIX_MUTATION_TOKEN` (env, never a CLI flag). Most triage
runs are pure read-only and spend no token.

---

## MASTER-IOCS aggregate

**Path / naming.** `MASTER-IOCS.json`, written into the **run directory** the aggregator is pointed at
(`--input` / `--output`; the `run_dir` config field, `master_iocs_aggregator.py:95`). A detached
signature **sidecar** lands beside it as `MASTER-IOCS.json.signature`
(`master_iocs_aggregator.py:24`). When this run directory is the operator's case directory, the
placeholder env var **`<AGENTROPIX_RUNNER_CASE_DIR>`** is what the downstream Wazuh push path points at
to find the file.

**Format.** JSON validating `schema/master_iocs.schema.json`, produced by
`wrappers/master_iocs_aggregator.py`. Carries the IOC record family
([data-dictionary §10](data-dictionary.md#10-wazuh-ioc-record-family)) — each record bound to its
`IOCProvenance` (and thereby to the evidence-image SHA-256).

**Lifecycle.** Aggregated per case by walking the per-host `report.json` files under the run directory
(`memory/<host>/` and `disks/<host>/`) and merging their IOCs additively. The aggregator is
**fail-closed on integrity**: it refuses to write unless the signer key
`AGENTROPIX_MASTER_IOCS_HMAC_KEY` is set (and at least 32 bytes long, `master_iocs_aggregator.py:70`).

**Integrity (detached sidecar, not an inline seal).** Unlike the report trio — whose seals live
*inside* the JSON — MASTER-IOCS is signed by a **separate** `MASTER-IOCS.json.signature` file. That
sidecar records the file's `target_filename`, its `target_sha256`, and a `signature_hex` = HMAC-SHA256
over the canonical file bytes keyed by `AGENTROPIX_MASTER_IOCS_HMAC_KEY`
(`master_iocs_aggregator.py:580`). Verification (`verify_master_iocs_signature`) re-hashes the file,
checks the filename and SHA-256 match the sidecar, then constant-time compares the recomputed HMAC
against `signature_hex`. It is the input the Wazuh push path reads to hunt IOCs in the SIEM; provenance
travels with every record so a pushed indicator remains traceable to the exact evidence bytes it was
extracted from.

---

## Approval hash-chain (OpenSearch index)

**Path / naming.** OpenSearch indices `agentropix-approvals-YYYY.MM.DD` (the `indexed_to` field of an
`ApprovalSubmitResponse`).

**Format.** Indexed approval documents, hash-chained per target via `prev_approval_hash` (empty on the
first approval for a target). Written by the optional approval sidecar's `writer.py` after PBKDF2 +
HMAC authentication ([data-dictionary §9](data-dictionary.md#9-approval-sidecar-models)).

**Lifecycle.** **Append-only.** Each examiner decision (`DRAFT → APPROVED → REJECTED → REVOKED`) is a
new document linked to the previous one for the same `target_id`; a retraction is a compensating
`approval`-typed VOID/REVOKED entry, never an in-place edit. ISM policies
(`AGENTROPIX_APPROVALS_*_RETENTION_DAYS`) govern retention. This is the durable, tamper-evident record
of human-in-the-loop sign-off on findings and timelines.

---

## Putting it together — a sealed run on disk

After a typical sealed CLI run against `case42.json`, the case directory holds:

```
case42.json              # the triage report (sealed, validates report.schema.json)
case42.session-key       # 32-byte HMAC key, mode 0600  ← the only secret
case42.audit-log.json    # Thymus access trail, HMAC-sealed, cross-bound to the report
```

Plus, depending on configuration: a live JSONL at `$AGENTROPIX_AUDIT_LOG`, a `MASTER-IOCS.json` (with
its detached `MASTER-IOCS.json.signature` sidecar) for the case, rows in the evidence-gate SQLite DB,
and approval documents in OpenSearch. An examiner with
the `.session-key` can verify — in constant time — that neither the report nor its cross-bound audit
log has been altered, and can replay every deterministic step from the `raw_output` snapshots in
`trace.tool_calls`.

---

## Cross-references

- Field-by-field detail for each record: [data-dictionary.md](data-dictionary.md)
- Object shapes and the courtroom invariant chain: [data-models.md](data-models.md)
- How these entities relate: [schema-er.md](schema-er.md)
- Environment variables governing paths/keys: [`.crew/env-vars.md`](../../.crew/env-vars.md)
