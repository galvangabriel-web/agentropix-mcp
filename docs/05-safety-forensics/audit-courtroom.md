# Audit & Courtroom Seal

> **Section 05 · Safety & Forensics**.
> Related: [Anti-Hallucination](anti-hallucination.md) ·
> [Provenance & Grounding](provenance-grounding.md) ·
> [Human-in-the-Loop](human-in-the-loop.md)

The Courtroom track is the cryptographic spine that makes an Agentropix-SIFT
report **court-defensible**: a report and its access trail are sealed with
HMAC-SHA256 under a per-run key, cross-bound to each other, and independently
re-verifiable so that post-hoc tampering of *either* file is detectable from
the other. This chapter covers report sealing, the JSONL audit log, the
chain-of-custody cross-binding, and integrity verification.

All of this lives in `src/agentropix_sift/courtroom.py` (ADR-016 / ADR-022,
BMAD-M8 Phase M8.2 + W-173) and the standalone verifiers under
`provenance/validate.py` and `audit/verify_seal.py`.

## The threat model

The Courtroom seal is explicit about what it defends against
(`courtroom.py:35-49`):

> "The session key is **per-run**, not a long-lived secret. The threat model is
> post-hoc tampering of the JSON, not impersonation."

It deliberately uses the **smallest primitive that achieves the goal** — HMAC-
SHA256 over canonical JSON, "no JOSE / JWT machinery" (`courtroom.py:37-39`).
The guarantee: change any byte of the sealed report and the recomputed MAC no
longer matches.

## The four invariants

| # | Invariant | Function | Source |
|---|-----------|----------|--------|
| 1 | Evidence image is hashed at session start | `evidence_image_sha256(path)` | `courtroom.py:89-142` |
| 2 | Report sealed with HMAC-SHA256 over canonical JSON | `seal_report` / `verify_seal` | `courtroom.py:161-182` |
| 3 | Per-run 32-byte session key, written 0600 | `write_session_key(out_path)` | `courtroom.py:185-202` |
| 4 | Audit log peer-sealed and cross-bound into the report seal | `seal_audit_log` / `write_sealed_session` | `courtroom.py:269-397` |

Invariant 1 (the pre/post SHA-256 evidence invariant) is covered in
[Anti-Hallucination](anti-hallucination.md#4--the-prepost-sha-256-evidence-invariant);
this chapter focuses on 2–4.

## HMAC-SHA256 report sealing

`seal_report(report_dict, key)` computes the hex MAC over a **canonicalised**
serialization of the report (`courtroom.py:161-170`). The seal field is part of
the document but obviously cannot be inside the bytes being MACed, so
`_canonical_for_seal` forces `report_seal` to a fixed sentinel `"__sealed__"`
before serialising, and the verifier does the same so the MAC is reproducible
(`courtroom.py:145-158`):

```python
snapshot = dict(report_dict)
snapshot["report_seal"] = "__sealed__"
return json.dumps(snapshot, sort_keys=True, separators=(",", ":"),
                  ensure_ascii=True, default=str).encode()
```

The canonicalisation is fixed on **both** sides: `sort_keys=True`, minimal
separators (no whitespace), `ensure_ascii=True`. The session key must be ≥ 32
bytes or `seal_report` raises (`courtroom.py:167-168`). Verification is
constant-time via `hmac.compare_digest` (`courtroom.py:173-182`):

```python
def verify_seal(report_dict, key, expected_seal) -> bool:
    recomputed = seal_report(report_dict, key)
    return hmac.compare_digest(recomputed, expected_seal)
```

Because the seal lives *inside* the JSON on disk, a verifier needs no
side-channel — just the report and its session-key file
(`courtroom.py:163-166`).

## The per-run session key

`write_session_key(out_path)` mints 32 random bytes via `secrets.token_bytes`
and writes them to `<stem>.session-key` beside the report, with mode `0600`
(user-rw only) (`courtroom.py:185-202`). One key per run; an existing key file
at that path is overwritten. This is the same per-run key used to seal the audit
log (invariant 4), which is what lets a verifier holding the report also detect
a swapped audit-log file.

## The JSONL audit log and chain-of-custody cross-binding

The Thymus policy emits an access trail — every `ALLOW` / `REJECT` /
`REJECT_WRITE` decision — to an in-memory bounded ring **and**, when
`AGENTROPIX_AUDIT_LOG` is set, to an append-only on-disk JSONL
(`mcp_server/thymus_policy.py:371-394`). Before W-173, neither was sealed, so a
hostile reviewer who replaced `report.json` could also silently rewrite the
JSONL — defeating the chain of custody (`courtroom.py:230-254`).

`write_sealed_session(...)` (`courtroom.py:341-397`) closes that gap with a
**single-key, cross-bound** flow:

1. Generate the session key once (`write_session_key`).
2. Drain the on-disk JSONL via `read_audit_log_jsonl` (tolerant of missing
   files and malformed lines, `courtroom.py:290-338`) into the sealed snapshot —
   so the sealed file reflects the trail-of-record, not the bounded ring that
   may have rolled over during a long run.
3. Build the audit dict (`metadata` + `audit_entries`), compute its seal with
   `seal_audit_log`, and embed it under `audit_log_seal`.
4. **Cross-bind**: copy `audit_log_seal` into the report dict *before*
   computing the report seal, so the report MAC covers the audit seal.
5. Compute and embed `report_seal`; write `report.json` and
   `<stem>.audit-log.json`.

```python
audit_seal = seal_audit_log(audit_dict, key)
audit_dict["audit_log_seal"] = audit_seal
# Cross-bind: report seal MACs over the audit_log_seal field
report_dict["audit_log_seal"] = audit_seal
report_seal = seal_report(report_dict, key)
report_dict["report_seal"] = report_seal
```

The cross-binding is the chain-of-custody linchpin: "a swapped audit-log file
with a valid internal seal but a different MAC will still fail the cross check"
(`courtroom.py:355-360`). Tampering with the audit log breaks *both* the audit
seal and the report seal (`courtroom.py:241-250`). The function returns the
three surfaces — `{"report": ..., "key": ..., "audit": ...}` — so the operator
can echo all of them (`courtroom.py:363-364, 397`).

> New code should prefer `write_sealed_session`; the older
> `write_sealed_report` (`courtroom.py:205-227`) seals only the report and is
> retained for callers with no audit entries (legacy/test paths).

## Seal & verify flow

```mermaid
sequenceDiagram
    autonumber
    participant ORCH as Orchestrator
    participant CR as courtroom.py
    participant FS as Disk (report + key + audit)
    participant V as Verifier (audit/verify_seal · provenance/validate)

    Note over ORCH: Session start
    ORCH->>CR: evidence_image_sha256(image_path)
    CR-->>ORCH: sha256 hex (or None, recorded)

    Note over ORCH: ...Trinity loop runs; Thymus logs ALLOW/REJECT to JSONL...

    Note over ORCH: Session end — seal
    ORCH->>CR: write_sealed_session(report, audit_entries, out_path)
    CR->>CR: write_session_key() → 32 bytes, 0600
    CR->>CR: seal_audit_log(audit_dict, key) → audit_log_seal
    CR->>CR: cross-bind audit_log_seal into report dict
    CR->>CR: seal_report(report_dict, key) → report_seal
    CR->>FS: write report.json + <stem>.session-key + <stem>.audit-log.json
    CR-->>ORCH: {report, key, audit} paths

    Note over V: Later — independent verification
    V->>FS: read report.json + audit-log.json + session-key
    V->>V: recompute audit seal → compare_digest(audit_log_seal)
    V->>V: recompute report seal → compare_digest(report_seal)
    alt all seals recompute & cross-bind holds
        V-->>V: ok (court-defensible)
    else any MAC mismatch
        V-->>V: forged → exit non-zero (TAMPER)
    end
```

The sequence shows the asymmetry that makes the seal trustworthy: **sealing**
needs the live session key (held in memory during the run, persisted 0600);
**verification** needs only the on-disk artifacts plus that key file, and
recomputes the MACs with `hmac.compare_digest`. The cross-bind step (audit seal
folded into the report seal *before* the report MAC is taken) means a verifier
who only re-checks the report seal still catches a swapped audit log, because
the report MAC was computed over the audit seal value.

## Integrity verification & classification

Two CLIs re-verify seals and classify every row; both exit non-zero only when a
*tamper* category is present.

**Wazuh audit JSONL** — `audit/verify_seal.py` (`verify_seal.py:8-27`):

| Category | Meaning | Tamper? |
|----------|---------|---------|
| `ok` | seal recomputes correctly | no |
| `unsealed` | no `seal` field (dry-run / out-of-band rows) | no |
| `seal_failed` | `SEAL_FAILED:` marker — seal computation crashed at write | no |
| `stale_session` | seal present, but `run_id` ≠ current session (per-run key rotation) | no |
| `forged` | seal present, run_id matches, MAC does **not** recompute | **yes** |
| `malformed` | unparseable JSON / bad envelope shape | **yes (forgery-equivalent)** |

> Exits non-zero iff `forged > 0 OR malformed > 0` (`verify_seal.py:27`). The
> session key defaults to `<jsonl-path>.session-key` next to the log
> (`verify_seal.py:29-31`), matching where `wazuh.seal.generate_session_key`
> writes it.

**Provenance sidecars** — `provenance/validate.py` uses the parallel
`ok / unsealed / forged / schema_failed / malformed` ladder
(`validate.py:25-43`), exiting non-zero iff
`forged + schema_failed + malformed > 0` (`validate.py:42, 90`). The grounding
semantics of these categories are covered in
[Provenance & Grounding](provenance-grounding.md#grounding-levels--how-well-a-claim-is-externally-supported).

The `stale_session` category deserves emphasis: because each run mints a fresh
key that overwrites the previous one (`verify_seal.py:32-38`), rows sealed under
a *prior* run's key cannot verify against the current key — but that is
**session rotation, not tampering**, so the verifier classifies them
`stale_session` and does not fail the run. To check historical rows, supply
each historical key, or scope with `--current-run-id`.

## Related sealing primitives

The same HMAC-SHA256-over-canonical-JSON pattern recurs across the safety spine,
each with a `verify_*` peer that recomputes in constant time:

| Surface | Module | Seal envelope binds |
|---------|--------|---------------------|
| Report + audit log | `courtroom.py` | report dict; audit dict; cross-bound `audit_log_seal` |
| Wazuh IOC push | `wazuh/seal.py:1-32` | operator, case_id, ts, evidence_token_id, endpoint, req/resp sha256, status |
| Approval ledger | `approval_sidecar/hash_chain.py` | deterministic `approval_id` + `prev_approval_hash` chain (see [Human-in-the-Loop](human-in-the-loop.md)) |

## See also

- [Anti-Hallucination](anti-hallucination.md) — the evidence digest (invariant
  1) and why the sealed report contains only deterministic-tool findings.
- [Provenance & Grounding](provenance-grounding.md) — the grounding-level
  taxonomy these verifiers implement.
- [Human-in-the-Loop](human-in-the-loop.md) — the append-only approval
  hash-chain, a sibling tamper-evidence mechanism.
