> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-022: Audit-Log Seal — Independent HMAC Envelope for the Thymus Access Trail

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-05-06 |
| **Decision Makers** | Operator (victor.galvan@idemia.com), Claude (Opus 4.7) |
| **Tracking ticket** | W-173 |
| **Supersedes/Extends** | Extends [ADR-016](ADR-016-courtroom-audit.md) (courtroom audit) |
| **Priority** | P2 — closes the "residual 3%" gap on G4 Forensic Soundness in the SANS rubric re-grade (`docs/SANS-RUBRIC-RE-GRADE-2026-05-06.md` lines 67-68) |

## Context

ADR-016 (M8.2, 2026-04-25) shipped an HMAC-SHA256 seal over the SIFT
report.json plus a per-run session key. The seal binds the report's
contents — findings, trace, evidence SHA-256, inference-constraint
declaration — so post-hoc tampering is detectable.

The Thymus access policy (`mcp_server/thymus_policy.py`) records every
ALLOW / REJECT / REJECT_WRITE decision against evidence paths. As of
W-091 (M8.6) it kept those decisions in two places:

1. A bounded in-process ring (`deque(maxlen=1000)` by default,
   env-tunable). Lives only as long as the MCP server process; rolls
   past capacity on long runs.
2. An optional append-only on-disk JSONL when `AGENTROPIX_AUDIT_LOG`
   was set. Lives across runs but is *not sealed*.

Neither was bound to the report seal. A hostile reviewer with write
access to the case directory could replace `report.json` AND
`audit.jsonl` post-run; the report seal would catch the report swap
but the JSONL would slip through silently. The 2026-05-06 SANS rubric
re-grade explicitly calls this out as the residual G4 gap:

> The Thymus audit log buffer is still in-process (M8.6-era gap). No
> HMAC-sealed audit log file exists yet; if the report.json is replaced
> post-run the audit log doesn't independently survive. That's the
> residual 3%.

## Decision

**Add a peer-sealed audit log file alongside the report, computed under
the same per-run session key, with cross-binding into the report seal.**

Three new courtroom functions in `agentropix_sift/courtroom.py`:

- `seal_audit_log(audit_dict, key)` / `verify_audit_seal(...)` — HMAC-SHA256
  envelope over a canonicalised audit-log dict, mirroring `seal_report`.
- `read_audit_log_jsonl(path)` — drains the on-disk JSONL into a list
  of entries, tolerant of missing path / malformed lines.
- `write_sealed_session(report_dict, audit_entries, out_path)` —
  one-call session closure that:
  1. Generates a single 32-byte session key (one per run).
  2. Builds the audit-log dict (`{metadata, audit_entries}`).
  3. Computes `audit_log_seal` over the canonical audit-log JSON.
  4. **Cross-binds**: copies `audit_log_seal` into the report dict
     *before* the report seal is computed, so the report MAC includes
     the audit seal as an input.
  5. Computes `report_seal` and writes report.json.
  6. Writes `<stem>.audit-log.json` next to the report.

Three files land on disk per run: `report.json`,
`<stem>.audit-log.json`, `<stem>.session-key`.

`write_sealed_report` is retained unchanged for legacy callers and
existing tests. `cli.py` (the only production session-end caller) was
moved to `write_sealed_session`.

## Threat model

**In scope.** Post-hoc tampering of report.json or the audit-log file
by a reviewer who does NOT have the session key.

| Attack | Detection |
|---|---|
| Edit any byte of report.json | Report seal mismatches on recompute |
| Edit any byte of audit-log.json | Audit seal mismatches on recompute |
| Drop a REJECT entry from audit-log.json | Audit seal mismatches |
| Reorder audit entries | Audit seal mismatches (canonical JSON encodes list order) |
| Swap audit-log.json for one sealed under a different key | Cross-bind check: `report.audit_log_seal != audit.audit_log_seal` |
| Delete audit-log.json entirely | `verify_seal.py` exits 2 when report carries `audit_log_seal` but file is missing |

**Out of scope.** An attacker who has the session key can re-seal
anything. The session key is per-run and not a long-lived secret; it
is part of the chain-of-custody package the operator must protect.
For a higher trust tier (third-party witness, RFC 3161 timestamping,
hardware-rooted attestation) see future-work below.

**Session-key file permission reliance.** `write_session_key` writes
the 32-byte key with mode `0600` (owner read/write only). This is a
hard requirement, not a best-practice: if the key file is world-
readable, any local user can re-seal a tampered report and the chain-
of-custody guarantee collapses. The mode is asserted in
`tests/unit/test_courtroom.py::TestWriteSessionKey::test_key_file_has_user_only_permissions`.
Operators transferring the key to another host must preserve these
permissions (e.g. `scp -p`, `rsync -p`, or explicit `chmod 0600`
after copy). Evidence packages submitted to SANS must include the key
file; submission pipelines are responsible for maintaining the 0600
invariant in transit.

## Consequences

### Positive

- **G4 Forensic Soundness**: closes the rubric residual gap. SANS
  rubric re-grade 2026-05-06 lists 3% remaining on G4 attributable to
  this exact item; W-173 lifts G4 from 97 to ~100.
- **Independent survival**: even if the report is reconstructed by a
  defense expert from the trace, the access trail proves whether
  Thymus saw any REJECT decisions and never let them slip into the
  report.
- **One-key UX**: operators handle one session-key file, not two.
- **Backwards compatible**: `verify_seal.py` still exits 0 for legacy
  reports (no `audit_log_seal` field, no audit-log.json file).

### Negative

- One additional file per run. For typical SRL-2018 DC runs the audit
  log is < 250 KB; not a storage concern.
- Verifier surface is now three checks rather than one. Mitigated by
  keeping `verify_seal.py` self-contained and dependency-free.

## Implementation references

- `src/agentropix_sift/courtroom.py` — `seal_audit_log`,
  `verify_audit_seal`, `read_audit_log_jsonl`, `write_sealed_session`,
  `_canonical_for_audit_seal`.
- `src/agentropix_sift/cli.py` — call site, replaces
  `write_sealed_report` with `write_sealed_session`; drains
  `AGENTROPIX_AUDIT_LOG` JSONL at session end; echoes audit-log path.
- `scripts/verify_seal.py` — extended with audit-log seal verification
  and cross-bind check; exit codes preserved (0/1/2).
- `tests/unit/test_courtroom.py` — 21 new tests across `TestSealAuditLog`,
  `TestReadAuditLogJsonl`, `TestWriteSealedSession` covering seal
  round-trip, single-byte tamper, reorder, addition, removal, metadata
  tamper, key mismatch, JSONL drain, cross-bind, swap-attack rejection,
  empty audit log, and `write_sealed_report` backwards-compat.

## Future work (deferred — not blocking)

- **RFC 3161 trusted timestamp** on the session-key file at session
  end. Would close the "operator with key forges old report" gap.
- **Hardware-rooted attestation** (TPM, SEV-SNP) for the MCP server
  process, so the audit log can be bound to a measured boot.
- **Append-only filesystem mode** for the on-disk JSONL (e.g.
  `chattr +a`) to make pre-seal tampering harder while a run is in
  flight.

These are tracked as latent work in SIFT-WEAKNESSES under the
"chain-of-custody depth" theme; none is required to clear the
hackathon rubric.
