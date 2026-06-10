# Observability & Integrity — Known Limitations

> **Section 07 · SDLC & Ops** — two honest negatives, stated plainly.
> Related: [Security Model](security-model.md) ·
> [Anti-Hallucination](../05-safety-forensics/anti-hallucination.md) ·
> [Audit & Courtroom Sealing](../05-safety-forensics/audit-courtroom.md) ·
> [Persisted Artifacts](../03-data/persisted-artifacts.md)

## How to read this page

This page documents **two things the system does NOT do**, why each is a deliberate
trade-off rather than an oversight, and (where one exists) the manual workaround. Both
were confirmed by exhaustive source-level triage of the engine
(`src/agentropix_sift/`) and the vendored portal package
(`agentropix_mcp/src/agentropix_mcp/`) on 2026-06-10 — every "exists / does not exist"
claim below cites the file and line range it was verified against. Nothing on this page
describes a planned feature as shipped. If any other portal page appears to claim either
capability as implemented runtime behavior, **this page wins** (and that page is a bug —
see [`docs/issues/CASE-GUIDE-AUDIT.md`](../issues/CASE-GUIDE-AUDIT.md) conventions).

| Limitation | Status | Workaround |
|---|---|---|
| [1. No automated post-run evidence re-hash](#1-no-automated-post-run-evidence-re-hash) | Not implemented (pre-hash IS implemented) | Manual re-hash vs the report's embedded digest — recipe below |
| [2. No token-usage metrics](#2-no-token-usage-metrics) | Not collected, by design | None needed — token accounting belongs to the MCP client, not the engine |

---

## 1. No automated post-run evidence re-hash

### What IS implemented (the "pre" half)

The evidence image is hashed **once, at session start**, and that digest is bound into
the sealed report:

- `courtroom.py:89-142` — `evidence_image_sha256()` computes the full SHA-256 of the
  evidence image ("hash the evidence image at session start", `courtroom.py:8-12`).
- `orchestrator.py:292` — the **single** call site; the digest is embedded in the report
  at `orchestrator.py:311` and echoed by the CLI (`cli.py:150-151`).
- The 🖥️ `evidence_register` MCP tool independently hashes evidence at registration time
  (`mcp_server/wrappers/case_lifecycle.py:413-489`, with dedup on
  `(case_id, path, sha256)`).
- The read-only **Thymus** boundary denies writes to evidence before any tool executes,
  and the HMAC courtroom seal protects the *report and audit log*
  (`courtroom.py:161-397`, `audit/verify_seal.py`).

### What is NOT implemented (the "post" half)

**There is no automated post-run re-hash-and-compare, and no abort-on-mismatch path,
anywhere in the runtime.** An exhaustive grep of `src/agentropix_sift/` for
`rehash`/`post_hash`/`recompute`-style routines found zero post-run evidence re-hash
code — the only digest recomputation in the tree is the HMAC *seal* recompute
(`wrappers/master_iocs_aggregator.py:604`) and the evidence-gate *token*-hash compare
(`evidence_gate/registry.py:296-299`), neither of which touches the evidence image. The
vendored portal copy was checked too: `agentropix_mcp/src/agentropix_mcp/courtroom.py`
is byte-identical to the engine's, so no post-run routine hides there either.

The "post" half of the pre/post invariant exists in exactly three weaker forms:

1. **Structural** — the Thymus read-only boundary makes evidence mutation by the
   pipeline impossible by construction, so a post-run hash *cannot* differ unless the
   evidence was altered out-of-band.
2. **CI-tested, on a sample** — `tests/integration/test_extract_files_e01.py:66-82`
   (`test_evidence_hash_unchanged`) hashes the **first 1 MiB** of the E01 before and
   after `extract_files` and asserts equality. This matches the engine's own framing
   ("SHA-256 of first 1 MiB unchanged post-triage" via tests, `docs/MASTER-PLAN.md:126`;
   "integration tests assert SHA-256 identity pre/post",
   `docs/PROJECT-ONBOARDING.md:177`). It is a 1 MiB header sample in CI — **not** a
   full-image check and **not** a runtime guarantee.
3. **Manual / offline** — because the full-image digest is embedded in every sealed
   report, *any* party can re-verify at any time. Recipe below.

### Why (the rationale)

Re-hashing a multi-gigabyte container (a 50 GB E01 is routine) after **every** run
roughly doubles wall-clock time — to confirm an invariant the read-only architecture
already makes structurally redundant. The embedded `evidence_image_sha256` was judged
the better control: it is cheap (paid once), it travels with the sealed report, and it
lets a judge, opposing examiner, or auditor re-verify offline **without trusting the
runtime at all**. The portal's
[Anti-Hallucination §4](../05-safety-forensics/anti-hallucination.md) already frames the
post side in exactly this register: *re-hashing the image after a run must reproduce the
same digest* — it is something a **verifier does**, not something the runtime does.

### Manual workaround — re-verify the digest yourself

> **🖥️ Expert (command):**
> ```bash
> sha256sum /cases/<your-image>.E01
> # compare against evidence_image_sha256 in the sealed report.json,
> # and/or the digest recorded by evidence_register for the case
> ```
> Or use the real MCP tool: 🖥️ `run_hashdeep` (`wrappers/hashdeep.py:155`) for a
> hashdeep-format audit of the evidence path.
>
> **💬 End-user (prompt):** *"Re-hash the evidence image for case X with hashdeep and
> tell me if it still matches the registered SHA-256."*
> (Maps to the real `run_hashdeep` + `evidence_register` tools — verified in the
> [tool list](../04-mcp-tools/tool-list.md).)

A mismatch means the evidence was altered **out-of-band** (outside the pipeline) — the
embedded digest makes that detectable after the fact; it does not prevent it.

> **GOTCHA — do not over-read the CI test.** `test_evidence_hash_unchanged` samples only
> the first 1 MiB of the E01 header. It is a regression tripwire for the extraction
> wrapper, not a full-image integrity check. The full-image claim rests on the
> session-start digest + the manual recipe above.

---

## 2. No token-usage metrics

**The engine collects no LLM token-usage metrics — by design, not omission.** A grep
over `src/` for `token_usage` / `input_tokens` / `output_tokens` / `prompt_tokens` /
`completion_tokens` returns **zero code hits**. The only matches in the entire oracle
are design-era documents: `docs/prd.md:1330` (**FR-MET-02**, a planned token-budget pool
decrement) and research sketches (`docs/research-technical-2026-01-01.md:899-907`,
`docs/test-design.md:272`).

> **Reconciliation note (earlier draft vs shipped).** The PRD *designed* token
> accounting (FR-MET-02); the shipped system does **not** implement it. No portal page
> should imply otherwise.

### Why this is architectural, not a gap to backfill

The deterministic engine never sees a token. In this architecture the **LLM is the edge
consumer**: Claude (Desktop / CLI / any MCP client) calls the server's deterministic
tools over MCP, and token consumption happens entirely **client-side**, between the user
and their model provider. The server is a token-blind, deterministic tool executor —
instrumenting it for tokens would measure nothing it can observe. Token accounting, if
wanted, belongs to the MCP client / provider console, which already owns those counters.

### The runtime telemetry that DOES exist

What the engine *does* instrument — and seals — is its own deterministic work, per tool
call, inside the report's trace:

- `trace.tool_calls[]` — one entry per call with exactly four fields: `tool`,
  `timestamp`, `duration_ms`, `result_summary` (e.g. 245 entries in the sealed
  W-238 run report).
- `trace.counters` — engine-side work counters such as `jsonl_rows_read` and
  `detectors_fired_by_id`.
- `thymus_audit[]` and `iterations[]` — policy decisions and per-iteration swarm
  plans / critic scores.

All of it lives inside the HMAC-sealed `report.json` — see
[Persisted Artifacts](../03-data/persisted-artifacts.md) and
[Audit & Courtroom Sealing](../05-safety-forensics/audit-courtroom.md) for the seal
mechanics. In short: **per-tool `duration_ms` and work counters are the system's
telemetry; tokens are the client's.**

---

## See also

- [Security Model](security-model.md) — the full defends / does-not-defend boundary.
- [Anti-Hallucination](../05-safety-forensics/anti-hallucination.md) — §4 on the
  pre-hash digest as the "pre" side of the invariant.
- [Audit & Courtroom Sealing](../05-safety-forensics/audit-courtroom.md) — HMAC seal
  and offline verification.
- [Tool list](../04-mcp-tools/tool-list.md) — `run_hashdeep`, `evidence_register`.
- [CANONICAL_FACTS](../08-reference/canonical-facts.md) — governing numbers.
