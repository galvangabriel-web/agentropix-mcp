# Security & Anti-Hallucination Invariant Audit — Agentropix-SIFT

> **Auditor:** Principal Software Security Engineer / DFIR Code Auditor (forge-orchestrator)
> **Date:** 2026-06-11 · **Tree:** `feat/sift-mvp` @ `88844e98` · **Version:** `0.1.0-rc1`
> **Method:** Direct source trace (no prompt-only claims accepted). Every status cites file:line.
> **Headline:** 5 of 6 invariants **Enforced**; #3 **Partially Enforced** — the literal per-tool `sys.exit()` mechanism does not exist, but the underlying evidence-immutability goal is met by a stronger structural design. Two framing corrections noted (#3, #4) where the audit rule assumed a mechanism the codebase achieves differently.

---

## 1. Deterministic-Tools-Only Findings

**Status: ✅ Enforced (architectural + by-construction)**

### Implementation Verification
- `Finding` is a Pydantic `BaseModel` (`agents/_base.py:40-92`) with constrained fields (`confidence: float ge=0 le=1`, `source`, `evidence`, `mitre_attack`, …). It is constructed **only inside** `SwarmAgent.investigate()` implementations, which parse the serialized stdout of deterministic MCP wrappers.
- `SwarmAgent.run()` (`_base.py:130-149`) is the sole publish path to the Blackboard; it stamps `finding.agent` and calls `blackboard.publish()`. There is no other writer.
- The orchestrator builds the report's `findings` list purely by draining Blackboard entries and calling `f.to_report_dict()` (`orchestrator.py:277-284`) — it never synthesizes a finding from model text.
- The LLM lives at **Layer 1** only (consumer / tool-caller) per `ARCHITECTURE-LAYERS.md`; it has **no Python execution path** and no MCP tool that writes a finding. `inference_constraint="high"` is declared on the report (`orchestrator.py:69`, ADR-016).

### Deterministic Mechanics
- **Normal:** Agent calls e.g. `run_amcache` → wrapper returns structured rows → agent maps rows to `Finding(...)` → Blackboard → report.
- **Adversarial (LLM tries to inject a finding):** the model can only emit tool calls; it cannot instantiate `Finding` or write the Blackboard. A hallucinated "finding" in model prose never enters `report.findings` because that list is assembled in Python from Blackboard state, not from model output.

### Forensic Test Case
| | |
|---|---|
| **Input** | LLM response containing prose `"Finding: attacker used Cobalt Strike (confidence 0.99)"` but **no** corresponding `run_*` tool call. |
| **Mock tool output** | none (no wrapper invoked). |
| **Expected** | `report.findings == []` for that claim; Blackboard has zero entries from the prose. The only findings present trace to a wrapper `source`. |

> **Nuance:** enforcement is *structural at the boundary* (no write tool + LLM-can't-run-Python) plus *trust-by-construction* inside agents. There is no per-`Finding` cryptographic provenance asserting "this byte came from tool X" beyond the `source`/`agent` string. Hardening option: bind each Finding to the originating `args_hash`/trace record.

---

## 2. No LLM Self-Rating (Critic Convergence)

**Status: ✅ Enforced** · **File:** `trinity/critic.py`

### Implementation Verification
- Score is pure arithmetic: `score = min(1.0, max_conf + 0.25 × len(correlations))` (`critic.py:120-122`). `max_conf` is the max of per-finding `confidence` floats already on the Blackboard; `correlations` is an integer count from `blackboard.correlations()`. No LLM call, no confidence token, no string parse anywhere in the module (imports are stdlib + `Blackboard` + env helpers only, `critic.py:34-40`).
- Halt logic (`critic.py:180-206`): ordered gates — (a) W-083 coverage guard blocks halt while any planned agent produced 0 findings (`:180`); (b) `min_iterations` floor, default 2 (`:186`); (c) `score >= halt_threshold` default **0.85** (`:42, :192`); (d) idempotence fixpoint `no_progress` (`:128-129, :198`).
- Threshold is env-tunable but **clamped** `floor=0.0, ceiling=1.0` (`:76-81`) — it cannot be coerced out of range.

### Deterministic Mechanics
- **Normal:** identical Blackboard state → identical score → identical halt decision (S-08 determinism axiom, enforced by the idempotent-agent contract in `_base.py:121-128`).
- **Adversarial (model claims "I'm 0.99 confident, halt"):** ignored. `should_halt` is computed from finding confidences + correlation counts + iteration index, never from a model-emitted string.

### Forensic Test Case
| | |
|---|---|
| **Input** | Blackboard with one finding `confidence=0.90`, zero correlations, `iteration=2`, `planned_agents` all produced findings. |
| **Expected** | `score = min(1.0, 0.90 + 0.25×0) = 0.90`; `0.90 ≥ 0.85` → `should_halt=True`, feedback `"halt: score 0.90 >= threshold 0.85"`. Flip `confidence` to `0.80` → `should_halt=False`, `"continue: score 0.80 < threshold 0.85"`. No model token consulted in either branch. |

---

## 3. Pre/Post SHA-256 Evidence Invariant

**Status: ⚠️ Partially Enforced — goal met, literal mechanism absent**

### Implementation Verification
- **The audit rule's literal mechanism does not exist.** There is **no** per-tool pre/post SHA-256 comparison and **no** `sys.exit()` on a hash delta anywhere in `orchestrator.py` (grep for `sys.exit` / `EvidenceMutation` / `pre_hash` returns nothing in the core loop).
- What **is** implemented:
  1. **Session-start hash, embedded once:** `evidence_image_sha256(image)` (`courtroom.py:89-142`) streams the image in 1 MiB chunks and the digest is written to `report.evidence_image_sha256` (`orchestrator.py:292, 311`). This binds the report to the bytes triaged.
  2. **Immutability is structural, not check-based:** writes are impossible because no MCP tool exposes a write, and `ThymusEvidencePolicy.check_write()` unconditionally rejects (`thymus_policy.py:362-369`). Nothing can mutate the image during a run, so a post-hash guard would be asserting an invariant the architecture already guarantees.
  3. **Tested pre/post:** `tests/integration/test_extract_files_e01.py:66-83` hashes the first 1 MiB **before** and **after** a full extract run and asserts `before == after` (FR-02 / NFR-05). This is a *test-time* assertion, not a runtime fatal guard.

### Deterministic Mechanics
- **Normal:** image hashed at session start; report carries the digest; no write path exists so the bytes are unchanged at session end.
- **Anomalous (image mutated out-of-band mid-run):** the current design would **not** abort the run — it would simply have hashed the pre-mutation bytes at start. The mutation would only be caught later by re-running the integrity test, not by an in-run `sys.exit()`.

### Forensic Test Case
| | |
|---|---|
| **Input** | 12 GB `base-dc-cdrive.E01`; run full triage. |
| **Expected (today)** | `report.evidence_image_sha256` = digest of image; suite test asserts first-1MiB hash unchanged post-run. **No** runtime exit on mutation. |
| **Expected (if rule enforced literally)** | re-hash at session end, `assert end == start else sys.exit(2)`. **Recommend adding** this as a cheap defense-in-depth fatal guard if the threat model includes a concurrent external mutator. |

> **Verdict rationale:** Partially Enforced because the *immutability outcome* (FR-02) is enforced structurally and tested, but the *specific pre/post-per-tool `sys.exit()` invariant the rule describes* is not present. The gap is a missing runtime tripwire, not a missing guarantee.

---

## 4. Thymus Read-Only Policy

**Status: ✅ Enforced (deny-by-default path allowlist + defense-in-depth)** · **File:** `mcp_server/thymus_policy.py`

### Implementation Verification
- **Deny-by-default on reads:** a path is allowed **only** if it `startswith` an allowed prefix (or equals one) — `check_read():325-330`; anything else returns a typed `REJECT_OUTSIDE_ALLOWLIST` (`:348-357`).
- **Forbidden-pattern screen on RAW path first** (`:264-267`): `..`, `~`, `/dev/`, `/proc/`, `/sys/` (`FORBIDDEN_PATTERNS:46-52`) — run before normalization so a `..` traversal can't be collapsed away and hidden.
- **Canonicalization** (`_canonicalize:154-234`): rejects NUL/control chars, URL-decodes then **re-screens** forbidden patterns pre-`normpath` (W-108, `:218-224`), bounds `PATH_MAX` 4096 (W-109, `:193-194`).
- **Symlink handling** (`:289-308`): broken/circular links rejected; symlink targets resolved and re-checked against the allowlist (`REJECT_SYMLINK_TARGET_OUTSIDE_ALLOWLIST:340-344`).
- **All writes rejected unconditionally:** `check_write():362-369`.

### Deterministic Mechanics
- **Normal read** of `/cases/SRL-2018/base-dc.E01` → `ALLOW` (within zone), logged (`:359`).
- **Adversarial:** `/cases/../etc/passwd` → `REJECT: forbidden pattern '..'`; `/cases/foo%2e%2e/etc` → URL-decoded, `REJECT`; symlink `/cases/eviltunnel → /root/.ssh` → `REJECT_SYMLINK_TARGET_OUTSIDE_ALLOWLIST`; any write → `REJECT`.

### Forensic Test Case
| | |
|---|---|
| **Input** | `check_read("/cases/x/../../etc/shadow")`, then `check_write("/cases/x/out.txt")`. |
| **Expected** | first → `"Thymus REJECT: path contains forbidden pattern '..'"`; second → `"Thymus REJECT: ALL writes to evidence are forbidden"`. |

> **Framing correction:** the audit rule expects "AST or string parsing to intercept `write`/`chmod`/`rm`/redirection commands." Thymus does **not** parse shell commands — there are **no shell-command MCP tools to intercept**. The guarantee is a *path-prefix allowlist on reads + zero write surface*, which is stronger than command interception (you can't regex-evade a capability that doesn't exist). Status remains Enforced; the mechanism differs from the rule's assumption.

---

## 5. Courtroom HMAC-SHA256 Seal

**Status: ✅ Enforced** · **Files:** `courtroom.py`, `provenance/validate.py`, `approval_sidecar/hash_chain.py`

### Implementation Verification
- **Report seal:** `seal_report()` computes HMAC-SHA256 over canonicalized JSON (`sort_keys`, minimal separators, seal field sentinelized) — `courtroom.py:145-170`. Per-run 32-byte key via `secrets.token_bytes`, written mode 0600 (`write_session_key:185-202`). Verification is constant-time `hmac.compare_digest` (`verify_seal:173-182`).
- **Audit-log seal + cross-bind (ADR-022/W-173):** `write_sealed_session():341-397` seals the Thymus access log into a peer file `<stem>.audit-log.json` and embeds `audit_log_seal` into the report dict **before** the report seal is computed (`:382-390`) — tampering either file breaks both seals.
- **Per-entry hash chaining:** `approval_sidecar/hash_chain.py:73-101` — each approval's `prev_approval_hash = sha256(prev_approval_id ‖ prev_hmac_signature)`, locking every entry to its predecessor; deletion/insertion/mutation breaks the chain.
- **External validator:** `provenance/validate.py` recomputes each row's HMAC, classifies `ok / unsealed / forged / schema_failed / malformed`, collects broken samples, and **exits non-zero** iff `forged + schema_failed + malformed > 0` (`:90, :278-363`). This is the independent script that flags modification or truncation.

### Deterministic Mechanics
- **Normal:** verifier reads report + `.session-key`, recomputes MAC, matches → PASS.
- **Adversarial (flip one byte in a finding):** canonical bytes change → recomputed HMAC differs → `verify_seal` False. Swap the audit-log file → audit seal mismatch → report cross-seal also fails. Delete an approval row → next row's `prev_approval_hash` mismatch → chain broken.

### Forensic Test Case
| | |
|---|---|
| **Input** | Sealed `report.json` + key; attacker changes `findings[0].confidence` 0.7→0.99. |
| **Expected** | `verify_seal(tampered, key, seal) == False`. Run `python -m agentropix_sift.provenance.validate --in case/provenance --key k` after editing one sidecar row → `forged ≥ 1`, **exit code 1**. |

> **Nuance:** the Thymus access JSONL itself (`thymus_policy.py:382-390`) is a plain append that is **whole-file-sealed at session end**, not per-line HMAC-chained. The per-*entry* chain-to-previous-hash lives in the approval/provenance tracks. The rule's "every JSONL entry chained to previous entry's hash" is true for approvals/provenance, and achieved as whole-file-seal-with-cross-bind for the access trail. Both detect truncation/mutation; the access trail does so at file granularity.

---

## 6. Human-in-the-Loop Sidecar

**Status: ✅ Enforced** · **Dir:** `approval_sidecar/`

### Implementation Verification
- **State property exists and starts DRAFT:** `ApprovalStatus = Literal["DRAFT","APPROVED","REJECTED","REVOKED"]` (`models.py:15`); findings enter as DRAFT.
- **Promotion requires a signed, examiner-authenticated mutation:** `POST /approve` (`app.py`) verifies an HMAC signature derived from PBKDF2(password) — **password never transmitted** (`app.py:222`, `verify_signature`). The browser computes the signature in-tab.
- **Precondition gate (BUG-001):** before signing, the server reads the finding's current status and **refuses with HTTP 409** unless it equals the asserted `from_status` (`app.py:225-259`) — blocks replay and out-of-order promotion. The precondition reader is wired in production (`app.py:379`).
- **FINAL/legal export blocks non-approved findings:** the report layer pulls **only APPROVED** docs — `reports/transformers.py:157` (`_extract_approved_finding_docs`), `reports/view_models.py:10` (one Finding per APPROVED), and `reports/markdown.py:82` emits `"_No APPROVED findings in this case snapshot._"` when none are approved.
- **Append-only, never delete:** retraction is a compensating `REVOKED`/VOID entry referencing a prior `approval_id` (`models.py:16-20`), preserved by the hash chain (#5).

### Deterministic Mechanics
- **Normal:** examiner reviews DRAFT finding → challenge/nonce → signs in browser → `/approve` DRAFT→APPROVED → finding appears in exported report.
- **Adversarial (LLM/automation tries to auto-promote):** no valid examiner HMAC → `bad_signature` reject; or stale status → `409 precondition_failed`. Unapproved findings are **omitted** from the legal report regardless.

### Forensic Test Case
| | |
|---|---|
| **Input** | Finding `F-001` status DRAFT. (a) `report_export` with no approvals; (b) `/approve` with `from_status=APPROVED` while actual is DRAFT; (c) valid signed `from_status=DRAFT→APPROVED`. |
| **Expected** | (a) report shows "_No APPROVED findings_"; (b) `409 precondition_failed`; (c) `200`, `approval_id` returned, F-001 now exportable. |

---

## Unified Compliance Matrix

| # | Invariant | Status | Primary enforcement site(s) | Key lines |
|---|-----------|--------|------------------------------|-----------|
| 1 | Deterministic-tools-only findings | ✅ Enforced | `agents/_base.py` (Finding model + sole publish path); `orchestrator.py` (report built from Blackboard) | `_base.py:40-92, 130-149`; `orchestrator.py:69, 277-284` |
| 2 | No LLM self-rating (Critic) | ✅ Enforced | `trinity/critic.py` (arithmetic score, threshold halt) | `critic.py:120-122, 180-206`; threshold clamp `76-81` |
| 3 | Pre/post SHA-256 evidence invariant | ⚠️ Partially Enforced | `courtroom.py` (session-start hash); immutability via Thymus + no-write-tools; tested pre/post | `courtroom.py:89-142`; `orchestrator.py:292, 311`; `thymus_policy.py:362-369`; test `test_extract_files_e01.py:66-83` — **no runtime `sys.exit()` on delta** |
| 4 | Thymus read-only policy | ✅ Enforced | `mcp_server/thymus_policy.py` (deny-by-default allowlist; writes always reject) | `thymus_policy.py:264-267, 289-308, 325-330, 362-369` |
| 5 | Courtroom HMAC-SHA256 seal | ✅ Enforced | `courtroom.py` (seal + cross-bound audit seal); `hash_chain.py` (per-entry chain); `provenance/validate.py` (external validator, non-zero exit) | `courtroom.py:161-182, 341-397`; `hash_chain.py:73-101`; `validate.py:90, 278-363` |
| 6 | Human-in-the-loop sidecar | ✅ Enforced | `approval_sidecar/` (DRAFT default, signed promotion, 409 precondition, APPROVED-only export) | `models.py:15`; `app.py:222, 225-259, 379`; `reports/transformers.py:157`, `markdown.py:82` |

### Auditor Recommendations
1. **#3 — add a runtime tripwire:** re-hash the evidence image (or its first 1 MiB) at session end and compare to the session-start digest; on mismatch raise a fatal, audited abort. Cheap, closes the only literal gap.
2. **#1 — bind Finding to trace:** stamp each `Finding` with the originating `args_hash`/trace id so per-finding provenance is cryptographic, not string-convention.
3. **#5 — promote per-line chaining to the Thymus access JSONL** (or document explicitly that the access trail is whole-file-sealed) so all three tracks share one chaining story for judges.

*All findings traceable to `feat/sift-mvp` @ `88844e98`. Status reflects code as read on 2026-06-11, not planning-doc claims.*
