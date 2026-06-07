# Use Case — Examiner Reviews and Approves Findings Before the Seal

> **Actors:** the analyst/agent (stages findings) and a **human examiner** (approves them).
> **Goal:** Move a finding from agent-authored **DRAFT** to examiner-signed **APPROVED** before any
> report is generated — so the LLM can never self-approve, and only HMAC-signed approvals reach the
> sealed report.
> **Surfaces exercised:** `record_finding` / `delete_finding` (`wrappers/case_records.py`),
> `approve_finding` / `retract_approval`, and the **HMAC approval sidecar**
> (`approval_sidecar/`). See [`tool-list.md`](../04-mcp-tools/tool-list.md) and
> [`env-vars.md`](../07-sdlc-ops/env-vars.md) §Approval-sidecar.
>
> **Doing the approval in the browser?** The step-by-step
> [Approval Portal walkthrough](../05-safety-forensics/approval-portal.md)
> (screenshot, every field, how to submit) covers the human side of this use case.

> **How to read this page (two audiences at once).** Like the
> [gold-standard user guide](../01-overview/user-guide.md), every operator action below is shown
> **both** ways in an eye-catching callout:
> - **🖥️ Expert (command):** the exact CLI / MCP / `curl` call to type.
> - **💬 End-user (prompt):** the plain-language question to type into a Claude session that has the
>   Agentropix MCP connected. A simple, focused question is enough — the session recognises it as an
>   Agentropix capability and routes it to the right MCP tool automatically.
>
> The **Execution → Output** blocks in [§Walkthrough](#walkthrough--gate-challenge-approval-resumed-run)
> label what you **run** vs what you **get back**. All nonces, tokens, salts, signatures and approval
> IDs are **placeholders** (`<nonce>`, `<egt-token>`, `<signature-hex>`, `<approval-id>`) — never paste
> a real secret into a tracked file.

This is the chain-of-custody spine that separates DRAFT analysis from a court-defensible report.
Every finding enters as **DRAFT** through the W-286 draft-gate (which strips any caller-supplied
`approval.*` field — the LLM cannot stamp its own approval), and only an HMAC-signed approval
routed to the W-288 sidecar promotes it. Report generation/export filter to **APPROVED only**, so
the approval step is load-bearing and must precede report tiers
(`docs/guides/playbooks.md` §C; `docs/guides/end-to-end-scenario.md` §Phase 5).

---

## Contents — what's in this page (and what to expect)

> Jump to any section below. Each row tells you what that part gives you, so you can go straight to your point.

| Section | What you'll get |
|---|---|
| [Use-case diagram](#use-case-diagram) | The actor/tool map showing who can do what — analyst stages DRAFTs, only the examiner approves, APPROVED flows to the sealed report. |
| [Sequence — DRAFT → APPROVED → sealed report](#sequence--draft--approved--sealed-report) | The full handshake timeline: draft-gate write, two-leg sidecar challenge/approve, then APPROVED-only generation and seal. |
| [Actor, preconditions, steps, postconditions](#actor-preconditions-steps-postconditions) | The runbook: actors, what must be true first, numbered steps (expert command + end-user prompt), and the guaranteed end state. |
| [Walkthrough — gate challenge, approval, resumed run](#walkthrough--gate-challenge-approval-resumed-run) | Copy-pasteable Execution → Output transcripts for the `/challenge` nonce, signed `/approve`, the resumed report, and retraction. |
| [See also](#see-also) | Links to where DRAFT findings originate, downstream IOC push, and the tool/module references. |

---

## Use-case diagram

```mermaid
graph TD
    analyst([Analyst / Agent])
    examiner([Human Examiner])

    subgraph Agentropix-SIFT
        UC1["record_finding<br/>(DRAFT, mutation_token)"]
        UC2["delete_finding<br/>(DRAFT-only self-correct)"]
        UC3["case_status<br/>(DRAFT/APPROVED/REJECTED counts)"]
        UC4["approve_finding<br/>(HMAC -> sidecar)"]
        UC5["retract_approval<br/>(compensating, append-only)"]
        UC6["report_generate / report_export<br/>(APPROVED only)"]
        UC7["report sealed<br/>(courtroom HMAC-SHA256)"]
    end

    analyst --> UC1
    analyst --> UC2
    analyst --> UC3
    examiner --> UC4
    examiner --> UC5
    UC4 --> UC6
    UC6 --> UC7

    classDef actor fill:#d0bfff,stroke:#7048e8,color:#2b1a52
    classDef api fill:#a5d8ff,stroke:#1971c2,color:#0b2545
    classDef core fill:#b2f2bb,stroke:#2f9e44,color:#15391f
    classDef gov fill:#ffc9c9,stroke:#e03131,color:#5c1a1a
    classDef sink fill:#ffec99,stroke:#f08c00,color:#5c4400

    class analyst,examiner actor
    class UC1,UC2,UC3 api
    class UC4,UC5 gov
    class UC6 core
    class UC7 sink

    style Agentropix-SIFT fill:#f1f3f5,stroke:#868e96,color:#212529
```

> 🔍 **[Open as SVG — full size, zoomable](assets/uc-approval-gate-1.svg)** (renders larger than the page column; the SVG zooms losslessly in a browser tab).

The analyst stages DRAFT findings and can self-correct an over-count with `delete_finding`
(DRAFT-only). The **examiner** — a separate human actor — issues the HMAC-signed `approve_finding`,
the only edge that promotes a finding to APPROVED. `retract_approval` is the compensating,
append-only reversal (ADR-016/022). Only APPROVED findings flow into `report_generate` /
`report_export`, which are then sealed by the courtroom.

---

## Sequence — DRAFT → APPROVED → sealed report

```mermaid
sequenceDiagram
    autonumber
    actor Agent
    actor Examiner
    participant MCP as FastMCP server
    participant Gate as EvidenceGate (mutation_token)
    participant Side as Approval sidecar (W-288)
    participant Chain as sidecar hash-chain
    participant Court as courtroom.seal_report

    Agent->>MCP: record_finding(finding, dry_run=true)
    MCP-->>Agent: preview (W-286 draft-gate strips approval.*)
    Agent->>MCP: record_finding(finding, dry_run=false, mutation_token=egt_...)
    MCP->>Gate: verify + spend one-shot token
    Gate-->>MCP: ok
    MCP-->>Agent: DRAFT document (status + provenance stamped)
    Agent->>MCP: case_status()
    MCP-->>Agent: {DRAFT: N, APPROVED: 0, REJECTED: 0}

    Examiner->>MCP: approve_finding(finding_id, approver_id, password,<br/>from_status=DRAFT, to_status=APPROVED)
    MCP->>MCP: compute PBKDF2 + HMAC-SHA256 from password
    MCP->>Side: POST /challenge (examiner, target) -> nonce
    Side-->>MCP: nonce + PBKDF2 params
    MCP->>Side: POST /approve (signed envelope + nonce)
    Side->>Chain: append APPROVED transition (hash-chained)
    Chain-->>Side: chained row
    Side-->>MCP: ApprovalSubmitResponse (APPROVED)
    MCP-->>Examiner: signed approval result

    Agent->>MCP: report_generate(profile="full")
    MCP-->>Agent: payload (APPROVED findings only)
    Agent->>MCP: report_export(tier="analyst", fmt="md")
    MCP->>Court: seal_report (HMAC-SHA256 over canonical report)
    Court-->>Agent: {tier, fmt, mime, path, content} (tamper-evident)
```

Findings are staged with `dry_run=true` first for preview, then committed with `dry_run=false` and a
valid one-shot `mutation_token` (`egt_<ULID>` from `AGENTROPIX_MUTATION_TOKEN`); the **W-286
draft-gate** strips any `approval.*` and stamps `DRAFT` + provenance, so the agent surface cannot
self-approve. Approval is a **two-leg sidecar handshake**: the MCP server first `POST /challenge`s for
a nonce bound to `(examiner, target)`, then `POST /approve`s the PBKDF2 + HMAC-SHA256-signed envelope
(`approval_sidecar/models.py` — `ChallengeRequest`/`ApprovalSubmitRequest`, `from_status`/`to_status`
∈ `DRAFT|APPROVED|REJECTED|REVOKED`). The DRAFT→APPROVED transition lives in the sidecar's
append-only **hash-chain**, never in the LLM. Report generation/export then filter to APPROVED and
seal with `courtroom.seal_report`.

> **Documented caveat (from the `approve_finding` docstring):** in this MVP flow the `password`
> transits the LLM request context for the call duration. Operators uneasy with that wait for the
> Phase-2 browser approval UI (`approval_sidecar/static/`). The `password` is consumed once and
> dropped after the HMAC is computed.

---

## Actor, preconditions, steps, postconditions

**Actors:**
- **Analyst / agent** — stages and self-corrects DRAFT findings.
- **Human examiner** — the only actor who can approve; holds the PBKDF2 credentials.

**Preconditions**

- An active case exists (`case_init` / `case_activate`); the active-case pointer lives at
  `~/.agentropix/active_case`.
- A valid one-shot mutation token is available for the live `record_finding` write
  (`agentropix-sift evidence-gate mint` → `AGENTROPIX_MUTATION_TOKEN`).
- The approval sidecar is running and reachable (`AGENTROPIX_APPROVAL_SIDECAR_URL`, default
  `http://127.0.0.1:8800`).
- The examiner's PBKDF2 identity is configured and **stable across restarts**:
  `AGENTROPIX_APPROVER_USER`, `AGENTROPIX_APPROVER_PASSWORD`, `AGENTROPIX_APPROVER_SALT_HEX`
  ([`env-vars.md`](../07-sdlc-ops/env-vars.md) §Approval-sidecar). A changed salt/password
  invalidates the hash-chain continuity.

**Numbered steps**

1. *(Analyst)* `record_finding(finding, dry_run=true)` — preview the staged DRAFT.
2. *(Analyst)* `record_finding(finding, dry_run=false, mutation_token=egt_...)` — commit the DRAFT
   (idempotent on `(case_id, finding_id)`). Self-correct an over-count with
   `delete_finding(finding_id, dry_run=false)` (DRAFT-only).
3. *(Analyst)* `case_status()` — confirm the DRAFT/APPROVED/REJECTED counts before approval.
4. *(Examiner)* `approve_finding(finding_id, approver_id, password, from_status="DRAFT",
   to_status="APPROVED", reason="...")` — the HMAC-signed seal; repeat per finding.
5. *(Analyst)* `report_generate(profile="full")` then `report_export(tier=..., fmt=...)` — render the
   APPROVED-only report and seal it.

Each step is shown in both audiences below. The Execution → Output transcript for the load-bearing
trio — **gate challenge → approval → resumed (APPROVED-only) report run** — is in
[§Walkthrough](#walkthrough--gate-challenge-approval-resumed-run).

#### Step 1–2 — Stage the DRAFT finding *(Analyst)*

> **🖥️ Expert (command):** first mint the one-shot mutation token the live write needs, then call the
> `record_finding` MCP tool (preview, then commit):
> ```bash
> # Mint the one-shot mutation token (prints egt_<26-char-ULID>); export it for the write
> export AGENTROPIX_MUTATION_TOKEN=$(agentropix-sift evidence-gate mint --emit token)
> ```
> ```jsonc
> // MCP tool call — preview (no token spent)
> record_finding(finding={...}, dry_run=true)
> // MCP tool call — commit the DRAFT (spends the one-shot token)
> record_finding(finding={...}, dry_run=false, mutation_token="egt_<ULID>")
> ```
> **💬 End-user (prompt):** *"Record this as a draft finding on the active case: <your finding>."*
> The session routes to the **`record_finding`** MCP tool, previews, and commits the DRAFT. The
> **W-286 draft-gate** strips any `approval.*` you (or the LLM) try to supply — the agent surface
> cannot self-approve.

#### Step 3 — Confirm the counts before approval *(Analyst)*

> **🖥️ Expert (command):**
> ```jsonc
> case_status()   // MCP tool call
> ```
> **💬 End-user (prompt):** *"How many draft, approved and rejected findings does this case have?"*
> The session routes to the **`case_status`** MCP tool and reports the DRAFT / APPROVED / REJECTED
> counts.

#### Step 4 — Examiner approves (HMAC-signed) *(Examiner)*

> **🖥️ Expert (command):** the single-call MCP path (the server runs the two-leg
> `POST /challenge` → `POST /approve` handshake for you):
> ```jsonc
> approve_finding(
>   finding_id="F-alice-001",
>   approver_id="<examiner>",
>   password="<approver-password>",
>   from_status="DRAFT",
>   to_status="APPROVED",
>   reason="verified against source artifact"
> )   // MCP tool call -> approval_sidecar/
> ```
> Prefer to keep the password out of the LLM context entirely? Drive the **two sidecar endpoints
> directly** with `curl` (or use the [browser Approval Portal](../05-safety-forensics/approval-portal.md)) —
> the raw handshake is enumerated in [§Walkthrough](#walkthrough--gate-challenge-approval-resumed-run).
> **💬 End-user (prompt):** *"Approve finding F-alice-001 on this case as <examiner>."*
> The session routes to the **`approve_finding`** MCP tool. It will need the approver password to sign;
> for a password-free flow, point the examiner at the browser portal instead.

#### Step 5 — Render the APPROVED-only report *(Analyst)*

> **🖥️ Expert (command):**
> ```jsonc
> report_generate(profile="full")            // MCP tool call (APPROVED findings only)
> report_export(tier="analyst", fmt="md")    // MCP tool call -> courtroom.seal_report
> ```
> **💬 End-user (prompt):** *"Generate the analyst report for this case and seal it."*
> The session routes to **`report_generate`** then **`report_export`**, which filter to APPROVED-only
> and seal the artifact with `courtroom.seal_report` (HMAC-SHA256).

**Postconditions**

- The finding is `APPROVED` in the sidecar's append-only hash-chain (PBKDF2 + HMAC-SHA256).
- Only APPROVED findings appear in any report tier; a report run before approval yields only the
  executive/empty shell.
- An accidental approval can be reversed with `retract_approval` — a **compensating, append-only**
  entry (the chain is never edited).
- The exported report is sealed by `courtroom.seal_report` (HMAC-SHA256) and is tamper-evident.

**CLI commands used (operator-local prerequisites)**

These two CLI commands provision the prerequisites; the forensic actions themselves are MCP tool calls.

> **🖥️ Expert (command):**
> ```bash
> # Mint the one-shot mutation token the live record_finding needs
> agentropix-sift evidence-gate mint   # -> egt_<ULID>; export as AGENTROPIX_MUTATION_TOKEN
>
> # Run the approval sidecar (HMAC human-in-the-loop service)
> python -m agentropix_sift.approval_sidecar
> ```
> **💬 End-user (prompt):** *(no prompt — these are operator-local setup steps.)* As an end-user you
> never mint tokens or start services; you just ask the session to record/approve/report and it routes
> the MCP tools. Ask your administrator if the sidecar is not up.

`record_finding`, `case_status`, `approve_finding`, `retract_approval`, `report_generate`, and
`report_export` are **MCP tool calls** issued by the MCP client against the running server — not CLI
subcommands. The CLI commands above provision the two prerequisites (the mutation token and the
sidecar service).

---

## Walkthrough — gate challenge, approval, resumed run

> **Real-data note.** The shapes below are the live request/response schemas
> (`approval_sidecar/models.py`: `ChallengeResponse`, `ApprovalSubmitRequest`, `ApprovalSubmitResponse`;
> `reports/export.py: ExportResult`). Every secret-bearing value is a **placeholder** — `<nonce>`,
> `<salt-hex>`, `<egt-token>`, `<signature-hex>`, `<approval-id>`, `<prev-hash>`. The sidecar binds
> loopback by default (`http://127.0.0.1:8800`, `AGENTROPIX_APPROVAL_SIDECAR_URL`).

### Execution A → Output A — request the gate challenge (nonce)

The first leg binds a single-use nonce to `(examiner, target)`. The MCP `approve_finding` tool does
this for you; the raw call (or the browser portal's client-side fetch) is:

*Execution A (POST /challenge):*
```bash
curl -fsS http://127.0.0.1:8800/challenge \
  -H 'content-type: application/json' \
  -d '{"examiner_id":"<examiner>","target_id":"F-alice-001","target_type":"finding"}'
```

*Output A (`ChallengeResponse` — nonce + PBKDF2 params, TTL ~60 s):*
```json
{
  "nonce": "<nonce>",
  "salt_hex": "<salt-hex>",
  "iterations": 600000,
  "ttl_seconds": 60.0
}
```

> The browser tab (or the MCP server) now derives `PBKDF2(password, salt_hex, iterations)` **locally**
> and computes `HMAC-SHA256` over the canonical signed message
> (`nonce ‖ target_id ‖ target_type ‖ from_status ‖ to_status ‖ case_id`, `auth.py:102`). The password
> is never put on the wire. A nonce older than `ttl_seconds` fails closed → `401 nonce_expired`.

### Execution B → Output B — submit the signed approval

Second leg: send the signature (never the password) with the same nonce.

*Execution B (POST /approve):*
```bash
curl -fsS http://127.0.0.1:8800/approve \
  -H 'content-type: application/json' \
  -d '{"case_id":"INC-2026-0042","target_id":"F-alice-001","target_type":"finding",
       "from_status":"DRAFT","to_status":"APPROVED","examiner_id":"<examiner>",
       "nonce":"<nonce>","signature_hex":"<signature-hex>","reason":"verified against source artifact"}'
```

*Output B (`ApprovalSubmitResponse` — APPROVED, hash-chained):*
```json
{
  "approval_id": "<approval-id>",
  "indexed_to": "agentropix-approvals-2026.06.06",
  "prev_approval_hash": "<prev-hash>",
  "approved_at": "2026-06-06T14:22:31Z"
}
```

> The sidecar consumes the nonce (single-use, target-bound), re-derives the key, verifies the HMAC,
> then appends an `APPROVED` transition to the **append-only hash-chain** and writes a deterministic
> doc to the daily `agentropix-approvals-YYYY.MM.DD` index. `prev_approval_hash` is empty on the first
> approval for a target. Failure tokens are machine-readable: `403 unknown_examiner`,
> `401 nonce_expired` / `nonce_unknown`, `401 bad_signature`, `409 precondition_failed` (the `from_status`
> gate). Wrong `from_status` here is the guard that stops a double-approve.

### Execution C → Output C — resume the run (APPROVED-only report)

With the finding APPROVED, the report tiers now include it and the export is sealed.

*Execution C (MCP tool calls):*
```jsonc
report_generate(profile="full")            // APPROVED findings only
report_export(tier="analyst", fmt="md")    // -> courtroom.seal_report
```

*Output C (`ExportResult` — tamper-evident, APPROVED finding present):*
```json
{
  "tier": "analyst",
  "fmt": "md",
  "mime": "text/markdown",
  "path": "/cases/<case>/reports/analyst.md",
  "content": "# Analyst Report ... F-alice-001 (APPROVED) ..."
}
```

> Run **before** approval, the same `report_generate` returns only the executive/empty shell (no DRAFT
> finding leaks into any tier). The exported artifact is sealed by `courtroom.seal_report`
> (HMAC-SHA256 over the canonical report) and is tamper-evident.

> **GOTCHA — `report_generate` on a brand-new DRAFT-only case.** As documented in the
> [user guide Phase 7](../01-overview/user-guide.md#phase-7--generate-and-verify-the-sealed-report),
> a `report_generate` against a case with zero APPROVED findings can return `case_not_found` /
> an empty shell. That is the gate working as designed — approve at least one finding first.

### Reversing an accidental approval

> **🖥️ Expert (command):**
> ```jsonc
> retract_approval(
>   approval_id="<approval-id>",
>   approver_id="<examiner>",
>   password="<approver-password>",
>   reason="approved in error"
> )   // MCP tool call -> compensating REVOKED entry (append-only)
> ```
> **💬 End-user (prompt):** *"Retract approval <approval-id> on this case — it was approved by mistake."*
> The session routes to the **`retract_approval`** MCP tool, which appends a compensating `REVOKED`
> entry referencing the prior `approval_id` (the original row is never mutated; ADR-016/022).

---

## See also

- [uc-disk-triage.md](uc-disk-triage.md) — where DRAFT disk findings originate.
- [uc-memory-triage.md](uc-memory-triage.md) — where DRAFT memory findings originate.
- [uc-wazuh-push.md](uc-wazuh-push.md) — pushing the APPROVED IOCs onward (optional integration).
- [`tool-list.md`](../04-mcp-tools/tool-list.md) — `[APPR]` approval-gated tools and `[MUT]` writes.
- [`module-map.md`](../02-architecture/module-map.md) — `approval_sidecar/`, `courtroom.py`, `evidence_gate/`.
