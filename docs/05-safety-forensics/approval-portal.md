# The Approval Portal — Operator Walkthrough

> **Section 05 · Safety & Forensics** — the human side of the approval gate.
> Related: [Human-in-the-Loop](human-in-the-loop.md) (how the gate works) ·
> [Approval-Gate use case](../06-use-cases/uc-approval-gate.md) ·
> [Audit & Courtroom Seal](audit-courtroom.md)

> **This is the operator's primary touchpoint with the whole platform.** Every
> finding the engine produces is held in `DRAFT` until a human signs off in this
> browser form. The LLM **cannot** self-approve. Read this page before you
> approve anything in a real case.

The approval sidecar (`src/agentropix_sift/approval_sidecar/`, SIFT-W-288 / W-294)
serves a self-contained browser form. On this workstation it is published on the
**tailnet only**, behind a valid TLS certificate, at:

**🔗 `https://siftworkstation.taile7c9ca.ts.net:8443/`**

`tailscale serve` fronts that HTTPS address and proxies it to the sidecar's local
bind `http://127.0.0.1:8800` (tailnet-only, device-authenticated — it is **not**
reachable from the LAN or the Internet). On the workstation itself you can also
open `http://127.0.0.1:8800/` directly.

![The Agentropix Approval Sidecar browser form](assets/approval-sidecar-ui.png)

*The Approval Portal as served at `https://siftworkstation.taile7c9ca.ts.net:8443/`.
PBKDF2 + HMAC-SHA256 are computed in your browser tab — the approver password
never leaves the page.*

## Prerequisites

- The approval sidecar process is running (Starlette/uvicorn), bound by default
  to `127.0.0.1:8800` (`AGENTROPIX_APPROVAL_SIDECAR_PORT` / config `port`).
- You can reach the portal (on the tailnet **and** device-approved in Tailscale).
- The approver credential env vars are set **and stable across restarts** — a
  changed password or salt invalidates HMAC verification
  ([`.crew/env-vars.md`](../../.crew/env-vars.md)):

  | Env var | Role |
  |---------|------|
  | `AGENTROPIX_APPROVER_USER` | Examiner identity; must match the form's **Examiner ID** |
  | `AGENTROPIX_APPROVER_PASSWORD` | PBKDF2 source secret; never crosses the wire |
  | `AGENTROPIX_APPROVER_SALT_HEX` | Per-examiner PBKDF2 salt; must stay stable |
  | `AGENTROPIX_APPROVER_INDEXER_USER` / `_PASSWORD` | Separate OpenSearch role that writes `agentropix-approvals-*` (dual-credential split) |

- The finding you intend to approve has been staged to `DRAFT` (via the
  `record_finding` / `approve_finding` MCP path).

## How to complete each field

| Field (UI label) | Form id | What to enter | Notes & failure mode |
|---|---|---|---|
| **Examiner ID** | `examiner_id` | Your approver username | Must equal `AGENTROPIX_APPROVER_USER`. Any other value → **`403 unknown_examiner`** (`app.py:143-152`). |
| **Case ID** | `case_id` | The case the finding belongs to, e.g. `INC-2026-0042` | Folded into the signed message; must match the finding's case or the precondition fails. |
| **Finding / Event / Approval ID** | `target_id` | The `DRAFT` item's ID, e.g. `F-alice-001` — **or** a prior `approval_id` when retracting | Read it from the finding/timeline entry in the report. Wrong id → **`409 target_not_found`**. |
| **Target Type** | `target_type` | `finding`, `timeline`, or `approval (retract / void)` | Pick what you are acting on. Choose `approval` only to **void** a prior approval (append-only, never a delete). |
| **From** | `from_status` | The target's **current** status — normally `DRAFT` (or `APPROVED` when revoking) | Must match the live status or → **`409 precondition_failed`** (BUG-001 gate, `app.py:233-260`). |
| **To** | `to_status` | Your decision: `APPROVED`, `REJECTED`, or `REVOKED` | `DRAFT→APPROVED` promotes; `DRAFT→REJECTED` declines; `APPROVED→REVOKED` voids. |
| **Reason (optional)** | *(textarea)* | Free-text rationale | Recorded with the decision; recommended for auditability. |
| **Approver password** | `password` | The approver password | Used **only** to derive the PBKDF2 key locally; never transmitted. Wrong password → **`401 bad_signature`** (`app.py:202-223`). |

## Submitting a decision — step by step

1. **Open** the portal URL above (you must be on the tailnet and device-approved).
2. **Identify yourself & the case** — fill **Examiner ID** and **Case ID**.
3. **Point at the target** — paste the **Finding / Event / Approval ID** and pick the matching **Target Type**.
4. **Set the transition** — choose **From** (the item's current status) and **To** (your decision). Optionally add a **Reason**.
5. **Enter the Approver password.**
6. Click **Sign & Submit.** The page then, entirely client-side:
   - calls `POST /challenge` to get a single-use **nonce** (TTL ~60 s) plus the PBKDF2 `salt_hex` / `iterations`;
   - derives the PBKDF2 key from your password **in the browser** and computes the **HMAC** of the signed move;
   - calls `POST /approve` with the signature — **only the HMAC is sent, never the password.**
7. **Clear** resets the form without submitting.

## Retracting / voiding a prior approval

Approvals are **append-only** — there is no delete (BUG-001). To void one:

1. **Target Type** → `approval (retract / void)`.
2. **Finding / Event / Approval ID** → the **`approval_id`** of the approval you are voiding (not the finding id).
3. **From** = `APPROVED`, **To** = `REVOKED`.
4. **Sign & Submit** as above. This appends a compensating `REVOKED` entry that
   references the prior `approval_id`; the original row is never mutated
   (`models.py:16-20`).

## What you'll see back

| Outcome | Meaning / next step |
|---|---|
| ✅ **Approval recorded** | A deterministic approval doc is written to the daily `agentropix-approvals-YYYY.MM.DD` index and the append-only hash chain is extended; the finding moves out of `DRAFT`. |
| `403 unknown_examiner` | The **Examiner ID** is not the configured approver — fix it. |
| `401 nonce_expired` / `nonce_unknown` | You waited too long (>TTL) between page-load and submit — just click **Sign & Submit** again to get a fresh nonce. |
| `401 bad_signature` | Wrong **Approver password** (or `AGENTROPIX_APPROVER_PASSWORD` / `_SALT_HEX` changed since the finding was staged). |
| `409 target_not_found` | The **Case ID** / **Target ID** don't match a recorded item. |
| `409 precondition_failed` | **From** doesn't match the target's current status (e.g. it's already `APPROVED`). |
| "This site can't be reached" | Not on the tailnet / device not approved / sidecar down — connect to Tailscale, approve the device, confirm the process is up. |

## Verifying the decision landed

- **In the portal:** a success response (approval recorded).
- **In the index:** a deterministic approval doc in `agentropix-approvals-YYYY.MM.DD`, extending the append-only hash chain (`app.py:262-310`, `hash_chain.py:48-101`).
- **In the audit log:** the decision appended to **`/var/log/agentropix/approval-sidecar.log`**.
- **Liveness:** `curl -fsS http://127.0.0.1:8800/healthz` → `200` (`app.py:99-100`).

## Operational & safety notes

- Your password is processed **entirely in this browser tab** (Web Crypto PBKDF2);
  only the HMAC of the approval message is transmitted.
- Approval is **single-examiner** in Phase 1 — only `AGENTROPIX_APPROVER_USER` is accepted.
- There is **no destructive action** here: every decision is an append-only ledger
  entry. A mistaken approval is corrected with a `REVOKED` retraction, not a delete.
- The deeper guarantees behind each step — nonce replay defence, signature
  verification, the precondition gate, and the tamper-evident hash chain — are in
  [Human-in-the-Loop](human-in-the-loop.md).
