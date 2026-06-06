# Sequence Diagrams

> **Section 02 · Architecture** — the dynamic view. The previous chapters describe the
> *structure*; this one shows the *flows*. Each diagram is followed by prose and cites the
> source it was derived from. The six flows: a full triage run, a single MCP tool call
> through Thymus, the finding → provenance → seal pipeline, the Architect↔Swarm↔Critic
> iteration with halt, the approval-sidecar human gate, and the optional Wazuh push.

These tie together the [Trinity Loop](trinity-loop.md), the
[Swarm and Blackboard](swarm-agents.md), the [FastMCP server](mcp-server.md), and the
[safety spine](component-architecture.md#3-the-safety-spine-layered).

---

## 1. Full triage run, end-to-end

```mermaid
sequenceDiagram
    actor Examiner
    participant CLI as cli.py (run)
    participant Orch as orchestrator.run_triage
    participant Court as courtroom
    participant Arch as Architect
    participant Swarm as Swarm agents
    participant BB as Blackboard
    participant Critic
    participant Seal as write_sealed_session

    Examiner->>CLI: agentropix-sift run IMAGE.E01
    CLI->>Orch: run_triage(image, max_iterations=5)
    Orch->>Court: evidence_image_sha256(image)
    Court-->>Orch: sha256 (or None)
    Orch->>Orch: configure_policy(extra_allowed=[image_dir])

    loop iteration 1..max_iterations
        Orch->>Arch: plan(feedback, stable_agents)
        Arch-->>Orch: ordered plan (subset of SWARM)
        loop each agent in plan
            Orch->>Swarm: agent.run(image) [fresh trace scope]
            Swarm->>BB: publish Finding(s)
            Swarm-->>Orch: findings + tool_call trace
        end
        Orch->>Critic: score(BB, planned_agents, iteration)
        Critic->>BB: max_confidence + correlations()
        Critic-->>Orch: TrinityResult(score, feedback, should_halt)
        alt should_halt
            Orch->>Orch: status = complete, break
        else continue
            Orch->>Orch: carry feedback + stable_agents forward
        end
    end

    Orch->>Orch: dedup findings, build TriageReport
    Orch-->>CLI: TriageReport (unsealed)
    CLI->>Seal: write_sealed_session(report, audit_entries, out)
    Seal-->>CLI: report.json, audit-log.json, session-key (0600)
    CLI-->>Examiner: findings, tool-call count, status, evidence SHA-256
```

**Reading the flow.** The examiner runs the CLI; `run_triage()` hashes the evidence image
(binding the report to the bytes), adds the image directory to the Thymus allow-list, and
enters the [Trinity Loop](trinity-loop.md). Each iteration plans a swarm slice, runs each
agent inside a fresh [trace scope](mcp-server.md#5-tool-tracing) so its MCP calls are
captured, scores the Blackboard, and either halts or carries the Critic's feedback forward.
After the loop, findings are deduplicated and rolled into a `TriageReport`, which the CLI
**seals on write** — three files land on disk: `report.json`, `audit-log.json`, and the
mode-0600 `session-key` (`cli.py:116-152`, `orchestrator.py:82-322`). The inference
constraint is reported as `high` ("LLM is orchestrator; facts from MCP tools").

---

## 2. Single MCP tool call through Thymus

```mermaid
sequenceDiagram
    participant Agent as LLM agent / SwarmAgent
    participant App as FastMCP (@app.tool)
    participant Traced as "@traced"
    participant RL as _rate_limiter
    participant Thymus as _policy.check_read
    participant Wrap as wrappers/<tool>.py
    participant Bin as SIFT binary (subprocess)

    Agent->>App: tools/call get_pslist(image)
    App->>Traced: enter span (start timer, hash args)
    Traced->>RL: check("get_pslist")
    alt over limit
        RL-->>Agent: ToolError(rate_limit)
    else ok
        RL->>Thymus: check_read(image)
        alt rejected (traversal / symlink / outside allowlist / write)
            Thymus->>Thymus: append REJECT to audit ring + JSONL
            Thymus-->>Agent: ToolError(thymus)
        else allowed
            Thymus->>Thymus: append ALLOW to audit ring + JSONL
            Thymus->>Wrap: (proceed)
            Wrap->>Bin: await create_subprocess_exec(vol3 ...)
            Bin-->>Wrap: stdout (CSV/JSON/text)
            Wrap-->>Traced: Pydantic model (PsList)
            Traced->>Traced: snapshot raw_output, record(args_hash, exit_code)
            Traced-->>Agent: model_dump() -> JSON-RPC response
        end
    end
```

**Reading the flow.** Every forensic tool runs the same ordered pipeline
(`server.py:355-370`, `docs/MCP-REQUEST-FLOW.md`): `@traced` opens a span and hashes the
args; the rate-limiter enforces a per-tool calls/minute cap; **Thymus `check_read` is the
read-only gate** — a rejected path (traversal `..`, broken symlink, outside the allow-list)
returns a typed `ToolError` and logs a REJECT to the
[audit ring + JSONL](mcp-server.md#4-thymus--the-read-only-evidence-boundary). Only on ALLOW
does the wrapper launch the subprocess. The result is typed into a Pydantic model, the
`raw_output` is snapshotted *before* any LLM summarisation, and the
`(args_hash, exit_code, raw_output)` record is pushed to the trace. **No write path exists**
— the worst an agent can do is fail to read.

---

## 3. Finding → provenance classification → Courtroom seal

```mermaid
sequenceDiagram
    participant Orch as orchestrator
    participant Court as courtroom
    participant Prov as provenance.validate
    participant FS as Disk (report dir)

    Orch->>Court: build report_dict (findings, trace, thymus_audit)
    Note over Court: read_audit_log_jsonl drains the on-disk trail
    Court->>Court: write_session_key -> 32-byte key, mode 0600
    Court->>Court: seal_audit_log(audit_dict, key) -> audit HMAC
    Court->>Court: embed audit_log_seal into report_dict (cross-bind)
    Court->>Court: seal_report(report_dict, key) -> HMAC-SHA256
    Note over Court: canonical JSON, sort_keys, no whitespace
    Note over Court: report_seal forced to sentinel before MAC
    Court->>FS: write report.json + audit-log.json + .session-key
    Court-->>Orch: paths

    Note over Prov: independent verification (later)
    Prov->>FS: read provenance/<list>.provenance.jsonl
    loop each IOC row
        Prov->>Prov: validate IOCProvenance schema
        Prov->>Prov: recompute row HMAC vs stored seal
        alt seal recomputes
            Prov->>Prov: classify "ok"
        else null seal
            Prov->>Prov: classify "unsealed"
        else mismatch / bad schema / bad JSON
            Prov->>Prov: classify "forged" / "schema_failed" / "malformed"
        end
    end
    Prov-->>FS: ValidateReport (exit != 0 if any forged/failed/malformed)
```

**Reading the flow.** Sealing happens at write time (`cli.py` → `courtroom.write_sealed_session`).
A single 32-byte per-run session key is minted to a mode-0600 file; the Thymus audit trail
is sealed into `audit-log.json` with its own HMAC, and that audit seal is **cross-bound**
into the report dict *before* the report seal is computed — so tampering with the audit log
breaks both seals (`courtroom.py:230-269`, ADR-022). The report seal is an HMAC-SHA256 over
the canonicalised JSON (`sort_keys=True`, no whitespace, `report_seal` replaced by a fixed
sentinel before MACing, so the verifier is reproducible; `courtroom.py:145-170`).

Separately, IOC **provenance sidecars** (written by the Wazuh push path) are validated
row-by-row by `provenance/validate.py`: each row's `IOCProvenance` schema is checked and its
HMAC seal recomputed. Rows classify as `ok`, `unsealed`, `forged`, `schema_failed`, or
`malformed`; any `forged`/`schema_failed`/`malformed` makes the validator exit non-zero —
this is the tamper-evidence gate (`provenance/validate.py` docstring,
[schema-dump.md](../../.crew/schema-dump.md) §8).

---

## 4. Architect ↔ Swarm ↔ Critic iteration with halt

```mermaid
sequenceDiagram
    participant Orch as orchestrator
    participant Arch as Architect
    participant Swarm
    participant BB as Blackboard
    participant Critic

    Note over Orch,Critic: iteration N
    Orch->>Arch: plan(last_feedback, stable_agents=last_stable)
    Arch->>Arch: deterministic SWARM order, drop stable agents (W-045)
    Arch-->>Orch: plan (HuntAgent still last)
    Orch->>Swarm: run each planned agent
    Swarm->>BB: publish Finding(s)
    Orch->>Critic: score(BB, planned_agents=plan, iteration=N)

    Critic->>BB: max_conf + correlations()
    Critic->>Critic: score = min(1.0, max_conf + 0.25·n_corr)

    alt any PLANNED agent produced 0 findings
        Critic-->>Orch: should_halt=False (coverage guard W-083)
    else iteration < min_iterations (2)
        Critic-->>Orch: should_halt=False (min-iter floor)
    else score >= 0.85
        Critic-->>Orch: should_halt=True (threshold met)
    else fingerprint == previous (no new findings)
        Critic-->>Orch: should_halt=True (fixed point, no progress)
    else
        Critic-->>Orch: should_halt=False (below threshold, still progressing)
    end

    alt should_halt
        Orch->>Orch: status=complete, exit loop
    else
        Orch->>Orch: last_stable = stable_agents, next iteration
    end
```

**Reading the flow.** This is the [deterministic halt logic](trinity-loop.md#4-the-deterministic-halt-logic)
as a sequence. The Architect returns the canonical SWARM order, dropping agents the Critic
flagged *stable* (`architect.py:170-191`). The Critic computes its closed-form score
`min(1.0, max_conf + 0.25·#correlations)` and evaluates a **fixed precedence of guards**
(`critic.py:166-206`): the coverage guard and min-iterations floor *refuse* to halt early
(overriding a saturated score), then `score ≥ 0.85` halts on confidence, and a repeated
Blackboard fingerprint halts on *no progress* (the idempotent fixed point). **No LLM rates
anything** — the same evidence and seed produce the same score, halt, and report
fingerprint. If neither halt fires within `max_iterations`, the run ends
`budget_exhausted`.

---

## 5. Approval-sidecar human gate

```mermaid
sequenceDiagram
    actor Examiner
    participant Form as Browser approval form
    participant SC as approval_sidecar (Starlette)
    participant Nonce as nonce store
    participant Chain as hash_chain
    participant OS as OpenSearch (approvals index)

    Examiner->>Form: open form (examiner_id, target_id, target_type)
    Form->>SC: POST /challenge
    SC->>Nonce: issue(examiner_id, target_id)
    Nonce-->>SC: nonce (TTL, target-bound, single-use)
    SC-->>Form: ChallengeResponse(nonce, salt_hex, iterations, ttl)
    Examiner->>Form: enter password
    Form->>Form: derive PBKDF2 key, HMAC-sign message
    Form->>SC: POST /approve (signature_hex, nonce, from/to status)
    SC->>Nonce: consume(nonce) [single-use]
    alt nonce expired / unknown
        SC-->>Form: ErrorResponse(nonce_expired / nonce_unknown, 401)
    else valid
        SC->>SC: re-derive key, verify_signature
        alt bad signature
            SC-->>Form: ErrorResponse(bad_signature, 401)
        else verified
            SC->>SC: verify target exists (anti-phantom)
            SC->>Chain: compute_approval_id, link prev_approval_hash
            SC->>OS: write approval doc (agentropix-approvals-YYYY.MM.DD)
            SC-->>Form: ApprovalSubmitResponse(approval_id, indexed_to, prev_hash)
        end
    end
```

**Reading the flow.** The approval sidecar is an **optional, out-of-process** Starlette
service (`approval_sidecar/app.py`) — the human-in-the-loop gate behind the `approve_finding`
/ `retract_approval` MCP tools. It is a two-step HMAC challenge/response: `/challenge`
issues a single-use, target-bound, TTL-bound **nonce**; the examiner's password derives a
PBKDF2 key in the browser (the password never leaves the client) that HMAC-signs the
approval message. `/approve` consumes the nonce, re-derives the key server-side, verifies
the signature, confirms the target actually exists (anti-phantom-approval), then links the
approval into an **append-only hash chain** (`prev_approval_hash`) and writes it to the
daily OpenSearch approvals index (`approval_sidecar/app.py:133-301`,
[schema-dump.md](../../.crew/schema-dump.md) §6). A retraction is a compensating
append-only `approval`-type entry — records are never edited. Bind defaults are loopback
(`AGENTROPIX_APPROVAL_SIDECAR_HOST=127.0.0.1`, port 8800;
[env-vars.md](../../.crew/env-vars.md) §Approval sidecar).

---

## 6. Wazuh push (optional sink)

```mermaid
sequenceDiagram
    participant Tool as wazuh_publish_iocs (MCP)
    participant Orch as wazuh.orchestrator.push_iocs
    participant Pri as PriorityClassifier
    participant Thy as ThymusBridge
    participant Gate as EvidenceGate
    participant Prov as provenance sidecar
    participant Client as WazuhClient
    participant Court as CourtroomSeal
    participant Audit as AuditLogger

    Tool->>Orch: push_iocs(case, dry_run, mutation_token)
    Note over Orch: kill switches — WAZUH_INTEGRATION_ENABLED, WAZUH_PUSH_ENABLED
    Note over Orch: WAZUH_DRY_RUN_ONLY, AGENTROPIX_INTEGRATION_NOT_PRODUCTION
    Orch->>Orch: CaseLoader -> IOCInventory
    Orch->>Pri: classify -> Tier 1+2 / excluded
    Orch->>Thy: validate_inventory (S-1)
    Orch->>Gate: verify(mutation_token) [one-shot, TTL]
    Orch->>Orch: transform -> CDB lists + rules XML
    Orch->>Prov: write per-list provenance.jsonl (HMAC-sealed)
    alt dry_run (default)
        Orch->>Orch: DryRunPlanner -> plan only
        Orch-->>Tool: WazuhIOCPushResult(outcome=dry_run, pushed=0)
    else --confirm
        Orch->>Client: write CDB lists + coalesced manager restart
        Client-->>Orch: write results
        Orch->>Court: HMAC-SHA256 stamp each PUT (ADR-016)
        Orch->>Audit: append JSONL audit row
        Orch-->>Tool: WazuhIOCPushResult(outcome=pushed_and_loaded, seal)
    end
```

**Reading the flow.** Wazuh push is **default-off and dry-run by default**, gated by four
kill switches (`WAZUH_INTEGRATION_ENABLED`, `WAZUH_PUSH_ENABLED`, `WAZUH_DRY_RUN_ONLY`,
plus the `AGENTROPIX_INTEGRATION_NOT_PRODUCTION` operator affirmation;
[env-vars.md](../../.crew/env-vars.md) §Wazuh kill switches). The happy path
(`wazuh/orchestrator.py:1-19`, ADR-018/008/016/017) loads the case IOC inventory,
classifies priority tiers, validates through the **Thymus bridge** and the **evidence gate**
(verifying the one-shot, TTL-bound `mutation_token`), transforms to CDB lists + rules XML,
and writes **HMAC-sealed provenance sidecars** (the rows
[§3](#3-finding--provenance-classification--courtroom-seal) later validates). With `dry_run` (the default)
the orchestrator only *plans* and returns `outcome=dry_run`; only `--confirm` actually
writes to the Wazuh manager and restarts it, stamping each PUT with a Courtroom HMAC and
appending a JSONL audit row. The Wazuh stack itself runs on a separate Docker host reachable
only over the tailnet ([system-context-c4.md](system-context-c4.md#3-deployment--exposure-the-tailnet-boundary)).

---

## 7. Where to go next

- The structural counterparts to these flows → [system-context-c4.md](system-context-c4.md),
  [component-architecture.md](component-architecture.md)
- The halt logic in detail → [trinity-loop.md](trinity-loop.md)
- The Thymus boundary and tool stack → [mcp-server.md](mcp-server.md)
- The data contracts each flow moves (`TriageReport`, `Finding`, `IOCProvenance`,
  approval models) → [03-data](../03-data/)
