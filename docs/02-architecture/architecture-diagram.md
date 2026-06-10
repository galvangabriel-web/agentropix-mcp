# Agentropix-SIFT — System Architecture Diagram

> **Audience:** architects, examiners, and reviewers who need a single verified picture of the runtime.
> **Question this page answers:** *what are the moving parts of Agentropix-SIFT, how do LLM clients reach the deterministic tools, and which guardrails are enforced in code versus by convention?*

## How to read this page

This page presents one validated architecture diagram of the Agentropix-SIFT runtime, derived from the oracle repository (`/home/admin2/agentropix-sift`, `src/` + docs) and reconciled against [`canonical-facts.md`](../08-reference/canonical-facts.md). Every component, connection, and guardrail shown below is grounded in a named source file (see the [Component-to-source map](#component-to-source-map)); claims that did not survive source verification are recorded as honest negatives rather than silently dropped.

Reading order:

1. **The diagram** — top-to-bottom: agent layer → transport/auth boundary → MCP server core → tool families → wrappers → SIFT Workstation binaries, with data sources feeding in, persistence at the side, and the findings → approval → sealed-report → Wazuh output pipeline.
2. **Two guardrail columns** flank the flow: **ARCHITECTURAL** (green, solid border — enforced in code, the model cannot bypass them) and **PROMPT-BASED** (amber, dashed border — conventions an LLM is instructed to honor). Each guardrail box names the point it protects (e.g. “protects: approval portal”); the full enforcement-file mapping is in the table below.
3. The **red, thick-bordered node** is the Examiner Approval Portal — the human HMAC hard-stop. No code path promotes a DRAFT finding to APPROVED without a valid challenge-response signature from the examiner.

The diagram is committed as a PNG (rendered from Mermaid source via `mmdc`) so it displays for every reader regardless of client-side Mermaid support.

![Agentropix-SIFT architecture](assets/architecture-diagram/architecture-diagram.png)

🔍 [Open as SVG — full size, zoomable](assets/architecture-diagram/architecture-diagram.svg) · 📄 [Download as PDF](assets/architecture-diagram/architecture-diagram.pdf) · [Mermaid source](assets/architecture-diagram/architecture-diagram.mmd)

---

## Architectural pattern

**Verdict: Custom MCP Server.**

Agentropix-SIFT is a purpose-built FastMCP 3.2.4 server (`FastMCP("agentropix-sift")`, entry point `agentropix-sift-mcp`) exposing 71 canonical / 72 live-registered forensic tools to general-purpose MCP clients. Claude Desktop and Claude Code attach via a literal `mcp.json` snippet shipped in the module docstring, over stdio (the default transport) or Bearer-protected streamable HTTP at `http://TAILNET-HOST:8765/mcp`. The server itself is the enforcement boundary: the Thymus read-only path policy, the rate limiter, the W-286 DRAFT gate, and the fail-closed Bearer auth all run server-side — *the agent literally has no tool to write evidence* — and the package ships no LLM client of its own in the MCP path. It is **not** a Direct Agent Extension (no Claude-internal plugin code) and **not** an Alternative Agentic IDE (no editing environment).

The verdict *"LLM at the edge, determinism inside"* is verified end-to-end: every fact originates from a named deterministic tool wrapping one of 16 SIFT Workstation binaries via no-shell subprocess execution, and the only in-runtime LLM call in the entire package is the optional, default-off, fail-open Architect reorder pass (`AGENTROPIX_ARCHITECT_LLM_REORDER`).

**Hybrid note — secondary elements that must not be mislabeled.** The same package ships an in-process Trinity-Loop/Blackboard swarm: 13 SwarmAgent classes (7 core specialists + 6 ATT&CK detectors), explicitly LLM-free, invoked by the local `agentropix-sift run` CLI and calling the tool core via **direct Python import, not network MCP** — a deterministic multi-agent runtime, not an LLM Multi-Agent Framework. The `agx_gearb.py` headless driver (non-LLM, workstation-side, outside the repo, DRAFT-only — it stops at the approval gate) and the BMAD/OpenClaw forge crews (build-time and documentation-production roles only) sit **outside** the product runtime diagram.

---

## Guardrails: prompt-based vs architectural

The distinction matters in court: an **ARCHITECTURAL** guardrail is enforced by code the model cannot reach around; a **PROMPT-BASED** guardrail is an instruction the model is expected — but not forced — to honor. Agentropix-SIFT pairs every load-bearing prompt-based control with a code-side backstop.

| Name | Type | Enforced by | What it does |
|---|---|---|---|
| Thymus read-only evidence policy | ARCHITECTURAL | `mcp_server/thymus_policy.py` + `server.py` (47 `check_read` sites) | Allowlist prefixes + forbidden patterns (`..`, `~`, `/dev`, `/proc`, `/sys`), URL-decode/symlink/PATH_MAX defenses; `check_write()` unconditionally rejects — read-only scoped to EVIDENCE (derived output still written to allowlisted out_dirs). |
| Fail-closed Bearer auth (HTTP) | ARCHITECTURAL | `mcp_server/fastmcp_app.py:173-306` | `AGENTROPIX_MCP_AUTH_TOKEN` required on every `/mcp` request, constant-time compare (SIFT-W-281); `_build_app()` refuses to start without a token unless `AGENTROPIX_MCP_DEV_MODE=1` (even stdio launches). |
| HTTP request audit log | ARCHITECTURAL | `fastmcp_app.py:310-335` | JSON-lines audit of every `/mcp` request to `/var/log/agentropix/http_audit.log` (dir env-overridable); the token is never logged, only `sha256[:16]`. |
| Per-tool rate limiter | ARCHITECTURAL | `mcp_server/server.py:194-254` | Sliding-window per-tool limit (default 60/min, per-tool env override) under `threading.Lock` for the HTTP worker pool. |
| `_safe_tool` error envelope (WZ-021) | ARCHITECTURAL | `mcp_server/wrappers/_safe_tool.py` | Every tool exception becomes a flat `{error, details}` envelope — failures never crash the FastMCP boundary (KeyboardInterrupt/SystemExit/CancelledError propagate). |
| W-286 DRAFT gate | ARCHITECTURAL | `mcp_server/wrappers/wazuh_tools.py:40-127` (+ `case_records.py`, `server.py:1273`) | `_apply_draft_gate` strips caller-supplied `approval.*` and forces `status=DRAFT` on every indexed finding — the LLM cannot self-approve via any write surface. |
| HMAC approval sidecar (human hard-stop) | ARCHITECTURAL | `approval_sidecar/app.py` + `auth.py` + `nonce.py` | DRAFT→APPROVED requires challenge-response: 60 s single-use nonce + HMAC-SHA256 with a PBKDF2(600k, env-tunable)-derived key from the examiner password; no code path writes an approval without a valid signature. |
| Nonce anti-replay store | ARCHITECTURAL | `approval_sidecar/nonce.py:49-113` | Single-use, TTL-bound, (examiner, target)-bound nonces; consumed even on failure so replay and cross-target approval are rejected in code. |
| Approval precondition gate (BUG-001) | ARCHITECTURAL | `approval_sidecar/app.py:225-260, 379-384` | The target must exist in the case AND currently hold the asserted `from_status` before an approval is written (409 on phantom/double/stale approvals). |
| Approval hash chain (Phase 2 live) | ARCHITECTURAL | `approval_sidecar/writer.py:141-328` | Per-CASE `prev_approval_hash` backfilled before every bulk write (BUG-002 fix); `verify_approval_chain` walks the chain; the deterministic `approval_id` includes the nonce (but is NOT wired as the OpenSearch `_id` — `bulk_index` auto-generates). |
| `dry_run=True` defaults + `egt_` mutation tokens | ARCHITECTURAL | `wazuh/evidence_gate.py` + `evidence_gate/registry.py` | Live mutation needs a single-use, scoped, TTL-capped (7 d) `egt_` token, hash-stored and atomically verify+spent in SQLite, fail-closed if the verifier is unimportable. NOT universal: `record_timeline_event` has no dry_run/token; the `AGENTROPIX_EVIDENCE_GATE_STEP1_STUB` hatch degrades verification to format-only. |
| `WAZUH_DRY_RUN_ONLY` kill switch | ARCHITECTURAL | `wazuh/config.py:236` + `wazuh_tools.py:200-208, 786-794` | Env-level boolean (default True) checked BEFORE token verification — rejects any live write regardless of token; the model cannot toggle it. |
| FP denylists + RFC1918 gating | ARCHITECTURAL | `wazuh/denylists.py` | Regex/provenance-aware false-positive gate before any IOC reaches Wazuh; internal IPs gated by `accept_internal_ips` + `WAZUH_OPERATOR_TRUSTED_CIDRS`. |
| Courtroom HMAC sealing + cross-binding | ARCHITECTURAL | `courtroom.py` (ADR-016/ADR-022) | HMAC-SHA256 with a per-run 32-byte session key (0600); audit-log seal embedded into the report before the report seal; `evidence_image_sha256` binds the report to image bytes (honest skip over the 50 GB cap). |
| Seal re-verification CLIs (hard gates) | ARCHITECTURAL | `audit/verify_seal.py` + `provenance/validate.py` | Row-by-row HMAC re-verification; exits non-zero iff forged/malformed (`schema_failed` for provenance) — used as run preflight/teardown gates. |
| `raw_stdout_sha256` provenance envelope | ARCHITECTURAL | `wrappers/tsk.py`, `evt.py`, `schema/pdf_extract_text.py` et al. | Wrapper response models carry the SHA-256 of the actual subprocess stdout, grounding every parsed result to the deterministic tool's raw bytes. |
| `report_generate` APPROVED-only filter | ARCHITECTURAL | `mcp_server/wrappers/case_records.py:1056-1180` | Findings/timeline/executive/full profiles include only APPROVED findings (code-side query filter); explicit warning when 0 APPROVED but DRAFTs exist. |
| `delete_finding` DRAFT-only | ARCHITECTURAL | `case_records.py:336-454` | Refuses in code to delete APPROVED/REJECTED/REVOKED findings; the live delete query is additionally scoped to `approval.status=DRAFT`; `dry_run` default. |
| Deterministic Critic halt + completion proofs | ARCHITECTURAL | `trinity/critic.py` + `orchestrator.py` | The Trinity stop decision is a pure function of Blackboard state (findings fingerprint, 0.85 threshold, coverage guard); completion-promise tokens issued only when an agent completed AND published ≥1 finding — no LLM in the loop. |
| Architect LLM-reorder output validation | ARCHITECTURAL | `trinity/architect.py:~407-424` | Code-side backstop on the one prompt-based runtime feature: the reordered agent set must exactly equal the deterministic set (duplicates rejected, falls through to deterministic order). |
| Credential redaction (fail-closed) | ARCHITECTURAL | `security/redact.py` | Credential patterns → `[REDACTED-hmac-tag]`; any uncaught exception raises `RedactionError` so aggregation aborts rather than emitting unredacted output. |
| Canonical-facts CI drift gate | ARCHITECTURAL | `scripts/check_canonical_facts.py` (oracle CI) | The build fails on backward/forward numeric drift in tracked docs — documentation numbers are machine-checked (the portal-side "never contradict" rule is the prompt-based companion). |
| Architect LLM reorder system prompt | PROMPT-BASED | `trinity/architect.py:~64-79` | "Output JSON order, do not add or remove agents" instruction to Claude haiku — violable by the model; harm prevented by the code-side set validation above. |
| SIMULATED-examiner-approval labeling | PROMPT-BASED | `docu_agentro/CLAUDE.md:116-118` | Recording convention: demo auto-approvals must be labelled "SIMULATED examiner approval (demo only)" — no code enforces the label. |
| Honest-negatives report discipline | PROMPT-BASED | `docu_agentro/CLAUDE.md` (case-reports section) | Refuted hypotheses stay in reports as honest negatives; synthesis grounded strictly in `confirmed-findings.json` — an instruction to drafting/critic agents, not code. |
| AI-disclosure transparency | PROMPT-BASED | [`docs/05-safety-forensics/ai-disclosure.md`](../05-safety-forensics/ai-disclosure.md) | Documents the three honest sources of non-determinism and AI-vs-deterministic-tool attribution — a transparency convention. |
| LLM narrative rendering of reports | PROMPT-BASED | `case_records.py:1071-1073` (docstring) | `report_generate` returns grounded APPROVED-only sections; the narrative prose layer is rendered by the calling LLM and relies on it honoring those sections. |

### Known gaps (honest negatives)

Recorded so the guardrail story is not overstated:

- `record_timeline_event` mutates the timeline index with **no** `dry_run`/token gate (rate-limit only; rows are still DRAFT-stamped).
- The `AGENTROPIX_EVIDENCE_GATE_STEP1_STUB` env hatch degrades `egt_` token verification to format-only.
- Thymus on-disk JSONL audit is conditional on `AGENTROPIX_AUDIT_LOG` being set (the in-memory ring always runs).
- The deterministic `approval_id`-as-OpenSearch-`_id` is design intent only — live `bulk_index` auto-generates `_id`, so retry idempotency via deterministic `_id` is not wired.

---

## Component-to-source map

Every box in the diagram traces to oracle source under `/home/admin2/agentropix-sift/src/agentropix_sift/` (paths relative to that package unless noted).

| Diagram component | Oracle source | Notes |
|---|---|---|
| FastMCP app, stdio + HTTP transports, fail-closed boot | `mcp_server/fastmcp_app.py` (`_build_app`) | FastMCP 3.2.4; 67 `@app.tool()` registrations here + 5 via Wazuh registrars = 72 live; the `health` tool's `len(await app.list_tools())` is the designated live tool-count source of truth. |
| BearerTokenMiddleware + HTTP audit | `mcp_server/fastmcp_app.py:173-306, 310-335` | Injected by wrapping `app.http_app()` — FastMCP 3.x removed the `.app` shim; NOT `app.run(middleware=[...])`. |
| Shared tool core (61 `mcp_*` async functions) | `mcp_server/server.py` | "The MCP server is the enforcement boundary — Thymus policy runs here, not in the agent." |
| `_RateLimiter` | `mcp_server/server.py:194-254` | `AGENTROPIX_RATE_LIMIT` default 60 + per-tool override. |
| ThymusEvidencePolicy | `mcp_server/thymus_policy.py` | 47 `check_read` call sites in `server.py`, including out_dir checks. |
| Wrapper layer (~52 modules, 59 `.py` files) | `mcp_server/wrappers/` | NOT the top-level `wrappers/` dir (3 standalone modules); the canonical-facts "~40 files" row is stale. |
| Subprocess discipline | `mcp_server/wrappers/_subprocess.py` | `asyncio.create_subprocess_exec` (argv list, never shell); `run_with_memory_limit` (RSS cap `max(4096 MB, GB×730)`, W-162) on exactly 7 memory-heavy wrappers; env-name `AGENTROPIX_*_TOOL` overrides exist for 11 tools, the rest resolve via bare `shutil.which`. |
| Error envelope | `mcp_server/wrappers/_safe_tool.py` | WZ-021. |
| Wazuh tool registrars | `mcp_server/wrappers/wazuh_tools.py` | `register_wazuh_tools` (4) + `register_wazuh_intel_tools` (1), try/except graceful degradation; `wazuh_hunt_ioc` is registered exactly once. |
| E01 FUSE lifecycle | `imaging/ewf_lifecycle.py` | Synchronous sudo'd `subprocess.run` (`ewfmount` → `ntfs-3g`); tool names validated against sudo-argv[0] injection. |
| ATT&CK detectors + YARA packs | `detectors/` + `detectors/yara_rules/` | 6 deterministic detector SwarmAgents. |
| Trinity Loop (Architect/Critic/orchestrator) | `trinity/architect.py`, `trinity/critic.py`, `trinity/orchestrator.py` | `run_triage` is a typer CLI path, NOT an MCP tool; the Swarm calls the tool core by direct Python import. |
| Findings/case/report tools | `mcp_server/wrappers/case_records.py` | DRAFT gate, APPROVED-only reports, DRAFT-only delete. |
| Approval sidecar (port 8800) | `approval_sidecar/app.py`, `auth.py`, `nonce.py`, `writer.py` | Starlette; W-288; Phase-2 hash chain lives in `writer.py:141-328`. |
| Evidence-gate tokens | `wazuh/evidence_gate.py` + `evidence_gate/registry.py` | SQLite registry at `~/.agentropix/evidence-gate.sqlite` (0600). |
| Wazuh publishing + kill switch + denylists | `wazuh/config.py`, `wazuh/denylists.py`, `mcp_server/wrappers/wazuh_tools.py` | Manager API on `https://TAILNET-HOST:55000` (JWT); Indexer on `https://TAILNET-HOST:9200` (Basic Auth) — two separate auth chains. |
| Courtroom sealing + verifiers | `courtroom.py`, `audit/verify_seal.py`, `provenance/validate.py` | ADR-016 / ADR-022. |
| Credential redaction | `security/redact.py` | Fail-closed (`RedactionError`). |
| CI drift gate | `scripts/check_canonical_facts.py` | Oracle CI. |

---

## Key canonical facts

Governing numeric authority: [`docs/08-reference/canonical-facts.md`](../08-reference/canonical-facts.md).

- **71 MCP tools** (canonical). The live `@app.tool` surface at HEAD is **72** (67 in `fastmcp_app.py` + 4 `wazuh_tools` + 1 `wazuh_intel`, no duplicates); the canonical lineage carries a persistent off-by-one and the `health` tool's live `len(list_tools())` is the designated source of truth — an explicit reconciliation, not a contradiction.
- **16 SIFT forensic binaries** driven by the wrappers: `vol`, `log2timeline.py`, `fls`, `icat`, `mmls`, `ewfinfo`, `evtx_dump.py`, `yara`, `bulk_extractor`, `rip.pl`, `pf`, `amcache_parser`, `shimcache_parser`, `exiftool`, `foremost`, `hashdeep` — plus Eric Zimmerman tools via `dotnet` and auxiliary binaries outside the 16.
- **4464 tests** (canonical).
- **72/72 (100%) disk recall** and **108/118 (91.5%) memory recall** (canonical).
- **Python 3.12+** (`pyproject` `requires-python >=3.12`); **FastMCP 3.2.4** (an earlier portal "2.x pin" note is stale; canonical is 3.2.4).
- **Transports:** stdio (default) and streamable HTTP on port 8765 at `/mcp` (`http://TAILNET-HOST:8765/mcp`), Bearer-protected, fail-closed boot, ADR-017 tailnet-only exposure.
- **11 tool families:** 4 + 10 + 7 + 16 + 6 + 4 + 6 + 7 + 2 + 5 + 5.
- **13 SwarmAgent classes** (7 core specialists + 6 ATT&CK detectors), deterministic and LLM-free; the only in-runtime LLM call is the optional fail-open Architect reorder (default OFF).
- **Approval crypto:** PBKDF2 600k iterations, 60 s single-use nonce, HMAC-SHA256; finding lifecycle DRAFT → APPROVED → REJECTED → REVOKED, every ingest force-stamped DRAFT (W-286).
- **8 routed `agentropix_*` CDB list kinds** (6 self-tested, 5 confirmed live — a bare "6" understates the routing surface).
- **Subprocess discipline:** argv-only, never shell; RSS cap `max(4096 MB, image_GB×730)` on the 7 memory-heavy wrappers, timeout-kill on the rest.
