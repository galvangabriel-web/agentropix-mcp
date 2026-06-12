# What You Get

A capability matrix for Agentropix-SIFT. Every entry below is sourced from the code,
not the pitch — see the inline citations and the shared references in
[`canonical-facts.md`](../08-reference/canonical-facts.md). For the *why* behind these capabilities, read
[What is Agentropix-SIFT?](what-is-agentropix.md); to run them, see the
[Quickstart](quickstart.md).

---

## Contents — what's in this page (and what to expect)

> Jump to any capability below. Each row tells you what that section gives you, so you can go straight to the proof you need.

| Section | What you'll get |
|---|---|
| [At a glance](#at-a-glance) | The full capability matrix in one table — each row links to its deep-dive page and names the source-code home. |
| [Trinity Loop — agentic control without self-rating](#trinity-loop--agentic-control-without-self-rating) | How the deterministic Architect → Swarm → Critic loop drives a run with no LLM self-rating, and when it halts. |
| [72 MCP tools on one FastMCP server](#71-mcp-tools-on-one-fastmcp-server) | The 72 tools grouped into families (with examples) plus the mutation-token / dry-run guards on state-changing tools. |
| [16 SIFT forensic wrappers](#16-sift-forensic-wrappers) | The 16 trusted SIFT binaries the engine drives and the hardening envelope (timeout, memory ceiling, retry, tracing) around each. |
| [7-agent Swarm (+ ATT&CK detectors)](#7-agent-swarm--attck-detectors) | What each of the 7 specialists investigates, the 6 deterministic ATT&CK detectors, and the completion-promise proofs. |
| [Thymus read-only enforcement](#thymus-read-only-enforcement) | How the path-allowlist immune gate keeps evidence structurally read-only, with an audit ring and chain-of-custody log. |
| [Courtroom seal — chain of custody you can verify](#courtroom-seal--chain-of-custody-you-can-verify) | The SHA-256 evidence binding and HMAC report/audit-log seals that make a report judge-verifiable. |
| [Provenance & grounding](#provenance--grounding) | The three layers (tool-sourced findings, `inference_constraint = high`, seal-chain validation) that trace every claim to a tool. |
| [Approval sidecar (human-in-the-loop)](#approval-sidecar-human-in-the-loop) | The optional HMAC examiner sign-off service — PBKDF2 key, nonce, append-only approval hash chain, browser form. |
| [Wazuh SIEM integration](#wazuh-siem-integration) | How findings/IOCs promote into Wazuh behind default-deny kill switches and the active-response CIDR guard. |
| [Chaos-tested resilience](#chaos-tested-resilience) | How fault-injection tests prove graceful degradation, plus the 4464-test surface and the real-data recall gates. |
| [Next](#next) | Where to go next — Quickstart to run it, and the positioning page for the why. |

---

## At a glance

Each row links to the page that explains that capability in depth — the
**Where it lives** column is the source-code home, and **Go deeper** routes you to the
reference or architecture page for the full treatment.

| Capability | What you get | Where it lives | Go deeper |
|------------|--------------|----------------|-----------|
| **Trinity Loop** | Deterministic Architect → Swarm → Critic control loop with fingerprint-based halt; **no LLM self-rating** | `trinity/architect.py`, `trinity/critic.py`, `orchestrator.py` | [Trinity Loop](../02-architecture/trinity-loop.md) |
| **72 MCP tools** | A single FastMCP server exposing **72 distinct forensic tools** over stdio + HTTP | `mcp_server/fastmcp_app.py` | [MCP Server](../02-architecture/mcp-server.md) · [Tool Reference](../04-mcp-tools/tool-reference.md) |
| **16 SIFT forensic wrappers** | Hardened drivers around the 16 trusted SIFT binaries (timeout, memory ceiling, retry, stderr capture, tracing) | `mcp_server/wrappers/` | [MCP Server](../02-architecture/mcp-server.md) |
| **7-agent Swarm** | Memory, Timeline, Filesystem, Artifact, Discovery, Mail, Hunt specialists + 6 ATT&CK detectors | `agents/`, `detectors/` | [Swarm Agents](../02-architecture/swarm-agents.md) |
| **Thymus read-only policy** | Path-allowlist enforcement of evidence read-only at the MCP boundary, with an audit ring | `mcp_server/thymus_policy.py` | [Anti-Hallucination](../05-safety-forensics/anti-hallucination.md) |
| **Courtroom seal** | SHA-256 evidence binding + HMAC-SHA256 report/audit-log sealing, mode-0600 session keys | `courtroom.py` | [Audit & Courtroom Seal](../05-safety-forensics/audit-courtroom.md) |
| **Provenance & grounding** | Tool-sourced findings (`_source`), `inference_constraint = high`, per-row HMAC seal-chain validation | `agents/_base.py`, `provenance/validate.py` | [Provenance & Grounding](../05-safety-forensics/provenance-grounding.md) |
| **Approval sidecar** | Optional HMAC human-in-the-loop examiner sign-off (PBKDF2 + nonce + hash chain) | `approval_sidecar/` | [Human-in-the-Loop](../05-safety-forensics/human-in-the-loop.md) |
| **Wazuh integration** | Promote findings/IOCs into a Wazuh SIEM behind default-deny kill switches | `wazuh/` | [Wazuh Integration](../09-integrations/wazuh-portal.md) |
| **Chaos-tested resilience** | Fault-injection tests over the failure paths (timeout, OOM, malformed output, …) | `tests/chaos/test_fault_paths.py` | [Testing](../07-sdlc-ops/testing.md) |

> **Canonical counts** (`72` tools, `16` wrappers, `4464` tests, recall `72/72` /
> `108/118`) are pinned in [`canonical-facts.md`](../08-reference/canonical-facts.md) (mirroring upstream
> `CANONICAL_FACTS.md`). Numbers below cite that file; re-query the live `tools/list`
> when an exact count is load-bearing in your own work.

---

## Trinity Loop — agentic control without self-rating

> **Deep dive:** [The Trinity Loop](../02-architecture/trinity-loop.md) (architecture).

The **Trinity Loop** is the engine's brain — a three-role control loop (Architect →
Swarm → Critic) that drives a triage run to completion. Its defining property is that
the *non-deterministic* part (an LLM, the model that orchestrates the run) only
**orchestrates** — it never authors a finding, never assigns a confidence, and never
decides "done." A **finding** is a single tool-grounded forensic observation; a
**fingerprint** is a hash of one pass's output used to detect when the run has stopped
changing.

- **Architect** (`trinity/architect.py`) — deterministic planner. Returns the canonical
  ordered `SWARM`, may prune agents the Critic marked *stable*, preserves run order so
  `HuntAgent` runs last.
- **Swarm** — runs each iteration, writing `Finding`s to a shared `Blackboard`.
- **Critic** (`trinity/critic.py`) — deterministic scorer. Score = `max(confidence) +
  0.25 · #correlations`, capped at 1.0. Halts when score ≥
  `AGENTROPIX_CRITIC_HALT_THRESHOLD` (**default 0.85**) **or** the per-pass output
  fingerprint reaches a fixed point — gated by a minimum-iterations guard and a refusal
  to halt while any planned agent produced zero findings.

The loop emits a `TrinityResult` (`score`, `feedback`, `should_halt`) per iteration,
all preserved in the report's `iterations[]` for audit (see
[`schema-dump.md`](../03-data/schema-dump.md) §3).

---

## 72 MCP tools on one FastMCP server

> **Deep dive:** [The FastMCP Server](../02-architecture/mcp-server.md) (architecture) ·
> [MCP Tool Reference](../04-mcp-tools/tool-reference.md) (per-tool signatures).

**MCP** is the Model Context Protocol — the open standard a model client (Claude Desktop,
Claude CLI) uses to call tools. **FastMCP** is the Python framework that serves them.
A single FastMCP server (`mcp_server/fastmcp_app.py`) exposes **72 distinct tool
functions** (`canonical-facts.md`, `mcp_tool_count = 72`) over both **stdio** (the client
launches the server as a subprocess) and **HTTP** transports. The
running server's `tools/list` is the authoritative argument schema; the full
categorized catalogue is in [`tool-list.md`](../04-mcp-tools/tool-list.md). The tool
families:

| Family | Count | Examples |
|--------|------:|----------|
| Case & session | 4 | `case_init`, `case_activate`, `case_status`, `health` |
| Evidence intake & disk imaging | 10 | `evidence_register`, `get_image_info`, `get_partitions`, `extract_files`, `fls` |
| Memory forensics (Volatility) | 7 | `run_volatility`, `get_pslist`, `get_malfind`, `get_netscan`, `get_svcscan` |
| Registry / execution / shell artifacts | 16 | `get_registry`, `get_amcache`, `get_shimcache`, `get_prefetch`, EZ-Tools, EAR |
| Event logs & timeline | 6 | `get_evtx`, `get_timeline`, `correlate_timeline`, `detect_sweep` |
| Mail / maldoc / documents | 4 | `analyze_maldoc`, `carve_pst_iocs`, `email_header_matrix`, `pdf_extract_text` |
| File analysis & carving | 6 | `run_strings`, `run_bulk_extractor`, `run_foremost`, `run_exiftool`, `run_hashdeep`, `scan_yara` |
| Findings, IOCs & reporting | 7 | `record_finding`, `promote_iocs`, `pivot_on_ioc`, `report_generate`, `report_export` |
| Approval workflow (HMAC) | 2 | `approve_finding`, `retract_approval` |
| Indexer (OpenSearch) | 5 | `idx_ingest`, `idx_search`, `idx_aggregate`, `idx_timeline`, `idx_case_summary` |
| Wazuh SIEM | 5 | `wazuh_hunt_ioc`, `wazuh_check_intel`, `wazuh_index_findings`, `wazuh_publish_iocs`, `wazuh_vuln_query` |

State-mutating tools (`record_finding`, `idx_ingest`, `promote_iocs`, …) require a
one-shot **mutation token** (`AGENTROPIX_MUTATION_TOKEN`, minted via
`agentropix-sift evidence-gate mint`); approval tools require HMAC-signed examiner
authorization; every promote/ingest/publish/delete tool carries a `dry_run` guard.

---

## 16 SIFT forensic wrappers

> **Deep dive:** [The FastMCP Server](../02-architecture/mcp-server.md) (how wrappers are
> driven and hardened).

A **wrapper** is a Python module that drives one external forensic binary as a safe,
uniform subprocess. **SIFT** is the SANS Investigative Forensic Toolkit — the Linux
distribution whose curated forensic binaries this project targets. The canonical
**16 forensic wrappers / 16 SIFT tools** are the trusted command-line binaries the
engine drives and that `agentropix-sift doctor` (the install pre-flight check)
verifies are present. Each wrapper ships a consistent **hardening envelope** —
**timeout** (kill a hung tool), **memory ceiling** (cap RAM), **retry**,
**stderr-capture**, and **tracing** (record the exact command for the audit trail) —
and resolves its binary via an `AGENTROPIX_<TOOL>_TOOL` environment-variable override
so it can point at a SIFT-installed path.

| # | Binary | Provides | Wrapper |
|---|--------|----------|---------|
| 1 | `vol` (Volatility3) | Memory forensics | `wrappers/volatility.py` |
| 2 | `log2timeline.py` (Plaso) | Super timeline | `wrappers/plaso.py` |
| 3 | `fls` (Sleuth Kit) | Filesystem listing | `wrappers/tsk.py` |
| 4 | `icat` (Sleuth Kit) | File extraction | `wrappers/extract.py` |
| 5 | `mmls` (Sleuth Kit) | Partition table | `wrappers/tsk.py` / `gpt_parser.py` |
| 6 | `ewfinfo` (libewf) | E01 image metadata | `wrappers/ewf.py` |
| 7 | `evtx_dump.py` | Windows `.evtx` logs | `wrappers/evtx.py` |
| 8 | `yara` | Pattern matching | `wrappers/yara.py` |
| 9 | `bulk_extractor` | Feature scanning | `wrappers/bulk_extractor.py` |
| 10 | `rip.pl` (RegRipper) | Registry hives | `wrappers/regripper.py` |
| 11 | `pf` | Prefetch parsing | `wrappers/prefetch.py` |
| 12 | `amcache_parser` | Amcache execution evidence | `wrappers/amcache.py` |
| 13 | `shimcache_parser` | Shimcache (AppCompatCache) | `wrappers/shimcache.py` |
| 14 | `exiftool` | File metadata | `wrappers/exiftool.py` |
| 15 | `foremost` | File carving | `wrappers/foremost.py` |
| 16 | `hashdeep` | Multi-algorithm hashing / audit | `wrappers/hashdeep.py` |

Source: `README.md:151`, `CHANGELOG.md:449`, and the `doctor` tool dict in
`src/agentropix_sift/cli.py:176-196`. EZ-Tools (`RECmd`, `MFTECmd`, `LECmd`, `JLECmd`,
`SBECmd`, `SQLECmd`, `bstrings`, `SRUM`) ship as additional wrappers on top of the core
16. See [EZ-Tools integration](../02-architecture/ez-tools-integration.md) for how these
bind into the MCP surface.

---

## 7-agent Swarm (+ ATT&CK detectors)

> **Deep dive:** [The Swarm Agents & Blackboard](../02-architecture/swarm-agents.md)
> (architecture) · [`agents-list.md`](../10-agents/agents-list.md)
> (per-agent breakdown).

A **Swarm** is the set of independent specialist agents that run each iteration; the
**Blackboard** is the shared store they all read from and write findings to. The
"7-agent Swarm" is the seven first-class **DFIR** (Digital Forensics & Incident
Response) specialists. The runnable `SWARM` tuple (`agents/__init__.py`) additionally
interleaves six deterministic **ATT&CK detector** agents — small rule-based agents that
emit findings tagged with MITRE ATT&CK technique IDs (e.g. `T1055` = process injection).
The total of 13 `SWARM` classes (7 specialists + 6 detectors) and the "7-agent Swarm"
framing are both reconciled in [`canonical-facts.md`](../08-reference/canonical-facts.md).

| Specialist | Investigates | Drives |
|------------|--------------|--------|
| `MemoryAgent` | Suspicious/orphan processes, injected/RWX regions, credential-dump evidence | Volatility, process-tree correlation, secretsdump |
| `TimelineAgent` | Execution/LOLBin timeline, EID 4688 events, lateral-movement sweeps | Plaso, sweep detection |
| `FilesystemAgent` | Suspicious filenames, deleted artifacts, inode evidence (with payload hashes) | Sleuth Kit (`fls`) |
| `ArtifactAgent` | Registry/Amcache/Shimcache execution evidence, scheduled-task persistence | `extract_files` → registry/amcache/shimcache chain |
| `DiscoveryAgent` | MITRE Discovery techniques (T1018/T1069/T1083/T1087/T1135) | Reads TimelineAgent's EID 4688 off the Blackboard (no re-run) |
| `MailAgent` | T1566 phishing, lookalike domains, maldoc chains | `email_headers`, PST/memory carve, oletools |
| `HuntAgent` | High-confidence cross-source correlations (≥3-agent agreement) | The Blackboard (runs **last**) |

The six deterministic ATT&CK detectors (`detectors/`) emit ATT&CK-tagged findings:
YARA hunt (T1055 family), process injection (T1055.001/.002), null-session baseline
(T1087.002), IFEO/accessibility hijack (T1546.008), IEX loopback C2 (T1059.001), and
svchost outbound HTTP (T1071.001).

Each specialist appends a verifiable **completion-promise** token (e.g.
`TIMELINE_GENERATED`, `MEMORY_TRIAGED`) to `report.completion_proofs` when it publishes
at least one finding without a tool error — a machine-checkable proof that the agent
actually ran.

---

## Thymus read-only enforcement

> **Deep dive:** [Anti-Hallucination](../05-safety-forensics/anti-hallucination.md)
> (how fabricated findings are prevented).

The **Thymus** policy (`mcp_server/thymus_policy.py`, "S-02") is the immune-system gate
(named for the organ that screens what the immune system is allowed to act on). An
**allowlist** is the explicit set of evidence paths a tool is permitted to read; an
**audit ring** is a fixed-size, in-memory circular log of those accesses. The gate is:
**every** `mcp_*` tool call is checked against a path allowlist *before* any subprocess
spawns. Evidence is structurally read-only — **no agent is given a write tool to call**.
Each access is recorded to an in-memory audit ring (size
`AGENTROPIX_THYMUS_AUDIT_LOG_RING_SIZE`, default 1000) and, when
`AGENTROPIX_AUDIT_LOG` is set, to an on-disk JSONL chain-of-custody log. The report's
`thymus_audit[]` array carries the read-only access trail (`timestamp`, `action`,
`path`, `reason`).

---

## Courtroom seal — chain of custody you can verify

> **Deep dive:** [Audit & Courtroom Seal](../05-safety-forensics/audit-courtroom.md).

A **chain of custody** is the documented, tamper-evident record of who touched the
evidence and when; **HMAC** is a keyed cryptographic signature that proves a file has not
been altered since it was sealed. `courtroom.py` (ADR-016 / ADR-022 — see the
[ADR index](../08-reference/adr-index.md) for what an ADR is) provides the cryptographic
anchor that makes a report judge-verifiable:

- **`evidence_image_sha256`** — SHA-256 of the evidence image at session start, binding
  the report to the exact bytes triaged (operator-suppliable via
  `AGENTROPIX_EVIDENCE_SHA256` when auto-hash is unavailable).
- **`report_seal`** — HMAC-SHA256 over the canonicalized report JSON, verified against a
  per-run **session key** written at mode `0600`.
- **Audit-log sealing + cross-binding** — the Thymus audit log is sealed into
  `<stem>.audit-log.json` and its seal cross-bound into the report.

A single run produces three files: `report.json`, `<stem>.audit-log.json`, and
`<stem>.session-key`. The standalone `audit/verify_seal.py` (and `scripts/verify_seal.py`)
verify them independently.

---

## Provenance & grounding

> **Deep dive:** [Provenance & Grounding](../05-safety-forensics/provenance-grounding.md).

**Grounding** means every claim in a report traces back to a deterministic tool's output
rather than to model invention; **provenance** is the recorded lineage of where each
finding or IOC (Indicator of Compromise) came from. Grounding is enforced at three
layers:

1. **Tool-sourced findings** — every `Finding` carries `_source` naming the deterministic
   tool that produced it; `file_sha256` carries the SHA-256 of the byte payload behind the
   finding where one was hashed (`agents/_base.py`,
   [`schema-dump.md`](../03-data/schema-dump.md) §2).
2. **Inference constraint** — the report declares `inference_constraint = high` (ADR-016):
   the LLM orchestrates only, and every fact originates from a named MCP tool captured in
   `trace.tool_calls`.
3. **Provenance-chain validation** — `provenance/validate.py` (`validate_dir`) verifies
   each row's HMAC seal to confirm a sealed chain has not been tampered. IOC records carry
   a first-class `IOCProvenance` (source evidence hash, extraction tool, args, timestamp,
   analyst); `AGENTROPIX_REQUIRE_IOC_PROVENANCE` makes provenance mandatory.

---

## Approval sidecar (human-in-the-loop)

> **Deep dive:** [Human-in-the-Loop](../05-safety-forensics/human-in-the-loop.md)
> (the gate) · [The Approval Portal](../05-safety-forensics/approval-portal.md)
> (operator walkthrough).

A **sidecar** is a small companion service that runs alongside the main server and adds
one capability without being baked into it. For findings that need an examiner's
signature, the optional **approval sidecar**
(`approval_sidecar/`) is a standalone Starlette HMAC service implementing a
challenge/submit handshake: PBKDF2-derived examiner key (default **600,000**
iterations), TTL-bounded nonce (default 60 s), exactly-64-hex HMAC signature, and an
**append-only hash chain** of approval state transitions
(`DRAFT → APPROVED → REJECTED → REVOKED`). It exposes two MCP tools — `approve_finding`
and the compensating, append-only `retract_approval` — and ships a browser approval form
(`approval_sidecar/static/`). Bind/host/port and credentials are configured via
`AGENTROPIX_APPROVAL_SIDECAR_*` / `AGENTROPIX_APPROVER_*` env vars (see
[`env-vars.md`](../07-sdlc-ops/env-vars.md) §1).

---

## Wazuh SIEM integration

> **Deep dive:** [Wazuh Integration — Operator Guide](../09-integrations/wazuh-portal.md)
> · [Use Case: Push a Finding to Wazuh](../06-use-cases/uc-wazuh-push.md).

A **SIEM** (Security Information and Event Management) is a platform that aggregates
security alerts for monitoring; **Wazuh** is the open-source SIEM this integration
targets. A **kill switch** here is an environment flag that defaults the integration to
*off* so nothing is published unless an operator explicitly enables it. The `wazuh/`
package promotes case findings and IOCs into a Wazuh SIEM — finding→alert
mapping, CDB-list IOC publishing, index templates, and ISM retention — through five MCP
tools (`wazuh_hunt_ioc`, `wazuh_check_intel`, `wazuh_index_findings`,
`wazuh_publish_iocs`, `wazuh_vuln_query`). The integration is **default-deny**: it stays
off unless `WAZUH_INTEGRATION_ENABLED=true`, writes require `WAZUH_PUSH_ENABLED=true`,
`WAZUH_DRY_RUN_ONLY=true` forces dry-run, and an operator must affirm the target is not
production (`AGENTROPIX_INTEGRATION_NOT_PRODUCTION`, W-188). An active-response guard
protects RFC-1918/loopback CIDRs from ever being blocked
(`AGENTROPIX_AR_PROTECTED_CIDRS`). See [`env-vars.md`](../07-sdlc-ops/env-vars.md) for
the full kill-switch matrix.

---

## Chaos-tested resilience

> **Deep dive:** [Testing](../07-sdlc-ops/testing.md) (the full test taxonomy) ·
> [Recovery & Resilience](../07-sdlc-ops/recovery-resilience.md).

**Chaos testing** (fault injection) deliberately makes dependencies fail — timeouts,
out-of-memory, garbage output, missing binaries — to prove the system degrades safely
instead of crashing. Forensic tools fail in hostile ways — they time out, run out of
memory, emit malformed
output, or are missing entirely. Agentropix-SIFT treats those as first-class paths:
fault-injection (**chaos**) tests in `tests/chaos/test_fault_paths.py` exercise the
failure paths (the suite is marked `chaos` in `pyproject.toml` as
"fault-injection / resilience-path tests"). A missing tool degrades gracefully (it is
skipped, surfaced by `doctor`) rather than aborting the run, and each wrapper's
timeout/retry/memory-ceiling envelope contains a misbehaving binary.

The whole surface is covered by **4464 collected tests**
([`canonical-facts.md`](../08-reference/canonical-facts.md), `test_count = 4464`), spanning unit,
integration (real-subprocess), chaos, and end-to-end recall gates. On the real-data
recall gate (SANS SRL-2018 corpus), disk per-IOC recall is **72/72 (100%)** on the
regression suite and **108/118 (91.5%)** memory+disk combined — both pinned in
`canonical-facts.md` with their methodology caveats.

---

## Related ADRs

Each capability above traces to an Architecture Decision Record (genesis, why it was
built the way it is, what was deferred) in [Section 11 — ADRs](../11-ADR/README.md):

| Capability (above) | ADR(s) — decision record |
|--------------------|--------------------------|
| Trinity Loop (deterministic execution) | [ADR-002 · Execution Engine](../11-ADR/ADR-002-execution-engine.md) |
| 72 MCP tools — `extract_files` (raw-E01 extraction) | [ADR-012 · `mcp_extract_files`](../11-ADR/ADR-012-extract-files.md) |
| 72 MCP tools — `get_evtx` (Windows Event Log) | [ADR-013 · `mcp_get_evtx`](../11-ADR/ADR-013-evtx-wrapper.md) |
| Swarm data-fetch agents — shared evidence-type gate | [ADR-011 · Evidence-Type Gate Consolidation](../11-ADR/ADR-011-evidence-gates.md) |
| Thymus read-only enforcement | [ADR-008 · Safety Architecture](../11-ADR/ADR-008-safety-architecture.md) |
| Courtroom seal · Provenance & grounding (`inference_constraint = high`) | [ADR-016 · Courtroom Audit + Sealing](../11-ADR/ADR-016-courtroom-audit.md), [ADR-022 · Audit-Log Seal](../11-ADR/ADR-022-audit-log-seal.md) |
| Wazuh SIEM integration — IOC push | [ADR-018 · Wazuh IOC Push](../11-ADR/ADR-018-wazuh-ioc-push.md) |
| Wazuh SIEM integration — Active-Response CIDR guard / confirmation gate | [ADR-019 · Active Response Confirmation Gate](../11-ADR/ADR-019-ar-confirmation-gate.md); two-person rule [deferred — ADR-021](../11-ADR/ADR-021-two-person-rule-defer.md) |
| Wazuh credential handling | [ADR-020 · Wazuh Credential Lifecycle](../11-ADR/ADR-020-credential-lifecycle.md) |
| Report tiering (`report_export`) | [ADR-024 · Multi-Tier Report Generation Engine](../11-ADR/ADR-024-multi-tier-report-engine.md) |

## Next

- **[Quickstart](quickstart.md)** — install, `doctor` pre-flight, first triage run.
- **[What is Agentropix-SIFT?](what-is-agentropix.md)** — the problem, the positioning,
  and the pipeline diagram.
