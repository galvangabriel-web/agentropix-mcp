# Tools by Agent

> **Which swarm agent invokes which tools.** The DFIR swarm is the *consumer* of the
> [71 MCP tools](tool-reference.md): each `SwarmAgent` investigates one dimension and drives a specific
> subset of wrappers, publishing `Finding`s to the shared Blackboard. This page maps every agent to the
> tools/wrappers it calls. Derived from `src/agentropix_sift/agents/`, `src/agentropix_sift/detectors/`,
> and the agent contract in `.crew/agents-list.md`.

Related: [Tool reference](tool-reference.md) · [Response envelope](response-envelope.md) ·
[Trinity Loop](../02-architecture/trinity-loop.md) · [Agents](../02-architecture/swarm-agents.md).

---

## The two-layer picture

The Architect proposes the canonical `SWARM` tuple; the Swarm runs deterministic forensic tools; the
Critic scores and halts on a deterministic convergence fingerprint (no LLM self-rating). The agents are
**pure async coroutines over the MCP boundary** — no LLM coupling. The `SWARM` run order (13 classes,
`agents/__init__.py`) matters because correlation-only agents must run after their inputs are on the
Blackboard:

```mermaid
graph LR
  M[MemoryAgent] --> T[TimelineAgent] --> F[FilesystemAgent] --> A[ArtifactAgent] --> D[DiscoveryAgent]
  D --> NS[NullSessionBaselineAgent] --> ML[MailAgent] --> YH[YARAHuntAgent]
  YH --> IJ[InjectionDetector] --> IF[AccessibilityIfeoHijackDetector]
  IF --> IX[IexLoopbackC2Detector] --> SV[T1071SvchostOutboundHttpDetector] --> H[HuntAgent]
  classDef derived fill:#eef,stroke:#557;
  class D,H derived;
```

DiscoveryAgent and HuntAgent (shaded) run **no wrappers at all** — they read prior findings/correlations
off the Blackboard. Everyone upstream of them must have published first, which is why run order is
fixed and HuntAgent is always last (`.crew/agents-list.md`). This is the structural reason the
correlation/derived tools in the [tool reference](tool-reference.md#three-kinds-of-tool) exist as a
distinct class.

---

## Core swarm specialists (the "7-agent Swarm") → tools

Each specialist declares a `name` and a `completion_promise` token appended to
`report.completion_proofs` when it publishes ≥1 Finding without a tool error (M8.3d).

| Agent (`name`) | Source | MCP tools / wrappers it invokes | Produces |
|----------------|--------|---------------------------------|----------|
| **MemoryAgent** (`memory`) | `agents/memory.py:536` | `get_pslist` (Volatility); `wrappers/volatility.py`; `build_process_tree` (`wrappers/correlation.py`); `wrappers/credentials` (impacket secretsdump) | Suspicious/orphan processes, injected/RWX regions, credential-dump evidence; sets `evidence_dict` for cross-modal IOC fusion |
| **TimelineAgent** (`timeline`) | `agents/timeline.py:252` | `get_timeline` (Plaso / `log2timeline.py`); `detect_sweep` (`wrappers/correlation.py`) | Execution/LOLBin timeline events, EID 4688 process-creation events (consumed by DiscoveryAgent), lateral-movement sweeps |
| **FilesystemAgent** (`filesystem`) | `agents/filesystem.py:65` | `fls` (Sleuth Kit); `wrappers/tsk._read_inode` | Suspicious filenames, deleted-file artifacts, inode-level evidence (with `file_sha256` payload hashes) |
| **ArtifactAgent** (`artifact`) | `agents/artifact.py:86` | `extract_files` → `get_registry` / `get_amcache` / `get_shimcache` chain; `wrappers/scheduled_tasks` (T1053.005) | Registry/Amcache/Shimcache execution evidence, scheduled-task persistence; per-source cap of 50 |
| **DiscoveryAgent** (`discovery`) | `agents/discovery.py:29` | **No re-run** — reads TimelineAgent's EID 4688 findings off the Blackboard; `_discovery_detectors` regex match | MITRE Discovery techniques T1018, T1069, T1083, T1087, T1135. Disk-only (early-returns on memory images) |
| **MailAgent** (`mail`) | `agents/mail.py:165` | `list_files`; top-level `wrappers/email_headers`; `wrappers/memory_mail_carve`; `_mail_maldoc_chain` (oletools) | T1566 phishing findings from carved Outlook/PST artefacts, lookalike-domain headers, maldoc-chain attachment analysis |
| **HuntAgent** (`hunt`) | `agents/hunt.py:68` | **No wrappers** — consumes `blackboard.correlations()` | High-confidence cross-source correlation findings (S-05: ≥3-agent agreement). Runs LAST |

### Notes on the specialist mappings

- **MemoryAgent** is the one swarm agent that touches the credential-dump path
  (`wrappers/credentials`, impacket `secretsdump`, W-072/ADR-014) in addition to the Volatility memory
  tools. Its `build_process_tree` call is a *derived* tool — it correlates the `get_pslist` output it
  already produced (see [response envelope → derived tools](response-envelope.md)).
- **TimelineAgent → DiscoveryAgent** is a producer/consumer pair: TimelineAgent emits EID 4688
  process-creation events; DiscoveryAgent re-reads them off the Blackboard and never re-runs a wrapper.
- **ArtifactAgent** runs a *chain*: `extract_files` pulls hives out of the image, then
  `get_registry`/`get_amcache`/`get_shimcache` parse them — capped at 50 findings per source.
- **HuntAgent** runs last and invokes zero forensic tools; its entire input is the Blackboard's
  `correlations()` (tokens appearing across ≥ quorum agents, default 2).

---

## Deterministic ATT&CK detector agents → tools

Also `SwarmAgent` subclasses (in `detectors/`), interleaved into `SWARM` so their inputs are already on
the Blackboard. Deterministic, no LLM; they emit ATT&CK-tagged findings.

| Detector (`name`) | ATT&CK | Source | Tools / wrappers driven | Produces |
|-------------------|--------|--------|-------------------------|----------|
| **YARAHuntAgent** (`yara_hunt`) | T1055 family | `detectors/yara_hunt.py:148` | `scan_yara` (drives `yara`) over memory/files | YARA rule matches; promise `YARA_HUNT_COMPLETE` |
| **InjectionDetector** | T1055 / .001 / .002 | `detectors/injection_detector.py` | Reads memory findings (`get_malfind`/pslist context) off the Blackboard | Process-injection indicators (code cave, PE injection) |
| **NullSessionBaselineAgent** (`null_session_baseline`) | T1087.002 | `detectors/t1087_002_null_session_baseline.py:441` | Reads account-discovery events; baseline z-threshold | Null-session account-discovery anomalies vs baseline; promise `NULL_SESSION_BASELINE_COMPLETE` |
| **AccessibilityIfeoHijackDetector** | T1546.008 | `detectors/t1546_008_accessibility_ifeo_hijack.py` | Reads registry/IFEO artefacts off the Blackboard | IFEO / accessibility-feature debugger hijack persistence |
| **IexLoopbackC2Detector** (`t1059_001_iex_loopback_c2`) | T1059.001 | `detectors/t1059_001_iex_loopback_c2.py:429` | Script-block hashing over PowerShell evidence | PowerShell IEX loopback C2; promise `T1059_001_IEX_LOOPBACK_SCAN_COMPLETE` |
| **T1071SvchostOutboundHttpDetector** (`t1071_001_svchost_outbound_http`) | T1071.001 | `detectors/t1071_001_svchost_outbound_http.py:215` | Reads `get_netscan` / process context off the Blackboard | svchost outbound HTTP beaconing; promise `T1071_001_SVCHOST_OUTBOUND_HTTP_COMPLETE` |

> The detectors mostly *consume* what the specialists already published (network sockets from
> `get_netscan`, memory regions from `get_malfind`, registry hits from `get_registry`), with
> YARAHuntAgent the exception that drives a binary (`yara`) of its own. That interleave is exactly why
> they sit after the specialists in the `SWARM` run order.

---

## Tool → invoking agent (reverse index)

The same mapping inverted, for the forensic execution tools that an agent drives directly. (Case-state,
reporting, indexer, Wazuh, and approval tools are invoked by the **orchestrator / CLI / operator**, not
by individual swarm agents — see note below.)

| Tool | Binary / kind | Invoking agent(s) |
|------|---------------|-------------------|
| `get_pslist` | Volatility (memory) | MemoryAgent |
| `build_process_tree` | derived | MemoryAgent |
| `get_malfind` | Volatility (memory) | (consumed by) InjectionDetector |
| `get_netscan` | Volatility (memory) | (consumed by) T1071SvchostOutboundHttpDetector |
| `get_timeline` | Plaso | TimelineAgent |
| `detect_sweep` | derived | TimelineAgent |
| `fls` | Sleuth Kit | FilesystemAgent |
| `extract_files` | Sleuth Kit `icat` | ArtifactAgent |
| `get_registry` | RegRipper | ArtifactAgent (+ consumed by IFEO detector) |
| `get_amcache` | EZ-Tools | ArtifactAgent |
| `get_shimcache` | EZ-Tools | ArtifactAgent |
| `list_files` | Sleuth Kit | MailAgent |
| `scan_yara` | `yara` | YARAHuntAgent |
| `blackboard.correlations()` | derived | HuntAgent, DiscoveryAgent |

> **Scope note.** The agent-to-tool mappings above are the forensic-read tools the swarm drives during
> a triage iteration. The remaining tool families — case lifecycle (`case_init`/`case_status`),
> findings/IOC persistence (`record_finding`, `promote_iocs`), reporting (`report_generate`/
> `report_export`), OpenSearch indexer (`idx_*`), Wazuh (`wazuh_*`), and approval
> (`approve_finding`/`retract_approval`) — are driven by the orchestrator, the CLI, or a human examiner
> around the swarm run, not by an individual `SwarmAgent`. Several are state-mutating and gated; see
> [response envelope → mutation & approval gating](response-envelope.md#mutation--approval-gating).

---

## Why this mapping is deterministic

Every agent extends `SwarmAgent` (`agents/_base.py:95`): the base `run()` applies the per-agent finding
cap (`AGENTROPIX_AGENT_FINDING_CAP`, default 500), stamps `Finding.agent = self.name` (W-196, enabling
per-agent recall), and publishes to the Blackboard. Investigations must be idempotent (S-08: same seed
→ identical trace). Because each agent calls a *fixed* set of deterministic MCP tools and every fact
originates from a named tool captured in `trace.tool_calls`, the run is replayable and the Critic's
score (max finding confidence + 0.25·#correlations, capped at 1.0) is reproducible — no LLM rates the
findings. See [Trinity Loop](../02-architecture/trinity-loop.md) and
[response envelope → availability & skip signalling](response-envelope.md#availability--skip-signalling).
