# Agents List (shared reference)

> The Trinity Loop roles (Architect, Critic, Blackboard) and the DFIR Swarm agents. For each swarm
> agent: class name, role, the forensic tools/wrappers it drives, and the findings it produces.
> Derived from `src/agentropix_sift/agents/`, `src/agentropix_sift/detectors/`, and
> `src/agentropix_sift/trinity/`.

## Trinity Loop roles

| Role | Class / object | Source | Responsibility |
|------|----------------|--------|----------------|
| **Architect** | `Architect` | `trinity/architect.py:146` | Deterministic planner (no LLM). Returns the canonical `SWARM` tuple, optionally pruning agents the Critic marked stable. Preserves SWARM order so HuntAgent stays last. |
| **Swarm** | `SWARM` tuple | `agents/__init__.py` | Ordered tuple of agent classes run each iteration. Each agent investigates one dimension and publishes `Finding`s to the shared `Blackboard`. |
| **Critic** | `Critic` → `TrinityResult` | `trinity/critic.py:67` | Deterministic scorer (no LLM self-rating). Score = max finding confidence + 0.25·#correlations (capped 1.0). Halts when score ≥ `AGENTROPIX_CRITIC_HALT_THRESHOLD` (default 0.85) **OR** the per-pass fingerprint reaches a fixed point — gated by a min-iterations guard and a refusal to halt while any planned agent produced zero findings. |
| **Blackboard** | `Blackboard` + `Correlation` | `agents/_blackboard.py:74` | Asyncio-locked `(agent, Finding)` registry. `correlations()` surfaces tokens (filenames, hashes, IPs, PIDs) appearing across ≥`quorum_threshold` agents (default 2). Powers HuntAgent's cross-source correlation (S-05) and the Critic's score. |

The loop is **Architect proposes → 7-agent Swarm (plus deterministic ATT&CK detectors) runs
deterministic forensic tools → Critic scores and halts on a deterministic convergence fingerprint**.
No LLM rates the findings; every fact originates from a named deterministic MCP tool
(`inference_constraint = high`, ADR-016).

## The `SWARM` run order (13 classes)

From `agents/__init__.py`, run order matters — HuntAgent must be last because it consumes everyone
else's findings; the ATT&CK detectors and DiscoveryAgent are positioned so their inputs are already
on the Blackboard:

```
MemoryAgent → TimelineAgent → FilesystemAgent → ArtifactAgent → DiscoveryAgent →
NullSessionBaselineAgent → MailAgent → YARAHuntAgent → InjectionDetector →
AccessibilityIfeoHijackDetector → IexLoopbackC2Detector →
T1071SvchostOutboundHttpDetector → HuntAgent
```

## Core swarm specialists (the "7-agent Swarm")

Each declares `name` and a `completion_promise` token (M8.3d) appended to
`report.completion_proofs` when the agent publishes ≥1 Finding without a tool error.

| Agent class | `name` | `completion_promise` | Drives (wrappers / MCP tools) | Produces |
|-------------|--------|----------------------|-------------------------------|----------|
| `MemoryAgent` (`agents/memory.py:536`) | `memory` | `MEMORY_TRIAGED` | `mcp_get_pslist` (Volatility), `wrappers/volatility.py`, `wrappers/correlation.build_process_tree`, `wrappers/credentials` (secretsdump) | Suspicious/orphan processes, injected/RWX regions, credential-dump evidence; sets `evidence_dict` for cross-modal IOC fusion |
| `TimelineAgent` (`agents/timeline.py:252`) | `timeline` | `TIMELINE_GENERATED` | `mcp_get_timeline` (Plaso/log2timeline), `wrappers/correlation.detect_sweep` | Execution/LOLBin timeline events, EID 4688 process-creation events (consumed by DiscoveryAgent), lateral-movement sweeps |
| `FilesystemAgent` (`agents/filesystem.py:65`) | `filesystem` | `FILESYSTEM_WALKED` | `mcp_fls` (Sleuth Kit), `wrappers/tsk._read_inode` | Suspicious filenames, deleted-file artifacts, inode-level evidence (with `file_sha256` payload hashes) |
| `ArtifactAgent` (`agents/artifact.py:86`) | `artifact` | `ARTIFACTS_PARSED` | `mcp_extract_files` → `mcp_get_registry` / `mcp_get_amcache` / `mcp_get_shimcache` chain; `wrappers/scheduled_tasks` (T1053.005) | Registry/Amcache/Shimcache execution evidence, scheduled-task persistence; per-source cap of 50 |
| `DiscoveryAgent` (`agents/discovery.py:29`) | `discovery` | `DISCOVERY_ENUMERATED` | **No re-run** — reads TimelineAgent's EID 4688 findings off the Blackboard; `_discovery_detectors` regex match | MITRE Discovery techniques T1018, T1069, T1083, T1087, T1135. Disk-only (early-returns on memory images) |
| `MailAgent` (`agents/mail.py:165`) | `mail` | `MAIL_TRIAGED` | `mcp_list_files`, top-level `wrappers/email_headers`, `wrappers/memory_mail_carve`, `_mail_maldoc_chain` (oletools) | T1566 phishing findings from carved Outlook/PST artefacts, lookalike-domain headers, maldoc-chain attachment analysis |
| `HuntAgent` (`agents/hunt.py:68`) | `hunt` | `CROSS_AGENT_CORRELATION_DONE` | **No wrappers** — consumes `blackboard.correlations()` | High-confidence cross-source correlation findings (S-05: ≥3-agent agreement). Runs LAST |

## Deterministic ATT&CK detector agents

Also `SwarmAgent` subclasses (in `detectors/`), interleaved into `SWARM` so their inputs are on the
Blackboard. Deterministic, no LLM; emit ATT&CK-tagged findings.

| Detector class | `name` | ATT&CK | Source | Produces |
|----------------|--------|--------|--------|----------|
| `YARAHuntAgent` | `yara_hunt` | T1055 family | `detectors/yara_hunt.py:148` | YARA rule matches over memory/files (drives `yara`); promise `YARA_HUNT_COMPLETE` |
| `InjectionDetector` | (injection) | T1055 / T1055.001 / T1055.002 | `detectors/injection_detector.py` | Process-injection indicators (code cave, PE injection) |
| `NullSessionBaselineAgent` | `null_session_baseline` | T1087.002 | `detectors/t1087_002_null_session_baseline.py:441` | Null-session account-discovery anomalies vs baseline (z-threshold); promise `NULL_SESSION_BASELINE_COMPLETE` |
| `AccessibilityIfeoHijackDetector` | (ifeo) | T1546.008 | `detectors/t1546_008_accessibility_ifeo_hijack.py` | IFEO / accessibility-feature debugger hijack persistence |
| `IexLoopbackC2Detector` | `t1059_001_iex_loopback_c2` | T1059.001 | `detectors/t1059_001_iex_loopback_c2.py:429` | PowerShell IEX loopback C2 (script-block hashing); promise `T1059_001_IEX_LOOPBACK_SCAN_COMPLETE` |
| `T1071SvchostOutboundHttpDetector` | `t1071_001_svchost_outbound_http` | T1071.001 | `detectors/t1071_001_svchost_outbound_http.py:215` | svchost outbound HTTP beaconing; promise `T1071_001_SVCHOST_OUTBOUND_HTTP_COMPLETE` |

## Agent contract notes (for chapter authors)

- All agents extend `SwarmAgent` (`agents/_base.py:95`): implement `async investigate(image)`,
  base `run()` applies the per-agent finding cap (`AGENTROPIX_AGENT_FINDING_CAP`, default 500),
  stamps `Finding.agent = self.name` (W-196, enables per-agent recall), and publishes to the
  Blackboard. Investigations must be idempotent (S-08: same seed → identical trace).
- Agents are **pure async coroutines over the MCP boundary** — no LLM coupling. The Trinity roles
  (Architect/Critic) orchestrate; they do not author findings.
- The "7-agent Swarm" of project prose = the 7 first-class specialists above. The runnable `SWARM`
  tuple is 13 classes (specialists + 6 detectors). When stating a count, prefer "7 core specialists
  + ATT&CK detectors" and cite `agents/__init__.py` (see `.crew/facts.md` note).
