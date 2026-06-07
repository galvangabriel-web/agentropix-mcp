# Use Case — Memory Triage with Volatility

> **Actor:** DFIR analyst (or an MCP-driving agent) hunting command-and-control in a memory image.
> **Goal:** From a memory capture, surface anomalous processes, injected code, outbound sockets, and
> services, then pivot a confirmed IOC across hosts — all through deterministic Volatility3-backed
> MCP tools.
> **Surfaces exercised:** the memory MCP tools (`mcp_server/wrappers/volatility.py`,
> `wrappers/correlation.py`) and the `MemoryAgent` swarm specialist. See
> [`canonical-facts.md`](../08-reference/canonical-facts.md) for numeric claims (memory recall = **108/118, 91.5%**).

Memory triage is the second forensic dimension of the engine. As with the disk path, there are two
entry points: the **autonomous** `agentropix-sift run` over a memory image (the `MemoryAgent` runs
first in the SWARM, `agents/__init__.py`), and the **granular MCP chain** an interactive agent
issues (modelled on Playbook B, `docs/guides/playbooks.md`). The disk path tells you *what ran*;
the memory path tells you *the parent/child shape and live network posture* of the host.

> **Note on `DiscoveryAgent`:** it is disk-only and early-returns on memory images
> (`agents/discovery.py`; [`agents-list.md`](../10-agents/agents-list.md)). On a pure memory
> capture, the memory/timeline/hunt specialists and the ATT&CK detectors do the work.

---

## Contents — what's in this page (and what to expect)

> Jump to any section below. Each row tells you what that part gives you, so you can go straight to your point.

| Section | What you'll get |
|---|---|
| [How to read this page (two audience tracks)](#how-to-read-this-page-two-audience-tracks) | The two audience tracks (🖥️ expert MCP call vs 💬 end-user prompt), the real-data preface (memory recall **108/118, 91.5%**), and how the GOTCHA boxes work. |
| [Use-case diagram](#use-case-diagram) | A diagram of the memory triage flow — baseline processes, sockets, injected code, services, then `pivot_on_ioc` across hosts (with the egress-gated intel edge). |
| [Sequence — memory C2 hunt (granular MCP chain)](#sequence--memory-c2-hunt-granular-mcp-chain) | The interactive tool-by-tool hunt order and why it runs that way, from `get_pslist` baseline through to the cross-host pivot. |
| [Sequence — autonomous `run` over a memory image (MemoryAgent path)](#sequence--autonomous-run-over-a-memory-image-memoryagent-path) | How the autonomous `agentropix-sift run` drives the SWARM — `MemoryAgent` first, `HuntAgent` last, Critic halt, sealed report. |
| [Actor, preconditions, steps, postconditions](#actor-preconditions-steps-postconditions) | The full dual-audience walkthrough: preconditions, 9 numbered steps (each with Execution → Output), postconditions, and the CLI commands. |
| [See also](#see-also) | Links to the disk-triage counterpart, approval gate, Wazuh push, and the tool/agent reference lists. |

---

## How to read this page (two audience tracks)

This use case is **operational**, so every memory tool below is shown **two ways** — pick the track
that matches you and follow it consistently. Both tracks hit the **same deterministic
Volatility3-backed MCP tool** and return the **same facts**; only the surface differs.

> **🖥️ Expert (command):** the exact MCP tool call (and, where relevant, the `run_volatility` /
> CLI equivalent) to issue against the running `agentropix-sift-mcp` server.
> **💬 End-user (prompt):** the plain-language question to type into a Claude Desktop / Claude CLI
> session that has the Agentropix MCP connected. A simple, focused question is enough — the session
> recognises it as an Agentropix capability and routes it to the right MCP tool automatically.
> *Adapt Agentropix to the user, not the user to Agentropix.*

**Real-data preface.** The "validated output" snippets below come from the **2026-05-05 full-case
evaluation run** (`Reports_results/FULL-CASE-20260505T004738Z/`, the source of the canonical recall
figures). The memory dimension of that run scored **108/118 (91.5%) combined recall** — and **30/40
(75%) on the credential-dumping technique T1003.002** specifically (cite
[`canonical-facts.md`](../08-reference/canonical-facts.md): `memory_recall_combined = 108/118`,
`memory_recall_T1003_002 = 30/40`). Your own run will produce *different* PIDs, addresses, and
timestamps, but the *shape* of each result will match. Where a number is quoted, it is what the
platform actually returned.

> ⚠️ **What a GOTCHA box is.** Boxes marked ⚠️ flag real-data quirks of memory forensics — a
> paused-VM image that needs `psscan` instead of `pslist`, an egress-gated tool that no-ops without a
> key, a Vol2.6-only plugin. Each explains the snag for **both** audiences: the symptom, and the fix.

---

## Use-case diagram

```mermaid
graph TD
    analyst([DFIR Analyst / Agent])

    subgraph sift["Agentropix-SIFT"]
        UC1["get_pslist / build_process_tree:<br/>baseline + parent-child anomaly"]
        UC2["get_netscan: outbound sockets"]
        UC3["get_malfind: RWX / injected code"]
        UC4["get_svcscan: service persistence"]
        UC5["pivot_on_ioc: campaign view across hosts"]
        UC6["threat_intel_lookup (egress-gated)"]
        UC7["MemoryAgent finding -> Blackboard"]
    end

    analyst --> UC1
    analyst --> UC2
    analyst --> UC3
    analyst --> UC4
    UC1 --> UC5
    UC2 --> UC5
    UC4 --> UC5
    UC5 -.optional.-> UC6
    UC1 --> UC7

    classDef actor fill:#d0bfff,stroke:#7048e8,color:#2b1a52
    classDef core fill:#b2f2bb,stroke:#2f9e44,color:#15391f
    classDef sink fill:#ffec99,stroke:#f08c00,color:#5c4400
    classDef ext fill:#e9ecef,stroke:#495057,color:#212529

    class analyst actor
    class UC1,UC2,UC3,UC4,UC5 core
    class UC7 sink
    class UC6 ext

    style sift fill:#f1f3f5,stroke:#868e96,color:#212529
```

> 🔍 **[Open as SVG — full size, zoomable](assets/uc-memory-triage-1.svg)** (renders larger than the page column; the SVG zooms losslessly in a browser tab).

The analyst baselines processes, then inspects sockets, injected code, and services. A confirmed
indicator (a C2 IP, a process name, a service) is pivoted across every host via `pivot_on_ioc`,
turning a single-host hit into a campaign view. `threat_intel_lookup` is a dashed (optional) edge
because it is **egress-gated** — a no-op unless `AGENTROPIX_ALLOW_EGRESS=1`
([`env-vars.md`](../07-sdlc-ops/env-vars.md) §6).

---

## Sequence — memory C2 hunt (granular MCP chain)

```mermaid
sequenceDiagram
    autonumber
    actor Agent
    participant MCP as FastMCP server
    participant Thymus as ThymusEvidencePolicy
    participant Vol as wrappers/volatility.py (vol3)
    participant Corr as wrappers/correlation.py

    Agent->>MCP: get_pslist(image=base-hunt-memory.raw)
    MCP->>Thymus: check_read(image)
    MCP->>Vol: windows.pslist
    Vol-->>Agent: process list + PIDs (baseline)
    Agent->>MCP: build_process_tree(image)
    MCP->>Corr: link by PPID (psscan fallback on paused-VM)
    Corr-->>Agent: roots / orphans (DKOM) / suspicious_count (LOLBins)
    Agent->>MCP: get_netscan(image)
    MCP->>Vol: windows.netscan
    Vol-->>Agent: typed TCP/UDP rows (state, pid, foreign_addr)
    Note over Agent: join netscan pid -> process tree to attribute the socket
    Agent->>MCP: get_malfind(image)
    MCP->>Vol: windows.malfind
    Vol-->>Agent: RWX VAD / injected-code hexdump
    Agent->>MCP: get_svcscan(image)
    MCP->>Vol: windows.svcscan
    Vol-->>Agent: pool-tag service rows (C2 persistence)
    Agent->>MCP: pivot_on_ioc(ioc, images=[...], ioc_type=ip)
    MCP-->>Agent: per-host hits across pslist/netscan/svcscan/evtx
    opt egress allowed
        Agent->>MCP: threat_intel_lookup(indicator, providers)
        MCP-->>Agent: VT/OTX enrichment (or egress_allowed=False)
    end
```

The hunt order is intentional: `get_pslist` (`windows.pslist`) establishes the baseline PIDs;
`build_process_tree` links them by PPID with a `psscan` fallback for paused-VM images and flags
**LOLBins** (e.g. `rubyw.exe`, `mshta.exe`) spawned under sensitive parents (`services.exe`,
`lsass.exe`) plus **orphans** (a DKOM/hollowing indicator). `get_netscan` returns typed socket rows
whose `pid` you join back to the tree to attribute an outbound connection to a process;
`get_malfind` confirms in-memory injection; `get_svcscan` finds service-installed persistence
(robust on paused/corrupted images). The typed renderers are preferred over
`run_volatility("netscan")` for structured rows (`docs/guides/playbooks.md` §B). `pivot_on_ioc`
fans the confirmed indicator out across every host — the bridge into cross-host correlation.

---

## Sequence — autonomous `run` over a memory image (MemoryAgent path)

```mermaid
sequenceDiagram
    autonumber
    actor Analyst
    participant CLI as agentropix-sift run
    participant Orch as orchestrator.run_triage
    participant Mem as MemoryAgent
    participant Hunt as HuntAgent
    participant BB as Blackboard
    participant Critic as Critic

    Analyst->>CLI: agentropix-sift run base-hunt-memory.raw -o mem-report.json
    CLI->>Orch: run_triage(image, max_iterations=5)
    Orch->>Mem: run(image)
    Note over Mem: MemoryAgent runs first in SWARM
    Mem->>Mem: get_pslist + build_process_tree + secretsdump (credentials)
    Mem->>BB: publish suspicious/orphan procs, injected regions
    Note over Mem: emits MEMORY_TRIAGED promise on >=1 finding
    Orch->>Hunt: run(image)
    Note over Hunt: HuntAgent runs LAST
    Hunt->>BB: read correlations() (>=2-agent token agreement)
    Hunt->>BB: publish CROSS_AGENT_CORRELATION_DONE findings
    Orch->>Critic: score(blackboard, planned_agents, iteration)
    Critic-->>Orch: TrinityResult (halt on >=0.85 or fingerprint)
    Orch-->>CLI: TriageReport (sealed by CLI)
```

In the autonomous path the `MemoryAgent` (`agents/memory.py`) runs **first** in the SWARM — it drives
`mcp_get_pslist`, `build_process_tree`, and the `wrappers/credentials` secretsdump path, then sets
`evidence_dict` for cross-modal IOC fusion and emits the `MEMORY_TRIAGED` completion promise once it
publishes ≥1 finding. The `HuntAgent` runs **last** because it consumes everyone else's findings via
`blackboard.correlations()` — tokens (IPs, hashes, PIDs) appearing across ≥`quorum_threshold`
(default 2) agents become high-confidence cross-source findings
([`agents-list.md`](../10-agents/agents-list.md)).

---

## Actor, preconditions, steps, postconditions

**Actor:** DFIR analyst, or an MCP client agent driving the server.

**Preconditions**

- Volatility3 (`vol`) is installed and resolvable — verify with `agentropix-sift doctor`.
- A memory image (`.raw`, `.mem`, `.lime`, etc.) exists; its parent directory becomes Thymus-allowed
  on first access.
- For `get_editbox` (Vol2.6 typed-credential recovery), the Py2.7 sandbox is configured
  (`docs/runbooks/vol26-install.md`; `AGENTROPIX_VOL26_BIN`). This step is optional.
- For `threat_intel_lookup`, egress must be explicitly enabled (`AGENTROPIX_ALLOW_EGRESS=1`) and a
  provider key supplied — otherwise it returns `egress_allowed=False` with no network call.

**Numbered steps (granular MCP path) — dual-audience walkthrough**

Each step below carries a **🖥️ Expert / 💬 End-user** callout and a labelled **Execution → Output**
pair. The Output snippets are from the validated 2026-05-05 run (memory recall **108/118, 91.5%**;
T1003.002 credential dumping **30/40, 75%** — [`canonical-facts.md`](../08-reference/canonical-facts.md)).

**Step 1 — Baseline the process set (`get_pslist`).**

> **🖥️ Expert (MCP call):**
> ```text
> get_pslist { "image":"/evidence/srl2018/base-hunt-memory.raw" }
> ```
> (Escape-hatch equivalent: `run_volatility { "target":"...raw", "plugin":"windows.pslist" }`.)
> **💬 End-user (prompt):** *"What processes were running in this memory image — give me the list with
> their PIDs."*
> The session calls `get_pslist` (which drives Volatility3 `windows.pslist`) and reports the process
> list. **A simple, focused question is enough — the session routes it to the right Volatility tool.**

**Execution A → Output A.**

*Execution A:* `get_pslist { "image":"...base-hunt-memory.raw" }`

*Output A (shape, from the validated run):* a typed row per live process — `pid`, `ppid`,
`name`, `create_time`, `exit_time`, `threads`. These baseline PIDs are what every later step joins
back to. (This is the first of the memory primitives that together contribute the **108/118** combined
memory recall.)

**Step 2 — Link the tree, flag anomalies (`build_process_tree`).**

> **🖥️ Expert (MCP call):**
> ```text
> build_process_tree { "image":"/evidence/srl2018/base-hunt-memory.raw" }
> ```
> **💬 End-user (prompt):** *"Show me the parent/child process tree and flag anything suspicious —
> orphans or odd parents."*
> The session calls `build_process_tree` (`wrappers/correlation.py`), which links PIDs by PPID (with a
> `psscan` fallback on paused-VM images) and surfaces orphans and LOLBin anomalies in plain language.

**Execution B → Output B.**

*Execution B:* `build_process_tree { "image":"...base-hunt-memory.raw" }`

*Output B (shape, validated run):* `roots`, `orphans` (a DKOM / process-hollowing indicator), and a
`suspicious_count` of **LOLBins** (e.g. `rubyw.exe`, `mshta.exe`) spawned under sensitive parents
(`services.exe`, `lsass.exe`).

> ⚠️ **GOTCHA (paused-VM images):** if `windows.pslist` returns a thin or empty list on a paused /
> snapshotted VM, `build_process_tree` automatically falls back to `psscan` (pool-tag scanning) to
> rebuild the forest. *(End-user: the assistant handles the fallback for you.)*

**Step 3 — Outbound sockets, attributed to a process (`get_netscan`).**

> **🖥️ Expert (MCP call):**
> ```text
> get_netscan { "image":"/evidence/srl2018/base-hunt-memory.raw" }
> ```
> **💬 End-user (prompt):** *"What network connections were open in this image, and which process owned
> each one?"*
> The session calls `get_netscan` (Volatility3 `windows.netscan`) and joins each socket's `pid` back to
> the process tree from Step 2 so it can tell you *which* process held the connection.

**Execution C → Output C.**

*Execution C:* `get_netscan { "image":"...base-hunt-memory.raw" }`

*Output C (shape, validated run):* typed TCP/UDP rows — `proto`, `local_addr`, `foreign_addr`,
`state`, `pid`, `owner`. Join the `pid` back to Step 2's tree to attribute an outbound C2 socket to a
named process.

**Step 4 — Injected / RWX code (`get_malfind`).**

> **🖥️ Expert (MCP call):**
> ```text
> get_malfind { "image":"/evidence/srl2018/base-hunt-memory.raw" }
> ```
> **💬 End-user (prompt):** *"Is there any injected or RWX code in this memory image?"*
> The session calls `get_malfind` (Volatility3 `windows.malfind`) and reports the RWX VAD regions and
> the injected-code hexdumps it found.

**Execution D → Output D.**

*Execution D:* `get_malfind { "image":"...base-hunt-memory.raw" }`

*Output D (shape, validated run):* per-region `pid`, `process`, `start_vpn`/`end_vpn`, `protection`
(`PAGE_EXECUTE_READWRITE`), and a `hexdump` of the injected bytes — the in-memory confirmation of
code injection.

**Step 5 — Service-installed persistence (`get_svcscan`).**

> **🖥️ Expert (MCP call):**
> ```text
> get_svcscan { "image":"/evidence/srl2018/base-hunt-memory.raw" }
> ```
> **💬 End-user (prompt):** *"List the Windows services in this image — anything that looks like
> malware persistence?"*
> The session calls `get_svcscan` (Volatility3 `windows.svcscan`, robust on paused/corrupted images)
> and flags service rows that look like C2 persistence.

**Execution E → Output E.**

*Execution E:* `get_svcscan { "image":"...base-hunt-memory.raw" }`

*Output E (shape, validated run):* pool-tag service rows — `name`, `display_name`, `state`, `start`,
`type`, `binary_path` — surfacing service-installed persistence.

**Step 6 — Typed credentials in Edit controls (`get_editbox`, optional, Vol2.6).**

> **🖥️ Expert (MCP call):**
> ```text
> get_editbox { "image":"/evidence/srl2018/base-hunt-memory.raw", "profile":"<vol2.6 profile>" }
> ```
> **💬 End-user (prompt):** *"Recover any text typed into edit/login boxes that's still in memory."*
> The session calls `get_editbox` (`wrappers/editbox.py`), the Vol2.6 typed-credential recovery path.

**Execution F → Output F.**

*Execution F:* `get_editbox { "image":"...base-hunt-memory.raw", "profile":"..." }`

*Output F (shape):* recovered Edit-control text (e.g. credentials typed into a login dialog). This is
part of the credential-dumping surface that the validated run scored **30/40 (75%)** on for T1003.002
([`canonical-facts.md`](../08-reference/canonical-facts.md): `memory_recall_T1003_002`).

> ⚠️ **GOTCHA (Vol2.6 sandbox):** `get_editbox` needs the Py2.7 Volatility-2.6 sandbox configured
> (`AGENTROPIX_VOL26_BIN`; `docs/runbooks/vol26-install.md`). Without it the tool self-skips — this
> step is optional and degrades gracefully. *(End-user: the assistant skips it cleanly if the sandbox
> isn't installed.)*

**Step 7 — Escape hatch: any allowlisted plugin (`run_volatility`).**

> **🖥️ Expert (MCP call):**
> ```text
> run_volatility { "target":"/evidence/srl2018/base-hunt-memory.raw",
>                  "plugin":"windows.cmdline", "args":[] }
> ```
> **💬 End-user (prompt):** *"Run the Volatility command-line plugin on this image and show me each
> process's launch arguments."*
> The session calls `run_volatility` with any allowlisted `windows.*` plugin when no typed wrapper
> exists. The typed renderers (Steps 1–5) are preferred for structured rows; reach for `run_volatility`
> only for plugins without a dedicated tool.

**Execution G → Output G.**

*Execution G:* `run_volatility { "target":"...raw", "plugin":"windows.cmdline" }`

*Output G (shape):* the raw-but-parsed plugin output for the requested `windows.*` plugin (here,
per-process command lines).

**Step 8 — Pivot the confirmed IOC across hosts (`pivot_on_ioc`).**

> **🖥️ Expert (MCP call):**
> ```text
> pivot_on_ioc { "ioc":"<C2 IP or hash>",
>                "images":["host-01-memory.raw","host-02-memory.raw"],
>                "ioc_type":"ip" }
> ```
> **💬 End-user (prompt):** *"Pivot on this C2 IP across every host in the case — which machines did it
> touch?"*
> The session calls `pivot_on_ioc` (`wrappers/ioc_registry.py`), which fans the indicator out across
> every image and groups the hits by host and artifact type — turning a single-host hit into a campaign
> view.

**Execution H → Output H.**

*Execution H:* `pivot_on_ioc { "ioc":"...", "images":[...], "ioc_type":"ip" }`

*Output H (shape, validated run):* per-host hit groups across `pslist` / `netscan` / `svcscan` /
`evtx`, so you can see exactly which machines the indicator appears on.

**Step 9 — Threat-intel enrichment (`threat_intel_lookup`, optional, egress-gated).**

> **🖥️ Expert (MCP call):**
> ```text
> threat_intel_lookup { "indicator":"<C2 IP or hash>",
>                       "indicator_type":"ip",
>                       "providers":["virustotal","otx"] }
> ```
> **💬 End-user (prompt):** *"Look up this indicator against threat intelligence — is it known-bad?"*
> The session calls `threat_intel_lookup` (`wrappers/threat_intel.py`). It only reaches the network
> when egress is explicitly enabled — otherwise it returns `egress_allowed=False` with no call.

**Execution I → Output I.**

*Execution I:* `threat_intel_lookup { "indicator":"...", "indicator_type":"ip", "providers":[...] }`

*Output I (shape):* VirusTotal / OTX enrichment for the indicator — **or** `egress_allowed=False`
(no network call) when egress is off.

> ⚠️ **GOTCHA (egress-gated, no-op by default):** `threat_intel_lookup` returns `egress_allowed=False`
> with **no** network call unless `AGENTROPIX_ALLOW_EGRESS=1` is set **and** a provider key is supplied
> ([`env-vars.md`](../07-sdlc-ops/env-vars.md) §6). This is the dashed (optional) edge in the
> use-case diagram. *(End-user: the assistant tells you it's disabled rather than failing silently.)*

**Postconditions**

- A typed result set per Volatility tool (process tree, sockets, malfind hexdumps, services).
- A cross-host `pivot_on_ioc` result grouping every hit by host and artifact type.
- In the autonomous path: a sealed `TriageReport` whose memory findings carry the `MEMORY_TRIAGED`
  promise and whose facts each originate from a named deterministic tool.

**CLI commands used**

```bash
# Pre-flight (confirms Volatility3 present)
agentropix-sift doctor

# Autonomous memory triage, sealed report
agentropix-sift run /evidence/srl2018/base-hunt-memory.raw \
    --max-iterations 5 \
    --out mem-report.json
```

The granular steps (`get_pslist`, `build_process_tree`, `get_netscan`, `get_malfind`, `get_svcscan`,
`pivot_on_ioc`, `threat_intel_lookup`) are **MCP tool calls**, not CLI subcommands — they are issued
by an MCP client (Claude Desktop / Claude Code) against the running
`agentropix-sift-mcp` server, not from the shell.

---

## See also

- [uc-disk-triage.md](uc-disk-triage.md) — the disk-image counterpart (execution evidence).
- [uc-approval-gate.md](uc-approval-gate.md) — promote memory findings via examiner approval.
- [uc-wazuh-push.md](uc-wazuh-push.md) — push pivoted IOCs into Wazuh (optional integration).
- [`tool-list.md`](../04-mcp-tools/tool-list.md) — the 7 Volatility tools and full catalogue.
- [`agents-list.md`](../10-agents/agents-list.md) — `MemoryAgent` / `HuntAgent` contracts.
- [agentic-architecture.md](../10-agents/agentic-architecture.md) — how `MemoryAgent` / `HuntAgent` fit the runtime swarm.

**Design rationale (ADRs).** Why the memory path works the way it does:

- [ADR-014 — Credential-dump triage (impacket)](../11-ADR/ADR-014-W072-impacket-secretsdump.md) — the genesis of the `secretsdump_local` credential path the `MemoryAgent` runs (Step "secretsdump"); also records why broader W-072 credential work is **deferred**.
- [ADR-011 — Evidence-Type Gate Consolidation](../11-ADR/ADR-011-evidence-gates.md) — the shared evidence-type gate every memory data-fetch (pslist/netscan/malfind/svcscan) passes through.

---

## Implementation proof (source)

> **For developers.** This section maps every use-case step above to the **real oracle source** that
> implements it — `file:symbol`, trimmed signatures, and the call path. Paths are relative to
> `/home/admin2/agentropix-sift/src`. Nothing here is illustrative: each symbol exists in the tree.

### Registration chain (how an MCP call reaches Volatility3)

Every memory tool is a three-layer stack: the FastMCP surface delegates to a `server.mcp_*`
guard, which delegates to the typed wrapper that shells `vol`.

| Layer | File:symbol | Role |
|---|---|---|
| FastMCP tool | `mcp_server/fastmcp_app.py` `@app.tool() get_pslist` (and siblings) | Public MCP surface; `result.model_dump()` back to the client. |
| Server guard | `mcp_server/server.py:mcp_get_pslist` (`@traced("get_pslist")`) | Rate-limit → archive-reject → **Thymus** `check_read` → wrapper; wraps raises as `ToolError`. |
| Typed wrapper | `mcp_server/wrappers/volatility.py:get_pslist` | Builds the `vol -f <img> -r csv windows.pslist.PsList` argv, parses to a typed model. |
| Policy | `mcp_server/thymus_policy.py:ThymusEvidencePolicy.check_read` (instantiated `server.py:177 _policy`) | The `Thymus` participant in the sequence diagram — gates evidence reads. |

The FastMCP layer is literal:

```python
# fastmcp_app.py
@app.tool()
async def get_pslist(image: str, pid_filter: list[int] | None = None) -> dict:
    result = await _inner.mcp_get_pslist(image, pid_filter=pid_filter)
    return result.model_dump()
```

```python
# server.py — the guard the sequence diagram labels "MCP -> Thymus: check_read"
@traced("get_pslist")
async def mcp_get_pslist(image: str, pid_filter: list[int] | None = None) -> PsList | ToolError:
    rate_err = _rate_limiter.check("get_pslist")
    if rate_err: return ToolError(tool="get_pslist", error=rate_err)
    archive_err = _reject_archive("get_pslist", image)
    if archive_err: return archive_err
    violation = _policy.check_read(image)            # ThymusEvidencePolicy
    if violation: return ToolError(tool="get_pslist", error=violation)
    try:
        return await get_pslist(image, pid_filter=pid_filter)
    except (FileNotFoundError, RuntimeError, TimeoutError, MemoryError) as e:
        return ToolError(tool="get_pslist", error=str(e))
```

### Step-by-step source map (granular MCP path)

| Use-case step | Implementing symbol | Notes from source |
|---|---|---|
| **Step 1 — `get_pslist`** | `wrappers/volatility.py:get_pslist` | `cmd = [vol, "-f", img, "-r", "csv", "windows.pslist.PsList"]`. **psscan fallback** is here: `if len(processes) == 0:` → `_get_psscan(image)` returns `used_fallback=True` with `reason=REASON_PSSCAN_FALLBACK`. W-135 disk-image short-circuit returns `tool_available=False`. |
| **Step 2 — `build_process_tree`** | `wrappers/correlation.py:build_process_tree` | Calls `get_pslist()` (so it inherits the psscan fallback — matches the "psscan fallback on paused-VM" note), links by PPID via the recursive `_attach`, classifies `roots` vs `orphans` (`node.ppid not in _SYSTEM_PIDS {0,4} and not in pid_set` → orphan = DKOM). LOLBin flagging: `correlation.py:_is_suspicious` checks `_SUSPICIOUS_PROCESS_NAMES` (`rubyw.exe`, `mshta.exe`, …) spawned by `_SENSITIVE_PARENTS` (`services.exe`, `lsass.exe`, …) → sets `suspicious_count`. |
| **Step 3 — `get_netscan`** | `wrappers/volatility.py:get_netscan` | `windows.netscan.NetScan` (W-075 default, pool-tag-driven; doc-comment explains why netscan over netstat). Returns typed `NetscanReport` sockets (`proto`/`local_addr`/`foreign_addr`/`state`/`pid`/`owner`). The "join pid → tree" attribution is done agent-side in `agents/memory.py:_findings_from_netscan`, which also IOC-promotes public/ESTABLISHED sockets via `_is_rfc1918`. |
| **Step 4 — `get_malfind`** | `wrappers/volatility.py:get_malfind` | `windows.malfind.Malfind`; Issue #11 chains `windows.vadinfo.VadInfo --dump` per hit (capped by `AGENTROPIX_MALFIND_DUMP_MAX_PER_HOST`) → fills `payload_sha256`/`payload_bytes`/`payload_strings`. Findings (T1055) emitted by `agents/memory.py:_findings_from_malfind`. |
| **Step 5 — `get_svcscan`** | `wrappers/volatility.py:get_svcscan` | `windows.svcscan.SvcScan`. Persistence scoring is agent-side: `agents/memory.py:_findings_from_svcscan` raises confidence and tags `T1543.003` when `is_service_binary_outside_system32(svc)`. |
| **Step 6 — `get_editbox`** | `wrappers/editbox.py:get_editbox` | Vol2.6 path; `_require_sandbox()` raises `FileNotFoundError` when the Py2.7 sandbox is unconfigured (the GOTCHA "self-skips"). Profile guard: `re.fullmatch(r"[A-Za-z0-9_]+", profile)` (argv-injection defense). |
| **Step 7 — `run_volatility`** | `wrappers/volatility.py:run_volatility` | `resolve_vol3_plugin(plugin)` enforces the allowlist (`VOL3_ALLOWED_PLUGINS`); `_flatten_args` builds `--key value` flags; `-r json` preserves rows verbatim. Raises `VolatilityPluginError` on disallowed plugins. |
| **Step 8 — `pivot_on_ioc`** | `wrappers/correlation.py:pivot_on_ioc` | Fans out: per image runs `get_pslist`/`get_netscan`/`get_svcscan`/`get_evtx` via `asyncio.gather`, case-insensitive substring `_match`, groups by `_host_from_image`. Default artifact set is the module constant `_DEFAULT_ARTIFACT_TYPES = ("pslist","netscan","svcscan","evtx")` — exactly the four the use case lists. |
| **Step 9 — `threat_intel_lookup`** | `wrappers/threat_intel.py:threat_intel_lookup` | Egress gate is the first thing checked: `egress_allowed = os.environ.get("AGENTROPIX_ALLOW_EGRESS") == "1"`; when off it returns the shim dict `{"egress_allowed": False, "aggregate_verdict": "unknown", ...}` with **zero** network calls — the documented no-op. |

### Autonomous path source map (`agentropix-sift run`)

| Sequence participant | Implementing symbol | Notes from source |
|---|---|---|
| `agentropix-sift run` → `run_triage` | `cli.py:117` → `orchestrator.py:run_triage(image, max_iterations=5, …)` | CLI calls `asyncio.run(run_triage(...))`. |
| **MemoryAgent runs first** | `agents/__init__.py:SWARM` tuple — `MemoryAgent` is element 0, `HuntAgent` is last | The module docstring states the invariant: "HuntAgent must execute LAST because it consumes the findings the other agents publish." |
| `MemoryAgent.run` | `agents/memory.py:MemoryAgent.investigate` | `looks_like_memory(image)` guard (else single `memory.skip` Finding + clears `completion_promise`); W-074 `_safe_get_info`/`is_snapshot_paused` paused-VM tag; `mcp_get_pslist` → suspicious/orphan loop → `build_process_tree` → best-effort `_safe_call` chain over malfind/netscan/svcscan/registry/credential plugins. |
| `MEMORY_TRIAGED` promise | `agents/memory.py:MemoryAgent.completion_promise = "MEMORY_TRIAGED"` | Promoted to `report.completion_proofs` only when the agent returns ≥1 finding — `orchestrator.py:194 if findings and agent.completion_promise: completion_proofs.add(...)`. |
| secretsdump (credentials) | `agents/memory.py:_credential_triage_findings` → `wrappers/credentials.py:secretsdump_local` | Three gates: `AGENTROPIX_IMPACKET_ENABLED=1`, tool on PATH, hive triple under `AGENTROPIX_HIVE_DIR` (`_resolve_hive_triple`). Each gate failure emits one `memory.credentials.unavailable` Finding (never a silent gap). Per-row findings tag T1003.002/.005/.001. |
| `evidence_dict` for cross-modal fusion | `agents/memory.py` Finding builders | `_findings_from_netscan`/`_malfind`/`_svcscan`/`_hashdump` populate structured `evidence_dict` keys (pid/foreign_addr/nt_hash/…) the correlation scorer reads. |
| **HuntAgent runs last** | `agents/hunt.py:HuntAgent` (`completion_promise = "CROSS_AGENT_CORRELATION_DONE"`) | Reads `self.blackboard.correlations()`. |
| ≥2-agent quorum | `agents/_blackboard.py:Blackboard.correlations` | A token is a `Correlation` only when `len(by_agent) >= self._quorum_threshold` (constructor `quorum_threshold: int = 2`, rejects `< 2`). Results sorted by `-max_confidence`. |
| Critic halt | `orchestrator.py:run_triage` loop → `critic.score(...)` → `if last_result.should_halt: halted = True` (`trinity.Critic` / `TrinityResult`) | Loop is `for iteration in range(1, max_iterations + 1)`; final status `"complete"` on halt else `"budget_exhausted"`. |
| TriageReport (sealed by CLI) | `orchestrator.py:TriageReport` (Pydantic, `completion_proofs: list[str]`) returned to `cli.py` | Findings deduped by `(source, description, evidence)` fingerprint before return. |

**Source files cited:** `mcp_server/wrappers/volatility.py`, `mcp_server/wrappers/correlation.py`,
`mcp_server/wrappers/threat_intel.py`, `mcp_server/wrappers/editbox.py`,
`mcp_server/wrappers/credentials.py`, `mcp_server/server.py`, `mcp_server/fastmcp_app.py`,
`mcp_server/thymus_policy.py`, `agents/memory.py`, `agents/hunt.py`, `agents/_blackboard.py`,
`agents/__init__.py`, `orchestrator.py`, `cli.py`.
