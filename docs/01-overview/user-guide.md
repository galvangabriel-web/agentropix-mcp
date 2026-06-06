# Agentropix-SIFT User Guide — The Complete Operator Runbook

> **Section 01 · Overview** — the single, deeply-detailed end-to-end walkthrough, written for **two
> audiences at once**: the **expert** who types CLI/MCP commands and reads raw output, and the
> **non-technical end-user** who types a plain-language prompt into Claude Desktop / Claude CLI (with
> the Agentropix MCP connected) and reads the result.
> Related: [Quickstart](quickstart.md) (the 3-command fast path) ·
> [What is Agentropix-SIFT?](what-is-agentropix.md) ·
> [What You Get](what-you-get.md) ·
> [Client Setup (Desktop & CLI)](../09-integrations/client-setup.md) ·
> [CLI Reference](../08-reference/cli-reference.md) ·
> [Tool capability map](../04-mcp-tools/capability-map.md) ·
> [Per-case attack-chain hypotheses](../06-use-cases/case-hypotheses.md) ·
> [Approval Portal](../05-safety-forensics/approval-portal.md) ·
> [Audit & Courtroom Seal](../05-safety-forensics/audit-courtroom.md) ·
> [Wazuh Integration](../09-integrations/wazuh-portal.md)

This guide takes you through one **complete DFIR case** the way a real examiner runs it, in full
operational depth: **prerequisites & clients → connect/verify the MCP → case init/activate → register
evidence (chain-of-custody hash) → the investigation tool chain → record findings → approve in the
portal → generate & verify the sealed report → curate & push IOCs to Wazuh.**

**The core principle: adapt Agentropix to the user, not the user to Agentropix.** Every operator
action in this guide is shown **two ways** — the exact command an expert runs, and the plain-language
prompt a non-technical user types to get the *same result*. You only need to follow one track.

---

## HOW TO READ THIS GUIDE

Read this short preface first — it tells you how the guide is structured and how to follow your track.

### (a) The example outputs are from a REAL run

Every "validated output" you see below — case IDs, SHA-256 hashes, entry counts, feature counts — comes
from a **real prior execution: the validated 2026-05-29 CFReDS run.** These are not invented examples.
You will see real artifacts and real IDs (e.g. `case_id INC-2026-0529224443`, evidence SHA-256
`96bebe80…`). Your own run will produce *different* IDs and timestamps, but the *shape* of the output
will match. Where we quote a number, it is what the platform actually returned that day.

### (b) What a GOTCHA box is

> ⚠️ **GOTCHA** boxes flag real-data quirks and genuine bugs found during the proving run. Because the
> examples are from a real run, real-world snags appear — a tool that needs a partition offset, a path
> the policy engine rejects, a background process that gets killed. Each GOTCHA explains the snag for
> **both** audiences: what the symptom looks like, and how to avoid it. The valuable bugs (B2–B5) are
> introduced together in the [Gotchas at a glance](#gotchas-at-a-glance) section below so you meet them
> before you hit them.

### (c) The two audience tracks

Throughout the guide, every single-command action carries a **dual-representation box**:

> **🖥️ Expert (command):** the exact CLI/MCP call to type into a terminal or pass over the MCP.
> **💬 End-user (prompt):** the plain-language question to type into a Claude session that has the
> Agentropix MCP connected. A simple, focused question is enough — the session recognises it as an
> Agentropix capability and routes it to the right MCP tool automatically.

**How to follow each track:**
- **Expert track** — copy the `🖥️` command, run it, read the raw JSON/text output (the "Output X" block).
- **End-user track** — type the `💬` prompt into Claude Desktop or Claude CLI. The assistant calls the
  same MCP tool behind the scenes and explains the result back to you in plain language. You never see
  the JSON unless you ask for it.

Both tracks hit the **same deterministic MCP tool** and get the **same facts** — only the surface differs.

---

## Usability matrix — find your lane

There are **two ways to drive a triage** (Manual vs Autonomous) and **two ways to interact** (Expert
CLI vs Non-expert prompt). That makes **four lanes**. Find yours, then follow it consistently through
the guide. All four operate on the **same real CFReDS data** and reach the **same sealed result**.

| | **🖥️ Expert (types CLI/MCP commands)** | **💬 Non-expert (types a plain-language prompt)** |
|---|---|---|
| **Path A — Manual** (you/the assistant drive each tool one at a time, inspecting output before the next step) | **Lane A-Expert.** Call each MCP tool yourself in a CLI session or run the operator shell commands (`mmls`, `ewfverify`). Read raw output inline. Best for demos and the approval gate. → [Path A](#path-a--manual-execution-you-drive-each-tool) | **Lane A-User.** Ask the assistant one focused question per step ("check the partition layout", "list deleted files"). It calls the tool and explains the answer. → use the `💬` prompts in [Path A](#path-a--manual-execution-you-drive-each-tool) |
| **Path B — Autonomous** (the engine runs the whole sequence unattended, staging findings as DRAFT) | **Lane B-Expert.** Launch the detached headless driver (`agx_gearb.py`-class) with the bearer token; monitor `run.log` + `SUMMARY.json`. The validated production pattern. → [Path B.2](#b2--headless-driver-fully-unattended-the-validated-pattern) | **Lane B-User.** Paste one autonomous prompt ("investigate this case end to end, stage findings as DRAFT, don't approve") and let the assistant run the full sequence, narrating progress. → [Path B.1](#b1--interactive-autonomous-prompt-desktop-or-cli) |

> **The four lanes stay separated through the doc.** Phase 4 is where Manual (A) and Autonomous (B)
> diverge — both are documented in full. Within each, the `🖥️`/`💬` boxes keep the Expert and Non-expert
> tracks side by side.

…and **two clients**, which differ architecturally:

- **Claude CLI** — speaks HTTP natively, scriptable/headless, no size cap. The recommended client for
  autonomous chains. (Lanes A-Expert and B-Expert live here.)
- **Claude Desktop** — GUI, human-in-the-loop, speaks stdio only (needs an `mcp-remote` shim) and
  enforces a hard **~1 MB single-tool-result cap**. (A great home for the `💬` non-expert prompts and
  the approval gate.)

> **Platform capability vs. validated example run.** Agentropix-SIFT *orchestrates* the SANS SIFT
> toolchain you already have. The platform exposes **71 deterministic MCP tools** across **16 forensic
> SIFT wrappers**, with **4464 tests** (cite [`.crew/facts.md`](../../.crew/facts.md):
> `mcp_tool_count=71`, `test_count=4464`). The LLM only *orchestrates*; the facts come from
> deterministic tools. Throughout this guide the **validated 2026-05-29 CFReDS run** is quoted as a
> worked example — that run was captured against an earlier build whose live `tools/list` enumerated
> **62** tools; treat 62 as the snapshot inventory and **71** as the current platform figure.

---

## The end-to-end pipeline at a glance

```mermaid
%%{init: {"theme":"base","themeVariables":{"fontFamily":"ui-sans-serif, system-ui","fontSize":"14px","lineColor":"#475569"}}}%%
flowchart LR
  P0[Phase 0<br/>clients + pre-flight] --> P1[Phase 1<br/>connect + verify MCP]
  P1 --> P2[Phase 2<br/>case init/activate]
  P2 --> P3[Phase 3<br/>register evidence]
  P3 --> P4[Phase 4<br/>investigation tool chain]
  P4 --> P5[Phase 5<br/>record findings DRAFT]
  P5 --> P6[Phase 6<br/>approve in portal]
  P6 --> P7[Phase 7<br/>generate + verify report]
  P7 --> P8[Phase 8<br/>curate + push IOCs to Wazuh]
  style P0 fill:#16a34a,color:#fff
  style P1 fill:#475569,color:#fff
  style P2 fill:#475569,color:#fff
  style P3 fill:#475569,color:#fff
  style P4 fill:#475569,color:#fff
  style P5 fill:#2563eb,color:#fff
  style P6 fill:#dc2626,color:#fff
  style P7 fill:#16a34a,color:#fff
  style P8 fill:#7c3aed,color:#fff
```

*The operator phases. Phase 4 (the investigation tool chain) is where Path A (manual) and Path B
(autonomous) diverge — both are documented in full below.*

---

## Tool capability map (summary)

The platform's **71 tools** group into DFIR functions — discovery/health, disk/partition, memory,
registry & execution artifacts, filesystem/MFT, timeline, event logs, email/PST, YARA/carve/strings,
IOC pivot, threat intel, Wazuh, and case/findings/reporting. Use the map to pick the right tool for the
phase you're in.

→ **Full map:** [Tool capability map (by DFIR function)](../04-mcp-tools/capability-map.md) — the
per-function tool table, cross-cutting conventions (Thymus path policy, auto-tempdirs,
`timeout_seconds`), and the canonical happy-path ordering. The complete per-tool catalogue is in
[`.crew/tool-list.md`](../../.crew/tool-list.md) and [Tool reference](../04-mcp-tools/tool-reference.md).

---

## The 1 MB cap (Desktop-only) and how to size tool output

Claude Desktop enforces a hard ~1 MB cap on a *single* MCP tool result; it is not configurable. The
identical chain that fails in Desktop runs inline in CLI. **Mitigation principle:** prefer a tool's
file-path / `out_dir` / `dest` return mode over inline payload, and scope queries. Most
carving/extraction wrappers accept `out_dir`/`dest` precisely so they return a path, not megabytes.

High-risk-in-Desktop tools and their mitigation:

| Tool | Why it can exceed 1 MB | Desktop mitigation |
|---|---|---|
| `get_timeline` (plaso) | super-timeline over a multi-GB E01 = tens of MB CSV | run server-side, consume the output **file path**; scope by `parsers` + time window |
| `run_bulk_extractor` | feature carving writes many features | pass `out_dir`; read specific feature files |
| `run_foremost` / `extract_files` / `extract_archive` | produce file sets | return `dest` dir + manifest, page through |
| `run_strings` / `get_bstrings` | strings dumps are many MB | always regex-filter (`get_bstrings`) or grep server-side |
| `idx_search` | large hit sets | page size / top-N; use `idx_aggregate` / `idx_case_summary` rollups |
| `fls` / `list_files` / `glob_paths` | full FS listing of a large image | scope by path/offset; enumerate incrementally |
| `get_evtx` | busy Security channel, no filter | always pass an EventID filter + time window |
| `scan_yara` | match list with `-s` strings balloons | drop `-s` for triage; return match list only, paginate |
| `report_generate` (full) | comprehensive IR payload | narrower profile, or write-to-disk + return path |

Inherently safe in Desktop (small results): `health`, `case_init`/`case_activate`/`case_status`,
`evidence_register`, `get_image_info`, `parse_gpt`, `record_finding`/`record_timeline_event`/`approve_finding`,
`threat_intel_lookup`, `wazuh_check_intel`, scoped `wazuh_hunt_ioc`/`wazuh_vuln_query`,
`build_process_tree`, `detect_sweep`, `pivot_on_ioc`.

---

## Gotchas at a glance

Meet the real-data snags before you hit them. Each is explained for **both** audiences. They recur in
context at the relevant phase, and the full troubleshooting ledger is at the [end of this guide](#troubleshooting-ledger).

| ID | What happens (expert symptom) | In plain terms (end-user) | The fix |
|----|-------------------------------|---------------------------|---------|
| **B2** | `fls` on a physical disk → `Cannot determine file system type` | "list the files" came back empty/errored because the tool started at the very front of the disk instead of inside the partition | Pass the partition `offset` (sectors) from `mmls`. For CFReDS, NTFS starts at **sector 63**. The assistant does this for you when you ask it to list files. |
| **B3** | `run_bulk_extractor` → `Thymus REJECT: path not found` | the place you asked it to write results to isn't on the allowed list | Write `out_dir` under an allowlisted prefix: `/tmp/agentropix-sift-*`, `/cases/`, `/mnt/`, `/media/`, `/evidence/` |
| **B4** | `record_finding` → `finding must contain non-empty finding_id` | the finding had no ID, so the system wouldn't file it | Always give every finding a `finding_id` (the assistant generates one) |
| **B5** (the big one) | An autonomous driver dies mid-run; later steps never log even though the server-side job finished | the unattended run got killed when its shell closed | Launch the driver **detached** (`setsid` + `nohup` + `disown`) and checkpoint per step. Non-experts: use the interactive autonomous prompt (Path B.1) instead, which avoids this entirely. |

Platform notes that look like bugs but are **working as designed**:

- **YARA smoke-test returns 0 matches** with `raw_stdout_sha256` = the empty-string hash. That is the
  *success* signature of a clean scan, not a failure. (Only `pf_smoketest.yar` is installed — add a
  production ruleset before relying on YARA.)
- **A `full` report shows `approved_finding_count 0`** right after recording a finding. Correct — DRAFT
  findings are not surfaced until an examiner approves (Phase 6).
- **Wazuh Discover shows 0 docs** on a 2004 image. The default time range doesn't cover 2004 — use the
  `@timestamp` field and widen the range.

---

## Phase 0 — Prerequisites and clients

> 🟢 **In plain terms:** put the evidence in the right place, make sure the forensic tools exist, start
> the MCP server, and pick your client (CLI or Desktop).

### 0.1 Evidence location and in-scope cases

Evidence lives under `/cases/` (**lowercase** — `/Cases/` does not exist). The in-scope test cases used
throughout this guide:

| Case key | Scenario | Evidence shape |
|---|---|---|
| `cfreds-fresh` | NIST "Hacking Case" — Greg Schardt / "Mr. Evil", Win XP (insider misuse) — **the validated example** | Single Win XP disk, EWF `4Dell-Latitude-CPi.E01` (+`.E02`) |
| `SRL-2015` | SANS FOR508 Stark Research Labs APT intrusion (multi-host) | 4 hosts, each C-drive E01 + memory raw + Mandiant `.mans` |
| `SRL-2018` | Stark Research Labs network-wide APT C2 deployment | many E01s + memory `.img` (each with `.md5`) |
| `rocba` | Stark Research Labs insider IP theft — Fred Rocba, 2020 | Single host: `rocba-cdrive.e01` (23.7 GB) + `Rocba-Memory.raw` (19.0 GB) |

Per-case attack-chain hypotheses (which tools to reach for first in each scenario) live in
[Per-case attack-chain hypotheses](../06-use-cases/case-hypotheses.md).

### 0.2 Forensic toolchain pre-flight (`doctor`)

Agentropix-SIFT does **not** ship the forensic binaries — it drives the SANS SIFT toolchain. `doctor`
resolves the binaries that back the **16** forensic SIFT wrappers, honoring any `AGENTROPIX_*_TOOL`
override, and prints `OK <path>` or `MISSING` for each.

> **🖥️ Expert (command):**
> ```bash
> uv run agentropix-sift doctor
> ```
> **💬 End-user (prompt):** *"Check that my Agentropix forensic environment is ready — are all the
> forensic tools installed?"*
> The session runs the same pre-flight (`doctor` / the `health` check) and tells you in plain language
> whether everything is present or what's missing. **A simple, focused question is enough — the session
> recognises this as an Agentropix capability and routes it to the right check.**

**Execution A → Output A.**

*Execution A:*
```bash
uv run agentropix-sift doctor
```

*Output A (all present):*
```text
  [OK  /usr/bin/vol] Volatility3 (memory forensics) (vol)
  [OK  /usr/bin/log2timeline.py] Plaso (timeline) (log2timeline.py)
  [OK  /usr/bin/fls] Sleuth Kit (filesystem) (fls)
  [OK  /usr/bin/mmls] Sleuth Kit (partitions) (mmls)
  [OK  /usr/bin/ewfinfo] ewftools (E01 image metadata) (ewfinfo)
  ... (more) ...
All tools available.
```

A `MISSING` tool degrades gracefully (the relevant agent self-skips) but lowers recall — resolve each
before a real run. Point at a non-default path with the override var (no symlink needed):

```bash
export AGENTROPIX_YARA_TOOL=/opt/sift/bin/yara
export AGENTROPIX_EVTX_TOOL=/usr/local/bin/evtx_dump.py
```

Deep reference: [CLI Reference · `doctor`](../08-reference/cli-reference.md#agentropix-sift-doctor) ·
[`.crew/env-vars.md`](../../.crew/env-vars.md).

### 0.3 Start / verify the MCP server (operator-local)

> **🖥️ Expert (command):**
> ```bash
> bash /home/admin2/.openclaw/workspace/scripts/start-agentropix-mcp.sh start
> bash /home/admin2/.openclaw/workspace/scripts/start-agentropix-mcp.sh status   # expect health: HTTP 200
> ```
> **💬 End-user (prompt):** *"Is the Agentropix MCP server running and healthy?"*
> If the MCP is already connected to your session, the assistant calls `health` and confirms. (Starting
> the server itself is an operator-local step — ask your administrator if it isn't up.)

The launcher pins the bearer token and binds the MCP endpoint on the tailnet.

> ⚠️ **GOTCHA (autonomous runs):** the server is reaped if the shell that started it exits inside a
> sandbox. For an unattended Path B run, start the server from a **detached / long-lived** process so it
> survives the launching shell. (Non-experts on the interactive autonomous prompt don't need to worry
> about this — it only affects the headless driver.)

### 0.4 Verify image integrity (chain of custody)

Before any tool opens a descriptor, confirm the image is byte-intact — its stored MD5 must equal its
calculated MD5.

> **🖥️ Expert (command):**
> ```bash
> ewfverify /cases/cfreds-fresh/4Dell-Latitude-CPi.E01
> ```
> **💬 End-user (prompt):** *"Verify the integrity of the CFReDS E01 image — does its stored hash match?"*
> The session runs the same verification and reports SUCCESS plus the matching MD5, or warns you if the
> image is corrupt. **One plain question routes to `ewfverify` automatically.**

**Execution B → Output B.**

*Execution B:*
```bash
ewfverify /cases/cfreds-fresh/4Dell-Latitude-CPi.E01
```

*Output B (validated):* `ewfverify` reports **`SUCCESS`**; stored MD5 == calculated MD5 ==
**`aee4fcd9301c03b3b054623ca261959a`**.

And the acquisition metadata:

> **🖥️ Expert (command):**
> ```bash
> ewfinfo /cases/cfreds-fresh/4Dell-Latitude-CPi.E01
> ```
> **💬 End-user (prompt):** *"Show me the acquisition details of the CFReDS image — who acquired it, when, and what OS is on it."*
> The session calls `ewfinfo` (the same metadata the `get_image_info` MCP tool returns) and summarises it.

**Execution C → Output C.**

*Execution C:*
```bash
ewfinfo /cases/cfreds-fresh/4Dell-Latitude-CPi.E01
```

*Output C (validated, `ewfinfo 20140816`):* case_number `Greg Schardt`, examiner `Shane Robinson`,
acquisition_date `Wed Sep 22 14:06:04 2004`, OS `Windows XP`, format `EnCase 4`.

- If `ewfinfo` reports `corrupted: yes`, **re-acquire** from your canonical source — a corrupt EWF
  chunk silently blocks hive/artifact extraction.

> ⚠️ **CONFIDENTIAL — Investigative Pre-Decisional.** Never submit indicators flagged *NEVER SUBMIT TO
> TI* (e.g. a packet-capture SHA-256) to any external service. All verification here is local and
> read-only.

---

## Phase 1 — Connect a client and verify the MCP

> 🟢 **In plain terms:** wire your client to the MCP endpoint, then call `health` and trust the live
> tool count — not the startup banner, not the docs.

The two clients differ at the **transport layer**, which cascades into everything else:

- **Claude CLI** speaks HTTP natively — it connects straight to the MCP endpoint over the tailnet, with
  the bearer token as a real HTTP header. **No bridge process.**
- **Claude Desktop** speaks stdio only — it cannot open an HTTP MCP connection itself, so it spawns a
  local **`mcp-remote`** shim (an `npx` package) that talks HTTP to the server and proxies JSON-RPC over
  stdio. **Prerequisite:** Node.js ≥ 18 on `PATH`.

Server transport is HTTP + SSE (FastMCP). Auth is a static bearer token compared constant-time
server-side; no TTL, no refresh. The endpoint has the documented shape `http://<TAILNET-IP>:8765/mcp`
and is reachable **only** from tailnet members. The operator's real tailnet host and token are not
reproduced here — get them from [Client Setup](../09-integrations/client-setup.md).

> ⚠️ **Server-side gotcha (defense-relevant):** if `AGENTROPIX_MCP_AUTH_TOKEN` is unset on the server,
> the auth middleware short-circuits and accepts **all** requests unauthenticated. Always confirm the
> token is set.

> **Dual-audience note for Phase 1 wiring.** Connecting a client to the MCP is a **one-time operator
> setup step** — it is the only action in this guide with no plain-language prompt equivalent, because an
> end-user can't add an MCP server by talking to a session that isn't connected yet. **💬 End-user:** if
> the Agentropix MCP is already wired into your Claude Desktop / CLI (your administrator did 1A or 1B
> below), skip to [§1.2](#12-sanity-check--call-health) and just ask *"how many Agentropix forensic tools
> are available?"* to confirm you're connected. If it isn't, ask your administrator to run the wiring step.

### 1A — Connect with Claude CLI (recommended)

```bash
claude mcp add --transport http agentropix-sift \
  "http://<TAILNET-IP>:8765/mcp" \
  --header "Authorization: Bearer <TOKEN>"
```

Verify:

```bash
claude mcp list
# Expected: agentropix-sift  http://<TAILNET-IP>:8765/mcp  ✓ Connected
```

This persists in `~/.claude.json` under `mcpServers` as
`{type:"http", url:..., headers:{Authorization:"Bearer <TOKEN>"}}`. Scope is user by default
(`-s user`) or project via a repo-root `.mcp.json`. **`~/.claude.json` is not hot-reloaded** — a manual
edit needs a full CLI restart.

### 1B — Connect with Claude Desktop (stdio shim)

Config file: Linux `~/.config/Claude/claude_desktop_config.json` · macOS
`~/Library/Application Support/Claude/claude_desktop_config.json` · Windows
`%APPDATA%\Claude\claude_desktop_config.json`. Entry:

```json
{ "mcpServers": { "agentropix-sift": {
  "command": "npx",
  "args": ["-y","mcp-remote","http://<TAILNET-IP>:8765/mcp","--allow-http","--header","Authorization: Bearer <TOKEN>"],
  "env": {} } } }
```

Desktop platform gotchas:
- **Windows must use** `"command":"npx.cmd"`.
- `--allow-http` is **required** for a plain-HTTP tailnet endpoint (`mcp-remote` refuses cleartext otherwise).
- After editing, **fully quit and relaunch** (Cmd-Q / tray Quit — closing the window does *not* reload).
- First `mcp-remote` spawn is slow; if the tool list is empty, prime it once with `npx -y mcp-remote --help`.
- Lock the config `0600` (it embeds the token in cleartext). Desktop MCP log (Linux):
  `~/.config/Claude/logs/mcp-server-agentropix-sift.log`.

**Token rules (both clients):** same value, different layer (CLI = HTTP header; Desktop = literal string
in the `mcp-remote --header` arg). Neither client expands `${VAR}` — paste the literal token. It must be
exactly `Authorization: Bearer <token>` (case-sensitive `Bearer`, single space, no quotes); a trailing
newline or smart-quote → `401`.

### 1.2 Sanity check — call `health`

From any connected client, call the `health` tool. Expect a small JSON object including a live
`tool_count`.

> **🖥️ Expert (command/MCP call):**
> ```text
> health  ->  { "status": "ok", "tool_count": 71, "version": "...", "uptime": ... }
> ```
> **💬 End-user (prompt):** *"How many Agentropix forensic tools are available right now?"*
> The session calls `health` and tells you the live count. **Trust this live number, not any banner.**

**Execution D → Output D.**

*Execution D:* call the `health` tool.

*Output D:* `{ "status": "ok", "tool_count": 71, "version": "...", "uptime": ... }`

> ⚠️ **Always live-verify the tool count.** The startup banner under-reports (it once showed `38`).
> Trust the live `health.tool_count` / `tools/list`, never the banner or stale docs. The 2026-05-29
> snapshot showed `62`; the current platform is `71`.

---

## Phase 2 — Open and activate the case (chain of custody)

> 🟢 **In plain terms:** create the case record (idempotent) and make it the *active* case so every
> later tool stamps to it.

> **🖥️ Expert (MCP calls):**
> ```text
> case_init     { "case_name":"CFReDS Hacking Case (Greg Schardt / Mr. Evil)",
>                 "examiner_id":"victor.galvan",
>                 "incident_type":"intrusion/hacking-tools",
>                 "severity":"high",
>                 "scope":"/cases/cfreds-fresh/4Dell-Latitude-CPi.E01" }
>                 ->  returns case_id, e.g. INC-2026-0529224443
> case_activate { "case_id":"<case_id from above>" }
> ```
> **💬 End-user (prompt):** *"Open a new high-severity case for the CFReDS hacking image (Greg Schardt /
> Mr. Evil), examiner victor.galvan, and make it the active case."*
> The session calls `case_init` then `case_activate`, then tells you the new case ID to quote later.

**Execution E → Output E.**

*Execution E:* `case_init` then `case_activate` (as above).

*Output E (CFReDS validated):*
- `case_init` → `case_id` = **`INC-2026-0529224443`**, status `active`,
  `started_at 2026-05-29T22:44:43.131054+00:00`.
- `case_activate` → pointer written to **`/home/admin2/.agentropix/active_case`**.

The active-case pointer is implicit state. If you skip activation, pass an explicit `case_id` to later
case-scoped tools. `case_init` is idempotent on `case_id`.

---

## Phase 3 — Register evidence (SHA-256 chain of custody)

> 🟢 **In plain terms:** hash the image and bind it to the active case. This is your custody anchor.

> **🖥️ Expert (MCP call):**
> ```text
> evidence_register { "path":"/cases/cfreds-fresh/4Dell-Latitude-CPi.E01",
>                     "description":"Windows XP system disk (EWF/E01)",
>                     "examiner_id":"victor.galvan" }
> ```
> **💬 End-user (prompt):** *"Register the CFReDS E01 image as evidence in this case and give me its
> SHA-256 custody hash."*
> The session calls `evidence_register`, returns the evidence ID and SHA-256, and confirms it's bound to
> the active case.

**Execution F → Output F.**

*Execution F:* `evidence_register` (as above).

*Output F (CFReDS validated):*
- `evidence_id` `235c7a7a998fc82e6ac812655983ccb5408e5d8c5ecaf6dc038bdd6bb1c35d38`
- evidence **SHA-256 `96bebe80f00541bf28fbc2ef0b02b580082ee6ad58837e991852ae66f077ec31`**
- `size_bytes` **`671094597`** (≈640 MiB on-disk EWF container)
- `indexed: true` → `agentropix-evidence-2026.05.29`

Confirm image metadata via the MCP tool (the in-band equivalent of the `ewfinfo` you ran in Phase 0.4):

> **🖥️ Expert (MCP call):**
> ```text
> get_image_info { "image":"/cases/cfreds-fresh/4Dell-Latitude-CPi.E01" }
> ```
> **💬 End-user (prompt):** *"What does Agentropix report about this image's media size and MD5?"*
> The session calls `get_image_info` (which drives `ewfinfo`) and summarises the acquisition metadata.

**Execution G → Output G.**

*Execution G:* `get_image_info` (as above).

*Output G (CFReDS validated, `ewfinfo 20140816`):* case_number `Greg Schardt`, examiner `Shane
Robinson`, acquisition_date `Wed Sep 22 14:06:04 2004`, OS `Windows XP`, format `EnCase 4`,
bytes/sector `512`, sectors `9514260`, **media_size `4.5 GiB (4871301120 bytes)`**, **MD5
`aee4fcd9301c03b3b054623ca261959a`**.

> 🔎 **Decision-point note (for both tracks):** `get_image_info` reports **4.5 GiB** (logical media)
> while `evidence_register` reports `671094597` bytes (~640 MiB). The latter is the *compressed EWF
> container on disk*; the former is the *logical media size*. Both are correct — don't be confused.

`evidence_register` is idempotent and audited; `evidence_id` is deterministic over (case_id, path,
sha256).

---

## Phase 4 — The investigation tool chain

This is where the two paths diverge. **Path A (manual)** and **Path B (autonomous)** below are each
complete, standalone procedures. Read the one you intend to run; the analysis tools and their meaning
are identical — only *who drives them* differs.

The analysis primitives are **case-agnostic** — their outputs are **not** auto-persisted. You turn an
analysis result into case state by shaping it into `record_finding`/`idx_ingest` (Phase 5). That seam is
intentional.

> **Steering which tools to run.** Which analysis primitives matter most depends on the scenario. The
> per-case attack-chain hypotheses (and the recommended tool order for each) live in
> [Per-case attack-chain hypotheses](../06-use-cases/case-hypotheses.md).

---

### Path A — MANUAL execution (you drive each tool)

> 🟢 **When to choose Path A:** you want to inspect each result before the next step; you're doing
> interactive examination, a demo, or the approval gate; the result of each call informs what you call
> next. Works in **both** CLI and Desktop (mind the 1 MB cap in Desktop).
> **Lanes:** A-Expert (run the commands) and A-User (ask the `💬` questions one at a time).

**Prerequisites:** Phases 0–3 done (server up, client connected, `health` ok, case active, evidence
registered).

**A.1 — Get the partition offset.** Disk images have a partition table; `fls` needs the partition
**offset in sectors**. Find the NTFS slot's start sector.

> **🖥️ Expert (command):**
> ```bash
> mmls /cases/cfreds-fresh/4Dell-Latitude-CPi.E01
> ```
> (Or the in-band MCP tool: `get_partitions { "image":"...E01" }`.)
> **💬 End-user (prompt):** *"What's the partition layout of the CFReDS image, and where does the NTFS
> partition start?"*
> The session calls `mmls` / `get_partitions` and tells you the start sector you'll need for the next
> step (it carries that offset forward automatically when you ask it to list files).

**Execution H → Output H.**

*Execution H:* `mmls /cases/cfreds-fresh/4Dell-Latitude-CPi.E01`

*Output H (validated):* the NTFS partition starts at sector **63**.

> ⚠️ **GOTCHA (bug B2):** omitting `offset` on a physical-disk image makes `fls` run at the MBR and fail
> with `Cannot determine file system type`. Always pass the mmls-derived `offset`. *(End-user: the
> assistant does this for you — that's why it checks the partition layout first.)*

**A.2 — File system listing (live + deleted).**

> **🖥️ Expert (MCP calls):**
> ```text
> fls { "image":"/cases/cfreds-fresh/4Dell-Latitude-CPi.E01", "offset":63, "recursive":true }
> fls { "image":"...E01", "offset":63, "recursive":true, "deleted_only":true }    # T1070.004
> ```
> **💬 End-user (prompt):** *"List all the files on the CFReDS image, then show me just the deleted
> files."*
> The session runs `fls` twice (live, then deleted-only) using the offset it found in A.1, and reports
> the counts plus notable entries.

**Execution I → Output I.**

*Execution I:* `fls` live, then `fls` deleted-only (as above).

*Output I (CFReDS validated):*
- Live: `entry_count` **`12545`** (allocated 12180, unallocated 365; regular files 11508, directories
  766). First entry: `/Documents and Settings` (inode `3671-144-7`, modified `2004-08-19 23:04:05 UTC`).
- Deleted-only: `entry_count` **`365`** (e.g. `/Documents and Settings/Default User/MPC7A4.tmp`, inode
  0, zeroed timestamps).

Move on once you have a non-zero live `entry_count` and have eyeballed the deleted set.

**A.3 — IOC carving (feature extraction).**

> **🖥️ Expert (MCP call):**
> ```text
> run_bulk_extractor { "target":"/cases/cfreds-fresh/4Dell-Latitude-CPi.E01",
>                      "out_dir":"/tmp/agentropix-sift-cfreds-be",
>                      "max_features":1000 }
> ```
> **💬 End-user (prompt):** *"Carve out all the indicators — emails, domains, IPs, URLs — from the
> CFReDS image."*
> The session runs `run_bulk_extractor` into an allowlisted output directory and reports how many
> features of each type it found.

**Execution J → Output J.**

*Execution J:* `run_bulk_extractor` (as above).

*Output J (CFReDS validated):* 25 feature types, **124,729 total features**. Notable: domain
**52,270**, email **30,452**, url **17,296**, ip **1,797**, telephone 1,774, winprefetch 88, winlnk
195, ether (MAC) 927, **aes_keys 1**, alerts 6. (On a first run this carves from scratch and takes
longer; a re-run reuses the existing carve — `reused_existing:true`, 0.0 s — with identical counts.)

> ⚠️ **GOTCHA (bug B3):** `out_dir` MUST be under a Thymus-allowlisted prefix —
> `/tmp/agentropix-sift-*`, `/cases/`, `/mnt/`, `/media/`, `/evidence/`. Otherwise Thymus rejects it
> with `path not found`. On Desktop the result returns as the **out_dir path** (not inline), which is
> correct — raw feature files exceed the 1 MB cap. *(End-user: the assistant picks an allowlisted
> location for you.)*

**A.4 — YARA (optional; currently weak).**

> **🖥️ Expert (MCP call):**
> ```text
> scan_yara { "target":"/cases/cfreds-fresh/4Dell-Latitude-CPi.E01",
>             "rules":["/cases/yara-rules/local/pf_smoketest.yar"],
>             "max_matches":200 }
> ```
> **💬 End-user (prompt):** *"Run a YARA scan over the CFReDS image and tell me if anything matched."*
> The session runs `scan_yara` and reports the match count. Zero matches on the smoke-test ruleset is
> the expected clean result — it does not mean the scan failed.

**Execution K → Output K.**

*Execution K:* `scan_yara` (as above).

*Output K (CFReDS validated):* `match_count 0`, `matches []`, `tool_available true`,
`compile_failures []`, `raw_stdout_sha256 e3b0c44298…` (the SHA-256 of the empty string).

> 🔎 **Read this correctly:** `match_count 0` with `raw_stdout_sha256` == the empty-string hash is the
> **success signature of a clean smoke-test**, not a failure. **GAP:** only the `pf_smoketest.yar`
> ruleset is installed; drop a production ruleset under an allowlisted prefix (e.g.
> `/usr/share/yara-rules/`) before relying on YARA.

**A.5 — Memory-image cases (SRL-2015, SRL-2018, rocba).** After `case_init` + `evidence_register` on the
`.img`/`.raw`/`.001`:

> **🖥️ Expert (MCP calls):**
> ```text
> get_pslist         { "image":"/cases/SRL-2018/base-wkstn-01-memory.img" }   # processes
> get_netscan        { "image":"..." }                                        # sockets
> get_malfind        { "image":"..." }                                        # injected / RWX code
> get_svcscan        { "image":"..." }                                        # services
> build_process_tree { "image":"..." }                                        # PPID forest, LOLBin flags
> ```
> **💬 End-user (prompt):** *"Analyse this memory image: what processes were running, what network
> connections were open, and is there any injected code?"*
> The session runs the Volatility-backed tools (`get_pslist`, `get_netscan`, `get_malfind`,
> `get_svcscan`, `build_process_tree`) and summarises the findings.

**A.6 — Cross-host correlation (multi-image cases).**

> **🖥️ Expert (MCP calls):**
> ```text
> correlate_timeline { "images":["host1.img","host2.img"], "event_ids":[...] }
> pivot_on_ioc       { "ioc":"<value>", "images":[...] }
> ```
> **💬 End-user (prompt):** *"Correlate the timelines across all the hosts in this case, then pivot on
> the C2 IP to see which machines it touched."*
> The session runs `correlate_timeline` (merging events across hosts into one UTC stream) and
> `pivot_on_ioc` (the substring hunt across images) and tells you where the indicator appears.

**A.7 — Disk-image registry / execution / event-log artifacts.** Extract the hives first, then parse
them. `get_amcache` is **Win7+ only** (XP has none); `get_evtx` is Vista+ (`.evtx`), while **XP uses
`.evt`, handled by `get_evt`**; `get_prefetch` works on XP (it *does* have prefetch).

> **🖥️ Expert (MCP calls):**
> ```text
> extract_files { "image":"...E01", "offset":63, "paths":["<hive paths>"], "dest":"/tmp/agentropix-sift-hives" }
> get_registry  { ... }   # RegRipper hive analysis
> get_shimcache { ... }   # AppCompatCache execution evidence
> get_amcache   { ... }   # Win7+ only
> get_prefetch  { ... }   # XP-compatible
> get_evtx      { ... }   # Vista+ (.evtx)  —  XP: get_evt (.evt)
> ```
> **💬 End-user (prompt):** *"Pull the registry hives off this disk image and tell me what programs were
> executed, what's set to auto-run, and what the event logs show."*
> The session calls `extract_files` to lift the hives to an allowlisted dir, then runs
> `get_registry`/`get_shimcache`/`get_prefetch` (and `get_amcache` on Win7+, `get_evtx`/`get_evt` for the
> event logs) and summarises the execution and persistence artifacts — automatically picking `get_evt`
> for an XP image and skipping Amcache where the OS has none.

When you've gathered enough analysis output to support your hypotheses, proceed to **Phase 5** to stage
findings.

---

### Path B — AUTONOMOUS execution (the engine drives)

> 🟢 **When to choose Path B:** you want the full sequence run end-to-end without supervision; the image
> is large; the run is long; you want overnight/fan-out runs. **Use Claude CLI** — Desktop is
> human-in-the-loop only and will hit the 1 MB cap on the heavy tools.
> **Lanes:** B-User (paste the autonomous prompt, B.1) and B-Expert (run the detached driver, B.2).

The autonomous path stages findings as **DRAFT** and **stops at the approval gate** — a bot must not
sign chain-of-custody. There are two flavors: B.1 an interactive autonomous *prompt* (the non-expert
lane), and B.2 a fully-unattended headless *driver* (the validated production pattern, the expert lane).

**Prerequisites:** Phases 0–1 done. For the unattended driver, start the MCP server from a **detached**
process (Phase 0.3 gotcha) so it isn't reaped.

#### B.1 — Interactive autonomous prompt (Desktop or CLI)

> **💬 End-user (prompt) — paste this to a client that has the MCP attached.** The agent runs the whole
> sequence itself, handling OS differences (e.g. XP has no Amcache/`.evtx`):
>
> *"You are a DFIR analyst with the Agentropix MCP. Investigate case `<case_id>` on image `<path>`. Run
> the full SIFT sequence (acquisition → examination → analysis → findings), staging findings as DRAFT.
> Use mmls-derived offsets for `fls` on physical disks. Write `bulk_extractor` `out_dir` under
> `/tmp/agentropix-sift-<case>`. Do NOT approve findings. Finish by generating the full report and
> summarising the thread chain."*
>
> **🖥️ Expert note:** the same prompt works in `claude --print` for a one-shot headless run; the
> sequence the agent follows per case is: 1) `case_init`→`case_activate`; 2) `evidence_register` (hash);
> 3) `get_image_info`; 4) `fls` (offset from mmls) live + deleted; 5) `run_bulk_extractor` (allowlisted
> out_dir); 6) [memory images] `get_pslist`/`get_netscan`/`get_malfind`/`get_svcscan`/`build_process_tree`;
> 7) `record_finding` (DRAFT) × N; 8) `report_generate { profile:"full" }`.

#### B.2 — Headless driver, fully unattended (the VALIDATED pattern)

This is the **B-Expert** lane. The reference driver (`agx_gearb.py`-class) holds **one persistent MCP
session** (initialize → capture `Mcp-Session-Id` → `notifications/initialized` → `tools/call`),
validates every param against the live schema, treats a non-empty `result.error` as a failure (no false
"ok"), **checkpoints `SUMMARY.json` after every step** (so a death never loses prior progress), and is
**idempotent** (reuses an existing carve rather than re-running it).

> **🖥️ Expert (command) — launch it DETACHED.** This is the single most important step:
> ```bash
> setsid nohup bash -c "python3 /path/to/agx_gearb.py '<BEARER_TOKEN>' <case_key> > run.log 2>&1" </dev/null >/dev/null 2>&1 &
> disown
> ```
> **💬 End-user equivalent:** non-experts don't run the detached driver — use the interactive autonomous
> prompt in **B.1** instead, which gets the same investigation without any shell-detachment concerns.

> ⚠️ **GOTCHA (bug B5, the big one):** a long-blocking tool call (e.g. `run_bulk_extractor` on a 20 GB
> image) is killed if the driver is **not** detached — the server-side job finishes but the client dies
> at a turn/shell boundary before it captures the result. `setsid` + `nohup` + `disown` (own
> session/pgroup, all fds redirected) plus per-step checkpointing makes the run **survivable**.

**What happens each iteration.** The driver walks the per-evidence sequence:
- **Memory** (`.img`/`.raw`/`.001`): `get_pslist`, `get_netscan`, `get_malfind`, `get_svcscan`,
  `build_process_tree`.
- **Disk** (E01): `fls` (mmls offset), `extract_files` for hives → `get_registry`/`get_shimcache`
  (+`get_amcache` Win7+ only), `get_prefetch`, `get_evtx` (Vista+; XP `.evt` → `get_evt`).

After each tool it writes the step's `ok`/`elapsed`/`error` into `SUMMARY.json`.

> **🖥️ Expert (command) — monitor progress:**
> ```bash
> tail -f run.log
> # and read the per-step checkpoint:
> #   gearB/<case>/SUMMARY.json   (per-step ok / elapsed / error)
> ```
> **💬 End-user (prompt) — on the interactive lane:** *"How's the investigation going — which steps are
> done?"* The assistant reports its progress as it works through the sequence.

**Survivability / halt behavior.** Findings are staged DRAFT and the driver **stops before approval**
(the examiner gate). If the driver process is killed, the incremental `SUMMARY.json` preserves completed
steps; relaunching resumes idempotently (an existing complete carve is detected via
`<out_dir>/report.xml` and skipped). If the MCP server died mid-run, the driver re-initializes the
session on the next failure.

**Execution L → Output L — the CFReDS validated 10/10-step run.** Final session
`8f34067e702e40ef92242a665d8999c8` (run3), finished `2026-05-29T22:44:45Z`, **10/10 steps OK**,
detached. Step-by-step:

| # | Step (Execution) | Result (Output, validated) |
|---|---|---|
| 01 | `case_init` | `case_id INC-2026-0529224443`, status `active` |
| 02 | `case_activate` | pointer `/home/admin2/.agentropix/active_case` |
| 03 | `get_image_info` | media 4.5 GiB, MD5 `aee4fcd9…`, OS Windows XP |
| 04 | `evidence_register` | sha256 `96bebe80…`, `indexed:true` → `agentropix-evidence-2026.05.29` |
| 05 | `fls` recursive | `entry_count 12545` |
| 06 | `fls` deleted-only | `entry_count 365` |
| 07 | `run_bulk_extractor` | reused carve, 25 feature types / 124,729 features |
| 08 | `scan_yara` (smoketest) | `match_count 0` (clean) |
| 09 | `record_finding` | `finding_id cfreds-acq-001`, `indexed:false` (DRAFT) |
| 10 | `report_generate full` | `report_id f5bde7c3…`, **`approved_finding_count 0`** |

> 🔎 The 09→10 result (`record_finding` shows `indexed:false`; the `full` report shows
> `approved_finding_count 0`) is the **approval gate working as designed** — DRAFT findings are not
> indexed or surfaced in the report until an examiner approves. That is Phase 6.

---

## Phase 5 — Record findings (staged DRAFT)

> 🟢 **In plain terms:** turn an analysis result into a case finding. It lands as `DRAFT`; the engine
> (and any LLM) **cannot** self-approve.

> **🖥️ Expert (MCP call):**
> ```text
> record_finding { "finding": {
>   "finding_id":"cfreds-acq-001",
>   "host":"cfreds-schardt-xp",
>   "mitre_attack":"T1588.002",
>   "confidence":0.6,
>   "timestamp":"2004-09-22T14:06:04Z",
>   "severity":"medium",
>   "title":"...",
>   "ioc_value":"...", "ioc_type":"...",
>   "source_artifact":"/tmp/agentropix-sift-cfreds-be/email.txt" } }
> ```
> **💬 End-user (prompt):** *"Record a medium-severity finding for the hacking-tool emails we carved,
> mapped to MITRE T1588.002, citing the email.txt artifact."*
> The session shapes a valid finding (generating the required `finding_id`) and calls `record_finding`.
> It will land as DRAFT — the assistant cannot approve it.

**Required fields (FindingsValidator):** `finding_id`, `host`, `mitre_attack` (a valid technique),
`confidence` (0.0–1.0), `timestamp` (ISO-8601). **Coherence:** `severity:high` needs `confidence ≥
0.70`; `critical` needs `≥ 0.85`. Findings land `DRAFT`; the draft-gate (W-286) strips any
caller-supplied `approval.*` and stamps provenance.

> ⚠️ **GOTCHA (bug B4):** a missing `finding_id` → `finding must contain non-empty finding_id`. Always
> include it. *(End-user: the assistant generates one for you.)*

**Execution M → Output M.**

*Execution M:* `record_finding` (as above).

*Output M (CFReDS validated):* `finding_id cfreds-acq-001`, `indexed:false`, `indexed_to
agentropix-findings-2026.05.29`, error empty. (DRAFT findings are intentionally not pushed to the index.)

---

## Phase 6 — Approve findings in the portal (human-only gate)

> 🟢 **In plain terms:** every finding stays `DRAFT` until a human signs off in a browser form. The LLM
> **cannot** self-approve — this is your primary touchpoint with the platform, and both execution paths
> stop here.

Promotion to `APPROVED` happens only through the HMAC approval sidecar — a self-contained browser form,
published on the **tailnet only**, behind a valid TLS certificate:

**🔗 `https://siftworkstation.taile7c9ca.ts.net:8443/`** (or, on the workstation itself,
`http://127.0.0.1:8800/`).

To submit a decision (the page does all crypto client-side — your password never leaves the tab):

1. **Open** the portal (you must be on the tailnet and device-approved).
2. **Identify** — fill **Examiner ID** (must equal `AGENTROPIX_APPROVER_USER`) and **Case ID** (e.g.
   `INC-2026-0529224443`).
3. **Target** — paste the `DRAFT` finding's **Finding / Event / Approval ID** (e.g. `cfreds-acq-001`)
   and pick the matching **Target Type**.
4. **Transition** — **From** = `DRAFT`, **To** = `APPROVED` / `REJECTED` / `REVOKED`; optional **Reason**.
5. **Enter the Approver password** and **Sign & Submit.** The page fetches a single-use nonce, derives
   the PBKDF2 key locally, and sends only the HMAC.

> **🖥️ Expert (MCP call) — the same human attestation in-band:**
> ```text
> approve_finding { "finding_id":"cfreds-acq-001",
>                   "approver_id":"victor.galvan",
>                   "password":"<examiner pw>" }
> ```
> **💬 End-user (prompt):** you do this step **yourself in the browser form** — there is no plain-language
> shortcut, by design. Ask the assistant *"which findings are waiting for my approval and what are their
> IDs?"*, then open the portal and approve. The assistant will not (and cannot) approve on your behalf.

A success writes a deterministic approval doc to the daily `agentropix-approvals-YYYY.MM.DD` index,
extends an append-only hash chain, and moves the finding out of `DRAFT`. Approvals are **append-only** —
correct a mistake with a `REVOKED` retraction, never a delete.

> **Hard stop.** Examiner crypto sign-off is a human-only decision. Only the configured
> `AGENTROPIX_APPROVER_USER` is accepted. Deep dive:
> [Approval Portal](../05-safety-forensics/approval-portal.md) ·
> [Human-in-the-Loop](../05-safety-forensics/human-in-the-loop.md) ·
> [Approval-Gate use case](../06-use-cases/uc-approval-gate.md).

---

## Phase 7 — Generate and verify the sealed report

> 🟢 **In plain terms:** build the report and confirm its seal so a third party can trust it hasn't
> changed.

> **🖥️ Expert (MCP call):**
> ```text
> report_generate { "profile":"full", "case_id":"INC-2026-0529224443" }
> ```
> **💬 End-user (prompt):** *"Generate the full report for this case."*
> The session calls `report_generate` with the `full` profile and returns the report ID and section
> counts. Remember: sections stay empty until findings are approved (Phase 6).

**Profiles:** `full` / `executive` / `timeline` (APPROVED only) / `ioc` / `findings` (APPROVED only) /
`status` (all states). Report profiles respect approval state — an empty `findings` section *before any
approval* is expected, not a bug.

**Execution N → Output N.**

*Execution N:* `report_generate { profile:"full", case_id:"INC-2026-0529224443" }`

*Output N (CFReDS validated):* `report_id
f5bde7c3b24de511fd67cd7f6769dd12580c0c6fdf7b80a59ceb3a1e9b8c787d`, `snapshot_at
2026-05-29T22:44:45.764637+00:00`, **`approved_finding_count 0`** (the one finding is still DRAFT),
sections executive_summary/findings/timeline/iocs all count 0, error empty.

For the CLI `run`-based flow, a single `run` writes three files next to `--out` and seals the report;
verify the seal with the standalone verifier:

> **🖥️ Expert (command):**
> ```bash
> uv run python scripts/verify_seal.py inc-0042-triage.json
> ```
> **💬 End-user (prompt):** *"Verify the seal on this report — confirm it hasn't been tampered with since
> it was generated."*
> The session runs the seal verifier and tells you whether the report and audit log are intact.

This confirms the report and audit log are unaltered since sealing — the judge-verifiable
chain-of-custody property at the heart of the engine (`report_seal` = HMAC-SHA256, audit seal
cross-bound, `evidence_image_sha256` binds the report to the exact image). Deep dive:
[Audit & Courtroom Seal](../05-safety-forensics/audit-courtroom.md) ·
[AI Disclosure](../05-safety-forensics/ai-disclosure.md).

---

## Phase 8 — Curate and push IOCs to Wazuh

> 🟢 **In plain terms:** push only a curated, provenance-tagged IOC set to Wazuh — never the raw carve.
> The push is a guarded mutation.

> **Status: EXPERIMENTAL / OPT-IN.** The Wazuh integration is disabled by default and gated behind kill
> switches plus a one-shot `mutation_token`. See [`.crew/env-vars.md`](../../.crew/env-vars.md).

**8.1 — Curate first (accountability).** Raw carve features are *candidate* strings, not IOCs; ~99% are
noise (usenet message-ids → `@4ax.com`, RFC/vendor domains, slack space). Pushing raw (100k+ candidates)
would pollute Wazuh. Run the pipeline: de-noise → dedup (`sort -u`) → tier-tag (Tier-1/2) → attach
provenance (source file, case_id, evidence_id, MD5/SHA-256) → a single consolidated `findings.json`.
Drop non-IOC families: `winprefetch`/`winlnk` become finding/timeline records with MITRE (T1204/exec),
and `aes_keys`/carved jpeg/zip are evidence artifacts, **not** IOCs.

**8.2 — Mint an evidence-gate token (mutation guard).** Live writes need a token `egt_<26-char-ULID>`
whose scope matches the op:

> **🖥️ Expert (command):**
> ```bash
> python3 -c "import agentropix_sift.evidence_gate as e; print(e.mint(scope='index_findings', ttl_seconds=3600, operator='victor.galvan'))"
> ```
> **💬 End-user (prompt):** minting a mutation token is a guarded operator step. Ask the assistant to
> *"prepare the curated IOC set and dry-run the Wazuh push"* — the live push (with token) is an
> operator-confirmed action.

**8.3 — Dry-run, then live.**

> **🖥️ Expert (MCP calls):**
> ```text
> wazuh_index_findings { "findings":[...], "case_id":"INC-2026-0529224443", "dry_run":true }                              # gate: expect ok, no errors
> wazuh_index_findings { "findings":[...], "case_id":"INC-2026-0529224443", "dry_run":false, "mutation_token":"egt_..." }
> ```
> **💬 End-user (prompt):** *"Dry-run the Wazuh push of the curated IOCs and tell me what would be
> indexed."* (The live push is the operator-gated follow-up.)

> ⚠️ **GOTCHA:** a live push without the token → `EvidenceGateRequired`. Mint a token scoped to the op
> (`index_findings`).

**Execution O → Output O — CFReDS validated, SUCCESS.** Evidence gate minted (scope `index_findings`,
ttl 3600 s, operator victor.galvan). Push: **`indexed_count=607, indexed_failed_count=0, batch_count=2,
outcome=indexed`**, run_id `b2d8aa6c`, index `agentropix-findings-2026.05.29`. **Independently verified
on the indexer:** total docs `607`; docs matching `case_id INC-2026-0529224443` = `607` (100%
accounted). Sample doc: `cfreds-ip-…` `{host=cfreds-schardt-xp, ioc=207.68.174.248, type=ipv4,
mitre=T1071.001, tier=2}`.

**What was pushed (curated, NOT raw):** 7 public IPs (tier-2) + 300 domains (capped) + 300 emails
(capped) = **607 findings**, each carrying provenance (case_id + E01 MD5 `aee4fcd9…` + SHA-256
`96bebe80…` + source_artifact). The highest-signal findings were tool-author emails —
`fyodor@insecure.org` (nmap), `dugsong@monkey.org` (dsniff), `ylo@cs.hut.fi` (ssh) — a hacking-tool
fingerprint consistent with the Mr. Evil scenario.

**8.4 — Verify in Wazuh.** Create an index pattern `agentropix-findings-*` with time field
**`@timestamp`** (NOT `timestamp`, which is the 2004 acquisition date), then Discover → filter
`case_id`. Or Dev Tools: `GET agentropix-findings-*/_count {query:{term:{case_id:"..."}}}`.

> ⚠️ **GOTCHA:** Wazuh Discover shows 0 if the default time range doesn't cover the evidence timestamps
> — use `@timestamp` / widen the range.

**Honest caveats.** The 2004 CFReDS image is a training image; the IOCs are carved candidates
(provenance-tagged, tier-tagged) with modest live-threat value. Domain/email were capped at 300 each.
Full procedure + dashboards: [Wazuh-Push use case](../06-use-cases/uc-wazuh-push.md) ·
[Wazuh Integration](../09-integrations/wazuh-portal.md).

---

## Per-case attack-chain hypotheses (summary)

Each in-scope case (SRL-2015 multi-host APT, SRL-2018 network-wide C2, cfreds-fresh insider misuse,
rocba insider IP theft) has a **hypothesis-only scaffold** that steers which tools to reach for first.
These are bias-checks, not conclusions — prove each link against live tool output before treating it as
fact.

→ **Full scaffolds:** [Per-case attack-chain hypotheses](../06-use-cases/case-hypotheses.md) — the
per-case chains, key tools, confidence ratings, and cross-case operator notes (e.g. `.mans` files are
SQLite; XP hosts have prefetch but no SRUM/amcache).

---

## Troubleshooting ledger

The six bugs found and fixed during the validated proving run, plus the inline tips. (Bugs B2–B5 are
also previewed up front in [Gotchas at a glance](#gotchas-at-a-glance).)

### The six bugs (symptom → root cause → fix → exit criteria)

| ID | Sev | Symptom | Root cause | Fix | Exit criteria |
|----|-----|---------|-----------|-----|----------------|
| **B1** | HIGH | Driver reported `ok=True` for every step incl. failures | checker only looked at JSON-RPC-level `error`; tools return `{"error":...}` **inside** a 200 result | treat a non-empty `result.error` as failure | a known-bad call (`fls` w/o offset) returns `ok=False` |
| **B2** | HIGH | `fls` → "Cannot determine file system type" | E01 is a physical disk (MBR); `fls` ran at offset 0 | pass the TSK sector `offset` (NTFS at **sector 63**, mmls-confirmed) | `fls` returns >0 entries (**got 12,545**) |
| **B3** | MED | `run_bulk_extractor` → "Thymus REJECT: path not found" | `out_dir` under a non-allowlisted path | put `out_dir` under `/tmp/agentropix-sift-*` (or `/cases//mnt//media//evidence/`) | bulk_extractor writes `report.xml` |
| **B4** | MED | `record_finding` → "must contain non-empty finding_id" | finding dict missing `finding_id` | add `finding_id` to every finding | `record_finding` returns `ok=True` |
| **B5** | CRIT | Driver died mid-run; steps 7–10 never logged though server-side carve completed | background process reaped at a turn/shell boundary; long blocking call outlived the parent | (a) launch detached `setsid`+`nohup`+`disown`, all fds redirected; (b) checkpoint `SUMMARY.json` per step; (c) idempotent/resumable (reuse existing carve) | driver survives a >60 s blocking call across a later tool call; `SUMMARY.json` reflects all steps |
| **B6** | MED | bulk_extractor response handling stalled the client | huge structured payload (30k+ emails) returned inline | prefer the tool's path+counts contract; cap `max_features`; read `out_dir` from disk (also satisfies the Desktop 1 MB cap) | client finalizes within seconds when carve output is on disk |

### Inline tips (quick reference)

| Symptom | Cause | Fix |
|---|---|---|
| `tools/list` returns 0 | bare POST, no MCP session | full handshake: initialize → `Mcp-Session-Id` → initialized → tools/list |
| `tool_count` says 38 | stale startup banner | live-verify via `tools/list` / `health.tool_count` |
| `401 invalid_bearer_token` | token mangled (`cut`/trailing newline/smart quote) | source the pinned export cleanly; exact `Authorization: Bearer <token>` |
| driver "10/10 ok" but empty | checker ignored in-result `error` | treat non-empty `result.error` as failure (B1) |
| server gone mid-run | reaped with parent shell | start detached; driver re-inits session on failure |
| live push `EvidenceGateRequired` | mutation guard | mint `egt_<ULID>` token, scope = op |
| Wazuh Discover shows 0 | default range vs 2004 timestamp | use `@timestamp` / widen range |
| Desktop tool result fails | >1 MB cap | use file-path/out-dir return mode; scope/paginate |
| Desktop tool list empty | first `mcp-remote` spawn slow | prime `npx -y mcp-remote --help` once |
| `claude --print` exits 0, empty stdout | context exhaustion | wrap with a watcher; incremental commits; `claude --continue` |

### Known gaps

- **YARA:** only `pf_smoketest.yar` installed; no production ruleset.
- **Memory-case sequences** (SRL-2015/2018/rocba): authored but not yet live-validated.
- **Report depth:** DRAFT findings only until examiner approval (intentional).
- **CFReDS:** 2004 training image; carved candidate IOCs (provenance-tagged), modest live-threat value.

---

## Quick command recap

```bash
# Phase 0 — pre-flight
uv run agentropix-sift doctor
bash /home/admin2/.openclaw/workspace/scripts/start-agentropix-mcp.sh start
ewfverify /cases/cfreds-fresh/4Dell-Latitude-CPi.E01

# Phase 1 — connect (CLI)
claude mcp add --transport http agentropix-sift "http://<TAILNET-IP>:8765/mcp" --header "Authorization: Bearer <TOKEN>"
claude mcp list        # ✓ Connected ; then call health -> tool_count

# Phases 2-3 (MCP tool calls): case_init -> case_activate -> evidence_register -> get_image_info

# Phase 4A — manual: mmls -> fls(offset) live+deleted -> run_bulk_extractor(out_dir) -> scan_yara
mmls /cases/cfreds-fresh/4Dell-Latitude-CPi.E01

# Phase 4B — autonomous (detached driver)
setsid nohup bash -c "python3 /path/to/agx_gearb.py '<TOKEN>' cfreds > run.log 2>&1" </dev/null >/dev/null 2>&1 &
disown ; tail -f run.log

# Phases 5-6 — record_finding (DRAFT) ; approve in portal (human):
#   https://siftworkstation.taile7c9ca.ts.net:8443/

# Phase 7 — report_generate{profile:full} ; verify seal:
uv run python scripts/verify_seal.py inc-0042-triage.json

# Phase 8 — curate -> mint egt_ token -> wazuh_index_findings(dry_run then live) -> verify on indexer
```

---

## Where to go next

- **[Quickstart](quickstart.md)** — the condensed 3-command path and seal verification.
- **[Client Setup](../09-integrations/client-setup.md)** — exact CLI/Desktop wiring, tailnet endpoint, token handling.
- **[CLI Reference](../08-reference/cli-reference.md)** — every flag, exit code, and output line of `run` and `doctor`.
- **[Tool capability map](../04-mcp-tools/capability-map.md)** — pick the right tool by DFIR function.
- **[Per-case attack-chain hypotheses](../06-use-cases/case-hypotheses.md)** — what to look for, per case.
- **Use cases** — [Disk triage](../06-use-cases/uc-disk-triage.md) ·
  [Memory triage](../06-use-cases/uc-memory-triage.md) ·
  [Approval gate](../06-use-cases/uc-approval-gate.md) ·
  [Wazuh push](../06-use-cases/uc-wazuh-push.md).
- **Safety & forensics** — [Approval Portal](../05-safety-forensics/approval-portal.md) ·
  [Audit & Courtroom Seal](../05-safety-forensics/audit-courtroom.md) ·
  [Provenance & Grounding](../05-safety-forensics/provenance-grounding.md).
- **Shared references (oracle)** — [`.crew/facts.md`](../../.crew/facts.md) (canonical numbers:
  71 MCP tools, 16 wrappers, 4464 tests), [`.crew/tool-list.md`](../../.crew/tool-list.md) (all
  71 tools), [`.crew/env-vars.md`](../../.crew/env-vars.md),
  [`.crew/agents-list.md`](../../.crew/agents-list.md).
