# Use Case — Triage an E01 Disk Image End to End

> **Actor:** DFIR analyst (or an MCP-driving agent) running on the SANS SIFT Workstation.
> **Goal:** Take a freshly acquired E01 disk image, establish chain-of-custody, run the
> autonomous Trinity Loop over it, and produce a **sealed** triage report on disk.
> **Surfaces exercised:** the `agentropix-sift run` CLI (`src/agentropix_sift/cli.py`) and the
> MCP disk-triage tool chain (`src/agentropix_sift/mcp_server/`). See
> [`canonical-facts.md`](../08-reference/canonical-facts.md) for every numeric claim.

This use case has two entry points that are deliberately distinct:

1. **The one-shot CLI run** (`agentropix-sift run <image>`) — drives the full 13-class `SWARM`
   under the Trinity Loop and seals the report. This is the autonomous path.
2. **The step-by-step MCP tool chain** — what an interactive agent issues when it wants to drive
   individual forensic tools (modelled on [Playbook A in the upstream guides](../08-reference/canonical-facts.md)
   and `docs/guides/playbooks.md`). This is the manual / exploratory path.

Both end at the same artefact: a finding set whose facts each originate from a named deterministic
MCP tool, sealed with an HMAC-SHA256 envelope.

---

## Contents — what's in this page (and what to expect)

> Jump to any section below. Each row tells you what that part gives you, so you can go straight to your point.

| Section | What you'll get |
|---|---|
| [How to read this page](#how-to-read-this-page) | The dual-audience convention (🖥️ expert command vs 💬 end-user prompt), the four-lane usability matrix, the real-data note, and how the GOTCHA boxes work. |
| [Use-case diagram](#use-case-diagram) | A Mermaid map of the actors and the path from `doctor` pre-flight through autonomous `run` or the MCP chain to a sealed report the examiner verifies. |
| [Sequence — the autonomous `agentropix-sift run` path](#sequence--the-autonomous-agentropix-sift-run-path) | The one-shot Trinity Loop run end to end — CLI guard rails, Architect→SWARM→Critic, the 0.85 halt, and the three sealed output files (with both audience tracks and validated output). |
| [Sequence — the granular MCP disk chain](#sequence--the-granular-mcp-disk-chain) | The step-by-step manual tool chain (`get_image_info`→`get_partitions`→`case_init`/`evidence_register`→`fls`→`extract_files`→execution-evidence→`run_hashdeep`), each shown both ways with real CFReDS outputs. |
| [Actor, preconditions, steps, postconditions](#actor-preconditions-steps-postconditions) | The formal use-case spec — actor, the 16 SIFT binary prerequisites, numbered steps for both paths, the sealed-report postconditions, and the CLI commands used. |
| [See also](#see-also) | Cross-links to the memory-triage, approval-gate, and Wazuh-push use cases plus the tool and agent catalogues. |

---

## How to read this page

This page follows the portal's **dual-audience** convention (the gold standard is
[`docs/01-overview/user-guide.md`](../01-overview/user-guide.md)). Every tool in the triage sequence is
shown **two ways at once**, side by side:

> **🖥️ Expert (command):** the exact CLI / MCP call to type into a terminal or pass over the MCP.
> **💬 End-user (prompt):** the plain-language question to type into a Claude session that has the
> Agentropix MCP connected. A simple, focused question is enough — the session recognises it as an
> Agentropix capability and routes it to the right MCP tool automatically.

Both surfaces hit the **same deterministic MCP tool** and return the **same facts** — only the surface
differs. Pick your track and follow it; you only need one.

**The example outputs below are from a REAL run.** The case IDs, hashes, sector offsets, and entry
counts (e.g. evidence SHA-256 `96bebe80…`, NTFS @ sector 63, `entry_count 12545`) come from the
**validated 2026-05-29 CFReDS run** (NIST "Hacking Case", Greg Schardt / "Mr. Evil", Windows XP). Your
own run will produce *different* IDs and timestamps, but the *shape* of the output will match. The image
path is written as a placeholder `<IMAGE>` (e.g. `/cases/cfreds-fresh/4Dell-Latitude-CPi.E01`); the
extraction directory as `<OUT_DIR>` (must be under a Thymus-allowlisted prefix —
`/tmp/agentropix-sift-*`, `/cases/`, `/mnt/`, `/media/`, `/evidence/`).

### Usability matrix — find your lane

There are **two ways to drive the triage** (Autonomous `run` vs Manual MCP chain) and **two ways to
interact** (Expert CLI/MCP vs Non-expert prompt). That makes **four lanes** — find yours and follow it
consistently. All four operate on the **same image** and reach the **same sealed artefact**.

| | **🖥️ Expert (types CLI/MCP commands)** | **💬 Non-expert (types a plain-language prompt)** |
|---|---|---|
| **Autonomous** (`agentropix-sift run` drives the whole Trinity Loop unattended, sealing the report) | **Lane Auto-Expert.** Run `agentropix-sift run <IMAGE> --max-iterations 5 --out report.json`. Read `report.json` + the audit log. The one-shot production path. → [autonomous sequence](#sequence--the-autonomous-agentropix-sift-run-path) | **Lane Auto-User.** Paste one autonomous prompt ("triage this disk image end to end and seal the report") and let the assistant narrate progress. → [autonomous sequence](#sequence--the-autonomous-agentropix-sift-run-path) |
| **Manual** (you/the assistant drive each disk tool one at a time, inspecting output before the next step) | **Lane Manual-Expert.** Call each disk-image MCP tool yourself (`get_image_info` → `get_partitions` → `fls` → `extract_files` → execution-evidence). Read raw JSON inline. → [granular MCP chain](#sequence--the-granular-mcp-disk-chain) | **Lane Manual-User.** Ask the assistant one focused question per step ("what's the partition layout?", "list the deleted files"). → use the `💬` prompts in the [granular MCP chain](#sequence--the-granular-mcp-disk-chain) |

> ⚠️ **What a GOTCHA box is.** GOTCHA boxes below flag real-data quirks found during the proving run —
> a tool that needs a partition offset, a path the policy engine rejects. Each explains the snag for
> **both** audiences: the expert symptom and the plain-language fix.

---

## Use-case diagram

```mermaid
graph TD
    analyst([DFIR Analyst / Agent])
    examiner([Examiner])

    subgraph Agentropix-SIFT
        UC1["doctor: pre-flight the 16 SIFT binaries"]
        UC2["run: autonomous Trinity triage of E01"]
        UC3["MCP disk chain:<br/>get_image_info -> get_partitions -> fls<br/>-> extract_files -> exec-evidence"]
        UC4["evidence_register: chain-of-custody hash"]
        UC5["report sealed (HMAC-SHA256)"]
    end

    analyst --> UC1
    analyst --> UC2
    analyst --> UC3
    analyst --> UC4
    UC2 --> UC5
    UC3 -.feeds.-> UC4
    examiner -.verifies seal.-> UC5

    classDef actor fill:#d0bfff,stroke:#7048e8,color:#2b1a52
    classDef core fill:#b2f2bb,stroke:#2f9e44,color:#15391f
    classDef gov fill:#ffc9c9,stroke:#e03131,color:#5c1a1a
    classDef sink fill:#ffec99,stroke:#f08c00,color:#5c4400

    class analyst,examiner actor
    class UC1,UC2,UC3 core
    class UC4 gov
    class UC5 sink
    style Agentropix-SIFT fill:#f1f3f5,stroke:#868e96,color:#212529
```

> 🔍 **[Open as SVG — full size, zoomable](assets/uc-disk-triage-1.svg)** (renders larger than the page column; the SVG zooms losslessly in a browser tab).

The analyst pre-flights the toolchain (`doctor`), then chooses either the autonomous `run` command
or the granular MCP chain. Both bind evidence via `evidence_register` and converge on a sealed
report the examiner can later verify. The dashed `verifies seal` edge is the cross-link into
[uc-approval-gate.md](uc-approval-gate.md), where a human examiner reviews findings before they are
promoted out of DRAFT.

---

## Sequence — the autonomous `agentropix-sift run` path

```mermaid
sequenceDiagram
    autonumber
    actor Analyst
    participant CLI as agentropix-sift run (cli.py)
    participant Pre as preflight_evidence_symlink
    participant Orch as orchestrator.run_triage
    participant Thymus as ThymusEvidencePolicy
    participant Arch as Architect
    participant Swarm as SWARM (13 agents)
    participant Critic as Critic
    participant Court as courtroom.write_sealed_session

    Analyst->>CLI: agentropix-sift run base-dc-cdrive.E01 -o report.json
    CLI->>CLI: image.exists()? else Exit(1)
    CLI->>Pre: validate_evidence_fixture(image)
    Pre-->>CLI: ok / BadParameter (dangling symlink, W-164)
    CLI->>CLI: write .claude/active-triage.json sentinel
    CLI->>Orch: run_triage(image, max_iterations=5, config)
    Orch->>Thymus: configure_policy(extra_allowed=[image_dir])
    loop up to max_iterations (Trinity Loop)
        Orch->>Arch: plan(last_feedback, stable_agents)
        Arch-->>Orch: ordered SWARM slice
        loop each agent in plan
            Orch->>Swarm: agent.run(image) under trace_scope
            Swarm->>Thymus: check_read(path) per tool call
            Swarm-->>Orch: Finding[] + per-tool trace
        end
        Orch->>Critic: score(blackboard, planned_agents, iteration)
        Critic-->>Orch: TrinityResult(score, should_halt)
        Note over Critic: halt when score >= 0.85 OR fixed-point fingerprint
    end
    Orch->>Court: evidence_image_sha256(image)
    Orch-->>CLI: TriageReport (report_seal=None)
    CLI->>Court: write_sealed_session(report_dict, audit_entries, out)
    Court-->>CLI: {report, audit, key} paths
    CLI->>CLI: unlink sentinel (finally)
    CLI-->>Analyst: Findings / Tool calls / Status / Evidence SHA-256
```

> 🔍 **[Open as SVG — full size, zoomable](assets/uc-disk-triage-2.svg)** (renders larger than the page column; the SVG zooms losslessly in a browser tab).

Steps 1–5 are CLI guard rails: the file must exist, the evidence symlink must not be dangling
(`_load_preflight_validator`, `cli.py:19-41`; W-164 — a broken symlink silently collapses recall
from 7/7 to 4/7), and a `.claude/active-triage.json` sentinel is written so the Ralph-loop Stop hook
knows a triage is in flight (`cli.py:92-114`). The orchestrator then runs the Trinity Loop:
**Architect proposes → SWARM runs deterministic tools → Critic scores** (`orchestrator.py:146-269`).
The Critic halts on a deterministic convergence fingerprint or when the score crosses
`AGENTROPIX_CRITIC_HALT_THRESHOLD` (default **0.85**, `trinity/critic.py:42`) — **no LLM self-rating**.
Finally the CLI seals the report (`courtroom.write_sealed_session`, `cli.py:134-142`), writing three
files: `report.json`, `<stem>.audit-log.json`, and a mode-0600 session key.

### Drive the autonomous path — both audiences

> **🖥️ Expert (command):**
> ```bash
> agentropix-sift run <IMAGE> --max-iterations 5 --out report.json --verbose
> ```
> **💬 End-user (prompt):** *"Triage this disk image end to end with Agentropix and seal the report —
> run the full autonomous sequence, stage findings as DRAFT, and don't approve anything."*
> The session drives the same Trinity Loop (Architect plans → SWARM runs deterministic tools → Critic
> scores) and tells you when the sealed report is on disk. **One focused request is enough — the
> session recognises this as the autonomous triage capability and routes it.**

**Execution A → Output A.**

*Execution A:* `agentropix-sift run <IMAGE> --max-iterations 5 --out report.json --verbose`

*Output A (CFReDS validated):* the CLI prints **Findings**, **Tool calls**, **Status**, and the
**Evidence SHA-256** (`96bebe80f00541bf28fbc2ef0b02b580082ee6ad58837e991852ae66f077ec31`), then writes
three files next to `report.json`:

| Artefact | What it is |
|---|---|
| `report.json` | the `TriageReport` (validates against `schema/report.schema.json`) with `findings`, per-agent + per-tool `trace`, `thymus_audit`, `critic_score`, `completion_proofs`, and the `report_seal` |
| `report.audit-log.json` | the append-only audit entries (every Thymus read decision, every tool call) |
| `report.key` (mode `0600`) | the per-session key material for `verify_seal` |

The Critic halts on the deterministic convergence fingerprint or when the score crosses
`AGENTROPIX_CRITIC_HALT_THRESHOLD` (default **0.85**) — **no LLM self-rating**.

> ⚠️ **GOTCHA (preconditions):** `run` exits `1` if `<IMAGE>` does not exist, and raises `BadParameter`
> (W-164) if the evidence symlink is dangling — a broken symlink silently collapses recall from 7/7 to
> 4/7. Pre-flight with `agentropix-sift doctor` and confirm the image resolves before launching.
> *(End-user: the assistant verifies the image is readable first — that's the `get_image_info` check it
> runs before anything else.)*

---

## Sequence — the granular MCP disk chain

```mermaid
sequenceDiagram
    autonumber
    actor Agent
    participant MCP as FastMCP server
    participant Thymus as ThymusEvidencePolicy
    participant Case as case_lifecycle

    Agent->>MCP: get_image_info(image=base-dc-cdrive.E01)
    MCP->>Thymus: check_read(image)
    MCP-->>Agent: ewfinfo metadata (case_number, examiner, MD5/SHA1)
    Agent->>MCP: get_partitions(image)
    MCP-->>Agent: partition rows + filesystem_offsets (NTFS start sector)
    Agent->>Case: case_init(case_name, examiner_id, case_id)
    Case-->>Agent: case doc + ~/.agentropix/active_case pointer
    Agent->>Case: evidence_register(path, description, examiner_id)
    Case-->>Agent: SHA-256 + deterministic evidence_id
    Agent->>MCP: fls(image, offset=(NTFS sector), recursive=true, summary_only=true)
    MCP-->>Agent: entry_count (deleted_only=true -> T1070.004 surface)
    Agent->>MCP: extract_files(image, paths=[...], offset=(sector))
    MCP-->>Agent: manifest with per-file dest (+ file_sha256)
    Agent->>MCP: get_shimcache / get_amcache / get_prefetch (extracted hives)
    MCP-->>Agent: execution-evidence rows
    Agent->>MCP: run_hashdeep(extracted executables)
    MCP-->>Agent: IOC-candidate hashes
```

> 🔍 **[Open as SVG — full size, zoomable](assets/uc-disk-triage-3.svg)** (renders larger than the page column; the SVG zooms losslessly in a browser tab).

The **load-bearing ordering rule**: you must capture the NTFS start sector from `get_partitions`
(`filesystem_offsets`) and pass it as `offset` to `fls` and `extract_files`. Reading offset 0 lands
on the MBR and fails filesystem detection (NIST1 ISSUE-001; `docs/guides/playbooks.md` §A note).
Every read passes the **Thymus read-only policy** (`mcp_server/thymus_policy.py`) — the image's parent
directory is auto-allowed on first touch (`_auto_allow_parent`), and each access is audited.

### Drive the granular chain — tool by tool, both audiences

Each disk-image tool below is a **real MCP tool** from
[`tool-list.md`](../04-mcp-tools/tool-list.md) (verify the live arg schema with `tools/list`). Follow
either the `🖥️` command track or the `💬` prompt track — both hit the same deterministic tool.

**B.1 — Image metadata (`get_image_info`).** Confirm readability + capture the acquisition hash.

> **🖥️ Expert (MCP call):**
> ```text
> get_image_info { "image":"<IMAGE>" }
> ```
> **💬 End-user (prompt):** *"What does Agentropix report about this disk image — who acquired it, when,
> the media size, and its MD5?"*
> The session calls `get_image_info` (which drives `ewfinfo`) and summarises the acquisition metadata.

**Execution B → Output B.**

*Execution B:* `get_image_info { "image":"<IMAGE>" }`

*Output B (CFReDS validated, `ewfinfo 20140816`):* case_number `Greg Schardt`, examiner `Shane
Robinson`, acquisition_date `Wed Sep 22 14:06:04 2004`, OS `Windows XP`, format `EnCase 4`,
bytes/sector `512`, **media_size `4.5 GiB (4871301120 bytes)`**, **MD5
`aee4fcd9301c03b3b054623ca261959a`**.

**B.2 — Partition table (`get_partitions`).** Capture the NTFS **start sector** — the single most
load-bearing value in the chain.

> **🖥️ Expert (MCP call):**
> ```text
> get_partitions { "image":"<IMAGE>" }
> ```
> (CLI equivalent for an operator shell: `mmls <IMAGE>`.)
> **💬 End-user (prompt):** *"What's the partition layout of this image, and where does the NTFS
> partition start?"*
> The session calls `get_partitions` (mmls) and tells you the start sector — and carries that offset
> forward automatically when you later ask it to list or extract files.

**Execution C → Output C.**

*Execution C:* `get_partitions { "image":"<IMAGE>" }`

*Output C (CFReDS validated):* partition rows with `filesystem_offsets`; the **NTFS partition starts at
sector 63**. Quote this offset (`63`) as `offset` in every downstream `fls` / `extract_files` call.

> ⚠️ **GOTCHA (the load-bearing ordering rule):** reading `offset 0` lands on the MBR and fails
> filesystem detection with `Cannot determine file system type` (NIST1 ISSUE-001). Always pass the
> `get_partitions`-derived sector as `offset` to `fls` and `extract_files`. *(End-user: the assistant
> does this for you — that's why it checks the partition layout before listing files.)*

**B.3 — Chain of custody (`case_init` → `evidence_register`).** Open the case, then hash + bind the
image.

> **🖥️ Expert (MCP calls):**
> ```text
> case_init         { "case_name":"<CASE NAME>", "examiner_id":"<EXAMINER>", "scope":"<IMAGE>" }
> evidence_register { "path":"<IMAGE>", "description":"Windows disk (EWF/E01)", "examiner_id":"<EXAMINER>" }
> ```
> **💬 End-user (prompt):** *"Open a case for this disk image, then register it as evidence and give me
> its SHA-256 custody hash."*
> The session calls `case_init` (writing the active-case pointer) then `evidence_register`, and returns
> the deterministic evidence ID and SHA-256 bound to the active case.

**Execution D → Output D.**

*Execution D:* `case_init` then `evidence_register` (as above).

*Output D (CFReDS validated):*
- `case_init` → `case_id` `INC-2026-0529224443`, status `active`, pointer
  `~/.agentropix/active_case`.
- `evidence_register` → evidence **SHA-256
  `96bebe80f00541bf28fbc2ef0b02b580082ee6ad58837e991852ae66f077ec31`**, deterministic `evidence_id`
  (over case_id + path + sha256), `size_bytes 671094597`, `indexed:true`.

**B.4 — Filesystem walk (`fls`).** List entries including deleted, using the offset from B.2.

> **🖥️ Expert (MCP calls):**
> ```text
> fls { "image":"<IMAGE>", "offset":63, "recursive":true, "summary_only":true }
> fls { "image":"<IMAGE>", "offset":63, "recursive":true, "deleted_only":true }    # T1070.004 surface
> ```
> **💬 End-user (prompt):** *"List the files on this image, then show me just the deleted ones."*
> The session runs `fls` (live, then deleted-only) using the offset it found in B.2 and reports the
> counts plus notable entries.

**Execution E → Output E.**

*Execution E:* `fls` live (summary), then `fls` deleted-only (as above).

*Output E (CFReDS validated):*
- Live: `entry_count` **`12545`**. First entry `/Documents and Settings` (inode `3671-144-7`).
- Deleted-only: `entry_count` **`365`** — the `T1070.004` (Indicator Removal: File Deletion) surface.

**B.5 — Pull hives / artefacts (`extract_files`).** Extract the key hives to an allowlisted dir,
passing the same offset.

> **🖥️ Expert (MCP call):**
> ```text
> extract_files { "image":"<IMAGE>", "offset":63, "paths":["<hive paths>"], "dest":"<OUT_DIR>" }
> ```
> **💬 End-user (prompt):** *"Pull the registry hives off this disk image so we can analyse what was
> executed."*
> The session calls `extract_files` (TSK `ifind`+`icat`) into an allowlisted directory and returns the
> per-file manifest. (Omit `dest` and it auto-creates a tempdir under `/tmp/agentropix-sift-extract-*`.)

**Execution F → Output F.**

*Execution F:* `extract_files { "image":"<IMAGE>", "offset":63, "paths":[...], "dest":"<OUT_DIR>" }`

*Output F (validated shape):* a manifest with a per-file `dest` and `file_sha256` for each extracted
hive — these `dest` keys feed every registry / execution-evidence parser in B.6.

> ⚠️ **GOTCHA (Thymus allowlist):** `dest` / `<OUT_DIR>` MUST be under a Thymus-allowlisted prefix
> (`/tmp/agentropix-sift-*`, `/cases/`, `/mnt/`, `/media/`, `/evidence/`) or Thymus rejects it with
> `path not found`. *(End-user: the assistant picks an allowlisted location for you.)*

**B.6 — Execution evidence (`get_shimcache` / `get_amcache` / `get_prefetch`).** Parse the extracted
hives.

> **🖥️ Expert (MCP calls):**
> ```text
> get_shimcache { "hive":"<OUT_DIR>/SYSTEM" }     # AppCompatCache execution evidence
> get_amcache   { "hive":"<OUT_DIR>/Amcache.hve" }# Win7+ only (XP has none)
> get_prefetch  { "target":"<OUT_DIR>/Prefetch" } # XP-compatible
> ```
> **💬 End-user (prompt):** *"From the hives we pulled, tell me what programs were executed and when."*
> The session runs `get_shimcache` / `get_prefetch` (and `get_amcache` on Win7+) over the extracted
> artefacts and summarises the execution evidence — automatically skipping Amcache on an XP image.

**Execution G → Output G.**

*Execution G:* `get_shimcache` / `get_amcache` / `get_prefetch` over the B.5 artefacts.

*Output G (validated shape):* execution-evidence rows (program path, first/last execution). On the
CFReDS XP image, `get_amcache` is skipped (XP has no Amcache); `get_prefetch` and `get_shimcache`
return rows.

**B.7 — IOC-candidate hashing (`run_hashdeep`).** Hash the recovered executables; the hashes become IOC
candidates for promotion.

> **🖥️ Expert (MCP call):**
> ```text
> run_hashdeep { "target":"<OUT_DIR>" }
> ```
> **💬 End-user (prompt):** *"Hash the executables we recovered so we have IOC candidates to promote."*
> The session calls `run_hashdeep` and returns the multi-algorithm hashes — the IOC candidates that
> later flow into the Executable Artifact Registry and Wazuh.

**Execution H → Output H.**

*Execution H:* `run_hashdeep { "target":"<OUT_DIR>" }`

*Output H (validated shape):* multi-algorithm hashes (MD5 / SHA-256) per recovered executable — the
IOC-candidate set promoted via `promote_iocs` / the EAR and pushed to Wazuh
([uc-wazuh-push.md](uc-wazuh-push.md)).

---

## Actor, preconditions, steps, postconditions

**Actor:** DFIR analyst, or an MCP client agent (Claude Desktop / Claude Code) driving the server.

**Preconditions**

- The 16 SIFT forensic binaries are installed and resolvable — verify with `agentropix-sift doctor`
  (`cli.py:175-217`), which pre-flights `vol`, `log2timeline.py`, `fls`, `icat`, `mmls`, `ewfinfo`,
  `evtx_dump.py`, `yara`, `bulk_extractor`, `rip.pl`, `pf`, `amcache_parser`, `shimcache_parser`,
  `exiftool`, `foremost`, `hashdeep` (plus `ssdeep`, `strings`). Missing tools can be pointed at an
  alternative binary via the `AGENTROPIX_*_TOOL` overrides (`_DOCTOR_ENV_OVERRIDES`, `cli.py:160-172`).
- The E01 image exists and any evidence symlink resolves (no dangling target).
- Python 3.12+.

**Numbered steps (autonomous path)**

1. `agentropix-sift doctor` — confirm all 16 SIFT tools are present.
2. `agentropix-sift run base-dc-cdrive.E01 --max-iterations 5 --out report.json` — launch the
   Trinity Loop over the image.
3. The Architect plans the SWARM; each agent runs its deterministic tools through the Thymus boundary
   and publishes `Finding`s to the shared `Blackboard`.
4. The Critic scores each pass and halts on the deterministic fingerprint or threshold ≥ 0.85.
5. The CLI seals the report and writes `report.json`, `report.audit-log.json`, and the 0600
   session key.

**Numbered steps (granular MCP path)**

1. `get_image_info(image)` → confirm readability + acquisition hash.
2. `get_partitions(image)` → capture the NTFS start sector.
3. `case_init(...)` then `evidence_register(...)` → chain-of-custody.
4. `fls(image, offset=<sector>, ...)` → filesystem walk (including deleted files).
5. `extract_files(image, paths=[...], offset=<sector>)` → pull hives/artefacts.
6. `get_shimcache` / `get_amcache` / `get_prefetch` over the extracted hives → execution evidence.
7. `run_hashdeep(...)` → IOC-candidate hashes for promotion.

**Postconditions**

- A `TriageReport` (validating against `schema/report.schema.json`) with `findings`, a per-agent and
  per-tool `trace`, the `thymus_audit` log, the final `critic_score`, and `completion_proofs`.
- `evidence_image_sha256` binds the report to the exact bytes triaged (`orchestrator.py:292`).
- `report_seal` — an HMAC-SHA256 envelope over the canonicalised report, computed at write time so it
  covers the final on-disk document (`courtroom.py`; ADR-016/022). Tamper-evident: a single byte
  change breaks `verify_seal`.

**CLI commands used**

```bash
# 1. Pre-flight the 16 SIFT binaries
agentropix-sift doctor

# 2. Autonomous end-to-end triage (Trinity Loop), sealed report
agentropix-sift run /evidence/srl2018/base-dc-cdrive.E01 \
    --max-iterations 5 \
    --out report.json \
    --verbose

# 3. (Optional) mint a one-shot mutation token for any later live write
agentropix-sift evidence-gate mint   # -> egt_<ULID> into AGENTROPIX_MUTATION_TOKEN
```

---

## See also

- [uc-memory-triage.md](uc-memory-triage.md) — the Volatility memory-triage counterpart.
- [uc-approval-gate.md](uc-approval-gate.md) — promote DRAFT findings via examiner approval.
- [uc-wazuh-push.md](uc-wazuh-push.md) — push the resulting IOCs into Wazuh (optional integration).
- [`tool-list.md`](../04-mcp-tools/tool-list.md) — the full 72-tool catalogue and the 16 SIFT wrappers.
- [`agents-list.md`](../10-agents/agents-list.md) — the SWARM run order and per-agent tools.
- [agentic-architecture.md](../10-agents/agentic-architecture.md) — how the runtime swarm is wired (the Trinity Loop behind the autonomous path).

**Design rationale (ADRs).** Why this triage path is built the way it is:

- [ADR-011 — Evidence-Type Gate Consolidation](../11-ADR/ADR-011-evidence-gates.md) — why every data-fetching agent (including the filesystem walk) routes through one shared evidence-type helper rather than inline literals.
- [ADR-012 — `mcp_extract_files` (raw-E01 extraction)](../11-ADR/ADR-012-extract-files.md) — the genesis of the `extract_files` tool used in step B.5 (typed Pydantic I/O + Thymus dest validation).
- [ADR-013 — `mcp_get_evtx` wrapper](../11-ADR/ADR-013-evtx-wrapper.md) — the dual-format Windows Event Log wrapper behind the execution-evidence chain.
- [ADR-M6.3 — Plaso per-parser sampling + priority filter](../11-ADR/ADR-M6.3-event-window.md) — the timeline-wrapper decision that shapes downstream timelining.
- [ADR-016 — Courtroom Audit + Cryptographic Sealing](../11-ADR/ADR-016-courtroom-audit.md) and [ADR-022 — Audit-Log Seal](../11-ADR/ADR-022-audit-log-seal.md) — why the report and its audit log are HMAC-SHA256 sealed and cross-bound (the `report_seal` postcondition).

---

## Implementation proof (source)

> **For a software developer.** This section maps each use-case step to the **real code** in
> `/home/admin2/agentropix-sift/src` that implements it — file:symbol, trimmed signatures, and the
> call path. Every claim above is grounded here. Snippets are abridged (`…`); line numbers are from
> the oracle at the time of writing — treat the symbol name as the stable anchor.

### 1. The autonomous CLI entry point — `cli.py`

The `agentropix-sift run` command is a Typer command, `run()` in
`src/agentropix_sift/cli.py:50`:

```python
@app.command()
def run(
    image: Path = typer.Argument(...),
    max_iterations: int = typer.Option(5, "--max-iterations", "-n", ...),
    out: Path = typer.Option(Path("report.json"), "--out", "-o", ...),
    verbose: bool = typer.Option(False, "--verbose", "-v", ...),
) -> None:
```

The guard-rail / seal sequence the autonomous-path diagram shows (steps 1–5) is literally this body:

| Use-case step | Code path (`cli.py`) |
|---|---|
| `image.exists()? else Exit(1)` | `cli.py:58-60` — `if not image.exists(): raise typer.Exit(1)` |
| evidence-symlink pre-flight (W-164) | `_load_preflight_validator()` (`cli.py:19-41`) path-imports `scripts/preflight_evidence_symlink.py:validate_evidence_fixture`; a falsy `result["ok"]` raises `typer.BadParameter` (`cli.py:67-74`) with a `ln -sfn …` repair hint |
| `.claude/active-triage.json` sentinel | `cli.py:90-114` — writes `{image, required_promises, started_at}`; `_REQUIRED_PROMISES` is the 5-token Ralph-loop contract list (`cli.py:92-98`) |
| run the Trinity Loop | `cli.py:116-117` — `asyncio.run(run_triage(image, max_iterations=…, verbose=…, config=…))` inside `try:` |
| unlink sentinel (clean **and** error) | `cli.py:118-124` — `finally: sentinel_path.unlink(missing_ok=True)` |
| seal the report → 3 files | `cli.py:134-149` — `write_sealed_session(report_dict, audit_entries, out, …)` then echoes `report` / `audit` / `key` paths |

`doctor()` (`cli.py:175`) is the pre-flight for the 16 SIFT binaries: it iterates the `tools` dict
(`cli.py:178-197`, the exact binary names listed in the use case — `vol`, `log2timeline.py`, `fls`,
`icat`, `mmls`, `ewfinfo`, …, `hashdeep`), resolving each via `_DOCTOR_ENV_OVERRIDES`
(`cli.py:160-172`) → `os.environ.get(env_var, cmd)` → `shutil.which(...)`, and `raise typer.Exit(1)`
when any are missing (`cli.py:210-215`).

### 2. The Trinity Loop — `orchestrator.py:run_triage`

`run_triage()` (`src/agentropix_sift/orchestrator.py:82`) is the async heart of the autonomous path:

```python
async def run_triage(image, *, max_iterations=5, verbose=False,
                     swarm=SWARM, config=None, hippocampus=None) -> TriageReport:
    image_dir = str(image.resolve().parent) + "/"
    configure_policy(extra_allowed=[image_dir])          # arm Thymus for this image dir
    ...
    architect = Architect(); critic = Critic()
    for iteration in range(1, max_iterations + 1):
        plan = architect.plan(last_feedback, stable_agents=last_stable, prior_traces=…)  # Architect
        for agent_cls in plan:
            agent = agent_cls(blackboard)
            with trace_scope() as agent_buf:             # per-agent MCP tool trace (W-032)
                findings = await agent.run(image)         # SWARM runs deterministic tools
                if findings and agent.completion_promise:
                    completion_proofs.add(agent.completion_promise)   # M8.3d
        critic_result = critic.score(blackboard, planned_agents=plan_names, iteration=iteration)  # Critic
        ...
        if last_result.should_halt:
            break
    image_sha256 = evidence_image_sha256(image)           # bind report to bytes (M8.2b)
    report = TriageReport(image=…, findings=findings_dicts, ... evidence_image_sha256=image_sha256, ...)
```

Diagram-to-code map for the autonomous sequence:

| Sequence participant / message | Code path |
|---|---|
| `Orch->>Thymus: configure_policy(extra_allowed=[image_dir])` | `orchestrator.py:109-110`; `configure_policy` in `mcp_server/server.py:180-183` (rebuilds the global `_policy = ThymusEvidencePolicy(...)`) |
| `Orch->>Arch: plan(...)` → ordered SWARM slice | `orchestrator.py:157-166`; `trinity/architect.py:Architect.plan` |
| `Orch->>Swarm: agent.run(image)` under `trace_scope` | `orchestrator.py:175-211`; `agents/_base.py:SwarmAgent.run` (`_base.py:130`) → `investigate()` then `blackboard.publish` |
| `Swarm->>Thymus: check_read(path)` per tool | inside each MCP handler (see §3); e.g. `mcp_fls` calls `_policy.check_read(image)` (`server.py:756`) |
| `Orch->>Critic: score(...)` → `TrinityResult` | `orchestrator.py:229-233`; `trinity/critic.py:Critic.score` (`critic.py:94`) |
| halt at `>= 0.85` OR fixed-point fingerprint | `critic.py:192-200` — `elif score >= self.halt_threshold: should_halt = True` / `elif no_progress: should_halt = True`; threshold `_DEFAULT_HALT_THRESHOLD = 0.85` (`critic.py:42`), overridable via `AGENTROPIX_CRITIC_HALT_THRESHOLD` (`critic.py:77-78`) |
| `Orch->>Court: evidence_image_sha256(image)` | `orchestrator.py:292`; `courtroom.py:evidence_image_sha256` (`courtroom.py:89`) |
| returns `TriageReport` (seal `None`) | `orchestrator.py:294+`; `TriageReport` model `orchestrator.py:33`, `report_seal: str \| None = None` (`orchestrator.py:71`) — seal is filled by the CLI at write time |

The "no LLM self-rating" guarantee is structural: `Critic.score` computes the score from blackboard
**facts only** — `max_conf = max(f.confidence for _, f in entries)` plus a correlation bonus
(`critic.py:120-122`) — and the fixed-point halt comes from a deterministic fingerprint
`frozenset((agent, f.source, f.description, f.evidence) …)` compared to the prior pass
(`critic.py:128-130`). The W-083 coverage guard refuses to halt while a planned agent produced zero
findings (`critic.py:172-185`).

### 3. The granular MCP disk chain — `mcp_server/server.py` handlers + `wrappers/`

Each tool in the granular chain is a `@traced(...)`-decorated async handler in
`src/agentropix_sift/mcp_server/server.py` that (a) rate-limits, (b) runs `_policy.check_read(...)`,
then (c) delegates to a deterministic wrapper. The FastMCP surface registers them in
`mcp_server/fastmcp_app.py` (each `@app.tool()` forwards to the `mcp_*` handler — e.g.
`fastmcp_app.py:545` → `_inner.mcp_get_partitions(image)`).

| Use-case step (B.x) | MCP handler (`server.py`) | Deterministic wrapper (`wrappers/…`) | SIFT binary |
|---|---|---|---|
| B.1 `get_image_info` | `mcp_get_image_info(image)` `server.py:2143` | `ewf.get_image_info` `ewf.py:62` → `ImageInfo` (`ewf.py:21`) | `ewfinfo` |
| B.2 `get_partitions` | `mcp_get_partitions(image)` `server.py:774` | `tsk.get_partitions` `tsk.py:349` → `PartitionTable.filesystem_offsets` (`tsk.py:303`) | `mmls` |
| B.3 `case_init` | `mcp_case_init(...)` `server.py:987` | `case_lifecycle.case_init` `case_lifecycle.py:196` | — (writes `~/.agentropix/active_case`) |
| B.3 `evidence_register` | `mcp_evidence_register(...)` `server.py:1057` | `case_lifecycle.evidence_register` `case_lifecycle.py:431` | — (SHA-256 hash) |
| B.4 `fls` | `mcp_fls(image, offset, recursive, deleted_only, summary_only, …)` `server.py:730` | `tsk.fls` `tsk.py:111` → `FileListing` (`tsk.py:42`) | `fls` |
| B.5 `extract_files` | `mcp_extract_files(image, paths, dest, offset, …)` `server.py:2022` | `extract` (`extract.py`: `_run_ifind`/`icat`, `ExtractManifest` `extract.py:152`) | `ifind` + `icat` |
| B.6 `get_shimcache` | `mcp_get_shimcache(hive)` `server.py:1709` | `shimcache.get_shimcache` `shimcache.py:154` | `shimcache_parser` |
| B.6 `get_amcache` | `mcp_get_amcache(hive)` `server.py:1687` | `amcache` wrapper | `amcache_parser` |
| B.6 `get_prefetch` | `mcp_get_prefetch(target)` `server.py:854` | `prefetch` wrapper | `pf` |
| B.7 `run_hashdeep` | `mcp_run_hashdeep(target, algos, recursive, …)` `server.py:2348` | `hashdeep.run_hashdeep` `hashdeep.py:155` → `HashdeepReport` (`hashdeep.py:57`) | `hashdeep` |

The handler body is uniform — `mcp_fls` (`server.py:729`) is representative:

```python
@traced("fls")
async def mcp_fls(image, offset=0, inode=None, recursive=False,
                  deleted_only=False, fstype=None, summary_only=False):
    rate_err = _rate_limiter.check("fls")
    if rate_err: return ToolError(tool="fls", error=rate_err)
    violation = _policy.check_read(image)                 # Thymus read-only gate
    if violation: return ToolError(tool="fls", error=violation)
    try:
        return await tsk_fls(image, offset=offset, recursive=recursive,
                             deleted_only=deleted_only, summary_only=summary_only, ...)
    except (FileNotFoundError, RuntimeError, TimeoutError) as e:
        return ToolError(tool="fls", error=str(e))
```

**The load-bearing offset rule** (capture NTFS start sector from B.2, pass to `fls`/`extract_files`)
is real in the signatures: `mcp_get_partitions` returns a `PartitionTable` whose `filesystem_offsets`
field (`tsk.py:303-316`, parsed from `mmls` by `_parse_mmls_output` `tsk.py:318`) is the start sector,
and both `mcp_fls` (`server.py:732`, `offset: int = 0`) and `mcp_extract_files` (`server.py:2025`,
`offset: int = 0`) take that `offset` through to the TSK wrapper. The docstring on
`mcp_get_partitions` (`server.py:777-779`) states the contract explicitly ("start sectors to pass to
`fls(offset=...)` / `extract_files`").

### 4. Chain of custody — `case_lifecycle.py`

`case_init` (`case_lifecycle.py:196`) creates the `CaseRecord` (`case_lifecycle.py:74`), defaults the
id to `INC-YYYY-MMDDHHMMSS` via `_default_case_id` (`case_lifecycle.py:155`), and — the load-bearing
local effect — stamps the active-case pointer **first**: `_set_active_case_id(resolved_case_id)`
(`case_lifecycle.py:266`) writes `~/.agentropix/active_case` (`ACTIVE_CASE_FILE_NAME`,
`case_lifecycle.py:55`; `_active_case_path` `case_lifecycle.py:139`), then attempts the index write
under `try/except` so the pointer survives an indexer outage (SIFT-W-296c note, `case_lifecycle.py:258-266`).

`evidence_register` (`case_lifecycle.py:431`) is the chain-of-custody hash:

```python
digest, size = _sha256_file(target)                       # SHA-256 over the image bytes
evidence_id = hashlib.sha256(
    f"{case_id}\x00{target!s}\x00{digest}".encode("utf-8")
).hexdigest()                                             # deterministic over (case_id, path, sha256)
```

That maps Output D directly: `sha256` is the custody hash (`96bebe80…` in the CFReDS run),
`evidence_id` is the deterministic id, `size_bytes` comes from `_sha256_file` (`case_lifecycle.py:413`),
and re-registering the same file is idempotent within a UTC day (docstring `case_lifecycle.py:445-447`;
deterministic `_id` upsert, `case_lifecycle.py:504-505`).

### 5. The Thymus read-only boundary — `mcp_server/thymus_policy.py`

`ThymusEvidencePolicy` (`thymus_policy.py:59`) is the policy object every handler calls.
`check_read(path)` (`thymus_policy.py:236`) returns `None` (allow) or a `"Thymus REJECT: …"` string:
PATH_MAX bound (`thymus_policy.py:249`), raw-path `FORBIDDEN_PATTERNS` screen incl. `..`
(`thymus_policy.py:264-267`), canonicalisation (`thymus_policy.py:274`), broken/circular-symlink
rejection (`thymus_policy.py:289-295`) — this is the W-164 enforcement counterpart — then
`_auto_allow_parent(path)` (`thymus_policy.py:314`) and the allowed-prefix `startswith` check.

`_auto_allow_parent` (`thymus_policy.py:127`) is the "image's parent dir auto-allowed on first touch"
behaviour: for a recognised evidence extension it appends `str(p.resolve().parent) + "/"` to
`_allowed_prefixes` (`thymus_policy.py:149-150`), bounded by `_max_auto_prefixes`. The default
allowlist prefixes the GOTCHA boxes cite live at `thymus_policy.py:32-36` — `/cases/`, `/mnt/`,
`/media/`, `/evidence/`, `/tmp/agentropix-sift-` — extensible via
`AGENTROPIX_THYMUS_ALLOWED_PREFIXES` (`thymus_policy.py:93`). `extract_files` enforces the boundary on
**both** `image` and `dest` (`server.py:2050-2061`), which is why `<OUT_DIR>` must be allowlisted.

### 6. Sealing the report — `courtroom.py`

`write_sealed_session(report_dict, audit_entries, out_path, …)` (`courtroom.py:341`) is the function
`cli.py:142` calls. It performs the single-key flow the postconditions describe:

1. `write_session_key(out_path)` (`courtroom.py:185`) → 32 random bytes, written to
   `<stem>.session-key` at mode `0600` (`courtroom.py:195-201`).
2. seal the audit dict → `seal_audit_log` (`courtroom.py:269`); embed `audit_log_seal`.
3. **cross-bind** the audit seal into the report (`courtroom.py:387`) so a swapped audit file fails
   the report seal too.
4. `seal_report(report_dict, key)` (`courtroom.py:161`) = `hmac.new(key, _canonical_for_seal(...),
   hashlib.sha256).hexdigest()` over the canonicalised JSON (`sort_keys=True`,
   `separators=(",",":")`, `report_seal` blanked to `"__sealed__"` — `courtroom.py:145-158`); embed
   under `report_seal`; write `report.json`.
5. write `<stem>.audit-log.json`.

Returns `{"report": …, "key": …, "audit": …}` (`courtroom.py:363,397`) — the three artefacts in the
Output-A table. Tamper-evidence is `verify_seal` (`courtroom.py:173`): it recomputes the MAC and
`hmac.compare_digest`s it, so a single-byte change to the on-disk document fails verification (this is
the dashed `examiner verifies seal` edge into [uc-approval-gate.md](uc-approval-gate.md)).

### 7. The autonomous filesystem agent — `agents/filesystem.py`

The autonomous path's filesystem walk is `FilesystemAgent` (`agents/filesystem.py:65`),
`name = "filesystem"`, `completion_promise = "FILESYSTEM_WALKED"` (`filesystem.py:66-67`) — the exact
token the orchestrator collects into `completion_proofs` and the sentinel's `_REQUIRED_PROMISES`. Its
`investigate(image)` (`filesystem.py:69`) early-returns on non-disk images (`looks_like_disk`,
`filesystem.py:70-71`) then calls the **same** `mcp_fls` handler the granular chain uses
(`filesystem.py:112` — `await mcp_fls(str(image), recursive=fls_recursive)`), emitting deleted/
suspicious-name `Finding`s. This is the structural proof that "both surfaces hit the same
deterministic MCP tool": the autonomous SWARM and the manual chain both route through
`server.py:mcp_fls` → `tsk.py:fls`. `SwarmAgent.run` (`agents/_base.py:130`) then publishes those
findings to the `Blackboard`, which the Critic scores.
