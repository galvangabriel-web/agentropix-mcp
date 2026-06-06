# Competitive positioning

> **Section 01 · Overview** — How Agentropix-SIFT differs from the DFIR + AI field, why
> those differences are *structural* rather than marketing, and where it honestly loses.
> Related: [What is Agentropix-SIFT?](what-is-agentropix.md) ·
> [What You Get](what-you-get.md) · [Quickstart](quickstart.md)

The first question a SANS judge asks is blunt: **"how is this different from
Velociraptor plus an LLM?"** The upstream
`agentropix-sift/docs/COMPETITIVE-DFIR.md` answers it directly, and this page mirrors that answer with the
counts reconciled to the portal's [canonical facts](../../.crew/facts.md). The short
version: the differentiators are **capability absences and deterministic control points**
— things a competitor cannot bolt on with a prompt — not feature-list length.

---

## Executive framing: old reality → new reality

The project is positioned against the **manual-triage status quo**, not just other tools.
Both framings below are quoted from the upstream big-picture report
(`PROJECT-ONBOARDING.md` / `DEMO-SCRIPT.md`, via `PROJECT-DESCRIPTION.md`):

| | The user's **old reality** | The user's **new reality** |
|--|----------------------------|-----------------------------|
| **Workflow** | Incident responders arrive at hour-3 of a breach with a stack of `.E01` images and a menu of CLI tools (plaso, Volatility 3, Sleuth Kit, RegRipper). They must extract artefacts, correlate across sources, and write a report — **without mutating evidence** — under a clock. | One command ingests the image; a deterministic loop drives the same trusted binaries, correlates across a 7-agent swarm, and emits a sealed JSON report. |
| **Time** | 4–8 hours per disk image, ×N hosts | "What used to be 4 hours of manual cross-correlation is 3 minutes of agentic triage." |
| **Trust** | "I ran a yara scan, got a hit, I think." (hand-kept notes) | Every finding carries `_source` → a tool call → an `args_hash`; the report is HMAC-sealed and **verifiable in court**. |

> The architecture exists to make the second sentence honest — *verifiable*, not merely
> *fast*. (`PROJECT-DESCRIPTION.md` §10)

---

## The unique angle

Agentropix-SIFT is the first DFIR-specific agentic system that unifies four properties,
each enforced in code (per `COMPETITIVE-DFIR.md` and `DESIGN-DECISIONS.md` §5):

1. **Real SANS SIFT toolkit as MCP** — the forensic binaries examiners already trust,
   exposed as uniformly-typed, uniformly-gated `mcp_*` tools (**16 SIFT forensic
   wrappers** on the **71-tool MCP surface**; see the count reconciliation below).
2. **Structural evidence safety** — no write tool exists; the agent cannot mutate
   evidence because there is no verb to call. The **Thymus** read-only policy rejects
   every write before any subprocess spawns.
3. **Multi-agent orchestration with deterministic halt** — a pure-Python
   Architect → Swarm → Critic loop whose termination is a fingerprint no-progress
   detector, with **no LLM in the halt path**.
4. **Cryptographically sealed chain-of-custody** — per-run HMAC-SHA256 report seal +
   independently-sealed audit log cross-bound into the report + evidence-image SHA-256
   anchor.

---

## Feature matrix vs the field

Imported from the oracle's `docs/COMPETITIVE-DFIR.md` feature matrix (2026-04-22), with
the SIFT-binary count rendered as **16 forensic wrappers**, the agent count as **7 core
specialists**, and the MCP surface as **71 tools** to match
[`.crew/facts.md`](../../.crew/facts.md) and `src/agentropix_sift/agents/__init__.py`.

| Capability | Agentropix-SIFT | Velociraptor + LLM | Autopsy + AI plugin | TheHive / Cortex | CADO Response | Magnet AXIOM Copilot |
|---|---|---|---|---|---|---|
| **Integration substrate** | **MCP** — 16 forensic wrappers on a **71-tool** `mcp_*` surface, uniform typing + gating | ad-hoc shell-out / VQL | ad-hoc plugin API | ticket / workflow bus | proprietary cloud API | proprietary desktop plugin |
| **Real SANS SIFT toolkit** | plaso, vol3, tsk, regripper, amcache, shimcache, evtx, yara, bulk_extractor, prefetch, extract_files, foremost, hashdeep, strings, ewfinfo, exiftool (**16 wrappers**) | VQL artifacts + shell-outs | Autopsy module subset | no native DFIR tools | proprietary carving | AXIOM artifact subset |
| **Evidence write-protection** | **structural — agents have no write tool**; Thymus gates every read | relies on VQL being read-only + operator discipline | Autopsy case-locking | N/A (no evidence access) | cloud-isolated snapshot | snapshotted case file |
| **Chain-of-custody** | SHA-256 of source image + per-tool audit trail, HMAC-sealed | artifact upload hash | Autopsy case hash | attachment hash | cloud-signed snapshot | AXIOM case hash |
| **Multi-agent orchestration** | **7 core specialists** + ATT&CK detectors, Trinity loop (Architect → Swarm → Critic) | single LLM over VQL output | single LLM over module output | no | "AI investigator" (opaque) | single LLM summariser |
| **Deterministic halt** | fingerprint no-progress detector — **no LLM in halt path** | LLM-terminated | N/A | N/A | vendor-defined | vendor-defined |
| **Budgeted execution** | per-tool timeout + RSS cap + rate limit | operator-enforced | operator-enforced | N/A | vendor-defined | vendor-defined |
| **Chaos-tested cleanup** | **14 chaos tests** (timeout-kill, EWF mount, fusermount rc=1, killpg race, tmpdir leak) | N/A | N/A | N/A | vendor-closed | vendor-closed |
| **Real-E01 validation** | **7 SRL-2018 APT images** (incl. case 20180905-001 Cobalt Strike DC, 2026-04-19 wargame) | lab demos | vendor demos | N/A | vendor case studies | vendor case studies |
| **Open source** | **yes** (MIT) | yes (GPL) | yes (ASL-2) | yes (Hive/Cortex), no (AXIOM) | **no** | **no** |

> **Count reconciliation.** The oracle competitive doc frames the toolkit as "16 / 16"
> and the swarm as a "5-agent swarm." This portal pins the canonical numbers:
> **16 forensic wrappers** drive the 16 SIFT binaries (`.crew/facts.md`; `README.md:151`;
> `cli.py` `doctor` tool dict); the **71-tool MCP surface** is the full `tools/list`
> (`.crew/facts.md`, `mcp_tool_count = 71`); and the swarm is **7 core specialists**
> (Memory, Timeline, Filesystem, Artifact, Discovery, Mail, Hunt) interleaved with six
> deterministic ATT&CK detector agents in the runnable `SWARM` tuple
> (`src/agentropix_sift/agents/__init__.py`). The "5-agent" framing predates the
> Discovery (issue #39) and Mail specialists; **7 core specialists** is the current
> code-derived count.

```mermaid
flowchart LR
    subgraph FIELD["The field — LLM is in the trust path"]
        V["Velociraptor + LLM<br/>LLM reads VQL JSON"]
        A["Autopsy + AI plugin<br/>LLM reads module output"]
        C["CADO / AXIOM<br/>vendor-defined LLM summariser"]
    end
    subgraph OURS["Agentropix-SIFT — LLM only orchestrates"]
        ORCH["LLM proposes next step"]
        DET["Deterministic Python disposes<br/>plan · score · halt-fingerprint"]
        TOOLS["16 forensic wrappers<br/>71-tool MCP surface · Thymus-gated"]
        SEAL["HMAC-SHA256 seal<br/>+ SHA-256 evidence anchor"]
    end

    V -->|"post-hoc: read my JSON"| OUT1["prose summary"]
    A -->|"post-hoc"| OUT1
    C -->|"vendor loop"| OUT1
    ORCH --> DET
    DET --> TOOLS
    TOOLS --> DET
    DET --> SEAL
    SEAL --> OUT2["sealed, replayable TriageReport"]

    classDef field fill:#ffc9c9,stroke:#e03131,color:#5c1a1a
    classDef ours fill:#b2f2bb,stroke:#2f9e44,color:#15391f
    classDef sink fill:#ffec99,stroke:#f08c00,color:#5c4400
    class V,A,C field
    class ORCH,DET,TOOLS,SEAL ours
    class OUT1,OUT2 sink
```

---

## Four positioning statements

Imported verbatim-in-substance from `COMPETITIVE-DFIR.md` §"Four positioning statements"
and `DESIGN-DECISIONS.md` §5:

1. **"We pick up where VQL-on-Velociraptor stops."** Velociraptor is best-in-class for
   agent-side collection, but the LLM step is still *"read my JSON and explain it."*
   Agentropix-SIFT drives *real DFIR tools* — plaso, Volatility, YARA — **inside** an
   agent loop, not after it.

2. **"Structural evidence safety is the moat."** Autopsy case-locking and CADO snapshots
   protect the artifact; they don't prevent an agent from overwriting an `.E01` if the
   operator exposes a write API. **We don't expose one.** The Thymus policy refuses every
   write call before the subprocess is spawned — **7 `REJECT_WRITE` events** were logged
   against real APT images in the 2026-04-19 wargame (`SIFT-WEAKNESSES.md` wargame entry,
   2026-04-19 22:49 UTC).

3. **"Deterministic halt beats LLM-terminated loops."** LLM-driven orchestrators burn
   budget deciding when to stop. The Critic halts on a fingerprint no-progress detector —
   same input, same output, same iteration count. Operators tune budget with
   `AGENTROPIX_*` env vars instead of a prompt (`trinity/critic.py`).

4. **"MCP is the integration substrate judges haven't seen elsewhere."** Every DFIR tool
   is exposed as an `mcp_*` tool with uniform typing and gating. The plug-in pipeline is
   proven end-to-end — **16 wrappers shipped**, each a ~60-line Python file with a single
   Thymus-gated subprocess call, not a plugin SDK download.

---

## Where we honestly lose

The project names its losses explicitly — these are deliberate non-goals, not gaps
(`COMPETITIVE-DFIR.md` §"Honest where we lose"; deferred list in
`docs/REVIEW-2026-04-20.md` §3):

- **Commercial-grade case management.** We don't replace AXIOM or CADO for analyst UX.
  We're a **triage engine, not a case file system**.
- **Windows-host collection.** Velociraptor's agent ecosystem is deeper. We **read-only
  consume** whatever you've already collected — we don't deploy a collection agent.
- **Polished reporting UI.** Our output is JSON + ledger. Autopsy and AXIOM ship HTML
  report generators with embedded charts; we don't.

---

## Six explicit non-goals

To prevent scope confusion, the project states its non-goals up front
(`PROJECT-DESCRIPTION.md` §7):

1. **Not a GUI / dashboard.** CLI + JSON output is the primary interface.
2. **Not a training tool.** It automates what an analyst already knows; it doesn't teach
   DFIR.
3. **Not real-time monitoring.** This is **post-incident triage on captured evidence** —
   not EDR, not XDR.
4. **Not a fine-tuning platform.** Existing Claude models are orchestrated; no model
   training.
5. **Not attacker-facing.** The agent is read-only by design — no remediation, no
   process-kill, no file-delete. Active Response is a separate, deferred tier (ADR-021).
6. **Not "give me the answer."** The analyst still reads, interprets, and contextualizes
   the findings; the system accelerates the legwork, not the thinking.

---

## Where to go next

- **[What is Agentropix-SIFT?](what-is-agentropix.md)** — the problem, the pipeline, and
  the LLM-only-vs-Agentropix contrast table.
- **[What You Get](what-you-get.md)** — the full capability matrix (Trinity loop, 71 MCP
  tools, 16 forensic wrappers, Thymus, Courtroom seal, chaos tests, recall gates).
- **[Quickstart](quickstart.md)** — install, `doctor` pre-flight, and a first triage run.
