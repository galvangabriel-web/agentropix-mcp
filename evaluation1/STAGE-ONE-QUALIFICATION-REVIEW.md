# Stage One Qualification Review — Find Evil! Hackathon (findevil.devpost.com)

**Reviewer role:** Stage One PASS/FAIL verification only (no scoring, no ranking)
**Review date:** 2026-06-12
**Submission inputs provided:**
- GitHub Repository URL: `https://github.com/galvangabriel-web/agentropix-mcp/`
- Devpost Project URL: **not provided**
- Demo Video URL: **not provided**

**Verification method:** all repository checks were performed against the **pushed state of
`main`** (commit `0a93e9c3c6a1b6430fa567f7796224b54926ed7e`, fetched 2026-06-12), with
unauthenticated HTTP probes to confirm public visibility. Video durations were measured with
`ffprobe` on the exact committed blobs. Raw command evidence: [`EVIDENCE-LOG.md`](EVIDENCE-LOG.md).

---

## 1 · Summary table

| # | Check | Status |
|---|-------|--------|
| 1 | Repository is public | ✅ PASS |
| 2 | Open source license (MIT or Apache 2.0) | ✅ PASS |
| 3 | README with setup instructions | ✅ PASS |
| 4 | Demo video (≤5 min, narrated terminal screencast) | ❌ **FAIL** |
| 5 | Architecture diagram | ✅ PASS |
| 6 | Written project description (Devpost story) | 🟡 NEEDS MANUAL REVIEW |
| 7 | Dataset documentation | ✅ PASS |
| 8 | Accuracy report | ✅ PASS |
| 9 | Try-it-out instructions | ✅ PASS |
| 10 | Agent execution logs | ✅ PASS |
| 11 | Disqualification screen | 🟡 One flag raised → NEEDS MANUAL REVIEW (flag only) |

## 2 · Overall verdict

### ❌ DOES NOT QUALIFY (as of this review)

One FAIL on checks 1–10 means elimination at Stage One. The failing check is:

- **CHECK 4 — Demo video.** No narrated ≤5-minute demo video link exists on a Devpost page or
  in the README. The repository's own judge-facing `EVALUATION-MAP.md` states this honestly:
  *"⚠️ Pending operator action: cut a ≤5-minute screencast **with audio narration** from this
  footage and upload to YouTube/Vimeo ≥48 h before the deadline. The committed MP4s are silent
  screen captures — narration is not yet recorded."*

Additionally, **CHECK 6 could not be verified** because no Devpost project URL was supplied.

Every other requirement (1–3, 5, 7–10) passes with directly quotable evidence. This submission
is one video upload and one Devpost page away from QUALIFIES.

---

## 3 · Detailed check results

### CHECK 1: Repository is public — ✅ PASS

- **EVIDENCE:** `https://github.com/galvangabriel-web/agentropix-mcp/` returns **HTTP 200**
  with no authentication (plain `curl`, no token, no cookies). The raw README and LICENSE also
  return HTTP 200 unauthenticated:
  - `https://raw.githubusercontent.com/galvangabriel-web/agentropix-mcp/main/README.md` → 200
  - `https://raw.githubusercontent.com/galvangabriel-web/agentropix-mcp/main/LICENSE` → 200
- The GitHub API confirms `"private": false`, default branch `main`.
- **Verified repository URL:** `https://github.com/galvangabriel-web/agentropix-mcp/`

### CHECK 2: Open source license (MIT or Apache 2.0) — ✅ PASS

- **EVIDENCE:** `LICENSE` file at the repository root —
  `https://github.com/galvangabriel-web/agentropix-mcp/blob/main/LICENSE` — first line reads
  **"MIT License"**, second line "Copyright (c) 2026 galvangabriel-web", followed by the full
  standard 21-line MIT text.
- **GitHub license detection:** the GitHub API reports `"license": { "spdx_id": "MIT",
  "name": "MIT License" }` — i.e. GitHub recognizes the file and displays the MIT badge in the
  repository's About section.
- **Direct URL:** `https://github.com/galvangabriel-web/agentropix-mcp/blob/main/LICENSE`

### CHECK 3: README with setup instructions — ✅ PASS

- **EVIDENCE:** `README.md` at the repository root contains real install-and-run instructions
  under two section headings (quoted exactly):
  - **`## ⚡ Connect in 60 seconds`** — client-side connection: Tailscale client install per OS,
    `claude mcp add` one-liner for Claude Code CLI (expected output shown), the `mcp-remote`
    shim config for Claude Desktop (with prerequisite "Node.js ≥ 18 on `PATH`
    (`node --version`)"), and a "✅ Smoke-test it" subsection.
  - **`## Installation / Quickstart`** — two documented paths with copy-paste commands:
    - *"**Path A — 60-second start (runs from this repo, today).**"* —
      `pip install https://github.com/galvangabriel-web/agentropix-mcp/releases/download/v0.2.2/agentropix_mcp-0.2.2-py3-none-any.whl`,
      then start the server (fail-closed without an auth token), then point Claude Code at it.
    - *"**Path B — self-host the full triage engine**"* — `uv sync` plus the `agentropix-sift`
      CLI (`doctor` / `run` / `review` / `approve` / `seal`).
  - Deeper links: `docs/01-overview/quickstart.md`, `docs/08-reference/cli-reference.md`,
    `docs/09-integrations/client-setup.md`, `docs/07-sdlc-ops/deployment.md`.

### CHECK 4: Demo video (5 minutes max) — ❌ FAIL

- **What exists:** the README and `EVALUATION-MAP.md` link substantial committed footage —
  e.g. `case-activation/runs/jimmy-wilson-poc/POC-RUN.mp4` (described as a "live terminal
  screencast of the full engine triage"), four recorded MCP activation-run MP4s, a 144-second
  animated "Submission Evidence Tour" (`assets/submission-tour/SUBMISSION-TOUR.mp4`, measured
  **144.08 s** ≤ 5 min), and two animated execution-log walkthroughs.
- **Why it FAILS — three independent grounds:**
  1. **The repo's own evidence map declares the requirement unmet.** `EVALUATION-MAP.md`,
     requirement row 2: *"⚠️ in-repo footage ready; YouTube/Vimeo upload pending"*, and §2:
     *"The committed MP4s are silent screen captures — narration is not yet recorded."* A
     narrated demo video link therefore does not exist anywhere.
  2. **No audio narration on any candidate file.** `ffprobe` on the committed
     `POC-RUN.mp4` blob shows a **video stream only — no audio stream**. The 144 s
     `SUBMISSION-TOUR.mp4` is an animated requirements deck, not a screencast of live terminal
     execution.
  3. **The flagship terminal screencast appears to be a broken stub.** The committed
     `POC-RUN.mp4` measures **9.25 seconds / 377 KB**, which cannot contain the full triage
     run it is described as showing ("`uv sync` → `doctor` → `run`, 129 findings · 86 tool
     calls"). It looks like a truncated/collided render that was committed by mistake.
- **Self-correction sequence:** the *material* is documented and ready —
  `EVALUATION-MAP.md` §2 specifies it precisely: *"iteration 1 runs all 13 agents, the Critic
  marks 11 **stable**, iterations 2–5 re-run only the 2 still producing new evidence"* — but it
  is not yet on a watchable narrated video.
- **IF FAIL — what is missing and how to fix:** record audio narration over a ≤5-minute cut of
  the existing terminal footage (including one on-screen self-correction sequence), upload it to
  YouTube/Vimeo, and link it from the README and the Devpost page.

### CHECK 5: Architecture diagram — ✅ PASS

- **EVIDENCE (file paths on `main`):**
  - Design document: `docs/02-architecture/main-architectural-agentropix-design.md`
  - Rendered diagram: `docs/02-architecture/assets/architecture-diagram/architecture-diagram.png`
    (plus `.svg` and `architecture-diagram-hd.pdf` in the same folder)
  - A second, simpler system diagram is embedded in the README's `## Architecture` section
    (`assets/readme-2.png` with editable Mermaid source inline).
- **Components connected:** the design doc walks "agent layer → MCP server → SIFT Workstation
  tools → data sources → output pipeline" as five numbered component sections (§1 The agent,
  §2 The SIFT Workstation tools, §3 The MCP server, §4 The data sources, §5 The output
  pipeline).
- **Architectural pattern identified:** §"Architectural pattern" states, quoted:
  **"Verdict: Custom MCP Server."** — and explicitly rules out the alternatives: *"It is
  **not** a Direct Agent Extension (no Claude-internal plugin code) and **not** an Alternative
  Agentic IDE (no editing environment)"*, with a hybrid note explaining why the in-process
  swarm is *"a deterministic multi-agent runtime, not an LLM Multi-Agent Framework."*
- **Prompt-based vs architectural guardrails distinguished:** §"Guardrails: prompt-based vs
  architectural" — quoted: *"an **ARCHITECTURAL** guardrail is enforced by code the model
  cannot reach around; a **PROMPT-BASED** guardrail is an instruction the model is expected —
  but not forced — to honor."* The diagram legend states: *"Two guardrail columns flank the
  flow: **ARCHITECTURAL** (green, solid border — enforced in code…) and **PROMPT-BASED**
  (amber, dashed border…)"*, each guardrail box naming the point it protects — i.e.
  security/trust boundaries are marked. A "Known gaps (honest negatives)" subsection is present.

### CHECK 6: Written project description (Devpost story) — 🟡 NEEDS MANUAL REVIEW

- **No Devpost project URL was provided**, so the live Devpost page could not be inspected.
  Do not infer its contents.
- **What the human reviewer should do:** open the Devpost project page and confirm all five
  story sections (What it does / How you built it / Challenges / What you learned / What's
  next) are substantively filled in — not boilerplate.
- **Repo-side note (not a substitute):** `EVALUATION-MAP.md` §4 contains a mapping table from
  each of the five Devpost story sections to committed source pages (e.g. *What's next* →
  `docs/02-architecture/PROJECT-ROADMAP-2026-06-11.md`), labelled *"✅ distributed across the
  portal (assembly guide below)"* — the material exists, but its presence **on Devpost** is
  unverified.

### CHECK 7: Dataset documentation — ✅ PASS

- **EVIDENCE (file paths + headings):**
  - **What data + its source:** `docs/06-use-cases/reproduce-datasets.md` — heading
    **"# Reproduce: get the evidence datasets"**; quoted preface: *"For each **publicly
    available** dataset it gives the real upstream download location… and an integrity anchor
    you can check after download. Datasets that **cannot be redistributed** (SANS course
    media, private hackathon evidence) are listed honestly as operator-host-only."* It states
    *"Every URL below was verified live (HTTP 200) on 2026-06-10."* `case-activation/INDEX.md`
    inventories 14 evidence sets (CFReDS, DFRWS 2005, SANS FOR500/FOR508, MemLabs, AMF…) with
    byte-exact sizes and custody hashes.
  - **What the agent found:** sealed case reports under `docs/12-CASES-REPORTS/`
    (`srl-2015-report/`, `srl-2018-report/`, `vanko-report/`) and per-run sealed reports under
    `case-activation/runs/` (e.g. `docs/12-CASES-REPORTS/srl-2018-report/submission/base-dc-report.json`).
  - **Ground truth:** committed fixtures in `docs/03-data/recall-ground-truth/`
    (`ground_truth_*.yaml`).

### CHECK 8: Accuracy report — ✅ PASS

- **EVIDENCE (all four required elements present, each with a file path):**
  - **Missed artifacts:** `docs/07-sdlc-ops/dataset-recall.md` ("# Evaluation Corpus & Recall
    Methodology") — disk recall 72/72 (100%), memory recall 108/118 (91.5%), with section
    **"## 5. The honest gap — SRL-2015 memory pool"** enumerating the 10 misses. Methodology in
    `docs/07-sdlc-ops/evaluation-scorecard.md`.
  - **False positives:** the VANKO case records 19 candidate findings of which **9 were refuted
    by the false-positive gate, 10 confirmed**; refuted hypotheses are kept as honest negatives
    in `docs/12-CASES-REPORTS/vanko-report/` (per `EVALUATION-MAP.md` §6 and the VANKO DFIR
    report).
  - **Hallucinated claims:** `docs/05-safety-forensics/anti-hallucination.md` plus the
    source-traced `docs/02-architecture/SECURITY-INVARIANT-AUDIT-2026-06-11.md` (6 invariants,
    file:line-cited, honestly scored "5 Enforced / 1 Partially").
  - **Evidence integrity (required section):** the invariant audit's §3 "Pre/Post SHA-256
    Evidence Invariant" and §4 "Thymus Read-Only Policy" document how the architecture prevents
    original data from being modified, and — critically — **each invariant carries an
    adversarial bypass case** describing what happens when the model ignores restrictions.
    Quoted from §4: *"**Adversarial:** `/cases/../etc/passwd` → `REJECT: forbidden pattern
    '..'`; … symlink `/cases/eviltunnel → /root/.ssh` → `REJECT_SYMLINK_TARGET_OUTSIDE_ALLOWLIST`;
    any write → `REJECT`."* And from §1: *"A hallucinated 'finding' in model prose never enters
    `report.findings` because that list is assembled in Python from Blackboard state, not from
    model output."* This is architectural enforcement, with live-run proof: 61 real `REJECT`
    decisions recorded in the committed
    `docs/12-CASES-REPORTS/srl-2018-report/submission/base-dc-thymus-audit.jsonl` (146 entries).
- *(Minor observation, not a warning: the accuracy material is distributed across several
  documents rather than one page; `EVALUATION-MAP.md` §6 is the assembly index that ties it
  together.)*

### CHECK 9: Try-it-out instructions — ✅ PASS

- **EVIDENCE:** local step-by-step run instructions with dependencies documented:
  - `README.md` → **"## Installation / Quickstart"** — Path A: pip-install the released wheel
    (release URL pinned), start the server, connect Claude Code; Path B: `uv sync` + the
    `agentropix-sift` CLI on a SIFT host. Python 3.12+ badge; deployment detail in
    `docs/07-sdlc-ops/deployment.md`; full client walkthrough in
    `docs/09-integrations/client-setup.md`.
  - A live deployment also exists (`http://100.85.162.82:8765/mcp` per README "Connect in 60
    seconds") — but it is **tailnet-only**, so a judge needs a Tailscale invite; the local-run
    path is the one that satisfies this check unconditionally.
- **Paths:** `README.md#installation--quickstart`, `docs/09-integrations/client-setup.md`.

### CHECK 10: Agent execution logs — ✅ PASS

- **EVIDENCE (log file paths on `main`):**
  - Gold report: `docs/12-CASES-REPORTS/srl-2018-report/submission/AGENT-EXECUTION-LOGS-REPORT.md`
  - Raw structured logs (same folder): `base-dc-report.json` (sealed report with a
    **176-entry timestamped `trace.tool_calls[]` sequence**), `base-dc-run.log`,
    `base-dc-thymus-audit.jsonl` (146 timestamped ALLOW/REJECT decisions),
    `base-dc-report.audit-log.json`, plus the parallel `notch-*` set; also
    `case-activation/runs/jimmy-wilson-poc/EXECUTION-LOG.md`.
  - **Multi-agent requirement (agent-to-agent messages):** report §3 *"Agent-to-Agent Message
    & Handoff Log (timestamped)"* defines handoff edges and verifies all 8 base-dc edges with
    both endpoints' timestamps ("zero UNVERIFIED").
  - **Iteration-over-iteration traces:** §2 documents per-iteration `stable_agents` /
    `dropped_agents` across the 5 Trinity iterations (the 13 → 2 plan shrink).
- **Spot-check performed (finding → log entry, verified in the committed files):** the report
  claims finding *"Cross-source agreement: 'evidence' flagged by 2 agents (artifact,
  t1546_008_accessibility_ifeo_hijack)"*. In the committed `base-dc-report.json`:
  `findings[15].description` matches exactly, timestamped `2026-06-11T15:56:32.095448+00:00`,
  `_source: "hunt.correlate"` — and the producing tool execution is `trace.tool_calls[151]`
  at `2026-06-11T15:56:32.095698+00:00` with `result_summary: "8 finding(s)"`. **Located. ✓**
- *Note on token usage:* the logs carry timestamps, durations, exit codes and args hashes; LLM
  token counts are not present because the swarm agents are explicitly LLM-free (deterministic) —
  documented in the architecture design doc. The applicable lane here is the multi-agent one
  (agent-to-agent logs), which is satisfied.

### CHECK 11: Disqualification screen — 🟡 flags below (humans decide)

- **(a) Thin LLM wrapper?** **No flag.** The engine is a deterministic multi-agent loop
  (Architect/Swarm/Critic over a quorum blackboard) with 176 logged tool executions per run and
  a closed-form halt rule — quoted from the README: *"never on an LLM's self-assessed
  confidence."* This is the opposite of pass-through prompting.
- **(b) No real case data?** **No flag.** Real public datasets (CFReDS, DFRWS 2005, MemLabs,
  SANS course images) with upstream URLs, custody hashes, sealed run outputs and ground-truth
  fixtures are committed.
- **(c) Proprietary-tool dependence?** **One flag — NEEDS MANUAL REVIEW.** The advertised
  "Connect in 60 seconds" live server is **tailnet-only** (`http://100.85.162.82:8765/mcp`
  reachable only after a Tailscale invite from the operator), so a judge cannot use that path
  unassisted. Quoted from README: *"Already have a SIFT host running on our tailnet? Point
  Claude at it right now."* **Mitigation in-repo:** the local install path (Check 9) uses only
  open-source components (FastMCP server wheel, Volatility3, Plaso, Sleuth Kit, YARA), and the
  evidence images are publicly downloadable — a judge can reproduce without the tailnet. A human
  should confirm the judges' access path (tailnet invite or local install) is acceptable.

---

## 4 · FIX LIST

1. **(CHECK 4 — blocking)** Record audio narration and cut a **≤5-minute** screencast from the
   existing terminal footage, showing live terminal execution end-to-end and including **one
   on-screen self-correction sequence** (the documented one: iteration 1 runs all 13 agents,
   the Critic marks 11 stable, iterations 2–5 re-run only the remaining 2). Upload to
   YouTube/Vimeo and put the link prominently in `README.md` and on the Devpost page.
2. **(CHECK 4 — blocking)** Replace the committed
   `case-activation/runs/jimmy-wilson-poc/POC-RUN.mp4`: the blob on `main` is a **9.25-second,
   377 KB, silent** file that cannot contain the full triage run its README describes — it
   appears to be a truncated/collided render. Re-render, `ffprobe`-verify the duration, and
   re-commit.
3. **(CHECK 6)** Create/complete the **Devpost project page** with all five story sections
   substantively filled in — the content is already mapped section-by-section in
   `EVALUATION-MAP.md` §4 (What it does / How you built it / Challenges / What you learned /
   What's next); paste/adapt from those pages. Add the architecture diagram PNG
   (`docs/02-architecture/assets/architecture-diagram/architecture-diagram.png`) to the Devpost
   image gallery and the demo video link from item 1.
4. **(CHECK 11c — warning)** On the Devpost page and in the README, state explicitly which
   try-it-out path judges should use: either offer a tailnet invite for the live server, or
   point judges to the local wheel-install path (Path A) as the canonical no-assistance route.
5. **(CHECK 10 — minor hardening)** Add one line to the execution-logs report stating that LLM
   token counts are intentionally absent because the swarm agents are LLM-free, with a pointer
   to the architecture doc — pre-empting a reviewer reading the single-agent rubric line.

---

*Stage One is pass/fail only. This review makes no statement about project quality or expected
scoring. All evidence above was gathered from the public repository state on 2026-06-12; raw
commands and outputs are in [`EVIDENCE-LOG.md`](EVIDENCE-LOG.md).*
