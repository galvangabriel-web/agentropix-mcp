# Stage One Qualification Review — Find Evil! Hackathon (findevil.devpost.com)

**Reviewer role:** PASS/FAIL verification against Official Rules' Submission & Project Requirements. No quality scoring, no ranking.
**Review date:** 2026-06-12 (UTC)
**Target provided:** `https://galvangabriel-web.github.io/agentropix-mcp/` (the only link supplied — no Devpost URL, no demo-video URL given)
**Repository resolved from target:** `https://github.com/galvangabriel-web/agentropix-mcp` (public, HTTP 200, verified unauthenticated)
**Raw evidence captured at review time:** see [`evidence/`](evidence/) in this folder (repo tree, commit list pages 1–2, README, EVALUATION-MAP, architecture-diagram source).

> ⚠️ **Entry-link note:** the URL supplied for evaluation — the GitHub Pages **root** — returns **HTTP 404**
> (verified by direct fetch; `https://galvangabriel-web.github.io/agentropix-mcp/` → 404; `index.html` → 404).
> The Pages *site itself works*: deep links such as
> `https://galvangabriel-web.github.io/agentropix-mcp/assets/submission-tour/watch-tour.html` and
> `…/docs/12-CASES-REPORTS/srl-2018-report/submission/watch.html` return HTTP 200. The repo has no root
> `index.html`, so the site root 404s. All checks below were run against the underlying public repository.

---

## 1. Summary table

| # | Check | Status |
|---|---|---|
| 1 | Repository is public | **PASS** (warning: the supplied Pages root URL 404s) |
| 2 | Open source license (MIT or Apache 2.0) | **PASS** |
| 3 | README with setup instructions | **PASS** |
| 4 | Demo video | **FAIL** (as of 2026-06-12) |
| 5 | Architecture diagram | **PASS** |
| 6 | Text description (Devpost) | **NEEDS MANUAL REVIEW** |
| 7 | Evidence dataset documentation | **PASS** |
| 8 | Accuracy report | **PASS** |
| 9 | Try-it-out access | **PASS** (warning on the live-deployment lane) |
| 10 | Agent execution logs | **PASS** (warning: token usage documented as a gap) |
| 11 | Project requirements screen | Appears demonstrated on all three capabilities; SIFT + Claude Code confirmed |
| 12 | Viability & integrity flags | 4 observations flagged NEEDS MANUAL REVIEW (no FAIL — flags only) |

## 2. Overall verdict

### DOES NOT QUALIFY (as of review date 2026-06-12)

- **Check 4 — Demo video: FAIL.** No publicly hosted YouTube/Vimeo/Youku demo video exists. The
  repository's own `EVALUATION-MAP.md` states: *"⚠️ in-repo footage ready; YouTube/Vimeo upload
  pending"* and *"The committed MP4s are silent screen captures — narration is not yet recorded."*
- **Check 6 — Devpost text description: NEEDS MANUAL REVIEW** (no Devpost project page URL was
  provided or discoverable from the repo; if no Devpost page exists by the deadline this becomes a FAIL).

Every other rule-mandated artifact (checks 1–3, 5, 7–10) **passes with direct evidence**. The two open
items are submission-mechanics, not engineering: the submission period runs through **June 15, 2026**,
so both are still fixable. Checks 11 and 12 produce no FAILs by definition; their flags are listed for
organizer follow-up. Disqualification decisions belong to the Sponsor under the Official Rules.

---

## 3. Detailed check results

### CHECK 1: Repository is public — **PASS**

- **EVIDENCE:** `https://github.com/galvangabriel-web/agentropix-mcp` fetched unauthenticated →
  HTTP 200. GitHub API confirms `"private": false`. Repo contains source
  (`agentropix_mcp/` — pip-installable src-layout package with `pyproject.toml`), assets, docs,
  case data, and run logs: 794 tracked paths (full tree in `evidence/agx_tree.json`).
- **Warning:** the *supplied* link `https://galvangabriel-web.github.io/agentropix-mcp/` returns
  HTTP 404 at the root (no root `index.html`; deep links under the same Pages site return 200).
  If that Pages root URL is what gets pasted into the Devpost form, judges will land on a 404.

### CHECK 2: Open source license — **PASS**

- **EVIDENCE:** `https://github.com/galvangabriel-web/agentropix-mcp/blob/main/LICENSE` — first line
  reads **"MIT License"**, second line "Copyright (c) 2026 galvangabriel-web", followed by the standard
  MIT grant ("Permission is hereby granted, free of charge…").
- **About-badge detection:** GitHub's API reports `"license": {"spdx_id": "MIT", "name": "MIT License"}`
  — i.e., GitHub machine-recognizes the file, which is exactly what drives the About-section badge.
  Detectable and visible: confirmed.

### CHECK 3: README with setup instructions — **PASS**

- **EVIDENCE:** `https://github.com/galvangabriel-web/agentropix-mcp/blob/main/README.md` (878 lines).
  Setup-bearing section headings (quoted from the file):
  - **"## ⚡ Connect in 60 seconds"** — client connection for Claude Code CLI (`claude mcp add --transport http …`) and Claude Desktop (`mcp-remote` shim, per-OS config paths).
  - **"## Installation / Quickstart"** — *Path A*: 3 commands (`pip install <released wheel>` → `AGENTROPIX_MCP_AUTH_TOKEN=… agentropix-mcp --transport http --port 8765` → `claude mcp add …`); *Path B*: full engine (`uv sync` → `uv run agentropix-sift doctor` → `uv run agentropix-sift run <image> -o report.json`).
  - **"### Deployment & requirements"** — prerequisites table: Python 3.12+, SANS SIFT Workstation host, the 16 forensic binaries on PATH, graceful-degradation note.
- Prerequisites, installation, and run instructions are all present. The referenced release wheel
  exists publicly (GitHub Releases: v0.3.0 published 2026-06-10, assets
  `agentropix_mcp-0.3.0-py3-none-any.whl` + `.tar.gz`; v0.2.2 likewise).

### CHECK 4: Demo video — **FAIL**

- **EVIDENCE OF ABSENCE:** No Devpost page URL was provided. No YouTube/Vimeo/Youku link exists
  anywhere in `README.md` or `EVALUATION-MAP.md` (all external links extracted and checked — the only
  video links are GitHub-Pages-hosted in-repo players). The repo's own requirement map,
  `EVALUATION-MAP.md` §2, states verbatim:
  > "⚠️ **Pending operator action:** cut a ≤5-minute screencast **with audio narration** from this
  > footage and upload to YouTube/Vimeo ≥48 h before the deadline. The committed MP4s are silent
  > screen captures — narration is not yet recorded."
- **What does exist (raw footage, not a compliant demo video):** in-repo MP4s/GIFs incl.
  `case-activation/runs/jimmy-wilson-poc/POC-RUN.mp4` (live terminal screencast of the full engine
  triage, contains the self-correction sequence per `EXECUTION-LOG.md`), the 144 s "Submission
  Evidence Tour" (`assets/submission-tour/`, plays at the Pages link, HTTP 200 verified), and a ~9-min
  narrated-by-slides VANKO walkthrough. None is hosted on an allowed platform and none has audio narration.
- **MISSING / FIX:** record audio narration over a ≤5-minute live-terminal cut (the self-correction
  iteration trace is already identified and on film in `POC-RUN.mp4`), upload to YouTube or Vimeo as
  public/unlisted, and link it on the Devpost page before June 15, 2026.

### CHECK 5: Architecture diagram — **PASS**

- **EVIDENCE:** `docs/02-architecture/assets/architecture-diagram/` contains `architecture-diagram.png`,
  `.svg`, `.pdf`, and `architecture-diagram-hd.pdf`, with narrative page
  `docs/02-architecture/main-architectural-agentropix-design.md`. The committed Mermaid source
  (`architecture-diagram.mmd`, captured in `evidence/agx_arch.mmd`) shows all five required element types:
  1. **Agent:** node `AGENT` — "Agent layer — the LLM consumers / Claude Code CLI · Claude Desktop".
  2. **SIFT tools:** subgraph `TL` "Forensic tool layer — SIFT Workstation" with "16 SIFT binaries + EZ-Tools / vol3 · plaso · tsk (fls/mmls/icat) · libewf · yara · bulk_extractor · RegRipper…".
  3. **MCP server:** subgraph `MCP` "MCP server core — the enforcement spine · pattern: CUSTOM MCP SERVER" (FastMCP app, 71 canonical tools).
  4. **Evidence sources:** node `EVID` "Evidence — read-only / /cases E01 disk images · memory dumps · triage archives · YARA rule packs".
  5. **Output pipeline:** subgraph `OUT` "Output pipeline — findings to courtroom" (report_generate/report_export HMAC-sealed, Wazuh SIEM push).
- **Trust boundaries are marked:** node `AUTH` "Transport + auth boundary … Bearer token, constant-time
  compare · fail-closed boot", plus an explicit guardrail split — `GA` "ARCHITECTURAL guardrails —
  enforced in code" vs `GP` "PROMPT-BASED guardrails — conventions". No warning needed.

### CHECK 6: Text description — **NEEDS MANUAL REVIEW**

- **EVIDENCE:** No Devpost project page URL was supplied, and none is linked from the repository.
  `EVALUATION-MAP.md` §4 ("Written project description (Devpost story)") marks the requirement
  "✅ distributed across the portal (assembly guide below)" — i.e., the *source material* for the
  Devpost story exists as repo pages (What-it-does / How-we-built-it / Challenges / What-we-learned /
  What's-next, each mapped to a committed doc), but the Devpost page itself has not been shown to exist.
- **WHAT THE HUMAN SHOULD CHECK:** open the team's Devpost submission (once submitted) and confirm the
  story field contains substantive feature/functionality text — the assembly guide in
  `EVALUATION-MAP.md` §4 indicates it will. If no Devpost page exists at the deadline, this is a FAIL.

### CHECK 7: Evidence dataset documentation — **PASS**

- **EVIDENCE:** `docs/06-use-cases/reproduce-datasets.md` — heading **"# Reproduce: get the evidence
  datasets"**. Names the test data with sources and integrity anchors, e.g. §1.1 *"CFReDS 'Hacking Case'
  (Greg Schardt / 'Mr. Evil') — NIST"* with publisher (NIST CFReDS), live-verified download URLs
  (`https://cfreds-archive.nist.gov/Hacking_Case.html`), and the EWF stored MD5
  `aee4fcd9301c03b3b054623ca261959a`. `EVALUATION-MAP.md` §5 inventories **14 documented evidence sets**
  (CFReDS, DFRWS 2005, SANS FOR500/FOR508, MemLabs, AMF…) via `case-activation/INDEX.md`; non-redistributable
  sets (SANS course media) are "listed honestly as operator-host-only".
- **What the agent found:** sealed case reports under `docs/12-CASES-REPORTS/` (SRL-2015, SRL-2018, VANKO)
  plus per-run sealed `report.json` records under `case-activation/runs/`.

### CHECK 8: Accuracy report — **PASS**

- **EVIDENCE:** all three required dimensions are addressed with specifics:
  - **Missed artifacts:** `docs/07-sdlc-ops/dataset-recall.md` ("Evaluation Corpus & Recall Methodology")
    — disk 72/72 (100%), memory 108/118 (91.5%), with the EVALUATION-MAP noting "the 10 misses are
    enumerated, not hidden"; §5 of that page is titled "The honest gap — SRL-2015 memory pool"
    (25 unground-truthed dumps, named action item).
  - **False positives:** `EVALUATION-MAP.md` §6 cites the VANKO case: "19 candidate findings, 9 refuted
    by the false-positive gate, 10 confirmed — refuted hypotheses kept as honest negatives" in
    `docs/12-CASES-REPORTS/vanko-report/`.
  - **Hallucinated claims:** `docs/05-safety-forensics/anti-hallucination.md` plus
    `docs/02-architecture/SECURITY-INVARIANT-AUDIT-2026-06-11.md` ("6 invariants, file:line-cited,
    5 Enforced / 1 Partially — the gap stated, not papered over").
- The "honesty valued over perfection" posture is explicit (admitted misses, admitted partial invariant,
  admitted uninstrumented token usage). Substantive on all three → PASS, no warning.

### CHECK 9: Try-it-out access — **PASS** (with a warning on the live lane)

- **EVIDENCE (local, unrestricted, free):** README "Installation / Quickstart" Path A is a complete
  3-command local run path: `pip install` of the public GitHub-release wheel (verified to exist,
  v0.3.0/v0.2.2 assets public), token-gated server start, `claude mcp add`. Dependencies are documented
  in the README's "Deployment & requirements" table and `docs/07-sdlc-ops/deployment.md`. Evidence to
  run against is provided via public download URLs in `docs/06-use-cases/reproduce-datasets.md`, with
  guided per-case sequences in `case-activation/` README/INDEX. No paywall, no signup wall on this path.
- **Warning (live deployment lane):** the "Connect in 60 seconds" live server `http://100.85.162.82:8765/mcp`
  is **tailnet-only** and requires accepting a Tailscale invite **and** "ping the operator to approve
  your device" — an operator-approval gate. That lane alone would not satisfy "without restriction";
  qualification rests on the local Path A, which does satisfy it. (Also note the README publishes a live
  Bearer token for that server — see Check 12 observation d4.)

### CHECK 10: Agent execution logs — **PASS** (with one warning)

- **EVIDENCE (multi-agent requirement — agent-to-agent message logs with timestamps):**
  - `case-activation/runs/jimmy-wilson-poc/blackboard-events.jsonl` — raw timestamped agent publish
    events, e.g. line 1: `{"ts": "2026-06-11T00:40:37.042522+00:00", "agent": "memory", "event": "publish", "detail": "1 finding(s)", "duration_ms": 0.11}`.
  - `docs/12-CASES-REPORTS/srl-2018-report/submission/AGENT-EXECUTION-LOGS-REPORT.md` (the "gold
    report") — §3 timestamped agent-to-agent handoff log, §4 full tool-execution sequence, §5
    iteration-over-iteration trace, with raw files beside it: `base-dc-run.log`, `notch-run.log`,
    `base-dc-thymus-audit.jsonl` (146 decisions, 61 REJECTs), sealed `report.json` + `audit-log.json` per run.
  - Persistent-loop trace: `case-activation/runs/jimmy-wilson-poc/EXECUTION-LOG.md` §1 shows the plan
    shrinking iteration-over-iteration (13 agents planned → 2 → 2 → 2 → 2; 11 dropped as stable).
- **SPOT-CHECK (finding → tool execution): traceable. PASS.** The README's headline claim for the
  Jimmy Wilson run ("**129 findings · 86 tool calls · 5 iterations**") traces to `EXECUTION-LOG.md` §2,
  where tool call #2 is `agent.timeline` at `00:49:40.886` producing "111 finding(s)" — and that exact
  event appears in the raw `blackboard-events.jsonl` line 2 with matching timestamp
  `2026-06-11T00:49:40.886576+00:00`, agent `timeline`, detail `111 finding(s)`, duration `543844.07 ms`.
  Log structure states all 86 invocations are recorded in `report.json → trace.tool_calls[]` as
  `{tool, timestamp, duration_ms, result_summary}`.
- **Warning — token usage:** the rules ask single-agent submissions for token usage; this is a
  multi-agent submission (A2A logs present, so the applicable requirement is met), but note the repo's
  own disclosure: "Token usage is an **honest negative** (LLM at the edge, uninstrumented — documented,
  not faked)" (`EVALUATION-MAP.md` §8). A judge applying the single-agent lens would find no token counts.

### CHECK 11: Project requirements screen — appears demonstrated (no flags raised)

- **(1) Self-correction without human intervention — evidenced.** The Trinity Loop iteration trace
  (`EXECUTION-LOG.md` §1) shows the Architect re-planning each iteration and the Critic dropping stable
  agents (13 → 2), with the same plan-shrink narrative documented for two further runs in the gold
  report §5; the sequence is on film in `POC-RUN.mp4`.
- **(2) Accuracy validation, findings traceable to specific artifacts — evidenced.** The gold report
  uses strict `file:json-path -> value` citation form for "every claim"; the SRL-2015 report states
  "82 claims, all `[host/modality $.jsonpath = value]` cited"; my own spot-check (Check 10) traced a
  README claim to a raw timestamped log line. Findings carry evidence SHA-256 anchors
  (e.g. `6c18f662…` for the Jimmy Wilson E01).
- **(3) Structured investigative narrative, not a raw log — evidenced.** The case reports
  (`docs/12-CASES-REPORTS/`: 7-section VANKO DFIR report, SRL-2018 gold report with roster/handoff/
  iteration/governance sections and traceability appendix) are narrative analyses layered on the raw
  logs, which are committed separately.
- **Framework/platform — confirmed.** Runs on the SANS SIFT Workstation (README requirements table:
  "Host: A SANS SIFT Workstation") and integrates with **Claude Code** as the primary client
  (`claude mcp add …`), via a custom MCP server (FastMCP). This is one of the two preferred stacks.
- Residual manual item: a judge should confirm capability (1) live during try-out (a recorded trace
  shows it happened; live re-run confirms it is autonomous, not curated).

### CHECK 12: Viability & integrity flags (flag only — no FAILs here)

**(a) Thin wrapper?** No indication. The repo ships a 794-path codebase with a deterministic 13-agent
swarm explicitly designed with "no LLM inside" the loop, policy enforcement (Thymus allowlist), HMAC
sealing, and 86–176 tool calls per recorded run. Not a pass-through wrapper.

**(b) No real case data?** No — real public datasets are documented with hashes (CFReDS, DFRWS 2005,
MemLabs, etc.) and sealed run outputs are committed. Note honestly: some referenced sets (SANS
FOR500/FOR508 course media) are non-redistributable and marked "operator-host-only"; public
alternatives with download URLs are provided for judges.

**(c) Proprietary/paid dependencies?** Partly. The forensic path is stated to run "fully local — no API
keys"; SIFT tooling is free. However, driving it as intended requires a **Claude** client (Anthropic
account — judges of this hackathon presumably have one), and the *hosted* try-out lane requires joining
the operator's tailnet with operator device-approval (free Tailscale account, but operator-gated). The
free local path (Check 9) mitigates this. — FLAG for awareness, not failure.

**(d) Earliest commit vs Submission Period (Apr 15 – Jun 15, 2026):** earliest commit is
`2026-06-05T03:22:19Z` — "Agentropix-SIFT documentation portal (Mermaid render test)" — **inside** the
window. GitHub repo created `2026-06-10T15:09:43Z`; pre-June-10 local history was pushed at creation
(visible "merge GitHub auto-init (root LICENSE)" commit `ec4fd83c`). 174 commits total as of review.
  - **(d2) Pre-existing foundation:** commit `c0173d4d` ("GitHub-only publishing (GitLab retired)")
    shows the documentation portal previously lived on a private GitLab, and the docs reference earlier
    validation runs (e.g. "the 2026-05-29 CFReDS run") predating the public repo. The rules allow
    pre-existing open-source foundations when the novel contribution is documented; the repo's
    Acknowledgments section credits the underlying DFIR tools, but I did not find an explicit
    "built-during-the-event vs pre-existing" statement. — **NEEDS MANUAL REVIEW:** ask the team to
    state what predates the Submission Period.
  - **(d3) Contributor identity:** the GitHub contributors API lists only `galvangabriel-web`
    (4 attributed commits); the remaining ~170 commits are authored as "Victor Galvan" with an email
    not linked to any GitHub account, so the de-facto sole developer shows almost no contribution graph.
    If the Devpost team roster lists different names than "Victor Galvan"/"Gabriel Galvan" (the README
    contains an "evaluator introduction letter from Gabriel Galvan", commit `06d0d67b`), organizers
    should reconcile identities. — **NEEDS MANUAL REVIEW.**
  - **(d4) Published credentials:** the README publishes a live Bearer token
    (`Authorization: Bearer jlviT…aLs`) and an open Tailscale invite link for the hosted demo server.
    Commit history marks this "operator-authorized" (`b256eb6f` "real tailnet quickstart values
    (operator-authorized)") — intentional for judge access, but organizers may want confirmation it is
    a sandboxed, throwaway credential. — **NEEDS MANUAL REVIEW** (security hygiene, not a rules item).

**(e) Giant commits vs incremental:** incremental — 174 commits over 2026-06-05 → 2026-06-12, small
scoped messages, 3 merged pull requests (#1–#3). The largest single import is the initial portal
snapshot on June 5 (consistent with migrating an existing docs tree in; see d2).

**(f) README referencing a different event:** none found. `README.md` contains no reference to any
hackathon or event at all (grep for "Find Evil"/"devpost"/"hackathon" in the README: zero hits;
`EVALUATION-MAP.md` is explicitly structured around this event's 8 submission requirements).

**(g) Team members as contributors:** covered in (d3) — single visible contributor; commit author
identity unlinked. Reconcile against the Devpost team roster when it exists.

**(h) Post-deadline commits (after Jun 15, 2026, 11:45 PM EDT):** none possible yet — review date is
2026-06-12; latest commit is `2026-06-12T02:15:51Z`. Re-check after the deadline; in particular confirm
the demo video (currently pending, Check 4) is uploaded **before** the deadline, since right now the
headline demo asset is the one artifact that would otherwise depend on post-deadline work.

---

## 4. FIX LIST (for the entrant)

**Blocking (FAILs / unresolved requirements):**

1. **Demo video (Check 4):** Cut a ≤5-minute screencast from the existing footage
   (`POC-RUN.mp4` already contains the live terminal run and the 13→2 self-correction sequence),
   **record audio narration over it**, upload it to YouTube or Vimeo with visibility Public or
   Unlisted, and paste the link into the Devpost submission form — before June 15, 2026, 11:45 PM EDT
   (the repo's own map recommends ≥48 h before, i.e. by June 13). Do not use third-party music.
2. **Devpost project page (Check 6):** Create and submit the Devpost project, filling the story text
   from the already-written assembly guide in `EVALUATION-MAP.md` §4 (What-it-does / How-we-built-it /
   Challenges / What-we-learned / What's-next), and attach the repo URL, video URL, and the
   architecture PNG (`docs/02-architecture/assets/architecture-diagram/architecture-diagram.png`)
   to the image gallery.

**Warnings (non-blocking, fix recommended):**

3. **Broken entry URL (Check 1):** Add a root `index.html` to the repo (even a one-line redirect to
   `README.md` or to `assets/submission-tour/watch-tour.html`) so
   `https://galvangabriel-web.github.io/agentropix-mcp/` stops returning 404 — or submit only the
   repository URL `https://github.com/galvangabriel-web/agentropix-mcp` on Devpost.
4. **Token usage (Check 10):** Add one sentence with approximate token counts per run (or a clearly
   labeled "not instrumented — multi-agent A2A logs provided instead" note directly in
   `AGENT-EXECUTION-LOGS-REPORT.md`) so a judge applying the single-agent checklist finds the answer
   in the log report itself, not only in `EVALUATION-MAP.md`.
5. **Pre-existing vs event work (Check 12 d2):** Add a short "What was built during the Submission
   Period" subsection (README or Devpost story) distinguishing the pre-existing GitLab-era
   documentation/portal foundation from the work done April 15 – June 15, 2026.
6. **Contributor identity (Check 12 d3/g):** Add the commit-author email ("Victor Galvan") to the
   `galvangabriel-web` GitHub account (GitHub → Settings → Emails) so the 170 unattributed commits
   appear in the contributor graph and match the Devpost team roster.
7. **Live credentials (Check 12 d4 / Check 9):** Keep the published Bearer token scoped to a
   sandboxed demo server only, plan to rotate it after judging ends, and state on the page that the
   tailnet lane is optional (the local Path A is the unrestricted judge path).
8. **Stale version reference (minor):** README "Installation / Quickstart" step 1 installs the
   **v0.2.2** wheel while the latest release and `EVALUATION-MAP.md` reference **v0.3.0** — point the
   command at the v0.3.0 wheel URL.

---

*Rules-of-conduct note: every status above cites a fetched URL, file path, or quoted text captured on
2026-06-12; raw captures are stored in [`evidence/`](evidence/). This review is Stage One pass/fail
only — it does not assess quality and does not predict scoring. Checks 11–12 never produce FAIL on
their own; final eligibility decisions belong to the Sponsor under the Official Rules.*
