# Evidence Log — Stage One review of github.com/galvangabriel-web/agentropix-mcp

Raw commands and outputs backing every status in
[`STAGE-ONE-QUALIFICATION-REVIEW.md`](STAGE-ONE-QUALIFICATION-REVIEW.md).
All repo-content checks ran against the **pushed** state `github/main` =
`0a93e9c3c6a1b6430fa567f7796224b54926ed7e` (fetched 2026-06-12).

---

## CHECK 1 — public access (unauthenticated HTTP)

```
$ curl -s -o /dev/null -w "HTTP %{http_code}\n" https://github.com/galvangabriel-web/agentropix-mcp/
HTTP 200
$ curl -s -o /dev/null -w "%{http_code}\n" https://raw.githubusercontent.com/galvangabriel-web/agentropix-mcp/main/README.md
200
$ curl -s -o /dev/null -w "%{http_code}\n" https://raw.githubusercontent.com/galvangabriel-web/agentropix-mcp/main/LICENSE
200
$ gh api repos/galvangabriel-web/agentropix-mcp --jq '{private:.private, license:.license.spdx_id, default_branch:.default_branch}'
{"default_branch":"main","license":"MIT","private":false}
```

## CHECK 2 — LICENSE content (first lines of the committed blob)

```
$ git show github/main:LICENSE | head -5
MIT License

Copyright (c) 2026 galvangabriel-web

Permission is hereby granted, free of charge, to any person obtaining a copy
```
21 lines total = the standard MIT text. GitHub API license detection: `spdx_id: "MIT"`.

## CHECK 3 — README setup headings (line numbers in README.md @ main)

```
L56:  ## ⚡ Connect in 60 seconds
L89:  **Prerequisite:** Node.js ≥ 18 on `PATH` (`node --version`); ...
L150: ### ✅ Smoke-test it
L506: ## Installation / Quickstart
L508: **Path A — 60-second start (runs from this repo, today).**
L514: pip install https://github.com/galvangabriel-web/agentropix-mcp/releases/download/v0.2.2/agentropix_mcp-0.2.2-py3-none-any.whl
L533: uv sync          # Path B — self-host the full triage engine
```

## CHECK 4 — demo video probes (ffprobe on the exact committed blobs)

```
$ git show github/main:assets/submission-tour/SUBMISSION-TOUR.mp4 > /tmp/eval-tour.mp4
$ ffprobe ... duration /tmp/eval-tour.mp4
144.083333            # 2 min 24 s — animated requirements deck, not a terminal screencast

$ git show github/main:case-activation/runs/jimmy-wilson-poc/POC-RUN.mp4 > /tmp/eval-poc.mp4
$ ffprobe ... duration + streams /tmp/eval-poc.mp4
9.254545              # 9.25 seconds
video                 # ONLY a video stream — no audio stream
$ git cat-file -s <blob>   # committed blob size
377841                # 377 KB — cannot hold the described full triage run
```

Quoted from `EVALUATION-MAP.md` (requirement row 2 and §2):

> ⚠️ in-repo footage ready; YouTube/Vimeo upload pending

> ⚠️ **Pending operator action:** cut a ≤5-minute screencast **with audio narration** from this
> footage and upload to YouTube/Vimeo ≥48 h before the deadline. The committed MP4s are silent
> screen captures — narration is not yet recorded.

## CHECK 5 — architecture diagram artifacts + key quotes

Files present on `main`:

```
docs/02-architecture/main-architectural-agentropix-design.md
docs/02-architecture/assets/architecture-diagram/architecture-diagram.png
docs/02-architecture/assets/architecture-diagram/architecture-diagram.svg     (linked from README)
docs/02-architecture/assets/architecture-diagram/architecture-diagram-hd.pdf  (linked from README)
assets/readme-2.png   (README §Architecture inline diagram, Mermaid source in a <details> block)
```

Quotes from `main-architectural-agentropix-design.md`:

> ## Architectural pattern
> **Verdict: Custom MCP Server.**
> ... It is **not** a Direct Agent Extension (no Claude-internal plugin code) and **not** an
> Alternative Agentic IDE (no editing environment).

> ## Guardrails: prompt-based vs architectural
> ... an **ARCHITECTURAL** guardrail is enforced by code the model cannot reach around; a
> **PROMPT-BASED** guardrail is an instruction the model is expected — but not forced — to honor.

> Two guardrail columns flank the flow: **ARCHITECTURAL** (green, solid border — enforced in
> code, the model cannot bypass them) and **PROMPT-BASED** (amber, dashed border ...)

Component sections: §1 The agent · §2 The SIFT Workstation tools · §3 The MCP server ·
§4 The data sources · §5 The output pipeline · §Known gaps (honest negatives).

## CHECK 6 — Devpost

No Devpost URL was provided to this review; the page was not fetched and nothing was inferred.
Repo-side assembly map exists: `EVALUATION-MAP.md` §4 (table mapping the five Devpost story
sections to committed pages).

## CHECK 7 — dataset documentation

`docs/06-use-cases/reproduce-datasets.md`, heading `# Reproduce: get the evidence datasets`:

> For each **publicly available** dataset it gives the real upstream download location, the
> provenance recorded in the matching Case Activation Guide, and an integrity anchor ...
> **Every URL below was verified live (HTTP 200) on 2026-06-10.**

Ground truth fixtures on `main`: `docs/03-data/recall-ground-truth/ground_truth_*.yaml` (4 files
+ run summary). Findings: `docs/12-CASES-REPORTS/{srl-2015,srl-2018,vanko}-report/` +
`case-activation/runs/*/`.

## CHECK 8 — accuracy report components

```
docs/07-sdlc-ops/dataset-recall.md        # "# Evaluation Corpus & Recall Methodology"
  §5 "The honest gap — SRL-2015 memory pool"   (the 10 memory misses enumerated)
docs/07-sdlc-ops/evaluation-scorecard.md
docs/05-safety-forensics/anti-hallucination.md
docs/02-architecture/SECURITY-INVARIANT-AUDIT-2026-06-11.md   # present on main (verified via git ls-tree)
```

Bypass-behavior quotes from `SECURITY-INVARIANT-AUDIT-2026-06-11.md`:

> **Adversarial (LLM tries to inject a finding):** ... A hallucinated "finding" in model prose
> never enters `report.findings` because that list is assembled in Python from Blackboard
> state, not from model output.

> **Adversarial:** `/cases/../etc/passwd` → `REJECT: forbidden pattern '..'`; ... symlink
> `/cases/eviltunnel → /root/.ssh` → `REJECT_SYMLINK_TARGET_OUTSIDE_ALLOWLIST`; any write → `REJECT`.

Live-run proof: `base-dc-thymus-audit.jsonl` — sealed metadata reports `"entry_count": 146`;
the gold report cites 61 `REJECT` entries; sample committed entry:

```json
{"timestamp": "2026-06-11T15:54:31.702524+00:00", "action": "REJECT",
 "path": "/tmp/claude-1001/agentropix-sift-extract-yazy9cbj",
 "reason": "REJECT_OUTSIDE_ALLOWLIST: '...' not under any allowed prefix"}
```

## CHECK 9 — try-it-out

README `## Installation / Quickstart` Path A (released wheel, pinned URL) + Path B (`uv sync`,
`agentropix-sift` CLI). Client walkthrough `docs/09-integrations/client-setup.md`; deployment
`docs/07-sdlc-ops/deployment.md`. Live server `http://100.85.162.82:8765/mcp` is tailnet-only.

## CHECK 10 — execution logs + spot-check

Files on `main` under `docs/12-CASES-REPORTS/srl-2018-report/submission/`:

```
AGENT-EXECUTION-LOGS-REPORT.md      base-dc-report.json        base-dc-run.log
base-dc-thymus-audit.jsonl          base-dc-report.audit-log.json
notch-report.json  notch-run.log  notch-thymus-audit.jsonl  notch-report.audit-log.json
```
Plus `case-activation/runs/jimmy-wilson-poc/EXECUTION-LOG.md`.

Spot-check (run with python3 against the committed `base-dc-report.json` blob):

```
finding[15]: Cross-source agreement: 'evidence' flagged by 2 agents (artifact, t1546_008_accessibility_ifeo_hijack)
timestamp:   2026-06-11T15:56:32.095448+00:00
source:      hunt.correlate
tool_calls:  176 entries in trace.tool_calls[]
tc[151]:     2026-06-11T15:56:32.095698+00:00   "8 finding(s)"
```

Matches the gold report's §3.2 Edge-2 claim exactly → finding located in the raw logs. ✓

## CHECK 11 — disqualification screen inputs

- Deterministic agentic engine (not a wrapper): README §Architecture — closed-form Critic rule
  `score = min(1.0, max_confidence + 0.25 · len(correlations))`, halt "never on an LLM's
  self-assessed confidence"; 176 logged tool calls per run.
- Real data: see CHECK 7.
- Access: live server tailnet-only (flagged); local path fully open-source.
