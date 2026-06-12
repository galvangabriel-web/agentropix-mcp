# Devpost submission draft — Agentropix-SIFT

Paste-ready content for the findevil.devpost.com project page. Every claim below is grounded
in a committed repo page (source cited per section — verify before pasting, trim freely).
Numbers follow `docs/08-reference/canonical-facts.md` (71 canonical / 72 live-registered MCP
tools, 16 wrappers, 4464 tests, 72/72 disk recall, 108/118 memory recall).

---

## Form fields (not the story)

| Devpost field | Value |
|---|---|
| **Project name** | Agentropix-SIFT |
| **Tagline** (~60 chars) | Autonomous DFIR triage on SIFT — the LLM never grades itself |
| **"Try it out" links** | `https://github.com/galvangabriel-web/agentropix-mcp` |
| **Video demo link** | *(YouTube/Vimeo URL — upload first; this field is blocking)* |
| **Built with** (tags) | python, fastmcp, mcp, claude, volatility3, plaso, sleuth-kit, yara, regripper, bulk-extractor, wazuh, sift-workstation |
| **Image gallery** | 1) `docs/02-architecture/assets/architecture-diagram/architecture-diagram.png` (first = thumbnail) 2) a sealed-report/terminal screenshot 3) `assets/submission-tour/proof/archdiag.png` or a Wazuh gallery capture 4) the self-correction funnel PNG (`docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/base-dc-self-correction-funnel.png`) |

---

## Story sections

### Inspiration

Incident response begins with triage: given a freshly acquired disk or memory image, an
analyst must answer *"what happened on this host, and is it bad?"* fast enough to scope the
incident. Done by hand it is a slow, error-prone chain of context switches — `fls`, a dozen
Volatility plugins, a Plaso super-timeline, RegRipper, YARA — with every intermediate result
held in the analyst's head. LLM-only assistants are fast but unusable in court: they rate
their own findings, they hallucinate, and they can't prove they never touched the evidence.
We wanted the speed of an agent with the defensibility of the deterministic toolchain
examiners already trust.
*(Source: `docs/01-overview/what-is-agentropix.md` §The DFIR problem it solves.)*

### What it does

Point Agentropix-SIFT at a Windows disk or memory image on a SANS SIFT Workstation:

```bash
agentropix-sift run evidence.E01 -o report.json
```

It drives **16 real SIFT forensic tools** (Volatility3, log2timeline/Plaso, The Sleuth Kit,
RegRipper, YARA, bulk_extractor, …) through **one custom MCP server (71 canonical / 72
live-registered tools)**, correlates findings across a **7-agent swarm + 6 ATT&CK detectors**
on a quorum blackboard, and emits a cryptographically sealed, schema-validated JSON triage
report — in minutes, entirely on the local host. The design rule that everything hangs off:
**no LLM is ever in the halt path and no LLM ever rates its own findings.** Every fact in the
report originates from a named forensic tool, captured in a tamper-evident, HMAC-SHA256-sealed
trace; a human examiner approves findings through an HMAC-gated portal before anything is
escalated to the SIEM (Wazuh).
*(Source: `docs/01-overview/what-is-agentropix.md`, README banner.)*

### How we built it

The architectural pattern is a **Custom MCP Server**: a purpose-built FastMCP server is the
enforcement boundary — the Thymus read-only path policy, the rate limiter, the DRAFT approval
gate, and fail-closed Bearer auth all run server-side, and *the agent literally has no tool
that can write evidence*. Claude Desktop / Claude Code attach as ordinary MCP clients over
stdio or Bearer-protected HTTP.

Around the server sits the **Trinity Loop**: a deterministic Architect proposes which swarm
agents to run, the agents publish findings to a shared Blackboard (cross-agent agreement at a
quorum of 2 becomes a Correlation), and a deterministic Critic halts on a closed-form rule —
`score = min(1.0, max_confidence + 0.25 · len(correlations))` plus a convergence fingerprint —
never on a model's self-assessed confidence. Safety is layered the same way: a pre/post
SHA-256 evidence invariant brackets every tool call, every run is sealed (report, audit log,
and approval chain cross-bound), and a guardrail audit distinguishes **architectural**
controls (code the model can't reach around) from **prompt-based** ones (instructions it's
expected to honor), pairing every load-bearing prompt control with a code-side backstop.
Python 3.12+, 4464 tests.
*(Sources: `docs/02-architecture/main-architectural-agentropix-design.md`,
`docs/07-sdlc-ops/implementation.md`, README §Architecture.)*

### Challenges we ran into

- **Regex can't decompose tasks semantically.** Our first Architect tried to route work with
  pattern matching; it collapsed on real phrasing variety and we rebuilt routing around an
  explicit, validated agent roster.
- **Monolithic system prompts collapse cache hit-rate and drive confabulation** — we split
  them, and paired the one remaining prompt-based runtime feature (LLM agent reordering) with
  a code-side validator that rejects any added/removed agent.
- **"Unit-tests-green ≠ live recall."** The recall sprints taught us that a passing suite says
  nothing about what the swarm actually surfaces from a real image; we built a ground-truth
  YAML corpus and measured live (72/72 disk, 108/118 memory — the 10 misses are enumerated,
  not hidden).
- **Seal everything, not just the report.** An attacker (or a bug) that can swap the audit log
  out from under a sealed report defeats the point; we now cross-bind report, audit log, and
  approval chain so flipping one byte anywhere breaks verification.
- **Real evidence is hostile to timeouts:** log2timeline on a full corporate disk image blew
  through a 5452-second ceiling mid-run — the engine recorded the timeout as an honest finding
  rather than stalling or fabricating a timeline.
*(Source: `docs/01-overview/lessons-learned.md` Lessons 1, 3, 4, 11; SRL-2018 run logs.)*

### Accomplishments that we're proud of

- **Measured accuracy, honestly reported:** 72/72 (100%) disk recall and 108/118 (91.5%)
  memory recall against committed ground truth; in the VANKO insider-theft case, 19 candidate
  findings went through a false-positive gate — 9 refuted, 10 confirmed, and the refuted
  hypotheses stay in the report as honest negatives.
- **Evidence integrity you can replay:** a sealed run on the SRL-2018 case recorded 146
  Thymus policy decisions including **61 real REJECTs** of out-of-allowlist paths — the
  read-only guarantee demonstrated live, not asserted.
- **Court-style traceability:** every finding in every sealed report resolves to a named tool
  execution with a timestamp in the committed logs (176 tool calls in the headline run).
*(Sources: `docs/07-sdlc-ops/dataset-recall.md`,
`docs/12-CASES-REPORTS/srl-2018-report/submission/`, `docs/12-CASES-REPORTS/vanko-report/`.)*

### What we learned

The thread through all thirteen documented lessons: **determinism is a feature you defend in
layers.** A constant `confidence=1.0` silently saturates a `min()`-capped score; secrets in a
gitignored `.env` are still a trap; a `0600` key file guarantees nothing if operators don't
preserve it in transit; and when live behavior contradicts your diagnosis, instrument before
you redesign. Above all: ground-truth keywords must be *evidence-recoverable*, not analysis
vocabulary — you can only claim recall against things a tool can actually surface.
*(Source: `docs/01-overview/lessons-learned.md` Lessons 8, 5, 10, 12, 13 + "The thread".)*

### What's next

Phases 1 (Foundation) and 2 (Orchestration) are complete; the current phase is **Scale & GA**:
hardening the packaged MCP server (wheels are already on GitHub releases), the optional Rust
acceleration layer for the hot wrappers, and broadening the evidence corpus. The longer
arc — the "Future of Agentropix" — is in the committed strategic roadmap: deeper ATT&CK
detector coverage, multi-host correlation as a first-class object, and the system-lifecycle
work (orchestration thread taxonomy, apoptosis of stale agents).
*(Source: `docs/02-architecture/PROJECT-ROADMAP-2026-06-11.md`.)*

---

## Paste checklist

1. **Upload the narrated ≤5-min video first** (Check 4 — blocking) and paste its URL into the
   video field; Devpost won't let you finalize without it for this hackathon.
2. Devpost's editor is rich-text with limited markdown — paste section by section, re-apply
   the bullet/code formatting by hand, and keep the section headings Devpost provides.
3. Upload gallery images (architecture diagram first — it becomes the thumbnail; landscape
   ~3:2 crops look best).
4. Add the GitHub URL under "Try it out", fill the Built-with tags.
5. Re-read once against the honesty rule: nothing in the story may claim more than the sealed
   reports do (no refuted finding presented as proof).
6. Save as draft, preview, then submit — and re-run the Stage One checklist
   (`STAGE-ONE-QUALIFICATION-REVIEW.md`) against the live page.
