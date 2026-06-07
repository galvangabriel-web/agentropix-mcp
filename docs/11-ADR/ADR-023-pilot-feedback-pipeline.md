> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-023: Pilot-Feedback Pipeline — Resurrect Sprint-18 Story-18.1 by Promoting the Script and Un-Ignoring the Survey Directory

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-05-14 |
| **Decision Makers** | Operator (victor.galvan@idemia.com), Claude (Opus 4.7) |
| **Tracking ticket** | W-202 (GitHub Issue #100) |
| **Follows** | W-200 (PR #99, commit `65ab000a1`) |
| **Priority** | P2 — un-blocks an internal feedback channel; no live pilot today, but the scaffolding is complete and ready |

## Context

Sprint-18 Story-18.1 shipped `.github/workflows/pilot-feedback.yml` and
`.github/ISSUE_TEMPLATE/pilot-feedback.yml` (commit `73a2c78e1`) along with
a 390-line processor script that defines `SurveyResponse`,
`ActionItem`, `analyze_feedback`, `generate_summary_report`, and
`generate_github_issue`.

The workflow validation bug (W-200) — `secrets` context in step-level
`if:` — silently failed every push for the lifetime of the feature, so
the workflow never ran. W-200 (PR #99) fixed the validation. The real-data
production verification that followed (run `25856348877`) exposed three
structural sub-bugs that together kept the feature unrunnable:

- **W-202a** — `.gitignore:106` excluded `reports/`, so no survey JSON
  could be committed and the `push.paths:
  'reports/pilot-surveys/**/*.json'` filter was structurally unreachable.
- **W-202b** — `.gitignore:126` excluded `/agentropix/`, where the
  script lived (developer scratch tree, not source).
- **W-202c** — `git ls-tree -r origin/main` confirmed the script was
  never committed to `main`. The workflow always referenced a path that
  did not exist on the runner.

### Problem statement

Resurrect or bury. The script exists and is structurally complete; the
workflow exists and is now valid (post-W-200); the only thing missing is
the wiring between them and a real spot for survey JSONs to live.

## Decision drivers

1. **Sunk cost vs forward cost** — W-200 just spent engineering time
   making the workflow pass validation. Burying 24 h later wastes it.
2. **Reversibility** — Both resurrect and bury are reversible; resurrect
   is easier to bury later than bury is to resurrect (bury loses the
   uncommitted script body, which lives only in one operator's worktree).
3. **No live data** — `git ls-tree` shows zero survey JSONs ever existed
   on `main`. No migration cost.
4. **Surgical-scope discipline** (`feedback_coding_discipline_2026-05-10`
   in operator memory) — favours small surgical PRs that trace every
   changed line to the request.

## Considered options

### Option A: Resurrect

Move the script to a tracked path, un-ignore `reports/pilot-surveys/`,
fix the workflow to point at the new path, add tests, add an ADR.

**Pros:**

- Keeps the Sprint-18 Story-18.1 deliverable alive at low cost
  (~4-6 h, ~+420 LOC).
- Aligns with the W-200 effort that just landed.
- Surgical single-PR scope.

**Cons:**

- Adds a new committing pattern (pilot survey responses in git). PII
  discipline is now an operator concern.
- Edge-cases in `git diff HEAD~1 HEAD` (squash-merge, first-commit) need
  a small fallback (this ADR codifies that fallback).

### Option B: Bury

Delete the workflow, the issue template, the script (it is untracked
anyway), and the unused `SLACK_WEBHOOK_URL` secret.

**Pros:**

- Zero ongoing maintenance.
- Removes a structurally-broken feature that gives a false impression
  of operability.

**Cons:**

- Throws away ~390 LOC of working processor code plus the W-200
  validation-fix effort.
- Loses the only intake channel for the first pilot whenever they sign.

## Decision

**Option A — Resurrect**, with a hard fallback rule: if no real pilot
has submitted a survey within 60 days of this ADR's merge date
(2026-07-14), re-open W-202 as a bury-PR.

### Implementation

| File | Change | Rationale |
|---|---|---|
| `scripts/process-pilot-feedback.py` | **Added** — copied from untracked `agentropix/scripts/process-pilot-feedback.py` | The repo's tracked-scripts convention puts pipeline scripts at top-level `scripts/`. `/agentropix/` remains gitignored — that path is the dev-scratch parent worktree (see `.gitignore:118-126`). |
| `.gitignore:105-112` | `!reports/pilot-surveys/` + `!reports/pilot-surveys/**` un-ignore; `reports/pilot-feedback-processed/` re-ignored explicitly | Survey responses are source-of-record; processed outputs are CI artifacts. |
| `.github/workflows/pilot-feedback.yml:67-77` | Fallback for `git diff HEAD~1 HEAD` → `origin/main...HEAD` when first variant returns empty | Handles first-commit-on-branch and squash-merge edge cases without needing `fetch-depth: 0`. |
| `.github/workflows/pilot-feedback.yml:86` | `agentropix/scripts/...` → `scripts/...` | Points at the tracked path. |
| `.github/workflows/pilot-feedback.yml:134-140` | **Not touched** — W-200 SLACK_WEBHOOK_URL hoist remains correct | |
| `tests/unit/test_process_pilot_feedback.py` | **Added** — real-data fixtures (engineer happy-path → 0 items; pilot-with-blockers → 7 items; internal-eval medium-path → 2 items) | Locks behavior; no mocks; uses on-disk JSON fixtures under `tests/fixtures/pilot-surveys/`. |
| `tests/fixtures/pilot-surveys/*.json` | **Added** — three real-shape fixtures | Lives outside `reports/pilot-surveys/` so the workflow does NOT trigger when fixtures are pushed. |
| `reports/pilot-surveys/.gitkeep` + `README.md` | **Added** — schema doc + PII reminder + engineer happy-path recipe | First-touch documentation for whoever onboards the first pilot. |

### Engineer happy-path

To smoke-test the pipeline without polluting the GitHub issue tracker,
score the survey with `overall_satisfaction = reliability_score =
performance_score = documentation_score = support_score = 5`,
`nps_score = 9`, `wants_call = false`, and empty `blockers /
challenges_encountered / feature_requests`. `analyze_feedback` returns
zero items in that configuration; the workflow runs end-to-end through
`Upload processed reports` and the `gh issue create` loop iterates over
zero entries.

## Consequences

### Positive

- The W-200 fix becomes end-to-end useful.
- A working intake channel exists the moment a real pilot signs.
- ADR-023 records the un-ignore exception so future cleanup PRs do not
  accidentally re-ignore `reports/pilot-surveys/`.

### Negative

- One more pattern for operators to remember: pilot survey JSONs are
  committed; everything else under `reports/` is not.
- PII discipline is now part of the pipeline contract. Mitigated by the
  README and by the fact that survey content is authored by the pilot
  who owns the redaction decision.

### Neutral

- The 60-day re-bury rule keeps this decision falsifiable. If the
  feature stays dormant past 2026-07-14, ADR-023 is superseded by a
  bury ADR rather than left as zombie scaffolding.

## Alternatives rejected

- **Use the workflow only via `workflow_dispatch`, never via push.**
  Loses the auto-trigger value-add. The architecture plan would still
  need to fix the script-not-found bug, so most of the work is the
  same.

- **Commit survey responses to a private sibling repo.** Adds cross-repo
  coordination overhead for zero gain at current scale.

- **Replace the script with a Lambda / Cloud Function.** Out of scope
  and inconsistent with the rest of the repo's "tracked Python scripts
  under `scripts/`" convention.

## References

- W-200 / PR #99 / commit `65ab000a1` — workflow validation fix
- GitHub Issue #100 — W-202 ticket with full architecture plan
- Run `25856348877` — empirical proof of script-not-found
- `feedback_coding_discipline_2026-05-10` (operator memory) — surgical
  scope discipline
- `feedback_openclaw_mandates_2026-05-06` (operator memory) — MANDATE 6
  (5-critic crew) + MANDATE 7 (resolution chain)
