# Judge Evaluation Draft — Find Evil! Hackathon (findevil.devpost.com)

**Submission evaluated:** `https://galvangabriel-web.github.io/agentropix-mcp/` →
repository `https://github.com/galvangabriel-web/agentropix-mcp` (public; HEAD at review = `0a93e9c3`, 2026-06-12T02:15:51Z)
**Review date:** 2026-06-12 — **before** the June 15, 2026, 11:45 PM EDT freeze; this draft judges current HEAD and must be re-checked against the deadline snapshot.
**Provided to the assistant:** repository link only. **No Devpost page, no demo-video link, no judge demo notes were supplied** — every video-dependent check below is explicitly marked unverifiable.
**Raw evidence captured:** [`evidence/`](evidence/) (gold logs report, raw sealed report + audit JSON, run.log, Thymus JSONL, policy & sealing source code, commit history, repo tree).

---

## ⚠️ CONFLICT-OF-INTEREST NOTICE — read first

The environment running this evaluation is authored by the same person as the submission: the local
git identity is **Victor Galvan**, and ~170 of the submission's 174 commits are authored by
**Victor Galvan** (plus an in-README "evaluator introduction letter from Gabriel Galvan").
**If you are a judge with any relationship to this team: recusal on the Devpost dashboard is the
correct move.** If the team is your employer's, the team itself may be ineligible under the Official
Rules and you should report it to the organizers. This document should therefore be treated as a
**self-assessment / mock-judging draft** — useful for calibration and gap-fixing, not enterable as a
judge score.

---

## Methodology note

Per the evaluation hazards: I anchored on the **execution logs, raw sealed artifacts, and source
code**, not on presentation. Where the gold report provided "How to verify" commands, **I executed
the equivalent verifications myself against the committed raw files** rather than trusting the
report's claims. There is no demo video to assess (none exists yet — see Red Flags), which removes
polish bias entirely but also removes the "functions as depicted" cross-check.

---

## Criterion 1 — AUTONOMOUS EXECUTION QUALITY

**Evidence examined.** `base-dc-report.json` (sealed, 176 tool calls), `base-dc-run.log`,
`base-dc-thymus-audit.jsonl`, `case-activation/runs/jimmy-wilson-poc/EXECUTION-LOG.md` +
`blackboard-events.jsonl`, gold report §5 iteration traces.

**Self-correction verification (the required trace):**
- **Genuine failure #1 — natural, not injected:** `base-dc-report.json $.trace.tool_calls[2]` =
  `"ERROR: log2timeline timed out after 5452s"` (exit_code 1), corroborated by
  `base-dc-run.log:L5` (`WRAPPER_TIMEOUT … image=/cases/SRL-2018/base-dc-cdrive.E01`) and the
  ~5462 s rollup duration in `tool_calls[1]` (`5461792.98 ms`). **I verified all three values in the
  committed raw files myself.** A 90-minute Plaso timeout on a domain-controller NTFS image is the
  most natural failure in DFIR — nothing about it looks staged. The run degraded gracefully
  (timeline agent skipped, swarm continued) rather than crashing.
- **Genuine failure #2:** the engine's own extract helper picked `/tmp/claude-1001/agentropix-sift-extract-yazy9cbj`
  and was **REJECTED by its own Thymus policy** (`tool_calls[8]`, `run.log:L7`,
  `thymus-audit.jsonl:L6` — all three verified matching, timestamp `2026-06-11T15:54:31.702524+00:00`).
  An emergent self-inflicted policy collision is strong evidence of un-staged execution.
- **Adjusted-parameter retry:** Jimmy Wilson `EXECUTION-LOG.md` §2 shows the event-log probe missing
  `/Windows/System32/config/SecEvent.Evt` then retrying the case-variant `/WINDOWS/system32/config/…`
  paths (tool calls #10–#15) — a real adapt-and-retry micro-pattern.
- **Plan re-sequencing:** gold §5.1 (citations into `$.iterations[]`): iteration 1 runs all 13
  agents; the Critic stabilizes 11 and re-targets only the 2 gap agents; plan 13 → 2. Verified
  shape in the sealed report.

**Strong:** the correction arc exists **in the logs, not just in prose**; failures are natural;
plan adaptation is recorded iteration-by-iteration; runs end honestly in `budget_exhausted` rather
than being dressed as convergence.

**Weak / unverifiable:** (1) Iterations 2–5 are an admitted **fixed point** — the same 2-agent plan
re-runs four times with verbatim-identical critic feedback. The system never tries a *different*
approach when the gap agents repeatedly produce zero findings; that is persistence, not strategy
adaptation. (2) The reasoning is **deterministic by design** ("The LLM is the Layer-1 orchestrator
ONLY… it does not generate forensic facts" — gold §1). Hypothesis formation à la senior analyst is
not what the engine logs show; the LLM layer that *does* reason is largely unlogged (token usage
admitted uninstrumented). (3) The claimed richer behavior (SRL-2015 15-iteration loops,
cross-host re-sequencing) I did not independently verify. (4) No video exists to corroborate
real-time behavior.

**DRAFT: ★★★★ (4/5).** Clearly above anchor-3 ("one genuine correction, static plan"): multiple
genuine, naturally-occurring failures are handled and the plan visibly re-sequences, with the whole
arc in sealed logs. It misses anchor-5 because the adaptive repertoire is shallow — once the plan
narrows, the loop retries identically until budget exhaustion, and the hypothesis-forming layer
(the LLM) leaves no trace in the committed logs. First tiebreak criterion, so note: the 4 rests on
verified log evidence, not on the writeup.

## Criterion 2 — IR ACCURACY

**Required claim traces (I ran these, not the team):**

| # | Claim (from project description/report) | Log evidence | Verdict |
|---|---|---|---|
| 1 | base-dc: "22 findings · 176 tool calls, critic 1.0, budget_exhausted" (README + gold §1) | My own parse of committed `base-dc-report.json`: `len(trace.tool_calls)=176`, `len(findings)=22`, `status=budget_exhausted`, `critic_score=1.0`; `run.log:L70` "Findings: 22" | **Supported** |
| 2 | "146 recorded decisions, 61 real REJECTs" (EVALUATION-MAP §6) | My count of committed `base-dc-thymus-audit.jsonl`: 146 lines, 61 `"action": "REJECT"`; sealed `audit-log.json $.metadata.entry_count = 146`; seals cross-bind (`audit_log_seal` equal in both files — verified True) | **Supported** |
| 3 | "log2timeline timed out after 5452s" 3-way correlation (gold §4.1) | `tool_calls[2].result_summary`, `run.log:L5/L6`, `tool_calls[1].duration_ms=5461792.98` — all match | **Supported** |
| 4 | Jimmy Wilson "129 findings · 86 tool calls · 5 iterations" (README) | `EXECUTION-LOG.md` §2 + raw `blackboard-events.jsonl` line 2: `agent.timeline` at `2026-06-11T00:49:40.886576+00:00`, 111 findings, 543844 ms — timestamps match to the microsecond | **Supported** |

4/4 traces supported; zero claims I checked failed to trace; I found **no unflagged hallucination**
in the artifacts I examined.

**Accuracy report quality:** genuinely self-critical with specifics on all three required axes —
missed artifacts (memory 108/118 with "the 10 misses enumerated, not hidden"; an entire section
titled "The honest gap — SRL-2015 memory pool"), false positives (VANKO: 19 candidates, 9 refuted
by the FP gate, refuted hypotheses retained as honest negatives), hallucination defense
(anti-hallucination page + `SECURITY-INVARIANT-AUDIT` admitting 5 Enforced / **1 Partially** —
the gap stated). Confirmed-vs-inference labeling is structural (`inference_constraint: "high"`,
findings carry `_source` tool attribution).

**Weak / unverifiable:** the recall numbers (72/72, 108/118) and VANKO FP counts are the **team's
own testing results**; ground-truth fixtures are committed but I did not re-run the agent against
them (verification-squad work). `critic_score` is pinned at 1.0 in every published run — as a
correctness signal it has zero discrimination; it is a coverage metric wearing a confidence
metric's name.

**DRAFT: ★★★★★ (5/5).** Every trace I attempted resolved cleanly to sealed tool executions, the
labeling discipline is structural rather than rhetorical, and the accuracy report is exactly the
"honesty over perfection" artifact the rules describe — misses, refuted findings, and an admitted
partially-enforced invariant are all in print. Held to the calibration bar ("would hold up in a
real engagement"): a sealed, hash-bound, honest-negative reporting chain is precisely what survives
cross-examination. The residual risk (self-reported recall) is listed in Confidence Notes and is
the verification squad's first stop.

## Criterion 3 — BREADTH AND DEPTH OF ANALYSIS

**Evidence.** Tool families in the architecture source (`architecture-diagram.mmd`): case, disk
imaging, memory, registry/execution, event log, mail/maldoc, carving, findings/IOC, approval,
indexer, SIEM — backed by 16 SIFT binaries + EZ-Tools. Case corpus: 14 documented evidence sets
(`reproduce-datasets.md`, `case-activation/INDEX.md`) spanning disk E01/raw/dd-split, memory dumps,
and a SIEM escalation path (Wazuh). `dataset-recall.md` documents an 11-disk + 25-memory-dump
corpus, a 27-technique MITRE ATT&CK span, and a **cross-modal coherence** section (disk-vs-memory
corroboration per host) — the correlation-as-depth signal the rubric asks for. The SRL-2015 report
claims cross-host correlation (spinlock.exe traced workstation → domain controller across 8 sealed
runs).

**Strong:** real depth on disk (verified: 176-call DC run; 204,884-entry fls walks claimed; EVTX/
registry/mail/carving wrappers in code), an honest demonstration that the same engine produces
*evidence-appropriate* different traces on a raw image vs E01 (notch §5.2 — agents that can't apply
themselves stabilize at zero rather than confabulating). Multi-source correlation is designed-in
(`hunt.correlate` producing 8 handoff edges in base-dc findings 14–21).

**Weak:** no network capture and no live/remote endpoint modality (Wazuh is an outbound push, not
endpoint collection). The notch run also exposes brittleness: an untyped raw filesystem yields a
4-agent rump plan and 10 findings — handled honestly, but shallow. Memory-side depth (the 108/118)
is documented, not independently verified here. The "200+ DFIR tools" event framing maps to **72
MCP tools wrapping 16 binaries** in this submission — respectable, but quote their numbers, not the
event's.

**DRAFT: ★★★★ (4/5).** Deep on disk + memory + log artifacts with genuine cross-modal and
cross-host correlation machinery, which the rubric explicitly values over thin breadth; missing
network/remote-endpoint coverage and with memory-side depth resting on team-reported recall keeps
it off 5.

## Criterion 4 — CONSTRAINT IMPLEMENTATION

**Architectural, verified at the code level (not prompt-based):**
- **No write tools exist:** `thymus_policy.py:1-7` — "The agent physically cannot write to evidence
  because no MCP tool exposes a write operation."
- **Read allowlist enforced before execution:** `ThymusEvidencePolicy.check_read()` at
  `thymus_policy.py:236`, typed REJECTs at lines 251–296 (`REJECT_OUTSIDE_ALLOWLIST`,
  `REJECT_PATH_TOO_LONG`, forbidden patterns `..`, `~`, `/dev/`, `/proc/`, `/sys/` at lines 45–51);
  enforcement is wired through the tool surface (`fastmcp_app.py:1687-1714` — glob/list piped
  through "same Thymus read-zone enforcement"; symlink screening at `:1903`).
- **Proven live, not just claimed:** the 61 REJECT entries in `base-dc-thymus-audit.jsonl` are the
  policy firing **during the flagship run** — including rejecting the engine's *own* extract path.
  That is bypass-resistance evidence from production, the strongest kind.
- **Evidence integrity by design:** `courtroom.py:89` (`evidence_image_sha256`), HMAC sealing
  `seal_report` (`:161`, `hmac.new(key, payload, hashlib.sha256)` at `:170`),
  `seal_audit_log` (`:269`), constant-time verification (`:173`, `:284`), 32-byte session keys
  (`:185`). Fail-closed boot (server refuses to start without an auth token — README quickstart,
  matches `fastmcp_app.py` design notes).
- **Trust boundaries marked:** the architecture diagram has an explicit "Transport + auth boundary"
  node and a labeled ARCHITECTURAL-vs-PROMPT-BASED guardrail split, with prompt-based conventions
  "each one backstopped by a code-side control".
- **Bypass testing documented:** `SECURITY-INVARIANT-AUDIT-2026-06-11.md` — 6 invariants,
  file:line-cited, each with an adversarial test case; verdict 5 Enforced / 1 Partially (gap
  disclosed).

**Weak:** I read the audit's framing and the policy code but did not execute the adversarial test
cases; the "1 Partially" invariant is disclosed but I didn't assess its blast radius. The committed
session keys undermine *ongoing* tamper-evidence of the published artifacts (see Red Flags — the
team marked them "treat as burned," a deliberate judge-verifiability tradeoff).

**DRAFT: ★★★★★ (5/5).** This is the submission's strongest axis and a textbook answer to the
criterion: guardrails live in typed code at the MCP boundary, the read-only property is structural
(no write tool exists to misuse), the policy demonstrably fired 61 times during the headline run,
sealing binds reports to evidence hashes, and the team shipped a self-critical invariant audit
instead of a claim of perfection.

## Criterion 5 — AUDIT TRAIL QUALITY

**Evidence.** The committed package per run: sealed `report.json` (full `trace.tool_calls[]` with
`args_hash`/`output_hash`/`exit_code`/`raw_output`), `audit-log.json` (sealed, entry-counted),
`thymus-audit.jsonl` (raw), live `run.log`, session key. Multi-agent requirement: timestamped
agent-to-agent handoff log (gold §3, 8 VERIFIED edges) and raw `blackboard-events.jsonl`.
Persistent-loop requirement: full iteration traces (`$.iterations[0..4]` with plan/stable/dropped/
gaps/feedback/should_halt). A claim→locator index (gold §7.2) in `file:jsonpath -> value` form and
a "How to verify" section of jq one-liners.

**The decisive test — I reconstructed without the team:** every verification I ran independently
passed: counts, statuses, seal cross-binding (`audit_log_seal` identical across report and audit
log), entry_count == array length == raw JSONL line count (146/146/146), and two worked 3-way
correlations matching across report/JSON-log/console-log. Another analyst **could** reconstruct the
investigation of the two gold runs from the logs alone — I effectively did.

**Weak:** (1) **Token usage is absent** — admitted: "Token usage is an honest negative (LLM at the
edge, uninstrumented — documented, not faked)" (EVALUATION-MAP §8). For a build whose orchestrator
is an LLM, the LLM layer's behavior is the one part of the system you cannot reconstruct from these
logs (the `case-activation/runs/*/step*.json` MCP captures only partially cover it). (2) **No
demo video exists**, so the required log-vs-video cross-check is impossible. (3) Engine version in
the sealed reports is `0.2.0-dev` while the released wheel is v0.3.0 — the logs were produced by a
build that isn't the published artifact (minor drift, worth one verification-squad question).

**DRAFT: ★★★★★ (5/5).** "Can a judge trace any finding back to the specific tool execution that
produced it?" — yes, and I did, four times, with cryptographic cross-binding I verified rather than
trusted. The structured/timestamped/complete bar is met for the deterministic engine; the LLM-layer
gap and missing video cross-check are real but disclosed, and the disclosure discipline is itself
what this criterion rewards.

## Criterion 6 — USABILITY AND DOCUMENTATION

**Strong:** Deploy-today path verified end-to-end on paper: public release wheel exists
(v0.3.0/v0.2.2 assets on GitHub Releases), README "Installation / Quickstart" Path A is three
commands with fail-closed token boot, client wiring for both Claude Code CLI and Claude Desktop,
prerequisites table (Python 3.12+, the 16 PATH binaries, graceful degradation), datasets
re-acquirable from public URLs with integrity anchors, and an unusually deep extension surface
(ADR index, component/data/sequence docs, dual expert-command/plain-prompt lanes on every
operational page).

**Weak — the reproducibility seam:** the flagship runs were produced by the **`agentropix-sift`
engine CLI, which this repo does not ship as a runnable command**. README Path B says verbatim the
commands "run from a checkout of the **full `agentropix-sift` engine distribution** — *not* from
this documentation portal," and the sealed logs reference `/home/admin2/agentropix-sift/…` — a
non-public checkout. The wheel *does* vendor the engine subpackages (`trinity/`, `agents/`,
`detectors/` via the `[engine]` extra, `pyproject.toml`), but the only console entry point is
`agentropix-mcp` (the server) — there is no documented command by which a community practitioner
re-runs the gold-report engine pipeline from this repo alone. The hosted try-out lane additionally
requires operator device-approval on a private tailnet.

**DRAFT: ★★★★ (4/5).** The MCP server — the submission's core — is deployable from the README
today by any practitioner, and the documentation depth is far beyond hackathon norm. It loses the
fifth star on the criterion's own terms ("winning code goes back into the community toolset"):
the engine that produced the headline results is not independently runnable from the public
package, which caps community build-on-ability until the engine CLI ships or its invocation is
documented.

---

## A. CLAIM-TO-CODE TRACE

**Claim 1 — "The agent physically cannot write to evidence; the Thymus deny-by-default policy
rejects every out-of-allowlist path before the subprocess spawns."**
→ **Implemented.** `agentropix_mcp/src/agentropix_mcp/thymus_policy.py` — module docstring lines
1–7 (no write tool exists; defense-in-depth read validation); `READONLY_PATHS` allowlist lines
31–44; `FORBIDDEN_PATTERNS` lines 45–51; `ThymusEvidencePolicy.check_read()` line 236 with typed
REJECT emission lines 251–296; wired into the tool surface in
`agentropix_mcp/src/agentropix_mcp/fastmcp_app.py` (read-zone enforcement at 1687–1714, symlink/
traversal screening at 1903). Runtime proof: 61 REJECT entries in the committed
`base-dc-thymus-audit.jsonl`.

**Claim 2 — "Reports are HMAC-sealed and bound to the evidence image SHA-256, with a sealed,
entry-counted audit trail."**
→ **Implemented.** `agentropix_mcp/src/agentropix_mcp/courtroom.py` — `evidence_image_sha256()`
line 89; canonicalization `_canonical_for_seal()` line 145; `seal_report()` line 161 (HMAC-SHA256
at line 170); `verify_seal()` line 173 using `hmac.compare_digest`; `seal_audit_log()` line 269;
`write_session_key()` line 185 (32 random bytes); `write_sealed_session()` line 341. Runtime
proof: I verified `audit_log_seal` matches between `base-dc-report.json` and
`base-dc-report.audit-log.json` and that `entry_count` (146) equals both the array length and the
raw JSONL line count.

Both headline claims have implementing code **and** committed runtime artifacts. No headline claim
I examined lacked code.

## B. RED FLAGS

1. **No demo video exists at review time.** `EVALUATION-MAP.md` §2: "⚠️ Pending operator action:
   cut a ≤5-minute screencast with audio narration… The committed MP4s are silent screen
   captures — narration is not yet recorded." Submission-blocking (see the Stage One report in
   this folder), and it makes the rules' "functions as depicted in the video" check impossible. If
   the video appears, confirm it's uploaded **before** the deadline — a headline demo depending on
   post-deadline work is the explicit red-flag case.
2. **The engine that produced the flagship logs is not publicly runnable from this repo.** Sealed
   logs cite `/home/admin2/agentropix-sift/submission/…`; README Path B requires "the full
   `agentropix-sift` engine distribution — not… this documentation portal"; the wheel's only entry
   point is the MCP server. Reproducibility of the headline runs currently depends on a non-public
   checkout. (Mitigations exist: engine subpackages are vendored in the wheel; raw sealed outputs
   are committed.) Follow-up, not verdict.
3. **Committed HMAC session keys make the published seals forgeable going forward.** Commit
   `699d92f1`: "publish per-run HMAC session keys (operator-authorized; treat as burned)." With the
   32-byte keys in the repo, anyone can recompute valid seals over modified artifacts; the seals
   now prove integrity only up to the moment of key publication. The team chose judge-verifiability
   over ongoing tamper-evidence and said so — legitimate, but the courtroom-grade framing should be
   read with that caveat. (Note the gold report §7 still says "do not print their bytes" while the
   key files sit committed beside it — internal inconsistency worth one question.)
4. **`critic_score` is pinned at 1.0 in every published run** and is marketed as a guarantee
   ("critic pinned at 1.0 across 10 runs"). As implemented it's a coverage guard, not an accuracy
   judgment; it cannot fail in a way that distinguishes good runs from bad ones. Probe in
   verification: what input would produce a critic_score < 1.0?
5. **Iterations 2–5 are verbatim-identical retries** ending `budget_exhausted` in both gold runs —
   honestly labeled, but the "persistent loop" demonstrates persistence more than adaptation; the
   per-iteration "approach changed" requirement is satisfied only by the single 13→2 narrowing
   step.
6. **Live credentials published in the README** (Bearer token + open Tailscale invite for the
   hosted server, commit `b256eb6f` "operator-authorized"). Deliberate for judge access, but it is
   an evidence-handling-adjacent hygiene risk and the hosted lane also requires operator device
   approval (a restriction; the free local path mitigates).
7. **Version drift:** sealed reports say engine `0.2.0-dev`; the published package is v0.3.0. The
   logs were not produced by the released artifact. Minor; ask which delta exists.
8. **Commit-history observations** (follow-up signals only, never verdicts): all 174 commits fall
   2026-06-05 → 2026-06-12 (inside the window), incremental and PR-structured — no giant-dump
   anomaly; but ~170 commits are authored under an email unlinked to any GitHub account (contributor
   graph shows only `galvangabriel-web`, 4 commits), and the portal foundation predates the public
   repo on a private GitLab (commit `c0173d4d` "GitLab retired") with no explicit
   "built-during-event vs pre-existing" statement. The rules allow pre-existing foundations when
   documented — ask the team to document the split.
9. **Thin wrapper? No.** Affirmatively ruled out: 13 deterministic agents, policy engine, sealing
   layer, 794-path repo, 86–176 tool calls per run with real failures. **No real case data? No** —
   public datasets with hashes and committed sealed outputs.

## C. STANDOUT ELEMENTS

- **Independently re-verifiable audit package.** The `file:jsonpath -> value` claim-locator index
  plus committed raw sealed artifacts let a skeptical judge re-run every verification — I did, and
  100% passed. I have not seen a hackathon artifact built to be *audited* like this.
- **The self-rejecting guardrail.** The flagship run's Thymus log shows the engine's own extract
  helper being denied by its own policy — live, unstaged constraint enforcement captured in the
  audit trail.
- **Honest-negative culture as architecture.** `budget_exhausted` not dressed up as convergence;
  refuted VANKO hypotheses retained; token instrumentation gap admitted; invariant audit shipping
  a "Partially" verdict. This is the exact behavior the event's "honesty over perfection" clause
  is trying to select for.
- **Determinism frame.** Pinning the LLM to orchestration and generating all forensic facts from
  deterministic tools (`inference_constraint: high`) is a defensible, novel answer to the
  hallucination problem — it relocates the problem rather than merely promising to behave.

## D. DRAFT SCORECARD

| # | Criterion | Draft | One-line justification |
|---|---|---|---|
| 1 | Autonomous Execution Quality | ★★★★ 4 | Genuine, natural failures handled and plan re-sequencing all visible in sealed logs; but iterations 2–5 are identical retries and the hypothesis-forming LLM layer is unlogged. |
| 2 | IR Accuracy | ★★★★★ 5 | 4/4 claim traces independently verified to sealed tool executions; structural confirmed-vs-inference labeling; a genuinely self-critical accuracy report with enumerated misses and refuted findings. |
| 3 | Breadth & Depth | ★★★★ 4 | Deep disk+memory+artifact coverage with real cross-modal/cross-host correlation machinery; no network/remote-endpoint modality and memory depth is team-reported. |
| 4 | Constraint Implementation | ★★★★★ 5 | Architectural guardrails verified in code (no write tools; typed pre-exec REJECTs), proven by 61 live REJECTs in the flagship run, plus sealing bound to evidence hashes and a self-critical invariant audit. |
| 5 | Audit Trail Quality | ★★★★★ 5 | I reconstructed the gold runs from logs alone — counts, seals, and 3-way correlations all verified; token usage absent but honestly disclosed; no video to cross-check. |
| 6 | Usability & Documentation | ★★★★ 4 | MCP server deployable today from the README (public wheel verified) with exceptional extension docs; the engine CLI behind the headline runs is not publicly runnable, capping community build-on. |

*(Scores 4–5 across the board are unusual; they are backed by my own re-verification, not the
team's prose — but given the COI above, a neutral judge should re-derive them, and Confidence
Notes below lists exactly which legs rest on team claims.)*

## E. CONFIDENCE NOTES — judgments resting on team claims, not my verification

1. **Recall numbers** (disk 72/72, memory 108/118, per-IOC 156/156) — team's own testing against
   committed fixtures; I did not re-run the agent. Decisive for Criterion 2's last word.
2. **VANKO false-positive figures** (19 → 9 refuted → 10 confirmed) — read from docs, not re-derived.
3. **SRL-2015 multi-host report** (8 sealed runs, 2,233 findings, 15-iteration loops, spinlock.exe
   workstation→DC correlation, "82 claims all cited") — structure observed, claims not traced by me.
4. **Adversarial bypass test cases** in the invariant audit — described in docs; I read the policy
   code but did not execute the bypass attempts.
5. **Demo video content** — nothing to verify; all video-dependent rubric language unassessed.
6. **Live hosted server behavior** (the 60-second connect path) — not exercised.
7. **"4464 tests" and test-suite health** — canonical-facts claim, not run.
8. **Deadline-state of the repo** — reviewed June 12; re-check HEAD as of June 15, 11:45 PM EDT and
   re-confirm no headline artifact (especially the video) lands after it.

## F. FINALIST RE-RUN CHECKLIST

Withheld per instructions — provide it only if you tell me this submission is in your top tier.
(When you do: the re-run should use README Path A + the `[engine,forensics]` extras, the CFReDS
Hacking Case from `reproduce-datasets.md` §1.1 as ground truth, and 3–5 repeat runs on
`base-dc-cdrive.E01` watching variance in findings count, iteration shape, and Thymus REJECT
profile; the team's determinism claim predicts near-zero variance — an easy, falsifiable test.)

---

*Hard-rules compliance: no score reflects prose polish; every Supported verdict above was
re-computed by this reviewer from committed raw artifacts; documented failure modes were scored as
signal. Final scoring discretion belongs to the human judge under the Official Rules.*
