# Use Case — Guided Demo Walkthrough (Judge-Facing)

> **Actor:** a SANS / Devpost judge (or any evaluator) being walked through a single live triage run.
> **Goal:** Map a guided, end-to-end demonstration to the Devpost rubric (D1 autonomous execution,
> D5 audit trail, D2 accuracy, D3 breadth) using only runtime evidence that is verifiable in the
> source tree — the completion-promise tokens emitted on a real run, the self-correction iteration
> log, the verbatim Thymus REJECT strings, and the mail-domain recovery numbers.
> **Surfaces exercised:** the `agentropix-sift run` CLI (`src/agentropix_sift/cli.py`), the Trinity
> orchestrator (`src/agentropix_sift/orchestrator.py`), the ATT&CK detectors
> (`src/agentropix_sift/detectors/`), the Thymus read-only gate
> (`src/agentropix_sift/mcp_server/thymus_policy.py`), and the courtroom seal. See
> [`.crew/facts.md`](../../.crew/facts.md) for every numeric claim.

This page is the narrated counterpart to the reference use cases. Where
[uc-disk-triage.md](uc-disk-triage.md) and [uc-memory-triage.md](uc-memory-triage.md) describe the
tool sequences, this walkthrough threads them into one demonstration a judge can follow beat by
beat, with each beat landing a specific rubric dimension. The beat structure is imported from the
upstream demo script (`docs/DEMO-SCRIPT.md` in the main repo, BMAD-M8 era); every claim below is
re-anchored to the source it can be checked against.

> **Honest note on recorded media.** Two captioned-MP4 recording attempts were made and **both were
> withdrawn by the operator as incorrect**; the MP4/GIF render artifacts were deleted. This
> walkthrough is therefore a **text artifact only** — the narrated structure plus the in-code
> evidence, not a video link. The narration script and the in-code tokens remain canonical and
> ready for a future recording attempt. (Provenance: the upstream `docs/DEMO-SCRIPT.md` describes
> the three asciinema casts; the withdrawn captioned renders are not judge-facing.)

---

## The numbers this demo speaks in

Everything narrated below uses the canonical figures — never invent a competing count on screen.

| Claim shown on screen | Canonical value | Source |
|---|---|---|
| MCP tools | **71** distinct tool functions | [`.crew/facts.md`](../../.crew/facts.md); `docs/tools/_TOOL-CATALOGUE.md` |
| SIFT binaries the wrappers drive | **16** | [`.crew/facts.md`](../../.crew/facts.md); `cli.py` `doctor` dict |
| Core swarm specialists | **7** (memory, timeline, filesystem, artifact, discovery, mail, hunt) | `agents/__init__.py` |
| ATT&CK detector agents (interleaved in `SWARM`) | **6** | `detectors/`; `agents/__init__.py` |
| Test count | **4464** | [`.crew/facts.md`](../../.crew/facts.md) |
| Critic halt threshold (default) | **0.85** | `trinity/critic.py:42` |
| Disk recall (regression) | **72/72 (100%)** | [`.crew/facts.md`](../../.crew/facts.md) |
| Memory recall (combined) | **108/118 (91.5%)** | [`.crew/facts.md`](../../.crew/facts.md) |

> **Reconciliation.** Earlier demo drafts said "46 MCP tools" and "an 11-agent swarm." The
> source-of-truth count is **71 tools** and **7 core specialists + 6 ATT&CK detectors** — use those.
> The "11" figure was a per-run plan size, not the agent roster; the "46" figure predates the tool
> growth documented in [`.crew/facts.md`](../../.crew/facts.md) §"MCP tool-count lineage."

---

## Beat map — demo to Devpost rubric

```mermaid
flowchart TD
    B0["Beat 0 — the 3 AM incident<br/>(sets the stakes)"]
    B1["Beat 1 — one-liner invocation<br/>agentropix-sift run image --max-iterations 5"]
    B2["Beat 2 — 4-layer build runs visibly<br/>swarm + detectors fan out, 6 promise tokens"]
    B3["Beat 3 — self-correction loop<br/>iter1 CONTINUE then iter2 HALT, stable-agent drop"]
    B4["Beat 4 — finding to tool to replay<br/>_source + args_hash + raw_output"]
    B5["Beat 5 — seal verify then tamper<br/>HMAC-SHA256 green then red mismatch"]
    B6["Beat 6 — mail-domain T1566<br/>pypff 10 of 544 then pffexport 534 of 544"]

    B0 --> B1 --> B2 --> B3 --> B4 --> B5 --> B6
    B3 -.lands.-> D1["D1 autonomous execution"]
    B4 -.lands.-> D5["D5 audit trail"]
    B5 -.lands.-> D5
    B6 -.lands.-> D2D3["D2 accuracy + D3 breadth"]
    B2 -.lands.-> D3

    style D1 fill:#e8f6f3,stroke:#117a65
    style D5 fill:#fff4e1,stroke:#d68910
    style D2D3 fill:#eaf2f8,stroke:#2874a6
```

| Beat | Rubric dimension | What the judge sees | Verifiable in |
|---|---|---|---|
| 0 | sets stakes | The 3 AM Tier-2 triage problem | `docs/DEMO-SCRIPT.md` Beat 1 |
| 1 | D6 usability | One command, no setup wizard | `cli.py` `run` subcommand |
| 2 | D3 breadth | 7 specialists + 6 detectors, the 6 promise tokens | `orchestrator.py`; `detectors/` |
| **3** | **D1 autonomous execution** | iter1 CONTINUE then iter2 HALT, `pslist→psscan` fallback | `orchestrator.py`; `volatility.py:1339` |
| **4** | **D5 audit trail** | `_source` + `args_hash` + `raw_output` linkage | `schema/report.schema.json` |
| **5** | **D5 audit trail** | seal verify green, tamper red mismatch | `scripts/verify_seal.py` |
| **6** | **D2 + D3** | mail recovery 10/544 then 534/544 (98.2%) | `_mail_parsers.py` (W-229) |

---

## Beat 0–1 — the problem, then the one-liner

The cold open frames the cost: a Tier-2 analyst paged at 3 AM with a compromised Windows domain
controller, a disk image and a memory dump, and one hour before the IR lead expects findings — today
that means running plaso, Volatility, Sleuth Kit, RegRipper and YARA by hand and mentally joining
their outputs. The demo's answer is a single command:

```bash
agentropix-sift run /evidence/srl2018/win2008r2-controller-memory.001 --max-iterations 5
```

Behind that one line the CLI hashes the evidence (so the report binds to the bytes), validates every
path against the operator-defined read-only zones (the Thymus gate, Beat 5), and launches the Trinity
Loop over the swarm. There is no profile to select. (`src/agentropix_sift/cli.py`.)

---

## Beat 2 — the 4-layer build runs visibly (D3 breadth)

The four layers of the stack run in order: the **deterministic SIFT toolkit** (16 binaries) under
the **typed MCP surface** (71 tools), driven by the **7-agent swarm + 6 ATT&CK detectors**, all
wrapped in the **courtroom envelope** (Beat 5). The proof that each agent actually contributed is the
**completion-promise token** it emits — one snake-case token per agent that successfully published at
least one finding this run, appended to `report.completion_proofs[]` and sorted for diff-stability.
A verifier can fail a run that delivered findings but is missing a required promise
(`src/agentropix_sift/schema/report.schema.json`; the emit logic is `orchestrator.py:194-195` —
`if findings and agent.completion_promise: completion_proofs.add(...)`).

On a real memory run, the six tokens emitted are:

| Promise token | Emitting agent / detector | Source |
|---|---|---|
| `CROSS_AGENT_CORRELATION_DONE` | HuntAgent (cross-modal correlation) | `agents/hunt.py:70` |
| `INJECTION_DETECTION_COMPLETE` | injection detector | `detectors/injection_detector.py:251` |
| `MEMORY_TRIAGED` | MemoryAgent | `agents/memory.py:538` |
| `T1059_001_IEX_LOOPBACK_SCAN_COMPLETE` | IEX loopback C2 detector | `detectors/t1059_001_iex_loopback_c2.py:436` |
| `T1546_008_ACCESSIBILITY_IFEO_HIJACK_COMPLETE` | IFEO accessibility-hijack detector | `detectors/t1546_008_accessibility_ifeo_hijack.py:619` |
| `YARA_HUNT_COMPLETE` | YARA hunt detector | `detectors/yara_hunt.py:164` |

> **Why these six and not the disk set.** The disk-triage path emits a different token set
> (`TIMELINE_GENERATED`, `ARTIFACTS_PARSED`, `FILESYSTEM_WALKED`, …; `cli.py` `_REQUIRED_PROMISES`).
> A pure memory run does not walk a filesystem, so its promise set reflects the memory + detector
> specialists that fired. Both are correct — the token list is a function of which agents published
> findings, not a fixed banner.

---

## Beat 3 — the self-correction loop (D1 autonomous execution)

This is the beat the rubric's autonomous-execution dimension is scored on. The orchestrator runs the
**Architect → Swarm → Critic** loop; the Critic scores the accumulated findings and either
**CONTINUEs** (re-plan, drop the agents whose contribution sets plateaued) or **HALTs** when the
score crosses the **0.85** threshold (`trinity/critic.py:42`, `_DEFAULT_HALT_THRESHOLD = 0.85`, with
`_DEFAULT_MIN_ITERATIONS = 2`).

The iteration log shape the judge watches:

```text
Iteration 1: plan=[memory, timeline, artifact, filesystem, hunt, <detectors>]
  → memory.injection malfind hit on rundll32.exe (T1055)
  → memory.persistence.registry HKLM\...\Run\Updater (T1547.001)
  → timeline.plaso 4624 logon as DOMAIN\Administrator (T1078)
  Critic score 0.82  (threshold 0.85)  →  CONTINUE  (drop stable agents)

Iteration 2: plan=[hunt]    ← memory / timeline / artifact stable, dropped
  → hunt.correlation new cross-modal token → previously-unseen join
  Critic score 0.94  (threshold 0.85)  →  HALT  (status=complete, 2 iter)
```

Two distinct self-corrections are visible:

1. **Stable-agent drop (the planner reallocates compute).** Agents whose contribution sets stopped
   changing are dropped from the next plan, so the remaining budget is spent only on agents still
   surfacing new material. The halt decision itself is a pure-Python state machine — deterministic
   and unit-testable, no LLM in the halt path (`trinity/critic.py`).

2. **`pslist → psscan` fallback inside the MemoryAgent.** When the memory dump is a paused-VM
   snapshot, `windows.info` reports `KeNumberProcessors=0` and the list-walking plugins silently
   return empty rows; the agent falls through to pool-scan plugins. The wrapper makes this concrete:
   *"pslist returned 0 processes (corrupted ActiveProcessLinks); falling back to psscan (pool tag
   scanning)"* — `mcp_server/wrappers/volatility.py:1339`, with the pre-flight rationale at
   `agents/memory.py:7-10` and `wrappers/volatility.py:236`. The result row carries
   `used_fallback=True` (`volatility.py:172`) so the self-correction is itself audited.

---

## Beat 4 — finding → tool → replay (D5 audit trail)

Every finding carries a `_source` field naming the MCP tool that produced it, and every tool call is
recorded in the report's trace with the SHA-256 of its arguments (`args_hash`), the `exit_code`, the
`duration_ms`, and the binary's `raw_output` captured **before** any LLM summarizes it
(`schema/report.schema.json`; the `@traced` span in `docs/DEMO-SCRIPT.md`'s architecture diagram).

```bash
# Pivot from a finding to the exact tool call that produced it:
jq '.findings[] | select(._source=="memory.injection")' report.json
jq '.trace.tool_calls[] | select(.args_hash=="f7e2c4d8...")' report.json
```

The replay story: extract a finding's `args_hash`, find the matching trace entry, and re-invoke the
tool with those exact arguments — the binary's output should match the recorded `raw_output`
byte-for-byte. The replay is deterministic because the facts come from the SIFT tools, not the model
(`inference_constraint=high` in the report; the ADR-016 design statement: *the AI orchestrates; the
SIFT tools generate the facts*).

---

## Beat 5 — seal verify, then tamper (D5 audit trail, continued)

The report is sealed with **HMAC-SHA256** under a per-run key written to a mode-`0600` file
(`<report>.session-key`); the audit log is independently sealed and cross-bound into the report seal,
so swapping the audit log post-run breaks the report seal too. Verification is a dependency-free
Python script a judge runs on any machine:

```bash
$ python scripts/verify_seal.py report.json
Recomputing HMAC-SHA256 over canonical JSON ...
✓ Seal verified — report not tampered since SIFT wrote it.

$ jq '.findings += [{"_source":"FAKE","confidence":1.0,"description":"fabricated"}]' \
       report.json > tampered.json
$ python scripts/verify_seal.py tampered.json
✗ Seal MISMATCH — report has been altered. Reject as evidence.
```

Green tick on the untouched report; instant red mismatch the moment a fabricated finding is injected.
The chain-of-custody story is a script you can run, not a marketing claim
(`scripts/verify_seal.py`; `docs/DEMO-SCRIPT.md` Beat 4).

---

## Beat 6 — mail-domain T1566 end-to-end (D2 accuracy + D3 breadth)

The mail domain is where the accuracy story is most concrete, because it is a measured recovery on a
real PST. On the SRL-2015 nromanoff corpus (544 messages total):

| Stage | Engine | Messages recovered | Source |
|---|---|---|---|
| Baseline | stock `pypff` | **10 / 544** clean (6 attachment-bearing) | W-218, PR #128 `f711f168b` |
| Recovery | `pffexport` subprocess + dedup | **534 / 544** (98.2%) — 10 pypff + 524 pffexport, 15 deduped | W-229, PR #129 `a8703fac9` |

That is a **53× coverage improvement** over the pypff-only path (W-229). The 534 messages are
unique-after-dedup (`_dedup_key = (subject[:1024], sender, normalized_date)`), and recovered messages
carry `parser_note="pffexport_recovered:synthesized_eml"` for chain-of-custody. The recovery has a
kill switch (`AGENTROPIX_MAIL_RECOVERY_ENABLED`, W-230) and a **byte-identity audit**
(`TestPffexportByteIdentityAudit`, W-231, PR #132 `00d13dc8b`) that asserts a SHA-256 match between
the `pypff.read_buffer()` and `pffexport` file-write paths for the shared messages — the strongest
chain-of-custody proof for the mail domain. (All numbers anchor to the merged PRs in the main repo's
`docs/SIFT-WEAKNESSES.md` ledger; 534/544 = 98.2%.)

This lands T1566 (Phishing): the recovered attachments are the IOC surface the `carve_pst_iocs` tool
(W-210, PR #133) turns into hash-pivotable forensic rows.

---

## See also

- [uc-disk-triage.md](uc-disk-triage.md) — the disk path narrated in Beats 1–5.
- [uc-memory-triage.md](uc-memory-triage.md) — the Volatility memory path and the `pslist→psscan`
  fallback shown in Beat 3.
- [uc-approval-gate.md](uc-approval-gate.md) — the DRAFT → APPROVED → sealed spine behind Beats 4–5.
- [`.crew/facts.md`](../../.crew/facts.md) — every numeric claim on this page (71 tools, 16 SIFT
  binaries, 4464 tests, 72/72 disk recall, 108/118 memory recall, halt threshold 0.85).
- [`.crew/agents-list.md`](../../.crew/agents-list.md) — the 7 core specialists + 6 ATT&CK detectors
  whose promise tokens land in Beat 2.
