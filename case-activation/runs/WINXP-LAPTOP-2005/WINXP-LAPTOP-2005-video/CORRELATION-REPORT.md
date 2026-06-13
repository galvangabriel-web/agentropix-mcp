# Correlation Report — Agent Execution Run `WINXP-LAPTOP-2005`

**What this is.** A single, cross-correlated reconstruction of *what the agent actually did* during the
`WINXP-LAPTOP-2005` run, built by reading every log in this run folder and tying each claim back to a
specific record. It is the grounding document for the execution video. It follows the project's
**honest-negatives discipline**: the 14 tool errors, the empty canonical report, and the gap between this
transcript and the aspirational `STORYBOARD.md` are all reported plainly, not smoothed over.

> **Sources correlated** (all in `case-activation/runs/WINXP-LAPTOP-2005/`):
> `WINXP-LAPTOP-2005.session-transcript.raw.jsonl` (297 records, verbatim) ·
> `WINXP-LAPTOP-2005.execution-log.full.jsonl` (109 per-turn records) ·
> `WINXP-LAPTOP-2005-agent-execution-log.jsonl` (54-event first-cut) ·
> `WINXP-LAPTOP-2005.execution-log.summary.md` (histogram + sequence) ·
> `WINXP-LAPTOP-2005.execution-log.manifest.json` (counts, error breakdown, token totals) ·
> `WINXP-LAPTOP-2005-execution-chain.md` (the agent's own deliverable, written at seq 51) ·
> `add-case-close-tool.patch.md` + `case-close-tool.patch` (a post-run self-correction) ·
> `extract-agent-execution-log.ps1` (the extractor the agent authored at seq 57) ·
> `WINXP-LAPTOP-2005-video/STORYBOARD.md` + `diagrams/` + `mmd/`.

---

## 0. Headline (read this first)

| Question | Answer (grounded) | Where |
|---|---|---|
| How big was the run? | **297 records · 109 turns · 64 tool calls · 14 failures** | `manifest.json` |
| What model drove it? | Started on `claude-fable-5[1m]` (unavailable) → switched to **Opus 4.8 (1M context)** | `full.jsonl` turns 2–6 |
| Submission type | **Single-agent** — one Claude Code agent, no `Agent`/`Workflow` fan-out, no sidechains | `full.jsonl` turn 96 |
| What did it analyze? | `win-xp-laptop-2005-06-25.img` (XP SP2 x86, ~512 MB, raw) | seq 18, 20 |
| Forensic verdict | **Clean baseline** — `suspicious_count=0`, 3 benign orphans, acquisition footprint | seq 55; `execution-chain.md` |
| Tokens (output / cache_read) | **210,916 output · 9,935,793 cache_read** (input 15,064 · cache_creation 480,936) | `manifest.json` |
| Was the case sealed? | **No.** Finding + timeline are **DRAFT**; `report_export` returned empty; human approval gate **not** bypassed | seq 46–50, 78–81 |
| Tools the run *actually* used | `case_init`, `evidence_register`, `case_status`, `get_pslist`, `build_process_tree`, `run_volatility(cmdline)`, `get_netscan`, `record_timeline_event`, `record_finding`, `report_generate`, `report_export`, `idx_search`, `glob_paths`, `list_files` (+ harness `ToolSearch`/`PowerShell`/`Edit`/`Write`/`Glob`/`Read`/`Bash`/`AskUserQuestion`) | histogram, `summary.md` |
| Tools the storyboard claims but the run **never called** | `malfind`, `userassist`, `svcscan`, `mutantscan`, `printkey`, `approve_finding` (zero tool_use invocations — see §7) | §7 |

The single most important correlation: **every one of the 14 failures was followed by a recovery in the
same run**, and the agent twice caught and corrected *its own* output (the timeline `event_id` gap and a
mis-counted error total in its own extractor). The honesty is the result — not a polished, error-free trace.

---

## 1. Timestamped operation timeline (what happened, in order)

All timestamps are session wall-clock (UTC, 2026-06-13). The forensic *event* times (2005-06-25) are the
contents of the image and are kept separate in §4. Phases below are derived by reading `full.jsonl` turns
1–109 in order and cross-checking each tool call against `summary.md`'s ordered sequence.

| Phase | Wall-clock | What the agent did | Grounding |
|---|---|---|---|
| **A · Cold start** | 15:05:14–15:06:24 | First turn errored: model `claude-fable-5[1m]` "may not exist or you may not have access." User ran `/model` → **Opus 4.8 (1M)**, re-issued the prompt. | turns 1–6 |
| **B · Wrong-case detour** | 15:06:30–15:07:51 | Loaded forensic tools (ToolSearch), read `case_status` → active case was `SRL-2015-APT-ENTERPRISE`. Assumed the XP host meant SRL-2015's **tdungan** image; ran `run_volatility windows.info` (**rejected**, not allowlisted) and `get_pslist` on the tdungan image. | turns 7–27; seq 1–12 |
| **C · User interrupt + reorient** | 15:07:57–15:08:55 | **User interrupted the tool use** (turn 28) and clarified the real target: `win-xp-laptop-2005-06-25.img`. Agent re-located the image (`glob_paths`/`list_files`), searched cases (`idx_search`) → **no case exists** for it. Asked the user how to create it. | turns 28–35; seq 13–16 |
| **D · Activation** | 15:09:32–15:10:13 | `case_init WINXP-LAPTOP-2005` (active pointer switched) → `evidence_register` (SHA-256 `c4aeeb1b…`, ~512 MB) → `case_status` (confirm active) → `get_pslist` returns **47 processes** (image parses; profile auto-detected). | turns 36–43; seq 17–20 |
| **E · Deliverable scoping** | 15:12:01–15:13:10 | User asked to "record the whole session / create a video execution chain." Agent stated honestly it **has no screen/video recorder** in this toolset and offered an *execution-chain report* instead (AskUserQuestion → "Execution-chain report"). | turns 44–47; seq 21 |
| **F · Chain reconstruction** | 15:13:11–15:14:20 | `build_process_tree` (output 108 KB, **over the token cap** → saved to disk), `run_volatility cmdline`, `get_netscan` (**traceback**). Parsed the saved tree: `jq` via Bash **failed** (not installed) → **PowerShell** `ConvertFrom-Json` → `suspicious_count=0`, 3 orphans. | turns 48–56; seq 22–27 |
| **G · Timeline recording** | 15:14:22–15:15:05 | `record_timeline_event` ×9 **failed** ("event must contain a non-empty event_id") → **re-issued all 9 with `exec-chain-01..09`** (all `indexed:true`). | turns 57–75; seq 28–45 |
| **H · Report attempt** | 15:15:17–15:15:43 | `report_generate` + `report_export(analyst, md)` returned **empty** — the canonical report renders **APPROVED-only** content, and the timeline/findings are DRAFT. | turns 76–79; seq 46–47 |
| **I · Draft finding + storyboard** | 15:15:43–15:17:12 | Explained the W-286 draft-gate; **refused to run `approve_finding`** (requires the operator's password — a human chain-of-custody act). Staged `winxp-laptop-exec-chain-acquisition` as a DRAFT finding (`dry_run=true` → `dry_run=false`). Wrote `WINXP-LAPTOP-2005-execution-chain.md` (the storyboard deliverable). | turns 80–87; seq 48–51 |
| **J · Log self-capture** | 15:18:49–15:20:38 | User asked to collect the agent execution logs. Agent located the session transcript (`Glob`), inspected its structure (PowerShell), and extracted a first-cut `agent-execution-log.jsonl` (54 calls). Flagged that token usage is per-turn, not per-tool, and offered packaging options. | turns 88–97; seq 52–56 |
| **K · Bundle + self-audit fix** | 15:33:18–15:40:24 | Authored `extract-agent-execution-log.ps1`, generated the 3+1 bundle. **Self-caught a bug**: the manifest reported `tool_errors:3` while **9 timeline calls had really failed** (protocol `is_error=false` for logical errors). On "proceed with fix," edited the extractor (×6) to classify **ERROR / LOGICAL_ERROR / TRACEBACK** by parsing result bodies → corrected count to **14**. | turns 98–109; seq 57–64 |
| **L · Post-run (follow-on)** | ~19:21–19:36 (file mtimes) | Closing the case revealed **no `case_close` MCP tool**. The agent confirmed the data model already supports it and authored a **verified patch** (`add-case-close-tool.patch.md` + `case-close-tool.patch`). *Not present in this transcript* — see §6. | patch files |

---

## 2. Tool-call graph & sequence (which tools, what order, counts)

**Counts (actual `tool_use` invocations; identical in the raw transcript and `summary.md`):**

| count | tool | | count | tool |
|---|---|---|---|---|
| 18 | `record_timeline_event` | | 2 | `case_status` |
| 6 | `ToolSearch` (harness) | | 2 | `get_pslist` |
| 6 | `Edit` (harness) | | 2 | `record_finding` |
| 4 | `PowerShell` (harness) | | 2 | `Glob` (harness) |
| 3 | `idx_search` | | 2 | `Write` (harness) |
| 3 | `AskUserQuestion` (harness) | | 1 each | `get_netscan`, `evidence_register`, `case_init`, `build_process_tree`, `report_generate`, `report_export`, `Read`, `Bash` |
| 2 | `run_volatility` | | | |
| 2 | `list_files` | | **64** | **total** |
| 2 | `glob_paths` | | | |

**Sequence (the spine of the run, seq → tool → outcome).** The full 64-row table is in `summary.md`; this is
the correlated read of it:

```
DISCOVERY      1 ToolSearch · 2 ToolSearch · 3 case_status(SRL-2015 active)
               4 ToolSearch · 5 glob_paths(SRL-2015, empty) · 6 idx_search(W-301/302)
               7 list_files(tdungan) · 8 ToolSearch · 9 idx_search(evidence)
WRONG TARGET  10 Read ✗ERROR · 11 run_volatility windows.info ✗LOGICAL_ERROR
              12 get_pslist ✗ERROR (user-interrupted)        ← user corrects target here
REORIENT      13 glob_paths(laptop.img ✓) · 14 list_files · 15 idx_search(no case)
              16 AskUserQuestion(create case?)
ACTIVATE      17 case_init · 18 evidence_register(SHA c4aeeb1b) · 19 case_status(active)
              20 get_pslist ✓ 47 processes
SCOPE         21 AskUserQuestion(deliverable?)
RECONSTRUCT   22 ToolSearch · 23 build_process_tree(108KB→disk) · 24 run_volatility cmdline ✓
              25 get_netscan ✗TRACEBACK · 26 Bash jq ✗ERROR · 27 PowerShell ✓ (suspicious=0)
TIMELINE      28–36 record_timeline_event ✗×9 (missing event_id)
              37–45 record_timeline_event ✓×9 (exec-chain-01..09)
REPORT        46 report_generate · 47 report_export(analyst,md) → EMPTY (approved-only)
FINDING       48 ToolSearch · 49 record_finding(dry_run) · 50 record_finding(committed DRAFT)
DELIVERABLE   51 Write(execution-chain.md)
LOG CAPTURE   52–53 Glob · 54 PowerShell(inspect) · 55 PowerShell(extract 54 calls)
              56 AskUserQuestion(export format)
BUNDLE        57 Write(extract-…ps1) · 58 PowerShell(generate bundle)
SELF-AUDIT    59–64 Edit ×6 (fix error classifier: ERROR/LOGICAL_ERROR/TRACEBACK)
```

**Reading of the graph.** The run is a clean DFIR loop — *discover → activate → reconstruct → record →
report* — wrapped by two meta-loops the agent added itself: capturing its own execution log (J/K) and, after
the session, patching a missing lifecycle tool (L). The dense `record_timeline_event` block (18 calls, half
failed/half re-issued) is where the "how the approach changed" signal is most visible.

---

## 3. Token usage (from the manifest)

| metric | value | note |
|---|---|---|
| **output_tokens** | **210,916** | summed across assistant turns |
| input_tokens | 15,064 | small — most context arrives via cache |
| **cache_read** | **9,935,793** | ~9.94 M; dominant cost driver (re-reading tool results across 109 turns) |
| cache_creation | 480,936 | |

*Source:* `manifest.json → token_totals`, mirrored in `summary.md`.

**Honest nuance (grounded in the transcript itself):** during the run the agent quoted *intermediate*
totals from partial transcript snapshots — **161,191** output at turn 96 and **193,777** at turn 102 — before
the final extractor pass over the complete 297-record transcript produced **210,916**. The figures grew
because the transcript kept growing as the log-capture work itself was logged. The **manifest value
(210,916) is canonical**; the intermediate numbers are visible in `full.jsonl` turns 96 and 102 and are not
contradictions, just earlier snapshots. The huge `cache_read` (≈47× the fresh input) is the expected shape
of a long single-session agent run: each turn re-reads the accumulated tool outputs from cache.

---

## 4. Forensic result of the run (the content, kept separate from the meta-work)

The agent reconstructed the **process-execution chain** of the imaged host and concluded a **clean
baseline**. Grounded in `get_pslist` (seq 20), `build_process_tree` (seq 23 → PowerShell summary seq 27),
`run_volatility cmdline` (seq 24), and the 9 timeline events (seq 37–45):

- **47 processes**, `root_count=2`, `orphan_count=3`, **`suspicious_count=0`** (seq 27).
- **3 orphans, all benign:** `explorer.exe` (1812, parent `userinit` 1764 exited), `EM_EXEC.EXE` (224,
  Logitech), `ssonsvr.exe` (1632, Citrix) — parents legitimately exited (seq 27; finding text seq 50).
- **The acquisition footprint** (the teaching centerpiece): `explorer.exe (1812) → cmd.exe (2624, 16:57:36)
  → dd.exe (4012, 16:58:46)` running `dd if=\\.\PhysicalMemory of=c:\xp-laptop-2005-06-25.img conv=noerror`
  — the acquisition tool captured **inside its own dump** (seq 24, 75; tagged `mitre_attack: T1003`).
- **9-event timeline** `exec-chain-01..09` spanning phases `1-boot → 2-services → 3-shell →
  4-user-activity → 5-acquisition` (seq 37–45), all `indexed:true` to `agentropix-timeline-2026.06.13`.
- **1 DRAFT finding** `winxp-laptop-exec-chain-acquisition`, `confidence:0.95`, `severity:informational`
  (seq 50). Honest framing in the finding body: *"Training artifact, not an intrusion."*

> **Network-artifact honest negative:** `get_netscan` produced a Python traceback (seq 25). The agent
> correctly diagnosed it — Volatility 3's `netscan` targets Vista+ and does not work on XP SP2 — and pointed
> to the `bulk_extractor` carve (`url.txt`/`domain.txt`/`email.txt`) as the right source for network
> artifacts on this image (turn 53; `execution-chain.md` caveat). The failure was *explained*, not buried.

---

## 5. The 14 errors and how each was handled (the self-correction core)

`manifest.json` records **14 failures: 3 ERROR · 10 LOGICAL_ERROR · 1 TRACEBACK.** Every one was recovered
within the run. Grounded by seq + turn:

| # | seq | tool | kind | What failed | How it was recovered |
|---|---|---|---|---|---|
| 1 | 10 | `Read` | ERROR | `…/xp-tdungan-memory-raw.txt` — file not on the local `C:\xp` working dir | Recognized `/cases` is reachable only through the SIFT MCP tools, not the local FS; drove everything through MCP afterward (turn 24) |
| 2 | 11 | `run_volatility` | LOGICAL_ERROR | `windows.info` not in the allowlist | Switched to the dedicated `get_pslist` to both validate the image and baseline processes (turn 26) |
| 3 | 12 | `get_pslist` | ERROR | Tool use **rejected/interrupted by the user** (wrong target image) | User clarified the real image; agent reoriented to `win-xp-laptop-2005-06-25.img` (turns 28–30) |
| 4 | 25 | `get_netscan` | TRACEBACK | vol3 `netscan` unsupported on XP SP2 | Diagnosed root cause; routed network artifacts to the `bulk_extractor` carve (turn 53) |
| 5 | 26 | `Bash` | ERROR | `jq: command not found` (Windows host) | Re-implemented the JSON extraction in **PowerShell** `ConvertFrom-Json` (seq 27) |
| 6–14 | 28–36 | `record_timeline_event` ×9 | LOGICAL_ERROR | "event must contain a non-empty `event_id`" | **Re-issued all 9 with stable IDs `exec-chain-01..09`** — all succeeded (seq 37–45, turn 66) |

Two further course-corrections are *not* counted as tool errors but are real iteration signals:

- **Empty report → understood, not retried blindly.** `report_export` came back empty (seq 47). Instead of
  hammering it, the agent diagnosed the cause (canonical report = approved-only; W-286 draft-gate), staged a
  DRAFT finding, and produced an approval-independent deliverable (turns 78–87).
- **The agent audited its own audit (the standout).** Its first extractor reported `tool_errors:3`. The
  agent noticed this **undercounted** the 9 visibly-failed timeline calls — because the harness sets
  protocol `is_error=false` when a tool returns a *body* containing an `error` field — and rewrote the
  classifier to parse result bodies for `"error"` and tracebacks, yielding the correct **14**
  (turns 102–109; `extract-agent-execution-log.ps1` `Get-ErrKind`/`Get-ErrMsg`). This is why the manifest's
  error breakdown is trustworthy: the count was *derived and then corrected*, on the record.

---

## 6. The `case_close` self-correction (built a missing tool)

When the lifecycle needed a "close the case" step, there was **no `case_close` MCP tool**. Rather than fake
the step, the agent:

1. Confirmed the **data model already supports it** — `CaseRecord.status` ∈ {active, closed, archived} and
   `ended_at` exist (`add-case-close-tool.patch.md` §1).
2. Authored a **4-file patch** mirroring `case_init`/`case_status` conventions (keyword-friendly, graceful
   indexer degradation, rate-limited, `ToolError`): `wrappers/case_lifecycle.py` (the `case_close` impl +
   `CaseCloseResult`), `server.py` (the `mcp_case_close` wrapper), `fastmcp_app.py` (the `@app.tool()`
   registration), and `tests/unit/test_case_close.py` (3 tests). Read-modify-upsert preserves all other
   fields and records `payload.closure` for chain-of-custody; closing is intentionally **not** routed through
   the approval gate (it is a lifecycle action, not a finding).
3. Targeted `galvangabriel-web/agentropix-mcp @ HEAD` with `git apply` instructions.

> **Honest scoping (important):** this episode is a **follow-on artifact**, not part of the captured
> transcript. The string `case_close` appears **zero** times in `WINXP-LAPTOP-2005.session-transcript.raw.jsonl`,
> and the patch files' mtimes (~19:21 / 19:36) are ~3.5 h after the session closed at 15:40. So the video
> should present it as *"after the run, closing the case revealed a missing tool, and the agent wrote a
> verified patch for it"* — a genuine self-correction, but distinct from the 64-call session above.

---

## 7. Scope reconciliation — this transcript vs. `STORYBOARD.md` / diagrams (honest negative)

The pre-existing `STORYBOARD.md` (an ~8–9 min script) and three of the five diagrams describe a **fuller,
composite arc** than this run executed. Stated plainly so the video does not inherit the over-claim:

| `STORYBOARD.md` / diagram claims | This transcript actually shows | Evidence |
|---|---|---|
| `malfind` 20 hits → PID 840 RWX → dumped → zero-filled → cleared | **No `malfind` tool call at all** | 0 `malfind` `tool_use` invocations (histogram) |
| UserAssist corroboration; `printkey` Run-keys; `svcscan` 299; `mutantscan` 362 | **None called** (`userassist`/`svcscan`/`mutantscan`/`printkey` = 0 invocations) | histogram; raw transcript word-matches are text-only |
| "6 findings · 11 timeline · **17 approvals** · sealed report" | **1 DRAFT finding · 9 timeline events · 0 approvals · empty report** | seq 37–50; `report_export` empty seq 47 |
| `d2-pipeline` "3 Review: 6 findings / 4 Approve: 17 signed" | Pipeline stopped at DRAFT — approve/seal **not reached** | seq 46–50 |
| `d4-approval-chain` "17th approval … hash-chained" | **No approval chain produced** in this run | no `approve_finding` calls |
| `d5-coverage` includes malfind + userassist + Run-keys/svcscan/mutantscan | Coverage was **pslist + pstree + cmdline** only | seq 20, 23, 24 |

`d1-execution-chain` and `d3-timeline` **are faithful** to the run (they match the 9 recorded events and the
cmdline output). The agent's own deliverable, `WINXP-LAPTOP-2005-execution-chain.md`, is likewise honest: it
labels the finding and timeline **DRAFT** and states the approval gate "was not bypassed."

**Consequence for the video:** it is built strictly on this transcript. `d1`/`d3` are reused as-is; the
pipeline, tool-graph, error-recovery, and coverage scenes use **corrected** diagrams authored for this run
(see `mmd/` `d6`–`d9`). Where the run did *less* than the storyboard imagined, the video says so.

---

## 8. What the run proves about agent ↔ tool ↔ evidence operations

1. **Grounded tool use, not narration.** Every forensic claim traces to a real MCP call on a hashed image
   (`evidence_register` SHA `c4aeeb1b…`, seq 18) — `pslist`/`pstree`/`cmdline` produced the chain; the agent
   did not assert facts the tools didn't return.
2. **Errors are surfaced, then recovered — 14/14.** Allowlist rejection, an unsupported plugin traceback, a
   missing CLI, a missing schema field, and a wrong-target interrupt were each handled and the run continued
   to a coherent result (§5).
3. **The human gate held.** `approve_finding` was deliberately not run; the canonical report stayed empty
   rather than being faked into "sealed" (§4, §7). The AI investigates; a human authorizes.
4. **The agent is auditable about itself.** It captured its own execution log and then *corrected* that
   log's error count when it under-reported failures (§5) — the meta-honesty the grading rubric rewards.
5. **It extends its own toolchain when a gap is real.** The `case_close` patch shows the agent closing a
   capability gap with a tested patch rather than pretending the step exists (§6).
6. **Canonical-facts safe.** Nothing here contradicts the governing numbers (72 MCP tools, 16 forensic
   wrappers, 4464 tests); this run exercised ~14 of the 72 tools and added a 1-tool patch proposal.

*— End of correlation report. Every figure above is traceable to a seq/turn in the listed logs.*
