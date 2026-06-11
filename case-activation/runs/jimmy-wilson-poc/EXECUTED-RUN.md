# Jimmy Wilson — autonomous triage (EXECUTED, recorded)

> **LOCAL / OPERATIONAL.** A real `agentropix-sift` engine run captured live on 2026-06-11 against
> the **Jimmy Wilson** study case (`2020JimmyWilson.E01`, NTFS disk). This is the self-host **engine**
> path (Path B) — the full `agentropix-sift` distribution, not the MCP-server package.

## The recorded session — [`POC-RUN.mp4`](POC-RUN.mp4)

```bash
uv sync                                                          # 1. install the orchestration layer
uv run agentropix-sift doctor                                   # 2. pre-flight — all 16 SIFT tools OK
uv run agentropix-sift run "/cases/study case/2020JimmyWilson.E01" -o report.json   # 3. triage
```

| Step | Result |
|---|---|
| `uv sync` | dependencies resolved |
| `doctor` | **All tools available** — the 16 SIFT binaries (vol, fls/mmls/icat, ewfinfo, evtx_dump, yara, bulk_extractor, rip.pl, EZ-Tools, …) resolve on PATH |
| `run` | **129 findings · 86 tool calls · 5 iterations**, sealed `report.json` (HMAC) + audit-log, evidence SHA-256 `6c18f662…`, status `budget_exhausted`, critic_score 1.0 |

## Structured execution logs (the agent-execution-log deliverable)

- **[`EXECUTION-LOG.md`](EXECUTION-LOG.md)** — the three reviewer views: tool execution (timestamps +
  durations), the **iteration-over-iteration** Trinity-Loop trace (iteration 1 runs all 13 agents;
  iterations 2–5 run only the 2 still finding new evidence after the Critic marks 11 **stable**), and
  agent / Blackboard activity (TimelineAgent 111 findings over 510,498 Plaso rows; HuntAgent 7 cross-source
  correlations; MITRE `T1070.006`×62, `T1059`×29, `T1547.001`×6, …).
- **[`report.json`](report.json)** — the sealed machine record (`trace.tool_calls[]`, `iterations[]`,
  `thymus_audit`, seals, evidence binding).
- **[`blackboard-events.jsonl`](blackboard-events.jsonl)** — derived timestamped agent publish/correlation
  events.
- **[`report.audit-log.json`](report.audit-log.json)** — the HMAC-sealed audit-log companion.

**Token usage:** not collected, by design (LLM is the edge orchestrator; facts come from deterministic
tools) — see `EXECUTION-LOG.md` §4. The per-run HMAC **session key is withheld** (the one secret), so the
seals are inspectable but not independently re-verifiable here.
