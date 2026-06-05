# Canonical Facts (shared reference)

> **Single source of truth for numeric claims.** Verbatim copy of the canonical-facts table
> from `CANONICAL_FACTS.md` in the source repo, plus load-bearing structural numbers confirmed
> against the code. Any doc that quotes one of these numbers MUST cite this file (or
> `CANONICAL_FACTS.md` upstream). Code wins over docs; this file wins over prose.

Source: `/home/admin2/agentropix-sift/CANONICAL_FACTS.md` (last verified upstream 2026-05-28; row-level dates below).

## Canonical numeric table (verbatim)

| Key | Value | Source | Last verified |
|-----|-------|--------|---------------|
| `test_count` | 4464 | `pytest --collect-only -q 2>/dev/null \| tail -1` | 2026-05-29 |
| `disk_recall_regression` | 72/72 (100%) | `Reports_results/FULL-CASE-20260505T004738Z/SUMMARY.md` §Recall | 2026-05-23 |
| `disk_recall_regression_note` | "post-hoc GT (6 of 7 ground_truth_*.yaml authored from run output); see Methodology" | `samples/SUMMARY.md` Methodology | 2026-05-23 |
| `disk_recall_blinded` | _pending Theme 4 execution_ | `Reports_results/BLIND-LEDGER.md` row 1 | _T-19_ |
| `memory_recall_combined` | 108/118 (91.5%) | `Reports_results/FULL-CASE-20260505T004738Z/SUMMARY.md` §memory | 2026-05-23 |
| `memory_recall_T1003_002` | 30/40 (75%) | same | 2026-05-23 |
| `time_to_decision_manual` | _pending Theme 2 execution_ | `Reports_results/BENCHMARKS/` | _T-19_ |
| `time_to_decision_agentropix` | _pending Theme 2 execution_ | `Reports_results/BENCHMARKS/` | _T-19_ |
| `time_to_decision_delta` | _derived_ | computed from rows above | _T-19_ |
| `last_full_eval_run` | 2026-05-05 | `Reports_results/FULL-CASE-20260505T004738Z/` | 2026-05-23 |
| `mcp_tool_count` | 71 | live `tools/list` + `health.tool_count`; also `_build_app().list_tools()` | 2026-06-02 |
| `rubric_score_self` | 83.83/100 | `docs/SANS-RUBRIC-RE-GRADE-2026-05-23.md` §8 | 2026-05-23 |
| `bmad_synthesis_score` | 75.6/100 (mean), 80/100 (top: Winston+Victor) | bmad-eval-sweep `SYNTHESIS_TEMPLATE.md` §3 | 2026-05-23 |

### MCP tool-count lineage (how 71 was reached)

Per `CANONICAL_FACTS.md`, the count grew incrementally and each step is auditable:
62→63 `get_partitions` (ISSUE-001), 63→64 `get_evt` (ISSUE-008), 64→65 `delete_finding` (ISSUE-014),
65→66 `build_executable_registry` (EAR), 66→69 `promote_executable_registry` + `exec_registry_get` +
`exec_registry_search` (EAR Phase 2), 69→70 `promote_iocs` (BUG-004), 70→71 `retract_approval`
(phantom-approval reconciliation). The decorator count is **74** `@app.tool()` occurrences →
**71 distinct tool functions** (67 in `fastmcp_app.py` + 5 wazuh wrappers; `wazuh_hunt_ioc` is
registered in two modules). Source: `docs/tools/_TOOL-CATALOGUE.md`.

## Confirmed structural numbers (code-derived, this inventory)

| Fact | Value | Where confirmed |
|------|-------|-----------------|
| MCP tool count | **71** distinct tool functions | `CANONICAL_FACTS.md`; `docs/tools/_TOOL-CATALOGUE.md` |
| SIFT forensic tools (the binaries the wrappers drive) | **16** | `README.md:151`; `CHANGELOG.md:449`; the `doctor` tool dict in `src/agentropix_sift/cli.py:176-196` |
| Forensic wrapper modules under `mcp_server/wrappers/` | ~40 wrapper `.py` files driving the 16 SIFT tools + EZ-Tools/correlation/mail | `src/agentropix_sift/mcp_server/wrappers/` |
| Test count | **4464** | `CANONICAL_FACTS.md` (`pytest --collect-only`) |
| Disk recall (regression) | **72/72 (100%)** | `CANONICAL_FACTS.md` |
| Memory recall (combined) | **108/118 (91.5%)** | `CANONICAL_FACTS.md` |
| Python | **3.12+** | seed; repo `pyproject.toml` |
| Standard `SWARM` agent classes (incl. ATT&CK detectors) | **13** classes in the `SWARM` tuple | `src/agentropix_sift/agents/__init__.py` |
| Core swarm specialists (the "7-agent Swarm") | **7**: memory, timeline, filesystem, artifact, discovery, mail, hunt | `src/agentropix_sift/agents/` |
| Critic halt threshold (default) | **0.85** (`AGENTROPIX_CRITIC_HALT_THRESHOLD`) | `src/agentropix_sift/trinity/critic.py:42` |
| Blackboard quorum threshold (default) | **2** | `src/agentropix_sift/agents/_blackboard.py:86` |

> **NOTE on "7-agent Swarm" vs 13 classes.** The seed and project prose describe a *7-agent Swarm*
> — the seven first-class DFIR specialists (Memory, Timeline, Filesystem, Artifact, Discovery, Mail,
> Hunt). The runnable `SWARM` tuple additionally interleaves six deterministic ATT&CK detector
> agents (YARA hunt, injection, null-session baseline, IFEO hijack, IEX loopback C2, svchost
> outbound HTTP) which are also `SwarmAgent` subclasses. Both statements are true; when a count is
> needed, prefer "7 core specialists + ATT&CK detectors" and cite `agents/__init__.py`.

## Authoring rules carried over from `CANONICAL_FACTS.md`

- Never state a number that contradicts the table above.
- A line quoting a canonical number is whitelisted by the upstream drift gate only if it contains
  `CANONICAL_FACTS`, the `{{ref:CANONICAL_FACTS#key}}` citation, or `historical`/`stale`.
- Stale `test_count` values the gate actively rejects: `1270`, `1129`, `1084`, `1073` (and the
  intermediate corrected values `3881`/`3899` are themselves now historical — current is `4464`).
- Forward-drift assertions enforce that `README.md` still contains the literals `4464` and `72/72`.
