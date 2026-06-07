# 06 · Use Cases

Worked end-to-end scenarios, dual-audience (expert command + end-user prompt), plus the per-case attack-chain hypotheses that guide tool selection.

## Read in this order

1. [uc-disk-triage.md](uc-disk-triage.md) — triage an E01 disk image start to finish (the canonical first use case).
2. [uc-memory-triage.md](uc-memory-triage.md) — triage a memory dump with the Volatility-backed agents.
3. [uc-approval-gate.md](uc-approval-gate.md) — review findings and approve them before anything is sealed (examiner path).
4. [uc-wazuh-push.md](uc-wazuh-push.md) — escalate an APPROVED finding to Wazuh as an alert (experimental integration).
5. [demo-walkthrough.md](demo-walkthrough.md) — a single end-to-end run, beat by beat, mapped to the Devpost rubric with runtime evidence (judge-facing).
6. [case-hypotheses.md](case-hypotheses.md) — for each in-scope test case, the likely attack chain and which tools confirm/refute each link (bias-checks, not findings).
7. [command-cheatsheet.md](command-cheatsheet.md) — every command exercised across the pages above, in execution order, on one page (quick reference).
8. [case-runbook-srl-2018.md](case-runbook-srl-2018.md) — the cheatsheet applied to the real SRL-2018 case (`/cases/SRL-2018/`) with verified evidence paths, hashes, and the C2-cascade hypothesis.
