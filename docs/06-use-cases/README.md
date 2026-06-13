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
9. [SRL-2018 Forensic Report](../12-CASES-REPORTS/srl-2018-report/SRL-2018-FORENSIC-REPORT.md) + [Technical Appendix](../12-CASES-REPORTS/srl-2018-report/TECHNICAL-APPENDIX.md) — where the runbook's live executions ended up: the **published sealed case report** (netscan/malfind/evtx depth, diagrams, recorded-session video). The early standalone execution demos (memory image ~6 min / 12 findings; full DC E01 ~100 min / **252 findings**, both sealed) were superseded by this report and removed in commit `32173fe` — git history retains them.
10. [reproduce-datasets.md](reproduce-datasets.md) — get the public evidence datasets (real upstream download URLs + provenance) so a judge can re-run; honest note on the non-redistributable cases.
11. [demo-script.md](demo-script.md) — the upstream 3-minute hackathon demo script (BMAD-M8) for the SANS Sunlight AI judging panel: five ~30-35s beats, with the three engine-repo cast variants tuned to different judging windows.

## Training-session recordings (`assets/`)

Curated companions to the action-recorded training sessions (cast → MP4 + GIF + transcript + a technical MD); raw output/casts/logs stay out of git.

- [srl-2018-training-session/](assets/srl-2018-training-session/README.md) — SRL-2018 "Compromised Enterprise" action-recording index (every command + response captured verbatim for training), plus its [attack-chain workflow](assets/srl-2018-training-session/ATTACK-CHAIN-WORKFLOW.md) reconstructing the whole-estate chain anchored on the `p.exe` DNS-tunneling C2 implant.
- [srl-2015-training-session/](assets/srl-2015-training-session/README.md) — SRL-2015 (SANS FOR508 Stark Research Labs APT, 4 Windows hosts) action-recording index modelled on the srl-2018 format, plus its [attack-chain workflow](assets/srl-2015-training-session/ATTACK-CHAIN-WORKFLOW.md) (15 numbered actions: backfilled initiation/memory phase + the live deeper-phase slice).
