# DFRWS 2005 Rodeo USB — autonomous triage PoC (sealed report)

> **Provenance.** A real `agentropix-sift` engine run executed 2026-06-10 against the
> **DFRWS 2005 Rodeo** USB image (`/cases/nist5/DFRWS2005-RODEO/RHINOUSB.dd`, raw dd, FAT16).
> Same self-host **engine** path (Path B) as the [Jimmy Wilson PoC](../jimmy-wilson-poc/EXECUTED-RUN.md)
> — the full `agentropix-sift` distribution, not the MCP-server package. This run predates the
> Jimmy Wilson recording; only the sealed machine record is published (no video was captured).

## What's here

- **[`report.json`](report.json)** — the sealed machine record: findings, full tool-call trace
  (timestamps + durations), iteration-over-iteration Trinity trace, Thymus audit (30 entries),
  evidence SHA-256, HMAC `report_seal` + `audit_log_seal`.
- **[`report.audit-log.json`](report.audit-log.json)** — the sealed (empty-in-this-run) audit-log
  companion (`audit_log_enabled: false` — engine audit-logging was not switched on for this PoC run;
  honest as captured).
- **[`report.session-key`](report.session-key)** — the per-run HMAC session key, published by explicit
  operator decision (treat as burned): it lets anyone independently re-verify `report_seal` /
  `audit_log_seal`, but the same key can also re-seal a modified report — so the seal is a
  verification/demo artifact here, not a tamper-proof.

## Run summary (from `report.json`)

| Field | Value |
|---|---|
| Evidence | `RHINOUSB.dd` · SHA-256 `ce550424…32be65` |
| Engine result | **9 findings · 68 tool calls · 5 iterations** in ~66 s, status `budget_exhausted`, critic_score 1.0 |
| Trinity trace | iteration 1 runs all 13 agents; the Critic marks 8 **stable**, iterations 2–5 re-run only the 5 gap agents (`timeline`, `filesystem`, `artifact`, `discovery`, `mail`) |
| Inference constraint | `high` (anti-hallucination posture) |

**Honest-negatives note:** this small FAT16 USB image is a low-signal case for a Windows-oriented
agent roster — 8 of the 9 findings are explicit skips/negatives recorded as findings (memory agents
skip a disk-only image, YARA hunt empty, two detector errors), and the 9th is the cross-agent
`hunt.correlate` roll-up (confidence 0.3). Nothing is inflated to look like a detection; that is
the point of publishing this record alongside the higher-signal Jimmy Wilson run.
