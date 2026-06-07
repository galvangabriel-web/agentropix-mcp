<!--
  agentropix-sift • Multi-Tier Report Engine (ADR-024) • TIER 2 — EXECUTIVE
  TEMPLATE MOCKUP (templates-first gate). Sample data: SRL-2018 DFIR corpus.
  STRUCTURALLY ALIGNED to the live emitter: render_executive_markdown(ExecutiveView)
  in src/agentropix_sift/reports/markdown.py — H1, then ## Key Performance Indicators
  (the fixed 6-row KPI table + an optional "Top tactics" line), then
  ## Critical & High Findings as back-anchored bullets in the exact
  "[title](#anchor) (severity) — business_impact _(see analyst finding `id`)_" shape.
  The executive tier emits NO prose narrative, NO storyboard, NO remediation table —
  those live in the Business tier. KPI values are deterministic rollups over the
  APPROVED finding set; each bullet's anchor resolves into analyst.md (no-drift). NOT live output.
-->

# Executive Summary — SRL-2018

## Key Performance Indicators

| Metric | Value |
| --- | --- |
| Approved findings | 9 |
| Critical | 3 |
| High | 3 |
| Affected hosts | 6 |
| Unique ATT&CK techniques | 10 |
| Dwell time (days) | 143.0 |

**Top tactics:** Persistence, Lateral Movement, Credential Access, Command & Control, Defense Evasion

<!--
  KPI DERIVATION (KPIRollup, view_models.py) — every number is computed from the
  canonical finding set, not authored:
    approved_finding_count = COUNT(findings)                         -> 9 (F-01…F-09)
    critical_count         = COUNT(severity == "critical")          -> 3 (F-01,F-02,F-03)
    high_count             = COUNT(severity == "high")              -> 3 (F-04,F-05,F-06)
    affected_host_count    = COUNT(DISTINCT host across evidence)   -> 6
        (dmz-ftp, base-dc, base-rd-01, pdo-win2016, MICROSO-8N79483, base-ftp)
    unique_technique_count = COUNT(DISTINCT mitre_techniques)       -> 10
        (T1190, T1550.002, T1021.002, T1543.003, T1053.005,
         T1136.001, T1071, T1070.001, T1057, T1552.001)
    dwell_time_days        = last_event - first_event              -> 143.0
        (2018-03-14 20:48Z  ->  2018-09-07 21:23:15Z)
    top_tactics            = most-frequent kill-chain phases (rendered only if non-empty)
  The KPI table is fixed-shape (6 rows always present); dwell_time_days prints "n/a"
  when first/last events are absent. medium/low findings (F-07,F-08,F-09) are counted
  in approved_finding_count but do NOT appear in the Critical & High list below.
-->

## Critical & High Findings
- **[Domain controller fully compromised — bi-daily service persistence + terminal C2 (base-dc)](#dc-persistence)** (critical) — Catastrophic: control of the DC is control of every domain identity; trust in all credentials is void until a krbtgt double-reset completes. _(see analyst finding `F-01`)_
- **[Pass-the-hash domain traversal across the DMZ→internal boundary](#pass-the-hash)** (critical) — Catastrophic for identity: any credential the actor replayed is a standing re-entry key; the flat DMZ→internal trust converts one FTP foothold into domain compromise. _(see analyst finding `F-02`)_
- **[Active C2 channel live at the edge of collection (36s jitter-free beacon)](#c2-beacon)** (critical) — High: an active, capable operator held a live channel out of the network; assume intent to exfiltrate or extort. _(see analyst finding `F-03`)_
- **[Six persistent backdoor local accounts on dmz-ftp](#backdoor-accounts)** (high) — High: standing re-entry vector that outlives credential resets; must be removed before eradication can be declared complete. _(see analyst finding `F-04`)_
- **[Scheduled-task / service persistence on the DC (3 rotations)](#sched-task-persistence)** (high) — High: durable re-entry independent of the C2 beacon; killing the beacon alone does not evict the actor. _(see analyst finding `F-05`)_
- **[Credential harvesting in DC memory (findstr against credential stores)](#cred-harvest)** (high) — High: any secret recovered from the DC is a re-entry key; reinforces the assume-all-credentials-exposed posture. _(see analyst finding `F-06`)_

<!--
  NO-DRIFT CONTRACT (ADR-024): each bullet is an ExecutiveItem projected from one
  analyst Finding — the [...](#anchor) target and the `F-NN` citation both resolve
  into analyst.md, so no executive claim can drift from its technical proof. The
  bullet text after "—" is the finding's verbatim business_impact field; the
  parenthesised severity is the finding's severity. Items are the critical+high
  subset only, in analyst order. Anchors referenced:
    #dc-persistence #pass-the-hash #c2-beacon
    #backdoor-accounts #sched-task-persistence #cred-harvest
-->
