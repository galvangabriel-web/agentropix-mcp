<!--
  agentropix-sift • Multi-Tier Report Engine (ADR-024) • TIER 3 — BUSINESS / RISK
  TEMPLATE MOCKUP (templates-first gate). Sample data: SRL-2018 DFIR corpus.
  STRUCTURALLY ALIGNED to the live emitter: render_business_markdown(BusinessView)
  in src/agentropix_sift/reports/markdown.py — H1, legend blockquote, then a SINGLE
  ## Risk Register section: one 8-column table sorted by risk score descending, one
  RiskItem row per finding, each back-anchored to the analyst tier. The business tier
  emits NO quadrant chart, NO gantt, NO per-risk attribute tables, NO compliance
  appendix — the register IS the report. Likelihood uses the FIRST-5 Literal; score is
  the deterministic likelihood_weight x severity_impact_weight product (0..25). NOT live output.
-->

# Business / Risk Report — SRL-2018

> **Likelihood scale (FIRST 5-tier):** almost_certain > highly_likely > likely > unlikely > remote. Likelihood estimates the probability of the assessed activity; it is kept separate from analytic confidence.
>
> **Confidence (LCA):** high / moderate / low — the analyst's confidence in the assessment given evidence quality and corroboration. Distinct from likelihood.

## Risk Register

| Risk | Likelihood | Severity | Score | Business impact | Compliance | Owner | Analyst ref |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Domain controller fully compromised — bi-daily service persistence + terminal C2 (base-dc) | highly_likely | critical | 20 | Catastrophic: control of the DC is control of every domain identity; trust in all credentials is void until a krbtgt double-reset completes. | NIST 800-53 AC-2/IA-5, ISO 27001 A.5.17, PCI-DSS 8.3, GDPR Art.32 | Identity / AD | [F-01](#dc-persistence) |
| Pass-the-hash domain traversal across the DMZ→internal boundary | highly_likely | critical | 20 | Catastrophic for identity: any replayed credential is a standing re-entry key; the flat DMZ→internal trust converts one FTP foothold into domain compromise. | NIST 800-53 IA-5/SC-7, ISO 27001 A.5.17/A.8.22, PCI-DSS 1.3/8.3.1 | Identity / Network | [F-02](#pass-the-hash) |
| Active C2 channel live at the edge of collection (36s jitter-free beacon) | highly_likely | critical | 20 | High: an active operator held a live channel out of the network at containment; unconfirmed exfil keeps a disclosure-liability tail. | GDPR Art.33/34, NIS2, PCI-DSS 10.x | SOC + Legal/DPO | [F-03](#c2-beacon) |
| Six persistent backdoor local accounts on dmz-ftp | highly_likely | high | 16 | High: standing re-entry vector that survives credential resets; must be removed before any all-clear. | NIST 800-53 AC-2, ISO 27001 A.5.16, PCI-DSS 8.1.3 | DMZ / infra ops | [F-04](#backdoor-accounts) |
| Scheduled-task / service persistence on the DC (3 rotations) | highly_likely | high | 16 | High: durable re-entry independent of the C2 beacon; presence beyond base-dc inferred, not yet enumerated. | NIST 800-53 SI-4, ISO 27001 A.8.16 | SOC / threat hunt | [F-05](#sched-task-persistence) |
| Credential harvesting in DC memory (findstr against credential stores) | likely | high | 12 | High: any secret recovered from the DC is a re-entry key; folds into the estate-wide credential rotation. | NIST 800-53 IA-5, ISO 27001 A.5.17, PCI-DSS 8.3.1 | Identity / endpoint | [F-06](#cred-harvest) |
| Host / process reconnaissance on the DC (tasklist) | likely | medium | 9 | Medium: deliberate target selection on the DC raises credibility of follow-on actions. | NIST 800-53 SI-4, ISO 27001 A.8.16 | SOC engineering | [F-07](#process-recon) |
| Defense evasion — event-log manipulation alongside DKOM unlinking | likely | medium | 9 | Medium: degrades timeline completeness and inflates analytic uncertainty across the case. | NIST 800-53 AU-9, ISO 27001 A.8.15 | SOC engineering | [F-08](#defense-evasion) |
| Detection / audit-visibility gap — no EID 4688 command-line auditing | likely | medium | 9 | Medium: slow detection multiplies every other finding's blast radius; highest-leverage detective control to add. | NIST 800-53 AU-2/AU-12/SI-4, ISO 27001 A.8.15/A.8.16, PCI-DSS 10.x | SOC engineering | [F-09](#audit-gap) |

<!--
  RISK SCORE DERIVATION (view_models.py) — risk_score = LIKELIHOOD_WEIGHT x
  SEVERITY_IMPACT_WEIGHT, capped 0..25, sorted descending so the register reads
  worst-first:
    LIKELIHOOD_WEIGHT  almost_certain=5 highly_likely=4 likely=3 unlikely=2 remote=1
    SEVERITY_IMPACT    critical=5 high=4 medium=3 low=2 info=0  (info -> 0 so an
                       informational finding can never inflate risk)
    F-01/02/03  highly_likely(4) x critical(5) = 20
    F-04/05     highly_likely(4) x high(4)     = 16
    F-06        likely(3)        x high(4)     = 12
    F-07/08/09  likely(3)        x medium(3)   =  9
  NOTE the score here is the business product (0..25); the analyst tier's per-finding
  "Risk score" is the same product on the same scale — both come from the one finding set.

  NO-DRIFT CONTRACT (ADR-024): every Analyst ref cell is an [F-NN](#anchor) link that
  resolves into analyst.md — no synthesized risks, every register row back-anchors to a
  real APPROVED analyst finding. Compliance refs are RiskItem.compliance_refs joined
  with ", "; Owner is RiskItem.remediation_owner; both print "—" when unset. Anchors:
    #dc-persistence #pass-the-hash #c2-beacon #backdoor-accounts
    #sched-task-persistence #cred-harvest #process-recon #defense-evasion #audit-gap
-->
