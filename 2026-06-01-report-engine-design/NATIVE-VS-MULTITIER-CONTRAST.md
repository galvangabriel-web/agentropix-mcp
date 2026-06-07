# NATIVE `report_generate` JSON vs. Multi-Tier Rendered Reports — Per-Case Contrast

**Date:** 2026-06-07 · **Scope:** local-only (`2026-06-01-report-engine-design/`, gitignored — nothing pushed)

This contrasts the **native** `report_generate` JSON profiles (`full`, `executive`, `findings`, `ioc`,
`timeline`, `status`) against the **multi-tier** rendered reports under
[`generated/`](generated/) (the `analyst` / `executive` / `business` tiers produced by
`report_export{tier,fmt,case_id}`).

- **Native side (this exercise):** all six profiles were run **live** for each of the four cases via
  `/tmp/mcpcli/call.mjs` (Bearer token from `/home/admin2/agentropix-sift/.env`, MCP endpoint on
  `<TAILNET-HOST>:8765/mcp`) on 2026-06-07. Raw captures live under `/tmp/native-reports/<CASE_ID>.json`.
- **Multi-tier side:** the previously-generated `generated/<slug>/{analyst,executive,business}.md`
  (+ `.html`, `.json` section bundles). Both sides read the **same** approved-finding set from the
  case's findings index, so the row-for-row counts below align.
- **Oracle:** native profiles → `src/agentropix_sift/mcp_server` `report_generate`; tiers →
  `src/agentropix_sift/reports/{transformers,view_models,markdown,render,export}.py` and
  `mcp_server/server.py::mcp_report_export`. `report_export` internally calls
  `report_generate(profile="full")`, then projects to a tier via `build_tier_bundle` (no-drift validated).

> **How to read this page (real-data preface).** Every count below is real, captured from the live MCP.
> The approved-finding sets grew between the original 2026-06-06 demo runs (`runs/<slug>/EXECUTED-RUN.md`,
> 1 approved finding each) and this 2026-06-07 reporting exercise: additional real findings/IOCs were
> recorded and approved on the two profileable Windows cases. So `CHALLENGE-NOTCHITUP` now seals **5**
> approved findings (was 1) and `AMF-WIN-SAMPLE001` **6** (was 1); the two unprofileable cases still
> carry exactly **1** honest-negative finding. The tables reflect the current sealed state, which is why
> they differ from the single-finding EXECUTED-RUN.md snapshots.

---

## Native profile shapes (common to every case)

| Native profile | Top-level `approved_finding_count` | `sections.*` keys | What it surfaces |
|----------------|-----------------------------------|-------------------|------------------|
| `full`      | = approved findings | `executive_summary` + `findings` + `timeline` + `iocs` | Everything: the union of all other profiles in one envelope. |
| `executive` | = approved findings | `approved_finding_count`, `top_tactics`, `top_hosts`, `severity_mix` | Roll-up counts only — no per-finding bodies. |
| `findings`  | = approved findings | `approved_findings[]`, `count` | The full approved-finding records (with `hmac_seal`). |
| `ioc`       | **0** (profile-scoped) | `iocs[]`, `count`, `by_type`, `by_mitre_technique` | Promoted IOCs + aggregations. `approved_finding_count` is not populated by this profile. |
| `timeline`  | **0** (profile-scoped) | `approved_timeline_events[]`, `count` | Approved timeline events. |
| `status`    | **0** (profile-scoped) | `total_findings`, `by_status` | Workflow state machine counts (DRAFT/APPROVED/…). |

Every profile envelope also carries `case_id`, `profile`, `report_id` (a fresh content hash per call),
`snapshot_at`, `truncated`, `result_bytes`, `error`, `warning`.

**Native quirk worth flagging:** the `status` profile reports `by_status = {"DRAFT": N}` for **all** N
findings on every case — i.e. the *finding documents themselves* are stored DRAFT, while approval lives
in the separate approvals index (the per-finding `hmac_seal`). That is why `full`/`findings`/`executive`
can report `approved_finding_count = N` while `status` shows `DRAFT: N`. The two views are consistent —
they read different indices — but a reader looking only at `status` would not see the approvals.

---

## Case 1 — CHALLENGE-NOTCHITUP (1.6 GB Windows x64 — profileable; richest case)

### Native profiles

| Profile | `approved_finding_count` | Section counts (native JSON) | `result_bytes` |
|---------|--------------------------|------------------------------|----------------|
| `full`      | 5 | executive_summary sev_mix `high×2, medium×2, info×1`; findings **5**; timeline **0**; iocs **5** | 6400 |
| `executive` | 5 | severity_mix `high×2, medium×2, info×1`; top_tactics `[]`; top_hosts `[]` | 487 |
| `findings`  | 5 | approved_findings **5** | 4632 |
| `ioc`       | 0 | iocs **5** — by_type `memory_region×2, process×2, sha256×1`; by_mitre `T1055×4, T1047×2` | 1774 |
| `timeline`  | 0 | approved_timeline_events **0** | 565 |
| `status`    | 0 | total_findings **5**; by_status `DRAFT×5` | 345 |

### Multi-tier rendered tiers (`generated/challenge-notchitup/`)

| Tier | Section counts (rendered) | Adds over native |
|------|---------------------------|------------------|
| **analyst** | Findings **5** (each with **risk score** + **likelihood** + **confidence band**) · IOCs **5** (table + Mermaid IOC graph) · Timeline 0 | Per-finding risk score (`F-NOTCH-004`/`F-NOTCH-001` = 8; `F-NOTCH-002`/`-003` = 6; `F-NOTCH-005` = 0); FIRST-5 likelihood + LCA confidence legend; in-page `<a id>` anchors for every finding. |
| **executive** | KPI table (Approved 5, Critical 0, **High 2**, Affected hosts 0, Unique ATT&CK **2**, Dwell n/a) · "Critical & High Findings" list = 2 (`F-NOTCH-004`, `F-NOTCH-001`) | Severity-filtered High list + back-links into the analyst anchors; KPI framing. |
| **business** | Risk Register = **5 rows** sorted by score desc (8, 8, 6, 6, 0) with Likelihood / Severity / Score / Business impact / Compliance / Owner / **Analyst ref** columns | Risk-register framing, descending-score ordering, owner/compliance columns (empty, ready to fill), no-drift `[F-NOTCH-xxx](#anchor)` back-links. |

---

## Case 2 — AMF-WIN-SAMPLE001 (511 MiB Windows XP — profileable)

### Native profiles

| Profile | `approved_finding_count` | Section counts (native JSON) | `result_bytes` |
|---------|--------------------------|------------------------------|----------------|
| `full`      | 6 | executive_summary sev_mix `medium×4, low×2`; findings **6**; timeline **0**; iocs **0** | 6074 |
| `executive` | 6 | severity_mix `medium×4, low×2`; top_tactics `[]`; top_hosts `[]` | 450 |
| `findings`  | 6 | approved_findings **6** | 5756 |
| `ioc`       | 0 | iocs **0** | 357 |
| `timeline`  | 0 | approved_timeline_events **0** | 563 |
| `status`    | 0 | total_findings **6**; by_status `DRAFT×6` | 343 |

### Multi-tier rendered tiers (`generated/amf-win-sample001/`)

| Tier | Section counts (rendered) | Adds over native |
|------|---------------------------|------------------|
| **analyst** | Findings **6** (risk score + likelihood + confidence each) · IOCs 0 ("No IOCs extracted.") · Timeline 0 | Risk scores: 4×medium→6, 2×low→4; anchors + FIRST-5/LCA legend. |
| **executive** | KPI table (Approved 6, Critical 0, **High 0**, Affected hosts 0, Unique ATT&CK **2**, Dwell n/a) · "Critical & High Findings" → *"No critical or high-severity findings in scope."* | Honest empty High list — the executive tier states the absence explicitly rather than leaving the reader to infer it from a severity_mix array. |
| **business** | Risk Register = **6 rows** (scores 6,6,6,6,4,4) | Risk register + back-links; surfaces medium-severity malfind concentrations (winlogon ×10, lsass ×2, csrss ×1, user-apps) as ranked rows. |

---

## Case 3 — CTF-CONTACT-ME-MEM (raw image — unprofileable by design)

### Native profiles

| Profile | `approved_finding_count` | Section counts (native JSON) | `result_bytes` |
|---------|--------------------------|------------------------------|----------------|
| `full`      | 1 | executive_summary sev_mix `medium×1`; findings **1**; timeline **0**; iocs **0** | 1345 |
| `executive` | 1 | severity_mix `medium×1` | 418 |
| `findings`  | 1 | approved_findings **1** | 1060 |
| `ioc`       | 0 | iocs **0** | 358 |
| `timeline`  | 0 | approved_timeline_events **0** | 564 |
| `status`    | 0 | total_findings **1**; by_status `DRAFT×1` | 344 |

### Multi-tier rendered tiers (`generated/contact-me-memory/`)

| Tier | Section counts (rendered) | Adds over native |
|------|---------------------------|------------------|
| **analyst** | Findings **1** (the honest-negative `F-CONTACTME-001`, medium, **risk 6**) · IOCs 0 · Timeline 0 | Renders the unprofileable outcome as a single readable finding with risk/likelihood/confidence; "No IOCs extracted." / "No approved timeline events." stated explicitly. |
| **executive** | KPI table (Approved 1, Critical 0, High 0, Unique ATT&CK 0) · High list empty | Frames "1 finding, nothing critical" for a non-technical reader. |
| **business** | Risk Register = **1 row** (medium, score 6) | Risk-register framing of an honest negative — the "unprofileable" result becomes a tracked, owner-assignable risk row. |

> The honest-negative finding is **medium / risk 6** here only because severity was recorded `medium`;
> contrast with memdump (`low` / risk 4) below. Both are real recorded severities, not engine choices.

---

## Case 4 — MEMDUMP-RAW-2014 (2014 raw image — NOT APPLICABLE BY DESIGN)

This image has **no profile-matchable Windows kernel symbol table** (Volatility3 2.28.0 cannot validate
`kernel.layer_name`/`symbol_table_name`); pslist/netscan/malfind/svcscan all return empty. There is
nothing to attribute — the single finding is the **honest negative**, not an invented artifact.

### Native profiles

| Profile | `approved_finding_count` | Section counts (native JSON) | `result_bytes` |
|---------|--------------------------|------------------------------|----------------|
| `full`      | 1 | executive_summary sev_mix `low×1`; findings **1**; timeline **0**; iocs **0** | 1370 |
| `executive` | 1 | severity_mix `low×1` | 413 |
| `findings`  | 1 | approved_findings **1** | 1088 |
| `ioc`       | 0 | iocs **0** | 356 |
| `timeline`  | 0 | approved_timeline_events **0** | 562 |
| `status`    | 0 | total_findings **1**; by_status `DRAFT×1` | 342 |

### Multi-tier rendered tiers (`generated/memdump-raw-2014/`)

| Tier | Section counts (rendered) | Adds over native |
|------|---------------------------|------------------|
| **analyst** | Findings **1** (`F-MEMDUMP-001`, low, **risk 4**) · IOCs 0 · Timeline 0 | Renders the no-symbol-table negative as a single low-severity finding; empty IOC/timeline stated explicitly, not silently. |
| **executive** | KPI table (Approved 1, Critical 0, High 0, Unique ATT&CK 0) · High list empty | "Nothing actionable" framing without exposing the raw symbol-table error to a non-technical reader. |
| **business** | Risk Register = **1 row** (low, score 4) | The unprofileable outcome becomes one tracked low-risk register entry with a back-link. |

---

## Where the multi-tier projection adds value (vs. raw native JSON)

1. **Audience framing the native JSON never computes.**
   - *Executive tier* synthesizes a **KPI table** (Approved / Critical / High / Affected hosts / Unique
     ATT&CK techniques / Dwell time) and a **severity-filtered Critical & High list** — neither exists
     in the native `executive` profile, which only returns `severity_mix` + empty `top_tactics`/`top_hosts`.
   - *Business tier* produces a **Risk Register** (Likelihood × Severity → Score, plus Business-impact /
     Compliance / Owner columns) sorted by descending risk. The native JSON has **no risk score at all**.
2. **Risk scoring is added at the projection layer.** `risk_score = LIKELIHOOD_WEIGHT × SEVERITY_IMPACT_WEIGHT`
   (0–25; `view_models.py`). Native findings carry no `likelihood`, so the transformer defaults every
   finding to `unlikely` (weight 2) → risk = 2 × impact: high→8, medium→6, low→4, info→0. These scores
   (visible as 8/6/4/0 across the tiers) are **derived presentation metadata**, not stored in the index.
3. **No-drift back-links.** Every executive/business item carries an `analyst_anchor` /
   `analyst_finding_id` back to its analyst finding (`[F-NOTCH-001](#…)`), and `validate_no_drift`
   *enforces* that every higher-tier claim resolves to a real analyst finding (raises `NoDriftError`
   otherwise). The native JSON profiles are independent snapshots with **no cross-profile linkage** — a
   reader cannot prove the `executive` severity_mix corresponds to specific `findings`-profile records.
4. **Honest-absence is rendered, not inferred.** The tiers print *"No IOCs extracted." / "No approved
   timeline events." / "No critical or high-severity findings in scope."* The native JSON conveys the
   same as empty arrays / `count:0`, which a human must interpret. This matters most on the two
   unprofileable cases, where the tiers make the honest-negative legible to a non-analyst.
5. **Render targets.** Tiers emit Markdown (+ Mermaid IOC graph on the analyst tier), self-contained
   HTML, and (intended) PDF. Native `report_generate` is JSON only.

## Divergences / caveats (where the two sides differ)

- **`approved_finding_count` is profile-scoped in the native API.** It is populated for `full` /
  `executive` / `findings` but is **`0`** for `ioc`, `timeline`, and `status` — those profiles don't
  echo the finding count. The tiers always carry the true count (they project from `profile=full`).
- **`status` profile vs. tier "Approved" KPI disagree on the surface.** Native `status` shows
  `by_status = {DRAFT: N}` (the finding docs are DRAFT in the findings index); the executive tier's KPI
  shows `Approved findings: N`. Both are correct — approval state lives in the separate approvals index
  (per-finding `hmac_seal`), which the tiers (via `profile=full`) read and `status` does not.
- **"Affected hosts: 0" despite a populated `host` field.** The executive KPI shows `Affected hosts: 0`
  for every case even though findings carry `host` (e.g. `notch-it-up`, `sample001`). Native
  `executive` likewise returns `top_hosts: []`. This is a **shared upstream gap** (host roll-up not
  populated), not a tier-projection bug — the tier faithfully reflects the empty native aggregation.
- **IOCs only flow to the analyst tier.** The native `ioc` profile exposes `by_type` /
  `by_mitre_technique` aggregations (e.g. CHALLENGE-NOTCHITUP `T1055×4, T1047×2`); the rendered tiers
  surface the IOC **list + Mermaid graph** on the analyst tier but **do not** re-expose those
  `by_type`/`by_mitre` aggregations in any tier. For IOC analytics, the native `ioc` profile is richer.
- **`report_id` differs every call** (content hash over a fresh `snapshot_at`), so native and tier
  report IDs never match across runs — expected, not drift.
