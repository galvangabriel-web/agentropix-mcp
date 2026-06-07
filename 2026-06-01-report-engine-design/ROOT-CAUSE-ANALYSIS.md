# ROOT-CAUSE-ANALYSIS — 36 near-empty multi-tier reports

**Date:** 2026-06-07
**Scope:** The 36 reports (4 cases × 3 tiers × 3 formats) under
`2026-06-01-report-engine-design/generated/`.
**Examiner:** victor.galvan
**Verdict:** **The reports are correct renderings of a near-empty dataset. This is a
data-population (workflow) defect, NOT a report-engine or rendering bug.** The engine
faithfully projected what was actually persisted to the Wazuh indices; almost nothing
was persisted.

---

## 1. Symptom

All 36 artifacts are near-empty. Every report tier, in every case, shows:

- exactly **1 approved finding**, carrying only a title (no evidence);
- **`_Evidence: —`** (empty);
- **`_No IOCs extracted._`**;
- **`_No approved timeline events._`**.

Markdown sizes confirm it (e.g. `contact-me-memory/analyst.md` = 21 lines / 1136 bytes;
`executive.md` ≈ 327 bytes — a KPI table reading `Approved findings: 1`, everything else
`0` / `n/a`).

Representative render — `generated/contact-me-memory/analyst.md`:

```
## Findings
### Memory image unprofileable: Volatility3 2.28.0 could not validate a Windows kernel symbol table …
- Finding ID: F-CONTACTME-001 · Severity: medium · …
_Evidence:_ —
## Indicators of Compromise
_No IOCs extracted._
## Timeline
_No approved timeline events._
```

`generated/amf-win-sample001/analyst.md` is identical in shape — and that case was fully
profileable (15 real `malfind` RWX hits), so "empty" cannot be blamed on the data being
absent at triage time.

---

## 2. What the engine is contractually allowed to project (verified in the oracle)

`report_generate` (oracle: `src/agentropix_sift/mcp_server/wrappers/case_records.py:1056`)
projects **only**:

- **APPROVED findings** — for the `full` / `findings` / `executive` / `timeline` profiles.
  Docstring (line 1064): *"Only APPROVED findings reach the findings/timeline/executive/full
  profiles."*
- **IOCs** — pulled from the **`agentropix-iocs-*`** index (the `ioc` profile;
  `IOCS_INDEX_PATTERN`, `case_records.py` + `mcp_server/wrappers/ioc_registry.py:29`).
- **Timeline events** — pulled from the **`agentropix-timeline-*`** index
  (`TIMELINE_INDEX_PATTERN`).

The report is data-driven from three Wazuh index families
(`agentropix-findings-*`, `agentropix-iocs-*`, `agentropix-timeline-*`) keyed on `case_id`.
If those indices are empty for a case, the report is empty **by design** — and the engine
even raises an honest warning for it (line 1169): *"0 APPROVED findings — profile includes
only APPROVED findings … approve them (approve_finding) or use profile='status'."*

Finding **Evidence** comes from each finding doc's own `evidence[]` array; **IOCs** come
from `agentropix-iocs-*`, which `ioc_registry.promote_iocs` populates by flattening the
`iocs[]` arrays of **APPROVED** findings (`ioc_registry.py:3-9`). So an approved finding
that carries neither an `evidence[]` nor an `iocs[]` array yields empty Evidence AND zero
IOCs even after IOC promotion.

---

## 3. What was actually persisted per case (the real cause)

Audited from each case's `case-activation/runs/<slug>/EXECUTED-RUN.md`:

| Case | `record_finding` (real, non-dry-run) | finding `evidence[]` | `record_timeline_event` | `promote_iocs` | approved |
| --- | --- | --- | --- | --- | --- |
| amf-win-sample001 | 1 (`F-AMF-S001-001`, title-only) | none | **0** | **0** | yes (SIMULATED) |
| challenge-notchitup | 1 | none | **0** | **0** | yes (SIMULATED) |
| contact-me-memory | 1 (`F-CONTACTME-001`) | none | **0** | **0** | yes (SIMULATED) |
| memdump-raw-2014 | 1 (NOT APPLICABLE BY DESIGN — no kernel symbol match) | none | **0** | **0** | yes (SIMULATED) |

(`record_timeline_event` and `promote_iocs` call counts are **0 in all four runs**.)

The persisted finding doc carries only `finding_id` / `host` / `mitre_attack` / `title`
(+ `hmac_seal` after approval). Example — the persisted `F-AMF-S001-001` payload captured
in `runs/amf-win-sample001/EXECUTED-RUN.md`:

```json
{ "finding_id": "F-AMF-S001-001", "host": "sample001", "mitre_attack": "T1055",
  "title": "15 RWX (PAGE_EXECUTE_READWRITE) injected-code regions … winlogon.exe (x10)",
  "hmac_seal": "hmac-sha256:29479f98…" }
```

No `evidence[]`, no `iocs[]`. Hence empty Evidence and zero IOCs in the report.

**The real triage data was captured — but only as prose in EXECUTED-RUN.md, never as
index records.** For amf-win-sample001 the run recovered 21 processes, 229 services, a
clean process tree, full `cmdline` output, `netscan` (0 sockets), and **15 real `malfind`
`PAGE_EXECUTE_READWRITE` regions (winlogon.exe ×10, lsass.exe ×2, csrss.exe ×1,
msmsgs.exe ×1, msimn.exe ×1)** — all documented in the run log, none written to
`agentropix-findings-*` `evidence[]`, `agentropix-iocs-*`, or `agentropix-timeline-*`.
The detailed `record_finding` was even invoked **`dry_run:true`** (EXECUTED-RUN line 202);
only a stripped, title-only representative finding was persisted for real.

**Root cause:** the case-activation runs persisted a single thin, title-only "representative"
finding per case and skipped the three population steps the report engine reads from —
populating finding `evidence[]`, `record_timeline_event`, and `promote_iocs`. The engine then
projected exactly that: 1 finding, empty evidence, 0 IOCs, 0 timeline.

---

## 4. Engine / render pipeline is healthy (ruled out)

- **Projection logic is correct:** `report_generate` resolves the case, runs the per-profile
  dispatch, computes a deterministic `report_id`, and emits structured `sections`
  (`case_records.py:1056-1190`). It behaved exactly to spec on the data given.
- **HTML render works:** `render_html` (oracle `reports/render.py:160`) converts the
  Markdown to self-contained HTML; all 9 HTML files rendered.
- **PDF render works:** all 12 PDFs are **16-18 KB and non-zero** (e.g.
  `amf-win-sample001/analyst.pdf` = 18074 bytes). A broken renderer would yield 0-byte or
  missing files; these are valid PDFs of near-empty source.

Conclusion: feeding the same engine populated findings (with `evidence[]`), a promoted
`agentropix-iocs-*` set, and recorded `agentropix-timeline-*` events will produce full
reports with no engine change required.

---

## 5. Secondary issue (already fixed): Chromium PDF under snap confinement

The ADR-024 default PDF engine is headless **Chromium** with a **WeasyPrint** pure-Python
fallback (`reports/render.py:8-10, 96-132`; `detect_pdf_capability(prefer=...)`). On this
host the snap-confined Chromium **fails silently and emits a 0-byte file while reporting
success**. **Resolution: render PDFs via WeasyPrint** (`prefer="weasyprint"`), which is the
pure-pip fallback and is unaffected by snap confinement. The current 16-18 KB PDFs confirm
the WeasyPrint path is working; this is recorded as already-fixed, independent of the
empty-data root cause above.

---

## 6. Remediation (data, not code)

To regenerate full reports, the workflow — not the engine — must populate the indices before
`report_generate`:

1. **Persist real findings with evidence.** For each case, write `record_finding` (non-dry-run,
   `scope=index_findings` gate) carrying a populated `evidence[]` (and `iocs[]` where
   applicable) sourced from EXECUTED-RUN.md — e.g. amf's 15 `malfind` RWX regions.
2. **Record timeline events** via `record_timeline_event` so `agentropix-timeline-*` is
   non-empty.
3. **Promote IOCs** via `promote_iocs` (`scope=promote_iocs` gate, non-dry-run) so
   `agentropix-iocs-*` is populated from the approved findings' `iocs[]`.
4. **Approve** the findings (SIMULATED examiner approval, demo only) so they reach the
   APPROVED-only profiles.
5. **Re-run `report_generate` / `report_export`**, preferring WeasyPrint for PDF.

**memdump-raw-2014 stays NOT APPLICABLE BY DESIGN** — Volatility3 found no matching kernel
symbol table, so there is no triage data to record; its near-empty report is honest and must
not be back-filled with invented findings.
