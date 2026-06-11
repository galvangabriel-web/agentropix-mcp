# MEMDUMP-RAW-2014 — generated report artifacts

These four files are the multi-tier report artifacts for the `memdump` memory-triage run
(unattributed 512 MiB raw RAM image, circa 2014, case `MEMDUMP-RAW-2014`). They were generated
by the Agentropix-SIFT report engine (ADR-024) from the case's sealed findings:
`report_generate(profile=full)` fuses the sealed case data (executive summary, findings, IOCs,
timeline) plus the run's raw MCP captures into one comprehensive document — executive dashboard
(KPIs, risk matrix), forensic sections (hosts, network, detailed finding, timeline), and a
coverage attestation — and a parallel 1-page executive summary. Each tier is rendered to `.md`
(canonical) and `.pdf` (share).

The single finding behind these reports went through the Examiner Approval Portal in
**simulated**, demo-only form — the comprehensive report discloses this itself: "the Examiner
Portal approval for `F-MEMDUMP-001` was **automated for the demo** (Playwright driving the
portal) and is **NOT a human sign-off**; the sealed snapshot shows the finding's
`approval.status` as `DRAFT` while it carries a valid HMAC seal. A production case requires an
interactive human examiner sign-off."

## The files

| File | Audience | What it contains | How produced |
|---|---|---|---|
| [`comprehensive.md`](comprehensive.md) | DFIR examiner / SOC / audit | Full 13-section sealed report: header + report ID and seals, executive summary, KPIs, risk matrix, key findings, attack chain & MITRE, IOC catalogue, host/network artefacts, detailed finding `F-MEMDUMP-001`, timeline, performance, coverage attestation, recommendations, appendix (methodology, tool versions, chain of custody, provenance) | Canonical Markdown emitted by `report_generate(profile=full)` |
| [`comprehensive.pdf`](comprehensive.pdf) | Same, for sharing | Render of `comprehensive.md` | PDF render of the canonical `.md` |
| [`executive-onepager.md`](executive-onepager.md) | CISO / stakeholder | 1-page summary: bottom line, KPIs, risk matrix, top finding, headline recommendation | Canonical Markdown, condensed from the same sealed data |
| [`executive-onepager.pdf`](executive-onepager.pdf) | Same, for sharing | Render of `executive-onepager.md` | PDF render of the canonical `.md` |

## Inside the reports (excerpts)

**Report ID + seal** (from the `comprehensive.md` header table) — provenance and integrity:
the report is individually identified and the finding is HMAC-sealed, so the negative result
is tamper-evident and reproducible:

> | **Report ID** | `778d18c3357516a41287d10f7ee3bbc38a0d2d894fe19a939752905f15317f9e` |
> | **Seal** | HMAC-SHA256 sealed report · 1 approved finding · `hmac-sha256:886603aa…0fba9ec07` (finding seal) |

**Executive-summary honest negative** (§1) — the report states the inconclusive scope in both
directions, which is exactly what an evidentiary document must do:

> "**No malicious activity was found, and none could be ruled out**: the dataset is structurally inconclusive. The platform recorded this as an honest negative rather than inventing artefacts."

**The one finding** (§4) — what the run actually established about the image:

> 🟢 **`F-MEMDUMP-001` — Raw 512 MiB image has no profile-matchable kernel symbol table** (Low) — Volatility3 cannot validate `kernel.layer_name` / `kernel.symbol_table_name`; `pslist` / `netscan` / `malfind` / `svcscan` all return empty. … Honest negative, confidence 0.9.

**Coverage attestation** (§12) — the no-fabrication control, stated as an attestation:

> "All triage plugins were run and their empty results recorded with explicit reason strings. The single finding was committed under a write-scoped evidence-gate token and HMAC-sealed. No artefact, IOC, process, socket, service or timeline event was fabricated; the inconclusive outcome is reported as such."

## Honest notes

This case is an unprofileable, honest-negative capture. The image carries no scenario metadata
and no declared OS profile, so Volatility3 2.28.0 could not match a kernel symbol table; every
triage wrapper completed but returned empty (pslist: 11 pid-0 `unknown` placeholder rows;
netscan `socket_count 0`; malfind `hit_count 0`; svcscan `service_count 0`). The reports
document **why no compromise verdict is possible**: the image may be Linux/Mac, an older or
partial Windows build, or a fragmentary dump — absence here means "not resolvable", never
"clean". The headline recommendation is accordingly to re-acquire with provenance or attempt
non-Windows analysis paths before re-triage.

A sealed report of a negative result is itself the point: the pipeline surveyed the full
wrapper surface, recorded each empty result with its explicit reason string, gated the finding
through the evidence gate, and HMAC-sealed the inconclusive outcome — anti-hallucination
discipline made auditable. Run transcript: [`../EXECUTED-RUN.md`](../EXECUTED-RUN.md).
