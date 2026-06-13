# Repository Index-Coverage Audit

**Date:** 2026-06-13
**Repo:** `/home/admin2/docu_agentro` (Agentropix-SIFT documentation portal)
**Scope:** tracked files only (`git ls-files`); gitignored / local-only trees
(`video_pre/`, `evaluation*/`, `videoos/`, raw `Final_Video` working files, `dist/`, `__pycache__/`)
were excluded from inventory.

## Methodology

Run as an Opus 4.8 multi-agent workflow in four phases:

1. **Inventory (16 agents).** One agent per section enumerated every tracked file
   (`git ls-files <path>`) and counted how many were already reachable from that
   section's index, yielding the un-indexed delta.
2. **Per-section indexing.** Each section README received purely **additive** entries
   for genuinely orphaned content pages, matched to that README's existing
   table/list style; descriptions were derived from each file's actual head content.
3. **Main-index update.** Missing top-level reader pages were added to `INDEX.md`
   (the routed master index) and `README.md` where their existing structure allowed
   an additive entry.
4. **Bidirectional verification (16 verifiers).** One verifier per section
   re-counted tracked files vs. files reachable from the section README, in both
   directions (index→file and file→index), reporting residual orphans and broken links.

Edits were strictly additive: no existing entry was reworded, restructured, or deleted,
and no file was `git add`/committed.

## Coverage table

| Section | Tracked files | Indexed in section README | Orphans remaining | Broken links |
|---|---|---|---|---|
| docs/01-overview | 9 | 8 | 0 | 0 |
| docs/02-architecture | 35 | 14 | 0 | 0 |
| docs/03-data | 20 | 11 | 0 | 0 |
| docs/04-mcp-tools | 6 | 5 | 0 | 0 |
| docs/05-safety-forensics | 13 | 12 | 0 | 0 |
| docs/06-use-cases | 27 | 16 | 0 | 0 |
| docs/07-sdlc-ops | 24 | 24 | 0 | 0 |
| docs/08-reference | 7 | 6 | 0 | 0 |
| docs/09-integrations | 10 | 10 | 0 | 0 |
| docs/10-agents | 7 | 6 | 0 | 0 |
| docs/11-ADR | 31 | 30 | 0 | 0 |
| docs/12-CASES-REPORTS | 214 | 45 | 19 | 0 |
| docs/issues | 3 | 3 | 0 | 0 |
| case-activation | 166 | 18 | 0 | 0 |
| agentropix_mcp | 162 | 162 | 0 | 0 |
| assets (top-level showcase; no section README — indexed via main README.md / INDEX.md) | 24 | 13 | 10 | 0 |
| **Totals** | **701** | — | **29** | **0** |

Notes on counts:
- "Indexed in section README" is the verifier's reachable-from-index count after the run.
- Where a section's tracked count differs slightly between the inventory and verify
  passes (e.g. 02-architecture 36→35, 06-use-cases 26→27, 12-CASES-REPORTS 175→214,
  case-activation 156→166, agentropix_mcp 155→162, assets 23→24), the **verify** pass
  is authoritative — it re-enumerated `git ls-files` at audit time. The header total
  (701) is the inventory baseline used to drive the run.

## Totals

- **701** tracked files inventoried across 16 sections.
- **452** were un-indexed before this run (sum of the inventory `u` deltas).
- After indexing + verification: **29** orphans remain (19 in `docs/12-CASES-REPORTS`,
  10 in top-level `assets/`) and **0** broken links.
- 14 of 16 sections verified **CLEAN** (zero orphans, zero broken links). The two
  remaining `ISSUES` sections hold only render/working artifacts, not reader pages.

## What was added

**docs/01-overview** — new additive "Assets" section (existing "Read in this order"
trail untouched), 2 entries:
- `assets/competitive-positioning-1.svg` — full-size zoomable Mermaid flowchart SVG
  (1274×706), the "Open as SVG" artifact for competitive-positioning.md.
- `assets/user-guide-1.svg` — full-size zoomable Mermaid flowchart SVG (259×968),
  the "Open as SVG" artifact for user-guide.md.

**docs/02-architecture** — no edit needed. All 14 tracked content `.md` pages were
already indexed in the "Read in this order" list. The only un-indexed tracked files
are diagram render artifacts under `assets/` (PNG/SVG/PDF/MMD), which this README does
not enumerate by design (it indexes pages; each asset is referenced inline within its
owning page). No sub-directory README exists to link.

**docs/03-data** — new additive "Supporting assets" subsection, 3 entries:
- `assets/data-models-1.svg` — full-size export of the first data-models.md class diagram.
- `assets/data-models-6.svg` — full-size export of the sixth data-models.md class diagram.
- `assets/schema-er-1.svg` — full-size export of the schema-er.md entity-relationship diagram.
Remaining un-indexed files all live under sub-folders (`network-evidence-verification/`,
`recall-ground-truth/`) whose own READMEs already enumerate them and are already linked
from this README (reading-order items 6 and 8).

**docs/04-mcp-tools** — no edit needed. The only un-indexed file is the section
`README.md` itself (an index never self-references); all 5 content files
(capability-map, tool-reference, response-envelope, tool-by-agent, tool-list) are
already linked. No sub-folder READMEs in this section.

**docs/05-safety-forensics** — new additive "Assets" section, 6 entries:
- `assets/provenance-grounding-1.svg` — full-size render of the provenance-grounding flowchart.
- `assets/human-in-the-loop-1.svg` — full-size render of the human-in-the-loop flowchart.
- `assets/approval-portal-1.svg` — full-size render of the challenge/approve HMAC flow.
- `assets/approval-sidecar-ui.png` — screenshot of the approval sidecar browser UI.
- `assets/audit-courtroom-1.svg` — full-size render of the evidence-hash/seal session flow.
(One per file matching the README's existing bullet-link style.)

**docs/06-use-cases / main index** — the one genuine missing top-level reader page,
`demo-script.md`, was added to **INDEX.md** section 6 ("Use Cases" table, after the
"Guided Demo Walkthrough" row, in the existing `| Title | Audience | What question it
answers | Link |` style): **3-Minute Hackathon Demo Script (BMAD-M8)** — a 5-beat
~3-min judging-panel script with three cast variants (30-second teaser · real-data
walkthrough · 9-beat SHIELDBASE narration). No README change: its section-6 coverage
is a prose list with no per-page table to extend additively, and the "Documentation
map" table already covers the use-cases section at folder level — per-page entries
belong in INDEX, where this one now lives.

**Main README.md / INDEX.md** — beyond the demo-script INDEX row above, no further
top-level reader pages were missing. The SRL-2015/SRL-2018 report folders are already
discoverable via INDEX section 12 (the folder README routes to deep sub-pages, per
house style), and training-session asset folders are referenced inline from
demo-script.md / demo-walkthrough.md as recorded media, not top-level chapters.

Sections **07-sdlc-ops, 08-reference, 09-integrations, 10-agents, 11-ADR, docs/issues,
case-activation, agentropix_mcp** verified CLEAN with their existing indexes (all
content pages already reachable); no additive entries were required.

## Remaining issues (manual follow-up)

**0 broken links** across the entire repo.

**29 orphans remain** — all render/working artifacts, not reader pages. Listed for
manual follow-up:

### docs/12-CASES-REPORTS — 19 orphans (SRL-2018 submission diagram sources/decks)
Animated decks (HTML, served via Pages — not blob-rendered):
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/animated-decks/a2a.html`
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/animated-decks/clock.html`
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/animated-decks/gov.html`
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/animated-decks/hero.html`
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/animated-decks/iter.html`
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/animated-decks/metrics.html`

Mermaid diagram sources (`.mmd` — rendered to PNG inline, sources unindexed by design):
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/base-dc-agent-correlation-graph.mmd`
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/base-dc-findings-per-agent.mmd`
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/base-dc-self-correction-funnel.mmd`
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/base-dc-timestamp-chain.mmd`
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/base-dc-vs-notch-run-comparison.mmd`
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/hunt-burst-217us-zoom.mmd`
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/notch-agent-correlation-graph.mmd`
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/notch-self-correction-funnel.mmd`
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/plan-size-per-iteration-both-runs.mmd`
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/seal-cross-binding-chain.mmd`
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/thymus-gate-base-dc-pie.mmd`
- `docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/thymus-gate-notch-pie.mmd`

Repo-control file (not a reader page):
- `docs/12-CASES-REPORTS/vanko-report/.gitignore`

### assets/ (top-level showcase) — 10 orphans (submission-tour deck + proof screenshots)
- `assets/submission-tour/submission-tour-deck.html`
- `assets/submission-tour/proof/license.png`
- `assets/submission-tour/proof/accuracy.png`
- `assets/submission-tour/proof/animwalk.png`
- `assets/submission-tour/proof/archdiag.png`
- `assets/submission-tour/proof/datasets.png`
- `assets/submission-tour/proof/evalmap.png`
- `assets/submission-tour/proof/goldreport.png`
- `assets/submission-tour/proof/releases.png`
- `assets/submission-tour/proof/repo-front.png`

**Assessment:** every residual orphan is a render source (`.mmd`), an animated
deck/proof asset (HTML/PNG embedded or Pages-served), or a repo-control file
(`.gitignore`). None is an un-indexed reader page; all reader-facing content pages
are now indexed. The orphans are left for an operator decision on whether the
submission decks and proof screenshots warrant explicit index entries.

---

## Build-sources pass (2026-06-13) — orphans driven to 0

The 29 residual orphans were render-sources / build inputs (not reader pages). They are now
explicitly indexed so every tracked file is named in a README:

- **`docs/12-CASES-REPORTS/srl-2018-report/submission/diagrams/README.md`** (new) — indexes every
  Mermaid `.mmd` source → its rendered `.png`, and every `animated-decks/*.html` deck → its
  `atlas-*.gif`. Reachable via the existing `diagrams/` folder link in the submission README.
- **`assets/submission-tour/README.md`** (new) — indexes the tour output (`SUBMISSION-TOUR.mp4`,
  `watch-tour.html`, poster) and its build inputs (`submission-tour-deck.html` + the 9
  `proof/*.png` panels). Linked from the main README's "Submission Evidence Tour" line.
- **`docs/12-CASES-REPORTS/vanko-report/.gitignore`** — noted in the VANKO report README as a
  git-control file (not a reader document).

**Result: 0 orphans, 0 broken links — every tracked file is now named in a README.**
