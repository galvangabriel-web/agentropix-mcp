# Recall ground-truth fixtures

> **Section 03 · Data.** The labelled expectations the recall numbers are scored
> against — committed so a reviewer can see *exactly* what "72/72 disk · 108/118 memory"
> is measured over, not just the headline.
> **Related:** [Recall Methodology](../../07-sdlc-ops/dataset-recall.md) ·
> [Canonical Facts](../../08-reference/canonical-facts.md) (the governing numbers) ·
> [Reproduce the datasets](../../06-use-cases/reproduce-datasets.md)

## How to read this folder

Each `ground_truth_*.yaml` is the **expected-findings fixture** for one host image: a
`case_id` + `image`, the `expected_tactics` (MITRE technique IDs the Trinity Loop must
cover), and per-IOC expectations (processes, IPs, accounts, files). A run is scored by
matching the swarm's sealed findings against these, counting a hit at a **co-occurrence
quorum of ≥2** (cohit≥2). The `run-summary-*.md` shows the resulting per-host table.

This is a **representative subset — 4 of 29** ground-truth YAMLs in the engine corpus
(`samples/ground_truth_*.yaml`); they are committed for inspection, not as the full set.

| File | Image | Why it's here |
|---|---|---|
| `ground_truth_dc.yaml` | `base-dc-cdrive.E01` (Domain Controller) | The founding DC disk fixture cited at [`dataset-recall.md`](../../07-sdlc-ops/dataset-recall.md) — Cobalt Strike APT: beacon, lateral movement, credential dumping |
| `ground_truth_base-file-cdrive.yaml` | `base-file-cdrive` | A disk fixture (one of the 6 authored 2026-05-06) — shows the disk-IOC shape |
| `ground_truth_base-wkstn-06-memory.yaml` | `base-wkstn-06-memory` | A memory fixture — the only host with a public-IP outbound IOC; shows per-IOC structure |
| `ground_truth_base-mail-memory.yaml` | `base-mail-memory` | A T1566 mail-memory fixture — shows the mail/phishing technique mapping |
| `run-summary-FULL-CASE-20260505T004738Z.md` | (whole corpus) | The sealed-run recall summary: per-disk **7/7 = 1.000** table, whole-corpus per-IOC totals, methodology + the re-score command |

## Honest preface (real data, training fiction)

These fixtures come from **SANS SRL-2018 training scenarios**. Hostnames, case IDs
(`SANS-APT-…`), and IP literals (e.g. `248.86.12.27`, `172.16.*`) are **scenario-internal
training fiction**, not real infrastructure. They are copied **verbatim** — `expected_findings`,
keywords, and counts are untouched so the scoring stays auditable. The run summary's one
operator-host script path was rewritten to a neutral `scripts/` reference; nothing else changed.

The recall figure is a **post-hoc measurement** with the caveat documented in
[`dataset-recall.md`](../../07-sdlc-ops/dataset-recall.md) — read that page for the methodology
and its honest limits before quoting the number.
