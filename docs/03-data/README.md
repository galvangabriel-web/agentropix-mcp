# 03 · Data

The data model: every field, how the models relate, how persisted artifacts relate as entities, and what lands on disk.

## Read in this order

1. [data-dictionary.md](data-dictionary.md) — every Pydantic field: name, type, semantics, and constraints (the vocabulary).
2. [data-models.md](data-models.md) — how TriageReport, Finding, Agent, and the envelope models relate (class diagram).
3. [schema-er.md](schema-er.md) — how the persisted artifacts relate as entities (ER diagram).
4. [persisted-artifacts.md](persisted-artifacts.md) — what gets written to disk (JSON report, JSONL audit log, session keys, Hippocampus) and where.
5. [schema-dump.md](schema-dump.md) — *(shared reference)* the machine-extracted Pydantic model schema behind this chapter.
6. [recall-ground-truth/](recall-ground-truth/README.md) — the labelled expected-findings fixtures (4 of 29) the recall numbers are scored against, plus a sealed-run recall summary.
7. [evidence-datasets.md](evidence-datasets.md) — the evidence corpus itself: per-case provenance (SANS SRL, NIST CFReDS, MemLabs, DFRWS, Volatility Foundation), evidence types, the network-capture story (five acquired pcaps — three DFRWS `rhino*.log` + two Vanko Wi-Fi captures; six bulk_extractor-carved; the SIFT chain does not parse pcap), and links to the in-repo case reports.
8. [network-evidence-verification/](network-evidence-verification/README.md) — **proof package** for the network-capture story: magic-byte verified inventory, raw `file(1)`/`xxd`/SHA-256 transcript for all 11 pcaps, claim-by-claim reconciliation, and the methodology post-mortem on the self-caught extension-search error.

## Supporting assets

Full-size zoomable SVG exports of the wide diagrams, linked inline from their pages:

- [assets/data-models-1.svg](assets/data-models-1.svg) — full-size export of the first `data-models.md` class diagram.
- [assets/data-models-6.svg](assets/data-models-6.svg) — full-size export of the sixth `data-models.md` class diagram.
- [assets/schema-er-1.svg](assets/schema-er-1.svg) — full-size export of the `schema-er.md` entity-relationship diagram.
