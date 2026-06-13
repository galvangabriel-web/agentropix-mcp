# SRL-2015 — Wazuh push receipts & pipeline summaries

> **What this is.** The raw, machine-readable receipts the Agentropix-SIFT pipeline emitted when it
> aggregated the SRL-2015 findings and pushed them to the Wazuh evidence cluster on 2026-06-10.
> Previously these lived only in the local pipeline working set (withheld by reference in the case
> [`../README.md`](../README.md) §3.4); they are published here, **unmodified**, so the headline
> numbers in the case report and the investigation video are independently verifiable from raw data.

These files are **already free of secrets** — they carry no Wazuh endpoint, internal IP, or
credential (those live in other working-set files that remain withheld). The index name
`agentropix-findings-2026.06.10` and the random per-call `run_id` hashes are not sensitive.

## Files

| File | What it is | Key field(s) |
|---|---|---|
| [`pipeline_summary.json`](pipeline_summary.json) | Summary of the **successful live findings push** | `findings.indexed_count = 1553`, `index = agentropix-findings-2026.06.10`, `iocs.vanko_preserved = true` |
| [`pipeline_summary_FINAL.json`](pipeline_summary_FINAL.json) | Summary of the **final re-run, which deliberately BLOCKED a second live push** | `aggregation.total_findings = 2233` (+ per-host breakdown), `findings_index.live_blocked = true` with the duplicate-pollution `block_reason`, `iocs.vanko_preserved = true`, `ledger.seq = 163 status=blocked` |
| [`dryrun_index.json`](dryrun_index.json) | Verbatim MCP JSON-RPC envelope of the **dry-run** `wazuh_index_findings` call | `indexed_count = 0`, `dry_run = true`, `run_id = e80e1fbe` |
| [`live_index.json`](live_index.json) | Verbatim MCP JSON-RPC envelope of the **live** `wazuh_index_findings` call | `indexed_count = 1553`, `dry_run = false`, `run_id = cb5c6dc0` |
| [`discover-findings-count-2874.png`](discover-findings-count-2874.png) | Wazuh **Discover** capture: the **2,874** evidence-document count for `case_id="SRL-2015-APT-ENTERPRISE"` | visual proof of the `2,874` headline |

> **Privacy note.** `discover-findings-count-2874.png` shows the live Wazuh Discover UI. It displays
> the `agentropix-findings-*` index pattern, the `case_id` filter, and the 2,874 hit count — but no
> endpoint URL, credential, or analysis-host identifier is visible in the capture.

## Reconciling the four numbers you'll see

The case report, video narration, and these receipts use several different real counts. They are
**not** contradictory — they measure different things:

| Number | Meaning | Source |
|---|---|---|
| **2,233** | Raw findings **aggregated** across all 8 host/modality runs (196+512+250+10+484+432+339+10) | `pipeline_summary_FINAL.json → aggregation.total_findings` (and the 8 per-host `disk.json`/`memory.json` in the withheld working set) |
| **1,553** | Distinct findings actually **indexed** in the one successful live push (post-dedup) | `live_index.json → indexed_count`, `pipeline_summary.json → findings.indexed_count` |
| **2,194** | Total SRL-2015 findings docs resident in the index after that push (641 prior + 1,553) | `pipeline_summary.json → findings.srl2015_docs_after`; `pipeline_summary_FINAL.json → existing_srl_docs` |
| **2,874** | Total **evidence documents** for the case visible in Wazuh Discover (findings docs **plus** IOC docs) | the Discover capture referenced in the case full report |

**Why a second live push was blocked.** The final re-run found the sanctioned
`wazuh_index_findings` tool auto-generates `_id` (no deterministic `_id=finding_id`), so re-pushing
the 2,233-finding set would have **added duplicates, not replaced** existing docs — irreversible
index pollution. The non-destructive fix would have required editing the sealed orchestrator /
ADR-016, which is a Hard-Stop. The pipeline therefore **blocked the push** and recorded the decision
to the hash-chained ledger (`run_id srl2015-pipeline`, seq 163, status `blocked`, chain intact). This
is the honest "the agent refused an irreversible action" record, not a failure.

**VANKO preservation.** Both summaries record `vanko_preserved = true` / `removed_other_case = false`:
the IOC merge was an **additive union** (`agentropix_malware_sha256`: 22 → 47, +25 SRL-2015), and the
other case's IOCs in the shared CDB lists were left intact.

## Provenance

Copied **byte-for-byte** from the local pipeline working set
`agentropix-sift/Reports_results/SRL2015-PIPELINE-V2/_push/` (withheld by reference). Source SHA-256
at publication (2026-06-13):

```
b1da39250d526b1099ffd729b8b244544a4b4be684cc0e93792aadc52ed19b19  pipeline_summary_FINAL.json
21dddb7be6a9cf0f15952489518a88543d4a38792b3b353e423999ebf8428dca  pipeline_summary.json
57da574daca8750342a575d877f9ce4e4ead93e7b8a4f4fdff5c3233be6ca5e0  dryrun_index.json
ab54d6ba009d369c1c5f45d1be497e735c4ab68097ade1d290fa1660323997f6  live_index.json
```

Verify with `sha256sum` against the files in this folder — they are unmodified, so the published
hashes equal the source hashes.
