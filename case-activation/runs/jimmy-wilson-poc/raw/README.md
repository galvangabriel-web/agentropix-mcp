# Raw run logs — the two earlier Jimmy Wilson engine runs (unedited)

> **Provenance.** Before the recorded PoC ([`../report.json`](../report.json), 00:40–00:49 UTC),
> the same command was executed twice on the same evidence — these are those runs' outputs,
> published exactly as the engine wrote them. Each run was produced by one invocation of
> `uv run agentropix-sift run "/cases/study case/2020JimmyWilson.E01" -o <name>.json`;
> on completion the engine emits a **triplet**: the sealed report, its sealed audit-log
> companion, and the per-run 32-byte HMAC session key used to compute both seals.

## Overview of the files

| File | What it is | How it was produced | Why it matters |
|---|---|---|---|
| [`jimmy.json`](jimmy.json) | Run #1 sealed report (23:53 → 00:02 UTC) | `agentropix-sift run … -o jimmy.json` | First full triage of the case: 129 findings · 86 tool calls · 5 iterations |
| [`jimmy.audit-log.json`](jimmy.audit-log.json) | Run #1 sealed audit-log companion | Written by the engine alongside the report | Proves the audit-log state (disabled) was itself sealed, not omitted |
| [`jimmy.session-key`](jimmy.session-key) | Run #1 HMAC key (32 B, binary) | Generated per-run by the engine; normally kept off-repo | Re-verifies run #1's `report_seal` `3cc20e1a…` and `audit_log_seal` `327f7b29…` |
| [`jimmyy.json`](jimmyy.json) | Run #2 sealed report (00:05 → 00:16 UTC) | Same command, second invocation | **Identical counts** to run #1 — run-to-run reproducibility on the same image |
| [`jimmyy.audit-log.json`](jimmyy.audit-log.json) | Run #2 audit-log companion | Engine-written | Same sealed-negative discipline, run #2's own seal `8091053a…` |
| [`jimmyy.session-key`](jimmyy.session-key) | Run #2 HMAC key (32 B, binary) | Per-run generation | Verifies run #2's seals — a key from one run cannot validate another |

All three runs (these two + the recorded one) produced **129 findings · 86 tool calls ·
5 iterations** with critic_score 1.0 — the impact of publishing the raw runs is exactly that
claim becoming checkable: same evidence in, same result out, three times, independently sealed.

## Read a piece of each file

**`jimmy.json` → the evidence-chain finding.** The artifact agent reads the E01's embedded
acquisition record — the original 2017 examiner and hashes travel inside the evidence itself:

```json
{"_source": "artifact.ewfinfo", "confidence": 0.5, "description": "Evidence chain: case=1 examiner=CEDONLEY", "evidence": "md5=b267fb0cd94645425eee00258d3a9b58 sha1=a1102c70a50768b588225fdcad6efa5d5d57341b acquired=Thu Dec 14 11:52:41 2017", …}
```

**`jimmy.json` → a cross-agent correlation.** The hunt agent only raises confidence when
independent agents agree — here filesystem and timeline corroborate each other across 88 findings:

```json
{"_source": "hunt.correlate", "confidence": 0.85, "description": "Cross-source agreement: 'file' flagged by 2 agents (filesystem, timeline)", "evidence": "token=file agents=['filesystem', 'timeline'] findings=88", …}
```

**`jimmy.audit-log.json` — quoted in full (222 bytes).** Audit-logging was off for these runs;
the honest way to record that is a sealed empty log, not a missing file:

```json
{
  "metadata": {
    "audit_log_enabled": false,
    "entry_count": 0,
    "audit_log_source_path": null
  },
  "audit_entries": [],
  "audit_log_seal": "327f7b29ebee6067dd4714595426e7357297c30639cc9b0931b98f88bfb31cbe"
}
```

**`jimmy.session-key` / `jimmyy.session-key`.** Raw 32-byte binary keys (no encoding — open with
a hex viewer). Published by explicit operator decision (treat as burned): anyone can recompute and
confirm the HMAC seals above, at the cost that the seals are now verification/demo artifacts, not
tamper-proofs.

## Honest notes

- `jimmyy.json` is run #2, not a typo'd duplicate — different window, different seal
  (`71f30934…`), same counts.
- Nothing here was post-processed: byte-for-byte what `agentropix-sift run` wrote to disk.
- The polished narrative of the recorded third run lives one level up:
  [`../README.md`](../README.md), [`../EXECUTION-LOG.md`](../EXECUTION-LOG.md).
