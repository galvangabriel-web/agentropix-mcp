# Analyst / Technical Report — MEMDUMP-RAW-2014

*Report ID:* `f88af671285cb767c774789b8c5862126be94c157308a69dc72f236e90de971e`  ·  *Snapshot:* 2026-06-07T01:35:39.033443+00:00

> **Likelihood scale (FIRST 5-tier):** almost_certain > highly_likely > likely > unlikely > remote. Likelihood estimates the probability of the assessed activity; it is kept separate from analytic confidence.
>
> **Confidence (LCA):** high / moderate / low — the analyst's confidence in the assessment given evidence quality and corroboration. Distinct from likelihood.

## Findings

<a id="raw-512-mib-memory-image-has-no-profile-matchable-kernel-symbol-table-volatility3-cannot-validate-kernel-layer-name-symbol-table-name-pslist-netscan-malfind-svcscan-all-return-empty-unattributed-2014-capture-no-injected-rwx-code-assessable"></a>
### Raw 512 MiB memory image has no profile-matchable kernel symbol table (Volatility3 cannot validate kernel.layer_name/symbol_table_name); pslist/netscan/malfind/svcscan all return empty - unattributed 2014 capture, no injected/RWX code assessable
- **Finding ID:** `F-MEMDUMP-001`  ·  **Severity:** low  ·  **Likelihood:** unlikely  ·  **Confidence:** high  ·  **Risk score:** 4

_Evidence:_ `evidence: /cases/memdump/memdump.mem sha256=d3b13f2224cab20440a4bb3c5c971662be6e61f431340f319cef7312bb6177f4 (512 MiB / 536870912 bytes), evidence_id=aa320ff2106af0ebd72e36342f537fc5672c8a94d95f9106fd2c87bf3db2a04f`<br>`Volatility3 2.28.0 get_pslist: process_count=11 (pid-0 'unknown' placeholders) - raw_stderr 'Unable to validate the plugin requirements: plugins.PsList.kernel.layer_name/symbol_table_name'`<br>`Volatility3 get_netscan: socket_count=0 - 'Unable to validate the plugin requirements: plugins.NetScan.kernel.layer_name/symbol_table_name'`<br>`Volatility3 get_malfind: hit_count=0 (no injected/RWX code assessable) - 'Unable to validate the plugin requirements: plugins.Malfind.kernel.layer_name/symbol_table_name'`<br>`Volatility3 get_svcscan: service_count=0 - 'Unable to validate the plugin requirements: plugins.SvcScan.kernel.layer_name/symbol_table_name'`<br>`build_process_tree: process_count=11, root_count=1, orphan_count=0, suspicious_count=0 (one 'unknown' root, 0 LOLBin flags)`

## Indicators of Compromise

_No IOCs extracted._

## Timeline

_No approved timeline events._
