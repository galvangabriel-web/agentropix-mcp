# Analyst / Technical Report — CTF-CONTACT-ME-MEM

*Report ID:* `65edb19d6a108c6036b55d1c3516abee06a99719e79417d9c6cbda7669c01166`  ·  *Snapshot:* 2026-06-07T01:33:07.469554+00:00

> **Likelihood scale (FIRST 5-tier):** almost_certain > highly_likely > likely > unlikely > remote. Likelihood estimates the probability of the assessed activity; it is kept separate from analytic confidence.
>
> **Confidence (LCA):** high / moderate / low — the analyst's confidence in the assessment given evidence quality and corroboration. Distinct from likelihood.

## Findings

<a id="memory-image-unprofileable-volatility3-2-28-0-could-not-validate-a-windows-kernel-symbol-table-so-pslist-netscan-malfind-svcscan-returned-placeholder-empty-results-no-clean-or-compromised-determination-possible"></a>
### Memory image unprofileable: Volatility3 2.28.0 could not validate a Windows kernel symbol table, so pslist/netscan/malfind/svcscan returned placeholder/empty results (no clean-or-compromised determination possible)
- **Finding ID:** `F-CONTACTME-001`  ·  **Severity:** medium  ·  **Likelihood:** unlikely  ·  **Confidence:** high  ·  **Risk score:** 6

_Evidence:_ `evidence SHA-256 1ab5eb6c3b87a0604f75a00cb4a64d91aaf7ab4e303bb7337b40f7e3df8ad61a (/cases/contact_me/contact_me, 1073741824 bytes = 1 GiB)`<br>`get_pslist: process_count=11, all rows placeholder pid:0 name:'unknown'; raw_stderr 'Unable to validate the plugin requirements: [plugins.PsList.kernel.layer_name, plugins.PsList.kernel.symbol_table_name]'`<br>`get_netscan: socket_count=0 (volatility3.windows.netscan.NetScan), raw_stderr 'Unable to validate the plugin requirements: [plugins.NetScan.kernel.layer_name, plugins.NetScan.kernel.symbol_table_name]'`<br>`get_malfind: hit_count=0 (volatility3.windows.malfind.Malfind), raw_stderr 'Unable to validate the plugin requirements: [plugins.Malfind.kernel.layer_name, plugins.Malfind.kernel.symbol_table_name]'`<br>`get_svcscan: service_count=0 (volatility3.windows.svcscan.SvcScan); build_process_tree: process_count=11 root_count=1 single pid:0 'unknown' root, suspicious_count=0`<br>`run_volatility plugin=cmdline: error 'vol3 emitted non-JSON output: Expecting value: line 2 column 1 (char 1)'`

## Indicators of Compromise

_No IOCs extracted._

## Timeline

_No approved timeline events._
