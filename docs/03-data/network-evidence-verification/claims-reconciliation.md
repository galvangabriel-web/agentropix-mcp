# Network / pcap Claims Reconciliation — docu_agentro (branch fix/stage-one-gaps)

Date: 2026-06-13. Ground truth: verified evidence inventory (magic-byte sweep of `/cases` + extraction
working dirs) — 11 pcap-magic files: 5 ACQUIRED (3 DFRWS `rhino*.log` + 2 Vanko 802.11 `.pcap`),
6 CARVED (`bulk_extractor packets.pcap`). Capability boundary: the Agentropix SIFT tool chain does
NOT parse pcap; network visibility = EVTX/SRUM/registry/memory `netscan` + nist2 CSV.

| Claim | File:line | Classification | Action taken |
|---|---|---|---|
| "The corpus contains no acquired network captures … find … returns nothing" | docs/03-data/evidence-datasets.md:50 (old) | UNDERCLAIM (falsified) | Rewrote §2 into §2a (5 acquired captures: 3 DFRWS rhino*.log + 2 Vanko Wi-Fi, with paths/sizes/magic/provenance), §2b (6 carved pcaps), §2c (capability boundary: SIFT does not parse pcap). |
| Carved-pcap sizes "64 KB / 302 KB / 966 KB" | docs/03-data/evidence-datasets.md:63,65-67 (old) | OVERCLAIM (rounding mismatch) | Corrected to verified 62 KB / 295 KB / 943 KB; added exact 301,634 B for the three identical Hacking Case carves. |
| §3: "No acquired network captures exist (§2)" | docs/03-data/evidence-datasets.md:86 (old) | UNDERCLAIM (falsified) | Replaced with "Acquired network captures: 5" bullet (3 DFRWS + 2 Vanko) + SIFT-does-not-parse-pcap caveat. |
| nist5 row "Network capture? No" | docs/03-data/evidence-datasets.md:28 | UNDERCLAIM | Changed to "Yes — 3 acquired pcaps (rhino*.log)"; added pcaps to evidence-types cell; noted SIFT does not parse pcap. |
| vanko row "Network capture? No" | docs/03-data/evidence-datasets.md:30 | UNDERCLAIM | Changed to "Yes — 2 pcaps on the suspect disk (testpcap.pcap, starbucks pcap.pcap, 802.11+radiotap)"; noted SIFT does not parse pcap. |
| nist2 row "No (CSV logs only, not a pcap)" | docs/03-data/evidence-datasets.md:25 | TRUE | Left unchanged (tabular telemetry, correctly distinguished from packets). |
| README index: "network-capture story (no acquired pcaps; six bulk_extractor-carved)" | docs/03-data/README.md:13 | UNDERCLAIM | Corrected to "five acquired pcaps — three DFRWS rhino*.log + two Vanko Wi-Fi captures; six bulk_extractor-carved; the SIFT chain does not parse pcap". |
| reproduce-datasets DFRWS row: "plus scenario pcaps" | docs/06-use-cases/reproduce-datasets.md:48 | TRUE | Left unchanged (correctly states scenario pcaps exist). |
| case-activation/README.md: "Companion rhino*.log files are actually pcap captures, out of scope" | case-activation/README.md:57 | TRUE | Left unchanged (honest; matches inventory). |
| dfrws-2005-rodeo-usb.md companion-pcaps note + custody-register lines | case-activation/dfrws-2005-rodeo-usb.md:24,84,107-111,277 | TRUE | Left unchanged (already honest: pcaps exist, SIFT does not parse, register for custody only). Sizes 288K/224K are pre-existing rounding, not introduced by this task; not contradicting. examiner_id values pre-existed — none added. |
| vanko-report DLP recommendation mentioning "netflow" retention | docs/12-CASES-REPORTS/vanko-report/VANKO-DFIR-REPORT.md:320 | TRUE (not a corpus claim) | Left unchanged (forward-looking DLP recommendation, not a claim about corpus contents or pcap analysis). |
| docs/07-sdlc-ops/dataset-recall.md | (no network/pcap hits) | n/a | No network-capture or pcap-capability claims present. |
| docs/08-reference/canonical-facts.md | (no network/pcap hits) | n/a | No network-capture or pcap-capability claims present. |

## Verification

Re-ran `grep -rniE "no acquired|contains no.*captur|no.*pcap|nothing under" --include="*.md"` —
zero statements remain that contradict the verified inventory. All surviving pcap/network mentions
are TRUE against ground truth or correctly state the SIFT-does-not-parse-pcap capability boundary.

## Sanitization

No absolute `~` paths introduced (evidence referred to as `/cases/...`). No new examiner_id
values or emails added. No new claims without verified backing.
