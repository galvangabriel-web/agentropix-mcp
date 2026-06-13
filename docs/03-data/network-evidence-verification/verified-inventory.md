# Network-Capture Evidence — Verified Inventory (magic-byte sweep)

Date: 2026-06-13
Scope: all of `/cases` (every depth) and `/tmp/agentropix-sift-*` (to depth 6).
Constraint: read-only on `/cases` and `/tmp`; detection by FILE MAGIC, not by extension.

## Methodology note — extension search vs magic search

The prior corpus note (`docs/03-data/evidence-datasets.md` §2) ran an
**extension-only** search:

```
find … -iname "*.pcap*" -o -iname "*.cap" -o -iname "*netflow*"
```

and concluded "**The corpus contains no acquired network captures**." That conclusion is
**FALSE**. An extension match cannot see a pcap whose name does not end in a capture
extension. Two whole classes of acquired captures were therefore invisible:

1. **DFRWS2005-RODEO `rhino*.log`** — named `.log` but are real `pcap v2.4` Ethernet
   captures (magic `d4 c3 b2 a1`). Extension search skips them because `.log` is not in
   the pattern.
2. **Vanko scenario `*.pcap`** — these *do* end in `.pcap`, but they live inside the
   suspect disk image (`/cases/vanko/surface_physical.E01` / `VANKO.zip`) and only appear
   on disk once the image is mounted/extracted to a working dir. The §2 search ran over the
   *evidence store as packaged* (the E01s/zip), not the extracted file tree, so it never
   traversed into the carved-out filesystem where the `.pcap` files surface.

The corrected approach: `find` with `-size -2000M` + extension *candidate* prefilter
(`*.log *.cap *.pcap* *.dmp *.bin *.dat`) piped through `xargs file`, then
`grep -Ei 'pcap|capture file|tcpdump'`. The candidate prefilter is a performance bound, not
a truth filter — every hit is confirmed by `file(1)` magic, and spot-checked with
`xxd -l 16` (`d4 c3 b2 a1` = little-endian microsecond pcap v2.4).

Corrected headline: **the corpus DOES contain acquired network captures** — the three
DFRWS rhino logs and the two Vanko Wi-Fi captures — in addition to the six
bulk_extractor-carved `packets.pcap` derivatives.

## ACQUIRED captures (scenario/source data shipped with a dataset)

| Path | Size | File magic | Provenance |
|---|---|---|---|
| `/cases/nist5/DFRWS2005-RODEO/rhino.log` | 3,187,907 B (~3.0 MB) | pcap capture file, microsecond ts (LE) — v2.4 (Ethernet, snaplen 65000) | DFRWS 2005 Rodeo challenge dataset; acquired wire capture mislabeled `.log` |
| `/cases/nist5/DFRWS2005-RODEO/rhino2.log` | 292,604 B (~286 KB) | pcap capture file, microsecond ts (LE) — v2.4 (Ethernet, snaplen 65000) | DFRWS 2005 Rodeo dataset; acquired capture, `.log` name |
| `/cases/nist5/DFRWS2005-RODEO/rhino3.log` | 226,094 B (~221 KB) | pcap capture file, microsecond ts (LE) — v2.4 (Ethernet, snaplen 65000) | DFRWS 2005 Rodeo dataset; acquired capture, `.log` name |
| `/tmp/agentropix-sift-vanko/collect/documents-media/Documents/testpcap.pcap` | 147,899 B (~144 KB) | pcap capture file, microsecond ts (LE) — v2.4 (802.11 w/ radiotap, snaplen 65535) | Acquired Wi-Fi capture residing on the Vanko suspect disk (`/cases/vanko/surface_physical.E01` / `VANKO.zip`), surfaced into the extraction working dir |
| `/tmp/agentropix-sift-vanko/collect/documents-media/Documents/starbucks pcap.pcap` | 195,688 B (~191 KB) | pcap capture file, microsecond ts (LE) — v2.4 (802.11 w/ radiotap, snaplen 65535) | Acquired Wi-Fi capture from the Vanko suspect disk; same extraction provenance |

Note on Vanko: these are *acquired* in the forensic sense (they are real wire captures the
suspect possessed), but on this host they only exist inside an extracted/mounted view of the
disk image — there is no loose `.pcap` directly under `/cases`. The authoritative source is
the E01/zip; the `/tmp/...vanko/collect/...` copies are the extracted instances.

## CARVED captures (bulk_extractor-derived from disk/memory) — all six VERIFIED PRESENT

| Path | Size | Derived from |
|---|---|---|
| `/tmp/agentropix-sift-srl2015-ctrl-be/packets.pcap` | 34,072 B (~33 KB) | SRL-2015 win2008R2 controller C-drive E01 (bulk_extractor) |
| `/tmp/agentropix-sift-srl2018-be/packets.pcap` | 63,624 B (~62 KB) | SRL-2018 evidence (bulk_extractor) |
| `/tmp/agentropix-sift-nist1/packets.pcap` | 301,634 B (~295 KB) | NIST CFReDS Hacking Case disk, run 1 (bulk_extractor) |
| `/tmp/agentropix-sift-nist1-run3/packets.pcap` | 301,634 B (~295 KB) | Same Hacking Case disk, run 3 — identical size (deterministic) |
| `/tmp/agentropix-sift-validate-be/packets.pcap` | 301,634 B (~295 KB) | Same Hacking Case disk, validation re-run — matches runs 1/3 |
| `/tmp/agentropix-sift-bulk-87exw9p0/packets.pcap` | 965,681 B (~943 KB) | Ad-hoc bulk_extractor run (2026-06-08) |

All six exist; the three identical-size (301,634 B) Hacking Case carves reproduce the §2
determinism observation. These are derived/regenerable artifacts in ephemeral working dirs,
not primary evidence.

## Other network-evidence artifacts (NOT packet captures)

- **nist2 attack-log CSV** — `/cases/nist2/archive/cybersecurity_attacks_data.csv` (17,450,894 B, ~16.6 MB): tabular network-attack telemetry, not packets; plus the companion page `/cases/nist2/cyber-attack-detection-and-network-traffic.htm`.
- **EVTX network events** — per-host EVTX extraction dirs `/tmp/agentropix-sift-srl2018-evtx{,-dmz-ftp,-file,-rd-01,-rd-02,-wkstn-01,-wkstn-05}` hold Windows event logs carrying network-relevant events (logons, firewall, share access), not captures.
- **SRUM network tables** — SRUM (`SRUDB.dat`) network-usage tables are available within the SRL-2018 disk/registry extraction set (per-host `srl2018-*` dirs); these are per-app network byte counters, not captures.
- **Memory netscan availability** — full memory images (`/cases/memdump/memdump.mem`, `/cases/AMF_MemorySamples/`, plus SRL-2015/2018 raw `.001`/`.img` dumps) support Volatility `netscan` for memory-resident socket/connection data — derived network state, not wire captures.

## Reconciliation action

`docs/03-data/evidence-datasets.md` §2 ("The corpus contains no acquired
network captures") and §3 ("No acquired network captures exist") are both now CONTRADICTED
by magic-byte evidence and should be corrected to acknowledge the 3 DFRWS rhino captures and
the 2 Vanko Wi-Fi captures.
