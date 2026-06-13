# Network-Capture Evidence Verification — Proof Package

> **Why this folder exists.** An early corpus audit (extension-only `find -iname "*.pcap*"`)
> concluded the evidence corpus contained **no acquired network captures**. A re-verification
> by **file magic** (`file(1)` + first-16-bytes hex) proved that conclusion wrong and corrected
> the record. This folder is the complete, reproducible proof trail — published in full because
> *honesty about a self-caught error is part of the submission's accuracy story*.

## What was wrong, and how it was caught

The extension search could not see pcaps whose names don't end in a capture extension.
Two whole classes of real captures were invisible:

1. **DFRWS 2005 Rodeo `rhino*.log`** — three genuine `pcap v2.4` Ethernet wire captures
   (magic `d4 c3 b2 a1`) shipped with the challenge dataset under a `.log` name.
2. **Vanko suspect-disk Wi-Fi captures** — two `.pcap` files (802.11 + radiotap) that live
   *inside* the suspect's disk image and only surface in the extracted file tree, which the
   packaged-evidence-store search never traversed.

The corrected sweep (candidate prefilter → `xargs file` → magic confirmation → `xxd` spot-check)
found **5 acquired + 6 carved** captures. The self-correction is itself documented evidence of
the project's verification discipline: the false claim was caught by re-checking with a stronger
method, and every affected statement in this repository was reconciled.

## Folder contents

| File | What it proves |
|---|---|
| [`verified-inventory.md`](verified-inventory.md) | The full corrected inventory: 5 acquired captures (3 DFRWS rhino + 2 Vanko Wi-Fi), 6 bulk_extractor-carved `packets.pcap`, all other network-evidence artifacts (nist2 CSV telemetry, EVTX, SRUM, memory netscan) — with the methodology note explaining exactly why the extension search failed. |
| [`raw-verification-capture.md`](raw-verification-capture.md) | The raw, dated command transcript: `file(1)` magic line, `xxd -l 16` header bytes, **SHA-256**, and byte size for **all 11 captures**. Anyone holding the source datasets can re-derive and compare hashes. |
| [`claims-reconciliation.md`](claims-reconciliation.md) | Claim-by-claim table (file:line, classification TRUE/OVERCLAIM/UNDERCLAIM/MISLEADING, action taken) showing every network-related statement in this repository reconciled to the verified inventory. |

## Honesty notes (read before citing)

- **The SIFT tool chain does not parse pcap.** The captures are inventoried evidence with
  chain-of-custody value; the agent's network visibility comes from disk/memory artifacts
  (EVTX logon/share events, SRUM per-app network tables, registry, memory `netscan`).
  No finding in any report claims pcap analysis.
- **Carve determinism, precisely stated:** the three NIST Hacking-Case carves
  (`packets.pcap` from independent bulk_extractor runs) have **identical sizes (301,634 B)
  but differing SHA-256s** — the carve is size-stable across runs, not byte-identical.
  An earlier note called this "deterministic"; the hashes in `raw-verification-capture.md`
  show the stricter truth.
- **Provenance:** the DFRWS captures are scenario data from the public DFRWS 2005 Rodeo
  challenge; the Vanko captures are case evidence found on the suspect disk image. Raw
  captures are **not redistributed** in this repository — obtain the source datasets from
  their publishers and verify against the hashes here.
