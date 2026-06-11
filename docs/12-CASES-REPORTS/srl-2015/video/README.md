# SRL-2015 investigation — command replay video

A screen-capture-style walkthrough of the **SRL-2015-APT-ENTERPRISE** investigation, from
evidence intake through Wazuh integration, threat-intel enrichment, malware quarantine, deep
reverse-engineering, and the final deliverable.

> **It is a faithful *reenactment*, not a live capture.** The replay shows the **real commands**
> we ran and the **real results** we got (2,233 findings, 2,874 indexed, 12 malicious IOCs, 21
> quarantined samples). Destructive/irreversible steps (Wazuh pushes, IOC merges, VT/OTX egress,
> evidence carving) were **not** re-executed to make the video — they are replayed for the record.

## Files
| File | What it is |
|---|---|
| `SRL-2015-investigation.mp4` | Full video — H.264, 1446×1184, ~53 s, 8 MB |
| `SRL-2015-investigation-web.mp4` | Web-optimized (smaller, scaled, `+faststart`) for sharing/embedding |
| `SRL-2015-investigation.gif` | Same content as an animated GIF (inline in chats/wikis) |
| `session.cast` | asciinema v2 source — re-render any format with `agg` |
| `playback.sh` | The replay script (the command timeline) |
| `render.sh` | Record → GIF → MP4 pipeline (asciinema + agg + ffmpeg) |

## How to play
- **Desktop:** `mpv SRL-2015-investigation.mp4` or `vlc …`, or open the `.mp4` in any browser.
- **Terminal (native):** `asciinema play session.cast` (crispest; real selectable text).
- **Inline:** drop the `.gif` into a chat / GitHub or GitLab issue / wiki page.
- **On github.com:** only the `.gif` plays inline in Markdown — GitHub's sanitizer strips
  `<video>` tags, so a repo-committed `.mp4` cannot be embedded; download it via the **Raw**
  button on the file page (raw serves `application/octet-stream`) and play locally.
- **Re-render** (e.g. different theme/size): `agg --theme dracula --font-size 20 session.cast out.gif`.

## Chapters (approx. timecodes — video is ~53 s)
| ~Time | Phase |
|---|---|
| 0:00 | Title |
| 0:03 | **0 ·** Recon & readiness (case lookup, cluster reachability, MCP health) |
| 0:08 | **1 ·** Process 4 hosts — autonomous DFIR swarm (`-n 15`) → 2,233 findings |
| 0:17 | **2 ·** Push findings to Wazuh (dry-run → live, append/merge IOCs, VANKO preserved) |
| 0:23 | **3 ·** Threat-intel enrichment (VirusTotal + OTX) → 12 malicious |
| 0:29 | **4 ·** Verify live on `<WAZUH-INDEXER>` + screenshot (`_count` 2,874 / 12) |
| 0:34 | **5 ·** Consolidated deliverable (full + executive PDF, IOC/EAR export, STIX) |
| 0:39 | **6 ·** Carve + quarantine executables (read-only mount, `zip -e`, SHA-256 manifest) |
| 0:43 | **7 ·** Recover memory-injection payloads (Volatility3 `malfind`) → 5, hash-verified |
| 0:47 | **8 ·** Deep static RE (VB6 LZMA injection loader, 2 variants, YARA) → 10 findings |
| 0:50 | **9 ·** Final deliverable tree |

## Provenance
Real run, 2026-06-10, against the live Agentropix-SIFT MCP server and Wazuh cluster
`https://<WAZUH-INDEXER>:9200`. Every figure shown is cross-checked against the artifacts under
`Reports_results/SRL2015-DELIVERABLE/` and the hash-chained decision ledger
(`~/.openclaw/ledger/decisions.jsonl`, run-id `srl2015-pipeline`).
