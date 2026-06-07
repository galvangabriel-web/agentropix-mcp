# SRL-2018 Runbook — CLI Capture (hybrid approach)

Live terminal capture of the **runnable shell subset** of
[`../../case-runbook-srl-2018.md`](../../case-runbook-srl-2018.md), produced with the **hybrid
approach**: `asciinema` for the CLI (tiny, sharp, replayable) + an animated **GIF** for inline GitLab
preview. All output is **real**, run live against `/cases/SRL-2018/` on this host.

> Default model for the agents that produced and reviewed this: **Opus 4.8** (`claude-opus-4-8`).

## Preview

![SRL-2018 CLI capture](srl-2018-cli.gif)

## Artifacts

| File | Size | Purpose |
|---|---:|---|
| `srl-2018-cli.cast` | 4.4 KB | **Source of truth** — asciinema v2 cast; replay with `asciinema play srl-2018-cli.cast` (sharp, selectable, seekable) |
| `srl-2018-cli.gif` | 248 KB | Inline preview (renders natively in GitLab markdown; no JS player needed) |
| `srl-2018-cli.transcript.txt` | 3.0 KB | Plain-text transcript — greppable, screen-reader friendly, diff-able |
| `capture-cli.sh` | 1.8 KB | The exact script that was recorded — re-run to reproduce |

Replay the cast: `asciinema play srl-2018-cli.cast` · Re-render the GIF:
`agg --font-size 16 --speed 1.4 --theme asciinema srl-2018-cli.cast srl-2018-cli.gif`

## What this captures (and what it can't)

The runbook is mostly **MCP tool calls** that execute against the MCP server (not a shell) and a few
steps that **don't run on this host**. This capture therefore covers the **runnable shell subset**:

- `agentropix-sift --help` → proves the installed CLI (v0.1.0.dev0) has **only `run` + `doctor`**.
- `agentropix-sift evidence-gate mint` → **"No such command"** — documents the template drift live.
- `ewfinfo base-dc-cdrive.E01` → real acquisition metadata (MD5 `e18b4501…ada27`, examiner Clint Barton).
- `fls -i ewf -o 0` vs `-o 63` → proves these E01s are **volume images (NTFS at offset 0)**.
- `img_stat` → image type/size confirmation.
- inventory counts → **7 E01 / 22 .img / 21 .md5**, and names the one `.img` with no `.md5`.
- `verify_seal.py` presence at its off-PATH absolute path.

**Not capturable as a terminal recording** (narrated in the runbook, not filmed): the MCP tool calls
(`get_pslist`, `record_finding`, `wazuh_publish_iocs`, …) need a driving MCP client; the autonomous
`agentropix-sift run` over the 33 GiB DC image is long-running; live `[MUT]` writes are token-gated.
There are **no GUI surfaces running** on this host (Approval Portal / Wazuh dashboards are down), so no
screenshots were taken — if those come up, capture them as high-res PNGs (the GUI half of the hybrid).

## Format evaluation (your question, answered with real numbers)

Same captured content, encoded every way, measured on this host:

| Format | Size | × vs cast | Text legible? | Notes |
|---|---:|---:|:--:|---|
| **asciinema `.cast`** | **4.4 KB** | **1×** | ✅ vector, selectable | best for space + readability; needs a player to view |
| plain transcript `.txt` | 3.0 KB | 0.7× | ✅ | smallest; no animation |
| **animated GIF (agg)** | **248 KB** | **~57×** | ✅ crisp raster | renders inline in GitLab; the hybrid's preview |
| MP4 — `yuv420p` (space-tuned) | 416 KB | ~96× | ⚠️ softened | 4:2:0 chroma subsampling blurs small text |
| MP4 — `yuv444p` (text-legible) | 608 KB | ~140× | ✅ | **largest of all** — legibility kills the space saving |

**Verdict — answering "ffmpeg webCLI vs regular mp4":** for CLI content, **neither MP4 wins**. The MP4
you'd actually accept for readability (`yuv444p`) is the **biggest** artifact here — 140× the cast and
2.4× the GIF. MP4 only earns its place for **GUI/video** content, of which this runbook has none.

**Recommendation (taken): hybrid = `.cast` (source) + `.gif` (inline preview) + `.txt` (accessible).**
Total committed = **268 KB**, fully text-legible, replayable, and diff-able — versus 416–608 KB for a
single MP4 that's either blurry or bigger. This also matches the repo's own precedent: see the
*"Honest note on recorded media"* in [`../../demo-walkthrough.md`](../../demo-walkthrough.md), where
two MP4 attempts were withdrawn in favour of text artifacts.

## GitLab upload

These are small text + raster assets committed **directly into the repo** (no Git LFS, no release
artifact needed) — consistent with the existing `assets/*.svg` here. The GIF renders inline in the
GitLab file/blob view and in any markdown that embeds it; the `.cast` is the canonical replayable
source.
