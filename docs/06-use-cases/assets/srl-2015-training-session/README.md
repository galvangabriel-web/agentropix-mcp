# SRL-2015 Training Session — Action Recording

> **Purpose:** capture **every action (command + response)** from the moment the recorder was armed
> until the session ends, for **training**. Modelled on the
> [`srl-2018-training-session/`](../srl-2018-training-session/README.md) format
> (cast → MP4 + GIF + transcript + a technical MD).

**Case:** `SRL-2015-APT-ENTERPRISE` — Stark Research Labs APT (SANS FOR508), 4 Windows hosts
(XP `tdungan`, Win7x32 `nromanoff`, Win7x64 `nfury`, Win2008R2 `controller`), each a C-drive E01 +
raw memory `.001` (56 GB).

## How it records (survives across separate tool calls)

The recorder is **filesystem-backed**, so it accumulates across every command regardless of shell
resets:

- `session-actions.log` — the master log; one numbered, UTC-timestamped block per action containing
  the command line(s), the live stdout/stderr, and the exit code (ANSI colour preserved for the
  later cast render).
- `rec.sh` — the logger. Each action is run as: write the command into `_step.sh` via a quoted
  heredoc (so any inner quoting is safe), then `bash rec.sh "<description>"` appends + executes it.
- **Capture mode: EVERYTHING VERBATIM** (operator-selected). Non-shell actions (Read / Edit / Write /
  Agent) are logged with their **full content** — file bodies read/written, edit diffs, and subagent
  prompts + results — not just one-line annotations. Larger log, maximally complete for training.

## Armed state

- Armed: 2026-06-09 (see log header) · Active case: `SRL-2015-APT-ENTERPRISE`
- MCP server live at `http://100.85.162.82:8765/mcp` (tool_count 72).
- **Scope:** whole-case. The initiation + first-pass memory phase that ran *before* the recorder was
  armed is **backfilled** (idempotent steps re-run through `rec.sh`; the 4 already-persisted DRAFT
  findings are annotated, not re-written), then the deeper disk + correlation phase is captured live.

## At session end (produced on "done")

1. Render `session-actions.log` → an asciinema `.cast` (`make_cast_paged.py`) → **`training-session-paged.mp4`** + GIF
   (legible, hi-res source) via `agg` + `ffmpeg`.
2. A plain-text **transcript** and a technical **MD** summarising every numbered step.
3. The `.cast` is kept as the faithful regen source.

## Render commands (at "done")

```bash
cd "$(dirname "$0")"
python3 make_cast_paged.py                                  # session-actions.log -> training-session-paged.cast
agg --font-size 14 training-session-paged.cast training-session-paged.gif
ffmpeg -y -i training-session-paged.gif -movflags +faststart -pix_fmt yuv420p training-session-paged.mp4
# transcript (ANSI-stripped):
sed -r 's/\x1b\[[0-9;]*m//g' session-actions.log > training-session.transcript.txt
```
