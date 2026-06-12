# SRL-2018 Training Session — Action Recording

> **Purpose:** capture **every action (command + response)** from the moment the recorder was armed
> until the session ends, for **training**. Modelled on the
> `srl-2018-dc-execution/` format (operator-host-only folder, not in this repo)
> (cast → MP4 + GIF + transcript + a technical MD).

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

- Armed: 2026-06-07 (see log header) · Active case: `SRL-2018-COMPROMISED-ENTERPRISE`
- MCP server live at `http://100.85.162.82:8765/mcp` (72 tools).

## At session end (produced on "done")

1. Render `session-actions.log` → an asciinema `.cast` → **`training-session.mp4`** + GIF (legible,
   hi-res source).
2. A plain-text **transcript** and a technical **MD** summarising every numbered step.
3. The `.cast` is kept as the faithful regen source (same approach as the DC execution report).
