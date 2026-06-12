# Full-Run Execution Evidence (machine-readable)

This folder holds the strongest machine-readable evidence that the engine's published claims
correspond to real, timestamped tool executions — two complete sealed run reports plus the
transcripts of the session that produced them. Nothing here is curated output: the failure
records (rate-limit errors, a budget-exhausted run that found almost nothing) are committed
unedited alongside the successes.

All files are sanitized copies of `audit-out/` from the private repo: absolute home-directory
paths are rewritten to `~/`, and no secrets or session keys are included (see
[Why the session keys are excluded](#why-the-session-keys-are-excluded)).

## What each file is

| File | What it is |
|------|------------|
| `report-dc.json` | The full Trinity-Loop run against the SRL-2018 domain-controller E01 disk image (`/cases/SRL-2018/base-dc-cdrive.E01`). Status `complete`, 2 of 5 iterations (deterministic halt), **275 findings**, **212 timestamped tool calls** in `trace.tool_calls` (each with `timestamp`, `duration_ms`, and — for MCP-boundary calls — `args_hash`, `exit_code`, `output_hash`, and the `raw_output` envelope), a **131-entry `thymus_audit`** (every evidence-path access decision: 131 ALLOW, 0 DENY), the per-iteration Trinity trace (`iterations[]`: plan → stable/dropped agents → gaps → critic score → halt decision), six `completion_proofs`, the evidence image SHA-256, and the HMAC `report_seal`. Run window: 2026-05-03 02:46:49 → 04:09:53 UTC (~83 min). |
| `report-sample.json` | The same pipeline against the tiny synthetic `samples/sample.dd` image. Status **`budget_exhausted`**: the loop ran all 5 iterations, four planned agents produced 0 findings each iteration, the critic kept returning `continue: plan gap …`, and the engine reported the failure honestly instead of inventing findings. 38 tool calls, 3 findings (all low/zero-confidence skip/empty markers). This is committed as honest-failure evidence, not as a success. |
| `02-sample-seal-check.txt` | Transcript of the seal verification for the sample run: `verify_seal: True` against the 32-byte session key, with the matching findings/tool-call counts (3 / 38). Proof the seal procedure was actually exercised. |
| `00-environment.txt` | The host fingerprint at run time (Phase 2 SIFT live-fire, 2026-05-03): kernel, uv, Python, glibc versions on the SIFT workstation. |
| `01-doctor.txt` | The pre-run `doctor` toolchain check: 15 forensic tools resolved to real binaries (Volatility3, Plaso, Sleuth Kit, RegRipper, YARA, bulk_extractor, …) and **3 honestly reported MISSING** (Prefetch/Amcache/Shimcache parsers) — the run proceeded with that gap on record. |

Not copied: `*.session-key` (HMAC keys — see below), and the raw evidence images themselves
(SANS/NIST forensic datasets are referenced by path and SHA-256 only, never committed).

## How to trace a finding to its tool execution (worked example)

Every finding in `findings[]` can be walked back to the tool call that produced its evidence.
Worked example — the T1053.005 scheduled-task persistence finding in `report-dc.json`:

1. **The finding.** Search `findings[]` for `CreateExplorerShellUnelevatedTask`:

   ```json
   {
     "_source": "artifact.scheduled_task",
     "confidence": 0.5,
     "description": "[T1053.005 Scheduled Task — beacon scheduled persistence candidate] Scheduled task (schtasks) CreateExplorerShellUnelevatedTask: command=C:\\Windows\\explorer.exe triggers=RegistrationTrigger",
     "evidence": "schtasks path=/Windows/System32/Tasks/CreateExplorerShellUnelevatedTask author=ExplorerShellUnelevated args=/NOUACCHECK run_level=LeastPrivilege user=shieldbase\\Administrator",
     "mitre_attack": "T1053.005"
   }
   ```

2. **The tool call that extracted that artifact.** Search `trace.tool_calls[]` for the same
   path. At `2026-05-03T04:09:02.462122+00:00` there is:

   ```json
   {
     "tool": "mcp.extract_files.icat",
     "timestamp": "2026-05-03T04:09:02.462122+00:00",
     "duration_ms": 905.28,
     "result_summary": "ok /Windows/System32/Tasks/CreateExplorerShellUnelevatedTask -> 3662B sha256=f7685939206e"
   }
   ```

   The paired `mcp.extract_files` envelope entry (same timestamp window) carries
   `args_hash`, `exit_code: 0`, `output_hash`, and a `raw_output` JSON naming the source image
   (`/cases/SRL-2018/base-dc-cdrive.E01`), the inode, the extracted size (3662 bytes), and the
   full SHA-256 whose 12-char prefix appears in the `result_summary`.

3. **The boundary check.** The `thymus_audit[]` entries for the same window show the evidence
   path was `ALLOW`ed as "within read-only zone" — the call could not have written to evidence.

So the chain is: finding → artifact path → `icat` extraction call (timestamp, duration,
content hash) → Thymus access decision → source image SHA-256 (`evidence_image_sha256`).
The same walk works for any of the 275 findings.

## The rate-limit failure cluster (genuine, unedited)

At the very end of the DC run (`2026-05-03T04:09:52.999…`), `trace.tool_calls` contains a
cluster of **69 consecutive `mcp.extract_files` calls with `exit_code: 1`** and
`result_summary: "ERROR: Rate limited: extract_files exceeded 60 calls/minute"`. The
ArtifactAgent's scheduled-task sweep hit the MCP server's per-tool rate limiter and every
rejected call was recorded with its non-zero exit code — none were retro-edited or dropped
from the trace. This cluster is left in deliberately: a trace in which 212 calls all exited 0
would be the suspicious one. It also demonstrates the rate limiter is real and enforced at the
tool boundary, not just documented.

`report-sample.json` is the second, larger-grained honest failure: an entire run that ended
`budget_exhausted` with effectively no findings, sealed and kept rather than re-rolled.

## Why the session keys are excluded

Each run writes a sibling `<report>.session-key` file: 32 random bytes used as the HMAC-SHA256
key for the report seal. The key is what makes the seal **tamper-evident to its holder** —
publishing it would let anyone re-seal a modified report, which defeats the entire purpose.
The keys therefore stay on the originating workstation (mode-restricted, outside any repo) and
only the verification *procedure* is published:

1. Load the report JSON and pop `report_seal`, substituting the literal `"__sealed__"`.
2. Canonicalize: `json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
3. Compute `hmac.new(key, payload, hashlib.sha256).hexdigest()` with the 32-byte session key.
4. Compare against the recorded `report_seal` with `hmac.compare_digest`
   (implementation: `seal_report` / `verify_seal` in `src/agentropix_sift/courtroom.py`).

`02-sample-seal-check.txt` is the recorded transcript of exactly this check passing
(`verify_seal: True`) against the original artifacts.

**Note on these copies:** the JSONs here were path-sanitized for publication (`/home/<user>` →
`~`), so re-running the HMAC over *these copies* will not reproduce the recorded seal
byte-for-byte. The seals verify against the unmodified originals retained with their keys on
the evidence workstation; the `report_seal` and `evidence_image_sha256` values themselves are
unchanged here so they can be compared against those originals.
