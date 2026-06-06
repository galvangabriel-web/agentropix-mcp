# Quickstart

Install Agentropix-SIFT, pre-flight the forensic toolchain, and run your first
end-to-end triage. For background, read [What is
Agentropix-SIFT?](what-is-agentropix.md); for the full capability set, see [What You
Get](what-you-get.md).

> 📘 **Want the whole case, not just the 3-command fast path?** The
> [User Guide — Start to Finish](user-guide.md) walks a first-time operator through one
> complete case — install/pre-flight, configure, triage, **review findings, approve in the
> portal, seal the report, and (optionally) escalate to Wazuh** — with expected output at
> every phase. This Quickstart is the condensed install-and-first-run subset of it.

> **Three steps, well under two minutes** on a prepared SIFT host:
>
> ```bash
> uv sync                                          # 1. install
> uv run agentropix-sift doctor                    # 2. pre-flight the toolchain
> uv run agentropix-sift run samples/sample.dd -o report.json   # 3. first triage
> ```

---

## Contents — what's in this page (and what to expect)

> Jump to any section below. Each row tells you what that part gives you, so you can go straight to your point.

| Section | What you'll get |
|---|---|
| [Prerequisites](#prerequisites) | Python ≥ 3.12 and the SANS SIFT forensic toolchain on `PATH`, plus what happens (graceful degradation) when a tool is missing. |
| [1. Install](#1-install) | Install the Python package and its two console scripts via `uv sync` (or pip), with expected resolve/sync output and what the toolchain does (and doesn't) ship. |
| [2. Pre-flight: `agentropix-sift doctor`](#2-pre-flight-agentropix-sift-doctor) | Run the pre-flight that confirms every required forensic binary is on `PATH`, read the `OK`/`MISSING` output, and point `doctor` at non-default binaries via override env vars. |
| [3. First end-to-end triage](#3-first-end-to-end-triage) | Run a full sealed triage over the synthetic fixture, understand the three output files, inspect the findings and cryptographic anchors, and verify the seal. |
| [Where to go next](#where-to-go-next) | Follow-on reading: the capability matrix, the positioning/pipeline overview, and the shared `.crew` reference files. |

---

## Prerequisites

| Requirement | Detail |
|-------------|--------|
| **Python ≥ 3.12** | `pyproject.toml` sets `requires-python = ">=3.12"`. Stock SIFT / Ubuntu 22.04 ships 3.10 — provide 3.12 via [`uv`](https://docs.astral.sh/uv/), `pyenv`, or the `deadsnakes` PPA. |
| **SANS SIFT forensic toolchain on `PATH`** | `volatility3`, `log2timeline`, The Sleuth Kit (`fls`/`icat`/`mmls`), `ewf-tools`, `yara`, `bulk_extractor`, `regripper`, `python-evtx`, and the execution-artifact parsers. On a non-SIFT host install via the GIFT PPA (`ppa:gift/stable`). |
| **(Optional) `uv`** | The project is `uv`-native (`uv sync` / `uv run`); `pip install -e ".[dev]"` works too. |

The triage **degrades gracefully** when a tool is missing — the relevant agent is
skipped rather than the run aborting — but recall drops, so run `doctor` first.

---

## 1. Install

The package is a standard Python project with two console scripts
(`pyproject.toml`):

- `agentropix-sift` → `agentropix_sift.cli:main` (the triage CLI)
- `agentropix-sift-mcp` → `agentropix_sift.mcp_server.fastmcp_app:main` (the MCP server)

From the repository root:

> **🖥️ Expert (command):**
> ```bash
> # uv-native (recommended) — resolves the locked dependency set into a venv
> uv sync
>
> # …or with pip
> python3.12 -m venv .venv && source .venv/bin/activate
> pip install -e ".[dev]"
> ```
> **💬 End-user (prompt):** installing the Python package is an **operator-local** step — there is no MCP
> tool for it, because the MCP server only exists *after* the package is installed. Ask your administrator
> to run `uv sync` (or have them follow this page) to stand up the server; once it is connected to your
> Claude session, every later step in this Quickstart has a plain-language prompt you can use yourself.

**Execution A → Output A.**

*Execution A:*
```bash
uv sync
```

*Output A (resolved + synced venv):*
```text
Resolved 142 packages in 38ms
Installed 96 packages in 1.21s
```

Runtime dependencies include `volatility3`, `fastmcp`, `yara-python`, `pydantic`,
`typer`, `libpff-python` (PST/OST), and `extract-msg` (Outlook `.msg`) — see
`pyproject.toml`. Optional extras: `reports` (Jinja2 / WeasyPrint for rendered
reports) and `dev` (pytest / ruff / basedpyright).

> **Note.** Agentropix-SIFT does **not** ship the forensic binaries — it *drives* the
> ones already installed on SIFT. Installing the Python package gives you the
> orchestration layer; the toolchain check in the next step confirms the binaries are
> present.

---

## 2. Pre-flight: `agentropix-sift doctor`

`doctor` (`src/agentropix_sift/cli.py:175-217`) verifies the required SIFT forensic
binaries are resolvable on `PATH`. For each tool it resolves the binary — honoring an
`AGENTROPIX_<TOOL>_TOOL` override env var where one exists, so you can point it at a
SIFT-installed path without symlinking — and prints `OK <path>` or `MISSING`.

> **🖥️ Expert (command):**
> ```bash
> uv run agentropix-sift doctor
> ```
> **💬 End-user (prompt):** *"Check that my Agentropix forensic environment is ready — are all the
> forensic tools installed and is the server healthy?"*
> The session runs the same pre-flight by calling the **`health`** MCP tool (which reports the live tool
> count and server status); a non-technical operator gets a plain-language "everything's present" or "X is
> missing" answer. **A simple, focused question is enough — the session recognises this as an Agentropix
> capability and routes it to the right check.**

**Execution B → Output B** (all tools present).

*Execution B:*
```bash
uv run agentropix-sift doctor
```

*Output B (all present):*

```text
  [OK  /usr/bin/vol] Volatility3 (memory forensics) (vol)
  [OK  /usr/bin/log2timeline.py] Plaso (timeline) (log2timeline.py)
  [OK  /usr/bin/fls] Sleuth Kit (filesystem) (fls)
  [OK  /usr/bin/icat] Sleuth Kit (file extraction) (icat)
  [OK  /usr/bin/mmls] Sleuth Kit (partitions) (mmls)
  [OK  /usr/bin/ewfinfo] ewftools (E01 image metadata) (ewfinfo)
  [OK  /usr/local/bin/evtx_dump.py] python-evtx (Windows Event Log parser) (evtx_dump.py)
  [OK  /usr/bin/yara] YARA (pattern matching) (yara)
  [OK  /usr/bin/bulk_extractor] bulk_extractor (bulk_extractor)
  [OK  /usr/bin/rip.pl] RegRipper (registry hives) (rip.pl)
  [OK  /usr/local/bin/pf] Prefetch parser (execution evidence) (pf)
  [OK  /usr/local/bin/amcache_parser] Amcache.hve parser (execution evidence) (amcache_parser)
  [OK  /usr/local/bin/shimcache_parser] Shimcache parser (AppCompatCache) (shimcache_parser)
  [OK  /usr/bin/ssdeep] ssdeep (fuzzy hashing) (ssdeep)
  [OK  /usr/bin/exiftool] ExifTool (metadata) (exiftool)
  [OK  /usr/bin/foremost] Foremost (carving) (foremost)
  [OK  /usr/bin/hashdeep] hashdeep (hashing) (hashdeep)
  [OK  /usr/bin/strings] GNU strings (printable-sequence extraction) (strings)

All tools available.
```

> **Note on the count.** `doctor` prints one `[OK …]` line per **binary** it resolves — **18** lines on a
> full SIFT host (the 16 SIFT forensic wrappers' backing binaries plus `icat` and `strings`, which
> `doctor` also pre-flights). The canonical figure **"16 forensic wrappers"** counts the wrapper layer,
> not the resolved-binary lines — both are correct. The closing `All tools available.` is the signal you
> care about.

**Execution C → Output C** (something missing). When a tool is absent `doctor` lists it as `MISSING`,
prints how many tools are absent, and **exits non-zero**:

*Execution C:*
```bash
uv run agentropix-sift doctor
```

*Output C (one or more missing):*
```text
  [MISSING] Plaso (timeline) (log2timeline.py)
  ...
2 tool(s) missing. Install, or set the corresponding AGENTROPIX_*_TOOL env var to a working binary.
```

To point `doctor` (and the matching wrapper) at a non-default binary path, set the
tool's override variable — e.g.:

```bash
export AGENTROPIX_YARA_TOOL=/opt/sift/bin/yara
export AGENTROPIX_EVTX_TOOL=/usr/local/bin/evtx_dump.py
```

The override-aware tools are listed in `_DOCTOR_ENV_OVERRIDES`
(`src/agentropix_sift/cli.py:160-172`); the full `AGENTROPIX_<TOOL>_TOOL` pattern is
documented in [`.crew/env-vars.md`](../../.crew/env-vars.md) §5.

---

## 3. First end-to-end triage

The repository ships a tiny synthetic fixture (`samples/sample.dd`, a 10 MB ext2 image)
so you can exercise the full pipeline without real case data:

> **🖥️ Expert (command):**
> ```bash
> uv run agentropix-sift run samples/sample.dd -o report.json
> ```
> **💬 End-user (prompt) — paste this to a Claude session that has the Agentropix MCP attached:**
> *"Open a case for the image at `samples/sample.dd`, register it as evidence, run the full SIFT triage
> over it staging findings as DRAFT, then generate the report."*
> The agent runs the same end-to-end sequence the CLI does, calling the real MCP tools in order —
> `case_init` → `case_activate` → `evidence_register` → the per-evidence analysis tools (e.g.
> `get_pslist`/`get_netscan` on memory, `fls`/`extract_files`/`get_registry` on disk) → `record_finding`
> (DRAFT) → `report_generate`. **One plain-language request is enough; the session recognises it as an
> Agentropix triage and routes the whole tool sequence for you.**

`run` (`src/agentropix_sift/cli.py:50-152`) executes the Trinity Loop over the image,
then **seals the result**. Useful options:

| Flag | Default | Meaning |
|------|---------|---------|
| `IMAGE` (positional) | — (required) | Path to the disk/memory image |
| `--max-iterations` / `-n` | `5` | Maximum Trinity Loop iterations (S-07) |
| `--out` / `-o` | `report.json` | Output report path |
| `--verbose` / `-v` | off | Detailed logging |

**Execution D → Output D.**

*Execution D:*
```bash
uv run agentropix-sift run samples/sample.dd -o report.json
```

*Output D (sealed triage on the synthetic fixture):*

```text
Agentropix-SIFT triage: samples/sample.dd
  max-iterations: 5
  output: report.json

Findings: 2
Tool calls: 11
Status: budget_exhausted
Report written to report.json
Audit log (sealed) at report.audit-log.json (11 entries)
Session key (mode 0600) at report.session-key
Evidence SHA-256: 9f2c…<64 hex>
Inference constraint: high (LLM is orchestrator; facts from MCP tools)
```

> **About this fixture's result.** `samples/sample.dd` is intentionally a tiny synthetic
> image, so a low finding count and `status: budget_exhausted` are expected — it proves
> the *pipeline* runs end-to-end, not the engine's real-data recall. On the real SANS
> SRL-2018 corpus the disk per-IOC recall is **72/72 (100%)** on the regression suite
> and **108/118 (91.5%)** memory+disk combined (see
> [`.crew/facts.md`](../../.crew/facts.md) for both numbers and their methodology
> caveats). To run the real-data recall gate, point `AGENTROPIX_E01_FIXTURE` at a SANS
> E01 and run `tests/integration/test_e2e_dc_recall.py` (a full run is 30–45 min
> wall-clock).

### What a run produces

A single `run` writes **three files** next to your `--out` path:

| File | Mode | Contents |
|------|------|----------|
| `report.json` | normal | The schema-validated `TriageReport`: `findings[]`, `trace`, `thymus_audit[]`, `evidence_image_sha256`, `report_seal`, `completion_proofs[]`, per-iteration `iterations[]` |
| `report.audit-log.json` | normal | The sealed Thymus read-only access audit log, cross-bound into the report |
| `report.session-key` | `0600` | The per-run 32-byte HMAC session key used to verify the seal |

The report validates against `report.schema.json` (draft 2020-12); the full field
contract is in [`.crew/schema-dump.md`](../../.crew/schema-dump.md) §1.

### Inspect the result

> **🖥️ Expert (command):**
> ```bash
> # Findings, trace size, and audit trail
> jq '.findings, (.trace.tool_calls | length), .thymus_audit' report.json
>
> # The cryptographic anchors
> jq '{evidence_image_sha256, report_seal, completion_proofs, status}' report.json
> ```
> **💬 End-user (prompt):** *"Summarise the findings for this case and show me the case status."*
> The session calls **`case_status`** (case state rollup) — and, on an indexed case,
> **`idx_case_summary`** / **`idx_search`** — to read back the findings and trace in plain language, so a
> non-technical operator never has to touch `jq`.

**Execution E → Output E.**

*Execution E:*
```bash
jq '{evidence_image_sha256, report_seal, completion_proofs, status}' report.json
```

*Output E (cryptographic anchors):*
```json
{
  "evidence_image_sha256": "9f2c…<64 hex>",
  "report_seal": "hmac-sha256:…",
  "completion_proofs": [],
  "status": "budget_exhausted"
}
```

Every `findings[]` entry names the deterministic tool that produced it in its `_source`
field — the grounding guarantee described in [What You Get](what-you-get.md#provenance--grounding).

### Verify the seal

The report and audit log are HMAC-SHA256 sealed and independently verifiable
(`courtroom.py`; standalone verifier `audit/verify_seal.py` /
`scripts/verify_seal.py`):

> **🖥️ Expert (command):**
> ```bash
> uv run python scripts/verify_seal.py report.json
> ```
> **💬 End-user (prompt):** seal verification is a deliberately **out-of-band, operator-local** check —
> there is no MCP tool for it, by design. The whole point of the seal is that *anyone* (an examiner, a
> judge, opposing counsel) can verify the report independently with the standalone script and the
> `report.session-key`, without trusting the running engine or its MCP. Run the script yourself, or ask
> your administrator to.

**Execution F → Output F.**

*Execution F:*
```bash
uv run python scripts/verify_seal.py report.json
```

*Output F (intact seal — the verifier resolves `report.session-key` next to the report automatically):*
```text
Reading report.json (1 lines)
Reading report.session-key (32 bytes, mode 0o600)
Recomputing HMAC-SHA256 over canonical report JSON ...
OK Report seal verified.
Reading report.audit-log.json (11 entries)
Recomputing HMAC-SHA256 over canonical audit-log JSON ...
OK Audit-log internal seal verified.
OK Cross-bind verified - report and audit log are paired.
Seal verification: ALL PASS - chain-of-custody intact.
```

This confirms the report has not been altered since it was sealed — the judge-verifiable
chain-of-custody property at the heart of the engine.

---

## Where to go next

- **[What You Get](what-you-get.md)** — the full capability matrix and the 71-tool
  catalogue.
- **[What is Agentropix-SIFT?](what-is-agentropix.md)** — the DFIR problem, positioning,
  and pipeline diagram.
- **Shared references** — [`.crew/tool-list.md`](../../.crew/tool-list.md) (all 71
  tools), [`.crew/env-vars.md`](../../.crew/env-vars.md) (configuration),
  [`.crew/agents-list.md`](../../.crew/agents-list.md) (the swarm).
