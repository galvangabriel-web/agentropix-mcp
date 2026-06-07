> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-012: `mcp_extract_files` — registry/artifact extraction from raw E01

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-04-19 |
| **Decision date** | 2026-04-19 |
| **Decision Makers** | Forge Orchestrator (author), Operator (gate G-M4.1) |
| **Bio-Agentic Component** | MCP tool surface — evidence marshalling (disk → artefact) |
| **Priority** | P1 (HIGH) — closes W-028, unblocks 4 registry/execution wrappers on raw E01 |

## Context

After the M3 wrapper expansion and the Phase 6 real-data validation the
SIFT swarm can parse `SOFTWARE` / `SYSTEM` / `SAM` / `NTUSER.DAT`
hives and amcache/shimcache/prefetch artifacts — **provided a caller
has already extracted them onto the host filesystem**. All four of
`regripper`, `amcache_parser`, `shimcache_parser`, and the prefetch
parser take a path to an *already-extracted* file, not an offset
inside an E01 container.

The 2026-04-19 DC dry-run (`reports/dryrun_dc.json`) surfaced the
consequence: `ArtifactAgent` ran in < 1 s, emitted one chain-of-custody
finding from `ewfinfo`, and zero detection findings. Four wrappers
(regripper, amcache, shimcache, prefetch) never fired because the
orchestrator has no way to get bytes out of the E01 and onto disk.

W-028 (HIGH, OPEN) records this gap:

> No `extract_hive` helper — registry/execution-evidence wrappers can't
> be driven from a raw E01. `regripper`, `amcache`, `shimcache` all
> take a path to an extracted hive on disk. To use them autonomously
> the orchestrator needs to chain `mcp_fls` → `icat` (or
> `tsk_recover`) → tmpdir, then point the wrapper at the extract.

### Problem Statement

The MCP surface exposes filesystem *listing* (`mcp_fls`) but not file
*content retrieval*. Without a content-retrieval tool, 4 of 8 wrappers
are dead on real E01 evidence and the M4 detection thesis ("wrappers
+ recursion + YARA lift recall from 0 to non-trivial") cannot be
tested on raw E01 containers.

### Constraints

- **Thymus boundary** must still enforce read-only-from-evidence /
  write-only-into-session-tmpdir. Extraction writes *derived files*;
  the evidence container is never modified.
- **No secret-of-evidence corruption** — the SHA-256 of every extracted
  file must be recorded in the manifest for audit.
- **Path-traversal safety** — the caller passes in-container paths
  (e.g. `Windows/System32/config/SOFTWARE`); the tool resolves those
  to TSK inodes and writes to a caller-supplied `dest` directory that
  must resolve under an allowed writable zone.
- **No new dep** — the SIFT OVA already ships `icat` and `ifind`
  (verified 4.11.1 on target host).
- **NTFS focus** — M4 target is Windows E01; ext/HFS support is a
  future concern.

### Assumptions

- TSK `fls -p -r` (recursive, full-path) produces in-container paths
  that are stable keys from a caller's perspective.
- `ifind -n <path>` resolves an in-container path to an inode for
  `icat` consumption; this is the standard `recover hive` recipe on
  SIFT.
- Windows registry hive paths are stable across NT 6.x / 10.x
  (`Windows/System32/config/{SOFTWARE,SYSTEM,SAM,SECURITY}`,
  `Users/*/NTUSER.DAT`, `Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat`).

## Decision Drivers

1. **Schema-clean MCP surface** — one new tool, typed Pydantic
   in/out, no signature churn on existing wrappers.
2. **Defense in depth** — Thymus validates both the evidence read and
   the session-tmpdir write. Path traversal via `..` in `paths` is
   rejected.
3. **Auditability** — every extract produces a row
   `{src_path, inode, dest, size, sha256, duration_ms}` in the returned
   manifest; the orchestrator folds these into `trace.tool_calls` via
   the existing `@traced` decorator.
4. **Small, composable unit** — does one thing (E01 → tmpdir).
   Registry wrapper invocation remains the orchestrator's job.
5. **Operator-override-friendly** — timeouts, size caps, and the
   TSK `icat` binary path are all env-var configurable via the same
   `AGENTROPIX_*` pattern as every other wrapper.

## Considered Options

### Option (a): `mcp_extract_files(image, paths, dest) → manifest`

**Description**: A single new MCP tool. Input is an image path, a list
of in-container paths (POSIX-style, forward slashes — TSK's native
convention), and a destination directory. Output is a manifest with
one row per requested path. Implementation uses `ifind -n` to resolve
each path to an inode, then `icat` to stream the inode's content into
`dest/<basename>`.

```python
class ExtractedFile(BaseModel):
    src_path: str         # in-container path as requested
    inode: str            # resolved via ifind
    dest: str             # on-host absolute path
    size: int             # bytes written
    sha256: str           # sha256 of extracted bytes
    duration_ms: float

class ExtractManifest(BaseModel):
    image_path: str
    offset: int
    fstype: str | None
    entry_count: int
    extracted: list[ExtractedFile]
    missing: list[str]    # paths that ifind could not resolve
    tool: str = "sleuthkit.icat"
    raw_stderr: str = ""
```

**Pros:**
- One tool, one responsibility. Composes cleanly with the existing
  wrappers (orchestrator: extract → parse).
- `missing` list gives the caller actionable feedback (hive moved, NT
  profile not present) without raising.
- Manifest is a structured artefact — Critic/HuntAgent can cross-
  reference extracted SHA-256s against `AmcacheEntry.sha1` and other
  hash fields.
- Env-var surface matches existing wrappers
  (`AGENTROPIX_EXTRACT_TIMEOUT`, `AGENTROPIX_EXTRACT_MAX_BYTES`).

**Cons:**
- Per-file `ifind` + `icat` spawns two subprocesses per path (the
  Windows hive preset is 4 paths → 8 subprocesses). Acceptable at M4
  volumes; revisit if we ever extract hundreds of files.
- Does not cover `tsk_recover` bulk-directory extraction. Out of scope
  for M4: we want named-path precision, not wholesale carve.

### Option (b): Extend `mcp_fls` with `--extract` flag

**Description**: Add `extract: bool = False` and `dest: Path | None`
parameters to `mcp_fls`. When set, emit file bytes into `dest` in the
same call.

**Pros:**
- No new tool.

**Cons:**
- Violates SRP: listing and extracting are different verbs. Test
  matrix combinatorial explosion.
- `fls` output parsing would need a shadow manifest path for SHA-256,
  adding a second data shape to the existing `FileListing` schema.
- Mixes read-pure (`fls`) with side-effectful (`icat`) in one MCP
  tool; Thymus already treats these differently.
- No precedent in the existing wrapper catalogue.

### Option (c): Pure-Python EWF + libregf reader

**Description**: Skip TSK; use `libewf-python` + `python-registry`
in-process to read hives directly from the E01 container.

**Pros:**
- No subprocess overhead.
- Pure-Python; easier to test.

**Cons:**
- New hard dependencies; SIFT OVA ships `icat` but not these bindings.
- Duplicates functionality TSK already provides.
- Bypasses the MCP subprocess audit trail (`@traced` + Thymus
  logging) — every other wrapper follows the subprocess pattern.
- Locks us into a specific EWF/registry library version.

## Decision

We will adopt **Option (a): `mcp_extract_files(image, paths, dest) →
ExtractManifest`** because (1) it is the minimum schema change that
unblocks W-028, (2) it composes naturally with the four already-
landed parsing wrappers, (3) it respects the Thymus boundary (Thymus
sees a structured read + a write request into a session tmpdir), and
(4) it matches the one-subprocess-wrapper-per-tool convention of the
existing catalogue.

### Public surface (new)

In `src/agentropix_sift/mcp_server/wrappers/extract.py`:

```python
async def extract_files(
    image: str | Path,
    paths: list[str],
    dest: str | Path,
    *,
    offset: int = 0,
    fstype: str | None = None,
    timeout: float | None = None,
    max_bytes: int | None = None,
) -> ExtractManifest: ...
```

In `src/agentropix_sift/mcp_server/server.py`:

```python
@traced("extract_files")
async def mcp_extract_files(
    image: str,
    paths: list[str],
    dest: str,
    offset: int = 0,
    fstype: str | None = None,
) -> ExtractManifest | ToolError: ...
```

### Env-var surface

| Variable | Default | Purpose |
|----------|---------|---------|
| `AGENTROPIX_EXTRACT_TIMEOUT` | 120.0 s | Per-file `ifind`+`icat` wall-clock |
| `AGENTROPIX_EXTRACT_MAX_BYTES` | 268435456 (256 MiB) | Per-file size cap |
| `AGENTROPIX_EXTRACT_TMPROOT` | `/tmp/agentropix-sift-extract` | Default tmpdir root (dest override still permitted) |
| `AGENTROPIX_ICAT_TOOL` | `icat` | TSK `icat` binary name |
| `AGENTROPIX_IFIND_TOOL` | `ifind` | TSK `ifind` binary name |

### Implementation Approach

1. `wrappers/extract.py` module with two dataclasses (`ExtractedFile`,
   `ExtractManifest`) and the async `extract_files()` function.
2. Per requested path:
   a. Normalise: reject `""`, `".."`, absolute paths (`/` or `\`
      leading), and paths containing `\x00`. Convert backslashes to
      forward slashes (TSK convention).
   b. `ifind -n <normalised>` → inode. Empty stdout or rc ≠ 0 → add
      to `manifest.missing`, continue.
   c. `dest.joinpath(basename)`. Resolve and verify the resolved
      absolute path is under `dest.resolve()` (defense-in-depth
      against basename tricks).
   d. `icat <image> <inode>` → stream to dest file. Abort at
      `max_bytes`. Compute SHA-256 rolling.
3. Return `ExtractManifest` with per-file rows; `tool_calls` trace
   rollup handled by `@traced` + `_trace.add_record` calls in the
   wrapper for per-path granularity.
4. `mcp_extract_files` server shim: rate-limit, Thymus read-check on
   image, Thymus write-check on dest (*new*: treat Thymus-approved
   read paths as the set of session tmpdirs).
5. `ArtifactAgent` gains a `_extract_hives()` helper that chains
   `mcp_extract_files` → `mcp_get_registry`/`mcp_get_amcache`/
   `mcp_get_shimcache`, guarded by `looks_like_e01()`. Hive paths
   come from a preset list in `agents/_hive_presets.py`.
6. `doctor` CLI extended to check for `icat` and `ifind` on PATH.

### Thymus semantics

- `check_read(image)` — existing behaviour, evidence-directory auto-allow.
- `check_read(dest)` — reused as a **"allowed-write-zone check"**.
  Today, Thymus's allowed zones include `/tmp/agentropix-sift-*`
  specifically for session tmpdirs; `extract_files` writes only to
  these zones. A dest outside is rejected before any subprocess runs.
- `check_write(...)` — **still always rejects**. Extraction writes
  are validated via the read-zone prefix check (write-zone is a
  subset of "inside-our-tmp-root"), not by calling `check_write()`.

This keeps the "no writes to evidence" invariant intact: the evidence
container (`.E01`) is read-only to `icat`, and the tmpdir is not
evidence. The audit log records both the read and the write.

### Migration Path

Lands as Phase M4.1 in the detection sprint. Independent of Phase
M4.2 (`evtx` wrapper) and downstream: registry wrapper tests and
MCP boundary tests reuse this tool in integration.

## Consequences

### Positive

- Closes W-028 (HIGH).
- Unblocks registry/execution wrappers on raw E01 (4 wrappers × 1 tool).
- Typed manifest enables HuntAgent SHA-256 cross-correlation against
  amcache/shimcache SHA-1 fields (M4 stretch goal).
- Audit trail: each extraction is a Thymus ALLOW line + a
  `@traced("extract_files")` row + per-path records.

### Negative

- N subprocesses per extraction (ifind + icat × path count).
  Mitigation: registry-hive preset is 4 files; latency budget is
  dominated by parsing, not extraction.
- `ifind -n` does not handle Windows short-name aliases. Mitigation:
  preset uses canonical long paths; caller can retry with 8.3 form
  if missing.

### Neutral

- NTFS-focused M4 target. ext/HFS extraction works via the same
  `icat` mechanism but is untested; add fixtures when needed.

## Bio-Agentic Mapping

| Agentropix Component | This Decision's Role |
|---------------------|---------------------|
| MCP surface | New typed tool — grows the surface from 8 → 9 tools. |
| Thymus Evidence Policy | Read-check on image; zone-check on dest. Reads evidence, writes to session-tmpdir. |
| Trinity Loop (Architect) | Can plan a "registry extraction" step in its iteration without agent-specific code. |
| DFIR Swarm (ArtifactAgent) | Gains a hive-extraction chain; turns 0 findings → registry findings on raw E01. |
| Hippocampus (future) | Manifest SHA-256s feed the reasoning trace ledger for cross-iteration dedup. |

## Validation Criteria

- [ ] `mcp_extract_files` returns `ExtractManifest` with per-file
      rows for a 4-path preset against `samples/base-dc-cdrive.E01`.
- [ ] A `..`-containing path is rejected as `ToolError` before any
      subprocess runs.
- [ ] An absolute in-container path (`/Windows/...`) is accepted; a
      host-absolute path (`/etc/passwd`) is rejected.
- [ ] `dest` outside the Thymus-allowed zones returns `ToolError`.
- [ ] A path whose extracted content exceeds `max_bytes` is truncated;
      the row records the truncated size and a `truncated: True` flag.
- [ ] `ifind` miss yields `manifest.missing` entry, not a raise.
- [ ] SHA-256 of each extracted file matches an independent
      `hashlib.sha256` over the dest bytes.
- [ ] ArtifactAgent on a real E01 produces > 1 finding after chaining.
- [ ] All 421 existing tests still pass.
- [ ] `doctor` surfaces both `icat` and `ifind`.

## References

- `src/agentropix_sift/mcp_server/wrappers/tsk.py` — sibling wrapper pattern.
- `src/agentropix_sift/mcp_server/thymus_policy.py` — read-zone & audit.
- `src/agentropix_sift/mcp_server/server.py:125` — `mcp_fls` shape.
- `docs/SIFT-WEAKNESSES.md#sift-w-028` — originating weakness.
- Related ADRs: ADR-008 (Safety Architecture — Thymus boundary),
  ADR-011 (Evidence-Type Gates — `looks_like_e01`).

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-04-19 | Forge Orchestrator | Initial draft; status Accepted (operator gate G-M4.1, 17:10 UTC). |
