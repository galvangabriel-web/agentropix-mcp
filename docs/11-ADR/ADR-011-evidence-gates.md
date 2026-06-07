> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-011: Evidence-Type Gate Consolidation

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-04-19 |
| **Decision date** | 2026-04-19 |
| **Decision Makers** | Builder-B crew (research), Operator (gate G1) |
| **Bio-Agentic Component** | DFIR Swarm — agent gating heuristics |
| **Priority** | P2 (Medium) — closes W-033, unblocks evidence-format expansion |

## Context

The five-agent DFIR swarm (`MemoryAgent`, `TimelineAgent`,
`FilesystemAgent`, `ArtifactAgent`, `HuntAgent`) gates each agent on the
evidence file's *probable type* so a memory-only image does not get fed to
Plaso and a disk-only image does not get fed to Volatility. Three of the
four data-fetching agents already share `agents/_evidence.py`:

- `MemoryAgent` → `looks_like_memory(image)`
- `TimelineAgent`, `FilesystemAgent` → `looks_like_disk(image)`
- `ArtifactAgent` → **inline** `image.suffix.lower() != ".e01"`
  (`agents/artifact.py:21`)

### Problem Statement

`artifact.py` bypasses `_evidence.py` entirely. The inline check is correct
*today* (E01 is the only forensic-image format `mcp_get_image_info` /
`ewfinfo` reads), but the asymmetry has three concrete costs:

1. **Hidden coupling to ewfinfo**: when `Lx01`, `AFF`, or `AFF4` support
   lands in `wrappers/ewf.py` (already imported in `thymus_policy.py:71`'s
   `_EVIDENCE_EXTENSIONS`), the artifact agent silently skips them. There
   is no test that fails when this happens.
2. **Gate drift**: the four data-fetching agents now use three different
   gating strategies (memory-suffix-or-name-hint, disk-suffix-or-keyword,
   single-suffix-equality). New agents will pick whichever they see first.
3. **No taxonomy**: `_MEMORY_SUFFIXES`, `_DISK_SUFFIXES`,
   `_EVIDENCE_EXTENSIONS` (in Thymus), and the artifact's `.e01` literal
   are four overlapping definitions of "evidence formats we recognise".

### Constraints

- Must not change agent runtime behaviour for the existing test corpus
  (artifact still no-ops for everything except `.e01` *today*).
- Must keep `_evidence.py` import-light (no pydantic, no IO).
- Must be friendly to the M3 wrapper expansion (5+ more wrappers landing).
- Must not introduce a Trinity dependency (this ADR ships ahead of W-029).

### Assumptions

- The set of forensic image formats grows monotonically over the project's
  lifetime; renames are rare.
- The Thymus `_EVIDENCE_EXTENSIONS` frozenset
  (`thymus_policy.py:69-72`) and the swarm's gating sets must agree, but
  neither can be the canonical source — Thymus runs at the MCP boundary
  before any agent gates.

## Decision Drivers

1. **Symmetry** — All four data-fetching agents should call the same
   helper module. No inline literals.
2. **Single source of truth** for "is this an EWF image / a memory dump /
   a raw disk", separate from Thymus's "is this an evidence file at all".
3. **Cheap to extend** — adding `Lx01` should be a one-line set update.
4. **Cheap to test** — the helper must be pure-function and fast.

## Considered Options

### Option (a): `looks_like_e01` helper in `_evidence.py`

**Description**: Add a third helper alongside `looks_like_memory` and
`looks_like_disk`:

```python
_E01_SUFFIXES = {".e01", ".ex01", ".lx01", ".l01"}  # EWF family
def looks_like_e01(image: Path) -> bool:
    return image.suffix.lower() in _E01_SUFFIXES
```

`artifact.py:21` becomes `if not looks_like_e01(image): return []`.

**Pros:**
- 3 LOC change in `_evidence.py`, 1 LOC change in `artifact.py`.
- Matches the existing `looks_like_*` boolean idiom.
- No type churn — agents keep their current `Path → bool` calls.
- Trivial to test (one parametrised test, ~6 cases).
- Ships in S1 of the Phase-1 sequencing (no other dependencies).

**Cons:**
- Still N functions for N format families; combinatorial drift returns the
  moment we add a *fifth* category (e.g., container formats).
- Does not unify with Thymus's `_EVIDENCE_EXTENSIONS`.

### Option (b): `EvidenceFormat` enum / taxonomy

**Description**: Replace the boolean helpers with an enum and a single
classifier:

```python
class EvidenceFormat(StrEnum):
    MEMORY = "memory"
    DISK_RAW = "disk_raw"
    DISK_EWF = "disk_ewf"
    UNKNOWN = "unknown"

def classify(image: Path) -> EvidenceFormat: ...
```

Each agent declares the formats it accepts:

```python
ACCEPTS = {EvidenceFormat.DISK_EWF}
async def investigate(self, image): 
    if classify(image) not in self.ACCEPTS: return []
```

**Pros:**
- One source of truth; adding a format updates one map.
- Could subsume Thymus's `_EVIDENCE_EXTENSIONS` (single import).
- Self-documenting per agent (`ACCEPTS = {…}` is the gate's intent).

**Cons:**
- Touches all 4 data-fetching agents (not just `artifact.py`).
- Forces a decision on memory-vs-disk precedence in the classifier rather
  than at the agent — `_evidence.py:1-7` calls out that "memory wins" is a
  deliberate per-call rule, not a taxonomy property.
- Higher test impact: ~10-15 existing agent tests need updating to set
  `ACCEPTS` or stub `classify`.
- Scope creep into Thymus is tempting but premature (Thymus boundary
  semantics are pinned by IDENTITY/SOUL — see hard non-goals in
  MASTER-PLAN-STATE.md).

## Decision

We will adopt **Option (a): `looks_like_e01` helper in `_evidence.py`**
because (1) it closes W-033 in one PR with zero risk to the other three
agents, (2) it preserves the deliberate "memory wins" precedence rule that
the boolean idiom already encodes, and (3) it leaves Option (b) on the
table as a follow-up ADR once a fifth format family actually appears
(YAGNI on the enum until the third disk-EWF variant lands).

### Public surface (new)

In `agents/_evidence.py`:

```python
_E01_SUFFIXES: frozenset[str] = frozenset({".e01", ".ex01", ".lx01", ".l01"})

def looks_like_e01(image: Path) -> bool:
    """True if `image` is an EWF-family forensic container.

    Uses suffix only — EWF files do not have reliable name hints. Memory
    precedence does not apply: `looks_like_memory` and `looks_like_e01`
    are independent (an `.e01` is never also a memory dump).
    """
    return image.suffix.lower() in _E01_SUFFIXES
```

Default suffix set is overridable via `AGENTROPIX_ARTIFACT_FORMATS` (env
var row 13 in `PHASE-1-PLUMBING-DESIGN.md`).

### Implementation Approach

1. Add `looks_like_e01` + `_E01_SUFFIXES` to `agents/_evidence.py`.
2. Replace `agents/artifact.py:21` (`if image.suffix.lower() != ".e01"`)
   with `if not looks_like_e01(image)`.
3. Add `_E01_SUFFIXES` to the env-var read path (Phase-1 row 13) so
   operators can extend without code changes.
4. Add a unit test that asserts all three helpers on a parametrised
   matrix of representative file names.

### Migration Path

This is Step S1 in `PHASE-1-PLUMBING-DESIGN.md` §5 — first to ship,
independent of W-030/W-031/W-032.

## Consequences

### Positive

- Closes W-033 (TRIVIAL) without surface changes.
- Symmetric gate idiom across all 4 data-fetching agents.
- Adds Lx01/Ex01/L01 support for free (current inline check would silently
  reject them).
- One-line operator override via `AGENTROPIX_ARTIFACT_FORMATS`.

### Negative

- N+1 boolean helpers as new format families land.
  - *Mitigation*: revisit Option (b) when a fourth helper is proposed.
- Does not unify with Thymus's `_EVIDENCE_EXTENSIONS`.
  - *Mitigation*: out of scope per Phase-1 hard non-goals; track as a
    follow-up if/when Thymus boundary semantics are reopened.

### Neutral

- The `.e01`-only behaviour is unchanged for the existing test corpus.

## Bio-Agentic Mapping

| Agentropix Component | This Decision's Role |
|---------------------|---------------------|
| DFIR Swarm — agent gating | Single source of truth for "is this evidence I can read?" per agent. |
| Thymus Evidence Policy | Unchanged; remains the pre-agent boundary check. |
| Trinity Loop (future) | Architect's plan validation can reuse `looks_like_*` to predict which agents will run. |

## Validation Criteria

- [ ] `looks_like_e01` returns True for `.e01`/`.ex01`/`.lx01`/`.l01` and
      False for everything else (case-insensitive).
- [ ] `agents/artifact.py` contains no inline suffix literal.
- [ ] All four data-fetching agents (`memory`, `timeline`, `filesystem`,
      `artifact`) gate via a `looks_like_*` call.
- [ ] `AGENTROPIX_ARTIFACT_FORMATS` overrides the default set with
      floor (≥1 token) and ceiling (≤16 tokens) enforcement.
- [ ] Existing `test_agents.py` artifact tests pass unchanged.

## References

- `src/agentropix_sift/agents/_evidence.py` — current helpers.
- `src/agentropix_sift/agents/artifact.py:21` — inline literal being removed.
- `src/agentropix_sift/mcp_server/thymus_policy.py:69-72` —
  `_EVIDENCE_EXTENSIONS` (out-of-scope sibling taxonomy).
- `docs/PHASE-1-PLUMBING-DESIGN.md` — §1 (W-030), §2 row 13 (env-var
  surface), §5 (sequencing).
- Related ADRs: ADR-008 (Safety Architecture — Thymus boundary).

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-04-19 | Builder-B crew | Initial draft (Proposed). |
| 2026-04-19 | Implementer-2D | Status Proposed → Accepted (operator gate G1, 04:06 UTC); helper landed in `_evidence.py` and `artifact.py` consumes it. |
