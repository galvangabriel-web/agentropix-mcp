> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-014: Credential-dump triage via `impacket-secretsdump.py` (W-072)

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted (path forward; Phase 6 of BMAD-M7 sprint) |
| **Date** | 2026-04-25 |
| **Decision Makers** | BMAD-M7 sprint executor (Claude), Operator (gate post-Phase 6) |
| **Bio-Agentic Component** | MemoryAgent credential-triage path |
| **Priority** | P2 (MEDIUM) — closes W-072; restores SAM/LSA/MSCache offline triage |

## Context

vol3 2.27.0 (which the project pins as `volatility3>=2.27.0` in
`pyproject.toml`) removed the `windows.hashdump`, `windows.lsadump`, and
`windows.cachedump` plugins from the upstream distribution. All three
were listed as required in the original T3 runbook and were assumed
present by SIFT MemoryAgent design.

**Operational impact (T3 memory triage, 2026-04-25):** every per-system
`MEMORY-TRIAGE.md` reported `_No credential material recovered_` because
the runner skipped the missing plugins. SIFT had no offline path to SAM
hashes, LSA secrets, or MSCache entries — a meaningful gap for an
APT-incident DFIR tool, since lateral-movement attribution often hinges
on which credentials the attacker harvested.

## Decision

**Do NOT downgrade vol3.** Keep the `>=2.27.0` pin. Rationale: pinning
to `<=2.5.0` loses (a) the csv renderer (`-r csv`) consistency that
SIFT's wrapper layer depends on, (b) the newer symbol packs that
W-074 / W-075 work in BMAD-M7 Phases 4-5 leans on, and (c) security
fixes accumulated across two years of upstream development. The
short-term cost of "no credential dumps until M7+" is acceptable given
the SANS submission deadline (2026-06-10) is recall-driven, not
credential-driven.

**Path forward (M7+ scope, post-deadline):**

1. Use vol3's surviving registry plugins to extract the relevant hives
   to disk.
2. Shell to `impacket-secretsdump.py LOCAL` against the extracted
   hives for offline parsing.
3. Convert the secretsdump output to `Finding` rows with the structured
   `evidence_dict` from BMAD-M7 Phase 2 (W-073) — `mitre_attack=T1003.002`
   for SAM, `T1003.005` for cached domain creds, `T1003.001` for LSA.

## Architecture

### Step 1: Hive extraction (vol3, available today)
```
vol -f <image> -r csv windows.registry.hivelist.HiveList
  → enumerates hive offsets and names (SAM, SECURITY, SYSTEM, NTUSER.DAT)

vol -f <image> windows.registry.printkey.PrintKey
  --offset <SAM_offset> --output-as <hive_dump_path>
  → write the hive's binary to disk for offline parsing
```

The same `mcp_extract_files` machinery from ADR-012 already drops files
under a Thymus-controlled tempdir; the new wrapper hooks into the same
pattern.

### Step 2: Offline parsing (impacket, optional dep)
```
impacket-secretsdump.py LOCAL
  -system  <SYSTEM hive>
  -sam     <SAM hive>
  -security <SECURITY hive>
  → emits one record per credential type:
    - SAM: NTLM hashes per local account
    - LSA: machine-account creds, DPAPI master keys, cached service creds
    - MSCache: cached domain creds (DCC2 / MSCASHv2 hashes)
```

`impacket` is a heavyweight dependency (PyCA cryptography, native
C extensions). Treat as **optional** — gate the wrapper on
`AGENTROPIX_IMPACKET_ENABLED=1`. When disabled, MemoryAgent emits a
single `memory.credentials.unavailable` Finding (confidence 0.1)
explaining why no credential triage ran.

### Step 3: Finding emission

```python
Finding(
    source="memory.credentials",
    confidence=0.95,                           # secretsdump output is authoritative
    description=f"NTLM hash extracted: {acct}",
    evidence=f"account={acct} rid={rid} hash={short_hash}",
    evidence_dict={
        "account": acct,
        "rid": rid,
        "ntlm_hash": full_hash,                # full hash for cross-modal
        "hive": "SAM",
        "extraction_tool": "impacket-secretsdump",
    },
    mitre_attack="T1003.002",                  # OS Credential Dumping: SAM
)
```

Memory-side wrappers shipped in BMAD-M7 Phase 7 (W-071) consume the
same `evidence_dict` schema, so the cross-modal fusion proposal from
MEMORY-TRIAGE-SUMMARY §Rec 3 covers credential findings out-of-the-box.

## Trade-offs considered

### Option A — Downgrade vol3 to ≤2.5.0
**Rejected.** Loses csv renderer consistency, modern symbol packs,
W-074/W-075 fixes. Gain (one-line credential triage) is not worth the
cost.

### Option B — Re-implement the removed plugins inside SIFT
**Rejected.** ~2000 LOC of low-level Win NT secret-derivation logic
(SYSKEY → hashed-bootkey → SAM-AES-decrypt → NTLM). impacket already
has this and is battle-tested. We are not in the business of
maintaining a fork of vol3's credential-extraction code.

### Option C — impacket as optional dependency (this ADR)
**Accepted.** Cleanest separation: vol3 handles memory parsing,
impacket handles credential decryption against the extracted hives.
Gate via env var so the install-size cost is opt-in.

### Option D — Defer credential triage entirely
**Rejected.** Credential extraction is a load-bearing feature for an
APT-DFIR tool. The current "no credentials" state is honest but
limiting. The ADR's path-forward keeps the door open without
committing the dedicated-session work today.

## Acceptance / Implementation gates

- [ ] `mcp_server/wrappers/credentials.py` — new wrapper around
      `impacket-secretsdump.py LOCAL`. Pydantic report schema.
      Thymus read-check on each hive path.
- [ ] `agents/memory.py` — credential-triage branch gated on
      `AGENTROPIX_IMPACKET_ENABLED=1` AND hive extraction succeeded.
- [ ] Integration test against a saved hive triple (SAM + SECURITY + SYSTEM)
      from one of the SRL-2018 systems where T3 memory triage already ran.
- [ ] Optional-dependency declaration in `pyproject.toml`:
      ```
      [project.optional-dependencies]
      credentials = ["impacket>=0.11.0"]
      ```
- [ ] `docs/AGENTS.md` glossary entry for the new env var.

## Status decision

W-072 status updates from **OPEN MEDIUM** → **DEFERRED MEDIUM (M7+)** with
this ADR as the deferral pointer. The deferral is principled (not
"forgotten") and the user-visible gap (`MEMORY-TRIAGE.md` reading
"no credentials") is documented rather than silent.

## References

- `docs/SIFT-WEAKNESSES.md::SIFT-W-072` (memory credentials gap)
- `docs/exec/BMAD-M7-WEAKNESS-CLOSURE-SPRINT.md::§2.7` (Phase 6 design)
- ADR-012 (`mcp_extract_files` — extraction substrate this builds on)
- vol3 release notes: <https://github.com/volatilityfoundation/volatility3/releases/tag/v2.27.0> (plugin removal)
- impacket: <https://github.com/fortra/impacket>
