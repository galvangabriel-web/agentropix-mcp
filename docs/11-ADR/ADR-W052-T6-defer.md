> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-W052-T6-defer — DEFER Truth #6 (beacon AppData injection)

**Status:** DEFERRED  
**Date:** 2026-04-21  
**Sprint:** BMAD M6.2  
**Decision owner:** Mary (BA)

## Context

Ground truth #6 (T6) expects a finding for CS beacon payload dropped in AppData prior to in-memory injection, with evidence keywords: `beacon`, `AppData`, `injection`.

- `beacon` can appear in filesystem findings (e.g., `ServerBeacon.dll` found in M6.1 run), giving cohit=1.
- `AppData` would require the beacon payload to be found in a user's AppData directory — plaso filestat or filesystem scan could surface a suspicious file in that path.
- `injection` is an analysis conclusion (process injection technique) — never emitted by plaso for any event type; it appears only in MITRE enrichment text or YARA rule names.

Expected agent is `MemoryAgent` with difficulty `yara_hit`.

## Decision

DEFER Truth #6. `injection` is not recoverable from plaso/filesystem evidence without memory analysis (Volatility) or YARA scanning. Even with `beacon` (1) + `AppData` (1) = cohit=2, the `injection` keyword cannot come from file-system or timeline evidence.

Changing the GT to drop `injection` would misrepresent the evidence (in-memory injection cannot be confirmed from disk artifacts alone).

## Consequence

T6 remains MISS in the recall gate. MemoryAgent currently has no Volatility integration; in-memory process injection detection is a W3+ capability.

## Re-attempt condition

Integrate Volatility (or equivalent) into MemoryAgent. Once process injection artifacts (e.g., `UNKNOWN` VAD regions, injected PE headers) can be detected, replace `injection` with the specific Volatility output token.
