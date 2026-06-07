> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-W052-T2-defer — DEFER Truth #2 (RUNDLL32 stager)

**Status:** DEFERRED  
**Date:** 2026-04-21  
**Sprint:** BMAD M6.2  
**Decision owner:** Mary (BA)

## Context

Ground truth #2 (T2) expects a finding for Cobalt Strike stager execution trace in the Prefetch directory with evidence keywords: `RUNDLL32`, `artifact.exe`, `stager`.

- `RUNDLL32` may appear in plaso prefetch/winevtx events and is a LOLBin.
- `artifact.exe` is the Cobalt Strike default beacon staging filename — a vendor-specific naming convention that plaso never emits as a structured field; it would only appear if the actual file on disk is named `artifact.exe` and captured by a filesystem or prefetch parser.
- `stager` is analysis vocabulary (MITRE/CS terminology) that plaso never emits for any event type.

Difficulty is marked `yara_hit` in the ground truth, indicating signature-based detection is required.

## Decision

DEFER Truth #2. Even if plaso captures RUNDLL32 execution (giving cohit=1), `artifact.exe` and `stager` are not recoverable from plaso event text without YARA signature matching against the beacon payload.

Changing the GT keywords would require dropping to 1-keyword cohit (which loosens the scoring gate) or guessing alternative keywords that may not appear in the image.

## Consequence

T2 remains MISS in the recall gate. The SANS demo must be updated to acknowledge T2 as a YARA-future capability.

## Re-attempt condition

Ship a YARA agent (W3 roadmap) that scans Prefetch entries for CS beacon staging artifacts. Once the YARA agent fires, restore `artifact.exe` / `stager` or replace with the YARA rule signature name.
