# 05 · Safety & Forensics

The forensic safety spine: how fabrication is prevented, how findings are grounded, how the audit is sealed, how a human approves before the seal, and what AI is disclosed.

## Read in this order

1. [anti-hallucination.md](anti-hallucination.md) — how fabricated findings are prevented (determinism, evidence sovereignty, no LLM self-rating) — the first-class guarantee.
2. [provenance-grounding.md](provenance-grounding.md) — how findings are grounded in evidence: the provenance tiers and grounding levels.
3. [human-in-the-loop.md](human-in-the-loop.md) — how the approval sidecar gate holds findings in DRAFT until an examiner approves (invariant, state machine, HMAC challenge-response, hash chain).
4. [approval-portal.md](approval-portal.md) — the browser sign-off form, field by field: how to submit, retract/void, and the error matrix (operator walkthrough).
5. [audit-courtroom.md](audit-courtroom.md) — how the audit log is HMAC-SHA256 sealed and the chain of custody validated.
6. [ai-disclosure.md](ai-disclosure.md) — what AI models are used (and pinned), what crosses the Anthropic boundary, and how a run is replayed deterministically.

## Assets

Full-size, zoomable renders and screenshots embedded in the pages above:

- [assets/provenance-grounding-1.svg](assets/provenance-grounding-1.svg) — full-size zoomable render of the provenance-grounding flowchart ("Open as SVG" link).
- [assets/human-in-the-loop-1.svg](assets/human-in-the-loop-1.svg) — full-size zoomable render of the human-in-the-loop flowchart ("Open as SVG" link).
- [assets/approval-portal-1.svg](assets/approval-portal-1.svg) — full-size zoomable render of the challenge/approve HMAC flow for approval-portal.md.
- [assets/approval-sidecar-ui.png](assets/approval-sidecar-ui.png) — screenshot of the approval sidecar browser UI embedded in approval-portal.md.
- [assets/audit-courtroom-1.svg](assets/audit-courtroom-1.svg) — full-size zoomable render of the evidence-hash/seal session flow for audit-courtroom.md.
- [assets/ai-disclosure-1.svg](assets/ai-disclosure-1.svg) — full-size zoomable render of the ai-disclosure flowchart ("Open as SVG" link).
