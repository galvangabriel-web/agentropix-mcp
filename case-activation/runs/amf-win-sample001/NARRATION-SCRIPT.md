# 🎙️ Narration script — AMF sample001 annotated run video

> **How to use this (v2 — still-based).** [`EXECUTED-RUN-ANNOTATED.mp4`](EXECUTED-RUN-ANNOTATED.mp4)
> is built from **annotated stills**: one steady frame per key moment with a thin red box that never
> moves. v3 places every box **pixel-precisely**: the text extents of each highlighted block were
> measured programmatically and the 3 px stroke is machine-verified to cross **zero text pixels**
> (every edge sits in the blank gutters between lines). The original [`EXECUTED-RUN.mp4`](EXECUTED-RUN.mp4) is untouched. Each scene holds
> long enough to speak its line. Record your voice per row, then mux:
> `ffmpeg -i EXECUTED-RUN-ANNOTATED.mp4 -i voice.m4a -c:v copy -c:a aac -shortest EXECUTED-RUN-NARRATED.mp4`.
> Video length 1:19; total speech ≈ 70 s — comfortable pace. This narrated cut satisfies the
> submission's "screencast **with audio narration**" requirement.

| ⏱ Time | On screen (red box) | 🎙️ Say this |
|---|---|---|
| 0:00–0:09 | Title + provenance page (no box) | "This is a real, live execution against a memory image from the Art of Memory Forensics corpus — a Windows XP RAM dump. Every output you'll see was captured from the live Agentropix MCP server. Nothing is simulated except where I'll tell you it is." |
| 0:09–0:17 | **Box: the `health` output — `tool_count: 72`** | "First, pre-flight. One health call confirms the server is up with all seventy-two forensic tools registered. If tools were missing, we'd know before spending a minute on the image." |
| 0:17–0:25 | **Box: `evidence_register` — the SHA-256 + size** | "Now chain of custody: the image is registered as evidence and hashed. This SHA-256 is the anchor — every finding from here on is tied to exactly these bytes." |
| 0:25–0:45 | **Boxes: netscan "0 sockets" + the malfind 15-RWX block** | "The triage battery: twenty-one processes. Zero network sockets — and the system reports that honest empty result instead of inventing activity. Then the real find: fifteen executable-writable memory regions, eight of them in winlogon dot e-x-e — exactly the signature of injected code. And notice the honesty in the timing: the first malfind pass hit the timeout, so it was re-run with a longer budget and completed in seventy-five seconds. Failures are shown, not hidden. The command lines cross-check the process list — twenty-one for twenty-one, consistent." |
| 0:45–0:56 | **Box: `record_finding` with `dry_run: true`** | "Now we record a finding for the injected regions — but look: dry run first. The anti-hallucination safeguard validates the finding and shows exactly what *would* be indexed. Nothing persists until an examiner is in the loop." |
| 0:56–1:09 | **Boxes: the SIMULATED-approval warning + the approval HMAC record** | "Full disclosure, and it's written right on the screen: this approval was automated by Playwright *for the demo only* — it is not a human sign-off. In real casework, DRAFT to APPROVED is a hard stop that only an examiner's HMAC signature can cross. The mechanism you see — the approval ID and the cryptographic record — is the real one." |
| 1:09–1:19 | **Box: `report_generate` — `approved_finding_count: 1` + `hmac_seal`** | "With the approval in place, the report materializes: one approved finding, sealed with an HMAC over the whole record. A 511-megabyte RAM dump went in; what came out is a tamper-evident, court-ready triage report." |

**Recording tips:** read each row when its red box appears (the box *is* the cue card, and it
holds still for the whole segment now). Every segment has breathing room — the battery scene holds
20 seconds for its 20-second line. Keep the SIMULATED disclosure verbatim — the honesty *is* the
feature.
