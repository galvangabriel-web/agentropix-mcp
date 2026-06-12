# 🎙️ Narration script — AMF sample001 annotated run video

> **How to use this.** [`EXECUTED-RUN-ANNOTATED.mp4`](EXECUTED-RUN-ANNOTATED.mp4) is a copy of the
> original [`EXECUTED-RUN.mp4`](EXECUTED-RUN.mp4) (untouched) with **red boxes appearing exactly when
> each line below should be spoken** — the boxes are your cue cards. Record your voice per segment
> (any recorder), then mux: `ffmpeg -i EXECUTED-RUN-ANNOTATED.mp4 -i voice.m4a -c:v copy -c:a aac
> -shortest EXECUTED-RUN-NARRATED.mp4`. Total speaking time ≈ 60 s in a 67 s video — comfortable pace.
> This narrated cut directly satisfies the submission's "screencast **with audio narration**" requirement.

| ⏱ Time | On screen (red box) | 🎙️ Say this |
|---|---|---|
| 0:00–0:09 | Title + provenance page (no box) | "This is a real, live execution against a memory image from the Art of Memory Forensics corpus — a Windows XP RAM dump. Every output you'll see was captured from the live Agentropix MCP server. Nothing is simulated except where I'll tell you it is." |
| 0:09–0:16 | **Box: the `health` output — `tool_count: 72`** | "First, pre-flight. One health call confirms the server is up with all seventy-two forensic tools registered. If tools were missing, we'd know before spending a minute on the image." |
| 0:17–0:24 | **Box: `evidence_register` — the SHA-256 + size** | "Now chain of custody: the image is registered as evidence and hashed. This SHA-256 is the anchor — every finding from here on is tied to exactly these bytes." |
| 0:25–0:28 | Battery header (no box) | "Then the memory triage battery — process list, network, and injection scan, all Volatility under the hood." |
| 0:29–0:37 | **Boxes: netscan '0 sockets' line + the malfind 15-RWX block** | "Twenty-one processes. Zero network sockets — and the system reports that honest empty result instead of inventing activity. And here's the real find: fifteen executable-writable memory regions, eight of them in winlogon dot e-x-e — exactly the signature of injected code. Note the first malfind pass hit the timeout; it was re-run with a longer budget and completed in seventy-five seconds. Failures are shown, not hidden." |
| 0:38–0:40 | cmdline page (no box) | "Command lines cross-check the process list — twenty-one for twenty-one, consistent." |
| 0:41–0:49 | **Box: `record_finding` with `dry_run: true`** | "Now we record a finding for the injected regions — but look: dry run first. The anti-hallucination safeguard validates the finding and shows exactly what *would* be indexed. Nothing persists until an examiner is in the loop." |
| 0:50–0:52 | Transition (no box) | "And that examiner step is next." |
| 0:53–1:00 | **Boxes: the SIMULATED-approval warning + the approval HMAC record** | "Full disclosure, and it's written right on the screen: this approval was automated by Playwright *for the demo only* — it is not a human sign-off. In real casework, DRAFT to APPROVED is a hard stop that only an examiner's HMAC signature can cross. The mechanism you see — the approval ID and the cryptographic record — is the real one." |
| 1:01–1:07 | **Box: `report_generate` — `approved_finding_count: 1` + `hmac_seal`** | "With the approval in place, the report materializes: one approved finding, sealed with an HMAC over the whole record. A 511-megabyte RAM dump went in; what came out is a tamper-evident, court-ready triage report — end to end, in about a minute of tool time." |

**Recording tips:** read each row when its red box appears (the box *is* the cue); the longest
segment (0:29–0:37) is ~9 s of video for ~20 s of speech — either trim the line or pause the video
during edit (`ffmpeg` freeze-frame or simple cut). Keep the SIMULATED disclosure verbatim — the
honesty *is* the feature.
