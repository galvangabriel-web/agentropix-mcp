# Agentropix-SIFT — Project Structure

This is the reader-facing **documentation portal** for Agentropix-SIFT, packaged together with the installable **`agentropix_mcp`** MCP-server (the governed read-only DFIR engine) and a set of **sealed DFIR case reports**. The portal docs explain the system across 12 numbered sections; the `agentropix_mcp/` package is the actual shippable code (src layout, console script, wheels on GitHub releases); the case folders hold real, sealed investigations.

**How to read this tree:** top-down by area — root files first, then the MCP-server package (core modules, then each subpackage), then the `docs/` sections, then `case-activation/` runs and the sealed case reports. Each `←` comment says what the file/dir actually does; only key files per area are shown.

```text
agentropix-mcp/
│
│  ── Root files: landing, index, evaluator routing, audits, LLM context ──
├── README.md                     ← Landing page — evaluator letter, 60-sec connect, workflow
├── INDEX.md                      ← Routed master TOC — audience + question-it-answers per page
├── EVALUATION-MAP.md             ← Judge router — 8 submission requirements to evidence
├── CLAUDE.md                     ← Portal working conventions + canonical/accuracy rules
├── DOCUMENTATION-PLAN.md         ← Build plan — oracle source, portal layout, sections
├── AUDIT-COVERAGE.md             ← Per-section index-coverage audit — 0 broken/orphan links
├── ACCURACY_REPORT.md            ← Code/QA accuracy audit — benchmarks, recall, thresholds
├── EVIDENCE_DATASET_DOCS.md      ← Evidence-dataset inventory — provenance, SHA-256, ingestion
├── llms.txt                      ← Curated LLM index — one-paragraph system summary
├── llms-full.txt                 ← Expanded LLM context — inlines 19 core docs
├── LICENSE                       ← MIT License (galvangabriel-web, 2026)
├── .gitignore                    ← Excludes local-only: evaluation*/, video archives, dist
├── .nojekyll                     ← Empty marker — disables Jekyll for GitHub Pages
│
│  ── agentropix_mcp/ : the installable MCP-server PACKAGE (src layout) ──
├── agentropix_mcp/
│   ├── pyproject.toml             ← Package metadata — deps + extras [forensics]/[reports]/[engine], console script
│   ├── README.md                 ← Package README — install, MCP client config, tool surface
│   ├── dist/                      ← Built wheel + sdist (gitignored; attached to GitHub releases)
│   ├── tests/                     ← Package test suite for the MCP server surface
│   └── src/agentropix_mcp/
│       │  ── Core modules ──
│       ├── __init__.py            ← Package init — version 0.3.0, governed-DFIR-MCP summary
│       ├── fastmcp_app.py         ← FastMCP stdio surface — entrypoint main(), thin routes over server.py
│       ├── server.py              ← Inner MCP tool implementations — enforcement boundary (read-only)
│       ├── thymus_policy.py       ← Thymus read-only path policy + JSONL audit ring at MCP boundary
│       ├── courtroom.py           ← Chain-of-custody — image SHA-256 + HMAC-sealed report/audit envelopes
│       ├── config.py              ← Config loader — file/env settings, policy + tool defaults
│       ├── audit_analyzer.py      ← Summarizes Thymus JSONL audit logs for security review
│       ├── secrets.py             ← Telegram-token resolver + logging-safe secret redactor
│       ├── _env.py                ← AGENTROPIX_* env-var helpers — clamped int/float tunables
│       ├── _trace.py              ← Per-tool tracing — contextvar buffer, @traced, args_hash
│       ├── _tool_pins.py          ← Startup SHA-256 pin-check of external forensic binaries
│       ├── _startup_banner.py     ← Logs effective AGENTROPIX_* env config banner at startup
│       │
│       │  ── Subpackages ──
│       ├── agents/                ← 7-agent DFIR SwarmAgent specialists + shared blackboard
│       │   ├── _base.py           ← Base SwarmAgent contract — pure, no LLM coupling
│       │   ├── _blackboard.py     ← Shared blackboard — cross-agent aggregation + quorum
│       │   ├── hunt.py            ← HuntAgent — cross-source correlation specialist
│       │   └── memory.py          ← MemoryAgent — volatile-evidence specialist
│       │                            (also: discovery, mail, timeline, artifact, filesystem)
│       ├── wrappers/              ← Forensic tool wrappers (Volatility/TSK/YARA/Plaso/registry/case)
│       │   ├── volatility.py      ← Volatility3 memory-forensics wrappers (pslist etc.)
│       │   ├── tsk.py             ← Sleuth Kit — filesystem listing via fls
│       │   ├── correlation.py     ← W-150 deterministic cross-artifact correlation
│       │   └── _safe_tool.py      ← Decorator so tool exceptions never escape
│       ├── wazuh/                 ← Wazuh SIEM integration — IOC push, alerts, registrars
│       │   ├── client.py          ← WazuhClient — sole owner of httpx async client
│       │   ├── orchestrator.py    ← push_iocs() orchestrator — IOC-push entry point
│       │   ├── finding_to_alert.py ← Maps Agentropix findings to Wazuh alerts
│       │   ├── evidence_gate.py   ← Mutation-token verification for Wazuh writes
│       │   └── seal.py            ← Courtroom seal for the IOC-push integration
│       ├── evidence_gate/         ← Step-2 mutation-token gate — registry + CLI
│       │   ├── registry.py        ← SQLite-backed token registry
│       │   ├── cli.py             ← CLI for the Step-2 evidence gate
│       │   └── errors.py          ← Exception hierarchy for the gate
│       ├── detectors/             ← ATT&CK technique detectors (4 T-codes) + YARA hunt
│       │   ├── injection_detector.py ← Vol-driven in-memory process-injection detection
│       │   ├── yara_hunt.py       ← YARAHuntAgent — Cobalt Strike stager detection
│       │   ├── t1059_001_iex_loopback_c2.py ← T1059.001 IEX loopback-C2 detector
│       │   └── yara_rules/        ← YARA rule files used by detectors
│       ├── reports/               ← ADR-024 multi-tier report render/export/diagrams
│       │   ├── render.py          ← Render pipeline — Markdown → HTML → PDF (gated)
│       │   ├── export.py          ← Export orchestration for the three tiers
│       │   ├── diagrams.py        ← Mermaid builders — kill-chain, ptree, IOC graph
│       │   └── transformers.py    ← sections dict → three tier view models
│       ├── schema/                ← Typed tool I/O result schemas + JSON schemas
│       │   ├── report.schema.json ← JSON schema for report output structure
│       │   ├── master_iocs.schema.json ← JSON schema for the master-IOC aggregate
│       │   └── extract_archive.py ← W-095 typed result schema for extract_archive
│       ├── security/              ← Shared credential-redaction layer (W-203)
│       │   └── redact.py          ← Walks dict/list tree, redacts credential patterns
│       ├── trinity/               ← Trinity loop — Architect → Swarm → Critic engine
│       │   ├── architect.py       ← Architect — picks swarm slice for next iteration
│       │   └── critic.py          ← Critic — scores pass, decides loop halt
│       └── approval_sidecar/      ← HMAC human-approval sidecar + hash chain (Starlette)
│           ├── app.py             ← Starlette approval-sidecar routes (W-288)
│           ├── auth.py            ← PBKDF2 derivation + HMAC-SHA256 signatures
│           ├── hash_chain.py      ← Hash-chain helpers (tamper-evident approvals)
│           ├── writer.py          ← IndexerClient writer, prev-hash backfill
│           └── nonce.py           ← In-memory TTL nonce store (replay defense)
│
│  ── docs/ : the documentation portal (12 numbered sections + QA logs) ──
├── docs/
│   ├── 01-overview/               ← Start-here: what-is, quickstart, gold-standard user-guide
│   ├── 02-architecture/           ← Engine build outside-in: context → Trinity loop → swarm → MCP
│   ├── 03-data/                   ← Data model: Pydantic fields, schema-ER, persisted artifacts, datasets
│   ├── 04-mcp-tools/              ← The 73-tool MCP surface: capability map, reference, envelope
│   ├── 05-safety-forensics/       ← Safety spine: anti-hallucination, provenance, HMAC seal, approval
│   ├── 06-use-cases/              ← Worked dual-audience scenarios + demo walkthrough + hypotheses
│   ├── 07-sdlc-ops/               ← Build/test/secure/deploy/evaluate/maintain + accuracy supplements
│   ├── 08-reference/              ← CLI, glossary, ADR index, design rationale, canonical-facts authority
│   ├── 09-integrations/           ← Wazuh SOC push + remote tailnet client setup
│   ├── 10-agents/                 ← Runtime swarm vs BMAD personas; Trinity↔Swarm↔MCP model
│   ├── 11-ADR/                    ← 31 Architecture Decision Records (oracle mirror; header = index)
│   ├── 12-CASES-REPORTS/          ← Sealed DFIR case reports — one folder per case, PNG diagrams
│   │   ├── README.md              ← House-style index — one heading + read-order per case
│   │   ├── srl-2015-report/       ← SRL-2015: 4-host enterprise APT, USB-over-Ethernet C2, 17 approved
│   │   ├── srl-2018-report/       ← SRL-2018: network-wide APT / Cobalt Strike-Empire C2, multi-host
│   │   ├── vanko-report/          ← VANKO: insider IP-theft (zebrafish trade secrets), 10 approved
│   │   ├── cfreds-hacking-case-report/ ← CFReDS: Mr. Evil wireless interception, XP disk, 35 approved
│   │   └── srl-2018-artifact-inventory.md ← SRL-2018 inventory (9,578 findings, 29 hosts; oracle mirror)
│   └── issues/                    ← QA logs: diagram/case-guide audits, video-playback troubleshooting
│
│  ── case-activation/ : per-case Activation Guides + executed runs ──
├── case-activation/
│   ├── README.md                  ← Folder intro — 8-step template, dual-audience, approval hard-stop
│   ├── INDEX.md                   ← Master index — disk/memory/mixed tables, recorded-runs
│   ├── cfreds-hacking-case-4dell.md ← Guide: NIST CFReDS Hacking Case (Greg Schardt XP disk)
│   ├── techhive-chad-lt-laptop.md ← Guide: TheTechHive Chad_LT — only Windows-on-ARM disk case
│   ├── jimmy-wilson-study-case.md ← Guide: Jimmy Wilson study-case NTFS E01 disk
│   ├── dfrws-2005-rodeo-usb.md    ← Guide: DFRWS 2005 Rodeo RHINOUSB (raw FAT16 dd)
│   ├── vanko-abducted-zebrafish.md ← Guide: VANKO insider IP-theft, 21-segment EWF disk
│   ├── amf-memory-samples.md      ← Guide: Art-of-Memory-Forensics RAM dumps (Win/Linux/Mac)
│   ├── challenge-notch-it-up.md   ← Guide: Challenge "Notch It Up" raw RAM dump
│   ├── contact-me-memory.md       ← Guide: CTF contact_me raw RAM dump
│   ├── memdump-mem.md             ← Guide: generic 512 MiB raw memory dump
│   ├── memlabs-dumps.md           ← Guide: MemLabs CTF memory dumps (6 labs)
│   ├── win-xp-laptop-2005.md      ← Guide: Windows XP 2005 RAM capture (mislabeled disk)
│   ├── srl-2015-apt-enterprise.md ← Guide: SRL-2015 4-host APT (mixed disk+memory)
│   ├── srl-2018-compromised-enterprise.md ← Guide: SRL-2018 compromised enterprise (7 EWF + 22 memory)
│   ├── rocba-hackathon-2026.md    ← Guide: ROCBA 2026 Win10 insider (1 EWF + raw memory)
│   └── runs/                      ← Executed transcripts — captured MCP/engine runs + rendered MP4s
│       ├── README.md              ← Runs index — per-folder kind/evidence/headline table
│       ├── contact-me-memory/     ← MCP full-loop run+video: contact_me RAM, SIMULATED approval
│       ├── amf-win-sample001/     ← MCP full-loop run+video: AMF Windows sample (300s malfind)
│       ├── memdump-raw-2014/      ← MCP full-loop run+video: 2014 raw RAM, windows_info caveat
│       ├── challenge-notchitup/   ← MCP full-loop run+video: Notch It Up pslist/netscan/malfind
│       ├── srl-2018-compromised-enterprise/ ← MCP activation steps 1-6: SRL-2018 DC disk+memory
│       ├── vanko-abducted-zebrafish/ ← MCP activation steps 1-5: VANKO 21-segment EWF
│       ├── jimmy-wilson-poc/      ← Engine triage PoC+video+raw logs: Jimmy Wilson E01
│       ├── dfrws-rodeo-poc/       ← Engine triage PoC+log: DFRWS Rodeo USB, honest negatives
│       ├── engine-smoke-sample-dd/ ← Engine smoke run: synthetic sample.dd, first sealed record
│       ├── rocba/                 ← Live-MCP triage + req-8 agent-execution log + engine-run
│       │   ├── EXECUTION-LOG.md   ← ROCBA req-8 agent-execution-log doc (findings, honest gotchas)
│       │   └── engine-run/        ← Trinity-engine agent↔blackboard showcase (publishes + plan-shrink)
│       ├── WINXP-LAPTOP-2005/     ← Agent-execution-log run + rendered 3:19 deck video
│       │   └── WINXP-LAPTOP-2005-video/ ← Rendered execution MP4 + watch.html + correlation/storyboard
│       └── _assets/               ← Shared assets for run pages
│
│  ── Media / supporting assets ──
├── assets/                        ← Shared portal images and SVGs
└── Final_Video/                   ← Featured Case Evaluation walkthrough video(s)
```

## Legend / conventions

- **`←` comments** describe what each file/dir actually does; only key files per area are listed (subpackages list their most load-bearing modules, not every file).
- **src layout:** the package is `agentropix_mcp/src/agentropix_mcp/` with a console script `agentropix-mcp` → `fastmcp_app:main`. `fastmcp_app.py` is the thin FastMCP/stdio protocol surface; `server.py` holds the real tool logic and the Thymus read-only enforcement boundary. Underscore-prefixed modules (`_env`, `_trace`, `_tool_pins`, `_startup_banner`) are internal infra.
- **Install extras:** `[forensics]` (Volatility/TSK/YARA/Plaso runtime deps), `[reports]` (MD→HTML→PDF render stack), `[engine]` (the Trinity loop + swarm agents). Built wheels live in the gitignored `dist/` and are attached to GitHub releases.
- **Docs ↔ audience mapping:** `01-overview`/`06-use-cases` are operator/end-user oriented (dual-audience, prompt + CLI); `02-architecture`/`03-data`/`04-mcp-tools`/`10-agents` are reference/architecture; `05-safety-forensics`/`07-sdlc-ops`/`08-reference`/`09-integrations` cover the forensic/safety, SDLC-ops, lookup, and integration layers; `11-ADR` is the decision record, `12-CASES-REPORTS` the sealed investigations.
- **Canonical numbers** (73 MCP tools, 31 ADRs, per-case approval counts) come from `docs/08-reference/canonical-facts.md`; case-report diagrams are committed as **PNG** (not inline Mermaid) for reliable GitHub rendering, and recovered malware is withheld-by-reference (SHA-256 only).
