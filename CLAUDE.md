# CLAUDE.md — Agentropix-SIFT Documentation Portal

Conventions for working on this documentation portal. **Read before editing or adding any page.**
The portal is the reader-facing docs for Agentropix-SIFT; `INDEX.md` is the routed master
index and `README.md` is the landing page. Sections live under `docs/01-overview` … `docs/09-integrations`.

## Source of truth & accuracy
- **Canonical numbers come from [`.crew/facts.md`](.crew/facts.md)** — `71` MCP tools, `16` forensic
  wrappers, `4464` tests, `72/72 (100%)` disk recall, `108/118 (91.5%)` memory recall, Python `3.12+`.
  **Never state a number that contradicts it.** Stale figures may only appear inside an explicit
  "earlier draft said X, canonical is Y" reconciliation note.
- **The main repo `/home/admin2/agentropix-sift` (docs + `src/`) is the oracle.** Every non-obvious
  claim, command, flag, path, and tool name must be verifiable there; cite the source file. The oracle
  wins any conflict with portal prose or imported source material.

## The documentation template (the standard for this portal)
The gold-standard page is [`docs/01-overview/user-guide.md`](docs/01-overview/user-guide.md). Apply
its conventions to all **operational / how-to** content:

1. **Dual-audience representation.** For any operator action, show BOTH ways to get the same result
   in an eye-catching callout, side by side:
   - **🖥️ Expert (command):** the exact CLI / MCP call.
   - **💬 End-user (prompt):** the plain-language prompt a non-technical user types into Claude
     Desktop / Claude CLI (with the Agentropix MCP connected) — it must map to a **real MCP tool**
     (verify against [`.crew/tool-list.md`](.crew/tool-list.md)). The point: a simple focused
     question is enough — the session recognizes it as an Agentropix capability and routes the tool.
   *Adapt Agentropix to the user, not the user to Agentropix.*
2. **Execution → Output enumeration.** Label command/result pairs consistently (Execution A → Output
   A, B → Output B …) so it is unambiguous what the reader **runs** vs what they **get back**.
3. **Audience separation + usability matrix.** Where both apply, give a matrix correlating
   **Manual ↔ Autonomous** × **Expert (CLI) ↔ Non-expert (prompt)**; keep the lanes clearly separated.
4. **"How to read this page" / real-data preface.** If a page shows real example output, say up front
   that it comes from a validated prior run (e.g. the 2026-05-29 CFReDS run) so readers expect real
   artifacts/IDs. Explain every **GOTCHA** box (what it is, why real-data quirks appear).
5. **Reference vs operational.** Pure reference/architecture pages (architecture, data, tool reference,
   ADRs) get the *clarity* standard — define terms, explain everything, consistent style — but do not
   force prompt-boxes where there are no commands.

## Diagrams (Mermaid) — GitLab rendering rules
GitLab renders Mermaid client-side; respect its limits:
- **No C4 diagrams** (`C4Context/Container/Deployment`) — GitLab can't render them; use `flowchart`/etc.
- In `sequenceDiagram` message text, **no `;`** (statement separator) — use `,`. **No bare `#`**
  (HTML-entity escape). In `classDiagram` members, **no `{}`**.
- Every `classDef` needs an explicit `color:` (dark text) so it's legible in light AND dark mode.
- Keep diagrams **narrow** (GitLab fits them to the ~800px column); split wide ones, prefer vertical
  layout, and add an **"Open as SVG"** link (committed under the section's `assets/`) for any diagram
  that renders wider than the column. Validate with `mermaid-cli` before pushing.

## Images
- Screenshots: **crop to the relevant content** so they're legible at column width; capture at 2×
  (`deviceScaleFactor`). Store under the section's `assets/` dir. Reference with relative links.

## Security / hygiene (this repo may be made public)
- **No secrets, ever** — no tokens, passwords, or bearer keys in any tracked file.
- **No raw internal IPs/hostnames** in pages — use placeholders (`<TAILNET-IP>`) or the documented
  tailnet hostname. Screenshots that show live data carry a privacy note.
- Gitignored (local-only, never publish): `gitlab.txt`, `compare/`, `end-user/`, `2026-*/`,
  `issues/*.png`. Confirm `git status` won't stage these before committing.

## Validate before every push
1. **Links/images** — every relative link + `![](…)` resolves (0 broken).
2. **Canonical facts** — no number contradicts `.crew/facts.md`.
3. **Mermaid** — every `mermaid` block renders (mermaid-cli) and is GitLab-safe.
4. Mirror changed files into `/home/admin2/agentropix-sift/docs/portal/` (the in-repo copy).

## Layout
```
README.md            landing page
INDEX.md             routed master index (audience + "question it answers" per page)
.crew/               canonical facts + reference extracts (facts, tool-list, module-map, …)
docs/01-overview     what-is, what-you-get, quickstart, user-guide (gold standard), competitive-positioning
docs/02-architecture system-context, component, trinity-loop, swarm-agents, mcp-server, sequence-diagrams
docs/03-data         data-dictionary, data-models, schema-er, persisted-artifacts
docs/04-mcp-tools    tool-reference, response-envelope, tool-by-agent, capability-map
docs/05-safety-forensics  anti-hallucination, provenance-grounding, audit-courtroom, human-in-the-loop, approval-portal, ai-disclosure
docs/06-use-cases    uc-disk/memory/approval/wazuh, demo-walkthrough, case-hypotheses
docs/07-sdlc-ops     implementation, testing, recovery-resilience, security-model, configuration, deployment, dataset-recall, evaluation-scorecard, maintenance-dual-repo
docs/08-reference    cli-reference, glossary, adr-index, design-decisions
docs/09-integrations wazuh-portal, client-setup
```
