# Accuracy Report — What the Recall Numbers Honestly Mean

> **Audience:** judges and auditors. This page consolidates, in one place, every accuracy
> caveat the project discloses: the curve-fit methodology admission, the honest combined
> recall number, the April failure history, concrete false positives and hallucinations
> the project caught in its own output (with weakness-ledger IDs), the artifacts the
> system is known to miss or not measure, and (§6) **how the architecture — not a
> prompt — prevents the original evidence from ever being modified.**

Companion pages: [Evaluation Corpus & Recall Methodology](dataset-recall.md) ·
[Cross-Modal Recall Summary (2026-05-06 snapshot)](cross-modal-recall-summary.md) ·
[Testing](testing.md) · [Observability & Integrity Notes](observability-and-integrity-notes.md).

---

## 1. The curve-fit disclosure (verbatim from the engine README)

The engine README's "Run the real-data recall gate" section carries this inline
methodology caveat, reproduced verbatim:

> **Disk per-IOC recall: 72/72 (100%) on the SRL-2018 regression suite.**
> *Methodology caveat (inline disclosure):* the recall figure is from the
> regression suite where 6 of 7 per-host ground-truth YAMLs in
> `samples/ground_truth_*.yaml` were authored from earlier wrapper output
> (one keyword was edited from `powershell` to `cmd.exe` to match
> observed cmd.exe findings). **The 100% number is partially curve-fit.** A
> blinded held-out re-score against a disk no wrapper author has seen
> output for is in progress (target 2026-05-27); the README headline
> will update to dual-report regression + blinded once it lands.

In plain terms: most of the disk ground truth was written *after* looking at what the
wrapper emitted, so the 100% disk figure measures regression stability (does the pipeline
keep finding what it found before?) more than blind detection power. That is why the
project refuses to lead with it.

## 2. The honest combined number

> **Memory + disk combined: 108/118 (91.5%)** — includes
> **T1003.002 = 30/40 = 75%** on the 25-dump memory corpus. The 100% disk
> headline does NOT include the memory side; **the combined number is the
> honest one.**

The worst-performing band is **T1003.002 (OS Credential Dumping: SAM)** at **30/40 = 75%**
— 10 of the 118 IOCs in the combined pool are missed there. The two-framing split
(canonical tactic-hit 72/72 + 108/118 vs. operator-attested per-IOC 156/156) is explained
in [dataset-recall.md §1](dataset-recall.md); the two figures use different units and must
not be added or reconciled.

## 3. April 2026 failure history — the gate did not start green

The recall gate was failing for most of April. The M6.x diagnostic-sprint trail
(preserved in the engine CHANGELOG) shows the climb:

| Milestone | Date | DC E01 cohit≥2 recall |
|---|---|---|
| W-046 gate first lands | mid-Apr 2026 | **1/7** (4/7 on the legacy scorer only) |
| M6.7 (W-064 csv field-size fix) | 2026-04-23 | 2/7 |
| M6.8 (W-066 MFT timestamp widen) | 2026-04-23 | 3/7 |
| M6.9 (W-067 per-plugin deque) | 2026-04-23 | 4/7 — gate threshold 0.57 reached |
| M6.10 (T1055 staging detector) | 2026-04-23 | 5/7 = 0.71 |
| M6.12 (W-069 T1105 enrichment) | 2026-04-24 | 7/7 = 1.000 |
| M6.11.1 live re-run | 2026-04-25 | 6/7 = 0.857 (T1055 miss = W-071 plaso non-determinism) |

The README's own framing: "Apr 2026 M6.x diagnostic-sprint history (recall 4/7, gate 0.57
not met) is preserved in CHANGELOG; this README headline tracks the May result." Note the
6/7 re-run on 2026-04-25: even after "perfect recall" was first claimed, a live re-run
dropped a technique to plaso non-determinism, and that was logged rather than hidden.

## 4. False positives and hallucinations the project caught in itself

The engine keeps a public-of-record weakness ledger (`docs/SIFT-WEAKNESSES.md` in the
engine repo, 280+ numbered entries). Concrete cases where a detector over-fired or a
claim was corrected:

- **W-168 — skip/error findings counted as hallucinations on clean images.** Two newer
  detectors (YARAHuntAgent, InjectionDetector) emitted `Finding` records with
  `confidence > 0.0` on skip/error/empty paths. The false-positive gate
  (`tests/integration/test_e2e_dc_recall.py`) filters on `confidence > 0.0`, so "ran but
  had nothing to do" was being scored as a confident hallucination on every clean image.
  Fixed by zeroing confidence on infrastructure-event paths.
- **W-180 — `yara_forge.bundle_active` status finding tripping the FP gate.** A
  status/bookkeeping finding regressed to `confidence=0.50`, failing
  `test_no_false_positives_on_clean_image` on every clean-image run with YARA staged.
  Fixed to `confidence=0.0` plus a dedicated regression guard test
  (`test_bundle_active_is_zero_confidence_for_fp_gate`).
- **W-270 — junction-name hint false positive on XP-era images.** The W-255
  reparse-point hint emitted unconditionally whenever a path contained `My Documents`
  etc. — correct on Vista+, a false positive on XP-era NTFS where `My Documents` is a
  real allocated directory (verified on the CFReDS Hacking Case image). Fix moved the
  hint to after a successful retry, with a falsifiable acceptance test (PR #151).
- **W-282 — real-data verify caught a just-merged wrong fix.** PR #177's
  `mount -o loop,sizelimit=...` approach for tail-truncated EWF images passed all mocked
  unit tests green, but the mandated real-data acceptance run on a real E01 proved it
  structurally wrong (ntfs-3g aborts reading the `$Boot`-claimed last sector). Corrected
  by PR #178 (dm-zero-pad), then verified end-to-end: 6,585,064 timeline events read.
  Logged in the ledger as the canonical "unit-vs-live" lesson.
- **W-106 — TimelineAgent Run-key emitter coasting on technique-label boilerplate.**
  The emitter was scoring via boilerplate technique labels rather than evidence-derived
  content (cohit fragility) — a corrected case of a detector "passing" the scorer
  without genuinely earning the hit. Companion tripwire W-107 locks ground-truth
  substrings against silent reword.
- Case-report level: the Vanko investigation's false-positive gate **refuted 9 of 19
  findings** (e.g. generic YARA family hits `with_sqlite` / `XMRIG_Miner` with no PE
  backing, and a pagefile `dropbox.com/s/` hit shown to be an obfuscator template, not
  the actor's link) — see
  [VANKO-FORENSIC-REPORT](../12-CASES-REPORTS/vanko-report/VANKO-FORENSIC-REPORT.md) and
  [anti-hallucination](../05-safety-forensics/anti-hallucination.md).

## 5. Missed artifacts and unmeasured surface

- **10 missed IOCs in the combined 118 pool**, concentrated in the T1003.002 SAM-dumping
  band (30/40 = 75%).
- **25 SRL-2015 memory dumps have no authored ground truth** — their recall is inferred,
  not measured (~1,069 IOCs surfaced but ungraded). See
  [dataset-recall.md §5](dataset-recall.md) ("The honest gap").
- **`base-rd-01` cross-modal coherence is 0.0%** — by-design complementarity of a
  paused-VM (Cat 2b) snapshot, reported as-is rather than excluded. See the
  [cross-modal summary](cross-modal-recall-summary.md).
- **T1055 on the DC image is non-deterministic** under plaso load (W-071/W-104/W-105/W-128
  lineage): the plaso timeout slope was twice retuned after borderline 4/7 nightly passes
  were caught and root-caused rather than waved through.
- Malfind-derived injection candidates in memory reports are explicitly framed as an
  *adjudication list*, not asserted injection, because malfind's false-positive rate on
  JIT/.NET regions is high (see the SRL-2018 technical appendix).

## 6. Evidence integrity — how the architecture prevents original data from being modified

Accuracy is not only about *what* the agent reports; it is about whether reporting it
could have *altered the thing being examined*. A triage agent that mutates the evidence
to find a fact has produced a hallucination of a different kind. This section states,
plainly, how Agentropix makes evidence modification **structurally impossible** — and
where that guarantee is honestly bounded.

> 📊 **Visual companion:** [Evidence Integrity, Visually](evidence-integrity-visual.md) —
> the same argument as colour-coded architecture diagrams + real-data charts (layer
> interconnection, the Thymus allow/deny flow, architectural-vs-prompt-based, and what
> happens when the model ignores the restriction).

### The guarantee is architectural, not prompt-based

The distinction matters in court: an **architectural** control is enforced by code the
model cannot reach around; a **prompt-based** control is an instruction the model is
merely *expected* to honor. Evidence integrity here is architectural at three layers:

1. **There is no write tool in the surface.** The read-only **Thymus** policy gates every
   evidence access. Its `check_write()` method
   (`thymus_policy.py:362`) does not conditionally allow anything — it is hard-coded to
   reject, with the in-source docstring *"All writes are rejected — evidence integrity is
   architectural ... No MCP tool should call it; it exists for defense-in-depth and audit
   completeness."* A source grep confirms the claim: **no tool in the 72-tool surface
   calls `check_write` at all**, because none of them can write evidence. Reads go through
   `check_read()` (`thymus_policy.py:236`), a deny-by-default allowlist
   (`/cases/`, `/mnt/`, `/media/`, `/evidence/`, …) that rejects traversal, symlink,
   URL-decode and PATH_MAX tricks *before any byte is opened*.
2. **Every forensic binary is invoked read-only, via argv — never a shell.** All wrappers
   spawn through `asyncio.create_subprocess_exec` with an argument list
   (e.g. `wrappers/tsk.py`, `wrappers/disk_container.py`, `wrappers/mftecmd.py`); there is
   **no `create_subprocess_shell` anywhere in the tree**, so neither the model nor a
   crafted path can smuggle a write/`dd`/`mount -o rw` through a shell string. Disk images
   are opened by read-only tooling (Sleuth Kit, ewf-tools) and loop-mounted read-only.
3. **The evidence is hash-pinned at session start and the report is HMAC-sealed.**
   `evidence_image_sha256()` (`courtroom.py:89`) computes the full SHA-256 of the image
   once, at session start, and that digest is embedded in the sealed `report.json`
   (single call site `orchestrator.py:292` → embedded `:311`); `evidence_register`
   independently hashes at registration. The report and audit log are then sealed with a
   per-run HMAC key and cross-bound, so any after-the-fact tampering with *either* the
   evidence digest or the findings breaks verification (`courtroom.py:161-397`,
   `audit/verify_seal.py`). A judge or opposing examiner can re-hash the image offline and
   compare against the embedded digest **without trusting the runtime at all**.

A fourth, related architectural stop protects the *findings* chain rather than the bytes:
the **W-286 gate** force-stamps every ingested finding to `DRAFT` and strips any
caller-supplied `approval.*` field (`wrappers/wazuh_tools.py:44-98`,
`approval_sidecar/__init__.py`), so the LLM cannot self-approve or seal a finding through
any write surface — promotion requires a human HMAC challenge-response.

### What happens if the model "ignores" the restriction

Because the controls are architectural, there is no instruction for the model to ignore —
the capability simply does not exist:

- If the model (or a buggy tool) attempted to write evidence, the only code path is
  `check_write()`, which returns a `Thymus REJECT` string and logs a `REJECT_WRITE` entry
  to the Thymus audit trail — the write never reaches the filesystem.
- If the model requested a path outside the evidence allowlist, `check_read()` denies it
  before any I/O and records the denial.
- The handful of genuinely **prompt-based** conventions in the system (the optional,
  default-off Architect agent-reorder system prompt; the AI-disclosure wording; the
  narrative-rendering layer) **touch no evidence and author no finding**, and each is
  paired with a code-side backstop (e.g. the reorder output is rejected unless it exactly
  equals the deterministic agent set). So even a fully misbehaving prompt layer cannot
  modify evidence or fabricate a sealed fact.

### Honest bound — the "post" half is offline, not automated

We state the limit as plainly as the guarantee: **there is no automated post-run
re-hash-and-compare, and no abort-on-mismatch path, in the runtime.** The image is hashed
once (the "pre" side); the "post" side exists in three weaker forms — the structural
read-only boundary (mutation is impossible by construction), a CI test that hashes only
the **first 1 MiB** of the E01 before/after extraction
(`tests/integration/test_extract_files_e01.py`, *not* a full-image or runtime check), and
the **manual/offline re-verification** any party can run against the embedded digest. A
full-image re-hash after every run was judged not worth roughly doubling wall-clock to
re-confirm an invariant the architecture already makes redundant. The complete analysis,
with file:line citations and the re-verify recipe, is in
[Observability & Integrity Notes §1](observability-and-integrity-notes.md#1-no-automated-post-run-evidence-re-hash).

## 7. Where to verify

| Claim | Where |
|---|---|
| Curve-fit caveat + 108/118 + T1003.002=30/40 | Engine README, "Run the real-data recall gate"; mirrored here §1–2 and in [dataset-recall.md](dataset-recall.md) |
| Evidence write rejected by construction (`check_write`) | `agentropix_mcp/src/agentropix_mcp/thymus_policy.py:362`; pre-hash `courtroom.py:89`; bound at `orchestrator.py:292/311` |
| No automated post-run re-hash (honest bound) | [observability-and-integrity-notes.md §1](observability-and-integrity-notes.md#1-no-automated-post-run-evidence-re-hash) |
| April 1/7→7/7 climb, 0.57 gate | Engine CHANGELOG milestone trail (M6.x) |
| W-numbered corrections | Engine `docs/SIFT-WEAKNESSES.md` ledger (W-168, W-180, W-270, W-282, W-106) |
| 156/156 per-IOC snapshot + 0% coherence host | [cross-modal-recall-summary.md](cross-modal-recall-summary.md) |
| 9 refuted Vanko findings | [docs/12-CASES-REPORTS/vanko-report/](../12-CASES-REPORTS/vanko-report/VANKO-FORENSIC-REPORT.md) |
| SRL-2018 finding inventory (9,578 findings / 29 hosts) | [SRL-2018 artifact inventory](../12-CASES-REPORTS/srl-2018-artifact-inventory.md) |
