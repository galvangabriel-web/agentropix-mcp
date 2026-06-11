# 🎨 Agent Execution Logs — Visual Atlas

> **What this is.** The graphical companion to
> [`AGENT-EXECUTION-LOGS-REPORT.md`](AGENT-EXECUTION-LOGS-REPORT.md): thirteen color diagrams, one
> per major topic of the report, each **generated from and verified against the raw data files in
> this folder** (`base-dc-report.json`, `notch-report.json`, the run logs, and the Thymus audit
> trails) — no invented numbers. Diagrams are committed as PNG (rendered with mermaid-cli) so they
> always display on GitHub; every figure's Mermaid source is in a collapsed block beneath it.
>
> **Shared palette:** 🟦 blue = agents/tools/files · 🟪 purple = ATT&CK detectors & governance/seals ·
> 🟩 green = success/ALLOW/stable · 🟥 red = errors/REJECT/timeouts/gaps · 🟧 amber = correlation & anchors ·
> ⬜ grey = skipped/silent.

---

## 1. Agent-to-Agent Communication — who talked to whom

Maps the report's §3 handoff log: producers → correlation tokens → the hunt hub.

> **Why this representation:** The hunt correlator's 8 base-dc edges are pairwise "cross-source agreement" links keyed on a token, so the most faithful and catchable representation is a tripartite flowchart LR: producer agents (left, colored by category) converge on token nodes (middle, amber, with the real confidence value), which feed the single hunt hub (right). Modeling tokens as nodes instead of edge labels makes the 2-agent vs 3-agent agreements (scan, yara) visually obvious as fan-ins, and keeps the graph under 900px wide. A second, deliberately tiny notch diagram shows the degenerate case — one lone 0.3 'found' edge correlated entirely from failure/negative-result messages — which is itself the story.

### base-dc: agent-to-agent communication graph via the hunt correlator

![base-dc run: six producer agents converge on eight correlation tokens, which the hunt correlator seals as cross-source agreement edges (findings 14-21).](diagrams/base-dc-agent-correlation-graph.png)

*base-dc run: six producer agents converge on eight correlation tokens, which the hunt correlator seals as cross-source agreement edges (findings 14-21).*

**What to see:** Six of the 13 planned agents fed the correlator: blue disk agents (artifact, yara_hunt, null_session_baseline), purple ATT&CK detectors (t1059.001, t1546.008), and even the gray memory agent, whose skip notice still contributed the 'coverage' token. The two 3-agent agreements stand out as triple fan-ins: 'scan' (null_session_baseline + t1059.001 + yara_hunt) and 'yara' (artifact + t1546.008 + yara_hunt), both at confidence 0.4; the strongest edges are 'case' and 'evidence' at 0.6, the weakest 'host' at 0.3. The red box is honest about who said nothing: timeline timed out after 5452s and filesystem's fls after 60s, while discovery and mail produced no findings at all.

<details>
<summary>Mermaid source</summary>

```mermaid
flowchart LR
  subgraph SRC["base-dc-cdrive.E01 — 13-agent plan"]
    ART["artifact<br/>chain: case 20180905-001"]
    YH["yara_hunt<br/>Forge tag 20260505"]
    NSB["null_session_baseline<br/>0 bursts / 81 windows"]
    T59["t1059.001 iex-loopback<br/>0 hits / 999 EID 4104"]
    T46["t1546.008 IFEO hijack<br/>LEG-A Thymus REJECT"]
    MEM["memory<br/>skipped: not a RAM dump"]
    ERR["timed out, no token:<br/>timeline (5452s)<br/>filesystem fls (60s)"]
    QUIET["no token contributed:<br/>injection_detector, t1071.001 (skipped)<br/>discovery, mail (no findings)"]
  end
  subgraph TOK["correlation tokens (confidence)"]
    Kcase(["case (0.6)"])
    Kevid(["evidence (0.6)"])
    Kyara(["yara (0.4)"])
    Kscan(["scan (0.4)"])
    Kacross(["across (0.4)"])
    Kcomp(["complete (0.4)"])
    Kcov(["coverage (0.4)"])
    Khost(["host (0.3)"])
  end
  HUNT["hunt correlator<br/>8 cross-source edges"]

  ART --> Kcase
  YH --> Kcase
  ART --> Kevid
  T46 --> Kevid
  ART --> Kyara
  T46 --> Kyara
  YH --> Kyara
  NSB --> Kscan
  T59 --> Kscan
  YH --> Kscan
  NSB --> Kacross
  T59 --> Kacross
  NSB --> Kcomp
  T59 --> Kcomp
  MEM --> Kcov
  YH --> Kcov
  T59 --> Khost
  T46 --> Khost

  Kcase --> HUNT
  Kevid --> HUNT
  Kyara --> HUNT
  Kscan --> HUNT
  Kacross --> HUNT
  Kcomp --> HUNT
  Kcov --> HUNT
  Khost --> HUNT

  classDef disk fill:#bbdefb,stroke:#1565c0,color:#1a1a1a
  classDef det fill:#e1bee7,stroke:#6a1b9a,color:#1a1a1a
  classDef skip fill:#e0e0e0,stroke:#616161,color:#1a1a1a
  classDef err fill:#ffcdd2,stroke:#b71c1c,color:#1a1a1a
  classDef tok fill:#ffe0b2,stroke:#e65100,color:#1a1a1a
  classDef hub fill:#ffe0b2,stroke:#e65100,stroke-width:3px,color:#1a1a1a
  class ART,YH,NSB disk
  class T59,T46 det
  class MEM,QUIET skip
  class ERR err
  class Kcase,Kevid,Kyara,Kscan,Kacross,Kcomp,Kcov,Khost tok
  class HUNT hub
```

</details>

### notch: the single degenerate correlation edge

![notch run: the same 13-agent plan yields exactly one correlation edge — the token 'found' at confidence 0.3, agreed by three agents whose messages were all failures or negative results.](diagrams/notch-agent-correlation-graph.png)

*notch run: the same 13-agent plan yields exactly one correlation edge — the token 'found' at confidence 0.3, agreed by three agents whose messages were all failures or negative results.*

**What to see:** On the raw notch image the communication graph collapses to one edge (finding 9): 'found' flagged by null_session_baseline, t1059.001 and yara_hunt at confidence 0.3 — the lowest tier seen in either run. Note the source texts: two evtx_dump rc=1 failures and yara_hunt's 'found no scannable files', so the lone agreement is a token match across negative-result messages, not a detection. The gray box accounts for the other nine planned agents, all skipped, failed, or silent.

<details>
<summary>Mermaid source</summary>

```mermaid
flowchart LR
  subgraph SRC["Challenge.raw (notch) — 13-agent plan"]
    NSB["null_session_baseline<br/>evtx_dump failed (rc=1)"]
    T59["t1059.001 iex-loopback<br/>evtx_dump failed (rc=1)"]
    YH["yara_hunt<br/>found no scannable files"]
    SKIP["no token contributed:<br/>memory, injection_detector,<br/>t1071.001 (not a RAM image)<br/>t1546.008 (not an E01 image)<br/>filesystem: fls failed (rc=1)<br/>timeline, artifact, discovery,<br/>mail (no findings)"]
  end
  K(["found (0.3)"])
  HUNT["hunt correlator<br/>1 cross-source edge"]
  NSB --> K
  T59 --> K
  YH --> K
  K --> HUNT

  classDef disk fill:#bbdefb,stroke:#1565c0,color:#1a1a1a
  classDef det fill:#e1bee7,stroke:#6a1b9a,color:#1a1a1a
  classDef skip fill:#e0e0e0,stroke:#616161,color:#1a1a1a
  classDef tok fill:#ffe0b2,stroke:#e65100,color:#1a1a1a
  classDef hub fill:#ffe0b2,stroke:#e65100,stroke-width:3px,color:#1a1a1a
  class NSB,YH disk
  class T59 det
  class SKIP skip
  class K tok
  class HUNT hub
```

</details>

---

## 2. The End-to-End Timestamp Chain

Maps §4: the run's clock from first agent call to sealed report — macro, budget, and a microsecond zoom.

> **Why this representation:** The topic is a causal chain of timestamped events spanning seven orders of magnitude (a 5,452-second timeout down to a 217-microsecond burst), so a vertical flowchart with elapsed-time edge labels is the only form that keeps the sequence readable while making the wild duration asymmetry visible through edge annotations and outcome colors. A companion pie quantifies the headline fact (96.8% of the wall clock was one blocked tool call), and a micro-zoom flowchart resolves the 217-microsecond correlation burst that is invisible at run scale — together they tell the macro and micro story of the same clock.

### base-dc run — end-to-end timestamp chain (14:22:29 → 15:56:32 UTC)

![The base-dc run's 1 h 34 m 02 s timestamp chain: every key tool-call event from the 14:22:29 memory baseline to the sealed report, colored by outcome with elapsed-time edges.](diagrams/base-dc-timestamp-chain.png)

*The base-dc run's 1 h 34 m 02 s timestamp chain: every key tool-call event from the 14:22:29 memory baseline to the sealed report, colored by outcome with elapsed-time edges.*

**What to see:** Notice the brutal asymmetry: the very first edge consumes 91 min 02 s (96.8% of the run) waiting for log2timeline to hit its 5452 s timeout (tc[2], exit 1), while everything after 15:54:31 — including the 131-call extract_files storm (61 Thymus REJECTs + 70 rate-limit blocks) and the null_session_baseline running in parallel — fits in the last 2 minutes. The amber agent.hunt node then emits 8 cross-source correlation findings in just 217 microseconds (15:56:32.095393 → .095610) before the run seals with 22 findings, 176 tool calls, and report_seal 151c9e88…

<details>
<summary>Mermaid source</summary>

```mermaid
flowchart TD
    A["14:22:29.658 UTC<br/>agent.memory baseline<br/>0.11 ms - 1 finding"]:::ok
    B["15:53:31.501<br/>get_timeline FAIL exit 1<br/>log2timeline timed out after 5452 s"]:::bad
    C["15:54:31.620<br/>fls FAIL<br/>timed out after 60.0 s"]:::bad
    D["15:54:31.700<br/>get_image_info OK<br/>79.43 ms - E01 metadata"]:::ok
    E["15:54:31.702836<br/>extract_files call 1<br/>Thymus REJECT_OUTSIDE_ALLOWLIST"]:::rej
    F["15:54:35.582 - 15:55:33.829<br/>extract_files storm - 131 calls<br/>61 Thymus REJECT + 70 rate-limited"]:::rej
    G["15:55:32.320<br/>null_session_baseline done<br/>56.7 s - 1 finding"]:::ok
    H["15:55:33.811 - .829<br/>yara_hunt + injection + T1546.008<br/>5 findings - YARA mount skipped"]:::ok
    I["15:56:32.093<br/>T1059.001 IEX + T1071.001 svchost<br/>58.3 s - 3 findings"]:::ok
    J["15:56:32.095393 - .095610<br/>agent.hunt correlation burst<br/>8 findings in 217 microseconds"]:::hunt
    K["15:56:32.119754<br/>final list_files sweep<br/>tool call 176 of 176"]:::tool
    L["SEALED REPORT<br/>22 findings - budget_exhausted - critic 1.0<br/>report_seal 151c9e88 - audit seal 1085b493<br/>146 audit entries - evidence SHA e2b9cf0c"]:::seal

    A -->|"91 min 02 s blocked - 96.8% of run"| B
    B -->|"+60.1 s"| C
    C -->|"+80 ms"| D
    D -->|"+2 ms"| E
    E -->|"storm spans 62.1 s"| F
    E -->|"parallel - 60.6 s later"| G
    F --> H
    G --> H
    H -->|"+58.3 s scan"| I
    I -->|"+2.3 ms"| J
    J -->|"+24 ms"| K
    K --> L

    classDef ok fill:#c8e6c9,stroke:#2e7d32,color:#1a1a1a
    classDef bad fill:#ffcdd2,stroke:#c62828,color:#1a1a1a
    classDef rej fill:#ffcdd2,stroke:#b71c1c,stroke-dasharray:4 3,color:#1a1a1a
    classDef tool fill:#bbdefb,stroke:#1565c0,color:#1a1a1a
    classDef hunt fill:#ffe0b2,stroke:#ef6c00,color:#1a1a1a
    classDef seal fill:#e1bee7,stroke:#6a1b9a,color:#1a1a1a
```

</details>

### Where the 5,642 seconds went

![Wall-clock budget of the 94-minute base-dc run: a single blocked log2timeline call dominates everything else combined by a factor of 30.](diagrams/base-dc-wallclock-pie.png)

*Wall-clock budget of the 94-minute base-dc run: a single blocked log2timeline call dominates everything else combined by a factor of 30.*

**What to see:** The log2timeline slice (5,461.8 s measured duration_ms on tc[2], against its 5452 s configured cap) is 96.8% of the run; the three remaining phases — the 60.1 s fls timeout, the 62.1 s extract_files Thymus-REJECT storm, and the 58.3 s T1059/T1071 detector scans — are near-invisible slivers. The entire correlation, final sweep, and sealing tail adds under 30 ms and does not register at this scale.

<details>
<summary>Mermaid source</summary>

```mermaid
pie showData title base-dc wall clock - 5642 s total (14:22:29 - 15:56:32 UTC)
    "log2timeline timeout wait" : 5461.8
    "fls timeout" : 60.1
    "extract_files storm + artifact phase" : 62.1
    "T1059 / T1071 detector scans" : 58.3
```

</details>

### Micro-zoom — the 217-microsecond agent.hunt correlation burst

![Inside the 217-microsecond window at 15:56:32.095 UTC: agent.hunt emits all 8 cross-source correlation findings, 22-55 microseconds apart, closing the CROSS_AGENT_CORRELATION_DONE proof.](diagrams/hunt-burst-217us-zoom.png)

*Inside the 217-microsecond window at 15:56:32.095 UTC: agent.hunt emits all 8 cross-source correlation findings, 22-55 microseconds apart, closing the CROSS_AGENT_CORRELATION_DONE proof.*

**What to see:** Each amber node is one real hunt finding from base-dc-report.json with its exact sub-millisecond timestamp: the burst opens with token 'case' at .095393 (artifact + yara_hunt agree) and closes with token 'host' at .095610 — 217 microseconds total inside a 2.33 ms agent.hunt call (tc[151]). Inter-finding gaps shrink from 55 us down to 22 us, and two tokens ('scan', 'yara') reach 3-agent agreement, the strongest cross-source signal of the run.

<details>
<summary>Mermaid source</summary>

```mermaid
flowchart TD
    P["tc 151 - agent.hunt<br/>15:56:32.095698 UTC - 2.33 ms<br/>8 cross-source findings"]:::tool
    T0["+0 us - .095393<br/>token case<br/>artifact + yara_hunt"]:::hunt
    T1["+55 us - .095448<br/>token evidence<br/>artifact + T1546.008"]:::hunt
    T2["+89 us - .095482<br/>token across<br/>null_session + T1059.001"]:::hunt
    T3["+118 us - .095511<br/>token complete<br/>null_session + T1059.001"]:::hunt
    T4["+142 us - .095535<br/>token coverage<br/>memory + yara_hunt"]:::hunt
    T5["+167 us - .095560<br/>token scan<br/>3 agents agree"]:::hunt
    T6["+195 us - .095588<br/>token yara<br/>3 agents agree"]:::hunt
    T7["+217 us - .095610<br/>token host<br/>T1059.001 + T1546.008"]:::hunt
    S["completion proof<br/>CROSS_AGENT_CORRELATION_DONE"]:::seal

    P --> T0
    T0 -->|"55 us"| T1
    T1 -->|"34 us"| T2
    T2 -->|"29 us"| T3
    T3 -->|"24 us"| T4
    T4 -->|"25 us"| T5
    T5 -->|"28 us"| T6
    T6 -->|"22 us"| T7
    T7 --> S

    classDef tool fill:#bbdefb,stroke:#1565c0,color:#1a1a1a
    classDef hunt fill:#ffe0b2,stroke:#ef6c00,color:#1a1a1a
    classDef seal fill:#e1bee7,stroke:#6a1b9a,color:#1a1a1a
```

</details>

---

## 3. Iteration-over-Iteration — how the approach changed

Maps §5: the self-correction funnels and the plan-size cliff, both runs.

> **Why this representation:** The self-correction story has two distinct shapes that need two distinct visuals: (1) a per-run vertical flowchart funnel that shows WHY the plan shrank — the critic banks the stable agents' findings, drops them from the plan, and re-plans only the zero-finding gap agents, then loops on those gaps until the iteration budget runs out; and (2) a single xychart-beta comparing both runs' plan-size trajectory (13→2 vs 13→4), which makes the funnel shape and its iter-2 cliff instantly catchable. The flowcharts carry the real agent names and critic verdicts so the reader sees self-correction (not random shrinkage); the bar/line chart carries the cross-run comparison the flowcharts cannot. Vertical TD layouts keep both funnels at ~586px intrinsic width; all three sources were rendered with mmdc and verified.

### BASE-DC run — plan shrinks 13 → 2 (gap-only re-planning)

![BASE-DC (base-dc-cdrive.E01): after iteration 1, the 11 finding-producing agents are dropped from the plan and only the two zero-finding gap agents (discovery, mail) are re-planned, four times, until budget_exhausted.](diagrams/base-dc-self-correction-funnel.png)

*BASE-DC (base-dc-cdrive.E01): after iteration 1, the 11 finding-producing agents are dropped from the plan and only the two zero-finding gap agents (discovery, mail) are re-planned, four times, until budget_exhausted.*

**What to see:** Iteration 1 plans the full 13-agent roster; 11 agents produce findings (green) and are immediately dropped from all later plans (grey) — their results are banked, not re-computed. The critic (score 1.00, should_halt=false) re-plans only the 2 gap agents, discovery and mail, which return 0 findings on every one of the four retries (red chain). The run ends as budget_exhausted at 5/5 iterations with 22 sealed findings — an honest negative: the gaps never close, the loop never pretends they did.

<details>
<summary>Mermaid source</summary>

```mermaid
flowchart TD
    P1["ITER 1 - plan: 13 agents (full roster)"]:::plan
    P1 --> S1["11 STABLE - findings banked<br/>memory, timeline, filesystem, artifact<br/>null_session_baseline, yara_hunt<br/>injection_detector, hunt, t1546_008<br/>t1059_001, t1071_001"]:::stable
    P1 --> G1["2 GAPS - 0 findings<br/>discovery, mail"]:::gap
    S1 --> DR["DROPPED from plan, iters 2 to 5<br/>results kept, never re-run"]:::dropped
    G1 --> C1["Critic 1.00, should_halt false<br/>continue: plan gap, re-plan gaps only"]:::critic
    C1 --> P2["ITER 2 - plan: 2<br/>discovery, mail"]:::plan
    P2 --> G2["0 findings again"]:::gap
    G2 --> P3["ITER 3 - plan: 2"]:::plan
    P3 --> G3["0 findings"]:::gap
    G3 --> P4["ITER 4 - plan: 2"]:::plan
    P4 --> G4["0 findings"]:::gap
    G4 --> P5["ITER 5 - plan: 2"]:::plan
    P5 --> G5["0 findings"]:::gap
    G5 --> FIN["STATUS: budget_exhausted<br/>5 of 5 iterations, 22 findings sealed"]:::final
    classDef plan fill:#bbdefb,stroke:#1565c0,color:#1a1a1a
    classDef stable fill:#c8e6c9,stroke:#2e7d32,color:#1a1a1a
    classDef gap fill:#ffcdd2,stroke:#c62828,color:#1a1a1a
    classDef dropped fill:#e0e0e0,stroke:#757575,color:#1a1a1a
    classDef critic fill:#e1bee7,stroke:#6a1b9a,color:#1a1a1a
    classDef final fill:#ffe0b2,stroke:#e65100,color:#1a1a1a
```

</details>

### NOTCH run — plan shrinks 13 → 4 (gap-only re-planning)

![NOTCH (Challenge.raw): the same 13-agent roster yields only 9 stable agents — timeline and artifact join discovery and mail as gaps — so iterations 2-5 re-plan 4 agents instead of 2, again ending budget_exhausted.](diagrams/notch-self-correction-funnel.png)

*NOTCH (Challenge.raw): the same 13-agent roster yields only 9 stable agents — timeline and artifact join discovery and mail as gaps — so iterations 2-5 re-plan 4 agents instead of 2, again ending budget_exhausted.*

**What to see:** Identical self-correction mechanics as BASE-DC but a different gap set: on this raw memory image, timeline and artifact also produce 0 findings, so the re-planned set is 4 agents (timeline, artifact, discovery, mail) rather than 2. The 9 stable agents (green) are dropped after iteration 1 and the run seals 10 findings at budget_exhausted. Comparing the two funnels shows the planner adapts per-evidence: the shrink target is data-driven (13 to 2 vs 13 to 4), not hard-coded.

<details>
<summary>Mermaid source</summary>

```mermaid
flowchart TD
    P1["ITER 1 - plan: 13 agents (same roster)"]:::plan
    P1 --> S1["9 STABLE - findings banked<br/>memory, filesystem, null_session_baseline<br/>yara_hunt, injection_detector, hunt<br/>t1546_008, t1059_001, t1071_001"]:::stable
    P1 --> G1["4 GAPS - 0 findings<br/>timeline, artifact, discovery, mail"]:::gap
    S1 --> DR["DROPPED from plan, iters 2 to 5<br/>results kept, never re-run"]:::dropped
    G1 --> C1["Critic 1.00, should_halt false<br/>continue: plan gap, re-plan gaps only"]:::critic
    C1 --> P2["ITER 2 - plan: 4<br/>timeline, artifact, discovery, mail"]:::plan
    P2 --> G2["0 findings again"]:::gap
    G2 --> P3["ITER 3 - plan: 4"]:::plan
    P3 --> G3["0 findings"]:::gap
    G3 --> P4["ITER 4 - plan: 4"]:::plan
    P4 --> G4["0 findings"]:::gap
    G4 --> P5["ITER 5 - plan: 4"]:::plan
    P5 --> G5["0 findings"]:::gap
    G5 --> FIN["STATUS: budget_exhausted<br/>5 of 5 iterations, 10 findings sealed"]:::final
    classDef plan fill:#bbdefb,stroke:#1565c0,color:#1a1a1a
    classDef stable fill:#c8e6c9,stroke:#2e7d32,color:#1a1a1a
    classDef gap fill:#ffcdd2,stroke:#c62828,color:#1a1a1a
    classDef dropped fill:#e0e0e0,stroke:#757575,color:#1a1a1a
    classDef critic fill:#e1bee7,stroke:#6a1b9a,color:#1a1a1a
    classDef final fill:#ffe0b2,stroke:#e65100,color:#1a1a1a
```

</details>

### Plan size per iteration — BASE-DC vs NOTCH

![Agents in the plan at each of the 5 iterations: BASE-DC (blue bars) collapses 13 to 2 after iteration 1; NOTCH (orange line) collapses 13 to 4 — both then hold flat until budget_exhausted.](diagrams/plan-size-per-iteration-both-runs.png)

*Agents in the plan at each of the 5 iterations: BASE-DC (blue bars) collapses 13 to 2 after iteration 1; NOTCH (orange line) collapses 13 to 4 — both then hold flat until budget_exhausted.*

**What to see:** Both runs start with the full 13-agent plan and collapse after a single iteration — BASE-DC to 2 agents (blue bars: 13, 2, 2, 2, 2), NOTCH to 4 (orange line: 13, 4, 4, 4, 4). The one-iteration cliff is the self-correction signal: ~85% (11/13) and ~69% (9/13) of the roster proved stable on the first pass and was never re-run. The flat tail at 2 and 4 shows the critic (score 1.00, should_halt=false every iteration) kept retrying only the persistent zero-finding gaps until the 5-iteration budget was exhausted.

<details>
<summary>Mermaid source</summary>

```mermaid
---
config:
  themeVariables:
    xyChart:
      backgroundColor: "#ffffff"
      titleColor: "#1a1a1a"
      xAxisLabelColor: "#1a1a1a"
      xAxisTitleColor: "#1a1a1a"
      xAxisLineColor: "#1a1a1a"
      xAxisTickColor: "#1a1a1a"
      yAxisLabelColor: "#1a1a1a"
      yAxisTitleColor: "#1a1a1a"
      yAxisLineColor: "#1a1a1a"
      yAxisTickColor: "#1a1a1a"
      plotColorPalette: "#1565c0, #e65100"
---
xychart-beta
    title "Plan size per iteration - bar: BASE-DC (13 to 2), line: NOTCH (13 to 4)"
    x-axis ["iter 1", "iter 2", "iter 3", "iter 4", "iter 5"]
    y-axis "agents in plan" 0 --> 14
    bar [13, 2, 2, 2, 2]
    line [13, 4, 4, 4, 4]
```

</details>

---

## 4. Governance & Sealing — the boundary and the tamper-evidence

Maps §6: the Thymus gate decisions and the HMAC cross-binding chain.

> **Why this representation:** Governance has two distinct stories that need two distinct visual grammars: (1) the boundary's behavior is a simple categorical split, best told by ALLOW/REJECT pies — one per case, because the 42% REJECT rate on base-dc versus 0% on notch is itself a finding (the gate fires when workloads stray, stays silent when they don't); (2) the sealing is a dependency chain, so a vertical flowchart shows how one 32-byte key cross-binds report.json and audit-log.json while the evidence sha256 anchors everything, with the REJECT path in red to show denials are inside (not outside) the sealed record. A consistent palette (green=ALLOW, red=REJECT, purple=seals/governance, blue=files, amber=hash anchor) ties the three figures together. All three diagrams were rendered with mermaid-cli and visually verified; every number was extracted from the raw jsonl/json with jq.

### Thymus policy gate — base-dc case (146 decisions)

![Thymus runtime boundary on the base-dc disk case: 85 of 146 file-access decisions allowed, 61 rejected.](diagrams/thymus-gate-base-dc-pie.png)

*Thymus runtime boundary on the base-dc disk case: 85 of 146 file-access decisions allowed, 61 rejected.*

**What to see:** The gate is not decorative — 61 of 146 decisions (42%) were REJECTed, every one with reason REJECT_OUTSIDE_ALLOWLIST against /tmp/claude-1001 scratch paths (59x a tasks dir, 1x an extract dir, 1x a w204 dir). All 85 ALLOWs share a single reason, 'within read-only zone', covering only /cases/SRL-2018 (20) and the base-dc-cdrive.E01 image itself (65). Agents never touched anything outside the evidence allowlist, and every denial is on the sealed record.

<details>
<summary>Mermaid source</summary>

```mermaid
%%{init: {"theme":"base","themeVariables":{"pie1":"#c8e6c9","pie2":"#ffcdd2","pieTitleTextColor":"#1a1a1a","pieLegendTextColor":"#1a1a1a","pieSectionTextColor":"#1a1a1a","pieStrokeColor":"#1a1a1a"}}}%%
pie showData title base-dc Thymus gate - 146 decisions
    "ALLOW - within read-only zone" : 85
    "REJECT - outside allowlist" : 61
```

</details>

### Thymus policy gate — notch case (26 decisions)

![The same Thymus boundary on the notch raw-image case: all 26 decisions ALLOW, zero rejections.](diagrams/thymus-gate-notch-pie.png)

*The same Thymus boundary on the notch raw-image case: all 26 decisions ALLOW, zero rejections.*

**What to see:** All 26 decisions are ALLOW 'within read-only zone' (20x the /cases/Challenge_NotchItUp directory, 6x Challenge.raw) — the REJECT slice is deliberately kept in the legend at 0 to show the gate was armed but never tripped. Contrast with base-dc's 61 REJECTs: the difference is workload shape (the disk case spawned /tmp scratch traffic the policy refused), not a relaxed policy.

<details>
<summary>Mermaid source</summary>

```mermaid
%%{init: {"theme":"base","themeVariables":{"pie1":"#c8e6c9","pie2":"#ffcdd2","pieTitleTextColor":"#1a1a1a","pieLegendTextColor":"#1a1a1a","pieSectionTextColor":"#1a1a1a","pieStrokeColor":"#1a1a1a"}}}%%
pie showData title notch Thymus gate - 26 decisions
    "ALLOW - within read-only zone" : 26
    "REJECT" : 0
```

</details>

### Tamper-evidence cross-binding — evidence anchor, HMAC seals, and the Thymus REJECT path (base-dc)

![How one 32-byte session key cross-binds the findings report and the Thymus audit log into a single tamper-evident unit, anchored to the evidence image's sha256.](diagrams/seal-cross-binding-chain.png)

*How one 32-byte session key cross-binds the findings report and the Thymus audit log into a single tamper-evident unit, anchored to the evidence image's sha256.*

**What to see:** Follow the purple governance lane: the same 32-byte HMAC session key produces both report_seal (151c9e88...e453b8c1) over base-dc-report.json and audit_log_seal (1085b493...6b5927) over the 146-entry audit log — and that audit_log_seal value is embedded byte-identically inside report.json, so editing either file breaks the cross-bind. The red edge is the boundary in action: 61 REJECTs of /tmp scratch paths are themselves part of the sealed record, while the green ALLOW path leads only to the evidence image, whose sha256 (e2b9cf0c...965b31b1) anchors the whole chain to the physical evidence. The audit log's entry_count 146 matching its 146 actual entries is the third independent consistency check.

<details>
<summary>Mermaid source</summary>

```mermaid
flowchart TD
    REQ["Swarm agents<br/>file-access requests"] --> GATE{"Thymus policy gate<br/>base-dc: 146 decisions"}
    GATE -->|"85 ALLOW<br/>within read-only zone"| EV["Evidence image<br/>base-dc-cdrive.E01"]
    GATE -->|"61 REJECT<br/>REJECT_OUTSIDE_ALLOWLIST"| REJ["Blocked scratch paths<br/>59x tasks dir, 1x extract, 1x w204<br/>all under tmp claude-1001"]
    GATE -. "every decision appended" .-> AUD["base-dc-report.audit-log.json<br/>146 entries = entry_count 146"]
    EV --> SHA["sha256 anchor<br/>e2b9cf0c...965b31b1"]
    SHA --> RPT["base-dc-report.json<br/>evidence_image_sha256 field"]
    KEY["per-case session key<br/>32 bytes - HMAC<br/>bytes never printed"]
    RPT --> RSEAL["report_seal<br/>151c9e88...e453b8c1"]
    AUD --> ASEAL["audit_log_seal<br/>1085b493...6b5927"]
    KEY --> RSEAL
    KEY --> ASEAL
    ASEAL --> BIND["SEALS-CROSS-BIND<br/>audit_log_seal identical in<br/>report.json and audit-log.json"]
    RPT --> BIND
    classDef gov fill:#e1bee7,stroke:#6a1b9a,color:#1a1a1a
    classDef ok fill:#c8e6c9,stroke:#2e7d32,color:#1a1a1a
    classDef bad fill:#ffcdd2,stroke:#b71c1c,color:#1a1a1a
    classDef file fill:#bbdefb,stroke:#1565c0,color:#1a1a1a
    classDef anchor fill:#ffe0b2,stroke:#e65100,color:#1a1a1a
    class GATE,KEY,RSEAL,ASEAL,BIND gov
    class EV ok
    class REJ bad
    class REQ,RPT,AUD file
    class SHA anchor
    linkStyle 2 stroke:#b71c1c,stroke-width:2px
```

</details>

---

## 5. The Numbers at a Glance

Headline metrics of both runs, chartable and comparable in one look.

> **Why this representation:** The topic is "run metrics at a glance," which is purely quantitative — bar charts (xychart-beta) are the only representation that makes magnitudes instantly comparable. Chart 1 ranks the 11 base-dc agents by findings so the hunt agent's dominance (8 of 22) pops immediately; Chart 2 puts the two runs side-by-side on all three headline metrics (calls, findings, runtime) using alternating blue/amber bars via a zero-placeholder two-series technique, so the 176-vs-60 and 94-min-vs-1.2-min contrasts are caught in one look. Every number was extracted from base-dc-report.json and notch-report.json with python3 (findings[] grouped by agent field; trace.tool_calls length; trace.total_duration_ms), and both Mermaid sources were render-verified with mermaid-cli to PNG.

### base-dc: Findings per Agent

![Findings per agent in the base-dc run (22 total, sorted descending) — the correlation hunt agent alone contributed 8.](diagrams/base-dc-findings-per-agent.png)

*Findings per agent in the base-dc run (22 total, sorted descending) — the correlation hunt agent alone contributed 8.*

**What to see:** The hunt (correlation) agent dominates with 8 of the 22 findings — 4x any single detector — showing most value came from cross-agent correlation rather than any one detector. The mid tier (artifact, yara, t1546 IFEO hijack, t1059 IEX loopback C2) contributed 2 each; six agents contributed 1 each. Note the memory bar is a skip marker, not a detection: the MemoryAgent recorded an honest 'disk-only image, Volatility requires RAM' skip with confidence 0.0.

<details>
<summary>Mermaid source</summary>

```mermaid
%%{init: {"xyChart": {"width": 880, "height": 430}, "themeVariables": {"xyChart": {"plotColorPalette": "#1565c0", "titleColor": "#1a1a1a", "xAxisLabelColor": "#1a1a1a", "xAxisTitleColor": "#1a1a1a", "xAxisLineColor": "#1a1a1a", "yAxisLabelColor": "#1a1a1a", "yAxisTitleColor": "#1a1a1a", "yAxisLineColor": "#1a1a1a"}}}}%%
xychart-beta
    title "base-dc run: 22 findings across 11 agents (94 min)"
    x-axis ["hunt", "artifact", "yara", "t1546", "t1059", "timeline", "filesys", "null-sess", "inject", "t1071", "memory"]
    y-axis "findings" 0 --> 9
    bar [8, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1]
```

</details>

### Run Comparison: base-dc vs notch

![Headline metrics of the two SRL-2018 submission runs side by side: tool calls, findings, and wall-clock runtime.](diagrams/base-dc-vs-notch-run-comparison.png)

*Headline metrics of the two SRL-2018 submission runs side by side: tool calls, findings, and wall-clock runtime.*

**What to see:** base-dc (blue) used 176 tool calls to seal 22 findings in 94.0 min; notch (amber) used 60 calls for 10 findings in just 72.4 seconds (1.2 min). The near-invisible 'min notch' bar IS the story: the 78x runtime gap is almost entirely one tool — base-dc's get_timeline call ran 5,461.8 s of the 5,642 s total (log2timeline timed out at 5452 s on the E01), while everything else on both runs completed in seconds. Both runs ended with status budget_exhausted after 5 iterations and a critic_score of 1.0.

<details>
<summary>Mermaid source</summary>

```mermaid
%%{init: {"xyChart": {"width": 860, "height": 430}, "themeVariables": {"xyChart": {"plotColorPalette": "#1565c0, #ef6c00", "titleColor": "#1a1a1a", "xAxisLabelColor": "#1a1a1a", "xAxisTitleColor": "#1a1a1a", "xAxisLineColor": "#1a1a1a", "yAxisLabelColor": "#1a1a1a", "yAxisTitleColor": "#1a1a1a", "yAxisLineColor": "#1a1a1a"}}}}%%
xychart-beta
    title "base-dc (blue) vs notch (amber): 176 vs 60 calls, 22 vs 10 findings, 94 vs 1.2 min"
    x-axis ["calls base-dc", "calls notch", "findings base-dc", "findings notch", "min base-dc", "min notch"]
    y-axis "count or minutes" 0 --> 180
    bar [176, 0, 22, 0, 94, 0]
    bar [0, 60, 0, 10, 0, 1.2]
```

</details>

---

*Built from the sealed records in this folder; cross-checked claims live in the
[gold report](AGENT-EXECUTION-LOGS-REPORT.md) (§3–§6) and are independently re-verifiable via its
"verify in 60 seconds" block. Folder guide: [README.md](README.md).*
