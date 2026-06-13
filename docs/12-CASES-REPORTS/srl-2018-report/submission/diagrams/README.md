# `submission/diagrams/` — Agent-Execution Atlas: sources & rendered outputs

This folder holds the SRL-2018 Agent-Execution Visual Atlas diagrams **and their build sources**.
The reports embed the **rendered outputs** (PNG / GIF); the **source files** (`.mmd`, deck `.html`)
are the render inputs — kept for reproducibility, not meant to be read directly.

## Static diagrams — Mermaid source (`.mmd`) → rendered `.png`

| Mermaid source | Rendered output | Diagram |
|---|---|---|
| `base-dc-agent-correlation-graph.mmd` | `base-dc-agent-correlation-graph.png` | base-dc agent-to-agent correlation graph |
| `base-dc-findings-per-agent.mmd` | `base-dc-findings-per-agent.png` | findings-per-agent bar |
| `base-dc-self-correction-funnel.mmd` | `base-dc-self-correction-funnel.png` | base-dc self-correction funnel |
| `base-dc-timestamp-chain.mmd` | `base-dc-timestamp-chain.png` | base-dc timestamp chain |
| `base-dc-vs-notch-run-comparison.mmd` | `base-dc-vs-notch-run-comparison.png` | base-dc vs notch run comparison |
| `base-dc-wallclock-pie.mmd` | `base-dc-wallclock-pie.png` | base-dc wall-clock pie |
| `hunt-burst-217us-zoom.mmd` | `hunt-burst-217us-zoom.png` | hunt-burst 217 µs zoom |
| `notch-agent-correlation-graph.mmd` | `notch-agent-correlation-graph.png` | notch agent-to-agent correlation graph |
| `notch-self-correction-funnel.mmd` | `notch-self-correction-funnel.png` | notch self-correction funnel |
| `plan-size-per-iteration-both-runs.mmd` | `plan-size-per-iteration-both-runs.png` | plan-size-per-iteration (both runs) |
| `seal-cross-binding-chain.mmd` | `seal-cross-binding-chain.png` | seal cross-binding chain |
| `thymus-gate-base-dc-pie.mmd` | `thymus-gate-base-dc-pie.png` | Thymus-gate base-dc pie |
| `thymus-gate-notch-pie.mmd` | `thymus-gate-notch-pie.png` | Thymus-gate notch pie |

Render with `mmdc` (mermaid-cli) per the repo's diagram recipe; the `.png` is what the reports embed.

## Animated decks — HTML source → rendered `.gif`

`animated-decks/` holds the HTML slide decks captured (CDP virtual-time, 12 fps) into the `atlas-*.gif`
animations shown in the Atlas:

| Deck source | Rendered output |
|---|---|
| `animated-decks/a2a.html` | `atlas-a2a.gif` |
| `animated-decks/clock.html` | `atlas-clock.gif` |
| `animated-decks/gov.html` | `atlas-gov.gif` |
| `animated-decks/hero.html` | `atlas-hero.gif` |
| `animated-decks/iter.html` | `atlas-iter.gif` |
| `animated-decks/metrics.html` | `atlas-metrics.gif` |
| `animated-decks/wallclock-bar.html` | wall-clock bar animation (deck source) |

← Back to the [submission package](../README.md) · the rendered diagrams appear in
[`AGENT-EXECUTION-VISUAL-ATLAS.md`](../AGENT-EXECUTION-VISUAL-ATLAS.md).
