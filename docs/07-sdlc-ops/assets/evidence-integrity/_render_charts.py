#!/usr/bin/env python3
"""Render the 4 real-data charts for the evidence-integrity visual page.

Every number here is verified against the repo (canonical-facts.md, the VANKO
confirmed-findings.json / FINDINGS.jsonl, the SRL-2018 notch Thymus audit, and
the jimmy-wilson-poc report.json trace). Honest-negatives discipline preserved:
91.5% is the headline, the 75% band is shown, and the 0-reject ledger is framed
as "in-bounds run, reject path code-enforced but not triggered."
"""
import json
import pathlib

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[3]  # docu_agentro/
DPI = 200

# Color language shared with the Mermaid diagrams
GREEN = "#16a34a"   # architectural / allow / good
AMBER = "#d97706"   # caveat / prompt-based
BLUE = "#2563eb"    # read-only evidence / neutral data
RED = "#dc2626"     # deny / refuted
GREY = "#6b7280"
INK = "#14532d"
plt.rcParams.update({"font.size": 12, "axes.edgecolor": "#334155",
                     "axes.titleweight": "bold", "axes.titlesize": 13})


def _bar_labels(ax, bars, labels, dy=1.5):
    for b, t in zip(bars, labels):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + dy, t,
                ha="center", va="bottom", fontweight="bold", fontsize=11)


# ----------------------------------------------------------------------------
# C1 — Recall, honestly reported
# ----------------------------------------------------------------------------
def c1_recall():
    fig, ax = plt.subplots(figsize=(8.2, 5.0))
    cats = ["Disk recall\n(72/72, regression)", "Memory recall\n(108/118, COMBINED)",
            "Worst band T1003.002\n(30/40, SAM dumping)"]
    vals = [100.0, 91.5, 75.0]
    colors = [AMBER, GREEN, RED]  # disk amber = curve-fit caveat; memory green = the honest headline
    bars = ax.bar(cats, vals, color=colors, edgecolor="#1e293b", width=0.62, zorder=3)
    _bar_labels(ax, bars, ["100%\n(partially curve-fit)", "91.5%\n← the honest number", "75%\n(10 IOCs missed)"])
    ax.axhline(91.5, ls="--", lw=1.2, color=GREEN, alpha=0.7, zorder=2)
    ax.set_ylim(0, 118)
    ax.set_ylabel("Recall (%)")
    ax.set_title("Recall, reported honestly — 91.5% combined is the headline")
    ax.grid(axis="y", ls=":", alpha=0.5, zorder=0)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(HERE / "c1-recall-honest.png", dpi=DPI, facecolor="white")
    plt.close(fig)


# ----------------------------------------------------------------------------
# C2 — VANKO honest negatives (FP gate refuting our own findings)
# ----------------------------------------------------------------------------
def c2_vanko():
    confirmed, refuted, total = 10, 9, 19
    # cross-check against the repo if the files are present
    cf = REPO / "docs/12-CASES-REPORTS/vanko-report/confirmed-findings.json"
    fl = REPO / "docs/12-CASES-REPORTS/vanko-report/FINDINGS.jsonl"
    if cf.exists():
        confirmed = len(json.load(open(cf)))
    if fl.exists():
        total = sum(1 for _ in open(fl))
        refuted = total - confirmed
    fig, ax = plt.subplots(figsize=(7.0, 5.0))
    wedges, _texts, _auto = ax.pie(
        [confirmed, refuted], colors=[GREEN, RED], startangle=90,
        autopct=lambda p: f"{int(round(p * total / 100))}",
        pctdistance=0.78, wedgeprops=dict(width=0.42, edgecolor="white", linewidth=2),
        textprops=dict(color="white", fontweight="bold", fontsize=15))
    ax.text(0, 0, f"{total}\nhypotheses", ha="center", va="center", fontweight="bold", fontsize=14)
    ax.set_title("VANKO — the FP gate refuted 9 of our own 19 findings")
    ax.legend(handles=[Patch(facecolor=GREEN, label=f"Confirmed ({confirmed})"),
                       Patch(facecolor=RED, label=f"Refuted by FP gate ({refuted})")],
              loc="lower center", ncol=2, frameon=False, bbox_to_anchor=(0.5, -0.08))
    fig.tight_layout()
    fig.savefig(HERE / "c2-vanko-honest-negatives.png", dpi=DPI, facecolor="white")
    plt.close(fig)


# ----------------------------------------------------------------------------
# C3 — Thymus access ledger (real SRL-2018 notch run)
# ----------------------------------------------------------------------------
def c3_thymus():
    allow, reject = 26, 0
    aud = REPO / "docs/12-CASES-REPORTS/srl-2018-report/submission/notch-thymus-audit.jsonl"
    if aud.exists():
        actions = [json.loads(l).get("action") for l in open(aud)]
        allow = sum(1 for a in actions if a == "ALLOW")
        reject = sum(1 for a in actions if a and a != "ALLOW")
    fig, ax = plt.subplots(figsize=(8.6, 4.8))
    bars = ax.barh(["ALLOW\n(in-bounds read)", "REJECT\n(out-of-bounds / write)"],
                   [allow, max(reject, 0)], color=[GREEN, RED], edgecolor="#1e293b", height=0.55, zorder=3)
    for b, v in zip(bars, [allow, reject]):
        ax.text(b.get_width() + 0.3, b.get_y() + b.get_height() / 2, str(v),
                va="center", fontweight="bold", fontsize=13)
    ax.set_xlim(0, allow + 4)
    ax.set_xlabel("Thymus policy decisions (count)")
    ax.set_title("Real SRL-2018 run: every evidence access passed the read-only gate")
    ax.grid(axis="x", ls=":", alpha=0.5, zorder=0)
    ax.set_axisbelow(True)
    fig.subplots_adjust(bottom=0.30, top=0.88, left=0.22, right=0.96)
    fig.text(0.5, 0.05,
             "Honest note: 0 rejects because the run stayed in-bounds — the REJECT path "
             "(check_write always denies)\nis code-enforced, simply not triggered on a clean run.",
             ha="center", fontsize=9.5, color=GREY, style="italic")
    fig.savefig(HERE / "c3-thymus-access-ledger.png", dpi=DPI, facecolor="white")
    plt.close(fig)


# ----------------------------------------------------------------------------
# C4 — Real-run performance shape (jimmy-wilson-poc)
# ----------------------------------------------------------------------------
def c4_performance():
    rp = REPO / "case-activation/runs/jimmy-wilson-poc/report.json"
    agg, cnt, n = {}, {}, 0
    if rp.exists():
        tc = json.load(open(rp)).get("trace", {}).get("tool_calls", [])
        n = len(tc)
        for c in tc:
            ms = c.get("duration_ms")
            if not isinstance(ms, (int, float)):
                continue
            tool = c.get("tool", "?").replace("agent.", "").replace("mcp.", "")
            agg[tool] = agg.get(tool, 0.0) + float(ms)  # total time per distinct tool
            cnt[tool] = cnt.get(tool, 0) + 1
    rows = sorted(agg.items(), key=lambda x: -x[1])[:10][::-1]
    labels = [f"{t}  (x{cnt[t]})" if cnt[t] > 1 else t for t, _ in rows]
    vals = [ms for _, ms in rows]
    colors = [RED if ms > 100000 else (AMBER if ms > 1000 else GREEN) for ms in vals]
    fig, ax = plt.subplots(figsize=(9.4, 5.4))
    bars = ax.barh(labels, vals, color=colors, edgecolor="#1e293b", height=0.66, zorder=3)
    ax.set_xscale("log")
    ax.set_xlabel("Total time per tool (ms, log scale)")
    ax.set_title("Real run shape — one heavy timeline pass, the rest is fast")
    ax.set_xlim(right=max(vals) * 3)
    for b, ms in zip(bars, vals):
        ax.text(b.get_width() * 1.10, b.get_y() + b.get_height() / 2,
                f"{ms/1000:.1f}s" if ms >= 1000 else f"{ms:.0f}ms",
                va="center", fontweight="bold", fontsize=9.5)
    ax.grid(axis="x", ls=":", alpha=0.5, zorder=0)
    ax.set_axisbelow(True)
    ax.text(0.99, 0.03, f"jimmy-wilson-poc: {n} tool calls · 129 findings · 5 Trinity iterations",
            transform=ax.transAxes, ha="right", fontsize=9.5, color=GREY, style="italic")
    fig.tight_layout()
    fig.savefig(HERE / "c4-realrun-performance.png", dpi=DPI, facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    c1_recall()
    c2_vanko()
    c3_thymus()
    c4_performance()
    print("rendered 4 charts to", HERE)
