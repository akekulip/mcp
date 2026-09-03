"""Experiment 1 (attack A3) -- packets-to-detect vs loss-rate scaling curve.

Reads the frozen 50-seed sweep
(`docs/review/artifacts/BASELINE-COMPARISON-SWEEP-2026-09-02.json`) and renders
the paper's headline technical figure at IEEE single-column size: median
packets-to-detect (with the interquartile band) against loss rate, log-log, for
all three arms. The claim the figure makes airtight is a COST-SCALING statement,
not a capability one -- MCP's packets-to-detect is Theta(1) in loss rate (flat
~22 M across 1.5% down to 1e-4) while SprayCheck-Z's median grows ~1/p and its
action rate collapses (100%->78%->0%), FlowPulse-theta failing one order
earlier. Non-detection (action rate 0 within the 160 M-packet budget) is drawn
as an explicit "no detection" marker at the budget ceiling, NOT hidden, and the
per-point action rate is annotated so the survivorship of the conditional median
is visible on the page.

Run: $RESEARCH_PYTHON docs/review/artifacts/figures/scaling_curve.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt  # noqa: F401

sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
import utils_mpl  # noqa: E402

HERE = Path(__file__).resolve().parent
ARTIFACTS = HERE.parent
SWEEP_JSON = ARTIFACTS / "BASELINE-COMPARISON-SWEEP-2026-09-02.json"
BUDGET_PACKETS = 160_000_000  # 80 post-onset epochs * 2 M packets/epoch

# CVD-safe categorical hues (Okabe-Ito), one meaning per color across the paper.
COLORS = {"mcp": "#0072B2", "spraycheck": "#D55E00", "flowpulse": "#009E73"}
MARKERS = {"mcp": "o", "spraycheck": "s", "flowpulse": "^"}
LABELS = {"mcp": "MCP (in-fabric witness)",
          "spraycheck": "SprayCheck-Z (passive)",
          "flowpulse": r"FlowPulse-$\theta$ (passive)"}


def load_curves():
    with open(SWEEP_JSON) as f:
        raw = json.load(f)
    rates = sorted((float(k) for k in raw), reverse=True)  # 1.5% ... 1e-4
    curves = {}
    for arm in ("mcp", "spraycheck", "flowpulse"):
        pts = []
        for p in rates:
            block = raw[repr(p) if repr(p) in raw else f"{p}"]
            pk = block[f"{arm}_packets"]
            action = block[arm]["action_rate"]
            median = pk["median"]
            q1, q3 = pk["iqr"]
            pts.append({"p": p, "action": action, "median": median,
                        "q1": q1, "q3": q3})
        curves[arm] = pts
    return rates, curves


def write_curve_data(rates, curves):
    """Emit the curve numbers next to the figure so every plotted point is
    traceable to the sweep without opening the raw JSON."""
    out = ARTIFACTS / "figures" / "scaling_curve_data.csv"
    lines = ["arm,loss_rate,action_rate,median_packets,iqr_lo_packets,iqr_hi_packets,detected_within_budget"]
    for arm, pts in curves.items():
        for pt in pts:
            det = pt["median"] is not None
            lines.append(
                f"{arm},{pt['p']:.5g},{pt['action']:.2f},"
                f"{'' if pt['median'] is None else int(pt['median'])},"
                f"{'' if pt['q1'] is None else int(pt['q1'])},"
                f"{'' if pt['q3'] is None else int(pt['q3'])},"
                f"{det}")
    out.write_text("\n".join(lines) + "\n")
    return out


def _fmt_p(p: float) -> str:
    return f"{p*100:g}%"


def main():
    rates, curves = load_curves()
    data_path = write_curve_data(rates, curves)

    utils_mpl.set_global()
    fig, ax = utils_mpl.get_fig(size=(3.5, 2.5))

    # x is loss rate p on a log axis, INVERTED so p decreases left->right (the
    # harder, rarer-fault regime to the right); a rising cost curve then reads
    # as "cost explodes as faults get rarer". Inverted-log-p is visually
    # identical to a 1/p axis but keeps the natural loss-rate tick labels.
    for arm in ("mcp", "spraycheck", "flowpulse"):
        pts = curves[arm]
        xs_det, ys_det, lo_det, hi_det = [], [], [], []
        for pt in pts:
            if pt["median"] is None:
                continue
            xs_det.append(pt["p"])
            ys_det.append(pt["median"])
            lo_det.append(pt["q1"] if pt["q1"] is not None else pt["median"])
            hi_det.append(pt["q3"] if pt["q3"] is not None else pt["median"])
        c = COLORS[arm]
        if len(xs_det) >= 2:
            ax.fill_between(xs_det, lo_det, hi_det, color=c, alpha=0.15, linewidth=0)
        ax.plot(xs_det, ys_det, color=c, linewidth=1.6, marker=None,
                label=LABELS[arm], zorder=3)
        for pt in pts:
            if pt["median"] is None:
                continue
            full = pt["action"] >= 0.999
            ax.plot([pt["p"]], [pt["median"]], marker=MARKERS[arm], color=c,
                    markersize=6, markerfacecolor=(c if full else "white"),
                    markeredgecolor=c, markeredgewidth=1.3, zorder=4)
            if pt["action"] < 0.999:  # annotate reduced action rate honestly
                ax.annotate(f"{pt['action']*100:.0f}% detect",
                            (pt["p"], pt["median"]), textcoords="offset points",
                            xytext=(7, -2), fontsize=7, color=c, zorder=5,
                            ha="left", va="top")
        for pt in pts:  # non-detection: an X at the budget ceiling
            if pt["median"] is None:
                ax.plot([pt["p"]], [BUDGET_PACKETS], marker="x", color=c,
                        markersize=7, markeredgewidth=1.8, zorder=4)

    ax.axhline(BUDGET_PACKETS, color="0.4", linestyle=":", linewidth=1.0, zorder=1)

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.invert_xaxis()
    ax.set_xlabel(r"Link loss rate $p$  (rarer faults $\rightarrow$)")
    ax.set_ylabel("Packets to detect (fleet total)")

    tick_p = rates
    ax.set_xticks(tick_p)
    ax.set_xticklabels([_fmt_p(p) for p in tick_p], rotation=30, ha="right")
    ax.set_xlim(max(tick_p) * 1.7, min(tick_p) * 0.6)  # inverted
    ax.set_ylim(1.5e7, 3.0e8)
    ax.plot([], [], marker="x", color="0.3", linestyle="none", markersize=7,
            markeredgewidth=1.8, label="no detection within budget")
    ax.legend(fontsize=6.5, loc="lower right", framealpha=0.92,
              borderpad=0.4, labelspacing=0.3)
    ax.annotate("160 M-packet budget", (max(tick_p) * 1.5, BUDGET_PACKETS),
                textcoords="offset points", xytext=(2, 3), fontsize=7, color="0.35")
    utils_mpl.set_grid(fig, ax)

    for ext in ("pdf", "png"):
        out = HERE / f"scaling_curve.{ext}"
        fig.savefig(out, transparent=(ext == "pdf"), dpi=400)
        print(f"wrote {out}")
    print(f"wrote {data_path}")


if __name__ == "__main__":
    main()
