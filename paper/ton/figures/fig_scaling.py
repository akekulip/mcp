#!/usr/bin/env python3
"""Fig. 1 (headline): post-onset packets to detect against loss rate, from
BASELINE-COMPARISON-SWEEP-2026-09-03.json (post-onset origin, 8 rates down to the
1e-5 floor, 50 seeds, 160 M budget). Replaces the copied 2026-09-02 figure, whose
costs included 20 M of warm-up packets. Hollow markers = action rate < 1 (median over
the seeds that detected, annotated); cross on the ceiling = no seed detected."""
import matplotlib.pyplot as plt
import numpy as np
from _common import *  # noqa

setup()
raw = load("BASELINE-COMPARISON-SWEEP-2026-09-03.json")
RATES8 = (0.015, 0.01, 0.005, 1e-3, 1e-4, 5e-5, 2e-5, 1e-5)
BUDGET = 160_000_000
fig, ax = utils_mpl.get_fig(size=(3.5, 2.6))
x = np.arange(len(RATES8))
for arm in ARMS:
    pts = [(i, raw[str(p)][arm + "_packets"], raw[str(p)][arm]["action_rate"]) for i, p in enumerate(RATES8)]
    xs = [i for i, pk, a in pts if pk["median"] is not None]
    ys = [pk["median"] for i, pk, a in pts if pk["median"] is not None]
    lo = [pk["iqr"][0] if pk["iqr"][0] is not None else pk["median"] for i, pk, a in pts if pk["median"] is not None]
    hi = [pk["iqr"][1] if pk["iqr"][1] is not None else pk["median"] for i, pk, a in pts if pk["median"] is not None]
    if xs:
        ax.fill_between(xs, lo, hi, color=COLORS[arm], alpha=0.15, linewidth=0)
        ax.plot(xs, ys, color=COLORS[arm], linewidth=1.4, label=LABELS[arm], zorder=3)
    for i, pk, a in pts:
        if pk["median"] is None:
            ax.plot([i], [BUDGET], marker="x", color=COLORS[arm], markersize=7, markeredgewidth=1.6, linestyle="none", zorder=4)
        else:
            full = a >= 0.999
            ax.plot([i], [pk["median"]], marker=MARKERS[arm], color=COLORS[arm], markersize=5.5,
                    markerfacecolor=(COLORS[arm] if full else "white"), markeredgewidth=1.3, linestyle="none", zorder=5)
            if not full:
                ax.annotate(f"{a:.2f}", (i, pk["median"]), textcoords="offset points", xytext=(6, -3), fontsize=6.5, color=COLORS[arm])
ax.axhline(BUDGET, color="0.4", linestyle=":", linewidth=1.0, zorder=1)
ax.text(len(RATES8) - 1.0, BUDGET * 1.25, "budget: 80 epochs, 160 M", fontsize=6.5, color="0.35", ha="right")
ax.axvline(len(RATES8) - 1, color="0.75", linewidth=0.8, zorder=0)
ax.text(len(RATES8) - 1.08, 2.3e6, "floor $f=10^{-5}$", fontsize=6.5, color="0.35", ha="right", rotation=90, va="bottom")
ax.set_yscale("log")
ax.set_xticks(x); ax.set_xticklabels([fmt_p(p) if p >= 0.005 else f"$10^{{{np.log10(p):.0f}}}$" if np.log10(p) == int(np.log10(p)) else f"${p*1e5:g}\\times10^{{-5}}$" for p in RATES8], rotation=30, ha="right", fontsize=7)
ax.set_xlabel(r"Link loss rate $p$ (rarer faults $\rightarrow$)")
ax.set_ylabel("Post-onset packets to detect")
utils_mpl.set_y_axis(ax, bnd=[1.2e6, 4e9], log=True)
ax.plot([], [], marker="x", color="0.3", linestyle="none", markersize=7, markeredgewidth=1.6, label="no detection in budget")
ax.legend(loc="upper left", ncol=2, framealpha=1.0, fontsize=6.3, columnspacing=0.9, handlelength=1.6)
utils_mpl.set_grid(fig, ax)
fig.savefig("scaling_curve.pdf", transparent=False)
fig.savefig("scaling_curve.png", dpi=400)
print("wrote scaling_curve.pdf/.png (post-onset, 8 rates)")
