#!/usr/bin/env python3
"""O1 companion to the scaling curve: action rate with 95% Wilson intervals against loss rate,
from BASELINE-COMPARISON-SWEEP-2026-09-02.json (50 seeds/cell, 160 M-packet budget). FP = 0.00 in
every cell, stated in the caption. Single column."""
import matplotlib.pyplot as plt
import numpy as np
from _common import *  # noqa

setup()
raw = load("BASELINE-COMPARISON-SWEEP-2026-09-03.json")
RATES = (0.015, 0.01, 0.005, 1e-3, 1e-4, 5e-5, 2e-5, 1e-5)
fig, ax = utils_mpl.get_fig(size=(3.5, 2.25))
x = np.arange(len(RATES))
for i, arm in enumerate(ARMS):
    y = np.array([raw[str(p)][arm]["action_rate"] for p in RATES])
    lo = np.array([raw[str(p)][arm]["action_rate_ci95"][0] for p in RATES])
    hi = np.array([raw[str(p)][arm]["action_rate_ci95"][1] for p in RATES])
    off = (i - 1) * 0.06
    ax.errorbar(x + off, y, yerr=[y - lo, hi - y], color=COLORS[arm], marker=MARKERS[arm],
                markersize=4.5, linewidth=1.3, capsize=2, elinewidth=0.8, label=LABELS[arm], zorder=3)
ax.set_xticks(x)
ax.set_xticklabels([fmt_p(p) if p >= 0.005 or p in (1e-3, 1e-4, 1e-5) else f"${p*1e5:g}\\times10^{{-5}}$" for p in RATES], rotation=30, ha="right", fontsize=ANNOT)
ax.set_xlabel(r"Link loss rate $p$ (rarer faults $\rightarrow$)")
ax.set_ylabel("Action rate (50 seeds)")
utils_mpl.set_y_axis(ax, bnd=[-0.03, 1.08])
ax.legend(loc="lower left", framealpha=1.0)
utils_mpl.set_grid(fig, ax)
fig.savefig("fig_action_rate.pdf", transparent=False)
fig.savefig("fig_action_rate.png", dpi=400)
print("wrote fig_action_rate.pdf/.png")
