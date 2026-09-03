#!/usr/bin/env python3
"""CounterPair-0B against controller read skew, from BASELINE-COMPARISON-SWEEP-2026-09-03.json.
(a) false-positive rate (fraction of seeds that flagged a healthy spine) against skew sigma as a
fraction of the epoch, for three loss rates; (b) action rate. Vertical line: the best-case skew
measured on the Tofino (2.6 ms pairwise read against a 100 ms epoch, sigma = 0.026)."""
import matplotlib.pyplot as plt
import numpy as np
from _common import *  # noqa

setup()
raw = load("BASELINE-COMPARISON-SWEEP-2026-09-03.json")
SKEWS = [0.0, 1e-4, 1e-3, 1e-2, 2.6e-2, 1e-1]
PS = [(0.01, "o", "-"), (0.001, "s", "--"), (0.0001, "^", ":")]
fig, axes = plt.subplots(1, 2, figsize=(7.16, 2.2))
xs = np.array([1e-5] + SKEWS[1:])  # plot sigma=0 at 1e-5 on the log axis
for ax, key, ylabel, title in ((axes[0], "false_positive_rate", "False-positive rate", "(a) healthy spines flagged"),
                               (axes[1], "action_rate", "Action rate", "(b) faulty spine flagged")):
    for p, mk, ls in PS:
        ys = [raw[str(p)]["counterpair"][str(s)]["epoch"][key] for s in SKEWS]
        ax.plot(xs, ys, marker=mk, linestyle=ls, color=COLORS["mcp"], markersize=4.5, linewidth=1.2,
                label=f"$p$ = {fmt_p(p)}", zorder=3)
    ax.axvline(2.6e-2, color="0.45", linewidth=0.9, linestyle="-.")
    ax.text(2.6e-2 * 1.15, 0.06, "measured\n2.6 ms", fontsize=6.3, color="0.35", ha="left", va="bottom")
    ax.set_xscale("log")
    ax.set_xticks([1e-5, 1e-4, 1e-3, 1e-2, 1e-1])
    ax.set_xticklabels(["0", "$10^{-4}$", "$10^{-3}$", "$10^{-2}$", "$10^{-1}$"])
    ax.set_xlabel(r"Read skew $\sigma$ (fraction of the epoch)")
    ax.set_ylabel(ylabel); ax.set_title(title, fontsize=8.5, loc="left")
    utils_mpl.set_y_axis(ax, bnd=[-0.03, 1.08])
axes[0].legend(loc="center left", bbox_to_anchor=(0.0, 0.55), framealpha=1.0, fontsize=6.5)
for a in axes:
    utils_mpl.set_grid(fig, a)
fig.savefig("fig_counterpair.pdf", transparent=False)
fig.savefig("fig_counterpair.png", dpi=400)
print("wrote fig_counterpair.pdf/.png")
