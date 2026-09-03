#!/usr/bin/env python3
"""O3: the ledger on Tofino silicon. Every value is transcribed from
SILICON-DETECTION-LOCALIZATION-FIDELITY-2026-09-03.md (Result 1, Result 2, Cells 1-2); see NUMBERS.md.
(a) recovered loss against injected loss, exact injector (ground truth = armed D) and stochastic
injector (ground truth = the injector's own drop counter); (b) per-sublink attribution for the
uplink cell and the downlink cell. Double column."""
import matplotlib.pyplot as plt
import numpy as np
from _common import *  # noqa

setup()
# (a) exact injector: (N, D, recovered)
exact = [(20000, 0, 0), (22050, 0, 0), (5000, 50, 50), (5000, 50, 50), (30000, 30, 30), (30000, 30, 30),
         (40000, 20, 20), (60000, 6, 6), (60000, 6, 6)]
# stochastic injector: (label, injector drop counter, recovered)
bern = [(r"$10^{-4}$ uplink", 7, 7), (r"$10^{-3}$ uplink", 67, 66), (r"$10^{-3}$ downlink", 13, 13)]
# (b) attribution: sublink labels as (vlink, ctx); uplink cell injected 50 on sublink 2;
# downlink cell injected Bernoulli on sublink 162, counter 13.
subs = ["2", "6", "10", "14", "162", "166", "170", "174"]
up_cell = [50, 0, 0, 0, 0, 0, 0, 0]
down_cell = [0, 0, 0, 0, 13, 0, 0, 0]

fig, axes = plt.subplots(1, 2, figsize=(7.16, 2.35), gridspec_kw={"width_ratios": [1, 1.25]})
ax = axes[0]
xs = np.array([d for _, d, _ in exact if d > 0]); ys = np.array([r for _, d, r in exact if d > 0])
ax.plot([1, 100], [1, 100], color="0.55", linewidth=0.8, linestyle=":", zorder=1, label="recovered = injected")
ax.plot(xs, ys, linestyle="none", marker="o", color=COLORS["mcp"], markersize=5.5, zorder=3, label="exact injector (armed $D$)")
bx = np.array([d for _, d, _ in bern]); by = np.array([r for _, _, r in bern])
ax.plot(bx, by, linestyle="none", marker="s", markerfacecolor="white", markeredgecolor=COLORS["mcp"],
        markeredgewidth=1.3, markersize=5.5, zorder=4, label="stochastic injector (drop counter)")
for (lab, d, r), dx, dy in zip(bern, (9, -8, -8), (-3, 4, 4)):
    ax.annotate(lab, (d, r), textcoords="offset points", xytext=(dx, dy), fontsize=6.5, color="0.25",
                ha="left" if dx > 0 else "right")
ax.annotate("exact: 6 of 60 000 at $p=10^{-4}$", (6, 6), textcoords="offset points", xytext=(4, -13), fontsize=6.5, color="0.25")
ax.set_xscale("log"); ax.set_yscale("log")
utils_mpl.set_x_axis(ax, bnd=[3, 120], log=True); utils_mpl.set_y_axis(ax, bnd=[3, 120], log=True)
ax.set_xlabel("Injected loss (packets)"); ax.set_ylabel("Recovered loss (packets)")
ax.set_title("(a) recovery, one sublink", fontsize=8.5, loc="left")
ax.legend(loc="upper left", framealpha=1.0, fontsize=6.5)

ax = axes[1]
x = np.arange(len(subs)); w = 0.38
ax.bar(x - w / 2, up_cell, w, color=COLORS["mcp"], edgecolor="black", linewidth=0.5, label="uplink cell: 50 armed on sublink 2")
ax.bar(x + w / 2, down_cell, w, color="white", edgecolor=COLORS["mcp"], hatch="////", linewidth=0.8,
       label="downlink cell: 13 counted on sublink 162")
for xi, v in zip(x - w / 2, up_cell):
    ax.text(xi, v + 1.2, str(v), ha="center", va="bottom", fontsize=6.5)
for xi, v in zip(x + w / 2, down_cell):
    ax.text(xi, v + 1.2, str(v), ha="center", va="bottom", fontsize=6.5)
ax.set_xticks(x); ax.set_xticklabels(subs)
ax.set_xlabel("Sublink (uplink sublinks 2--14, downlink sublinks 162--174)")
ax.set_ylabel("Recovered loss (packets)")
utils_mpl.set_y_axis(ax, bnd=[0, 60])
ax.set_title("(b) attribution across eight active sublinks", fontsize=8.5, loc="left")
ax.legend(loc="upper right", framealpha=1.0, fontsize=6.5)
for a in axes:
    utils_mpl.set_grid(fig, a)
fig.savefig("fig_silicon.pdf", transparent=False)
fig.savefig("fig_silicon.png", dpi=400)
print("wrote fig_silicon.pdf/.png")
