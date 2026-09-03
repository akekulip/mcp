#!/usr/bin/env python3
"""The ledger's wall tracks the floor f, from FLOOR-SWEEP-2026-09-03.json (50 seeds per cell).
Median epochs to detect against p/f for three floors; a cross at the top marks a cell in which no
seed detected within 80 epochs, a hollow marker a partial action rate (annotated)."""
import matplotlib.pyplot as plt
import numpy as np
from _common import *  # noqa

setup()
raw = load("FLOOR-SWEEP-2026-09-03.json")
FLOORS = [("1e-06", "$f=10^{-6}$", "o", "-"), ("1e-05", "$f=10^{-5}$", "s", "--"), ("0.0001", "$f=10^{-4}$", "^", ":")]
fig, ax = utils_mpl.get_fig(size=(3.5, 2.3))
CEIL = 80
for fkey, lab, mk, ls in FLOORS:
    cells = raw[fkey]
    ms = sorted(float(m) for m in cells)
    xs, ys = [], []
    for m in ms:
        c = cells[str(m) if str(m) in cells else f"{m:g}"]
        a = c["mcp"]["action_rate"]; med = c["mcp"]["median"]
        if med is None:
            ax.plot([m], [CEIL], marker="x", color=COLORS["mcp"], markersize=7, markeredgewidth=1.6, linestyle="none", zorder=4)
        else:
            ep = med - 10 + 1  # epochs since onset (onset at epoch 10)
            xs.append(m); ys.append(ep)
            ax.plot([m], [ep], marker=mk, color=COLORS["mcp"], markersize=5, markerfacecolor=(COLORS["mcp"] if a >= 0.999 else "white"),
                    markeredgewidth=1.2, linestyle="none", zorder=5)
            if a < 0.999:
                ax.annotate(f"{a:.2f}", (m, ep), textcoords="offset points", xytext=(5, 3), fontsize=6.5, color="0.3")
    ax.plot(xs, ys, color=COLORS["mcp"], linestyle=ls, linewidth=1.2, label=lab, zorder=3)
ax.axhline(CEIL, color="0.4", linestyle=":", linewidth=1.0)
ax.text(1.05, CEIL * 1.12, "budget: 80 epochs", fontsize=6.5, color="0.35", ha="left", va="bottom")
ax.set_xscale("log"); ax.set_yscale("log")
ax.set_xticks([1, 2, 5, 10, 50]); ax.set_xticklabels(["1", "2", "5", "10", "50"])
ax.set_xlabel(r"Loss rate over floor, $p/f$")
ax.set_ylabel("Epochs to detect (median)")
utils_mpl.set_x_axis(ax, bnd=[0.8, 70], log=True); utils_mpl.set_y_axis(ax, bnd=[0.7, 120], log=True)
ax.legend(loc="upper right", framealpha=1.0, fontsize=6.5)
utils_mpl.set_grid(fig, ax)
fig.savefig("fig_floor.pdf", transparent=False)
fig.savefig("fig_floor.png", dpi=400)
print("wrote fig_floor.pdf/.png")
