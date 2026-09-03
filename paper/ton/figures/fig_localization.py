#!/usr/bin/env python3
"""O2: localization under spraying, from LOCALIZATION-COMPARISON-SWEEP-2026-09-02.json.
(a) exact-localization rate, downlink fault; (b) exact rate, uplink fault; (c) mean size of the
named set over detections (1 = exact, 2 = the uplink/downlink pair). Double column."""
import matplotlib.pyplot as plt
import numpy as np
from _common import *  # noqa

setup()
raw = load("LOCALIZATION-COMPARISON-SWEEP-2026-09-02.json")
fig, axes = plt.subplots(1, 3, figsize=(7.16, 2.3))
x = np.arange(len(RATES))


def key(fam, p):
    return f"{fam}@{p}"


for ax, fam, lab in ((axes[0], "down", "(a) downlink fault"), (axes[1], "up", "(b) uplink fault")):
    for i, arm in enumerate(ARMS):
        cells = [raw[key(fam, p)][arm] for p in RATES]
        y = np.array([c["exact_rate"] for c in cells])
        lo = np.array([c["exact_ci95"][0] for c in cells]); hi = np.array([c["exact_ci95"][1] for c in cells])
        off = (i - 1) * 0.07
        ax.errorbar(x + off, y, yerr=[y - lo, hi - y], color=COLORS[arm], marker=MARKERS[arm], markersize=4.2,
                    linewidth=1.2, capsize=2, elinewidth=0.8, label=LABELS[arm], zorder=3)
    ax.set_xticks(x); ax.set_xticklabels([fmt_p(p) for p in RATES], rotation=25)
    ax.set_xlabel(r"Link loss rate $p$")
    ax.set_ylabel("Exact-localization rate")
    utils_mpl.set_y_axis(ax, bnd=[-0.03, 1.08])
    ax.set_title(lab, fontsize=8.5, loc="left")

ax = axes[2]
for fam, ls in (("down", "-"), ("up", "--")):
    for arm in ("spraycheck", "flowpulse"):
        cells = [raw[key(fam, p)][arm] for p in RATES]
        y = np.array([c["mean_cardinality"] if c["n_detected"] > 0 else np.nan for c in cells])
        lo = np.array([c["cardinality_ci95"][0] if c["n_detected"] > 0 else np.nan for c in cells])
        hi = np.array([c["cardinality_ci95"][1] if c["n_detected"] > 0 else np.nan for c in cells])
        ax.errorbar(x, y, yerr=[y - lo, hi - y], color=COLORS[arm], marker=MARKERS[arm], markersize=4.2,
                    linewidth=1.2, linestyle=ls, capsize=2, elinewidth=0.8,
                    label=f"{LABELS[arm]}, {'downlink' if fam == 'down' else 'uplink'}", zorder=3)
ax.axhline(1.0, color=COLORS["mcp"], linewidth=1.4, zorder=2, label="Ledger, both (size 1.00)")
ax.axhline(2.0, color="0.45", linewidth=0.8, linestyle=":", zorder=1)
ax.text(0.05, 2.06, "uplink+downlink pair", fontsize=7, color="0.35", ha="left", va="bottom")
ax.set_xticks(x); ax.set_xticklabels([fmt_p(p) for p in RATES], rotation=25)
ax.set_xlabel(r"Link loss rate $p$")
ax.set_ylabel("Mean named-set size")
utils_mpl.set_y_axis(ax, bnd=[0.8, 4.6])
ax.set_title("(c) set size over detections", fontsize=8.5, loc="left")
axes[0].legend(loc="center right", framealpha=1.0)
ax.legend(loc="lower left", bbox_to_anchor=(0.40, 0.50), framealpha=1.0, fontsize=6.3)
for a in axes:
    utils_mpl.set_grid(fig, a)
fig.savefig("fig_localization.pdf", transparent=False)
fig.savefig("fig_localization.png", dpi=400)
print("wrote fig_localization.pdf/.png")
