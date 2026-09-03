#!/usr/bin/env python3
"""O4: the correlated-fault gate, from CORRELATED-FAULT-STRESS-SWEEP-2026-09-03.json (50 seeds/cell,
40 post-onset epochs, 64 directed links). (a) R1: exact-all rate with 95% Wilson intervals for two and
three independent faults; (b) R2: healthy links falsely named at the final epoch under a fleet-wide
shift with no culprit (64 = every link); (c) R3: exact-all rate for one culprit inside a shift.
Double column; the ledger's R2/R3 failure is drawn, not hidden."""
import matplotlib.pyplot as plt
import numpy as np
from _common import *  # noqa

setup()
raw = load("CORRELATED-FAULT-STRESS-SWEEP-2026-09-03b.json")
fig, axes2 = plt.subplots(2, 2, figsize=(7.16, 4.3))
axes = axes2.ravel()
w = 0.26


def bars(ax, cells, ticklabels, field, err=None, arms=ARMS, ylabel="", title=""):
    x = np.arange(len(cells))
    for i, arm in enumerate(arms):
        y = np.array([raw[c][arm]["union_over_window" if field != "final" else "final_epoch"][key]
                      for c, key in cells_keys(cells, field)])
        kw = dict(color=COLORS[arm] if not HATCH[arm] else "white", edgecolor=COLORS[arm], hatch=HATCH[arm],
                  linewidth=0.8, label=LABELS[arm])
        if err:
            lo = np.array([raw[c][arm]["union_over_window"][err][0] for c in cells])
            hi = np.array([raw[c][arm]["union_over_window"][err][1] for c in cells])
            ax.bar(x + (i - 1) * w, y, w, yerr=[y - lo, hi - y], capsize=2, error_kw=dict(elinewidth=0.8), **kw)
        else:
            ax.bar(x + (i - 1) * w, y, w, **kw)
        for xi, v in zip(x + (i - 1) * w, y):
            if v > 0:
                ax.text(xi, v + (0.02 if field != "final" else 0.6), f"{v:.2f}" if v < 10 else f"{v:.0f}",
                        ha="center", va="bottom", fontsize=6, color="0.2")
    ax.set_xticks(x); ax.set_xticklabels(ticklabels, fontsize=7)
    ax.set_ylabel(ylabel); ax.set_title(title, fontsize=8.5, loc="left")


def cells_keys(cells, field):
    return [(c, "exact_all_rate" if field == "exact" else "mean_false_links") for c in cells]


# (a) R1 exact-all with CI
r1 = ["R1_multi2@0.005", "R1_multi3@0.005", "R1_multi2@0.001", "R1_multi3@0.001"]
bars(axes[0], r1, ["M=2\n0.5%", "M=3\n0.5%", "M=2\n$10^{-3}$", "M=3\n$10^{-3}$"], "exact", err="exact_all_ci95",
     ylabel="Exact-all rate", title="(a) two or three independent faults")
utils_mpl.set_y_axis(axes[0], bnd=[0, 1.42])
axes[0].legend(loc="upper center", ncol=3, framealpha=1.0, fontsize=6.2, columnspacing=0.8, handlelength=1.4)

# (b) R2 mean false links at final epoch (do-nothing = 0)
r2 = ["R2_shock@0.005", "R2_shock@0.001"]
bars(axes[1], r2, ["shift 0.5%", "shift 0.1%"], "final", ylabel="Healthy links named, final epoch",
     title="(b) fleet-wide shift, no culprit")
utils_mpl.set_y_axis(axes[1], bnd=[0, 74])
axes[1].axhline(64, color="0.45", linewidth=0.8, linestyle=":")
axes[1].text(1.4, 65.5, "all 64 links", fontsize=6.5, color="0.35", ha="right", va="bottom")

# (c) R3 exact-all with CI
r3 = ["R3_shock1e-3_culprit1e-2", "R3_shock5e-3_culprit5e-2"]
bars(axes[2], r3, ["shift 0.1%\nculprit 1%", "shift 0.5%\nculprit 5%"], "exact", err="exact_all_ci95",
     ylabel="Exact-all rate", title="(c) one culprit inside a shift")
utils_mpl.set_y_axis(axes[2], bnd=[0, 1.15])

# (d) R4 incast: healthy links named at the final epoch (8 = every congested downlink)
r4 = ["R4_incast@0.005", "R4_incast@0.001", "R4_incast1e-3_culprit_outside", "R4_incast1e-3_culprit_inside"]
bars(axes[3], r4, ["incast\n0.5%", "incast\n0.1%", "+culprit\noutside", "+culprit\ninside"], "final",
     ylabel="Healthy links named, final epoch", title="(d) incast on one leaf's downlinks")
utils_mpl.set_y_axis(axes[3], bnd=[0, 10.2])
axes[3].axhline(8, color="0.45", linewidth=0.8, linestyle=":")
axes[3].text(3.4, 8.9, "all 8 congested links", fontsize=6.5, color="0.35", ha="right", va="bottom")
for a in axes:
    utils_mpl.set_grid(fig, a)
fig.savefig("fig_correlated.pdf", transparent=False)
fig.savefig("fig_correlated.png", dpi=400)
print("wrote fig_correlated.pdf/.png")
