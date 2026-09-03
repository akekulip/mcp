#!/usr/bin/env python3
"""Figure 2: the receiver ledger on a sprayed leaf-spine fabric (IEEE single column).
Labels come from LEDGER-WIRE-REDUCTION-2026-09-02.md and SILICON-DETECTION-LOCALIZATION-FIDELITY-2026-09-03.md
(register names reg_wit_seq / reg_wit_observed; 2-byte witness seq; link reconstructed from ingress port + spray).
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "Times", "Nimbus Roman", "DejaVu Serif"],
                     "font.size": 8, "pdf.fonttype": 42, "ps.fonttype": 42, "svg.fonttype": "none"})
W, H = 3.5, 2.6
fig = plt.figure(figsize=(W, H)); ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, 100); ax.set_ylim(0, 67); ax.axis("off")
ink, grey, light = "#111111", "#666666", "#e8e8e8"

def box(x, y, w, h, text, fc="white", lw=0.8, fs=7.5, bold=False, ec=ink):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=1.2", fc=fc, ec=ec, lw=lw))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=ink, fontweight="bold" if bold else "normal", linespacing=1.15)

def arrow(x0, y0, x1, y1, lw=0.9, color=ink, style="-|>", ls="-"):
    ax.add_patch(FancyArrowPatch((x0, y0), (x1, y1), arrowstyle=style, mutation_scale=7, lw=lw, color=color, linestyle=ls, shrinkA=0, shrinkB=0))

# sender leaf
box(2, 22, 20, 22, "Leaf $L_a$\n(sender)", bold=True)
box(1, 4, 25, 15, "egress stamp:\n2-byte witness,\nper-directed-link seq", fc=light, fs=7)
arrow(12, 19, 12, 22, lw=0.7, color=grey)
# spines
spine_x = [36, 48, 60]
for i, sx in enumerate(spine_x):
    box(sx - 5, 36, 10, 9, f"$S_{i+1}$" if i < 2 else "$S_k$", fs=7.5)
ax.text(54, 40.5, "…", ha="center", va="center", fontsize=9)
ax.text(48, 48.5, "per-packet spray across $k$ spines", ha="center", va="center", fontsize=7, color=grey)
# uplinks / downlinks
for sx in spine_x:
    arrow(22, 33, sx - 5, 40.5, lw=0.7)
    arrow(sx + 5, 40.5, 76, 33, lw=0.7)
ax.text(24.5, 27.5, "uplinks", fontsize=7, color=grey); ax.text(67, 27.5, "downlinks", fontsize=7, color=grey)
# receiver leaf + ledger
box(76, 22, 22, 22, "Leaf $L_b$\n(receiver)", bold=True)
box(44, 1, 54, 18, "ingress: link $\\leftarrow$ port + spray field\n"
                   "per link: reg_wit_seq (16 b),\nreg_wit_observed (32 b)\n"
                   "loss = $\\Delta$seq $-$ $\\Delta$observed", fc=light, fs=7)
arrow(87, 22, 87, 19, lw=0.7, color=grey)
# controller
box(22, 52, 56, 14, "controller, once per epoch:\nread ledger $\\rightarrow$ loss per directed link\n$\\rightarrow$ ratio to fleet floor $\\rightarrow$ e-BH\n$\\rightarrow$ detection + localization", fs=7)
arrow(79, 19, 79, 52, lw=0.7, color=grey, ls=(0, (2, 2)))
ax.text(80.5, 47, "epoch read", fontsize=7, color=grey, rotation=90, va="center")
for ext in ("pdf", "png", "svg"):
    fig.savefig(f"fig_system.{ext}", dpi=600 if ext == "png" else None, bbox_inches=None)
print("wrote fig_system.pdf/.png/.svg at %.2f x %.2f in" % (W, H))
