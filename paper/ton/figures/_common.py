"""Shared styling for the ToN figures: IEEE sizing via utils_mpl, one palette per paper
(Okabe-Ito, the same mapping as scaling_curve.pdf: ledger blue, SprayCheck vermilion,
FlowPulse green), one marker per arm so every figure survives grayscale printing."""
import os
import sys
from pathlib import Path
import json

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))          # vendored utils_mpl.py (MPL-2.0, T. Guillod) lives beside this file
import utils_mpl  # noqa: E402
os.chdir(HERE)                         # every script writes its figure files next to itself

ARTIFACTS = HERE.parents[2] / "docs" / "review" / "artifacts"
# Okabe-Ito, one colour / marker / hatch per arm for the whole paper; the counter pair
# carries the thesis and gets its own identity (reddish purple), distinct in grayscale.
COLORS = {"mcp": "#0072B2", "spraycheck": "#D55E00", "flowpulse": "#009E73", "counterpair": "#CC79A7"}
MARKERS = {"mcp": "o", "spraycheck": "s", "flowpulse": "^", "counterpair": "D"}
HATCH = {"mcp": "", "spraycheck": "//", "flowpulse": "..", "counterpair": "xx"}
LABELS = {"mcp": "Ledger", "spraycheck": "SprayCheck-Z", "flowpulse": r"FlowPulse-$\theta$",
          "counterpair": "CounterPair-0B"}
ARMS = ("mcp", "spraycheck", "flowpulse")   # the three arms that appear in every sweep
RATES = (0.015, 0.01, 0.005, 0.001, 0.0001)                       # localization sweep
RATES8 = (0.015, 0.01, 0.005, 1e-3, 1e-4, 5e-5, 2e-5, 1e-5)       # detection sweep (2026-09-03)


def fmt_p(p):
    return f"{p*100:g}%" if p >= 0.005 else f"$10^{{{int(round(__import__('math').log10(p)))}}}$"


def load(name):
    with open(ARTIFACTS / name) as f:
        return json.load(f)


def panel_label(ax, text):
    ax.text(-0.18, 1.04, text, transform=ax.transAxes, fontsize=9, fontweight="bold", va="bottom", ha="left")


def setup():
    utils_mpl.set_global()
    import matplotlib as mpl
    mpl.rcParams["hatch.linewidth"] = 0.5
    # 7 pt is the hard floor for print; legend 8, labels 9, ticks 8, annotations 7.5.
    mpl.rcParams["legend.fontsize"] = 8
    mpl.rcParams["axes.labelsize"] = 9
    mpl.rcParams["xtick.labelsize"] = 8
    mpl.rcParams["ytick.labelsize"] = 8


ANNOT = 7.5   # annotation font size used by every script
