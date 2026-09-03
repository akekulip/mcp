"""Shared styling for the ToN figures: IEEE sizing via utils_mpl, one palette per paper
(Okabe-Ito, the same mapping as scaling_curve.pdf: ledger blue, SprayCheck vermilion,
FlowPulse green), one marker per arm so every figure survives grayscale printing."""
import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
import utils_mpl  # noqa: E402

ARTIFACTS = Path(__file__).resolve().parents[3] / "docs" / "review" / "artifacts"
COLORS = {"mcp": "#0072B2", "spraycheck": "#D55E00", "flowpulse": "#009E73"}
MARKERS = {"mcp": "o", "spraycheck": "s", "flowpulse": "^"}
HATCH = {"mcp": "", "spraycheck": "//", "flowpulse": ".."}
LABELS = {"mcp": "Ledger", "spraycheck": "SprayCheck-Z", "flowpulse": r"FlowPulse-$\theta$"}
ARMS = ("mcp", "spraycheck", "flowpulse")
RATES = (0.015, 0.01, 0.005, 0.001, 0.0001)


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
    mpl.rcParams["legend.fontsize"] = 7.5
    mpl.rcParams["axes.labelsize"] = 8.5
    mpl.rcParams["xtick.labelsize"] = 8
    mpl.rcParams["ytick.labelsize"] = 8
