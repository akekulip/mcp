"""SprayCheck-Z — a faithful replay of SprayCheck's Z-test (Krebs, Amir, Landau
Feibish, Silberstein, "SprayCheck: Finding Gray Failures in Adaptive Routing
Networks", arXiv:2605.03702, May 2026), verified against the primary source's
HTML (arxiv.org/html/2605.03702v1) this session, §3.5-3.6 and §5.3, Table 1.

WHAT THE PAPER'S SWITCH SEES, AND WHAT THIS ARM IS THEREFORE GIVEN
--------------------------------------------------------------------
SprayCheck's destination leaf never sees TX, drop, or any other switch's
counters. It picks ONE outgoing flow at a time (round-robin over destination
leaves, §3.4), prioritises it, and counts only "the number of packets
observed arriving from a given spine at the leaf switch" (§3.5) for that one
flow, indexed by (destination QP, upstream spine). This module is therefore
built to consume ONLY a per-spine RX/arrival count for a bounded measurement
window of `flow_packets` (N) packets sprayed over `k` candidate spines — never
a TX count, never a drop count, never another link's counters. Feeding it
anything else would silently hand it ground truth SprayCheck's own switch
does not have.

THE EXACT TEST (§3.5, quoted from the primary source)
--------------------------------------------------------------------
"Consider a single flow of N packets from a source leaf switch to destination
leaf switch, routed through k spine switches. Packets are sprayed across all
k candidate spines, and each leaf-spine link carries, in expectation,
lambda = E[X_i] = N/k packets... Our null hypothesis is a healthy path with a
mean of lambda, while our tested hypothesis is a lower mean due to a gray
failure... we flag a failure on the path via a given spine i whenever X_i...
is below a threshold t = lambda - s*sqrt(N/k), where the parameter s
determines the sensitivity."

And on how s is set (§3.5, §5.3): "s can be chosen either analytically based
on sigma^2 and the desired detection confidence, or by empirically checking
which value results in the desired confidence on a given network (we use the
latter approach for our evaluation)." The paper never states a numeric value
of s — it calibrates s once via ROC search on its own testbed, then finds the
minimum per-spine packet count P_min that lets each target drop rate reach
0% FPR / 100% TPR (0.4% floor at 8 spines / 500k-packet flow -> Table 1: 7k
packets/spine for 1.5% loss, 20k for 1.0%, 60k for 0.5%). `calibrate_s` and
`find_p_min` below reproduce exactly that two-step procedure; see the module
docstring in `sim/baselines/tests/test_spraycheck_z.py` for how closely it
reproduces Table 1's numbers, and where it does not.

JUDGMENT CALLS DISCLOSED HERE (do not silently fill these in elsewhere)
--------------------------------------------------------------------
1. `s` is not given a numeric value in the paper — it is a per-deployment
   calibration constant. `calibrate_s` reproduces the paper's OWN calibration
   procedure (ROC search on synthetic per-spine counts) rather than guessing
   a number; the resulting `s` is reported, not assumed.
2. The paper derives sigma ~ sqrt(lambda) from an implicit i.i.d./Poisson
   model of "random" spraying (§3.5's own SNR derivation), even though its
   real deployment uses adaptive JSQ(2)-style least-loaded-port spraying
   (lower variance than i.i.d.). `calibrate_s`/`find_p_min` use the SAME i.i.d.
   Poisson model the paper's formula assumes, since that is what the equation
   itself is built on; this is expected to need MORE packets than Table 1's
   real, JSQ(2)-tuned numbers to hit the same (FPR, TPR) point. The fidelity
   check in `tests/test_spraycheck_z.py` reports this gap explicitly rather
   than silently matching Table 1 to the packet.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List

import numpy as np


@dataclass(frozen=True)
class SprayCheckConfig:
    """One deployment's calibrated parameters (§3.5)."""
    k: int              # number of candidate spines for the measured flow
    flow_packets: int   # N: nominal size of the measurement flow
    s: float            # sensitivity, calibrated (see calibrate_s)

    @property
    def lam(self) -> float:
        """lambda = E[X_i] = N/k, the expected healthy per-spine arrival count."""
        return self.flow_packets / self.k

    @property
    def threshold(self) -> float:
        """t = lambda - s*sqrt(N/k)  (§3.5, "Threshold Selection")."""
        return self.lam - self.s * math.sqrt(self.lam)


class SprayCheckDetector:
    """Replays SprayCheck's per-flow detection and cross-flow localization.

    Usage mirrors the paper's own life cycle (§3.3, §3.6): accumulate one
    flow's per-spine RX counts until `flow_packets` have arrived in total
    (the flow's "maximum expected sequence number"), then test each spine's
    count against the threshold. `detect_flow` takes RX-only per-spine deltas
    for exactly one measured flow — it is the caller's job (the replay
    harness) never to hand this class a TX or drop column.
    """

    def __init__(self, config: SprayCheckConfig):
        self.config = config

    def detect_flow(self, per_spine_arrivals: Dict[int, int]) -> List[int]:
        """per_spine_arrivals: {spine_id: RX packet count for THIS flow, over
        its full measurement window}. Returns the spine ids flagged failed
        (X_i below threshold, §3.6)."""
        t = self.config.threshold
        return [spine for spine, x in per_spine_arrivals.items() if x < t]

    @staticmethod
    def localize(reports: Dict[str, List[str]]) -> List[str]:
        """Cross-leaf localization by report intersection (§3.6, Fig. 5).

        `reports`: {leaf_id: [failed "leaf-spine" path names reported by that
        leaf's flow measurement]}. A path is confirmed failed only if it
        appears in reports from >=2 different destination leaves that each
        implicate a DIFFERENT source leaf sharing the same spine -- the
        paper's own example: flows from L1 and L3 both report a failure via
        S2 to L2, so L2S2 (not L1S2 or L3S2) is the actual failed link.

        This module's fidelity check (below) validates DETECTION, which is
        what SprayCheck's published operating points (Table 1) are stated
        in terms of. Localization is implemented from the paper's stated
        rule but is not separately fidelity-checked against a published
        localization-accuracy number (the paper reports none) -- disclosed,
        not silently assumed to be correct to the same standard.
        """
        from collections import Counter
        votes: Counter = Counter()
        for leaf, failed_paths in reports.items():
            for path in failed_paths:
                votes[path] += 1
        return [path for path, n in votes.items() if n >= 2]


# ---------------------------------------------------------------------------
# Calibration: reproduces the paper's own two-step procedure (§5.3).
# ---------------------------------------------------------------------------

def _fpr_tpr(lam: float, p: float, s: float, trials: int, rng: np.random.Generator):
    """Empirical (FPR, TPR) of the Z-test at threshold t=lam-s*sqrt(lam),
    under the paper's own i.i.d. Poisson(lambda) model for a healthy spine
    and Poisson(lambda*(1-p)) for a spine carrying a p-fraction gray loss."""
    t = lam - s * math.sqrt(lam)
    healthy = rng.poisson(lam, size=trials)
    faulty = rng.poisson(lam * (1.0 - p), size=trials)
    fpr = float(np.mean(healthy < t))
    tpr = float(np.mean(faulty < t))
    return fpr, tpr


def calibrate_s(lam: float, floor_p: float, trials: int = 20000, seed: int = 0,
                 s_grid=None) -> float:
    """§5.3 "Calibration on the testbed": find the largest s (tightest,
    least false-positive-prone threshold) that still achieves near-perfect
    detection (TPR>=0.999, FPR<=0.001) at the paper's own calibration floor
    (lam=500_000/8=62_500, floor_p=0.004 reproduces "perfect accuracy for
    drop rates >=0.4% on a single link in the 8-spine topology with 500K
    packets per spine", §5.3). Returns the calibrated s; raises if no grid
    point reaches that target, so a caller never silently gets an
    uncalibrated arm.
    """
    rng = np.random.default_rng(seed)
    if s_grid is None:
        s_grid = np.linspace(0.05, 6.0, 400)
    best = None
    for s in s_grid:
        fpr, tpr = _fpr_tpr(lam, floor_p, float(s), trials, rng)
        if fpr <= 0.001 and tpr >= 0.999:
            if best is None or s > best:
                best = float(s)
    if best is None:
        raise ValueError(
            f"no s in the swept grid reaches (FPR<=0.001, TPR>=0.999) at "
            f"lam={lam}, p={floor_p} over {trials} trials; SprayCheck's "
            f"own perfect-detection claim is not reproducible at this "
            f"(lam, p) under an i.i.d. Poisson noise model -- widen the grid "
            f"or raise lam before trusting this arm at this operating point."
        )
    return best


def find_p_min(k: int, p: float, s: float, target_fpr: float = 0.001,
                target_tpr: float = 0.999, trials: int = 20000, seed: int = 1,
                lam_grid=None) -> int:
    """§5.3 "Calibration on the testbed" / Table 1: given a calibrated `s`,
    find the smallest per-spine packet budget P_min = N/k such that a gray
    fault of rate `p` is detected with (FPR<=target_fpr, TPR>=target_tpr).
    Returns P_min in packets-per-spine, directly comparable to Table 1's
    "kPackets/Spine" column. Returns None if no grid point qualifies within
    the search range (undetectable at this s/trial count/range)."""
    rng = np.random.default_rng(seed)
    if lam_grid is None:
        lam_grid = np.unique(np.round(np.geomspace(50, 2_000_000, 400)).astype(int))
    for lam in lam_grid:
        fpr, tpr = _fpr_tpr(float(lam), p, s, trials, rng)
        if fpr <= target_fpr and tpr >= target_tpr:
            return int(lam)
    return None
