"""Unit tests + fidelity check for `sim/baselines/spraycheck_z.py`.

The fidelity check (`SprayCheckFidelityTest`) is the one required by the
task: does this replay arm reproduce SprayCheck's own published detection
point (arXiv:2605.03702, Table 1, §5.3)? The honest answer, established here
with numbers, is: the exact ALGORITHM and its 1/p^2 SCALING LAW reproduce
almost exactly, but the ABSOLUTE packet counts needed are ~20-27x higher than
Table 1's, because Table 1's numbers come from SprayCheck's real deployment
(adaptive JSQ(2) least-loaded-port spraying, lower per-spine count variance)
while this replay uses the i.i.d. Poisson noise model the paper's OWN
Z-test formula is analytically derived from (§3.5's sigma~sqrt(lambda)).
See `spraycheck_z.py`'s module docstring, judgment call #2, for the full
argument. This gap is reported, not hidden, and does not block using the arm
as a comparison baseline: both the qualitative claim (order-of-magnitude
thousands-to-low-millions of packets needed at 0.5-1.5% loss) and the
decisive claim for this project (SprayCheck-Z cannot detect at MCP's target
1e-3 to 1e-4 regime, at any practical packet budget) hold either way.
"""
import math
import unittest

import numpy as np

from sim.baselines.spraycheck_z import (
    SprayCheckConfig, SprayCheckDetector, calibrate_s, find_p_min,
)


class ZTestHandComputedTest(unittest.TestCase):
    """The core statistic, on numbers small enough to check by hand."""

    def test_lambda_and_threshold(self):
        # N=1000, k=10 -> lambda=100; s=2 -> t = 100 - 2*sqrt(100) = 80.
        cfg = SprayCheckConfig(k=10, flow_packets=1000, s=2.0)
        self.assertAlmostEqual(cfg.lam, 100.0)
        self.assertAlmostEqual(cfg.threshold, 80.0)

    def test_flags_spine_below_threshold_only(self):
        cfg = SprayCheckConfig(k=4, flow_packets=400, s=1.0)  # lam=100, t=90
        det = SprayCheckDetector(cfg)
        # spine 2 got only 85 (< 90): flagged. spine 3 got exactly 90: NOT
        # flagged (paper's rule is strictly "below", §3.6).
        flagged = det.detect_flow({0: 100, 1: 95, 2: 85, 3: 90})
        self.assertEqual(flagged, [2])

    def test_never_needs_tx_or_drop_columns(self):
        # The detector's API only accepts a spine->arrivals dict -- there is
        # no way to hand it a TX or drop count even by mistake, since
        # detect_flow takes exactly the RX-only mapping SprayCheck's own
        # destination leaf has (module docstring, "WHAT THE PAPER'S SWITCH
        # SEES"). This test documents that constraint rather than testing
        # behaviour.
        import inspect
        sig = inspect.signature(SprayCheckDetector.detect_flow)
        self.assertEqual(list(sig.parameters)[1:], ["per_spine_arrivals"])

    def test_localize_requires_two_leaf_reports_sharing_a_spine(self):
        # Paper's own Fig. 5 example: L1's flow reports {L1S2, L2S2} failed,
        # L3's flow reports {L3S2, L2S2} failed -> L2S2 is the actual fault.
        reports = {"L1": ["L1S2", "L2S2"], "L3": ["L3S2", "L2S2"]}
        self.assertEqual(SprayCheckDetector.localize(reports), ["L2S2"])

    def test_localize_does_not_confirm_a_single_report(self):
        reports = {"L1": ["L1S2"]}
        self.assertEqual(SprayCheckDetector.localize(reports), [])


class SprayCheckFidelityTest(unittest.TestCase):
    """Reproduces §5.3's own two-step calibration procedure and checks the
    result against Table 1, with the gap explained above disclosed inline.
    """

    def test_calibration_floor_is_not_reachable_at_the_papers_own_scale(self):
        # Paper's calibration point: 8 spines, 500k-packet flow -> lambda =
        # 62_500, target drop rate 0.4% ("SprayCheck achieves perfect
        # accuracy for drop rates >=0.4% on a single link in the 8-spine
        # topology with 500K packets per spine", §5.3). Under the i.i.d.
        # Poisson model the Z-test's own SNR formula assumes, SNR =
        # p*sqrt(lambda) = 0.004*sqrt(62_500) = 1.0 -- nowhere near the ~6.2
        # combined tail separation a (FPR<=0.1%, TPR>=99.9%) corner needs.
        # No value of s reaches it. This is the central, disclosed fidelity
        # gap, confirmed as a hard limit rather than a search-grid miss.
        with self.assertRaises(ValueError):
            calibrate_s(500_000 / 8, floor_p=0.004, trials=20_000, seed=0)

    def test_calibration_succeeds_at_a_scaled_up_floor_and_reproduces_scaling_law(self):
        # Calibrate at a lambda where the i.i.d. model CAN reach the
        # paper's stated (0% FPR, 100% TPR) corner at its own 0.4% floor,
        # then use that single calibrated s to find P_min at 1.5%, 1.0%,
        # 0.5% -- exactly Table 1's three operating points.
        s = calibrate_s(2_500_000, floor_p=0.004, trials=100_000, seed=0)
        self.assertGreater(s, 0.0)

        pmin_15 = find_p_min(k=8, p=0.015, s=s, trials=100_000, seed=1)
        pmin_10 = find_p_min(k=8, p=0.010, s=s, trials=100_000, seed=1)
        pmin_05 = find_p_min(k=8, p=0.005, s=s, trials=100_000, seed=1)
        self.assertIsNotNone(pmin_15)
        self.assertIsNotNone(pmin_10)
        self.assertIsNotNone(pmin_05)

        # (1) the SCALING LAW: SprayCheck's own SNR formula (p*sqrt(lambda))
        # predicts P_min should scale as ~1/p^2 for a fixed (FPR, TPR)
        # target. Table 1 itself: 20000/7000=2.86 (vs (1.5/1)^2=2.25),
        # 60000/20000=3.0 (vs (1/0.5)^2=4.0) -- not exact either, because
        # real testbed noise is not exactly i.i.d. Our own ratios should
        # land near the analytical 1/p^2 prediction, since that IS the
        # model we simulate exactly.
        ratio_1510 = pmin_10 / pmin_15
        ratio_1005 = pmin_05 / pmin_10
        self.assertAlmostEqual(ratio_1510, (1.5 / 1.0) ** 2, delta=0.5)
        self.assertAlmostEqual(ratio_1005, (1.0 / 0.5) ** 2, delta=0.5)

        # (2) the ABSOLUTE GAP: our P_min values are higher than Table 1's
        # (7000, 20000, 60000) by a STABLE factor attributable to the
        # disclosed i.i.d.-vs-JSQ(2) noise-model difference, not a random
        # or wildly varying one. If implemented correctly the three ratios
        # should sit within roughly one order of magnitude of each other.
        paper = {0.015: 7000, 0.010: 20000, 0.005: 60000}
        ratios = [pmin_15 / paper[0.015], pmin_10 / paper[0.010], pmin_05 / paper[0.005]]
        for r in ratios:
            self.assertGreater(r, 1.0, "expected our i.i.d. model to need MORE packets, not fewer")
            self.assertLess(r, 100.0, "gap is far larger than the ~20-30x this check established")
        self.assertLess(max(ratios) / min(ratios), 3.0,
                        "the three ratios should be close to each other (a stable factor), "
                        "not fanning out -- if they diverge sharply something other than the "
                        "known i.i.d.-vs-JSQ(2) gap is at play")

    def test_undetectable_at_mcps_target_regime(self):
        # The decisive comparison for this project: at p in {1e-3, 1e-4}
        # (PREREG's target, 40-150x below any published detection floor per
        # docs/review/LITERATURE.md), SprayCheck-Z should NOT reach
        # (FPR<=0.001, TPR>=0.999) at any packet budget up to 2e6/spine --
        # i.e. it is not just "worse", it is off the chart the paper itself
        # operates on.
        s = calibrate_s(2_500_000, floor_p=0.004, trials=100_000, seed=0)
        for p in (1e-3, 1e-4):
            pmin = find_p_min(k=8, p=p, s=s, trials=100_000, seed=1)
            self.assertIsNone(
                pmin,
                f"SprayCheck-Z unexpectedly detects p={p} within the search range; "
                "re-examine whether this arm is still a fair (i.e. not accidentally "
                "privileged) comparison baseline before using this result."
            )


if __name__ == "__main__":
    unittest.main()
