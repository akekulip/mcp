"""Unit tests + fidelity check for `sim/baselines/flowpulse_theta.py`.

FlowPulse's ONE stated exact constant is its 1% detection threshold
(HotNets'25 §5.3: "FlowPulse uses a detection threshold of 1%") -- that part
needs no calibration and is tested by hand-computed numbers below. The
fidelity check reproduces the QUALITATIVE shape of the paper's own Fig. 5(a)
ROC sweep (near-perfect classification at >=1.5% drop, degraded at
0.08-0.32%) and Fig. 5(b)'s radix effect (higher radix dilutes the fault's
visibility at a fixed drop rate), using the SAME "more observed packets ->
tighter distribution around the mean" noise mechanism SprayCheck's own Z-test
formula is built on -- FlowPulse's per-port counter and SprayCheck's
per-spine counter are the same kind of quantity (a passive arrival count).

The per-port packet/byte scale needed to make this qualitative shape appear
is NOT given in the paper (its ns-3 setup, 32 leaf/16 spine, is not fully
specified down to per-port packet counts) -- it is a disclosed choice made in
this test file, picked so the classifier's behaviour crosses from
near-perfect to near-useless in the same 0.08%-1.5% band the paper's own
Fig. 5(a) legend uses, not fit after the fact to any specific FPR/FNR number
in the paper.
"""
import unittest

import numpy as np

from sim.baselines.flowpulse_theta import (
    FlowPulseDetector, LearnedLoadModel, AnalyticalLoadModel, THRESHOLD_1PCT,
)


class DeviationHandComputedTest(unittest.TestCase):

    def test_threshold_is_exactly_one_percent(self):
        self.assertAlmostEqual(THRESHOLD_1PCT, 0.01)

    def test_deviation_below_threshold_not_flagged(self):
        det = FlowPulseDetector()
        # baseline 1000, observed 995 -> 0.5% deviation, below 1%.
        self.assertAlmostEqual(det.deviation(995, 1000), 0.005)
        self.assertFalse(det.flag(995, 1000))

    def test_deviation_above_threshold_flagged(self):
        det = FlowPulseDetector()
        # baseline 1000, observed 985 -> 1.5% deviation, above 1%.
        self.assertAlmostEqual(det.deviation(985, 1000), 0.015)
        self.assertTrue(det.flag(985, 1000))

    def test_deviation_exactly_at_threshold_not_flagged(self):
        # discrepancy must EXCEED the threshold (§5.3: "if the discrepancy
        # exceeds a predefined threshold"), so an exact 1% match does not
        # alarm.
        det = FlowPulseDetector()
        self.assertFalse(det.flag(990, 1000))


class AnalyticalLoadModelHandComputedTest(unittest.TestCase):

    def test_fig2_style_redistribution(self):
        # §5.2's own worked example: d bytes for a pair, f of s spines
        # failed -> each remaining spine carries d/(s-f).
        model = AnalyticalLoadModel(total_spines=8, known_failed_spines=2)
        demand = {"A->leaf0": 600.0}
        dest = {"A->leaf0": "leaf0"}
        # 600 / (8-2) = 100 per remaining spine's contribution to leaf0
        self.assertAlmostEqual(model.predicted_port_load(demand, dest, "leaf0"), 100.0)

    def test_sums_over_multiple_pairs_to_the_same_leaf(self):
        model = AnalyticalLoadModel(total_spines=4, known_failed_spines=0)
        demand = {"A->leaf0": 400.0, "B->leaf0": 800.0, "C->leaf1": 400.0}
        dest = {"A->leaf0": "leaf0", "B->leaf0": "leaf0", "C->leaf1": "leaf1"}
        # leaf0 gets contributions from A and B only: 400/4 + 800/4 = 300
        self.assertAlmostEqual(model.predicted_port_load(demand, dest, "leaf0"), 300.0)


class LearnedLoadModelTest(unittest.TestCase):

    def test_no_prediction_until_bootstrap_complete(self):
        model = LearnedLoadModel(bootstrap_iters=3)
        model.observe("p0", 100.0)
        model.observe("p0", 102.0)
        self.assertIsNone(model.predicted_port_load("p0"))
        model.observe("p0", 98.0)
        self.assertAlmostEqual(model.predicted_port_load("p0"), 100.0)

    def test_rebaseline_after_recovery(self):
        # §5.2 Fig. 3: after a fault heals, the stale (lower) baseline is
        # replaced so the detector stops alarming on the recovery itself.
        model = LearnedLoadModel(bootstrap_iters=2)
        model.observe("p0", 80.0)
        model.observe("p0", 80.0)  # baseline learned at 80 (during a fault)
        self.assertAlmostEqual(model.predicted_port_load("p0"), 80.0)
        model.rebaseline("p0", 100.0)
        self.assertAlmostEqual(model.predicted_port_load("p0"), 100.0)


class LocalizationHandComputedTest(unittest.TestCase):

    def test_all_senders_equally_affected_is_local(self):
        observed = {"L1": 90.0, "L3": 90.0}
        expected = {"L1": 100.0, "L3": 100.0}
        self.assertEqual(FlowPulseDetector.localize_by_sender(observed, expected), "local")

    def test_single_sender_affected_is_remote(self):
        # Fig. 4's own example: only the L1 contribution at this port is
        # short; L3's is at its expected level -> the L1-S1 link failed.
        observed = {"L1": 60.0, "L3": 100.0}
        expected = {"L1": 100.0, "L3": 100.0}
        self.assertEqual(FlowPulseDetector.localize_by_sender(observed, expected), "L1")


class FlowPulseFidelityTest(unittest.TestCase):
    """Reproduces the qualitative shape of Fig. 5(a) and Fig. 5(b)."""

    # Chosen so the 1% threshold sits near the perfect-classifier corner at
    # p=1.5% (matching Fig. 5(a)'s own labelled point) while the smaller
    # drop rates from the SAME legend (0.08/0.16/0.24/0.32%) stay near
    # chance -- see module + file docstrings for why this scale is a
    # disclosed choice, not a number read off the paper.
    PORT_LOAD = 200_000

    def _fpr_tpr(self, p: float, trials: int = 20_000, seed: int = 42):
        rng = np.random.default_rng(seed)
        det = FlowPulseDetector()
        healthy = rng.poisson(self.PORT_LOAD, size=trials)
        faulty = rng.poisson(self.PORT_LOAD * (1 - p), size=trials)
        fpr = float(np.mean(np.abs(healthy - self.PORT_LOAD) / self.PORT_LOAD > det.threshold))
        tpr = float(np.mean(np.abs(faulty - self.PORT_LOAD) / self.PORT_LOAD > det.threshold))
        return fpr, tpr

    def test_one_percent_threshold_is_near_perfect_at_1_5_percent_drop(self):
        # Fig. 5(a): "a 1% threshold is a perfect classifier for drop
        # rates >= 1.5%".
        fpr, tpr = self._fpr_tpr(0.015)
        self.assertLess(fpr, 0.01)
        self.assertGreater(tpr, 0.95)

    def test_classifier_degrades_at_the_legends_lower_drop_rates(self):
        # Fig. 5(a): "For lower drop rates the classifier becomes less
        # effective" -- at the SAME fixed 1% threshold, the four smaller
        # legend drop rates should be far from perfect (TPR well under the
        # 1.5% case, near the false-positive floor).
        _, tpr_15 = self._fpr_tpr(0.015)
        for p in (0.0008, 0.0016, 0.0024, 0.0032):
            fpr, tpr = self._fpr_tpr(p)
            self.assertLess(fpr, 0.01)  # threshold is fixed, FPR does not move
            self.assertLess(tpr, 0.1, f"p={p} should be far below the 1.5% TPR")
            self.assertLess(tpr, tpr_15)

    def test_radix_dilutes_detectability_at_a_fixed_drop_rate(self):
        # Fig. 5(b): "FlowPulse cannot detect the fault with drop rate 0.8%
        # for radix 32, but works well for radix 16" -- higher radix shares
        # the port among more source-destination pairs, diluting one
        # faulty pair's relative deviation (module docstring, judgment call
        # #2: qualitative reproduction only, via a disclosed radix->load
        # mapping, not the paper's own fat-tree topology).
        det = FlowPulseDetector()
        p_at_radix16, p_at_radix32 = 0.008, 0.004  # disclosed dilution mapping
        rng = np.random.default_rng(7)
        trials = 20_000
        healthy16 = rng.poisson(self.PORT_LOAD, size=trials)
        faulty16 = rng.poisson(self.PORT_LOAD * (1 - p_at_radix16), size=trials)
        healthy32 = rng.poisson(self.PORT_LOAD, size=trials)
        faulty32 = rng.poisson(self.PORT_LOAD * (1 - p_at_radix32), size=trials)
        tpr16 = float(np.mean(np.abs(faulty16 - self.PORT_LOAD) / self.PORT_LOAD > det.threshold))
        tpr32 = float(np.mean(np.abs(faulty32 - self.PORT_LOAD) / self.PORT_LOAD > det.threshold))
        fpr16 = float(np.mean(np.abs(healthy16 - self.PORT_LOAD) / self.PORT_LOAD > det.threshold))
        fpr32 = float(np.mean(np.abs(healthy32 - self.PORT_LOAD) / self.PORT_LOAD > det.threshold))
        self.assertLess(fpr16, 0.01)
        self.assertLess(fpr32, 0.01)
        self.assertGreater(tpr16, 3 * tpr32,
                           "radix 32 should be substantially harder to detect than radix 16")
        self.assertGreater(tpr16, 0.1, "radix 16 should still show meaningfully higher TPR")


if __name__ == "__main__":
    unittest.main()
