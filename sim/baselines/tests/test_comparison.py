import math
import unittest

from sim.baselines.comparison import simulate_epoch, summarize, wilson_ci
from sim.baselines.comparison import RunResult


class WilsonCITest(unittest.TestCase):
    def test_zero_trials_gives_a_degenerate_interval(self):
        self.assertEqual(wilson_ci(0, 0), (0.0, 0.0))

    def test_all_successes_interval_excludes_zero(self):
        lo, hi = wilson_ci(50, 50)
        self.assertGreater(lo, 0.9)
        self.assertAlmostEqual(hi, 1.0, places=2)

    def test_all_failures_interval_excludes_one(self):
        lo, hi = wilson_ci(0, 50)
        self.assertAlmostEqual(lo, 0.0, places=2)
        self.assertLess(hi, 0.1)

    def test_matches_a_hand_computed_point(self):
        # Wilson interval for 8/8 successes, z=1.96 (a standard textbook
        # example: n=8, x=8 -> center and half-width computed by hand).
        n, x, z = 8, 8, 1.96
        p = x / n
        denom = 1 + z * z / n
        center = (p + z * z / (2 * n)) / denom
        half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
        expected = (max(0.0, center - half), min(1.0, center + half))
        self.assertEqual(wilson_ci(x, n), expected)


class SummarizeTest(unittest.TestCase):
    def _result(self, mcp_epoch):
        return RunResult(mcp_epoch=mcp_epoch, mcp_packets=mcp_epoch * 1000 if mcp_epoch else None,
                         spraycheck_epoch=None, spraycheck_packets=None,
                         flowpulse_epoch=None, flowpulse_packets=None,
                         mcp_false_positive=False, spraycheck_false_positive=False,
                         flowpulse_false_positive=False)

    def test_action_rate_and_ci_reflect_detected_fraction(self):
        results = [self._result(10), self._result(12), self._result(None), self._result(14)]
        summary = summarize(results, "mcp_epoch")
        self.assertAlmostEqual(summary["action_rate"], 0.75)
        self.assertEqual(summary["n"], 4)
        lo, hi = summary["action_rate_ci95"]
        self.assertLess(lo, 0.75)
        self.assertGreater(hi, 0.75)

    def test_median_ignores_non_detections(self):
        results = [self._result(10), self._result(None), self._result(20)]
        summary = summarize(results, "mcp_epoch")
        self.assertAlmostEqual(summary["median"], 15)

    def test_no_detections_gives_none_median_and_zero_action_rate(self):
        results = [self._result(None), self._result(None)]
        summary = summarize(results, "mcp_epoch")
        self.assertIsNone(summary["median"])
        self.assertAlmostEqual(summary["action_rate"], 0.0)


class SimulateEpochTest(unittest.TestCase):
    def test_tx_counts_sum_to_packets_per_epoch(self):
        import numpy as np
        rng = np.random.default_rng(0)
        snapshot = simulate_epoch(k=8, faulty_spine=0, faulty_rate=0.1,
                                  healthy_rate=0.0, packets_per_epoch=10_000, rng=rng)
        self.assertEqual(sum(tx for tx, _ in snapshot.values()), 10_000)

    def test_healthy_spines_lose_nothing_at_zero_healthy_rate(self):
        import numpy as np
        rng = np.random.default_rng(0)
        snapshot = simulate_epoch(k=4, faulty_spine=0, faulty_rate=0.5,
                                  healthy_rate=0.0, packets_per_epoch=10_000, rng=rng)
        for spine, (tx, rx) in snapshot.items():
            if spine != 0:
                self.assertEqual(tx, rx)

    def test_none_faulty_spine_means_every_spine_is_healthy(self):
        import numpy as np
        rng = np.random.default_rng(0)
        snapshot = simulate_epoch(k=4, faulty_spine=None, faulty_rate=0.9,
                                  healthy_rate=0.0, packets_per_epoch=10_000, rng=rng)
        for tx, rx in snapshot.values():
            self.assertEqual(tx, rx)


if __name__ == "__main__":
    unittest.main()
