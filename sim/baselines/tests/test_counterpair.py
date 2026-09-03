"""CounterPair-0B arm, the post-onset packets origin, and the R4 generator."""
import unittest

import numpy as np

from sim.baselines.comparison import (
    SprayCheckDetectorCalibration, counterpair_tx, run_one_trial,
)
from sim.baselines.correlated import simulate_epoch_correlated
from sim.baselines.localization import (
    CounterPairLocalizer, MCPLocalizer, mcp_link_counters, simulate_epoch,
)


class PostOnsetOrigin(unittest.TestCase):
    def test_packets_to_detect_counts_from_onset_not_epoch_zero(self):
        s = SprayCheckDetectorCalibration.get(2_500_000)
        r = run_one_trial(8, 1e-2, 1e-5, 2_000_000, 10, 20, 0, s)
        # the ledger detects on the first post-onset epoch (epoch index 10)
        self.assertEqual(r.mcp_epoch, 10)
        # and the packet cost is that one epoch, not 11 epochs
        self.assertEqual(r.mcp_packets, 2_000_000)
        post = (r.mcp_epoch - 10 + 1) * 2_000_000
        self.assertEqual(r.mcp_packets, post)


class CounterPairSkewModel(unittest.TestCase):
    def test_zero_skew_is_the_witness(self):
        rng = np.random.default_rng(1)
        tx_obs, off = counterpair_tx(1000, 990, 1000.0, 0.0, 0.0, rng)
        self.assertEqual((tx_obs, off), (1000, 0.0))

    def test_positive_skew_perturbs_tx_and_never_below_rx(self):
        rng = np.random.default_rng(2)
        seen_different = False
        prev = 0.0
        for _ in range(200):
            tx_obs, prev = counterpair_tx(1000, 990, 1000.0, 0.5, prev, rng)
            self.assertGreaterEqual(tx_obs, 990)
            if tx_obs != 1000:
                seen_different = True
        self.assertTrue(seen_different)

    def test_skew_noise_is_zero_mean_and_scales_with_rate(self):
        rng = np.random.default_rng(3)
        prev = 0.0
        devs = []
        for _ in range(5000):
            tx_obs, prev = counterpair_tx(10_000_000, 0, 10_000_000.0, 1e-2, prev, rng)
            devs.append(tx_obs - 10_000_000)
        devs = np.array(devs, dtype=float)
        # std of rate*(o_e - o_{e-1}) with o = U-U' on [0, skew): rate*skew/sqrt(6)*... ~
        self.assertLess(abs(devs.mean()), 0.05 * devs.std())
        self.assertGreater(devs.std(), 10_000_000 * 1e-2 * 0.3)

    def test_counterpair_localizer_at_zero_skew_matches_the_ledger(self):
        rng = np.random.default_rng(4)
        mcp = MCPLocalizer()
        cp = CounterPairLocalizer(0.0, seed=4)
        for epoch in range(6):
            draw = simulate_epoch(4, 8, None, 1e-2, 1e-5, 200_000, rng)
            c = mcp_link_counters(draw, 4, 8)
            self.assertEqual(mcp.tick(epoch, c), cp.tick(epoch, c))
        for epoch in range(6, 9):
            draw = simulate_epoch(4, 8, ("down", 0, 0), 1e-2, 1e-5, 200_000, rng)
            c = mcp_link_counters(draw, 4, 8)
            self.assertEqual(mcp.tick(epoch, c), cp.tick(epoch, c))


class R4Generator(unittest.TestCase):
    def test_elevated_subset_loses_at_elevated_rate_and_rest_at_base(self):
        rng = np.random.default_rng(5)
        incast = frozenset(("down", i, 0) for i in range(8))
        draw = simulate_epoch_correlated(4, 8, frozenset(), 0.0, 0.0, 200_000, rng,
                                         elevated_links=incast, elevated_rate=0.05)
        c = mcp_link_counters(draw, 4, 8)
        for link, (tx, rx) in c.items():
            loss = (tx - rx) / tx
            if link in incast:
                self.assertAlmostEqual(loss, 0.05, delta=0.01)
            else:
                self.assertEqual(loss, 0.0)

    def test_fault_inside_elevated_subset_takes_the_faulty_rate(self):
        rng = np.random.default_rng(6)
        incast = frozenset(("down", i, 0) for i in range(8))
        draw = simulate_epoch_correlated(4, 8, frozenset({("down", 0, 0)}), 0.2, 0.0,
                                         200_000, rng, elevated_links=incast,
                                         elevated_rate=0.05)
        c = mcp_link_counters(draw, 4, 8)
        tx, rx = c[("down", 0, 0)]
        self.assertAlmostEqual((tx - rx) / tx, 0.2, delta=0.02)


if __name__ == "__main__":
    unittest.main()
