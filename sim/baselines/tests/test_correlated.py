"""Unit + sanity tests for `sim/baselines/correlated.py` (attack A4 harness).

Pins the load-bearing NEW units: the multi-fault / common-mode generator's
injected-quantity-in-the-DATA (cross-check #2), the multi-fault scorer's four
cases including the empty-true-set (common-mode) case, the fabric-wide FlowPulse
wrapper, and the oracle/do-nothing anchors (cross-check #1/#4).
"""
import unittest

import numpy as np

from sim.baselines.correlated import (
    FleetFlowPulseLocalizer, score_multi, simulate_epoch_correlated,
)
from sim.baselines.localization import mcp_link_counters


class GeneratorTest(unittest.TestCase):
    def test_multi_independent_faults_lose_at_faulty_rate_in_the_data(self):
        # cross-check #2: read the realized loss OUT OF the counters, not flags.
        rng = np.random.default_rng(0)
        faulty = frozenset({('down', 0, 0), ('up', 1, 3)})
        f_tx = f_lost = b_tx = b_lost = 0
        for _ in range(5):
            d = simulate_epoch_correlated(4, 8, faulty, 0.05, 1e-5, 2_000_000, rng)
            for link, (tx, rx) in mcp_link_counters(d, 4, 8).items():
                if link in faulty:
                    f_tx += tx; f_lost += tx - rx
                else:
                    b_tx += tx; b_lost += tx - rx
        faulty_loss = f_lost / f_tx
        background_loss = b_lost / b_tx
        self.assertGreater(faulty_loss, 0.03)        # ~5% (downlink compounds a bit)
        self.assertLess(background_loss, 1e-3)        # ~1e-5 background
        self.assertGreater(faulty_loss, 30 * background_loss)

    def test_common_mode_shock_elevates_every_link_with_no_culprit(self):
        rng = np.random.default_rng(1)
        d = simulate_epoch_correlated(4, 8, frozenset(), 0.0, 5e-3, 2_000_000, rng)
        rates = []
        for _, (tx, rx) in mcp_link_counters(d, 4, 8).items():
            rates.append((tx - rx) / tx)
        # every link sits near the shock level; none is an outlier culprit
        self.assertGreater(np.mean(rates), 2e-3)
        self.assertLess(max(rates), 3 * np.mean(rates))

    def test_shock_plus_culprit_makes_one_link_stand_out(self):
        rng = np.random.default_rng(2)
        culprit = ('down', 0, 0)
        c_tx = c_lost = o_tx = o_lost = 0
        for _ in range(5):
            d = simulate_epoch_correlated(4, 8, frozenset({culprit}), 5e-2, 5e-3,
                                          2_000_000, rng)
            for link, (tx, rx) in mcp_link_counters(d, 4, 8).items():
                if link == culprit:
                    c_tx += tx; c_lost += tx - rx
                else:
                    o_tx += tx; o_lost += tx - rx
        self.assertGreater(c_lost / c_tx, 0.04)       # culprit ~5%
        self.assertLess(o_lost / o_tx, 1e-2)          # background ~0.5%
        self.assertGreater(c_lost / c_tx, 5 * (o_lost / o_tx))


class ScoreMultiTest(unittest.TestCase):
    def test_all_true_hit_nothing_false_is_exact_all(self):
        true = frozenset({('down', 0, 0), ('up', 1, 3)})
        s = score_multi(true, true)
        self.assertTrue(s.detected)
        self.assertEqual(s.n_true_hit, 2)
        self.assertEqual(s.n_false, 0)
        self.assertEqual(s.recall, 1.0)
        self.assertTrue(s.exact_all)
        self.assertFalse(s.any_false)

    def test_partial_recall_with_a_false_link(self):
        true = frozenset({('down', 0, 0), ('up', 1, 3)})
        got = frozenset({('down', 0, 0), ('up', 2, 5)})  # 1 hit, 1 false, 1 miss
        s = score_multi(got, true)
        self.assertEqual(s.n_true_hit, 1)
        self.assertEqual(s.n_false, 1)
        self.assertEqual(s.recall, 0.5)
        self.assertFalse(s.exact_all)
        self.assertTrue(s.any_false)

    def test_common_mode_empty_true_set_any_named_link_is_false(self):
        s = score_multi(frozenset({('down', 0, 0)}), frozenset())
        self.assertEqual(s.n_true, 0)
        self.assertIsNone(s.recall)          # recall undefined with no true fault
        self.assertEqual(s.n_false, 1)
        self.assertTrue(s.any_false)
        self.assertFalse(s.exact_all)

    def test_do_nothing_anchor_never_false_never_detects(self):
        true = frozenset({('down', 0, 0)})
        s = score_multi(frozenset(), true)
        self.assertFalse(s.detected)
        self.assertEqual(s.recall, 0.0)
        self.assertFalse(s.any_false)

    def test_oracle_anchor_on_common_mode_is_clean(self):
        # cross-check #1: the perfect arm names nothing under common-mode.
        s = score_multi(frozenset(), frozenset())
        self.assertFalse(s.detected)
        self.assertFalse(s.any_false)
        self.assertIsNone(s.recall)


class FleetFlowPulseTest(unittest.TestCase):
    def test_fabric_wide_flowpulse_localizes_a_downlink_fault(self):
        rng = np.random.default_rng(30)
        fp = FleetFlowPulseLocalizer(4, 8)
        for _ in range(8):  # bootstrap healthy
            fp.observe(simulate_epoch_correlated(4, 8, frozenset(), 0.0, 1e-5,
                                                 2_000_000, rng))
        d = simulate_epoch_correlated(4, 8, frozenset({('down', 0, 0)}), 0.05,
                                      1e-5, 2_000_000, rng)
        detected, links = fp.localize(d)
        self.assertTrue(detected)
        self.assertIn(('down', 0, 0), links)   # names the faulty downlink


if __name__ == "__main__":
    unittest.main()
