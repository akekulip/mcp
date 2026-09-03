"""Unit + fidelity tests for `sim/baselines/localization.py`.

The scoring and localization RULES are the new, load-bearing units here (the
detection arms themselves are already fidelity-checked in their own test files).
These tests pin: the shared 2-hop generator's conservation and single-link fault
placement; SprayCheck's §3.6 cross-leaf intersection (resolves both a downlink
and an uplink fault when corroborated, degrades to the ambiguous 2-set when
not); FlowPulse's §5.3 per-sender rule INCLUDING the sprayed-regime dilution
that makes it miss an uplink fault whose signal falls below its 1% aggregate
threshold; and the three localization metrics.
"""
import unittest

import numpy as np

from sim.baselines.localization import (
    ArmLocalization, EpochDraw, FlowPulseLocalizer, MCPLocalizer,
    SprayCheckLocalizer, mcp_link_counters, score_localization, simulate_epoch,
    spraycheck_localize,
)


class SimulateEpochTest(unittest.TestCase):
    def test_healthy_epoch_loses_almost_nothing_at_zero_rates(self):
        rng = np.random.default_rng(0)
        d = simulate_epoch(4, 8, None, 0.5, 0.0, 100_000, rng)
        # every ordered pair sends packets_per_pair; diagonal is empty
        self.assertEqual(int(d.tx[0, 0, :].sum()), 0)
        self.assertEqual(int(d.tx[0, 1, :].sum()), 100_000)
        # zero loss on both hops -> arrivals == tx
        self.assertTrue((d.arr == d.tx).all())

    def test_only_the_faulty_downlink_loses(self):
        rng = np.random.default_rng(1)
        d = simulate_epoch(4, 8, ('down', 0, 0), 0.9, 0.0, 200_000, rng)
        # downlink S0->L0 carries all sources to L0 via spine0 and loses ~90%
        arrived = int(d.arr[:, 0, 0].sum())
        entered = int(d.su[:, 0, 0].sum())
        self.assertLess(arrived, 0.2 * entered)
        # a healthy downlink (spine1 into L0) loses nothing
        self.assertEqual(int(d.arr[:, 0, 1].sum()), int(d.su[:, 0, 1].sum()))

    def test_only_the_faulty_uplink_loses_and_only_for_that_source(self):
        rng = np.random.default_rng(2)
        d = simulate_epoch(4, 8, ('up', 1, 0), 0.9, 0.0, 200_000, rng)
        # uplink L1->S0 loses ~90% of source 1's spine-0 traffic
        self.assertLess(int(d.su[1, :, 0].sum()), 0.2 * int(d.tx[1, :, 0].sum()))
        # source 2's uplink into spine 0 is untouched
        self.assertEqual(int(d.su[2, :, 0].sum()), int(d.tx[2, :, 0].sum()))


class MCPCountersTest(unittest.TestCase):
    def test_downlink_fault_shows_only_on_that_directed_link(self):
        rng = np.random.default_rng(3)
        d = simulate_epoch(4, 8, ('down', 0, 0), 0.5, 0.0, 400_000, rng)
        counters = mcp_link_counters(d, 4, 8)
        tx, rx = counters[('down', 0, 0)]
        self.assertLess(rx, 0.7 * tx)             # faulty link is lossy
        utx, urx = counters[('up', 1, 0)]
        self.assertEqual(utx, urx)                # its feeding uplink is clean
        # MCP's own decision loop rejects exactly the faulty link across epochs
        mcp = MCPLocalizer()
        rejected = frozenset()
        for e in range(30):
            dd = simulate_epoch(4, 8, ('down', 0, 0), 0.5, 0.0, 400_000, rng)
            rejected = mcp.tick(e, mcp_link_counters(dd, 4, 8))
            if rejected:
                break
        self.assertEqual(rejected, frozenset({('down', 0, 0)}))


class SprayCheckIntersectionTest(unittest.TestCase):
    def _cum(self, n_leaves, k, faulty, rate, epochs, seed):
        rng = np.random.default_rng(seed)
        cum = np.zeros((n_leaves, k), dtype=np.int64) if False else None
        acc = np.zeros((n_leaves, n_leaves, k), dtype=np.int64)
        for _ in range(epochs):
            d = simulate_epoch(n_leaves, k, faulty, rate, 0.0, 1_000_000, rng)
            acc += d.arr
        return acc

    def test_downlink_resolved_by_two_source_intersection(self):
        cum = self._cum(4, 8, ('down', 0, 0), 0.5, 3, 10)
        detected, localized, _ = spraycheck_localize(cum, 4, 8, s=3.2)
        self.assertTrue(detected)
        self.assertEqual(localized, frozenset({('down', 0, 0)}))

    def test_uplink_resolved_by_two_destination_intersection(self):
        cum = self._cum(4, 8, ('up', 1, 0), 0.5, 3, 11)
        detected, localized, _ = spraycheck_localize(cum, 4, 8, s=3.2)
        self.assertTrue(detected)
        self.assertEqual(localized, frozenset({('up', 1, 0)}))

    def test_single_uncorroborated_path_stays_the_ambiguous_two_set(self):
        # Hand-built cumulative arrivals: exactly ONE flow (0->1) is deficient
        # on spine 0, no other flow corroborates -> §3.6 cannot confirm a link,
        # so the honest output is the 2-link path {uplink, downlink}.
        cum = np.full((4, 4, 8), 125_000, dtype=np.int64)
        for a in range(4):
            for b in range(4):
                if a == b:
                    cum[a, b, :] = 0
        cum[0, 1, 0] = 1_000  # only this flow's spine-0 arrivals collapse
        detected, localized, paths = spraycheck_localize(cum, 4, 8, s=3.2)
        self.assertTrue(detected)
        self.assertEqual(paths, [(0, 0, 1)])
        self.assertEqual(localized, frozenset({('up', 0, 0), ('down', 0, 1)}))


class FlowPulseRuleTest(unittest.TestCase):
    def _bootstrap(self, fp, rng, epochs=8):
        for _ in range(epochs):
            fp.observe(simulate_epoch(4, 8, None, 0.5, 0.0, 2_000_000, rng))

    def test_all_senders_affected_marks_local_downlink(self):
        rng = np.random.default_rng(20)
        fp = FlowPulseLocalizer(spine=0, dst=0, senders=[1, 2, 3])
        self._bootstrap(fp, rng)
        d = simulate_epoch(4, 8, ('down', 0, 0), 0.05, 0.0, 2_000_000, rng)
        detected, localized = fp.localize(d)
        self.assertTrue(detected)
        self.assertEqual(localized, frozenset({('down', 0, 0)}))

    def test_one_sender_affected_marks_that_uplink(self):
        rng = np.random.default_rng(21)
        fp = FlowPulseLocalizer(spine=0, dst=0, senders=[1, 2, 3])
        self._bootstrap(fp, rng)
        # a large uplink loss on source 1 so the port aggregate clears 1%
        d = simulate_epoch(4, 8, ('up', 1, 0), 0.2, 0.0, 2_000_000, rng)
        detected, localized = fp.localize(d)
        self.assertTrue(detected)
        self.assertEqual(localized, frozenset({('up', 1, 0)}))

    def test_uplink_signal_diluted_below_one_percent_is_missed(self):
        # Faithful sprayed-regime limitation: a 1.5% loss on ONE of three
        # senders moves the aggregate port load by only ~0.5% (< the paper's
        # 1% threshold), so FlowPulse's aggregate detector never fires.
        rng = np.random.default_rng(22)
        fp = FlowPulseLocalizer(spine=0, dst=0, senders=[1, 2, 3])
        self._bootstrap(fp, rng)
        detected, localized = fp.localize(
            simulate_epoch(4, 8, ('up', 1, 0), 0.015, 0.0, 2_000_000, rng))
        self.assertFalse(detected)
        self.assertEqual(localized, frozenset())


class ScoreLocalizationTest(unittest.TestCase):
    def test_exact_single_correct_link(self):
        r = score_localization(frozenset({('down', 0, 0)}), ('down', 0, 0), True)
        self.assertEqual(r, ArmLocalization(True, True, False, 1))

    def test_ambiguous_set_containing_truth_is_not_exact_and_is_wrong(self):
        r = score_localization(frozenset({('up', 0, 0), ('down', 0, 0)}),
                               ('down', 0, 0), True)
        self.assertFalse(r.exact)
        self.assertTrue(r.wrong)          # contains a non-faulty link
        self.assertEqual(r.cardinality, 2)

    def test_single_wrong_link(self):
        r = score_localization(frozenset({('up', 2, 5)}), ('down', 0, 0), True)
        self.assertFalse(r.exact)
        self.assertTrue(r.wrong)
        self.assertEqual(r.cardinality, 1)

    def test_miss_when_not_detected(self):
        r = score_localization(frozenset(), ('down', 0, 0), False)
        self.assertEqual(r, ArmLocalization(False, False, False, None))


if __name__ == "__main__":
    unittest.main()


class SweepStatsTest(unittest.TestCase):
    """The paired-comparison + CI machinery used to build the artifact table."""

    def _trials(self, mcp_exacts, base_exacts):
        from sim.baselines.run_localization_sweep import TrialResult
        out = []
        for m, b in zip(mcp_exacts, base_exacts):
            out.append(TrialResult(
                mcp=ArmLocalization(True, m, not m, 1 if m else 2),
                spraycheck=ArmLocalization(True, b, not b, 1 if b else 2),
                flowpulse=ArmLocalization(True, b, not b, 1 if b else 2)))
        return out

    def test_mcnemar_all_discordant_in_mcp_favor(self):
        from sim.baselines.run_localization_sweep import mcnemar_exact
        # MCP exact on all 10, baseline exact on none: 10 discordant, all one way
        trials = self._trials([True] * 10, [False] * 10)
        r = mcnemar_exact(trials, "mcp", "spraycheck")
        self.assertEqual(r["discordant"], 10)
        self.assertEqual(r["b_mcp_only"], 10)
        self.assertEqual(r["c_spraycheck_only"], 0)
        self.assertAlmostEqual(r["exact_rate_diff"], 1.0)
        self.assertLess(r["p_value"], 0.01)      # 2*0.5^10 ~= 0.002

    def test_mcnemar_no_discordance_gives_p_one(self):
        from sim.baselines.run_localization_sweep import mcnemar_exact
        trials = self._trials([True] * 5, [True] * 5)
        r = mcnemar_exact(trials, "mcp", "spraycheck")
        self.assertEqual(r["discordant"], 0)
        self.assertEqual(r["p_value"], 1.0)

    def test_bootstrap_ci_is_degenerate_for_constant_values(self):
        from sim.baselines.run_localization_sweep import bootstrap_mean_ci
        self.assertEqual(bootstrap_mean_ci([2, 2, 2, 2]), (2.0, 2.0))

    def test_bootstrap_ci_brackets_the_mean(self):
        from sim.baselines.run_localization_sweep import bootstrap_mean_ci
        lo, hi = bootstrap_mean_ci([1, 1, 2, 2, 3, 3], iters=2000, seed=1)
        self.assertLessEqual(lo, 2.0)
        self.assertGreaterEqual(hi, 2.0)
