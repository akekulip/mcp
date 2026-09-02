import random
import unittest

from controller.absolute_eprocess import (
    FleetAbsoluteEProcess,
    FleetEpochRecord,
    log_spaced_alternatives,
)


class LogSpacedAlternativesTest(unittest.TestCase):
    def test_endpoints_are_included_for_multi_point_grids(self):
        grid = log_spaced_alternatives(1e-4, 0.5, count=5)
        self.assertAlmostEqual(grid[0], 1e-4, places=9)
        self.assertAlmostEqual(grid[-1], 0.5, places=9)
        self.assertEqual(len(grid), 5)

    def test_grid_is_increasing(self):
        grid = log_spaced_alternatives(1e-4, 0.5, count=8)
        self.assertEqual(list(grid), sorted(grid))

    def test_rejects_bad_bounds(self):
        with self.assertRaises(ValueError):
            log_spaced_alternatives(0.5, 0.1, count=3)


class FleetAbsoluteEProcessTest(unittest.TestCase):
    def make_process(self, **overrides):
        config = {
            "alpha": 0.05,
            "alternatives": log_spaced_alternatives(1e-3, 0.5, count=12),
        }
        config.update(overrides)
        return FleetAbsoluteEProcess(**config)

    def test_wealth_starts_at_one(self):
        process = self.make_process()
        result = process.ingest(FleetEpochRecord(epoch=0, tx=0, rx=0, floor=1e-5))
        self.assertAlmostEqual(result.wealth, 1.0)
        self.assertFalse(result.alarmed)

    def test_censored_epoch_is_a_factor_of_one_even_with_a_huge_loss(self):
        process = self.make_process()
        before = process.ingest(FleetEpochRecord(epoch=0, tx=1000, rx=999, floor=1e-4))
        after = process.ingest(FleetEpochRecord(epoch=1, tx=1000, rx=0, floor=1e-4,
                                                 censored=True))
        self.assertAlmostEqual(after.wealth, before.wealth)

    def test_censoring_does_not_reset_prior_wealth(self):
        process = self.make_process()
        random.seed(3)
        for epoch in range(30):
            tx = 100
            rx = sum(1 for _ in range(tx) if random.random() > 0.4)  # 40% loss, bad link
            process.ingest(FleetEpochRecord(epoch=epoch, tx=tx, rx=rx, floor=1e-4))
        wealth_before_censor = process.ingest(
            FleetEpochRecord(epoch=30, tx=100, rx=60, floor=1e-4)).wealth
        censored_result = process.ingest(
            FleetEpochRecord(epoch=31, tx=100, rx=0, floor=1e-4, censored=True))
        self.assertAlmostEqual(censored_result.wealth, wealth_before_censor)
        self.assertGreater(censored_result.wealth, 1.0)

    def test_repair_generation_bump_resets_wealth(self):
        process = self.make_process()
        random.seed(4)
        for epoch in range(30):
            tx = 100
            rx = sum(1 for _ in range(tx) if random.random() > 0.4)
            process.ingest(FleetEpochRecord(epoch=epoch, tx=tx, rx=rx, floor=1e-4))
        result = process.ingest(FleetEpochRecord(epoch=0, tx=0, rx=0, floor=1e-4,
                                                  repair_generation=1))
        self.assertAlmostEqual(result.wealth, 1.0)
        self.assertEqual(result.repair_generation, 1)

    def test_repair_generation_cannot_move_backwards(self):
        process = self.make_process()
        process.ingest(FleetEpochRecord(epoch=0, tx=10, rx=10, floor=1e-4,
                                         repair_generation=2))
        with self.assertRaises(ValueError):
            process.ingest(FleetEpochRecord(epoch=1, tx=10, rx=10, floor=1e-4,
                                             repair_generation=1))

    def test_epochs_must_be_strictly_increasing(self):
        process = self.make_process()
        process.ingest(FleetEpochRecord(epoch=5, tx=10, rx=10, floor=1e-4))
        with self.assertRaises(ValueError):
            process.ingest(FleetEpochRecord(epoch=5, tx=10, rx=10, floor=1e-4))

    def test_sustained_elevated_loss_eventually_alarms(self):
        process = self.make_process(alpha=0.05)
        random.seed(5)
        floor = 1e-4
        true_loss_rate = 5e-3  # 50x the floor
        alarmed = False
        for epoch in range(500):
            tx = 200
            rx = sum(1 for _ in range(tx) if random.random() >= true_loss_rate)
            result = process.ingest(FleetEpochRecord(epoch=epoch, tx=tx, rx=rx, floor=floor))
            if result.alarmed:
                alarmed = True
                break
        self.assertTrue(alarmed)

    def test_wealth_matches_the_hand_computed_likelihood_ratio_exactly(self):
        # Deterministic pin on the exact log-LR formula, not a statistical
        # estimate: a single alternative makes the mixture trivial (wealth =
        # exp(log-LR) directly), so this catches an exact-arithmetic
        # regression (delivered/tx swap, sign flip, floor/alternative swap)
        # immediately and without Monte Carlo flakiness
        # (docs/review/artifacts/STATS-LAYER-REVIEW-2026-09-02.md, weak-test
        # finding: the existing tolerance-based Monte Carlo checks did not
        # catch a "use tx instead of delivered" mutation).
        import math
        process = FleetAbsoluteEProcess(alpha=0.05, alternatives=(0.5,))
        result = process.ingest(FleetEpochRecord(epoch=0, tx=10, rx=7, floor=0.2))
        delivered, lost = 7, 3
        expected_log_lr = (delivered * math.log((1.0 - 0.5) / (1.0 - 0.2)) +
                           lost * math.log(0.5 / 0.2))
        self.assertAlmostEqual(result.wealth, math.exp(expected_log_lr), places=12)

        # a "use tx instead of delivered" mutation would instead produce this:
        mutant_log_lr = (10 * math.log((1.0 - 0.5) / (1.0 - 0.2)) +
                         lost * math.log(0.5 / 0.2))
        self.assertNotAlmostEqual(result.wealth, math.exp(mutant_log_lr), places=6)

    def test_monte_carlo_false_alarm_rate_under_a_true_and_moving_floor(self):
        # The floor is redrawn every epoch (previsible: computed independent of
        # this trial's own outcome) and data is generated at exactly that
        # epoch's floor, so the null is true throughout even though it moves.
        # Ville's inequality bounds P(ever alarm) <= alpha for a true e-process.
        alpha = 0.05
        trials = 300
        rng = random.Random(7)
        alarms = 0
        for _ in range(trials):
            process = self.make_process(alpha=alpha)
            for epoch in range(60):
                floor = rng.choice([1e-4, 5e-4, 2e-3, 1e-2])
                tx = 100
                rx = sum(1 for _ in range(tx) if rng.random() >= floor)
                result = process.ingest(
                    FleetEpochRecord(epoch=epoch, tx=tx, rx=rx, floor=floor))
                if result.alarmed:
                    alarms += 1
                    break
        self.assertLess(alarms / trials, 0.15)

    def test_rejects_rx_greater_than_tx(self):
        process = self.make_process()
        with self.assertRaises(ValueError):
            process.ingest(FleetEpochRecord(epoch=0, tx=5, rx=6, floor=1e-4))

    def test_rejects_floor_out_of_range(self):
        process = self.make_process()
        with self.assertRaises(ValueError):
            process.ingest(FleetEpochRecord(epoch=0, tx=5, rx=5, floor=0.0))

    def test_rejects_bad_construction(self):
        with self.assertRaises(ValueError):
            FleetAbsoluteEProcess(alpha=0.0, alternatives=(0.1,))
        with self.assertRaises(ValueError):
            FleetAbsoluteEProcess(alpha=0.05, alternatives=())


if __name__ == "__main__":
    unittest.main()
