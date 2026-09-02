import math
import random
import unittest

from controller.absolute_eprocess import FleetEpochRecord, FleetRatioEProcess


class FleetRatioEProcessTest(unittest.TestCase):
    def make_process(self, **overrides):
        config = {"alpha": 0.05, "ratios": (2.0, 5.0, 10.0, 50.0)}
        config.update(overrides)
        return FleetRatioEProcess(**config)

    def test_wealth_starts_at_one(self):
        process = self.make_process()
        result = process.ingest(FleetEpochRecord(epoch=0, tx=0, rx=0, floor=1e-5))
        self.assertAlmostEqual(result.wealth, 1.0)

    def test_rejects_ratio_at_or_below_one(self):
        with self.assertRaises(ValueError):
            FleetRatioEProcess(alpha=0.05, ratios=(1.0, 5.0))
        with self.assertRaises(ValueError):
            FleetRatioEProcess(alpha=0.05, ratios=(0.5,))

    def test_censored_epoch_is_a_factor_of_one(self):
        process = self.make_process()
        before = process.ingest(FleetEpochRecord(epoch=0, tx=1000, rx=999, floor=1e-4)).wealth
        after = process.ingest(FleetEpochRecord(epoch=1, tx=1000, rx=0, floor=1e-4,
                                                 censored=True)).wealth
        self.assertAlmostEqual(after, before)

    def test_repair_generation_bump_resets_wealth(self):
        process = self.make_process()
        random.seed(1)
        for epoch in range(30):
            tx = 100
            rx = sum(1 for _ in range(tx) if random.random() > 0.4)
            process.ingest(FleetEpochRecord(epoch=epoch, tx=tx, rx=rx, floor=1e-4))
        result = process.ingest(FleetEpochRecord(epoch=0, tx=0, rx=0, floor=1e-4,
                                                  repair_generation=1))
        self.assertAlmostEqual(result.wealth, 1.0)

    def test_wealth_matches_the_hand_computed_likelihood_ratio_exactly(self):
        process = FleetRatioEProcess(alpha=0.05, ratios=(2.5,))
        result = process.ingest(FleetEpochRecord(epoch=0, tx=10, rx=7, floor=0.2))
        # alternative = floor * ratio = 0.5, matching the absolute_eprocess pin test
        delivered, lost = 7, 3
        expected_log_lr = (delivered * math.log((1.0 - 0.5) / (1.0 - 0.2)) +
                           lost * math.log(0.5 / 0.2))
        self.assertAlmostEqual(result.wealth, math.exp(expected_log_lr), places=12)

    def test_monte_carlo_false_alarm_rate_under_a_true_and_moving_floor(self):
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
                result = process.ingest(FleetEpochRecord(epoch=epoch, tx=tx, rx=rx, floor=floor))
                if result.alarmed:
                    alarms += 1
                    break
        self.assertLess(alarms / trials, 0.15)

    def test_clean_traffic_does_not_explode_against_an_inflated_floor(self):
        # The exact round-3 CRITICAL-1 mechanism: a fixed absolute-rate grid
        # tested against a floor contaminated upward by a stale-healthy
        # epoch could itself alarm on perfectly clean traffic (measured
        # wealth 1.2e+74). A ratio-above-floor grid must not reproduce this.
        process = self.make_process()
        true_clean_rate = 1e-3
        random.seed(3)
        wealth = 1.0
        for epoch, inflated_floor in enumerate([0.001, 0.01, 0.1]):
            tx = 200
            rx = sum(1 for _ in range(tx) if random.random() >= true_clean_rate)
            result = process.ingest(FleetEpochRecord(epoch=epoch, tx=tx, rx=rx,
                                                      floor=inflated_floor))
            wealth = result.wealth
        self.assertLess(wealth, 1.0)
        self.assertFalse(result.alarmed)

    def test_sustained_elevated_loss_still_alarms(self):
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

    def test_change_point_epoch_is_gated_by_a_minimum_climb(self):
        # Under a true null, a low-ratio alternative's log-capital still
        # random-walks with slightly negative drift and touches a "new
        # minimum" almost every epoch by construction -- an un-gated
        # running-min epoch would track essentially "now" throughout normal
        # healthy operation, discarding a fault's own early evidence right
        # when a caller needs it (measured in decision_loop.py: this
        # collapsed the restoration action rate on a real fault before the
        # gate was added). A tiny climb must not be trusted as a real
        # change point.
        process = self.make_process()
        random.seed(21)
        floor = 1e-3
        for epoch in range(80):  # sustained clean traffic, pure null noise
            tx = 200
            rx = sum(1 for _ in range(tx) if random.random() >= floor)
            process.ingest(FleetEpochRecord(epoch=epoch, tx=tx, rx=rx, floor=floor))
            self.assertIsNone(process.change_point_epoch(),
                              f"epoch {epoch}: a null-noise climb should never be trusted")

    def test_change_point_epoch_is_none_before_any_evidence(self):
        process = self.make_process()
        self.assertIsNone(process.change_point_epoch())

    def test_change_point_epoch_tracks_where_evidence_actually_started(self):
        process = self.make_process()
        random.seed(11)
        floor = 1e-4
        for epoch in range(50):  # 50 clean epochs
            tx = 100
            rx = sum(1 for _ in range(tx) if random.random() >= floor)
            process.ingest(FleetEpochRecord(epoch=epoch, tx=tx, rx=rx, floor=floor))
        for epoch in range(50, 80):  # then a sustained, strong degradation
            tx = 100
            rx = sum(1 for _ in range(tx) if random.random() >= 0.05)
            process.ingest(FleetEpochRecord(epoch=epoch, tx=tx, rx=rx, floor=floor))
        change_point = process.change_point_epoch()
        self.assertIsNotNone(change_point)
        # the true change was at epoch 50; the CUSUM estimate should land
        # close to it, not diluted back toward epoch 0
        self.assertGreaterEqual(change_point, 45)
        self.assertLess(change_point, 55)


if __name__ == "__main__":
    unittest.main()
