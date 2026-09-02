import random
import unittest

from controller.absolute_eprocess import log_spaced_alternatives
from controller.mitigation_weight import RestorationEProcess, weight_from_wealth


class WeightFromWealthTest(unittest.TestCase):
    def test_wealth_of_one_gives_full_weight(self):
        self.assertAlmostEqual(weight_from_wealth(1.0, w_min=0.05), 1.0)

    def test_wealth_below_one_still_gives_full_weight(self):
        # sub-1 wealth is not evidence against the null; never boost above 1
        self.assertAlmostEqual(weight_from_wealth(0.3, w_min=0.05), 1.0)

    def test_infinite_wealth_reaches_the_floor(self):
        self.assertAlmostEqual(weight_from_wealth(float("inf"), w_min=0.05), 0.05)

    def test_weight_is_strictly_decreasing_in_wealth(self):
        w_min = 0.05
        weights = [weight_from_wealth(wealth, w_min) for wealth in (2, 5, 20, 100, 1000)]
        self.assertEqual(weights, sorted(weights, reverse=True))
        for w in weights:
            self.assertGreaterEqual(w, w_min)

    def test_a_lone_small_wealth_bump_only_nudges_weight_slightly(self):
        w_min = 0.05
        weight_at_2 = weight_from_wealth(2.0, w_min)
        self.assertGreater(weight_at_2, 0.5)  # far from the floor after one weak signal

    def test_rejects_bad_w_min(self):
        with self.assertRaises(ValueError):
            weight_from_wealth(5.0, w_min=0.0)
        with self.assertRaises(ValueError):
            weight_from_wealth(5.0, w_min=1.0)

    def test_rejects_negative_wealth(self):
        with self.assertRaises(ValueError):
            weight_from_wealth(-1.0, w_min=0.05)


class RestorationEProcessTest(unittest.TestCase):
    def make_restoration(self):
        return RestorationEProcess(
            alpha=0.05,
            healthy_alternatives=log_spaced_alternatives(1e-5, 1e-3, count=8))

    def test_not_armed_before_arm_is_called(self):
        restoration = self.make_restoration()
        self.assertFalse(restoration.armed)
        with self.assertRaises(RuntimeError):
            restoration.ingest(epoch=0, tx=10, rx=10)

    def test_armed_starts_unrecovered(self):
        restoration = self.make_restoration()
        restoration.arm(suspect_rate=0.05)
        self.assertTrue(restoration.armed)
        self.assertFalse(restoration.recovered)

    def test_sustained_healthy_traffic_eventually_recovers(self):
        restoration = self.make_restoration()
        restoration.arm(suspect_rate=0.05)
        random.seed(9)
        recovered = False
        for epoch in range(200):
            tx = 100
            rx = sum(1 for _ in range(tx) if random.random() >= 1e-4)  # near-healthy
            restoration.ingest(epoch=epoch, tx=tx, rx=rx)
            if restoration.recovered:
                recovered = True
                break
        self.assertTrue(recovered)

    def test_disarm_clears_state(self):
        restoration = self.make_restoration()
        restoration.arm(suspect_rate=0.05)
        restoration.disarm()
        self.assertFalse(restoration.armed)

    def test_rejects_bad_suspect_rate(self):
        restoration = self.make_restoration()
        with self.assertRaises(ValueError):
            restoration.arm(suspect_rate=0.0)

    def test_rejects_a_suspect_rate_at_or_below_every_healthy_alternative(self):
        # healthy_alternatives top out at 1e-3; a suspect_rate of 1e-4 would
        # make every mixture component bet the wrong way and never restore
        restoration = self.make_restoration()
        with self.assertRaises(ValueError):
            restoration.arm(suspect_rate=1e-4)
        with self.assertRaises(ValueError):
            restoration.arm(suspect_rate=1e-3)  # exactly at the boundary, still rejected

    def test_censored_epoch_does_not_move_restoration_wealth(self):
        restoration = self.make_restoration()
        restoration.arm(suspect_rate=0.05)
        before = restoration.ingest(epoch=0, tx=100, rx=99).wealth
        after = restoration.ingest(epoch=1, tx=100, rx=0, censored=True).wealth
        self.assertAlmostEqual(after, before)


if __name__ == "__main__":
    unittest.main()
