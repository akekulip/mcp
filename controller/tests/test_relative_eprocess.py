import random
import unittest

from controller.relative_eprocess import RelativeEpochRecord, RelativeExchangeabilityTest


class RelativeExchangeabilityTestTest(unittest.TestCase):
    def make_test(self, **overrides):
        config = {
            "alpha": 0.05,
            "known_share": 0.25,
            "excess_shares": (0.35, 0.5, 0.7, 0.9),
        }
        config.update(overrides)
        return RelativeExchangeabilityTest(**config)

    def test_wealth_starts_at_one(self):
        test = self.make_test()
        self.assertAlmostEqual(test.wealth(), 1.0)

    def test_zero_stratum_losses_is_a_factor_of_one(self):
        test = self.make_test()
        result = test.ingest(RelativeEpochRecord(epoch=0, stratum_total_losses=0,
                                                   sublink_losses=0))
        self.assertAlmostEqual(result, 1.0)

    def test_share_exactly_matching_the_null_does_not_grow_wealth_much(self):
        test = self.make_test()
        random.seed(0)
        for epoch in range(200):
            total = 40
            # sublink draws its losses at exactly the known (null) share
            k = sum(1 for _ in range(total) if random.random() < 0.25)
            test.ingest(RelativeEpochRecord(epoch=epoch, stratum_total_losses=total,
                                             sublink_losses=k))
        self.assertFalse(test.alarmed)

    def test_sustained_excess_share_eventually_alarms(self):
        test = self.make_test()
        random.seed(1)
        for epoch in range(200):
            total = 40
            # sublink draws its losses at a share well above the null (0.6 vs 0.25)
            k = sum(1 for _ in range(total) if random.random() < 0.6)
            test.ingest(RelativeEpochRecord(epoch=epoch, stratum_total_losses=total,
                                             sublink_losses=k))
            if test.alarmed:
                break
        self.assertTrue(test.alarmed)

    def test_monte_carlo_false_alarm_rate_under_the_true_null(self):
        # Ville's inequality: P(ever crossing 1/alpha) <= alpha under a true null.
        alpha = 0.05
        trials = 300
        alarms = 0
        rng = random.Random(42)
        for trial in range(trials):
            test = self.make_test(alpha=alpha)
            for epoch in range(50):
                total = 30
                k = sum(1 for _ in range(total) if rng.random() < 0.25)
                test.ingest(RelativeEpochRecord(epoch=epoch, stratum_total_losses=total,
                                                 sublink_losses=k))
                if test.alarmed:
                    alarms += 1
                    break
        # generous slack above the nominal 5% for a 300-trial Monte Carlo estimate
        self.assertLess(alarms / trials, 0.15)

    def test_epochs_must_be_strictly_increasing(self):
        test = self.make_test()
        test.ingest(RelativeEpochRecord(epoch=5, stratum_total_losses=10, sublink_losses=2))
        with self.assertRaises(ValueError):
            test.ingest(RelativeEpochRecord(epoch=5, stratum_total_losses=10, sublink_losses=2))

    def test_rejects_sublink_losses_exceeding_stratum_total(self):
        test = self.make_test()
        with self.assertRaises(ValueError):
            test.ingest(RelativeEpochRecord(epoch=0, stratum_total_losses=5, sublink_losses=6))

    def test_rejects_excess_share_outside_range(self):
        with self.assertRaises(ValueError):
            self.make_test(excess_shares=(0.1,))  # below known_share

    def test_rejects_bad_alpha_or_known_share(self):
        with self.assertRaises(ValueError):
            self.make_test(alpha=1.5)
        with self.assertRaises(ValueError):
            self.make_test(known_share=0.0)


if __name__ == "__main__":
    unittest.main()
