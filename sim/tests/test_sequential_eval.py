import io
import unittest

from sim.clf.sequential_eval import evaluate, run_campaign, write_csv


class SequentialEvaluationTest(unittest.TestCase):
    def test_total_blackhole_is_immediate_for_all_arms(self):
        result = run_campaign(0.0, runs=10, horizon=5, seed=1)
        self.assertEqual(result.presence_rate, 1.0)
        self.assertEqual(result.fixed_starved_rate, 1.0)
        self.assertEqual(result.ledger_action_rate, 1.0)
        self.assertEqual(result.ledger_median_epoch, 1.0)

    def test_perfect_delivery_never_acts(self):
        result = run_campaign(1.0, runs=10, horizon=10, seed=1)
        self.assertEqual(result.presence_rate, 0.0)
        self.assertEqual(result.fixed_starved_rate, 0.0)
        self.assertEqual(result.ledger_action_rate, 0.0)
        self.assertEqual(result.statistical_alarm_rate, 0.0)

    def test_fixed_seed_evaluation_and_csv_are_reproducible(self):
        first = evaluate((0.5, 0.99), runs=20, horizon=5, seed=7)
        second = evaluate((0.5, 0.99), runs=20, horizon=5, seed=7)
        self.assertEqual(first, second)
        output = io.StringIO()
        write_csv(first, output)
        self.assertIn("statistical_alarm_rate", output.getvalue().splitlines()[0])
        self.assertEqual(len(output.getvalue().splitlines()), 3)


if __name__ == "__main__":
    unittest.main()
