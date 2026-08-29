import math
import unittest

from sim.dynamic.metrics import (
    INERT_LABEL,
    NO_FAULT_LABEL,
    CellSummary,
    RunRecord,
    bootstrap_median_ci,
    format_table,
    summarize,
    wilson,
)
from sim.gate.replay import scenario_seed


def make_record(**overrides) -> RunRecord:
    """A benign baseline run; each test overrides only the fields it is about."""
    base = dict(
        quarantined_faulty=False,
        unsafe_packets=0,
        detect_us=None,
        healthy_epochs=60,
        false_quarantine_epochs=0,
        collateral_packets=0,
        restored=False,
        restore_us=None,
        unsafe_restorations=0,
        flaps=0,
        installs=0,
        coalesced=0,
        stale_dropped=0,
        offered_faulty=200_000,
        lost_faulty=0,
        offered_healthy=800_000,
        lost_healthy=0,
        evidence_epochs=0,
        epochs=60,
    )
    base.update(overrides)
    return RunRecord(**base)


class WilsonTest(unittest.TestCase):
    def test_zero_successes_gives_exactly_zero_lower_bound_and_positive_upper(self):
        low, high = wilson(0, 50)
        self.assertEqual(low, 0.0)
        self.assertGreater(high, 0.0)
        self.assertAlmostEqual(high, 0.07135003417431873, places=12)

    def test_all_successes_gives_exactly_one_upper_bound(self):
        low, high = wilson(50, 50)
        self.assertEqual(high, 1.0)
        self.assertAlmostEqual(low, 0.9286499658256813, places=12)

    def test_zero_trials_is_vacuous_rather_than_a_division_by_zero(self):
        self.assertEqual(wilson(0, 0), (0.0, 1.0))

    def test_matches_the_closed_form_on_a_hand_computed_case(self):
        """Closed form for x=2, n=100, z=1.96, recomputed here rather than copied from a table."""
        x, n, z = 2, 100, 1.96
        phat = x / n
        denominator = 1.0 + z * z / n
        centre = (phat + z * z / (2.0 * n)) / denominator
        half = (z / denominator) * math.sqrt(phat * (1.0 - phat) / n + z * z / (4.0 * n * n))
        low, high = wilson(x, n)
        self.assertAlmostEqual(low, centre - half, places=15)
        self.assertAlmostEqual(high, centre + half, places=15)
        self.assertAlmostEqual(low, 0.005501852234968185, places=12)
        self.assertAlmostEqual(high, 0.07001316294199365, places=12)

    def test_interval_always_lies_inside_the_unit_interval(self):
        for n in (1, 3, 30, 1000):
            for x in range(n + 1):
                low, high = wilson(x, n)
                self.assertGreaterEqual(low, 0.0)
                self.assertLessEqual(high, 1.0)
                self.assertLessEqual(low, x / n)
                self.assertGreaterEqual(high, x / n)


class BootstrapTest(unittest.TestCase):
    def test_empty_input_returns_nan_rather_than_raising(self):
        low, high = bootstrap_median_ci([], seed=1)
        self.assertTrue(math.isnan(low))
        self.assertTrue(math.isnan(high))

    def test_is_deterministic_given_a_seed_and_varies_with_it(self):
        values = [float(v) for v in (12, 15, 19, 21, 40, 41, 55, 900)]
        seed = scenario_seed("dynamic_metrics", "bootstrap")
        first = bootstrap_median_ci(values, seed=seed, iters=500)
        second = bootstrap_median_ci(values, seed=seed, iters=500)
        self.assertEqual(first, second)
        self.assertNotEqual(first, bootstrap_median_ci(values, seed=seed + 1, iters=500))

    def test_interval_brackets_the_sample_median_and_stays_in_range(self):
        values = [float(v) for v in range(1, 100)]
        low, high = bootstrap_median_ci(values, seed=7, iters=500)
        self.assertLessEqual(low, 50.0)
        self.assertGreaterEqual(high, 50.0)
        self.assertGreaterEqual(low, 1.0)
        self.assertLessEqual(high, 99.0)

    def test_constant_input_gives_a_degenerate_interval(self):
        self.assertEqual(bootstrap_median_ci([4.0] * 10, seed=3, iters=100), (4.0, 4.0))


class SummarizeTest(unittest.TestCase):
    def test_round_trip_over_synthetic_runs(self):
        records = [
            make_record(quarantined_faulty=True, unsafe_packets=100, detect_us=2200,
                        false_quarantine_epochs=1, collateral_packets=10,
                        restored=True, restore_us=9000, flaps=1, installs=2, coalesced=3,
                        stale_dropped=1, lost_faulty=2000, lost_healthy=8,
                        evidence_epochs=30),
            make_record(quarantined_faulty=True, unsafe_packets=300, detect_us=4400,
                        collateral_packets=20, installs=1, lost_faulty=2400, lost_healthy=8,
                        evidence_epochs=42),
            make_record(unsafe_packets=500, lost_faulty=1600, lost_healthy=8, evidence_epochs=6),
        ]
        cell = summarize(records, seed=scenario_seed("dynamic_metrics", "round_trip"))

        self.assertEqual(cell.runs, 3)
        self.assertEqual(cell.quarantined_runs, 2)
        self.assertAlmostEqual(cell.quarantine_rate, 2 / 3)
        self.assertEqual(cell.quarantine_ci, wilson(2, 3))
        self.assertFalse(cell.inert)
        self.assertEqual(cell.healthy_epochs, 180)
        self.assertEqual(cell.false_quarantine_epochs, 1)
        self.assertAlmostEqual(cell.false_quarantine_rate, 1 / 180)
        self.assertEqual(cell.unsafe_packets, 900)
        self.assertEqual(cell.collateral_packets, 30)
        self.assertEqual(cell.detect_us_median, 3300.0)
        self.assertEqual(cell.restored_runs, 1)
        self.assertAlmostEqual(cell.restore_rate, 0.5)
        self.assertEqual(cell.restore_us_median, 9000.0)
        self.assertEqual((cell.installs, cell.coalesced, cell.stale_dropped), (3, 3, 1))
        self.assertEqual(cell.flaps, 1)
        self.assertEqual(cell.offered_packets, 3_000_000)
        self.assertAlmostEqual(cell.faulty_loss_rate, 6000 / 600_000)
        self.assertAlmostEqual(cell.healthy_loss_rate, 24 / 2_400_000)
        self.assertAlmostEqual(cell.loss_ratio, 1000.0)
        self.assertTrue(cell.fault_injected)
        self.assertAlmostEqual(cell.evidence_epoch_fraction, 78 / 180)

    def test_restoration_is_counted_only_for_runs_that_quarantined_the_fault(self):
        """A false quarantine that is later withdrawn must not inflate the restoration rate."""
        records = [make_record(restored=True, restore_us=1000, false_quarantine_epochs=2)]
        cell = summarize(records, seed=1)
        self.assertEqual(cell.restored_runs, 0)
        self.assertTrue(math.isnan(cell.restore_rate))

    def test_empty_cell_is_a_harness_bug_not_a_zero(self):
        with self.assertRaises(ValueError):
            summarize([], seed=1)


class FormatTableTest(unittest.TestCase):
    def inert_cell(self) -> CellSummary:
        records = [make_record(lost_faulty=2000, lost_healthy=8, evidence_epochs=10)
                   for _ in range(30)]
        return summarize(records, seed=scenario_seed("dynamic_metrics", "inert"))

    def acting_cell(self) -> CellSummary:
        records = [make_record(quarantined_faulty=True, detect_us=2200 + 10 * i,
                               installs=1, lost_faulty=2000, lost_healthy=8, evidence_epochs=10)
                   for i in range(30)]
        return summarize(records, seed=scenario_seed("dynamic_metrics", "acting"))

    def test_a_cell_that_never_quarantines_is_labelled_inert(self):
        """A rule that never fires is not a safe rule (repo CLAUDE.md, cross-check item 4)."""
        cell = self.inert_cell()
        self.assertTrue(cell.inert)
        self.assertEqual(cell.quarantine_rate, 0.0)
        self.assertEqual(cell.false_quarantine_rate, 0.0)   # perfectly safe, perfectly useless
        table = format_table({"none/h=8.0": cell})
        row = [line for line in table.splitlines() if line.startswith("| none/h=8.0")][0]
        self.assertIn(INERT_LABEL, row)

    def test_a_cell_that_quarantines_is_not_labelled_inert(self):
        table = format_table({"cw4/h=8.0": self.acting_cell()})
        row = [line for line in table.splitlines() if line.startswith("| cw4/h=8.0")][0]
        self.assertNotIn(INERT_LABEL, row)
        self.assertIn("acts", row)

    def test_safety_and_usefulness_are_adjacent_columns(self):
        header = format_table({}).splitlines()[0]
        columns = [c.strip() for c in header.strip("| ").split("|")]
        quarantine = columns.index("quarantine rate (95%)")
        self.assertEqual(columns[quarantine + 1], "false-quarantine rate (95%)")
        self.assertEqual(columns[quarantine + 2], "acts?")

    def test_a_cell_whose_faulty_link_is_no_worse_than_healthy_is_labelled_no_fault_injected(self):
        """Ratio <= 1 means the injector never composed with the background rate (H32)."""
        records = [make_record(quarantined_faulty=True, detect_us=2200, installs=1,
                               lost_faulty=2, lost_healthy=8, evidence_epochs=10)
                   for _ in range(30)]
        cell = summarize(records, seed=scenario_seed("dynamic_metrics", "no_fault"))
        self.assertLessEqual(cell.loss_ratio, 1.0)
        self.assertFalse(cell.fault_injected)
        table = format_table({"cw4/p=1e-4": cell})
        row = [line for line in table.splitlines() if line.startswith("| cw4/p=1e-4")][0]
        self.assertIn(NO_FAULT_LABEL, row)

    def test_a_zero_loss_faulty_link_is_labelled_no_fault_injected(self):
        cell = self.acting_cell()
        table = format_table({"ok": cell, "zero": summarize(
            [make_record(quarantined_faulty=True, lost_faulty=0, lost_healthy=0)],
            seed=2)})
        rows = {line.split("|")[1].strip(): line for line in table.splitlines()}
        self.assertNotIn(NO_FAULT_LABEL, rows["ok"])
        self.assertIn(NO_FAULT_LABEL, rows["zero"])

    def test_realised_parameter_columns_are_present_with_their_values(self):
        cell = self.acting_cell()
        table = format_table({"cw4": cell})
        header = [c.strip() for c in table.splitlines()[0].strip("| ").split("|")]
        for column in ("offered pkts", "faulty loss", "healthy loss", "ratio", "fault check"):
            self.assertIn(column, header)
        row = table.splitlines()[2]
        self.assertIn(str(cell.offered_packets), row)
        self.assertIn("%.2f" % cell.loss_ratio, row)

    def test_rates_carry_their_wilson_interval_and_latencies_their_bootstrap_interval(self):
        cell = self.acting_cell()
        row = format_table({"cw4": cell}).splitlines()[2]
        low, high = wilson(cell.quarantined_runs, cell.runs)
        self.assertIn("%.4f [%.4f, %.4f]" % (cell.quarantine_rate, low, high), row)
        self.assertIn("%.0f [%.0f, %.0f]" % (cell.detect_us_median, cell.detect_us_ci[0],
                                             cell.detect_us_ci[1]), row)

    def test_table_is_markdown_with_one_row_per_cell(self):
        table = format_table({"a": self.inert_cell(), "b": self.acting_cell()})
        lines = table.splitlines()
        self.assertEqual(len(lines), 4)
        self.assertTrue(lines[1].startswith("|---"))
        self.assertEqual([line.split("|")[1].strip() for line in lines[2:]], ["a", "b"])


if __name__ == "__main__":
    unittest.main()
