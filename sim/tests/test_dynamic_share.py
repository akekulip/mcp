"""Tests for the context-share parameter and the collateral-vs-share curve (HURDLES H37).

Two jobs. First, pin the DEFAULT: `context_share` became a parameter so the headline ratio could be
decomposed, and every number measured before that change has to survive the change untouched --
including the exact collateral pair H37 recorded, which is asserted here as an external witness
rather than as a self-consistency check. Second, pin the curve's shape and its arithmetic baseline,
so that if the measured reduction ever stops being a closed form in the share vector somebody looks
at why instead of celebrating.
"""
import unittest

from sim.dynamic.fabric import Fabric
from sim.dynamic.runner import (
    UNIFORM_QUARTER,
    RunConfig,
    build_scenario,
    fault_site,
    run,
)
from sim.dynamic.share_sweep import (
    ADVERSARIAL_SHARE,
    SHARE_SWEEP,
    collateral_curve,
    format_share_table,
    measure_point,
    share_vector,
)
from sim.dynamic.sweep import seed_values


def cfg(**overrides) -> RunConfig:
    base = dict(scenario="persistent_partial", arm="cw4_feedback", tau_feedback_us=0,
                tau_write_us=0, h=6.5, clean_epochs_to_restore=3, p_fault=1e-3, epochs=40, seed=1)
    base.update(overrides)
    return RunConfig(**base)


class DefaultShareIsUnchangedTest(unittest.TestCase):
    """The parameter is new; the default must be the frozen uniform quarter, bit for bit."""

    def test_the_default_is_the_uniform_quarter_over_four_contexts(self):
        self.assertEqual(UNIFORM_QUARTER, (0.25, 0.25, 0.25, 0.25))
        self.assertEqual(cfg().context_share, UNIFORM_QUARTER)
        self.assertEqual(cfg().n_context, 4)
        self.assertEqual(Fabric(seed=0, scenario="no_fault").context_share, UNIFORM_QUARTER)

    def test_build_scenario_threads_the_share_into_the_fabric(self):
        self.assertEqual(build_scenario(cfg())[0].context_share, UNIFORM_QUARTER)
        shares = (0.7, 0.1, 0.1, 0.1)
        fab, _ = build_scenario(cfg(context_share=shares))
        self.assertEqual(fab.context_share, shares)
        self.assertEqual(fab.n_context, 4)

    def test_stating_the_default_explicitly_changes_nothing(self):
        """A run configured with the uniform quarter by hand must be the same run as the default."""
        self.assertEqual(run(cfg()), run(cfg(n_context=4, context_share=UNIFORM_QUARTER)))

    def test_the_h37_collateral_pair_is_reproduced_exactly(self):
        """The externally recorded witness: HURDLES H37, persistent_partial p=1e-3 h=6.5, seed 1.

        1,510,436 against 10,572,965 = 6.9999x. If threading the share vector through had perturbed
        the fabric, this pair would move.
        """
        selective = run(cfg(arm="cw4_feedback"))
        directed = run(cfg(arm="directed_w4"))
        self.assertEqual(selective.collateral_packets, 1_510_436)
        self.assertEqual(directed.collateral_packets, 10_572_965)
        self.assertEqual(selective.false_quarantine_epochs, 0)
        self.assertEqual(directed.false_quarantine_epochs, 87)
        self.assertEqual(selective.unsafe_packets, directed.unsafe_packets)

    def test_the_fault_site_draw_does_not_move_when_the_share_moves(self):
        """The curve is only a curve if the fault stays on the same sublink along it."""
        site = fault_site("persistent_partial", 1, 4)
        for shares in (UNIFORM_QUARTER, (0.05, 0.95 / 3, 0.95 / 3, 0.95 / 3),
                       (0.85, 0.05, 0.05, 0.05)):
            _fab, faulty = build_scenario(cfg(context_share=shares))
            self.assertEqual(faulty, site)


class ShareValidationTest(unittest.TestCase):
    def test_a_share_vector_that_does_not_cover_the_link_is_rejected(self):
        with self.assertRaises(ValueError):
            cfg(context_share=(0.25, 0.25, 0.25))            # sums to 0.75
        with self.assertRaises(ValueError):
            cfg(context_share=(0.5, 0.5, 0.5, 0.5))          # sums to 2.0

    def test_a_share_vector_of_the_wrong_length_is_rejected(self):
        with self.assertRaises(ValueError):
            cfg(n_context=4, context_share=(0.5, 0.5))

    def test_a_context_count_past_the_four_bit_capsule_is_rejected(self):
        with self.assertRaises(ValueError):
            cfg(n_context=17, context_share=(1.0 / 17,) * 17)

    def test_a_negative_share_is_rejected(self):
        with self.assertRaises(ValueError):
            cfg(context_share=(1.5, -0.5, 0.5, -0.5))

    def test_a_non_default_context_count_is_accepted_and_threaded(self):
        fab, faulty = build_scenario(cfg(n_context=8, context_share=(0.125,) * 8))
        self.assertEqual(fab.n_context, 8)
        self.assertLess(faulty[1], 8)


class ShareVectorTest(unittest.TestCase):
    def test_it_puts_the_share_on_the_faulty_context_and_splits_the_rest_evenly(self):
        vector = share_vector(0.7, faulty_context=2, n_context=4)
        self.assertEqual(vector[2], 0.7)
        self.assertAlmostEqual(sum(vector), 1.0, places=12)
        self.assertEqual(len(set(vector[c] for c in (0, 1, 3))), 1)

    def test_the_uniform_quarter_is_a_point_on_the_axis_like_any_other(self):
        for context in range(4):
            self.assertEqual(share_vector(0.25, context, 4), UNIFORM_QUARTER)

    def test_every_produced_vector_is_a_legal_run_config(self):
        for share in SHARE_SWEEP + (ADVERSARIAL_SHARE,):
            for context in range(4):
                cfg(context_share=share_vector(share, context, 4))

    def test_impossible_arguments_are_rejected(self):
        for bad in ((0.0, 0, 4), (1.5, 0, 4), (0.5, 9, 4), (0.5, 0, 1)):
            with self.assertRaises(ValueError):
                share_vector(*bad)


class CollateralCurveTest(unittest.TestCase):
    """The curve, its arithmetic baseline, and the point chosen against us.

    Kept to 3 seeds x 20 epochs: the shape below is invariant to seeds, epochs, h, tau and to
    p_fault across two orders of magnitude, which is itself the finding.
    """

    @classmethod
    def setUpClass(cls):
        cls.points = collateral_curve(seed_values(3), epochs=20, onset_epoch=5)

    def test_the_curve_covers_the_frozen_shares_and_ends_with_the_adversarial_point(self):
        self.assertEqual([p.faulty_share for p in self.points],
                         list(SHARE_SWEEP) + [ADVERSARIAL_SHARE])
        self.assertTrue(self.points[-1].label.startswith("ADVERSARIAL"))

    def test_the_arithmetic_baseline_is_exactly_one_over_the_share(self):
        for point in self.points:
            self.assertAlmostEqual(point.arithmetic, 1.0 / point.faulty_share, places=12)
            self.assertAlmostEqual(point.residual, point.reduction / point.arithmetic, places=12)

    def test_the_reduction_falls_monotonically_as_the_faulty_context_grows(self):
        """Expected direction: the more of the link the faulty context carries, the less a
        selective quarantine can save. Monotone because 1/s is."""
        reductions = [p.reduction for p in self.points]
        # STRICTLY decreasing: a flat curve would mean the share vector never reached the fabric,
        # which is the mistake this whole module exists to make impossible.
        for higher, lower in zip(reductions, reductions[1:]):
            self.assertGreater(higher, lower)

    def test_the_measured_reduction_is_a_closed_form_in_the_share_vector(self):
        """(2 - s) / s at every point, to 4 significant figures -- the residue is the integer
        truncation in the fabric's per-context packet count.

        This is the H37 result, asserted so it cannot quietly stop being true: the measured
        reduction carries NO information beyond the share vector. The directed arm removes the
        whole link (1 - s of it healthy) plus the path-key spillover onto other vlinks in all four
        contexts (1.0), while the selective arm removes only that spillover in one context (s), so
        the ratio is (2 - s)/s with nothing in it about evidence, threshold or transport. If this
        test ever fails, the ratio has become a measurement -- find out why before quoting it.
        """
        for point in self.points:
            closed_form = (2.0 - point.faulty_share) / point.faulty_share
            self.assertAlmostEqual(point.reduction / closed_form, 1.0, places=3)

    def test_the_adversarial_point_leaves_almost_nothing_of_the_advantage(self):
        adversarial = self.points[-1]
        self.assertGreater(adversarial.faulty_share, 0.5)
        self.assertLess(adversarial.reduction, 1.5)
        self.assertLess(adversarial.residual, 1.2)

    def test_every_point_compares_the_arms_at_equal_unsafe_exposure(self):
        """The claim is "less collateral at IDENTICAL exposure"; if that stops holding the ratio is
        buying safety with collateral and the comparison is not the one being made."""
        for point in self.points:
            self.assertTrue(point.equal_exposure, point.label)
            self.assertEqual(point.selective_quarantined_runs, point.runs)
            self.assertEqual(point.directed_quarantined_runs, point.runs)

    def test_the_selective_arm_never_false_quarantines_and_the_directed_arm_always_does(self):
        for point in self.points:
            self.assertEqual(point.selective_false_quarantine_epochs, 0)
            self.assertGreater(point.directed_false_quarantine_epochs, 0)

    def test_the_table_puts_the_arithmetic_baseline_beside_the_measured_ratio(self):
        table = format_share_table(self.points)
        header = [c.strip() for c in table.splitlines()[0].strip("| ").split("|")]
        measured = header.index("measured reduction")
        self.assertEqual(header[measured + 1], "arithmetic 1/s")
        self.assertEqual(header[measured + 2], "residual (measured/arithmetic)")
        self.assertEqual(len(table.splitlines()), len(self.points) + 2)
        self.assertIn("ADVERSARIAL", table)

    def test_a_point_is_deterministic(self):
        seeds = seed_values(2)
        self.assertEqual(measure_point(0.25, seeds, epochs=20, onset_epoch=5),
                         measure_point(0.25, seeds, epochs=20, onset_epoch=5))


if __name__ == "__main__":
    unittest.main()
