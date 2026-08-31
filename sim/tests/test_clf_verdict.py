import unittest
from sim.clf.verdict import Verdict, verdict, frontier_mask, compare


class TruthTableTest(unittest.TestCase):
    def test_idle_is_never_faulty(self):
        for gap in (None, False, True):
            self.assertEqual(verdict(False, False, gap), Verdict.IDLE)

    def test_healthy_requires_contiguous_continuity(self):
        self.assertEqual(verdict(True, True, False), Verdict.HEALTHY)

    def test_partial_loss_is_the_cw4_case(self):
        self.assertEqual(verdict(True, True, True), Verdict.PARTIAL_LOSS)

    def test_blackhole_needs_positive_source_evidence(self):
        """TX=1 RX=0 is the only state that may be called a blackhole."""
        self.assertEqual(verdict(True, False, None), Verdict.BLACKHOLE)
        self.assertEqual(verdict(True, False, False), Verdict.BLACKHOLE)

    def test_arrival_without_departure_is_reported_not_classified(self):
        self.assertEqual(verdict(False, True, None), Verdict.IMPOSSIBLE)

    def test_missing_evidence_is_inconclusive_never_faulty(self):
        """A management failure must not be reported as a link failure."""
        for tx in (True, False):
            for rx in (True, False):
                self.assertEqual(verdict(tx, rx, None, evidence_complete=False),
                                 Verdict.INCONCLUSIVE)

    def test_no_continuity_evidence_on_a_live_context_is_inconclusive(self):
        self.assertEqual(verdict(True, True, None), Verdict.INCONCLUSIVE)

    def test_every_input_maps_to_exactly_one_frozen_verdict(self):
        seen = set()
        for tx in (0, 1):
            for rx in (0, 1):
                for gap in (None, False, True):
                    seen.add(verdict(bool(tx), bool(rx), gap))
        self.assertEqual(seen, {Verdict.IDLE, Verdict.HEALTHY, Verdict.PARTIAL_LOSS,
                                Verdict.BLACKHOLE, Verdict.IMPOSSIBLE, Verdict.INCONCLUSIVE})


class MaskTest(unittest.TestCase):
    def test_pack_is_per_link_and_context_indexed(self):
        seen = {(3 << 4) | 0: 1, (3 << 4) | 2: 1, (5 << 4) | 1: 1}
        self.assertEqual(frontier_mask(seen, 3), 0b101)
        self.assertEqual(frontier_mask(seen, 5), 0b10)
        self.assertEqual(frontier_mask(seen, 7), 0)

    def test_compare_finds_committed_but_unseen(self):
        self.assertEqual(compare(0b1011, 0b0011), 0b1000)
        self.assertEqual(compare(0b1111, 0b1111), 0)

    def test_receiver_ahead_of_source_shows_as_zero_not_negative(self):
        """RX bits with no TX bit are the IMPOSSIBLE state; compare() must not go negative."""
        self.assertEqual(compare(0b0001, 0b1111), 0)


# --- count-based frontier (saturating) -------------------------------------------------
from sim.clf.verdict import verdict_counts, STARVED_RATIO, FRONTIER_SATURATION


def test_counts_preserve_blackhole_meaning():
    """BLACKHOLE must still mean exactly 'source committed, nothing arrived'.

    Results decided under the presence-bit encoding stay comparable only if this holds.
    """
    assert verdict_counts(255, 0) is Verdict.BLACKHOLE
    assert verdict_counts(1, 0) is Verdict.BLACKHOLE
    assert verdict_counts(0, 0) is Verdict.IDLE          # no source evidence, never faulty


def test_single_stray_arrival_is_not_health():
    """The defect this encoding exists to remove.

    On silicon a total blackhole read HEALTHY while the injector discarded 401 packets,
    because one stray background packet set the presence bit. With counts that state is
    STARVED, which is a report rather than a silence.
    """
    assert verdict_counts(255, 1) is Verdict.STARVED
    assert verdict_counts(400 % 256 or 255, 1) is not Verdict.HEALTHY


def test_saturation_only_blurs_the_unambiguous_end():
    """Both registers saturate at 255, and that must cost nothing where it matters.

    If RX has saturated the link is carrying traffic and cannot be starved, so the ratio
    is only consulted while RX is small -- exactly the regime the rule decides.
    """
    assert verdict_counts(FRONTIER_SATURATION, FRONTIER_SATURATION) is Verdict.HEALTHY
    assert verdict_counts(FRONTIER_SATURATION, FRONTIER_SATURATION - 1) is Verdict.HEALTHY


def test_starved_threshold_is_the_declared_ratio():
    tx = 240
    boundary = tx // STARVED_RATIO
    assert verdict_counts(tx, boundary) is Verdict.STARVED
    assert verdict_counts(tx, boundary + 1) is Verdict.HEALTHY


def test_starved_boundary_is_inclusive_at_one_eighth():
    """The implemented Phase A boundary is RX/TX <= 1/8 while unsaturated."""
    assert verdict_counts(64, 8) is Verdict.STARVED
    assert verdict_counts(64, 9) is Verdict.HEALTHY


def test_impossible_still_reported_not_classified():
    assert verdict_counts(0, 7) is Verdict.IMPOSSIBLE


def test_missing_evidence_is_never_faulty():
    assert verdict_counts(255, 0, evidence_complete=False) is Verdict.INCONCLUSIVE


def test_gap_evidence_still_yields_partial_loss():
    assert verdict_counts(255, 255, gap_seen=True) is Verdict.PARTIAL_LOSS
