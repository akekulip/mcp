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
