"""P3 feedback path: coalescing, epoch/stale handling, flap damping, and the shared pool."""
import unittest

from controller.sublink_feedback import GapEvent, SublinkFeedback, QUARANTINED, HEALTHY


class Recorder:
    def __init__(self):
        self.installed, self.removed = [], []

    def install(self, vlink, ctx, alt):
        self.installed.append((vlink, ctx, alt))

    def remove(self, vlink, ctx):
        self.removed.append((vlink, ctx))


def warm(fb, vlink=20, contexts=(0, 1, 2, 3), epochs=(1, 2, 3), packets=150000):
    """Sibling sublinks carrying production, which is where the background rate comes from."""
    for ctx in contexts:
        for ep in epochs:
            fb.observe_clean(vlink, ctx, packets, ep)


class TestSublinkFeedback(unittest.TestCase):
    def setUp(self):
        self.rec = Recorder()
        self.fb = SublinkFeedback(self.rec.install, self.rec.remove)

    def test_sublink_id_and_loss_decode(self):
        ev = GapEvent(vlink=20, context=3, epoch=1, gap=0xFFFB, observed_packets=1000)
        self.assertEqual(ev.sublink, (20 << 4) | 3)
        self.assertEqual(ev.lost, 5, "a gap of 2^16-5 means five packets vanished")
        self.assertEqual(GapEvent(20, 3, 1, 1, 1000).lost, 0,
                         "a small positive gap is a duplicate or reorder, not loss")

    def test_gap_against_sibling_background_quarantines(self):
        warm(self.fb)
        self.fb.begin_epoch(4)
        act = self.fb.on_gap(GapEvent(20, 3, 4, 0xFFF0, 150000))
        self.assertEqual(act, "QUARANTINE")
        self.assertEqual(self.rec.installed, [(20, 3, 1)])

    def test_healthy_sublink_is_not_quarantined(self):
        warm(self.fb)
        self.fb.begin_epoch(4)
        for ctx in (0, 1, 2, 3):
            self.fb.observe_clean(20, ctx, 150000, 4)
        self.assertEqual(self.rec.installed, [], "clean traffic must never install a quarantine")

    def test_coalescing_one_install_per_sublink_epoch(self):
        warm(self.fb)
        self.fb.begin_epoch(4)
        ev = GapEvent(20, 3, 4, 0xFFF0, 150000)
        self.fb.on_gap(ev)
        for _ in range(5):
            self.assertIsNone(self.fb.on_gap(ev), "further gaps in the same epoch must coalesce")
        self.assertEqual(len(self.rec.installed), 1)
        self.assertEqual(self.fb.summary()["coalesced"], 5)

    def test_stale_event_from_an_earlier_epoch_is_dropped(self):
        warm(self.fb)
        self.fb.begin_epoch(9)
        self.assertIsNone(self.fb.on_gap(GapEvent(20, 3, 4, 0xFFF0, 150000)))
        self.assertEqual(self.rec.installed, [], "an event about a past epoch must not act")
        self.assertEqual(self.fb.summary()["stale_dropped"], 1)

    def test_restore_requires_sustained_clean_evidence(self):
        warm(self.fb)
        self.fb.begin_epoch(4)
        self.fb.on_gap(GapEvent(20, 3, 4, 0xFFF0, 150000))
        self.assertIsNone(self.fb.on_clean_epoch(20, 3), "one clean epoch is not enough")
        self.assertIsNone(self.fb.on_clean_epoch(20, 3))
        self.assertEqual(self.fb.on_clean_epoch(20, 3), "RESTORE")
        self.assertEqual(self.rec.removed, [(20, 3)])

    def test_repeated_quarantine_is_damped(self):
        """A sublink that keeps failing must be held longer each time, or the loop flaps at its
        own frequency — the failure the 20 ms flap-period measurement exposes."""
        warm(self.fb)
        self.fb.begin_epoch(4)
        self.fb.on_gap(GapEvent(20, 3, 4, 0xFFF0, 150000))
        for _ in range(3):
            self.fb.on_clean_epoch(20, 3)
        self.fb.begin_epoch(5)
        self.fb.on_gap(GapEvent(20, 3, 5, 0xFFF0, 150000))
        cleans = 0
        while self.fb.on_clean_epoch(20, 3) != "RESTORE":
            cleans += 1
            self.assertLess(cleans, 20, "damping must still terminate")
        self.assertGreaterEqual(cleans + 1, 6,
                                "a second quarantine must require more clean evidence than the first")

    def test_other_contexts_of_the_same_link_are_untouched(self):
        warm(self.fb)
        self.fb.begin_epoch(4)
        self.fb.on_gap(GapEvent(20, 3, 4, 0xFFF0, 150000))
        installed_contexts = {c for _, c, _ in self.rec.installed}
        self.assertEqual(installed_contexts, {3},
                         "quarantine must name one behavioural sublink, not the whole link")


if __name__ == "__main__":
    unittest.main()
