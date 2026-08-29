import random
import unittest

from sim.dynamic.transport import DelayLine, Delivery
from sim.gate.replay import scenario_seed


class DelayLineTest(unittest.TestCase):
    def test_zero_tau_delivers_in_the_same_instant(self):
        """tau_us == 0 is the instantaneous-feedback bound, so it must not cost one step."""
        line = DelayLine(0)
        line.send(1000, "event")
        self.assertEqual(line.due(1000), ["event"])
        self.assertEqual(line.pending(), 0)

    def test_nothing_is_delivered_before_its_due_time(self):
        line = DelayLine(2200)
        line.send(0, "a")
        self.assertEqual(line.due(2199), [])
        self.assertEqual(line.pending(), 1)
        self.assertEqual(line.due(2200), ["a"])

    def test_ordering_is_total_and_stable_when_many_items_share_a_due_time(self):
        """Simultaneous items come back in send order; the payload never enters the comparison."""
        line = DelayLine(100)
        for index in range(50):
            line.send(0, {"unorderable": index})   # dicts would raise if compared
        self.assertEqual([item["unorderable"] for item in line.due(100)], list(range(50)))

    def test_ordering_is_by_due_time_then_send_order_under_interleaved_sends(self):
        rng = random.Random(scenario_seed("dynamic_transport", "order"))
        line = DelayLine(500)
        expected = []
        for seq in range(200):
            t_us = rng.choice((0, 0, 0, 100, 100, 250, 250, 250, 900))
            line.send(t_us, seq)
            expected.append((t_us + 500, seq, seq))
        expected.sort()
        self.assertEqual(line.due(10_000), [payload for _, _, payload in expected])

    def test_pending_tracks_in_flight_items_exactly(self):
        line = DelayLine(1000)
        self.assertEqual(line.pending(), 0)
        for index in range(5):
            line.send(index * 400, index)
        self.assertEqual(line.pending(), 5)
        line.due(1000)                              # items sent at 0 only
        self.assertEqual(line.pending(), 4)
        line.due(1_000_000)
        self.assertEqual(line.pending(), 0)

    def test_negative_tau_is_rejected(self):
        with self.assertRaises(ValueError):
            DelayLine(-1)

    def test_two_identical_delay_lines_produce_identical_traces(self):
        rng = random.Random(scenario_seed("dynamic_transport", "determinism"))
        script = [(rng.randrange(0, 5000), rng.randrange(0, 1000)) for _ in range(300)]
        polls = sorted(rng.randrange(0, 8000) for _ in range(40))

        def trace():
            line = DelayLine(2200)
            out = []
            for t_us, payload in script:
                line.send(t_us, payload)
            for t_us in polls:
                out.append((t_us, tuple(line.due(t_us)), line.pending()))
            return out

        self.assertEqual(trace(), trace())

    def test_delivery_identity_is_the_due_time_and_sequence_number(self):
        self.assertLess(Delivery(at_us=5, seq=1, item=None), Delivery(at_us=5, seq=2, item=None))
        self.assertLess(Delivery(at_us=5, seq=9, item=None), Delivery(at_us=6, seq=0, item=None))


if __name__ == "__main__":
    unittest.main()
