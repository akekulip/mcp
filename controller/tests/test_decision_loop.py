import random
import unittest

from controller.absolute_eprocess import log_spaced_alternatives
from controller.decision_loop import FleetDecisionLoop


def make_loop(**overrides):
    config = {
        "alpha": 0.05,
        "alternatives": log_spaced_alternatives(1e-3, 0.5, count=12),
        "restoration_alternatives": log_spaced_alternatives(1e-5, 1e-3, count=8),
        "floor_window_epochs": 20,
        "w_min": 0.05,
    }
    config.update(overrides)
    return FleetDecisionLoop(**config)


class FleetDecisionLoopTest(unittest.TestCase):
    def test_all_clean_fleet_stays_at_full_weight(self):
        loop = make_loop()
        rng = random.Random(1)
        sublinks = [2, 6, 10, 14]
        for epoch in range(30):
            snapshots = {}
            for sublink in sublinks:
                tx = 100
                rx = sum(1 for _ in range(tx) if rng.random() >= 1e-4)
                snapshots[sublink] = (tx, rx)
            decisions = loop.tick(epoch, snapshots)
        for decision in decisions.values():
            self.assertAlmostEqual(decision.weight, 1.0, places=2)
            self.assertFalse(decision.fleet_rejected)

    def test_a_single_bad_sublink_is_detected_and_weight_is_cut(self):
        loop = make_loop()
        rng = random.Random(2)
        sublinks = [2, 6, 10, 14]
        bad = 10
        last_decisions = None
        for epoch in range(200):
            snapshots = {}
            for sublink in sublinks:
                tx = 100
                rate = 5e-2 if sublink == bad else 1e-4
                rx = sum(1 for _ in range(tx) if rng.random() >= rate)
                snapshots[sublink] = (tx, rx)
            last_decisions = loop.tick(epoch, snapshots)
            if last_decisions[bad].weight < 0.9:
                break
        self.assertLess(last_decisions[bad].weight, 0.9)
        # a genuinely bad link's own suffering does not inflate the floor used
        # for its healthy siblings, so their weight should stay well above
        # the bad sublink's -- occasional weak, chance evidence on a healthy
        # sibling is expected (that is what alpha allows) and only nudges
        # weight down slightly, never anywhere near the bad sublink's cut
        for sublink in sublinks:
            if sublink != bad:
                self.assertGreater(last_decisions[sublink].weight, 0.6)
                self.assertGreater(last_decisions[sublink].weight,
                                   last_decisions[bad].weight)

    def test_fleet_rejection_flags_only_the_bad_sublink(self):
        loop = make_loop()
        rng = random.Random(3)
        sublinks = list(range(20))
        bad = 5
        decisions = None
        for epoch in range(300):
            snapshots = {}
            for sublink in sublinks:
                tx = 100
                rate = 8e-2 if sublink == bad else 1e-4
                rx = sum(1 for _ in range(tx) if rng.random() >= rate)
                snapshots[sublink] = (tx, rx)
            decisions = loop.tick(epoch, snapshots)
            if decisions[bad].fleet_rejected:
                break
        self.assertTrue(decisions[bad].fleet_rejected)
        for sublink in sublinks:
            if sublink != bad:
                self.assertFalse(decisions[sublink].fleet_rejected)

    def test_weight_never_drops_below_w_min(self):
        loop = make_loop(w_min=0.1)
        rng = random.Random(4)
        decisions = None
        for epoch in range(400):
            tx = 100
            rx = sum(1 for _ in range(tx) if rng.random() >= 0.3)  # very bad link
            decisions = loop.tick(epoch, {2: (tx, rx)})
        self.assertGreaterEqual(decisions[2].weight, 0.1 - 1e-9)

    def test_a_recovered_link_is_restored_to_full_weight(self):
        loop = make_loop()
        rng = random.Random(5)
        decisions = None
        epoch = 0
        # degrade the link until it is under mitigation
        while epoch < 300:
            tx = 100
            rx = sum(1 for _ in range(tx) if rng.random() >= 0.05)
            decisions = loop.tick(epoch, {2: (tx, rx)})
            epoch += 1
            if decisions[2].weight < 0.5:
                break
        self.assertLess(decisions[2].weight, 0.5)
        # now feed healthy traffic and expect restoration
        recovered = False
        for _ in range(300):
            tx = 100
            rx = sum(1 for _ in range(tx) if rng.random() >= 1e-5)
            decisions = loop.tick(epoch, {2: (tx, rx)})
            epoch += 1
            if not decisions[2].restoring and decisions[2].weight >= 0.999:
                recovered = True
                break
        self.assertTrue(recovered)

    def test_snapshots_may_add_new_sublinks_over_time(self):
        loop = make_loop()
        decisions = loop.tick(0, {2: (100, 100)})
        self.assertIn(2, decisions)
        decisions = loop.tick(1, {2: (100, 100), 6: (100, 100)})
        self.assertIn(6, decisions)


if __name__ == "__main__":
    unittest.main()
