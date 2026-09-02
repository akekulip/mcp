import random
import unittest

from controller.absolute_eprocess import log_spaced_alternatives
from controller.decision_loop import FleetDecisionLoop


def make_loop(**overrides):
    config = {
        "alpha": 0.05,
        "alternatives": log_spaced_alternatives(1e-3, 0.5, count=12),
        "restoration_grid_low": 1e-8,
        "restoration_grid_count": 8,
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
        # a single-sublink fleet has no leave-one-out pool at all and is
        # correctly always censored (CRITICAL 1's fix) -- give it healthy
        # siblings so a real floor exists and the bad link can be judged.
        loop = make_loop(w_min=0.1)
        rng = random.Random(4)
        decisions = None
        for epoch in range(400):
            snapshots = {}
            for sublink in (6, 10, 14):
                tx = 100
                rx = sum(1 for _ in range(tx) if rng.random() >= 1e-4)
                snapshots[sublink] = (tx, rx)
            tx = 100
            rx = sum(1 for _ in range(tx) if rng.random() >= 0.3)  # very bad link
            snapshots[2] = (tx, rx)
            decisions = loop.tick(epoch, snapshots)
        self.assertGreaterEqual(decisions[2].weight, 0.1 - 1e-9)
        self.assertLess(decisions[2].weight, 0.5)

    def test_a_recovered_link_is_restored_to_full_weight(self):
        loop = make_loop()
        rng = random.Random(5)
        decisions = None
        epoch = 0

        def tick_with_siblings(rate):
            snapshots = {}
            for sublink in (6, 10, 14):
                tx = 100
                rx = sum(1 for _ in range(tx) if rng.random() >= 1e-5)
                snapshots[sublink] = (tx, rx)
            tx = 100
            rx = sum(1 for _ in range(tx) if rng.random() >= rate)
            snapshots[2] = (tx, rx)
            return loop.tick(epoch, snapshots)

        # degrade the link until it is under mitigation
        while epoch < 300:
            decisions = tick_with_siblings(0.05)
            epoch += 1
            if decisions[2].weight < 0.5:
                break
        self.assertLess(decisions[2].weight, 0.5)
        # now feed healthy traffic and expect restoration
        recovered = False
        for _ in range(400):
            decisions = tick_with_siblings(1e-5)
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

    # --- regression tests for the CRITICAL findings in
    # docs/review/artifacts/STATS-LAYER-REVIEW-2026-09-02.md ---

    def test_a_single_sublink_fleet_is_censored_not_falsely_rejected(self):
        # CRITICAL 1: an empty leave-one-out pool must never fall back to a
        # numeric floor -- it must be censored. Previously this configuration
        # measured 200/200 false alarms on a healthy fleet.
        loop = make_loop()
        rng = random.Random(11)
        decisions = None
        for epoch in range(200):
            tx = 100
            rx = sum(1 for _ in range(tx) if rng.random() >= 2e-3)
            decisions = loop.tick(epoch, {2: (tx, rx)})
            self.assertTrue(decisions[2].censored)
        self.assertFalse(decisions[2].fleet_rejected)
        self.assertAlmostEqual(decisions[2].weight, 1.0)

    def test_all_siblings_under_mitigation_censors_rather_than_false_alarms(self):
        # CRITICAL 1: when every sibling is currently unhealthy, the pool for
        # a newly-arriving healthy sublink is empty and must censor, not
        # substitute min_floor. Previously measured 195/200 false alarms.
        #
        # Simultaneous, EQUAL degradation of every comparison sublink is not
        # individually detectable by a leave-one-out design (none look
        # anomalous relative to the others -- a known, disclosed limitation,
        # not this test's target). To reach "all under mitigation" instead,
        # establish real clean history first so the floor lags behind a
        # sudden, strong joint jump for the ~window_epochs it takes to
        # ingest new samples -- exactly the regime this fix must still
        # detect correctly in.
        loop = make_loop()
        rng = random.Random(12)
        sublinks = [6, 10, 14]
        decisions = None
        for epoch in range(30):  # clean warm-up, builds real floor history
            snapshots = {s: (200, 200 - sum(1 for _ in range(200) if rng.random() < 1e-4))
                        for s in sublinks}
            decisions = loop.tick(epoch, snapshots)
        for epoch in range(30, 60):  # sudden, strong, simultaneous jump
            snapshots = {s: (300, 300 - sum(1 for _ in range(300) if rng.random() < 0.3))
                        for s in sublinks}
            decisions = loop.tick(epoch, snapshots)
            if all(decisions[s].weight < 1.0 for s in sublinks):
                break
        self.assertTrue(all(decisions[s].weight < 1.0 for s in sublinks))
        # keep them unhealthy for a full floor window so every stale
        # healthy=True sample from the warm-up period (still valid evidence
        # of what healthy looked like, correctly not purged early) ages out
        # -- the pool is only truly empty once the whole trailing window is
        # unhealthy, not on the first tick weight dips below one.
        for epoch in range(epoch + 1, epoch + 1 + 20):
            snapshots = {s: (300, 300 - sum(1 for _ in range(300) if rng.random() < 0.3))
                        for s in sublinks}
            decisions = loop.tick(epoch, snapshots)
        # now a brand-new, actually healthy sublink joins while every
        # existing sublink is still marked unhealthy -- its leave-one-out
        # pool is empty and must censor rather than false-alarm
        healthy_false_alarms = 0
        for epoch in range(epoch + 1, epoch + 6):
            snapshots = {s: (300, 300 - sum(1 for _ in range(300) if rng.random() < 0.3))
                        for s in sublinks}
            tx = 200
            rx = tx - sum(1 for _ in range(tx) if rng.random() < 1e-4)  # genuinely clean
            snapshots[2] = (tx, rx)
            decisions = loop.tick(epoch, snapshots)
            self.assertTrue(decisions[2].censored)
            if decisions[2].fleet_rejected:
                healthy_false_alarms += 1
        self.assertEqual(healthy_false_alarms, 0)

    def test_floor_is_previsible_not_leaked_from_a_siblings_same_epoch_shock(self):
        # CRITICAL 2, deterministic: a sibling's shock THIS epoch must not
        # enter the floor used to judge another sublink THIS SAME epoch.
        # Two sublinks, a single fixed alternative (0.5) for a hand-checkable
        # mixture, no randomness.
        loop = make_loop(alpha=0.05, alternatives=(0.5,),
                        restoration_grid_low=1e-6, restoration_grid_count=1,
                        floor_window_epochs=20)
        # epoch 0: both sublinks report identically; both pools are empty
        # (leave-one-out excludes the only other sublink's not-yet-recorded
        # data) so both must be censored.
        decisions = loop.tick(0, {2: (100, 90), 6: (100, 90)})
        self.assertTrue(decisions[2].censored)
        self.assertTrue(decisions[6].censored)

        # epoch 1: sublink 2 has zero loss; sublink 6 takes a big, sudden
        # shock (rate 0.5) THIS epoch. Sublink 2's floor at epoch 1 must come
        # from sublink 6's epoch-0 sample ONLY (lost=10/tx=100 -> floor=0.1),
        # never from sublink 6's epoch-1 shock.
        decisions = loop.tick(1, {2: (100, 100), 6: (100, 50)})
        self.assertFalse(decisions[2].censored)

        import math
        correct_log_lr = 100 * math.log(0.5 / (1.0 - 0.1))   # previsible floor = 0.1
        leaked_log_lr = 100 * math.log(0.5 / (1.0 - 0.3))    # what a leak would use
        self.assertAlmostEqual(math.log(decisions[2].wealth), correct_log_lr, places=6)
        self.assertNotAlmostEqual(math.log(decisions[2].wealth), leaked_log_lr, places=2)

    def test_restoration_never_arms_unrestorable(self):
        # arm() now rejects a suspect_rate at or below every healthy
        # alternative, decision_loop only calls arm() with a previsible,
        # windowed rate estimate, and the grid tracks the current floor -- so
        # 500 epochs of a persistently bad link (it never actually recovers
        # here, so its restoration wealth correctly decaying toward zero is
        # the RIGHT behaviour, not a bug) must still arm without raising, and
        # a genuinely recovering link (separately covered by
        # test_a_recovered_link_is_restored_to_full_weight) must be able to
        # actually cross back to full weight -- not "no exception" alone,
        # which a permanently-stuck sequence would also satisfy.
        loop = make_loop()
        rng = random.Random(14)
        for epoch in range(500):
            snapshots = {}
            for sublink in (6, 10, 14):
                tx = 100
                rx = sum(1 for _ in range(tx) if rng.random() >= 1e-5)
                snapshots[sublink] = (tx, rx)
            tx = 100
            rx = sum(1 for _ in range(tx) if rng.random() >= 0.05)
            snapshots[2] = (tx, rx)
            loop.tick(epoch, snapshots)  # must not raise
        state = loop._states[2]
        self.assertTrue(state.restoration.armed)

    def test_a_permanently_blackholed_sublink_does_not_crash_the_loop(self):
        # CRITICAL A: a sublink with rx=0 for its entire recorded history
        # produces a raw suspect-rate ratio of exactly 1.0 once it becomes
        # eligible to arm restoration -- this used to raise uncaught and
        # permanently wedge tick().
        loop = make_loop()
        for epoch in range(10):
            snapshots = {
                6: (1000, 998), 10: (1000, 997), 14: (1000, 999),
                2: (1000, 0),  # fully blackholed from epoch 0
            }
            decisions = loop.tick(epoch, snapshots)  # must not raise
        self.assertIn(2, decisions)


if __name__ == "__main__":
    unittest.main()
