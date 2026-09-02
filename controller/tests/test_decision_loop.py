import random
import unittest

from controller.decision_loop import FleetDecisionLoop


def make_loop(**overrides):
    config = {
        "alpha": 0.05,
        "ratios": (2.0, 5.0, 10.0, 50.0, 200.0),
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
        for _ in range(600):
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
        # pool is empty. With 100% of the fleet mitigated we are deep in an
        # incident regime (Q3), so it gets the frozen historical baseline as
        # a fallback floor instead of pure censoring -- the point of Q3 is
        # exactly to avoid the old permanent-censoring deadlock. Either way,
        # genuinely clean traffic must never be falsely flagged.
        healthy_false_alarms = 0
        for epoch in range(epoch + 1, epoch + 6):
            snapshots = {s: (300, 300 - sum(1 for _ in range(300) if rng.random() < 0.3))
                        for s in sublinks}
            tx = 200
            rx = tx - sum(1 for _ in range(tx) if rng.random() < 1e-4)  # genuinely clean
            snapshots[2] = (tx, rx)
            decisions = loop.tick(epoch, snapshots)
            self.assertTrue(decisions[2].censored or decisions[2].incident_fallback)
            if decisions[2].fleet_rejected:
                healthy_false_alarms += 1
        self.assertEqual(healthy_false_alarms, 0)

    def test_baseline_decay_does_not_shrink_with_fleet_size(self):
        # round-4 HIGH 2: the baseline's decay used to be applied once PER
        # SUBLINK inside the per-epoch loop, so its effective memory shrank
        # with fleet size instead of staying "much slower than the live
        # floor window" regardless of scale. A 4-sublink and a 16-sublink
        # fleet fed the SAME per-sublink clean traffic for the same number
        # of epochs must reach the same baseline estimate.
        def final_baseline(num_sublinks, epochs=50):
            loop = make_loop(baseline_decay=0.9)
            for epoch in range(epochs):
                snapshots = {s: (100, 99) for s in range(num_sublinks)}
                loop.tick(epoch, snapshots)
            return loop._baseline_floor()

        small = final_baseline(4)
        large = final_baseline(16)
        self.assertIsNotNone(small)
        self.assertIsNotNone(large)
        self.assertAlmostEqual(small, large, places=6)

    def test_baseline_floor_is_clamped_never_exactly_zero_or_one(self):
        # round-4 finding: an unclamped baseline of exactly 0.0 or 1.0
        # crashes FleetRatioEProcess.ingest ("floor must lie in (0, 1)").
        loop = make_loop()
        for epoch in range(30):  # zero loss every epoch -> raw estimate is 0.0
            loop.tick(epoch, {2: (100, 100), 6: (100, 100)})
        baseline = loop._baseline_floor()
        self.assertIsNotNone(baseline)
        self.assertGreater(baseline, 0.0)
        self.assertLess(baseline, 1.0)

    def test_floor_is_previsible_not_leaked_from_a_siblings_same_epoch_shock(self):
        # CRITICAL 2, deterministic: a sibling's shock THIS epoch must not
        # enter the floor used to judge another sublink THIS SAME epoch.
        # Two sublinks, a single ratio (5.0) for a hand-checkable mixture, no
        # randomness. With the previsible floor at 0.1 (below), the realized
        # alternative is floor*ratio = 0.5, matching the pre-Q1 pin exactly.
        loop = make_loop(alpha=0.05, ratios=(5.0,),
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

    def test_restoration_grid_is_rebuilt_from_the_current_floor_each_call(self):
        # Direct regression for round-3 CRITICAL B / round-4's mutant-testing
        # finding: a full revert of _restoration_grid's floor-coupling (using
        # a fixed value instead of `current_floor`) passed the entire suite
        # undetected before this test existed. The grid must track whatever
        # floor is handed to it, not a value fixed at construction.
        loop = make_loop(restoration_grid_low=1e-8, restoration_grid_count=4)
        grid_low_floor = loop._restoration_grid(1e-4)
        grid_high_floor = loop._restoration_grid(1e-2)
        self.assertIsNotNone(grid_low_floor)
        self.assertIsNotNone(grid_high_floor)
        self.assertNotEqual(grid_low_floor, grid_high_floor)
        self.assertLessEqual(max(grid_low_floor), 1e-4 * (1 + 1e-9))
        self.assertLessEqual(max(grid_high_floor), 1e-2 * (1 + 1e-9))
        self.assertGreater(max(grid_high_floor), max(grid_low_floor))

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

    # --- end-to-end regressions for the redesign proposal
    # (docs/review/artifacts/STATS-LAYER-REDESIGN-PROPOSAL-2026-09-02.md)
    # implemented after the round-3 review found a permanent, fleet-wide
    # absorbing deadlock and a restoration action rate of 0/8. ---

    def _run_single_fault_fleet(self, seed, degraded_rate, horizon, num_sublinks=16,
                                fault_end=200):
        # round-4 review: a "weight >= 0.999 and not restoring" check alone
        # cannot distinguish a genuine restoration from "arming never
        # happened at all" or a premature restore -- it only measures what
        # its name says when checked alongside repair_generation, and only
        # after the fault window has actually closed.
        loop = make_loop(ratios=(2.0, 5.0, 10.0, 50.0, 200.0))
        rng = random.Random(seed)
        sublinks = list(range(num_sublinks))
        bad = 0
        max_mitigated = 0
        recovered_at = None
        premature_repair_epoch = None
        last_decisions = None
        for epoch in range(horizon):
            snapshots = {}
            for sublink in sublinks:
                tx = 200
                rate = degraded_rate if (sublink == bad and 100 <= epoch < fault_end) else 1e-3
                rx = sum(1 for _ in range(tx) if rng.random() >= rate)
                snapshots[sublink] = (tx, rx)
            decisions = loop.tick(epoch, snapshots)
            last_decisions = decisions
            state = loop._states[bad]
            max_mitigated = max(max_mitigated,
                                sum(1 for d in decisions.values() if d.weight < 1.0))
            if (premature_repair_epoch is None and 100 <= epoch < fault_end and
                    state.repair_generation > 0):
                premature_repair_epoch = epoch
            if (recovered_at is None and epoch >= fault_end and
                    state.repair_generation > 0 and decisions[bad].weight >= 0.999 and
                    not decisions[bad].restoring):
                recovered_at = epoch
        return max_mitigated, recovered_at, premature_repair_epoch, last_decisions

    def test_a_single_fault_does_not_cascade_into_a_fleet_wide_deadlock(self):
        # The round-3 CRITICAL 1 scenario exactly: one link degraded for 100
        # epochs on a 16-sublink fleet. Previously this measured 15/16
        # sublinks mitigated by epoch 2500 and still 100% mitigated at epoch
        # 4999 (4800 epochs after the fault's own 100-epoch window closed).
        # "max_mitigated" here is the peak SIMULTANEOUS count in any one
        # epoch, not a claim that no other sublink is EVER individually
        # mitigated across the whole run at a different time.
        max_mitigated, recovered_at, premature, decisions = self._run_single_fault_fleet(
            seed=42, degraded_rate=0.20, horizon=5000)
        self.assertEqual(max_mitigated, 1)  # only the genuinely bad link, ever, at once
        self.assertIsNotNone(recovered_at)
        self.assertIsNone(premature)
        self.assertEqual(sum(1 for d in decisions.values() if d.weight < 1.0), 0)

    def test_restoration_action_rate_meets_the_design_target(self):
        # brainstorm H2/H3: action rate >= 0.9 per repaired fault. Previously
        # measured 0/8 at both of these exact degraded rates. Reported next
        # to the premature-restoration (safety) rate over the SAME trials,
        # not in isolation -- a usefulness number without its safety number
        # beside it is not a complete report (repo CLAUDE.md cross-check
        # rule 4; round-4 review's own HIGH 1 finding).
        for rate in (0.20, 0.05):
            results = [self._run_single_fault_fleet(seed, rate, horizon=3000)
                      for seed in range(8)]
            action_rate = sum(1 for _, recovered, _, _ in results if recovered is not None) / 8
            premature_rate = sum(1 for _, _, premature, _ in results
                                 if premature is not None) / 8
            self.assertGreaterEqual(
                action_rate, 0.9,
                f"rate={rate}: action_rate={action_rate:.2f}, "
                f"premature_restoration_rate={premature_rate:.2f}")
            self.assertEqual(
                premature_rate, 0.0,
                f"rate={rate}: action_rate={action_rate:.2f}, "
                f"premature_restoration_rate={premature_rate:.2f}")


if __name__ == "__main__":
    unittest.main()
