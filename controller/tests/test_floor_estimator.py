import unittest

from controller.floor_estimator import FleetFloorEstimator


class FleetFloorEstimatorTest(unittest.TestCase):
    def test_cold_start_returns_none(self):
        estimator = FleetFloorEstimator(window_epochs=10, min_floor=1e-5)
        self.assertIsNone(estimator.floor_for(2))

    def test_excludes_the_sublink_itself(self):
        estimator = FleetFloorEstimator(window_epochs=10, min_floor=1e-6)
        estimator.record_epoch(2, epoch=0, tx=1000, rx=500, healthy=True)  # 50% loss
        estimator.record_epoch(6, epoch=0, tx=1000, rx=999, healthy=True)  # 0.1% loss
        floor = estimator.floor_for(2)
        self.assertAlmostEqual(floor, 0.001, places=6)

    def test_excludes_unhealthy_siblings(self):
        estimator = FleetFloorEstimator(window_epochs=10, min_floor=1e-6)
        estimator.record_epoch(6, epoch=0, tx=1000, rx=999, healthy=True)   # clean
        estimator.record_epoch(10, epoch=0, tx=1000, rx=500, healthy=False)  # quarantined, bad
        floor = estimator.floor_for(2)
        self.assertAlmostEqual(floor, 0.001, places=6)

    def test_returns_none_when_every_sibling_is_unhealthy(self):
        estimator = FleetFloorEstimator(window_epochs=10, min_floor=1e-6)
        estimator.record_epoch(6, epoch=0, tx=1000, rx=500, healthy=False)
        estimator.record_epoch(10, epoch=0, tx=1000, rx=500, healthy=False)
        self.assertIsNone(estimator.floor_for(2))

    def test_pools_across_multiple_healthy_siblings(self):
        estimator = FleetFloorEstimator(window_epochs=10, min_floor=1e-6)
        estimator.record_epoch(6, epoch=0, tx=1000, rx=999, healthy=True)
        estimator.record_epoch(10, epoch=0, tx=1000, rx=998, healthy=True)
        floor = estimator.floor_for(2)
        self.assertAlmostEqual(floor, 3.0 / 2000.0, places=6)

    def test_window_prunes_by_epoch_age_not_call_count(self):
        estimator = FleetFloorEstimator(window_epochs=2, min_floor=1e-6)
        estimator.record_epoch(6, epoch=0, tx=1000, rx=0, healthy=True)   # 100% loss, old
        estimator.record_epoch(6, epoch=1, tx=1000, rx=999, healthy=True)
        estimator.record_epoch(6, epoch=2, tx=1000, rx=999, healthy=True)
        # epoch 0 is now older than (current epoch 2) - (window 2) = epoch 0, so it
        # is pruned; a sublink reporting on a different epoch cadence still ages
        # out correctly because pruning keys off the stored epoch, not the count
        # of calls made so far.
        floor = estimator.floor_for(2)
        self.assertAlmostEqual(floor, 2.0 / 2000.0, places=6)

    def test_a_sublink_that_stops_reporting_still_ages_out_of_the_pool(self):
        estimator = FleetFloorEstimator(window_epochs=2, min_floor=1e-6)
        estimator.record_epoch(6, epoch=0, tx=1000, rx=0, healthy=True)  # 100% loss
        # sublink 6 never reports again; sublink 10 keeps advancing the clock
        for epoch in range(1, 5):
            estimator.record_epoch(10, epoch=epoch, tx=1000, rx=999, healthy=True)
        # sublink 6's stale, never-pruned-by-a-later-call-to-itself sample must
        # not poison sublink 2's floor once the fleet clock has moved past it
        floor = estimator.floor_for(2)
        self.assertAlmostEqual(floor, 1.0 / 1000.0, places=6)

    def test_estimate_is_clamped_below_one(self):
        estimator = FleetFloorEstimator(window_epochs=10, min_floor=1e-6)
        estimator.record_epoch(6, epoch=0, tx=100, rx=0, healthy=True)
        floor = estimator.floor_for(2)
        self.assertLess(floor, 1.0)

    def test_rejects_rx_greater_than_tx(self):
        estimator = FleetFloorEstimator(window_epochs=10)
        with self.assertRaises(ValueError):
            estimator.record_epoch(2, epoch=0, tx=10, rx=11, healthy=True)

    def test_rejects_non_positive_window(self):
        with self.assertRaises(ValueError):
            FleetFloorEstimator(window_epochs=0)

    def test_rejects_min_floor_out_of_range(self):
        with self.assertRaises(ValueError):
            FleetFloorEstimator(window_epochs=5, min_floor=1.0)


if __name__ == "__main__":
    unittest.main()
