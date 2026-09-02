import unittest

from controller.floor_estimator import FleetFloorEstimator


class FleetFloorEstimatorTest(unittest.TestCase):
    def test_cold_start_returns_min_floor(self):
        estimator = FleetFloorEstimator(window_epochs=10, min_floor=1e-5)
        self.assertEqual(estimator.floor_for(2), 1e-5)

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

    def test_pools_across_multiple_healthy_siblings(self):
        estimator = FleetFloorEstimator(window_epochs=10, min_floor=1e-6)
        estimator.record_epoch(6, epoch=0, tx=1000, rx=999, healthy=True)
        estimator.record_epoch(10, epoch=0, tx=1000, rx=998, healthy=True)
        floor = estimator.floor_for(2)
        self.assertAlmostEqual(floor, 3.0 / 2000.0, places=6)

    def test_window_trims_epochs_older_than_the_window(self):
        estimator = FleetFloorEstimator(window_epochs=2, min_floor=1e-6)
        estimator.record_epoch(6, epoch=0, tx=1000, rx=0, healthy=True)  # 100% loss, old
        estimator.record_epoch(6, epoch=1, tx=1000, rx=999, healthy=True)
        estimator.record_epoch(6, epoch=2, tx=1000, rx=999, healthy=True)
        floor = estimator.floor_for(2)
        # epoch 0 has fallen out of the 2-epoch window; only epochs 1 and 2 remain
        self.assertAlmostEqual(floor, 2.0 / 2000.0, places=6)

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
