import unittest

from sim.sublink_capacity import (
    POLICIES,
    Policy,
    SizeSchema,
    class_selective_scenario,
    full_direction_scenario,
    misaligned_size_scenario,
    no_fault_scenario,
    run_scenario,
    size_aligned_scenario,
)


class BehavioralSublinkCapacityTest(unittest.TestCase):
    def setUp(self):
        self.schema = SizeSchema()

    def results(self, scenario, alternate_headroom=0.0):
        return {
            policy: run_scenario(scenario, policy, self.schema, alternate_headroom)
            for policy in POLICIES
        }

    def assert_equal_safety(self, results):
        for policy, result in results.items():
            self.assertEqual(result.unsafe_primary_bytes, 0, policy)

    def test_aligned_fault_retains_safe_forward_context_and_ties_oracle(self):
        results = self.results(size_aligned_scenario(affected_forward_fraction=0.5))
        self.assert_equal_safety(results)
        self.assertAlmostEqual(results[Policy.PHYSICAL].safe_delivery_fraction, 0.0)
        self.assertAlmostEqual(results[Policy.DIRECTED_W4].safe_delivery_fraction, 0.5)
        self.assertAlmostEqual(results[Policy.WITNESS_STOP].safe_delivery_fraction, 0.5)
        self.assertAlmostEqual(results[Policy.CW4_SIZE].safe_delivery_fraction, 0.75)
        self.assertEqual(results[Policy.CW4_SIZE], results[Policy.ORACLE])

    def test_policy_order_holds_across_frozen_sweep(self):
        for affected in (0.10, 0.25, 0.50, 0.75, 0.90):
            for headroom in (0.0, 0.10, 0.25, 0.50):
                results = self.results(size_aligned_scenario(affected), headroom)
                self.assert_equal_safety(results)
                physical = results[Policy.PHYSICAL].safe_delivery_fraction
                directed = results[Policy.DIRECTED_W4].safe_delivery_fraction
                witness = results[Policy.WITNESS_STOP].safe_delivery_fraction
                cw4 = results[Policy.CW4_SIZE].safe_delivery_fraction
                oracle = results[Policy.ORACLE].safe_delivery_fraction
                self.assertLessEqual(physical, directed)
                self.assertEqual(directed, witness)
                self.assertLessEqual(directed, cw4)
                self.assertLessEqual(cw4, oracle)

    def test_cw4_uses_less_detour_when_the_faulty_share_is_small(self):
        results = self.results(size_aligned_scenario(0.10), alternate_headroom=0.25)
        self.assertEqual(results[Policy.CW4_SIZE].safe_delivery_fraction, 1.0)
        self.assertLess(results[Policy.CW4_SIZE].alternate_bytes,
                        results[Policy.DIRECTED_W4].alternate_bytes)
        self.assertLess(results[Policy.CW4_SIZE].healthy_primary_quarantined_bytes,
                        results[Policy.DIRECTED_W4].healthy_primary_quarantined_bytes)

    def test_misaligned_boundary_exposes_granularity_cost(self):
        results = self.results(misaligned_size_scenario())
        self.assert_equal_safety(results)
        self.assertEqual(results[Policy.CW4_SIZE].safe_delivery_fraction, 0.5)
        self.assertEqual(results[Policy.ORACLE].safe_delivery_fraction, 0.75)
        self.assertGreater(results[Policy.CW4_SIZE].healthy_primary_quarantined_bytes, 0)

    def test_size_only_cw4_cannot_claim_class_isolation(self):
        results = self.results(class_selective_scenario())
        self.assert_equal_safety(results)
        self.assertEqual(results[Policy.CW4_SIZE], results[Policy.DIRECTED_W4])
        self.assertGreater(results[Policy.ORACLE].safe_delivery_fraction,
                           results[Policy.CW4_SIZE].safe_delivery_fraction)

    def test_controls_do_not_create_a_false_advantage(self):
        no_fault = self.results(no_fault_scenario())
        self.assertTrue(all(r.safe_delivery_fraction == 1.0 for r in no_fault.values()))
        whole_direction = self.results(full_direction_scenario())
        self.assertEqual(whole_direction[Policy.CW4_SIZE],
                         whole_direction[Policy.DIRECTED_W4])


if __name__ == "__main__":
    unittest.main()
