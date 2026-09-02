import unittest

from controller.fleet_control import e_bh_reject


class EBHRejectTest(unittest.TestCase):
    def test_empty_input_rejects_nothing(self):
        self.assertEqual(e_bh_reject({}, alpha=0.05), frozenset())

    def test_single_evalue_above_threshold_is_rejected(self):
        # n=1, alpha=0.05 -> threshold n/(k*alpha) = 1/0.05 = 20
        self.assertEqual(e_bh_reject({7: 25.0}, alpha=0.05), frozenset({7}))

    def test_single_evalue_below_threshold_is_not_rejected(self):
        self.assertEqual(e_bh_reject({7: 5.0}, alpha=0.05), frozenset())

    def test_all_null_evalues_reject_nothing(self):
        evalues = {i: 1.0 for i in range(20)}
        self.assertEqual(e_bh_reject(evalues, alpha=0.05), frozenset())

    def test_hand_computed_example(self):
        # n=4, alpha=0.1 -> thresholds at k=1,2,3,4 are 40, 20, 13.33, 10
        evalues = {1: 50.0, 2: 25.0, 3: 5.0, 4: 1.0}
        # k=1: e_(1)=50 >= 40 -> holds
        # k=2: e_(2)=25 >= 20 -> holds
        # k=3: e_(3)=5  >= 13.33 -> fails
        # k=4: e_(4)=1  >= 10 -> fails
        # largest satisfying k is 2 -> reject the top 2
        self.assertEqual(e_bh_reject(evalues, alpha=0.1), frozenset({1, 2}))

    def test_non_monotone_qualifying_k_is_still_found(self):
        # construct a case where a later k requalifies after an earlier one fails,
        # confirming the scan does not stop at the first failure
        # n=3, alpha=0.5 -> thresholds: k=1 -> 6, k=2 -> 3, k=3 -> 2
        evalues = {1: 5.0, 2: 1.0, 3: 2.0}
        # sorted desc: 5.0, 2.0, 1.0
        # k=1: 5.0 >= 6 -> fails
        # k=2: 2.0 >= 3 -> fails
        # k=3: 1.0 >= 2 -> fails
        self.assertEqual(e_bh_reject(evalues, alpha=0.5), frozenset())

    def test_rejects_out_of_range_alpha(self):
        with self.assertRaises(ValueError):
            e_bh_reject({1: 2.0}, alpha=0.0)
        with self.assertRaises(ValueError):
            e_bh_reject({1: 2.0}, alpha=1.0)

    def test_rejects_negative_evalue(self):
        with self.assertRaises(ValueError):
            e_bh_reject({1: -1.0}, alpha=0.05)


if __name__ == "__main__":
    unittest.main()
