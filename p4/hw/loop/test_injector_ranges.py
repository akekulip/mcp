import unittest

from injector_ranges import modular_drop_ranges


class TestModularDropRanges(unittest.TestCase):
    def test_contiguous_range_starts_after_two_safe_packets(self):
        self.assertEqual(modular_drop_ranges(100, 5), ((103, 107),))

    def test_wrapped_range_splits_without_losing_or_duplicating_sequences(self):
        self.assertEqual(
            modular_drop_ranges(65530, 10),
            ((65533, 65535), (0, 6)))

    def test_full_sequence_space_is_one_range(self):
        self.assertEqual(modular_drop_ranges(9, 65536), ((0, 65535),))

    def test_invalid_drop_count_is_rejected(self):
        for count in (0, -1, 65537):
            with self.subTest(count=count), self.assertRaises(ValueError):
                modular_drop_ranges(0, count)


if __name__ == "__main__":
    unittest.main()
