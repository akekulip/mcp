import itertools
import math
import unittest

from controller.evidence_ledger import (
    CensorReason,
    EpochRecord,
    ReceiptStatus,
    SequentialEvidenceLedger,
    Verdict,
)


class SequentialEvidenceLedgerTest(unittest.TestCase):
    def make_ledger(self, **overrides):
        config = {
            "alpha": 0.05,
            "healthy_delivery": 0.99,
            "alternatives": (0.10, 0.50, 0.90, 0.97),
            "saturation": 255,
        }
        config.update(overrides)
        return SequentialEvidenceLedger(**config)

    def record(self, epoch, tx, rx, **overrides):
        values = {
            "sublink": 2,
            "epoch": epoch,
            "tx": tx,
            "rx": rx,
            "repair_generation": 0,
        }
        values.update(overrides)
        return EpochRecord(**values)

    def test_exact_positive_tx_zero_rx_is_immediate_blackhole(self):
        result = self.make_ledger().ingest(self.record(0, 1, 0))
        self.assertEqual(result.verdict, Verdict.BLACKHOLE)
        self.assertEqual(result.reason, "positive departures with zero arrivals")

    def test_idle_is_not_a_fault(self):
        result = self.make_ledger().ingest(self.record(0, 0, 0))
        self.assertEqual(result.verdict, Verdict.IDLE)
        self.assertEqual(result.e_value, 1.0)

    def test_impossible_rx_above_tx_invalidates_the_sequence(self):
        ledger = self.make_ledger()
        ledger.ingest(self.record(0, 20, 20))
        result = ledger.ingest(self.record(1, 10, 11))
        self.assertEqual(result.verdict, Verdict.INCONCLUSIVE)
        self.assertEqual(result.censor_reason, CensorReason.IMPOSSIBLE)
        self.assertEqual(result.e_value, 1.0)

    def test_saturation_and_incomplete_evidence_reset_instead_of_becoming_numbers(self):
        for kwargs, reason in (
            ({"tx": 255, "rx": 10}, CensorReason.SATURATED),
            ({"tx": 20, "rx": 10, "censor_reason": CensorReason.INCOMPLETE},
             CensorReason.INCOMPLETE),
            ({"tx": 20, "rx": 10, "receipt_status": ReceiptStatus.INVALID},
             CensorReason.INVALID_RECEIPT),
        ):
            with self.subTest(reason=reason):
                ledger = self.make_ledger()
                ledger.ingest(self.record(0, 20, 19))
                result = ledger.ingest(self.record(1, **kwargs))
                self.assertEqual(result.verdict, Verdict.INCONCLUSIVE)
                self.assertEqual(result.censor_reason, reason)
                self.assertEqual(result.e_value, 1.0)
                self.assertEqual(result.sequence_index, 1)
                self.assertAlmostEqual(result.sequence_alpha, ledger.alpha / 4.0)

    def test_geometric_alpha_spending_bounds_restarts_within_a_repair_generation(self):
        ledger = self.make_ledger(alpha=0.08)
        first = ledger.ingest(self.record(0, 20, 20))
        self.assertEqual(first.sequence_index, 0)
        self.assertAlmostEqual(first.sequence_alpha, 0.04)
        second = ledger.ingest(self.record(
            1, 20, 10, censor_reason=CensorReason.BOUNDARY_RACE))
        self.assertEqual(second.sequence_index, 1)
        self.assertAlmostEqual(second.sequence_alpha, 0.02)

    def test_epoch_gap_resets_and_does_not_score_boundary_raced_record(self):
        ledger = self.make_ledger()
        ledger.ingest(self.record(4, 20, 20))
        result = ledger.ingest(self.record(6, 20, 1))
        self.assertEqual(result.verdict, Verdict.INCONCLUSIVE)
        self.assertEqual(result.censor_reason, CensorReason.EPOCH_GAP)
        self.assertEqual(result.e_value, 1.0)

    def test_stale_or_duplicate_record_cannot_change_capital(self):
        ledger = self.make_ledger()
        first = ledger.ingest(self.record(7, 20, 19))
        stale = ledger.ingest(self.record(7, 20, 0))
        self.assertEqual(stale.verdict, Verdict.INCONCLUSIVE)
        self.assertEqual(stale.censor_reason, CensorReason.STALE)
        self.assertEqual(stale.e_value, first.e_value)

    def test_repair_generation_starts_a_fresh_certificate(self):
        ledger = self.make_ledger()
        old = ledger.ingest(self.record(0, 40, 20))
        fresh = ledger.ingest(self.record(1, 40, 40, repair_generation=1))
        self.assertEqual(fresh.repair_generation, 1)
        self.assertLess(fresh.e_value, 1.0)
        self.assertNotEqual(fresh.e_value, old.e_value)
        stale = ledger.ingest(self.record(2, 40, 0, repair_generation=0))
        self.assertEqual(stale.verdict, Verdict.INCONCLUSIVE)
        self.assertEqual(stale.censor_reason, CensorReason.STALE_GENERATION)

    def test_repeated_gray_loss_crosses_the_preregistered_threshold(self):
        ledger = self.make_ledger()
        result = None
        for epoch in range(20):
            result = ledger.ingest(self.record(epoch, 20, 18))
            if result.verdict is Verdict.GRAYHOLE:
                break
        self.assertIsNotNone(result)
        self.assertEqual(result.verdict, Verdict.GRAYHOLE)
        self.assertGreaterEqual(result.e_value, 1.0 / ledger.alpha)

    def test_healthy_epochs_reduce_or_hold_evidence(self):
        ledger = self.make_ledger()
        values = [ledger.ingest(self.record(epoch, 20, 20)).e_value
                  for epoch in range(10)]
        self.assertTrue(all(value <= 1.0 for value in values))
        self.assertNotIn(Verdict.GRAYHOLE, [
            ledger.ingest(self.record(epoch + 10, 20, 20)).verdict
            for epoch in range(5)
        ])

    def test_fixed_alternative_factor_has_null_expectation_one(self):
        p0 = 0.99
        p1 = 0.90
        for packets in range(1, 9):
            expected = 0.0
            for delivered in range(packets + 1):
                probability = (math.comb(packets, delivered) *
                               p0 ** delivered * (1.0 - p0) ** (packets - delivered))
                factor = ((p1 / p0) ** delivered *
                          ((1.0 - p1) / (1.0 - p0)) ** (packets - delivered))
                expected += probability * factor
            self.assertAlmostEqual(expected, 1.0, places=12)

    def test_optional_stopping_false_alarm_probability_is_bounded(self):
        alpha = 0.20
        p0 = 0.80
        horizon = 8
        alarm_probability = 0.0
        for path in itertools.product((0, 1), repeat=horizon):
            probability = math.prod(p0 if delivered else 1.0 - p0
                                    for delivered in path)
            ledger = SequentialEvidenceLedger(
                alpha=alpha,
                healthy_delivery=p0,
                alternatives=(0.20, 0.50),
                saturation=255,
            )
            alarmed = False
            for epoch, delivered in enumerate(path):
                result = ledger.ingest(EpochRecord(
                    sublink=2,
                    epoch=epoch,
                    tx=1,
                    rx=delivered,
                    repair_generation=0,
                ))
                # The deterministic BLACKHOLE observation is a separate operational
                # verdict, not a sequential-alpha claim.  Only GRAYHOLE spends alpha.
                if result.statistical_alarm:
                    alarmed = True
                    break
            if alarmed:
                alarm_probability += probability
        self.assertLessEqual(alarm_probability, alpha + 1e-12)


if __name__ == "__main__":
    unittest.main()
