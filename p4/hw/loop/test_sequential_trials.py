import contextlib
import io
import importlib.util
import pathlib
import sys
import unittest


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))

from controller.evidence_ledger import CensorReason, ReceiptStatus, Verdict

MODULE_PATH = HERE / "sequential_trials.py"
spec = importlib.util.spec_from_file_location("sequential_trials", MODULE_PATH)
sequential_trials = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sequential_trials)


GOOD_BUILD_ID = "a" * 64
GOOD_RUNTIME_ID = "b" * 64
GOOD_IDENTITY = "IDENTITY mcp_fabric_clf_eg %s %s 123\n" % (
    GOOD_BUILD_ID, GOOD_RUNTIME_ID)


class FakeGate:
    def __init__(self, replies):
        self.replies = list(replies)
        self.commands = []

    def request(self, command, timeout=25):
        self.commands.append(command)
        if not self.replies:
            raise AssertionError("unexpected gate command %r" % command)
        return self.replies.pop(0)


class FakeProbe:
    def __init__(self, sent=None, error=None):
        self.sent = sent
        self.error = error
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.sent


class SequentialTrialTest(unittest.TestCase):
    def test_default_alternatives_match_preregistered_mixture(self):
        self.assertEqual(
            sequential_trials.DEFAULT_ALTERNATIVES,
            (0.01, 0.10, 0.50, 0.75, 0.90, 0.97),
        )

    def config(self, **overrides):
        values = {
            "program": "mcp_fabric_clf_eg",
            "sublink": 2,
            "epoch": 7,
            "packets": 40,
            "pps": 200,
            "contexts": "2",
            "survival": 0.95,
            "expected_build_id": GOOD_BUILD_ID,
            "expected_runtime_id": GOOD_RUNTIME_ID,
            "guard_seconds": 0.0,
        }
        values.update(overrides)
        return sequential_trials.TrialConfig(**values)

    def happy_replies(self, tx=40, rx=38, drops=2, bank=0, epoch=7):
        return [
            GOOD_IDENTITY,
            "OK 0\n",                         # C
            "OK 4\n",                         # N active
            "OK 4\n",                         # E active
            "OK 0\n",                         # Z
            "OK 0\n",                         # X zero verification
            "ARMED 2 5 6\nOK 1\n",            # A detail plus range-count terminator
            "OK 4\n",                         # N freeze
            "OK 4\n",                         # E next epoch
            "X %d 0 2 %d %d\nOK 0\n" % (bank, tx, rx),
            "I 2 5 6 %d\nOK 0\n" % drops,
            "OK 1\n",                         # cleanup C
        ]

    def run_once(self, replies, probe=None, config=None, ledger=None):
        gate = FakeGate(replies)
        if probe is None:
            probe = FakeProbe(sent=40)
        if config is None:
            config = self.config()
        outcome = sequential_trials.run_trial(gate, probe, ledger, config)
        self.assertEqual(gate.replies, [])
        return outcome, gate, probe

    def test_sealed_epoch_orders_commands_and_cleans_injector(self):
        outcome, gate, probe = self.run_once(self.happy_replies())

        self.assertEqual(gate.commands, [
            "V", "C", "N 0", "E 7", "Z", "X", "A 2 2",
            "N 1", "E 8", "X", "I", "C",
        ])
        self.assertEqual(probe.requests, [
            sequential_trials.ProbeRequest(packets=40, pps=200, contexts="2")
        ])
        self.assertEqual(outcome.record.sublink, 2)
        self.assertEqual(outcome.record.epoch, 7)
        self.assertEqual(outcome.record.tx, 40)
        self.assertEqual(outcome.record.rx, 38)
        self.assertEqual(outcome.record.receipt_status, ReceiptStatus.COMPLETE)
        self.assertIsNone(outcome.record.censor_reason)
        self.assertEqual(outcome.measured_drops, 2)
        self.assertEqual(outcome.decision.verdict, Verdict.MONITOR)

    def test_probe_failure_still_cleans_injector(self):
        gate = FakeGate([
            GOOD_IDENTITY, "OK 0\n", "OK 4\n", "OK 4\n", "OK 0\n", "OK 0\n",
            "ARMED 2 5 6\nOK 1\n", "OK 1\n",
        ])
        probe = FakeProbe(error=sequential_trials.HarnessError("probe failed"))

        with self.assertRaisesRegex(sequential_trials.HarnessError, "probe failed"):
            sequential_trials.run_trial(gate, probe, None, self.config())

        self.assertEqual(gate.commands, ["V", "C", "N 0", "E 7", "Z", "X", "A 2 2", "C"])

    def test_identity_mismatch_fails_before_any_mutation(self):
        bad = "IDENTITY mcp_fabric_gate_event %s %s 123\n" % ("a" * 64, "b" * 64)
        gate = FakeGate([bad])

        with self.assertRaisesRegex(sequential_trials.HarnessError, "expected mcp_fabric_clf_eg"):
            sequential_trials.run_trial(gate, FakeProbe(sent=40), None, self.config())

        self.assertEqual(gate.commands, ["V"])

    def test_build_and_runtime_identity_mismatch_fail_before_any_mutation(self):
        cases = [
            ("IDENTITY mcp_fabric_clf_eg %s %s 123\n" % ("c" * 64, GOOD_RUNTIME_ID),
             "build_id"),
            ("IDENTITY mcp_fabric_clf_eg %s %s 123\n" % (GOOD_BUILD_ID, "d" * 64),
             "runtime_id"),
        ]
        for identity, message in cases:
            with self.subTest(message=message):
                gate = FakeGate([identity])
                with self.assertRaisesRegex(sequential_trials.HarnessError, message):
                    sequential_trials.run_trial(gate, FakeProbe(sent=40), None, self.config())
                self.assertEqual(gate.commands, ["V"])

    def test_mutations_require_ok_counts_and_exact_bank_epoch_rewrites(self):
        cases = [
            (["ERR stale owner\n"], "C failed"),
            (["OK 0\n", "OK 3\n"], "N 0 modified 3 rows, expected 4"),
            (["OK 0\n", "OK 4\n", "OK 0\n"], "E 7 modified 0 rows, expected 4"),
        ]
        for tail, message in cases:
            with self.subTest(message=message):
                gate = FakeGate([GOOD_IDENTITY] + tail + ["OK 1\n"])
                with self.assertRaisesRegex(sequential_trials.HarnessError, message):
                    sequential_trials.run_trial(gate, FakeProbe(sent=40), None, self.config())
                self.assertEqual(gate.commands[-1], "C")

    def test_arm_requires_armed_detail_and_ok_count(self):
        cases = [
            ("ARMED 2 5 6\n", "A 2 2 reply missing OK terminator"),
            ("ARMED 3 5 6\nOK 1\n", "A 2 2 failed"),
            ("ARMED 2 5 6\nOK 0\n", "A 2 2 installed 0 injector ranges"),
        ]
        for reply, message in cases:
            with self.subTest(message=message):
                gate = FakeGate([
                    GOOD_IDENTITY, "OK 0\n", "OK 4\n", "OK 4\n",
                    "OK 0\n", "OK 0\n", reply, "OK 1\n",
                ])
                with self.assertRaisesRegex(sequential_trials.HarnessError, message):
                    sequential_trials.run_trial(gate, FakeProbe(sent=40), None, self.config())
                self.assertEqual(gate.commands[-1], "C")

    def test_tcp_gate_waits_for_ok_after_armed_detail(self):
        self.assertFalse(sequential_trials._reply_complete(b"ARMED 2 5 6\n"))
        self.assertTrue(sequential_trials._reply_complete(b"ARMED 2 5 6\nOK 1\n"))

    def test_saturation_and_impossible_counts_are_censored_not_scored(self):
        cases = [
            ((255, 1), CensorReason.SATURATED),
            ((10, 11), CensorReason.IMPOSSIBLE),
        ]
        for (tx, rx), reason in cases:
            with self.subTest(reason=reason):
                outcome, _gate, _probe = self.run_once(
                    self.happy_replies(tx=tx, rx=rx, drops=2)
                )
                self.assertEqual(outcome.record.censor_reason, reason)
                self.assertEqual(outcome.decision.verdict, Verdict.INCONCLUSIVE)
                self.assertEqual(outcome.decision.censor_reason, reason)

    def test_missing_injector_ground_truth_censors_the_epoch(self):
        replies = self.happy_replies(drops=2)
        replies[-2] = "OK 0\n"
        outcome, _gate, _probe = self.run_once(replies)

        self.assertIsNone(outcome.measured_drops)
        self.assertEqual(outcome.record.receipt_status, ReceiptStatus.MISSING)
        self.assertEqual(outcome.record.censor_reason, CensorReason.INVALID_RECEIPT)
        self.assertEqual(outcome.decision.verdict, Verdict.INCONCLUSIVE)

    def test_injector_count_mismatch_censors_the_epoch(self):
        outcome, _gate, _probe = self.run_once(self.happy_replies(tx=40, rx=38, drops=1))

        self.assertEqual(outcome.measured_drops, 1)
        self.assertEqual(outcome.record.receipt_status, ReceiptStatus.INVALID)
        self.assertEqual(outcome.record.censor_reason, CensorReason.INVALID_RECEIPT)
        self.assertEqual(outcome.decision.verdict, Verdict.INCONCLUSIVE)

    def test_injector_count_matching_deficit_but_not_intent_is_censored(self):
        outcome, _gate, _probe = self.run_once(self.happy_replies(tx=40, rx=37, drops=3))

        self.assertEqual(outcome.measured_drops, 3)
        self.assertEqual(outcome.record.receipt_status, ReceiptStatus.INVALID)
        self.assertEqual(outcome.record.censor_reason, CensorReason.INVALID_RECEIPT)
        self.assertEqual(outcome.decision.verdict, Verdict.INCONCLUSIVE)

    def test_tx_count_not_equal_to_sent_count_is_censored(self):
        outcome, _gate, _probe = self.run_once(self.happy_replies(tx=41, rx=39, drops=2))

        self.assertEqual(outcome.record.censor_reason, CensorReason.INCOMPLETE)
        self.assertEqual(outcome.decision.verdict, Verdict.INCONCLUSIVE)

    def test_total_blackhole_uses_full_range_and_requires_exact_receipt(self):
        replies = [
            GOOD_IDENTITY, "OK 0\n", "OK 4\n", "OK 4\n", "OK 0\n", "OK 0\n",
            "BLACKHOLED 2 [0..65535]\nOK 1\n",
            "OK 4\n", "OK 4\n", "X 0 0 2 40 0\nOK 0\n",
            "I 2 0 65535 40\nOK 0\n", "OK 1\n",
        ]

        outcome, gate, _probe = self.run_once(
            replies, config=self.config(survival=0.0)
        )

        self.assertIn("K 2 0 65535", gate.commands)
        self.assertNotIn("A 2 40", gate.commands)
        self.assertEqual(outcome.record.receipt_status, ReceiptStatus.COMPLETE)
        self.assertEqual(outcome.record.censor_reason, None)
        self.assertEqual(outcome.decision.verdict, Verdict.BLACKHOLE)

    def test_zero_readback_ignores_unrelated_background_rows(self):
        replies = self.happy_replies()
        replies[5] = (
            "X 0 0 3 7 7\n"
            "X 1 0 2 9 9\n"
            "OK 0\n"
        )

        outcome, _gate, _probe = self.run_once(replies)

        self.assertEqual(outcome.record.tx, 40)
        self.assertEqual(outcome.record.rx, 38)

    def test_zero_readback_retries_transient_target_residue(self):
        replies = self.happy_replies()
        replies[5] = "X 0 0 2 0 1\nOK 0\n"
        replies.insert(6, "OK 0\n")
        replies.insert(7, "OK 0\n")

        outcome, gate, _probe = self.run_once(replies)

        self.assertEqual(gate.commands, [
            "V", "C", "N 0", "E 7", "Z", "X", "Z", "X", "A 2 2",
            "N 1", "E 8", "X", "I", "C",
        ])
        self.assertEqual(outcome.record.tx, 40)
        self.assertEqual(outcome.record.rx, 38)

    def test_zero_readback_rejects_persistent_target_residue(self):
        replies = [
            GOOD_IDENTITY, "OK 0\n", "OK 4\n", "OK 4\n",
            "OK 0\n", "X 0 0 2 0 1\nOK 0\n",
            "OK 0\n", "X 0 0 2 0 1\nOK 0\n",
            "OK 0\n", "X 0 0 2 0 1\nOK 0\n",
            "OK 1\n",
        ]

        with self.assertRaisesRegex(sequential_trials.HarnessError, "zero did not take"):
            self.run_once(replies)

    def test_survival_point_uses_packet_budget_without_sequence_multiplier(self):
        self.assertEqual(sequential_trials.drops_for_survival(40, 0.95), 2)
        with self.assertRaisesRegex(ValueError, "below saturation"):
            sequential_trials.TrialConfig(
                program="mcp_fabric_clf_eg",
                sublink=2,
                epoch=0,
                packets=255,
                pps=200,
                contexts="2",
                survival=0.95,
                expected_build_id=GOOD_BUILD_ID,
                expected_runtime_id=GOOD_RUNTIME_ID,
            )

    def test_single_sublink_trial_rejects_multi_context_probe(self):
        with self.assertRaisesRegex(ValueError, "single context"):
            self.config(contexts="all")

    def test_cli_requires_expected_build_and_runtime_identity(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                sequential_trials.main([
                    "--program", "mcp_fabric_clf_eg",
                    "--expected-build-id", GOOD_BUILD_ID,
                ])

    def test_repeated_measured_gray_loss_triggers_statistical_action(self):
        replies = []
        for epoch in range(20):
            replies.extend(self.happy_replies(tx=40, rx=36, drops=4, bank=epoch % 2, epoch=epoch))
        gate = FakeGate(replies)
        probe = FakeProbe(sent=40)
        config = self.config(epoch=0, survival=0.90)

        outcomes = sequential_trials.run_campaign(gate, probe, config, epochs=20)

        self.assertIn(Verdict.GRAYHOLE, [outcome.decision.verdict for outcome in outcomes])
        self.assertTrue(any(outcome.decision.statistical_alarm for outcome in outcomes))


if __name__ == "__main__":
    unittest.main()
