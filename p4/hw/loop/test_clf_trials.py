import importlib.util
import pathlib
import unittest
from unittest import mock


HERE = pathlib.Path(__file__).resolve().parent
MODULE_PATH = HERE / "clf_trials.py"
spec = importlib.util.spec_from_file_location("clf_trials", MODULE_PATH)
clf_trials = importlib.util.module_from_spec(spec)
spec.loader.exec_module(clf_trials)


class FakeAgent:
    def __init__(self, replies):
        self.replies = list(replies)
        self.commands = []

    def __call__(self, cmd):
        self.commands.append(cmd)
        if not self.replies:
            raise AssertionError("unexpected command %r" % cmd)
        return self.replies.pop(0)


class FragmentedSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.recv_calls = 0

    def settimeout(self, _timeout):
        pass

    def sendall(self, _payload):
        pass

    def recv(self, _size):
        self.recv_calls += 1
        return self.chunks.pop(0) if self.chunks else b""

    def close(self):
        pass


class TrialProtocolTest(unittest.TestCase):
    def test_agent_waits_for_ok_after_fragmented_blackhole_detail(self):
        sock = FragmentedSocket([b"BLACKHOLED 2 [0..65535]\n", b"OK 1\n"])
        with mock.patch.object(clf_trials.socket, "create_connection", return_value=sock):
            reply = clf_trials.agent("K 2")

        self.assertEqual(reply, "BLACKHOLED 2 [0..65535]\nOK 1\n")
        self.assertEqual(sock.recv_calls, 2)

    def test_fault_arm_requires_standard_ok_terminator(self):
        fake = FakeAgent(["OK 0\n", "OK 4\n", "BLACKHOLED 2 [0..65535]\n"])
        with mock.patch.object(clf_trials, "agent", fake), \
                mock.patch.object(clf_trials.time, "sleep"):
            with self.assertRaisesRegex(clf_trials.HarnessError,
                                        "K 2 reply missing OK terminator"):
                clf_trials.trial(2, guard=0.0, bank=0)

    def test_trials_refuse_agent_bound_to_another_program(self):
        reply = "IDENTITY mcp_fabric_gate_event %s %s 123\n" % ("b" * 64, "c" * 64)
        with mock.patch.object(clf_trials, "agent", return_value=reply):
            with self.assertRaisesRegex(clf_trials.HarnessError, "expected mcp_fabric_clf_eg"):
                clf_trials.require_agent_identity(
                    "mcp_fabric_clf_eg", "b" * 64, "c" * 64)

    def test_trials_refuse_unexpected_build_or_runtime_identity(self):
        reply = "IDENTITY mcp_fabric_clf_eg %s %s 123\n" % ("b" * 64, "c" * 64)
        for build_id, runtime_id, message in (
                ("a" * 64, "c" * 64, "build"),
                ("b" * 64, "d" * 64, "runtime")):
            with self.subTest(message=message), \
                    mock.patch.object(clf_trials, "agent", return_value=reply):
                with self.assertRaisesRegex(clf_trials.HarnessError, "expected %s" % message):
                    clf_trials.require_agent_identity(
                        "mcp_fabric_clf_eg", build_id, runtime_id)

    def test_main_uses_the_cli_program_for_identity_check(self):
        reply = "IDENTITY custom_prog %s %s 123\n" % ("b" * 64, "c" * 64)
        with mock.patch.object(clf_trials.sys, "argv",
                               ["clf_trials.py", "--program", "custom_prog",
                                "--build-id", "b" * 64, "--runtime-id", "c" * 64,
                                "--trials", "0"]), \
                mock.patch.object(clf_trials, "agent", return_value=reply), \
                mock.patch.object(clf_trials, "trial") as trial:
            clf_trials.main()

        trial.assert_not_called()

    def test_probe_uses_an_unsaturated_explicit_packet_budget(self):
        completed = mock.Mock(returncode=0, stdout="sent 40 probes\n", stderr="")
        with mock.patch.object(clf_trials.subprocess, "run", return_value=completed) as run:
            sent = clf_trials.probe("/tmp/probe_spray0.py", packets=40, gap=0.005)

        self.assertEqual(sent, 40)
        run.assert_called_once_with(
            ["python3", "/tmp/probe_spray0.py", "40", "0.005"],
            capture_output=True,
            text=True,
            timeout=300,
        )

    def test_probe_rejects_a_saturating_packet_budget(self):
        with self.assertRaisesRegex(ValueError, "below the 255-count saturation value"):
            clf_trials.probe("/tmp/probe_spray0.py", packets=255)

    def run_trial(self, replies, target_sublink=2, probe_sent=40):
        fake = FakeAgent(replies)
        with mock.patch.object(clf_trials, "agent", fake), \
                mock.patch.object(clf_trials, "probe", return_value=probe_sent), \
                mock.patch.object(clf_trials.time, "sleep"):
            result = clf_trials.trial(target_sublink, guard=0.0, bank=0)
        self.assertEqual(fake.replies, [])
        return result, fake.commands

    def test_fault_trial_arms_before_zero_and_classifies_counts(self):
        (verdicts, sent, drops), commands = self.run_trial([
            "OK 0\n",                         # C
            "OK 4\n",                         # N 0
            "BLACKHOLED 2 [0..65535]\nOK 1\n", # K 2
            "OK 0\n",                         # Z
            "OK 0\n",                         # X zero verification
            "OK 4\n",                         # N 1 freeze
            "I 2 0 65535 39\nOK 0\n",         # injector ground truth
            "X 0 0 2 40 5\nOK 0\n",           # frozen count rows
        ])

        self.assertLess(commands.index("K 2"), commands.index("Z"))
        self.assertEqual(commands, ["C", "N 0", "K 2", "Z", "X", "N 1", "I", "X"])
        self.assertEqual(sent, 40)
        self.assertEqual(drops, 39)
        self.assertEqual(verdicts[(0, 2)], clf_trials.Verdict.STARVED)

    def test_zero_verification_rejects_residue(self):
        with self.assertRaisesRegex(clf_trials.HarnessError, "zero did not take"):
            self.run_trial([
                "OK 0\n",
                "OK 4\n",
                "BLACKHOLED 2 [0..65535]\nOK 1\n",
                "OK 0\n",
                "X 0 0 2 1 0\nOK 0\n",
                "OK 0\n",
                "X 0 0 2 1 0\nOK 0\n",
                "OK 0\n",
                "X 0 0 2 1 0\nOK 0\n",
            ])

    def test_zero_verification_retries_transient_target_residue(self):
        (verdicts, sent, drops), commands = self.run_trial([
            "OK 0\n",
            "OK 4\n",
            "BLACKHOLED 2 [0..65535]\nOK 1\n",
            "OK 0\n",
            "X 0 0 2 0 1\nOK 0\n",
            "OK 0\n",
            "OK 0\n",
            "OK 4\n",
            "I 2 0 65535 39\nOK 0\n",
            "X 0 0 2 40 0\nOK 0\n",
        ])

        self.assertEqual(commands, ["C", "N 0", "K 2", "Z", "X", "Z", "X", "N 1", "I", "X"])
        self.assertEqual(sent, 40)
        self.assertEqual(drops, 39)
        self.assertEqual(verdicts[(0, 2)], clf_trials.Verdict.BLACKHOLE)

    def test_zero_verification_ignores_unrelated_background_residue(self):
        (verdicts, sent, drops), commands = self.run_trial([
            "OK 0\n",
            "OK 4\n",
            "BLACKHOLED 2 [0..65535]\nOK 1\n",
            "OK 0\n",
            "X 0 1 1 1 1\nOK 0\n",
            "OK 4\n",
            "I 2 0 65535 39\nOK 0\n",
            "X 0 0 2 40 0\nX 0 1 1 1 1\nOK 0\n",
        ])

        self.assertEqual(commands, ["C", "N 0", "K 2", "Z", "X", "N 1", "I", "X"])
        self.assertEqual(sent, 40)
        self.assertEqual(drops, 39)
        self.assertEqual(verdicts[(0, 2)], clf_trials.Verdict.BLACKHOLE)

    def test_probe_failure_is_excluded_before_freeze(self):
        fake = FakeAgent([
            "OK 0\n",
            "OK 4\n",
            "BLACKHOLED 2 [0..65535]\nOK 1\n",
            "OK 0\n",
            "OK 0\n",
        ])
        with mock.patch.object(clf_trials, "agent", fake), \
                mock.patch.object(clf_trials, "probe", side_effect=clf_trials.HarnessError("probe failed")), \
                mock.patch.object(clf_trials.time, "sleep"):
            with self.assertRaisesRegex(clf_trials.HarnessError, "probe failed"):
                clf_trials.trial(2, guard=0.0, bank=0)
        self.assertNotIn("N 1", fake.commands)

    def test_fault_trial_requires_injector_ground_truth(self):
        with self.assertRaisesRegex(clf_trials.HarnessError, "injector reported no drops"):
            self.run_trial([
                "OK 0\n",
                "OK 4\n",
                "BLACKHOLED 2 [0..65535]\nOK 1\n",
                "OK 0\n",
                "OK 0\n",
                "OK 4\n",
                "I 2 0 65535 0\nOK 0\n",
            ])

    def test_freeze_requires_exact_positive_bank_rewrite(self):
        with self.assertRaisesRegex(clf_trials.HarnessError, "N 1 modified 0 act_enter rows"):
            self.run_trial([
                "OK 0\n",
                "OK 4\n",
                "BLACKHOLED 2 [0..65535]\nOK 1\n",
                "OK 0\n",
                "OK 0\n",
                "OK 0\n",
            ])

    def test_incomplete_count_read_is_rejected(self):
        with self.assertRaisesRegex(clf_trials.HarnessError, "X reply missing OK terminator"):
            self.run_trial([
                "OK 0\n",
                "OK 4\n",
                "BLACKHOLED 2 [0..65535]\nOK 1\n",
                "OK 0\n",
                "OK 0\n",
                "OK 4\n",
                "I 2 0 65535 40\nOK 0\n",
                "X 0 0 2 40 0\n",
            ])

    def test_mutating_agent_err_and_n_zero_are_rejected(self):
        cases = [
            ("ERR schema mismatch\n", "N 0 failed"),
            ("OK 0\n", "N 0 modified 0 act_enter rows"),
        ]
        for reply, message in cases:
            with self.subTest(reply=reply):
                with self.assertRaisesRegex(clf_trials.HarnessError, message):
                    self.run_trial(["OK 0\n", reply])


class ClassifierTest(unittest.TestCase):
    def test_bank_flip_requires_all_four_source_act_enter_rows(self):
        self.assertEqual(clf_trials.EXPECTED_ACT_ENTER_ROWS, 4)

    def test_count_rows_drive_verdict_counts_by_default(self):
        rows = clf_trials.parse_count_frontiers(
            "X 0 0 2 255 0\n"
            "X 0 0 3 255 1\n"
            "X 0 0 4 40 10\n"
            "OK 0\n"
        )

        verdicts = clf_trials.classify_counts(rows)

        self.assertEqual(verdicts[(0, 2)], clf_trials.Verdict.BLACKHOLE)
        self.assertEqual(verdicts[(0, 3)], clf_trials.Verdict.STARVED)
        self.assertEqual(verdicts[(0, 4)], clf_trials.Verdict.HEALTHY)

    def test_presence_classification_remains_explicit_historical_comparison(self):
        rows = clf_trials.parse_frontiers("F 0 0 0x0008 0x0008 0x0000\nOK 0\n")

        verdicts = clf_trials.classify_presence(rows)

        self.assertEqual(verdicts[(0, 3)], clf_trials.Verdict.INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()
