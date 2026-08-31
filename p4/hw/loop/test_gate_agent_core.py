import hashlib
import pathlib
import tempfile
import unittest

from gate_agent_core import (
    add_batch_strict,
    format_arm_reply,
    format_blackhole_reply,
    clear_entries_strict,
    is_not_found,
    peer_allowed,
    parse_bank_command,
    parse_blackhole_command,
    parse_epoch_command,
    rewrite_act_enter_field,
    sync_counters_strict,
    verify_loaded_build,
    verify_sha256_manifest,
)


class FakeTable:
    def __init__(self, fail_add=False, fail_delete_at=None, fail_sync=False):
        self.fail_add = fail_add
        self.fail_delete_at = fail_delete_at
        self.fail_sync = fail_sync
        self.add_calls = []
        self.delete_calls = []
        self.operation_calls = []

    def entry_add(self, target, keys, data):
        self.add_calls.append((target, keys, data))
        if self.fail_add:
            raise RuntimeError("batch rejected")

    def entry_del(self, target, keys):
        self.delete_calls.append((target, keys))
        if self.fail_delete_at == len(self.delete_calls):
            raise RuntimeError("delete rejected")

    def operations_execute(self, target, operation):
        self.operation_calls.append((target, operation))
        if self.fail_sync:
            raise RuntimeError("sync rejected")


class FakeDataTuple:
    def __init__(self, name, value):
        self.name = name
        self.value = value


class FakeRewriteTable:
    def __init__(self, rows, fail_mod_at=None):
        self.rows = list(rows)
        self.fail_mod_at = fail_mod_at
        self.mod_calls = []
        self.make_data_calls = []

    def entry_get(self, target, keys, flags):
        self.get_calls = getattr(self, "get_calls", 0) + 1
        for key, data in self.rows:
            yield data, key

    def make_data(self, fields, action_name):
        self.make_data_calls.append((tuple((f.name, f.value) for f in fields), action_name))
        return dict((f.name, f.value) for f in fields)

    def entry_mod(self, target, keys, data):
        self.mod_calls.append((keys, data))
        if self.fail_mod_at == len(self.mod_calls):
            raise RuntimeError("mod rejected")
        for key, update_data in zip(keys, data):
            update = dict(update_data)
            for i, (old_key, old_data) in enumerate(self.rows):
                if old_key == key:
                    current = old_data.to_dict()
                    current.update(update)
                    self.rows[i] = (old_key, FakeRewriteData(current))
                    break
            else:
                raise RuntimeError("missing key")


class FakeRewriteData:
    def __init__(self, row):
        self.row = dict(row)

    def to_dict(self):
        return dict(self.row)


class TestGateAgentCore(unittest.TestCase):
    def test_arm_reply_carries_detail_and_standard_ok_terminator(self):
        self.assertEqual(
            format_arm_reply(2, ((5, 6), (0, 1))),
            "ARMED 2 5 6 0 1\nOK 2\n",
        )

    def test_blackhole_reply_carries_detail_and_standard_ok_terminator(self):
        self.assertEqual(
            format_blackhole_reply(2, 0, 65535),
            "BLACKHOLED 2 [0..65535]\nOK 1\n",
        )

    def test_blackhole_command_requires_exact_arity_and_range(self):
        self.assertEqual(parse_blackhole_command(["K", "2"]), (2, 0, 65535))
        self.assertEqual(parse_blackhole_command(["K", "2", "5", "9"]), (2, 5, 9))
        for fields in (["K", "2", "5"], ["K", "2", "5", "9", "10"],
                       ["K", "1024"], ["K", "2", "9", "5"]):
            with self.subTest(fields=fields):
                with self.assertRaises(ValueError):
                    parse_blackhole_command(fields)

    def test_counter_sync_failure_propagates(self):
        table = FakeTable(fail_sync=True)
        with self.assertRaisesRegex(RuntimeError, "sync rejected"):
            sync_counters_strict(table, "target")
        self.assertEqual(table.operation_calls, [("target", "SyncCounters")])

    def test_runtime_manifest_requires_exact_import_closure_and_matching_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            expected = ("gate_agent.py", "gate_agent_core.py", "injector_ranges.py")
            for name in expected:
                (root / name).write_text(name + "\n")
            manifest = root / "prog.runtime-manifest.sha256"
            manifest.write_text("".join(
                "%s  %s\n" % (hashlib.sha256((name + "\n").encode()).hexdigest(), name)
                for name in expected
            ))

            identity = verify_sha256_manifest(root, manifest.name, expected_files=expected)
            self.assertEqual(identity, hashlib.sha256(manifest.read_bytes()).hexdigest())

            (root / "gate_agent_core.py").write_text("tampered\n")
            with self.assertRaisesRegex(RuntimeError, "sha256 mismatch"):
                verify_sha256_manifest(root, manifest.name, expected_files=expected)

            (root / "gate_agent_core.py").write_text("gate_agent_core.py\n")
            with self.assertRaisesRegex(RuntimeError, "manifest file set"):
                verify_sha256_manifest(root, manifest.name,
                                       expected_files=expected + ("missing.py",))

    def test_loaded_build_receipt_must_name_live_switchd_and_build_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            proc = root / "proc"
            pid_dir = proc / "123"
            pid_dir.mkdir(parents=True)
            (pid_dir / "comm").write_text("bf_switchd\n")
            (pid_dir / "cmdline").write_bytes(
                b"bf_switchd\0--conf-file\0" +
                str(root / "prog_abs.conf").encode() + b"\0")
            (root / "prog.loaded-build.sha256").write_text("123 build-id\n")

            self.assertEqual(
                verify_loaded_build(root, "prog", "build-id", proc_root=proc), 123)
            (root / "prog.loaded-build.sha256").write_text("123 stale-id\n")
            with self.assertRaisesRegex(RuntimeError, "build identity"):
                verify_loaded_build(root, "prog", "build-id", proc_root=proc)
    def test_batch_is_exactly_one_call_and_failure_propagates(self):
        table = FakeTable(fail_add=True)
        with self.assertRaisesRegex(RuntimeError, "batch rejected"):
            add_batch_strict(table, "target", ["k1", "k2"], ["d1", "d2"])
        self.assertEqual(len(table.add_calls), 1)

    def test_clear_reports_partial_failure(self):
        table = FakeTable(fail_delete_at=2)
        with self.assertRaisesRegex(RuntimeError, "failed to clear 1/3"):
            clear_entries_strict(table, "target", ["k1", "k2", "k3"])
        self.assertEqual(len(table.delete_calls), 3)

    def test_expected_absent_row_and_peer_allowlist_are_explicit(self):
        self.assertTrue(is_not_found(RuntimeError("code NOT_FOUND")))
        self.assertFalse(is_not_found(RuntimeError("permission denied")))
        allowed = {"127.0.0.1", "10.10.54.166"}
        self.assertTrue(peer_allowed("10.10.54.166", allowed))
        self.assertFalse(peer_allowed("10.10.54.99", allowed))

    def test_act_enter_rewrite_preserves_unmodified_action_fields(self):
        rows = [
            ("k1", FakeRewriteData({
                "action_name": "Ingress.act_enter",
                "next_hop": 1,
                "epoch": 7,
                "bank": 0,
            })),
            ("k2", FakeRewriteData({
                "action_name": "Ingress.act_transit",
                "next_hop": 2,
                "epoch": 999,
                "bank": 1,
            })),
            ("k3", FakeRewriteData({
                "action_name": "Ingress.act_enter",
                "next_hop": 3,
                "epoch": 8,
                "bank": 0,
            })),
        ]
        table = FakeRewriteTable(rows)

        changed = rewrite_act_enter_field(
            table, "target", FakeDataTuple, "bank", 1, expected_count=2)

        self.assertEqual(changed, 2)
        self.assertEqual(table.make_data_calls, [
            ((("next_hop", 1), ("epoch", 7), ("bank", 1)), "Ingress.act_enter"),
            ((("next_hop", 3), ("epoch", 8), ("bank", 1)), "Ingress.act_enter"),
        ])
        self.assertEqual(len(table.mod_calls), 1)
        self.assertEqual(table.mod_calls[0][0], ["k1", "k3"])
        self.assertEqual(table.rows[0][1].to_dict()["bank"], 1)
        self.assertEqual(table.rows[1][1].to_dict()["bank"], 1)
        self.assertEqual(table.rows[2][1].to_dict()["bank"], 1)

    def test_act_enter_rewrite_fails_closed_on_schema_or_count_mismatch(self):
        cases = (
            ([("k1", FakeRewriteData({"action_name": "Ingress.act_transit", "bank": 0}))],
             "no act_enter"),
            ([("k1", FakeRewriteData({"action_name": "Ingress.act_enter", "next_hop": 1}))],
             "missing action field bank"),
            ([("k1", FakeRewriteData({"action_name": "Ingress.act_enter", "bank": 0}))],
             "missing action field next_hop"),
        )
        for rows, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(RuntimeError, message):
                rewrite_act_enter_field(
                    FakeRewriteTable(rows), "target", FakeDataTuple, "bank", 1)

        rows = [("k1", FakeRewriteData({
            "action_name": "Ingress.act_enter", "next_hop": 1, "epoch": 0, "bank": 0,
        }))]
        with self.assertRaisesRegex(RuntimeError, "expected 2 act_enter rows"):
            rewrite_act_enter_field(
                FakeRewriteTable(rows), "target", FakeDataTuple, "bank", 1,
                expected_count=2)

        rows = [
            ("k1", FakeRewriteData({
                "action_name": "Ingress.act_enter", "next_hop": 1,
                "epoch": 0, "bank": 0,
            })),
            ("k2", FakeRewriteData({
                "action_name": "Ingress.act_enter", "next_hop": 2,
                "epoch": 0,
            })),
        ]
        table = FakeRewriteTable(rows)
        with self.assertRaisesRegex(RuntimeError, "missing action field bank"):
            rewrite_act_enter_field(table, "target", FakeDataTuple, "bank", 1)
        self.assertEqual(table.mod_calls, [], "schema validation must precede every write")

    def test_act_enter_rewrite_propagates_mod_failure_and_requires_readback(self):
        rows = [("k1", FakeRewriteData({
            "action_name": "Ingress.act_enter", "next_hop": 1, "epoch": 0, "bank": 0,
        }))]
        with self.assertRaisesRegex(RuntimeError, "mod rejected"):
            rewrite_act_enter_field(
                FakeRewriteTable(rows, fail_mod_at=1), "target", FakeDataTuple, "bank", 1)

        class IgnoringTable(FakeRewriteTable):
            def entry_mod(self, target, keys, data):
                self.mod_calls.append((keys, data))

        with self.assertRaisesRegex(RuntimeError, "readback mismatch"):
            rewrite_act_enter_field(
                IgnoringTable(rows), "target", FakeDataTuple, "bank", 1)

    def test_protocol_helpers_reject_arity_and_ranges(self):
        self.assertEqual(parse_bank_command(["N", "1"]), 1)
        self.assertEqual(parse_epoch_command(["E", "65535"]), 65535)
        invalid = (
            (parse_bank_command, ["N"]),
            (parse_bank_command, ["N", "2"]),
            (parse_bank_command, ["N", "1", "4"]),
            (parse_epoch_command, ["E"]),
            (parse_epoch_command, ["E", "65536"]),
            (parse_epoch_command, ["E", "-1"]),
            (parse_epoch_command, ["E", "1", "4"]),
        )
        for parser, fields in invalid:
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                parser(fields)


if __name__ == "__main__":
    unittest.main()
