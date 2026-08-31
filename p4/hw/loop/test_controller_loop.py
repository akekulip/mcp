import importlib.util
import pathlib
import socket
import struct
import queue
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("controller_loop.py")
SPEC = importlib.util.spec_from_file_location("controller_loop", MODULE_PATH)
controller_loop = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(controller_loop)


class FakePacketSocket:
    def __init__(self):
        self.bound = None
        self.options = []
        self.timeout = None

    def bind(self, address):
        self.bound = address

    def setsockopt(self, level, option, value):
        self.options.append((level, option, value))

    def settimeout(self, timeout):
        self.timeout = timeout


class FakeControlSocket:
    def __init__(self, reply):
        self.reply = reply

    def setsockopt(self, *args):
        pass

    def settimeout(self, timeout):
        pass

    def connect(self, address):
        pass

    def sendall(self, payload):
        pass

    def recv(self, size):
        return self.reply

    def close(self):
        pass


class RecordingControlSocket:
    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []

    def setsockopt(self, *args):
        pass

    def settimeout(self, timeout):
        pass

    def connect(self, address):
        pass

    def sendall(self, payload):
        self.sent.append(payload)

    def recv(self, size):
        if not self.replies:
            return b""
        return self.replies.pop(0)

    def close(self):
        pass


class TestMirrorSocket(unittest.TestCase):
    def test_capture_enables_promiscuous_membership_for_mirror_destination_mac(self):
        """Removing PACKET_MR_PROMISC would make non-NIC-addressed mirrors invisible."""
        packet_socket = FakePacketSocket()
        with mock.patch.object(controller_loop.socket, "socket", return_value=packet_socket), \
                mock.patch.object(controller_loop.socket, "if_nametoindex", return_value=17):
            with mock.patch.object(controller_loop, "attach_mirror_filter") as attach:
                actual = controller_loop.open_mirror_socket("eth-test", backup_vlink=1)

        self.assertIs(actual, packet_socket)
        attach.assert_called_once_with(packet_socket, 1)
        expected_membership = struct.pack("IHH8s", 17, 1, 0, b"\x00" * 8)
        self.assertIn((263, 1, expected_membership), packet_socket.options)
        self.assertEqual(packet_socket.bound, ("eth-test", 0))
        self.assertEqual(packet_socket.timeout, 0.01)

    def test_kernel_filter_accepts_only_gap_events_or_backup_link_proof(self):
        self.assertEqual(controller_loop.mirror_filter_program(1), (
            (0x28, 0, 0, 22),       # mirror flags
            (0x45, 2, 0, 0x8),      # gap bit -> accept
            (0x28, 0, 0, 16),       # mirror vlink
            (0x15, 0, 1, 1),        # backup vlink -> accept
            (0x06, 0, 0, 262144),
            (0x06, 0, 0, 0),
        ))

    def test_receive_timeout_honours_reorder_deadline(self):
        self.assertEqual(controller_loop.receive_timeout(None, now=10.0), 0.01)
        self.assertAlmostEqual(
            controller_loop.receive_timeout(10.001, now=10.0), 0.001)

    def test_receive_timeout_never_blocks_past_an_expired_deadline(self):
        self.assertEqual(
            controller_loop.receive_timeout(9.0, now=10.0), 0.0001)


class TestCensusWorker(unittest.TestCase):
    def test_poll_returns_arrival_observation_from_observed_growth_only(self):
        replies = iter((
            {0: controller_loop.CensusCell(tx_seq=65530, observed=10),
             1: controller_loop.CensusCell(tx_seq=10, observed=10),
             2: controller_loop.CensusCell(tx_seq=100, observed=100)},
            {0: controller_loop.CensusCell(tx_seq=65535, observed=10),
             1: controller_loop.CensusCell(tx_seq=99, observed=10),
             2: controller_loop.CensusCell(tx_seq=130, observed=130)},
        ))
        worker = controller_loop.CensusWorker(lambda: next(replies), interval_s=1.0)

        self.assertEqual(worker.poll_once(epoch=7), [])
        self.assertEqual(worker.poll_once(epoch=8), [(0, 2, 30)])

    def test_poll_treats_decrease_as_reset_and_saturation_as_no_new_evidence(self):
        replies = iter((
            {0: controller_loop.CensusCell(tx_seq=10, observed=100),
             1: controller_loop.CensusCell(tx_seq=20, observed=65534),
             2: controller_loop.CensusCell(tx_seq=30, observed=40)},
            {0: controller_loop.CensusCell(tx_seq=99, observed=7),
             1: controller_loop.CensusCell(tx_seq=21, observed=65535),
             2: controller_loop.CensusCell(tx_seq=31, observed=40)},
        ))
        worker = controller_loop.CensusWorker(lambda: next(replies), interval_s=1.0)

        self.assertEqual(worker.poll_once(epoch=7), [])
        self.assertEqual(worker.poll_once(epoch=8), [(0, 0, 7)])

    def test_background_poll_does_not_block_the_capture_thread(self):
        release = controller_loop.threading.Event()

        def slow_census():
            release.wait(1.0)
            return {2: 100}

        worker = controller_loop.CensusWorker(slow_census, interval_s=0.01)
        worker.start(lambda: 3)
        try:
            with self.assertRaises(queue.Empty):
                worker.results.get(timeout=0.02)
            self.assertTrue(worker.is_alive(), "the slow BFRT read belongs to the worker")
        finally:
            release.set()
            worker.stop()


class TestReroutedProbeIdentity(unittest.TestCase):
    def test_plain_delivery_copy_matches_the_exact_probe_tuple(self):
        copy = {
            "vlink": 1,
            "fabric": None,
            "ipv4": {"diffserv": 0x00, "src": "10.0.1.1", "dst": "10.0.1.3"},
            "udp": {"src_port": 41000, "dst_port": 4449},
        }
        self.assertTrue(controller_loop.is_rerouted_probe(
            copy, 1, 2, 0x00, "10.0.1.1", "10.0.1.3", 41000, 4449))


    def test_unrelated_backup_traffic_cannot_end_the_measurement(self):
        copy = {
            "vlink": 1,
            "fabric": None,
            "ipv4": {"diffserv": 0x00, "src": "10.0.9.9", "dst": "10.0.1.3"},
            "udp": {"src_port": 41000, "dst_port": 4449},
        }
        self.assertFalse(controller_loop.is_rerouted_probe(
            copy, 1, 2, 0x00, "10.0.1.1", "10.0.1.3", 41000, 4449))

    def test_wrong_context_same_five_tuple_cannot_end_the_measurement(self):
        copy = {
            "vlink": 1,
            "fabric": None,
            "ipv4": {"diffserv": 0x20, "src": "10.0.1.1", "dst": "10.0.1.3"},
            "udp": {"src_port": 41000, "dst_port": 4449},
        }
        self.assertFalse(controller_loop.is_rerouted_probe(
            copy, 1, 2, 0x00, "10.0.1.1", "10.0.1.3", 41000, 4449))

    def test_capsule_copy_can_match_context_directly(self):
        copy = {"vlink": 1, "fabric": {"pad": 2}, "ipv4": None, "udp": None}
        self.assertTrue(controller_loop.is_rerouted_probe(
            copy, 1, 2, 0x00, "10.0.1.1", "10.0.1.3", 41000, 4449))


class TestGateClient(unittest.TestCase):
    def test_census_reply_requires_valid_rows_and_success_terminator(self):
        self.assertEqual(controller_loop.parse_census_reply(
            b"S 2 0 2 123 99\nS 6 0 6 456 100\nOK 2\n"),
            {
                2: controller_loop.CensusCell(tx_seq=123, observed=99),
                6: controller_loop.CensusCell(tx_seq=456, observed=100),
            })

    def test_census_reply_requires_requested_rows_and_matching_terminal_count(self):
        payload = b"S 2 0 2 0 0\nS 6 0 6 456 0\nOK 2\n"
        self.assertEqual(set(controller_loop.parse_census_reply(
            payload, requested_sublinks=(2, 6)).keys()), {2, 6})
        invalid = (
            b"S 2 0 2 0 0\nOK 0\n",
            b"S 2 0 2 0 0\nOK 1\n",
            b"S 2 0 2 0 0\nS 2 0 2 1 1\nOK 2\n",
        )
        for reply in invalid:
            with self.subTest(reply=reply), self.assertRaises(RuntimeError):
                controller_loop.parse_census_reply(reply, requested_sublinks=(2, 6))

    def test_census_reply_rejects_error_truncation_and_malformed_rows(self):
        invalid = (
            b"ERR unauthorized peer\n",
            b"S 2 0 2 123 99\n",
            b"S 2 0 2 nope 99\nOK 1\n",
            b"S 2 0 3 123 99\nOK 1\n",
            b"OK nope\n",
        )
        for reply in invalid:
            with self.subTest(reply=reply), self.assertRaises(RuntimeError):
                controller_loop.parse_census_reply(reply)

    def test_remote_error_reply_raises_instead_of_committing_controller_state(self):
        gate = controller_loop.GateClient("switch.test")
        control_socket = FakeControlSocket(b"ERR table full\n")
        with mock.patch.object(controller_loop.socket, "socket", return_value=control_socket):
            with self.assertRaisesRegex(RuntimeError, "table full"):
                gate.install_many(((0, 0, 0, 2, 1),))
        self.assertEqual(gate.write_us, [])

    def test_malformed_or_empty_reply_raises(self):
        gate = controller_loop.GateClient("switch.test")
        for reply in (b"", b"OK", b"OK nope", b"ATTN 2 3 4"):
            with self.subTest(reply=reply), \
                    mock.patch.object(controller_loop.socket, "socket",
                                      return_value=FakeControlSocket(reply)):
                with self.assertRaises(RuntimeError):
                    gate.install(0, 0, 0, 2, 1)

    def test_gate_reply_size_is_bounded(self):
        gate = controller_loop.GateClient("switch.test")
        control_socket = RecordingControlSocket([b"X" * controller_loop.MAX_GATE_REPLY_BYTES])
        with mock.patch.object(controller_loop.socket, "socket", return_value=control_socket):
            with self.assertRaisesRegex(RuntimeError, "exceeded"):
                gate.install(0, 0, 0, 2, 1)

    def test_gate_reply_can_arrive_fragmented_across_tcp_reads(self):
        gate = controller_loop.GateClient("switch.test")
        control_socket = RecordingControlSocket([b"O", b"K 7\n"])
        with mock.patch.object(controller_loop.socket, "socket", return_value=control_socket):
            self.assertEqual(gate.install(0, 0, 0, 2, 1), "OK 7")

        self.assertEqual(control_socket.sent, [b"Q 0 0 0 2 1\n"])

    def test_install_many_is_one_wire_operation(self):
        gate = controller_loop.GateClient("switch.test")
        with mock.patch.object(gate, "_send", return_value="OK 7") as send:
            reply = gate.install_many((
                (0, 0, 0, 2, 1),
                (0, 1, 0, 2, 1),
                (0, 2, 0, 2, 1),
                (0, 3, 0, 2, 1),
            ))

        self.assertEqual(reply, "OK 7")
        send.assert_called_once_with(
            "B 0 0 0 2 1 0 1 0 2 1 0 2 0 2 1 0 3 0 2 1\n")

    def test_targeted_census_names_only_demand_carrying_sublinks(self):
        gate = controller_loop.GateClient(
            "switch.test", census_sublinks=(14, 2, 10, 6, 2))
        self.assertEqual(gate.census_request(), b"R 2 6 10 14\n")

    def test_empty_target_set_retains_full_census_compatibility(self):
        gate = controller_loop.GateClient("switch.test")
        self.assertEqual(gate.census_request(), b"R\n")

    def test_set_epoch_requires_expected_modified_count(self):
        gate = controller_loop.GateClient("switch.test")
        sockets = []

        def socket_factory(*args):
            sock = RecordingControlSocket([b"OK 4\n"])
            sockets.append(sock)
            return sock

        with mock.patch.object(controller_loop.socket, "socket", side_effect=socket_factory):
            self.assertEqual(gate.set_epoch(12, expected_count=4), "OK 4")

        self.assertEqual(sockets[0].sent, [b"E 12\n"])
        self.assertEqual(gate.write_us, [], "row-count acknowledgements are not latency samples")
        with mock.patch.object(controller_loop.socket, "socket",
                               return_value=RecordingControlSocket([b"OK 3\n"])):
            with self.assertRaisesRegex(RuntimeError, "expected 4"):
                gate.set_epoch(12, expected_count=4)

    def test_agent_identity_must_match_expected_program(self):
        gate = controller_loop.GateClient("switch.test")
        reply = ("IDENTITY mcp_fabric_clf_eg %s %s 987\n" %
                 ("b" * 64, "c" * 64)).encode()
        with mock.patch.object(controller_loop.socket, "socket",
                               return_value=FakeControlSocket(reply)):
            identity = gate.verify_identity(
                "mcp_fabric_clf_eg", "b" * 64, "c" * 64)
        self.assertEqual(identity["build_id"], "b" * 64)
        self.assertEqual(identity["runtime_id"], "c" * 64)
        self.assertEqual(identity["switchd_pid"], 987)

        with mock.patch.object(controller_loop.socket, "socket",
                               return_value=FakeControlSocket(reply)):
            with self.assertRaisesRegex(RuntimeError, "expected mcp_fabric_gate_event"):
                gate.verify_identity("mcp_fabric_gate_event", "b" * 64, "c" * 64)

        for build_id, runtime_id, message in (
                ("a" * 64, "c" * 64, "build"),
                ("b" * 64, "d" * 64, "runtime")):
            with self.subTest(message=message), \
                    mock.patch.object(controller_loop.socket, "socket",
                                      return_value=FakeControlSocket(reply)):
                with self.assertRaisesRegex(RuntimeError, "expected %s" % message):
                    gate.verify_identity("mcp_fabric_clf_eg", build_id, runtime_id)

    def test_agent_identity_can_arrive_fragmented_across_tcp_reads(self):
        gate = controller_loop.GateClient("switch.test")
        reply = ("IDENTITY mcp_fabric_clf_eg %s %s 987\n" %
                 ("b" * 64, "c" * 64)).encode()
        control_socket = RecordingControlSocket([reply[:9], reply[9:40], reply[40:]])
        with mock.patch.object(controller_loop.socket, "socket", return_value=control_socket):
            identity = gate.verify_identity(
                "mcp_fabric_clf_eg", "b" * 64, "c" * 64)

        self.assertEqual(identity["runtime_id"], "c" * 64)
        self.assertEqual(control_socket.sent, [b"V\n"])

    def test_set_epoch_rejects_wrap_before_sending(self):
        gate = controller_loop.GateClient("switch.test")
        with mock.patch.object(controller_loop.socket, "socket") as socket_factory:
            with self.assertRaisesRegex(ValueError, "16-bit"):
                gate.set_epoch(65536, expected_count=4)
        socket_factory.assert_not_called()

    def test_reset_fails_closed_on_any_gate_delete_error(self):
        gate = mock.Mock()
        gate.remove.side_effect = ["OK 1", RuntimeError("delete failed")]
        with self.assertRaisesRegex(RuntimeError, "delete failed"):
            controller_loop.reset_gate_entries(gate, src_leaf=0, context=2)


class TestCampaignStop(unittest.TestCase):
    def test_campaign_stops_only_after_a_reroute_proof(self):
        self.assertFalse(controller_loop.campaign_complete(True, None))
        self.assertTrue(controller_loop.campaign_complete(True, 123))
        self.assertFalse(controller_loop.campaign_complete(False, 123))

    def test_publication_campaign_requires_targeted_census(self):
        with self.assertRaisesRegex(ValueError, "requires --census-sublinks"):
            controller_loop.require_targeted_census(True, ())
        controller_loop.require_targeted_census(True, (2, 6, 10, 14))
        controller_loop.require_targeted_census(False, ())


class FakeFeedback:
    def __init__(self):
        self.current_epoch = 0
        self.begun = []
        self.gaps = []
        self.clean_batches = []

    def begin_epoch(self, epoch):
        self.begun.append(epoch)
        self.current_epoch = epoch

    def on_gap(self, event):
        self.gaps.append(event)

    def observe_clean_batch(self, observations, epoch):
        self.clean_batches.append((tuple(observations), epoch))


class TestEpochApplication(unittest.TestCase):
    def test_advance_epoch_stamps_hardware_before_feedback_epoch(self):
        feedback = FakeFeedback()
        gate = mock.Mock()
        gate.set_epoch.return_value = "OK 4"

        controller_loop.advance_epoch(feedback, gate, 9, expected_epoch_rows=4)

        self.assertEqual(gate.set_epoch.call_args_list, [mock.call(9, 4)])
        self.assertEqual(feedback.begun, [9])

    def test_gap_event_hardware_epoch_is_not_relabelled(self):
        feedback = FakeFeedback()
        feedback.begin_epoch(7)
        event = controller_loop.GapEvent(vlink=2, context=3, epoch=7,
                                         gap=0xFFF0, observed_packets=100)

        controller_loop.apply_gap_event(feedback, event)

        self.assertEqual(feedback.gaps, [event])

    def test_stale_gap_event_is_dropped_before_decision_core(self):
        feedback = FakeFeedback()
        feedback.begin_epoch(9)
        event = controller_loop.GapEvent(vlink=2, context=3, epoch=8,
                                         gap=0xFFF0, observed_packets=100)

        self.assertFalse(controller_loop.apply_gap_event(feedback, event))

        self.assertEqual(feedback.gaps, [])

    def test_stale_census_result_is_dropped_without_relabelling(self):
        feedback = FakeFeedback()
        feedback.begin_epoch(9)

        applied = controller_loop.apply_census_result(
            feedback, census_epoch=8, observations=[(0, 2, 5)],
            quarantine_target=None)

        self.assertFalse(applied)
        self.assertEqual(feedback.clean_batches, [])

    def test_future_epoch_evidence_is_rejected_until_controller_catches_up(self):
        feedback = FakeFeedback()
        feedback.begin_epoch(9)
        event = controller_loop.GapEvent(vlink=2, context=3, epoch=10,
                                         gap=0xFFF0, observed_packets=100)

        self.assertFalse(controller_loop.apply_gap_event(feedback, event))
        self.assertFalse(controller_loop.apply_census_result(
            feedback, census_epoch=10, observations=[(0, 2, 5)],
            quarantine_target=None))
        self.assertEqual(feedback.gaps, [])
        self.assertEqual(feedback.clean_batches, [])


if __name__ == "__main__":
    unittest.main()
