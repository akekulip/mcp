"""P3 feedback path: coalescing, epoch/stale handling, reorder netting, evidence-sized probation."""
import json
import math
import pathlib
import unittest

from controller import sublink_feedback
from controller.sublink_feedback import (
    AUDIT_ROUND_MAX_TOKENS,
    AuditReceipt,
    AuditRound,
    GapEvent,
    SublinkFeedback,
    QUARANTINED,
    HEALTHY,
    probation_packets_required,
)


class Recorder:
    def __init__(self):
        self.installed, self.removed = [], []

    def install(self, src_leaf, dst_leaf, spray, ctx, alt):
        self.installed.append((src_leaf, dst_leaf, spray, ctx, alt))

    def remove(self, src_leaf, dst_leaf, spray, ctx):
        self.removed.append((src_leaf, dst_leaf, spray, ctx))


class FakeGC:
    class BfruntimeRpcException(Exception):
        pass

    @staticmethod
    def KeyTuple(name, value):
        return (name, value)

    @staticmethod
    def DataTuple(name, value):
        return (name, value)


class FakeGateTable:
    def __init__(self):
        self.added, self.modified, self.deleted = [], [], []

    def make_key(self, fields):
        return tuple(fields)

    def make_data(self, fields, action):
        return action, tuple(fields)

    def entry_add(self, target, keys, data):
        self.added.append((target, keys[0], data[0]))

    def entry_mod(self, target, keys, data):
        self.modified.append((target, keys[0], data[0]))

    def entry_del(self, target, keys):
        self.deleted.append((target, keys[0]))


class BrokenGateTable(FakeGateTable):
    def entry_add(self, target, keys, data):
        raise ValueError("malformed health-gate request")


class DuplicateGateTable(FakeGateTable):
    def entry_add(self, target, keys, data):
        raise FakeGC.BfruntimeRpcException("entry already exists")


class FakeBfrt:
    def __init__(self, table, expected="pipe.Ingress.tbl_health_gate"):
        self.table = table
        self.expected = expected

    def table_get(self, name):
        if name != self.expected:
            raise AssertionError("wrong BFRT table %s" % name)
        return self.table


def warm(fb, vlink=2, contexts=(0, 1, 2, 3), epochs=(1, 2, 3), packets=150000):
    """Sibling sublinks carrying production, which is where the background rate comes from."""
    for ctx in contexts:
        for ep in epochs:
            fb.observe_clean(vlink, ctx, packets, ep)


def deliver(fb, *events):
    """Feed gap events and then close the epoch's held evidence; -> the actions taken.

    A loss-bearing event is HELD for within-epoch reorder netting, so a test that needs the
    decision must displace or flush it, exactly as the epoch boundary does at runtime.
    """
    for ev in events:
        fb.on_gap(ev)
    return fb.flush_held()


def element_of(fb, vlink=2, context=3):
    return fb.infer_state.elements["sublink:%d" % ((vlink << 4) | context)]


class TestSublinkFeedback(unittest.TestCase):
    def setUp(self):
        self.rec = Recorder()
        self.fb = SublinkFeedback(self.rec.install, self.rec.remove)

    def test_sublink_id_and_loss_decode(self):
        ev = GapEvent(vlink=2, context=3, epoch=1, gap=0xFFFB, observed_packets=1000)
        self.assertEqual(ev.sublink, (2 << 4) | 3)
        self.assertEqual(ev.lost, 5, "a gap of 2^16-5 means five packets vanished")
        self.assertEqual(GapEvent(2, 3, 1, 1, 1000).lost, 0,
                         "a small positive gap is a duplicate or reorder, not loss")

    def test_observed_arrivals_are_not_reduced_by_the_gap_twice(self):
        """The survivor count and the inferred missing count are disjoint evidence."""
        self.fb.begin_epoch(1)
        deliver(self.fb, GapEvent(2, 3, 1, 0xFFFB, 1000))
        element = self.fb.infer_state.elements["sublink:%d" % ((2 << 4) | 3)]
        self.assertEqual(element.loss_alpha, 6.0)  # prior 1 + five missing packets
        self.assertEqual(element.loss_beta, 1001.0)  # prior 1 + 1000 observed arrivals

    def test_gap_against_sibling_background_quarantines(self):
        warm(self.fb)
        self.fb.begin_epoch(4)
        act = deliver(self.fb, GapEvent(2, 3, 4, 0xFFF0, 150000))
        self.assertEqual(act, ["QUARANTINE"])
        self.assertEqual(self.rec.installed, [
            (1, 0, 0, 3, 1), (1, 1, 0, 3, 1),
            (1, 2, 0, 3, 1), (1, 3, 0, 3, 1),
        ])

    def test_hardware_census_is_one_pooled_update_per_epoch(self):
        """A census is one fabric observation, not one observation per sublink.

        Applying ``forget_rho`` separately to every row makes the result depend on
        BFRT register iteration order and lets the fault sample replace its own
        reference population.  This is the hardware shape: four equally active
        contexts, five clean census epochs, then a 655-packet discontinuity after a
        saturated 16-bit clean run.  Batched evidence must retain enough sibling
        background to quarantine at the frozen h=6.5 operating point.
        """
        for epoch in range(1, 6):
            self.fb.observe_clean_batch(
                [(0, context, 6000) for context in range(4)], epoch)
        self.assertEqual(self.fb.infer_state.pool.n_obs_loss, 5)

        self.fb.begin_epoch(6)
        actions = deliver(self.fb, GapEvent(0, 2, 6, 0xFD71, 65536))

        self.assertEqual(actions, ["QUARANTINE"])
        self.assertEqual({context for _, _, _, context, _ in self.rec.installed}, {2})

    def test_healthy_sublink_is_not_quarantined(self):
        warm(self.fb)
        self.fb.begin_epoch(4)
        for ctx in (0, 1, 2, 3):
            self.fb.observe_clean(2, ctx, 150000, 4)
        self.assertEqual(self.rec.installed, [], "clean traffic must never install a quarantine")

    def test_coalescing_one_install_per_sublink_epoch(self):
        warm(self.fb)
        self.fb.begin_epoch(4)
        ev = GapEvent(2, 3, 4, 0xFFF0, 150000)
        self.assertIsNone(self.fb.on_gap(ev), "the first loss event is held for reorder netting")
        self.assertEqual(self.fb.on_gap(ev), "QUARANTINE",
                         "the second event displaces the held one, which is what decides")
        for _ in range(4):
            self.assertIsNone(self.fb.on_gap(ev), "further gaps in the same epoch must coalesce")
        self.assertEqual(len(self.rec.installed), 4)
        self.assertEqual(self.fb.summary()["coalesced"], 5)

    def test_stale_event_from_an_earlier_epoch_is_dropped(self):
        warm(self.fb)
        self.fb.begin_epoch(9)
        self.assertIsNone(self.fb.on_gap(GapEvent(2, 3, 4, 0xFFF0, 150000)))
        self.assertEqual(self.rec.installed, [], "an event about a past epoch must not act")
        self.assertEqual(self.fb.summary()["stale_dropped"], 1)

    def test_restore_requires_sustained_clean_evidence(self):
        warm(self.fb)
        self.fb.begin_epoch(4)
        deliver(self.fb, GapEvent(2, 3, 4, 0xFFF0, 150000))
        self.assertIsNone(self.fb.on_clean_epoch(2, 3, 1000), "one clean epoch is not enough")
        self.assertIsNone(self.fb.on_clean_epoch(2, 3, 1000))
        self.assertEqual(self.fb.on_clean_epoch(2, 3, 1000), "RESTORE")
        self.assertEqual(self.rec.removed, [
            (1, 0, 0, 3), (1, 1, 0, 3), (1, 2, 0, 3), (1, 3, 0, 3),
        ])

    def test_silence_on_a_quarantined_primary_is_not_clean_evidence(self):
        """Removing the production route makes the primary silent by construction.

        A timer that counts that silence as clean would restore the failed sublink without a
        single packet traversing it.  Restoration must therefore wait for explicit positive
        observations from a probation or audit path.
        """
        warm(self.fb)
        self.fb.begin_epoch(4)
        deliver(self.fb, GapEvent(2, 3, 4, 0xFFF0, 150000))
        for _ in range(10):
            self.assertIsNone(self.fb.on_clean_epoch(2, 3))
        self.assertEqual(self.rec.removed, [],
                         "absence of gaps on an unobserved primary must not restore it")
        self.assertEqual(self.fb.state[(2 << 4) | 3].state, QUARANTINED)

    def test_repeated_quarantine_is_damped(self):
        """A repeatedly failing sublink requires progressively more observed clean evidence."""
        warm(self.fb)
        self.fb.begin_epoch(4)
        deliver(self.fb, GapEvent(2, 3, 4, 0xFFF0, 150000))
        for _ in range(3):
            self.fb.on_clean_epoch(2, 3, 1000)
        self.fb.begin_epoch(5)
        deliver(self.fb, GapEvent(2, 3, 5, 0xFFF0, 150000))
        cleans = 0
        while self.fb.on_clean_epoch(2, 3, 1000) != "RESTORE":
            cleans += 1
            self.assertLess(cleans, 20, "damping must still terminate")
        self.assertGreaterEqual(cleans + 1, 6,
                                "a second quarantine must require more clean evidence than the first")

    def test_other_contexts_of_the_same_link_are_untouched(self):
        warm(self.fb)
        self.fb.begin_epoch(4)
        deliver(self.fb, GapEvent(2, 3, 4, 0xFFF0, 150000))
        installed_contexts = {c for _, _, _, c, _ in self.rec.installed}
        self.assertEqual(installed_contexts, {3},
                         "quarantine must name one behavioural sublink, not the whole link")

    def test_install_names_the_exact_health_gate_key(self):
        """The P2 table is keyed by src, dst, selected spray, and context.

        A feedback callback that only receives ``(vlink, context)`` cannot program that table: the
        same directed link participates in paths to multiple destinations.  The installed record
        must therefore carry all four key fields plus the alternate spray.
        """
        warm(self.fb)
        self.fb.begin_epoch(4)
        deliver(self.fb, GapEvent(2, 3, 4, 0xFFF0, 150000))
        self.assertEqual(self.rec.installed, [
            (1, 0, 0, 3, 1), (1, 1, 0, 3, 1),
            (1, 2, 0, 3, 1), (1, 3, 0, 3, 1),
        ], "an uplink fault must protect every destination sharing that directed link")

    def test_quarantine_can_install_all_exact_keys_as_one_batch(self):
        batches = []
        feedback = SublinkFeedback(
            self.rec.install, self.rec.remove,
            install_many=lambda rows: batches.append(tuple(rows)))
        warm(feedback)
        feedback.begin_epoch(4)

        deliver(feedback, GapEvent(2, 3, 4, 0xFFF0, 150000))

        self.assertEqual(self.rec.installed, [], "the scalar compatibility path must not run")
        self.assertEqual(batches, [(
            (1, 0, 0, 3, 1), (1, 1, 0, 3, 1),
            (1, 2, 0, 3, 1), (1, 3, 0, 3, 1),
        )])

    def test_failed_batch_does_not_commit_a_false_quarantined_state(self):
        def fail(_rows):
            raise RuntimeError("switch write failed")

        feedback = SublinkFeedback(
            self.rec.install, self.rec.remove, install_many=fail)
        warm(feedback)
        feedback.begin_epoch(4)
        feedback.on_gap(GapEvent(2, 3, 4, 0xFFF0, 150000))
        inference_before = feedback.infer_state

        with self.assertRaisesRegex(RuntimeError, "switch write failed"):
            feedback.flush_held()

        state = feedback.state[(2 << 4) | 3]
        self.assertEqual(state.state, HEALTHY)
        self.assertEqual(state.gate_keys, ())
        self.assertEqual(feedback.installs, 0)
        self.assertIn((2 << 4) | 3, feedback.held,
                      "failed hardware evidence must remain retryable")
        self.assertIs(feedback.infer_state, inference_before,
                      "failed actuation must not commit or duplicate inference evidence")

    def test_gate_key_expansion_covers_both_link_directions(self):
        self.assertEqual(sublink_feedback.gate_keys_for_sublink(2, 7), (
            (1, 0, 0, 7), (1, 1, 0, 7), (1, 2, 0, 7), (1, 3, 0, 7),
        ))
        self.assertEqual(sublink_feedback.gate_keys_for_sublink(13, 7), (
            (0, 1, 1, 7), (1, 1, 1, 7), (2, 1, 1, 7), (3, 1, 1, 7),
        ))


class TestAuditRound(unittest.TestCase):
    def setUp(self):
        self.rec = Recorder()
        # These cases exercise ROUND mechanics.  The packet budget is real and is exercised at
        # its 1e-3 default in TestEvidenceSizedProbation; here a 0.2 target keeps the budget
        # (14 packets) inside what two declared rounds can actually carry, so the rounds below
        # supply enough evidence rather than the criterion being relaxed.
        self.fb = SublinkFeedback(
            self.rec.install, self.rec.remove, clean_epochs_to_restore=2, p_restore_target=0.2)
        warm(self.fb)
        self.fb.begin_epoch(4)
        deliver(self.fb, GapEvent(2, 3, 4, 0xFFF0, 150000))

    def _receipt(self, token, epoch=5, gap=0, vlink=2, context=3):
        return AuditReceipt(vlink, context, epoch, token, token - 40000, gap)

    def test_complete_declared_receipts_count_as_one_positive_clean_epoch(self):
        self.fb.begin_epoch(5)
        audit = AuditRound(2, 3, 5, (40001, 40002, 40003))
        for token in audit.expected_tokens:
            self.assertTrue(audit.accept(self._receipt(token)))
        result = audit.finish(self.fb)
        self.assertEqual((result.status, result.sent, result.received, result.missing),
                         ("CLEAN", 3, 3, ()))
        self.assertEqual(self.fb.state[(2 << 4) | 3].clean_epochs, 1)
        self.assertEqual(self.rec.removed, [])

    def test_missing_receipt_is_negative_liveness_evidence_and_never_restores(self):
        self.fb.begin_epoch(5)
        audit = AuditRound(2, 3, 5, (40001, 40002, 40003))
        audit.accept(self._receipt(40001))
        audit.accept(self._receipt(40003))
        result = audit.finish(self.fb)
        self.assertEqual(result.status, "INCOMPLETE")
        self.assertEqual(result.missing, (40002,))
        self.assertEqual(self.fb.state[(2 << 4) | 3].clean_epochs, 0)
        self.assertEqual(self.fb.state[(2 << 4) | 3].state, QUARANTINED)
        self.assertEqual(self.rec.removed, [])

    def test_gap_receipt_is_explicit_loss_and_never_counts_clean(self):
        self.fb.begin_epoch(5)
        audit = AuditRound(2, 3, 5, (40001, 40002))
        audit.accept(self._receipt(40001))
        audit.accept(self._receipt(40002, gap=0xFFFB))
        result = audit.finish(self.fb)
        self.assertEqual(result.status, "LOSS")
        self.assertEqual(result.gap_tokens, (40002,))
        self.assertEqual(self.fb.state[(2 << 4) | 3].clean_epochs, 0)
        self.assertEqual(self.rec.removed, [])

    def test_stale_wrong_sublink_and_undeclared_receipts_cannot_certify(self):
        self.fb.begin_epoch(5)
        audit = AuditRound(2, 3, 5, (40001,))
        self.assertFalse(audit.accept(self._receipt(40001, epoch=4)))
        self.assertFalse(audit.accept(self._receipt(40001, vlink=3)))
        self.assertFalse(audit.accept(self._receipt(49999)))
        result = audit.finish(self.fb)
        self.assertEqual((result.status, result.invalid_receipts), ("INCOMPLETE", 3))
        self.assertEqual(result.missing, (40001,))

    def test_duplicate_receipt_does_not_inflate_evidence_and_finish_is_idempotent(self):
        self.fb.begin_epoch(5)
        audit = AuditRound(2, 3, 5, (40001,))
        self.assertTrue(audit.accept(self._receipt(40001)))
        self.assertFalse(audit.accept(self._receipt(40001)))
        first = audit.finish(self.fb)
        second = audit.finish(self.fb)
        self.assertIs(first, second)
        self.assertEqual((first.status, first.received, first.duplicate_receipts),
                         ("CLEAN", 1, 1))
        self.assertEqual(self.fb.state[(2 << 4) | 3].clean_epochs, 1)

    def test_sustained_complete_rounds_restore_but_a_stale_round_cannot(self):
        """Full 16-token rounds, so the packet budget is met by evidence, not by relaxation."""
        needed = self.fb.probation_packets_needed(2, 3)
        self.assertLessEqual(needed, 2 * AUDIT_ROUND_MAX_TOKENS,
                             "this fixture must be able to pay its own budget in two rounds")
        self.fb.begin_epoch(5)
        first = AuditRound(2, 3, 5, tuple(range(40001, 40001 + AUDIT_ROUND_MAX_TOKENS)))
        for token in first.expected_tokens:
            first.accept(self._receipt(token))
        self.assertEqual(first.finish(self.fb).status, "CLEAN")

        self.fb.begin_epoch(6)
        stale = AuditRound(2, 3, 5, (40100,))
        stale.accept(self._receipt(40100, epoch=5))
        self.assertEqual(stale.finish(self.fb).status, "STALE")
        self.assertEqual(self.rec.removed, [])

        second = AuditRound(2, 3, 6, tuple(range(40201, 40201 + AUDIT_ROUND_MAX_TOKENS)))
        for token in second.expected_tokens:
            second.accept(self._receipt(token, epoch=6))
        self.assertEqual(second.finish(self.fb).status, "RESTORE")
        self.assertEqual(len(self.rec.removed), 4)

    def test_round_requires_a_nonempty_unique_set_within_the_p4_table_capacity(self):
        with self.assertRaisesRegex(ValueError, "at least one"):
            AuditRound(2, 3, 5, ())
        with self.assertRaisesRegex(ValueError, "unique"):
            AuditRound(2, 3, 5, (40001, 40001))
        with self.assertRaisesRegex(ValueError, "16"):
            AuditRound(2, 3, 5, tuple(range(17)))


class TestBfrtHealthGate(unittest.TestCase):
    def test_writer_programs_and_removes_the_p2_exact_key(self):
        """Catch a controller that claims to install P2 but never emits the table's real schema."""
        writer_cls = getattr(sublink_feedback, "BfrtHealthGate", None)
        if writer_cls is None:
            self.fail("P3 has no BFRT writer for the P2 health gate")
        table = FakeGateTable()
        writer = writer_cls(FakeGC, FakeBfrt(table), "target")
        writer.install(1, 2, 0, 7, 1)
        writer.remove(1, 2, 0, 7)
        key = (("md.src_leaf", 1), ("md.dst_leaf", 2),
               ("md.spray_idx", 0), ("md.ctx", 7))
        self.assertEqual(table.added, [
            ("target", key, ("Ingress.sublink_reroute", (("alt_spray", 1),))),
        ])
        self.assertEqual(table.modified, [])
        self.assertEqual(table.deleted, [("target", key)])

    def test_writer_modifies_an_existing_p2_exact_key(self):
        table = DuplicateGateTable()
        writer = sublink_feedback.BfrtHealthGate(FakeGC, FakeBfrt(table), "target")
        writer.install(1, 2, 0, 7, 1)
        key = (("md.src_leaf", 1), ("md.dst_leaf", 2),
               ("md.spray_idx", 0), ("md.ctx", 7))
        self.assertEqual(table.modified, [
            ("target", key, ("Ingress.sublink_reroute", (("alt_spray", 1),))),
        ])

    def test_writer_does_not_mask_non_bfrt_failures_as_duplicate_entries(self):
        writer = sublink_feedback.BfrtHealthGate(FakeGC, FakeBfrt(BrokenGateTable()), "target")
        with self.assertRaisesRegex(ValueError, "malformed"):
            writer.install(1, 2, 0, 7, 1)


class TestBfrtAuditSteer(unittest.TestCase):
    def test_writer_installs_modifies_and_removes_declared_probe_token(self):
        table = FakeGateTable()
        writer = sublink_feedback.BfrtAuditSteer(
            FakeGC, FakeBfrt(table, "pipe.Ingress.tbl_audit_steer"), "target")
        writer.install(40001, spray=0)
        writer.remove(40001)
        key = (("md.audit_src", 1),
               ("hdr.udp.dst_port", sublink_feedback.AUDIT_UDP_DST),
               ("hdr.udp.src_port", 40001))
        self.assertEqual(table.added, [
            ("target", key, ("Ingress.set_audit_spray", (("spray", 0),))),
        ])
        self.assertEqual(table.deleted, [("target", key)])

        duplicate = DuplicateGateTable()
        writer = sublink_feedback.BfrtAuditSteer(
            FakeGC, FakeBfrt(duplicate, "pipe.Ingress.tbl_audit_steer"), "target")
        writer.install(40001, spray=1)
        self.assertEqual(duplicate.modified, [
            ("target", key, ("Ingress.set_audit_spray", (("spray", 1),))),
        ])

    def test_writer_rejects_values_outside_the_p4_contract(self):
        writer = sublink_feedback.BfrtAuditSteer(
            FakeGC, FakeBfrt(FakeGateTable(), "pipe.Ingress.tbl_audit_steer"), "target")
        with self.assertRaisesRegex(ValueError, "token"):
            writer.install(65536, spray=0)
        with self.assertRaisesRegex(ValueError, "spray"):
            writer.install(40001, spray=2)

    def test_writer_key_matches_the_checked_in_current_bfrt_schema(self):
        schema_path = (pathlib.Path(__file__).resolve().parents[2] /
                       "p4/hw/schema/mcp_fabric_gate_event.bfrt.json")
        schema = json.loads(schema_path.read_text())
        table = next(t for t in schema["tables"]
                     if t["name"] == "pipe.Ingress.tbl_audit_steer")
        self.assertEqual(
            [field["name"] for field in table["key"]],
            ["md.audit_src", "hdr.udp.dst_port", "hdr.udp.src_port"],
        )


class TestReorderCredit(unittest.TestCase):
    """Rule 2 of `sim/dynamic/PREREG.md`: pure reordering must not manufacture loss.

    The event tuples below are emulated from the compiled Tofino assembly and cross-checked
    against `p4/ptf/gap_event/test.py::Test50` (`docs/review/P3-DYNAMIC-RESULT.md`).
    """

    # (arrival order, events as (gap, observed_packets), real packets lost)
    ONE_SWAP = ("0,1,3,2,4,5", [(0xFFFF, 4), (0x0002, 2)], 0)
    LATE_SWAP = ("0,1,2,3,5,4,6,7", [(0xFFFF, 6), (0x0002, 2)], 0)
    PTF_TEST50 = ("0,1,4,5", [(0xFFFE, 3)], 2)

    def setUp(self):
        self.rec = Recorder()
        self.fb = SublinkFeedback(self.rec.install, self.rec.remove)
        warm(self.fb)
        self.fb.begin_epoch(4)

    def _events(self, spec, vlink=2, context=3, epoch=4):
        return [GapEvent(vlink, context, epoch, gap, obs) for gap, obs in spec]

    def _net_loss_fed_to_infer(self, vlink=2, context=3):
        """Loss reaching the frozen layer, read off its state rather than a controller counter."""
        prior = sublink_feedback.infer.PRIOR_BETA_ALPHA
        return element_of(self.fb, vlink, context).loss_alpha - prior

    def test_pure_reordering_feeds_zero_loss_and_never_quarantines(self):
        for arrivals, spec, real_loss in (self.ONE_SWAP, self.LATE_SWAP):
            with self.subTest(arrivals=arrivals):
                rec, fb = Recorder(), None
                fb = SublinkFeedback(rec.install, rec.remove)
                warm(fb)
                fb.begin_epoch(4)
                self.fb = fb
                self.assertEqual(deliver(fb, *self._events(spec)), [])
                self.assertEqual(self._net_loss_fed_to_infer(), real_loss,
                                 "reordering must not manufacture loss for the frozen layer")
                self.assertEqual(rec.installed, [], "a reorder must never quarantine")
                self.assertEqual(fb.summary()["netted_out"], 1)
                self.assertEqual(fb.summary()["reorder_credits"], 1)

    def test_the_ptf_test50_loss_sequence_is_untouched_and_still_quarantines(self):
        arrivals, spec, real_loss = self.PTF_TEST50
        self.assertEqual(deliver(self.fb, *self._events(spec)), ["QUARANTINE"], arrivals)
        self.assertEqual(self._net_loss_fed_to_infer(), real_loss,
                         "real loss must reach the frozen layer unreduced")
        self.assertEqual(self.rec.installed, [
            (1, 0, 0, 3, 1), (1, 1, 0, 3, 1), (1, 2, 0, 3, 1), (1, 3, 0, 3, 1),
        ])
        self.assertEqual(self.fb.summary()["reorder_credits"], 0)

    def test_a_credit_never_pushes_the_reported_loss_below_zero(self):
        events = self._events([(0xFFFD, 5)] + [(0x0002, 1)] * 6)   # three lost, six credits
        self.assertEqual(deliver(self.fb, *events), [])
        self.assertEqual(self._net_loss_fed_to_infer(), 0.0)
        self.assertEqual(self.fb.summary()["reorder_credits"], 3,
                         "only the packets actually reported missing can be credited back")
        self.assertEqual(self.fb.summary()["netted_out"], 1)
        self.assertEqual(self.rec.installed, [])

    def test_a_credit_on_a_different_sublink_does_not_cancel(self):
        self.fb.on_gap(GapEvent(2, 3, 4, 0xFFFE, 3))
        self.fb.on_gap(GapEvent(2, 2, 4, 0x0002, 2))       # sibling context, same physical link
        self.assertEqual(self.fb.flush_held(), ["QUARANTINE"])
        self.assertEqual(self._net_loss_fed_to_infer(2, 3), 2.0)
        self.assertEqual(self.fb.summary()["reorder_credits"], 0)

    def test_a_credit_in_a_later_epoch_cannot_cancel(self):
        self.fb.on_gap(GapEvent(2, 3, 4, 0xFFFE, 3))
        self.fb.begin_epoch(5)                              # flush: nothing is held across epochs
        self.assertEqual(self._net_loss_fed_to_infer(), 2.0)
        self.fb.on_gap(GapEvent(2, 3, 5, 0x0002, 2))
        self.assertEqual(self.fb.summary()["reorder_credits"], 0,
                         "a credit may only cancel loss reported in its own epoch")
        self.assertEqual(self.fb.summary()["netted_out"], 0)
        self.assertEqual(len(self.rec.installed), 4,
                         "the quarantine taken at the epoch flush stands")

    def test_a_credit_cannot_cancel_a_held_event_belonging_to_another_epoch(self):
        """The netting window is one epoch, independently of when the flush happens.

        An event that arrives early and describes the next epoch is held, but a credit observed in
        the current epoch is not a receipt for it.
        """
        self.fb.on_gap(GapEvent(2, 3, 5, 0xFFFE, 3))       # early: describes the next epoch
        self.fb.on_gap(GapEvent(2, 3, 4, 0x0002, 2))       # a receipt from this epoch
        self.assertEqual(self.fb.summary()["reorder_credits"], 0)
        self.assertEqual(self.fb.flush_held(), ["QUARANTINE"])
        self.assertEqual(self._net_loss_fed_to_infer(), 2.0)

    def test_a_held_event_on_a_sublink_that_then_goes_silent_is_still_delivered(self):
        """A link failing to a blackhole emits one gap and nothing else, ever."""
        self.assertIsNone(self.fb.on_gap(GapEvent(2, 3, 4, 0xFFF0, 150000)))
        self.assertEqual(self.rec.installed, [], "the first loss event is held, not yet decided")
        self.fb.begin_epoch(5)                              # no further event on this sublink
        self.assertEqual(self._net_loss_fed_to_infer(), 16.0)
        self.assertEqual(len(self.rec.installed), 4, "held evidence must not be lost with the link")
        self.assertEqual(self.fb.state[(2 << 4) | 3].state, QUARANTINED)
        self.assertEqual(self.fb.summary()["held"], 0)

    def test_a_real_loss_beside_a_reorder_nets_to_the_real_loss_only(self):
        """One swap beside one genuine loss: the witness reports two, the truth is one.

        The paired control is the same event without the credit, so the assertion is that the
        credit removed exactly the phantom packet -- not that it silenced the sublink.
        """
        control_rec = Recorder()
        control = SublinkFeedback(control_rec.install, control_rec.remove)
        warm(control)
        control.begin_epoch(4)
        self.assertEqual(deliver(control, GapEvent(2, 3, 4, 0xFFFE, 4)), ["QUARANTINE"])
        self.assertEqual(
            element_of(control).loss_alpha - sublink_feedback.infer.PRIOR_BETA_ALPHA, 2.0)

        self.assertEqual(deliver(self.fb, *self._events([(0xFFFE, 4), (0x0002, 2)])), [])
        self.assertEqual(self._net_loss_fed_to_infer(), 1.0)
        self.assertEqual(self.rec.installed, [],
                         "one real loss beside a swap is not the two the witness reported")

    def test_a_gap_above_the_credit_window_is_not_a_credit(self):
        self.assertEqual(self.fb.reorder_credit_max, sublink_feedback.REORDER_CREDIT_MAX)
        self.assertTrue(self.fb.is_reorder_credit(GapEvent(2, 3, 4, self.fb.reorder_credit_max, 1)))
        self.assertFalse(
            self.fb.is_reorder_credit(GapEvent(2, 3, 4, self.fb.reorder_credit_max + 1, 1)))
        self.assertFalse(self.fb.is_reorder_credit(GapEvent(2, 3, 4, 0, 1)))
        self.fb.on_gap(GapEvent(2, 3, 4, 0xFFFE, 3))
        self.fb.on_gap(GapEvent(2, 3, 4, self.fb.reorder_credit_max + 1, 1))
        self.assertEqual(self._net_loss_fed_to_infer(), 2.0,
                         "a gap outside the credit window displaces the held event unreduced")
        self.assertEqual(self.fb.summary()["reorder_credits"], 0)

    def test_a_credit_still_contributes_its_arrivals_to_the_shared_pool(self):
        fresh = SublinkFeedback(self.rec.install, self.rec.remove)
        fresh.begin_epoch(4)
        fresh.on_gap(GapEvent(5, 1, 4, 0x0002, 700))
        element = fresh.infer_state.elements["sublink:%d" % ((5 << 4) | 1)]
        self.assertEqual(element.loss_alpha, sublink_feedback.infer.PRIOR_BETA_ALPHA,
                         "a credit is never loss evidence")
        self.assertEqual(element.loss_beta,
                         sublink_feedback.infer.PRIOR_BETA_BETA + 700,
                         "a credit is still a receipt that 700 packets arrived")


class TestEvidenceSizedProbation(unittest.TestCase):
    """Rule 4 of `sim/dynamic/PREREG.md`: restoration must be priced in evidence, not in rounds."""

    def setUp(self):
        self.rec = Recorder()
        self.fb = SublinkFeedback(self.rec.install, self.rec.remove)
        warm(self.fb)
        self.fb.begin_epoch(4)
        deliver(self.fb, GapEvent(2, 3, 4, 0xFFF0, 150000))

    def test_probation_packets_required_matches_the_closed_form(self):
        for p_target in (1e-2, 1e-3, 1e-4):
            for alpha in (0.05, 0.01):
                with self.subTest(p_target=p_target, alpha=alpha):
                    expected = int(math.ceil(math.log(alpha) / math.log(1.0 - p_target)))
                    self.assertEqual(probation_packets_required(p_target, alpha), expected)

    def test_the_reported_operating_point_is_derived_not_asserted(self):
        budget = self.fb.probation_budget()
        self.assertEqual(budget["packets"], probation_packets_required(1e-3, 0.05))
        self.assertEqual(budget["packets"], 2995)            # docs/review/P3-DYNAMIC-RESULT.md
        self.assertEqual(budget["packets_per_round"], AUDIT_ROUND_MAX_TOKENS)
        self.assertEqual(budget["rounds"], 188)
        self.assertAlmostEqual(budget["seconds"], 18.8)
        self.assertGreaterEqual(budget["rounds"] * budget["packets_per_round"], budget["packets"])
        self.assertLess((budget["rounds"] - 1) * budget["packets_per_round"], budget["packets"])

    def test_three_full_audit_rounds_do_not_restore_a_still_faulty_sublink(self):
        """The frozen k=3 rule certified a 1e-3 sublink 95.3 % of the time: 48 packets
        exclude nothing."""
        for _ in range(self.fb.clean_epochs_to_restore):
            self.assertIsNone(self.fb.on_clean_epoch(2, 3, AUDIT_ROUND_MAX_TOKENS))
        state = self.fb.state[(2 << 4) | 3]
        self.assertEqual(state.clean_epochs, self.fb.clean_epochs_to_restore)
        self.assertEqual(state.clean_packets,
                         self.fb.clean_epochs_to_restore * AUDIT_ROUND_MAX_TOKENS)
        self.assertEqual(state.state, QUARANTINED)
        self.assertEqual(self.rec.removed, [], "the round count is met; the evidence is not")

    def test_restoration_happens_once_the_accumulated_budget_is_met(self):
        needed = self.fb.probation_packets_needed(2, 3)
        expected_rounds = self.fb.probation_budget()["rounds"]
        rounds = 0
        while True:
            rounds += 1
            action = self.fb.on_clean_epoch(2, 3, AUDIT_ROUND_MAX_TOKENS)
            if action == "RESTORE":
                break
            self.assertLess(rounds, 10 * expected_rounds, "probation must terminate")
        self.assertEqual(rounds, expected_rounds)
        self.assertGreaterEqual(rounds * AUDIT_ROUND_MAX_TOKENS, needed)
        self.assertEqual(self.fb.state[(2 << 4) | 3].state, HEALTHY)
        self.assertEqual(len(self.rec.removed), 4)

    def test_the_damping_multiplier_scales_the_packet_budget(self):
        per_round = 500
        while self.fb.on_clean_epoch(2, 3, per_round) != "RESTORE":
            pass
        self.fb.begin_epoch(5)
        deliver(self.fb, GapEvent(2, 3, 5, 0xFFF0, 150000))
        state = self.fb.state[(2 << 4) | 3]
        self.assertEqual(state.quarantines, 2)
        self.assertEqual(self.fb.probation_packets_needed(2, 3), 2 * self.fb.probation_packets)
        rounds_by_count = self.fb.clean_epochs_to_restore * state.quarantines
        for _ in range(rounds_by_count):
            self.assertIsNone(self.fb.on_clean_epoch(2, 3, per_round))
        self.assertEqual(state.clean_epochs, rounds_by_count,
                         "the round count is satisfied and restoration is still refused")
        rounds = rounds_by_count
        while self.fb.on_clean_epoch(2, 3, per_round) != "RESTORE":
            rounds += 1
            self.assertLess(rounds, 100, "damped probation must still terminate")
        rounds += 1
        self.assertEqual(rounds, -(-2 * self.fb.probation_packets // per_round),
                         "a second quarantine must demand twice the packets, "
                         "not merely twice the rounds")

    def test_a_round_with_no_observed_packets_contributes_nothing(self):
        for _ in range(50):
            self.assertIsNone(self.fb.on_clean_epoch(2, 3, 0))
        state = self.fb.state[(2 << 4) | 3]
        self.assertEqual((state.clean_epochs, state.clean_packets), (0, 0))
        self.assertEqual(state.state, QUARANTINED)

    def test_the_budget_rejects_impossible_targets(self):
        with self.assertRaisesRegex(ValueError, "p_restore_target"):
            probation_packets_required(0.0, 0.05)
        with self.assertRaisesRegex(ValueError, "restore_alpha"):
            probation_packets_required(1e-3, 1.0)


if __name__ == "__main__":
    unittest.main()
