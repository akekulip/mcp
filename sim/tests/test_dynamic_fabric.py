"""Dynamic-operating-point fabric: loss composition, C-W4 emission, gate honouring, determinism.

Each test pins one clause of ``sim/dynamic/PREREG.md``; if the clause is broken the test fails.
The blackhole and gate tests exist because a harness that reports evidence a real witness could
never see would measure the harness, not the mechanism (HURDLES H29/H32).
"""
import random
import time
import unittest
from unittest import mock

from controller.sublink_feedback import SublinkFeedback, gate_keys_for_sublink
from sim.dynamic import fabric as fabric_mod
from sim.dynamic.fabric import (
    ARRIVAL_MAX,
    EPOCH_US,
    PKT_PER_LINK_EPOCH,
    WITNESS_MODES,
    Fabric,
    FaultSpec,
    _SublinkState,
)


def witness_trace(arrivals, witness_mode="baseline", seq_start=0):
    """Drive the real witness state object over an explicit arrival order."""
    st = _SublinkState(next_seq=seq_start, expect_seq=seq_start, witness_mode=witness_mode)
    out = []
    for seq in arrivals:
        gap, observed = st.observe(seq)
        if gap != 0:
            lost = (1 << 16) - gap if gap > (1 << 15) else 0
            out.append((gap, lost, observed))
    return out


def witness_events(arrivals, witness_mode="baseline", seq_start=0):
    """``(seq, gap)`` for every event, i.e. the tuples quoted in docs/review/P3-DYNAMIC-RESULT.md."""
    st = _SublinkState(next_seq=seq_start, expect_seq=seq_start, witness_mode=witness_mode)
    out = []
    for seq in arrivals:
        gap, _ = st.observe(seq)
        if gap != 0:
            out.append((seq, gap))
    return out


def naive_unsigned_trace(arrivals, seq_start=0):
    """The REJECTED formulation ``if (v <= seq) v = seq + 1`` -- unsigned, not modular.

    Not a supported ``witness_mode``: it lives here only so the wrap-with-loss test can show what
    it costs.  `docs/review/P3-DYNAMIC-RESULT.md` records that wrap ALONE does not distinguish the
    three formulations, so a wrap-only regression test would have let this through.
    """
    expect = seq_start & 0xFFFF
    out = []
    for seq in arrivals:
        gap = (expect - seq) & 0xFFFF
        if expect <= seq:
            expect = (seq + 1) & 0xFFFF
        if gap != 0:
            out.append((seq, gap))
    return out


class LossCompositionTest(unittest.TestCase):
    def test_fault_composes_with_background_instead_of_overwriting_it(self):
        """H32: an injector that assigns p_eff = p_fault deletes the background rate."""
        fab = Fabric(seed=1, scenario="persistent_partial", p_bg=1e-6,
                     faults=[FaultSpec(vlink=3, context=1, p_fault=1e-3, onset_epoch=0)])
        self.assertEqual(fab.p_eff(3, 1, 0), 1.0 - (1.0 - 1e-6) * (1.0 - 1e-3))
        self.assertNotEqual(fab.p_eff(3, 1, 0), 1e-3)
        self.assertEqual(fab.p_eff(3, 0, 0), 1e-6)          # sibling context keeps the background
        self.assertEqual(fab.p_eff(2, 1, 0), 1e-6)          # sibling vlink too

    def test_fault_window_respects_onset_clear_and_duty(self):
        fab = Fabric(seed=1, scenario="intermittent", p_bg=1e-6, faults=[
            FaultSpec(vlink=0, context=0, p_fault=1e-2, onset_epoch=5, clear_epoch=9),
            FaultSpec(vlink=1, context=0, p_fault=1e-2, onset_epoch=0, duty=(2, 3)),
        ])
        self.assertEqual(fab.p_eff(0, 0, 4), 1e-6)
        self.assertGreater(fab.p_eff(0, 0, 5), 1e-3)
        self.assertEqual(fab.p_eff(0, 0, 9), 1e-6)
        self.assertGreater(fab.p_eff(1, 0, 0), 1e-3)        # on-phase epochs 0,1
        self.assertEqual(fab.p_eff(1, 0, 2), 1e-6)          # off-phase epochs 2,3,4
        self.assertGreater(fab.p_eff(1, 0, 5), 1e-3)        # on again


class EmissionRuleTest(unittest.TestCase):
    def test_total_blackhole_emits_no_evidence_while_a_sibling_still_does(self):
        """A run with no surviving successor is not observable, so a blackhole is silent."""
        fab = Fabric(seed=7, scenario="all_context_blackhole", p_bg=1e-6, faults=[
            FaultSpec(vlink=0, context=0, p_fault=1.0, onset_epoch=0),
            FaultSpec(vlink=0, context=1, p_fault=1e-2, onset_epoch=0),
        ])
        dark, lit, dark_lost = 0, 0, 0
        for epoch in range(40):
            out = fab.step(epoch)
            for _, ev in out.gap_events:
                if (ev.vlink, ev.context) == (0, 0):
                    dark += 1
                elif (ev.vlink, ev.context) == (0, 1):
                    lit += 1
            dark_lost += out.lost[(0, 0)]
        self.assertEqual(dark, 0)
        self.assertGreater(lit, 0)
        self.assertGreater(dark_lost, 0)                    # packets really were destroyed

    def test_selective_blackhole_silences_one_context_and_leaves_siblings_reporting(self):
        fab = Fabric(seed=11, scenario="selective_blackhole", p_bg=1e-6,
                     faults=[FaultSpec(vlink=2, context=0, p_fault=1.0, onset_epoch=0)])
        seen_clean, events = set(), 0
        for epoch in range(20):
            out = fab.step(epoch)
            events += sum(1 for _, ev in out.gap_events if (ev.vlink, ev.context) == (2, 0))
            seen_clean |= {(v, c) for v, c, _ in out.clean_obs}
        self.assertEqual(events, 0)
        self.assertNotIn((2, 0), seen_clean)                # silence, not a clean observation
        for context in (1, 2, 3):
            self.assertIn((2, context), seen_clean)

    def test_run_across_the_sequence_wrap_gives_the_same_gap_as_away_from_it(self):
        """gap = (-L) mod 2^16 must not depend on where the 16-bit counter happens to be."""
        share = (20.0 / PKT_PER_LINK_EPOCH,) * 4
        faults = [FaultSpec(vlink=0, context=0, p_fault=0.3, onset_epoch=0)]
        wrapping = Fabric(seed=5, scenario="wrap", p_bg=0.0, faults=faults,
                          context_share=share, seq_start=(1 << 16) - 25)
        far = Fabric(seed=5, scenario="wrap", p_bg=0.0, faults=faults,
                     context_share=share, seq_start=100)
        wrapped, gaps_w, gaps_f = False, [], []
        prev = wrapping._sub[(0, 0)].next_seq
        for epoch in range(8):
            for _, ev in wrapping.step(epoch).gap_events:
                if (ev.vlink, ev.context) == (0, 0):
                    gaps_w.append((ev.gap, ev.lost))
            for _, ev in far.step(epoch).gap_events:
                if (ev.vlink, ev.context) == (0, 0):
                    gaps_f.append((ev.gap, ev.lost))
            now = wrapping._sub[(0, 0)].next_seq
            wrapped = wrapped or now < prev
            prev = now
        self.assertTrue(wrapped, "the test did not actually cross 65535 -> 0")
        self.assertTrue(gaps_w)
        self.assertEqual(gaps_w, gaps_f)
        for gap, lost in gaps_w:
            self.assertEqual(gap, (-lost) & 0xFFFF)
            self.assertGreater(lost, 0)

    def test_reorder_only_traffic_manufactures_phantom_losses(self):
        """One adjacent swap emits THREE events, two of them read as loss, with nothing lost.

        The unconditional resync at mcp_fabric_gate_event.p4:749 fires on the way out of order and
        again on the way back in.  Modelling a swap as a single benign gap would make the
        pre-registration's ``reorder_only`` control pass trivially.
        """
        fab = Fabric(seed=13, scenario="reorder_only", p_bg=0.0, reorder_rate=1e-4)
        events, phantom = 0, 0
        for epoch in range(5):
            out = fab.step(epoch)
            self.assertEqual(sum(out.lost.values()), 0)      # no packet ever left the link
            for _, ev in out.gap_events:
                events += 1
                phantom += ev.lost
        self.assertGreater(events, 0)
        self.assertGreater(phantom, 0, "reordering must not be credited with zero false evidence")

    def test_matches_ptf_test50_one_forced_event_per_discontinuity(self):
        """Mirrors p4/ptf/gap_event/test.py::Test50 so the cross-check cannot silently rot.

        Six offered packets with 2 and 3 lost gives arrivals 0,1,4,5.  The PTF decoder reports
        ``prior_arrivals + 1`` (test.py:84), which Test50 asserts is 3.

        Run under BOTH witness semantics: the advance-only variant is a claim about the REORDER
        path, so if it perturbed the loss path at all it would be buying the reorder fix with a
        regression in the mechanism's primary job, and this is where that would show.
        """
        share = (6.0 / PKT_PER_LINK_EPOCH,) * 4
        for mode in WITNESS_MODES:
            calls = []

            def once(n, p, rng, _calls=calls):
                _calls.append(n)
                return [[2, 3]] if len(_calls) == 1 else []

            fab = Fabric(seed=61, scenario="wrap", p_bg=0.0, context_share=share,
                         witness_mode=mode)
            with mock.patch.object(fabric_mod, "_loss_runs", once):
                first = [ev for _, ev in fab.step(0).gap_events
                         if (ev.vlink, ev.context) == (0, 0)]
                second = [ev for _, ev in fab.step(1).gap_events
                          if (ev.vlink, ev.context) == (0, 0)]
            self.assertEqual(len(first), 1, mode)
            self.assertEqual(first[0].gap, 0xFFFE, mode)
            self.assertEqual(first[0].lost, 2, mode)
            self.assertEqual(first[0].observed_packets, 3, mode)
            self.assertEqual(second, [], "%s: the resync must not repeat the event" % mode)

    def test_witness_reproduces_the_exact_arrival_order_traces(self):
        """Derived from the RegisterAction, not fitted to the expected numbers."""
        self.assertEqual(witness_trace([0, 1, 4, 5]), [(0xFFFE, 2, 3)])
        self.assertEqual(
            witness_trace([0, 1, 2, 3, 5, 4, 6, 7]),
            [(0xFFFF, 1, 5), (0x0002, 0, 1), (0xFFFF, 1, 1)])
        self.assertEqual(
            witness_trace([0, 1, 3, 2, 5, 4, 6, 7]),
            [(0xFFFF, 1, 3), (0x0002, 0, 1), (0xFFFE, 2, 1),
             (0x0002, 0, 1), (0xFFFF, 1, 1)])

    def test_fast_path_matches_a_brute_force_per_packet_witness(self):
        """The clean-stretch shortcut must be an optimisation, never a semantic change.

        Checked under BOTH witness semantics.  The shortcut writes ``expect_seq`` directly across
        an in-order stretch, which is only sound while ``expect_seq`` is exactly the stretch's
        first sequence; advance-only can leave ``expect_seq`` at a different place than baseline
        after a window, so the shortcut has to be re-earned rather than assumed for the new mode.
        """
        n = 24
        share = (float(n) / PKT_PER_LINK_EPOCH,) * 4
        rng = random.Random(2718)
        for _ in range(60):
            runs, i = [], 0
            while i < n:
                if rng.random() < 0.12:
                    end = min(n - 1, i + rng.randrange(3))
                    runs.append([i, end])
                    i = end + 2
                else:
                    i += 1
            lost = {j for a, b in runs for j in range(a, b + 1)}
            swaps, a = [], 0
            while a < n - 1:
                if rng.random() < 0.15 and a not in lost and a + 1 not in lost:
                    swaps.append(a)
                    a += 2
                else:
                    a += 1
            seq0 = rng.randrange(1 << 16)
            ends = [r[1] for r in runs]
            for mode in WITNESS_MODES:
                fab = Fabric(seed=71, scenario="wrap", p_bg=0.0, context_share=share,
                             seq_start=seq0, witness_mode=mode)
                with mock.patch.object(fabric_mod, "_loss_runs", lambda *_a, **_k: [list(r) for r in runs]), \
                     mock.patch.object(Fabric, "_swap_points", lambda *_a, **_k: list(swaps)):
                    got = []
                    for epoch in range(3):
                        got += [(ev.gap, ev.observed_packets)
                                for _, ev in fab.step(epoch).gap_events
                                if (ev.vlink, ev.context) == (0, 0)]
                want = []
                ref = _SublinkState(next_seq=seq0, expect_seq=seq0, witness_mode=mode)
                for epoch in range(3):
                    base = (seq0 + epoch * n) & 0xFFFF
                    for idx in Fabric._arrival_order(0, n - 1, runs, ends, swaps):
                        gap, observed = ref.observe((base + idx) & 0xFFFF)
                        if gap != 0:
                            want.append((gap, observed))
                self.assertEqual(got, want, "%s runs=%r swaps=%r" % (mode, runs, swaps))

    def test_arrival_register_saturates_like_the_16_bit_salu(self):
        st = _SublinkState(next_seq=0, expect_seq=0)
        for seq in range(ARRIVAL_MAX + 500):
            st.observe(seq & 0xFFFF)
        self.assertEqual(st.arrivals, ARRIVAL_MAX)

    def test_a_run_still_open_at_the_epoch_boundary_carries_into_the_next_epoch(self):
        """Conservation: every lost packet is either reported by an event or still un-observed."""
        fab = Fabric(seed=19, scenario="wrap", p_bg=0.0,
                     context_share=(20.0 / PKT_PER_LINK_EPOCH,) * 4,
                     faults=[FaultSpec(vlink=0, context=0, p_fault=0.3, onset_epoch=0)])
        reported = destroyed = 0
        straddled = False
        for epoch in range(30):
            out = fab.step(epoch)
            destroyed += out.lost[(0, 0)]
            reported += sum(ev.lost for _, ev in out.gap_events
                            if (ev.vlink, ev.context) == (0, 0))
            straddled = straddled or fab._sub[(0, 0)].open_run > 0
        self.assertTrue(straddled, "no run was left open at an epoch boundary")
        self.assertGreater(reported, 0)
        self.assertEqual(reported + fab._sub[(0, 0)].open_run, destroyed)

    def test_observed_packets_are_disjoint_from_inferred_losses(self):
        """observed_packets counts arrivals only; the modular gap counts the missing packets."""
        fab = Fabric(seed=17, scenario="persistent_partial", p_bg=1e-6,
                     faults=[FaultSpec(vlink=1, context=2, p_fault=1e-3, onset_epoch=0)])
        reported, delivered = 0, 0
        for epoch in range(10):
            out = fab.step(epoch)
            delivered += out.offered[(1, 2)] - out.lost[(1, 2)]
            reported += sum(ev.observed_packets for _, ev in out.gap_events
                            if (ev.vlink, ev.context) == (1, 2))
        pending = fab._sub[(1, 2)].arrivals
        self.assertGreater(reported, 0)
        self.assertEqual(reported + pending, delivered)


class WitnessModeTest(unittest.TestCase):
    """Both compiled witness semantics, so the proposed silicon fix is measured, not assumed.

    ``baseline`` is `p4/witness/mcp_fabric_gate_event.p4:749` (unconditional resync);
    ``advance_only`` is `p4/witness/mcp_fabric_gate_event_advonly.p4:749`, which predicates the
    resync on the SIGNED sign of the difference the SALU already computes.  Every expectation
    below is the arithmetic consequence of that one predicate -- reordering is nowhere
    special-cased, so these numbers are evidence about the variant rather than a restatement of
    the reason it was written.
    """

    def test_an_unknown_mode_is_rejected_rather_than_silently_treated_as_baseline(self):
        with self.assertRaises(ValueError):
            Fabric(seed=1, scenario="no_fault", witness_mode="advance-only")
        with self.assertRaises(ValueError):
            Fabric(seed=1, scenario="no_fault", witness_mode="")
        self.assertEqual(WITNESS_MODES, ("baseline", "advance_only"))
        self.assertEqual(Fabric(seed=1, scenario="no_fault").witness_mode, "baseline")

    def test_one_adjacent_swap_costs_three_events_today_and_two_under_advance_only(self):
        """The whole point of the variant: the third, spurious event disappears.

        Arrivals 0,1,2,3,5,4,6,7 -- a single adjacent swap of 4 and 5, nothing lost.  Baseline
        resyncs `expected` BACKWARDS on the late packet, so the next in-order arrival reports a
        loss that never happened; advance-only leaves `expected` alone and the trace stops after
        the pair.
        """
        arrivals = [0, 1, 2, 3, 5, 4, 6, 7]
        self.assertEqual([gap for gap, _, _ in witness_trace(arrivals, "baseline")],
                         [0xFFFF, 0x0002, 0xFFFF])
        self.assertEqual([gap for gap, _, _ in witness_trace(arrivals, "advance_only")],
                         [0xFFFF, 0x0002])
        # ... and the controller reads one phantom loss instead of two.
        self.assertEqual(sum(lost for _, lost, _ in witness_trace(arrivals, "baseline")), 2)
        self.assertEqual(sum(lost for _, lost, _ in witness_trace(arrivals, "advance_only")), 1)

    def test_advance_only_reproduces_the_event_tuples_quoted_in_the_p3_result(self):
        """`docs/review/P3-DYNAMIC-RESULT.md`: `[(3, 0xFFFF), (2, 0x0002)]` for 0,1,3,2,4,5.

        Pinned as ``(seq, gap)`` pairs because those are the two numbers the controller-side
        credit rule consumes, and because an independently written emulation produced them.
        """
        self.assertEqual(witness_events([0, 1, 3, 2, 4, 5], "advance_only"),
                         [(3, 0xFFFF), (2, 0x0002)])
        self.assertEqual(witness_events([0, 1, 3, 2, 4, 5], "baseline"),
                         [(3, 0xFFFF), (2, 0x0002), (4, 0xFFFF)])

    def test_two_swaps_halve_from_four_events_to_two(self):
        """Linear in the number of swaps, in both modes -- not a special case for the first one."""
        arrivals = [0, 1, 3, 2, 5, 4, 6, 7]
        self.assertEqual(len(witness_events(arrivals, "baseline")), 5)
        self.assertEqual(witness_events(arrivals, "advance_only"),
                         [(3, 0xFFFF), (2, 0x0002), (5, 0xFFFF), (4, 0x0002)])
        self.assertEqual(sum(lost for _, lost, _ in witness_trace(arrivals, "advance_only")), 2)

    def test_the_loss_path_is_bit_identical_in_both_modes(self):
        """PTF Test50 arrivals: one event, gap 0xFFFE, observed_packets 3, then silence."""
        for mode in WITNESS_MODES:
            self.assertEqual(witness_trace([0, 1, 4, 5], mode), [(0xFFFE, 2, 3)], mode)

    def test_wrap_coinciding_with_loss_emits_one_event_and_wedges_in_neither_mode(self):
        """Wrap ALONE proves nothing -- every formulation is silent on a contiguous wrap.

        `docs/review/P3-DYNAMIC-RESULT.md` records that correction, so the regression test is wrap
        WITH loss: sequences 65533, 65534, then 65535 and 0 destroyed, then 1, 2, ...  The naive
        unsigned form ``if (v <= seq)`` is included as a REJECTED third formulation -- not a
        supported mode -- to show what this test is protecting against: it wedges permanently at
        expected = 65535 and bleeds one false event per packet with a growing gap.
        """
        arrivals = [65533, 65534, 1, 2, 3, 4, 5]
        for mode in WITNESS_MODES:
            trace = witness_trace(arrivals, mode, seq_start=65533)
            self.assertEqual(trace, [(0xFFFE, 2, 3)], mode)
            st = _SublinkState(next_seq=65533, expect_seq=65533, witness_mode=mode)
            for seq in arrivals:
                st.observe(seq)
            self.assertEqual(st.expect_seq, 6, "%s wedged at %d" % (mode, st.expect_seq))

        wedged = naive_unsigned_trace(arrivals, seq_start=65533)
        self.assertEqual(len(wedged), 5)
        self.assertEqual([gap for _, gap in wedged],
                         [0xFFFE, 0xFFFD, 0xFFFC, 0xFFFB, 0xFFFA])

    def test_wrap_with_loss_through_the_whole_fabric_in_both_modes(self):
        """The same discontinuity driven through ``Fabric.step``, not just the register model."""
        share = (6.0 / PKT_PER_LINK_EPOCH,) * 4
        for mode in WITNESS_MODES:
            calls = []

            def once(n, p, rng, _calls=calls):
                _calls.append(n)
                return [[2, 3]] if len(_calls) == 1 else []

            fab = Fabric(seed=83, scenario="wrap", p_bg=0.0, context_share=share,
                         seq_start=(1 << 16) - 3, witness_mode=mode)
            with mock.patch.object(fabric_mod, "_loss_runs", once):
                first = [ev for _, ev in fab.step(0).gap_events
                         if (ev.vlink, ev.context) == (0, 0)]
                later = []
                for epoch in range(1, 4):
                    later += [ev for _, ev in fab.step(epoch).gap_events
                              if (ev.vlink, ev.context) == (0, 0)]
            self.assertEqual(len(first), 1, mode)
            self.assertEqual((first[0].gap, first[0].lost, first[0].observed_packets),
                             (0xFFFE, 2, 3), mode)
            self.assertEqual(later, [], "%s: the wrap must not wedge the witness" % mode)

    def test_advance_only_leaves_the_reorder_control_lossless_but_quieter(self):
        """Zero packets leave the link in either mode; advance-only manufactures less evidence."""
        counted = {}
        for mode in WITNESS_MODES:
            fab = Fabric(seed=13, scenario="reorder_only", p_bg=0.0, reorder_rate=1e-4,
                         witness_mode=mode)
            events = phantom = 0
            for epoch in range(5):
                out = fab.step(epoch)
                self.assertEqual(sum(out.lost.values()), 0, mode)
                for _, ev in out.gap_events:
                    events += 1
                    phantom += ev.lost
            counted[mode] = (events, phantom)
        self.assertGreater(counted["baseline"][0], 0)
        self.assertLess(counted["advance_only"][0], counted["baseline"][0])
        self.assertLess(counted["advance_only"][1], counted["baseline"][1])
        # Advance-only alone is NOT exact: one `lost = 1` per swap survives, and it is the
        # controller-side credit for a small positive gap that removes it (P3-DYNAMIC-RESULT.md).
        # Asserting zero here would credit the data-plane half with the whole fix.
        self.assertGreater(counted["advance_only"][1], 0)


class GateHonouringTest(unittest.TestCase):
    def test_installing_every_key_stops_traffic_and_evidence_and_removal_restores_both(self):
        fault = [FaultSpec(vlink=0, context=0, p_fault=1e-2, onset_epoch=0)]
        fab = Fabric(seed=23, scenario="persistent_partial", faults=fault)
        before = fab.step(0)
        self.assertGreater(before.offered[(0, 0)], 0)
        self.assertGreater(sum(1 for _, ev in before.gap_events
                               if (ev.vlink, ev.context) == (0, 0)), 0)
        for key in gate_keys_for_sublink(0, 0):
            fab.install(*key, 1)
        gated = fab.step(1)
        self.assertEqual(gated.offered[(0, 0)], 0)
        self.assertEqual(gated.lost[(0, 0)], 0)
        self.assertEqual([ev for _, ev in gated.gap_events
                          if (ev.vlink, ev.context) == (0, 0)], [])
        self.assertNotIn((0, 0), {(v, c) for v, c, _ in gated.clean_obs})
        for key in gate_keys_for_sublink(0, 0):
            fab.remove(*key)
        restored = fab.step(2)
        self.assertEqual(restored.offered[(0, 0)], before.offered[(0, 0)])
        self.assertGreater(sum(1 for _, ev in restored.gap_events
                               if (ev.vlink, ev.context) == (0, 0)), 0)

    def test_installing_half_the_keys_halves_the_offered_load(self):
        fab = Fabric(seed=29, scenario="no_fault")
        base = fab.step(0).offered[(0, 0)]
        keys = gate_keys_for_sublink(0, 0)
        for key in keys[: len(keys) // 2]:
            fab.install(*key, 1)
        self.assertLessEqual(abs(fab.step(1).offered[(0, 0)] - base / 2.0), 1.0)

    def test_audit_packets_bypass_the_gate_and_feel_the_injected_loss(self):
        fab = Fabric(seed=31, scenario="persistent_partial", p_bg=0.0,
                     faults=[FaultSpec(vlink=0, context=0, p_fault=0.5, onset_epoch=0)])
        for key in gate_keys_for_sublink(0, 0):
            fab.install(*key, 1)
        self.assertEqual(fab.step(0).offered[(0, 0)], 0)
        tokens = tuple(range(1000))
        survivors = fab.audit_survivals(0, 0, 0, tokens)
        self.assertTrue(set(survivors) <= set(tokens))
        self.assertLess(abs(len(survivors) - 500), 60)
        healthy = fab.audit_survivals(1, 0, 0, tokens)
        self.assertEqual(len(healthy), len(tokens))          # p_bg = 0 on the healthy sublink


class DeterminismTest(unittest.TestCase):
    def _run(self, seed, witness_mode="baseline"):
        fab = Fabric(seed=seed, scenario="persistent_partial", p_bg=1e-6,
                     faults=[FaultSpec(vlink=5, context=3, p_fault=1e-3, onset_epoch=0)],
                     witness_mode=witness_mode)
        return [fab.step(epoch) for epoch in range(5)]

    def test_same_seed_reproduces_and_a_different_seed_does_not(self):
        for mode in WITNESS_MODES:
            self.assertEqual(self._run(41, mode), self._run(41, mode), mode)
            self.assertNotEqual(self._run(41, mode), self._run(42, mode), mode)

    def test_the_witness_mode_does_not_disturb_the_random_streams(self):
        """Reordering the RNG draws would make every cross-mode comparison a seed comparison.

        The two modes must see the SAME injected losses and the same swaps on the same seed; only
        what the witness makes of them may differ.  Otherwise a difference in the reported
        quarantine count could just as easily be a different fault.
        """
        base = Fabric(seed=97, scenario="persistent_partial", p_bg=1e-6,
                      faults=[FaultSpec(vlink=5, context=3, p_fault=1e-3, onset_epoch=0)],
                      witness_mode="baseline")
        adv = Fabric(seed=97, scenario="persistent_partial", p_bg=1e-6,
                     faults=[FaultSpec(vlink=5, context=3, p_fault=1e-3, onset_epoch=0)],
                     witness_mode="advance_only")
        for epoch in range(5):
            a, b = base.step(epoch), adv.step(epoch)
            self.assertEqual(a.offered, b.offered, epoch)
            self.assertEqual(a.lost, b.lost, epoch)

    def test_event_times_are_ordered_within_the_epoch(self):
        fab = Fabric(seed=43, scenario="persistent_partial", p_bg=1e-4)
        for epoch in range(3):
            times = [t for t, _ in fab.step(epoch).gap_events]
            self.assertEqual(times, sorted(times))
            for t in times:
                self.assertTrue(epoch * EPOCH_US <= t < (epoch + 1) * EPOCH_US)


class PreregDecisionRuleTest(unittest.TestCase):
    """PREREG rule 2: `reorder_only` and `wrap` produce zero quarantines at every swept `h`."""

    HS = (5.0, 6.5, 8.0, 10.0)

    def _quarantines(self, h, epochs, **kw):
        fab = Fabric(seed=0, scenario=kw.pop("scenario"), **kw)
        fb = SublinkFeedback(install=fab.install, remove=fab.remove, h=h)
        events = 0
        for epoch in range(epochs):
            out = fab.step(epoch)
            fb.begin_epoch(epoch)
            for vlink, context, delivered in out.clean_obs:
                fb.observe_clean(vlink, context, delivered, epoch)
            for _, ev in out.gap_events:
                events += 1
                fb.on_gap(ev)
        return fb.summary()["installs"], events

    def test_wrap_alone_produces_no_evidence_and_no_quarantine(self):
        """The wrap half of rule 2 HOLDS: crossing 65535 -> 0 is not a discontinuity."""
        for h in self.HS:
            installs, events = self._quarantines(h, 20, scenario="wrap", p_bg=0.0,
                                                 reorder_rate=0.0, seq_start=65000)
            self.assertEqual((installs, events), (0, 0), "h=%s" % h)

    def test_reordering_alone_can_quarantine_at_the_frozen_thresholds(self):
        """The reorder half of rule 2 FAILS, and that is a result, not a bug.

        Zero packets are lost, yet the unconditional resync manufactures two phantom `lost = 1`
        events per adjacent swap, which is enough evidence to quarantine.  Pinned here so the
        finding cannot be smoothed away by a later change to the witness model.
        """
        quarantined = []
        for h in self.HS:
            installs, events = self._quarantines(h, 20, scenario="reorder_only",
                                                 p_bg=0.0, reorder_rate=1e-5)
            self.assertGreater(events, 0, "h=%s" % h)
            quarantined.append(installs)
        self.assertGreater(sum(quarantined), 0,
                           "reordering must not be credited with zero false quarantines")


class RealisedParameterTest(unittest.TestCase):
    def test_measured_loss_rate_on_the_faulty_sublink_matches_p_eff(self):
        """Doctrine: verify the injected quantity in the data, not in the flags."""
        fab = Fabric(seed=47, scenario="persistent_partial", p_bg=1e-6,
                     faults=[FaultSpec(vlink=4, context=1, p_fault=1e-2, onset_epoch=0)])
        faulty_lost = faulty_offered = healthy_lost = healthy_offered = 0
        for epoch in range(50):
            out = fab.step(epoch)
            faulty_lost += out.lost[(4, 1)]
            faulty_offered += out.offered[(4, 1)]
            healthy_lost += out.lost[(4, 0)]
            healthy_offered += out.offered[(4, 0)]
        measured = faulty_lost / faulty_offered
        expected = fab.p_eff(4, 1, 0)
        self.assertLess(abs(measured - expected) / expected, 0.10)
        self.assertGreater(measured, healthy_lost / healthy_offered)

    def test_full_scale_run_is_fast_enough_to_sweep(self):
        fab = Fabric(seed=53, scenario="persistent_partial", p_bg=1e-6,
                     faults=[FaultSpec(vlink=6, context=2, p_fault=1e-3, onset_epoch=10)])
        start = time.time()
        for epoch in range(60):
            out = fab.step(epoch)
        elapsed = time.time() - start
        self.assertEqual(len(out.offered), 16 * 4)
        self.assertLess(elapsed, 10.0)


if __name__ == "__main__":
    unittest.main()
