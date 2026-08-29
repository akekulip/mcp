"""Dynamic operating point: the runner drives the REAL controller, and says so with evidence.

Each test pins one rule of `sim/dynamic/PREREG.md` or one clause of the runner's contract, and is
written so that it FAILS if that rule breaks — not so that it passes.  Three of them exist because
of the repo's "cross-check before concluding" doctrine rather than because of a feature:

* the oracle floor (an upper-bound arm that cannot find the answer it was handed is a harness bug,
  HURDLES H29/H32);
* the blackhole blind spot (it must appear as a measured zero, never as an exception or a gap in
  the table);
* the STALE audit result (the documented consequence of a feedback path slower than an epoch is
  asserted, not engineered around).
"""
import unittest

from controller.sublink_feedback import QUARANTINED, SublinkFeedback
from sim.dynamic.fabric import EPOCH_US
from sim.dynamic.metrics import RunRecord, format_table, summarize
from sim.dynamic.fabric import WITNESS_MODES
from sim.dynamic.runner import (
    FAULT_SCENARIOS,
    CellKey,
    HarnessError,
    RunConfig,
    build_scenario,
    cell_key,
    check_oracle_floor,
    faulty_sublinks,
    run,
    run_verbose,
)
from sim.dynamic.sweep import build_configs, execute, seed_values, witness_modes

BASE = dict(tau_feedback_us=0, tau_write_us=0, h=6.5, clean_epochs_to_restore=3,
            p_fault=1e-3, epochs=20, seed=11)


def cfg(**overrides) -> RunConfig:
    kwargs = dict(BASE)
    kwargs.update(overrides)
    return RunConfig(**kwargs)


class DrivesTheRealControllerTest(unittest.TestCase):
    """The one rule that matters: no re-implementation, no override, no monkeypatch."""

    def test_the_run_drives_a_real_sublinkfeedback_instance(self):
        _, trace = run_verbose(cfg(scenario="persistent_partial", arm="cw4_feedback"))
        self.assertIsInstance(trace.feedback, SublinkFeedback)
        self.assertIs(type(trace.feedback), SublinkFeedback)      # not a subclass-to-override
        self.assertGreater(trace.feedback.summary()["installs"], 0)

    def test_every_gate_write_is_one_the_real_state_machine_asked_for(self):
        """installs x (keys per sublink) == the writes the fabric actually received."""
        record, trace = run_verbose(cfg(scenario="persistent_partial", arm="cw4_feedback"))
        installs = [w for w in trace.write_ops if w[1] == "install"]
        self.assertEqual(record.installs, trace.feedback.summary()["installs"])
        self.assertEqual(len(installs), 4 * record.installs)      # 4 gate keys per sublink
        self.assertGreater(record.installs, 0)

    def test_directed_w4_expands_the_same_decision_to_every_context(self):
        """Same evidence, wider blast radius: 4 contexts x 4 keys per decision."""
        record, trace = run_verbose(cfg(scenario="persistent_partial", arm="directed_w4"))
        installs = [w for w in trace.write_ops if w[1] == "install"]
        self.assertEqual(record.installs, trace.feedback.summary()["installs"])
        self.assertEqual(len(installs), 16 * record.installs)
        self.assertEqual(len(set(key[3] for _, _, key in installs)), 4)


class ArmsTest(unittest.TestCase):
    def test_none_arm_never_installs_anything(self):
        record, trace = run_verbose(cfg(scenario="persistent_partial", arm="none"))
        self.assertEqual(trace.write_ops, [])
        self.assertEqual(record.installs, 0)
        self.assertFalse(record.quarantined_faulty)
        self.assertIsNone(record.detect_us)
        self.assertEqual(record.collateral_packets, 0)
        self.assertEqual(trace.fabric.installed_keys, set())

    def test_oracle_quarantines_every_scenario_that_injected_a_fault(self):
        for scenario in FAULT_SCENARIOS:
            for seed in seed_values(3):
                record = run(cfg(scenario=scenario, arm="oracle", seed=seed))
                self.assertTrue(record.quarantined_faulty,
                                "oracle missed %s seed %d" % (scenario, seed))
                self.assertIsNotNone(record.detect_us)

    def test_cw4_feedback_quarantines_the_persistent_partial_fault_at_1e_3(self):
        for seed in seed_values(5):
            record = run(cfg(scenario="persistent_partial", arm="cw4_feedback", seed=seed))
            self.assertTrue(record.quarantined_faulty, "missed seed %d" % seed)
            self.assertIsNotNone(record.detect_us)
            self.assertEqual(record.false_quarantine_epochs, 0)

    def test_cw4_feedback_does_not_quarantine_the_no_fault_control(self):
        for seed in seed_values(5):
            record = run(cfg(scenario="no_fault", arm="cw4_feedback", seed=seed))
            self.assertEqual(record.installs, 0, "false quarantine on seed %d" % seed)
            self.assertEqual(record.false_quarantine_epochs, 0)
            self.assertFalse(record.quarantined_faulty)
            # ... and it is not silent: the fabric did hand it evidence to reject.
            self.assertGreater(record.evidence_epochs, 0)


class TransportTest(unittest.TestCase):
    def test_gate_effectiveness_respects_tau_write(self):
        """A write does not exist until it lands; three epochs of tau_write cost three epochs."""
        fast = run(cfg(scenario="persistent_partial", arm="cw4_feedback", tau_write_us=0))
        slow = run(cfg(scenario="persistent_partial", arm="cw4_feedback",
                       tau_write_us=3 * EPOCH_US))
        self.assertIsNotNone(fast.detect_us)
        self.assertIsNotNone(slow.detect_us)
        self.assertEqual(slow.detect_us - fast.detect_us, 3 * EPOCH_US)
        self.assertGreater(slow.unsafe_packets, fast.unsafe_packets)

    def test_full_sweep_controller_latency_drops_every_event_as_stale(self):
        """106.6 ms feedback: `on_gap` drops by EPOCH, so the mechanism stops, it does not slow.

        This is the documented consequence of the real state machine, asserted rather than hidden:
        no event survives the epoch boundary, so nothing is ever quarantined, no probation round is
        ever opened, and restoration is unreachable.
        """
        record = run(cfg(scenario="persistent_partial", arm="cw4_feedback",
                         tau_feedback_us=106600, tau_write_us=106600))
        self.assertGreater(record.stale_dropped, 0)
        self.assertEqual(record.installs, 0)
        self.assertFalse(record.quarantined_faulty)
        self.assertFalse(record.restored)
        self.assertEqual((record.audit_clean, record.audit_loss,
                          record.audit_incomplete, record.audit_stale), (0, 0, 0, 0))

    def test_audit_rounds_close_stale_when_the_round_trip_outlives_the_epoch(self):
        """A probation round whose receipts need longer than an epoch can never restore.

        At tau_feedback = 60 ms the round trip is 120 ms, so `AuditRound.finish` sees
        `feedback.current_epoch` already past the round's epoch and returns STALE for every round.
        Quarantine still happens (early-epoch events beat the boundary); restoration cannot.
        """
        record, trace = run_verbose(cfg(scenario="persistent_partial", arm="cw4_feedback",
                                        tau_feedback_us=60000, tau_write_us=0, seed=1))
        self.assertTrue(record.quarantined_faulty)
        self.assertGreater(record.audit_stale, 0)
        self.assertEqual(record.audit_clean, 0)
        self.assertFalse(record.restored)
        self.assertEqual(set(r.status for r in trace.audit_results), {"STALE"})


class WriteOrderTest(unittest.TestCase):
    def test_a_remove_never_overtakes_the_install_it_undoes(self):
        """Otherwise the gate strands: installed in the fabric, believed restored by the controller.

        This caught a real harness bug.  Probation used to open the moment the CONTROLLER decided,
        which is before the install has landed, so a round that closed CLEAN enqueued its `remove`
        ahead of the in-flight `install`.  The delay line delivered them in that order, the key
        stayed installed forever, and the controller believed it had restored -- visible only as
        the impossible result "k=1 never restores, k=3 always does".

        Repeated installs of the same key are NOT a violation: `on_gap` coalesces per (sublink,
        epoch), so a sublink that is already quarantined but still emitting evidence in a LATER
        epoch is re-installed, and at tau_write >= one epoch that happens every epoch until the
        write lands.  The install is idempotent; what it is not is free -- each one increments the
        controller's `quarantines` damping counter.
        """
        for k in (1, 3):
            for tau_write in (0, EPOCH_US):
                _, trace = run_verbose(cfg(scenario="persistent_partial", arm="cw4_feedback",
                                           clean_epochs_to_restore=k, tau_write_us=tau_write,
                                           epochs=30, seed=1))
                per_key = {}
                for due, op, key in trace.write_ops:
                    per_key.setdefault(key, []).append(op)
                self.assertTrue(per_key)
                for key, ops in per_key.items():
                    depth = 0
                    for op in ops:
                        depth += 1 if op == "install" else -1
                        self.assertGreaterEqual(depth, 0, (k, tau_write, key, ops))

    def test_probation_only_runs_while_the_gate_is_effective(self):
        _, trace = run_verbose(cfg(scenario="persistent_partial", arm="cw4_feedback",
                                   tau_write_us=2 * EPOCH_US, epochs=30, seed=1))
        first_install = min(due for due, op, _ in trace.write_ops if op == "install")
        self.assertTrue(trace.audit_results)
        for result in trace.audit_results:
            self.assertGreaterEqual(result.epoch * EPOCH_US, first_install)


class BlindSpotTest(unittest.TestCase):
    def test_all_context_blackhole_produces_no_evidence_and_no_quarantine(self):
        """PREREG rule 3: UNDETECTED must be a measured zero, not an exception.

        `p_bg` is set to zero so the only possible evidence would be the fault's own, and a total
        blackhole produces none: the witness needs a survivor to expose the discontinuity.
        """
        record, trace = run_verbose(cfg(scenario="all_context_blackhole", arm="cw4_feedback",
                                        p_bg=0.0))
        self.assertEqual(record.evidence_epochs, 0)
        self.assertEqual(record.installs, 0)
        self.assertFalse(record.quarantined_faulty)
        self.assertIsNone(record.detect_us)
        self.assertEqual(trace.feedback.summary()["quarantined"], 0)
        self.assertGreater(record.lost_faulty, 0)                 # the fault WAS injected
        self.assertEqual(len(trace.faulty_set), 4)                # all four contexts of the vlink

    def test_selective_blackhole_is_equally_invisible_and_that_is_a_finding(self):
        """One context at 100 % loss emits nothing either: `md.sublink = (vlink << 4) | ctx`.

        The witness register is indexed per behavioural sublink, so a fully blackholed CONTEXT is
        as silent as a fully blackholed link.  The oracle still finds it, which is what separates
        "the mechanism is blind here" from "the harness never injected the fault".
        """
        blind = run(cfg(scenario="selective_blackhole", arm="cw4_feedback", p_bg=0.0))
        oracle = run(cfg(scenario="selective_blackhole", arm="oracle", p_bg=0.0))
        self.assertEqual(blind.evidence_epochs, 0)
        self.assertFalse(blind.quarantined_faulty)
        self.assertTrue(oracle.quarantined_faulty)
        self.assertLess(oracle.unsafe_packets, blind.unsafe_packets)


class ExposureTest(unittest.TestCase):
    def test_unsafe_exposure_is_counted_from_onset_only(self):
        """Background loss before onset is not exposure; a window starting at 0 would show it."""
        oracle = run(cfg(scenario="persistent_partial", arm="oracle", p_bg=1e-2))
        none = run(cfg(scenario="persistent_partial", arm="none", p_bg=1e-2))
        self.assertGreater(oracle.lost_faulty, 0)
        self.assertLess(oracle.unsafe_packets, oracle.lost_faulty / 3.0)
        self.assertGreater(none.unsafe_packets, 5 * oracle.unsafe_packets)

    def test_unmitigated_exposure_grows_after_onset(self):
        short = run(cfg(scenario="persistent_partial", arm="none", epochs=12))
        long = run(cfg(scenario="persistent_partial", arm="none", epochs=40))
        self.assertGreater(short.unsafe_packets, 0)
        self.assertGreater(long.unsafe_packets, short.unsafe_packets)


class ScenarioTest(unittest.TestCase):
    def test_controls_name_no_faulty_sublink_and_faults_name_one(self):
        for scenario in ("reorder_only", "wrap", "no_fault"):
            fab, faulty = build_scenario(cfg(scenario=scenario, arm="none"))
            self.assertIsNone(faulty, scenario)
            self.assertEqual(faulty_sublinks(fab), ())
        for scenario in FAULT_SCENARIOS:
            fab, faulty = build_scenario(cfg(scenario=scenario, arm="none"))
            self.assertIsNotNone(faulty, scenario)
            self.assertIn(faulty, faulty_sublinks(fab))

    def test_reordering_reaches_the_decision_path_carrying_zero_loss(self):
        """The reorder control must be a control: no packet leaves the link, yet evidence flows.

        This pins the harness, NOT the verdict.  PREREG decision rule 2 ("reorder_only produces
        zero quarantines at every swept h") is an experimental outcome, and the measured answer is
        that it FAILS: at a 1e-4 adjacent-swap rate the witness emits `gap = 0xFFFF`, which the
        controller reads as `lost = 1`, and over 5 seeds x 12 epochs that produced 32 / 10 / 3 / 0
        quarantines at h = 5.0 / 6.5 / 8.0 / 10.0.  Asserting zero here would have pinned a
        pre-judged result; asserting the invariant leaves the sweep free to report the failure.
        """
        record = run(cfg(scenario="reorder_only", arm="cw4_feedback", p_fault=1e-4, epochs=12))
        self.assertEqual(record.lost_faulty + record.lost_healthy, 0)
        self.assertGreater(record.evidence_epochs, 0)

    def test_the_sequence_wrap_control_never_quarantines(self):
        """Crossing 65535 -> 0 must be silent: modular arithmetic, not a 65535-packet loss."""
        for seed in seed_values(5):
            record = run(cfg(scenario="wrap", arm="cw4_feedback", epochs=12, seed=seed))
            self.assertEqual(record.installs, 0, seed)
            self.assertEqual(record.false_quarantine_epochs, 0, seed)


class DeterminismTest(unittest.TestCase):
    def test_the_same_config_twice_gives_an_identical_record(self):
        config = cfg(scenario="intermittent", arm="cw4_feedback")
        self.assertEqual(run(config), run(config))

    def test_a_different_seed_moves_the_fault(self):
        seeds = seed_values(8)
        sites = set(build_scenario(cfg(scenario="persistent_partial", arm="none", seed=s))[1]
                    for s in seeds)
        self.assertGreater(len(sites), 1)


class WitnessModeTest(unittest.TestCase):
    """The witness semantics is a swept parameter, and the table must never confuse the two."""

    def test_an_unknown_witness_mode_is_rejected_by_the_config(self):
        with self.assertRaises(ValueError):
            cfg(scenario="no_fault", arm="none", witness_mode="advance-only")
        self.assertEqual(cfg(scenario="no_fault", arm="none").witness_mode, "baseline")

    def test_build_scenario_threads_the_mode_into_the_fabric(self):
        for mode in WITNESS_MODES:
            fab, _ = build_scenario(cfg(scenario="reorder_only", arm="none", witness_mode=mode))
            self.assertEqual(fab.witness_mode, mode)

    def test_the_cell_key_makes_the_mode_visible_and_keeps_the_cells_apart(self):
        """Two rows that differ only in which silicon they model must not merge or read alike."""
        keys = [cell_key(cfg(scenario="reorder_only", arm="cw4_feedback", witness_mode=m))
                for m in WITNESS_MODES]
        self.assertEqual(len(set(keys)), 2)
        for key, mode in zip(keys, WITNESS_MODES):
            self.assertIn("wit=%s" % mode, str(key))
        self.assertNotEqual(str(keys[0]), str(keys[1]))

    def test_both_runs_every_cell_under_each_mode_and_labels_the_printed_row(self):
        self.assertEqual(witness_modes("both"), WITNESS_MODES)
        self.assertEqual(witness_modes("advance_only"), ("advance_only",))
        with self.assertRaises(ValueError):
            witness_modes("advance-only")

        configs = build_configs(("no_fault",), ("cw4_feedback",), (0,), (6.5,), (3,), (1e-3,),
                                seed_values(1), 12, modes=witness_modes("both"))
        self.assertEqual(len(configs), 2)
        self.assertEqual([c.witness_mode for c in configs], list(WITNESS_MODES))
        cells = execute(configs)
        self.assertEqual(len(cells), 2)
        table = format_table({key: summarize(records, seed=1)
                              for key, records in cells.items()})
        for mode in WITNESS_MODES:
            self.assertIn("wit=%s" % mode, table)

    def test_advance_only_never_costs_extra_false_quarantines_on_the_reorder_control(self):
        """The measurement the variant exists for, through the REAL SublinkFeedback.

        `reorder_only` loses no packets in either mode, so every quarantine here is false and the
        arm is genuinely comparable across the two witnesses.  What is asserted is the INVARIANT
        (advance-only never manufactures more false quarantines than the shipped witness, and both
        modes still put evidence in front of the controller); the VERDICT -- how many quarantines
        each produces at each `h` -- is a measurement and belongs in the reported table, not in an
        assertion, exactly as `test_reordering_reaches_the_decision_path_carrying_zero_loss`
        already argues.  Pinning a number here would also pin the controller-side credit rule,
        which is a separate mechanism with its own owner.
        """
        counts = {}
        for mode in WITNESS_MODES:
            installs = 0
            for seed in seed_values(3):
                record = run(cfg(scenario="reorder_only", arm="cw4_feedback", p_fault=1e-5,
                                 h=5.0, epochs=12, seed=seed, witness_mode=mode))
                self.assertEqual(record.lost_faulty + record.lost_healthy, 0, mode)
                self.assertGreater(record.evidence_epochs, 0, mode)
                installs += record.installs
            counts[mode] = installs
        self.assertLessEqual(counts["advance_only"], counts["baseline"], counts)

    def test_advance_only_hands_the_controller_strictly_less_phantom_loss(self):
        """The controller-independent half of the claim, measured on the fabric alone.

        Event counts and their `lost` fields are a property of the witness, so this stays true
        whatever the controller does with them: one adjacent swap costs three events carrying two
        phantom losses under the shipped witness, and two events carrying one under the variant.
        """
        offered = {}
        for mode in WITNESS_MODES:
            fab, faulty = build_scenario(cfg(scenario="reorder_only", arm="none", p_fault=1e-5,
                                             epochs=12, witness_mode=mode))
            self.assertIsNone(faulty)
            events = phantom = 0
            for epoch in range(12):
                out = fab.step(epoch)
                self.assertEqual(sum(out.lost.values()), 0, mode)
                events += len(out.gap_events)
                phantom += sum(ev.lost for _, ev in out.gap_events)
            offered[mode] = (events, phantom)
        self.assertGreater(offered["advance_only"][0], 0, "the control must still be a control")
        # 3 events / 2 phantom losses per swap becomes 2 events / 1 phantom loss per swap.
        self.assertEqual(offered["baseline"][0], 3 * (offered["advance_only"][0] // 2))
        self.assertEqual(offered["baseline"][1], 2 * offered["advance_only"][1])

    def test_the_fault_path_is_unchanged_by_the_mode(self):
        """Advance-only is a claim about reordering only; detection must survive it intact."""
        for seed in seed_values(3):
            records = {m: run(cfg(scenario="persistent_partial", arm="cw4_feedback",
                                  seed=seed, witness_mode=m)) for m in WITNESS_MODES}
            for mode, record in records.items():
                self.assertTrue(record.quarantined_faulty, (mode, seed))
            self.assertEqual(records["baseline"].detect_us,
                             records["advance_only"].detect_us, seed)

    def test_determinism_holds_in_both_modes(self):
        for mode in WITNESS_MODES:
            config = cfg(scenario="intermittent", arm="cw4_feedback", witness_mode=mode)
            self.assertEqual(run(config), run(config), mode)


class OracleFloorTripwireTest(unittest.TestCase):
    """PREREG tripwire 1, mechanically: a broken upper bound aborts the sweep."""

    @staticmethod
    def _record(**overrides) -> RunRecord:
        base = dict(quarantined_faulty=True, unsafe_packets=0, detect_us=0, healthy_epochs=60,
                    false_quarantine_epochs=0, collateral_packets=0, restored=False,
                    restore_us=None, unsafe_restorations=0, flaps=0, installs=1, coalesced=0,
                    stale_dropped=0, offered_faulty=1, lost_faulty=1, offered_healthy=1,
                    lost_healthy=0, evidence_epochs=1, epochs=60)
        base.update(overrides)
        return RunRecord(**base)

    @staticmethod
    def _key(scenario="persistent_partial", arm="oracle") -> CellKey:
        return CellKey(scenario=scenario, arm=arm, tau_feedback_us=0, tau_write_us=0, h=6.5,
                       clean_epochs_to_restore=3, p_fault=1e-3)

    def test_a_working_oracle_passes(self):
        check_oracle_floor({self._key(): [self._record(), self._record()]})

    def test_a_broken_oracle_raises_and_names_the_cell(self):
        cells = {self._key(): [self._record(), self._record(quarantined_faulty=False)]}
        with self.assertRaises(HarnessError) as caught:
            check_oracle_floor(cells)
        self.assertIn("persistent_partial", str(caught.exception))
        self.assertIn("oracle", str(caught.exception))

    def test_the_floor_ignores_arms_and_scenarios_it_does_not_bound(self):
        check_oracle_floor({self._key(arm="cw4_feedback"): [self._record(
            quarantined_faulty=False)]})
        check_oracle_floor({self._key(scenario="no_fault"): [self._record(
            quarantined_faulty=False)]})
        check_oracle_floor({self._key(scenario="reorder_only"): [self._record(
            quarantined_faulty=False)]})

    def test_a_real_sweep_of_oracle_cells_passes_the_floor(self):
        cells = {}
        for scenario in FAULT_SCENARIOS:
            config = cfg(scenario=scenario, arm="oracle", epochs=12)
            cells.setdefault(self._key(scenario=scenario), []).append(run(config))
        check_oracle_floor(cells)


class AuditReportingTest(unittest.TestCase):
    """The four probation outcomes have to survive aggregation into the printed table."""

    def test_audit_counts_aggregate_and_print(self):
        records = [run(cfg(scenario="persistent_partial", arm="cw4_feedback", seed=s))
                   for s in seed_values(2)]
        cell = summarize(records, seed=1)
        self.assertEqual(cell.audit_clean, sum(r.audit_clean for r in records))
        self.assertEqual(cell.audit_stale, sum(r.audit_stale for r in records))
        self.assertGreater(cell.audit_clean, 0)
        table = format_table({"persistent_partial/cw4_feedback": cell})
        self.assertIn("audit c/l/i/s", table)
        self.assertIn("%d/%d/%d/%d" % (cell.audit_clean, cell.audit_loss,
                                       cell.audit_incomplete, cell.audit_stale), table)

    def test_undersized_probation_evidence_no_longer_certifies_a_still_faulty_sublink(self):
        """Eight-token rounds must NOT certify a 1e-3 sublink, and the real machine refuses.

        This test used to assert the opposite, and it was right to: `SublinkFeedback` counted clean
        *rounds*, so `clean_epochs_to_restore = 3` certified a still-faulty 1e-3 sublink 95.3 % of
        the time (`docs/review/P3-DYNAMIC-RESULT.md`, rule 4 -- the H28 defect class, a criterion
        with no dimension).  The controller now also requires an accumulated PACKET budget, so the
        same 30-epoch run holds the sublink instead.  Inverted rather than deleted: the scenario is
        still the one that matters, and what changed is the verdict, not the question.
        """
        record, trace = run_verbose(cfg(scenario="persistent_partial", arm="cw4_feedback",
                                        epochs=30, seed=1))
        feedback = trace.feedback
        vlink, context = trace.faulty
        state = feedback.state[(vlink << 4) | context]

        self.assertFalse(record.restored)
        self.assertEqual(record.unsafe_restorations, 0)
        self.assertEqual(state.state, QUARANTINED)
        # The fault is still there, so refusing is the correct answer and not an accident.
        self.assertGreater(trace.fabric.p_eff(vlink, context, epoch=29), trace.fabric.p_bg)
        # ... and the refusal is a SHORTFALL against a stated budget, not silence: the rounds
        # requirement was met many times over and the packet requirement was not.
        needed = feedback.probation_packets_needed(vlink, context)
        self.assertGreater(record.audit_clean, BASE["clean_epochs_to_restore"])
        self.assertGreater(state.clean_packets, 0)
        self.assertLess(state.clean_packets, needed)
        self.assertEqual(needed, feedback.probation_budget()["packets"])

    def test_restoration_happens_once_the_packet_budget_is_actually_met(self):
        """The counterpart: the rule refuses on thin evidence, it does not refuse forever.

        A rule that never fires is not a safe rule (repo CLAUDE.md, cross-check item 4), so the
        refusal above is only meaningful beside a run that pays the budget.  `repaired` clears the
        fault, 16-token rounds are the widest `tbl_audit_steer` allows, and the budget at the
        controller's own defaults is 2,995 packets = 188 rounds = 18.8 s -- which is what the run
        takes, so the price is measured rather than asserted.
        """
        record, trace = run_verbose(cfg(scenario="repaired", arm="cw4_feedback",
                                        epochs=260, audit_tokens=16, seed=11))
        budget = trace.feedback.probation_budget()
        self.assertTrue(record.restored)
        self.assertEqual(record.unsafe_restorations, 0)
        self.assertGreaterEqual(record.audit_clean, budget["rounds"])
        self.assertGreaterEqual(record.restore_us, budget["seconds"] * 1e6)


if __name__ == "__main__":
    unittest.main()
