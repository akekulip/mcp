"""Guards on the controller-host feedback-path benchmark: what it measures, and what it claims.

The claim guards exist because the earlier P3 write-up presented a 97.4 us same-switch congestion
result as C-W4 feedback (retracted in ``docs/review/P3-FEEDBACK-RESULT.md``).  A benchmark of one
segment of the path must be impossible to read as a measurement of the whole path.
"""
import io
import json
import re
import unittest
from contextlib import redirect_stdout

from controller import bench_feedback_path as bench

SMALL = 5           # timed iterations; the fixed 200-iteration warm-up still runs
TIME_FIGURE = re.compile(r"\d+(?:\.\d+)?\s*(?:ns|us|µs|ms)\b")


class TestBenchRuns(unittest.TestCase):
    def test_runs_end_to_end_and_reports_all_four_stages(self):
        result = bench.run_bench(iterations=SMALL, seed=1)
        for arm in bench.ARMS:
            stages = result["arms"][arm]["stages"]
            self.assertEqual(set(stages), set(bench.STAGES), "arm %s lost a stage" % arm)
            for stage, stats in stages.items():
                self.assertEqual(stats["n"], SMALL, "%s/%s timed the wrong count" % (arm, stage))
                self.assertGreaterEqual(stats["p99_us"], stats["median_us"])
            self.assertGreaterEqual(result["arms"][arm]["total"]["median_us"], 0.0)

    def test_cli_text_and_json_paths(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(bench.main(["--iterations", str(SMALL)]), 0)
        self.assertIn("arm quarantine", buf.getvalue())

        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(bench.main(["--iterations", str(SMALL), "--json"]), 0)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["iterations"], SMALL)
        for arm in bench.ARMS:
            self.assertEqual(set(doc["arms"][arm]["stages"]), set(bench.STAGES))

    def test_machine_identity_is_reported(self):
        """A timing claim without a machine is not reproducible."""
        report = bench.format_report(bench.run_bench(iterations=SMALL, seed=1))
        self.assertIn("machine   :", report)
        self.assertIn("perf_counter_ns", report)

    def test_same_seed_gives_the_same_synthetic_event_stream(self):
        a = bench.build_event_stream(7, 32, "quarantine")
        self.assertEqual(a, bench.build_event_stream(7, 32, "quarantine"))
        self.assertNotEqual(a, bench.build_event_stream(8, 32, "quarantine"))
        self.assertNotEqual(a, bench.build_event_stream(7, 32, "coalesced"),
                            "the coalesced arm must repeat one epoch, not advance it")


class TestArmsAreDifferentPaths(unittest.TestCase):
    def test_coalesced_arm_installs_strictly_fewer_entries(self):
        """Proves the two arms are two paths, not two names for the same path."""
        result = bench.run_bench(iterations=SMALL, seed=1)
        quarantine = result["arms"]["quarantine"]["installs_recorded_by_fake_bfrt"]
        coalesced = result["arms"]["coalesced"]["installs_recorded_by_fake_bfrt"]
        self.assertLess(coalesced, quarantine)
        self.assertEqual(coalesced, 0, "a coalesced event must return before any gate write")
        self.assertEqual(result["arms"]["coalesced"]["coalesced_events"], SMALL + bench.WARMUP_ITERATIONS)

    def test_reorder_credit_arm_reaches_no_decision_and_installs_nothing(self):
        """The netted reorder is now a distinct path: phantom loss cancelled, nothing installed.

        ``netted_out`` is asserted positive on purpose: without it this test would also pass if
        the credit events were being discarded as stale or coalesced, which is a different
        no-install path and would not exercise netting at all.
        """
        arm = bench.run_arm("reorder_credit", iterations=SMALL, seed=1)
        pairs = SMALL + bench.WARMUP_ITERATIONS
        self.assertEqual(arm["quarantine_decisions"], 0)
        self.assertEqual(arm["installs_recorded_by_fake_bfrt"], 0)
        self.assertEqual(arm["netted_out"], pairs, "every pair must net its phantom loss to zero")
        self.assertEqual(arm["reorder_credits"], pairs)
        self.assertEqual(arm["coalesced_events"], 0, "netting is not coalescing")
        self.assertEqual(arm["copies_parsed_per_iteration"], 2)

    def test_credit_stream_is_deterministic_and_carries_only_receipts(self):
        from controller.hw_adapter import gap_event_from_copy, parse_copy
        credits = bench.build_credit_stream(3, 16)
        self.assertEqual(credits, bench.build_credit_stream(3, 16))
        self.assertNotEqual(credits, bench.build_credit_stream(4, 16))
        for frame in credits:
            event = gap_event_from_copy(parse_copy(frame))
            self.assertTrue(0 < event.gap <= 16, "a receipt is a small POSITIVE gap")
            self.assertEqual(event.lost, 0, "a receipt is never loss evidence")

    def test_fake_bfrt_records_the_exact_expanded_key_count(self):
        """S4 must have driven the real writer, not a stub that skipped the key expansion.

        One directed uplink sublink expands into one exact P2 key per destination leaf: four on
        the configured 4x2 fabric.
        """
        arm = bench.run_arm("quarantine", iterations=SMALL, seed=1)
        self.assertEqual(arm["quarantine_decisions"], SMALL,
                         "every timed iteration of this arm must actually decide")
        self.assertEqual(arm["installs_recorded_by_fake_bfrt"],
                         SMALL * bench.EXPECTED_KEYS_PER_DECISION)
        self.assertEqual(bench.EXPECTED_KEYS_PER_DECISION, 4)


class TestNoEndToEndClaim(unittest.TestCase):
    def setUp(self):
        self.report = bench.format_report(bench.run_bench(iterations=SMALL, seed=1))

    def test_report_carries_the_exclusion_label(self):
        self.assertIn("controller-host software segment; excludes mirror transport and "
                      "BFRT gRPC + switch programming", self.report)
        self.assertIn("excluded :", self.report)

    def test_report_never_repeats_the_retracted_congestion_figure(self):
        self.assertNotIn("97.4", self.report)
        self.assertNotIn("97.4", json.dumps(bench.run_bench(iterations=SMALL, seed=1)))

    def test_no_line_attaches_a_measured_figure_to_the_end_to_end_path(self):
        """`end-to-end` may only appear where the report says it is unmeasured.

        Both halves of the guard are checked against the report first, so neither can pass by
        matching nothing: the phrase must be present, and the figure regex must fire on a real
        stage line.
        """
        mentions = [l for l in self.report.splitlines() if "end-to-end" in l.lower()]
        self.assertTrue(mentions, "the report must say the end-to-end latency is unmeasured")
        self.assertIsNotNone(TIME_FIGURE.search("the end-to-end latency is 48.040 us"),
                             "the figure regex must be able to detect a reported time")
        for line in self.report.splitlines():
            if "end-to-end" not in line.lower():
                continue
            self.assertTrue("unmeasured" in line.lower() or "not measured" in line.lower(),
                            "end-to-end mentioned without saying it is unmeasured: %r" % line)
            self.assertIsNone(TIME_FIGURE.search(line),
                              "a time figure appears on an end-to-end line: %r" % line)

    def test_docstring_states_the_bound_it_is(self):
        doc = bench.__doc__ or ""
        self.assertIn("remains unmeasured", doc)
        self.assertIn("LOWER BOUND", doc)
        self.assertIn("EXCLUDED", doc)


class TestScopeOfThePerStageFigures(unittest.TestCase):
    """PI review 2026-08-29: the per-stage S1/S2 medians are in-loop costs, not call costs."""

    def setUp(self):
        self.result = bench.run_bench(iterations=SMALL, seed=1)
        self.report = bench.format_report(self.result)

    def test_isolated_reference_is_measured_and_names_its_frame(self):
        iso = self.result["isolated_reference"]
        self.assertEqual(set(iso["S1_parse_copy"]), {"median_us", "p95_us", "p99_us", "n"})
        self.assertEqual(iso["S1_parse_copy"]["n"], SMALL)
        self.assertGreater(iso["S1_parse_copy"]["median_us"], 0.0)
        self.assertEqual(iso["frame_bytes"], 106,
                         "a C-W4 gap-event copy: mirror_h 30 + eth 14 + fabric_h 12 + csig_h 14 "
                         "+ witness 4 + payload 32; a plain data copy is 76 B and parses shallower")
        self.assertIn("isolated reference", self.report)
        self.assertIn("frame parsed: 106 B", self.report)

    def test_report_says_which_figures_may_be_cited(self):
        self.assertIn("TOTAL and S3 are the figures this project cites", self.report)
        self.assertIn("not isolated call costs", self.report)

    def test_report_states_that_the_netting_hold_is_in_no_figure(self):
        """S3 is the cost of a decision, never its elapsed time.

        A loss-bearing event is held for up to one epoch for reorder netting.  Dropping this
        caveat would let a reader add these microseconds up into a reaction time that the
        mechanism deliberately does not have.
        """
        self.assertIn("HELD for up to one epoch", self.report)
        self.assertIn("it is in NO figure below", self.report)
        self.assertIn("the cost of a complete decision, never its elapsed time", self.report)


class TestS3Decomposition(unittest.TestCase):
    def setUp(self):
        self.decomp = bench.measure_s3_decomposition(iterations=SMALL, seed=1)

    def test_the_dominant_term_is_the_frozen_localizer_not_the_p3_logic(self):
        frozen = self.decomp["frozen_infer_update_localize"]["median_us"]
        rest = self.decomp["rest_of_on_gap"]["median_us"]
        self.assertGreater(frozen, rest,
                           "S3 is dominated by infer.update+infer.localize, not by coalescing, "
                           "key expansion and state bookkeeping")
        self.assertGreater(self.decomp["frozen_share_of_proxied_median_pct"], 50.0)
        self.assertEqual(self.decomp["rest_of_on_gap"]["n"], SMALL)

    def test_the_frozen_module_binding_is_restored(self):
        """The frozen layer is timed from the outside and must be left exactly as found."""
        from controller import infer, sublink_feedback
        self.assertIs(sublink_feedback.infer, infer,
                      "the timing proxy leaked into the frozen inference layer's binding")

    def test_the_proxy_delegates_the_frozen_layer_unchanged(self):
        from controller import infer
        proxy = bench._TimedInfer(infer)
        self.assertIs(proxy.Sample, infer.Sample)          # bound directly, off the hot path
        self.assertIs(proxy.InferState, infer.InferState)
        self.assertEqual(proxy.BASELINE_MODE, infer.BASELINE_MODE)   # via __getattr__
        self.assertEqual(proxy.module_hash(), infer.module_hash(),
                         "the proxy must not alter the frozen module it wraps")


if __name__ == "__main__":
    unittest.main()
