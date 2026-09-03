"""Semantics and schema contract for the receiver ledger, `mcp_fabric_ledger.p4`.

Three things are tested, in the order the implementation plan asks for them.

(a) **Ledger arithmetic.** A software model of the two ingress SALUs is driven with
    controlled drop, reorder and wrap streams, and `dhi - dlo` is asserted to equal the
    injected loss count EXACTLY.  The model is not trusted on its own: every arithmetic
    line it implements is pinned against the literal text of the P4 source, so the model
    cannot silently drift away from the program it claims to model.

(b) **Bernoulli injector.** The two-entry range SCHEME is checked: that
    `W = round(p * 65536)` over disjoint inclusive ranges yields rate `p`, and that
    `offered == drop_ctr + none_ctr`, the identity that makes the rate readable on chip
    at all.  Note honestly what this is worth: the draw is CPython's RNG, so the rate
    test exercises the arithmetic of the entry layout and the counter identity, NOT
    Tofino's `Random<bit<16>>`.  Uniformity of the hardware draw and the inclusivity of
    the hardware range bounds are ASSUMPTIONS here, and only a model/PTF run can
    discharge them -- see LEDGER-COMPILE-GATE.md section 7.

(c) **Schema regression.** The generated bfrt schema archived alongside the compile gate
    is checked to prove `reg_rx_frontier` / `tbl_rx_frontier` and the bank-parity index
    arithmetic are gone, and that the ledger registers have the widths the controller
    will read.

NOT covered here: this is a software model, not a tofino-model or PTF run.  The local
model harness (`p4/ptf/model/run_context_regressions.sh`) needs a per-program conf and a
PTF case under `p4/ptf/`, which is outside this pass.  Nothing in this file is evidence
about silicon.
"""
import json
import pathlib
import random
import unittest


HERE = pathlib.Path(__file__).resolve().parent
LEDGER_P4 = HERE / "mcp_fabric_ledger.p4"
BASE_P4 = HERE / "mcp_fabric_clf_eg.p4"
BFRT = HERE / "artifacts" / "mcp_fabric_ledger.bfrt.json"

MOD16 = 1 << 16
MOD32 = 1 << 32


def signed16(v):
    """The (int<16>) cast the SALU applies to a bit<16>."""
    v &= 0xFFFF
    return v - MOD16 if v & 0x8000 else v


class Sublink:
    """One directed sublink's three registers, as the P4 program keeps them.

    Egress (sender):  reg_wit_seq   -- read-then-increment, modular bit<16>
    Ingress (receiver): reg_wit_expect  = the ledger's `hi`, advance-only bit<16>
                        reg_wit_observed = the ledger's `lo`, never-reset bit<32>
    """

    def __init__(self):
        self.tx_seq = 0          # Egress.reg_wit_seq
        self.hi = 0              # Ingress.reg_wit_expect
        self.lo = 0              # Ingress.reg_wit_observed
        self.gap_events = 0      # tbl_wit_verdict's wit_loss entry

    def stamp(self):
        """Egress `wit_seq_next`: rv = v; v = v + 1."""
        seq = self.tx_seq
        self.tx_seq = (self.tx_seq + 1) % MOD16
        return seq

    def arrive(self, seq, advance_only=True):
        """Ingress: wit_check (hi) then wit_count (lo).  Returns the gap.

        `advance_only=False` reproduces the OLD unconditional resync that
        mcp_fabric_clf_eg.p4 ships, so the two can be compared on one stream.
        """
        gap = (self.hi - seq) % MOD16
        if advance_only:
            if signed16(self.hi - seq) <= 0:
                self.hi = (seq + 1) % MOD16
        else:
            self.hi = (seq + 1) % MOD16
        self.lo = min(self.lo + 1, MOD32 - 1)      # |+| : saturating
        if gap != 0:
            self.gap_events += 1
        return gap

    def read(self):
        return self.hi, self.lo


def scored_loss(before, after):
    """What the controller computes: (dhi mod 2^16) - dlo."""
    hi0, lo0 = before
    hi1, lo1 = after
    return ((hi1 - hi0) % MOD16) - (lo1 - lo0)


class TestLedgerSourcePinsTheModel(unittest.TestCase):
    """The model above is only evidence if it is the same arithmetic as the P4."""

    @classmethod
    def setUpClass(cls):
        cls.src = LEDGER_P4.read_text()

    def test_hi_is_the_advance_only_frontier(self):
        self.assertIn(
            "RegisterAction<bit<16>, bit<16>, bit<16>>(reg_wit_expect) wit_check = {",
            self.src)
        self.assertIn("            rv = v - hdr.witness.seq;", self.src)
        self.assertIn("            if ((int<16>)(v - hdr.witness.seq) <= 0) {", self.src)
        self.assertIn("                v = hdr.witness.seq + 1;", self.src)

    def test_lo_is_a_never_reset_32_bit_arrivals_counter(self):
        self.assertIn("Register<bit<32>, bit<16>>(1024, 0) reg_wit_observed;", self.src)
        self.assertIn(
            "RegisterAction<bit<32>, bit<16>, bit<16>>(reg_wit_observed) wit_count = {",
            self.src)
        self.assertIn("            v  = v |+| 1;", self.src)
        body = self.src.split("reg_wit_observed) wit_count = {", 1)[1].split("};", 1)[0]
        self.assertNotIn("v = 0", body,
                         "lo must never be reset: that is what makes dhi - dlo an "
                         "interval estimator instead of a since-last-gap counter")
        self.assertNotIn("md.wit_result.gap", body,
                         "reading gap here re-serialises the two ledger SALUs into "
                         "separate MAU stages; see LEDGER-COMPILE-GATE.md 2.2")

    def test_base_program_still_has_the_old_semantics_it_is_compared_against(self):
        """`advance_only=False` in the model is a real program, not a straw man.

        THIS PINS ANOTHER FILE.  If `mcp_fabric_clf_eg.p4` is legitimately edited, this
        test fails even though nothing here is wrong.  The fix is then to re-point the
        `advance_only=False` branch of the model at whatever the base now does, or to
        drop the comparison -- not to delete the assertion.  Note the asymmetry that
        makes this worth pinning: `mcp_fabric_noclf.p4` is GENERATED from the base by
        gen_variants.py, while `mcp_fabric_ledger.p4` is a hand copy, so base edits
        propagate to one derivative and silently not to the other.
        """
        base = BASE_P4.read_text()
        self.assertIn("            rv = v - hdr.witness.seq;\n"
                      "            v  = hdr.witness.seq + 1;\n", base)
        self.assertIn("            if (md.wit_result.gap != 0) {\n"
                      "                v = 0;\n", base)


class TestLedgerCountsLossExactly(unittest.TestCase):
    """(a) dhi - dlo equals the injected loss count, exactly."""

    def _run(self, n, drop_seqs, start_hi=0, start_lo=0, start_tx=0):
        s = Sublink()
        s.tx_seq, s.hi, s.lo = start_tx, start_hi, start_lo
        before = s.read()
        for _ in range(n):
            seq = s.stamp()
            if seq in drop_seqs:
                continue          # tbl_eg_fail / tbl_eg_bern: dropped post-stamp
            s.arrive(seq)
        return scored_loss(before, s.read()), s

    def test_no_loss_scores_zero(self):
        lost, _ = self._run(1000, set())
        self.assertEqual(lost, 0)

    def test_two_isolated_drops(self):
        lost, _ = self._run(10, {3, 7})
        self.assertEqual(lost, 2)

    def test_a_burst_is_counted_once_per_packet_not_once_per_burst(self):
        lost, s = self._run(100, set(range(40, 55)))
        self.assertEqual(lost, 15)
        self.assertEqual(s.gap_events, 1,
                         "a 15-packet burst is one discontinuity, so one mirror event, "
                         "but fifteen scored losses")

    def test_exact_over_many_random_drop_patterns(self):
        """Exact for every drop a survivor has already revealed.

        The expected value is NOT simply `k`.  A discontinuity is only observable
        to the next survivor, so a drop in the trailing run -- after the last packet
        that actually arrived -- has not happened yet as far as the frontier is
        concerned.  That is the idle-tail blindness the witness has always had (see
        `p4/witness/COMPILE-GATE.md` 5.3); it is a property of a post-hoc sequence,
        not of the ledger, and `test_trailing_loss_is_invisible_until_the_next_survivor`
        below pins it on its own.
        """
        rng = random.Random(20260901)
        for trial in range(200):
            n = rng.randint(50, 400)
            k = rng.randint(0, n // 3)
            drops = set(rng.sample(range(n), k))
            arrived = [q for q in range(n) if q not in drops]
            if not arrived:
                continue
            revealed = sum(1 for q in drops if q < arrived[-1])
            lost, _ = self._run(n, drops)
            self.assertEqual(lost, revealed,
                             "trial %d: n=%d k=%d revealed=%d" % (trial, n, k, revealed))

    def test_trailing_loss_is_invisible_until_the_next_survivor(self):
        lost, _ = self._run(10, {8, 9})
        self.assertEqual(lost, 0,
                         "nothing arrived after seq 7, so the frontier cannot know "
                         "that 8 and 9 were sent at all")
        lost, _ = self._run(11, {8, 9})
        self.assertEqual(lost, 2, "seq 10 arriving reveals both")

    def test_the_estimator_needs_a_read_before_the_frontier_wraps(self):
        """`hi` is bit<16>: an interval of >= 2^16 packets is not readable.

        Pinned as a test because it is a hard requirement on the controller's read
        cadence, not a tuning knob.  `lo` is 32 bits and does not have this problem.
        """
        # seq 5000 is stamped exactly once in a 70000-packet run (only seq < 4464
        # comes round twice), so the true loss is 1 in both runs.
        ok, _ = self._run(60000, {5000})
        self.assertEqual(ok, 1)
        broken, _ = self._run(70000, {5000})
        self.assertNotEqual(broken, 1, "an over-long interval must not look correct")
        self.assertEqual((1 - broken) % MOD16, 0,
                         "the error is a whole number of frontier wraps: %d" % broken)

    def test_exact_across_the_16_bit_sequence_wrap(self):
        # start the sender 20 short of the wrap so the interval straddles it
        lost, s = self._run(200, {65530, 65535, 0, 5}, start_hi=65516, start_tx=65516)
        self.assertEqual(lost, 4)
        self.assertLess(s.tx_seq, 65516, "the stream must actually have wrapped")

    def test_lo_is_a_lifetime_counter_not_a_since_gap_counter(self):
        _, s = self._run(100, {10, 20, 30})
        self.assertEqual(s.lo, 97,
                         "lo counts every arrival for the life of the register; the "
                         "controller differences it, the data plane never resets it")

    def test_a_read_mid_stream_is_self_consistent(self):
        """No guard interval: any two reads bracket a valid interval estimate."""
        s = Sublink()
        marks = []
        dropped_between = []
        pending = 0
        for i in range(600):
            if i % 100 == 0:
                marks.append(s.read())
                dropped_between.append(pending)
                pending = 0
            seq = s.stamp()
            if i % 37 == 0:
                pending += 1
                continue
            s.arrive(seq)
        marks.append(s.read())
        dropped_between.append(pending)
        for j in range(1, len(marks)):
            self.assertEqual(scored_loss(marks[j - 1], marks[j]), dropped_between[j],
                             "interval %d" % j)


class TestAdvanceOnlyFixesTheReorderRegression(unittest.TestCase):
    """H33: the shipped witness reported a single adjacent reorder as loss."""

    REORDER = [0, 1, 3, 2, 4]

    def _replay(self, stream, advance_only):
        s = Sublink()
        before = s.read()
        for seq in stream:
            s.arrive(seq, advance_only=advance_only)
        return scored_loss(before, s.read()), s

    def test_a_pure_reorder_with_no_loss_scores_zero(self):
        lost, _ = self._replay(self.REORDER, advance_only=True)
        self.assertEqual(lost, 0)

    def test_the_frontier_never_rewinds(self):
        s = Sublink()
        seen = []
        for seq in self.REORDER:
            s.arrive(seq)
            seen.append(s.hi)
        self.assertEqual(seen, sorted(seen), "hi must be non-decreasing: %r" % (seen,))
        self.assertEqual(seen, [1, 2, 4, 4, 5])

    def test_the_packet_after_a_reorder_is_clean_under_advance_only(self):
        new_gaps = self._replay(self.REORDER, advance_only=True)[1].gap_events
        old_gaps = self._replay(self.REORDER, advance_only=False)[1].gap_events
        self.assertEqual(new_gaps, 2, "the forward jump and the late arrival itself")
        self.assertEqual(old_gaps, 3,
                         "the old unconditional resync rewound hi, so the NEXT in-order "
                         "packet raised a third, phantom gap -- HURDLES H33")

    def test_the_old_resync_could_score_negative_loss_where_the_ledger_scores_zero(self):
        truncated = [0, 1, 3, 2]      # read taken before the reorder is resolved
        self.assertEqual(self._replay(truncated, advance_only=True)[0], 0)
        self.assertEqual(self._replay(truncated, advance_only=False)[0], -1)


class TestReorderCreditWindowIsNotClaimedSolved(unittest.TestCase):
    """Red-team finding 4.  The estimator is exact only after the window elapses.

    This is the one property the plan requires be stated rather than quietly assumed,
    so it is asserted as a test: an instantaneous read taken while packets are still
    out of order over-counts, and nothing in the data plane fixes that.
    """

    def test_an_instantaneous_read_over_counts_while_a_reorder_is_outstanding(self):
        s = Sublink()
        before = s.read()
        for seq in (0, 1, 3):
            s.arrive(seq)
        self.assertEqual(scored_loss(before, s.read()), 1,
                         "seq 2 is not lost, only late -- the read cannot know that yet")
        s.arrive(2)
        self.assertEqual(scored_loss(before, s.read()), 0,
                         "the debt is retired once the late packet lands")

    def test_a_duplicate_arrival_drives_the_estimate_NEGATIVE(self):
        """The other direction of the same window, and the one easiest to miss.

        A duplicate increments `lo` without advancing `hi`, so `dhi - dlo` goes below
        zero.  The controller must clamp at zero rather than treat a negative as an
        underflow of the modular subtraction.
        """
        s = Sublink()
        before = s.read()
        for seq in (0, 1, 2, 2):
            s.arrive(seq)
        self.assertEqual(scored_loss(before, s.read()), -1)

    def test_a_reordered_packet_that_never_arrives_stays_scored_as_loss(self):
        s = Sublink()
        before = s.read()
        for seq in (0, 1, 3, 4):
            s.arrive(seq)
        self.assertEqual(scored_loss(before, s.read()), 1,
                         "seq 2 never lands, so the debt is never retired -- which is "
                         "the case the credit window is supposed to resolve INTO loss")

    def test_the_source_refuses_the_exact_at_any_instant_claim(self):
        # Comments wrap, so scan a whitespace-normalised stream rather than lines.
        flat = " ".join(LEDGER_P4.read_text().replace("*", " ").lower().split())
        for phrase in ("exact at any instant", "exact-at-any-instant"):
            start = 0
            while True:
                at = flat.find(phrase, start)
                if at < 0:
                    break
                window = flat[max(0, at - 80):at]
                self.assertTrue(
                    "not" in window or "never" in window,
                    "the phrase may only appear negated; context: %r"
                    % flat[max(0, at - 80):at + len(phrase)])
                start = at + len(phrase)
        self.assertIn("reorder-credit window", flat)
        self.assertIn("not exact at an arbitrary instant", flat)
        gate = (HERE.parents[1] / "docs/review/artifacts/LEDGER-COMPILE-GATE.md").read_text()
        self.assertIn("reorder-credit", gate.lower())
        self.assertIn("NOT IMPLEMENTED", gate)


class BernoulliInjector:
    """`tbl_eg_bern` as the control plane programs it.

    Two entries per armed sublink over disjoint ranges of the per-packet draw:
        (sublink, [0, W-1])    -> eg_bern_drop   with W = round(p * 65536)
        (sublink, [W, 65535])  -> eg_bern_none
    Both actions call eg_bern_ctr.count(), so offered = drop + none.
    """

    def __init__(self, p, seed):
        self.width = round(p * MOD16)
        self.rng = random.Random(seed)
        self.drop_ctr = 0
        self.none_ctr = 0

    def offer(self):
        draw = self.rng.randrange(MOD16)          # Random<bit<16>>
        if draw < self.width:
            self.drop_ctr += 1
            return True
        self.none_ctr += 1
        return False

    @property
    def offered(self):
        return self.drop_ctr + self.none_ctr

    @property
    def configured_p(self):
        return self.width / MOD16


class TestBernoulliInjector(unittest.TestCase):
    """(b) realised rate matches the configured probability within tolerance."""

    N = 200000

    def test_realised_rate_matches_configuration_within_five_sigma(self):
        for i, p in enumerate((0.5, 0.1, 0.01, 0.001)):
            with self.subTest(p=p):
                inj = BernoulliInjector(p, seed=1000 + i)
                for _ in range(self.N):
                    inj.offer()
                target = inj.configured_p
                sigma = (self.N * target * (1 - target)) ** 0.5
                self.assertAlmostEqual(
                    inj.drop_ctr, self.N * target, delta=5 * sigma,
                    msg="p=%g configured=%g realised=%g"
                        % (p, target, inj.drop_ctr / self.N))

    def test_offered_is_the_sum_of_both_counters(self):
        inj = BernoulliInjector(0.02, seed=7)
        for _ in range(50000):
            inj.offer()
        self.assertEqual(inj.offered, 50000)
        self.assertEqual(inj.offered, inj.drop_ctr + inj.none_ctr)

    def test_p_equals_one_is_not_representable_and_must_not_be_configured(self):
        """W = 65536 does not fit a bit<16> range bound; a 100% blackhole needs
        tbl_eg_fail with a full-width range, or a separate unconditional entry."""
        self.assertEqual(round(1.0 * MOD16), MOD16)
        self.assertGreater(MOD16, 0xFFFF, "65536 is not a legal bit<16> range bound")
        inj = BernoulliInjector(1.0, seed=3)
        self.assertEqual(inj.width, MOD16)

    def test_a_zero_width_range_never_drops(self):
        inj = BernoulliInjector(0.0, seed=7)
        for _ in range(10000):
            self.assertFalse(inj.offer())
        self.assertEqual(inj.drop_ctr, 0)
        self.assertEqual(inj.none_ctr, 10000)

    def test_injected_loss_is_what_the_ledger_scores(self):
        """The two halves meet: whatever the injector drops, the ledger counts."""
        s = Sublink()
        inj = BernoulliInjector(0.01, seed=99)
        before = s.read()
        n = 60000              # < 2^16: one read interval, no frontier wrap
        for _ in range(n):
            seq = s.stamp()
            if inj.offer():
                continue
            s.arrive(seq)
        # A trailing run of drops is not yet observable (see the idle-tail test);
        # `hi` names the last sequence that actually arrived, so the tail is derivable.
        tail = (n - s.hi) % MOD16
        self.assertEqual(scored_loss(before, s.read()), inj.drop_ctr - tail,
                         "every drop except any trailing run is scored")
        self.assertGreater(inj.drop_ctr, 0)

    def test_the_table_shape_the_model_assumes_is_the_table_in_the_source(self):
        src = LEDGER_P4.read_text()
        self.assertIn("Random<bit<16>>() rng_eg_bern;", src)
        self.assertIn(
            "DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) eg_bern_ctr;", src)
        tbl = src.split("table tbl_eg_bern {", 1)[1].split("\n    }", 1)[0]
        self.assertIn("md.sublink : exact;", tbl)
        self.assertIn("md.eg_rnd  : range;", tbl)
        self.assertIn("actions  = { eg_bern_drop; eg_bern_none; }", tbl)
        self.assertIn("counters = eg_bern_ctr;", tbl)
        for act in ("eg_bern_drop", "eg_bern_none"):
            body = src.split("action %s() {" % act, 1)[1].split("}", 1)[0]
            self.assertIn("eg_bern_ctr.count();", body,
                          "%s must count or `offered` is unreadable" % act)
        self.assertIn("eg_dprsr_md.drop_ctl = 1;",
                      src.split("action eg_bern_drop() {", 1)[1].split("}", 1)[0])
        # the deterministic one-shot arm survives alongside it
        self.assertIn("table tbl_eg_fail {", src)
        self.assertLess(src.index("tbl_eg_fail.apply();"), src.index("tbl_eg_bern.apply();"))
        # and both run after the sequence is consumed, or neither can produce a gap
        self.assertLess(src.index("tbl_wit_stamp.apply();"), src.index("tbl_eg_fail.apply();"))


class TestClfSchemeIsGone(unittest.TestCase):
    """(c) nothing can silently keep reading the retired state."""

    @classmethod
    def setUpClass(cls):
        cls.src = LEDGER_P4.read_text()
        cls.schema = json.loads(BFRT.read_text())
        cls.names = {t["name"] for t in cls.schema["tables"]}

    def test_the_rx_frontier_is_absent_from_the_source(self):
        for gone in ("reg_rx_frontier", "rx_seen", "rx_frontier_mark",
                     "md.clf_idx", "md.clf_rx_prev"):
            self.assertNotIn(gone + ";", self.src)
            self.assertNotIn(gone + ".", self.src)
            self.assertNotIn(gone + " =", self.src)
        self.assertNotIn("tbl_rx_frontier.apply()", self.src)

    def test_the_rx_frontier_is_absent_from_the_generated_schema(self):
        for gone in ("pipe.Ingress.reg_rx_frontier", "pipe.Ingress.tbl_rx_frontier"):
            self.assertNotIn(gone, self.names)
        self.assertEqual([n for n in self.names if "rx_frontier" in n], [])

    def test_the_bank_or_index_arithmetic_is_absent(self):
        self.assertNotIn("16w0x100", self.src)
        self.assertNotIn("16w0x400", self.src)
        self.assertNotIn("clf_bank != 0", self.src)
        # the wire field itself deliberately survives; see LEDGER-COMPILE-GATE.md 1
        self.assertIn("bit<8>  clf_bank;", self.src)
        self.assertIn("hdr.fabric.clf_bank = bank;", self.src)

    def test_the_ledger_registers_have_the_widths_the_controller_reads(self):
        widths = {}
        for t in self.schema["tables"]:
            for d in t.get("data", []):
                s = d.get("singleton")
                if s and any(a.get("value") == "register_data"
                             for a in s.get("annotations", [])):
                    widths[t["name"]] = s["type"]["width"]
        self.assertEqual(widths["pipe.Ingress.reg_wit_expect"], 16)    # hi, modular
        self.assertEqual(widths["pipe.Ingress.reg_wit_observed"], 32)  # lo, lifetime
        self.assertEqual(widths["pipe.Egress.reg_tx_frontier"], 32)    # TX frontier

    def test_the_sender_and_receiver_index_the_same_sublink(self):
        """The estimator is meaningless unless TX and RX name the same object.

        The model collapses both into one Sublink, so the pairing has to be pinned
        against the source or the model assumes away the thing that matters.

        Overhead-reduction pass 2026-09-02 stopped carrying link_id on the wire: the
        receiver now reconstructs md.wit_link from its own ingress port/spray plus a
        freshly re-derived ctx nibble (tbl_wit_link_recon + tbl_wit_ctx_index), rather
        than reading it straight off the wire. What still has to be pinned is that
        this reconstruction lands on the SAME sublink identity the sender used --
        i.e. that md.wit_link's composition mirrors md.sublink's own two-step
        composition (vlink upper bits, then ctx low nibble) exactly.
        """
        self.assertIn("action set_wit_link(bit<16> wit_vlink_base) {", self.src)
        self.assertIn("md.wit_link = wit_vlink_base;", self.src)          # vlink upper bits
        self.assertIn("action wit_ctx_index() { md.wit_link[3:0] = md.ctx[3:0]; }", self.src)
        self.assertIn("md.sublink = vlink_base;", self.src)               # sender's own vlink upper bits
        self.assertIn("action ctx_index() { md.sublink[3:0] = md.ctx[3:0]; }", self.src)
        self.assertIn("wit_check.execute(md.wit_link)", self.src)      # hi index
        self.assertIn("wit_count.execute(md.wit_link)", self.src)      # lo index
        self.assertIn("tx_seen.execute(md.clf_tx_idx)", self.src)      # TX index
        self.assertIn("md.clf_tx_idx = md.sublink;", self.src)

    def test_the_tx_frontier_is_deep_enough_for_the_sublink_index_space(self):
        """md.sublink = (vlink << 4) | ctx spans 0..1023; 512 slots aliased."""
        self.assertIn("Register<bit<32>, bit<16>>(2048, 0) reg_tx_frontier;", self.src)
        self.assertIn("Register<bit<32>, bit<16>>(1024, 0) reg_wit_observed;", self.src)
        self.assertIn("Register<bit<16>, bit<16>>(1024, 0) reg_wit_expect;", self.src)

    def test_the_bernoulli_table_reached_the_schema(self):
        self.assertIn("pipe.Egress.tbl_eg_bern", self.names)
        self.assertIn("pipe.Egress.tbl_eg_fail", self.names)

    def test_the_csig_egress_telemetry_was_not_deleted_with_the_clf_scheme(self):
        """Red-team finding 8: keep worst_qdepth carriage, delete only the CLF half."""
        for kept in ("tbl_csig_diff", "tbl_csig_replace_a", "tbl_csig_replace_b"):
            self.assertIn("table %s" % kept, self.src)
        self.assertIn("hdr.csig.worst_qdepth = md.this_q;", self.src)

    def test_the_base_program_is_untouched_by_this_pass(self):
        base = BASE_P4.read_text()
        self.assertIn("Register<bit<8>, bit<16>>(512, 0) reg_rx_frontier;", base)
        self.assertIn("md.clf_idx | 16w0x100;", base)


if __name__ == "__main__":
    unittest.main()
