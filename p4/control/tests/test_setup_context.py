"""tbl_context — the capsule classifier that makes a behavioural sublink behavioural.

Everything here runs against the very rows install_context() writes (via
setup_skeleton.classify_context, which walks plan_context() in priority order), so a
passing test is a statement about the plan and not about a second copy of it.

The one thing these tests CANNOT check is the unit mismatch itself: tbl_context keys
hdr.ipv4.total_len while sim/sublink_capacity.py's SizeSchema describes
mcp_fabric_cw4.p4's eg_intr_md.pkt_length.  See the CONTEXT CAPSULE block in
setup_skeleton.py.  What is checked below is the consequence that matters —
test_frozen_scenario_sizes_are_immune_to_the_header_offset.
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3]))

import setup_skeleton as sk
from sim.sublink_capacity import SizeSchema


DSCP_CS0, DSCP_CS1, DSCP_CS2, DSCP_CS3 = 0x00, 0x20, 0x40, 0x60
ECN_NOT_ECT, ECN_ECT0, ECN_ECT1, ECN_CE = 0b00, 0b10, 0b01, 0b11


class SizeSchemaAgreementTest(unittest.TestCase):
    """The switch and the simulator must not be able to drift apart silently."""

    def test_boundaries_are_the_frozen_size_schema(self):
        self.assertEqual(sk.CTX_SIZE_BOUNDARIES, SizeSchema().boundaries)

    def test_every_size_bin_index_matches_the_schema_stratum(self):
        schema = SizeSchema()
        for low, high, size_bin in sk.ctx_size_bins():
            self.assertEqual(schema.stratum(low), size_bin)
            self.assertEqual(schema.stratum(high), size_bin)

    def test_the_number_of_strata_matches(self):
        self.assertEqual(len(sk.ctx_size_bins()), len(SizeSchema().boundaries) + 1)

    def test_class_zero_contexts_are_the_bare_size_strata(self):
        """sim/dynamic/PREREG.md: "contexts 0..3 (the four compiled size strata)"."""
        schema = SizeSchema()
        for size in (0, 255, 256, 1023, 1024, 2047, 2048, 65535):
            self.assertEqual(sk.classify_context(size, DSCP_CS0), schema.stratum(size))


class BoundaryTest(unittest.TestCase):
    """Off-by-one at a stratum edge is the failure this table exists to not have."""

    def test_exact_boundary_values(self):
        for total_len, expected in ((0, 0), (1, 0), (255, 0), (256, 1),
                                    (257, 1), (1023, 1), (1024, 2),
                                    (1025, 2), (2047, 2), (2048, 3),
                                    (2049, 3), (65535, 3)):
            self.assertEqual(sk.classify_context(total_len, DSCP_CS0), expected,
                             "total_len %d" % total_len)

    def test_each_boundary_is_the_first_byte_of_the_upper_stratum(self):
        for boundary in SizeSchema().boundaries:
            below = sk.classify_context(boundary - 1, DSCP_CS0)
            at = sk.classify_context(boundary, DSCP_CS0)
            self.assertEqual(at, below + 1,
                             "boundary %d must open a new stratum" % boundary)

    def test_boundaries_hold_in_every_dscp_class(self):
        for dscp, dscp_class in ((DSCP_CS0, 0), (DSCP_CS1, 1),
                                 (DSCP_CS2, 2), (DSCP_CS3, 3)):
            for total_len, size_bin in ((255, 0), (256, 1), (1023, 1),
                                        (1024, 2), (2047, 2), (2048, 3)):
                self.assertEqual(sk.classify_context(total_len, dscp),
                                 sk.ctx_of(size_bin, dscp_class),
                                 "total_len %d dscp 0x%02X" % (total_len, dscp))


class TilingTest(unittest.TestCase):
    """A gap falls through to the const default set_ctx(0) — a silent merge into
    stratum 0.  An overlap makes the context depend on entry order."""

    def test_bins_abut_with_no_gap_and_no_overlap(self):
        bins = sk.ctx_size_bins()
        self.assertEqual(bins[0][0], 0)
        self.assertEqual(bins[-1][1], sk.CTX_LEN_MAX)
        for (_lo, hi, _i), (lo2, _hi2, _j) in zip(bins, bins[1:]):
            self.assertEqual(lo2, hi + 1)

    def test_every_total_len_matches_exactly_one_row_per_class(self):
        """Exhaustive over the whole 16-bit range, at every stratum edge and a
        sample in between: a range table cannot be argued about, only enumerated."""
        rows = [k for k, _ in sk.plan_context() if (k[2] & k[3]) == DSCP_CS0]
        probes = set()
        for low, high, _bin in sk.ctx_size_bins():
            probes.update((low - 1, low, low + 1, high - 1, high, high + 1))
        probes.update((0, 1, 42, 1500, 9000, 65534, sk.CTX_LEN_MAX))
        for total_len in sorted(p for p in probes if 0 <= p <= sk.CTX_LEN_MAX):
            hits = [k for k in rows if k[0] <= total_len <= k[1]]
            self.assertEqual(len(hits), 1,
                             "total_len %d matched %d rows" % (total_len, len(hits)))

    def test_full_sweep_of_the_16_bit_range_is_covered(self):
        covered = set()
        for low, high, _bin in sk.ctx_size_bins():
            span = set(range(low, high + 1))
            self.assertEqual(covered & span, set(), "size bins overlap")
            covered |= span
        self.assertEqual(covered, set(range(0, sk.CTX_LEN_MAX + 1)))

    def test_priorities_are_unique_and_the_plan_fits_the_table(self):
        rows = sk.plan_context()
        self.assertEqual(len(rows), 16)
        self.assertEqual(len(set(k[4] for k, _ in rows)), len(rows))
        self.assertLessEqual(len(rows), 32, "tbl_context is size = 32 in the P4")


class EcnTest(unittest.TestCase):
    """ECN is set by congested queues anywhere on the path.  If it reached the key,
    congestion would silently move a packet into a different behavioural sublink —
    which is exactly the signal the sublink exists to measure."""

    def test_mask_excludes_the_two_ecn_bits(self):
        self.assertEqual(sk.CTX_DSCP_MASK, 0xFC)
        self.assertEqual(sk.CTX_DSCP_MASK & 0x03, 0)

    def test_every_ecn_codepoint_gives_the_same_context(self):
        for dscp in (DSCP_CS0, DSCP_CS1, DSCP_CS2, DSCP_CS3):
            for total_len in (0, 255, 256, 1023, 1024, 2047, 2048, 9000, 65535):
                contexts = set(sk.classify_context(total_len, dscp | ecn)
                               for ecn in (ECN_NOT_ECT, ECN_ECT0, ECN_ECT1, ECN_CE))
                self.assertEqual(len(contexts), 1,
                                 "ECN changed the context of a %d B DSCP 0x%02X packet: %s"
                                 % (total_len, dscp, sorted(contexts)))

    def test_congestion_marking_a_packet_mid_flow_does_not_reclassify_it(self):
        before = sk.classify_context(1400, DSCP_CS2 | ECN_ECT0)
        after = sk.classify_context(1400, DSCP_CS2 | ECN_CE)
        self.assertEqual(before, after)
        self.assertEqual(after, sk.ctx_of(2, 2))


class EncodingTest(unittest.TestCase):
    def test_context_is_class_over_size_and_fits_the_shim_pad_nibble(self):
        for _key, ctx in sk.plan_context():
            self.assertGreaterEqual(ctx, 0)
            self.assertLessEqual(ctx, 0xF, "ctx must fit hdr.fabric.pad's low nibble")

    def test_published_mapping_matches_the_ptf_tests(self):
        """p4/ptf/test_capsule.py and p4/ptf/test_health_gate.py both define
        ctx_of(size_bin, dscp_class) = (dscp_class << 2) | size_bin over
        SIZE_BINS [(0,255,0),(256,1023,1),(1024,2047,2),(2048,65535,3)] and
        DSCP_CLASSES [(0x00,0),(0x08,1),(0x10,2),(0x18,3)] at mask 0xFC."""
        expected = []
        priority = 1
        for low, high, size_bin in ((0, 255, 0), (256, 1023, 1),
                                    (1024, 2047, 2), (2048, 65535, 3)):
            for dscp, dscp_class in ((0x00, 0), (0x08, 1), (0x10, 2), (0x18, 3)):
                expected.append(((low, high, dscp << 2, 0xFC, priority),
                                 (dscp_class << 2) | size_bin))
                priority += 1
        self.assertEqual(sk.plan_context(), expected)

    def test_a_missing_row_would_fall_through_to_context_zero(self):
        """Documents the failure mode the tiling test guards: the P4's const
        default_action is set_ctx(0), so an uncovered packet is not dropped — it is
        silently merged into stratum 0.  DSCP CS4 (codepoint 32, byte 0x80) is not
        one of the four published classes, so a 4096 B CS4 packet lands in context 0
        rather than in stratum 3."""
        self.assertEqual(sk.classify_context(4096, 0x80), 0)
        self.assertEqual(sk.classify_context(4096, DSCP_CS3), sk.ctx_of(3, 3))


class HeaderOffsetTest(unittest.TestCase):
    """THE UNIT MISMATCH.

    tbl_context keys hdr.ipv4.total_len (IP header + payload).  The frozen
    SizeSchema describes mcp_fabric_cw4.p4's tbl_stratum, which keys
    eg_intr_md.pkt_length under `if (hdr.csig.isValid())` — ethernet(14) +
    fabric(12) + csig(14) + witness(4) + total_len.  The two quantities differ by a
    constant 44 bytes on a fabric pass, or 14 on a bare host frame.

    These tests do not hide that.  They pin down exactly where it does and does not
    matter, so the decision is auditable instead of assumed.
    """

    ETH = 14
    CW4_EGRESS_SHIM = 14 + 12 + 14 + 4          # eth + fabric + csig + witness

    # every packet size the frozen experiment uses (sim/sublink_capacity.py)
    FROZEN_SIZES = (512, 1400, 1800, 4096)

    def test_frozen_scenario_sizes_are_immune_to_the_header_offset(self):
        """The reason CTX_LEN_OFFSET = 0 is safe for every published row: no frozen
        size is within 44 bytes of a boundary, so classifying on total_len, on the
        host frame, or on the C-W4 egress frame gives the same stratum."""
        schema = SizeSchema()
        for size in self.FROZEN_SIZES:
            strata = set(schema.stratum(size + offset)
                         for offset in (0, self.ETH, self.CW4_EGRESS_SHIM))
            self.assertEqual(len(strata), 1,
                             "size %d B straddles a boundary under some header "
                             "convention: %s" % (size, sorted(strata)))
            self.assertEqual(sk.classify_context(size, DSCP_CS0), strata.pop())

    def test_the_offset_does_matter_just_below_every_boundary(self):
        """Stated rather than glossed: inside these bands the capsule and the C-W4
        egress classifier disagree by one stratum.  Traffic generation must avoid
        them, or CTX_LEN_OFFSET must be set to the shim size."""
        schema = SizeSchema()
        for boundary in schema.boundaries:
            total_len = boundary - 1
            self.assertEqual(sk.classify_context(total_len, DSCP_CS0),
                             schema.stratum(total_len))
            self.assertNotEqual(sk.classify_context(total_len, DSCP_CS0),
                                schema.stratum(total_len + self.CW4_EGRESS_SHIM))

    def test_the_offset_is_the_single_constant_that_moves_every_boundary(self):
        original = sk.CTX_LEN_OFFSET
        try:
            sk.CTX_LEN_OFFSET = self.CW4_EGRESS_SHIM
            bins = sk.ctx_size_bins()
            self.assertEqual([high for _lo, high, _b in bins[:-1]],
                             [b - self.CW4_EGRESS_SHIM - 1
                              for b in SizeSchema().boundaries])
            # and with the offset applied, a packet 1 byte under a boundary now
            # classifies the way C-W4's egress frame would
            for boundary in SizeSchema().boundaries:
                self.assertEqual(sk.classify_context(boundary - 1, DSCP_CS0),
                                 SizeSchema().stratum(boundary - 1
                                                      + self.CW4_EGRESS_SHIM))
            self.assertEqual(bins[0][0], 0)
            self.assertEqual(bins[-1][1], sk.CTX_LEN_MAX)
        finally:
            sk.CTX_LEN_OFFSET = original
        self.assertEqual(sk.CTX_LEN_OFFSET, 0)


class PlanSelfCheckTest(unittest.TestCase):
    def test_self_check_covers_the_classifier(self):
        sk.self_check()          # asserts the tiling, priorities and ECN mask


if __name__ == "__main__":
    unittest.main()
