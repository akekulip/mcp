"""Generator contract for the topology-realistic P3 mirror event variant."""
import pathlib
import subprocess
import sys
import unittest


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]


class TestGapEventVariant(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run([sys.executable, str(HERE / "gen_variants.py")], check=True,
                       cwd=str(ROOT), stdout=subprocess.DEVNULL)
        cls.source = (HERE / "mcp_fabric_gate_event.p4").read_text()

    def test_event_is_generated_from_the_capsule_health_gate(self) -> None:
        self.assertEqual(self.source.count("table tbl_health_gate"), 1)
        self.assertIn("struct wit_result_t", self.source)
        self.assertIn("Register<bit<16>, bit<16>>(1024, 0) reg_wit_expect", self.source)
        self.assertIn("Register<bit<16>, bit<16>>(1024, 0) reg_wit_observed", self.source)
        self.assertIn("table tbl_wit_count", self.source)

    def test_nonzero_gap_forces_dedicated_mirror_session_and_attribution(self) -> None:
        self.assertIn("action set_gap_event()", self.source)
        self.assertIn("md.mirror_sid           = 2;", self.source)
        self.assertIn("md.flags_out            = md.flags_out | 8;", self.source)
        self.assertIn("md.vlink_id             = md.wit_link;", self.source)
        self.assertIn("md.mir_path             = md.wit_result.gap;", self.source)
        self.assertIn("md.attn                 = md.wit_result.observed;", self.source)
        self.assertLess(self.source.index("tbl_final.apply();"),
                        self.source.index("set_gap_event();"),
                        "event metadata must overwrite ordinary mirror metadata last")

    def test_event_session_retains_csig_and_witness(self) -> None:
        setup = (ROOT / "p4/control/setup_attention.py").read_text()
        self.assertIn("(2, 128)", setup)

    def test_reserved_audit_packets_bypass_quarantine_and_force_receipt_evidence(self) -> None:
        self.assertIn("const bit<16> AUDIT_UDP_DST = 4792;", self.source)
        self.assertIn("table tbl_audit_steer", self.source)
        self.assertIn("if (md.hop == 0 && md.is_audit == 0) {", self.source)
        self.assertIn("tbl_health_gate.apply();", self.source)
        self.assertIn("action set_audit_receipt()", self.source)
        self.assertIn("md.flags_out            = md.flags_out | 16;", self.source)
        self.assertIn("action set_audit_gap_event()", self.source)
        self.assertIn("md.flags_out            = md.flags_out | 24;", self.source)
        self.assertIn(
            "if (md.hop != 0 && hdr.witness.isValid() && md.is_audit != 0) {",
            self.source,
        )

    def test_audit_bypass_requires_authorized_ingress_provenance(self) -> None:
        self.assertIn("bit<16> audit_src;", self.source)
        self.assertIn(
            "action set_role(bit<16> role, bit<16> src_leaf, bit<16> audit_src)",
            self.source,
        )
        self.assertIn("md.audit_src     : exact;", self.source)
        self.assertIn("const default_action = set_role(ROLE_OTHER, 0, 0);", self.source)

    def test_fault_injector_drops_after_the_witness_sequence_is_consumed(self) -> None:
        self.assertIn("table tbl_eg_fail", self.source)
        self.assertIn("hdr.witness.seq : range;", self.source)
        self.assertIn("DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) eg_fail_ctr;", self.source)
        self.assertLess(
            self.source.index("tbl_wit_link.apply();"),
            self.source.index("tbl_eg_fail.apply();"),
        )
        self.assertLess(
            self.source.index("tbl_eg_fail.apply();"),
            self.source.index("tbl_csig_diff.apply();"),
        )

    def test_capsule_parser_uses_same_width_copy_before_low_nibble_composition(self) -> None:
        self.assertIn("bit<8>  ctx;        // capsule read off the shim", self.source)
        self.assertIn("md.ctx = hdr.fabric.pad;", self.source)
        self.assertIn("md.sublink[3:0] = md.ctx[3:0];", self.source)
        self.assertNotIn("md.ctx = (bit<16>)hdr.fabric.pad;", self.source)


if __name__ == "__main__":
    unittest.main()
