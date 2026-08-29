import unittest
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import setup_attention
import setup_skeleton


class Cw4ControlPlaneTest(unittest.TestCase):
    def test_baseline_egress_vlink_action_keeps_original_shape(self):
        self.assertEqual(setup_attention.eg_vlink_action_fields(9, contextual=False),
                         (("vlink", 9),))

    def test_cw4_egress_vlink_action_supplies_shifted_base(self):
        self.assertEqual(setup_attention.eg_vlink_action_fields(9, contextual=True),
                         (("vlink", 9), ("vlink_base", 9 << 4)))

    def test_every_capsule_or_context_program_uses_the_contextual_action_shape(self):
        for program in ("mcp_fabric_cw4", "mcp_fabric_capsule", "mcp_fabric_gate",
                        "mcp_fabric_gate_event"):
            self.assertTrue(setup_attention.is_contextual_program(program), program)
        self.assertFalse(setup_attention.is_contextual_program("mcp_fabric"))

    def test_all_deployed_vlinks_fit_above_the_stratum_nibble(self):
        for _port, _qid, vlink in setup_attention.plan_eg_vlink():
            fields = dict(setup_attention.eg_vlink_action_fields(vlink, contextual=True))
            self.assertEqual(fields["vlink_base"] | 0xF, (vlink << 4) | 0xF)
            self.assertLessEqual(fields["vlink_base"] | 0xF, 1023)

    def test_skeleton_accepts_the_cw4_program_name(self):
        program, remaining = setup_skeleton.extract_program_arg(
            ["up", "--program", "mcp_fabric_cw4"])
        self.assertEqual(program, "mcp_fabric_cw4")
        self.assertEqual(remaining, ["up"])

    def test_skeleton_program_defaults_without_mutating_other_flags(self):
        program, remaining = setup_skeleton.extract_program_arg(["--dry-run", "--json"])
        self.assertEqual(program, setup_skeleton.PROG)
        self.assertEqual(remaining, ["--dry-run", "--json"])


if __name__ == "__main__":
    unittest.main()
