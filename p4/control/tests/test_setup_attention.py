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

    def test_live_schema_introspection_failure_never_falls_back_to_program_name(self):
        class BrokenBfrt:
            def table_get(self, _name):
                raise RuntimeError("schema unavailable")

        with self.assertRaisesRegex(RuntimeError, "schema unavailable"):
            setup_attention.is_contextual_program("mcp_fabric_gate_event", BrokenBfrt())

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


class EgVlinkVerificationTest(unittest.TestCase):
    def _planned_snapshot(self, contextual=False):
        rows = []
        for port, qid, vlink in setup_attention.plan_eg_vlink():
            rows.append({
                "key": {
                    "eg_intr_md.egress_port": {"value": port},
                    "eg_intr_md.egress_qid": {"value": qid},
                },
                "action": "Egress.set_eg_vlink",
                "data": dict(setup_attention.eg_vlink_action_fields(vlink, contextual)),
            })
        return rows

    def test_exact_eg_vlink_verification_accepts_complete_planned_snapshot(self):
        self.assertEqual(
            setup_attention.verify_eg_vlink_snapshot(self._planned_snapshot(contextual=True),
                                                     contextual=True),
            "tbl_eg_vlink verified: 16 exact rows",
        )

    def test_exact_eg_vlink_verification_ignores_bfrt_entry_metadata(self):
        rows = self._planned_snapshot(contextual=True)
        for row in rows:
            row["data"]["is_default_entry"] = False
        self.assertEqual(
            setup_attention.verify_eg_vlink_snapshot(rows, contextual=True),
            "tbl_eg_vlink verified: 16 exact rows",
        )

    def test_exact_eg_vlink_verification_rejects_missing_row(self):
        rows = self._planned_snapshot()
        with self.assertRaisesRegex(ValueError, "missing row"):
            setup_attention.verify_eg_vlink_snapshot(rows[:-1])

    def test_exact_eg_vlink_verification_rejects_stale_row(self):
        rows = self._planned_snapshot()
        rows.append({
            "key": {
                "eg_intr_md.egress_port": {"value": 9},
                "eg_intr_md.egress_qid": {"value": 0},
            },
            "action": "Egress.set_eg_vlink",
            "data": {"vlink": 99},
        })
        with self.assertRaisesRegex(ValueError, "stale row"):
            setup_attention.verify_eg_vlink_snapshot(rows)

    def test_exact_eg_vlink_verification_rejects_wrong_action(self):
        rows = self._planned_snapshot()
        rows[0]["action"] = "Egress.wrong_action"
        with self.assertRaisesRegex(ValueError, "wrong action"):
            setup_attention.verify_eg_vlink_snapshot(rows)

    def test_exact_eg_vlink_verification_rejects_wrong_vlink(self):
        rows = self._planned_snapshot()
        rows[0]["data"]["vlink"] = 99
        with self.assertRaisesRegex(ValueError, "wrong data"):
            setup_attention.verify_eg_vlink_snapshot(rows)

    def test_exact_eg_vlink_verification_rejects_wrong_contextual_base(self):
        rows = self._planned_snapshot(contextual=True)
        rows[0]["data"]["vlink_base"] = 99
        with self.assertRaisesRegex(ValueError, "wrong data"):
            setup_attention.verify_eg_vlink_snapshot(rows, contextual=True)

    def test_exact_eg_vlink_verification_rejects_extra_action_data(self):
        rows = self._planned_snapshot()
        rows[0]["data"]["unexpected"] = 1
        with self.assertRaisesRegex(ValueError, "wrong data"):
            setup_attention.verify_eg_vlink_snapshot(rows)


if __name__ == "__main__":
    unittest.main()
