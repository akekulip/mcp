"""Reproducibility contract for deriving the no-CLF witness variant."""
import pathlib
import subprocess
import sys
import unittest


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

sys.path.insert(0, str(HERE))
import gen_variants  # noqa: E402


class TestNoClfGeneration(unittest.TestCase):
    def test_noclf_is_deterministically_derived_from_clf_source(self) -> None:
        clf = (HERE / "mcp_fabric_clf_eg.p4").read_text()
        expected = (HERE / "mcp_fabric_noclf.p4").read_text()

        self.assertEqual(gen_variants.derive_noclf_from_clf(clf), expected)

    def test_noclf_transform_fails_closed_when_exact_anchor_is_missing(self) -> None:
        clf = (HERE / "mcp_fabric_clf_eg.p4").read_text()
        broken = clf.replace("Register<bit<8>, bit<16>>(512, 0) reg_rx_frontier;", "")

        with self.assertRaises(SystemExit):
            gen_variants.derive_noclf_from_clf(broken)

    def test_regeneration_preserves_checked_in_noclf_bytes(self) -> None:
        before = (HERE / "mcp_fabric_noclf.p4").read_bytes()

        subprocess.run([sys.executable, str(HERE / "gen_variants.py")], check=True,
                       cwd=str(ROOT), stdout=subprocess.DEVNULL)

        self.assertEqual((HERE / "mcp_fabric_noclf.p4").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
