import contextlib
import io
import sys
import unittest
from unittest import mock

from sim.sublink import feedback


class FeedbackReportTest(unittest.TestCase):
    def test_default_report_uses_measured_partial_loss_feedback_not_f6_attention(self):
        """The 97.4 us measurement is a same-switch congestion-attention result, not the
        downstream-C-W4-to-upstream-health-gate path this report is supposed to model.
        """
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["feedback.py"]), contextlib.redirect_stdout(out):
            feedback.main()
        report = out.getvalue()
        self.assertNotIn("data plane, measured tau_fast", report)
        self.assertNotIn("97.4", report)
        self.assertIn("4.998 ms is the measured partial-loss attributed-batch median", report)
        self.assertIn("measured attributed batch median", report)
        self.assertIn("minimal controller reference", report)


if __name__ == "__main__":
    unittest.main()
