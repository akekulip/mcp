import contextlib
import io
import sys
import unittest
from unittest import mock

from sim.sublink import feedback


class FeedbackReportTest(unittest.TestCase):
    def test_default_report_does_not_present_f6_attention_as_cw4_feedback(self):
        """The 97.4 us measurement is a same-switch congestion-attention result, not the
        downstream-C-W4-to-upstream-health-gate path this report is supposed to model.
        """
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["feedback.py"]), contextlib.redirect_stdout(out):
            feedback.main()
        report = out.getvalue()
        self.assertNotIn("data plane, measured tau_fast", report)
        self.assertIn("no end-to-end C-W4 feedback latency has been measured", report)


if __name__ == "__main__":
    unittest.main()
