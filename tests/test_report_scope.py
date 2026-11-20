"""The report leads with scope and a disclaimer, and gives no letter grade (pressure test 2026-11-19). Offline."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import report  # noqa: E402
from test_pressure_2026_11_15 import cert, view  # noqa: E402

GRADES = ("PQC-ready", "On track", "Not started", "At risk", "F:", "D:", "grade ")


class ReportScope(unittest.TestCase):
    def setUp(self):
        self.md, self.summary = report.build_report(view(lambda b: (
            b.add_certificate(cert("a.example")),
            b.add_tls_kex("a.example", "X25519MLKEM768", "TLSv1.3", "TLS_AES_256_GCM_SHA384"))))

    def test_no_letter_grade(self):
        for g in GRADES:
            self.assertNotIn(g, self.md, g)
        self.assertIsNone(self.summary["grade"])

    def test_scope_and_disclaimer_lead_the_report(self):
        head = self.md.split("## Bottom line")[0]
        self.assertIn("**Scope:**", head)
        self.assertIn("not an inventory of all the cryptography", head)
        self.assertIn("Not a compliance determination", head)
        self.assertIn("not a compliance determination", self.md.split("## Bottom line")[1].split("##")[0])

    def test_observed_facts_replace_the_grade(self):
        self.assertIn("post-quantum key exchange on 1 of 1 TLS endpoint(s)", self.md)
        self.assertEqual(self.summary["tls_endpoints"], 1)
        self.assertEqual(self.summary["tls_endpoints_pq_kex"], 1)

    def test_summary_carries_scope_and_disclaimer(self):
        self.assertEqual(self.summary["scope"]["coverage"], "partial")
        self.assertIn("not an inventory", self.summary["scope"]["statement"])
        self.assertIn("not a compliance determination", self.summary["disclaimer"])


if __name__ == "__main__":
    unittest.main()


class CodeSpanPipe(unittest.TestCase):
    """1.7.0: a backslash before a pipe in a code span never leaves the pipe unescaped (markdown-it counts them)."""

    def test_one_backslash_before_every_pipe(self):
        import re as _re
        for raw in ("a\\|b", "a\\\\|b", "x\\", "|", "\\|\\|", "p\\" + "&#124;q"):
            out = report.md_code(report.md_text(raw))
            for m in _re.finditer(r"\|", out):
                run = _re.match(r"\\*", out[:m.start()][::-1]).group(0)
                self.assertEqual(len(run), 1, (raw, out))
