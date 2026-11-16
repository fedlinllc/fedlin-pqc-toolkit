"""A policy result is used only if its verdicts re-check (pressure test 2026-11-15). Offline."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import policy  # noqa: E402
import report  # noqa: E402
from test_mcp_server import make_outputs  # noqa: E402

def _load(path):
    with open(path) as f:
        return json.load(f)


def _dump(obj, path):
    with open(path, "w") as f:
        json.dump(obj, f)



class Check(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.cbom = make_outputs(self.t.name)
        self.pol = os.path.join(self.t.name, "cbom.policy.json")

    def tearDown(self):
        self.t.cleanup()

    def forge(self):
        r = _load(self.pol)
        for f in r["findings"]:
            if f["status"] == "vulnerable":
                f.update(status="compliant", quantumVulnerable=False, priority="None", target="None")
        _dump(r, self.pol)

    def verify_rc(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = policy.main(["verify", "--cbom", self.cbom, "--policy", self.pol])
        return rc, out.getvalue()

    def test_genuine_result_passes(self):
        self.assertTrue(policy.check(_load(self.pol), self.cbom)["ok"])
        self.assertEqual(self.verify_rc()[0], 0)

    def test_forged_verdicts_fail_verify_and_are_not_reported(self):
        self.forge()
        rc, out = self.verify_rc()
        self.assertEqual(rc, 1)
        self.assertIn("verdicts do not match a re-evaluation", out)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            view = report._load_view(self.cbom, self.pol)
        self.assertIn("not used", err.getvalue())
        _, summary = report.build_report(view)
        self.assertGreater(summary["quantum_vulnerable"], 0)

    def test_other_ruleset_is_not_trusted(self):
        r = _load(self.pol)
        r["policy"]["digest"]["value"] = "0" * 64
        _dump(r, self.pol)
        c = policy.check(r, self.cbom)
        self.assertTrue(c["bound"])
        self.assertFalse(c["ruleset"] or c["ok"])
        self.assertIsNone(c["reproduced"])

    def test_duplicate_forged_finding_is_caught(self):
        r = _load(self.pol)
        f = next(x for x in r["findings"] if x["status"] == "vulnerable")
        r["findings"].insert(0, dict(f, status="compliant", priority="None", quantumVulnerable=False, target="None"))
        _dump(r, self.pol)
        c = policy.check(r, self.cbom)
        self.assertFalse(c["ok"])
        self.assertTrue(any("copies of one finding" in m for m in c["mismatches"]))

    def test_edited_controls_or_summary_are_caught(self):
        r = _load(self.pol)
        r["findings"][0]["controls"] = ["XX-1"]
        self.assertFalse(policy.check(r, self.cbom)["ok"])
        r = _load(self.pol)
        r["summary"] = {"compliant": 99}
        self.assertFalse(policy.check(r, self.cbom)["ok"])


if __name__ == "__main__":
    unittest.main()
