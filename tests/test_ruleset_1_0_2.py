"""Regressions for ruleset 1.0.2 and the input-handling fixes (2026-11-15)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import cnsa20_ruleset as cnsa  # noqa: E402
import tier2_pipeline as tp  # noqa: E402


class Notes(unittest.TestCase):
    def test_hmac_sha1_cites_rev3_draft_and_2030(self):
        r = cnsa.classify("hmac-sha1", profile="civilian")
        self.assertIn("SP800-131A-R3-IPD", r["cite"])
        self.assertIn("2030", r["note"])

    def test_chacha20_note_says_not_fips_approved(self):
        self.assertIn("not a FIPS-approved", cnsa.classify("chacha20-poly1305", profile="civilian")["note"])

    def test_every_cited_source_exists(self):
        for cid, a in cnsa.ALGORITHMS.items():
            for key in a["cite"]:
                self.assertIn(key, cnsa.SOURCES, f"{cid} cites unknown source {key}")


class RepoArgumentIsData(unittest.TestCase):
    def test_cdxgen_gets_argv_not_shell(self):
        with tempfile.TemporaryDirectory() as d:
            evil = os.path.join(d, 'x"; touch PWNED; "')
            os.mkdir(evil)
            with mock.patch.object(tp.subprocess, "run") as r:
                tp.generate_deps_sbom(evil, "cdxgen", os.path.join(d, "o.json"))
            argv = r.call_args[0][0]
            self.assertIsInstance(argv, list)
            self.assertEqual(argv[-1], os.path.abspath(evil))
            self.assertNotIn("shell", r.call_args[1])

    def test_missing_repo_is_skipped(self):
        with mock.patch.object(tp.subprocess, "run") as r:
            self.assertFalse(tp.generate_deps_sbom("/nonexistent/repo", "cdxgen", "/dev/null"))
        r.assert_not_called()


class KubeInputs(unittest.TestCase):
    def test_kube_cli_rejects_shell_text(self):
        self.assertFalse(tp._CLI_RE.match("oc; rm -rf /"))
        self.assertFalse(tp._CLI_RE.match("$(id)"))
        self.assertTrue(tp._CLI_RE.match("/usr/local/bin/kubectl"))

    def test_node_name_from_cluster_is_validated(self):
        with mock.patch.object(tp, "run", return_value="node1;id"):
            self.assertEqual(tp.capture_fips("oc", "openshift"), "unknown")


class Redaction(unittest.TestCase):
    def test_redact_removes_intermediates_and_keeps_valid_json(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "cbom.json")
            p = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "tier2_pipeline.py"),
                                "--no-runtime", "--merge-cbom", os.path.join(d, "none.json"),
                                "--name", "corp.internal", "--redact", "corp.internal=example.gov",
                                "--out", out], capture_output=True, text=True, timeout=120)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertFalse(os.path.exists(out + ".runtime.json"))
            with open(out) as f:
                text = f.read()
            json.loads(text)
            self.assertNotIn("corp.internal", text)

    def test_redact_that_breaks_json_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "cbom.json")
            p = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "tier2_pipeline.py"),
                                "--no-runtime", "--merge-cbom", os.path.join(d, "none.json"),
                                "--name", "corp", "--redact", 'corp=a"b', "--out", out],
                               capture_output=True, text=True, timeout=120)
            self.assertEqual(p.returncode, 2)
            self.assertIn("invalid JSON", p.stderr)


if __name__ == "__main__":
    unittest.main()
