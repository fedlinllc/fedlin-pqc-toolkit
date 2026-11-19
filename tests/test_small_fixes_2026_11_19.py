"""Smaller findings of the 2026-11-19 newcomer pressure test (1.5.0). Offline."""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
PIPE = os.path.join(ROOT, "scripts", "tier2_pipeline.py")

import cnsa20_ruleset as cnsa  # noqa: E402
import mcp_server as ms  # noqa: E402
import report  # noqa: E402
import tier2_pipeline as tp  # noqa: E402
import wave  # noqa: E402


class Endpoints(unittest.TestCase):
    def test_bare_ipv6_is_accepted(self):
        self.assertEqual(tp.parse_endpoints(["2001:db8::1"]), ["[2001:db8::1]"])

    def test_port_must_be_in_range(self):
        for bad in ("example.com:0", "example.com:65536", "example.com:99999", "example.com:abc", "[::1]:70000"):
            self.assertEqual(tp.parse_endpoints([bad]), [], bad)
        self.assertEqual(tp.parse_endpoints(["example.com:8443"]), ["example.com:8443"])


class Cli(unittest.TestCase):
    def run_pipe(self, *args):
        with tempfile.TemporaryDirectory() as d:
            p = subprocess.run([sys.executable, "-I", PIPE, "--out", os.path.join(d, "c.json"), *args],
                               capture_output=True, text=True, timeout=120, env=dict(os.environ, KUBECONFIG="/dev/null"))
            return p.returncode, p.stderr

    def test_unknown_regime_is_refused(self):
        rc, err = self.run_pipe("--endpoints", "example.com", "--regime", "fedramp")
        self.assertEqual(rc, 2)
        self.assertIn("invalid choice", err)

    def test_regime_case_does_not_matter(self):
        rc, err = self.run_pipe("--endpoints", "127.0.0.1:1", "--regime", "fisma", "--no-enumerate",
                                "--no-classical-probe")
        self.assertNotIn("invalid choice", err)


class Text(unittest.TestCase):
    def test_bidi_and_invisible_characters_removed(self):
        for f in (report.md_text, wave.md_text):
            self.assertEqual(f("A‮B​C⁦D﻿E"), "ABCDE")


class Ruleset(unittest.TestCase):
    def test_transport_suites_cite_sc8_not_sc28(self):
        for n in ("TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "ECDHE-RSA-AES256-GCM-SHA384",
                  "aes256-gcm@openssh.com"):
            c = cnsa.classify(n)["controls"]
            self.assertIn("SC-8", c, n)
            self.assertNotIn("SC-28", c, n)
        self.assertIn("SC-28", cnsa.classify("AES-256-GCM")["controls"])   # a bare cipher keeps it


class Mcp(unittest.TestCase):
    def test_deeply_nested_request_is_a_parse_error(self):
        with tempfile.TemporaryDirectory() as d:
            out = io.StringIO()
            deep = '{"jsonrpc":"2.0","id":1,"method":"ping","params":' + "[" * 100000 + "]" * 100000 + "}\n"
            ms.Server(d).serve(io.StringIO(deep + '{"jsonrpc":"2.0","id":2,"method":"ping"}\n'), out)
            lines = [json.loads(x) for x in out.getvalue().splitlines()]
            self.assertEqual(lines[0]["error"]["code"], -32700)
            self.assertEqual(lines[1]["id"], 2)                          # the server kept going


if __name__ == "__main__":
    unittest.main()
