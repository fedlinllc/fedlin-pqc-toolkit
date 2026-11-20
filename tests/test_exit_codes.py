"""Exit codes promised in STABILITY.md: invalid input is 2, never an empty CBOM with 0. Offline."""
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PIPE = os.path.join(ROOT, "scripts", "tier2_pipeline.py")


def run(*args):
    with tempfile.TemporaryDirectory() as d:
        p = subprocess.run([sys.executable, "-I", PIPE, "--out", os.path.join(d, "cbom.json"), *args],
                           capture_output=True, text=True, timeout=120)
        return p.returncode, p.stderr, os.path.exists(os.path.join(d, "cbom.json"))


class ExitCodes(unittest.TestCase):
    def test_invalid_input_is_2(self):
        for args in (["--no-runtime", "--endpoints", "a;b,$(id).com"],
                     ["--no-runtime", "--merge-cbom", "/nonexistent/x.json"],
                     ["--no-runtime", "--repo", "/nonexistent/repo"],
                     ["--no-runtime", "--theia-dir", "/nonexistent/dir"]):
            rc, err, wrote = run(*args)
            self.assertEqual(rc, 2, (args, err[-300:]))
            self.assertIn("[error]", err)
            self.assertFalse(wrote, args)

    def test_nothing_reachable_is_2(self):
        # 1.5.0: a run whose only source produced nothing exits 2 and writes no CBOM (it used to exit 0)
        rc, err, wrote = run("--no-runtime", "--endpoints", "127.0.0.1:1", "--no-enumerate", "--no-classical-probe")
        self.assertEqual(rc, 2, err[-300:])
        self.assertIn("none of the 1 endpoint(s)", err)
        self.assertFalse(wrote)

    def test_missing_hosts_file_is_2(self):
        for v in ("hosts.txt", "./hosts", "lists/hosts", "example.com,missing.csv"):
            rc, err, wrote = run("--no-runtime", "--endpoints", v)
            self.assertEqual(rc, 2, (v, err[-300:]))
            self.assertIn("no such file", err)
            self.assertFalse(wrote, v)

    def test_missing_tool_is_2(self):
        with tempfile.TemporaryDirectory() as d:
            cbom = os.path.join(d, "in.json")
            with open(cbom, "w") as f:
                f.write('{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}')
            for args in (["--repo", d, "--cdxgen", "/nonexistent/cdxgen"],
                         ["--theia-dir", d, "--theia", "/nonexistent/theia"],
                         ["--merge-cbom", cbom, "--cyclonedx", "/nonexistent/cyclonedx"]):
                rc, err, wrote = run("--no-runtime", *args)
                self.assertEqual(rc, 2, (args, err[-300:]))
                self.assertIn("run ./setup.sh", err)
                self.assertFalse(wrote, args)

    def test_failed_merge_is_2(self):
        with tempfile.TemporaryDirectory() as d:
            tool = os.path.join(d, "cyclonedx")
            with open(tool, "w") as f:
                f.write("#!/bin/sh\nexit 1\n")
            os.chmod(tool, 0o755)
            cbom = os.path.join(d, "in.json")
            with open(cbom, "w") as f:
                f.write('{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}')
            rc, err, wrote = run("--no-runtime", "--merge-cbom", cbom, "--cyclonedx", tool)
            self.assertEqual(rc, 2, err[-300:])
            self.assertIn("could not be merged", err)
            self.assertFalse(wrote)

    def test_endpoint_file_detection(self):
        sys.path.insert(0, os.path.join(ROOT, "scripts"))
        import tier2_pipeline as t
        self.assertEqual(t.missing_endpoint_files(
            ["host.txt", "example.com", "https://example.com/robots.txt", "example.com/a.txt", "lists/hosts",
             "./h", "a.com, b.csv", "10.0.0.1:443", "[::1]:443"]),
            ["host.txt", "lists/hosts", "./h", "b.csv"])

    def test_bad_flag_is_2(self):
        self.assertEqual(run("--no-such-flag")[0], 2)

    def test_version_is_0(self):
        p = subprocess.run([sys.executable, "-I", PIPE, "--version"], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0)


if __name__ == "__main__":
    unittest.main()


class FailOn(unittest.TestCase):
    """--fail-on (1.7.0): exit 3 when the scan finds a listed status; exit 2 stays "the scan failed"."""

    def setUp(self):
        sys.path.insert(0, os.path.join(ROOT, "scripts"))
        import tier2_pipeline as t
        self.t = t

    def test_unknown_status_is_2(self):
        rc, err, wrote = run("--no-runtime", "--endpoints", "example.com", "--fail-on", "vulnerabel")
        self.assertEqual(rc, 2)
        self.assertIn("unknown status vulnerabel", err)
        self.assertFalse(wrote)

    def test_hits(self):
        res = {"findings": [{"status": "broken"}, {"status": "vulnerable"}, {"status": "compliant"},
                            {"status": "unclassified"}]}
        tls = {"type": "cryptographic-asset", "name": "a.example:443",
               "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"type": "tls"}},
               "properties": [{"name": "pkic:profile:disclosure:keyExchange", "value": "unknown"}]}
        bom = {"components": [tls]}
        h = self.t.fail_on_hits
        self.assertEqual(h(res, bom, set()), {})
        self.assertEqual(h(res, bom, {"vulnerable"}), {"vulnerable": 2})      # includes broken
        self.assertEqual(h(res, bom, {"broken", "transitional"}), {"broken": 1})
        self.assertEqual(h(res, bom, {"unclassified"}), {"unclassified": 1})
        self.assertEqual(h({"findings": []}, {"components": []}, {"incomplete"}), {})
        self.assertEqual(self.t._fail_on_arg("Vulnerable, INCOMPLETE"), {"vulnerable", "incomplete"})
        self.assertEqual(self.t.EXIT_FAIL_ON, 3)


class ProbeRetry(unittest.TestCase):
    """A dropped handshake is retried once before the endpoint is recorded as not observed (1.7.0)."""

    def test_host_probe_retries_once(self):
        sys.path.insert(0, os.path.join(ROOT, "scripts"))
        import tier2_pipeline as t
        calls = []
        ok = ("CONNECTED(00000003)\n---\nNegotiated TLS1.3 group: X25519MLKEM768\n"
              "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n")

        def fake(cmd, *a, **k):
            calls.append(cmd)
            return "" if len(calls) == 1 else ok
        orig = t.run
        t.run = fake
        try:
            grp, via, complete = t._probe_kex_group("example.com", 443)
        finally:
            t.run = orig
        self.assertEqual(len(calls), 2)
        self.assertEqual((via, complete), ("host", True))
        self.assertTrue(grp and "MLKEM" in grp.upper(), grp)


class BadJsonEverywhere(unittest.TestCase):
    """1.7.0: deeply nested or wrongly shaped JSON exits 2 with [error] in every script, never a traceback."""

    def test_scripts(self):
        with tempfile.TemporaryDirectory() as d:
            deep, lst = os.path.join(d, "deep.json"), os.path.join(d, "list.json")
            with open(deep, "w") as f:
                f.write("[" * 100000 + "]" * 100000)
            with open(lst, "w") as f:
                f.write('[{"bomFormat": "CycloneDX"}]')
            ctx = os.path.join(d, "ctx.json")
            with open(ctx, "w") as f:
                f.write('{"schema": "fedlin.pqc-context", "schemaVersion": "1.0", "systems": '
                        '[{"name": "a", "impact": "low", "endpoints": ["x"]}]}')
            wv = os.path.join(d, "w.json")
            with open(wv, "w") as f:
                f.write('{"schema": "fedlin.pqc-wave", "schemaVersion": "1.0", "wave": "w", '
                        '"items": [{"id": "a", "endpoint": "x", "check": "mlkem"}]}')
            S = lambda n: os.path.join(ROOT, "scripts", n)  # noqa: E731
            for bad in (deep, lst):
                for cmd in ([S("report.py"), "--cbom", bad, "--out", os.path.join(d, "r.md")],
                            [S("policy.py"), "evaluate", "--cbom", bad, "--out", os.path.join(d, "p.json")],
                            [S("wave_draft.py"), "--cbom", bad, "--wave", "1", "--out", os.path.join(d, "w2.json")],
                            [S("wave.py"), "check", "--wave", wv, "--cbom", bad],
                            [S("wave.py"), "check", "--wave", bad, "--cbom", lst],
                            [S("context.py"), "rank", "--context", ctx, "--cbom", bad],
                            [S("context.py"), "rank", "--context", bad, "--cbom", lst]):
                    if not os.path.exists(cmd[0]):      # wave_draft.py is private: absent from the public tree
                        continue
                    p = subprocess.run([sys.executable, "-I", *cmd], capture_output=True, text=True, timeout=120)
                    self.assertEqual(p.returncode, 2, (cmd, p.stderr[-300:]))
                    self.assertIn("[error]", p.stderr, cmd)
                    self.assertNotIn("Traceback", p.stderr, cmd)
                    self.assertNotIn("changed after its policy result", p.stderr, cmd)
