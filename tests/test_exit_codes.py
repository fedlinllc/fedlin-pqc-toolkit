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
