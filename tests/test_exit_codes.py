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

    def test_bad_flag_is_2(self):
        self.assertEqual(run("--no-such-flag")[0], 2)

    def test_version_is_0(self):
        p = subprocess.run([sys.executable, "-I", PIPE, "--version"], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0)


if __name__ == "__main__":
    unittest.main()
