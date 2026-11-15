"""Regression tests for the 2026-11-15 fresh-clone setup run."""
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))


class SetupScript(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, "setup.sh")) as f:
            self.src = f.read()

    def test_setup_is_executable_in_git(self):
        # The README runs ./setup.sh; the git mode must carry the executable bit.
        try:
            out = subprocess.run(["git", "-C", ROOT, "ls-files", "-s", "setup.sh"],
                                 capture_output=True, text=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("not a git checkout")
        if not out:
            self.skipTest("setup.sh not tracked here")
        self.assertTrue(out.startswith("100755"), out)

    def test_no_global_installs(self):
        # corepack enable and npm -g need root on most hosts and aborted setup.
        self.assertNotRegex(self.src, r"(?m)^[^#]*corepack enable")
        self.assertNotRegex(self.src, r"(?m)^[^#]*npm install -g")

    def test_theia_built_in_pinned_image(self):
        # Upstream's Dockerfile pulls unpinned golang/alpine; build in our digest-pinned image instead.
        self.assertNotRegex(self.src, r"(?m)^[^#]*podman build[^\n]*theia")
        m = re.search(r"GO_IMAGE=(\S+)", self.src)
        self.assertIsNotNone(m)
        self.assertIn("@sha256:", m.group(1))
        with open(os.path.join(ROOT, "Containerfile")) as f:
            self.assertIn(m.group(1), f.read())


class GradeWording(unittest.TestCase):
    def test_grade_text_avoids_classified(self):
        import report
        for score in (None, 95, 75, 50, 20, 5):
            self.assertNotIn("classified", report.grade(score)[1])


if __name__ == "__main__":
    unittest.main()
