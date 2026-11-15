"""The toolkit version is stated once in code and must agree with toolkit.lock and CHANGELOG.md."""
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import tier2_pipeline as tp  # noqa: E402

SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")


class Version(unittest.TestCase):
    def test_semver(self):
        self.assertRegex(tp.TOOLKIT_VERSION, SEMVER)

    def test_lock_header_matches(self):
        with open(os.path.join(ROOT, "toolkit.lock")) as f:
            self.assertIn(f"(v{tp.TOOLKIT_VERSION})", f.readline())

    def test_changelog_top_release_matches(self):
        with open(os.path.join(ROOT, "CHANGELOG.md")) as f:
            text = f.read()
        releases = re.findall(r"^## \[(\d+\.\d+\.\d+[^\]]*)\] - \d{4}-\d{2}-\d{2}$", text, re.M)
        self.assertTrue(releases, "no dated releases in CHANGELOG.md")
        self.assertEqual(releases[0], tp.TOOLKIT_VERSION)
        self.assertIn(f"[{tp.TOOLKIT_VERSION}]: ", text)

    def test_cbom_stamps_toolkit_version(self):
        tools = tp.CBOM("example.com", "", {}).to_dict()["metadata"]["tools"]["components"]
        self.assertEqual(tools[0]["version"], tp.TOOLKIT_VERSION)


if __name__ == "__main__":
    unittest.main()
