"""The image must identify itself and ship /licenses (Red Hat preflight: HasRequiredLabel,
HasNoProhibitedLabels, HasLicense)."""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ContainerLabels(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, "Containerfile")) as f:
            src = f.read()
        # Only the final stage ships.
        self.final = src[src.rindex("\nFROM "):]

    def test_required_labels_set_in_final_stage(self):
        for key in ("name", "vendor", "maintainer", "version", "release", "summary", "description"):
            self.assertRegex(self.final, r'(?m)^\s*(LABEL\s+)?%s="[^"]+"' % key, key)

    def test_labels_do_not_name_red_hat(self):
        for key in ("name", "vendor", "maintainer"):
            m = re.search(r'(?m)^\s*(?:LABEL\s+)?%s="([^"]+)"' % key, self.final)
            self.assertIsNotNone(m, key)
            self.assertNotRegex(m.group(1).lower(), r"red ?hat|rhel", key)

    def test_licenses_directory_populated(self):
        self.assertIn("/licenses/fedlin-pqc-toolkit.LICENSE", self.final)
        for d in os.listdir(os.path.join(ROOT, "third_party")):
            self.assertTrue(os.path.isfile(os.path.join(ROOT, "third_party", d, "LICENSE")), d)

    def test_project_licence_present(self):
        # Source tree keeps it in public/; the exported public tree has it at the root.
        self.assertTrue(any(os.path.isfile(os.path.join(ROOT, p)) for p in ("LICENSE", "public/LICENSE")))

    def test_notice_shipped(self):
        # Apache-2.0 4(d): redistributions keep the NOTICE; the image carries it next to the licence
        self.assertIn("/licenses/fedlin-pqc-toolkit.NOTICE", self.final)
        self.assertTrue(any(os.path.isfile(os.path.join(ROOT, p)) for p in ("NOTICE", "public/NOTICE")))

    def test_trademark_policy_present(self):
        path = next((os.path.join(ROOT, p) for p in ("TRADEMARKS.md", "public/TRADEMARKS.md")
                     if os.path.isfile(os.path.join(ROOT, p))), None)
        self.assertIsNotNone(path)
        with open(path) as f:
            self.assertIn("performed, reviewed, approved, certified or endorsed", f.read())

    def test_bundled_musl_licence_vendored(self):
        # The kex probe ships musl's loader; MIT requires its notice alongside.
        self.assertIn("ld-musl", self.final)
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "third_party", "musl", "LICENSE")))

    def test_release_passes_version_build_arg(self):
        with open(os.path.join(ROOT, ".github", "workflows", "release.yml")) as f:
            wf = f.read()
        self.assertRegex(wf, r"build-args:\s*\|\s*\n\s*VERSION=\$\{\{ steps\.v\.outputs\.version \}\}")

    def test_runs_as_non_root(self):
        users = re.findall(r"(?m)^USER\s+(\S+)", self.final)
        self.assertTrue(users and users[-1] not in ("0", "root"), users)


if __name__ == "__main__":
    unittest.main()
