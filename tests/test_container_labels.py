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
        # Two images ship (ADR-066): the default target "certified" is the core stage unchanged; "probe" adds the
        # Alpine key-exchange probe. Labels and /licenses come from the core stage.
        self.src = src
        self.default_target = src[src.rindex("\nFROM "):].strip()
        start = src.index("\nFROM registry.access.redhat.com/ubi9/")
        self.final = src[start:src.index("\n# --- probe image")]
        self.probe = src[src.index("\nFROM core AS probe"):src.rindex("\nFROM ")]

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

    def test_certified_image_has_no_probe(self):
        # ADR-066: the certified (default) image carries Red Hat crypto only
        self.assertEqual(self.default_target, "FROM core AS certified")
        for x in ("kexprobe", "kex-probe", "ld-musl", "FEDLIN_KEX_PROBE_OPENSSL", "alpine"):
            self.assertNotIn(x, self.final.lower() if x == "alpine" else self.final, x)

    def test_probe_image_carries_probe_musl_licence_and_its_own_name(self):
        # The probe image ships musl's loader; MIT requires its notice alongside.
        self.assertIn("ld-musl", self.probe)
        self.assertIn("/licenses/third_party-musl.LICENSE", self.probe)
        self.assertIn('name="fedlin-pqc-toolkit-probe"', self.probe)
        self.assertIn("ENV FEDLIN_KEX_PROBE_OPENSSL=", self.probe)
        self.assertRegex(self.probe, r"(?m)^USER 1001\s*$")
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "third_party", "musl", "LICENSE")))

    def test_release_builds_and_attests_both_images(self):
        with open(os.path.join(ROOT, ".github", "workflows", "release.yml")) as f:
            wf = f.read()
        self.assertIn("target: probe", wf)
        self.assertIn("${{ env.IMAGE }}-probe", wf)
        self.assertEqual(wf.count("actions/attest-build-provenance@"), 3)   # files, image, probe image

    def test_release_passes_version_build_arg(self):
        with open(os.path.join(ROOT, ".github", "workflows", "release.yml")) as f:
            wf = f.read()
        self.assertRegex(wf, r"build-args:\s*\|\s*\n\s*VERSION=\$\{\{ steps\.v\.outputs\.version \}\}")

    def test_runs_as_non_root(self):
        users = re.findall(r"(?m)^USER\s+(\S+)", self.final)
        self.assertTrue(users and users[-1] not in ("0", "root"), users)


if __name__ == "__main__":
    unittest.main()
