"""CMVP (FIPS 140-3) candidate matching against the vendored snapshot. Offline."""
import datetime
import hashlib
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import cmvp  # noqa: E402
import report  # noqa: E402

TODAY = datetime.date(2026, 11, 15)


def lib(name, version="1.0", group="", purl=""):
    c = {"type": "library", "name": name, "version": version}
    if group:
        c["group"] = group
    if purl:
        c["purl"] = purl
    return c


def os_comp(os_id, ver, fips="true", host="h1"):
    return {"type": "operating-system", "name": f"{os_id} {ver} — {host}",
            "properties": [{"name": "fedlin:hw_class", "value": "os"}, {"name": "fedlin:host", "value": host},
                           {"name": "fedlin:os_id", "value": os_id}, {"name": "fedlin:os_version_id", "value": ver},
                           {"name": "fedlin:fips_enabled", "value": fips}]}


class Snapshot(unittest.TestCase):
    def setUp(self):
        self.snap, self.path = cmvp.load_snapshot()

    def test_snapshot_present_and_pinned_in_lock(self):
        self.assertIsNotNone(self.snap)
        with open(os.path.join(ROOT, "toolkit.lock")) as f:
            lock = f.read()
        m = re.search(r"\[cmvp-snapshot\].*?file\s*=\s*(\S+).*?sha256\s*=\s*([0-9a-f]{64})", lock, re.S)
        self.assertIsNotNone(m)
        self.assertEqual(os.path.join(ROOT, m.group(1)), self.path)
        with open(self.path, "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), m.group(2))

    def test_every_candidate_family_has_certificates(self):
        for fam in cmvp.FAMILIES:
            if fam["kind"] == "candidate":
                self.assertTrue(cmvp.family_certs(self.snap["modules"], fam), fam["id"])

    def test_rhel9_fips_host(self):
        f = cmvp.match({"components": [os_comp("rhel", "9.6")]}, self.snap, TODAY)
        self.assertEqual(len(f), 1)
        certs = [c["cert"] for c in f[0]["certificates"]]
        self.assertIn(5573, certs)
        self.assertTrue(all("Red Hat Enterprise Linux 9" in c["module"] for c in f[0]["certificates"]))
        self.assertIn("FIPS mode true", f[0]["seen"][0])

    def test_unknown_distribution_is_not_matched(self):
        self.assertEqual(cmvp.match({"components": [os_comp("gentoo", "2.17")]}, self.snap, TODAY), [])

    def test_libraries(self):
        bom = {"components": [lib("bc-fips", "2.0.0", group="org.bouncycastle"),
                              lib("cryptography", "44.0.0", purl="pkg:pypi/cryptography@44.0.0"),
                              lib("@noble/curves", "1.9.0")]}
        by = {f["family"]: f for f in cmvp.match(bom, self.snap, TODAY)}
        self.assertTrue(by["bc-fja"]["certificates"])
        self.assertEqual(by["pyca-wheels"]["kind"], "no-module")
        self.assertEqual(by["pure-js"]["kind"], "no-module")

    def test_hsm(self):
        bom = {"components": [{"type": "device", "name": "HSM — h1 (Thales TCT Luna Network HSM)",
                               "properties": [{"name": "fedlin:hw_class", "value": "hsm"}]}]}
        f = cmvp.match(bom, self.snap, TODAY)
        self.assertEqual(f[0]["family"], "hsm-luna")
        self.assertTrue(any("ML-KEM" in c["pqc_approved"] for c in f[0]["certificates"]))

    def test_sunset_certificates_are_dropped(self):
        later = datetime.date(2040, 1, 1)
        f = cmvp.match({"components": [lib("bc-fips", group="org.bouncycastle")]}, self.snap, later)
        self.assertEqual(f[0]["certificates"], [])

    def test_report_wording_never_claims_validated(self):
        f = cmvp.match({"components": [os_comp("rhel", "9.6")]}, self.snap, TODAY)
        text = "\n".join(cmvp.report_lines(f, self.snap))
        self.assertIn("candidate", text)
        self.assertNotRegex(text, r"(?i)\bis validated\b|\bare validated\b|\bFIPS[- ]validated\b")

    def test_endpoint_only_report(self):
        text = "\n".join(cmvp.report_lines([], self.snap))
        self.assertIn("cannot see the server's implementation", text)

    def test_summary_in_report(self):
        md, summary = report.build_report({"components": [], "metadata": {}})
        self.assertIn("## FIPS 140-3 validation (CMVP)", md)
        self.assertEqual(summary["cmvp"]["snapshot"], self.snap["fetched"])


class CollectorsStateFactsOnly(unittest.TestCase):
    """Validation status comes from the dated snapshot in the report, never from text baked into a CBOM."""

    def test_no_certificate_numbers_or_forecasts_in_collectors(self):
        for name in ("collect-hardware-linux.py", "collect-hardware-windows.ps1", "collect-windows.ps1"):
            with open(os.path.join(ROOT, "scripts", name), encoding="utf-8") as f:
                text = f.read()
            self.assertNotRegex(text, r"(?i)CMVP (cert )?#\d{4}", name)
            self.assertNotRegex(text, r"(?i)expected (in )?20\d\d", name)
            self.assertNotRegex(text, r"(?i)FIPS 140-2 validated", name)

    def test_powershell_collectors_are_ascii(self):
        for name in ("collect-hardware-windows.ps1", "collect-windows.ps1"):
            with open(os.path.join(ROOT, "scripts", name), "rb") as f:
                data = f.read()
            if data.startswith(b"\xef\xbb\xbf"):
                continue  # UTF-8 with BOM is read correctly by Windows PowerShell 5.1
            self.assertTrue(all(b < 128 for b in data), f"{name}: non-ASCII without a BOM")


class Parsers(unittest.TestCase):
    def test_list_row(self):
        page = ('<tr id="cert-row-0"><td><a href="/x/certificate/9" id="cert-number-link-0">9</a></td>'
                '<td id="cert-vendor-name-0">ACME &amp; Co</td><td id="cert-module-name-0">ACME  Module</td>'
                '<td id="cert-module-type-0">Software</td><td id="cert-validation-dates-0">01/02/2026<br/></td></tr>')
        self.assertEqual(cmvp._parse_list(page), [{"cert": 9, "vendor": "ACME & Co", "module": "ACME Module",
                                                    "type": "Software", "validated": ["01/02/2026"]}])

    def test_detail(self):
        page = ("<h3>Certificate #9</h3> Details Module Name X Standard FIPS 140-3 Status Active "
                "Sunset Date 1/2/2031 Overall Level 1 Caveat When operated in approved mode. "
                "Security Level Exceptions none Module Type Software Approved Algorithms AES-GCM A1 "
                "ML-KEM KeyGen A1 SHA2-256 A1 Vendor ACME")
        d = cmvp._parse_detail(page)
        self.assertEqual((d["standard"], d["status"], d["sunset"], d["level"]),
                         ("FIPS 140-3", "Active", "1/2/2031", "1"))
        self.assertEqual(d["pqc_approved"], ["ML-KEM"])


if __name__ == "__main__":
    unittest.main()
