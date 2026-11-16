"""Verdict table: the ruleset as data for hosted scanners. Offline."""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import cnsa20_ruleset as cnsa  # noqa: E402
import policy  # noqa: E402
import verdict_table as vt  # noqa: E402

# What fedlin.com's scanner reports today (src/pages/api/pqc-scan.ts): hybrid groups, classical groups and
# certificate key types with sizes. Every one must resolve, never fall to "unknown".
HOSTED = [("X25519MLKEM768", None), ("SecP256r1MLKEM768", None), ("SecP384r1MLKEM1024", None),
          ("X25519", None), ("P-256", None), ("P-384", None), ("prime256v1", None), ("secp384r1", None),
          ("secp521r1", None), ("X448", None), ("RSA", 2048), ("RSA", 3072), ("RSA", 4096), ("EC", 256),
          ("EC", 384), ("DH", 2048), ("TLSv1.2", None), ("TLSv1.3", None), ("RSA", None), ("EC", None)]


class VerdictTable(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = vt.build()

    def test_deterministic(self):
        self.assertEqual(vt.dumps(self.t), vt.dumps(vt.build()))

    def test_identity(self):
        self.assertEqual((self.t["schema"], self.t["schemaVersion"]), ("fedlin.pqc-verdict-table", "1.0"))
        self.assertEqual(self.t["ruleset"]["version"], cnsa.RULESET_VERSION)
        self.assertEqual(self.t["ruleset"]["digest"]["value"], policy._ruleset_digest())

    def test_every_key_matches_the_policy_stage(self):
        # the table must give exactly what a toolkit run gives for the same name, bits and profile
        for name, bits in vt._inputs():
            if bits is None and vt.key(name) in self.t["bands"]:
                continue  # size-dependent names are covered by test_bands_match_every_key_size
            entry, _ = vt.lookup(self.t, name, bits, "civilian")
            for profile in cnsa.PROFILES:
                v = cnsa.classify(name, bits, profile=profile)
                if v["canonical"] is None:
                    self.assertIsNone(entry, name)
                    continue
                got = vt.lookup(self.t, name, bits, profile)[1]
                self.assertEqual(got["status"], policy._status(v), (name, bits, profile))
                self.assertEqual(got["target"], v["cnsa_target"], (name, bits, profile))

    def test_hosted_scanner_names_resolve(self):
        for name, bits in HOSTED:
            entry, v = vt.lookup(self.t, name, bits)
            self.assertIsNotNone(entry, (name, bits))

    def test_profiles_differ_where_they_should(self):
        self.assertEqual(vt.lookup(self.t, "X25519MLKEM768")[1]["status"], "compliant")
        self.assertEqual(vt.lookup(self.t, "X25519MLKEM768", profile="nss")[1]["status"], "transitional")
        self.assertEqual(vt.lookup(self.t, "x25519")[1]["status"], "vulnerable")
        self.assertEqual(vt.lookup(self.t, "RSA", 1024)[1]["status"], "broken")

    def test_bands_match_every_key_size(self):
        # the threshold shortcut must equal a scan of every size (pressure test 2026-11-15)
        for name in ("RSA", "ECDSA", "DH", "id-ecPublicKey"):
            for b in range(1, 16385, 1 if name in ("ECDSA", "id-ecPublicKey") else 3):
                for profile in cnsa.PROFILES:
                    v = cnsa.classify(name, b, profile=profile)
                    got = vt.lookup(self.t, name, b, profile)[1]
                    self.assertEqual((got["status"], got["target"]), (policy._status(v), v["cnsa_target"]),
                                     (name, b, profile))

    def test_weak_sizes_are_broken(self):
        for name, bits in (("RSA", 1536), ("DH", 1536), ("ECDSA", 192), ("RSA", 1024)):
            self.assertEqual(vt.lookup(self.t, name, bits)[1]["status"], "broken", (name, bits))

    def test_common_names_resolve(self):
        for n in ("AES-256-GCM", "AES256-GCM", "aes256-gcm@openssh.com", "aes128-ctr", "AES-128-CBC", "HMAC-SHA256",
                  "SHA3-256", "ECDHE-RSA-AES256-GCM-SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "DES-CBC3-SHA",
                  "id-slh-dsa-sha2-128s"):
            self.assertIsNotNone(vt.lookup(self.t, n)[0], n)
        self.assertEqual(vt.lookup(self.t, "DES-CBC3-SHA")[1]["status"], "broken")

    def test_unknown_is_never_guessed(self):
        self.assertEqual(vt.lookup(self.t, "NotAnAlgorithm"), (None, None))
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(vt.main(["lookup", "NotAnAlgorithm"]), 1)
        self.assertIn('"status": "unknown"', out.getvalue())

    def test_schema_shape(self):
        with open(os.path.join(ROOT, "schemas", "verdict-table-1.0.schema.json")) as f:
            s = json.load(f)
        self.assertEqual(set(s["required"]), set(self.t))
        ereq = set(s["properties"]["entries"]["items"]["required"])
        vreq = set(s["properties"]["entries"]["items"]["properties"]["verdicts"]["additionalProperties"]["required"])
        statuses = set(s["properties"]["entries"]["items"]["properties"]["verdicts"]["additionalProperties"]
                       ["properties"]["status"]["enum"])
        ids = {e["id"] for e in self.t["entries"]}
        for e in self.t["entries"]:
            self.assertEqual(set(e), ereq)
            for v in e["verdicts"].values():
                self.assertEqual(set(v), vreq)
                self.assertIn(v["status"], statuses)
        for k, eid in self.t["index"].items():
            self.assertRegex(k, r"^[a-z0-9]+$")
            self.assertIn(eid, ids)
        for k, rows in self.t["bands"].items():
            self.assertEqual(rows[0]["minBits"], 1, k)
            self.assertIsNone(rows[-1]["maxBits"], k)
            for a, b in zip(rows, rows[1:]):
                self.assertEqual(a["maxBits"] + 1, b["minBits"], k)  # contiguous, no gaps or overlaps
            self.assertTrue(all(r["id"] in ids for r in rows), k)


if __name__ == "__main__":
    unittest.main()
