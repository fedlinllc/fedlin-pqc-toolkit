"""Tests for the policy stage (scripts/policy.py): facts-only CBOM, digest binding, result format.

Run:  python3 -m unittest discover -s tests -v
"""

import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import policy  # noqa: E402
import tier2_pipeline as tp  # noqa: E402

# Required keys and constants of pkic.cbom.policy-result 0.1
# (github.com/pkic/cbom docs/methodology/policy-result.schema.json, MIT).
PKIC_REQUIRED = ["resultFormat", "resultFormatVersion", "policy", "evaluationDate", "documents",
                 "findings", "notAsserted"]


def facts_cbom(tmp):
    b = tp.CBOM("test", "1", {})
    b.add_certificate({"host": "a.example", "subject": "a", "issuer": "CA", "key_alg": "id-ecPublicKey",
                       "key_bits": 256, "sig_alg": "ecdsa-with-SHA256"})
    b.add_tls_kex("a.example", "X25519MLKEM768", "TLSv1.3", "TLS_AES_256_GCM_SHA384")
    b.add_sealed_secrets(3)
    path = os.path.join(tmp, "cbom.json")
    with open(path, "w") as f:
        json.dump(b.to_dict(), f, indent=2)
    return path


class Policy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = facts_cbom(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_cbom_has_no_verdicts(self):
        with open(self.path) as f:
            bom = json.load(f)
        self.assertFalse(policy.has_verdicts(bom))
        names = {p["name"] for c in bom["components"] for p in c.get("properties", [])}
        self.assertFalse(any(n.startswith(("cnsa2:", "crosswalk:")) for n in names), names)
        self.assertIn("fedlin:canonical", names)  # identity is a fact and stays

    def test_result_matches_pkic_format(self):
        r = policy.evaluate(self.path, profile="civilian", date="2026-11-14")
        for k in PKIC_REQUIRED:
            self.assertIn(k, r)
        self.assertEqual(r["resultFormat"], "pkic.cbom.policy-result")
        for k in ("policyId", "version", "digest"):
            self.assertIn(k, r["policy"])
        self.assertEqual(r["evaluationDate"], "2026-11-14")
        self.assertGreaterEqual(len(r["documents"]), 1)
        for d in r["documents"]:
            self.assertEqual(set(d["digest"]), {"alg", "value"})
        self.assertGreaterEqual(len(r["notAsserted"]), 1)
        self.assertIn("IR8547", r["policy"]["sources"])

    def test_digest_binds_the_cbom(self):
        r = policy.evaluate(self.path)
        self.assertTrue(policy.verify(r, self.path))
        with open(self.path, "a") as f:
            f.write(" ")  # any change to the bytes breaks the binding
        self.assertFalse(policy.verify(r, self.path))
        with open(self.path) as f:
            bom = json.load(f)
        with self.assertRaises(policy.DigestMismatch):
            policy.apply(bom, r, self.path)

    def test_profile_is_recorded_and_changes_compliance(self):
        civ = policy.evaluate(self.path, profile="civilian")
        nss = policy.evaluate(self.path, profile="nss")
        self.assertEqual(civ["policy"]["policyId"], "fedlin.pqc-ruleset.civilian")
        self.assertEqual(nss["policy"]["policyId"], "fedlin.pqc-ruleset.nss")
        hybrid = lambda r: next(f for f in r["findings"] if f["name"] == "X25519MLKEM768")  # noqa: E731
        self.assertEqual(hybrid(civ)["status"], "compliant")
        self.assertEqual(hybrid(nss)["status"], "transitional")

    def test_hndl_material_rule(self):
        r = policy.evaluate(self.path)
        f = next(x for x in r["findings"] if x.get("lane") == "hndl")
        self.assertEqual(f["priority"], "Critical")  # sealing key is RSA: quantum-vulnerable

    def test_view_carries_verdicts_without_touching_disk(self):
        before = pathlib.Path(self.path).read_bytes()
        view, r = policy.load_view(self.path, profile="civilian")
        self.assertTrue(policy.has_verdicts(view))
        self.assertEqual(pathlib.Path(self.path).read_bytes(), before)

    def test_legacy_inline_verdicts_are_stripped(self):
        with open(self.path) as f:
            bom = json.load(f)
        bom["components"][0].setdefault("properties", []).append({"name": "cnsa2:priority", "value": "High"})
        self.assertEqual(policy.strip_verdicts(bom), 1)
        self.assertFalse(policy.has_verdicts(bom))


if __name__ == "__main__":
    unittest.main()
