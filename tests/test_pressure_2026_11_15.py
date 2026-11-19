"""Regressions from the 2026-11-15 adversarial review of the public tree (ruleset 1.0.1)."""

import json
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import cnsa20_ruleset as cnsa  # noqa: E402
import policy  # noqa: E402
import report  # noqa: E402
import tier2_pipeline as tp  # noqa: E402


def view(build):
    b = tp.CBOM("test", "1", {})
    build(b)
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "cbom.json")
        with open(path, "w") as f:
            json.dump(b.to_dict(), f)
        return policy.load_view(path)[0]


def cert(host):
    return {"host": host, "subject": host, "issuer": "CA", "key_alg": "id-ecPublicKey", "key_bits": 256,
            "sig_alg": "ecdsa-with-SHA256"}


class SshMlkemHybrids(unittest.TestCase):
    def test_nist_curve_hybrids_are_quantum_resistant(self):
        v = cnsa.classify("mlkem1024nistp384-sha384", profile="nss")
        self.assertIs(v["quantum_vulnerable"], False)
        self.assertTrue(v["cnsa_target"].startswith("None"))     # the CNSA 2.0 target itself
        v = cnsa.classify("mlkem768nistp256-sha256", profile="civilian")
        self.assertIs(v["quantum_vulnerable"], False)
        self.assertTrue(v["cnsa_target"].startswith("None"))

    def test_x448_hybrid_named_as_hybrid(self):
        self.assertEqual(cnsa.classify("X448MLKEM1024")["canonical"], "x448mlkem1024")

    def test_unknown_hybrid_judged_by_mlkem_component(self):
        v = cnsa.classify("mlkem768secp256r1-sha256")
        self.assertIs(v["quantum_vulnerable"], False)


class StaticRsaSuites(unittest.TestCase):
    def test_openssl_static_rsa_suites_are_vulnerable(self):
        for name in ("AES256-SHA", "AES128-GCM-SHA256", "AES256-SHA256", "CAMELLIA256-SHA"):
            v = cnsa.classify(name)
            self.assertIs(v["quantum_vulnerable"], True, name)
            self.assertEqual(v["lane"], "key-establishment", name)
            self.assertIn("forward secrecy", v["note"], name)

    def test_des_cbc3_is_3des(self):
        self.assertEqual(cnsa.classify("DES-CBC3-SHA")["canonical"], "3des")

    def test_forward_secret_and_tls13_unchanged(self):
        self.assertEqual(cnsa.classify("ECDHE-RSA-AES256-GCM-SHA384")["canonical"], "ecdh")
        self.assertIs(cnsa.classify("TLS_AES_256_GCM_SHA384")["quantum_vulnerable"], False)
        self.assertEqual(cnsa.classify("aes256-gcm@openssh.com")["canonical"], "aes-256")

    def test_static_rsa_session_records_rsa_key_exchange(self):
        bom = view(lambda b: b.add_tls_kex("old.example", None, "TLSv1.2", "AES256-SHA"))
        iface = next(c for c in bom["components"] if c["bom-ref"].startswith("crypto/proto/tls/"))
        props = {p["name"]: p["value"] for p in iface["properties"]}
        self.assertEqual(props.get("pkic:profile:keyExchange"), "RSA")
        self.assertEqual(report.score_summary(bom)["kex_unobserved"], [])


class IncompleteEvidence(unittest.TestCase):
    def test_unobserved_kex_withholds_grade(self):
        bom = view(lambda b: (b.add_certificate(cert("a.example")),
                              b.add_tls_kex("a.example", None, "TLSv1.3", "TLS_AES_256_GCM_SHA384")))
        md, summary = report.build_report(bom)
        self.assertTrue(summary["incomplete"])
        self.assertIsNone(summary["grade"])
        self.assertEqual(summary["kex_unobserved"], 1)
        self.assertIn("Incomplete: key exchange not observed on 1 of 1", md)
        self.assertNotIn("almost entirely quantum-vulnerable", md)

    def test_observed_kex_keeps_grade(self):
        bom = view(lambda b: (b.add_certificate(cert("a.example")),
                              b.add_tls_kex("a.example", "X25519MLKEM768", "TLSv1.3", "TLS_AES_256_GCM_SHA384")))
        _, summary = report.build_report(bom)
        self.assertFalse(summary["incomplete"])


class ReportText(unittest.TestCase):
    def setUp(self):
        bom = view(lambda b: (b.add_certificate(cert("a.example")),
                              b.add_tls_kex("a.example", "X25519MLKEM768", "TLSv1.3", "TLS_AES_256_GCM_SHA384")))
        self.md, _ = report.build_report(bom)

    def test_no_unsupported_regulatory_claims(self):
        self.assertNotIn("supersedes M-23-02", self.md)
        self.assertNotIn("schema-validated", self.md)
        self.assertNotRegex(self.md, r"CNSA 2\.0[^\n]*SLH-DSA")
        self.assertNotRegex(self.md, r"\*\*NSM-10\*\*: PQC for key establishment")

    def test_no_roadmap_promise_without_roadmap(self):
        if report._roadmap is None:
            self.assertNotIn("roadmap below", self.md)


if __name__ == "__main__":
    unittest.main()
