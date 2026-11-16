"""Regressions from the 2026-11-15 competitive benchmark (report correctness). Offline."""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import policy  # noqa: E402
import report  # noqa: E402
import tier2_pipeline as tp  # noqa: E402


def build(d):
    b = tp.CBOM("bench", "1", {})
    b.add_certificate({"host": "old.example.com", "subject": "old", "issuer": "CA", "key_alg": "rsaEncryption",
                       "key_bits": 2048, "sig_alg": "sha256WithRSAEncryption",
                       "not_before": "2015-04-09T00:00:00Z", "not_after": "2015-04-12T23:59:59Z"})
    b.add_tls_kex("old.example.com", "secp256r1", "TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256")
    b.add_tls_kex("pq.example.com", "X25519MLKEM768", "TLSv1.3", "TLS_AES_256_GCM_SHA384")
    p = os.path.join(d, "cbom.json")
    with open(p, "w") as f:
        json.dump(b.to_dict(), f)
    view, _ = policy.load_view(p, profile="civilian")
    return report.build_report(view)


class Benchmark(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.md, self.summary = build(self.t.name)

    def tearDown(self):
        self.t.cleanup()

    def test_expired_certificate_is_flagged(self):
        self.assertIn("already expired", self.md)
        self.assertIn("days ago**: replace now", self.md)
        self.assertNotIn("compliant through 2029 caps", self.md.split("old.example.com", 1)[-1].split("\n", 1)[0])

    def test_classical_key_exchange_counts_as_hndl(self):
        self.assertEqual(self.summary["hndl_exposures"], 1)  # the ECDHE endpoint, not the ML-KEM hybrid one

    def test_rsa_certificate_signature_is_a_signature(self):
        v = policy.evaluate(os.path.join(self.t.name, "cbom.json"))
        sig = [f for f in v["findings"] if f["name"] and "WithRSA" in f["name"]]
        self.assertTrue(sig)
        self.assertTrue(all(f["lane"] == "signature" for f in sig))


if __name__ == "__main__":
    unittest.main()
