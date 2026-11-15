"""Tests for the usage-weighted readiness score (scripts/report.py score_summary).

CBOMs are built with the pipeline's own CBOM builder so weights come from real dependency edges.
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
import report  # noqa: E402
import tier2_pipeline as tp  # noqa: E402


def cert(host, key_alg="id-ecPublicKey", bits=256, sig="ecdsa-with-SHA256"):
    return {"host": host, "subject": host, "issuer": "CA", "key_alg": key_alg, "key_bits": bits, "sig_alg": sig}


def build(profile="civilian", certs=(), sessions=(), ssh=None):
    """Facts-only CBOM from the pipeline builder, then the policy stage's in-memory view."""
    b = tp.CBOM("test", "1", {})
    for c in certs:
        b.add_certificate(c)
    for host, kex, proto, cipher in sessions:
        b.add_tls_kex(host, kex, proto, cipher)
    if ssh:
        b.add_ssh(ssh)
    bom = b.to_dict()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "cbom.json")
        with open(path, "w") as f:
            json.dump(bom, f)
        view, _ = policy.load_view(path, profile=profile)
    return view


class Score(unittest.TestCase):
    def test_usage_weighting(self):
        # 3 certificates on EC keys (6 vulnerable usages: key + signature each) and one PQC
        # key-exchange session (1 compliant usage). Distinct-type counting would give 1/3 = 33.
        bom = build(certs=[cert(f"h{i}.example") for i in range(3)],
                    sessions=[("h0.example", "X25519MLKEM768", "TLSv1.3", "TLS_AES_256_GCM_SHA384")])
        s = report.score_summary(bom)
        self.assertEqual(s["scored"], 7)
        self.assertEqual(s["score"], round(100 * 1 / 7))

    def test_symmetric_and_protocol_do_not_move_score(self):
        # Before the rework TLS 1.3 and AES-256 counted as resistant types and lifted 0 to 50.
        bom = build(certs=[cert("fedlin.example")],
                    sessions=[("fedlin.example", None, "TLSv1.3", "TLS_AES_256_GCM_SHA384")])
        s = report.score_summary(bom)
        self.assertEqual(s["score"], 0)
        self.assertEqual(s["lanes"]["protocol"]["compliant"], 1)
        self.assertEqual(s["lanes"]["symmetric"]["compliant"], 1)

    def test_profile_changes_compliance_not_vulnerability(self):
        sess = [("a.example", "X25519MLKEM768", "TLSv1.3", "TLS_AES_256_GCM_SHA384")]
        civ = report.score_summary(build("civilian", certs=[cert("a.example")], sessions=sess))
        nss = report.score_summary(build("nss", certs=[cert("a.example")], sessions=sess))
        self.assertEqual(civ["score"], round(100 * 1 / 3))     # hybrid ML-KEM-768 compliant (civilian)
        self.assertEqual(nss["score"], 0)                      # below CNSA 2.0 target: transitional
        self.assertEqual(len(nss["transitional"]), 1)
        self.assertEqual(civ["profile"], "civilian")
        self.assertEqual(nss["profile"], "nss")

    def test_broken_public_key_counts_as_vulnerable(self):
        bom = build(certs=[cert("old.example", key_alg="rsaEncryption", bits=1024, sig="sha1WithRSAEncryption")])
        s = report.score_summary(bom)
        self.assertEqual(s["score"], 0)
        self.assertEqual(s["lanes"]["public-key"]["broken"], 1)

    def test_no_public_key_usage_is_not_applicable(self):
        bom = build(sessions=[("x.example", None, "TLSv1.3", "TLS_AES_128_GCM_SHA256")])
        self.assertIsNone(report.score_summary(bom)["score"])

    def test_ssh_offered_algorithms_each_count_and_markers_are_skipped(self):
        ssh = {"version": "OpenSSH_9.9", "kex": ["mlkem768x25519-sha256", "curve25519-sha256", "ext-info-s",
                                                  "kex-strict-s-v00@openssh.com"],
               "hostkeys": ["ssh-ed25519"], "ciphers": ["aes256-gcm@openssh.com"]}
        bom = build(ssh=ssh)
        names = {c["name"] for c in bom["components"] if c["cryptoProperties"].get("assetType") == "algorithm"}
        self.assertNotIn("ext-info-s", names)
        s = report.score_summary(bom)
        self.assertEqual(s["scored"], 3)               # mlkem hybrid, curve25519, ed25519
        self.assertEqual(s["score"], round(100 * 1 / 3))

    def test_report_wording_uses_resistant(self):
        bom = build(certs=[cert("a.example")],
                    sessions=[("a.example", "X25519MLKEM768", "TLSv1.3", "TLS_AES_256_GCM_SHA384")])
        md, summary = report.build_report(bom)
        self.assertNotRegex(md.lower(), r"\bsafe\b")
        self.assertIn("quantum_resistant", summary)
        self.assertNotIn("quantum_safe", summary)


if __name__ == "__main__":
    unittest.main()
