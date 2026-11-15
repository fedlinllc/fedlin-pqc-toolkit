"""Structural checks for the PKI Consortium CBOM interface profiles (entry profile
pkic.example.interface-enumeration v0.3, github.com/pkic/cbom, MIT).

These encode the rules as read from the vendored profile files in third_party/pkic-cbom/; they do not
run the PKIC validator. Run the validator itself as the conformance check:
  python3 third_party/pkic-cbom/validate_cbom.py out/cbom.json \
      third_party/pkic-cbom/profile-interface-enumeration.rules.json
"""

import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import tier2_pipeline as tp  # noqa: E402

PROFILE = json.loads((ROOT / "third_party/pkic-cbom/profile-interface-disclosure.rules.json").read_text())
COVERAGE = set(PROFILE["coverageVocabulary"])
IFACE_TYPES = set(PROFILE["interfaceTypeVocabulary"])
P = "pkic:profile:"


def props(el):
    out = {}
    for p in el.get("properties", []):
        out.setdefault(p["name"], []).append(p["value"])
    return out


def scan_cbom(with_ssh=False, kex=None):
    b = tp.CBOM("prod-edge.example.com", "1", {})
    b.subject_tag = tp.default_subject_tag("prod-edge.example.com", date="2026-11-14")
    b.add_certificate({"host": "a.example.com", "subject": "a", "issuer": "CA", "key_alg": "id-ecPublicKey",
                       "key_bits": 256, "sig_alg": "ecdsa-with-SHA256"})
    b.add_tls_kex("a.example.com", kex, "TLSv1.3", "TLS_AES_256_GCM_SHA384")
    if with_ssh:
        b.add_ssh({"version": "OpenSSH_9.9", "kex": ["mlkem768x25519-sha256"], "hostkeys": ["ssh-ed25519"],
                   "ciphers": ["aes256-gcm@openssh.com"]})
    return b.to_dict()


def interfaces(bom):
    return [c for c in bom["components"] if P + "interfaceType" in props(c)]


class ProfileShape(unittest.TestCase):
    def test_subject_declared_identified_and_covered(self):           # P3, P4, P5
        s = props(scan_cbom()["metadata"]["component"])
        self.assertEqual(s[P + "subjectType"], ["deployment"])
        self.assertTrue(s[P + "subjectIdentifier"][0].startswith("tag:"))
        self.assertIn(s[P + "coverage"][0], COVERAGE)

    def test_single_observed_stage(self):                              # P6, I8
        bom = scan_cbom()
        self.assertEqual(bom["metadata"]["lifecycles"], [{"phase": "discovery"}])
        for i in interfaces(bom):
            self.assertEqual(props(i)[P + "lifecycleStage"], ["observed"])

    def test_tls_interface_attributes(self):                           # P1, I1, I2, I7
        ifs = interfaces(scan_cbom(kex="X25519MLKEM768"))
        self.assertEqual(len(ifs), 1)
        i = ifs[0]
        pp = i["cryptoProperties"]["protocolProperties"]
        ip = props(i)
        self.assertEqual(pp["type"], "tls")
        self.assertEqual(ip[P + "protocolVersion"], ["1.3"])
        self.assertIn(ip[P + "interfaceType"][0], IFACE_TYPES)
        self.assertEqual(ip[P + "keyExchange"], ["X25519MLKEM768"])
        self.assertEqual(ip[P + "authentication"], ["ECDSA-secp256r1-SHA-256"])   # registry name
        self.assertEqual(len([k for k in ip if k.startswith(P + "endpointRole:")]), 2)   # I6 minCount 2
        self.assertEqual(ip[P + "observationMethod"], ["active-probe"])

    def test_unobserved_is_declared_unknown_not_silent(self):
        ip = props(interfaces(scan_cbom(kex=None))[0])
        self.assertNotIn(P + "keyExchange", ip)
        self.assertEqual(ip[P + "disclosure:keyExchange"], ["unknown"])

    def test_ssh_configuration_is_not_an_observed_interface(self):
        bom = scan_cbom(with_ssh=True)
        self.assertEqual(len(interfaces(bom)), 1)
        ssh = next(c for c in bom["components"] if c["bom-ref"] == "crypto/proto/ssh")
        self.assertIn("configured", props(ssh)["fedlin:evidence"][0])

    def test_source_only_scan_is_a_build_record(self):
        b = tp.CBOM("repo", "1", {})
        b.algo_ref("RSA", 2048)
        self.assertEqual(b.to_dict()["metadata"]["lifecycles"], [{"phase": "build"}])

    def test_default_subject_tag(self):
        self.assertEqual(tp.default_subject_tag("prod-edge.example.com", "2026-11-14"),
                         "tag:prod-edge.example.com,2026-11-14:prod-edge-example-com")
        self.assertEqual(tp.default_subject_tag("openshift-cluster", "2026-11-14"),
                         "tag:pqc-toolkit.invalid,2026-11-14:openshift-cluster")


if __name__ == "__main__":
    unittest.main()
