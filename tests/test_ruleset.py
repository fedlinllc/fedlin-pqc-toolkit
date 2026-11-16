"""Unit tests for scripts/cnsa20_ruleset.py (stdlib unittest; no third-party deps).

Run:  python3 -m unittest discover -s tests -v
Each case is (identifier, bits, expected priority, expected quantum_vulnerable, canonical).
The cases include every defect found in the 2026-11-14 gap assessment.
"""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import cnsa20_ruleset as r  # noqa: E402

# (name, bits, civilian priority, nss priority, quantum_vulnerable, canonical)
CASES = [
    # --- defects found 2026-11-14 ---
    ("curve25519-sha256", None, "High", "High", True, "x25519"),
    ("curve25519-sha256@libssh.org", None, "High", "High", True, "x25519"),
    ("sntrup761x25519-sha512", None, "Low", "Low", False, "sntrup761x25519-sha512"),
    ("sntrup761x25519-sha512@openssh.com", None, "Low", "Low", False, "sntrup761x25519-sha512"),
    ("mlkem768x25519-sha256", None, "None", "Low", False, "mlkem768x25519-sha256"),
    ("ML-KEM-512", None, "None", "Low", False, "ml-kem-512"),
    ("ML-DSA-44", None, "None", "Low", False, "ml-dsa-44"),
    ("ML-DSA-65", None, "None", "Low", False, "ml-dsa-65"),
    ("ML-DSA-87", None, "None", "None", False, "ml-dsa-87"),
    ("SLH-DSA-SHA2-128s", None, "None", "Low", False, "slh-dsa-128"),
    ("Falcon-512", None, "Low", "Low", False, "fn-dsa"),
    ("x25519kyber768draft00", None, "Low", "Low", False, "x25519kyber768draft00"),
    ("X25519Kyber768Draft00", None, "Low", "Low", False, "x25519kyber768draft00"),
    ("id-ecPublicKey", 256, "High", "High", True, "ec"),
    ("id-ecPublicKey", None, "High", "High", True, "ec"),
    ("RSA-1024", 1024, "Critical", "Critical", True, "rsa"),
    ("rsaEncryption", 1024, "Critical", "Critical", True, "rsa"),
    ("rsaEncryption", 2048, "High", "High", True, "rsa"),
    ("rsaEncryption", 4096, "High", "High", True, "rsa"),
    ("ideal-mode", None, "Review", "Review", None, None),
    ("ECMQV", None, "High", "High", True, "mqv"),
    ("ElGamal", None, "High", "High", True, "elgamal"),
    ("brainpoolP256r1", None, "High", "High", True, "ec"),
    ("secp256k1", None, "High", "High", True, "ec"),
    ("Curve25519", None, "High", "High", True, "x25519"),
    ("EdDSA", None, "High", "High", True, "eddsa"),
    ("TLSv1.0", None, "Critical", "Critical", True, "tls-legacy"),
    ("TLSv1.1", None, "Critical", "Critical", True, "tls-legacy"),
    ("TLSv1.2", None, "Low", "Low", False, "tls1.2"),
    ("TLSv1.3", None, "None", "None", False, "tls1.3"),
    # --- cipher suites (worst component wins) ---
    ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", None, "High", "High", True, "ecdh"),
    ("ECDHE-RSA-AES256-GCM-SHA384", None, "High", "High", True, "ecdh"),
    ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", None, "Critical", "Critical", True, "3des"),
    ("TLS_AES_128_GCM_SHA256", None, "None", "Low", False, "aes-128"),
    ("TLS_AES_256_GCM_SHA384", None, "None", "None", False, "aes-256"),
    ("TLS_CHACHA20_POLY1305_SHA256", None, "Low", "Low", False, "chacha20"),
    # --- TLS groups ---
    ("X25519MLKEM768", None, "None", "Low", False, "x25519mlkem768"),
    ("SecP256r1MLKEM768", None, "None", "Low", False, "secp256r1mlkem768"),
    ("SecP384r1MLKEM1024", None, "None", "None", False, "secp384r1mlkem1024"),
    ("MLKEM1024", None, "None", "None", False, "ml-kem-1024"),
    ("X25519", None, "High", "High", True, "x25519"),
    ("secp256r1", None, "High", "High", True, "ecdh"),
    ("ffdhe2048", None, "High", "High", True, "dh"),
    # --- SSH ---
    ("ssh-ed25519", None, "High", "High", True, "ed25519"),
    ("ssh-ed25519-cert-v01@openssh.com", None, "High", "High", True, "ed25519"),
    ("ssh-rsa", None, "Critical", "Critical", True, "sha-1"),
    ("rsa-sha2-512", None, "High", "High", True, "rsa"),
    ("ecdsa-sha2-nistp256", None, "High", "High", True, "ecdsa"),
    ("ssh-dss", None, "Critical", "Critical", True, "dsa"),
    ("diffie-hellman-group1-sha1", None, "Critical", "Critical", True, "dh"),
    ("diffie-hellman-group14-sha1", None, "Critical", "Critical", True, "sha-1"),
    ("diffie-hellman-group14-sha256", None, "High", "High", True, "dh"),
    ("diffie-hellman-group16-sha512", None, "High", "High", True, "dh"),
    ("ecdh-sha2-nistp384", None, "High", "High", True, "ecdh"),
    ("aes256-gcm@openssh.com", None, "None", "None", False, "aes-256"),
    ("aes128-ctr", None, "None", "Low", False, "aes-128"),
    ("chacha20-poly1305@openssh.com", None, "Low", "Low", False, "chacha20"),
    ("3des-cbc", None, "Critical", "Critical", True, "3des"),
    # --- certificate signature algorithms ---
    ("sha256WithRSAEncryption", None, "High", "High", True, "rsa"),
    ("sha1WithRSAEncryption", None, "Critical", "Critical", True, "sha-1"),
    ("md5WithRSAEncryption", None, "Critical", "Critical", True, "md5"),
    ("ecdsa-with-SHA256", None, "High", "High", True, "ecdsa"),
    ("ecdsa-with-SHA384", None, "High", "High", True, "ecdsa"),
    ("ecdsa-with-SHA1", None, "Critical", "Critical", True, "sha-1"),
    ("ED25519", None, "High", "High", True, "ed25519"),
    ("rsassaPss", None, "High", "High", True, "rsa"),
    ("dsaEncryption", 2048, "Critical", "Critical", True, "dsa"),
    # --- legacy / broken ---
    ("RC4", None, "Critical", "Critical", True, "rc4"),
    ("DES-CBC", None, "Critical", "Critical", True, "des"),
    ("3DES-EDE-CBC", None, "Critical", "Critical", True, "3des"),
    ("DESede", None, "Critical", "Critical", True, "3des"),
    ("MD5", None, "Critical", "Critical", True, "md5"),
    ("SHA1", None, "Critical", "Critical", True, "sha-1"),
    ("SHA-1", None, "Critical", "Critical", True, "sha-1"),
    ("RC2-CBC", None, "Critical", "Critical", True, "rc2"),
    # --- symmetric / hash / mac / kdf ---
    ("AES-256-GCM", None, "None", "None", False, "aes-256"),
    ("AES256", None, "None", "None", False, "aes-256"),
    ("AES-128", None, "None", "Low", False, "aes-128"),
    ("AES", None, "Review", "Review", False, "aes"),
    ("AES-GCM", None, "Review", "Review", False, "aes"),
    ("CHACHA20-POLY1305", None, "Low", "Low", False, "chacha20"),
    ("SHA-256", None, "None", "Low", False, "sha-256"),
    ("SHA-384", None, "None", "None", False, "sha-384"),
    ("SHA-512", None, "None", "None", False, "sha-512"),
    ("SHA3-256", None, "None", "Low", False, "sha3"),
    ("HMAC-SHA256", None, "None", "Low", False, "sha-256"),
    ("HMAC-SHA1", None, "None", "Low", False, "hmac-sha1"),
    # ruleset 1.0.2 (2026-11-15)
    ("SHA-512/256", None, "None", "Low", False, "sha-512/256"),  # 256-bit output: not CNSA 2.0
    ("sha512/224", None, "None", "Low", False, "sha-512/224"),
    ("hmac-sha2-256-etm@openssh.com", None, "None", "Low", False, "sha-256"),
    ("hmac-sha2-512", None, "None", "None", False, "sha-512"),
    ("umac-64-etm@openssh.com", None, "Low", "Low", False, "umac"),
    ("umac-128@openssh.com", None, "Low", "Low", False, "umac"),
    ("aria128-gcm", None, "Low", "Low", False, "aria"),
    ("camellia256", None, "Low", "Low", False, "camellia"),
    ("PBKDF2", None, "None", "Low", False, "pbkdf2"),  # nss: confirm underlying hash is SHA-384+
    ("rsa-sha2-256", None, "High", "High", True, "rsa"),  # hash size must not be read as key size
    ("bcrypt", None, "Low", "Low", False, "password-hash"),
    ("aria-256-gcm", None, "Low", "Low", False, "aria"),
    ("SEED", None, "Low", "Low", False, "seed"),
    # --- generic quantum-vulnerable ---
    ("RSA", None, "High", "High", True, "rsa"),
    ("RSA-2048", None, "High", "High", True, "rsa"),
    ("ECDSA", None, "High", "High", True, "ecdsa"),
    ("ECDH", None, "High", "High", True, "ecdh"),
    ("Ed448", None, "High", "High", True, "ed448"),
    ("DHE", None, "High", "High", True, "dh"),
    ("ML-KEM-1024", None, "None", "None", False, "ml-kem-1024"),
    ("ML-KEM-768", None, "None", "Low", False, "ml-kem-768"),
    ("LMS", None, "None", "None", False, "lms"),
]


class RulesetCases(unittest.TestCase):
    def test_cases(self):
        for name, bits, civ, nss, qv, canonical in CASES:
            for profile, expected in (("civilian", civ), ("nss", nss)):
                with self.subTest(name=name, bits=bits, profile=profile):
                    v = r.classify(name, bits, profile=profile)
                    self.assertEqual(v["priority"], expected, f"{name} [{profile}]: {v['note']}")
                    self.assertEqual(v["quantum_vulnerable"], qv, name)
                    self.assertEqual(v["canonical"], canonical, name)


class Conventions(unittest.TestCase):
    """Conventions that report.py and tier2_pipeline.py depend on."""

    def test_compliant_target_starts_with_none(self):
        for name in ("ML-KEM-1024", "ML-DSA-87", "AES-256-GCM", "SHA-384"):
            for p in r.PROFILES:
                v = r.classify(name, profile=p)
                self.assertTrue(v["cnsa_target"].startswith("None"), (name, p, v["cnsa_target"]))

    def test_noncompliant_target_does_not_start_with_none(self):
        for name in ("ML-KEM-768", "AES-128", "SHA-256"):
            v = r.classify(name, profile="nss")
            self.assertFalse(v["cnsa_target"].startswith("None"), (name, v["cnsa_target"]))

    def test_broken_target_says_replace_now(self):
        for name in ("RC4", "MD5", "TLSv1.0"):
            self.assertIn("Replace now", r.classify(name)["cnsa_target"])
        self.assertIn("Replace now", r.classify("rsaEncryption", 1024)["cnsa_target"])

    def test_required_keys(self):
        keys = {"primitive", "crypto_functions", "quantum_vulnerable", "nist_pqc_level", "cnsa_target",
                "controls", "note", "algorithm", "classical_security_level", "priority",
                "canonical", "cite", "profile", "rule_id", "components"}
        for name in ("RSA", "unknown-thing", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"):
            self.assertTrue(keys <= set(r.classify(name)), name)

    def test_every_rule_cites_a_known_source(self):
        for cid, a in r.ALGORITHMS.items():
            self.assertTrue(a["cite"], f"{cid} has no citation")
            for s in a["cite"]:
                self.assertIn(s, r.SOURCES, f"{cid} cites unknown source {s}")

    def test_every_alias_targets_a_known_algorithm(self):
        for alias, cid in r.ALIASES.items():
            self.assertIn(cid, r.ALGORITHMS, alias)

    def test_classical_strength(self):
        self.assertEqual(r.classify("rsaEncryption", 2048)["classical_security_level"], 112)
        self.assertEqual(r.classify("rsaEncryption", 3072)["classical_security_level"], 128)
        self.assertEqual(r.classify("id-ecPublicKey", 384)["classical_security_level"], 192)
        self.assertEqual(r.classify("Ed25519")["classical_security_level"], 128)

    def test_ir8547_dates(self):
        v = r.classify("rsaEncryption", 2048)
        self.assertEqual((v["deprecated_after"], v["disallowed_after"]), (2030, 2035))
        # IR 8547 final (Oct 2026): every strength is deprecated after 2030, including EdDSA.
        for name, bits in (("rsaEncryption", 3072), ("Ed25519", None), ("id-ecPublicKey", 384), ("X25519", None)):
            v = r.classify(name, bits)
            self.assertEqual((v["deprecated_after"], v["disallowed_after"]), (2030, 2035), name)

    def test_cipher_suite_reports_components(self):
        v = r.classify("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        got = {c["canonical"] for c in v["components"]}
        self.assertTrue({"ecdh", "rsa", "aes-128"} <= got, got)

    def test_pseudo_ssh_markers(self):
        for name in ("ext-info-c", "kex-strict-s-v00@openssh.com"):
            self.assertTrue(r.is_pseudo(name))
        self.assertFalse(r.is_pseudo("curve25519-sha256"))

    def test_unknown_profile_rejected(self):
        with self.assertRaises(ValueError):
            r.classify("RSA", profile="fips")


class RsaSignatures(unittest.TestCase):
    """Ruleset 1.0.3: an RSA signature name is a signature, migrated to ML-DSA/SLH-DSA."""

    def test_signature_lane_and_target(self):
        for n in ("sha256WithRSAEncryption", "sha384WithRSAEncryption", "RSASSA-PSS", "rsa-sha2-256"):
            v = r.classify(n, profile="civilian")
            self.assertEqual((v["primitive"], v["lane"]), ("signature", "signature"), n)
            self.assertTrue(v["cnsa_target"].startswith("ML-DSA (FIPS 204) or SLH-DSA"), n)
            self.assertTrue(r.classify(n, profile="nss")["cnsa_target"].startswith("ML-DSA-87"), n)

    def test_rsa_key_and_suites_unchanged(self):
        self.assertEqual(r.classify("rsaEncryption", 2048)["lane"], "public-key")
        self.assertEqual(r.classify("AES256-SHA")["lane"], "key-establishment")
        self.assertIn("disallowed by SP 800-131A", r.classify("RSA", 1024)["note"])


if __name__ == "__main__":
    unittest.main()
