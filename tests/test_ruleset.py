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
    ("brainpoolP256r1", None, "High", "High", True, "ecdh"),  # a TLS group (1.0.4)
    ("secp256k1", None, "High", "High", True, "ecdh"),   # 1.0.6: a TLS group (key exchange)
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


class ParameterSet106(unittest.TestCase):
    """Ruleset 1.0.6: a bare name takes parameterSetIdentifier only when that names a more specific algorithm."""

    def test_helper(self):
        f = r.name_with_parameter_set
        self.assertEqual(f("ML-KEM", "1024"), "ML-KEM-1024")
        self.assertEqual(f("ML-DSA", "65"), "ML-DSA-65")
        self.assertEqual(f("rsaEncryption", "2048"), "rsaEncryption")
        self.assertEqual(f("id-ecPublicKey", "256"), "id-ecPublicKey")
        self.assertEqual(f("ML-KEM-768", "1024"), "ML-KEM-768")      # the name already has one
        self.assertEqual(f("ML-KEM", "x y"), "ML-KEM")

    def test_policy_verdicts(self):
        import tempfile, json as _j
        import policy
        def alg(ref, name, ps):
            return {"type": "cryptographic-asset", "bom-ref": ref, "name": name,
                    "cryptoProperties": {"assetType": "algorithm",
                                         "algorithmProperties": {"parameterSetIdentifier": ps}}}
        with tempfile.TemporaryDirectory() as d:
            p = d + "/c.json"
            with open(p, "w") as fh:
                _j.dump({"bomFormat": "CycloneDX", "specVersion": "1.6",
                         "components": [alg("a", "ML-KEM", "1024"), alg("b", "rsaEncryption", "1024")]}, fh)
            fs = {x["bomRef"]: x for x in policy.evaluate(p, "nss")["findings"]}
        self.assertEqual(fs["a"]["canonical"], "ml-kem-1024")
        self.assertEqual(fs["a"]["status"], "compliant")
        self.assertEqual(fs["b"]["status"], "broken")               # 1024-bit RSA: the size still counts
        self.assertEqual(fs["b"]["name"], "rsaEncryption")


class LegacyCurves106(unittest.TestCase):
    """Ruleset 1.0.6: legacy SEC 2 / X9.62 / brainpool curves are judged, not Review; under 112-bit security is Critical."""

    def test_verdicts(self):
        for name, prio, lane in (("secp160r1", "Critical", "key-establishment"),
                                 ("sect163k1", "Critical", "key-establishment"),
                                 ("sect193r1", "Critical", "key-establishment"),
                                 ("secp192k1", "Critical", "key-establishment"),
                                 ("brainpoolP160r1", "Critical", "public-key"),
                                 ("secp224k1", "High", "key-establishment"),
                                 ("sect233k1", "High", "key-establishment"),
                                 ("sect571r1", "High", "key-establishment"),
                                 ("ECDHE-secp160r1", "Critical", "key-establishment")):
            v = r.classify(name)
            self.assertEqual((v["priority"], v["lane"]), (prio, lane), name)
            self.assertTrue(v["quantum_vulnerable"], name)
        self.assertIn("SP800-186", r.classify("sect163k1")["cite"])
        self.assertEqual(r.classify("secp160r1")["standard_status"], "non-nist")
        self.assertEqual(r.classify("secp256r1")["priority"], "High")       # unchanged


class HashBasedSignatureNames106(unittest.TestCase):
    """Ruleset 1.0.6: SP 800-208 parameter-set names are LMS / XMSS signatures, not their hash."""

    def test_names(self):
        for n in ("LMS_SHA256_M32_H10", "lms-sha256-m24-h20", "LMOTS_SHA256_N32_W8", "LMOTS_SHAKE_N32_W4"):
            v = r.classify(n)
            self.assertEqual((v["canonical"], v["lane"]), ("lms", "signature"), n)
            self.assertFalse(v["quantum_vulnerable"], n)
        self.assertEqual(r.classify("XMSSMT-SHA2_20/2_256")["canonical"], "xmssmt")     # 1.0.7: its own entry
        self.assertEqual(r.classify("SHA-256")["canonical"], "sha-256")       # a plain hash is still a hash
        self.assertIsNone(r.classify("films")["canonical"])


class MultitreeNotCNSA107(unittest.TestCase):
    """Ruleset 1.0.7: NSA CNSA 2.0 FAQ (Ver. 2.0, April 2024, p. 5): "The multitree algorithms HSS and XMSSMT are not
    allowed" in NSS. Compliant under civilian (SP 800-208); quantum-resistant but not CNSA 2.0 under nss."""

    def test_verdicts(self):
        for n in ("HSS", "HSS/LMS", "HSS_LMS_SHA256", "hss-sha256", "XMSSMT", "XMSSMT-SHA2_20/2_256"):
            civ, nss = r.classify(n, profile="civilian"), r.classify(n, profile="nss")
            self.assertEqual(civ["priority"], "None", n)
            self.assertEqual(nss["priority"], "Low", n)
            self.assertFalse(nss["quantum_vulnerable"], n)
            self.assertIn("CNSA2-FAQ", nss["cite"], n)
        for n in ("LMS", "LMS_SHA256_M24_H10", "XMSS", "XMSS-SHA2_10_256"):      # single-tree: still CNSA 2.0
            self.assertEqual(r.classify(n, profile="nss")["priority"], "None", n)



class MultitreeSpellings107(unittest.TestCase):
    """Review of 1.8.0: every spelling of HSS and XMSS^MT is the multitree entry; single-tree names are unchanged."""

    def test_spellings(self):
        for n in ("XMSS-MT-SHA2_20/2_256", "XMSS_MT_SHA2_20_2_256", "XMSS^MT signature", "xmss-mt signature",
                  "XMSS-MT", "xmss_mt"):
            self.assertEqual(r.classify(n, profile="nss")["canonical"], "xmssmt", n)
        for n in ("hss-lms-signature", "HSS_LMS signature", "id-alg-hss-lms-hashsig", "LMS/HSS", "HSS-LMS"):
            self.assertEqual(r.classify(n, profile="nss")["canonical"], "hss", n)
        for n, want in (("LMS-SHA256/192", "lms"), ("lms-sha256-m32-h10", "lms"), ("XMSS-SHA2_10_256", "xmss"),
                        ("xmss-sha256", "xmss"), ("LMOTS_SHA256_N32_W8", "lms")):
            v = r.classify(n, profile="nss")
            self.assertEqual((v["canonical"], v["priority"]), (want, "None"), n)
        for n in ("chss", "xmssmtx"):
            self.assertIsNone(r.classify(n)["canonical"], n)
        self.assertIn("L=1", r.classify("HSS")["note"])


class BareKeyTarget108(unittest.TestCase):
    """Ruleset 1.0.8: a bare RSA or EC key (a certificate's rsaEncryption / id-ecPublicKey) never gets ML-KEM as
    its only or first target. A certificate key signs, so the signature replacement (ML-DSA / SLH-DSA) leads and
    ML-KEM is named only for key establishment. Found by the 2026-11-23 audit of the fedlin.com quick check."""

    def test_bare_keys(self):
        for n, bits in (("id-ecPublicKey", 256), ("EC", 384), ("rsaEncryption", 2048), ("RSA", 3072)):
            civ = r.classify(n, bits, profile="civilian")["cnsa_target"]
            self.assertTrue(civ.startswith("ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures"), (n, civ))
            self.assertIn("ML-KEM (FIPS 203) for key establishment", civ, n)
            self.assertNotIn("ML-KEM (FIPS 203) / ML-DSA", civ, n)
            nss = r.classify(n, bits, profile="nss")["cnsa_target"]
            self.assertTrue(nss.startswith("ML-DSA-87 for signatures"), (n, nss))

    def test_specific_uses_unchanged(self):
        self.assertTrue(r.classify("ecdsa", 256)["cnsa_target"].startswith("ML-DSA (FIPS 204) or SLH-DSA (FIPS 205);"))
        self.assertTrue(r.classify("x25519")["cnsa_target"].startswith("ML-KEM (FIPS 203), e.g. hybrid"))

    def test_version(self):
        self.assertEqual(r.RULESET_VERSION, "1.0.8")
