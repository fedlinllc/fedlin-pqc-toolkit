"""Regressions for ruleset 1.0.4 (pressure test of v1.3.0, 2026-11-16; CORRECTIONS.md). Offline."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import cnsa20_ruleset as cnsa  # noqa: E402
import policy  # noqa: E402
import verdict_table as vt  # noqa: E402


def status(name, bits=None, profile="civilian"):
    return policy._status(cnsa.classify(name, bits, profile=profile))


class PreStandard(unittest.TestCase):
    """Kyber, Dilithium and SPHINCS+ are not FIPS 203/204/205, under either profile (as X25519Kyber768Draft00)."""

    def test_kyber_and_dilithium_are_not_fips(self):
        for name, canon in (("kyber512", "kyber"), ("Kyber768", "kyber"), ("kyber1024", "kyber"), ("kyber", "kyber"),
                            ("p256_kyber768", "kyber"), ("dilithium2", "dilithium"), ("dilithium3", "dilithium"),
                            ("dilithium5", "dilithium"), ("Dilithium", "dilithium")):
            for p in cnsa.PROFILES:
                v = cnsa.classify(name, profile=p)
                self.assertEqual(v["canonical"], canon, name)
                self.assertEqual(policy._status(v), "transitional", (name, p))
                self.assertEqual(v["standard_status"], "pre-standard", name)
                self.assertFalse(v["quantum_vulnerable"], name)
        self.assertEqual(status("X25519Kyber768Draft00", profile="nss"), status("kyber1024", profile="nss"))

    def test_only_fips205_slh_dsa_is_slh_dsa(self):
        for name, canon in (("SLH-DSA-SHA2-128s", "slh-dsa-128"), ("SLH-DSA-SHAKE-256f", "slh-dsa-256"),
                            ("id-slh-dsa-sha2-192s", "slh-dsa-192"), ("SLH-DSA", "slh-dsa"),
                            ("id-hash-slh-dsa-shake-128s-with-shake128", "slh-dsa-128")):
            self.assertEqual(cnsa.classify(name)["canonical"], canon, name)
            self.assertEqual(status(name), "compliant", name)
        for name in ("SPHINCS+-Haraka-128f-robust", "SPHINCS+-SHA2-128s-simple", "sphincsplus",
                     "slh-dsa-haraka-128s"):
            self.assertEqual(cnsa.classify(name)["canonical"], "sphincs+", name)
            self.assertEqual(status(name), "transitional", name)
        for name in ("english-slh", "slhfoo", "slh-dsa-md5-128s"):
            self.assertIsNone(cnsa.classify(name)["canonical"], name)
            self.assertEqual(cnsa.classify(name)["priority"], "Review", name)
        self.assertNotEqual(status("xslh-dsa-128s"), "compliant")


class Suites(unittest.TestCase):
    def test_psk_suite_keeps_its_mac(self):
        self.assertEqual(status("PSK-AES256-CBC-SHA", profile="nss"), "transitional")  # HMAC-SHA-1 is not CNSA 2.0
        comps = {c["canonical"] for c in cnsa.classify("PSK-AES256-CBC-SHA")["components"]}
        self.assertEqual(comps, {"aes-256", "hmac-sha1"})

    def test_srp_key_exchange_is_quantum_vulnerable(self):
        for name in ("SRP-AES-256-CBC-SHA", "SRP-RSA-AES-256-CBC-SHA", "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"):
            for p in cnsa.PROFILES:
                v = cnsa.classify(name, profile=p)
                self.assertEqual((v["canonical"], v["priority"]), ("srp", "High"), (name, p))

    def test_psk_with_key_exchange(self):
        self.assertEqual(cnsa.classify("DHE-PSK-AES256-CBC-SHA")["canonical"], "dh")
        self.assertEqual(cnsa.classify("ECDHE-PSK-AES256-CBC-SHA")["canonical"], "ecdh")
        self.assertEqual(cnsa.classify("RSA-PSK-AES256-GCM-SHA384")["canonical"], "rsa")


class Hybrids(unittest.TestCase):
    def test_unregistered_pairings_are_hybrids(self):
        for name in ("X25519MLKEM1024", "SecP256r1MLKEM1024", "secp256r1_mlkem1024", "p521_mlkem1024"):
            v = cnsa.classify(name, profile="nss")
            self.assertEqual(v["canonical"], "hybrid-ml-kem-1024", name)
            self.assertEqual(policy._status(v), "transitional", name)  # not CNSA 2.0 compliant
            self.assertEqual(status(name), "compliant", name)  # civilian: ML-KEM-1024 hybrid
        self.assertEqual(cnsa.classify("mlkem1024x448-sha512")["canonical"], "x448mlkem1024")
        self.assertEqual(status("mlkem1024x448-sha512", profile="nss"), "transitional")

    def test_registered_pairings_unchanged(self):
        for name, canon, nss in (("SecP384r1MLKEM1024", "secp384r1mlkem1024", "compliant"),
                                 ("X25519MLKEM768", "x25519mlkem768", "transitional"),
                                 ("mlkem1024nistp384-sha384", "mlkem1024nistp384-sha384", "compliant"),
                                 ("MLKEM1024", "ml-kem-1024", "compliant"),
                                 ("ML-KEM-768", "ml-kem-768", "transitional")):
            self.assertEqual(cnsa.classify(name)["canonical"], canon, name)
            self.assertEqual(status(name, profile="nss"), nss, name)

    def test_nonsense_parameter_sets_are_unknown(self):
        for name in ("mlkem10240", "MLKEM768-1024", "mldsa870", "ML-KEM-5120"):
            v = cnsa.classify(name)
            self.assertIsNone(v["canonical"], name)
            self.assertEqual(policy._status(v), "unclassified", name)


class Signatures(unittest.TestCase):
    def test_fn_dsa_is_not_dsa(self):
        for name in ("FN-DSA-512", "FN-DSA-1024", "fn-dsa", "id-fn-dsa-512", "Falcon-512"):
            v = cnsa.classify(name)
            self.assertEqual(v["canonical"], "fn-dsa", name)
            self.assertEqual(policy._status(v), "transitional", name)  # not final (FIPS 206 draft), as Falcon

    def test_sha1_and_md5_signatures_are_critical(self):
        for name in ("RSA-SHA1", "rsa-sha1", "rsa_pkcs1_sha1", "ecdsa_sha1", "RSA-MD5", "dsa_sha1"):
            for bits in (None, 3072):
                v = cnsa.classify(name, bits)
                self.assertEqual(v["priority"], "Critical", (name, bits))
                self.assertTrue(v["classically_broken"], name)
        # same verdict as the certificate spelling
        self.assertEqual(cnsa.classify("RSA-SHA1", 2048)["priority"],
                         cnsa.classify("sha1WithRSAEncryption", 2048)["priority"])
        for name in ("RSA-SHA256", "rsa_pkcs1_sha256", "ecdsa_secp256r1_sha256", "hmac-sha1", "RSA-OAEP-SHA1"):
            self.assertNotEqual(cnsa.classify(name)["priority"], "Critical", name)

    def test_ssh_sizes_are_kept(self):
        for name in ("diffie-hellman-group-exchange-sha256", "rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-512",
                     "rsa-sha2-256-cert-v01@openssh.com"):
            self.assertEqual(cnsa.classify(name, 1024)["priority"], "Critical", name)
            self.assertEqual(cnsa.classify(name, 3072)["priority"], "High", name)
        # a size fixed by the name still wins
        self.assertEqual(cnsa.classify("diffie-hellman-group14-sha256", 1024)["priority"], "High")


class Groups(unittest.TestCase):
    def test_brainpool_groups_classify(self):
        for g in ("brainpoolP256r1tls13", "brainpoolP384r1tls13", "brainpoolP512r1tls13"):
            v = cnsa.classify(g)
            self.assertEqual(v["canonical"], "ecdh", g)
            self.assertTrue(v["quantum_vulnerable"], g)
            self.assertIn("not a NIST-approved curve", v["note"])
        self.assertTrue(cnsa.classify("brainpoolP256r1")["quantum_vulnerable"])

    def test_verdict_table_knows_the_new_names(self):
        t = vt.build()
        for name, want in (("brainpoolP256r1tls13", "vulnerable"), ("kyber1024", "transitional"),
                           ("dilithium5", "transitional"), ("SRP-AES-256-CBC-SHA", "vulnerable"),
                           ("FN-DSA-512", "transitional")):
            _, v = vt.lookup(t, name, profile="nss")
            self.assertIsNotNone(v, name)
            self.assertEqual(v["status"], want, name)


class Invariants(unittest.TestCase):
    def test_unknown_is_never_compliant(self):
        for name in ("mlkem10240", "slhfoo", "english-slh", "MLKEM768-1024", "unparsed-kex-group", "zzz"):
            for p in cnsa.PROFILES:
                v = cnsa.classify(name, profile=p)
                self.assertNotEqual(policy._status(v), "compliant", (name, p))

    def test_canonical_ids_classify_to_themselves(self):
        for cid in ("kyber", "dilithium", "sphincs+", "srp", "hybrid-ml-kem-512", "hybrid-ml-kem-768",
                    "hybrid-ml-kem-1024", "fn-dsa"):
            self.assertEqual(cnsa.classify(cid)["canonical"], cid)

    def test_version(self):
        self.assertEqual(cnsa.RULESET_VERSION, "1.0.4")


if __name__ == "__main__":
    unittest.main()
