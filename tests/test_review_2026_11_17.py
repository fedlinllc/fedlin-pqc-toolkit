"""Regressions from the two reviews of the 1.4.0 candidate (2026-11-17). Offline."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cnsa20_ruleset as cnsa  # noqa: E402
import policy  # noqa: E402
import report  # noqa: E402
import tier2_pipeline as tp  # noqa: E402
import verdict_table as vt  # noqa: E402
import wave  # noqa: E402
from test_wave import HOST, ENUM_PQ, Base, cert, build, items  # noqa: E402


def status(name, profile="civilian"):
    return policy._status(cnsa.classify(name, profile=profile))


# ---------- 1. an unreadable key exchange is never a pass ----------
CONFLICT = "a handshake reported X25519MLKEM768, but the enumeration found that the server refuses it"


def unparsed_doc(conflict=True):
    """What a load balancer with mixed backends leaves: the kex probe met an ML-KEM backend, enumeration did not."""
    b = tp.CBOM("w", "1", {})
    c, extra = cert(HOST, "ML-DSA-65", None, "ML-DSA-65", "bb" * 32)
    b.add_certificate(c, extra=extra)
    b.add_tls_kex(HOST, tp.UNPARSED_GROUP, "TLSv1.3", "TLS_AES_256_GCM_SHA384", None, {"outcome": "rejected"},
                  ENUM_PQ, kex_note=CONFLICT if conflict else None)
    d = b.to_dict()
    d["metadata"]["timestamp"] = "2026-03-01T00:00:00Z"
    return d


class UnreadableKex(Base):
    def test_placeholder_findings_have_a_lane(self):
        self.assertEqual(cnsa.classify(tp.UNPARSED_GROUP)["lane"], "key-establishment")
        self.assertEqual(cnsa.classify("unparsed-public-key-algorithm")["lane"], "public-key")
        self.assertEqual(status(tp.UNPARSED_GROUP), "unclassified")

    def test_wave_checks_are_not_observed(self):
        for conflict in (True, False):
            w = items({"id": "f", "endpoint": HOST, "check": "findings-resolved", "priorities": ["Critical", "High"],
                       "lanes": ["key-establishment"]},
                      {"id": "m", "endpoint": HOST, "check": "mlkem"})
            _, it = self.run_check(unparsed_doc(conflict), w)
            self.assertEqual(it["f"]["status"], "not-observed", conflict)
            self.assertEqual(it["m"]["status"], "not-observed", conflict)

    def test_review_priority_check_counts_the_placeholder(self):
        w = items({"id": "f", "endpoint": HOST, "check": "findings-resolved", "priorities": ["Review"],
                   "lanes": ["key-establishment"]})
        _, it = self.run_check(unparsed_doc(), w)
        self.assertEqual(it["f"]["status"], "fail")

    def test_report_is_incomplete_and_lists_the_conflict(self):
        p = self.put("c.json", unparsed_doc())
        view, _ = policy.load_view(p)
        md, summary = report.build_report(view)
        self.assertIn("Incomplete: key exchange not observed on 1 of 1", md)
        self.assertIn("Key exchange not recorded on 1 endpoint(s)", md)
        self.assertIn("refuses it", md)
        self.assertEqual(summary["kex_unobserved"], 1)


# ---------- 2. post-quantum names never fall to the classical DSA token ----------
class PqNames(unittest.TestCase):
    def test_slh_dsa_spellings(self):
        for name, canon in (("id-alg-slh-dsa-sha2-128s", "slh-dsa-128"), ("CKM_SLH_DSA", "slh-dsa"),
                            ("CKK_SLH_DSA", "slh-dsa"), ("OpenSSL SLH-DSA-SHA2-128s", "slh-dsa-128"),
                            ("SLH-DSA-SHA2-128s-pure", "slh-dsa-128"), ("SLH-DSA-SHA2-128s:prehash", "slh-dsa-128"),
                            ("SLH-DSA-SHA2-128s-SHA512", "slh-dsa-128"),  # HashSLH-DSA with SHA-512
                            ("id-hash-slh-dsa-shake-256f-with-shake256", "slh-dsa-256")):
            self.assertEqual(cnsa.classify(name)["canonical"], canon, name)
            self.assertEqual(status(name), "compliant", name)
        for name in ("SLH-DSA-SHA2-128s-v2", "slh-dsa-sha2-128s-md5", "xslh-dsa-128s"):
            self.assertIsNone(cnsa.classify(name)["canonical"], name)  # unknown, reported for review

    def test_never_dsa(self):
        names = ("FN-DSA-1024-padded", "fn-dsa-512-prehash", "id-alg-slh-dsa-sha2-128s", "CKM_SLH_DSA",
                 "SLH-DSA-SHA2-128s-v2", "slh-dsa-x", "xslh-dsa", "sphincs-dsa", "falcon-dsa", "ML-DSA-65-ipd",
                 "mldsa870-dsa", "ml-dsa-x", "dilithium-dsa", "id-ml-dsa", "slh_dsa_haraka")
        for name in names:
            for bits in (None, 2048):
                self.assertNotEqual(cnsa.classify(name, bits)["canonical"], "dsa", name)
                self.assertNotEqual(cnsa.classify(name, bits)["priority"], "Critical", name)
        # plain DSA is still DSA
        self.assertEqual(cnsa.classify("dsaWithSHA256")["canonical"], "dsa")

    def test_initial_public_drafts_are_pre_standard(self):
        for name, canon in (("ML-KEM-1024-ipd", "ml-kem-ipd"), ("MLKEM1024-IPD", "ml-kem-ipd"),
                            ("mlkem768_ipd", "ml-kem-ipd"), ("ML-DSA-65-ipd", "ml-dsa-ipd"),
                            ("SLH-DSA-SHA2-128s-ipd", "slh-dsa-ipd")):
            for p in cnsa.PROFILES:
                v = cnsa.classify(name, profile=p)
                self.assertEqual(v["canonical"], canon, name)
                self.assertEqual(policy._status(v), "transitional", (name, p))
                self.assertEqual(v["standard_status"], "pre-standard", name)

    def test_composite_weak_hash_and_rsa_word(self):
        # Round-2 review: a SHA-1 composite passed nss; "universal" read as an RSA half.
        for n in ("MLDSA87-ECDSA-P384-SHA1", "MLDSA87-RSA3072-MD5"):
            self.assertEqual(cnsa.normalize(n)[0], [], n)
        self.assertEqual(cnsa.normalize("ML-DSA-87 universal")[0][0][0], "ml-dsa-87")
        self.assertEqual(cnsa.normalize("MLDSA87-RSA-4096")[0][0][0], "composite-ml-dsa-87-cnsa")
        self.assertEqual(cnsa.normalize("mldsa87rsa3072")[0][0][0], "composite-ml-dsa-87-cnsa")

    def test_composite_signatures_are_judged_as_composites(self):
        cases = (("MLDSA87-ECDSA-P384-SHA512", "composite-ml-dsa-87-cnsa", "compliant", "compliant"),
                 ("MLDSA87-RSA3072-PSS-SHA512", "composite-ml-dsa-87-cnsa", "compliant", "compliant"),
                 ("MLDSA87-Ed448", "composite-ml-dsa-87", "compliant", "transitional"),
                 ("MLDSA87-ECDSA-brainpoolP384r1-SHA512", "composite-ml-dsa-87", "compliant", "transitional"),
                 ("MLDSA65-RSA3072-PSS-SHA512", "composite-ml-dsa-65", "compliant", "transitional"),
                 ("MLDSA44-Ed25519-SHA512", "composite-ml-dsa-44", "compliant", "transitional"))
        for name, canon, civ, nss in cases:
            self.assertEqual(cnsa.classify(name)["canonical"], canon, name)
            self.assertEqual((status(name), status(name, "nss")), (civ, nss), name)
            self.assertEqual(cnsa.classify(name)["standard_status"], "pre-standard", name)
        # HashML-DSA is ML-DSA, not a composite
        self.assertEqual(cnsa.classify("HashML-DSA-87-with-SHA512")["canonical"], "ml-dsa-87")

    def test_brainpool_curve_names_are_groups(self):
        for g in ("brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1", "brainpoolP256r1tls13"):
            v = cnsa.classify(g)
            self.assertEqual((v["canonical"], v["lane"], v["standard_status"]), ("ecdh", "key-establishment",
                                                                                 "non-nist"), g)

    def test_verdict_table_has_the_review_names(self):
        t = vt.build()
        for name, want in (("RSA-SHA1", "broken"), ("rsa_pkcs1_sha1", "broken"), ("ecdsa_sha1", "broken"),
                           ("X25519MLKEM1024", "transitional"), ("SecP256r1MLKEM1024", "transitional"),
                           ("MLDSA87-Ed448", "transitional")):
            _, v = vt.lookup(t, name, profile="nss")
            self.assertEqual((v or {}).get("status"), want, name)

    def test_canonical_ids_classify_to_themselves(self):
        # every canonical ID except the three that were never names (password-hash, null-cipher, tls-legacy)
        for cid in set(cnsa.ALGORITHMS) - {"password-hash", "null-cipher", "tls-legacy"}:
            self.assertEqual(cnsa.classify(cid)["canonical"], cid, cid)


# ---------- 3. an OpenSSL without some group names (3.0 / 3.1) ----------
def fake_openssl(outputs, lacks):
    """run() of an OpenSSL that rejects a -groups list containing any name in `lacks`."""
    it, cmds = iter(outputs), []

    def run(cmd, timeout=25):
        cmds.append(cmd)
        if cmd.endswith("version"):
            return "OpenSSL 3.0.13"
        if "-groups " in cmd:
            bad = [g for g in cmd.split("-groups ")[1].split()[0].split(":") if g in lacks]
            if bad:
                return f"Call to SSL_CONF_cmd(-groups, {bad[0]}) failed"
            if "127.0.0.1:9" in cmd:
                return "connect:errno=111"
        return next(it)
    return run, cmds


REJECT = ("CONNECTED(00000003)\n40F7:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake failure:"
          "SSL alert number 40\n---\nno peer certificate available\n---\nNew, (NONE), Cipher is (NONE)\n")
ACCEPT = ("CONNECTED(00000003)\n---\nPeer Temp Key: X25519, 253 bits\n---\n"
          "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n---\n")
OLD = ("brainpoolP256r1tls13", "brainpoolP384r1tls13", "brainpoolP512r1tls13")


class OlderOpenSSL(unittest.TestCase):
    def probe(self, out):
        run, cmds = fake_openssl([out], OLD)
        with mock.patch.object(tp, "run", side_effect=run), mock.patch.dict(tp._GROUP_SUPPORT, clear=True), \
             mock.patch.object(tp, "_default_probe_image", return_value=""), \
             mock.patch.dict("os.environ", {"FEDLIN_KEX_PROBE_IMAGE": "", "FEDLIN_KEX_PROBE_OPENSSL": ""}):
            return tp._probe_classical_only("svc.example.org"), cmds

    def test_offers_what_it_has_with_x25519(self):
        r, cmds = self.probe(ACCEPT)
        self.assertEqual(r["outcome"], "accepted")
        self.assertEqual(r["group"], "X25519")
        self.assertIn("-groups X25519:", r["command"])
        self.assertNotIn("brainpoolP256r1tls13", r["command"])
        self.assertEqual(r["not_offered"], list(OLD))
        self.assertFalse(r["offer_complete"])

    def test_rejection_names_what_was_not_offered(self):
        r, _ = self.probe(REJECT)
        self.assertEqual(r["outcome"], "inconclusive")
        b = tp.CBOM("t", "1", {})
        b.add_tls_kex("svc.example.org", "X25519", "TLSv1.3", "TLS_AES_256_GCM_SHA384", None, r)
        props = {p["name"]: p["value"] for p in b.components[-1]["properties"]}
        self.assertEqual(props["fedlin:classicalOnlyOfferReduced"], "client OpenSSL lacks " + ",".join(OLD))

    def test_fips_host_still_uses_the_fips_subset(self):
        run, _ = fake_openssl([REJECT], OLD + ("X25519", "X448"))
        with mock.patch.object(tp, "run", side_effect=run), mock.patch.dict(tp._GROUP_SUPPORT, clear=True), \
             mock.patch.object(tp, "_default_probe_image", return_value=""), \
             mock.patch.dict("os.environ", {"FEDLIN_KEX_PROBE_IMAGE": "", "FEDLIN_KEX_PROBE_OPENSSL": ""}):
            r = tp._probe_classical_only("svc.example.org")
        self.assertIn(tp._CLASSICAL_GROUPS_FIPS, r["command"])
        self.assertNotIn("not_offered", r)

    def test_enumeration_offers_each_group_alone(self):
        # one name an OpenSSL lacks can only cost its own handshake
        script = tp._enum_script("openssl", "h:443", "h")
        for g in tp._ENUM_GROUPS:
            for part in script.split("; "):
                if f"-groups {g} " in part:
                    self.assertNotIn(":", part.split("-groups ")[1].split()[0], part[:100])

    def test_classical_offer_includes_legacy_tls12_curves(self):
        offered = tp._CLASSICAL_GROUPS.split(":")
        for g in ("secp224r1", "secp224k1", "secp256k1", "secp192r1", "secp192k1", "secp160r1", "secp160k1",
                  "secp160r2", "sect163r1", "sect193r1", "sect193r2", "sect239k1"):
            self.assertIn(g, offered)
        self.assertIn("secp224r1", tp._CLASSICAL_GROUPS_FIPS.split(":"))


class LegacyOnlyGaps(unittest.TestCase):
    """1.7.0: a client lacking only legacy curves (RHEL: no sect*) still makes a complete modern offer."""
    LACKS = ("sect163r1", "sect193r1", "sect193r2", "sect239k1")

    def test_rejection_stays_rejected(self):
        run, _ = fake_openssl([REJECT], self.LACKS)
        with mock.patch.object(tp, "run", side_effect=run), mock.patch.dict(tp._GROUP_SUPPORT, clear=True), \
             mock.patch.object(tp, "_default_probe_image", return_value=""), \
             mock.patch.dict("os.environ", {"FEDLIN_KEX_PROBE_IMAGE": "", "FEDLIN_KEX_PROBE_OPENSSL": ""}):
            r = tp._probe_classical_only("svc.example.org")
        self.assertEqual((r["outcome"], r["offer_complete"]), ("rejected", True))
        self.assertEqual(r["not_offered"], list(self.LACKS))
        b = tp.CBOM("t", "1", {})
        b.add_tls_kex("svc.example.org", "X25519", "TLSv1.3", "TLS_AES_256_GCM_SHA384", None, r)
        props = {p["name"]: p["value"] for p in b.components[-1]["properties"]}
        self.assertNotIn("fedlin:classicalOnlyOfferReduced", props)
        self.assertEqual(props["fedlin:classicalOnlyNotOffered"], ",".join(self.LACKS))


# ---------- 5. machine outputs keep raw values; Markdown and HTML get them inert ----------
RAW = "R&D <core> | prod\\x"


class RawValues(Base):
    def doc(self):
        b = tp.CBOM(RAW, "1", {})
        b.add_certificate({"host": HOST, "subject": "CN=a", "issuer": "CN=b", "key_alg": "rsaEncryption",
                           "key_bits": 2048, "sig_alg": "sha256WithRSAEncryption"})
        b.add_tls_kex(HOST, "X25519", "TLSv1.3", "TLS_AES_256_GCM_SHA384")
        d = b.to_dict()
        d["components"].append({"type": "cryptographic-asset", "bom-ref": "secret/x", "name": "aws-key",
                                "cryptoProperties": {"assetType": "related-crypto-material",
                                                     "relatedCryptoMaterialProperties": {"type": "token"}},
                                "evidence": {"occurrences": [{"location": "src/<a>|b`c.py"}]}})
        return self.put("raw.json", d)

    def test_summary_keeps_raw_values(self):
        view, _ = policy.load_view(self.doc())
        md, summary = report.build_report(view)
        self.assertEqual(summary["system"], RAW)
        self.assertNotIn("<core>", md)
        self.assertIn("R&D &lt;core&gt; &#124; prod\\\\x", md)  # backslash escaped too

    def test_title_escaped_once_and_controls_stripped(self):
        with mock.patch.dict(sys.modules, {"markdown": None}):
            h = report.md_to_html("x", title="PQC Readiness Report: " + RAW + "\x1b[31m\x07")
        self.assertIn("<title>PQC Readiness Report: R&amp;D &lt;core&gt; | prod\\x</title>", h)
        self.assertNotIn("\x1b", h)

    def test_control_bytes_are_removed(self):
        self.assertEqual(report.md_text("a\x1b[2Jb\x07c\x00d"), "abcd")
        self.assertEqual(wave.md_text("a\x1b[2Jb\x07c"), "abc")

    def test_code_span_shows_the_characters(self):
        self.assertEqual(report.md_code(report.md_text("src/<a>|b`c.py")), "src/<a>\\|b'c.py")

    def test_code_span_entities_cannot_break_the_line(self):
        # Round-2 review: md_code unescaped "&#10;" back into a line break, so a CBOM location could start a raw
        # HTML block or a new table row in report.md.
        for raw in ("a.py&#10;<img src=x onerror=alert(1)>&#10;| injected | row |", "a&#13;&#10;b", "a&#x0a;b",
                    "a&NewLine;b", "a&#9;b&#27;[31mc", "a&#96;b&#124;c"):
            out = report.md_code(report.md_text(raw))
            self.assertNotIn("\n", out, raw)
            self.assertNotIn("\r", out, raw)
            self.assertNotIn("\x1b", out, raw)
            self.assertNotIn("`", out, raw)
            self.assertNotRegex(out, r"(?<!\\)\|", raw)

    def test_mcp_summary_is_raw(self):
        import mcp_server
        p = self.doc()
        out = mcp_server.Server(os.path.dirname(p)).call("summarize", {"cbom": os.path.basename(p)})
        self.assertEqual(out["system"], RAW)


# ---------- NIT: the shell cut equals the Python cut on real output ----------
REAL_TLS13 = (
    "Connecting to 127.0.0.1\ndepth=0 CN=localhost\nverify error:num=18:self-signed certificate\nverify return:1\n"
    "depth=0 CN=localhost\nverify return:1\nCONNECTED(00000003)\n---\nCertificate chain\n 0 s:CN=localhost\n"
    "   i:CN=localhost\n   a:PKEY: RSA, 2048 (bit); sigalg: sha256WithRSAEncryption\n"
    "   v:NotBefore: Nov 17 02:47:28 2026 GMT; NotAfter: Dec 17 02:47:28 2026 GMT\n---\nServer certificate\n"
    "-----BEGIN CERTIFICATE-----\nMIIBtrimmed\n-----END CERTIFICATE-----\nsubject=CN=localhost\nissuer=CN=localhost\n"
    "---\nNo client certificate CA names sent\nPeer signing digest: SHA256\nPeer signature type: rsa_pss_rsae_sha256\n"
    "Peer Temp Key: ECDH, prime256v1, 256 bits\n---\nSSL handshake has read 1463 bytes and written 733 bytes\n"
    "Verification error: self-signed certificate\n---\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
    "Protocol: TLSv1.3\nServer public key is 2048 bit\nThis TLS version forbids renegotiation.\nNo ALPN negotiated\n"
    "Early data was not sent\nVerify return code: 18 (self-signed certificate)\n---\n---\n"
    "Post-Handshake New Session Ticket arrived:\nSSL-Session:\n    Protocol  : TLSv1.3\n"
    "    Cipher    : TLS_AES_256_GCM_SHA384\n    TLS session ticket lifetime hint: 7200 (seconds)\n"
    "    TLS session ticket:\n    0000 - 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00   ................\n\n"
    "    Start Time: 1794885505\n    Timeout   : 7200 (sec)\n    Verify return code: 18 (self-signed certificate)\n"
    "    Extended master secret: no\n    Max Early Data: 0\n---\nread R BLOCK\n\n---\n"
    "Negotiated TLS1.3 group: SecP384r1MLKEM1024\nServer Temp Key: <img src=x onerror=alert(1)>\n"
    "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
    "288B8B61417F0000:error:0A000126:SSL routines::unexpected eof while reading:ssl/record/rec_layer_s3.c:698:\n"
    "---\nPost-Handshake New Session Ticket arrived:\nSSL-Session:\n    Protocol  : TLSv1.3\n---\nread R BLOCK\nDONE\n")


class CutEquivalence(unittest.TestCase):
    def test_shell_and_python_cut_agree_on_real_output(self):
        got = subprocess.run(["sh", "-c", tp._HS_CUT], input=REAL_TLS13, capture_output=True, text=True).stdout
        self.assertEqual(got.rstrip("\n"), tp._handshake_part(REAL_TLS13).rstrip("\n"))
        self.assertEqual(tp._parse_kex_group(REAL_TLS13), "prime256v1")


if __name__ == "__main__":
    unittest.main()


class Review170(unittest.TestCase):
    """Fresh review of the 1.7.0 change set."""

    def test_vendor_readiness_key_size_still_counts(self):
        import vendor_readiness as vr
        f = vr.cbom_facts({"components": [{"type": "cryptographic-asset", "bom-ref": "a", "name": "RSA",
                                           "cryptoProperties": {"assetType": "algorithm", "algorithmProperties":
                                                                {"parameterSetIdentifier": "1024"}}}]}, "civilian")
        self.assertEqual(f["algorithms"][0]["priority"], "Critical")

    def test_bom_and_nulls_load(self):
        import policy
        with tempfile.TemporaryDirectory() as d:
            for name, raw in (("bom.json", b'\xef\xbb\xbf{"bomFormat":"CycloneDX","components":[]}'),
                              ("null.json", b'{"bomFormat":"CycloneDX","components":null}'),
                              ("cp.json", b'{"components":[{"type":"cryptographic-asset","name":"x",'
                                          b'"cryptoProperties":null,"properties":null}]}')):
                p = os.path.join(d, name)
                with open(p, "wb") as fh:
                    fh.write(raw)
                self.assertIsInstance(policy.evaluate(p)["findings"], list, name)

    def test_legacy_curve_handshake_on_dhe_is_not_a_group(self):
        out = ("=== LEGACYCURVES\nCONNECTED(00000003)\nServer Temp Key: DH, 2048 bits\n"
               "New, TLSv1.2, Cipher is DHE-RSA-AES128-GCM-SHA256\n")
        r = tp._parse_enum(out)
        self.assertNotIn("DH", r["groups"])
        self.assertNotIn("legacy_curves", r)
        self.assertTrue(r["versions"]["TLSv1.2"])
