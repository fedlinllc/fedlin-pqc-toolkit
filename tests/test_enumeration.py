"""Endpoint enumeration (v1.0 benchmark gap): parsing, tri-state results, CBOM facts, policy and report. Offline."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import policy  # noqa: E402
import report  # noqa: E402
import tier2_pipeline as tp  # noqa: E402

OK13 = "CONNECTED(00000003)\nNegotiated TLS1.3 group: X25519MLKEM768\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
REFUSED = ("CONNECTED(00000003)\n4087:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake failure:"
           "ssl/record/rec_layer_s3.c:918:SSL alert number 40\nNew, (NONE), Cipher is (NONE)\n")
VERSION_REFUSED = ("CONNECTED(00000003)\n4087:error:0A00042E:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version:"
                   "ssl/record/rec_layer_s3.c:918:SSL alert number 70\nNew, (NONE), Cipher is (NONE)\n")
STATIC_RSA = "CONNECTED(00000003)\nNew, TLSv1.2, Cipher is AES128-SHA\n"  # completes, no key-exchange group
CLIENT_ABORT = ("CONNECTED(00000003)\n4087:error:0A00018A:SSL routines:tls_process_ske_dhe:dh key too small:"
                "ssl/statem/statem_clnt.c:2090:\nNew, (NONE), Cipher is (NONE)\n")
SILENT = ""  # timeout: nothing printed
CERT = ("subject=CN=example.com\nissuer=CN=Test CA\nnotBefore=Jan  1 00:00:00 2026 GMT\nnotAfter=Jan  1 00:00:00 2027 GMT\n"
        "sha256 Fingerprint=AA:BB:CC\n    Signature Algorithm: sha256WithRSAEncryption\n"
        "    Public Key Algorithm: rsaEncryption\n        Public-Key: (2048 bit)\n")

OUT = "\n".join([
    "TOOL OpenSSL 3.5.9 test",
    "=== DEFAULT", OK13,
    "=== LEGACY", STATIC_RSA,
    "=== VERSION TLSv1", VERSION_REFUSED,
    "=== VERSION TLSv1.2", "CONNECTED(00000003)\nNew, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256",
    "=== VERSION TLSv1.3", OK13,
    "=== SUITE TLSv1.3 TLS_AES_256_GCM_SHA384", OK13,
    "=== SUITE TLSv1.3 TLS_AES_128_CCM_SHA256", REFUSED,
    "=== ITER TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256", "CONNECTED(00000003)\nNew, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256",
    "=== ITER TLSv1.2 AES128-SHA", "CONNECTED(00000003)\nNew, TLSv1.2, Cipher is AES128-SHA",
    "=== ITER TLSv1.2 DHE-RSA-AES128-SHA", "CONNECTED(00000003)\nServer Temp Key: DH, 1024 bits\nNew, TLSv1.2, Cipher is DHE-RSA-AES128-SHA",
    "=== GROUP13 X25519MLKEM768", OK13,
    "=== GROUP13 SecP384r1MLKEM1024", REFUSED,
    "=== GROUP13 secp521r1", SILENT,
    "=== GROUP12 secp521r1", SILENT,
    "=== GROUP13 MLKEM1024", STATIC_RSA,          # completed without that group: no evidence
    "=== GROUP12 ffdhe2048", CLIENT_ABORT,        # the client gave up, not the server: no evidence
    "=== VERSION TLSv1.1", REFUSED,               # handshake failure on a version: not testable, not refused
    "=== INCOMPLETE TLSv1.2",
    "=== CERT RSA", CERT,
])

def _load(path):
    with open(path) as f:
        return json.load(f)


def _dump(obj, path):
    with open(path, "w") as f:
        json.dump(obj, f)



class Parse(unittest.TestCase):
    def setUp(self):
        self.r = tp._parse_enum(OUT)

    def test_tri_state(self):
        self.assertEqual(self.r["versions"], {"TLSv1": False, "TLSv1.1": None, "TLSv1.2": True, "TLSv1.3": True})
        self.assertEqual(self.r["groups"], {"X25519MLKEM768": True, "SecP384r1MLKEM1024": False, "secp521r1": None,
                                            "MLKEM1024": None, "ffdhe2048": None})
        self.assertEqual(self.r["incomplete"], ["TLSv1.2"])
        self.assertEqual(self.r["legacy"]["cipher"], "AES128-SHA")

    def test_suites_dh_and_certs(self):
        self.assertEqual(self.r["suites"]["TLSv1.3"], ["TLS_AES_256_GCM_SHA384"])
        self.assertEqual(self.r["suites"]["TLSv1.2"], ["ECDHE-RSA-AES128-GCM-SHA256", "AES128-SHA", "DHE-RSA-AES128-SHA"])
        self.assertEqual(self.r["dh_bits"], [1024])
        c = self.r["certs"][0]
        self.assertEqual((c["key_alg"], c["key_bits"], c["sig_alg"], c["fingerprint"]),
                         ("rsaEncryption", 2048, "sha256WithRSAEncryption", "aabbcc"))
        self.assertEqual(self.r["default"]["group"], "X25519MLKEM768")

    def test_script_is_shell_safe(self):
        hp, h = tp._hp("example.com", 443)
        sc = tp._enum_script("openssl", hp, h)
        self.assertIn("-servername example.com", sc)
        self.assertNotIn("$(id)", sc)

    def test_pace(self):
        hp, h = tp._hp("example.com", 443)
        self.assertIn("; sleep 0.5; ", tp._enum_script("openssl", hp, h, 0.5))
        self.assertNotIn("sleep", tp._enum_script("openssl", hp, h))

    def test_disabled(self):
        with mock.patch.object(tp, "ENUMERATE", False):
            self.assertIsNone(tp.enumerate_endpoint("example.com"))


def cbom(d, en):
    b = tp.CBOM("enum", "1", {})
    b.add_tls_kex("svc.example.com", "X25519MLKEM768", "TLSv1.3", "TLS_AES_256_GCM_SHA384", None, None, en)
    for x in en.get("certs", []):
        b.add_certificate(dict(x, host="svc.example.com"), extra="RSA")
    p = os.path.join(d, "cbom.json")
    with open(p, "w") as f:
        json.dump(b.to_dict(), f)
    return p


class Downstream(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        en = dict(tp._parse_enum(OUT), status="complete", client="host")
        self.path = cbom(self.t.name, en)
        self.bom = _load(self.path)

    def tearDown(self):
        self.t.cleanup()

    def props(self):
        return {p["name"]: p["value"] for c in self.bom["components"] for p in c.get("properties", [])}

    def test_cbom_facts(self):
        p = self.props()
        self.assertEqual(p["fedlin:acceptedProtocolVersions"], "TLSv1.2,TLSv1.3")
        self.assertEqual(p["fedlin:untestedProtocolVersions"], "TLSv1.1")
        self.assertNotIn("TLSv1,", p["fedlin:acceptedProtocolVersions"] + ",")
        self.assertEqual(p["fedlin:refusedGroups"], "SecP384r1MLKEM1024")
        self.assertEqual(p["fedlin:untestedGroups"], "secp521r1,MLKEM1024,ffdhe2048")
        self.assertEqual(p["fedlin:enumerationIncomplete"], "TLSv1.2")
        self.assertEqual(p["fedlin:dhGroupBits"], "1024")
        self.assertTrue(any(c["name"] == "svc.example.com (RSA certificate)" for c in self.bom["components"]))

    def test_policy_findings_and_recheck(self):
        r = policy.evaluate(self.path)
        conf = {f["name"]: f for f in r["findings"] if f["lane"] == "configuration"}
        self.assertEqual(conf["accepts Diffie-Hellman group of 1024 bits"]["status"], "broken")
        self.assertEqual(conf["accepts cipher suite (TLSv1.2) AES128-SHA"]["priority"], "High")
        self.assertNotIn("accepts protocol version TLSv1", conf)  # refused, not accepted
        with open(os.path.join(self.t.name, "cbom.policy.json"), "w") as f:
            json.dump(r, f)
        self.assertTrue(policy.check(r, self.path)["ok"])

    def test_report(self):
        view, _ = policy.load_view(self.path)
        md, summary = report.build_report(view)
        self.assertIn("## Server configuration (enumerated)", md)
        self.assertIn("TLSv1.2, TLSv1.3 (not tested: TLSv1.1)", md)
        self.assertIn("Diffie-Hellman group of 1024 bits** (Critical)", md)
        self.assertIn("1 static-RSA cipher suite(s)", md)
        self.assertEqual(summary["configuration"]["endpoints_accepting_broken"], 1)

    def test_score_ignores_configuration(self):
        # the usage-weighted score follows the negotiated session and certificates, not the accepted extras
        view, _ = policy.load_view(self.path)
        _, s1 = report.build_report(view)
        bom = _load(self.path)
        for c in bom["components"]:
            c["properties"] = [p for p in c.get("properties", []) if not p["name"].startswith("fedlin:accepted")
                               and p["name"] != "fedlin:dhGroupBits"]
        p2 = os.path.join(self.t.name, "plain.json")
        _dump(bom, p2)
        view2, _ = policy.load_view(p2)
        _, s2 = report.build_report(view2)
        self.assertEqual(s1["readiness_score"], s2["readiness_score"])


class Fallbacks(unittest.TestCase):
    def test_session_protocol_from_session_block(self):
        # "New, SSLv3, Cipher is AES128-SHA" names the suite's minimum version, not the negotiated one
        out = "CONNECTED(00000003)\nNew, SSLv3, Cipher is AES128-SHA\n    Protocol  : TLSv1.2\n"
        self.assertEqual(tp._parse_session(out), ("TLSv1.2", "AES128-SHA"))

    def test_unreachable_by_host_is_captured_via_enumeration(self):
        en = dict(tp._parse_enum(OUT), status="complete", client="container")
        en["certs"][0]["requested"] = "ANY"
        with mock.patch.object(tp, "run", return_value=""), \
             mock.patch.object(tp, "enumerate_endpoint", return_value=en), \
             mock.patch.object(tp, "_probe_classical_only", return_value=None):
            c = tp.capture_cert("legacy.example.com")
        self.assertIsNotNone(c)
        self.assertEqual((c["key_alg"], c["tls_cipher"]), ("rsaEncryption", "TLS_AES_256_GCM_SHA384"))
        self.assertTrue(c["kex_probe_via"].startswith("enumeration client"))

    def test_anonymous_and_null_suites_are_broken(self):
        import cnsa20_ruleset as r
        for n in ("ADH-AES128-SHA", "AECDH-AES256-SHA", "ECDHE-RSA-NULL-SHA", "AECDH-NULL-SHA",
                  "TLS_DH_anon_WITH_AES_128_CBC_SHA"):
            self.assertEqual(r.classify(n)["priority"], "Critical", n)

    def test_endpoint_canonicalization(self):
        self.assertEqual(tp.parse_endpoints(["a.example.com,a.example.com:443,[2001:db8::1]"]),
                         ["a.example.com", "[2001:db8::1]"])


if __name__ == "__main__":
    unittest.main()
