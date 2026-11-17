"""Classical-only fallback probe (PQCMM 4.3.1): parsing, client order, CBOM facts, report and evidence. Offline."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import pqcmm_evidence as pe  # noqa: E402
import report as rp  # noqa: E402
import tier2_pipeline as tp  # noqa: E402

# Shapes of real OpenSSL 3.5 s_client output.
ACCEPTED = ("CONNECTED(00000003)\n---\nNegotiated TLS1.3 group: X25519\n---\n"
            "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n")
REJECTED = ("CONNECTED(00000003)\n40F7:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake "
            "failure:ssl/record/rec_layer_s3.c:916:SSL alert number 40\n---\nno peer certificate available\n---\n"
            "New, (NONE), Cipher is (NONE)\nSSL-Session:\n    Protocol  : TLSv1.3\n    Cipher    : 0000\n")
NO_ANSWER = "connect:errno=111\n"
# Pressure-test cases: TCP accepted then closed; HTTP on the port; TLS 1.2 server demanding a client
# certificate after sending its own (alert 40 after Certificate); insufficient_security refusal.
CLOSED = "CONNECTED(00000003)\nwrite:errno=104\n---\nno peer certificate available\n---\nNew, (NONE), Cipher is (NONE)\n"
HTTP = ("CONNECTED(00000003)\n40F7:error:0A00010B:SSL routines:ssl3_get_record:wrong version number\n---\n"
        "no peer certificate available\n---\nNew, (NONE), Cipher is (NONE)\n")
CLIENT_CERT = ("CONNECTED(00000003)\n40F7:error:0A000410:SSL routines::sslv3 alert handshake failure:"
               "SSL alert number 40\n---\nCertificate chain\n 0 s:CN=etcd\n---\nServer certificate\n"
               "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\nPeer Temp Key: ECDH, prime256v1, 256 bits\n"
               "New, (NONE), Cipher is (NONE)\n")
INSUFFICIENT = ("CONNECTED(00000003)\n40F7:error:0A00042F:SSL routines::tlsv1 alert insufficient security:"
                "SSL alert number 71\n---\nno peer certificate available\n---\nNew, (NONE), Cipher is (NONE)\n")
FIPS_REFUSAL = "Call to SSL_CONF_cmd(-groups, X25519:secp256r1) failed"


def _runner(outputs, lacks=("X25519", "X448")):
    """Fake run(): canned handshake outputs in order; the per-name group check against 127.0.0.1:9 refuses `lacks`
    (a FIPS-mode OpenSSL by default)."""
    it = iter(outputs)

    def fake(cmd, timeout=25):
        if "-connect 127.0.0.1:9 -groups " in cmd:
            g = cmd.split("-groups ")[1].split()[0]
            return f"Call to SSL_CONF_cmd(-groups, {g}) failed" if g in lacks else "connect:errno=111"
        return "OpenSSL 3.5.8" if cmd.endswith("version") else next(it)
    return fake


class Parse(unittest.TestCase):
    def test_outcomes(self):
        self.assertEqual(tp._classical_result(ACCEPTED), ("accepted", "TLSv1.3", "TLS_AES_256_GCM_SHA384", "X25519"))
        self.assertEqual(tp._classical_result(REJECTED)[0], "rejected")
        self.assertIsNone(tp._classical_result(NO_ANSWER)[0])

    def test_unrelated_failures_are_not_rejections(self):
        for out in (CLOSED, HTTP):
            self.assertEqual(tp._classical_result(out)[0], "inconclusive", out)

    def test_server_certificate_sent_means_classical_was_chosen(self):
        self.assertEqual(tp._classical_result(CLIENT_CERT)[0], "accepted")

    def test_insufficient_security_is_a_rejection(self):
        self.assertEqual(tp._classical_result(INSUFFICIENT)[0], "rejected")

    def test_offer_is_classical_only(self):
        for groups in (tp._CLASSICAL_GROUPS, tp._CLASSICAL_GROUPS_FIPS):
            self.assertFalse(any(tp._is_pqc_group(g) for g in groups.split(":")), groups)


class Probe(unittest.TestCase):
    env = {"FEDLIN_KEX_PROBE_IMAGE": "", "FEDLIN_KEX_PROBE_OPENSSL": ""}

    def probe(self, outputs):
        with mock.patch.object(tp, "run", side_effect=_runner(outputs)), \
             mock.patch.dict(tp._GROUP_SUPPORT, clear=True), \
             mock.patch.object(tp, "_default_probe_image", return_value=""), \
             mock.patch.dict("os.environ", self.env):
            return tp._probe_classical_only("pq.example")

    def test_host_accepts(self):
        r = self.probe([ACCEPTED])
        self.assertEqual((r["outcome"], r["offer_complete"], r["tool"]), ("accepted", True, "OpenSSL 3.5.8"))
        self.assertIn("-groups " + tp._CLASSICAL_GROUPS, r["command"])

    def test_host_rejects(self):
        self.assertEqual(self.probe([REJECTED])["outcome"], "rejected")

    def test_unreachable_is_untested(self):
        self.assertEqual(self.probe([NO_ANSWER])["outcome"], "untested")

    def test_silent_bundled_client_stops_the_probe(self):
        # The bundled client ran and got no connection: answer is untested, no 8 s retries on other clients.
        with mock.patch.object(tp, "run", side_effect=_runner([FIPS_REFUSAL, NO_ANSWER])), \
             mock.patch.dict("os.environ", {"FEDLIN_KEX_PROBE_OPENSSL": "/opt/kex-probe/openssl"}), \
             mock.patch.object(tp.os.path, "isfile", return_value=True), \
             mock.patch.object(tp.os, "access", return_value=True), \
             mock.patch.object(tp, "_container_s_client") as c:
            self.assertEqual(tp._probe_classical_only("pq.example")["outcome"], "untested")
        c.assert_not_called()

    def test_disabled(self):
        with mock.patch.object(tp, "CLASSICAL_PROBE", False), \
             mock.patch.object(tp, "run", return_value="Certificate:\n  Signature Algorithm: x\n"), \
             mock.patch.object(tp, "_probe_kex_group", return_value=(None, "host", True)), \
             mock.patch.object(tp, "_probe_classical_only") as p:
            self.assertIsNone(tp.capture_cert("example.com")["classical_only"])
        p.assert_not_called()

    def test_fips_reduced_offer_rejection_is_inconclusive(self):
        r = self.probe([FIPS_REFUSAL, REJECTED])
        self.assertEqual((r["outcome"], r["offer_complete"]), ("inconclusive", False))

    def test_fips_reduced_offer_acceptance_is_definitive(self):
        self.assertEqual(self.probe([FIPS_REFUSAL, ACCEPTED])["outcome"], "accepted")

    def test_container_used_on_fips_host(self):
        with mock.patch.object(tp, "run", side_effect=_runner([FIPS_REFUSAL])), \
             mock.patch.object(tp, "_default_probe_image", return_value="localhost/fedlin-kex-probe:0.1"), \
             mock.patch.dict("os.environ", self.env), \
             mock.patch.object(tp, "_container_s_client", return_value="TOOL: OpenSSL 3.5.9\n" + REJECTED):
            r = tp._probe_classical_only("pq.example")
        self.assertEqual((r["outcome"], r["offer_complete"], r["tool"]), ("rejected", True, "OpenSSL 3.5.9"))
        self.assertTrue(r["command"].startswith("podman run --rm --pull=never localhost/fedlin-kex-probe:0.1 sh -c "))
        self.assertIn("echo | timeout 8 openssl s_client", r["command"])


def write_cbom(d, outcomes):
    b = tp.CBOM("prod-edge.example.com", "1", {})
    b.subject_tag = tp.default_subject_tag("prod-edge.example.com", date="2026-11-15")
    for i, o in enumerate(outcomes):
        host = f"h{i}.example.com"
        co = {"outcome": o, "tool": "OpenSSL 3.5.9", "command": f"openssl s_client -connect {host}:443"}
        if o == "accepted":
            co.update(protocol="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", group="X25519")
        b.add_tls_kex(host, "X25519MLKEM768", "TLSv1.3", "TLS_AES_256_GCM_SHA384", None, co)
    path = os.path.join(d, "cbom.json")
    with open(path, "w") as f:
        json.dump(b.to_dict(), f)
    return path


class Downstream(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.d.cleanup()

    def test_cbom_records_facts(self):
        with open(write_cbom(self.d.name, ["accepted"])) as f:
            bom = json.load(f)
        p = {x["name"]: x["value"] for c in bom["components"] for x in c.get("properties", [])}
        self.assertEqual(p["fedlin:classicalOnlyOffer"], "accepted")
        self.assertEqual(p["fedlin:classicalOnlyNegotiated"], "TLSv1.3 TLS_AES_256_GCM_SHA384 X25519")
        self.assertEqual(p["fedlin:classicalOnlyTool"], "OpenSSL 3.5.9")

    def test_report_section(self):
        with open(write_cbom(self.d.name, ["accepted", "rejected"])) as f:
            bom = json.load(f)
        self.assertEqual([o for _, o, _ in rp.classical_fallback(bom)], ["accepted", "rejected"])
        md, summary = rp.build_report(bom)
        self.assertIn("## Classical fallback", md)
        self.assertIn("| h1.example.com | rejected | - |", md)
        self.assertEqual(summary["classical_fallback"], {"accepted": 1, "rejected": 1})

    def test_pqcmm_431(self):
        for outcomes, want in ((["rejected", "rejected"], "rejected"), (["rejected", "accepted"], "accepted"),
                               (["untested", "untested"], "untested"), (["rejected", "inconclusive"], None),
                               (["inconclusive"], None)):
            e = pe.build(write_cbom(self.d.name, outcomes))["evidence"]["4.3.1"]
            self.assertEqual(e["fields"].get("classicalConnectionOutcome"), want, outcomes)
            self.assertEqual(e["provenance"], "observed")
            self.assertNotIn("configurationMechanism", e["fields"])  # the vendor's to state

    def test_no_probe_no_431(self):
        b = tp.CBOM("x.example.com", "1", {})
        b.add_tls_kex("x.example.com", "X25519", "TLSv1.3", "TLS_AES_256_GCM_SHA384")
        path = os.path.join(self.d.name, "plain.json")
        with open(path, "w") as f:
            json.dump(b.to_dict(), f)
        self.assertNotIn("4.3.1", pe.build(path)["evidence"])


if __name__ == "__main__":
    unittest.main()
