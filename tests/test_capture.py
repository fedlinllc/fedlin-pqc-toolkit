"""Tests for capture parsing and endpoint validation in scripts/tier2_pipeline.py (no network)."""

import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
import tier2_pipeline as tp  # noqa: E402


class Capture(unittest.TestCase):
    def test_host_validation(self):
        for good in ("fedlin.com", "a.b-c.example", "10.0.0.1", "[::1]"):
            self.assertTrue(tp.valid_host(good), good)
        for bad in ("a;b", "$(id).com", "`x`", "a b", "", "x" * 300):
            self.assertFalse(tp.valid_host(bad), bad)

    def test_parse_endpoints_drops_invalid(self):
        got = tp.parse_endpoints(["fedlin.com,$(id)x.com,a;b,example.org:8443,https://www.fedlin.com/x"])
        self.assertEqual(got, ["fedlin.com", "example.org:8443", "www.fedlin.com"])

    def test_parse_kex_group_openssl_formats(self):
        cases = {
            "Negotiated TLS1.3 group: X25519MLKEM768": "X25519MLKEM768",
            "Negotiated TLS1.3 group: <NULL>\nPeer Temp Key: ECDH, prime256v1, 256 bits": "prime256v1",
            "Server Temp Key: X25519, 253 bits": "X25519",
            "Peer Temp Key: DH, 2048 bits": "DH",
            "no handshake": None,
        }
        for out, want in cases.items():
            self.assertEqual(tp._parse_kex_group(out), want, out)

    def test_parse_session(self):
        out = "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nProtocol: TLSv1.3\n"
        self.assertEqual(tp._parse_session(out), ("TLSv1.3", "TLS_AES_256_GCM_SHA384"))

    def test_fips_subset_classical_result_is_not_recorded(self):
        # Host refuses the full offer (FIPS), reduced offer negotiates a classical curve.
        outs = iter(["Call to SSL_CONF_cmd(-groups, X25519MLKEM768) failed",
                     "Peer Temp Key: ECDH, prime256v1, 256 bits"])
        with mock.patch.object(tp, "run", side_effect=lambda cmd, timeout=25: next(outs)), \
             mock.patch.object(tp, "_default_probe_image", return_value=""), \
             mock.patch.dict("os.environ", {"FEDLIN_KEX_PROBE_IMAGE": ""}):
            self.assertEqual(tp._probe_kex_group("fedlin.com"), ("prime256v1", "host-fips-subset", False))

    def test_fips_subset_pqc_result_is_definitive(self):
        outs = iter(["Call to SSL_CONF_cmd(-groups, X25519MLKEM768) failed",
                     "Negotiated TLS1.3 group: SecP256r1MLKEM768"])
        with mock.patch.object(tp, "run", side_effect=lambda cmd, timeout=25: next(outs)), \
             mock.patch.object(tp, "_default_probe_image", return_value=""), \
             mock.patch.dict("os.environ", {"FEDLIN_KEX_PROBE_IMAGE": ""}):
            grp, how, complete = tp._probe_kex_group("pq.example")
        self.assertEqual((grp, complete), ("SecP256r1MLKEM768", False))
        self.assertTrue(tp._is_pqc_group(grp))

    def test_fips_host_uses_probe_image_for_full_offer(self):
        with mock.patch.object(tp, "run", return_value="Call to SSL_CONF_cmd(-groups, X25519MLKEM768) failed"), \
             mock.patch.object(tp, "_default_probe_image", return_value="localhost/fedlin-kex-probe:0.1"), \
             mock.patch.dict("os.environ", {"FEDLIN_KEX_PROBE_IMAGE": ""}), \
             mock.patch.object(tp, "_probe_kex_group_container", return_value="X25519MLKEM768") as c:
            self.assertEqual(tp._probe_kex_group("fedlin.com"), ("X25519MLKEM768", "container", True))
        self.assertEqual(c.call_args[0][2], "localhost/fedlin-kex-probe:0.1")

    def test_fips_host_uses_bundled_probe_openssl_first(self):
        outs = iter(["Call to SSL_CONF_cmd(-groups, X25519MLKEM768) failed",
                     "Negotiated TLS1.3 group: X25519MLKEM768"])
        cmds = []
        def fake_run(cmd, timeout=25):
            cmds.append(cmd)
            return next(outs)
        with mock.patch.object(tp, "run", side_effect=fake_run), \
             mock.patch.dict("os.environ", {"FEDLIN_KEX_PROBE_OPENSSL": "/usr/local/bin/kex-probe-openssl"}), \
             mock.patch.object(tp.os.path, "isfile", return_value=True), \
             mock.patch.object(tp.os, "access", return_value=True), \
             mock.patch.object(tp, "_probe_kex_group_container") as c:
            self.assertEqual(tp._probe_kex_group("fedlin.com"), ("X25519MLKEM768", "bundled", True))
        c.assert_not_called()
        self.assertIn("/usr/local/bin/kex-probe-openssl s_client", cmds[1])

    def test_missing_bundled_probe_is_skipped(self):
        outs = iter(["Call to SSL_CONF_cmd(-groups, X25519MLKEM768) failed",
                     "Peer Temp Key: ECDH, prime256v1, 256 bits"])
        with mock.patch.object(tp, "run", side_effect=lambda cmd, timeout=25: next(outs)), \
             mock.patch.object(tp, "_default_probe_image", return_value=""), \
             mock.patch.dict("os.environ", {"FEDLIN_KEX_PROBE_IMAGE": "",
                                            "FEDLIN_KEX_PROBE_OPENSSL": "/nonexistent/openssl"}):
            self.assertEqual(tp._probe_kex_group("fedlin.com"), ("prime256v1", "host-fips-subset", False))

    def test_capture_cert_never_invents_rsa(self):
        with mock.patch.object(tp, "run", return_value="Certificate:\n  Signature Algorithm: x\n"), \
             mock.patch.object(tp, "_probe_kex_group", return_value=(None, "host", True)):
            c = tp.capture_cert("example.com")
        self.assertEqual(c["key_alg"], "unparsed-public-key-algorithm")


if __name__ == "__main__":
    unittest.main()
