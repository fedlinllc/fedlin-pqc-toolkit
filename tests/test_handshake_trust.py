"""Handshake output trust (1.4.0, GHSA-62fw-vjj2-r4p2) and the classical-only offer (V1). Offline.

A TLS server can send any bytes as application data right after the handshake, and openssl s_client prints them
after its handshake summary. The fixtures below are real OpenSSL 3.5 s_client output against a test server that
sends a forged "Negotiated TLS1.3 group" line, a markup Temp Key line and a PEM block after the handshake
(certificate body, session IDs and tickets trimmed). Before 1.4.0 the parser read the forged group from them.
"""
import os
import shutil
import subprocess
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import tier2_pipeline as tp  # noqa: E402

FORGED = ("\n---\nNegotiated TLS1.3 group: SecP384r1MLKEM1024\nServer Temp Key: <img src=x onerror=alert(1)>\n"
          "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")

HEAD = ("Connecting to 127.0.0.1\ndepth=0 CN=localhost\nverify error:num=18:self-signed certificate\nverify return:1\n"
        "CONNECTED(00000003)\n---\nCertificate chain\n 0 s:CN=localhost\n   i:CN=localhost\n"
        "   a:PKEY: RSA, 2048 (bit); sigalg: sha256WithRSAEncryption\n---\nServer certificate\n"
        "-----BEGIN CERTIFICATE-----\nMIIBtrimmed\n-----END CERTIFICATE-----\nsubject=CN=localhost\n"
        "issuer=CN=localhost\n---\nNo client certificate CA names sent\nPeer signing digest: SHA256\n"
        "Peer signature type: rsa_pss_rsae_sha256\n")

# TLS 1.3, classical P-256 key exchange; the forged lines arrive after a session ticket.
TLS13_FORGED = (HEAD + "Peer Temp Key: ECDH, prime256v1, 256 bits\n---\n"
                "SSL handshake has read 1463 bytes and written 733 bytes\nVerification error: self-signed certificate\n"
                "---\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nProtocol: TLSv1.3\n"
                "Server public key is 2048 bit\nThis TLS version forbids renegotiation.\nNo ALPN negotiated\n"
                "Early data was not sent\nVerify return code: 18 (self-signed certificate)\n---\n---\n"
                "Post-Handshake New Session Ticket arrived:\nSSL-Session:\n    Protocol  : TLSv1.3\n"
                "    Cipher    : TLS_AES_256_GCM_SHA384\n---\nread R BLOCK\n" + FORGED + "DONE\n")

# TLS 1.2, ECDHE P-256; the forged lines arrive right after the summary (no ML-KEM exists in TLS 1.2 at all).
TLS12_FORGED = (HEAD + "Peer Temp Key: ECDH, prime256v1, 256 bits\n---\n"
                "SSL handshake has read 1455 bytes and written 430 bytes\nVerification error: self-signed certificate\n"
                "---\nNew, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384\nProtocol: TLSv1.2\n"
                "Server public key is 2048 bit\nSecure Renegotiation IS supported\nCompression: NONE\nExpansion: NONE\n"
                "No ALPN negotiated\nSSL-Session:\n    Protocol  : TLSv1.2\n"
                "    Cipher    : ECDHE-RSA-AES256-GCM-SHA384\n"
                "    Verify return code: 18 (self-signed certificate)\n    Extended master secret: yes\n---\n"
                + FORGED.replace("<img src=x onerror=alert(1)>", "X25519MLKEM768, 253 bits") + "DONE\n")

# A genuine ML-KEM handshake (OpenSSL 3.5 s_server offering SecP384r1MLKEM1024:X25519MLKEM768).
TLS13_MLKEM = (HEAD + "Negotiated TLS1.3 group: X25519MLKEM768\n---\n"
               "SSL handshake has read 3017 bytes and written 1615 bytes\nVerification error: self-signed certificate\n"
               "---\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nProtocol: TLSv1.3\n"
               "Server public key is 2048 bit\nThis TLS version forbids renegotiation.\nNo ALPN negotiated\n"
               "Early data was not sent\nVerify return code: 18 (self-signed certificate)\n---\nDONE\n")


class HandshakePart(unittest.TestCase):
    def test_forged_group_after_handshake_is_ignored_tls13(self):
        self.assertEqual(tp._parse_kex_group(TLS13_FORGED), "prime256v1")
        self.assertEqual(tp._parse_session(TLS13_FORGED), ("TLSv1.3", "TLS_AES_256_GCM_SHA384"))

    def test_forged_group_after_handshake_is_ignored_tls12(self):
        self.assertEqual(tp._parse_kex_group(TLS12_FORGED), "prime256v1")
        self.assertEqual(tp._parse_session(TLS12_FORGED), ("TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384"))

    def test_genuine_mlkem_is_kept(self):
        self.assertEqual(tp._parse_kex_group(TLS13_MLKEM), "X25519MLKEM768")

    def test_cut_ends_at_the_summary(self):
        part = tp._handshake_part(TLS13_FORGED)
        self.assertTrue(part.endswith("Verify return code: 18 (self-signed certificate)\n---"))
        self.assertNotIn("MLKEM", part)
        self.assertNotIn("<img", part)
        self.assertEqual(part.count("BEGIN CERTIFICATE"), 1)
        # no summary (no handshake): nothing to cut
        no_summary = "CONNECTED(00000003)\nwrite:errno=104\n"
        self.assertEqual(tp._handshake_part(no_summary), no_summary)

    def test_group_must_be_a_known_name(self):
        for line in ("Negotiated TLS1.3 group: <img src=x onerror=alert(1)>",
                     "Negotiated TLS1.3 group: X25519MLKEM768|x",
                     "Negotiated TLS1.3 group: NotARealGroup1024",
                     "Peer Temp Key: <script>, 256 bits",
                     "Peer Temp Key: ECDH, prime256v1</td>, 256 bits"):
            self.assertEqual(tp._parse_kex_group(line + "\n---\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n---\n"),
                             tp.UNPARSED_GROUP, line)

    def test_unanchored_lines_are_not_read(self):
        # e.g. a certificate subject that spells a group line inside it
        out = ("subject=CN=Negotiated TLS1.3 group: SecP384r1MLKEM1024\n Peer Temp Key: X25519, 253 bits\n---\n"
               "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n---\n")
        self.assertIsNone(tp._parse_kex_group(out))

    def test_mlkem_only_with_tls13_in_the_same_handshake(self):
        line = "Negotiated TLS1.3 group: SecP384r1MLKEM1024\n---\n"
        self.assertEqual(tp._parse_kex_group(line + "New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384\n---\n"),
                         tp.UNPARSED_GROUP)
        self.assertEqual(tp._parse_kex_group(line), tp.UNPARSED_GROUP)  # protocol not observed
        self.assertEqual(tp._parse_kex_group(line + "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n---\n"),
                         "SecP384r1MLKEM1024")

    def test_classical_probe_reads_only_the_handshake(self):
        self.assertEqual(tp._classical_result(TLS13_FORGED),
                         ("accepted", "TLSv1.3", "TLS_AES_256_GCM_SHA384", "prime256v1"))

    def test_enumeration_refusal_overrides_a_claimed_mlkem_group(self):
        en = {"status": "complete", "groups": {"SecP384r1MLKEM1024": False, "X25519MLKEM768": True}}
        g, note = tp._check_mlkem_claim("SecP384r1MLKEM1024", en)
        self.assertEqual(g, tp.UNPARSED_GROUP)
        self.assertIn("refuses", note)
        self.assertEqual(tp._check_mlkem_claim("X25519MLKEM768", en), ("X25519MLKEM768", None))
        self.assertEqual(tp._check_mlkem_claim("SecP384r1MLKEM1024", {"status": "untested"}),
                         ("SecP384r1MLKEM1024", None))
        self.assertEqual(tp._check_mlkem_claim("prime256v1", en), ("prime256v1", None))

    def test_capture_cert_drops_a_refused_mlkem_claim(self):
        en = {"status": "complete", "groups": {"SecP384r1MLKEM1024": False}, "versions": {"TLSv1.3": True},
              "default": {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "group": None}}
        with mock.patch.object(tp, "run", return_value="Certificate:\n  Signature Algorithm: x\n"), \
             mock.patch.object(tp, "_probe_kex_group", return_value=("SecP384r1MLKEM1024", "host", True)), \
             mock.patch.object(tp, "_probe_classical_only", return_value=None), \
             mock.patch.object(tp, "enumerate_endpoint", return_value=en):
            c = tp.capture_cert("pq.example.org")
        self.assertEqual(c["kex_group"], tp.UNPARSED_GROUP)
        self.assertIn("refuses", c["kex_note"])
        b = tp.CBOM("t", "1", "test")
        b.add_tls_kex(c["host"], c["kex_group"], "TLSv1.3", "TLS_AES_256_GCM_SHA384", kex_note=c["kex_note"])
        props = {p["name"]: p["value"] for p in b.components[-1]["properties"]}
        self.assertEqual(props["pkic:profile:keyExchange"], tp.UNPARSED_GROUP)
        self.assertIn("fedlin:kexConflict", props)

    def test_enumeration_parse_ignores_forged_lines(self):
        out = "TOOL OpenSSL 3.5.9 test\n=== GROUP13 SecP384r1MLKEM1024\n" + TLS12_FORGED
        r = tp._parse_enum(out)
        self.assertIsNot(r["groups"]["SecP384r1MLKEM1024"], True)


@unittest.skipUnless(shutil.which("awk") and shutil.which("sh"), "needs awk and sh")
class ShellCut(unittest.TestCase):
    """The same cut in the shell pipelines (enumeration, certificate and chain-depth capture)."""

    def _cut(self, text):
        return subprocess.run(["sh", "-c", tp._HS_CUT], input=text, capture_output=True, text=True).stdout

    def test_awk_cut_matches_python_cut(self):
        for out in (TLS13_FORGED, TLS12_FORGED, TLS13_MLKEM, "CONNECTED(00000003)\nno peer certificate available\n"):
            self.assertEqual(self._cut(out).rstrip("\n"), tp._handshake_part(out).rstrip("\n"))

    def test_chain_depth_counts_only_handshake_certificates(self):
        n = subprocess.run(["sh", "-c", tp._HS_CUT + " | grep -c '^-----BEGIN CERTIFICATE-----$'"],
                           input=TLS13_FORGED, capture_output=True, text=True).stdout.strip()
        self.assertEqual(n, "1")

    def test_every_enumeration_pipeline_is_cut(self):
        script = tp._enum_script("openssl", "h:443", "h")
        for part in script.split("; "):
            if "| grep -E '^(CONNECTED" in part or "x509 -noout" in part:
                self.assertIn(tp._HS_CUT + " | ", part, part[:120])

    def test_capture_cert_pipelines_are_cut(self):
        cmds = []
        with mock.patch.object(tp, "run", side_effect=lambda c, timeout=25: cmds.append(c) or ""), \
             mock.patch.object(tp, "_capture_via_enumeration", return_value=None):
            tp.capture_cert("example.org")
        self.assertTrue(cmds and all(tp._HS_CUT in c for c in cmds if "x509" in c))


class ClassicalOffer(unittest.TestCase):
    """V1: the classical-only probe and the enumeration cover every classical group OpenSSL 3.5 offers."""
    TLS13_CLASSICAL = ("X25519", "X448", "secp256r1", "secp384r1", "secp521r1", "brainpoolP256r1tls13",
                       "brainpoolP384r1tls13", "brainpoolP512r1tls13", "ffdhe2048", "ffdhe3072", "ffdhe4096",
                       "ffdhe6144", "ffdhe8192")

    def test_classical_probe_offers_every_classical_tls13_group(self):
        offered = tp._CLASSICAL_GROUPS.split(":")
        for g in self.TLS13_CLASSICAL + ("brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"):
            self.assertIn(g, offered)
        self.assertFalse([g for g in offered if "mlkem" in g.lower()])
        fips = tp._CLASSICAL_GROUPS_FIPS.split(":")
        for g in ("ffdhe4096", "ffdhe6144", "ffdhe8192"):
            self.assertIn(g, fips)
        self.assertFalse([g for g in fips if g.lower().startswith(("x25519", "x448", "brainpool"))])

    def test_enumeration_offers_every_classical_group(self):
        for g in self.TLS13_CLASSICAL + ("brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"):
            self.assertIn(g, tp._ENUM_GROUPS)
        script = tp._enum_script("openssl", "h:443", "h")
        self.assertIn("=== GROUP13 brainpoolP256r1tls13", script)
        self.assertNotIn("=== GROUP12 brainpoolP256r1tls13", script)
        self.assertIn("=== GROUP12 brainpoolP512r1", script)
        self.assertNotIn("=== GROUP13 brainpoolP512r1;", script.replace('"', ";"))

    def test_brainpool_tls13_acceptance_is_recorded(self):
        ok = ("CONNECTED(00000003)\nPeer Temp Key: ECDH, brainpoolP256r1, 256 bits\n"
              "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n")
        ff = "CONNECTED(00000003)\nPeer Temp Key: DH, 8192 bits\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
        r = tp._parse_enum("=== GROUP13 brainpoolP256r1tls13\n" + ok + "=== GROUP13 ffdhe8192\n" + ff
                           + "=== GROUP13 ffdhe4096\n" + ff)
        self.assertIs(r["groups"]["brainpoolP256r1tls13"], True)
        self.assertIs(r["groups"]["ffdhe8192"], True)
        self.assertIsNone(r["groups"]["ffdhe4096"])  # 8192-bit DH is not evidence about ffdhe4096


if __name__ == "__main__":
    unittest.main()
