"""Regressions from the 2026-11-23 competitive rerun and the 1.9.0 review (HNDL without a recorded key exchange,
suite families the enumeration client cannot offer). Offline."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import report  # noqa: E402
import tier2_pipeline as tp  # noqa: E402


def enum(groups, versions=None):
    return {"status": "complete", "groups": groups,
            "versions": versions or {"TLSv1.2": True, "TLSv1.3": None}}


class NoTls13Inference(unittest.TestCase):
    def test_tls12_host_session_classical_groups(self):
        # client-cert-missing.badssl.com: the host's default handshake (offers TLS 1.3) got TLS 1.2, X25519MLKEM768
        # got no answer, secp256r1 accepted
        r = tp._no_tls13_hndl("TLSv1.2", None, enum({"secp256r1": True, "X25519MLKEM768": None}))
        self.assertIn("negotiated TLSv1.2 with a client offering TLS 1.3", r)
        self.assertIn("accepts secp256r1", r)

    def test_tls13_accepted_by_enumeration_rules_it_out(self):
        # review finding: the version may come from a probe that never offered TLS 1.3
        self.assertIsNone(tp._no_tls13_hndl("TLSv1.2", None, enum(
            {"secp256r1": True}, {"TLSv1.2": True, "TLSv1.3": True})))

    def test_mlkem_group_accepted_rules_it_out(self):
        self.assertIsNone(tp._no_tls13_hndl("TLSv1.2", None, enum({"X25519MLKEM768": True, "secp256r1": True})))

    def test_needs_host_session_and_complete_enumeration(self):
        self.assertIsNone(tp._no_tls13_hndl(None, None, enum({"secp256r1": True})))
        self.assertIsNone(tp._no_tls13_hndl("TLSv1.3", None, enum({"secp256r1": True})))
        self.assertIsNone(tp._no_tls13_hndl("TLSv1.2", None, {"status": "untested"}))
        self.assertIsNone(tp._no_tls13_hndl("TLSv1.2", None, enum({"secp256r1": None})))
        self.assertIsNone(tp._no_tls13_hndl("TLSv1.2", "secp256r1", enum({"secp256r1": True})))  # recorded: counted anyway


KEX = "pkic:profile:" + "keyExchange"


def tls(name, props):
    return {"type": "cryptographic-asset", "name": name,
            "properties": [{"name": k, "value": v} for k, v in props.items()],
            "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"type": "tls", "version": "1.2"}}}


def hndl_names(*components):
    return [n for n, _, _ in report.other_assets({"components": list(components)})[1]]


class ReportReadsTheProperty(unittest.TestCase):
    def test_inferred_counts(self):
        self.assertEqual(hndl_names(tls("a", {"fedlin:hndlInferred": "negotiated TLSv1.2 ..."})), ["a"])

    def test_tls12_without_the_property_does_not_count(self):
        # the report no longer infers on its own: a TLS 1.2 record from a -tls1_2 probe proves nothing about ML-KEM
        self.assertEqual(hndl_names(tls("b", {"fedlin:acceptedGroups": "secp256r1"})), [])

    def test_recorded_kex_counted_once(self):
        props = {KEX: "ECDHE-secp256r1", "fedlin:hndlInferred": "x"}
        self.assertEqual(hndl_names(tls("c", props)), ["c"])


class OldCbomKeepsCaveat(unittest.TestCase):
    def test_complete_enumeration_without_property(self):
        bom = {"components": [tls("TLS 1.2 - old.example.com", {"fedlin:enumeration": "complete",
                                                                 "fedlin:acceptedGroups": "secp256r1"})]}
        rows = report.server_configuration(bom)
        self.assertTrue(rows and rows[0]["legacy"])


if __name__ == "__main__":
    unittest.main()
