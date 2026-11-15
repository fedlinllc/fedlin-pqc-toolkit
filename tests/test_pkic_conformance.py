"""Conformance gate: run the vendored PKI Consortium validator (third_party/pkic-cbom, MIT, pinned)
on a CBOM built offline by the toolkit's own builder.

Entry profile (interface-enumeration v0.3) must CONFORM (exit 0). The baseline (interface-disclosure
v0.9) is checked for the two failures an outside scan cannot close on its own, and nothing else.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
VENDOR = ROOT / "third_party" / "pkic-cbom"
sys.path.insert(0, str(ROOT / "scripts"))
import tier2_pipeline as tp  # noqa: E402


def write_cbom(d, kex):
    b = tp.CBOM("prod-edge.example.com", "1", {})
    b.subject_tag = tp.default_subject_tag("prod-edge.example.com", date="2026-11-14")
    b.add_certificate({"host": "a.example.com", "subject": "a", "issuer": "CA", "key_alg": "id-ecPublicKey",
                       "key_bits": 256, "sig_alg": "ecdsa-with-SHA256"})
    b.add_tls_kex("a.example.com", kex, "TLSv1.3", "TLS_AES_256_GCM_SHA384")
    path = os.path.join(d, "cbom.json")
    with open(path, "w") as f:
        json.dump(b.to_dict(), f)
    return path


def validate(cbom, profile):
    r = subprocess.run([sys.executable, "-I", str(VENDOR / "validate_cbom.py"), cbom,
                        str(VENDOR / f"profile-{profile}.rules.json"), "--json"],
                       capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout


class PkicConformance(unittest.TestCase):
    def test_entry_profile_conforms(self):
        with tempfile.TemporaryDirectory() as d:
            code, out = validate(write_cbom(d, "X25519MLKEM768"), "interface-enumeration")
        self.assertEqual(code, 0, out[-2000:])

    def test_baseline_only_fails_on_what_an_outside_scan_cannot_know(self):
        with tempfile.TemporaryDirectory() as d:
            code, out = validate(write_cbom(d, "X25519MLKEM768"), "interface-disclosure")
        self.assertEqual(code, 1)
        rep = json.loads(out)["report"]
        failed = {r["id"].rsplit("#", 1)[-1] for r in rep["product"] if r["level"] == "MUST" and not r["ok"]}
        for iface in rep["interfaces"]:
            failed |= {r["id"].rsplit("#", 1)[-1] for r in iface["rows"] if r["level"] == "MUST" and not r["ok"]}
        # Key exchange observed, so only the server's implementation package remains unknown.
        self.assertEqual(failed, {"I9"}, failed)

    def test_unobserved_key_exchange_is_reported_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            code, out = validate(write_cbom(d, None), "interface-disclosure")
        rows = json.loads(out)["report"]["interfaces"][0]["rows"]
        i3 = next(r for r in rows if r["id"].endswith("#I3"))
        self.assertEqual((i3["ok"], i3["state"]), (False, "unknown"))


if __name__ == "__main__":
    unittest.main()
