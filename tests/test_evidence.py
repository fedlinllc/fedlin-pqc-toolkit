"""CycloneDX component evidence: how each record was observed (1.1). Offline."""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import evidence as ev  # noqa: E402
import policy  # noqa: E402
import report  # noqa: E402
import tier2_pipeline as tp  # noqa: E402


def _methods(c):
    return {(m["technique"], m["confidence"], m["value"].split(":", 1)[0].split("/", 1)[1])
            for i in c["evidence"]["identity"] for m in i["methods"]}


def _by_ref(doc):
    return {c["bom-ref"]: c for c in doc["components"]}


def _bench():
    b = tp.CBOM("ev", "1", {})
    b.add_certificate({"host": "a.example.com", "subject": "a", "issuer": "CA", "key_alg": "rsaEncryption",
                       "key_bits": 2048, "sig_alg": "sha256WithRSAEncryption", "fingerprint": "ab" * 32})
    b.add_tls_kex("a.example.com", "X25519MLKEM768", "TLSv1.3", "TLS_AES_256_GCM_SHA384")
    b.add_certificate({"host": "a.example.com", "subject": "a", "issuer": "CA", "key_alg": "id-ecPublicKey",
                       "key_bits": 256, "sig_alg": "ecdsa-with-SHA256", "fingerprint": "cd" * 32}, extra="ECDSA")
    b.add_ssh({"version": "OpenSSH_9.9", "kex": ["mlkem768x25519-sha256"], "hostkeys": ["ssh-ed25519"],
               "ciphers": ["aes256-gcm@openssh.com"]})
    b.add_sealed_secrets(3)
    return b.to_dict()


class Builder(unittest.TestCase):
    def setUp(self):
        self.doc = _bench()
        self.c = _by_ref(self.doc)

    def test_every_record_states_its_evidence(self):
        for c in self.doc["components"]:
            self.assertTrue(ev.has_identity(c), c["bom-ref"])

    def test_handshake_records(self):
        cert = self.c["crypto/cert/a-example-com"]
        self.assertEqual(_methods(cert), {("dynamic-analysis", 1.0, "handshake")})
        self.assertEqual(cert["evidence"]["occurrences"], [{"location": "a.example.com"}])
        self.assertEqual(_methods(self.c["crypto/proto/tls/a-example-com"]),
                         {("dynamic-analysis", 1.0, "handshake")})
        self.assertIn(("dynamic-analysis", 1.0, "handshake"),
                      _methods(self.c["crypto/algo/x25519mlkem768"]))

    def test_extra_certificate_is_probe(self):
        extra = [c for r, c in self.c.items() if r.startswith("crypto/cert/a-example-com-ecdsa")][0]
        self.assertEqual(_methods(extra), {("dynamic-analysis", 1.0, "probe")})

    def test_ssh_is_configuration(self):
        self.assertEqual(_methods(self.c["crypto/proto/ssh"]), {("other", 0.8, "configuration")})
        self.assertEqual(_methods(self.c["crypto/algo/ssh-ed25519"]), {("other", 0.8, "configuration")})
        self.assertNotIn("occurrences", self.c["crypto/proto/ssh"]["evidence"])  # a command is not a location

    def test_assumption_is_lowest_and_shared_algorithm_keeps_both(self):
        key = self.c["crypto/material/sealed-secrets-key"]
        self.assertEqual(_methods(key), {("other", 0.1, "assumption")})
        rsa4096 = self.c["crypto/algo/rsaencryption-4096"]
        self.assertEqual(rsa4096["evidence"]["identity"][0]["confidence"], 0.1)
        self.assertEqual(ev.sources_of(key), ["assumption"])

    def test_stamp_is_idempotent_and_confidence_is_max(self):
        c = {"type": "cryptographic-asset", "name": "RSA"}
        ev.stamp(c, "dependency")
        ev.stamp(c, "dependency")
        ev.stamp(c, "handshake", "h:8443")
        ev.stamp(c, "handshake", "h:8443")
        ident = c["evidence"]["identity"]
        self.assertEqual(len(ident), 1)
        self.assertEqual(len(ident[0]["methods"]), 2)
        self.assertEqual(ident[0]["confidence"], 1.0)
        self.assertEqual(c["evidence"]["occurrences"], [{"location": "h:8443"}])
        self.assertEqual(ev.sources_of(c), ["handshake", "dependency"])

    def test_verdicts_do_not_depend_on_evidence(self):
        stripped = json.loads(json.dumps(self.doc))
        for c in stripped["components"]:
            c.pop("evidence", None)
        with tempfile.TemporaryDirectory() as d:
            pa, pb = os.path.join(d, "a.json"), os.path.join(d, "b.json")
            for p, doc in ((pa, self.doc), (pb, stripped)):
                with open(p, "w") as f:
                    json.dump(doc, f)
            a = policy.evaluate(pa, "civilian")
            b = policy.evaluate(pb, "civilian")
        strip = lambda r: [{k: v for k, v in f.items() if k != "document"} for f in r["findings"]]  # noqa: E731
        self.assertEqual(strip(a), strip(b))


class Paths(unittest.TestCase):
    def test_placeholder_name_claims_no_identity(self):
        b = tp.CBOM("ev", "1", {})
        b.add_certificate({"host": "pq.example.com", "subject": "s", "issuer": "CA",
                           "key_alg": "unparsed-public-key-algorithm", "sig_alg": None, "fingerprint": "ef" * 32})
        c = _by_ref(b.to_dict())["crypto/algo/unparsed-public-key-algorithm"]
        self.assertNotIn("identity", c["evidence"])
        self.assertEqual(c["evidence"]["occurrences"], [{"location": "pq.example.com"}])
        self.assertEqual(ev.sources_of(c), ["name not parsed"])

    def test_interface_with_enumeration_is_handshake_only(self):
        # the interface's own facts are the recorded session; enumeration results are properties on it
        en = {"status": "complete", "client": "bundled", "tool": "openssl 3.5", "versions": {"TLSv1.2": True},
              "suites": {}, "groups": {}, "certs": []}
        b = tp.CBOM("ev", "1", {})
        b.add_certificate({"host": "old.example.com", "subject": "s", "issuer": "CA", "key_alg": "rsaEncryption",
                           "key_bits": 2048, "sig_alg": "sha256WithRSAEncryption", "fingerprint": "01" * 32})
        b.add_tls_kex("old.example.com", "secp256r1", "TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", None, None, en)
        c = _by_ref(b.to_dict())
        self.assertEqual({m[2] for m in _methods(c["crypto/proto/tls/old-example-com"])}, {"handshake"})
        self.assertEqual({m[2] for m in _methods(c["crypto/cert/old-example-com"])}, {"handshake"})

    def test_shared_algorithm_lists_every_method_and_location(self):
        b = tp.CBOM("ev", "1", {})
        for h in ("a.example.com", "b.example.com"):
            b.add_certificate({"host": h, "subject": "s", "issuer": "CA", "key_alg": "rsaEncryption",
                               "key_bits": 4096, "sig_alg": None, "fingerprint": "02" * 32})
        b.add_sealed_secrets(1)
        rsa = _by_ref(b.to_dict())["crypto/algo/rsaencryption-4096"]
        self.assertEqual({m[2] for m in _methods(rsa)}, {"handshake", "assumption"})
        self.assertEqual(rsa["evidence"]["identity"][0]["confidence"], 1.0)
        self.assertEqual([o["location"] for o in rsa["evidence"]["occurrences"]],
                         ["a.example.com", "b.example.com"])

    def test_exclude_never_drops_runtime_records(self):
        b = tp.CBOM("ev", "1", {})
        for h in ("www.agency.gov", "docs.agency.gov"):
            b.add_certificate({"host": h, "subject": "s", "issuer": "CA", "key_alg": "rsaEncryption",
                               "key_bits": 2048, "sig_alg": "sha256WithRSAEncryption", "fingerprint": "03" * 32})
            b.add_tls_kex(h, "X25519MLKEM768", "TLSv1.3", "TLS_AES_256_GCM_SHA384")
        runtime = b.to_dict()
        scanned = {"type": "cryptographic-asset", "bom-ref": "theia-1", "name": "RSA",
                   "evidence": {"occurrences": [{"location": "docs/example-hit.txt"}]}}
        final = json.loads(json.dumps(runtime))
        final["components"].append(scanned)
        keep = {c["bom-ref"] for c in runtime["components"]}
        for pat in ("docs", "*.gov", "agency"):
            doc = json.loads(json.dumps(final))
            dropped = tp.filter_excluded(doc, [pat], keep)
            self.assertEqual({c["bom-ref"] for c in doc["components"]} - {"theia-1"}, keep, pat)
            self.assertEqual(dropped, 1 if pat == "docs" else 0, pat)

    def test_windows_collector_selector(self):
        win = {"type": "cryptographic-asset",
               "properties": [{"name": "fedlin:source", "value": "windows-collector (LocalMachine My)"}]}
        other = {"type": "cryptographic-asset", "properties": [{"name": "fedlin:source", "value": "cbomkit"}]}
        self.assertTrue(tp._is_windows_collector(win))
        self.assertFalse(tp._is_windows_collector(other))
        doc = {"components": [win, other]}
        self.assertEqual(ev.stamp_missing(doc, "configuration", tp._is_windows_collector), 1)
        self.assertEqual(ev.sources_of(win), ["configuration"])


class Merged(unittest.TestCase):
    def test_restore_puts_back_occurrence_detail(self):
        rich = {"location": "src/Main.java", "line": 42, "offset": 7, "symbol": "gen", "additionalContext": "ctx"}
        orig = {"components": [{"type": "cryptographic-asset", "bom-ref": "x", "name": "RSA",
                                "evidence": {"occurrences": [rich]}}]}
        merged = {"components": [{"type": "cryptographic-asset", "bom-ref": "x", "name": "RSA",
                                  "evidence": {"occurrences": [{"location": "src/Main.java"}]}}]}
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "o.json")
            with open(p, "w") as f:
                json.dump(orig, f)
            self.assertEqual(ev.restore(merged, [p]), 1)
        self.assertEqual(merged["components"][0]["evidence"]["occurrences"], [rich])

    def test_restore_skips_conflicting_refs(self):
        a = {"components": [{"bom-ref": "x", "evidence": {"occurrences": [{"location": "a"}]}}]}
        b = {"components": [{"bom-ref": "x", "evidence": {"occurrences": [{"location": "b"}]}}]}
        merged = {"components": [{"bom-ref": "x", "evidence": {"occurrences": [{"location": "m"}]}}]}
        with tempfile.TemporaryDirectory() as d:
            paths = []
            for i, doc in enumerate((a, b)):
                paths.append(os.path.join(d, f"{i}.json"))
                with open(paths[-1], "w") as f:
                    json.dump(doc, f)
            self.assertEqual(ev.restore(merged, paths), 0)
        self.assertEqual(merged["components"][0]["evidence"]["occurrences"], [{"location": "m"}])

    def test_nested_components(self):
        doc = {"components": [{"type": "library", "name": "x", "components": [
            {"type": "cryptographic-asset", "name": "RSA"}]}]}
        self.assertEqual(ev.stamp_missing(doc, "file"), 1)
        self.assertEqual(ev.summarize(doc), {"file": 1})


    def test_foreign_evidence_is_kept(self):
        foreign = {"type": "cryptographic-asset", "name": "AES",
                   "evidence": {"identity": [{"field": "name", "confidence": 0.5,
                                              "methods": [{"technique": "source-code-analysis",
                                                           "confidence": 0.5, "value": "cbomkit"}]}]}}
        bare = {"type": "cryptographic-asset", "name": "RSA"}
        lib = {"type": "library", "name": "openssl"}
        doc = {"components": [foreign, bare, lib]}
        self.assertEqual(ev.stamp_missing(doc, "file"), 1)
        self.assertEqual(len(foreign["evidence"]["identity"][0]["methods"]), 1)
        self.assertEqual(ev.sources_of(foreign), ["other tool"])
        self.assertEqual(ev.sources_of(bare), ["file"])
        self.assertNotIn("evidence", lib)
        self.assertEqual(ev.summarize(doc), {"file": 1, "other tool": 1})

    def test_normalize_restores_list_form(self):
        # cyclonedx-cli merge writes identity as a single object
        doc = {"components": [{"type": "cryptographic-asset", "name": "RSA",
                               "evidence": {"identity": {"field": "name", "methods": []}}}]}
        self.assertEqual(ev.normalize(doc), 1)
        self.assertIsInstance(doc["components"][0]["evidence"]["identity"], list)
        self.assertEqual(ev.sources_of({"type": "cryptographic-asset"}), ["not stated"])

    def test_dependency_capability(self):
        doc = {"components": [{"type": "library", "name": "liboqs"}]}
        self.assertTrue(tp.detect_library_crypto(doc))
        for c in doc["components"][1:]:
            self.assertEqual({m[2] for m in _methods(c)}, {"dependency"})
            self.assertEqual(c["evidence"]["identity"][0]["confidence"], 0.3)


class Report(unittest.TestCase):
    def test_section_and_summary(self):
        doc = _bench()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "cbom.json")
            with open(p, "w") as f:
                json.dump(doc, f)
            view, _ = policy.load_view(p, None)
            md, summary = report.build_report(view)
        self.assertIn("## How each record was observed", md)
        self.assertIn("| Observed in a handshake with the endpoint, recorded as its session or certificate "
                      "| dynamic-analysis | 1.0 |", md)
        self.assertIn("Every cryptographic record in this inventory states", md)
        self.assertEqual(summary["evidence"]["assumption"], 2)  # the sealing key and its assumed RSA-4096
        self.assertEqual(sum(summary["evidence"].values()),
                         sum(1 for c in doc["components"] if c["type"] == "cryptographic-asset"))



class SshMacsAndHostKeys180(unittest.TestCase):
    """1.8.0 (#632): SSH MACs and host key sizes are captured from sshd -T and the host keys' .pub files."""

    def test_capture_and_verdicts(self):
        import tempfile as _tf
        from unittest import mock
        sshd = ("kexalgorithms mlkem768x25519-sha256,curve25519-sha256\nciphers aes256-gcm@openssh.com\n"
                "macs hmac-sha2-256-etm@openssh.com,hmac-md5\nhostkeyalgorithms rsa-sha2-512,ssh-ed25519\n"
                "hostkey /etc/ssh/ssh_host_rsa_key\nhostkey /etc/ssh/ssh_host_ed25519_key\n"
                "hostkey /etc/ssh/ssh_host_ecdsa_key\n")
        keygen = {"/etc/ssh/ssh_host_rsa_key.pub": "1024 SHA256:abc root@h (RSA)",
                  "/etc/ssh/ssh_host_ed25519_key.pub": "256 SHA256:def root@h (ED25519)",
                  "/etc/ssh/ssh_host_ecdsa_key.pub": "384 SHA256:ghi root@h (ECDSA)"}
        seen = []

        def fake(cmd, *a, **k):
            seen.append(cmd)
            if "sshd -T" in cmd:
                return sshd
            if cmd.startswith("ssh -V"):
                return "OpenSSH_9.9p1"
            for path, out in keygen.items():
                if path in cmd:
                    return out
            return ""
        with mock.patch.object(tp, "run", side_effect=fake):
            ssh = tp.capture_ssh()
        self.assertEqual(ssh["macs"], ["hmac-sha2-256-etm@openssh.com", "hmac-md5"])
        self.assertEqual([(k["name"], k["bits"]) for k in ssh["hostkey_sizes"]],
                         [("rsaEncryption", 1024), ("ssh-ed25519", 256), ("ecdsa-sha2-nistp384", 384)])
        self.assertFalse(any("ssh-keygen" in c and not c.split("-f ", 1)[1].split()[0].strip("'").endswith(".pub")
                             for c in seen))                      # never the private key
        b = tp.CBOM("ssh", "1", {})
        b.add_ssh(ssh)
        with _tf.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            with open(p, "w") as f:
                json.dump(b.to_dict(), f)
            import policy
            fs = {(x["name"], x.get("canonical")): x for x in policy.evaluate(p)["findings"]}
        prio = {k[0]: v["priority"] for k, v in fs.items()}
        self.assertEqual(prio["rsaEncryption"], "Critical")          # 1024-bit RSA host key
        self.assertEqual(prio["hmac-md5"], "Critical")
        self.assertIn("ecdsa-sha2-nistp384", prio)

    def test_keygen_parse(self):
        self.assertIsNone(tp._ssh_key_size(""))
        self.assertIsNone(tp._ssh_key_size("not a key"))
        self.assertEqual(tp._ssh_key_size("3072 SHA256:x a b (RSA)")["bits"], 3072)
        self.assertEqual(tp._ssh_key_size("4096 SHA256:x (XYZ)")["name"], "unparsed-public-key-algorithm (XYZ)")


if __name__ == "__main__":
    unittest.main()
