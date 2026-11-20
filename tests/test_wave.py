"""Migration wave check (fedlin.pqc-wave 1.0): declared end state against a later scan. Offline."""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import tier2_pipeline as tp  # noqa: E402
import wave  # noqa: E402
try:
    import wave_draft  # noqa: E402  (private: not in the public tree)
except ImportError:
    wave_draft = None

OLD_FP, NEW_FP = "aa" * 32, "bb" * 32
HOST = "svc.example.com"
PROBES = {"RSA": "refused", "ECDSA": "refused", "EdDSA": "refused", "ML-DSA": "certificate", "ANY": "certificate"}
ENUM_PQ = {"status": "complete", "client": "bundled", "tool": "openssl 3.5", "versions": {"TLSv1.3": True},
           "suites": {}, "groups": {"X25519MLKEM768": True, "SecP384r1MLKEM1024": False, "x25519": False},
           "cert_probes": PROBES}
ENUM_CLASSIC = {"status": "complete", "client": "bundled", "tool": "openssl 3.5", "versions": {"TLSv1.2": True},
                "suites": {}, "groups": {"X25519MLKEM768": False, "secp256r1": True},
                "cert_probes": dict(PROBES, RSA="certificate", **{"ML-DSA": "refused"})}


def cert(host, key, bits, sig, fp, extra=None):
    return ({"host": host, "subject": "s", "issuer": "CA", "key_alg": key, "key_bits": bits, "sig_alg": sig,
             "fingerprint": fp}, extra)


def build(certs, kex=None, proto="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", classical=None, enum=None,
          host=HOST, ts="2026-03-01T00:00:00Z", partial=None):
    b = tp.CBOM("w", "1", {})
    for c, extra in certs:
        b.add_certificate(c, extra=extra)
    b.add_tls_kex(host, kex, proto, cipher, partial, {"outcome": classical} if classical else None, enum)
    d = b.to_dict()
    d["metadata"]["timestamp"] = ts
    return d


def before_doc(enum=None):
    return build([cert(HOST, "rsaEncryption", 2048, "sha256WithRSAEncryption", OLD_FP)], "secp256r1", "TLSv1.2",
                 "ECDHE-RSA-AES128-GCM-SHA256", "accepted", enum, ts="2026-01-01T00:00:00Z")


def after_doc(classical="rejected", key="ML-DSA-65", sig="ML-DSA-65", enum=ENUM_PQ, extra_old=False, fp=None, **kw):
    host = kw.get("host", HOST)
    fp = fp or (NEW_FP if key.startswith("ML") else "dd" * 32)   # a different key is a different certificate
    certs = [cert(host, key, 2048 if key == "rsaEncryption" else None, sig, fp)]
    if extra_old:   # the old RSA certificate is still served to RSA-only clients
        certs.append(cert(host, "rsaEncryption", 2048, "sha256WithRSAEncryption", OLD_FP, extra="RSA"))
    return build(certs, kw.pop("kex", "X25519MLKEM768"), classical=classical, enum=enum, **kw)


WAVE = {"schema": "fedlin.pqc-wave", "schemaVersion": "1.0", "wave": "Wave 1", "profile": "civilian",
        "items": [
            {"id": "a", "endpoint": HOST + ":443", "check": "findings-resolved", "priorities": ["High"],
             "lanes": ["key-establishment", "signature", "public-key"]},
            {"id": "b", "endpoint": HOST, "check": "mlkem"},
            {"id": "c", "endpoint": HOST.upper(), "check": "refuses-classical-only"},
            {"id": "d", "endpoint": "https://" + HOST + "/", "check": "certificate-replaced",
             "baselineFingerprint": ":".join(OLD_FP[i:i + 2] for i in range(0, 64, 2)), "keyAlgorithm": "ML-DSA"},
        ]}


def items(*its, profile="civilian"):
    return dict(WAVE, profile=profile, items=list(its))


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)

    def put(self, name, obj):
        p = os.path.join(self.d.name, name)
        with open(p, "w") as f:
            json.dump(obj, f)
        return p

    def run_check(self, after, wave_doc=WAVE, before=None):
        b = self.put("before.json", before) if before else None
        r = wave.check(self.put("wave.json", wave_doc), self.put("after.json", after), b)
        return r, {i["id"]: i for i in r["items"]}


class Checks(Base):
    def test_all_pass_after_the_work(self):
        r, it = self.run_check(after_doc(), before=before_doc())
        self.assertTrue(r["passed"], r)
        self.assertEqual({i["status"] for i in it.values()}, {"pass"})
        self.assertEqual(r["regressions"], [])
        self.assertEqual(set(r["documents"]), {"wave", "cbom", "baseline"})
        self.assertTrue(r["rulesetDigest"])
        self.assertEqual(r["documents"]["cbom"]["toolkitVersion"], tp.TOOLKIT_VERSION)

    def test_nothing_passes_before_the_work(self):
        r, it = self.run_check(before_doc(enum=ENUM_CLASSIC))
        self.assertFalse(r["passed"])
        self.assertEqual({k: v["status"] for k, v in it.items()}, {"a": "fail", "b": "fail", "c": "fail", "d": "fail"})
        self.assertTrue(it["a"]["remaining"])

    def test_classical_still_accepted_fails_only_that_item(self):
        r, it = self.run_check(after_doc(classical="accepted"))
        self.assertEqual(it["c"]["status"], "fail")
        self.assertEqual([it[k]["status"] for k in "abd"], ["pass"] * 3)

    def test_inconclusive_probe_proves_nothing(self):
        _, it = self.run_check(after_doc(classical="inconclusive"))
        self.assertEqual(it["c"]["status"], "not-observed")

    def test_mlkem_accepts_mode(self):
        w = items({"id": "x", "endpoint": HOST, "check": "mlkem", "mode": "accepts"})
        self.assertEqual(self.run_check(before_doc(enum=ENUM_CLASSIC), w)[1]["x"]["status"], "fail")
        self.assertEqual(self.run_check(before_doc(), w)[1]["x"]["status"], "not-observed")
        acc = dict(ENUM_CLASSIC, groups={"X25519MLKEM768": True, "secp256r1": True})
        r = self.run_check(before_doc(enum=acc), w)[1]["x"]
        self.assertEqual(r["status"], "pass")
        self.assertIn("accepted", r["detail"])

    def test_mlkem_respects_nss_profile(self):
        w = items({"id": "x", "endpoint": HOST, "check": "mlkem", "mode": "accepts"}, profile="nss")
        self.assertEqual(self.run_check(after_doc(), w)[1]["x"]["status"], "fail")   # 768 is not 1024
        self.assertEqual(self.run_check(after_doc(kex="SecP384r1MLKEM1024"), w)[1]["x"]["status"], "pass")

    def test_unknown_key_exchange_is_not_observed(self):
        w = items({"id": "x", "endpoint": HOST, "check": "mlkem"},
                  {"id": "y", "endpoint": HOST, "check": "findings-resolved", "priorities": ["High"],
                   "lanes": ["key-establishment"]})
        _, it = self.run_check(after_doc(kex=None, partial="FIPS-mode client could not offer it"), w)
        self.assertEqual(it["x"]["status"], "not-observed")
        self.assertEqual(it["y"]["status"], "not-observed")


class Certificates(Base):
    def test_old_certificate_still_served_to_rsa_clients(self):
        _, it = self.run_check(after_doc(extra_old=True))
        self.assertEqual(it["d"]["status"], "fail")
        self.assertEqual(it["a"]["status"], "fail")

    def test_without_enumeration_replacement_is_unproven(self):
        r, it = self.run_check(after_doc(enum=None))
        self.assertEqual(it["d"]["status"], "not-observed")
        self.assertEqual(it["a"]["status"], "not-observed")
        self.assertFalse(r["passed"])

    def test_renewal_with_same_key_type_fails_target(self):
        _, it = self.run_check(after_doc(key="rsaEncryption", sig="sha256WithRSAEncryption"))
        self.assertEqual(it["d"]["status"], "fail")
        self.assertIn("no served certificate has key ML-DSA", it["d"]["detail"])

    def test_fingerprints_compared_normalized(self):
        doc = after_doc(extra_old=True)
        for c in doc["components"]:
            for p in c.get("properties", []):
                if p["name"] == "fedlin:sha256Fingerprint" and p["value"] == OLD_FP:
                    p["value"] = ":".join(OLD_FP[i:i + 2] for i in range(0, 64, 2)).upper()
        self.assertEqual(self.run_check(doc)[1]["d"]["status"], "fail")

    def test_algorithm_matching(self):
        m = wave.same_algorithm
        self.assertTrue(m("ML-DSA", "ML-DSA-65"))
        self.assertTrue(m("ML-DSA-65", "ML-DSA-65"))
        self.assertFalse(m("ML-DSA-87", "ML-DSA-65"))
        self.assertFalse(m("DSA", "ML-DSA-65"))
        self.assertFalse(m("ML-DSA-65", "id-MLDSA65-RSA3072-PSS-SHA512"))
        self.assertFalse(m("RSA-3072", "rsaEncryption", 2048))
        self.assertTrue(m("RSA-3072", "rsaEncryption", 3072))
        self.assertTrue(m("ECDSA", "id-ecPublicKey", 256))
        self.assertTrue(m("P-384", "id-ecPublicKey", 384))
        self.assertFalse(m("secp384r1", "id-ecPublicKey", 256))
        self.assertFalse(m("ecdsa-with-SHA384", "ecdsa-with-SHA256"))
        self.assertFalse(m("sha384WithRSAEncryption", "sha256WithRSAEncryption"))
        self.assertTrue(m("sha384WithRSAEncryption", "sha384WithRSAEncryption"))


class Evidence(Base):
    def test_missing_endpoint_is_not_observed_never_fixed(self):
        w = items({"id": "x", "endpoint": "gone.example.com", "check": "findings-resolved",
                   "priorities": ["Critical", "High"]})
        r, it = self.run_check(after_doc(), w)
        self.assertEqual(it["x"]["status"], "not-observed")
        self.assertFalse(r["passed"])

    def test_records_without_fresh_evidence_prove_nothing(self):
        doc = after_doc()
        for c in doc["components"]:
            c.pop("evidence", None)
        _, it = self.run_check(doc)
        self.assertEqual({i["status"] for i in it.values()}, {"not-observed"})

    def test_records_from_another_scan_do_not_count(self):
        doc = after_doc(host="other.example.com")
        old = after_doc()
        doc["components"] += [c for c in old["components"] if c["bom-ref"].startswith(("crypto/cert/", "crypto/proto/"))]
        _, it = self.run_check(doc)
        self.assertEqual({i["status"] for i in it.values()}, {"not-observed"})

    def test_default_lanes_include_unclassified_findings(self):
        doc = after_doc(key="unparsed-public-key-algorithm", sig="1.2.3.4.5")
        w = items({"id": "r", "endpoint": HOST, "check": "findings-resolved", "priorities": ["Review"]})
        self.assertEqual(self.run_check(doc, w)[1]["r"]["status"], "fail")

    def test_ipv6_endpoints(self):
        self.assertEqual(wave.endpoint_key("[2001:DB8::1]:443"), "[2001:db8::1]")
        self.assertEqual(wave.endpoint_key("2001:db8::1"), "[2001:db8::1]")
        self.assertEqual(wave.endpoint_key("[2001:db8::1]:8443"), "[2001:db8::1]:8443")
        doc = after_doc(host="[2001:db8::1]")
        w = items({"id": "x", "endpoint": "2001:db8::1", "check": "mlkem"})
        self.assertEqual(self.run_check(doc, w)[1]["x"]["status"], "pass")


class Regressions(Base):
    def test_regression_against_baseline(self):
        before = after_doc(ts="2026-02-01T00:00:00Z")
        after = after_doc(key="rsaEncryption", sig="sha256WithRSAEncryption")
        r, it = self.run_check(after, items({"id": "b", "endpoint": HOST, "check": "mlkem"}), before)
        self.assertEqual(it["b"]["status"], "pass")
        self.assertIn("rsaEncryption", {x["name"] for x in r["regressions"]})
        self.assertFalse(r["passed"])

    def test_only_what_the_baseline_could_see(self):
        before = build([cert(HOST, "ML-DSA-65", None, "ML-DSA-65", OLD_FP)], None, classical="rejected",
                       ts="2026-01-01T00:00:00Z", partial="FIPS")
        r, _ = self.run_check(after_doc(kex="secp256r1"), items({"id": "b", "endpoint": HOST, "check": "mlkem"}),
                              before)
        self.assertEqual(r["regressions"], [])

    def test_baseline_must_be_older_and_match_the_wave(self):
        with self.assertRaises(wave.WaveError):
            self.run_check(before_doc(), before=after_doc())
        w = dict(WAVE, baseline={"file": "x.json", "sha256": "0" * 64})
        with self.assertRaises(wave.WaveError):
            self.run_check(after_doc(), w, before_doc())


class BaselineIdentity(Base):
    """1.7.0: a re-serialised planning baseline is recognised by serial number and timestamp, not only bytes."""

    def wave_for(self, doc):
        return dict(WAVE, schemaVersion="1.1", baseline={
            "file": "before.json", "sha256": "0" * 64, "serialNumber": doc["serialNumber"],
            "timestamp": doc["metadata"]["timestamp"]})

    def test_reserialised_baseline_is_refused(self):
        b = before_doc()
        with self.assertRaises(wave.WaveError) as e:
            self.run_check(json.loads(json.dumps(b, indent=4)), self.wave_for(b))
        self.assertIn("serial number", str(e.exception))

    def test_reserialised_baseline_given_as_baseline_is_accepted(self):
        b = before_doc()
        r, _ = self.run_check(after_doc(), self.wave_for(b), json.loads(json.dumps(b, indent=4)))
        self.assertIn("baseline", r["documents"])

    def test_draft_records_identity_and_10_still_loads(self):
        if wave_draft is None:
            self.skipTest("wave_draft.py is not in the public tree")
        p = self.put("b.json", before_doc())
        d = wave_draft.draft(p, 1)
        self.assertEqual(d["schemaVersion"], "1.1")
        self.assertIn("serialNumber", d["baseline"])
        wave.load_wave(self.put("w10.json", WAVE))           # a 1.0 wave file is still read
        with self.assertRaises(wave.WaveError):
            wave.load_wave(self.put("w10b.json", dict(WAVE, baseline={"sha256": "0" * 64, "serialNumber": "x"})))

    def test_schema_11(self):
        with open(os.path.join(ROOT, "schemas", "wave-1.1.schema.json")) as f:
            sch = json.load(f)
        self.assertEqual(set(sch["properties"]["baseline"]["properties"]),
                         {"file", "sha256", "serialNumber", "timestamp"})
        self.assertEqual(sch["properties"]["schemaVersion"]["enum"], list(wave.SCHEMA_VERSIONS))


class Round2(Base):
    def test_unanswered_certificate_probe_proves_nothing(self):
        # the old RSA certificate may still be served, but the RSA probe got no answer
        en = dict(ENUM_PQ, cert_probes=dict(PROBES, RSA=None))
        r, it = self.run_check(after_doc(enum=en))
        self.assertEqual(it["d"]["status"], "not-observed")
        self.assertEqual(it["a"]["status"], "not-observed")
        self.assertFalse(r["passed"])

    def test_truncated_suites_do_not_block_certificate_and_group_checks(self):
        en = dict(ENUM_PQ, truncated=["TLSv1.2"])
        _, it = self.run_check(after_doc(enum=en, kex="secp256r1"),
                               items(dict(WAVE["items"][3]), {"id": "m", "endpoint": HOST, "check": "mlkem",
                                                              "mode": "accepts"},
                                     {"id": "f", "endpoint": HOST, "check": "findings-resolved",
                                      "priorities": ["High"], "lanes": ["configuration"]}))
        self.assertEqual(it["d"]["status"], "pass")
        self.assertEqual(it["m"]["status"], "pass")
        self.assertIn(it["f"]["status"], ("fail", "not-observed"))   # configuration needs untruncated
        self.assertNotEqual(it["f"]["status"], "pass")

    def test_mlkem_accepts_untested_groups_are_not_a_fail(self):
        en = dict(ENUM_CLASSIC, groups={"X25519MLKEM768": None, "secp256r1": True})
        w = items({"id": "x", "endpoint": HOST, "check": "mlkem", "mode": "accepts"})
        self.assertEqual(self.run_check(before_doc(enum=en), w)[1]["x"]["status"], "not-observed")

    def test_baseline_from_toolkit_1_1(self):
        before = after_doc(ts="2026-02-01T00:00:00Z")
        for c in before["components"]:
            c["properties"] = [p for p in c.get("properties", []) if p["name"] != "fedlin:observedIn"]
        after = after_doc(key="rsaEncryption", sig="sha256WithRSAEncryption")
        r, _ = self.run_check(after, items({"id": "b", "endpoint": HOST, "check": "mlkem"}), before)
        self.assertIn("rsaEncryption", {x["name"] for x in r["regressions"]})

    def test_primary_certificate_regression_without_baseline_enumeration(self):
        before = after_doc(enum=None, ts="2026-02-01T00:00:00Z")
        after = after_doc(key="rsaEncryption", sig="sha256WithRSAEncryption", enum=None)
        r, _ = self.run_check(after, items({"id": "b", "endpoint": HOST, "check": "mlkem"}), before)
        self.assertIn("rsaEncryption", {x["name"] for x in r["regressions"]})
        self.assertTrue(r["notCompared"])                                   # configuration was not compared
        self.assertIn("configuration", r["notCompared"][0]["lanes"])

    def test_broken_to_vulnerable_is_progress_not_regression(self):
        before = build([cert(HOST, "rsaEncryption", 1024, "sha1WithRSAEncryption", OLD_FP)], "X25519MLKEM768",
                       classical="rejected", enum=dict(ENUM_PQ, cert_probes=dict(PROBES, RSA="certificate")),
                       ts="2026-01-01T00:00:00Z")
        after = build([cert(HOST, "id-ecPublicKey", 256, "ecdsa-with-SHA256", NEW_FP)], "X25519MLKEM768",
                      classical="rejected", enum=dict(ENUM_PQ, cert_probes=dict(PROBES, ECDSA="certificate")))
        w = items({"id": "c", "endpoint": HOST, "check": "certificate-replaced", "baselineFingerprint": OLD_FP},
                  {"id": "f", "endpoint": HOST, "check": "findings-resolved", "priorities": ["Critical"]})
        r, it = self.run_check(after, w, before)
        self.assertEqual(r["regressions"], [])
        self.assertEqual(it["c"]["status"], "pass")

    def test_unclassifiable_certificate_algorithm_is_not_observed(self):
        _, it = self.run_check(after_doc(key="2.16.840.1.101.3.4.3.99", sig="2.16.840.1.101.3.4.3.99"))
        self.assertEqual(it["d"]["status"], "not-observed")

    def test_classical_refusal_contradicted_by_enumeration(self):
        _, it = self.run_check(after_doc(enum=dict(ENUM_PQ, groups={"X25519MLKEM768": True, "x25519": True})))
        self.assertEqual(it["c"]["status"], "fail")                     # x25519 alone was accepted
        _, it = self.run_check(after_doc(enum=dict(ENUM_PQ, versions={"TLSv1.3": True, "TLSv1.2": True})))
        self.assertEqual(it["c"]["status"], "fail")                     # TLS 1.2 has no ML-KEM key exchange
        _, it = self.run_check(after_doc(enum=dict(ENUM_PQ, dh_bits=[2048])))
        self.assertEqual(it["c"]["status"], "fail")
        _, it = self.run_check(after_doc(enum=dict(ENUM_PQ, groups={"X25519MLKEM768": True, "x25519": False})))
        self.assertEqual(it["c"]["status"], "pass")

    def test_variants_do_not_match(self):
        m = wave.same_algorithm
        self.assertFalse(m("SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s"))
        self.assertFalse(m("sha256WithRSAEncryption", "RSASSA-PSS"))
        self.assertFalse(m("ML-DSA-65", "HashML-DSA-65"))

    def test_wave_and_timestamp_guards(self):
        a = after_doc()
        p = self.put("after.json", a)
        import hashlib
        with open(p, "rb") as f:
            same = hashlib.sha256(f.read()).hexdigest()
        with self.assertRaises(wave.WaveError):
            wave.check(self.put("w.json", dict(WAVE, baseline={"file": "after.json", "sha256": same})), p)
        b = before_doc()
        del b["metadata"]["timestamp"]
        with self.assertRaises(wave.WaveError):
            self.run_check(after_doc(), before=b)

    def test_keys_that_do_not_apply_are_rejected(self):
        with self.assertRaises(wave.WaveError):
            wave.load_wave(self.put("x.json", items({"id": "a", "endpoint": HOST, "check": "mlkem",
                                                     "priorities": ["High"]})))
        with self.assertRaises(wave.WaveError):
            wave.load_wave(self.put("y.json", dict(WAVE, baseline={"file": "x", "sha256": "z" * 64})))

    def test_probe_outcomes_recorded(self):
        doc = after_doc()
        iface = [c for c in doc["components"] if c["bom-ref"].startswith("crypto/proto/tls/")][0]
        val = {p["name"]: p["value"] for p in iface["properties"]}["fedlin:certificateProbes"]
        self.assertIn("RSA:refused", val)
        self.assertIn("ML-DSA:certificate", val)

    def test_colliding_host_slugs_get_distinct_records(self):
        b = tp.CBOM("w", "1", {})
        for h in ("a-b.example.com", "a.b.example.com"):
            b.add_certificate({"host": h, "subject": "s", "issuer": "CA", "key_alg": "rsaEncryption",
                               "key_bits": 2048, "sig_alg": None, "fingerprint": "12" * 32})
            b.add_tls_kex(h, "X25519MLKEM768", "TLSv1.3", "TLS_AES_256_GCM_SHA384")
        refs = [c["bom-ref"] for c in b.to_dict()["components"] if c["bom-ref"].startswith(("crypto/cert", "crypto/proto"))]
        self.assertEqual(len(refs), len(set(refs)))


class Round3(Base):
    def enum(self, **kw):
        return dict(ENUM_PQ, **kw)

    def test_newly_accepted_classical_items_are_regressions(self):
        before = after_doc(enum=self.enum(groups={"X25519MLKEM768": True, "x25519": True}), classical="accepted",
                           ts="2026-02-01T00:00:00Z")
        after = after_doc(enum=self.enum(groups={"X25519MLKEM768": True, "x25519": True, "secp256r1": True,
                                                 "ffdhe2048": True}), classical="accepted")
        r, _ = self.run_check(after, items({"id": "b", "endpoint": HOST, "check": "mlkem"}), before)
        names = {x["name"] for x in r["regressions"]}
        self.assertTrue(any("secp256r1" in n for n in names), names)
        self.assertTrue(any("ffdhe2048" in n for n in names), names)
        self.assertFalse(r["passed"])

    def test_primary_slot_compared_on_its_own(self):
        before = build([cert(HOST, "ML-DSA-65", None, "ML-DSA-65", OLD_FP),
                        cert(HOST, "rsaEncryption", 2048, "sha256WithRSAEncryption", "cc" * 32, extra="RSA")],
                       "X25519MLKEM768", classical="rejected",
                       enum=self.enum(cert_probes=dict(PROBES, RSA="certificate")), ts="2026-02-01T00:00:00Z")
        after = build([cert(HOST, "id-ecPublicKey", 256, "ecdsa-with-SHA256", NEW_FP)], "X25519MLKEM768",
                      classical="rejected", enum=self.enum(cert_probes=dict(PROBES, ECDSA="certificate")))
        r, _ = self.run_check(after, items({"id": "b", "endpoint": HOST, "check": "mlkem"}), before)
        self.assertIn("ecdsa-with-SHA256", {x["name"] for x in r["regressions"]})

    def test_primary_only_comparison_is_disclosed(self):
        before = after_doc(enum=None, ts="2026-02-01T00:00:00Z")
        after = after_doc(enum=self.enum(cert_probes=dict(PROBES, RSA="certificate")), extra_old=True)
        r, _ = self.run_check(after, items({"id": "b", "endpoint": HOST, "check": "mlkem"}), before)
        reasons = {tuple(n["lanes"]): n["reason"] for n in r["notCompared"]}
        self.assertIn(("signature", "public-key"), reasons)
        self.assertIn("primary certificates only", reasons[("signature", "public-key")])
        self.assertIn("Not compared with the baseline", wave.markdown(r))

    def test_same_rank_group_change_is_not_a_regression(self):
        before = after_doc(kex="secp256r1", ts="2026-02-01T00:00:00Z")
        r, _ = self.run_check(after_doc(kex="x25519"), items({"id": "c", "endpoint": HOST,
                                                             "check": "refuses-classical-only"}), before)
        self.assertEqual([x for x in r["regressions"] if x["lane"] == "key-establishment"], [])

    def test_certificate_family_mismatch_counts_as_answered(self):
        out = ("=== CERT RSA\nCONNECTED(00000003)\n4067:error:0A00016A:SSL routines::wrong signature type:\n"
               "=== CERT ECDSA\nCONNECTED(00000003)\n")
        probes = tp._parse_enum(out)["cert_probes"]
        self.assertEqual(probes["RSA"], "mismatch")
        self.assertIsNone(probes["ECDSA"])

    def test_generic_family_names_leave_the_variant_open(self):
        self.assertTrue(wave.same_algorithm("RSA", "rsassaPss"))
        self.assertTrue(wave.same_algorithm("RSA", "sha256WithRSAEncryption"))
        self.assertFalse(wave.same_algorithm("sha256WithRSAEncryption", "rsassaPss"))


class Round4(Base):
    ALL = dict(PROBES, RSA="certificate", ECDSA="certificate")

    def test_keeping_the_old_certificate_is_not_a_regression(self):
        before = build([cert(HOST, "rsaEncryption", 2048, "sha256WithRSAEncryption", OLD_FP)], "X25519MLKEM768",
                       classical="rejected", enum=dict(ENUM_PQ, cert_probes=self.ALL), ts="2026-02-01T00:00:00Z")
        after = build([cert(HOST, "ML-DSA-65", None, "ML-DSA-65", NEW_FP),
                       cert(HOST, "rsaEncryption", 2048, "sha256WithRSAEncryption", OLD_FP, extra="RSA")],
                      "X25519MLKEM768", classical="rejected", enum=dict(ENUM_PQ, cert_probes=self.ALL))
        r, _ = self.run_check(after, items({"id": "b", "endpoint": HOST, "check": "mlkem"}), before)
        self.assertEqual(r["regressions"], [])
        self.assertTrue(r["passed"])

    def test_downgraded_key_with_same_algorithm_is_a_regression(self):
        before = build([cert(HOST, "ML-DSA-65", None, "ML-DSA-65", NEW_FP),
                        cert(HOST, "rsaEncryption", 2048, "sha256WithRSAEncryption", OLD_FP, extra="RSA")],
                       "X25519MLKEM768", classical="rejected", enum=dict(ENUM_PQ, cert_probes=self.ALL),
                       ts="2026-02-01T00:00:00Z")
        after = build([cert(HOST, "ML-DSA-65", None, "ML-DSA-65", NEW_FP),
                       cert(HOST, "rsaEncryption", 1024, "sha256WithRSAEncryption", "dd" * 32, extra="RSA")],
                      "X25519MLKEM768", classical="rejected", enum=dict(ENUM_PQ, cert_probes=self.ALL))
        r, _ = self.run_check(after, items({"id": "b", "endpoint": HOST, "check": "mlkem"}), before)
        self.assertIn(("rsaEncryption", "Critical"), {(x["name"], x["priority"]) for x in r["regressions"]})

    def test_probe_that_never_connected_is_not_answered(self):
        out = ("=== CERT ML-DSA\n4067:error:0A0000F3:SSL routines:tls_setup_handshake:no suitable signature "
               "algorithm:\n=== CERT RSA\nCONNECTED(00000003)\n4067:error:0A00016A:SSL routines::wrong signature type:\n")
        probes = tp._parse_enum(out)["cert_probes"]
        self.assertIsNone(probes["ML-DSA"])
        self.assertEqual(probes["RSA"], "mismatch")


class Input(Base):
    def test_invalid_wave_files(self):
        bad = [{}, dict(WAVE, schemaVersion="2.0"), dict(WAVE, items=[]), dict(WAVE, extra=1),
               items({"id": "a", "endpoint": "x", "check": "nope"}),
               items({"id": "a", "endpoint": "x", "check": "findings-resolved"}),
               items({"id": "a", "endpoint": "x", "check": "findings-resolved", "priorities": ["High"], "lanes": []}),
               items({"id": "a", "endpoint": "x", "check": "certificate-replaced", "baselineFingerprint": "abc"}),
               items({"id": "a", "endpoint": "x", "check": "certificate-replaced", "baselineFingerprint": OLD_FP,
                      "keyalgorithm": "ML-DSA"}),
               items({"id": "a", "endpoint": "x", "check": "certificate-replaced", "baselineFingerprint": OLD_FP,
                      "keyAlgorithm": 5}),
               items({"id": "a", "endpoint": "x", "check": "mlkem"}, {"id": "a", "endpoint": "y", "check": "mlkem"})]
        for i, w in enumerate(bad):
            with self.assertRaises(wave.WaveError, msg=i):
                wave.load_wave(self.put(f"bad{i}.json", w))

    def test_cli_exit_codes(self):
        wp, ok, nok = self.put("w.json", WAVE), self.put("ok.json", after_doc()), self.put("nok.json", before_doc())
        out = os.path.join(self.d.name, "r.json")
        self.assertEqual(wave.main(["check", "--wave", wp, "--cbom", ok, "--out", out]), 0)
        self.assertTrue(os.path.exists(os.path.join(self.d.name, "r.md")))
        self.assertEqual(wave.main(["check", "--wave", wp, "--cbom", nok, "--out", out]), 1)
        self.assertEqual(wave.main(["check", "--wave", self.put("x.json", {}), "--cbom", ok]), 2)
        self.assertEqual(wave.main(["check", "--wave", wp, "--cbom", "/nonexistent.json"]), 2)
        for i, junk in enumerate(([1, 2], {"components": 5})):
            self.assertEqual(wave.main(["check", "--wave", wp, "--cbom", self.put(f"j{i}.json", junk)]), 2)

    def test_schema_matches_code(self):
        with open(os.path.join(ROOT, "schemas", "wave-1.0.schema.json")) as f:
            sch = json.load(f)
        self.assertEqual(set(sch["properties"]), wave.TOP_KEYS)
        it = sch["properties"]["items"]["items"]
        self.assertEqual(set(it["properties"]), wave.ITEM_KEYS)
        self.assertEqual(tuple(it["properties"]["check"]["enum"]), wave.CHECKS)
        self.assertFalse(sch["additionalProperties"])
        self.assertFalse(it["additionalProperties"])

    def test_primary_certificate_records_fingerprint_and_run(self):
        doc = before_doc()
        c = [c for c in doc["components"] if c["bom-ref"] == "crypto/cert/svc-example-com"][0]
        props = {p["name"]: p["value"] for p in c["properties"]}
        self.assertEqual(props["fedlin:sha256Fingerprint"], OLD_FP)
        self.assertEqual(props["fedlin:observedIn"], doc["serialNumber"])

    def test_markdown_has_no_dashes(self):
        md = wave.markdown(self.run_check(before_doc())[0])
        self.assertNotIn(chr(0x2014), md)
        self.assertNotIn(chr(0x2013), md)


if __name__ == "__main__":
    unittest.main()
