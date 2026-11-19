"""PQCMM evidence mode: vendored model integrity and evidence that never awards a level. Offline."""
import hashlib
import json
import os
import re
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import pqcmm_evidence as pe  # noqa: E402
import tier2_pipeline as tp  # noqa: E402


def write_cbom(d, kex="X25519MLKEM768"):
    b = tp.CBOM("prod-edge.example.com", "1", {})
    b.subject_tag = tp.default_subject_tag("prod-edge.example.com", date="2026-11-15")
    b.add_certificate({"host": "a.example.com", "subject": "a", "issuer": "CA", "key_alg": "id-ecPublicKey",
                       "key_bits": 256, "sig_alg": "ecdsa-with-SHA256"})
    b.add_tls_kex("a.example.com", kex, "TLSv1.3", "TLS_AES_256_GCM_SHA384")
    path = os.path.join(d, "cbom.json")
    with open(path, "w") as f:
        json.dump(b.to_dict(), f)
    return path


class Model(unittest.TestCase):
    def test_vendored_files_pinned_in_lock(self):
        with open(os.path.join(ROOT, "toolkit.lock")) as f:
            lock = f.read()
        for name in ("pqcmm-model-1.0.1.yaml", "pqcmm-model-1.0.1.json"):
            m = re.search(re.escape(name) + r"\s*=\s*([0-9a-f]{64})", lock)
            self.assertIsNotNone(m, name)
            with open(os.path.join(ROOT, "third_party", "pkic-pqcmm", name), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), m.group(1), name)

    def test_model_shape(self):
        m = pe.load_model()
        self.assertEqual(m["model"]["version"], "1.0.1")
        self.assertEqual(len(pe._criteria(m)), 22)
        self.assertEqual(len(pe._questions(m)), 72)


class Evidence(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.res = pe.build(write_cbom(self.d.name))

    def tearDown(self):
        self.d.cleanup()

    def test_fields_match_the_models_response_schema(self):
        Q = pe._questions(self.res["model"])
        for qid, e in self.res["evidence"].items():
            self.assertIn(qid, Q)
            keys = {f["key"] for f in (Q[qid].get("response") or {}).get("fields", [])}
            if keys:
                self.assertLessEqual(set(e["fields"]), keys, qid)
            self.assertIn(e["provenance"], ("observed", "derived", "snapshot", "vendor"))

    def test_never_awards_a_level_or_marks_met(self):
        j = pe.to_json(self.res)
        self.assertIsNone(j["levelAwarded"])
        for c in j["criteria"]:
            self.assertNotIn("met", c["status"].replace("not-met", ""))
        md = pe.report_md(self.res)
        self.assertIn("This is evidence, not a maturity level", md)

    def test_level0_contradicted_when_pqc_observed(self):
        c = {x["id"]: x for x in self.res["criteria"]}
        self.assertTrue(c["0.1.2"]["status"].startswith("contradicted"))
        with tempfile.TemporaryDirectory() as d:
            res = pe.build(write_cbom(d, kex="X25519"))
        self.assertFalse({x["id"]: x for x in res["criteria"]}["0.1.2"]["status"].startswith("contradicted"))
        self.assertNotIn("2.3.3", res["evidence"])

    def test_interop_from_active_probe(self):
        e = self.res["evidence"]["2.3.3"]
        self.assertEqual(e["provenance"], "observed")
        self.assertIn("X25519MLKEM768", e["fields"]["protocol"])

    def test_inventory_completeness_on_builder_output(self):
        self.assertTrue(self.res["evidence"]["3.2.2"]["fields"]["allFieldsPresent"])

    def test_vendor_declarations_are_marked_vendor(self):
        with tempfile.TemporaryDirectory() as d:
            ans = os.path.join(d, "answers.json")
            with open(ans, "w") as f:
                json.dump({"answers": {"I1": {"answer": "x", "claims": {"pqc_algorithms": ["ML-DSA-65"]}},
                                       "A1": {"answer": "none", "claims": {"traditional_asymmetric": False}}}}, f)
            res = pe.build(write_cbom(d), answers_path=ans)
        e = res["evidence"]["5.4.2"]
        self.assertEqual(e["provenance"], "vendor")
        self.assertIn("ML-DSA-65 (vendor): not observed", e["fields"]["sampledAlgorithms"])
        self.assertIn("A1", res["evidence"]["3.3.1"]["fields"]["toolVsDisclosureGaps"])



class Answers152(unittest.TestCase):
    """pqcmm_evidence --answers (fedlin-website re-test of 1.5.1)."""
    def build(self, answers, cbom_kwargs=None):
        d = tempfile.mkdtemp()
        cbom = write_cbom(d, **(cbom_kwargs or {}))
        p = os.path.join(d, "answers.json")
        with open(p, "w") as f:
            json.dump(answers, f)
        return pe.build(cbom, answers_path=p)

    def gaps(self, res):
        return res["evidence"]["3.3.1"]["fields"]["toolVsDisclosureGaps"]

    def test_contradictions_are_listed_not_no_gap(self):
        res = self.build({"answers": {
            "A6": {"answer": "no", "claims": {"traditional_asymmetric_auth": False}},
            "T3": {"answer": "no", "claims": {"hybrid": False}},
            "L1": {"answer": "no", "claims": {"cbom": False}}}})
        g = self.gaps(res)
        for q in ("A6 contradicted", "T3 contradicted", "L1 contradicted"):
            self.assertIn(q, g)
        self.assertNotIn("No answer contradicts", g)

    def test_a1_gap_does_not_cite_certificates(self):
        res = self.build({"answers": {"A1": {"answer": "no", "claims": {"traditional_asymmetric": False}}}})
        self.assertNotIn("A1 contradicted", self.gaps(res))       # only ML-KEM hybrid key exchange; certs are A6
        res = self.build({"answers": {"A1": {"answer": "no", "claims": {"traditional_asymmetric": False}}}},
                         {"kex": "X25519"})
        self.assertIn("A1 contradicted", self.gaps(res))
        self.assertNotIn("certificate", self.gaps(res).split("A1 contradicted")[1].split("\n")[0])

    def test_product_mismatch_noted(self):
        res = self.build({"product": "Other Product", "version": "9", "answers": {"A1": {"answer": "x"}}})
        self.assertIn("check they are the same product", self.gaps(res))

    def test_bad_input_exits_2(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "bad.json")
            with open(bad, "w") as f:
                f.write("{oops")
            cbom = write_cbom(d)
            with contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(pe.main(["--cbom", cbom, "--answers", bad, "--out", os.path.join(d, "o.md")]), 2)
                self.assertEqual(pe.main(["--cbom", bad, "--out", os.path.join(d, "o.md")]), 2)
            self.assertIn("[error]", err.getvalue())


if __name__ == "__main__":
    unittest.main()
