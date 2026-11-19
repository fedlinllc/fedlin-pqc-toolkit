"""Vendor readiness: the ASD/CISA/NSA questions and the checks against a vendor CBOM. Offline."""
import collections
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import vendor_readiness as vr  # noqa: E402


def algo(ref, name, functions=None):
    return {"type": "cryptographic-asset", "bom-ref": ref, "name": name,
            "cryptoProperties": {"assetType": "algorithm",
                                 "algorithmProperties": {"cryptoFunctions": functions or ["unknown"]}}}


def cert(sig_ref, key_ref):
    return {"type": "cryptographic-asset", "bom-ref": "cert/1", "name": "cert",
            "cryptoProperties": {"assetType": "certificate",
                                 "certificateProperties": {"signatureAlgorithmRef": sig_ref,
                                                           "subjectPublicKeyRef": key_ref}}}


class Data(unittest.TestCase):
    def setUp(self):
        self.doc = vr.load_questions()

    def test_31_questions_in_latice_phases(self):
        qs = self.doc["questions"]
        self.assertEqual(len(qs), 31)
        self.assertEqual(len({q["id"] for q in qs}), 31)
        self.assertEqual(collections.Counter(q["phase"] for q in qs),
                         {"Locate": 8, "Assess": 6, "Triage": 5, "Implement": 6, "Communicate and educate": 6})

    def test_claim_types_and_checks_are_known(self):
        for q in self.doc["questions"]:
            self.assertIn(q["claim_type"], self.doc["claim_types"])
            self.assertTrue(q["why_it_matters"] and q["key_response_considerations"], q["id"])
            if q["check"]:
                self.assertIsNotNone(vr.run_check(q, {}, None, {"profile": "civilian"}), q["id"])

    def test_verbatim_samples_and_license(self):
        by = {q["id"]: q["question"] for q in self.doc["questions"]}
        self.assertEqual(by["I6"], "Is PQC included in base licensing?")
        self.assertEqual(by["L2"], "Where is cryptography implemented?")
        self.assertIn("CC BY 4.0", self.doc["source"]["license"])
        self.assertEqual(len(self.doc["common_concerns"]), 7)

    def test_questionnaire_and_template_cover_every_question(self):
        md = vr.questionnaire_md(self.doc)
        t = vr.template(self.doc)
        for q in self.doc["questions"]:
            self.assertIn(f"### {q['id']}. ", md)
            self.assertIn(q["id"], t["answers"])
        self.assertIn("pqc_algorithms", t["answers"]["I1"]["claims"])


class Assess(unittest.TestCase):
    def run_case(self, answers, components=None):
        with tempfile.TemporaryDirectory() as d:
            if components is not None:
                with open(os.path.join(d, "cbom.json"), "w") as f:
                    json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}, f)
                answers["cbom"] = "cbom.json"
            p = os.path.join(d, "answers.json")
            with open(p, "w") as f:
                json.dump(answers, f)
            return vr.assess(p, "civilian")

    def test_contradiction_on_traditional_asymmetric(self):
        res = self.run_case({"answers": {"A1": {"answer": "none", "claims": {"traditional_asymmetric": False}}}},
                            [algo("a/1", "ECDH", ["keygen"]), algo("a/2", "AES-256")])
        self.assertEqual(res["results"]["A1"]["status"], "contradicted")
        self.assertIn("ECDH", res["results"]["A1"]["detail"])

    def test_auth_uses_certificate_algorithms(self):
        res = self.run_case({"answers": {"A6": {"answer": "none", "claims": {"traditional_asymmetric_auth": False}}}},
                            [algo("a/sig", "sha256WithRSAEncryption"), algo("a/key", "rsaEncryption"),
                             cert("a/sig", "a/key")])
        self.assertEqual(res["results"]["A6"]["status"], "contradicted")

    def test_hybrid_without_pqc_only_date(self):
        res = self.run_case({"answers": {"T3": {"answer": "yes", "claims": {"hybrid": True}}}},
                            [algo("a/1", "X25519MLKEM768")])
        self.assertEqual(res["results"]["T3"]["status"], "missing-date")

    def test_claimed_algorithm_found_inside_hybrid(self):
        res = self.run_case({"answers": {"I1": {"answer": "x", "claims": {"pqc_algorithms": ["ML-KEM-768"],
                                                                          "ga_date": "2026-06"}}}},
                            [algo("a/1", "X25519MLKEM768")])
        self.assertEqual(res["results"]["I1"]["status"], "consistent")
        self.assertIn("within X25519MLKEM768", res["results"]["I1"]["detail"])

    def test_claimed_algorithm_absent_from_cbom(self):
        res = self.run_case({"answers": {"I1": {"answer": "x", "claims": {"pqc_algorithms": ["ML-DSA-65"],
                                                                          "ga_date": "2026-06"}}}},
                            [algo("a/1", "ECDSA")])
        self.assertEqual(res["results"]["I1"]["status"], "not-evidenced")

    def test_dates(self):
        res = self.run_case({"answers": {"T1": {"answer": "x", "claims": {"pqc_ready_date": "2031-03"}},
                                         "C5": {"answer": "x", "claims": {"roadmap_date": "2029"}}}})
        self.assertEqual(res["results"]["T1"]["status"], "late")
        self.assertEqual(res["results"]["C5"]["status"], "consistent")
        self.assertEqual(res["results"]["C3"]["status"], "missing-date")

    def test_concerns_from_structured_fields(self):
        res = self.run_case({"answers": {"I6": {"answer": "add-on", "claims": {"pqc_in_base_license": False}},
                                         "A5": {"answer": "RSA-4096", "evidence": ["guide"]}}})
        names = [c for c, _ in res["concerns"]]
        for want in ("limited visibility of cryptographic use", "treatment of PQC as an optional or premium function",
                     "over-reliance on compensating controls", "lack of governance or ownership"):
            self.assertIn(want, names)

    def test_unrecognised_algorithm_is_listed_not_labelled_opaque(self):
        res = self.run_case({"answers": {}}, [algo("a/1", "HQC-128")])
        self.assertNotIn("use of proprietary or opaque cryptography", [c for c, _ in res["concerns"]])
        self.assertIn("does not recognise", vr.report_md(res))
        self.assertIn("HQC-128", vr.report_md(res))

    def test_report_and_summary(self):
        res = self.run_case({"vendor": "V", "answers": {"A1": {"answer": "none",
                                                               "claims": {"traditional_asymmetric": False}}}},
                            [algo("a/1", "RSA")])
        md = vr.report_md(res)
        self.assertIn("## Common concerns", md)
        self.assertIn("| A1 |", md)
        self.assertEqual(vr.summary(res)["contradicted"], ["A1"])



class Fixes20261119(unittest.TestCase):
    """fedlin-website stranger test of vendor_readiness, 2026-11-19: attribution and false "consistent"."""
    run_case = Assess.run_case

    def setUp(self):
        self.doc = vr.load_questions()

    def test_questionnaire_carries_cc_by_attribution(self):
        md = vr.questionnaire_md(self.doc)
        for want in ("(c) Commonwealth of Australia 2026", "https://creativecommons.org/licenses/by/4.0/",
                     "media.defense.gov", "Changes:", "have not reviewed or endorsed",
                     "*Key response considerations:*"):
            self.assertIn(want, md)
        self.assertNotIn("What a strong answer includes", md)

    def test_report_carries_attribution(self):
        res = self.run_case({"answers": {}})
        self.assertIn("(c) Commonwealth of Australia 2026", vr.report_md(res))

    def test_string_claims_are_checked(self):
        for no in ("false", "No", "no.", "none"):
            res = self.run_case({"answers": {"A1": {"answer": "none", "claims": {"traditional_asymmetric": no}}}},
                                [algo("a/1", "rsaEncryption", ["encapsulate"])])
            self.assertEqual(res["results"]["A1"]["status"], "contradicted", no)
        res = self.run_case({"answers": {"T3": {"answer": "no", "claims": {"hybrid": "no"}}}},
                            [algo("a/1", "X25519MLKEM768")])
        self.assertEqual(res["results"]["T3"]["status"], "contradicted")
        res = self.run_case({"answers": {"I6": {"answer": "add-on", "claims": {"pqc_in_base_license": "No"}}}})
        self.assertIn("treatment of PQC as an optional or premium function", [c for c, _ in res["concerns"]])

    def test_algorithm_list_as_string(self):
        res = self.run_case({"answers": {"I1": {"answer": "x", "claims": {"pqc_algorithms": "ML-KEM-768, ML-DSA-65",
                                                                          "ga_date": "2026-06"}}}},
                            [algo("a/1", "X25519MLKEM768")])
        d = res["results"]["I1"]["detail"]
        self.assertIn("ML-KEM-768:", d)
        self.assertIn("ML-DSA-65: meets the `civilian` profile target; not in the CBOM", d)
        self.assertNotIn("compliant", d)
        self.assertEqual(res["results"]["I1"]["status"], "not-evidenced")

    def test_unknown_claimed_algorithm_is_not_consistent(self):
        res = self.run_case({"answers": {"I1": {"answer": "x", "claims": {"pqc_algorithms": ["QuantumShield-9000"],
                                                                          "ga_date": "2026-06"}}}},
                            [algo("a/1", "X25519MLKEM768")])
        self.assertEqual(res["results"]["I1"]["status"], "not-evidenced")

    def test_unanswered_is_never_consistent(self):
        res = self.run_case(vr.template(self.doc), [algo("a/1", "X25519MLKEM768"), algo("a/2", "ECDSA", ["sign"])])
        self.assertNotIn("consistent", [r["status"] for r in res["results"].values()])
        self.assertEqual(res["results"]["A1"]["status"], "unanswered")

    def test_prose_only_answer_is_not_checked(self):
        res = self.run_case({"answers": {"A1": {"answer": "We use modern cryptography."}}}, [algo("a/1", "RSA")])
        self.assertEqual(res["results"]["A1"]["status"], "not-checked")

    def test_l1_claim_without_cbom(self):
        res = self.run_case({"answers": {"L1": {"answer": "yes", "claims": {"cbom": True}}}})
        self.assertEqual(res["results"]["L1"]["status"], "contradicted")

    def test_partial_cbom_does_not_prove_absence(self):
        comps = [algo("a/1", "ML-KEM-768"), algo("a/2", "ML-DSA-65", ["sign"])]
        res = self.run_case({"answers": {"A1": {"answer": "none", "claims": {"traditional_asymmetric": False}},
                                         "A6": {"answer": "none", "claims": {"traditional_asymmetric_auth": False}}}},
                            comps)
        self.assertEqual(res["results"]["A1"]["status"], "not-evidenced")
        self.assertEqual(res["results"]["A6"]["status"], "not-evidenced")
        self.assertIn("coverage", vr.report_md(res))

    def test_complete_cbom_can_support_absence(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "cbom.json"), "w") as f:
                json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6",
                           "metadata": {"component": {"name": "p", "properties": [
                               {"name": "pkic:profile:coverage", "value": "complete"}]}},
                           "components": [algo("a/1", "ML-KEM-768")]}, f)
            p = os.path.join(d, "a.json")
            with open(p, "w") as f:
                json.dump({"cbom": "cbom.json", "answers": {
                    "A1": {"answer": "none", "claims": {"traditional_asymmetric": False}}}}, f)
            res = vr.assess(p, "civilian")
        self.assertEqual(res["results"]["A1"]["status"], "consistent")



class Fixes20261119b(unittest.TestCase):
    """Vendor items 3-5 of the fedlin-website stranger test (1.5.1)."""
    run_case = Assess.run_case

    def test_a1_ignores_signature_algorithms(self):
        # data in transit on ML-KEM, authenticated with ECDSA: A1 ("data flows rely on traditional asymmetric")
        # is not contradicted by the signature; A6 is
        comps = [algo("a/1", "X25519MLKEM768"), algo("a/2", "ECDSA", ["sign"])]
        res = self.run_case({"answers": {
            "A1": {"answer": "no", "claims": {"traditional_asymmetric": False}},
            "A6": {"answer": "no", "claims": {"traditional_asymmetric_auth": False}}}}, comps)
        self.assertNotEqual(res["results"]["A1"]["status"], "contradicted")
        self.assertEqual(res["results"]["A6"]["status"], "contradicted")

    def test_l4_ignores_non_crypto_libraries(self):
        jackson = {"type": "library", "group": "com.fasterxml.jackson.core", "name": "jackson-databind"}
        res = self.run_case({"answers": {"L4": {"answer": "no", "claims": {"third_party_crypto": False}}}},
                            [jackson, algo("a/1", "ML-KEM-768")])
        self.assertNotEqual(res["results"]["L4"]["status"], "contradicted")
        bc = {"type": "library", "group": "org.bouncycastle", "name": "bcprov-jdk18on"}
        res = self.run_case({"answers": {"L4": {"answer": "no", "claims": {"third_party_crypto": False}}}},
                            [bc, algo("a/1", "ML-KEM-768")])
        self.assertEqual(res["results"]["L4"]["status"], "contradicted")

    def test_kyber_hybrid_counts_as_hybrid(self):
        res = self.run_case({"answers": {"T3": {"answer": "no", "claims": {"hybrid": False}}}},
                            [algo("a/1", "X25519Kyber768Draft00")])
        self.assertEqual(res["results"]["T3"]["status"], "contradicted")

    def test_dates(self):
        self.assertEqual(vr._date("Q3 2027"), vr.datetime.date(2027, 9, 30))
        self.assertEqual(vr._date("2027-Q4"), vr.datetime.date(2027, 12, 31))
        self.assertEqual(vr._date("2027-02"), vr.datetime.date(2027, 2, 28))
        self.assertEqual(vr._date("2027-03-01T10:00:00Z"), vr.datetime.date(2027, 3, 1))
        self.assertIsNone(vr._date("2026-13"))
        res = self.run_case({"answers": {"T1": {"answer": "x", "claims": {"pqc_ready_date": "2026-13"}}}})
        self.assertIn("is not a date", res["results"]["T1"]["detail"])
        res = self.run_case({"answers": {"T3": {"answer": "yes", "claims": {"hybrid": True,
                                                                            "pqc_only_date": "2033"}}}},
                            [algo("a/1", "X25519MLKEM768")])
        self.assertEqual(res["results"]["T3"]["status"], "late")
        res = self.run_case({"answers": {"I1": {"answer": "x", "claims": {"pqc_algorithms": ["ML-KEM-768"],
                                                                          "ga_date": "2032-01"}}}},
                            [algo("a/1", "ML-KEM-768")])
        self.assertEqual(res["results"]["I1"]["status"], "late")

    def test_a5_negative_answer_raises_no_concern(self):
        res = self.run_case({"answers": {"A5": {"answer": "No.", "evidence": ["x"]}}})
        self.assertNotIn("over-reliance on compensating controls", [c for c, _ in res["concerns"]])

    def test_report_has_scope_disclaimer_and_provenance(self):
        res = self.run_case({"answers": {}}, [algo("a/1", "ML-KEM-768")])
        md = vr.report_md(res)
        for want in ("**Scope:**", "**Not a determination.**", "not a compliance determination",
                     "fedlin-pqc-toolkit", "SHA-256"):
            self.assertIn(want, md)
        self.assertNotIn("compliant", md.replace("compliance", ""))
        sm = vr.summary(res)
        self.assertIn("statuses", sm)
        self.assertIn("cbom", sm["inputs"])

    def _run_cli(self, d, answers_text, cbom_text=None):
        if cbom_text is not None:
            with open(os.path.join(d, "cbom.json"), "w") as f:
                f.write(cbom_text)
        p = os.path.join(d, "a.json")
        with open(p, "w") as f:
            f.write(answers_text)
        import contextlib
        import io
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = vr.main(["assess", "--answers", p, "--out", os.path.join(d, "r.md")])
        return rc, err.getvalue()

    def test_bad_inputs_exit_2_without_traceback(self):
        cases = [("{not json", None), ("[]", None), ('{"answers": []}', None),
                 ('{"answers": {"A1": "yes"}}', None), ('{"answers": {"A1": {"answer": 5}}}', None), ('{"cbom": "missing.json", "answers": {}}', None),
                 ('{"cbom": "cbom.json", "answers": {}}', "{oops"), ('{"cbom": 5, "answers": {}}', None)]
        for answers_text, cbom_text in cases:
            with tempfile.TemporaryDirectory() as d:
                rc, err = self._run_cli(d, answers_text, cbom_text)
            self.assertEqual(rc, 2, answers_text)
            self.assertIn("[error]", err, answers_text)

    def test_unknown_question_ids_are_reported(self):
        with tempfile.TemporaryDirectory() as d:
            rc, err = self._run_cli(d, '{"answers": {"Z9": {"answer": "x"}}}')
        self.assertEqual(rc, 0)
        self.assertIn("Z9", err)


if __name__ == "__main__":
    unittest.main()
