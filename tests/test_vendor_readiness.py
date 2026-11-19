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
                            [algo("a/1", "ECDSA", ["sign"]), algo("a/2", "AES-256")])
        self.assertEqual(res["results"]["A1"]["status"], "contradicted")
        self.assertIn("ECDSA", res["results"]["A1"]["detail"])

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

    def test_opaque_algorithm_flagged(self):
        res = self.run_case({"answers": {}}, [algo("a/1", "ACME-Secret-Cipher")])
        self.assertIn("use of proprietary or opaque cryptography", [c for c, _ in res["concerns"]])

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
                                [algo("a/1", "ECDSA", ["sign"])])
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
        self.assertIn("ML-DSA-65: compliant; not in the CBOM", d)
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


if __name__ == "__main__":
    unittest.main()
