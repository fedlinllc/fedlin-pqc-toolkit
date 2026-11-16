"""Business context (fedlin.pqc-context 1.0): attention order and urgency, verdicts unchanged. Offline."""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import context  # noqa: E402
import policy  # noqa: E402
import report  # noqa: E402
import tier2_pipeline as tp  # noqa: E402

FULL = {"status": "complete", "client": "bundled", "tool": "openssl 3.5", "versions": {"TLSv1.3": True, "TLSv1.2": False},
        "suites": {}, "groups": {"X25519MLKEM768": True, "x25519": False, "secp256r1": False},
        "cert_probes": {"RSA": "certificate", "ECDSA": "refused", "EdDSA": "refused", "ML-DSA": "refused"}}


def cbom(hosts, ts="2026-11-16T00:00:00Z"):
    """hosts: {host: (kex, key, bits, sig, enum, classical_outcome)}; kex None = not observed."""
    b = tp.CBOM("ctx", "1", {})
    for i, (h, spec) in enumerate(sorted(hosts.items())):
        kex, key, bits, sig = spec[:4]
        enum = spec[4] if len(spec) > 4 else None
        classical = spec[5] if len(spec) > 5 else None
        b.add_certificate({"host": h, "subject": "s", "issuer": "CA", "key_alg": key, "key_bits": bits,
                           "sig_alg": sig, "fingerprint": f"{i:02x}" * 32})
        b.add_tls_kex(h, kex, "TLSv1.3", "TLS_AES_256_GCM_SHA384", None,
                      {"outcome": classical} if classical else None, enum)
    d = b.to_dict()
    d["metadata"]["timestamp"] = ts
    return d


RSA = ("rsaEncryption", 2048, "sha256WithRSAEncryption")
HOSTS = {
    "pay.example.gov": ("secp256r1",) + RSA,                                   # exposed: negotiates classical
    "www.example.gov": ("X25519MLKEM768",) + RSA + (FULL, "rejected"),         # not exposed
    "old.example.gov": ("secp256r1", "rsaEncryption", 1024, "sha1WithRSAEncryption"),   # Critical
    "10.2.0.5:8443": ("secp256r1",) + RSA,
    "stray.example.org": ("secp256r1",) + RSA,
}
CTX = {"schema": "fedlin.pqc-context", "schemaVersion": "1.0", "systems": [
    {"name": "Payments", "owner": "Payments platform", "impact": "high", "dataLifetimeYears": 10,
     "migrationYears": 2, "endpoints": ["pay.example.gov"]},
    {"name": "Public site", "owner": "Web team", "impact": "low", "dataLifetimeYears": 1,
     "endpoints": ["*.example.gov"]},
    {"name": "Internal API", "impact": "moderate", "dataLifetimeYears": 3, "endpoints": ["10.2.0.0/16"]},
]}


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)

    def put(self, name, obj):
        p = os.path.join(self.d.name, name)
        with open(p, "w") as f:
            json.dump(obj, f)
        return p

    def ranked(self, ctx=CTX, hosts=HOSTS, profile="civilian", **kw):
        return context.rank(self.put("ctx.json", ctx), self.put("cbom.json", cbom(hosts, **kw)), profile)

    def rows(self, **kw):
        return {r["endpoint"]: r for r in self.ranked(**kw)["endpoints"]}


class Rank(Base):
    def test_order_owners_and_most_demanding_values(self):
        att = self.ranked()
        pay = {r["endpoint"]: r for r in att["endpoints"]}["pay.example.gov"]
        self.assertEqual(pay["impact"], "high")
        self.assertEqual(pay["dataLifetimeYears"], 10)
        self.assertEqual(pay["owners"], ["Payments platform", "Web team"])
        self.assertEqual(att["endpoints"][0]["endpoint"], "pay.example.gov")
        self.assertEqual([u["endpoint"] for u in att["noContext"]], ["stray.example.org"])
        self.assertEqual(att["resultFormat"], "fedlin.pqc-attention")

    def test_ties_go_to_the_worse_finding(self):
        # low x Critical (old) and high x Low would tie; here old (Critical) must rank above www (no High+)
        order = [r["endpoint"] for r in self.ranked()["endpoints"]]
        self.assertLess(order.index("old.example.gov"), order.index("www.example.gov"))

    def test_mosca_on_exposed_endpoints(self):
        rows = self.rows()
        self.assertEqual(rows["pay.example.gov"]["exposure"], "exposed")
        self.assertEqual(rows["pay.example.gov"]["urgent"], "yes")             # 2026 + 10 + 2 > 2035
        self.assertIn("2038", rows["pay.example.gov"]["urgency"])
        self.assertEqual(rows["10.2.0.5:8443"]["urgent"], "no")                # 2026 + 3, no migration given
        self.assertIn("may be understated", rows["10.2.0.5:8443"]["urgency"])

    def test_not_exposed_needs_full_evidence(self):
        rows = self.rows()
        self.assertEqual(rows["www.example.gov"]["exposure"], "not exposed")
        self.assertEqual(rows["www.example.gov"]["urgent"], "no")

    def test_hybrid_but_accepts_classical_is_exposed(self):
        accepts = dict(FULL, groups={"X25519MLKEM768": True, "x25519": True})
        rows = self.rows(hosts={"hyb.example.gov": ("X25519MLKEM768",) + RSA + (accepts, "accepted")},
                         ctx=dict(CTX, systems=[dict(CTX["systems"][0], endpoints=["hyb.example.gov"],
                                                     dataLifetimeYears=25)]))
        r = rows["hyb.example.gov"]
        self.assertEqual(r["exposure"], "exposed")
        self.assertTrue(any("x25519" in x for x in r["exposureReasons"]))
        self.assertTrue(any("classical-only" in x for x in r["exposureReasons"]))
        self.assertEqual(r["urgent"], "yes")

    def test_tls12_accepted_is_exposed(self):
        en = dict(FULL, versions={"TLSv1.3": True, "TLSv1.2": True})
        r = self.rows(hosts={"www.example.gov": ("X25519MLKEM768",) + RSA + (en, "rejected")})["www.example.gov"]
        self.assertEqual(r["exposure"], "exposed")

    def test_unobserved_or_unclassified_key_exchange_is_undetermined(self):
        rows = self.rows(hosts={"a.example.gov": (None,) + RSA,
                                "b.example.gov": ("curveFOO", "ML-DSA-65", None, "ML-DSA-65"),
                                "c.example.gov": ("X25519MLKEM768",) + RSA})       # ML-KEM, not enumerated
        for h in ("a.example.gov", "b.example.gov", "c.example.gov"):
            self.assertEqual(rows[h]["exposure"], "undetermined", h)
            self.assertEqual(rows[h]["urgent"], "not assessed", h)
            self.assertNotIn("no quantum-vulnerable", rows[h]["urgency"])
        self.assertEqual(rows["b.example.gov"]["worstPriority"], "Review")         # Review ranks, not "none"

    def test_missing_migration_time_is_never_borrowed(self):
        ctx = dict(CTX, systems=[
            {"name": "A", "impact": "low", "dataLifetimeYears": 5, "endpoints": ["pay.example.gov"]},
            {"name": "B", "impact": "low", "dataLifetimeYears": 1, "migrationYears": 2, "endpoints": ["*.gov"]}])
        r = self.rows(ctx=ctx)["pay.example.gov"]
        self.assertIn("migration time not given (A)", r["urgency"])
        self.assertIn("may be understated", r["urgency"])

    def test_missing_data_lifetime_is_not_assessed(self):
        ctx = dict(CTX, systems=[{"name": "N", "impact": "high", "endpoints": ["pay.example.gov"]}])
        att = self.ranked(ctx=ctx)
        r = {x["endpoint"]: x for x in att["endpoints"]}["pay.example.gov"]
        self.assertEqual(r["urgent"], "not assessed")
        self.assertEqual(att["missingDataLifetime"], ["N"])
        self.assertEqual(att["missingMigrationTime"], [])

    def test_zero_lifetime_is_not_urgent(self):
        ctx = dict(CTX, systems=[{"name": "Z", "impact": "high", "dataLifetimeYears": 0, "migrationYears": 20,
                                  "endpoints": ["pay.example.gov"]}])
        self.assertEqual(self.rows(ctx=ctx)["pay.example.gov"]["urgent"], "no")

    def test_mixed_systems_note_and_not_assessed(self):
        m = lambda per: context.mosca({"_per": per, "dataLifetimeYears": None, "migrationYears": None}, 2026, 2035)  # noqa: E731
        self.assertIn("2033", m([("A", 1, 1), ("B", 5, 2)])[1])          # closest to the horizon is shown
        self.assertEqual(m([("A", None, None), ("B", 1, 1)])[0], "not assessed")
        self.assertEqual(m([("A", 0, None), ("B", None, None)])[0], "not assessed")
        self.assertEqual(m([("A", 12, None), ("B", None, None)])[0], "yes")

    def test_negotiated_classical_without_group_is_exposed(self):
        rows = self.rows(hosts={"ff.example.gov": ("FFDHE-ffdhe2048",) + RSA})
        self.assertEqual(rows["ff.example.gov"]["exposure"], "exposed")
        b = tp.CBOM("ctx", "1", {})
        b.add_certificate({"host": "dhe.example.gov", "subject": "s", "issuer": "CA", "key_alg": "rsaEncryption",
                           "key_bits": 2048, "sig_alg": "sha256WithRSAEncryption", "fingerprint": "ab" * 32})
        b.add_tls_kex("dhe.example.gov", None, "TLSv1.2", "DHE-RSA-AES256-GCM-SHA384")
        d = b.to_dict()
        d["metadata"]["timestamp"] = "2026-11-16T00:00:00Z"
        att = context.rank(self.put("c.json", CTX), self.put("d.json", d))
        r = {x["endpoint"]: x for x in att["endpoints"]}["dhe.example.gov"]
        self.assertEqual(r["exposure"], "exposed")
        self.assertTrue(any("TLSv1.2" in x for x in r["exposureReasons"]), r["exposureReasons"])

    def test_nothing_observed_message(self):
        att = {"scanYear": 2026, "horizon": 2035, "horizonSource": "x", "endpoints": [], "noContext": [],
               "notRanked": [], "unusedSystems": ["A"], "missingDataLifetime": [], "missingMigrationTime": []}
        self.assertIn("no endpoint observed by a handshake", context.markdown(att))
        self.assertNotIn("check their patterns", context.markdown(att))

    def test_unused_systems_and_horizon(self):
        ctx = dict(CTX, horizon=2045, systems=CTX["systems"] + [
            {"name": "Unused", "impact": "high", "dataLifetimeYears": 30, "endpoints": ["*.typo.gov"]}])
        att = self.ranked(ctx=ctx)
        self.assertEqual(att["unusedSystems"], ["Unused"])
        self.assertEqual(att["horizonSource"], "context file")
        self.assertEqual({r["endpoint"]: r for r in att["endpoints"]}["pay.example.gov"]["urgent"], "no")
        self.assertIn("NIST IR 8547", self.ranked()["horizonSource"])
        self.assertIn("CNSA 2.0", self.ranked(profile="nss")["horizonSource"])

    def test_records_from_another_run_are_listed_not_ranked(self):
        doc = cbom({"pay.example.gov": HOSTS["pay.example.gov"]})
        other = cbom({"merged.example.gov": HOSTS["pay.example.gov"]})
        doc["components"] += [c for c in other["components"] if c["bom-ref"].startswith(("crypto/cert", "crypto/proto"))]
        att = context.rank(self.put("c.json", CTX), self.put("x.json", doc))
        self.assertEqual([r["endpoint"] for r in att["endpoints"]], ["pay.example.gov"])
        self.assertEqual(att["notRanked"][0]["endpoint"], "merged.example.gov")

    def test_redaction_applied_to_context(self):
        att = context.rank(self.put("c.json", CTX), self.put("x.json", cbom({"pay.example.net": HOSTS["pay.example.gov"]})),
                           redact=[("example.gov", "example.net"), ("Payments platform", "Team A")])
        r = att["endpoints"][0]
        self.assertEqual(r["endpoint"], "pay.example.net")
        self.assertEqual(r["owners"], ["Team A", "Web team"])

    def test_verdicts_and_rest_of_report_unchanged(self):
        att = self.ranked()
        view, _ = policy.load_view(os.path.join(self.d.name, "cbom.json"))
        md, summary = report.build_report(view, attention=att)
        md0, summary0 = report.build_report(view)
        cut = md.index("## Attention order"), md.index("## Certificate posture")
        self.assertEqual(md[:cut[0]] + md[cut[1]:], md0)
        self.assertEqual({k: v for k, v in summary.items() if k != "attention"},
                         {k: v for k, v in summary0.items() if k != "attention"})
        self.assertEqual(summary["attention"]["urgent"], 1)
        self.assertIsNone(summary0["attention"])
        self.assertIn("not a forecast", md)
        self.assertIn("2030-12-31", md)
        self.assertNotIn(chr(0x2014), md)
        self.assertNotIn(chr(0x2013), md)

    def test_pipes_escaped(self):
        ctx = dict(CTX, systems=[dict(CTX["systems"][0], owner="Ops | Sec")])
        md = context.markdown(self.ranked(ctx=ctx))
        row = [x for x in md.splitlines() if x.startswith("| 1 |")][0]
        self.assertIn("Ops \\| Sec", row)

    def test_empty_ranking_says_so(self):
        ctx = dict(CTX, systems=[{"name": "X", "impact": "low", "endpoints": ["nothing.example"]}])
        self.assertIn("nothing could be ranked", context.markdown(self.ranked(ctx=ctx)))


class ReportCli(Base):
    def test_report_ranks_under_the_policy_profile(self):
        import subprocess
        p = self.put("cbom.json", cbom({"www.example.gov": ("X25519MLKEM768", "ML-DSA-87", None, "ML-DSA-87")}))
        with open(p.rsplit(".", 1)[0] + ".policy.json", "w") as f:
            json.dump(policy.evaluate(p, profile="nss"), f)
        ctx = self.put("ctx.json", dict(CTX, systems=[dict(CTX["systems"][1], endpoints=["*.gov"])]))
        out = os.path.join(self.d.name, "r.md")
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "scripts", "report.py"), "--cbom", p,
                            "--context", ctx, "--out", out], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out) as f:
            md = f.read()
        row = [x for x in md.splitlines() if x.startswith("| 1 | www.example.gov")][0]
        self.assertIn("| Low |", row)            # X25519MLKEM768 is transitional (Low) under nss, not "none"
        self.assertIn("CNSA 2.0", md)


class Patterns(unittest.TestCase):
    def test_matching(self):
        m = context.matches
        self.assertTrue(m("*.example.gov", "www.example.gov"))
        self.assertFalse(m("*.example.gov", "example.gov"))
        self.assertTrue(m("api.example.gov:8443", "api.example.gov:8443"))
        self.assertFalse(m("api.example.gov:8443", "api.example.gov"))
        self.assertTrue(m("api.example.gov", "api.example.gov:8443"))
        self.assertTrue(m("10.2.0.0/16", "10.2.9.9"))
        self.assertTrue(m("10.2.0.0/16:8443", "10.2.0.5:8443"))
        self.assertFalse(m("10.2.0.0/16:8443", "10.2.0.5"))
        self.assertTrue(m("2001:db8::/32", "[2001:db8::1]"))
        self.assertTrue(m("[2001:db8::/32]:8443", "[2001:db8::1]:8443"))
        self.assertFalse(m("10.2.0.0/16", "ten.example.gov"))
        self.assertTrue(m("api.example.gov.", "api.example.gov"))

    def test_bad_patterns(self):
        for p in ("[2001:db8::]:abc", "[::1]junk", "bad host!", "2001:db8::/32:8443", "a.gov:99999"):
            with self.assertRaises(context.ContextError, msg=p):
                context._pattern(p)


class Input(Base):
    def test_invalid_files(self):
        sysd = CTX["systems"][0]
        bad = [{}, dict(CTX, schemaVersion="2.0"), dict(CTX, systems=[]), dict(CTX, extra=1),
               dict(CTX, horizon="2035"), dict(CTX, horizon=2001), dict(CTX, systems=[dict(sysd, impact="critical")]),
               dict(CTX, systems=[dict(sysd, dataLifetimeYears=-1)]), dict(CTX, systems=[dict(sysd, endpoints=[])]),
               dict(CTX, systems=[dict(sysd, endpoints=["bad host!"])]), dict(CTX, systems=[dict(sysd, tier=1)]),
               dict(CTX, systems=[sysd, dict(sysd, name="payments ")])]
        for i, c in enumerate(bad):
            with self.assertRaises(context.ContextError, msg=i):
                context.load_context(self.put(f"b{i}.json", c))

    def test_cli(self):
        out = os.path.join(self.d.name, "att.json")
        ok = context.main(["rank", "--context", self.put("c.json", CTX), "--cbom", self.put("x.json", cbom(HOSTS)),
                           "--json", out])
        self.assertEqual(ok, 0)
        with open(out) as f:
            self.assertEqual(json.load(f)["resultFormat"], "fedlin.pqc-attention")
        self.assertEqual(context.main(["rank", "--context", self.put("e.json", {}), "--cbom",
                                       os.path.join(self.d.name, "x.json")]), 2)
        self.assertEqual(context.main(["rank", "--context", self.put("c2.json", CTX), "--cbom",
                                       self.put("junk.json", [1])]), 2)

    def test_schema_matches_code(self):
        with open(os.path.join(ROOT, "schemas", "context-1.0.schema.json")) as f:
            sch = json.load(f)
        self.assertEqual(set(sch["properties"]), context.TOP_KEYS)
        self.assertEqual(set(sch["properties"]["systems"]["items"]["properties"]), context.SYSTEM_KEYS)
        self.assertEqual(sch["properties"]["systems"]["items"]["properties"]["impact"]["enum"], list(context.IMPACT))


if __name__ == "__main__":
    unittest.main()
