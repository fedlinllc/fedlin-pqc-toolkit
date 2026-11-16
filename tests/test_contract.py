"""1.x stability contract (see STABILITY.md): listed names may be added to, never removed. Offline."""
import json
import os
import re
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mcp_server as ms  # noqa: E402
import policy  # noqa: E402
import report  # noqa: E402
from test_mcp_server import make_outputs  # noqa: E402

CBOM_PROPERTIES = {
    "fedlin:enumeration", "fedlin:enumerationTool", "fedlin:acceptedProtocolVersions",
    "fedlin:untestedProtocolVersions", "fedlin:acceptedGroups", "fedlin:refusedGroups", "fedlin:untestedGroups",
    "fedlin:dhGroupBits", "fedlin:enumerationTruncated", "fedlin:enumerationIncomplete", "fedlin:enumerationNote", "fedlin:certificateSelectedBy",
    "fedlin:sha256Fingerprint", "fedlin:not_captured",
    "fedlin:capability", "fedlin:capture", "fedlin:chain_depth", "fedlin:classicalOnlyCommand",
    "fedlin:classicalOnlyNegotiated", "fedlin:classicalOnlyOffer", "fedlin:classicalOnlyOfferReduced",
    "fedlin:classicalOnlyTool", "fedlin:etcd_encryption", "fedlin:evidence", "fedlin:fips_enabled",
    "fedlin:hndl_exposure", "fedlin:host", "fedlin:hsm_indicators", "fedlin:hw_action",
    "fedlin:hw_action_detail", "fedlin:hw_class", "fedlin:hw_fips_status", "fedlin:hw_pqc_capable",
    "fedlin:hw_pqc_gate", "fedlin:hw_vendor", "fedlin:kex_partial_evidence", "fedlin:kex_probe",
    "fedlin:kube_version", "fedlin:min_tls", "fedlin:mode", "fedlin:ocp_version", "fedlin:openssl_version",
    "fedlin:os_id", "fedlin:os_version_id", "fedlin:registry_family", "fedlin:registry_name",
    "fedlin:sealed_secret_crs", "fedlin:source", "fedlin:tls_ciphers",
}
PKIC_PROPERTIES = {
    "pkic:profile:interfaceType", "pkic:profile:lifecycleStage", "pkic:profile:endpointRole:server",
    "pkic:profile:endpointRole:client", "pkic:profile:observationMethod", "pkic:profile:protocolVersion",
    "pkic:profile:keyExchange", "pkic:profile:encryption", "pkic:profile:authentication",
}
POLICY_KEYS = {"documents", "evaluationDate", "findings", "notAsserted", "policy", "resultFormat",
               "resultFormatVersion", "summary"}
POLICY_BLOCK = {"digest", "file", "policyId", "profile", "sources", "version"}
FINDING_KEYS = {"bomRef", "canonical", "cite", "classicalSecurityLevel", "controls", "deadlineNote",
                "deprecatedAfter", "disallowedAfter", "document", "lane", "name", "nistQuantumSecurityLevel",
                "note", "priority", "quantumVulnerable", "ruleId", "status", "target"}
SUMMARY_KEYS = {"algorithms_classified", "awaiting_review", "cbom_timestamp", "certificates",
                "certs_expiring_90d", "certs_over_lifetime_cap", "cipher_suites", "classical_fallback", "cmvp", "evidence",
                "grade", "hndl_exposures", "kex_unobserved", "lanes", "min_tls", "other_assets", "profile",
                "public_key_usages_scored", "quantum_resistant", "quantum_vulnerable", "readiness_score", "regime",
                "secret_hygiene_detections", "system"}
CLI_FLAGS = {"--version", "--out", "--name", "--repo", "--theia-dir", "--theia-image", "--cdxgen", "--theia",
             "--cyclonedx", "--validate", "--redact", "--profile", "--subject-tag", "--regime", "--deep",
             "--debug-image", "--kube-cli", "--report", "--merge-cbom", "--exclude", "--no-dep-crypto",
             "--no-classical-probe", "--no-enumerate", "--enumerate-pace", "--endpoints", "--no-runtime"}
EVIDENCE_SOURCES = {  # STABILITY.md "Evidence sources": source -> (technique, confidence)
    "handshake": ("dynamic-analysis", 1.0), "probe": ("dynamic-analysis", 1.0),
    "configuration": ("other", 0.8), "file": ("other", 0.8),
    "dependency": ("manifest-analysis", 0.3), "assumption": ("other", 0.1),
}
MCP_TOOLS = {"list_files": set(), "verify_policy": {"cbom", "policy"},
             "summarize": {"cbom", "policy", "profile"}, "pqcmm_evidence": {"cbom", "answers", "profile"},
             "vendor_readiness": {"answers", "profile"}, "lookup_verdict": {"name", "bits", "profile"}}

def _load(path):
    with open(path) as f:
        return json.load(f)


def _dump(obj, path):
    with open(path, "w") as f:
        json.dump(obj, f)



def _source(*names):
    out = []
    for n in names:
        with open(os.path.join(ROOT, "scripts", n), encoding="utf-8") as f:
            out.append(f.read())
    return "".join(out)


class Contract(unittest.TestCase):
    def test_cbom_property_names(self):
        # a promised name must have an emission site, not merely appear somewhere in the source
        src = _source("tier2_pipeline.py", "collect-hardware-linux.py", "merge-hw-cbom.py", "cmvp.py")
        written = set(re.findall(r'"name":\s*"(fedlin:[A-Za-z0-9_]+)"', src))
        written |= set(re.findall(r'"name":\s*"(pkic:profile:[A-Za-z:_]+)"', src))
        written |= {"pkic:profile:" + m for m in re.findall(r'"name":\s*P \+ "([A-Za-z:_]+)"', src)}
        written |= set(re.findall(r'\("[a-z_]+", "(fedlin:[A-Za-z0-9_]+)"\)', src))  # (field, property-name) tables
        # scan context keys become fedlin:<key> metadata properties (CBOM.to_dict)
        ctx_keys = set(re.findall(r'ctx\[["\']([a-z_]+)["\']\]\s*=', src))
        for body in re.findall(r'ctx = \{(.*?)\}', src, re.S):
            ctx_keys |= set(re.findall(r'"([a-z_]+)":', body))
        written |= {"fedlin:" + k for k in ctx_keys}
        with tempfile.TemporaryDirectory() as d:  # names built at run time: read them from a real CBOM
            bom = _load(make_outputs(d))
        written |= {p["name"] for c in bom["components"] for p in c.get("properties", [])}
        self.assertEqual(CBOM_PROPERTIES - written, set())
        self.assertIn('f"fedlin:acceptedCipherSuites:{v}"', src)  # one property per protocol version
        self.assertEqual(PKIC_PROPERTIES - written, set())

    def test_policy_result_and_summary(self):
        with tempfile.TemporaryDirectory() as d:
            cbom = make_outputs(d)
            r = _load(os.path.join(d, "cbom.policy.json"))
            view, _ = policy.load_view(cbom, os.path.join(d, "cbom.policy.json"))
            _, summary = report.build_report(view)
        self.assertEqual(POLICY_KEYS - set(r), set())
        self.assertEqual(POLICY_BLOCK - set(r["policy"]), set())
        self.assertEqual(FINDING_KEYS - set(r["findings"][0]), set())
        self.assertEqual(SUMMARY_KEYS - set(summary), set())

    def test_evidence_sources(self):
        import evidence
        for src, (tech, conf) in EVIDENCE_SOURCES.items():
            self.assertIn(src, evidence.SOURCES)
            self.assertEqual(evidence.SOURCES[src][:2], (tech, conf), src)
        # the documented table says the same as the code
        with open(os.path.join(ROOT, "STABILITY.md"), encoding="utf-8") as f:
            doc = {m[0]: (m[1], float(m[2])) for m in re.findall(
                r"^\| `([a-z]+)` \| `([a-z-]+)` \| ([0-9.]+) \|", f.read(), re.M)}
        self.assertEqual(doc, {k: v[:2] for k, v in evidence.SOURCES.items()})
        # each promised source has an emission site
        code = _source("tier2_pipeline.py")
        for src in EVIDENCE_SOURCES:
            self.assertIn('"%s"' % src, code, src)
        with tempfile.TemporaryDirectory() as d:
            bom = _load(make_outputs(d))
        stamped = [c for c in bom["components"] if c.get("type") == "cryptographic-asset"
                   and (c.get("evidence") or {}).get("identity")]
        self.assertTrue(stamped)
        for c in stamped:
            ident = c["evidence"]["identity"]
            self.assertIsInstance(ident, list)
            self.assertEqual(ident[0]["field"], "name")
            for m in ident[0]["methods"]:
                self.assertTrue(m["value"].startswith("fedlin-pqc-toolkit/"))

    def test_cli_flags(self):
        flags = set(re.findall(r'add_argument\("(--[a-z0-9-]+)"', _source("tier2_pipeline.py")))
        self.assertEqual(CLI_FLAGS - flags, set())

    def test_mcp_tools(self):
        got = {t["name"]: set(t["inputSchema"]["properties"]) for t in ms.Server.TOOLS}
        for name, args in MCP_TOOLS.items():
            self.assertIn(name, got)
            self.assertEqual(args - got[name], set(), name)


if __name__ == "__main__":
    unittest.main()
