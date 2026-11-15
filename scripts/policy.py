#!/usr/bin/env python3
"""Policy stage: judge a facts-only CBOM and write a digest-bound policy result.

A CBOM records facts (algorithms, parameter sets, certificates, protocol sessions). Verdicts such
as "quantum-vulnerable", "compliant under the civilian profile", a migration target or a priority
change when guidance changes, so they live here, in a separate result that names the ruleset and its
version, the profile, the evaluation date, and every CBOM it read by SHA-256 digest. The result
points to the CBOM; the CBOM never points to the result. This follows the PKI Consortium CBOM
methodology's decision record 0002 ("A CBOM records facts; judgements are made by external policy")
and its result format `pkic.cbom.policy-result` 0.1 (github.com/pkic/cbom, MIT).

Usage:
  python3 policy.py evaluate --cbom out/cbom.json [--profile civilian|nss] [--regime FISMA]
                             [--date YYYY-MM-DD] [--out out/cbom.policy.json]
  python3 policy.py verify   --cbom out/cbom.json --policy out/cbom.policy.json
Exit: 0 ok, 1 digest mismatch, 2 usage error
"""

import argparse
import copy
import datetime
import hashlib
import json
import os
import sys

import cnsa20_ruleset as cnsa
import crosswalk

RESULT_FORMAT = "pkic.cbom.policy-result"
RESULT_FORMAT_VERSION = "0.1"
POLICY_ID = "fedlin.pqc-ruleset"

NOT_ASSERTED = [
    "that the disclosed values are true; the ruleset was applied to what the CBOM states",
    "anything about algorithms, keys or protocols the CBOM does not disclose (see the scan's coverage)",
    "compliance with any framework; verdicts are migration-planning evidence, not an authorization",
    "a PKI Consortium PQCMM level; the readiness score is FEDLIN's own measure",
    "anything after the evaluation date; the same facts give a different result under a later date or ruleset",
]

# Verdict properties the report and delta read. They are written into an in-memory view only.
VERDICT_PREFIXES = ("cnsa2:", "crosswalk:")
VERDICT_NAMES = ("fedlin:profile", "fedlin:lane", "fedlin:rule_id", "fedlin:cite")


class DigestMismatch(Exception):
    pass


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _ruleset_digest():
    return sha256_file(os.path.abspath(cnsa.__file__.replace(".pyc", ".py")))


def _props(c):
    return {p.get("name"): p.get("value") for p in c.get("properties", [])}


def _bits(ap):
    b = ap.get("parameterSetIdentifier")
    return int(b) if b and str(b).isdigit() else None


def _status(v):
    if v["priority"] == "Critical":
        return "broken"
    if v["quantum_vulnerable"] is True:
        return "vulnerable"
    if v["quantum_vulnerable"] is False:
        return "compliant" if (v["cnsa_target"] or "").startswith("None") else "transitional"
    return "unclassified"


def evaluate(cbom_path, profile=None, regime=None, date=None):
    """Evaluate a CBOM file and return a policy result (dict)."""
    profile = (profile or cnsa.DEFAULT_PROFILE).lower()
    if profile not in cnsa.PROFILES:
        raise ValueError(f"unknown profile {profile!r}")
    date = date or datetime.datetime.utcnow().strftime("%Y-%m-%d")
    with open(cbom_path, "rb") as f:
        data = f.read()
    bom = json.loads(data)
    doc = os.path.basename(cbom_path)

    findings, refs = [], {}
    for c in bom.get("components", []):
        if c.get("type") != "cryptographic-asset":
            continue
        cp = c.get("cryptoProperties", {})
        if cp.get("assetType") != "algorithm":
            continue
        ap = cp.get("algorithmProperties", {})
        v = cnsa.classify(c.get("name", ""), _bits(ap), profile=profile)
        f = {
            "document": doc, "bomRef": c.get("bom-ref"), "name": c.get("name"),
            "canonical": v["canonical"], "lane": v["lane"], "status": _status(v),
            "quantumVulnerable": v["quantum_vulnerable"], "priority": v["priority"],
            "target": v["cnsa_target"], "controls": v["controls"],
            "nistQuantumSecurityLevel": v["nist_pqc_level"],
            "classicalSecurityLevel": v["classical_security_level"],
            "deprecatedAfter": v["deprecated_after"], "disallowedAfter": v["disallowed_after"],
            "ruleId": v["rule_id"], "cite": v["cite"], "note": v["note"],
        }
        if v.get("components"):
            f["components"] = v["components"]
        if v.get("deadline_note"):
            f["deadlineNote"] = v["deadline_note"]
        if regime:
            xs = crosswalk.regime_refs(v["controls"], regime)
            if xs:
                f["crosswalk"] = {"regime": regime, "refs": xs}
        findings.append(f)
        refs[c.get("bom-ref")] = f

    # Harvest-now-decrypt-later material: wrapped by a quantum-vulnerable algorithm -> Critical.
    for c in bom.get("components", []):
        p = _props(c)
        if "fedlin:hndl_exposure" not in p:
            continue
        rcm = c.get("cryptoProperties", {}).get("relatedCryptoMaterialProperties", {})
        alg = refs.get(rcm.get("algorithmRef"))
        vuln = bool(alg and alg["quantumVulnerable"])
        findings.append({
            "document": doc, "bomRef": c.get("bom-ref"), "name": c.get("name"), "lane": "hndl",
            "status": "vulnerable" if vuln else "unclassified",
            "priority": "Critical" if vuln else "Review",
            "quantumVulnerable": True if vuln else None,
            "target": (alg or {}).get("target", "Manual review"),
            "ruleId": f"{cnsa.RULESET_VERSION}:hndl-material",
            "note": "Harvest-now-decrypt-later exposure: " + p["fedlin:hndl_exposure"],
            "cite": ["IR8547"] if vuln else [],
        })

    summary = {}
    for f in findings:
        summary[f["status"]] = summary.get(f["status"], 0) + 1
    return {
        "resultFormat": RESULT_FORMAT, "resultFormatVersion": RESULT_FORMAT_VERSION,
        "policy": {"policyId": f"{POLICY_ID}.{profile}", "version": cnsa.RULESET_VERSION,
                   "file": "cnsa20_ruleset.py", "profile": profile,
                   "digest": {"alg": "SHA-256", "value": _ruleset_digest()},
                   "sources": {k: cnsa.SOURCES[k] for k in sorted({s for f in findings for s in f.get("cite", [])})}},
        "evaluationDate": date,
        "documents": [{"file": doc, "serialNumber": bom.get("serialNumber"), "version": bom.get("version"),
                       "digest": {"alg": "SHA-256", "value": hashlib.sha256(data).hexdigest()}}],
        "summary": summary,
        "findings": findings,
        "notAsserted": NOT_ASSERTED,
    }


def verify(result, cbom_path):
    """True when the CBOM file's SHA-256 matches the digest the result recorded for it."""
    want = {d["file"]: d["digest"]["value"] for d in result.get("documents", [])}
    got = sha256_file(cbom_path)
    return want.get(os.path.basename(cbom_path)) == got or got in want.values()


def apply(bom, result, cbom_path=None):
    """Return a copy of `bom` with the result's verdicts as properties (in memory only).

    The report and delta stages read verdicts from component properties. This view lets them run
    unchanged while the CBOM on disk stays facts-only. If `cbom_path` is given, the digest is
    verified first and a mismatch raises DigestMismatch.
    """
    if cbom_path and not verify(result, cbom_path):
        raise DigestMismatch(f"{cbom_path} does not match the digest in the policy result")
    view = copy.deepcopy(bom)
    by_ref = {f["bomRef"]: f for f in result.get("findings", [])}
    profile = result.get("policy", {}).get("profile")
    for c in view.get("components", []):
        f = by_ref.get(c.get("bom-ref"))
        if not f:
            continue
        props = [p for p in c.get("properties", [])
                 if not p.get("name", "").startswith(VERDICT_PREFIXES) and p.get("name") not in VERDICT_NAMES]
        if f.get("lane") == "hndl":
            props.append({"name": "cnsa2:priority", "value": f["priority"]})
        else:
            props += [
                {"name": "cnsa2:quantum_vulnerable", "value": str(f["quantumVulnerable"])},
                {"name": "cnsa2:target", "value": f["target"]},
                {"name": "cnsa2:controls", "value": ",".join(f.get("controls", []))},
                {"name": "cnsa2:priority", "value": f["priority"]},
                {"name": "fedlin:lane", "value": f.get("lane") or "other"},
            ]
            if profile:
                props.append({"name": "fedlin:profile", "value": profile})
            if f.get("crosswalk"):
                props.append({"name": f"crosswalk:{f['crosswalk']['regime']}",
                              "value": " | ".join(f["crosswalk"]["refs"])})
        c["properties"] = props
    view.setdefault("metadata", {}).setdefault("properties", [])
    view["metadata"]["properties"] = [p for p in view["metadata"]["properties"]
                                      if p.get("name") != "fedlin:profile"]
    if profile:
        view["metadata"]["properties"].append({"name": "fedlin:profile", "value": profile})
    if any(f.get("crosswalk") for f in result.get("findings", [])):
        regime = next(f["crosswalk"]["regime"] for f in result["findings"] if f.get("crosswalk"))
        if not any(p.get("name") == "fedlin:regime" for p in view["metadata"]["properties"]):
            view["metadata"]["properties"].append({"name": "fedlin:regime", "value": regime})
    return view


def has_verdicts(bom):
    """True for a legacy CBOM that carries verdicts inline (pre-split toolkit output)."""
    return any(p.get("name") == "cnsa2:quantum_vulnerable"
               for c in bom.get("components", []) for p in c.get("properties", []))


def strip_verdicts(bom):
    """Remove inline verdict properties so a CBOM records facts only. Returns the number removed."""
    n = 0
    for c in bom.get("components", []):
        if "properties" not in c:
            continue
        keep = [p for p in c["properties"]
                if not p.get("name", "").startswith(VERDICT_PREFIXES) and p.get("name") not in VERDICT_NAMES]
        n += len(c["properties"]) - len(keep)
        if keep:
            c["properties"] = keep
        else:
            del c["properties"]
    return n


def load_view(cbom_path, policy_path=None, profile=None, regime=None):
    """CBOM + verdicts for reporting. Uses the policy file if given (digest-verified); otherwise
    evaluates the CBOM now. Returns (view, result)."""
    with open(cbom_path) as f:
        bom = json.load(f)
    if policy_path:
        with open(policy_path) as f:
            result = json.load(f)
        return apply(bom, result, cbom_path), result
    result = evaluate(cbom_path, profile=profile, regime=regime)
    return apply(bom, result), result


def main(argv=None):
    ap = argparse.ArgumentParser(description="Evaluate or verify a FEDLIN PQC policy result.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("evaluate")
    e.add_argument("--cbom", required=True)
    e.add_argument("--profile", choices=list(cnsa.PROFILES), default=cnsa.DEFAULT_PROFILE)
    e.add_argument("--regime", default="")
    e.add_argument("--date", default=None)
    e.add_argument("--out", default="")
    v = sub.add_parser("verify")
    v.add_argument("--cbom", required=True)
    v.add_argument("--policy", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "evaluate":
        r = evaluate(a.cbom, a.profile, a.regime or None, a.date)
        out = a.out or a.cbom.rsplit(".", 1)[0] + ".policy.json"
        with open(out, "w") as f:
            json.dump(r, f, indent=2)
        print(f"[ok] policy result: {out} — {r['policy']['policyId']} {r['policy']['version']}, "
              f"{len(r['findings'])} finding(s): {r['summary']}")
        return 0
    with open(a.policy) as f:
        r = json.load(f)
    if verify(r, a.cbom):
        print(f"[ok] {a.cbom} matches the digest recorded in {a.policy}")
        return 0
    print(f"[FAIL] {a.cbom} does not match the digest recorded in {a.policy}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
