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
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling modules, also under python -I
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


class InputError(ValueError):
    """A CBOM or result file that cannot be read as JSON of the expected shape (exit 2, never a traceback)."""


def load_json(path, what="--cbom", cyclonedx=True):
    """Parsed JSON from path; InputError for unreadable, invalid or too deeply nested JSON, or (cyclonedx) a
    document that is not a CycloneDX object with a components list."""
    try:
        with open(path, "rb") as f:
            doc = json.loads(f.read())      # bytes: UTF-8 with or without a BOM, UTF-16 and UTF-32
    except OSError as e:
        raise InputError(f"{what} {path}: {e.strerror}")
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise InputError(f"{what} {path}: not valid JSON ({str(e)[:120]})")
    if cyclonedx and (not isinstance(doc, dict) or not isinstance(doc.get("components", []) or [], list)
                      or not all(isinstance(c, dict) for c in doc.get("components", []) or [])):
        raise InputError(f"{what} {path}: not a CycloneDX BOM (expected an object with a components list)")
    if not cyclonedx and not isinstance(doc, dict):
        raise InputError(f"{what} {path}: expected a JSON object")
    if cyclonedx:
        doc["components"] = doc.get("components") or []        # absent or null: no components
        for c in doc["components"]:     # a null where an object or list belongs means "none", not a traceback
            for k in ("cryptoProperties", "properties", "components", "evidence"):
                if k in c and c[k] is None:
                    del c[k]
    return doc


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _ruleset_digest():
    return sha256_file(os.path.abspath(cnsa.__file__.replace(".pyc", ".py")))


def _props(c):
    return {p.get("name"): p.get("value") for p in (c.get("properties") or [])}


def _bits(ap):
    b = ap.get("parameterSetIdentifier")
    return int(b) if b and str(b).isdigit() else None


def _csv(v):
    return [x for x in (v or "").split(",") if x and x != "none"]


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
    bom = load_json(cbom_path)
    with open(cbom_path, "rb") as f:
        data = f.read()
    doc = os.path.basename(cbom_path)

    findings, refs = [], {}
    for c in bom.get("components", []):
        if c.get("type") != "cryptographic-asset":
            continue
        cp = c.get("cryptoProperties") or {}
        if cp.get("assetType") != "algorithm":
            continue
        ap = cp.get("algorithmProperties") or {}
        judged = cnsa.name_with_parameter_set(c.get("name", ""), ap.get("parameterSetIdentifier"))
        v = cnsa.classify(judged, None if judged != (c.get("name") or "").strip() else _bits(ap), profile=profile)
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
        rcm = (c.get("cryptoProperties") or {}).get("relatedCryptoMaterialProperties") or {}
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

    # What a TLS endpoint accepts besides the negotiated session (enumeration facts on the interface): every
    # accepted protocol version, cipher suite, key-exchange group and DH size, judged by the same ruleset.
    # Lane "configuration": reported and listed as exposures, but not part of the usage-weighted score.
    for c in bom.get("components", []):
        p = _props(c)
        if p.get("fedlin:enumeration") != "complete":
            continue
        items = [("protocol version", v, None) for v in _csv(p.get("fedlin:acceptedProtocolVersions"))]
        for k, v in sorted(p.items()):
            if k.startswith("fedlin:acceptedCipherSuites:"):
                items += [(f"cipher suite ({k.split(':', 2)[2]})", x, None) for x in _csv(v)]
        items += [("key-exchange group", g, None) for g in _csv(p.get("fedlin:acceptedGroups"))]
        items += [("Diffie-Hellman group", "DH", int(b)) for b in _csv(p.get("fedlin:dhGroupBits")) if b.isdigit()]
        for kind, item, bits in items:
            v = cnsa.classify(item, bits, profile=profile)
            label = f"of {bits} bits" if bits else item
            findings.append({
                "document": doc, "bomRef": c.get("bom-ref"), "name": f"accepts {kind} {label}",
                "canonical": v["canonical"], "lane": "configuration", "status": _status(v),
                "quantumVulnerable": v["quantum_vulnerable"], "priority": v["priority"],
                "target": v["cnsa_target"], "controls": v["controls"],
                "nistQuantumSecurityLevel": v["nist_pqc_level"], "classicalSecurityLevel": v["classical_security_level"],
                "deprecatedAfter": v["deprecated_after"], "disallowedAfter": v["disallowed_after"],
                "ruleId": v["rule_id"], "cite": v["cite"], "note": v["note"],
                "configItem": {"kind": kind, "value": item, "bits": bits},
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


# Every field of the result is compared with a fresh evaluation, except the evaluation date (1.5.0; before,
# only status, target, quantumVulnerable, priority, controls, lane and canonical were, so dates, citations,
# notes and the policy's sources could be changed unnoticed).
_NOT_COMPARED = ("evaluationDate",)
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _regime_of(result):
    """The crosswalk regime the result was evaluated with (None without one), so it can be re-evaluated alike."""
    for f in result.get("findings", []) or []:
        cw = f.get("crosswalk") if isinstance(f, dict) else None
        if isinstance(cw, dict) and cw.get("regime"):
            return str(cw["regime"])
    return None


def check(result, cbom_path):
    """Can these verdicts be trusted for this CBOM? Three independent checks, all must pass.

    bound:       the CBOM file's SHA-256 matches the digest the result recorded for it.
    ruleset:     the result names this toolkit's ruleset (same SHA-256), so it can be re-checked here.
    reproduced:  re-evaluating the CBOM with that ruleset, profile and regime gives the same result, field for
                 field (every finding, the policy block, documents, summary, notAsserted); only the
                 evaluation date may differ. None when the ruleset differs.
    A policy result is not signed: a file that passes says only that its verdicts are what this ruleset
    gives for this CBOM, which is exactly what can be checked without trusting whoever wrote it.
    """
    out = {"bound": bool(verify(result, cbom_path)), "ruleset": False, "reproduced": None, "mismatches": []}
    pol = result.get("policy", {}) or {}
    out["ruleset"] = (pol.get("digest") or {}).get("value") == _ruleset_digest()
    if out["bound"] and out["ruleset"]:
        profile = pol.get("profile") if pol.get("profile") in cnsa.PROFILES else None
        if profile is None:
            out["reproduced"] = False
            out["mismatches"].append("policy result names no known profile")
        else:
            regime = _regime_of(result)
            try:
                fresh = evaluate(cbom_path, profile=profile, regime=regime)
            except Exception as e:  # an unknown regime, for instance
                fresh = evaluate(cbom_path, profile=profile)
                out["mismatches"].append(f"cannot re-evaluate with regime {regime!r}: {e}")
            if not _DATE_RE.match(str(result.get("evaluationDate", ""))):
                out["mismatches"].append("evaluationDate is not a YYYY-MM-DD date")
            for k in sorted(set(result) | set(fresh)):
                if k in _NOT_COMPARED or k in ("findings", "summary"):
                    continue
                a, b = fresh.get(k), result.get(k)
                if a == b:
                    continue
                if isinstance(a, dict) and isinstance(b, dict):
                    sub = sorted(x for x in set(a) | set(b) if a.get(x) != b.get(x))
                    out["mismatches"].append(f"{k}: {', '.join(sub)} differ{'s' if len(sub) == 1 else ''}")
                else:
                    out["mismatches"].append(f"{k}: {'added' if a is None else 'missing' if b is None else 'differs'}")
            key = lambda f: (f.get("bomRef"), f.get("lane"), f.get("name"))  # noqa: E731
            seen = {}
            for f in result.get("findings", []) or []:
                seen[key(f)] = seen.get(key(f), 0) + 1
            for k, n in seen.items():
                if n > 1:  # a duplicate could hide a forged copy behind a genuine one
                    out["mismatches"].append(f"{k[0]} {k[2]}: {n} copies of one finding")
            want = {key(f): f for f in fresh["findings"]}
            got = {key(f): f for f in result.get("findings", []) or []}
            if (result.get("summary") or {}) != fresh["summary"]:
                out["mismatches"].append("summary counts differ from a re-evaluation")
            for k in sorted(set(want) | set(got), key=str):
                a, b = want.get(k), got.get(k)
                if a is None or b is None:
                    out["mismatches"].append(f"{k[0]} {k[2]}: finding {'added' if a is None else 'missing'}")
                    continue
                diff = sorted(x for x in set(a) | set(b) if a.get(x) != b.get(x))
                if diff:
                    out["mismatches"].append(f"{k[0]} {k[2]}: {', '.join(diff)} differ")
            out["reproduced"] = not out["mismatches"]
    out["ok"] = bool(out["bound"] and out["ruleset"] and out["reproduced"])
    return out


def apply(bom, result, cbom_path=None):
    """Return a copy of `bom` with the result's verdicts as properties (in memory only).

    The report and delta stages read verdicts from component properties. This view lets them run
    unchanged while the CBOM on disk stays facts-only. If `cbom_path` is given, the digest is
    verified first and a mismatch raises DigestMismatch.
    """
    if cbom_path and not verify(result, cbom_path):
        raise DigestMismatch(f"{cbom_path} does not match the digest in the policy result")
    view = copy.deepcopy(bom)
    by_ref = {f["bomRef"]: f for f in result.get("findings", []) if f.get("lane") != "configuration"}
    config = {}
    for f in result.get("findings", []):
        if f.get("lane") == "configuration":
            config.setdefault(f["bomRef"], []).append(
                {"item": f["name"], "status": f["status"], "priority": f["priority"], "target": f["target"]})
    profile = result.get("policy", {}).get("profile")
    for c in view.get("components", []):
        f = by_ref.get(c.get("bom-ref"))
        if not f:
            continue
        props = [p for p in (c.get("properties") or [])
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
    for c in view.get("components", []):
        if c.get("bom-ref") in config:
            c["properties"] = [p for p in (c.get("properties") or []) if p.get("name") != "cnsa2:config"] + [
                {"name": "cnsa2:config", "value": json.dumps(config[c["bom-ref"]], separators=(",", ":"))}]
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
               for c in bom.get("components", []) for p in (c.get("properties") or []))


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
    bom = load_json(cbom_path)
    if policy_path:
        result = load_json(policy_path, "--policy", cyclonedx=False)
        return apply(bom, result, cbom_path), result
    result = evaluate(cbom_path, profile=profile, regime=regime)
    return apply(bom, result), result


def main(argv=None):
    ap = argparse.ArgumentParser(description="Evaluate or verify a FEDLIN PQC policy result.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("evaluate")
    e.add_argument("--cbom", required=True)
    e.add_argument("--profile", choices=list(cnsa.PROFILES), default=cnsa.DEFAULT_PROFILE)
    e.add_argument("--regime", default="", type=str.upper, choices=["", *crosswalk.REGIMES],
                   metavar="{" + ",".join(crosswalk.REGIMES) + "}")
    e.add_argument("--date", default=None)
    e.add_argument("--out", default="")
    v = sub.add_parser("verify")
    v.add_argument("--cbom", required=True)
    v.add_argument("--policy", required=True)
    a = ap.parse_args(argv)
    try:
        return _main(a)
    except InputError as e:
        sys.stderr.write(f"[error] {e}\n")
        return 2


def _main(a):
    if a.cmd == "evaluate":
        r = evaluate(a.cbom, a.profile, a.regime or None, a.date)
        out = a.out or a.cbom.rsplit(".", 1)[0] + ".policy.json"
        with open(out, "w") as f:
            json.dump(r, f, indent=2)
        print(f"[ok] policy result: {out}: {r['policy']['policyId']} {r['policy']['version']}, "
              f"{len(r['findings'])} finding(s): {r['summary']}")
        return 0
    r = load_json(a.policy, "--policy", cyclonedx=False)
    load_json(a.cbom)
    c = check(r, a.cbom)
    pol = r.get("policy", {}) or {}
    print(f"[{'ok' if c['bound'] else 'FAIL'}] CBOM digest {'matches' if c['bound'] else 'does not match'} {a.policy}")
    if c["ruleset"]:
        print(f"[ok] ruleset {cnsa.RULESET_VERSION} (this toolkit's)")
    else:
        print(f"[FAIL] the result names ruleset {pol.get('version')!r}, not this toolkit's {cnsa.RULESET_VERSION} "
              "(different digest): its verdicts cannot be re-checked here; re-run `policy.py evaluate`")
    if c["reproduced"] is True:
        print("[ok] every field reproduced by re-evaluating the CBOM (only the evaluation date may differ)")
    elif c["reproduced"] is False:
        print(f"[FAIL] verdicts do not match a re-evaluation ({len(c['mismatches'])}): " + "; ".join(c["mismatches"][:10]))
    return 0 if c["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
