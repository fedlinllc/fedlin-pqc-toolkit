#!/usr/bin/env python3
"""PQCMM evidence: map what the toolkit observed to the PKI Consortium PQC Maturity Model's questions.

The PQC Maturity Model (PKI Consortium, v1.0.1, MIT, vendored in third_party/pkic-pqcmm) assesses a product
or service. This toolkit observes one deployment. So this module does not award a level or mark any
criterion met: it pre-fills PQCMM response fields with values it can evidence, says where each value came
from, and leaves every criterion for an assessor to decide.

Provenance of each value:
  observed   seen directly in the CBOM (a handshake, a certificate, a component)
  derived    computed from the CBOM by this toolkit's ruleset or checks
  snapshot   from the dated NIST CMVP snapshot (candidates only)
  vendor     taken from a vendor-readiness answers file: vendor-stated, not independently verified

Usage:
    python3 scripts/pqcmm_evidence.py --cbom out/cbom.json [--answers answers.json] [--profile civilian|nss]
"""
import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cmvp  # noqa: E402
import cnsa20_ruleset as cnsa  # noqa: E402
import vendor_readiness as vr  # noqa: E402

MODEL = os.path.join(ROOT, "third_party", "pkic-pqcmm", "pqcmm-model-1.0.1.json")
MODEL_SOURCE = "https://github.com/pkic/pqcmm (tag v1.0.1, commit 5ad816e)"
PQC_FAMILIES = ("ML-KEM", "ML-DSA", "SLH-DSA", "LMS", "XMSS", "FN-DSA")
P = "pkic:profile:"


def load_model(path=MODEL):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _props(c):
    return {p.get("name"): p.get("value") for p in c.get("properties", []) or []}


def _questions(model):
    out = {}
    for L in model["levels"]:
        for g in L["assessment"]["groups"]:
            for q in g["questions"]:
                out[q["id"]] = dict(q, level=L["number"], group=g["name"])
    return out


def _criteria(model):
    return [dict(c, level=L["number"]) for L in model["levels"] for c in L["criteria"]["items"]]


# --- facts ------------------------------------------------------------------------------------
class Facts:
    def __init__(self, bom, cbom_path, profile, answers=None):
        self.bom, self.path, self.profile, self.answers = bom, cbom_path, profile, answers or {}
        f = vr.cbom_facts(bom, profile)
        self.algos, self.certs, self.libs = f["algorithms"], f["certificates"], f["libraries"]
        self.protocols, self.by_ref = f["protocols"], f["by_ref"]
        self.coverage = f["coverage"]
        md = bom.get("metadata", {}) or {}
        self.subject = md.get("component", {}) or {}
        self.timestamp = md.get("timestamp", "")
        tools = (md.get("tools", {}) or {}).get("components", []) if isinstance(md.get("tools"), dict) else []
        self.tool = ", ".join(f"{t.get('name')} {t.get('version', '')}".strip() for t in tools) or "unknown"
        # Whether this toolkit produced the CBOM; a vendor-supplied CBOM is the vendor's statement (1.6.0)
        self.ours = any("fedlin" in str(t.get("name") or "").lower() for t in tools)
        self.inputs = {}
        snap, _ = cmvp.load_snapshot()
        self.snap = snap
        self.cmvp = cmvp.match(bom, snap)
        self.pqc = [a for a in self.algos if a["vulnerable"] is False and a["family"] in PQC_FAMILIES]
        self.match_notes = []
        if self.answers:
            # Do the answers describe the product this CBOM describes?
            want = " ".join(str(self.answers.get(k) or "") for k in ("product", "version")).strip().lower()
            have = " ".join(str(self.subject.get(k) or "") for k in ("name", "version")).strip().lower()
            prod = str(self.answers.get("product") or "").strip().lower()
            if prod and self.subject.get("name") and prod not in have and str(self.subject.get("name")).lower() not in want:
                self.match_notes.append(f"The answers are for product {self.answers.get('product')!r} but the CBOM "
                                        f"describes {self.subject.get('name')!r}: check they are the same product.")
            ver = str(self.answers.get("version") or "").strip()
            if ver and self.subject.get("version") and ver != str(self.subject.get("version")):
                self.match_notes.append(f"The answers are for version {ver} but the CBOM describes version "
                                        f"{self.subject.get('version')}.")
        self.vulnerable = [a for a in self.algos if a["vulnerable"] is True]

    def interfaces(self):
        out = []
        for c in self.protocols:
            p = _props(c)
            kex = p.get(P + "keyExchange") or "unknown"
            r = cnsa.classify(kex, profile=self.profile) if kex != "unknown" else {}
            out.append({"name": c.get("name"), "method": p.get(P + "observationMethod", ""),
                        "kex": kex, "kex_vulnerable": True if (kex == "unknown" and p.get("fedlin:hndlInferred"))
                        else r.get("quantum_vulnerable"), "hndl_inferred": p.get("fedlin:hndlInferred", ""),
                        "kex_family": r.get("family"), "kex_canonical": r.get("canonical") or "",
                        "auth": p.get(P + "authentication", ""), "enc": p.get(P + "encryption", ""),
                        "server": p.get(P + "endpointRole:server", ""), "version": p.get(P + "protocolVersion", ""),
                        "co": p.get("fedlin:classicalOnlyOffer"), "co_got": p.get("fedlin:classicalOnlyNegotiated", ""),
                        "co_tool": p.get("fedlin:classicalOnlyTool", ""),
                        "co_cmd": p.get("fedlin:classicalOnlyCommand", "")})
        return out

    def cert_rows(self):
        rows = []
        for c in self.certs:
            cp = (c.get("cryptoProperties", {}) or {}).get("certificateProperties", {}) or {}
            sig = self.by_ref.get(cp.get("signatureAlgorithmRef"), {}).get("name", "?")
            key = self.by_ref.get(cp.get("subjectPublicKeyRef"), {}).get("name", "?")
            rows.append((c.get("name"), sig, key))
        return rows


def _ev(fields, provenance, note=""):
    return {"fields": {k: v for k, v in fields.items() if v not in (None, "", [])}, "provenance": provenance,
            "note": note}


def _pkic_conforms(path):
    if not path:
        return None
    return vr.pkic_entry_profile(path)


# --- evidence per question ------------------------------------------------------------------
def evidence(F):
    """{question id: evidence} for the questions this toolkit can evidence from a CBOM."""
    E = {}
    version = F.subject.get("version") or ""
    ifaces = F.interfaces()
    pqc_names = sorted({a["name"] for a in F.pqc})

    E["0.2.2"] = _ev({"available": True, "documentUrl": os.path.basename(F.path)}, "observed",
                     "CycloneDX CBOM of the assessed deployment, produced by this toolkit." if F.ours else
                     f"CycloneDX CBOM supplied with the assessment (generated by {F.tool}); not produced or "
                     "verified by this toolkit.")
    if pqc_names:
        note = ("Observed in the assessed deployment. The PQCMM also asks for release notes confirming the release "
                "channel or GA status; this toolkit cannot see those.")
        E["1.2.1"] = _ev({"algorithms": ", ".join(pqc_names), "productVersion": version}, "observed", note)
        E["2.2.1"] = _ev({"algorithms": ", ".join(pqc_names), "productVersion": version}, "observed", note)
    breakdown = [f"{i['name']}: key exchange {i['kex']}, authentication {i['auth'] or '?'}" for i in ifaces]
    breakdown += [f"certificate {n}: signature {s}, key {k}" for n, s, k in F.cert_rows()]
    if breakdown:
        E["1.3.1"] = _ev({"componentBreakdown": "\n".join(breakdown)}, "observed",
                         ("Interfaces and certificates the scan reached" if F.ours else "Interfaces and certificates "
                          "the CBOM lists") + f"; declared coverage: {F.coverage}.")
        E["2.2.2"] = _ev({"componentBreakdown": "\n".join(
            b for b in breakdown if any(n in b for n in pqc_names)) or "No component uses a PQC algorithm."},
            "observed")
        all_rows = breakdown + [f"{a['name']} ({a['lane'] or 'unclassified'})" for a in F.algos
                                if a["lane"] in ("symmetric", "hash", "protocol")]
        E["1.3.2"] = _ev({"cryptography": "\n".join(all_rows)}, "observed",
                         "Low-level components (firmware, bootloader) are visible only if a host collector ran.")
    libs = []
    for f in F.cmvp:
        libs.append(f"{f['label']} ({'; '.join(f['seen'])})")
    for c in F.libs:
        libs.append(f"{c.get('name')} {c.get('version') or '(no version)'}")
    if libs:
        for qid in ("1.5.1", "2.2.3"):
            E[qid] = _ev({"libraries": "\n".join(dict.fromkeys(libs))}, "observed")
        E["5.5.3"] = _ev({"libraryName": "; ".join(dict.fromkeys(libs))}, "observed",
                         "The CBOM shows which libraries are present, not which one implements each PQC algorithm.")
    if pqc_names:
        stds = []
        for a in F.pqc:
            r = cnsa.classify(a["name"], profile=F.profile)
            stds.append(f"{a['name']}: " + "; ".join(cnsa.SOURCES.get(k, k) for k in r.get("cite", []) if k in cnsa.SOURCES))
        E["2.3.1"] = _ev({"standards": "\n".join(dict.fromkeys(stds)), "algorithmNaming": "standard names"},
                         "derived", "Standards the observed algorithm names belong to, per the toolkit ruleset. "
                                    "Conformance itself needs CAVP/CMVP or test evidence.")
    cands = [(f, c) for f in F.cmvp if f["kind"] == "candidate" for c in f["certificates"]]
    if cands:
        nums = ", ".join(f"#{c['cert']}" for _, c in cands)
        urls = "\n".join(f"{cmvp.CMVP_BASE}/certificate/{c['cert']}" for _, c in cands)
        pqc_ok = sorted({x for _, c in cands for x in (c.get("pqc_approved") or [])})
        note = (f"Candidate certificates from the CMVP snapshot of {F.snap.get('fetched')}: not proof that the deployed "
                "build is validated. Approved PQC algorithms on these certificates: " + (", ".join(pqc_ok) or "none") + ".")
        E["2.3.2"] = _ev({"proofType": "CMVP listing (candidate)", "certificateNumber": nums, "listingUrl": urls},
                         "snapshot", note)
        E["5.5.1"] = _ev({"scheme": "FIPS 140-3 (candidate)", "certificateNumber": nums, "listingUrl": urls},
                         "snapshot", note)
    interop = [i for i in ifaces if i["method"] == "active-probe" and i["kex_vulnerable"] is False
               and i["kex_family"] in PQC_FAMILIES]
    if interop:
        E["2.3.3"] = _ev({"implementation": "fedlin-pqc-toolkit probe client (OpenSSL 3.5); server implementation "
                                            "not identifiable from outside",
                          "protocol": "; ".join(f"TLS {i['version']} {i['kex']} with {i['server'].split(':', 1)[-1]}"
                                                for i in interop),
                          "outcome": "success (key exchange negotiated)"}, "observed",
                         "A completed handshake between the toolkit's client and the server. Whether the two "
                         "implementations are independent depends on the server's implementation, which an outside "
                         "scan cannot see.")
    tested = [i for i in ifaces if i["co"]]
    if tested:
        seen = [i["co"] for i in tested]
        # The model's select allows rejected / accepted / untested. One acceptance is a finding; "rejected"
        # only if every endpoint refused; nothing contacted is "untested"; any other mix is left to the assessor.
        overall = ("accepted" if "accepted" in seen else "rejected" if set(seen) == {"rejected"}
                   else "untested" if set(seen) == {"untested"} else None)
        counts = ", ".join(f"{seen.count(o)} {o}" for o in dict.fromkeys(seen))
        lines = []
        for i in tested:
            host = i["server"].split(":", 1)[-1]
            lines.append(f"{host}: {i['co_cmd'] or '(command not recorded)'} -> {i['co']}"
                         + (f" ({i['co_got']})" if i["co_got"] else ""))
        E["4.3.1"] = _ev({"testTool": "; ".join(dict.fromkeys(i["co_tool"] for i in tested if i["co_tool"])),
                          "testCommand": "\n".join(lines), "classicalConnectionOutcome": overall}, "observed",
                         "A second handshake from a client offering only classical key exchange (TLS 1.2 allowed). "
                         "It tests the deployment as configured; whether a zero-legacy configuration was applied, and "
                         "how (configurationMechanism), is the vendor's to state. Only key exchange was restricted: "
                         "the server certificate's signature algorithm is a separate question (4.3.3). "
                         f"Per endpoint: {counts}. 'inconclusive' means the handshake failed for a reason other than "
                         "a handshake-failure/insufficient-security alert, or a FIPS-mode client (no X25519/X448) was "
                         "refused; when endpoints are inconclusive and none accepted, the outcome field is left for "
                         "the assessor.")
    E["3.2.1"] = _ev({"inventoryFormat": f"CycloneDX {F.bom.get('specVersion', '?')}", "productVersion": version,
                      "lastUpdated": F.timestamp[:10]}, "observed")
    E["4.2.1"] = _ev({"cbomFormat": f"CycloneDX {F.bom.get('specVersion', '?')} (cryptoProperties)",
                      "schemaVersion": F.bom.get("specVersion"), "generationTool": F.tool,
                      "generationDate": F.timestamp[:10], "productVersion": version}, "observed")
    incomplete = []
    # key size of a signature algorithm lives on the certificate key it is used with
    cert_key_sized = set()
    for c in F.certs:
        cp = (c.get("cryptoProperties", {}) or {}).get("certificateProperties", {}) or {}
        key = F.by_ref.get(cp.get("subjectPublicKeyRef"), {})
        kap = ((key.get("cryptoProperties", {}) or {}).get("algorithmProperties", {}) or {})
        if kap.get("parameterSetIdentifier") or kap.get("curve"):
            cert_key_sized.add(cp.get("signatureAlgorithmRef"))
    checked = [a for a in F.algos if a["lane"] != "protocol"]
    for a in checked:
        c = F.by_ref.get(a["ref"], {})
        ap = (c.get("cryptoProperties", {}) or {}).get("algorithmProperties", {}) or {}
        missing = []
        sized = (ap.get("parameterSetIdentifier") or ap.get("curve") or ap.get("classicalSecurityLevel")
                 or (ap.get("nistQuantumSecurityLevel") or 0) >= 1 or a["ref"] in cert_key_sized)
        if not sized:
            missing.append("parameter set / key size")
        if not [f for f in ap.get("cryptoFunctions", []) or [] if f not in ("unknown", "other")]:
            missing.append("usage")
        if not any(a["ref"] in ((p.get("cryptoProperties", {}) or {}).get("protocolProperties", {}) or {})
                   .get("cryptoRefArray", []) for p in F.protocols) and not a["auth"]:
            missing.append("component context")
        if missing:
            incomplete.append(f"{a['name']}: missing {', '.join(missing)}")
    fields = {"allFieldsPresent": not incomplete, "incompleteEntries": "\n".join(incomplete),
              "entriesSampled": f"all {len(checked)} algorithm entries (protocol-version entries excluded)"}
    E["3.2.2"] = _ev(fields, "derived")
    E["4.2.2"] = _ev(dict({k: v for k, v in fields.items() if k != "entriesSampled"}, samplingMethod=f"all {len(checked)} algorithm entries checked; protocol-version entries excluded"), "derived")
    vul_rows = []
    for i in ifaces:
        if i["kex_vulnerable"]:
            vul_rows.append(f"{i['name']}: key exchange {i['kex']}")
    for n, s, k in F.cert_rows():
        for alg in (s, k):
            r = cnsa.classify(alg, profile=F.profile)
            if r.get("quantum_vulnerable"):
                vul_rows.append(f"certificate {n}: {alg}")
    vul_rows += [f"{a['name']} ({a['lane']})" for a in F.vulnerable
                 if not any(a["name"] in row for row in vul_rows)]
    f331 = {"nonQuantumSafeFeaturesPresent": bool(vul_rows), "featureList": "\n".join(dict.fromkeys(vul_rows)),
            "analysisTool": f"{F.tool}; ruleset {cnsa.RULESET_VERSION}, profile {F.profile}"}
    A = (F.answers or {}).get("answers", {})
    if A:
        # The vendor-readiness disclosure checks, run against this CBOM (1.5.2: before, only A1 was compared and
        # its gap cited certificate algorithms, so four contradictions could read "No gap").
        facts = vr.cbom_facts(F.bom, F.profile)
        dl, dl_text = vr.deadline_for(F.profile, F.answers or {})
        ctx = {"profile": F.profile, "pkic": None, "cmvp": F.cmvp, "deadline": dl, "deadline_text": dl_text}
        doc = vr.load_questions()
        res = {q["id"]: vr.run_check(q, A.get(q["id"]) or {}, facts, ctx) for q in doc["questions"]
               if q.get("check") and q["check"] != "dated"}
        res = {k: v for k, v in res.items() if v}
        gaps = [f"{k} contradicted: {v['detail']}" for k, v in sorted(res.items()) if v["status"] == "contradicted"]
        gaps += [f"{k} not evidenced: {v['detail']}" for k, v in sorted(res.items()) if v["status"] == "not-evidenced"]
        gaps += F.match_notes
        counts = {}
        for v in res.values():
            if v["status"] in vr.CBOM_STATUSES:     # a date status (missing-date, late...) is not a CBOM check
                counts[v["status"]] = counts.get(v["status"], 0) + 1
        f331["toolVsDisclosureGaps"] = "\n".join(gaps) or (
            f"No answer contradicts the CBOM in the {sum(counts.values())} checks against it ("
            + ", ".join(f"{n} {k}" for k, n in sorted(counts.items())) + ").")
    E["3.3.1"] = _ev(f331, "derived", "The feature list is what the scan observed; components it did not reach "
                                      "are not covered.")
    E["3.3.3"] = _ev({"inventoryFormat": f"CycloneDX {F.bom.get('specVersion', '?')}",
                      "schemaVersion": F.bom.get("specVersion")}, "observed",
                     "Algorithm-level detail is preserved; use the toolkit's --redact to remove names.")
    conforms = _pkic_conforms(F.path)
    E["3.4.1"] = _ev({"sbomFormat": "CycloneDX", "schemaVersion": F.bom.get("specVersion"), "generationTool": F.tool,
                      "generationDate": F.timestamp[:10],
                      "validationOutcome": {True: "valid (PKI Consortium CBOM entry profile: conforms)",
                                            False: "PKI Consortium CBOM entry profile: does not conform",
                                            None: "not validated"}[conforms]}, "derived")
    if F.libs:
        unversioned = [c.get("name") for c in F.libs if not c.get("version")]
        E["3.4.2"] = _ev({"allLibrariesVersioned": not unversioned,
                          "libraryVersions": "\n".join(f"{c.get('name')} {c.get('version') or '(none)'}" for c in F.libs)},
                         "observed")
    comps = [c for c in F.bom.get("components", []) or [] if c.get("type") != "cryptographic-asset"]
    with_id = [c for c in comps if c.get("purl") or c.get("cpe")]
    ident = {"topLevelPurl": F.subject.get("purl"), "topLevelCpe": F.subject.get("cpe"),
             "sampledComponents": f"{len(with_id)} of {len(comps)} non-crypto components carry a purl or CPE"}
    note = ("The PQCMM requires at least one CPE 2.3 name or purl for the product. This CBOM's subject has none: "
            "an outside scan identifies a deployment, not a product." if not (F.subject.get("purl") or F.subject.get("cpe"))
            else "")
    E["3.4.4"] = _ev(ident, "observed", note)
    crypto_refs = {c.get("bom-ref") for c in F.bom.get("components", []) or [] if c.get("type") == "cryptographic-asset"}
    identified = {c.get("bom-ref") for c in comps if c.get("purl") or c.get("cpe")}
    if F.subject.get("purl") or F.subject.get("cpe"):
        identified.add(F.subject.get("bom-ref"))
    bound = set()
    for dep in F.bom.get("dependencies", []) or []:
        if dep.get("ref") in identified:
            bound |= set(dep.get("dependsOn", []) or []) & crypto_refs
    E["4.2.5"] = _ev({"topLevelPurl": F.subject.get("purl"), "topLevelCpe": F.subject.get("cpe"),
                      "sampledAssets": f"{len(bound)} of {len(crypto_refs)} cryptographic-asset entries are bound "
                                       f"(via dependencies) to a component carrying a purl or CPE"},
                     "derived", note)
    hndl = [i for i in ifaces if i["kex_vulnerable"]]
    unk = [i for i in ifaces if i["kex"] == "unknown"]
    reg = [(f"{i['name']}: {i['hndl_inferred']}" if i.get("hndl_inferred") else
            f"{i['name']}: key exchange {i['kex']} (quantum-vulnerable)")
           + ": traffic recorded today could be decrypted later" for i in hndl]
    reg += [f"{i['name']}: key exchange not observed; exposure unknown" for i in unk if not i.get("hndl_inferred")]
    reg += [f"{i['name']}: key exchange {i['kex']} (quantum-resistant)" for i in ifaces
            if i["kex_vulnerable"] is False]
    if ifaces:
        E["3.7.1"] = _ev({"dataFlowCoverage": "\n".join(reg), "lastUpdated": F.timestamp[:10]}, "derived",
                         "A starting point for the register: it lists observed interfaces and their key exchange. "
                         "Which flows carry long-lived confidentiality requirements is for the vendor to state.")
    libs_alg = [c for c in F.bom.get("components", []) or []
                if _props(c).get("fedlin:capability") == "true" and str(_props(c).get("fedlin:evidence", "")).startswith("dependency:")]
    if F.libs:
        contrib = {}
        for c in libs_alg:
            for pkg in _props(c)["fedlin:evidence"].split(":", 1)[1].split(","):
                contrib.setdefault(pkg.strip(), []).append(c.get("name"))
        E["4.2.3"] = _ev({"librariesWithAlgorithmEntries": "\n".join(f"{k}: {', '.join(v)}" for k, v in contrib.items()),
                          "librariesWithoutAlgorithmEntries": "\n".join(
                              c.get("name") for c in F.libs if c.get("name") not in contrib)}, "derived")
    sym = [a for a in F.algos if a["lane"] in ("symmetric", "hash")]
    if sym:
        rows = []
        for a in sym:
            civ = cnsa.classify(a["name"], profile="civilian").get("priority")
            nss = cnsa.classify(a["name"], profile="nss").get("priority")
            rows.append(f"{a['name']}: civilian {'meets' if civ == 'None' else 'below target'}, "
                        f"CNSA 2.0 {'meets' if nss == 'None' else 'below target'}")
        E["4.4.1"] = _ev({"dataClassStrengths": "\n".join(rows),
                          "guidanceReferenced": "NIST SP 800-131A, NIST IR 8547; NSA CNSA 2.0 (AES-256, SHA-384/512)"},
                         "derived", "Which data is long-lived is for the vendor to state (HNDL register).")
    hyb = sorted({i["kex"] for i in ifaces if i["kex_canonical"] and vr._HYBRID.search(i["kex_canonical"])}
                 | {a["name"] for a in F.pqc if a["canonical"] and vr._HYBRID.search(a["canonical"])})
    if ifaces or F.pqc:
        E["4.5.1"] = _ev({"hybridSupported": bool(hyb), "schemes": ", ".join(hyb),
                          "referenceStandard": cnsa.SOURCES.get("TLS-MLKEM", "") if hyb else "",
                          "interoperabilityOutcome": "success (observed handshake)" if interop and hyb else ""},
                         "observed", "Observed in use; whether hybrid can be turned off or replaced by PQC-only is "
                                     "not observable from a scan.")
    declared = (A.get("I1", {}).get("claims") or {}).get("pqc_algorithms") if A else None
    if declared is not None or pqc_names:
        rows = []
        for name in declared or []:
            r = cnsa.classify(name, profile=F.profile)
            want = (r.get("canonical") or "").replace("-", "")
            hit = [a["name"] for a in F.pqc if want and want in (a["canonical"] or "").replace("-", "")]
            rows.append(f"declared {name} (vendor): {'observed as ' + ', '.join(hit) if hit else 'not observed'}")
        for n in pqc_names:
            if not any(n in r for r in rows):
                rows.append(f"observed {n}: not declared" if declared is not None else f"observed {n}")
        E["5.4.2"] = _ev({"analysisTool": f"{F.tool}; ruleset {cnsa.RULESET_VERSION}",
                          "analysisDate": datetime.date.today().isoformat(), "sampledAlgorithms": "\n".join(rows)},
                         "derived" if declared is None else "vendor",
                         "" if declared is not None else "No vendor declaration supplied (--answers); observed only.")
    return E


def criteria_status(model, E, F):
    """Per criterion: which mapped questions have toolkit evidence, and any contradiction. Never 'met'."""
    out = []
    for c in _criteria(model):
        qids = c.get("assessmentQuestionIds") or []
        have = [q for q in qids if q in E]
        status = "evidence for {}/{} questions".format(len(have), len(qids)) if qids else "no assessment questions"
        contra = ""
        if c["id"] == "0.1.2" and F.pqc:
            contra = ("The CBOM shows quantum-resistant algorithms in use (" + ", ".join(sorted({a['name'] for a in F.pqc}))
                      + "), so 'no quantum-safe algorithm available' does not hold.")
        out.append({"id": c["id"], "level": c["level"], "text": c["text"], "questions": qids, "evidenced": have,
                    "status": "contradicted by evidence" if contra else status, "detail": contra})
    return out


def build(cbom_path, profile=None, answers_path=None, model=None):
    model = model or load_model()
    profile = profile or cnsa.DEFAULT_PROFILE
    try:
        with open(cbom_path, "rb") as f:
            craw = f.read()
        bom = json.loads(craw.decode("utf-8"))
    except OSError as e:
        raise vr.VendorInputError(f"--cbom {cbom_path}: {e.strerror}")
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise vr.VendorInputError(f"--cbom {cbom_path}: not valid JSON ({e})")
    if not isinstance(bom, dict) or not isinstance(bom.get("components", []) or [], list):
        raise vr.VendorInputError(f"--cbom {cbom_path}: not a CycloneDX document")
    answers = None
    inputs = {"cbom": {"file": os.path.basename(cbom_path), "sha256": hashlib.sha256(craw).hexdigest()}}
    if answers_path:
        answers, araw = vr.load_answers(answers_path)
        inputs["answers"] = {"file": os.path.basename(answers_path), "sha256": hashlib.sha256(araw).hexdigest()}
    F = Facts(bom, cbom_path, profile, answers)
    F.inputs = inputs
    E = evidence(F)
    return {"model": model, "facts": F, "evidence": E, "criteria": criteria_status(model, E, F), "profile": profile}


def _cell(s):
    return str(s).replace("|", "\\|").replace("\n", "<br>")


def report_md(res):
    model, F, E = res["model"], res["facts"], res["evidence"]
    Q = _questions(model)
    m = model["model"]
    L = [f"# PQCMM evidence: {F.subject.get('name', '?')}", "",
         f"Model: {m['name']} {m['version']} ({MODEL_SOURCE}, MIT). Scope of the model: {m['scope']}. "
         f"Evidence from `{os.path.basename(F.path)}` ({F.tool}), profile `{res['profile']}`; produced "
         f"{datetime.date.today().isoformat()} with fedlin-pqc-toolkit {vr._toolkit_version()} (ruleset "
         f"{cnsa.RULESET_VERSION}). Inputs: "
         + ", ".join(f"{v['file']} (SHA-256 {v['sha256'][:16]}...)" for v in F.inputs.values()) + ".", "",
         "> This is evidence, not a maturity level. The PQCMM assesses a product or service; "
         + ("this toolkit observed one deployment" if F.ours else
            "the CBOM was supplied with the assessment, not produced by this toolkit, and *observed* means "
            "\"stated in that CBOM\"; it describes one configuration")
         + ", and a capability shown here holds only for that configuration. Every criterion is left "
         "for an assessor. Values marked *vendor* are vendor-stated, not independently verified; *snapshot* values "
         "are CMVP candidates, not validation claims.", "",
         f"Scoring rule ({model['scoring']['method']}): {model['scoring']['rule']}", "",
         f"**Questions with toolkit evidence: {len(E)} of {len(Q)}.**", "",
         "## Criteria", "", "| Criterion | Level | Toolkit evidence | Note |", "|---|---|---|---|"]
    for c in res["criteria"]:
        L.append(f"| {c['id']} | {c['level']} | {c['status']}"
                 + (f" ({', '.join(c['evidenced'])})" if c["evidenced"] else "") + f" | {_cell(c['detail'])} |")
    L += ["", "## Evidence by question", ""]
    for qid in sorted(E, key=lambda x: [int(p) for p in x.split(".")]):
        q, e = Q[qid], E[qid]
        L += [f"### {qid} (Level {q['level']}, {q['group']})", "", f"*{q['question'].strip()}*", "",
              f"Provenance: **{e['provenance']}**." + (f" {e['note']}" if e["note"] else ""), "",
              "| Field | Value |", "|---|---|"]
        labels = {f["key"]: f.get("label", f["key"]) for f in (q.get("response") or {}).get("fields", [])}
        for k, v in e["fields"].items():
            L.append(f"| {_cell(labels.get(k, k))} | {_cell(v)} |")
        L.append("")
    missing = [qid for qid in Q if qid not in E]
    L += ["## Questions this toolkit cannot evidence", "",
          "These need vendor documents, hands-on tests or an assessor: " + ", ".join(missing) + ".", ""]
    return "\n".join(L)


def to_json(res):
    F = res["facts"]
    return {"model": {"id": res["model"]["model"]["id"], "version": res["model"]["model"]["version"],
                      "source": MODEL_SOURCE},
            "subject": {"name": F.subject.get("name"), "version": F.subject.get("version"),
                        "purl": F.subject.get("purl"), "cpe": F.subject.get("cpe")},
            "assessedConfiguration": {"cbom": os.path.basename(F.path), "cbomTimestamp": F.timestamp,
                                      "tool": F.tool, "profile": res["profile"],
                                      "cmvpSnapshot": (F.snap or {}).get("fetched"),
                                      "cbomProducedByToolkit": F.ours, "cbomCoverage": F.coverage},
            "inputs": F.inputs, "toolkitVersion": vr._toolkit_version(), "rulesetVersion": cnsa.RULESET_VERSION,
            "levelAwarded": None,
            "questions": res["evidence"],
            "criteria": [{k: c[k] for k in ("id", "level", "status", "evidenced", "detail")} for c in res["criteria"]]}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cbom", required=True)
    ap.add_argument("--answers", default="", help="vendor-readiness answers file (adds vendor-stated declarations)")
    ap.add_argument("--profile", choices=list(cnsa.PROFILES), default=cnsa.DEFAULT_PROFILE)
    ap.add_argument("--out", default="", help="report path (default: <cbom base>.pqcmm.md); JSON written beside it")
    a = ap.parse_args(argv)
    try:
        res = build(a.cbom, a.profile, a.answers or None)
    except vr.VendorInputError as e:
        sys.stderr.write(f"[error] {e}\n")
        return 2
    out = a.out or a.cbom.rsplit(".", 1)[0] + ".pqcmm.md"
    with open(out, "w", encoding="utf-8") as f:
        f.write(report_md(res) + "\n")
    with open(out.rsplit(".", 1)[0] + ".json", "w") as f:
        json.dump(to_json(res), f, indent=2)
    contra = [c["id"] for c in res["criteria"] if c["status"].startswith("contradicted")]
    print(f"[ok] {out}: evidence for {len(res['evidence'])} PQCMM questions; contradicted criteria: {contra or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
