#!/usr/bin/env python3
"""Vendor post-quantum readiness: the ASD/CISA/NSA questions, checked against the vendor's own CBOM.

Source: "Post-quantum questions to ask your vendors" (ASD's ACSC with CISA and NSA, November 2026,
CC BY 4.0), in data/vendor-questions/. Each question carries a claim type:

  disclosure  a fact about the product. Where a check exists, the answer is compared with the CBOM.
  capability  the product can do something. Recorded with its evidence; holds only for the version assessed.
  intent      a plan, date or commitment. Recorded; missing or post-2030 dates are flagged; never verified.

The seven "common concerns in vendor responses" from the publication are raised from structured fields
only (claims, evidence lists, the CBOM). Free-text answers are reported, not interpreted.

Usage:
    python3 scripts/vendor_readiness.py questionnaire --out vendor-questions.md
    python3 scripts/vendor_readiness.py template --out answers.json
    python3 scripts/vendor_readiness.py assess --answers answers.json [--profile civilian|nss] [--out report.md]
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cmvp  # noqa: E402
import cnsa20_ruleset as cnsa  # noqa: E402

QUESTIONS = os.path.join(ROOT, "data", "vendor-questions", "asd-cisa-nsa-2026-11.json")
VALIDATOR = os.path.join(ROOT, "third_party", "pkic-cbom")
DEADLINE = datetime.date(2030, 12, 31)
_HYBRID = re.compile(r"mlkem.*(x25519|x448|secp|nistp)|(x25519|x448|secp|nistp).*mlkem", re.I)


def load_questions(path=QUESTIONS):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# --- questionnaire and template -------------------------------------------------------------
def questionnaire_md(doc):
    s = doc["source"]
    L = [f"# {s['title']}", "",
         f"Questions from {s['authors']}, published {s['published']}. Reproduced under CC BY 4.0.", "",
         f"> {s['scaling_note']}", "",
         "For each question, please give your answer and the evidence behind it (document names, links, "
         "release notes). Where you have a cryptographic bill of materials (CBOM), please attach it in "
         "CycloneDX format.", ""]
    phase = None
    for q in doc["questions"]:
        if q["phase"] != phase:
            phase = q["phase"]
            L += [f"## {phase}", ""]
        L += [f"### {q['id']}. {q['question']}", "",
              f"*Why it matters:* {q['why_it_matters']}", "",
              f"*What a strong answer includes:* {q['key_response_considerations']}", "",
              "Answer:", "", "Evidence:", ""]
    return "\n".join(L)


def template(doc):
    answers = {}
    for q in doc["questions"]:
        a = {"answer": "", "evidence": []}
        if q["structured_claims"]:
            a["claims"] = {k: None for k in q["structured_claims"]}
        answers[q["id"]] = a
    return {"vendor": "", "product": "", "version": "", "answered": "", "cbom": "",
            "_help": {q["id"]: q["structured_claims"] for q in doc["questions"] if q["structured_claims"]},
            "answers": answers}


# --- CBOM facts -----------------------------------------------------------------------------
def _date(s):
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m", "%Y"):
        try:
            d = datetime.datetime.strptime(str(s), fmt).date()
            if fmt == "%Y-%m":
                d = d.replace(day=28)
            elif fmt == "%Y":
                d = d.replace(month=12, day=31)
            return d
        except ValueError:
            continue
    return None


def cbom_facts(bom, profile):
    """Algorithms (judged by the ruleset), certificates, protocols and libraries in a vendor CBOM."""
    comps = bom.get("components", []) or []
    by_ref = {c.get("bom-ref"): c for c in comps}
    algos, certs, protocols, libs, layers = [], [], [], [], set()
    for c in comps:
        t = c.get("type")
        if t in ("library", "framework"):
            libs.append(c)
            layers.add("library")
        elif t in ("operating-system", "firmware", "device"):
            layers.add(t)
        elif t == "application":
            layers.add("application")
        if t != "cryptographic-asset":
            continue
        cp = c.get("cryptoProperties", {}) or {}
        at = cp.get("assetType")
        if at == "algorithm":
            ap = cp.get("algorithmProperties", {}) or {}
            name = c.get("name", "")
            r = cnsa.classify(name, profile=profile)
            algos.append({"ref": c.get("bom-ref"), "name": name, "canonical": r.get("canonical"),
                          "lane": r.get("lane"), "vulnerable": r.get("quantum_vulnerable"),
                          "standard": r.get("standard_status"), "family": r.get("family"),
                          "priority": r.get("priority"),
                          "functions": [f.lower() for f in ap.get("cryptoFunctions", []) or []],
                          "primitive": (ap.get("primitive") or "").lower()})
        elif at == "certificate":
            certs.append(c)
        elif at == "protocol":
            protocols.append(c)
    # algorithms a certificate uses for its signature or key are authentication algorithms
    cert_refs = set()
    for c in certs:
        cp = (c.get("cryptoProperties", {}) or {}).get("certificateProperties", {}) or {}
        cert_refs |= {cp.get("signatureAlgorithmRef"), cp.get("subjectPublicKeyRef")}
    for a in algos:
        a["auth"] = (a["ref"] in cert_refs or a["lane"] == "signature"
                     or bool({"sign", "verify"} & set(a["functions"])) or a["primitive"] == "signature")
    return {"algorithms": algos, "certificates": certs, "protocols": protocols, "libraries": libs,
            "layers": sorted(layers | ({"protocol"} if protocols else set()) | ({"certificate"} if certs else set())),
            "by_ref": by_ref}


def pkic_entry_profile(cbom_path):
    """Exit status of the vendored PKI Consortium validator for the entry profile (None if unavailable)."""
    try:
        r = subprocess.run([sys.executable, "-I", os.path.join(VALIDATOR, "validate_cbom.py"), cbom_path,
                            os.path.join(VALIDATOR, "profile-interface-enumeration.rules.json"), "--json"],
                           capture_output=True, text=True, timeout=60)
        return r.returncode == 0
    except Exception:
        return None


# --- checks ---------------------------------------------------------------------------------
def _r(status, detail):
    return {"status": status, "detail": detail}


def _claim(a, key):
    return (a.get("claims") or {}).get(key)


def run_check(q, a, facts, ctx):
    """One check result: consistent | contradicted | not-evidenced | no-cbom | missing-date | late | info."""
    chk = q.get("check")
    if not chk:
        return None
    if chk == "dated":
        key = next(iter(q["structured_claims"]))
        d = _date(_claim(a, key))
        if not d:
            return _r("missing-date", f"No date given in `{key}`.")
        if d > DEADLINE:
            return _r("late", f"`{key}` = {_claim(a, key)}, after the end of 2030.")
        return _r("consistent", f"`{key}` = {_claim(a, key)}, before the end of 2030 (not verifiable).")
    if facts is None:
        if chk == "cbom_supplied":
            return _r("no-cbom", "No CBOM supplied.")
        return _r("no-cbom", "No CBOM to check against.")
    algos = facts["algorithms"]
    if chk == "cbom_supplied":
        n = len(algos) + len(facts["certificates"]) + len(facts["protocols"])
        conf = ctx.get("pkic")
        conf_s = {True: "conforms to the PKI Consortium CBOM entry profile",
                  False: "does not conform to the PKI Consortium CBOM entry profile",
                  None: "PKI Consortium conformance not checked"}[conf]
        if n == 0:
            return _r("contradicted", "CBOM supplied but contains no cryptographic assets.")
        return _r("consistent", f"CBOM supplied: {len(algos)} algorithm(s), {len(facts['certificates'])} "
                                f"certificate(s), {len(facts['protocols'])} protocol(s), "
                                f"{len(facts['libraries'])} librar(ies); {conf_s}.")
    if chk == "cbom_layers":
        return _r("info", "Layers present in the CBOM: " + (", ".join(facts["layers"]) or "none") + ".")
    if chk == "third_party_crypto":
        found = ctx.get("cmvp", [])
        libs = facts["libraries"]
        claimed = _claim(a, "third_party_crypto")
        if claimed is False and (found or libs):
            return _r("contradicted", f"Answer says no, but the CBOM lists {len(libs)} librar(ies)"
                                      + (f", including {', '.join(sorted({f['label'] for f in found}))}" if found else "")
                                      + ".")
        if not libs:
            return _r("not-evidenced", "The CBOM lists no library components, so inherited cryptography cannot "
                                       "be checked.")
        return _r("consistent", f"The CBOM lists {len(libs)} librar(ies)"
                                + (f"; recognised crypto implementations: {', '.join(sorted({f['label'] for f in found}))}"
                                   if found else "") + ".")
    if chk in ("traditional_asymmetric", "auth_asymmetric"):
        vul = [x for x in algos if x["vulnerable"] is True and (chk == "traditional_asymmetric" or x["auth"])]
        key = "traditional_asymmetric" if chk == "traditional_asymmetric" else "traditional_asymmetric_auth"
        claimed = _claim(a, key)
        names = ", ".join(sorted({x["name"] for x in vul})[:8])
        if claimed is False and vul:
            return _r("contradicted", f"Answer says none, but the CBOM shows quantum-vulnerable "
                                      f"{'authentication ' if chk == 'auth_asymmetric' else ''}algorithms: {names}.")
        if claimed is True and not vul:
            return _r("not-evidenced", "Answer says yes, but the CBOM shows no quantum-vulnerable algorithm; "
                                       "the CBOM may be incomplete.")
        if vul:
            return _r("consistent", f"CBOM shows: {names}.")
        return _r("consistent", "The CBOM shows no quantum-vulnerable algorithm.")
    if chk == "hybrid":
        hyb = sorted({x["name"] for x in algos if x["canonical"] and _HYBRID.search(x["canonical"])})
        claimed = _claim(a, "hybrid")
        plan = _date(_claim(a, "pqc_only_date"))
        if claimed is False and hyb:
            return _r("contradicted", f"Answer says no hybrid support, but the CBOM shows {', '.join(hyb)}.")
        if hyb or claimed:
            if not plan:
                return _r("missing-date", (f"Hybrid in use ({', '.join(hyb)}) " if hyb else "Hybrid supported ")
                          + "with no `pqc_only_date`; the publication expects a documented de-hybridisation plan.")
            return _r("consistent", f"Hybrid treated as transitional; PQC-only planned {_claim(a, 'pqc_only_date')}.")
        return _r("info", "No hybrid key establishment in the CBOM.")
    if chk == "pqc_algorithms":
        claimed = _claim(a, "pqc_algorithms") or []
        in_cbom = {}
        for x in algos:
            if x["canonical"] and x["vulnerable"] is False and x["family"] in ("ML-KEM", "ML-DSA", "SLH-DSA", "LMS", "XMSS", "FN-DSA"):
                in_cbom[x["canonical"]] = x
        rows = []
        missing = []
        for name in claimed:
            r = cnsa.classify(name, profile=ctx["profile"])
            if not r.get("canonical") or r.get("quantum_vulnerable") is not False:
                rows.append(f"{name}: not a recognised quantum-resistant algorithm")
                continue
            ok = "compliant" if r.get("priority") == "None" else f"below the `{ctx['profile']}` target ({r.get('cnsa_target')})"
            want = r["canonical"].replace("-", "")
            hits = sorted(x["name"] for k, x in in_cbom.items() if want == k.replace("-", "") or want in k.replace("-", ""))
            if not hits:
                missing.append(name)
                rows.append(f"{name}: {ok}; not in the CBOM")
            else:
                direct = any(want == in_cbom[k]["canonical"].replace("-", "") for k in in_cbom
                             if in_cbom[k]["name"] in hits)
                rows.append(f"{name}: {ok}; in the CBOM" + ("" if direct else f" (within {', '.join(hits)})"))
        ga = _date(_claim(a, "ga_date"))
        tail = "" if ga else " No `ga_date` given."
        if not claimed:
            if in_cbom:
                return _r("not-evidenced", "No algorithms listed in the answer, but the CBOM shows "
                                           + ", ".join(sorted(in_cbom)) + "." + tail)
            return _r("missing-date" if not ga else "info", "No PQC algorithms listed." + tail)
        status = "not-evidenced" if missing else "consistent"
        return _r(status, "; ".join(rows) + "." + tail)
    if chk == "library_validation":
        found = ctx.get("cmvp", [])
        if not found:
            return _r("info", "No library in the CBOM maps to a known CMVP module family.")
        parts = []
        for f in found:
            if f["kind"] == "no-module":
                parts.append(f"{f['label']}: no CMVP module")
            else:
                parts.append(f"{f['label']}: {len(f['certificates'])} active candidate certificate(s)")
        return _r("info", "; ".join(parts) + ". Candidates only; confirm against each Security Policy.")
    return None


# --- concerns -------------------------------------------------------------------------------
def concerns(doc, answers, results, facts):
    """The publication's seven common concerns, raised from structured fields only."""
    out = []
    A = answers.get("answers", {})

    def answered(i):
        return bool((A.get(i) or {}).get("answer", "").strip())

    if facts is None or not answered("L1") or not answered("L2") or \
            (facts is not None and not facts["algorithms"] and not facts["certificates"] and not facts["protocols"]):
        out.append(("limited visibility of cryptographic use",
                    "No usable CBOM, or the inventory questions (L1, L2) are unanswered."))
    subst = [q["id"] for q in doc["questions"] if q["claim_type"] in ("disclosure", "capability")
             and answered(q["id"]) and not (A.get(q["id"]) or {}).get("evidence")]
    total = sum(1 for q in doc["questions"] if q["claim_type"] in ("disclosure", "capability") and answered(q["id"]))
    if total and len(subst) * 2 >= total:
        out.append(("reliance on general assurances",
                    f"{len(subst)} of {total} answered disclosure/capability questions cite no evidence: "
                    + ", ".join(subst) + "."))
    late = [i for i in ("T1", "I1", "C3", "C5") if results.get(i) and results[i]["status"] in ("missing-date", "late")]
    if late:
        out.append(("unclear or deferred transition timelines", "Missing or post-2030 dates: " + ", ".join(late) + "."))
    if facts is not None:
        opaque = sorted({x["name"] for x in facts["algorithms"] if not x["canonical"] or x["standard"] == "non-nist"})
        if opaque:
            out.append(("use of proprietary or opaque cryptography",
                        "Unrecognised or non-standard algorithms in the CBOM: " + ", ".join(opaque[:10]) + "."))
    if _claim(A.get("I6") or {}, "pqc_in_base_license") is False:
        out.append(("treatment of PQC as an optional or premium function", "I6: PQC is not in base licensing."))
    if answered("A5") and not _claim(A.get("I1") or {}, "pqc_algorithms"):
        out.append(("over-reliance on compensating controls",
                    "Stronger traditional settings are offered (A5) but no PQC algorithms are committed (I1). "
                    "Larger classical keys do not address the risk from a CRQC."))
    if not answered("T5") or not (A.get("T5") or {}).get("evidence"):
        out.append(("lack of governance or ownership", "T5 is unanswered or cites no evidence."))
    return out


# --- assess ---------------------------------------------------------------------------------
def assess(answers_path, profile=None, doc=None):
    doc = doc or load_questions()
    profile = profile or cnsa.DEFAULT_PROFILE
    with open(answers_path, encoding="utf-8") as f:
        answers = json.load(f)
    facts, ctx = None, {"profile": profile}
    cbom_path = answers.get("cbom") or ""
    if cbom_path and not os.path.isabs(cbom_path):
        cbom_path = os.path.join(os.path.dirname(os.path.abspath(answers_path)), cbom_path)
    if cbom_path and os.path.exists(cbom_path):
        with open(cbom_path, encoding="utf-8") as f:
            bom = json.load(f)
        facts = cbom_facts(bom, profile)
        ctx["pkic"] = pkic_entry_profile(cbom_path)
        snap, _ = cmvp.load_snapshot()
        ctx["cmvp"] = cmvp.match(bom, snap)
    results = {}
    for q in doc["questions"]:
        r = run_check(q, answers.get("answers", {}).get(q["id"]) or {}, facts, ctx)
        if r:
            results[q["id"]] = r
    return {"doc": doc, "answers": answers, "profile": profile, "facts": facts, "ctx": ctx,
            "results": results, "concerns": concerns(doc, answers, results, facts),
            "cbom_path": cbom_path if facts is not None else ""}


def _cell(s):
    return (s or "").replace("|", "\\|").replace("\n", " ").strip()


def report_md(res):
    doc, ans = res["doc"], res["answers"]
    A = ans.get("answers", {})
    counts = {}
    for r in res["results"].values():
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    answered = sum(1 for q in doc["questions"] if (A.get(q["id"]) or {}).get("answer", "").strip())
    L = [f"# Vendor PQC readiness: {ans.get('vendor') or '?'} {ans.get('product') or ''} {ans.get('version') or ''}".rstrip(),
         "",
         f"Answers dated {ans.get('answered') or '?'}; verdict profile `{res['profile']}`. Questions: "
         f"{doc['source']['title']} ({doc['source']['authors']}, {doc['source']['published']}; CC BY 4.0).",
         "",
         f"**{answered} of {len(doc['questions'])} questions answered.** Checks against the vendor's CBOM: "
         + (", ".join(f"{v} {k}" for k, v in sorted(counts.items())) or "none") + ".",
         "",
         "Disclosure answers are compared with the vendor's CBOM where a check exists. Capability answers hold "
         "only for the version assessed. Intent answers are plans and are not verified.",
         ""]
    if not res["facts"]:
        L += ["> No CBOM was supplied, so no disclosure answer could be checked.", ""]
    L += ["## Common concerns", ""]
    if res["concerns"]:
        L += [f"- **{c}:** {d}" for c, d in res["concerns"]]
    else:
        L.append("None raised from the structured answers.")
    L += ["", "The publication notes these concerns do not necessarily indicate unacceptable risk; weigh them "
              "against the vendor's risk level, data sensitivity and longevity, and willingness to engage.", ""]
    phase = None
    for q in doc["questions"]:
        if q["phase"] != phase:
            phase = q["phase"]
            L += [f"## {phase}", "", "| # | Question | Type | Answer | Evidence | Check |", "|---|---|---|---|---|---|"]
        a = A.get(q["id"]) or {}
        r = res["results"].get(q["id"])
        chk = f"**{r['status']}**: {r['detail']}" if r else "-"
        ev = "; ".join(a.get("evidence") or []) or "none cited"
        txt = (a.get("answer") or "").strip() or "*unanswered*"
        L.append(f"| {q['id']} | {_cell(q['question'])} | {q['claim_type']} | {_cell(txt[:400])} | {_cell(ev[:200])} | {_cell(chk)} |")
        nxt = doc["questions"][doc["questions"].index(q) + 1]["phase"] if q is not doc["questions"][-1] else None
        if nxt != phase:
            L.append("")
    return "\n".join(L)


def summary(res):
    counts = {}
    for r in res["results"].values():
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    A = res["answers"].get("answers", {})
    return {"vendor": res["answers"].get("vendor"), "product": res["answers"].get("product"),
            "version": res["answers"].get("version"), "profile": res["profile"],
            "answered": sum(1 for q in res["doc"]["questions"] if (A.get(q["id"]) or {}).get("answer", "").strip()),
            "questions": len(res["doc"]["questions"]), "checks": counts,
            "contradicted": sorted(k for k, v in res["results"].items() if v["status"] == "contradicted"),
            "concerns": [c for c, _ in res["concerns"]], "cbom": bool(res["facts"])}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("questionnaire", "template"):
        s = sub.add_parser(name)
        s.add_argument("--out", required=True)
    s = sub.add_parser("assess")
    s.add_argument("--answers", required=True)
    s.add_argument("--profile", choices=list(cnsa.PROFILES), default=cnsa.DEFAULT_PROFILE)
    s.add_argument("--out", default="", help="report path (default: <answers>.report.md); a .summary.json is written beside it")
    a = ap.parse_args(argv)
    doc = load_questions()
    if a.cmd == "questionnaire":
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(questionnaire_md(doc) + "\n")
        print(f"[ok] {a.out}: {len(doc['questions'])} questions")
        return 0
    if a.cmd == "template":
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(template(doc), f, indent=2)
            f.write("\n")
        print(f"[ok] {a.out}: fill in answers, evidence and claims; set 'cbom' to the vendor's CBOM path")
        return 0
    res = assess(a.answers, a.profile, doc)
    out = a.out or a.answers.rsplit(".", 1)[0] + ".report.md"
    with open(out, "w", encoding="utf-8") as f:
        f.write(report_md(res) + "\n")
    s = summary(res)
    with open(out.rsplit(".", 1)[0] + ".summary.json", "w") as f:
        json.dump(s, f, indent=2)
    print(f"[ok] {out}: {s['answered']}/{s['questions']} answered; checks {s['checks']}; "
          f"contradicted {s['contradicted'] or 'none'}; concerns {len(s['concerns'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
