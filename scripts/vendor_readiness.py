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
import hashlib
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
FIPS_PQC = datetime.date(2024, 8, 13)      # FIPS 203, 204 and 205 published
# Statuses that come from comparing an answer with the CBOM; date checks are reported separately
CBOM_STATUSES = ("consistent", "contradicted", "not-evidenced", "not-checked", "unanswered", "no-cbom", "info",
                 "below-target")
DATE_STATUSES = ("planned", "past", "implausible", "late", "missing-date")
STATUSES = CBOM_STATUSES + DATE_STATUSES
_HYBRID = re.compile(r"(mlkem|kyber).*(x25519|x448|secp|nistp|p256|p384|p521)|"
                     r"(x25519|x448|secp|nistp|p256|p384|p521).*(mlkem|kyber)", re.I)
# A library that provides cryptography, by name, when it is not in the toolkit's known-library table
_CRYPTO_LIB = re.compile(r"crypt|ssl|tls|sodium|nacl|bouncycastle|bcprov|bcpkix|noble|jose|jwt|openssl|"
                         r"boringssl|wolfssl|mbedtls|gcrypt|gnutls|libnss|\bnss\b|aws-lc|botan|liboqs|oqs|rustls|"
                         r"^ring$|/ring$|jsrsasign|node-rsa|\brsa\b|ecdsa|ed25519|x509|pkcs|tink|cipher", re.I)


_NIST_OIDS = {
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512", "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s", "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s", "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s", "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
    "2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s", "2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
    "2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s", "2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
    "2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s", "2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
}
# Common classical public-key OIDs, so an OID-only entry is judged rather than left unrecognised (1.6.0)
_NIST_OIDS.update({
    "1.2.840.113549.1.1.1": "rsaEncryption", "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.113549.1.1.7": "RSAES-OAEP", "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.2.840.10045.4.3.2": "ECDSA", "1.2.840.10045.4.3.3": "ECDSA", "1.2.840.10045.4.3.4": "ECDSA",
    "1.3.132.1.12": "ECDH", "1.2.840.10046.2.1": "DH", "1.3.101.110": "X25519", "1.3.101.111": "X448",
    "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448",
})


def _all_components(comps):
    """Every component, including those nested under another (CycloneDX components[].components)."""
    out, stack = [], list(comps or [])[::-1]
    while stack:
        c = stack.pop()
        if not isinstance(c, dict):
            continue
        out.append(c)
        stack.extend(list(c.get("components") or [])[::-1])
    return out


def _algo_name(c, ap):
    """The name to judge: the component name, with its parameter set when the name lacks one (ML-KEM + 768 is
    ML-KEM-768), or the algorithm an OID names when the name is only an OID."""
    name = (c.get("name") or "").strip()
    oid = ((c.get("cryptoProperties") or {}).get("oid") or "").strip()
    if name in _NIST_OIDS or (not name and oid in _NIST_OIDS):
        return _NIST_OIDS[name or oid]
    if oid in _NIST_OIDS and not re.search(r"\d", name):
        return _NIST_OIDS[oid]
    ps = str(ap.get("parameterSetIdentifier") or "").strip()
    if ps and not re.search(r"\d", name) and re.fullmatch(r"[0-9A-Za-z]{1,8}", ps):
        # Only when the ruleset knows the joined name: for RSA and EC keys this field holds the key size, and
        # "rsaEncryption-2048" is not a name the ruleset recognises (regression in 1.5.2, fixed in 1.6.0).
        joined = f"{name}-{ps}"
        if cnsa.classify(joined).get("canonical"):
            return joined
    return name


class VendorInputError(ValueError):
    """The answers file or the CBOM it names cannot be used: stop with exit code 2."""


def attribution(doc, md=True):
    """CC BY 4.0 attribution for the reproduced questions: title, authors, copyright, licence, source and the
    changes made (section 3(a)(1) of the licence), and no implied endorsement."""
    s = doc["source"]
    urls = s.get("urls") or []
    link = (lambda u: f"<{u}>") if md else (lambda u: u)
    return ("Questions, \"why it matters\" and \"key response considerations\" from "
            f"*{s['title']}* by {s['authors']}, published {s['published']}. (c) Commonwealth of Australia 2026, "
            "licensed under CC BY 4.0 (" + link("https://creativecommons.org/licenses/by/4.0/") + "). Source: "
            + ", ".join(link(u) for u in urls) + ". Changes: the text is reproduced as published apart from PDF "
            "line-break hyphenation; the question ids (L1 to C6), the answer and evidence prompts, the claim types "
            "and the checks are added by fedlin-pqc-toolkit. ASD, CISA and NSA have not reviewed or endorsed this "
            "tool or its results.")


def load_questions(path=QUESTIONS):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# --- questionnaire and template -------------------------------------------------------------
def questionnaire_md(doc):
    s = doc["source"]
    L = [f"# {s['title']}", "",
         attribution(doc), "",
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
              f"*Key response considerations:* {q['key_response_considerations']}", "",
              "Answer:", "", "Evidence:", ""]
    return "\n".join(L)


def template(doc):
    answers = {}
    for q in doc["questions"]:
        a = {"_question": q["question"], "_type": q["claim_type"], "answer": "", "evidence": []}
        if q["structured_claims"]:
            a["claims"] = {k: None for k in q["structured_claims"]}
        answers[q["id"]] = a
    return {"vendor": "", "product": "", "version": "", "answered": "", "cbom": "",
            "_help": {q["id"]: q["structured_claims"] for q in doc["questions"] if q["structured_claims"]},
            "answers": answers}


# --- CBOM facts -----------------------------------------------------------------------------
_QUARTER = re.compile(r"^(?:q([1-4])\s*[-/ ]?\s*(\d{4})|(\d{4})\s*[-/ ]?\s*q([1-4]))$", re.I)


def _date(s):
    """A planned date: YYYY-MM-DD, YYYY-MM, YYYY, an ISO date-time, or a quarter (Q3 2027, 2027-Q3). The latest
    day the value allows, so a plan is never read as earlier than stated. None if absent or not a date."""
    if s in (None, ""):
        return None
    t = str(s).strip()
    m = _QUARTER.match(t)
    if m:
        q, y = (int(m.group(1)), int(m.group(2))) if m.group(1) else (int(m.group(4)), int(m.group(3)))
        return datetime.date(y, 3 * q, 30 if q in (2, 3) else 31)
    if re.match(r"^\d{4}-\d{2}-\d{2}[T ]", t):
        t = t[:10]
    for fmt in ("%Y-%m-%d", "%Y-%m", "%Y"):
        try:
            d = datetime.datetime.strptime(t, fmt).date()
            if fmt == "%Y-%m":
                nxt = d.replace(year=d.year + 1, month=1) if d.month == 12 else d.replace(month=d.month + 1)
                d = nxt - datetime.timedelta(days=1)
            elif fmt == "%Y":
                d = d.replace(month=12, day=31)
            return d
        except ValueError:
            continue
    return None


def _date_issue(a, key):
    """(date, problem): problem says why a given value is not usable as a date."""
    v = _claim(a, key)
    d = _date(v)
    if d is None and v not in (None, ""):
        return None, (f"`{key}` = {str(v)[:40]!r} is not a date (use YYYY-MM-DD, YYYY-MM, YYYY or a quarter "
                      "such as Q3 2027).")
    return d, None


def cbom_facts(bom, profile):
    """Algorithms (judged by the ruleset), certificates, protocols and libraries in a vendor CBOM."""
    comps = _all_components(bom.get("components", []) or [])
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
            name = _algo_name(c, ap)
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
    try:
        from tier2_pipeline import LIB_CRYPTO
    except Exception:  # pragma: no cover
        LIB_CRYPTO = {}
    crypto_libs = []
    for c in libs:
        g, n = (c.get("group") or "").strip(), (c.get("name") or "").strip()
        full = (f"{g}/{n}" if g else n).lower()
        if full in LIB_CRYPTO or _CRYPTO_LIB.search(full) or c.get("cryptoProperties"):
            crypto_libs.append(c)
    for a in algos:
        a["auth"] = (a["ref"] in cert_refs or a["lane"] == "signature"
                     or bool({"sign", "verify"} & set(a["functions"])) or a["primitive"] == "signature")
    meta = (bom.get("metadata", {}) or {}).get("component", {}) or {}
    coverage = next((p.get("value") for p in meta.get("properties", []) or []
                     if p.get("name") == "pkic:profile:coverage"), None)
    other_libs = [c for c in libs if c not in crypto_libs]
    return {"coverage": coverage or "not declared",
            "unrecognised": sorted({x["name"] or "(empty name)" for x in algos if not x["canonical"]}),
            "other_libraries": sorted({(c.get("name") or "?") for c in other_libs}),
            "algorithms": algos, "certificates": certs, "protocols": protocols, "libraries": libs,
            "crypto_libraries": crypto_libs,
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


_TRUE = {"true", "yes", "y", "1"}
_FALSE = {"false", "no", "n", "0", "none"}


def _bool_claim(a, key):
    """A true/false claim: True, False, or None when absent or not a yes/no answer. Strings such as "No" or
    "false" count (before 1.5.0 only the JSON value false did, so "No" skipped every check)."""
    v = _claim(a, key)
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)) and v in (0, 1):
        return bool(v)
    if isinstance(v, str):
        t = v.strip().lower().rstrip(".")
        if t in _TRUE:
            return True
        if t in _FALSE:
            return False
    return None


def _list_claim(a, key):
    """A list-of-names claim: a JSON list, or a string of names separated by commas or semicolons (before, a
    string was read one character at a time)."""
    v = _claim(a, key)
    if isinstance(v, str):
        return [x.strip() for x in re.split(r"[,;\n]", v) if x.strip()]
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    return []


def _answered(a):
    return bool(str((a or {}).get("answer") or "").strip())


def _cov(facts):
    c = facts.get("coverage")
    return "not declared" if c in (None, "not declared") else c


def _complete(facts):
    """Whether the CBOM declares complete coverage of its subject (PKI Consortium pkic:profile:coverage).
    Absence of an algorithm in a partial CBOM says nothing about the product."""
    return facts.get("coverage") == "complete"


def _absence(facts, what, unknown=()):
    """Status for a claim of absence that the CBOM does not contradict. Never "consistent" while the CBOM holds
    entries this toolkit cannot classify: an unrecognised entry may be exactly what the answer denies (1.6.0)."""
    unknown = sorted(set(unknown))
    if unknown:
        shown = ", ".join(unknown[:8]) + ("" if len(unknown) <= 8 else f" and {len(unknown) - 8} more")
        return _r("not-evidenced", f"The CBOM shows {what} that this toolkit recognises, but it also lists entries "
                                   f"the toolkit cannot classify ({shown}), so it cannot show the answer holds. "
                                   "Ask the vendor what they are.")
    if _complete(facts):
        return _r("consistent", f"The CBOM, which declares complete coverage, shows {what}.")
    cov = _cov(facts)
    return _r("not-evidenced", f"The CBOM shows {what}, but its coverage is {cov if cov != 'not declared' else 'not declared'}"
                               ", so this does not show the product has none.")


def _unclaimed(a, cbom_says):
    """No usable true/false claim: never "consistent". Unanswered, or answered in prose only."""
    if not _answered(a):
        return _r("unanswered", "Not answered. " + cbom_says)
    return _r("not-checked", "The answer gives no true/false claim, so it was not compared with the CBOM. "
                             + cbom_says)


def run_check(q, a, facts, ctx):
    """One check result. Against the CBOM: consistent | contradicted | not-evidenced | not-checked | unanswered |
    no-cbom | info. Stated dates: planned | past | implausible | missing-date | late."""
    chk = q.get("check")
    if not chk:
        return None
    if chk == "dated":
        key = next(iter(q["structured_claims"]))
        d, bad = _date_issue(a, key)
        if bad:
            return _r("missing-date", bad)
        if not d:
            return _r("missing-date", f"No date given in `{key}`.")
        if d > DEADLINE:
            return _r("late", f"`{key}` = {_claim(a, key)}, after the end of 2030.")
        if d < FIPS_PQC and key in ("pqc_ready_date", "roadmap_date"):
            return _r("implausible", f"`{key}` = {_claim(a, key)}, before NIST published FIPS 203/204/205 "
                                     "(August 2024); ask what the date refers to.")
        if d < datetime.date.today():
            return _r("past", f"`{key}` = {_claim(a, key)}, already passed: ask for evidence it happened.")
        return _r("planned", f"`{key}` = {_claim(a, key)}, before the end of 2030. A plan; not verified.")
    if facts is None:
        if chk == "cbom_supplied":
            if _bool_claim(a, "cbom") is True:
                return _r("contradicted", "The answer says a CBOM is supplied, but none was found at the "
                                          "answers file's `cbom` path.")
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
        claimed = _bool_claim(a, "cbom")
        what = (f"{len(algos)} algorithm(s), {len(facts['certificates'])} certificate(s), "
                f"{len(facts['protocols'])} protocol(s), {len(facts['libraries'])} librar(ies); {conf_s}")
        if claimed is False:
            return _r("contradicted", f"The answer says no CBOM is available, but one was supplied: {what}.")
        if claimed is None:
            return _unclaimed(a, f"A CBOM was supplied (coverage: {_cov(facts)}): {what}.")
        return _r("consistent", f"CBOM supplied (coverage: {_cov(facts)}): {len(algos)} algorithm(s), {len(facts['certificates'])} "
                                f"certificate(s), {len(facts['protocols'])} protocol(s), "
                                f"{len(facts['libraries'])} librar(ies); {conf_s}.")
    if chk == "cbom_layers":
        return _r("info", "Layers present in the CBOM: " + (", ".join(facts["layers"]) or "none") + ".")
    if chk == "third_party_crypto":
        found = ctx.get("cmvp", [])
        libs = facts["crypto_libraries"]       # libraries that provide cryptography, not every dependency
        claimed = _bool_claim(a, "third_party_crypto")
        if claimed is None:
            return _unclaimed(a, f"The CBOM lists {len(libs)} cryptographic librar(ies).")
        if claimed is False and (found or libs):
            return _r("contradicted", f"Answer says no, but the CBOM lists {len(libs)} cryptographic librar(ies) "
                                      f"({', '.join(sorted({c.get('name') or '?' for c in libs})[:6])})"
                                      + (f", including {', '.join(sorted({f['label'] for f in found}))}" if found else "")
                                      + ".")
        if not libs:
            if claimed is False:
                return _absence(facts, "no cryptographic library", facts.get("other_libraries", []))
            return _r("not-evidenced", "The CBOM lists no cryptographic library, so inherited cryptography cannot "
                                       "be checked.")
        return _r("consistent", f"The CBOM lists {len(libs)} cryptographic librar(ies)"
                                + (f"; recognised crypto implementations: {', '.join(sorted({f['label'] for f in found}))}"
                                   if found else "") + ".")
    if chk in ("traditional_asymmetric", "auth_asymmetric"):
        # A1 asks about protecting customer data flows (key establishment, encryption); signatures and
        # certificate keys are A6's subject, so A1 counts only non-authentication algorithms.
        vul = [x for x in algos if x["vulnerable"] is True
               and (x["auth"] if chk == "auth_asymmetric" else not x["auth"])
               and (chk == "auth_asymmetric" or x["lane"] in ("key-establishment", "public-key"))]
        key = "traditional_asymmetric" if chk == "traditional_asymmetric" else "traditional_asymmetric_auth"
        claimed = _bool_claim(a, key)
        names = ", ".join(sorted({x["name"] for x in vul})[:8])
        hybrids = sorted({x["name"] for x in algos if chk == "traditional_asymmetric" and not x["auth"]
                          and _HYBRID.search(x["name"] or "")})
        if claimed is False and not vul and hybrids:
            return _r("not-evidenced", f"Answer says none, but the CBOM shows hybrid key establishment "
                                       f"({', '.join(hybrids[:6])}), whose classical half is traditional asymmetric "
                                       "cryptography. Ask whether the answer counts it.")
        if claimed is True and not vul and hybrids:
            return _r("consistent", f"The CBOM shows hybrid key establishment ({', '.join(hybrids[:6])}), whose "
                                    "classical half is traditional asymmetric cryptography.")
        if claimed is None:
            return _unclaimed(a, f"The CBOM shows {names or 'no quantum-vulnerable algorithm'}.")
        if claimed is False and vul:
            return _r("contradicted", f"Answer says none, but the CBOM shows quantum-vulnerable "
                                      f"{'authentication' if chk == 'auth_asymmetric' else 'key-establishment'} "
                                      f"algorithms: {names}.")
        if claimed is True and not vul:
            return _r("not-evidenced", "Answer says yes, but the CBOM shows no quantum-vulnerable "
                                       f"{'authentication' if chk == 'auth_asymmetric' else 'key-establishment'} "
                                       "algorithm; the CBOM may be incomplete.")
        if vul:
            return _r("consistent", f"CBOM shows: {names}.")
        return _absence(facts, "no quantum-vulnerable algorithm", facts.get("unrecognised", []))
    if chk == "hybrid":
        hyb = sorted({x["name"] for x in algos if _HYBRID.search(x["name"] or "")
                      or (x["canonical"] and _HYBRID.search(x["canonical"]))})
        claimed = _bool_claim(a, "hybrid")
        plan, bad = _date_issue(a, "pqc_only_date")
        if claimed is None and not hyb:
            return _unclaimed(a, "No hybrid key establishment in the CBOM.")
        if claimed is False and hyb:
            return _r("contradicted", f"Answer says no hybrid support, but the CBOM shows {', '.join(hyb)}.")
        if claimed is True and not hyb:
            return _r("not-evidenced", "Answer says hybrid key establishment is supported, but the CBOM shows "
                                       f"none (coverage: {_cov(facts)}).")
        if claimed is None:
            return _unclaimed(a, f"The CBOM shows hybrid key establishment: {', '.join(hyb)}.")
        if claimed is False:
            return _absence(facts, "no hybrid key establishment", facts.get("unrecognised", []))
        if hyb or claimed:
            if not plan:
                return _r("missing-date", (f"Hybrid in use ({', '.join(hyb)}) " if hyb else "Hybrid supported ")
                          + "with no usable `pqc_only_date`; the publication expects a documented de-hybridisation "
                          "plan." + (" " + bad if bad else ""))
            if plan > DEADLINE:
                return _r("late", f"Hybrid treated as transitional, but PQC-only is planned for "
                                  f"{_claim(a, 'pqc_only_date')}, after the end of 2030.")
            if plan < datetime.date.today():
                if hyb:
                    return _r("contradicted", f"PQC-only was due {_claim(a, 'pqc_only_date')}, but the CBOM still "
                                              f"shows hybrid key establishment ({', '.join(hyb)}).")
                return _r("past", f"PQC-only date {_claim(a, 'pqc_only_date')} has passed: ask for evidence.")
            return _r("consistent", f"Hybrid treated as transitional; PQC-only planned {_claim(a, 'pqc_only_date')}.")
        return _r("info", "No hybrid key establishment in the CBOM.")
    if chk == "pqc_algorithms":
        claimed = _list_claim(a, "pqc_algorithms")
        in_cbom = {}
        for x in algos:
            # any recognised quantum-resistant public-key algorithm, including draft names such as Kyber768
            if x["canonical"] and x["vulnerable"] is False and x["lane"] in ("key-establishment", "signature",
                                                                              "public-key"):
                in_cbom[x["canonical"]] = x
        rows = []
        missing, below = [], []
        for name in claimed:
            r = cnsa.classify(name, profile=ctx["profile"])
            if not r.get("canonical") or r.get("quantum_vulnerable") is not False:
                missing.append(name)
                rows.append(f"{name}: not in this toolkit's ruleset, so not checked (it may still be a "
                            "quantum-resistant algorithm)")
                continue
            ok = (f"meets the `{ctx['profile']}` profile target" if r.get("priority") == "None"
                  else f"below the `{ctx['profile']}` profile target ({r.get('cnsa_target')})")
            if r.get("priority") != "None":
                below.append(name)
            want = r["canonical"].replace("-", "")
            hits = sorted(x["name"] for k, x in in_cbom.items() if want == k.replace("-", "") or want in k.replace("-", ""))
            if not hits:
                missing.append(name)
                rows.append(f"{name}: {ok}; not in the CBOM")
            else:
                direct = any(want == in_cbom[k]["canonical"].replace("-", "") for k in in_cbom
                             if in_cbom[k]["name"] in hits)
                rows.append(f"{name}: {ok}; in the CBOM" + ("" if direct else f" (within {', '.join(hits)})"))
        ga, bad = _date_issue(a, "ga_date")
        tail = (" " + bad) if bad else ("" if ga else " No `ga_date` given.")
        if ga and ga > DEADLINE:
            tail = f" `ga_date` = {_claim(a, 'ga_date')}, after the end of 2030."
        early = bool(ga and ga < FIPS_PQC)
        if early:
            tail = (f" `ga_date` = {_claim(a, 'ga_date')}, before NIST published FIPS 203/204/205 (August 2024): "
                    "ask what was generally available then.")
        if not claimed:
            seen = (" The CBOM shows " + ", ".join(sorted({x["name"] for x in in_cbom.values()})) + ".") if in_cbom else ""
            if not _answered(a):
                return _r("unanswered", "Not answered." + seen)
            # answered in prose only: nothing to compare (1.6.0; was "not-evidenced")
            return _r("not-checked", "The answer lists no algorithms in `pqc_algorithms`, so it was not compared "
                                     "with the CBOM." + seen + tail)
        future = bool(ga and ga > datetime.date.today())
        if missing and future:
            # not generally available yet: absence from today's CBOM is expected, not a gap (1.6.0)
            rows.append(f"`ga_date` {_claim(a, 'ga_date')} is in the future, so algorithms not yet in the CBOM "
                        "are a plan, not a gap")
        status = ("late" if ga and ga > DEADLINE
                  else "planned" if missing and future
                  else "not-evidenced" if missing else "missing-date" if bad else "implausible" if early
                  else "below-target" if below else "consistent")
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
    late = [i for i in ("T1", "T3", "I1", "C3", "C5")
            if results.get(i) and results[i]["status"] in ("missing-date", "late", "implausible")]
    if late:
        out.append(("unclear or deferred transition timelines", "Missing or post-2030 dates: " + ", ".join(late) + "."))
    # "Proprietary or opaque cryptography" is not raised automatically: a name the ruleset does not recognise is
    # not evidence that the vendor uses proprietary cryptography (1.5.1). Such names are listed in the report for
    # review instead.
    if _bool_claim(A.get("I6") or {}, "pqc_in_base_license") is False:
        out.append(("treatment of PQC as an optional or premium function", "I6: PQC is not in base licensing."))
    if _bool_claim(A.get("A5") or {}, "stronger_traditional_settings") is True \
            and not _list_claim(A.get("I1") or {}, "pqc_algorithms"):
        out.append(("over-reliance on compensating controls",
                    "Stronger traditional settings are offered (A5) but no PQC algorithms are committed (I1). "
                    "Larger classical keys do not address the risk from a CRQC."))
    if not answered("T5") or not (A.get("T5") or {}).get("evidence"):
        out.append(("lack of governance or ownership", "T5 is unanswered or cites no evidence."))
    return out


# --- assess ---------------------------------------------------------------------------------
def load_answers(answers_path):
    """(answers dict, raw bytes), checked for shape; VendorInputError otherwise."""
    try:
        with open(answers_path, "rb") as f:
            raw = f.read()
        answers = json.loads(raw.decode("utf-8"))
    except OSError as e:
        raise VendorInputError(f"--answers {answers_path}: {e.strerror}")
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise VendorInputError(f"--answers {answers_path}: not valid JSON ({e})")
    if not isinstance(answers, dict) or not isinstance(answers.get("answers", {}), dict):
        raise VendorInputError(f"--answers {answers_path}: expected an object with an \"answers\" object "
                               "(start from `vendor_readiness.py template`)")
    for qid, a in answers.get("answers", {}).items():
        if not isinstance(a, dict) or not isinstance(a.get("claims", {}) or {}, dict) \
                or not isinstance(a.get("evidence", []) or [], list) \
                or not isinstance(a.get("answer", "") or "", str):
            raise VendorInputError(f"--answers {answers_path}: answer {qid!r} must be an object with \"answer\" "
                                   "text, an \"evidence\" list and a \"claims\" object")
    return answers, raw


def answers_cbom_path(answers, answers_path):
    """The CBOM the answers name (relative to the answers file), '' if none; VendorInputError if missing."""
    cbom_path = answers.get("cbom") or ""
    if cbom_path and not isinstance(cbom_path, str):
        raise VendorInputError(f"--answers {answers_path}: \"cbom\" must be a file path")
    if cbom_path and not os.path.isabs(cbom_path):
        cbom_path = os.path.join(os.path.dirname(os.path.abspath(answers_path)), cbom_path)
    if cbom_path and not os.path.isfile(cbom_path):
        raise VendorInputError(f"the answers name a CBOM at {cbom_path}, which does not exist (the path is relative "
                               "to the answers file)")
    return cbom_path


def assess(answers_path, profile=None, doc=None):
    doc = doc or load_questions()
    profile = profile or cnsa.DEFAULT_PROFILE
    answers, raw = load_answers(answers_path)
    known = {q["id"] for q in doc["questions"]}
    unknown = sorted(k for k in answers.get("answers", {}) if k not in known)
    inputs = {"answers": {"file": os.path.basename(answers_path), "sha256": hashlib.sha256(raw).hexdigest()}}
    facts, ctx = None, {"profile": profile}
    cbom_path = answers_cbom_path(answers, answers_path)
    if cbom_path:
        try:
            with open(cbom_path, "rb") as f:
                craw = f.read()
            bom = json.loads(craw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as e:
            raise VendorInputError(f"CBOM {cbom_path}: not valid JSON ({e})")
        if not isinstance(bom, dict) or not isinstance(bom.get("components", []) or [], list):
            raise VendorInputError(f"CBOM {cbom_path}: not a CycloneDX document")
        inputs["cbom"] = {"file": os.path.basename(cbom_path), "sha256": hashlib.sha256(craw).hexdigest()}
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
            "cbom_path": cbom_path if facts is not None else "", "unknown_ids": unknown, "inputs": inputs,
            "run_date": datetime.date.today().isoformat()}


def _cut(s, n):
    return s if len(s) <= n else s[:n].rstrip() + " [... truncated; full text in the answers file]"


def _toolkit_version():
    try:
        from tier2_pipeline import TOOLKIT_VERSION
        return TOOLKIT_VERSION
    except Exception:  # pragma: no cover
        return "?"


def _cell(s):
    return (s or "").replace("|", "\\|").replace("\n", " ").strip()


def report_md(res):
    doc, ans = res["doc"], res["answers"]
    A = ans.get("answers", {})
    counts, dates = {}, {}
    for r in res["results"].values():
        bucket = counts if r["status"] in CBOM_STATUSES else dates
        bucket[r["status"]] = bucket.get(r["status"], 0) + 1
    answered = sum(1 for q in doc["questions"] if (A.get(q["id"]) or {}).get("answer", "").strip())
    contra = sorted(k for k, v in res["results"].items() if v["status"] == "contradicted")
    L = [f"# Vendor PQC readiness: {ans.get('vendor') or '?'} {ans.get('product') or ''} {ans.get('version') or ''}".rstrip(),
         "",
         f"Answers dated {ans.get('answered') or '?'}; ruleset profile `{res['profile']}`; assessed "
         f"{res.get('run_date', '?')} with fedlin-pqc-toolkit {_toolkit_version()} (ruleset {cnsa.RULESET_VERSION}). "
         "Inputs: " + ", ".join(f"{v['file']} (SHA-256 {v['sha256'][:16]}...)" for v in res.get("inputs", {}).values())
         + ".",
         "",
         "> **Scope:** the vendor's own answers, checked against the CBOM the vendor supplied"
         + (f" (declared coverage: {res['facts']['coverage']})" if res["facts"] else " (none supplied)")
         + ". A check compares the answer with that CBOM only: it does not verify the CBOM, the product, or any "
         "other version.  ",
         "> **Not a determination.** \"consistent\" means the answer and the CBOM agree; it does not mean the "
         "product is quantum-resistant or meets any requirement. \"contradicted\" means they disagree; it is a "
         "question to put to the vendor, not a finding of bad faith. This is not a compliance determination, a "
         "certification or a FIPS 140-3 validation.",
         "",
         "*" + attribution(doc) + "*",
         "",
         f"**{answered} of {len(doc['questions'])} questions answered.** Checks against the vendor's CBOM: "
         + (", ".join(f"{v} {k}" for k, v in sorted(counts.items())) or "none") + ". Stated dates (plans, not "
         "verified): " + (", ".join(f"{v} {k}" for k, v in sorted(dates.items())) or "none") + ".",
         "",
         (f"**{len(contra)} answer(s) contradict the vendor's own CBOM: {', '.join(contra)}.** Put these to the "
          "vendor first." if contra else "No answer contradicts the vendor's CBOM."),
         "",
         "Disclosure answers are compared with the vendor's CBOM where a check exists. Capability answers hold "
         "only for the version assessed. Intent answers are plans and are not verified.",
         ""]
    if not res["facts"]:
        L += ["> No CBOM was supplied, so no disclosure answer could be checked.", ""]
    elif not _complete(res["facts"]):
        cov = _cov(res["facts"])
        L += [f"> The vendor's CBOM {'declares ' + cov + ' coverage' if cov != 'not declared' else 'does not declare its coverage'}"
              ", so an algorithm missing from it "
              "may still be in the product: a claim that something is absent is \"not-evidenced\", never "
              "\"consistent\".", ""]
    if res.get("unknown_ids"):
        L += ["> Answers with ids that are not among the 31 questions were ignored: "
              + ", ".join(res["unknown_ids"]) + ".", ""]
    unrec = sorted({x["name"] for x in (res["facts"] or {}).get("algorithms", []) if not x["canonical"]})
    if unrec:
        L += ["> Algorithm names in the CBOM that the ruleset does not recognise (review them; this is not a "
              "judgement that they are proprietary): " + ", ".join(_cell(n) or "(empty name)" for n in unrec[:20])
              + ("" if len(unrec) <= 20 else f" and {len(unrec) - 20} more") + ".", ""]
    L += ["## Common concerns", ""]
    if res["concerns"]:
        L += [f"- **{c}:** {d}" for c, d in res["concerns"]]
    else:
        L.append("None of the publication's seven concerns was raised from the structured answers"
                 + (" (the contradictions above are listed separately)." if contra else "."))
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
        L.append(f"| {q['id']} | {_cell(q['question'])} | {q['claim_type']} | {_cell(_cut(txt, 400))} | "
                 f"{_cell(_cut(ev, 200))} | {_cell(chk)} |")
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
            "concerns": [c for c, _ in res["concerns"]], "cbom": bool(res["facts"]),
            "cbom_coverage": res["facts"]["coverage"] if res["facts"] else None,
            "statuses": {k: v["status"] for k, v in sorted(res["results"].items())},
            "claims_given": sum(1 for a in A.values() if isinstance(a, dict)
                                for v in (a.get("claims") or {}).values() if v not in (None, "", [])),
            "evidence_cited": sum(1 for a in A.values() if isinstance(a, dict) and a.get("evidence")),
            "unknown_ids": res.get("unknown_ids", []), "inputs": res.get("inputs", {}),
            "toolkit_version": _toolkit_version(), "ruleset_version": cnsa.RULESET_VERSION,
            "assessed": res.get("run_date")}


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
    s.add_argument("--fail-on", default="",
                   help="comma-separated check statuses that make the exit code 1, e.g. contradicted,late; an "
                        "unknown status is an error (exit 2). Default: exit 0 whatever the checks found")
    a = ap.parse_args(argv)
    fail = set()
    if a.cmd == "assess":
        fail = {x.strip().lower() for x in a.fail_on.split(",") if x.strip()}
        bad = sorted(fail - set(STATUSES))
        if bad:
            sys.stderr.write(f"[error] --fail-on: unknown status {', '.join(bad)}; use any of {', '.join(STATUSES)}\n")
            return 2
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
    try:
        res = assess(a.answers, a.profile, doc)
    except VendorInputError as e:
        sys.stderr.write(f"[error] {e}\n")
        return 2
    if res["unknown_ids"]:
        sys.stderr.write(f"[warn] ignored answers with unknown question ids: {', '.join(res['unknown_ids'])}\n")
    out = a.out or a.answers.rsplit(".", 1)[0] + ".report.md"
    with open(out, "w", encoding="utf-8") as f:
        f.write(report_md(res) + "\n")
    s = summary(res)
    with open(out.rsplit(".", 1)[0] + ".summary.json", "w") as f:
        json.dump(s, f, indent=2)
    print(f"[ok] {out}: {s['answered']}/{s['questions']} answered; checks {s['checks']}; "
          f"contradicted {s['contradicted'] or 'none'}; concerns {len(s['concerns'])}")
    hit = sorted(k for k, st in s["statuses"].items() if st in fail)
    if hit:
        print(f"[fail-on] {', '.join(hit)} have a status in --fail-on ({', '.join(sorted(fail))})")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
