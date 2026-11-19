#!/usr/bin/env python3
"""FEDLIN PQC Toolkit: report stage (v0.1).

Turns a validated CycloneDX 1.6 CBOM (as produced by tier2_pipeline.py) into the
two artifacts a buyer actually reads and funds:

  1. an EXECUTIVE SCORECARD: a PQC-readiness score, exposure counts, top risks,
     and mandate alignment (EO 14412 / OMB M-26-15 / NIST IR 8547 / CNSA 2.0);
  2. a PRIORITIZED MIGRATION ROADMAP: vulnerable assets sequenced into waves
     anchored to the NIST IR 8547 timeline (RSA/ECC deprecated 2030, disallowed
     2035), each with its migration target (civilian or nss profile) and 800-53 controls.

Deterministic (Mode C): reads only what the overlay already stamped onto the CBOM
(`cnsa2:*` verdicts, `crosswalk:<regime>` refs). No AI, no network at classification time, no re-eval.
The CBOM is the single source of truth: this stage never re-classifies.

Usage:  python3 report.py --cbom out/cbom.json --out out/cbom.report.md [--json out/cbom.summary.json]
"""
import argparse
import datetime
import html
import json
import os
import re
import sys


# Optional private modules (FEDLIN engagement kit). The public toolkit runs without them.
try:
    import roadmap as _roadmap  # engineered migration sequencing
except ImportError:
    _roadmap = None
try:
    import whitelabel as _whitelabel  # reseller branding
except ImportError:
    _whitelabel = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling modules, also under python -I
import cnsa20_ruleset as cnsa  # HNDL: classify negotiated key exchange
import cmvp as _cmvp  # FIPS 140-3 (CMVP) candidates from the dated snapshot in data/cmvp/
import evidence as _ev  # how each CBOM record was observed (CycloneDX component evidence)

PRIORITY_ORDER = {"Critical": 0, "High": 1, "Low": 2, "None": 3, "Review": 4}

# Characters that would let a CBOM string change the Markdown around it (GHSA-gmv4-8882-x388): a line break or a
# table-cell separator, raw HTML, a link target, a code span, a backslash escape. Names in a CBOM can be chosen by a
# scanned server (certificate subjects) or by whoever wrote a merged CBOM (--merge-cbom), so none of them is
# trusted. A pipe becomes the entity rather than "\|" because the same strings are also parsed as JSON here
# (cnsa2:config). Terminal escape sequences and other control bytes are removed first.
_MD_UNSAFE = (("\\", "\\\\"), ("\r", " "), ("\n", " "), ("\t", " "), ("|", "&#124;"), ("<", "&lt;"),
              (">", "&gt;"), ("](", "]&#40;"), ("`", "&#96;"))
# Control bytes, terminal escapes, line/paragraph separators, and (1.5.0) the invisible and bidirectional
# formatting characters (zero-width, LRM/RLM, LRE..RLO, LRI..PDI, BOM, tag characters).
_CONTROL = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-_]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029"
                      r"\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff\U000e0000-\U000e007f]")


def md_text(v):
    """A CBOM string made inert in Markdown: one line, no control bytes, no cell separator, no raw HTML, no link
    target, no backslash escape."""
    s = _CONTROL.sub("", str(v))
    for a, b in _MD_UNSAFE:
        s = s.replace(a, b)
    return s


def md_code(v):
    """An inert string (md_text) for use inside a `code span`: the characters shown as written, the backtick and
    the table-cell separator still neutralised."""
    s = html.unescape(str(v)).replace("\\\\", "\\")
    # Unescaping can turn an entity the CBOM carried as text (&#10;, &#13;) back into a line break or control
    # byte, so those are removed again after it: the span must stay on one line.
    s = _CONTROL.sub("", s)
    for a, b in (("\r", " "), ("\n", " "), ("\t", " ")):
        s = s.replace(a, b)
    return s.replace("`", "'").replace("|", "\\|")


def _inert(o):
    """Every string in a CBOM (values, not keys) through md_text, for building the report Markdown from it. A
    JSON-valued property (cnsa2:config) is made inert inside, so it still parses."""
    if isinstance(o, dict):
        if o.get("name") == "cnsa2:config" and isinstance(o.get("value"), str):
            try:
                return {"name": "cnsa2:config", "value": json.dumps(_inert(json.loads(o["value"])))}
            except ValueError:
                pass
        return {k: _inert(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_inert(v) for v in o]
    return md_text(o) if isinstance(o, str) else o


def load(path):
    with open(path) as f:
        return json.load(f)


def props(comp):
    return {p["name"]: p["value"] for p in comp.get("properties", [])}


def _coverage(bom):
    """The coverage the CBOM declares for its subject (PKI Consortium profile), 'partial' if it declares none."""
    comp = (bom.get("metadata", {}) or {}).get("component", {}) or {}
    return next((p.get("value") for p in comp.get("properties", []) or []
                 if p.get("name") == "pkic:profile:coverage"), None) or "partial"


def meta_props(bom):
    return {p["name"]: p["value"] for p in bom.get("metadata", {}).get("properties", [])}


_LANE_BY_PRIMITIVE = {
    "kem": "key-establishment", "key-agree": "key-establishment", "signature": "signature",
    "pke": "public-key", "block-cipher": "symmetric", "stream-cipher": "symmetric", "ae": "symmetric",
    "mac": "symmetric", "hash": "hash", "kdf": "kdf",
}
PUBLIC_KEY_LANES = ("key-establishment", "signature", "public-key")


def _usage_counts(bom):
    """How many assets (certificates, protocol sessions, ...) reference each algorithm bom-ref."""
    n = {}
    for d in bom.get("dependencies", []):
        for ref in d.get("dependsOn", []):
            n[ref] = n.get(ref, 0) + 1
    return n


def _lane(c, p):
    """Lane from the stamped ruleset property, else from the CBOM primitive (never re-classified)."""
    if p.get("fedlin:lane"):
        return p["fedlin:lane"]
    name = (c.get("name") or "").lower()
    if name.startswith(("tlsv", "sslv")):
        return "protocol"
    prim = c.get("cryptoProperties", {}).get("algorithmProperties", {}).get("primitive", "")
    return _LANE_BY_PRIMITIVE.get(prim, "other")


def algorithms(bom):
    """Algorithm assets the overlay classified (carry a cnsa2 verdict), with usage weight and lane."""
    usage = _usage_counts(bom)
    out = []
    for c in bom.get("components", []):
        if c.get("type") != "cryptographic-asset":
            continue
        cp = c.get("cryptoProperties", {})
        if cp.get("assetType") != "algorithm":
            continue
        p = props(c)
        if "cnsa2:quantum_vulnerable" not in p:
            continue  # merged-in asset without our overlay; not scored
        out.append({
            "name": c.get("name", "unknown"),
            "ref": c.get("bom-ref"),
            "vulnerable": p.get("cnsa2:quantum_vulnerable"),
            "target": p.get("cnsa2:target", ""),
            "controls": [x for x in p.get("cnsa2:controls", "").split(",") if x],
            "priority": p.get("cnsa2:priority", "Review"),
            "crosswalk": next((v for k, v in p.items() if k.startswith("crosswalk:")), None),
            "regime": next((k.split(":", 1)[1] for k in p if k.startswith("crosswalk:")), None),
            "capability": p.get("fedlin:capability") == "true",
            "evidence": p.get("fedlin:evidence", ""),
            "lane": _lane(c, p),
            "profile": p.get("fedlin:profile"),
            # an algorithm no asset references (e.g. merged from a source scan) still counts once
            "weight": max(1, usage.get(c.get("bom-ref"), 0)),
        })
    return out


def _w(items):
    return sum(a["weight"] for a in items)


def score_summary(bom, regime=None):
    """Scoring primitive shared by the report and the delta stage.

    Score = usages of profile-compliant quantum-resistant public-key algorithms divided by
    (compliant + quantum-vulnerable) public-key usages. A usage is one reference from an asset
    (a certificate's key or signature, a TLS session's key exchange, an offered SSH algorithm),
    so 50 certificates on the same key type weigh 50, not 1.

    - Public-key lanes only (key establishment, signature, public key). Symmetric, hash, KDF and
      protocol-version assets are reported in `lanes` but do not move the score.
    - Compliance follows the profile the CBOM was built with (fedlin:profile; civilian = NIST/IR 8547,
      nss = CNSA 2.0): a target starting "None" is compliant. Quantum-resistant usages below the
      profile target are "transitional" and excluded from the denominator.
    - Classically broken items (priority Critical) count as vulnerable when they are public-key, and
      lead Wave 0 in every lane.
    `regime` is accepted for backward compatibility; the profile already decided compliance.
    """
    algos = algorithms(bom)
    resistant = [a for a in algos if a["vulnerable"] == "False"]
    vuln = [a for a in algos if a["vulnerable"] == "True"]
    review = [a for a in algos if a["vulnerable"] not in ("True", "False")]
    compliant = [a for a in resistant if (a["target"] or "").startswith("None")]
    transitional = [a for a in resistant if not (a["target"] or "").startswith("None")]

    pk = lambda xs: [a for a in xs if a["lane"] in PUBLIC_KEY_LANES]  # noqa: E731
    num, vul = _w(pk(compliant)), _w(pk(vuln))
    scored = num + vul
    score = round(100 * num / scored) if scored else None

    lanes = {}
    # membership by identity: `a in vuln` compared whole dicts, quadratic on a large CBOM (an MCP summarize of
    # a 2 MB CBOM took ~50 s)
    vuln_ids, compliant_ids, transitional_ids = ({id(a) for a in xs} for xs in (vuln, compliant, transitional))
    for a in algos:
        d = lanes.setdefault(a["lane"], {"compliant": 0, "transitional": 0, "vulnerable": 0,
                                         "broken": 0, "review": 0})
        if a["priority"] == "Critical":
            d["broken"] += a["weight"]
        elif id(a) in vuln_ids:
            d["vulnerable"] += a["weight"]
        elif id(a) in compliant_ids:
            d["compliant"] += a["weight"]
        elif id(a) in transitional_ids:
            d["transitional"] += a["weight"]
        else:
            d["review"] += a["weight"]
    profiles = sorted({a["profile"] for a in algos if a.get("profile")})
    tls = [c for c in bom.get("components", [])
           if any(p.get("name") == "pkic:profile:interfaceType" for p in c.get("properties", []))]
    # not observed: declared unknown, or a group the scan could not read (unparsed-kex-group, fedlin:kexConflict)
    kex_unobserved = [c["name"] for c in tls
                      if any((p.get("name") == "pkic:profile:disclosure:keyExchange" and p.get("value") == "unknown")
                             or (p.get("name") == "pkic:profile:keyExchange" and p.get("value") == "unparsed-kex-group")
                             for p in c.get("properties", []))]
    kex_pq = [c["name"] for c in tls
              if any(p.get("name") == "pkic:profile:keyExchange" and "mlkem" in (p.get("value") or "").lower()
                     for p in c.get("properties", []))]
    return {"interfaces": len(tls), "kex_unobserved": kex_unobserved, "kex_pq": kex_pq, "score": score, "resistant": resistant, "compliant": compliant, "transitional": transitional,
            "vuln": vuln, "review": review, "scored": scored, "lanes": lanes,
            "profile": profiles[0] if len(profiles) == 1 else ("mixed" if profiles else None)}


def _mark(a):
    """Append a capability marker to a dependency-inferred asset name."""
    return f"{a['name']} †" if a.get("capability") else a["name"]


SECRET_HYGIENE_TYPES = {"token", "password", "credential"}


def is_secret_hygiene(comp):
    """A gitleaks-style secret detection (API key / token) surfaced by cbomkit-theia.

    These are leaked credentials, NOT quantum-vulnerable cryptography: they carry no
    algorithm and must not pollute the PQC crypto-asset count or the readiness score.
    Distinguisher: related-crypto-material with NO algorithmRef and a token/credential
    type (or a 'key' type whose name is an API-key rule). Legitimate key material (e.g.
    a private key tied to an algorithm via algorithmRef) is NOT caught.
    """
    cp = comp.get("cryptoProperties", {})
    if cp.get("assetType") != "related-crypto-material":
        return False
    rcmp = cp.get("relatedCryptoMaterialProperties", {})
    if rcmp.get("algorithmRef"):
        return False  # tied to a real algorithm → legitimate crypto material
    t = (rcmp.get("type") or "").lower()
    name = (comp.get("name") or "").lower()
    if t in SECRET_HYGIENE_TYPES:
        return True
    if t == "key" and any(k in name for k in ("api-key", "apikey", "api key", "token", "secret", "credential", "password")):
        return True
    return False


def secret_hygiene_items(bom):
    """gitleaks secret detections, with locations (never values): for the incidental section."""
    out = []
    for c in bom.get("components", []):
        if c.get("type") == "cryptographic-asset" and is_secret_hygiene(c):
            locs = sorted({o.get("location", "") for o in (c.get("evidence", {}).get("occurrences") or [])
                           if o.get("location")})
            out.append({
                "name": c.get("name", "?"),
                "type": c.get("cryptoProperties", {}).get("relatedCryptoMaterialProperties", {}).get("type", "?"),
                "locations": locs,
            })
    return out


def other_assets(bom):
    """Non-algorithm crypto assets (certs, protocols, key material): for the inventory line.
    Excludes gitleaks secret-hygiene detections, which are reported separately (not PQC)."""
    counts = {}
    hndl = []
    for c in bom.get("components", []):
        if c.get("type") != "cryptographic-asset":
            continue
        if is_secret_hygiene(c):
            continue  # surfaced in the incidental secret-hygiene section, not the PQC inventory
        at = c.get("cryptoProperties", {}).get("assetType", "other")
        if at == "algorithm":
            continue
        counts[at] = counts.get(at, 0) + 1
        p = props(c)
        if "fedlin:hndl_exposure" in p:
            hndl.append((c.get("name", "asset"), p["fedlin:hndl_exposure"], p.get("cnsa2:priority", "High")))
        # A TLS session negotiated with quantum-vulnerable key exchange can be recorded now and decrypted later.
        kex = [x.get("value") for x in c.get("properties", []) if x.get("name") == "pkic:profile:keyExchange"]
        if at == "protocol" and kex and any(cnsa.classify(k).get("quantum_vulnerable") is True for k in kex):
            hndl.append((c.get("name", "TLS session"), "key exchange " + ", ".join(kex) + " is quantum-vulnerable; "
                         "recorded sessions can be decrypted later", "High"))
    return counts, hndl


def _parse_ts(s):
    """Parse an RFC3339-ish CBOM timestamp to a naive UTC datetime (deterministic; no clock read)."""
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(s, fmt)
        except (ValueError, TypeError):
            continue
    return None


def certificates(bom):
    """X.509 certificate assets, with validity window and chain depth (for the posture section)."""
    out = []
    for c in bom.get("components", []):
        cp = c.get("cryptoProperties", {})
        if c.get("type") != "cryptographic-asset" or cp.get("assetType") != "certificate":
            continue
        certp = cp.get("certificateProperties", {})
        p = props(c)
        out.append({
            "name": c.get("name", "?"),
            "subject": certp.get("subjectName", ""),
            "issuer": certp.get("issuerName", ""),
            "not_before": certp.get("notValidBefore"),
            "not_after": certp.get("notValidAfter"),
            "chain_depth": p.get("fedlin:chain_depth"),
            "public_trust": p.get("fedlin:public_trust"),  # "true"/"false"/None (None → assume public, conservative)
        })
    return out


# CA/Browser Forum maximum TLS certificate lifetime step-down (398 -> 47 days by 2029).
# A cert whose validity window already exceeds an upcoming cap cannot be renewed like-for-like
# under that cap: i.e. it forces shorter-lived certs and thus renewal automation.
CERT_LIFETIME_CAPS = [
    ("2026-03-15", 200, "CA/B Forum 200-day cap (first step-down)"),
    ("2027-03-15", 100, "CA/B Forum 100-day cap"),
    ("2029-03-15", 47, "CA/B Forum 47-day cap (target)"),
]


def cert_posture(bom):
    """Renewal-exposure view of the certificate estate, deterministic against the CBOM timestamp.

    Surfaces the CA/Browser-Forum 47-day cert-cliff (certs expiring soon, and the shrinking
    max-lifetime caps that make manual renewal untenable): the crypto-agility discipline PCI
    DSS 4.0 §12.3.3 and the cert-lifetime step-down turn into recurring work.
    """
    now = _parse_ts(bom.get("metadata", {}).get("timestamp", ""))
    certs = certificates(bom)
    rows, buckets = [], {"expired": 0, "d30": 0, "d90": 0, "d365": 0, "beyond": 0}
    for c in certs:
        na = _parse_ts(c["not_after"])
        days = None
        if na and now:
            days = (na - now).days
            if days < 0:
                buckets["expired"] += 1
            elif days <= 30:
                buckets["d30"] += 1
            elif days <= 90:
                buckets["d90"] += 1
            elif days <= 365:
                buckets["d365"] += 1
            else:
                buckets["beyond"] += 1
        # lifetime span (issuance -> expiry) vs the upcoming CA/B caps
        nb = _parse_ts(c["not_before"])
        span = (na - nb).days if (na and nb) else None
        now_date = now.date() if now else None
        # CA/B Forum lifetime caps apply only to publicly-trusted TLS server certificates.
        # Internal PKI roots and internally-issued certs are not CA/B-governed.
        # Explicit "false" → skip; unset (None) → conservative, apply caps.
        skip_cab = (c.get("public_trust") == "false")
        all_exceeded = [] if skip_cab else [(d, cap, label) for d, cap, label in CERT_LIFETIME_CAPS
                                            if span is not None and span > cap]
        exceeds_current = [label for d, cap, label in all_exceeded
                           if now_date and datetime.date.fromisoformat(d) <= now_date]
        exceeds_future = [(d, cap, label) for d, cap, label in all_exceeded
                          if not now_date or datetime.date.fromisoformat(d) > now_date]
        rows.append({**c, "days_left": days, "span_days": span,
                     "exceeds_caps": exceeds_current, "exceeds_caps_future": exceeds_future,
                     "skip_cab": skip_cab})
    return {"rows": rows, "buckets": buckets, "count": len(certs), "now": now}


def transport_posture(mp):
    """Transport/crypto-agility posture from captured cluster context (metadata properties)."""
    out = {}
    if mp.get("fedlin:min_tls"):
        raw = mp["fedlin:min_tls"]
        out["min_tls"] = {"VersionTLS10": "TLS 1.0", "VersionTLS11": "TLS 1.1",
                          "VersionTLS12": "TLS 1.2", "VersionTLS13": "TLS 1.3"}.get(raw, raw)
        out["min_tls_weak"] = raw in ("VersionTLS10", "VersionTLS11")
    ciphers = mp.get("fedlin:tls_ciphers")
    if ciphers:
        try:
            clist = json.loads(ciphers)
        except (ValueError, TypeError):
            clist = [x for x in ciphers.replace("[", "").replace("]", "").replace('"', "").split(",") if x]
        out["cipher_count"] = len(clist)
        out["ciphers"] = clist
        # crypto-agility red flags a questionnaire / PCI 12.3.3 review would raise
        out["cbc_ciphers"] = sorted(c for c in clist if "CBC" in c.upper())
        out["sha1_ciphers"] = sorted(c for c in clist if c.upper().endswith("SHA") or "-SHA1" in c.upper())
        out["aes128_ciphers"] = sorted(c for c in clist if "AES128" in c.upper() or "AES-128" in c.upper())
    if mp.get("fedlin:etcd_encryption"):
        out["etcd_encryption"] = mp["fedlin:etcd_encryption"]
    if mp.get("fedlin:hsm_indicators"):
        out["hsm"] = mp["fedlin:hsm_indicators"]
    return out


def hardware_components(bom):
    """Device and OS components with PQC hardware posture (CycloneDX type: device, operating-system, firmware)."""
    out = []
    for c in bom.get("components", []):
        if c.get("type") not in ("device", "operating-system", "firmware"):
            continue
        p = props(c)
        if "fedlin:hw_class" not in p:
            continue
        out.append({
            "name": c.get("name", "?"),
            "hw_class": p.get("fedlin:hw_class", ""),
            "pqc_capable": p.get("fedlin:hw_pqc_capable", "unknown"),
            "action": p.get("fedlin:hw_action", ""),
            "action_detail": p.get("fedlin:hw_action_detail", ""),
            "fips_status": p.get("fedlin:hw_fips_status", ""),
            "tls13": p.get("fedlin:tls13_enabled"),
            "pqc_gate": p.get("fedlin:hw_pqc_gate") == "true",
        })
    return out


def server_configuration(bom):
    """Per TLS endpoint: what it accepts (enumeration facts) with the policy stage's verdicts (cnsa2:config)."""
    rows = []
    for c in bom.get("components", []):
        p = props(c)
        if not p.get("fedlin:enumeration"):
            continue
        server = (p.get("pkic:profile:endpointRole:server") or c.get("name", "")).split(":", 1)[-1]
        try:
            items = json.loads(p.get("cnsa2:config") or "[]")
        except ValueError:
            items = []
        groups = [g for g in (p.get("fedlin:acceptedGroups") or "").split(",") if g and g != "none"]
        rows.append({"server": server, "status": p["fedlin:enumeration"],
                     "versions": [v for v in (p.get("fedlin:acceptedProtocolVersions") or "").split(",") if v and v != "none"],
                     "mlkem": [g for g in groups if "mlkem" in g.lower()],
                     "refused_mlkem": [g for g in (p.get("fedlin:refusedGroups") or "").split(",") if "mlkem" in g.lower()],
                     "broken": [i["item"] for i in items if i["status"] == "broken"],
                     "vulnerable": [i["item"] for i in items if i["status"] == "vulnerable"],
                     "static_rsa": list(dict.fromkeys(i["item"].split(" ", 4)[-1] for i in items
                                                      if (i.get("target") or "").startswith("Disable static-RSA suites"))),
                     "unanswered": [v for v in (p.get("fedlin:untestedProtocolVersions") or "").split(",") if v],
                     "items": items, "note": p.get("fedlin:enumerationNote", ""), "tool": p.get("fedlin:enumerationTool", ""),
                     "truncated": p.get("fedlin:enumerationTruncated", ""),
                     "incomplete": p.get("fedlin:enumerationIncomplete", "")})
    return rows


def classical_fallback(bom):
    """TLS interfaces probed with a classical-only client: [(server, outcome, negotiated)]. Facts from the CBOM."""
    rows = []
    for c in bom.get("components", []):
        p = props(c)
        o = p.get("fedlin:classicalOnlyOffer")
        if o:
            server = (p.get("pkic:profile:endpointRole:server") or c.get("name", "")).split(":", 1)[-1]
            got = p.get("fedlin:classicalOnlyNegotiated", "")
            if p.get("fedlin:classicalOnlyOfferReduced"):
                got = (got + " " if got else "") + "(reduced FIPS offer)"
            rows.append((server, o, got))
    return rows


DISCLAIMER = ("The readiness score is this toolkit's own measure of the cryptography this scan observed. It is not "
              "a compliance determination: not an ATO, a FedRAMP authorization, a claim of FISMA compliance, a FIPS "
              "140-3 validation or a PKI Consortium PQCMM level.")


def scope_statement(mp):
    """What this scan covered, from the CBOM's capture record, and that it is not an estate inventory."""
    capture = (mp.get("fedlin:scope_covered") or mp.get("fedlin:capture") or "what this scan was pointed at").rstrip(".")
    return (f"{capture}. Only what this scan was pointed at: not an inventory of all the cryptography the "
            "organization runs")


def observed_note(s):
    """What was observed, in plain terms, in place of a letter grade (retired in 1.5.0: a grade read as a ruling
    and could not carry its scope). Counts only; no judgement beyond the verdicts."""
    if s["score"] is None:
        return "no public-key usages were scored"
    parts = []
    if s["interfaces"]:
        parts.append(f"post-quantum key exchange negotiated on {len(s['kex_pq'])} of {s['interfaces']} TLS "
                     "endpoint(s)")
    for lane, label in (("signature", "signature"), ("public-key", "public-key (certificate key)"),
                        ("key-establishment", "key-establishment")):
        d = s["lanes"].get(lane)
        if not d:
            continue
        total = d["compliant"] + d["transitional"] + d["vulnerable"] + d["broken"]
        if total:
            parts.append(f"{d['compliant'] + d['transitional']} of {total} {label} usage(s) quantum-resistant")
    return "; ".join(parts) or "public-key usages were scored; see the table below"


def _findings_table(vuln, review, resistant, cap, profile):
    """Public findings: each quantum-vulnerable algorithm with its standard migration target, the 800-53
    controls it is evidence for, and a confidence level. Not sequenced or owner-assigned."""
    L = []
    # ---- GATED: flat vulnerable-list with confidence bands, no engineered sequencing ----
    L.append("## Detected quantum-vulnerable algorithms")
    L.append("")
    L.append("Standard migration targets for each detected quantum-vulnerable algorithm. The list is not "
             "sequenced, scoped or owner-assigned.")
    L.append("")
    L.append("| Algorithm | Standard migration target | 800-53 | Confidence |")
    L.append("|---|---|---|---|")
    seen = set()
    for a in sorted(vuln, key=lambda x: (PRIORITY_ORDER.get(x["priority"], 9), x["name"])):
        if a["name"] in seen:
            continue
        seen.add(a["name"])
        conf = ("Low: dependency capability, verify usage" if a.get("capability")
                else "Low: needs analyst" if a["priority"] == "Review"
                else "High: deterministic ruleset match")
        L.append(f"| {_mark(a)} | {a['target']} | {', '.join(a['controls']) or '-'} | {conf} |")
    if not vuln:
        L.append("| - | no quantum-vulnerable algorithms detected in static reach | - |: |")
    L.append("")
    if review:
        L.append(f"**{len(review)} algorithm(s) could not be classified** and are flagged **Low confidence "
                 f"needs analyst**: {', '.join(sorted({a['name'] for a in review}))}.")
        L.append("")
    L.append("### Limits of these findings")
    L.append("")
    L.append("- They are not sequenced into a migration plan against the NIST IR 8547 timeline, data lifetime or "
             "harvest-now-decrypt-later exposure.")
    L.append("- Low-confidence and Review findings have not been verified by an analyst.")
    L.append("- No owners are assigned, and the report is not signed.")
    L.append("")
    compliant_named = sorted({_mark(a) for a in resistant if a["priority"] == "None"})
    if compliant_named:
        L.append(f"### Already compliant ({profile} profile)")
        L.append("")
        L.append(", ".join(compliant_named) + ".")
        L.append("")
    if cap:
        L.append("† **Dependency-inferred (capability).** Provided by a library in the dependency graph: evidence "
                 "the code *can* use these algorithms, not proof it does. Sources: "
                 + "; ".join(sorted({f"{a['name']} ⟵ {a['evidence'].replace('dependency: ', '')}" for a in cap}))
                 + ".")
        L.append("")
    return L


def build_report(bom, self_serve=False, brand="FEDLIN", signed=False, attestation_name=None, attention=None,
                 signer=None):
    """(Markdown report, summary). The Markdown is built from a copy of the CBOM whose every string is inert
    (md_text), so no CBOM string can change its structure; the summary is built from the CBOM as is, so machine
    outputs (summary.json, the MCP server) keep the values unaltered."""
    kw = dict(self_serve=self_serve, brand=brand, signed=signed, attestation_name=attestation_name,
              attention=attention, signer=signer)
    md, _ = _build_report(_inert(bom), **kw)
    _, summary = _build_report(bom, **kw)
    return md, summary


def _build_report(bom, self_serve=False, brand="FEDLIN", signed=False, attestation_name=None, attention=None,
                  signer=None):
    mp = meta_props(bom)
    sysname = bom.get("metadata", {}).get("component", {}).get("name", "system")
    ts = bom.get("metadata", {}).get("timestamp", "")
    ocounts, hndl = other_assets(bom)
    secrets = secret_hygiene_items(bom)

    s = score_summary(bom, regime=mp.get("fedlin:regime"))
    resistant, compliant, transitional, vuln, review, scored, score = (
        s["resistant"], s["compliant"], s["transitional"], s["vuln"], s["review"], s["scored"], s["score"])
    algos = resistant + vuln + review
    pk = lambda xs: [a for a in xs if a["lane"] in PUBLIC_KEY_LANES]  # noqa: E731
    profile = s["profile"] or "civilian"
    profile_label = {"civilian": "NIST FIPS 203/204/205 + IR 8547 (civilian profile)",
                     "nss": "NSA CNSA 2.0 (nss profile)"}.get(profile, f"{profile} profile")
    cap = [a for a in algos if a.get("capability")]
    gnote = observed_note(s)
    incomplete = s["kex_unobserved"]
    if incomplete and score is not None:
        # An unobserved key exchange is not evidence of a classical one: the score is marked partial.
        gnote = (f"incomplete: key exchange was not observed on {len(incomplete)} of {s['interfaces']} TLS "
                 f"endpoint(s), so this score covers only what was observed; {gnote}")
    tp = transport_posture(mp)
    cposture = cert_posture(bom)
    hw = hardware_components(bom)

    regime = mp.get("fedlin:regime") or (algos[0]["regime"] if algos and algos[0]["regime"] else None)

    L = []
    if self_serve:
        L.append(f"# PQC Readiness: Automated Self-Serve Scan: {sysname}")
        L.append("")
        L.append("> **WARNING: THIS IS AN AUTOMATED SCAN, NOT AN ASSESSMENT.** It runs a deterministic ruleset over "
                 "what static/source tooling can see. It does **not** replace an assessment: it carries no "
                 "engineered migration sequencing, no NSS-vs-commercial path judgment, no analyst verification, "
                 "no owner assignments, and no live runtime/endpoint capture. Treat every finding as indicative, "
                 "subject to the confidence band shown.")
        L.append("")
        L.append("> **Out of static reach:** source scanning cannot see runtime TLS/SSH negotiation, edge/CDN "
                 "termination, HSM/key-store material, or config-driven cipher selection. Cryptography that lives "
                 "only at runtime will be under-counted here: a full assessment captures it.")
        L.append("")
    else:
        L.append(f"# PQC Readiness Report: {sysname}")
        L.append("")
    L.append(f"*Generated by fedlin-pqc-toolkit report stage from a CycloneDX 1.6 CBOM. "
             f"CBOM timestamp: {ts or 'n/a'}.*")
    L.append("")
    L.append(f"> **Scope:** {scope_statement(mp)}.  ")
    L.append(f"> **Not a compliance determination.** {DISCLAIMER}")
    L.append("")
    if incomplete:
        L.append(f"> **Incomplete: key exchange not observed on {len(incomplete)} of {s['interfaces']} TLS "
                 "endpoint(s).** The score is partial. Either the key exchange could not be "
                 "read (a group the scan does not know, or one the enumeration contradicted: listed below if so), "
                 "or the scan host could not offer it: a FIPS-mode OpenSSL cannot offer post-quantum key "
                 "exchange, so run `./setup.sh` to build the probe image, then scan again.")
        L.append("")
    conflicts = [(c.get("name", "TLS session"), p.get("value")) for c in bom.get("components", [])
                 for p in c.get("properties", []) or [] if p.get("name") == "fedlin:kexConflict"]
    if conflicts:
        L.append(f"> **Key exchange not recorded on {len(conflicts)} endpoint(s) because the scan's observations "
                 "contradict each other** (for example a load balancer with backends configured differently):")
        L += [f"> - {name}: {note}" for name, note in conflicts]
        L.append("")

    # ---- bottom line up front (full report only; self-serve leads with its own disclaimer) ----
    if not self_serve:
        expired = cposture["buckets"]["expired"]
        soon = cposture["buckets"]["d30"] + cposture["buckets"]["d90"]
        bits = [f"a readiness score of **{score if score is not None else 'N/A'}"
                f"{'/100' if score is not None else ''}**"
                f"{' (incomplete)' if incomplete and score is not None else ''}"
                " (toolkit measure, not a compliance determination)"]
        if score is not None and s["interfaces"]:
            bits.append(f"post-quantum key exchange on {len(s['kex_pq'])} of {s['interfaces']} TLS endpoint(s)")
        pk_total = _w(pk(compliant)) + _w(pk(transitional)) + _w(pk(vuln))
        if pk_total:
            bits.append(f"{_w(pk(vuln))} of {pk_total} public-key usages are quantum-vulnerable")
        if pk(transitional):
            bits.append(f"{_w(pk(transitional))} quantum-resistant but below the {profile} profile target")
        if hndl:
            bits.append(f"{len(hndl)} harvest-now-decrypt-later exposure(s) demand priority")
        if expired:
            bits.append(f"**{expired} certificate(s) already expired**")
        if soon:
            bits.append(f"{soon} certificate(s) expire within 90 days")
        L.append("## Bottom line")
        L.append("")
        L.append(f"**{sysname}** has " + "; ".join(bits) + ".")
        L.append("")
        if score is None:
            lead = ("No algorithm assets were assessed in this capture: the score is not applicable. "
                    "Extend the scan (runtime/endpoint/source) before drawing a readiness conclusion.")
        elif score >= 70:
            lead = ("Most public-key usages this scan scored are quantum-resistant: the work is hardening and "
                    "monitoring.")
        else:
            lead = ("Quantum-vulnerable public-key cryptography is the dominant exposure"
                    + ("; the roadmap below sequences the migration." if _roadmap is not None else "."))
        L.append(lead + " This CBOM is machine-readable inventory evidence for the mandates below"
                 + ("; the prioritized roadmap below sequences the work. " if _roadmap is not None else ". ") +
                 ("Certificate-renewal exposure and transport crypto-agility are called out separately: "
                  "they are the recurring discipline (PCI DSS 4.0 §12.3.3 / the CA/Browser-Forum cert-lifetime "
                  "step-down) that a one-time fix does not close." if cposture["count"] else ""))
        L.append("")

    # ---- executive scorecard ----
    L.append("## Executive scorecard")
    L.append("")
    L.append(f"**Readiness score: {score if score is not None else 'N/A'}"
             f"{'/100' if score is not None else ''}.** {gnote[:1].upper() + gnote[1:]}.")
    L.append("")
    L.append("| Measure | Value |")
    L.append("|---|---|")
    L.append(f"| System | {sysname} |")
    if mp.get("fedlin:report_id"):
        L.append(f"| Report ID | {mp['fedlin:report_id']} |")
    if mp.get("fedlin:report_version"):
        L.append(f"| Report version | {mp['fedlin:report_version']} |")
    if mp.get("fedlin:reassessment_date"):
        L.append(f"| Re-assessment due | {mp['fedlin:reassessment_date']} |")
    if mp.get("fedlin:ocp_version") and mp.get("fedlin:ocp_version") != "unknown":
        L.append(f"| Platform version | OpenShift {mp['fedlin:ocp_version']} |")
    elif mp.get("fedlin:kube_version"):
        L.append(f"| Platform version | Kubernetes {mp['fedlin:kube_version']} |")
    L.append(f"| FIPS mode | {mp.get('fedlin:fips', 'not checked')} |")
    if mp.get("fedlin:kex_probe"):
        L.append(f"| Kex probe | {mp['fedlin:kex_probe']} |")
    L.append(f"| Verdict profile | {profile_label} |")
    L.append(f"| Public-key usages scored | {scored} ({_w(pk(compliant))} compliant / {_w(pk(vuln))} quantum-vulnerable"
             + (f"; {_w(pk(transitional))} transitional, not scored" if pk(transitional) else "") + ") |")
    for lane in ("symmetric", "hash", "kdf", "protocol"):
        d = s["lanes"].get(lane)
        if d:
            parts = [f"{d[k]} {k}" for k in ("compliant", "transitional", "vulnerable", "broken", "review") if d[k]]
            L.append(f"| {lane.title()} usages (not scored) | {', '.join(parts)} |")
    if review:
        L.append(f"| Awaiting analyst review | {len(review)} |")
    for at, n in sorted(ocounts.items()):
        L.append(f"| {at.replace('-', ' ').title()} assets | {n} |")
    if mp.get("fedlin:tls_secret_count"):
        L.append(f"| TLS secrets (in scope) | {mp['fedlin:tls_secret_count']} |")
    if mp.get("fedlin:sealed_secret_count"):
        L.append(f"| Sealed secrets (RSA-wrapped) | {mp['fedlin:sealed_secret_count']} |")
    if regime:
        L.append(f"| Compliance dialect | {regime} (crosswalked from NIST 800-53) |")
    if secrets:
        L.append(f"| Secret-hygiene detections | {len(secrets)}: **incidental, not PQC** (see below) |")
    if cap:
        L.append(f"| Dependency-inferred (†) | {len(cap)}: capability from the SBOM, usage not confirmed |")
    L.append("")
    L.append(f"*Score = compliant quantum-resistant public-key usages ÷ (compliant + quantum-vulnerable "
             f"public-key usages), against the {profile_label}. A usage is one reference from an asset: a "
             "certificate's key or signature, a TLS session's key exchange, an offered SSH algorithm. "
             "Symmetric, hash, KDF and protocol-version usages are listed above and do not move the score; "
             "classically broken items lead Wave 0 in every lane. Quantum-resistant usages below the profile "
             "target and items awaiting analyst review are excluded from the denominator. Secret-hygiene "
             "detections are excluded from the crypto-asset inventory entirely. This is the toolkit's own readiness "
             "score, not a PKI Consortium PQCMM level.*")
    L.append("")
    # scope disclosure: naming coverage boundaries prevents "inventory complete" from implying completeness
    scope_covered = mp.get("fedlin:scope_covered") or mp.get("fedlin:capture", "")
    scope_not = mp.get("fedlin:scope_not_covered", "")
    if scope_covered or scope_not:
        parts = []
        if scope_covered:
            parts.append(f"**Covered (partial: only what this scan was pointed at):** {scope_covered}.")
        if scope_not:
            parts.append(f"**Not in scope: expand assessment to reach:** {scope_not}.")
        L.append("  ".join(parts))
        L.append("")

    # ---- transport & crypto-agility posture (the PCI 12.3.3 / questionnaire cipher-inventory view) ----
    if tp:
        L.append("## Transport & crypto-agility posture")
        L.append("")
        L.append("The negotiated transport configuration: the cipher inventory a vendor security "
                 "questionnaire or **PCI DSS 4.0 §12.3.3** (documented, annually-reviewed inventory of "
                 "cipher suites and protocols) asks you to enumerate.")
        L.append("")
        L.append("| Measure | Value |")
        L.append("|---|---|")
        if "min_tls" in tp:
            flag = ": **below TLS 1.2; remediate**" if tp.get("min_tls_weak") else ""
            L.append(f"| Minimum TLS version | {tp['min_tls']}{flag} |")
        if "cipher_count" in tp:
            L.append(f"| Enumerated cipher suites | {tp['cipher_count']} |")
        if tp.get("etcd_encryption"):
            L.append(f"| etcd encryption at rest | {tp['etcd_encryption']} |")
        if tp.get("hsm"):
            L.append(f"| HSM / PKCS#11 indicators | {tp['hsm']} |")
        L.append("")
        agility = []
        if tp.get("cbc_ciphers"):
            agility.append(f"**{len(tp['cbc_ciphers'])} CBC-mode** cipher suite(s) (prefer AEAD/GCM)")
        if tp.get("aes128_ciphers"):
            agility.append(f"**{len(tp['aes128_ciphers'])} AES-128** suite(s) (CNSA 2.0 prefers AES-256)")
        if tp.get("sha1_ciphers"):
            agility.append(f"**{len(tp['sha1_ciphers'])} SHA-1 MAC** suite(s)")
        if agility and not self_serve:
            L.append("Crypto-agility flags in the negotiated suite set: " + "; ".join(agility) + ".")
            L.append("")

    # ---- classical fallback (second handshake offering only classical key exchange) ----
    fb = classical_fallback(bom)
    if fb:
        L.append("## Classical fallback")
        L.append("")
        L.append("Each TLS endpoint whose certificate was captured was contacted a second time by a client "
                 "offering only classical key-exchange groups (X25519, NIST curves, X448, finite-field), with "
                 "TLS 1.2 permitted through the client's default cipher list. **Accepted**: the server chose "
                 "classical parameters, so a harvest-now, decrypt-later recording remains possible for any client "
                 "that does not offer ML-KEM. **Rejected**: the server refused with a handshake-failure or "
                 "insufficient-security alert. **Inconclusive**: the handshake failed for another reason, or a "
                 "FIPS-mode scan client (which cannot offer X25519 or X448) was refused. **Untested**: no "
                 "connection on the second attempt. Rows marked *reduced FIPS offer* did not offer X25519 or X448. "
                 "These results do not change the score.")
        L.append("")
        L.append("| Endpoint | Classical-only client | Negotiated |")
        L.append("|---|---|---|")
        for server, o, got in fb:
            L.append(f"| {server} | {o} | {got or '-'} |")
        L.append("")

    # ---- server configuration (enumeration) ----
    conf = server_configuration(bom)
    if conf:
        L.append("## Server configuration (enumerated)")
        L.append("")
        L.append("Each endpoint was also tested for what it accepts, one handshake at a time: TLS 1.0 to 1.3 (SSLv3 "
                 "is not tested), the cipher suites of each version (TLS 1.3 suites individually; for TLS 1.0 to 1.2 "
                 "the client offers all suites and removes each one the server picks until it refuses), the "
                 "key-exchange groups in the probe list (hybrid and pure ML-KEM, X25519, X448, NIST curves, FFDHE), "
                 "and one certificate per signature-scheme family (RSA, ECDSA, EdDSA, ML-DSA). Accepted versions, "
                 "suites and groups are judged by the same ruleset and listed here and as exposures; they do not "
                 "change the score. Certificates the endpoint serves, including additional ones found here, are "
                 "certificates in use and are scored.")
        L.append("")
        L.append("| Endpoint | Protocol versions accepted | ML-KEM groups accepted | Broken items accepted | "
                 "Quantum-vulnerable items accepted |")
        L.append("|---|---|---|---|---|")
        for r in conf:
            if r["status"] != "complete":
                L.append(f"| {r['server']} | not enumerated{': ' + r['note'] if r['note'] else ''} | - | - | - |")
                continue
            na = f" (not tested: {', '.join(r['unanswered'])})" if r["unanswered"] else ""
            L.append(f"| {r['server']} | {', '.join(r['versions']) or 'none'}{na} | {', '.join(r['mlkem']) or 'none'} | "
                     f"{len(r['broken'])} | {len(r['vulnerable'])} |")
        L.append("")
        for r in conf:
            if r["broken"]:
                L.append(f"- **{r['server']}** accepts, and should stop accepting: " + "; ".join(
                    x.replace("accepts ", "") for x in r["broken"]) + ".")
        for r in conf:
            if r["static_rsa"]:
                L.append(f"- **{r['server']}** accepts {len(r['static_rsa'])} static-RSA cipher suite(s), which have no "
                         f"forward secrecy: {', '.join(r['static_rsa'][:8])}{' ...' if len(r['static_rsa']) > 8 else ''}.")
        refused = sorted({g for r in conf for g in r["refused_mlkem"]})
        if refused and profile == "nss":
            L.append(f"- Under CNSA 2.0 the key-establishment target is ML-KEM-1024. Groups refused by at least one "
                     f"endpoint: {', '.join(refused)}.")
        L.append("- Not tested: suites the enumeration client (OpenSSL 3.5) does not implement (3DES, RC4, export). "
                 "A version or group listed as not tested got no answer, or could not be tested with this client; "
                 "it is never counted as refused.")
        inc = [f"{r['server']} ({r['incomplete']})" for r in conf if r["incomplete"]]
        if inc:
            L.append(f"- Suite lists are partial (the server stopped answering before refusing): {', '.join(inc)}.")
        trunc = [r["server"] for r in conf if r["truncated"]]
        if trunc:
            L.append(f"- Suite enumeration stopped at its limit on: {', '.join(trunc)} (more suites may be accepted).")
        L.append("")

    # ---- top exposures ----
    L.append("## Top exposures")
    L.append("")
    top = sorted(vuln, key=lambda a: PRIORITY_ORDER.get(a["priority"], 9))
    accepted_broken = sorted({(x.replace("accepts ", ""), r["server"]) for r in conf for x in r["broken"]})
    if accepted_broken:
        L.append("**Accepted by the server and broken or disallowed today:**")
        L.append("")
        by_item = {}
        for item, server in accepted_broken:
            by_item.setdefault(item, []).append(server)
        for item, servers in sorted(by_item.items()):
            L.append(f"- **{item}** (Critical): accepted by {', '.join(servers)}.")
        L.append("")
    if hndl:
        L.append("**Harvest-now-decrypt-later (HNDL):**")
        L.append("")
        for name, note, pr in hndl:
            L.append(f"- **{name}** ({pr}): {note}.")
        L.append("")
    if top:
        L.append("**Highest-priority quantum-vulnerable algorithms:**")
        L.append("")
        seen = set()
        for a in top[:6]:
            if a["name"] in seen:
                continue
            seen.add(a["name"])
            L.append(f"- **{a['name']}**: {a['priority']}. Target: {a['target']}.")
        L.append("")
    if not top and not hndl and not accepted_broken:
        L.append("No quantum-vulnerable assets detected among the algorithms assessed.")
        L.append("")

    has_roadmap = _roadmap is not None and not self_serve
    if has_roadmap:
        L += _roadmap.render(algos=algos, resistant=resistant, cap=cap, regime=regime, profile=profile,
                             mark=_mark)
    else:
        L += _findings_table(vuln=vuln, review=review, resistant=resistant, cap=cap, profile=profile)

    # ---- attention order from business context (scripts/context.py; verdicts unchanged) ----
    if attention:
        import context as _context
        L.extend(_context.markdown(attention).splitlines())

    # ---- certificate posture & renewal exposure (the 47-day cert-cliff view) ----
    if cposture["count"]:
        b = cposture["buckets"]
        L.append("## Certificate posture & renewal exposure")
        L.append("")
        n_public = sum(1 for r in cposture["rows"] if not r.get("skip_cab"))
        any_internal = any(r.get("skip_cab") for r in cposture["rows"])
        if n_public and any_internal:
            cab_note = (" For publicly-trusted certificates, the CA/Browser-Forum maximum-lifetime step-down "
                        "(398 → 47 days by 2029) creates continuous renewal pressure; internally-issued "
                        "certificates are governed by internal PKI policy, not CA/B Forum limits.")
        elif n_public:
            cab_note = (" The **CA/Browser-Forum maximum-lifetime step-down** (398 → 47 days by 2029) turns "
                        "certificate rotation into continuous, automation-dependent work rather than an annual task.")
        else:
            cab_note = (" All certificates in scope are internally issued; CA/Browser-Forum lifetime limits "
                        "do not apply: renewal schedule is governed by internal PKI policy.")
        L.append(f"{cposture['count']} X.509 certificate(s) in scope. Renewal exposure is measured against the "
                 f"CBOM capture time.{cab_note}")
        L.append("")
        L.append("| Window (from capture) | Certificates |")
        L.append("|---|---|")
        L.append(f"| Already expired | {b['expired']} |")
        L.append(f"| Expiring ≤ 30 days | {b['d30']} |")
        L.append(f"| Expiring 31 to 90 days | {b['d90']} |")
        L.append(f"| Expiring 91 to 365 days | {b['d365']} |")
        L.append(f"| Beyond 365 days | {b['beyond']} |")
        L.append("")
        # soonest-expiring certs (deterministic order); flag those whose lifetime already exceeds a coming cap
        dated = [r for r in cposture["rows"] if r["days_left"] is not None]
        if dated and not self_serve:
            soonest = sorted(dated, key=lambda r: (r["days_left"], r["name"]))[:8]
            L.append("**Soonest-expiring certificates:**")
            L.append("")
            L.append("| Certificate | Days left | Lifetime (days) | Renewal note |")
            L.append("|---|---|---|---|")
            for r in soonest:
                if r["days_left"] < 0:
                    note = f"**expired {-r['days_left']} days ago**: replace now"
                elif r.get("skip_cab"):
                    note = "internal PKI: CA/B Forum lifetime limits do not apply"
                elif r.get("exceeds_caps"):
                    note = "lifetime exceeds current " + r["exceeds_caps"][0].split("(")[0].strip().replace("CA/B Forum ", "")
                elif r.get("exceeds_caps_future"):
                    eff_d, eff_cap, _ = r["exceeds_caps_future"][0]
                    eff = datetime.date.fromisoformat(eff_d).strftime("%B %Y")
                    note = f"compliant now; reconfiguration required before {eff} ({eff_cap}-day cap)"
                else:
                    note = "compliant through 2029 caps"
                span = r["span_days"] if r["span_days"] is not None else "-"
                L.append(f"| {r['name']} | {r['days_left']} | {span} | {note} |")
            L.append("")
        over_current = [r for r in cposture["rows"] if r.get("exceeds_caps")]
        over_future = [r for r in cposture["rows"] if r.get("exceeds_caps_future") and not r.get("exceeds_caps")]
        if over_current:
            L.append(f"*{len(over_current)} certificate(s) exceed a CA/Browser-Forum cap already in effect and "
                     "must be replaced with shorter-lived certificates.*")
            L.append("")
        if over_future:
            eff_d, eff_cap, _ = over_future[0]["exceeds_caps_future"][0]
            eff = datetime.date.fromisoformat(eff_d).strftime("%B %Y")
            L.append(f"*{len(over_future)} certificate(s) are compliant today but will require reconfiguration "
                     f"before the {eff_cap}-day CA/Browser-Forum cap takes effect in {eff}. "
                     "This is the crypto-agility planning case: renewal automation must be in place before then.*")
            L.append("")

    # ---- hardware posture (OS, TPM, HSM, network appliances) ----
    if hw and not self_serve:
        L.append("## Hardware posture")
        L.append("")
        ACTION_ORDER = {"replace": 0, "procure": 1, "upgrade": 2, "firmware-update": 3, "configure": 4}
        CAPABLE_LABEL = {"true": "Yes", "partial": "Partial: firmware update",
                         "false": "No", "unknown": "Unverified"}
        ACTION_LABEL = {"replace": "Replace", "procure": "Procure", "upgrade": "OS upgrade",
                        "firmware-update": "Firmware update", "configure": "Configure"}
        gates = [h for h in hw if h["pqc_gate"]]
        if gates:
            L.append("**Migration gates: these block progress on other migration work:**")
            L.append("")
            for h in gates:
                act = ACTION_LABEL.get(h["action"], h["action"].replace("-", " ").title())
                L.append(f"- **{h['name']}** ({act}): {h['action_detail']}")
            L.append("")
        tls12 = [h for h in hw if h.get("tls13") == "false"]
        if tls12:
            L.append(f"**TLS 1.3 prerequisite: not yet enabled on {len(tls12)} system(s):**")
            L.append("")
            L.append("PQC key exchange requires TLS 1.3. Software PQC updates have no effect until TLS 1.3 is active:")
            L.append("")
            for h in tls12:
                L.append(f"- **{h['name']}**")
            L.append("")
        L.append("| Component | PQC capable | Action |")
        L.append("|---|---|---|")
        for h in sorted(hw, key=lambda x: (ACTION_ORDER.get(x["action"], 9), x["name"])):
            capable = CAPABLE_LABEL.get(h["pqc_capable"], h["pqc_capable"] or "-")
            action = ACTION_LABEL.get(h["action"], h["action"].replace("-", " ").title() if h["action"] else "-")
            L.append(f"| {h['name']} | {capable} | {action} |")
        L.append("")

    # ---- incidental: secret hygiene (NOT PQC) ----
    if secrets:
        L.append("## Incidental: secret hygiene (NOT a PQC finding)")
        L.append("")
        L.append("> The scanner's secret-detection layer (gitleaks) flagged **candidate** committed credentials. "
                 "These are **not quantum-vulnerable cryptography** and do **not** affect the PQC readiness score: "
                 "reported here as a courtesy. **Verify before acting:** secret scanners false-positive, and some "
                 "tokens (e.g. read-only content-delivery tokens) may be intentionally public. No secret values are "
                 "read or stored: locations only.")
        L.append("")
        L.append("| Detection | Type | Location(s) |")
        L.append("|---|---|---|")
        for it in sorted(secrets, key=lambda x: x["name"]):
            loc = ", ".join(f"`{md_code(p)}`" for p in it["locations"]) or "-"
            L.append(f"| {it['name']} | {it['type']} | {loc} |")
        L.append("")
        L.append("*Recommended: verify each, rotate any live credential, remove from tracked files, and scrub git "
                 "history. Consider `--exclude` for docs/examples/backup paths on re-scan.*")
        L.append("")

    # ---- how each record was observed (CycloneDX component evidence; facts, not verdicts) ----
    ev_counts = _ev.summarize(bom, skip=is_secret_hygiene)
    if ev_counts:
        L.append("## How each record was observed")
        L.append("")
        lead = ("Every cryptographic record in this inventory" if not {"other tool", "not stated"} & set(ev_counts)
                else "Each record written by this toolkit")
        L.append(lead + " states how it was found, as CycloneDX component evidence (a technique and a fixed "
                 "confidence that ranks how directly it was observed, with the endpoint where it applies). A record "
                 "seen by several methods counts once, under the strongest. Records another tool produced keep that "
                 "tool's evidence (\"other tool\"); records nobody described are \"not stated\"; a key algorithm the "
                 "scan could not parse has a location but no identity (\"name not parsed\"). These values do not "
                 "change verdicts or the score.")
        L.append("")
        L.append("| How observed | CycloneDX technique | Confidence | Records |")
        L.append("|---|---|---|---|")
        for src in sorted(ev_counts, key=lambda k: -(_ev.SOURCES.get(k, ("", -1))[1])):
            tech, conf, meaning = _ev.SOURCES.get(src, ("-", None, src))
            L.append(f"| {meaning[0].upper() + meaning[1:]} | {tech} | "
                     f"{conf if conf is not None else '-'} | {ev_counts[src]} |")
        L.append("")

    # ---- CBOM inventory appendix (the machine-readable inventory, human-legible) ----
    if not self_serve:
        L.append("## Appendix A: CBOM inventory")
        L.append("")
        L.append("The algorithm assets underlying the score, for auditor traceability. The "
                 "authoritative artifact is the attached CycloneDX 1.6 CBOM (ECMA-424); this table is its "
                 "human-legible projection.")
        L.append("")
        L.append("| Asset | Type | Quantum status | Priority | Migration target |")
        L.append("|---|---|---|---|---|")
        seen = set()
        for a in sorted(algos, key=lambda x: (PRIORITY_ORDER.get(x["priority"], 9), x["name"])):
            if a["name"] in seen:
                continue
            seen.add(a["name"])
            # same words as the policy result (policy._status), so the report and the result never disagree
            status = ("broken" if a["priority"] == "Critical"
                      else "vulnerable" if a["vulnerable"] == "True"
                      else ("compliant" if (a["target"] or "").startswith("None") else "transitional")
                      if a["vulnerable"] == "False" else "review")
            L.append(f"| {_mark(a)} | algorithm | {status} | {a['priority']} | {a['target']} |")
        for at, n in sorted(ocounts.items()):
            L.append(f"| ({n}) | {at.replace('-', ' ')} | - | - | inventory only |")
        L.append("")

    # ---- FIPS 140-3 validation (CMVP) ----
    cmvp_snap, _ = _cmvp.load_snapshot()
    cmvp_found = _cmvp.match(bom, cmvp_snap)
    L.extend(_cmvp.report_lines(cmvp_found, cmvp_snap))

    # ---- methodology, scope & limitations ----
    L.append("## Methodology, scope & limitations")
    L.append("")
    cap_mode = mp.get("fedlin:mode") or mp.get("fedlin:capture") or "runtime + source capture"
    L.append(f"- **Capture:** {cap_mode}. FIPS posture at capture: {mp.get('fedlin:fips', 'not checked')}.")
    if mp.get("fedlin:not_captured"):
        L.append(f"- **Reached but not captured:** {mp['fedlin:not_captured']}.")
    if "endpoint-scan" in (cap_mode or ""):
        L.append("- **Endpoint scan scope: certificate algorithms + TLS handshake kex:** the scan reads "
                 "X.509 certificate public-key and signature algorithms, and additionally probes the TLS 1.3 "
                 "session key-exchange group negotiated during the handshake (e.g., X25519MLKEM768). Kex groups "
                 "appear in the CBOM as protocol assets and are scored independently from the certificate "
                 "algorithms: an organization running ML-KEM hybrid key exchange in production receives credit "
                 "for that posture even when the certificate itself still uses classical algorithms. "
                 "Note: OpenSSL in FIPS mode will not offer X25519MLKEM768; on such hosts the toolkit uses "
                 "its probe image (images/kex-probe, or FEDLIN_KEX_PROBE_IMAGE). Without one it tries a "
                 "reduced FIPS offer and records anything it could not observe as unknown.")
    L.append("- **Deterministic classification:** a versioned ruleset normalizes each algorithm "
             f"identifier and assigns its verdict under the {profile_label}, citing a primary source for each "
             "rule. No AI, no network at classification time, no re-classification at report time. "
             "The CBOM is the single source of truth.")
    L.append("- **Secret values:** endpoint and cluster capture read public certificate metadata, object names and "
             "counts, and effective configuration; secret values are not printed or stored. `--repo` and "
             "`--theia-dir` read the files you name, which can include key files. Secret-hygiene detections "
             "report locations, never values.")
    if review:
        L.append(f"- **Analyst review outstanding:** {len(review)} asset(s) the ruleset did not recognize are "
                 "flagged for analyst sign-off before delivery: verdicts are not automated for these.")
    if not self_serve and cap:
        L.append(f"- **Dependency-inferred capability (†):** {len(cap)} asset(s) are evidence a library *can* use "
                 "an algorithm, not proof it does; usage is analyst-confirmed.")
    L.append("- **Not an authorization:** this is cryptographic-inventory and migration-planning evidence toward "
             "NIST 800-53 / RMF and the mandates below. It is not an ATO, a FedRAMP authorization, or a claim of "
             "\"FISMA compliant\" status.")
    L.append("")

    # ---- mandate alignment ----
    L.append("## Mandate alignment")
    L.append("")
    L.append(("This automated scan is a **starting** cryptographic inventory toward the requirements of:"
              if self_serve else
              "This report is cryptographic-inventory evidence toward:"))
    L.append("")
    L.append("- **EO 14412: \"Securing the Nation Against Advanced Cryptographic Attacks\"** (June 2026) and "
             "**OMB M-26-15**: PQC for key establishment by **2030** and digital signatures by **2031** for "
             "High Value Assets / high-impact systems (high-impact as defined by NSM-10).")
    L.append("- **OMB M-26-15: \"Execution of the Migration to Post-Quantum Cryptography\"** (June 2026): "
             "a five-phase federal roadmap to 2035; **Phase 1 (2026 to 2027) covers inventory** of HVAs and "
             "high-impact systems. Agency migration plans were first due October 22, 2026, and the memo treats the "
             "plan as a living document. This CBOM is inventory evidence for Phase 1 over the scope it declares "
             "(coverage: " + _coverage(bom) + ")"
             + (", and the roadmap supports the plan's sequencing" if has_roadmap else "")
             + ", in a machine-readable, standards-based form (CycloneDX / ECMA-424).")
    L.append("- **NIST IR 8547 (final, October 2026)**: the algorithm-level transition timeline: every "
             "quantum-vulnerable signature and key-establishment scheme is deprecated after 2030 and "
             "disallowed after 2035"
             + (", which the roadmap is sequenced against." if has_roadmap else ", which the migration should follow."))
    L.append("- **CNSA 2.0**: the National Security Systems algorithm suite (ML-KEM-1024 / FIPS 203, "
             "ML-DSA-87 / FIPS 204, LMS/XMSS / SP 800-208 for firmware and code signing, AES-256, SHA-384/512)"
             + (", cited in every target above." if profile == "nss" else
                "; the targets above follow the civilian profile (FIPS 203/204/205), run with "
                "`--profile nss` for CNSA 2.0 targets."))
    L.append("")
    L.append("*Scope: this supports NIST 800-53 / RMF evidence and the M-26-15 Phase 1 inventory obligation. "
             "It is not an ATO, a FedRAMP authorization, or a claim of \"FISMA compliant\" status.*")
    L.append("")

    # ---- attestation & integrity (only when the toolkit actually signed the deliverable) ----
    # The signer is named by the key that signs (signer = {"publicKeyId", "fedlin"}), never assumed: "FEDLIN"
    # appears only when that key is FEDLIN's published one (1.5.0).
    if signed and signer and signer.get("publicKeyId"):
        att = attestation_name or "the attached attestation file"
        kid = str(signer["publicKeyId"])
        L.append("## Attestation & integrity")
        L.append("")
        L.append("This report and its CycloneDX 1.6 CBOM are covered by a **detached SLH-DSA (FIPS 205) "
                 "attestation**: `" + att + "`: binding the SHA-256 of each artifact and signed with a "
                 "quantum-resistant hash-based signature by the key with ID `" + kid + "`. A recipient can prove "
                 "that neither the report nor the CBOM was altered after signing, and that this key signed them.")
        L.append("")
        if signer.get("fedlin"):
            L.append("This is **FEDLIN's published signing key**. FEDLIN publishes its key ID and public key in "
                     "SECURITY.md of https://github.com/fedlinllc/fedlin-pqc-toolkit: compare it with the key ID "
                     "the verifier prints.")
        else:
            L.append("This is **not FEDLIN's published signing key**: the signature shows only that whoever holds "
                     "this key signed these files. FEDLIN has not signed or reviewed them.")
        L.append("")
        L.append("Verify: `python3 sign.py verify " + att + "` re-hashes the artifacts, checks the signature and "
                 "prints the signing key's ID (exit 0 = intact and signed by FEDLIN's published key).")
        L.append("")
        L.append("*SLH-DSA here provides commercial document-integrity signing of the deliverable: it is FIPS 205, "
                 "quantum-resistant, and distinct from the CNSA 2.0/NSS signing targets (ML-DSA-87, LMS/XMSS) named "
                 "for the assessed estate above.*")
        L.append("")

    summary = {
        "system": sysname,
        "cbom_timestamp": ts,
        "readiness_score": score,
        "grade": None,                    # letter grades retired in 1.5.0; the key stays (STABILITY.md)
        "incomplete": bool(incomplete) and score is not None,
        "kex_unobserved": len(incomplete),
        "tls_endpoints": s["interfaces"],
        "tls_endpoints_pq_kex": len(s["kex_pq"]),
        "scope": {"mode": mp.get("fedlin:mode"), "capture": mp.get("fedlin:capture"),
                  "endpoints_supplied": int(mp["fedlin:endpoints_supplied"])
                  if str(mp.get("fedlin:endpoints_supplied", "")).isdigit() else None,
                  "coverage": "partial", "statement": scope_statement(mp)},
        "disclaimer": DISCLAIMER,
        "profile": profile,
        "public_key_usages_scored": scored,
        "lanes": s["lanes"],
        "algorithms_classified": len(algos),
        "quantum_resistant": len(resistant),
        "quantum_vulnerable": len(vuln),
        "awaiting_review": len(review),
        "other_assets": ocounts,
        "hndl_exposures": len(hndl),
        "configuration": {"endpoints_enumerated": sum(1 for r in server_configuration(bom) if r["status"] == "complete"),
                          "endpoints_accepting_broken": sum(1 for r in server_configuration(bom) if r["broken"]),
                          "broken_items_accepted": sorted({x.replace("accepts ", "") for r in server_configuration(bom)
                                                           for x in r["broken"]})},
        "classical_fallback": {o: sum(1 for _, x, _ in fb if x == o) for o in dict.fromkeys(x for _, x, _ in fb)},
        "evidence": _ev.summarize(bom, skip=is_secret_hygiene),
        "attention": None if not attention else {
            "horizon": attention["horizon"],
            "urgent": sum(1 for r in attention["endpoints"] if r["urgent"] == "yes"),
            "notAssessed": sum(1 for r in attention["endpoints"] if r["urgent"] == "not assessed"),
            "endpoints": len(attention["endpoints"]), "noContext": len(attention["noContext"]),
            "notRanked": len(attention["notRanked"]), "unusedSystems": attention["unusedSystems"],
            "missingMigrationTime": attention["missingMigrationTime"],
            "missingDataLifetime": attention["missingDataLifetime"]},
        "cmvp": _cmvp.summary(cmvp_found, cmvp_snap),
        "secret_hygiene_detections": len(secrets),
        "regime": regime,
        "certificates": cposture["count"],
        "certs_expiring_90d": cposture["buckets"]["expired"] + cposture["buckets"]["d30"] + cposture["buckets"]["d90"],
        "certs_over_lifetime_cap": sum(1 for r in cposture["rows"] if r["exceeds_caps"]),
        "min_tls": tp.get("min_tls"),
        "cipher_suites": tp.get("cipher_count"),
        "self_serve": self_serve,
        "brand": brand,
    }
    md = "\n".join(L)
    if brand and brand != "FEDLIN":
        if _whitelabel is None:
            raise RuntimeError("white-label output (--brand) is part of the FEDLIN engagement kit")
        md = _whitelabel.apply(md, brand)
    return md, summary


_SAFE_SCHEMES = ("http", "https", "mailto")


def _safe_url(u):
    """True for a relative URL or an http(s)/mailto one; javascript:, data: and the rest are dropped."""
    u = re.sub(r"[\x00-\x20\x7f]", "", html.unescape(u or ""))
    m = re.match(r"([A-Za-z][A-Za-z0-9+.-]*):", u)
    return not m or m.group(1).lower() in _SAFE_SCHEMES


def md_to_html(md, title="PQC Readiness Report"):
    """Convert the report markdown to a self-contained HTML document for Drive upload.

    Safe for any input (GHSA-gmv4-8882-x388): raw HTML in the Markdown is not passed through (it is shown as text),
    link and image targets other than http(s), mailto and relative ones are removed, and the fallback without
    Python-Markdown escapes everything."""
    try:
        import markdown as mdlib
    except ImportError:
        mdlib = None
    if mdlib is None:
        # Fallback: the Markdown as escaped text in a <pre> (better than broken tables)
        body = f"<pre>{html.escape(md)}</pre>"
    else:
        conv = mdlib.Markdown(extensions=["tables", "nl2br"])
        conv.preprocessors.deregister("html_block")
        conv.inlinePatterns.deregister("html")

        class _DropUnsafeUrls(mdlib.treeprocessors.Treeprocessor):
            def run(self, root):
                amp = getattr(mdlib.util, "AMP_SUBSTITUTE", "")
                for el in root.iter():
                    for attr in ("href", "src"):
                        v = el.get(attr)
                        if v is not None and not _safe_url(v.replace(amp, "&") if amp else v):
                            del el.attrib[attr]

        conv.treeprocessors.register(_DropUnsafeUrls(conv), "fedlin_drop_unsafe_urls", -1)  # after unescape
        body = conv.convert(md)
    title = html.escape(_CONTROL.sub("", title).replace("\n", " ").replace("\r", " "))
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{title}</title>
<style>
  body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; color: #222; line-height: 1.5; }}
  h1 {{ font-size: 1.6em; }} h2 {{ font-size: 1.3em; border-bottom: 1px solid #ddd; padding-bottom: 4px; }}
  h3 {{ font-size: 1.1em; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
  th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; vertical-align: top; }}
  th {{ background: #f4f4f4; font-weight: bold; }}
  code {{ background: #f6f6f6; padding: 1px 4px; border-radius: 3px; font-size: 0.9em; }}
  blockquote {{ border-left: 3px solid #ccc; margin: 1em 0; padding: 0.5em 1em; color: #555; }}
  em {{ font-style: italic; }}
</style></head><body>
{body}
</body></html>"""


def _load_view(cbom_path, policy_path="", profile=None):
    """CBOM with verdicts for reporting: a digest-verified policy result, else a fresh evaluation.
    A legacy CBOM that carries verdicts inline is used as is."""
    import policy as policymod
    bom = load(cbom_path)
    sibling = cbom_path.rsplit(".", 1)[0] + ".policy.json"
    if not policy_path and os.path.exists(sibling):
        policy_path = sibling
    if policy_path:
        with open(policy_path) as f:
            result = json.load(f)
        c = policymod.check(result, cbom_path)
        if not c["bound"]:
            raise policymod.DigestMismatch(f"{cbom_path} does not match the digest recorded in {policy_path}")
        if c["ok"]:
            return policymod.apply(load(cbom_path), result, cbom_path)
        # Never report verdicts that cannot be re-checked: evaluate now under the recorded profile.
        why = ("its verdicts do not match a re-evaluation (" + "; ".join(c["mismatches"][:5]) + ")" if c["ruleset"]
               else f"it was written by ruleset {((result.get('policy') or {}).get('version'))!r}, not this toolkit's")
        prof = (result.get("policy") or {}).get("profile") or profile
        sys.stderr.write(f"[warn] {policy_path} not used: {why}; evaluated now instead.\n")
        view, _ = policymod.load_view(cbom_path, profile=prof if prof in policymod.cnsa.PROFILES else None)
        return view
    if policymod.has_verdicts(bom) and not profile:
        sys.stderr.write("[warn] legacy CBOM with inline verdicts; re-run the pipeline for a facts-only CBOM "
                         "and a policy result.\n")
        return bom
    view, r = policymod.load_view(cbom_path, profile=profile)
    sys.stderr.write(f"[ok] no policy result found; evaluated now under {r['policy']['policyId']} "
                     f"{r['policy']['version']}\n")
    return view


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cbom", required=True, help="input validated CycloneDX 1.6 CBOM")
    ap.add_argument("--out", default="", help="output Markdown report (default: <cbom>.report.md)")
    ap.add_argument("--html", default="", help="also write an HTML version (for Drive upload with clean tables)")
    ap.add_argument("--json", default="", help="optional machine-readable summary JSON")
    ap.add_argument("--context", default="",
                    help="business context (fedlin.pqc-context 1.0): attention order and urgency in the report")
    ap.add_argument("--self-serve", action="store_true",
                    help="automated-scan variant of the report (automated-scan disclaimer, confidence bands)")
    ap.add_argument("--brand", default="FEDLIN", help="name the report is issued under")
    ap.add_argument("--attestation-name", default="",
                    help="name of an EXISTING, VALID detached SLH-DSA attestation file: adds the integrity "
                         "section only if that attestation exists and its signature verifies (deliverable is "
                         "signed with sign.py). Claim discipline: no signed section without a real signature.")
    ap.add_argument("--node", default="node", help="node binary for attestation verification")
    ap.add_argument("--policy", default="",
                    help="policy result for this CBOM (default: <cbom>.policy.json if present; its SHA-256 "
                         "digest must match the CBOM). Without one, the CBOM is evaluated now.")
    ap.add_argument("--profile", choices=["civilian", "nss"], default=None,
                    help="profile used when evaluating a CBOM that has no policy result (default civilian)")
    kit = {"self_serve": _roadmap is not None, "brand": _whitelabel is not None}
    for action in ap._actions:
        if action.dest in kit and not kit[action.dest]:
            action.help = argparse.SUPPRESS
    args = ap.parse_args()
    if args.self_serve and not kit["self_serve"]:
        ap.error("--self-serve is part of the FEDLIN engagement kit and is not in this build")
    if args.brand != "FEDLIN" and not kit["brand"]:
        ap.error("--brand is part of the FEDLIN engagement kit and is not in this build")

    out = args.out or (args.cbom.rsplit(".", 1)[0] + ".report.md")

    # Only claim a signature if the named attestation actually exists and its signature verifies:
    # never assert "signed by FEDLIN" from the flag alone (claim discipline).
    signed, signer = False, None
    if args.attestation_name:
        att_path = os.path.join(os.path.dirname(os.path.abspath(out)), args.attestation_name)
        if not os.path.exists(att_path):
            sys.stderr.write(f"[warn] --attestation-name {args.attestation_name}: not found next to the report; "
                             "emitting an UNSIGNED report (no signature claim).\n")
        else:
            try:
                import sign as signmod
                _ok, detail = signmod.verify_attestation(att_path, node_bin=args.node)
                if _ok:
                    signed = True
                    signer = {"publicKeyId": detail.get("publicKeyId"), "fedlin": bool(detail.get("fedlin_key"))}
                else:
                    sys.stderr.write(f"[warn] {args.attestation_name}: signature did not verify or the artifacts "
                                     "changed; emitting an UNSIGNED report (no signature claim).\n")
            except Exception as e:
                sys.stderr.write(f"[warn] could not verify {args.attestation_name} ({e}); emitting an UNSIGNED "
                                 "report.\n")

    try:
        bom = _load_view(args.cbom, args.policy, args.profile)
    except Exception as e:  # includes policy.DigestMismatch
        sys.stderr.write(f"[error] {e}. The CBOM changed after its policy result was written; re-run the "
                         "policy stage (python3 policy.py evaluate --cbom ...) or the pipeline.\n")
        sys.exit(1)
    attention = None
    if args.context:
        import context as _context
        # rank under the profile the report's verdicts came from (the policy result's), not a default
        pol = args.policy or (args.cbom.rsplit(".", 1)[0] + ".policy.json")
        prof = args.profile
        if not prof and os.path.exists(pol):
            try:
                with open(pol) as f:
                    prof = (json.load(f).get("policy") or {}).get("profile")
            except (OSError, ValueError):
                prof = None
        try:
            attention = _context.rank(args.context, args.cbom, prof or "civilian")
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as e:
            sys.stderr.write(f"[error] --context: {e}\n")
            sys.exit(2)
    md, summary = build_report(bom, self_serve=args.self_serve, brand=args.brand,
                               signed=signed, signer=signer,
                               attestation_name=args.attestation_name or None, attention=attention)
    with open(out, "w") as f:
        f.write(md + "\n")
    print(f"[ok] report: {out}: score {summary['readiness_score']}{' (incomplete)' if summary['incomplete'] else ''}, "
          f"algorithms (all lanes): {summary['quantum_vulnerable']} vulnerable / {summary['quantum_resistant']} resistant")
    if args.html:
        html_out = args.html if args.html != "auto" else out.replace(".md", ".html")
        sysname = summary.get("system", "system")
        with open(html_out, "w") as f:
            f.write(md_to_html(md, title=f"PQC Readiness Report: {sysname}"))
        print(f"[ok] html: {html_out}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"[ok] summary: {args.json}")


if __name__ == "__main__":
    main()
