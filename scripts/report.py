#!/usr/bin/env python3
"""FEDLIN PQC Toolkit — report stage (v0.1).

Turns a validated CycloneDX 1.6 CBOM (as produced by tier2_pipeline.py) into the
two artifacts a buyer actually reads and funds:

  1. an EXECUTIVE SCORECARD — a PQC-readiness score, exposure counts, top risks,
     and mandate alignment (EO 14412 / OMB M-26-15 / NIST IR 8547 / CNSA 2.0);
  2. a PRIORITIZED MIGRATION ROADMAP — vulnerable assets sequenced into waves
     anchored to the NIST IR 8547 timeline (RSA/ECC deprecated 2030, disallowed
     2035), each with its migration target (civilian or nss profile) and 800-53 controls.

Deterministic (Mode C): reads only what the overlay already stamped onto the CBOM
(`cnsa2:*` verdicts, `crosswalk:<regime>` refs). No AI, no network at classification time, no re-eval.
The CBOM is the single source of truth — this stage never re-classifies.

Usage:  python3 report.py --cbom out/cbom.json --out out/cbom.report.md [--json out/cbom.summary.json]
"""
import argparse
import datetime
import json
import os
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

PRIORITY_ORDER = {"Critical": 0, "High": 1, "Low": 2, "None": 3, "Review": 4}


def load(path):
    with open(path) as f:
        return json.load(f)


def props(comp):
    return {p["name"]: p["value"] for p in comp.get("properties", [])}


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
    for a in algos:
        d = lanes.setdefault(a["lane"], {"compliant": 0, "transitional": 0, "vulnerable": 0,
                                         "broken": 0, "review": 0})
        if a["priority"] == "Critical":
            d["broken"] += a["weight"]
        elif a in vuln:
            d["vulnerable"] += a["weight"]
        elif a in compliant:
            d["compliant"] += a["weight"]
        elif a in transitional:
            d["transitional"] += a["weight"]
        else:
            d["review"] += a["weight"]
    profiles = sorted({a["profile"] for a in algos if a.get("profile")})
    return {"score": score, "resistant": resistant, "compliant": compliant, "transitional": transitional,
            "vuln": vuln, "review": review, "scored": scored, "lanes": lanes,
            "profile": profiles[0] if len(profiles) == 1 else ("mixed" if profiles else None)}


def _mark(a):
    """Append a capability marker to a dependency-inferred asset name."""
    return f"{a['name']} †" if a.get("capability") else a["name"]


SECRET_HYGIENE_TYPES = {"token", "password", "credential"}


def is_secret_hygiene(comp):
    """A gitleaks-style secret detection (API key / token) surfaced by cbomkit-theia.

    These are leaked credentials, NOT quantum-vulnerable cryptography — they carry no
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
    """gitleaks secret detections, with locations (never values) — for the incidental section."""
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
    """Non-algorithm crypto assets (certs, protocols, key material) — for the inventory line.
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
# under that cap — i.e. it forces shorter-lived certs and thus renewal automation.
CERT_LIFETIME_CAPS = [
    ("2026-03-15", 200, "CA/B Forum 200-day cap (first step-down)"),
    ("2027-03-15", 100, "CA/B Forum 100-day cap"),
    ("2029-03-15", 47, "CA/B Forum 47-day cap (target)"),
]


def cert_posture(bom):
    """Renewal-exposure view of the certificate estate, deterministic against the CBOM timestamp.

    Surfaces the CA/Browser-Forum 47-day cert-cliff (certs expiring soon, and the shrinking
    max-lifetime caps that make manual renewal untenable) — the crypto-agility discipline PCI
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


def grade(score):
    if score is None:
        return "N/A", "no classified algorithm assets found"
    if score >= 90:
        return "A — PQC-ready", "the estate is largely on quantum-resistant cryptography"
    if score >= 70:
        return "B — On track", "a minority of assets remain quantum-vulnerable"
    if score >= 40:
        return "C — Partial", "roughly half the classified crypto is quantum-vulnerable"
    if score >= 15:
        return "D — At risk", "most classified crypto is quantum-vulnerable"
    return "F — Not started", "the estate is almost entirely quantum-vulnerable"


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
        conf = ("Low — dependency capability, verify usage" if a.get("capability")
                else "Low — needs analyst" if a["priority"] == "Review"
                else "High — deterministic ruleset match")
        L.append(f"| {_mark(a)} | {a['target']} | {', '.join(a['controls']) or '—'} | {conf} |")
    if not vuln:
        L.append("| — | no quantum-vulnerable algorithms detected in static reach | — | — |")
    L.append("")
    if review:
        L.append(f"**{len(review)} algorithm(s) could not be classified** and are flagged **Low confidence "
                 f"— needs analyst**: {', '.join(sorted({a['name'] for a in review}))}.")
        L.append("")
    L.append("### Not included in this report")
    L.append("")
    L.append("- Migration sequencing against the NIST IR 8547 timeline, by data lifetime and "
             "harvest-now-decrypt-later exposure.")
    L.append("- Analyst verification of Low-confidence and Review findings.")
    L.append("- Owner assignments, a signed attestation, and baseline-to-baseline deltas.")
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


def build_report(bom, self_serve=False, brand="FEDLIN", signed=False, attestation_name=None):
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
    g, gnote = grade(score)
    tp = transport_posture(mp)
    cposture = cert_posture(bom)
    hw = hardware_components(bom)

    regime = mp.get("fedlin:regime") or (algos[0]["regime"] if algos and algos[0]["regime"] else None)

    L = []
    if self_serve:
        L.append(f"# PQC Readiness — Automated Self-Serve Scan — {sysname}")
        L.append("")
        L.append("> **WARNING — THIS IS AN AUTOMATED SCAN, NOT AN ASSESSMENT.** It runs a deterministic ruleset over "
                 "what static/source tooling can see. It does **not** replace an assessment: it carries no "
                 "engineered migration sequencing, no NSS-vs-commercial path judgment, no analyst verification, "
                 "no owner assignments, and no live runtime/endpoint capture. Treat every finding as indicative, "
                 "subject to the confidence band shown.")
        L.append("")
        L.append("> **Out of static reach:** source scanning cannot see runtime TLS/SSH negotiation, edge/CDN "
                 "termination, HSM/key-store material, or config-driven cipher selection. Cryptography that lives "
                 "only at runtime will be under-counted here — a full assessment captures it.")
        L.append("")
    else:
        L.append(f"# PQC Readiness Report — {sysname}")
        L.append("")
    L.append(f"*Generated by fedlin-pqc-toolkit report stage from a schema-validated CycloneDX 1.6 CBOM. "
             f"CBOM timestamp: {ts or 'n/a'}.*")
    L.append("")

    # ---- bottom line up front (full report only; self-serve leads with its own disclaimer) ----
    if not self_serve:
        soon = cposture["buckets"]["expired"] + cposture["buckets"]["d30"] + cposture["buckets"]["d90"]
        bits = [f"**{score if score is not None else 'N/A'}"
                f"{'/100' if score is not None else ''} ({g})** on post-quantum readiness"]
        pk_total = _w(pk(compliant)) + _w(pk(transitional)) + _w(pk(vuln))
        if pk_total:
            bits.append(f"{_w(pk(vuln))} of {pk_total} public-key usages are quantum-vulnerable")
        if pk(transitional):
            bits.append(f"{_w(pk(transitional))} quantum-resistant but below the {profile} profile target")
        if hndl:
            bits.append(f"{len(hndl)} harvest-now-decrypt-later exposure(s) demand priority")
        if soon:
            bits.append(f"{soon} certificate(s) expire within 90 days")
        L.append("## Bottom line")
        L.append("")
        L.append(f"**{sysname}** scores " + "; ".join(bits) + ".")
        L.append("")
        if score is None:
            lead = ("No algorithm assets were classified in this capture — the score is not applicable. "
                    "Extend the scan (runtime/endpoint/source) before drawing a readiness conclusion.")
        elif score >= 70:
            lead = "The estate is largely quantum-ready — the work is hardening and monitoring."
        else:
            lead = ("Quantum-vulnerable public-key cryptography is the dominant exposure; the roadmap below "
                    "sequences the migration.")
        L.append(lead + " This CBOM is the machine-readable inventory the mandates below require; the "
                 "prioritized roadmap is the plan. " +
                 ("Certificate-renewal exposure and transport crypto-agility are called out separately — "
                  "they are the recurring discipline (PCI DSS 4.0 §12.3.3 / the CA/Browser-Forum cert-lifetime "
                  "step-down) that a one-time fix does not close." if cposture["count"] else ""))
        L.append("")

    # ---- executive scorecard ----
    L.append("## Executive scorecard")
    L.append("")
    L.append(f"**PQC-readiness score: {score if score is not None else 'N/A'}"
             f"{'/100' if score is not None else ''} — grade {g}.** {gnote.capitalize()}.")
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
        L.append(f"| Secret-hygiene detections | {len(secrets)} — **incidental, not PQC** (see below) |")
    if cap:
        L.append(f"| Dependency-inferred (†) | {len(cap)} — capability from the SBOM, usage not confirmed |")
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
    # scope disclosure — naming coverage boundaries prevents "inventory complete" from implying completeness
    scope_covered = mp.get("fedlin:scope_covered") or mp.get("fedlin:capture", "")
    scope_not = mp.get("fedlin:scope_not_covered", "")
    if scope_covered or scope_not:
        parts = []
        if scope_covered:
            parts.append(f"**Covered:** {scope_covered}.")
        if scope_not:
            parts.append(f"**Not in scope — expand assessment to reach:** {scope_not}.")
        L.append("  ".join(parts))
        L.append("")

    # ---- transport & crypto-agility posture (the PCI 12.3.3 / questionnaire cipher-inventory view) ----
    if tp:
        L.append("## Transport & crypto-agility posture")
        L.append("")
        L.append("The negotiated transport configuration — the cipher inventory a vendor security "
                 "questionnaire or **PCI DSS 4.0 §12.3.3** (documented, annually-reviewed inventory of "
                 "cipher suites and protocols) asks you to enumerate.")
        L.append("")
        L.append("| Measure | Value |")
        L.append("|---|---|")
        if "min_tls" in tp:
            flag = " — **below TLS 1.2; remediate**" if tp.get("min_tls_weak") else ""
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

    # ---- top exposures ----
    L.append("## Top exposures")
    L.append("")
    top = sorted(vuln, key=lambda a: PRIORITY_ORDER.get(a["priority"], 9))
    if hndl:
        L.append("**Harvest-now-decrypt-later (HNDL):**")
        L.append("")
        for name, note, pr in hndl:
            L.append(f"- **{name}** ({pr}) — {note}.")
        L.append("")
    if top:
        L.append("**Highest-priority quantum-vulnerable algorithms:**")
        L.append("")
        seen = set()
        for a in top[:6]:
            if a["name"] in seen:
                continue
            seen.add(a["name"])
            L.append(f"- **{a['name']}** — {a['priority']}. Target: {a['target']}.")
        L.append("")
    if not top and not hndl:
        L.append("No quantum-vulnerable assets detected among classified algorithms.")
        L.append("")

    has_roadmap = _roadmap is not None and not self_serve
    if has_roadmap:
        L += _roadmap.render(algos=algos, resistant=resistant, cap=cap, regime=regime, profile=profile,
                             mark=_mark)
    else:
        L += _findings_table(vuln=vuln, review=review, resistant=resistant, cap=cap, profile=profile)

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
                        "do not apply — renewal schedule is governed by internal PKI policy.")
        L.append(f"{cposture['count']} X.509 certificate(s) in scope. Renewal exposure is measured against the "
                 f"CBOM capture time.{cab_note}")
        L.append("")
        L.append("| Window (from capture) | Certificates |")
        L.append("|---|---|")
        L.append(f"| Already expired | {b['expired']} |")
        L.append(f"| Expiring ≤ 30 days | {b['d30']} |")
        L.append(f"| Expiring 31–90 days | {b['d90']} |")
        L.append(f"| Expiring 91–365 days | {b['d365']} |")
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
                if r.get("skip_cab"):
                    note = "internal PKI — CA/B Forum lifetime limits do not apply"
                elif r.get("exceeds_caps"):
                    note = "lifetime exceeds current " + r["exceeds_caps"][0].split("(")[0].strip().replace("CA/B Forum ", "")
                elif r.get("exceeds_caps_future"):
                    eff_d, eff_cap, _ = r["exceeds_caps_future"][0]
                    eff = datetime.date.fromisoformat(eff_d).strftime("%B %Y")
                    note = f"compliant now; reconfiguration required before {eff} ({eff_cap}-day cap)"
                else:
                    note = "compliant through 2029 caps"
                span = r["span_days"] if r["span_days"] is not None else "—"
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
                     "This is the crypto-agility planning case — renewal automation must be in place before then.*")
            L.append("")

    # ---- hardware posture (OS, TPM, HSM, network appliances) ----
    if hw and not self_serve:
        L.append("## Hardware posture")
        L.append("")
        ACTION_ORDER = {"replace": 0, "procure": 1, "upgrade": 2, "firmware-update": 3, "configure": 4}
        CAPABLE_LABEL = {"true": "Yes", "partial": "Partial — firmware update",
                         "false": "No", "unknown": "Unverified"}
        ACTION_LABEL = {"replace": "Replace", "procure": "Procure", "upgrade": "OS upgrade",
                        "firmware-update": "Firmware update", "configure": "Configure"}
        gates = [h for h in hw if h["pqc_gate"]]
        if gates:
            L.append("**Migration gates — these block progress on other migration work:**")
            L.append("")
            for h in gates:
                act = ACTION_LABEL.get(h["action"], h["action"].replace("-", " ").title())
                L.append(f"- **{h['name']}** ({act}) — {h['action_detail']}")
            L.append("")
        tls12 = [h for h in hw if h.get("tls13") == "false"]
        if tls12:
            L.append(f"**TLS 1.3 prerequisite — not yet enabled on {len(tls12)} system(s):**")
            L.append("")
            L.append("PQC key exchange requires TLS 1.3. Software PQC updates have no effect until TLS 1.3 is active:")
            L.append("")
            for h in tls12:
                L.append(f"- **{h['name']}**")
            L.append("")
        L.append("| Component | PQC capable | Action |")
        L.append("|---|---|---|")
        for h in sorted(hw, key=lambda x: (ACTION_ORDER.get(x["action"], 9), x["name"])):
            capable = CAPABLE_LABEL.get(h["pqc_capable"], h["pqc_capable"] or "—")
            action = ACTION_LABEL.get(h["action"], h["action"].replace("-", " ").title() if h["action"] else "—")
            L.append(f"| {h['name']} | {capable} | {action} |")
        L.append("")

    # ---- incidental: secret hygiene (NOT PQC) ----
    if secrets:
        L.append("## Incidental — secret hygiene (NOT a PQC finding)")
        L.append("")
        L.append("> The scanner's secret-detection layer (gitleaks) flagged **candidate** committed credentials. "
                 "These are **not quantum-vulnerable cryptography** and do **not** affect the PQC readiness score — "
                 "reported here as a courtesy. **Verify before acting:** secret scanners false-positive, and some "
                 "tokens (e.g. read-only content-delivery tokens) may be intentionally public. No secret values are "
                 "read or stored — locations only.")
        L.append("")
        L.append("| Detection | Type | Location(s) |")
        L.append("|---|---|---|")
        for it in sorted(secrets, key=lambda x: x["name"]):
            loc = ", ".join(f"`{p}`" for p in it["locations"]) or "—"
            L.append(f"| {it['name']} | {it['type']} | {loc} |")
        L.append("")
        L.append("*Recommended: verify each, rotate any live credential, remove from tracked files, and scrub git "
                 "history. Consider `--exclude` for docs/examples/backup paths on re-scan.*")
        L.append("")

    # ---- CBOM inventory appendix (the machine-readable inventory, human-legible) ----
    if not self_serve:
        L.append("## Appendix A — CBOM inventory")
        L.append("")
        L.append("The classified cryptographic assets underlying the score, for auditor traceability. The "
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
            status = ("vulnerable" if a["vulnerable"] == "True"
                      else "resistant" if a["vulnerable"] == "False" else "review")
            L.append(f"| {_mark(a)} | algorithm | {status} | {a['priority']} | {a['target']} |")
        for at, n in sorted(ocounts.items()):
            L.append(f"| ({n}) | {at.replace('-', ' ')} | — | — | inventory only |")
        L.append("")

    # ---- methodology, scope & limitations ----
    L.append("## Methodology, scope & limitations")
    L.append("")
    cap_mode = mp.get("fedlin:mode") or mp.get("fedlin:capture") or "runtime + source capture"
    L.append(f"- **Capture:** {cap_mode}. FIPS posture at capture: {mp.get('fedlin:fips', 'not checked')}.")
    if "endpoint-scan" in (cap_mode or ""):
        L.append("- **Endpoint scan scope — certificate algorithms + TLS handshake kex:** the scan reads "
                 "X.509 certificate public-key and signature algorithms, and additionally probes the TLS 1.3 "
                 "session key-exchange group negotiated during the handshake (e.g., X25519MLKEM768). Kex groups "
                 "appear in the CBOM as protocol assets and are scored independently from the certificate "
                 "algorithms — an organization running ML-KEM hybrid key exchange in production receives credit "
                 "for that posture even when the certificate itself still uses classical algorithms. "
                 "Note: OpenSSL in FIPS mode will not offer X25519MLKEM768; on such hosts the toolkit uses "
                 "its probe image (images/kex-probe, or FEDLIN_KEX_PROBE_IMAGE). Without one it tries a "
                 "reduced FIPS offer and records anything it could not observe as unknown.")
    L.append("- **Deterministic classification (Mode C):** a versioned ruleset normalizes each algorithm "
             f"identifier and assigns its verdict under the {profile_label}, citing a primary source for each "
             "rule. No AI, no network at classification time, no re-classification at report time. "
             "The CBOM is the single source of truth.")
    L.append("- **Reads no secrets, by construction:** the capture reads public certificate metadata, object names/counts, "
             "and effective configuration only. No private key or secret value is ever read — secret-hygiene "
             "detections report locations, never values.")
    if review:
        L.append(f"- **Analyst review outstanding:** {len(review)} asset(s) the ruleset did not recognize are "
                 "flagged for analyst sign-off before delivery — verdicts are not automated for these.")
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
              "This assessment produces the cryptographic inventory and migration plan called for by:"))
    L.append("")
    L.append("- **EO 14412 — \"Securing the Nation Against Advanced Cryptographic Attacks\"** (June 2026) and "
             "**NSM-10** — PQC for key establishment by **2030** and digital signatures by **2031** for "
             "High Value Assets / high-impact systems.")
    L.append("- **OMB M-26-15 — \"Execution of the Migration to Post-Quantum Cryptography\"** (June 2026, "
             "**supersedes M-23-02**) — a five-phase federal roadmap to 2035; **Phase 1 (2026–27) is inventory** "
             "of HVAs/high-impact systems, and civilian agencies submit migration plans by Oct 2026. This CBOM "
             + ("+ roadmap is the Phase 1 inventory and plan" if has_roadmap else "is the Phase 1 inventory") +
             ", in a machine-readable, standards-based (CycloneDX / ECMA-424) form"
             + (" — an automated static scan is a partial inventory until runtime capture is added." if self_serve else "."))
    L.append("- **NIST IR 8547 (final, October 2026)** — the algorithm-level transition timeline: every "
             "quantum-vulnerable signature and key-establishment scheme is deprecated after 2030 and "
             "disallowed after 2035"
             + (", which the roadmap is sequenced against." if has_roadmap else ", which the migration should follow."))
    L.append("- **CNSA 2.0** — the target algorithm suite (ML-KEM-1024 / FIPS 203, ML-DSA-87 / FIPS 204, "
             "SLH-DSA / FIPS 205, LMS/XMSS / SP 800-208) cited in every target above.")
    L.append("")
    L.append("*Scope: this supports NIST 800-53 / RMF evidence and the M-26-15 Phase 1 inventory obligation. "
             "It is not an ATO, a FedRAMP authorization, or a claim of \"FISMA compliant\" status.*")
    L.append("")

    # ---- attestation & integrity (only when the toolkit actually signed the deliverable) ----
    if signed:
        att = attestation_name or "the attached attestation file"
        L.append("## Attestation & integrity")
        L.append("")
        L.append("This report and its CycloneDX 1.6 CBOM are covered by a **detached SLH-DSA (FIPS 205) "
                 "attestation** — `" + att + "` — binding the SHA-256 of each artifact and signed with a "
                 "quantum-resistant hash-based signature. A recipient can prove that neither the report nor the "
                 "CBOM was altered after FEDLIN signed it, and that it was signed by FEDLIN's holder of the "
                 "published signing key.")
        L.append("")
        L.append("Verify with the toolkit: `python3 sign.py verify " + att + "` "
                 "(re-hashes the artifacts and checks the signature; exit 0 = intact).")
        L.append("")
        L.append("*SLH-DSA here provides commercial document-integrity signing of the deliverable — it is FIPS 205, "
                 "quantum-resistant, and distinct from the CNSA 2.0/NSS signing targets (ML-DSA-87, LMS/XMSS) named "
                 "for the assessed estate above.*")
        L.append("")

    summary = {
        "system": sysname,
        "cbom_timestamp": ts,
        "readiness_score": score,
        "grade": g,
        "profile": profile,
        "public_key_usages_scored": scored,
        "lanes": s["lanes"],
        "algorithms_classified": len(algos),
        "quantum_resistant": len(resistant),
        "quantum_vulnerable": len(vuln),
        "awaiting_review": len(review),
        "other_assets": ocounts,
        "hndl_exposures": len(hndl),
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


def md_to_html(md_text, title="PQC Readiness Report"):
    """Convert the report markdown to a self-contained HTML document for Drive upload."""
    try:
        import markdown as mdlib
        body = mdlib.markdown(md_text, extensions=["tables", "nl2br"])
    except ImportError:
        # Fallback: wrap raw markdown in a <pre> — better than broken tables
        body = f"<pre>{md_text}</pre>"
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
        view, _ = policymod.load_view(cbom_path, policy_path)  # raises DigestMismatch on a mismatch
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
    ap.add_argument("--self-serve", action="store_true",
                    help="gated automated-scan variant (disclaimer, confidence bands, roadmap withheld)")
    ap.add_argument("--brand", default="FEDLIN", help="white-label the deliverable under a reseller's name")
    ap.add_argument("--attestation-name", default="",
                    help="name of an EXISTING, VALID detached SLH-DSA attestation file — adds the integrity "
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

    # Only claim a signature if the named attestation actually exists and its signature verifies —
    # never assert "signed by FEDLIN" from the flag alone (claim discipline).
    signed = False
    if args.attestation_name:
        att_path = os.path.join(os.path.dirname(os.path.abspath(out)), args.attestation_name)
        if not os.path.exists(att_path):
            sys.stderr.write(f"[warn] --attestation-name {args.attestation_name}: not found next to the report; "
                             "emitting an UNSIGNED report (no signature claim).\n")
        else:
            try:
                import sign as signmod
                _ok, detail = signmod.verify_attestation(att_path, node_bin=args.node)
                if detail.get("signature_valid"):
                    signed = True
                else:
                    sys.stderr.write(f"[warn] {args.attestation_name}: signature did not verify; emitting an "
                                     "UNSIGNED report (no signature claim).\n")
            except Exception as e:
                sys.stderr.write(f"[warn] could not verify {args.attestation_name} ({e}); emitting an UNSIGNED "
                                 "report.\n")

    try:
        bom = _load_view(args.cbom, args.policy, args.profile)
    except Exception as e:  # includes policy.DigestMismatch
        sys.stderr.write(f"[error] {e}. The CBOM changed after its policy result was written; re-run the "
                         "policy stage (python3 policy.py evaluate --cbom ...) or the pipeline.\n")
        sys.exit(1)
    md, summary = build_report(bom, self_serve=args.self_serve, brand=args.brand,
                               signed=signed,
                               attestation_name=args.attestation_name or None)
    with open(out, "w") as f:
        f.write(md + "\n")
    print(f"[ok] report: {out} — score {summary['readiness_score']} ({summary['grade']}), "
          f"{summary['quantum_vulnerable']} vulnerable / {summary['quantum_resistant']} resistant")
    if args.html:
        html_out = args.html if args.html != "auto" else out.replace(".md", ".html")
        sysname = summary.get("system", "system")
        with open(html_out, "w") as f:
            f.write(md_to_html(md, title=f"PQC Readiness Report — {sysname}"))
        print(f"[ok] html: {html_out}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"[ok] summary: {args.json}")


if __name__ == "__main__":
    main()
