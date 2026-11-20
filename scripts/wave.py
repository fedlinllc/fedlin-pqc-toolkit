#!/usr/bin/env python3
"""Check a migration wave against a later scan: did each declared item reach its end state?

A wave file (schema fedlin.pqc-wave 1.0, schemas/wave-1.0.schema.json) lists what a migration wave
promises to change, per endpoint. This checks each item against a CBOM from a scan taken after the work,
and writes a result (fedlin.pqc-wave-result 1.0) bound to the files by SHA-256.

An item passes only on what this scan saw. A record counts only if this scan run observed it (property
fedlin:observedIn equal to the CBOM's serialNumber, written by toolkit 1.2.0 and later), so records merged in
from another CBOM never count. Each check also needs its own observation: what the server accepts needs a
complete, untruncated enumeration; the key exchange needs to have been seen; ML-KEM groups the server accepts
need the group probes; and a statement about every certificate the endpoint serves needs an answer (a
certificate or a refusal) from the certificate probe of every signature-scheme family. When that observation
is missing the item is "not observed", never passed. Verdicts come from evaluating the CBOM now with this
toolkit's ruleset, never from a stored policy result. The result is only as trustworthy as the CBOM; a
signed attestation over the CBOM and the result (engagement kit) is what binds them to the scan.

Checks:
  findings-resolved        no finding with one of the given priorities remains at the endpoint (only in the
                           given lanes, if any), under the wave's profile
  mlkem                    the recorded session negotiated an ML-KEM group that meets the profile (nss:
                           ML-KEM-1024), or with "accepts", the server accepts one
  refuses-classical-only   a client offering only classical key exchange was refused
  certificate-replaced     no certificate the endpoint serves has the baseline fingerprint, and (if given) one
                           it serves has the expected key and signature algorithms

Usage:
  python3 scripts/wave.py check --wave wave.json --cbom after/cbom.json [--baseline before/cbom.json]
                          [--out wave-result.json]
Exit codes: 0 every item passed and no regression; 1 not passed; 2 invalid input.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling modules, also under python -I
import cnsa20_ruleset as cnsa  # noqa: E402
import evidence as evmod  # noqa: E402
import policy  # noqa: E402

SCHEMA, SCHEMA_VERSION = "fedlin.pqc-wave", "1.1"
SCHEMA_VERSIONS = ("1.0", "1.1")   # 1.1 (1.7.0): baseline may record serialNumber and timestamp
RESULT, RESULT_VERSION = "fedlin.pqc-wave-result", "1.0"
CHECKS = ("findings-resolved", "mlkem", "refuses-classical-only", "certificate-replaced")
PRIORITIES = ("Critical", "High", "Low", "Review")
LANES = ("key-establishment", "signature", "public-key", "symmetric", "hash", "kdf", "protocol", "configuration")
FRESH = ("handshake", "probe")   # evidence sources that count as observing the endpoint
TOP_KEYS = {"schema", "schemaVersion", "wave", "profile", "baseline", "notes", "items"}
ITEM_KEYS = {"id", "endpoint", "check", "priorities", "lanes", "mode", "baselineFingerprint", "keyAlgorithm",
             "signatureAlgorithm"}
CHECK_KEYS = {"findings-resolved": {"priorities", "lanes"}, "mlkem": {"mode"}, "refuses-classical-only": set(),
              "certificate-replaced": {"baselineFingerprint", "keyAlgorithm", "signatureAlgorithm"}}
CERT_FAMILIES = ("RSA", "ECDSA", "EdDSA", "ML-DSA")   # the enumeration's per-family certificate probes
RANK = {"Critical": 3, "High": 2, "Low": 1, "Review": 0, "None": -1}
FP_RE = re.compile(r"([0-9a-fA-F]{2}:?){31}[0-9a-fA-F]{2}")


class WaveError(ValueError):
    pass


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _fp(v):
    return str(v or "").replace(":", "").strip().lower()


def endpoint_key(ep):
    """The endpoint as the CBOM records it: host, host:port, [IPv6] or [IPv6]:port (443 omitted), lower-case."""
    ep = re.sub(r"^[a-z][a-z0-9+.-]*://", "", str(ep).strip().lower()).split("/")[0]
    if ep.startswith("[") and "]" in ep:
        host, _, port = ep[1:].partition("]")
        host, port = f"[{host}]", port.lstrip(":")
    elif ep.count(":") == 1:
        host, port = ep.split(":")
    elif ep.count(":") > 1:                     # bare IPv6 address
        host, port = f"[{ep}]", ""
    else:
        host, port = ep, ""
    return host if port in ("", "443") else f"{host}:{port}"


def _props(c):
    return {p.get("name"): p.get("value") for p in c.get("properties", []) or [] if isinstance(p, dict)}


def load_wave(path):
    try:
        with open(path) as f:
            w = json.load(f)
    except (OSError, ValueError, RecursionError) as e:
        raise WaveError(f"{path}: {e}")
    if not isinstance(w, dict) or w.get("schema") != SCHEMA or w.get("schemaVersion") not in SCHEMA_VERSIONS:
        raise WaveError(f"{path}: not a {SCHEMA} {' or '.join(SCHEMA_VERSIONS)} file")
    extra = set(w) - TOP_KEYS
    if extra:
        raise WaveError(f"{path}: unknown key(s) {', '.join(sorted(extra))}")
    if w.get("profile", "civilian") not in cnsa.PROFILES:
        raise WaveError(f"{path}: unknown profile {w.get('profile')!r}")
    b = w.get("baseline")
    bkeys = {"file", "sha256"} | ({"serialNumber", "timestamp"} if w["schemaVersion"] == "1.1" else set())
    if b is not None and (not isinstance(b, dict) or set(b) - bkeys
                          or not re.fullmatch(r"[0-9a-fA-F]{64}", str(b.get("sha256", "0" * 64)))
                          or not all(isinstance(b.get(k, ""), str) for k in ("file", "serialNumber", "timestamp"))):
        raise WaveError(f"{path}: baseline must be an object with file and a SHA-256 sha256"
                        + (" (and optionally serialNumber and timestamp)" if w["schemaVersion"] == "1.1" else ""))
    items = w.get("items")
    if not isinstance(items, list) or not items:
        raise WaveError(f"{path}: items must be a non-empty list")
    seen = set()
    for i, it in enumerate(items):
        where = f"{path}: items[{i}]"
        if not isinstance(it, dict):
            raise WaveError(f"{where}: must be an object")
        extra = set(it) - ITEM_KEYS
        if extra:
            raise WaveError(f"{where}: unknown key(s) {', '.join(sorted(extra))}")
        if not isinstance(it.get("id"), str) or not it["id"] or it["id"] in seen:
            raise WaveError(f"{where}: id must be a unique non-empty string")
        seen.add(it["id"])
        if it.get("check") not in CHECKS:
            raise WaveError(f"{where}: check must be one of {', '.join(CHECKS)}")
        stray = set(it) - {"id", "endpoint", "check"} - CHECK_KEYS[it["check"]]
        if stray:
            raise WaveError(f"{where}: {', '.join(sorted(stray))} do(es) not apply to {it['check']}")
        if not isinstance(it.get("endpoint"), str) or not it["endpoint"].strip():
            raise WaveError(f"{where}: endpoint is required")
        for k in ("keyAlgorithm", "signatureAlgorithm"):
            if k in it and (not isinstance(it[k], str) or not it[k].strip()):
                raise WaveError(f"{where}: {k} must be a non-empty string")
        if it["check"] == "findings-resolved":
            pr = it.get("priorities")
            if not isinstance(pr, list) or not pr or any(p not in PRIORITIES for p in pr):
                raise WaveError(f"{where}: priorities must be a non-empty list of {', '.join(PRIORITIES)}")
            ln = it.get("lanes")
            if ln is not None and (not isinstance(ln, list) or not ln or any(x not in LANES for x in ln)):
                raise WaveError(f"{where}: lanes must be a non-empty list of {', '.join(LANES)}")
        if it["check"] == "mlkem" and it.get("mode", "negotiates") not in ("negotiates", "accepts"):
            raise WaveError(f"{where}: mode must be negotiates or accepts")
        if it["check"] == "certificate-replaced":
            if not isinstance(it.get("baselineFingerprint"), str) or not FP_RE.fullmatch(it["baselineFingerprint"]):
                raise WaveError(f"{where}: baselineFingerprint must be a SHA-256 fingerprint (hex, colons optional)")
    return w


class Scan:
    """What one CBOM's own scan run observed at each endpoint, with verdicts evaluated now."""

    def __init__(self, cbom_path, profile, baseline=False):
        self.baseline = baseline
        try:
            with open(cbom_path) as f:
                self.bom = json.load(f)
        except (OSError, ValueError, RecursionError) as e:
            raise WaveError(f"{cbom_path}: {e}")
        if not isinstance(self.bom, dict) or not isinstance(self.bom.get("components", []), list):
            raise WaveError(f"{cbom_path}: not a CycloneDX BOM")
        self.serial = self.bom.get("serialNumber")
        self.timestamp = (self.bom.get("metadata") or {}).get("timestamp")
        tools = ((self.bom.get("metadata") or {}).get("tools") or {})
        tools = tools.get("components", []) if isinstance(tools, dict) else tools
        self.toolkit = next((t.get("version") for t in tools or []
                             if isinstance(t, dict) and t.get("name") == "fedlin-pqc-toolkit"), None)
        result = policy.evaluate(cbom_path, profile=profile)
        self.findings = result["findings"]
        self.ruleset_digest = (result.get("policy") or {}).get("digest")
        comps = [c for c in self.bom.get("components", []) if isinstance(c, dict)]
        self.comps = comps
        self.names = {}
        for c in comps:
            if c.get("bom-ref"):
                self.names.setdefault(c["bom-ref"], c)
        self.deps = {}
        for d in self.bom.get("dependencies", []) or []:
            if isinstance(d, dict) and d.get("ref"):
                self.deps.setdefault(d["ref"], []).extend(d.get("dependsOn", []) or [])
        self.by_ref = {}
        for f in self.findings:
            self.by_ref.setdefault(f["bomRef"], []).append(f)

    def _ours(self, c):
        """Observed by this scan run: run marker and handshake/probe evidence written by the toolkit. A baseline
        from before the run marker (toolkit 1.1) counts on its evidence alone."""
        run = _props(c).get("fedlin:observedIn")
        if run is None and self.baseline:
            mine = True
        else:
            mine = bool(self.serial) and run == self.serial
        return mine and any(s in FRESH for s in evmod.sources_of(c))

    def interface(self, ep):
        for c in self.comps:
            if (c.get("cryptoProperties") or {}).get("assetType") == "protocol" and self._ours(c) and \
                    endpoint_key(str(_props(c).get("pkic:profile:endpointRole:server", ""))
                                 .replace("endpoint:", "", 1)) == ep:
                return c
        return None

    def certificates(self, ep):
        out = [c for c in self.comps if (c.get("cryptoProperties") or {}).get("assetType") == "certificate"
               and self._ours(c) and endpoint_key(_props(c).get("fedlin:host") or c.get("name") or "") == ep]
        primary = [c for c in out if "fedlin:certificateSelectedBy" not in _props(c)]
        return primary + [c for c in out if c not in primary]

    def records(self, ep):
        return [c for c in [self.interface(ep)] + self.certificates(ep) if c]

    def observed(self, ep):
        return bool(self.records(ep))

    def channels(self, ep):
        """What this scan could see at the endpoint: (lanes, info). A lane outside the set proves nothing.

        info: configuration (complete, untruncated enumeration), certificates (every per-family certificate
        probe answered with a certificate or a refusal), groups (accepted / refused / untested groups)."""
        iface, certs = self.interface(ep), self.certificates(ep)
        p = _props(iface) if iface else {}
        complete = p.get("fedlin:enumeration") == "complete"
        configuration = complete and not p.get("fedlin:enumerationTruncated") and \
            not p.get("fedlin:enumerationIncomplete")
        probes = dict(x.split(":", 1) for x in str(p.get("fedlin:certificateProbes", "")).split(",") if ":" in x)
        all_certs = bool(certs) and complete and all(probes.get(f) in ("certificate", "refused", "mismatch")
                                                     for f in CERT_FAMILIES)
        split = lambda k: [g for g in str(p.get(k, "")).split(",") if g and g != "none"]  # noqa: E731
        groups = {"accepted": split("fedlin:acceptedGroups"), "refused": split("fedlin:refusedGroups"),
                  "untested": split("fedlin:untestedGroups")} if complete else None
        seen = set()
        if iface:
            # an unreadable or contradicted key exchange (unparsed-kex-group, fedlin:kexConflict) is not observed
            if "pkic:profile:keyExchange" in p and not kex_unreadable(iface):
                seen.add("key-establishment")
            if "pkic:profile:encryption" in p:
                seen |= {"symmetric", "hash", "kdf"}
            if "pkic:profile:protocolVersion" in p:
                seen.add("protocol")
            if configuration:
                seen.add("configuration")
        if all_certs:
            seen |= {"signature", "public-key"}
        return seen, {"configuration": configuration, "certificates": all_certs, "groups": groups,
                      "primary": certs[0] if certs else None}

    def findings_at(self, ep, records=None):
        refs = []
        for c in (self.records(ep) if records is None else records):
            refs.append(c["bom-ref"])
            refs += self.deps.get(c["bom-ref"], [])
        seen, out = set(), []
        for r in refs:
            for f in self.by_ref.get(r, []):
                k = (f["bomRef"], f["name"], f["lane"], f["status"])
                if k not in seen:
                    seen.add(k)
                    out.append(f)
        return out

    def algorithm(self, ref):
        """(name, bits) of an algorithm record."""
        c = self.names.get(ref) if ref else None
        if not c:
            return None, None
        ps = ((c.get("cryptoProperties") or {}).get("algorithmProperties") or {}).get("parameterSetIdentifier")
        return c.get("name"), int(ps) if str(ps or "").isdigit() else None


def _bits(name):
    n = name.lower()
    m = re.search(r"rsa\D{0,3}(\d{4})", n) or re.search(r"(?:\bp-?|secp|prime)(\d{3})", n)
    return int(m.group(1)) if m else None


def _hash(name):
    m = re.search(r"sha-?(\d{3})", name.lower())
    return m.group(1) if m else None


def _composite(name):
    n = re.sub(r"[^a-z0-9]", "", name.lower())
    return "mldsa" in n and bool(re.search(r"rsa|ecdsa|ed25519|ed448|brainpool|p256|p384", n.replace("mldsa", "")))


def _variant(name):
    """Distinctions within one family the ruleset's canonical name does not carry."""
    n = re.sub(r"[^a-z0-9]", "", name.lower())
    return ("pss" in n, "shake" in n, n.startswith("hash") and "mldsa" in n)


_GENERIC = {"rsa", "ecdsa", "ec", "eddsa", "mldsa", "slhdsa", "dsa"}   # family names that leave the variant open


def classifiable(name, bits=None):
    return bool(name) and cnsa.classify(name, bits).get("canonical") is not None


def same_algorithm(wanted, actual, actual_bits=None):
    """Whether an algorithm the wave expects matches the one recorded: same algorithm and variant (PSS,
    SHAKE, pre-hash), and the same parameter set, key size or curve and hash wherever the wave names one.
    No substring matching. A key size named in the wave must match exactly."""
    if not actual:
        return False
    generic = re.sub(r"[^a-z0-9]", "", wanted.lower()) in _GENERIC
    if _composite(wanted) != _composite(actual) or (not generic and _variant(wanted) != _variant(actual)):
        return False
    w, a = cnsa.classify(wanted), cnsa.classify(actual, actual_bits)
    wc, ac = w.get("canonical"), a.get("canonical")
    if not wc or not ac:
        return False
    ec = {"ec", "ecdsa", "ecdh"}
    family = wc == ac or (wc in ec and ac in ec) or ac.startswith(wc + "-")
    if not family:
        return False
    if wc != ac and not (wc in ec and ac in ec) and re.search(r"\d", wc):  # e.g. ml-dsa-65 vs ml-dsa-87
        return False
    wb = _bits(wanted)
    if wb and (actual_bits or _bits(actual)) != wb:
        return False
    wh = _hash(wanted)
    if wh and _hash(actual) != wh:
        return False
    return True


def _mlkem_meets(group, profile):
    n = re.sub(r"[^a-z0-9]", "", str(group or "").lower())
    if "mlkem" not in n:
        return False
    return "1024" in n if profile == "nss" else True


UNPARSED_KEX = "unparsed-kex-group"  # tier2_pipeline.UNPARSED_GROUP


def kex_unreadable(iface):
    """True when the interface's key exchange is a placeholder or contradicted by the enumeration."""
    props = (iface or {}).get("properties", []) or []
    return any(isinstance(x, dict) and ((x.get("name") == "pkic:profile:keyExchange" and x.get("value") == UNPARSED_KEX)
                                        or x.get("name") == "fedlin:kexConflict") for x in props)


def _classical_group(g):
    return "mlkem" not in re.sub(r"[^a-z0-9]", "", g.lower())


def check_item(it, scan, profile):
    ep = endpoint_key(it["endpoint"])
    base = {"id": it["id"], "check": it["check"], "endpoint": ep}

    def not_observed(why):
        return dict(base, status="not-observed", detail=why + "; nothing is proven")

    if not scan.observed(ep):
        return not_observed("this scan did not observe the endpoint by a handshake")
    seen, info = scan.channels(ep)
    kind = it["check"]
    if kind == "findings-resolved":
        lanes = set(it["lanes"]) if it.get("lanes") else None
        blind = sorted((lanes or set(LANES)) - seen)
        pr = set(it["priorities"])
        left = [f for f in scan.findings_at(ep) if f["priority"] in pr and (lanes is None or f["lane"] in lanes)]
        if left:
            names = sorted({f"{f['name']} ({f['lane'] or 'unclassified'}, {f['status']})" for f in left})
            return dict(base, status="fail", detail=f"{len(names)} finding(s) remain", remaining=names)
        if blind:
            return not_observed("not observed in this scan for lane(s) " + ", ".join(blind))
        return dict(base, status="pass", detail="no finding of the given priorities remains")
    iface = scan.interface(ep)
    p = _props(iface) if iface else {}
    if kind == "mlkem":
        kex = [str(x.get("value")) for x in (iface or {}).get("properties", []) or []
               if isinstance(x, dict) and x.get("name") == "pkic:profile:keyExchange"]
        if kex_unreadable(iface) and it.get("mode", "negotiates") == "negotiates":
            return not_observed("the key exchange could not be read or contradicted the enumeration ("
                                + ", ".join(kex) + ")")
        if any(_mlkem_meets(v, profile) for v in kex):
            return dict(base, status="pass", detail="ML-KEM negotiated: " + ", ".join(kex))
        if it.get("mode", "negotiates") == "accepts":
            g = info["groups"]
            if g is None:
                return not_observed("the key-exchange groups the server accepts were not enumerated")
            ok = [x for x in g["accepted"] if _mlkem_meets(x, profile)]
            if ok:
                return dict(base, status="pass", detail="ML-KEM accepted: " + ",".join(ok))
            tried = [x for x in g["refused"] + g["untested"] if _mlkem_meets(x, profile)]
            if tried and all(x in g["refused"] for x in tried):
                return dict(base, status="fail", detail="every ML-KEM group meeting the profile was refused: "
                            + ",".join(tried))
            return not_observed("no ML-KEM group meeting the profile was both offered and answered")
        if "key-establishment" not in seen:
            return not_observed("the key exchange was not observed")
        return dict(base, status="fail", detail="negotiated " + (", ".join(kex) or "a non-ML-KEM group")
                    + (" (nss requires ML-KEM-1024)" if profile == "nss" and any("mlkem" in v.lower().replace("-", "") for v in kex)
                       else ""))
    if kind == "refuses-classical-only":
        o = p.get("fedlin:classicalOnlyOffer")
        # Enumeration can show classical key exchange accepted directly: a classical group offered alone, or any
        # TLS 1.2 or older session (those versions have no ML-KEM key exchange).
        g = info["groups"] or {}
        contra = [x for x in g.get("accepted", []) if _classical_group(x)]
        if p.get("fedlin:enumeration") == "complete":
            old = [v for v in str(p.get("fedlin:acceptedProtocolVersions", "")).split(",")
                   if v in ("TLSv1", "TLSv1.0", "TLSv1.1", "TLSv1.2", "SSLv3")]
            contra += [f"{v} accepted" for v in old]
            if p.get("fedlin:dhGroupBits"):
                contra.append(f"finite-field DHE ({p['fedlin:dhGroupBits']} bits)")
        if contra:
            return dict(base, status="fail", detail="enumeration shows classical key exchange accepted: "
                        + ", ".join(contra))
        if o == "rejected":
            return dict(base, status="pass", detail="classical-only client refused")
        if o == "accepted":
            return dict(base, status="fail", detail="classical-only client accepted: "
                        + (p.get("fedlin:classicalOnlyNegotiated") or "negotiated classical parameters"))
        return not_observed(f"classical-only probe {o or 'not run'}")
    if kind == "certificate-replaced":
        old = _fp(it["baselineFingerprint"])
        certs = scan.certificates(ep)
        fps = [_fp(_props(c).get("fedlin:sha256Fingerprint")) for c in certs]
        if old in fps:
            return dict(base, status="fail", detail="the baseline certificate is still served")
        if not info["certificates"] or not all(fps):
            return not_observed("not every signature-scheme family's certificate probe was answered")
        want_k, want_s = it.get("keyAlgorithm"), it.get("signatureAlgorithm")
        served, unknown = [], False
        for c in certs:
            cp = (c.get("cryptoProperties") or {}).get("certificateProperties") or {}
            kn, kb = scan.algorithm(cp.get("subjectPublicKeyRef"))
            sn, _ = scan.algorithm(cp.get("signatureAlgorithmRef"))
            served.append((kn, kb, sn))
            unknown |= bool((want_k and not classifiable(kn, kb)) or (want_s and not classifiable(sn)))
            if (not want_k or same_algorithm(want_k, kn, kb)) and (not want_s or same_algorithm(want_s, sn)):
                return dict(base, status="pass", detail=f"replaced (key {kn}{f' {kb}' if kb else ''}, signature {sn})")
        if unknown:
            return not_observed("a served certificate's algorithm could not be identified")
        return dict(base, status="fail", detail="replaced, but no served certificate has "
                    + " and ".join(x for x in (want_k and f"key {want_k}", want_s and f"signature {want_s}") if x)
                    + ": " + "; ".join(f"{k} {b or ''}/{s}".replace(" /", "/") for k, b, s in served))
    raise WaveError(kind)


def _slot(c):
    """Which certificate slot a record fills: the primary, or the signature family that selected it."""
    return _props(c).get("fedlin:certificateSelectedBy") or "primary"


def _config_kind(name):
    m = re.match(r"accepts ([a-z-]+(?: [a-z-]+)?)", str(name))
    return m.group(1) if m else ""


def regressions(wave, scan, before):
    """Critical or High findings at the wave's endpoints that are new or worse than in the baseline.

    Compared only where both scans could see; everything else is listed under notCompared, never counted as
    "no regression". A finding matched in the baseline (same algorithm, same lane; for what the server accepts,
    also the same kind of item) counts only if it is now of a higher priority (e.g. an RSA key cut from 2048
    to 1024 bits).
    - What the server accepts (configuration lane) is a set: any newly accepted kind of item counts.
    - Certificates: one the baseline already served (same fingerprint) is never new. A new certificate is
      compared with the baseline certificate in the same slot (primary, or the signature family that selected
      it), and counts unless that one was at least as bad; replacing a broken certificate with a
      quantum-vulnerable one is progress. A new certificate in a slot the baseline did not have counts in
      full. If the baseline did not probe every signature family, only primary certificates are compared, and
      that is listed under notCompared.
    - The negotiated session counts when new and not matched by a baseline finding of the same or worse
      priority in that lane; a same-rank change of group is not a regression."""
    out, skipped = [], []

    def key(f):
        base = (f.get("canonical") or f["name"], f["lane"])
        return base + ((_config_kind(f["name"]),) if f["lane"] == "configuration" else ())

    rank = lambda fs: max((RANK.get(h["priority"], -1) for h in fs), default=None)  # noqa: E731

    def worse(f, had):
        """f is new, or a matched baseline finding was of a lower priority."""
        same = [h for h in had if key(h) == key(f)]
        return not same or rank(same) < RANK[f["priority"]]

    def add(ep, f):
        r = {"endpoint": ep, "name": f["name"], "lane": f["lane"], "status": f["status"], "priority": f["priority"]}
        if r not in out:
            out.append(r)

    for ep in sorted({endpoint_key(i["endpoint"]) for i in wave["items"]}):
        if not scan.observed(ep) or not before.observed(ep):
            skipped.append({"endpoint": ep, "lanes": ["all"], "reason": "endpoint not observed in "
                            + ("this scan" if not scan.observed(ep) else "the baseline")})
            continue
        now_seen, now_info = scan.channels(ep)
        was_seen, was_info = before.channels(ep)
        lanes = now_seen & was_seen
        all_certs = now_info["certificates"] and was_info["certificates"]
        blind = sorted(set(LANES) - lanes - {"signature", "public-key"})
        if blind:
            skipped.append({"endpoint": ep, "lanes": blind, "reason": "not observed in both scans"})
        if not all_certs:
            skipped.append({"endpoint": ep, "lanes": ["signature", "public-key"],
                            "reason": "not every certificate family was probed in both scans; primary certificates "
                                      "only" if now_info["primary"] and was_info["primary"] else
                                      "certificates not observed in both scans"})
        # certificates: by fingerprint first, then slot by slot (across lanes: the ruleset files sha1WithRSA
        # under hash and ECDSA under signature)
        fp = lambda c: _fp(_props(c).get("fedlin:sha256Fingerprint"))  # noqa: E731
        was_certs = before.certificates(ep)
        was_fps = {fp(c) for c in was_certs if fp(c)}
        was_slots = {_slot(c): c for c in was_certs}
        cert_refs = set()
        for c in scan.certificates(ep):
            mine = scan.findings_at(ep, [c])
            cert_refs |= {f["bomRef"] for f in mine}
            if fp(c) and fp(c) in was_fps:
                continue                                     # the same certificate was already served
            slot = _slot(c)
            if not all_certs and slot != "primary":
                continue
            if slot in was_slots:
                had = before.findings_at(ep, [was_slots[slot]])
                had_rank = rank(had)
                for f in mine:
                    if f["priority"] in ("Critical", "High") and worse(f, had) and \
                            (had_rank is None or had_rank < RANK[f["priority"]] or
                             any(key(h) == key(f) for h in had)):
                        add(ep, f)
            elif all_certs:
                for f in mine:
                    if f["priority"] in ("Critical", "High"):
                        add(ep, f)
        had_all = before.findings_at(ep)
        for f in scan.findings_at(ep):
            if f["priority"] not in ("Critical", "High") or f["bomRef"] in cert_refs or f["lane"] not in lanes:
                continue
            if f["lane"] == "configuration":
                if worse(f, had_all):
                    add(ep, f)
                continue
            same_lane = [h for h in had_all if h["lane"] == f["lane"]]
            if not worse(f, same_lane):
                continue
            if any(key(h) == key(f) for h in same_lane) or rank(same_lane) is None or \
                    rank(same_lane) < RANK[f["priority"]]:
                add(ep, f)
    return out, skipped


def _instant(ts):
    """A CBOM timestamp as a comparable UTC instant (offsets and fractional seconds handled); the string if it does
    not parse, so two unparseable values still compare as before."""
    import datetime as _dt
    try:
        t = _dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return (0, (t if t.tzinfo else t.replace(tzinfo=_dt.timezone.utc)).timestamp())
    except ValueError:
        return (1, str(ts))


def check(wave_path, cbom_path, baseline_path=None):
    wave = load_wave(wave_path)
    profile = wave.get("profile", "civilian")
    scan = Scan(cbom_path, profile)
    before = Scan(baseline_path, profile, baseline=True) if baseline_path else None
    wb = wave.get("baseline") or {}
    want = str(wb.get("sha256", "")).lower()
    if want and want == _sha256(cbom_path):
        raise WaveError("the CBOM is the scan the wave was planned from; check against a later scan")
    # The same scan re-serialised has other bytes but the same serial number and timestamp (1.7.0; before, only the
    # bytes were compared, so a reformatted planning baseline was checked against itself)
    if wb.get("serialNumber") and scan.serial == wb["serialNumber"]:
        raise WaveError("the CBOM has the serial number of the scan the wave was planned from; check against a "
                        "later scan")
    if wb.get("timestamp") and scan.timestamp and _instant(scan.timestamp) <= _instant(wb["timestamp"]):
        raise WaveError("the CBOM is not newer than the scan the wave was planned from (metadata.timestamp)")
    if before:
        same_scan = bool(wb.get("serialNumber")) and before.serial == wb["serialNumber"] \
            and (not wb.get("timestamp") or before.timestamp == wb["timestamp"])
        if want and want != _sha256(baseline_path) and not same_scan:
            raise WaveError(f"--baseline {baseline_path} is not the CBOM the wave was planned from (sha256 differs)")
        if not before.timestamp or not scan.timestamp:
            raise WaveError("both CBOMs need metadata.timestamp to compare them")
        if _instant(scan.timestamp) <= _instant(before.timestamp):
            raise WaveError("the CBOM is not newer than the baseline (metadata.timestamp)")
    items = [check_item(it, scan, profile) for it in wave["items"]]
    regs, skipped = regressions(wave, scan, before) if before else (None, None)
    counts = {s: sum(1 for i in items if i["status"] == s) for s in ("pass", "fail", "not-observed")}
    passed = counts["pass"] == len(items) and not regs

    def doc(path, s):
        return {"file": os.path.basename(path), "sha256": _sha256(path), "serialNumber": s.serial,
                "timestamp": s.timestamp, "toolkitVersion": s.toolkit}

    docs = {"wave": {"file": os.path.basename(wave_path), "sha256": _sha256(wave_path)}, "cbom": doc(cbom_path, scan)}
    if before:
        docs["baseline"] = doc(baseline_path, before)
    return {
        "resultFormat": RESULT, "resultFormatVersion": RESULT_VERSION,
        "evaluationDate": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "wave": wave.get("wave", ""), "profile": profile,
        "rulesetVersion": cnsa.RULESET_VERSION, "rulesetDigest": scan.ruleset_digest,
        "documents": docs,
        "passed": passed,
        "summary": dict(counts, items=len(items), regressions=None if regs is None else len(regs)),
        "items": items,
        "regressions": regs,
        "notCompared": skipped,
    }


# Wave files, endpoints and CBOM names are not trusted to leave the Markdown alone (GHSA-gmv4-8882-x388): no line
# break, table-cell separator, raw HTML, link target or code span (as report.md_text; a pipe is escaped as "\|",
# which GFM and Python-Markdown tables both read as text).
_MD_UNSAFE = (("\\", "\\\\"), ("\r", " "), ("\n", " "), ("|", "\\|"), ("<", "&lt;"), (">", "&gt;"), ("](", "]&#40;"),
              ("`", "&#96;"))


# Control bytes, terminal escapes, line/paragraph separators, and (1.5.0) the invisible and bidirectional
# formatting characters (zero-width, LRM/RLM, LRE..RLO, LRI..PDI, BOM, tag characters).
_CONTROL = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-_]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029"
                      r"\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff\U000e0000-\U000e007f]")


def md_text(v):
    """A string made inert in Markdown: one line, no control bytes, no cell separator, no raw HTML, no link
    target."""
    s = _CONTROL.sub("", str(v)).replace("\t", " ")
    for a, b in _MD_UNSAFE:
        s = s.replace(a, b)
    return s


def markdown(result):
    m = md_text
    L = [f"## Migration wave check: {m(result['wave'] or 'wave')}", ""]
    s = result["summary"]
    verdict = "**Passed.**" if result["passed"] else "**Not passed.**"
    L.append(f"{verdict} {s['pass']} of {s['items']} item(s) passed, {s['fail']} failed, "
             f"{s['not-observed']} not observed in this scan"
             + ("" if s["regressions"] is None else f"; {s['regressions']} regression(s) against the baseline")
             + f". Profile: {result['profile']}; ruleset {result['rulesetVersion']}. An item passes only on what "
             "this scan itself observed; where it could not see, the item is \"not observed\".")
    L += ["", "| Item | Endpoint | Check | Result | Detail |", "|---|---|---|---|---|"]
    for i in result["items"]:
        L.append(f"| {m(i['id'])} | {m(i['endpoint'])} | {m(i['check'])} | {m(i['status'])} | {m(i['detail'])} |")
    if result["regressions"]:
        L += ["", "Regressions (Critical or High findings at these endpoints, new or worse than in the baseline):", ""]
        L += [f"- {m(r['endpoint'])}: {m(r['name'])} ({m(r['lane'])}, {m(r['status'])}, {m(r['priority'])})"
              for r in result["regressions"]]
    if result.get("notCompared"):
        L += ["", "Not compared with the baseline (no regression can be claimed or ruled out here):", ""]
        L += [f"- {m(n['endpoint'])}: {m(', '.join(n['lanes']))} ({m(n['reason'])})" for n in result["notCompared"]]
    L.append("")
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="check a wave file against a CBOM from a scan taken after the work")
    c.add_argument("--wave", required=True)
    c.add_argument("--cbom", required=True)
    c.add_argument("--baseline", default="", help="CBOM from before the wave, to list regressions")
    c.add_argument("--out", default="", help="result JSON (default: <cbom>.wave.json); Markdown beside it")
    a = ap.parse_args(argv)
    for p in [a.wave, a.cbom] + ([a.baseline] if a.baseline else []):
        if not os.path.isfile(p):
            sys.stderr.write(f"[error] not a file: {p}\n")
            return 2
    try:
        result = check(a.wave, a.cbom, a.baseline or None)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as e:   # WaveError is a ValueError
        sys.stderr.write(f"[error] {e}\n")
        return 2
    out = a.out or os.path.splitext(a.cbom)[0] + ".wave.json"
    with open(out, "w") as f:
        json.dump(result, f, indent=2)
    with open(os.path.splitext(out)[0] + ".md", "w") as f:
        f.write(markdown(result))
    s = result["summary"]
    print(f"[{'ok' if result['passed'] else 'not passed'}] wave check: {s['pass']}/{s['items']} passed, "
          f"{s['fail']} failed, {s['not-observed']} not observed -> {out}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
