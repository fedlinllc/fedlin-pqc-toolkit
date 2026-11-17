#!/usr/bin/env python3
"""Verdict table: the toolkit's ruleset as versioned data for other scanners (fedlin.com scan, MCP hub).

A scanner that observes an algorithm name (and a key size where it matters) looks it up here instead of
carrying its own verdict logic, so a hosted quick check and a toolkit run give the same verdict for the
same ruleset version. Every verdict comes from `cnsa20_ruleset.classify` and `policy._status`, the code
that writes the policy result.

Lookup rule for consumers (also stated in the file):
  key = lowercase(name) with every character outside [a-z0-9] removed. If the verdict depends on key size,
  `bands[key]` lists contiguous bit ranges: with a known size use the band that contains it, without one
  use `index[key]`. Otherwise use `index[key]`. A name in neither is "unknown": report it as unknown, never
  as a pass. Curve and group names (P-256, X25519, secp384r1) are key-exchange names; for a certificate
  public key look up its key type (rsaEncryption, id-ecPublicKey, Ed25519, ML-DSA-65) with its size.

The output is deterministic for a given ruleset (no timestamps), so its SHA-256 identifies it.

Usage:
  verdict_table.py build [--out verdicts-<ruleset>.json]
  verdict_table.py lookup NAME [--bits N] [--profile civilian|nss] [--table FILE]
"""
import argparse
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cnsa20_ruleset as cnsa  # noqa: E402
import policy  # noqa: E402

SCHEMA = "fedlin.pqc-verdict-table"
SCHEMA_VERSION = "1.0"

# Names a TLS/certificate scanner reports, in the spellings seen from OpenSSL, Node.js tls, IANA and
# CycloneDX. Bit-dependent families are listed at the sizes that occur in practice.
OBSERVABLE = [
    # TLS 1.3 / 1.2 key-exchange groups (IANA names, OpenSSL and Node.js spellings)
    "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X448MLKEM1024", "MLKEM512", "MLKEM768",
    "MLKEM1024", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "X25519Kyber768Draft00", "X25519MLKEM1024",
    "SecP256r1MLKEM1024",
    "X25519", "X448", "x25519", "x448", "secp256r1", "secp384r1", "secp521r1", "prime256v1", "P-256",
    "P-384", "P-521", "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192", "brainpoolP256r1tls13",
    "brainpoolP384r1tls13", "brainpoolP512r1tls13",
    ("DH", 1024), ("DH", 2048), ("DH", 3072), ("DH", 4096), ("ECDH", 256), ("ECDH", 384), ("ECDH", 521),
    # certificate public keys
    ("RSA", 1024), ("RSA", 2048), ("RSA", 3072), ("RSA", 4096), ("RSA", 8192),
    ("rsaEncryption", 1024), ("rsaEncryption", 2048), ("rsaEncryption", 3072), ("rsaEncryption", 4096),
    ("EC", 256), ("EC", 384), ("EC", 521), ("id-ecPublicKey", 256), ("id-ecPublicKey", 384),
    ("id-ecPublicKey", 521), "Ed25519", "Ed448", "ED25519", "ED448",
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-256s", ("DSA", 1024), ("DSA", 2048),
    # certificate signature algorithms (OpenSSL names)
    "sha1WithRSAEncryption", "sha256WithRSAEncryption", "sha384WithRSAEncryption", "sha512WithRSAEncryption",
    "md5WithRSAEncryption", "rsassaPss", "RSASSA-PSS", "ecdsa-with-SHA1", "ecdsa-with-SHA256",
    "ecdsa-with-SHA384", "ecdsa-with-SHA512", "ED25519", "id-ml-dsa-44", "id-ml-dsa-65", "id-ml-dsa-87",
    # TLS signature schemes and other spellings of SHA-1 signatures; composite ML-DSA (IETF draft names)
    "RSA-SHA1", "rsa_pkcs1_sha1", "ecdsa_sha1", "MLDSA87-ECDSA-P384-SHA512", "MLDSA87-Ed448",
    "MLDSA65-RSA3072-PSS-SHA512", "MLDSA65-ECDSA-P256-SHA512", "MLDSA44-Ed25519-SHA512",
    "MLDSA87-RSA3072-PSS-SHA512", "MLDSA44-RSA2048-PSS-SHA256", "MLDSA87-ECDSA-brainpoolP384r1-SHA512",
    # pre-standard drafts (FIPS 203/204/205 initial public drafts, Kyber, Dilithium, SPHINCS+) and other spellings
    # of the standard names
    "ML-KEM-768-ipd", "ML-KEM-1024-ipd", "MLKEM1024-IPD", "ML-DSA-65-ipd", "ML-DSA-87-ipd",
    "SLH-DSA-SHA2-128s-ipd", "kyber768", "kyber1024", "dilithium3", "dilithium5", "p256_kyber768",
    "id-alg-slh-dsa-sha2-128s", "id-alg-slh-dsa-shake-128s", "FN-DSA-512", "FN-DSA-1024", "FN-DSA-1024-padded",
    "Falcon-512", "p256_falcon512", "SPHINCS+-SHA2-128s-simple",
    # protocol versions and common TLS 1.3 cipher suites
    "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3", "SSLv3",
    "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
]


def key(name, bits=None):
    k = cnsa._compact(str(name))
    return f"{k}@{int(bits)}" if bits else k


def _verdict(name, bits, profile):
    v = cnsa.classify(name, bits, profile=profile)
    return {"status": policy._status(v), "quantum_vulnerable": v["quantum_vulnerable"],
            "target": v["cnsa_target"], "priority": v["priority"], "note": v["note"],
            "cite": sorted(v["cite"] or [])}, v


EXTRA = ["AES-128-GCM", "AES-256-GCM", "AES-128-CBC", "AES-256-CBC", "AES128-GCM", "AES256-GCM", "aes128-ctr",
         "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com",
         "3DES", "DES-EDE3-CBC", "DES", "RC4", "ChaCha20-Poly1305", "SHA-1", "SHA1", "SHA-224", "SHA-256", "SHA-384",
         "SHA-512", "SHA256", "SHA384", "SHA512", "SHA3-256", "SHA3-384", "SHA3-512", "MD5", "HMAC-SHA1", "HMAC-SHA256",
         "HMAC-SHA384", "HMAC-SHA512", "hmac-sha1", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha2-256-etm@openssh.com",
         "hmac-sha2-512-etm@openssh.com", "umac-128-etm@openssh.com", "id-slh-dsa-sha2-128s", "id-slh-dsa-sha2-128f",
         "id-slh-dsa-sha2-192s", "id-slh-dsa-sha2-256s", "id-slh-dsa-shake-128s", "id-slh-dsa-shake-256s",
         # legacy suites OpenSSL 3.5 no longer lists, which a weak server still reports
         "DES-CBC3-SHA", "ECDHE-RSA-DES-CBC3-SHA", "EDH-RSA-DES-CBC3-SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
         "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "RC4-SHA", "RC4-MD5", "ECDHE-RSA-RC4-SHA", "TLS_RSA_WITH_RC4_128_SHA",
         "TLS_RSA_WITH_RC4_128_MD5", "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "EXP-RC4-MD5", "DES-CBC-SHA", "NULL-SHA",
         "NULL-MD5"]
SUITES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "tls-cipher-suites.tsv")
MAX_BITS = 16384
_SIZED_FAMILIES = {"rsa", "dsa", "dh", "ec", "ecdh", "ecdsa", "elgamal", "mqv"}
_SUITE_TOKENS = re.compile(r"aes|camellia|aria|chacha|null|psk|srp|des|rc4|gcm|cbc|seed|idea")


def _points():
    """Key sizes to evaluate: 1, MAX_BITS, and both sides of every size threshold in the ruleset's strength
    functions (SP 800-57). Between consecutive points the verdict is constant by construction of those
    functions; tests/test_verdict_table.py checks this against a scan of every size."""
    import inspect
    src = inspect.getsource(cnsa._ifc_strength) + inspect.getsource(cnsa._ecc_strength) + inspect.getsource(
        cnsa._verdict_for)
    ts = {int(x) for x in re.findall(r"\b(\d{2,5})\b", src)}
    pts = {1, MAX_BITS} | {t + d for t in ts for d in (-1, 0, 1) if 1 <= t + d <= MAX_BITS}
    return sorted(pts)


def _sig(name, bits):
    out = []
    for p in cnsa.PROFILES:
        v = cnsa.classify(name, bits, profile=p)
        out.append((v["canonical"], policy._status(v), v["cnsa_target"], v["priority"], v["quantum_vulnerable"],
                    re.sub(rf"\b{bits}-bit key\b", "", v["note"]), v["deprecated_after"], v["disallowed_after"]))
    return tuple(out)


def _banded(name, bits):
    """Entry for one key size with the size-specific wording made size-neutral, so a band shares one entry."""
    e = _entry(name, bits)
    if e:
        for v in e["verdicts"].values():
            v["note"] = re.sub(rf"\b{bits}-bit key\b", "This key size", v["note"])
    return e
_SAMPLE_BITS = (160, 192, 224, 256, 384, 512, 521, 768, 1024, 1536, 2048, 3072, 4096, 7680, 8192, 15360)


def _suites():
    out = []
    with open(SUITES, encoding="utf-8") as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                out += [x for x in line.split() if x]
    return out


def _inputs():
    seen = set()
    items = []
    for x in OBSERVABLE:
        name, bits = (x, None) if isinstance(x, str) else x
        if key(name, bits) not in seen:
            seen.add(key(name, bits))
            items.append((name, bits))
    for name in EXTRA + _suites() + sorted(cnsa.ALGORITHMS):
        if key(name) not in seen:
            seen.add(key(name))
            items.append((name, None))
    # every exact alias, TLS group and curve the ruleset knows, so spelling variants resolve too
    for k in sorted(set(cnsa.ALIASES) | set(cnsa.TLS_GROUPS) | set(cnsa.CURVES) | set(cnsa.SSH_KEX)
                    | set(cnsa.SSH_HOSTKEY)):
        if k not in seen:
            seen.add(k)
            items.append((k, None))
    return items


def _entry(name, bits):
    civ, raw = _verdict(name, bits, "civilian")
    if raw["canonical"] is None:
        return None
    nss, _ = _verdict(name, bits, "nss")
    return {"canonical": raw["canonical"], "family": raw["family"],
            "parameter_set": raw["parameter_set"] if bits is None else None, "bits": None,
            "lane": cnsa.lane_of(raw["canonical"], raw["primitive"]), "primitive": raw["primitive"],
            "nist_pqc_level": raw["nist_pqc_level"], "classically_broken": raw["classically_broken"],
            "deprecated_after": raw["deprecated_after"], "disallowed_after": raw["disallowed_after"],
            "verdicts": {"civilian": civ, "nss": nss}}


_CACHE = {}


def build():
    """The table for the loaded ruleset (computed once per process)."""
    if "t" not in _CACHE:
        _CACHE["t"] = _build()
    return json.loads(json.dumps(_CACHE["t"]))


def _build():
    entries, index, bands, by_sig = [], {}, {}, {}

    def intern(entry):
        sig = json.dumps(entry, sort_keys=True)
        if sig not in by_sig:
            by_sig[sig] = f"e{len(entries)}"
            entries.append(dict(entry, id=by_sig[sig]))
        return by_sig[sig]

    sized = {}
    for name, bits in _inputs():
        k = key(name)
        if bits is not None:
            sized.setdefault(k, name)
            continue
        e = _entry(name, None)
        if e is None:
            continue  # unknown to the ruleset: consumers report "unknown"
        index[k] = intern(e)
        sized.setdefault(k, name)
    # names whose verdict depends on key size get exact bands, computed at every size up to MAX_BITS
    for k, name in sorted(sized.items()):
        base = _entry(name, None)
        probe = cnsa.classify(name, 2048)
        if probe["canonical"] not in _SIZED_FAMILIES or probe.get("components") or _SUITE_TOKENS.search(k):
            continue  # key size applies only to a single public-key algorithm, not to suites or hybrids
        sigs = {json.dumps(_banded(name, b), sort_keys=True) for b in _SAMPLE_BITS}
        if len(sigs) == 1:
            continue  # the verdict does not depend on key size
        rows, cur, last = [], None, None
        for b in _points():
            sig = _sig(name, b)  # the verdict can change only at a threshold in the ruleset
            if cur and sig == last:
                cur["maxBits"] = b
                continue
            if cur:
                cur["maxBits"] = b - 1
            e = _banded(name, b)
            cur = {"minBits": b, "maxBits": b, "id": intern(e) if e else None}
            rows.append(cur)
            last = sig
        rows[-1]["maxBits"] = None  # open-ended: the verdict at MAX_BITS holds above it
        bands[k] = [r for r in rows if r["id"]]
        if base is not None:
            index[k] = intern(base)
    used = sorted({c for e in entries for p in e["verdicts"].values() for c in p["cite"]})
    return {
        "schema": SCHEMA, "schemaVersion": SCHEMA_VERSION,
        "ruleset": {"policyId": policy.POLICY_ID, "version": cnsa.RULESET_VERSION,
                    "file": "cnsa20_ruleset.py", "digest": {"alg": "SHA-256", "value": policy._ruleset_digest()}},
        "profiles": {"civilian": "NIST FIPS 203/204/205 and NIST IR 8547 (default)",
                     "nss": "NSA CNSA 2.0 (National Security Systems)"},
        "statuses": {"compliant": "meets the profile's target",
                     "transitional": "not quantum-vulnerable, but below the profile's target",
                     "vulnerable": "quantum-vulnerable",
                     "broken": "classically broken or disallowed; fix regardless of the post-quantum timeline",
                     "unclassified": "recognized but not judged by this profile"},
        "lookup": "key = lowercase(name) with characters outside [a-z0-9] removed. If key is in bands and the key "
                  "size is known, use the band whose minBits..maxBits contains it (maxBits null = no upper bound); "
                  "otherwise use index[key]. A name in neither is unknown: report it as unknown, never as a pass. "
                  "Curve and group names are key-exchange names; for a certificate public key look up its key type "
                  "(rsaEncryption, id-ecPublicKey, Ed25519, ML-DSA-65) with its size.",
        "sources": {k: cnsa.SOURCES[k] for k in used if k in cnsa.SOURCES},
        "index": dict(sorted(index.items())),
        "bands": dict(sorted(bands.items())),
        "entries": entries,
    }


def dumps(table):
    return json.dumps(table, indent=1, sort_keys=False, ensure_ascii=True) + "\n"


def lookup(table, name, bits=None, profile="civilian"):
    """The consumer algorithm, in Python: returns (entry, verdict) or (None, None) for unknown."""
    k = key(name)
    eid = None
    if bits and k in table["bands"]:
        b = int(bits)
        eid = next((r["id"] for r in table["bands"][k]
                    if r["minBits"] <= b and (r["maxBits"] is None or b <= r["maxBits"])), None)
    eid = eid or table["index"].get(k)
    if not eid:
        return None, None
    entry = next(e for e in table["entries"] if e["id"] == eid)
    return entry, entry["verdicts"][profile]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--out", default="")
    q = sub.add_parser("lookup")
    q.add_argument("name")
    q.add_argument("--bits", type=int)
    q.add_argument("--profile", choices=list(cnsa.PROFILES), default="civilian")
    q.add_argument("--table", default="")
    a = ap.parse_args(argv)
    if a.cmd == "build":
        text = dumps(build())
        out = a.out or f"verdicts-{cnsa.RULESET_VERSION}.json"
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[ok] {out} sha256 {hashlib.sha256(text.encode()).hexdigest()}")
        return 0
    table = json.load(open(a.table, encoding="utf-8")) if a.table else build()
    entry, v = lookup(table, a.name, a.bits, a.profile)
    if not entry:
        print(json.dumps({"name": a.name, "status": "unknown"}))
        return 1
    print(json.dumps({"name": a.name, "canonical": entry["canonical"], "profile": a.profile, **v}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
