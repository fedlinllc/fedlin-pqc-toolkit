#!/usr/bin/env python3
"""FIPS 140-3 (CMVP) validation status for the cryptographic implementations a CBOM records.

What this can and cannot say. A CMVP certificate covers one module at the versions and operating
environments listed in its Security Policy, used in its approved mode. The CBOM records a library
name, an OS release or an HSM product, not the module build. So a match here is a **candidate**:
an active certificate exists for that module family, and the analyst confirms version, operating
environment and approved mode against the Security Policy before claiming validation. Libraries
with no validated module are reported as such.

Data comes from a dated snapshot of NIST's CMVP pages (data/cmvp/), so runs are offline and
reproducible. Refresh it deliberately, at release time:

    python3 scripts/cmvp.py snapshot --out data/cmvp/cmvp-YYYY-MM-DD.json

Usage:
    python3 scripts/cmvp.py match --cbom out/cbom.json [--snapshot data/cmvp/....json]
"""
import argparse
import datetime
import glob
import hashlib
import html
import json
import os
import re
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CMVP_BASE = "https://csrc.nist.gov/projects/cryptographic-module-validation-program"
PQC_ALGOS = ("ML-KEM", "ML-DSA", "SLH-DSA", "LMS", "XMSS")

# --- Module families -------------------------------------------------------------------------
# kind "candidate": active certificates may cover it. kind "no-module": no CMVP module exists for it.
# match: how the family is recognised in a CBOM.
#   packages: library component names (lower-case, group/name or name) or purl prefixes
#   os: {os_id: module regex with {major}/{version}} for distribution modules (needs FIPS mode)
#   hsm: substrings of an HSM component's name
# cmvp: (vendor regex, module regex) pairs selecting certificates from the snapshot.
FAMILIES = [
    {"id": "openssl-distro", "label": "Distribution OpenSSL FIPS provider", "kind": "candidate",
     "match": {"os": {
         "rhel": r"Red Hat Enterprise Linux {major}\b.*OpenSSL",
         "rocky": r"Rocky Linux .*\b{major}\b.*OpenSSL",
         "almalinux": r"OpenSSL FIPS Provider for AlmaLinux {major}\b",
         "ol": r"Oracle Linux {major}\b.*OpenSSL",
         "ubuntu": r"Ubuntu {version}\b.*OpenSSL",
         "sles": r"SUSE Linux Enterprise OpenSSL",
         "amzn": r"Amazon Linux {major}\b.*OpenSSL"}},
     "cmvp": [(r"Red Hat|Ctrl IQ|TuxCare|Cloudlinux|Oracle|Canonical|SUSE|Amazon", r"OpenSSL")],
     "confirm": "The host must run in FIPS mode, and its OpenSSL package version and OS release must be "
                "listed in the certificate's Security Policy."},
    {"id": "openssl-upstream", "label": "OpenSSL FIPS Provider (upstream)", "kind": "candidate",
     "match": {"packages": ["openssl", "pkg:generic/openssl", "pkg:conan/openssl"]},
     "cmvp": [(r"^The OpenSSL (Corporation|Project)$", r"^OpenSSL FIPS Provider$")],
     "confirm": "Only the FIPS provider (fips.so) at a validated version, loaded and configured as the "
                "Security Policy describes, is validated; the rest of OpenSSL is not."},
    {"id": "bc-fja", "label": "Bouncy Castle FIPS Java API (BC-FJA)", "kind": "candidate",
     "match": {"packages": ["org.bouncycastle/bc-fips", "bc-fips", "pkg:maven/org.bouncycastle/bc-fips"]},
     "cmvp": [(r"Legion of the Bouncy Castle", r"BC-FJA")],
     "confirm": "The bc-fips version must match the certificate, running in approved-only mode on a "
                "listed JVM and OS."},
    {"id": "aws-lc", "label": "AWS-LC", "kind": "candidate",
     "match": {"packages": ["aws-lc-fips-sys", "aws-lc-rs", "aws-lc-sys", "pkg:cargo/aws-lc-fips-sys",
                            "pkg:cargo/aws-lc-rs", "pkg:cargo/aws-lc-sys"]},
     "cmvp": [(r"^Amazon Web Services", r"^AWS-LC")],
     "confirm": "Only a FIPS build (aws-lc-fips-sys, or aws-lc-rs with its fips feature) at a validated "
                "version is in scope; the default aws-lc-sys build is not."},
    {"id": "boringcrypto", "label": "BoringCrypto (BoringSSL FIPS)", "kind": "candidate",
     "match": {"packages": ["boringssl", "boring", "boring-sys", "pkg:cargo/boring", "pkg:cargo/boring-sys"]},
     "cmvp": [(r"^Google", r"^BoringCrypto$")],
     "confirm": "Only the FIPS build of BoringSSL (BoringCrypto) at a validated version is in scope."},
    {"id": "wolfcrypt", "label": "wolfCrypt", "kind": "candidate",
     "match": {"packages": ["wolfssl", "wolfcrypt", "wolfssl-py", "pkg:pypi/wolfssl", "pkg:pypi/wolfcrypt"]},
     "cmvp": [(r"^wolfSSL", r"^wolfCrypt$")],
     "confirm": "Only the wolfCrypt FIPS edition at a validated version and operating environment is in scope."},
    {"id": "go-crypto", "label": "Go Cryptographic Module", "kind": "candidate",
     "match": {"packages": ["pkg:golang/stdlib", "stdlib"]},
     "cmvp": [(r"^Geomys", r"^Go Cryptographic Module$")],
     "confirm": "Go 1.24 or later built with a validated module version (GOFIPS140) and running in FIPS "
                "140-3 mode (GODEBUG=fips140=on)."},
    {"id": "hsm-luna", "label": "Thales Luna HSM", "kind": "candidate",
     "match": {"hsm": ["luna"]},
     "cmvp": [(r"^Thales", r"Luna")],
     "confirm": "Match the HSM model and firmware version to the certificate, and confirm it runs in its "
                "FIPS-approved mode."},
    {"id": "hsm-nshield", "label": "Entrust nShield HSM", "kind": "candidate",
     "match": {"hsm": ["nshield"]},
     "cmvp": [(r"^Entrust", r"nShield")],
     "confirm": "Match the HSM model and firmware version to the certificate, and confirm it runs in its "
                "FIPS-approved mode."},
    {"id": "hsm-yubihsm", "label": "YubiHSM 2", "kind": "candidate",
     "match": {"hsm": ["yubihsm"]},
     "cmvp": [(r"^Yubico", r"YubiHSM")],
     "confirm": "Match the device and firmware version to the certificate, and confirm FIPS mode."},
    # --- no CMVP module exists for these as shipped --------------------------------------------
    {"id": "pyca-wheels", "label": "pyca/cryptography (PyPI wheels)", "kind": "no-module",
     "match": {"packages": ["cryptography", "pkg:pypi/cryptography"]},
     "note": "PyPI wheels bundle their own OpenSSL without the FIPS provider. To use a validated module, "
             "build against the system OpenSSL in FIPS mode."},
    {"id": "bcprov", "label": "Bouncy Castle provider (non-FIPS build)", "kind": "no-module",
     "match": {"packages": ["org.bouncycastle/bcprov-jdk18on", "org.bouncycastle/bcprov-jdk15on",
                            "org.bouncycastle/bcprov-jdk15to18", "bcprov-jdk18on", "bcprov-jdk15on"]},
     "note": "bcprov is not a validated module. The validated build is BC-FJA (org.bouncycastle:bc-fips)."},
    {"id": "go-x-crypto", "label": "golang.org/x/crypto", "kind": "no-module",
     "match": {"packages": ["golang.org/x/crypto", "pkg:golang/golang.org/x/crypto"]},
     "note": "Outside the Go Cryptographic Module boundary; only the standard library's crypto packages "
             "are covered in FIPS 140-3 mode."},
    {"id": "pure-js", "label": "Pure-JavaScript cryptography", "kind": "no-module",
     "match": {"packages": ["@noble/curves", "@noble/hashes", "@noble/ciphers", "@noble/post-quantum",
                            "@noble/secp256k1", "@noble/ed25519", "elliptic", "tweetnacl", "node-forge",
                            "node-rsa", "crypto-js"]},
     "note": "No CMVP-validated module exists for these libraries. Use Node's crypto module backed by a "
             "validated OpenSSL FIPS provider."},
    {"id": "other-python", "label": "PyCryptodome / PyNaCl", "kind": "no-module",
     "match": {"packages": ["pycryptodome", "pycryptodomex", "pynacl", "pkg:pypi/pycryptodome",
                            "pkg:pypi/pynacl"]},
     "note": "No CMVP-validated module exists for these libraries."},
]


# --- Snapshot -------------------------------------------------------------------------------
def _get(url, ua):
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def _parse_list(page):
    rows = re.findall(
        r'cert-number-link-(\d+)">(\d+)</a>.*?cert-vendor-name-\1">(.*?)</td>.*?cert-module-name-\1">(.*?)</td>'
        r'.*?cert-module-type-\1">(.*?)</td>.*?cert-validation-dates-\1">(.*?)</td>', page, re.S)
    out = []
    for _, cert, vendor, module, mtype, dates in rows:
        out.append({"cert": int(cert), "vendor": html.unescape(vendor).strip(),
                    "module": re.sub(r"\s+", " ", html.unescape(module)).strip(),
                    "type": html.unescape(mtype).strip(),
                    "validated": [d.strip() for d in re.split(r"<br\s*/?>", dates) if d.strip()]})
    return out


def _field(text, label, nxt):
    m = re.search(re.escape(label) + r"\s*(.*?)\s*(?:" + "|".join(map(re.escape, nxt)) + ")", text)
    return m.group(1).strip() if m else ""


def _parse_detail(page):
    t = html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))
    i = t.find("Details Module Name")
    t = t[i:] if i >= 0 else t
    labels = ["Module Name", "Standard", "Status", "Sunset Date", "Overall Level", "Caveat",
              "Security Level Exceptions", "Module Type", "Embodiment", "Description", "Approved Algorithms",
              "Vendor"]
    d = {}
    for k, nxt in (("standard", ["Status"]), ("status", ["Sunset Date", "Overall Level"]),
                   ("sunset", ["Overall Level"]), ("level", ["Caveat", "Security Level", "Module Type"]),
                   ("caveat", ["Security Level Exceptions", "Module Type"])):
        d[k] = _field(t, {"standard": "Standard", "status": "Status", "sunset": "Sunset Date",
                          "level": "Overall Level", "caveat": "Caveat"}[k], nxt)
    algos = t[t.find("Approved Algorithms"):t.find(" Vendor ", t.find("Approved Algorithms"))] \
        if "Approved Algorithms" in t else ""
    d["pqc_approved"] = sorted({a for a in PQC_ALGOS if re.search(r"\b" + re.escape(a) + r"\b", algos)})
    d["caveat"] = d["caveat"][:300]
    del labels
    return d


def family_certs(rows, fam):
    pats = [(re.compile(v, re.I), re.compile(m, re.I)) for v, m in fam.get("cmvp", [])]
    return [r for r in rows if any(v.search(r["vendor"]) and m.search(r["module"]) for v, m in pats)]


def build_snapshot(out, delay=1.0, ua="fedlin-pqc-toolkit cmvp-snapshot"):
    page = _get(f"{CMVP_BASE}/validated-modules/search/all", ua)
    rows = _parse_list(page)
    wanted = {}
    for fam in FAMILIES:
        for r in family_certs(rows, fam):
            wanted[r["cert"]] = r
    for n, cert in enumerate(sorted(wanted)):
        time.sleep(delay)
        try:
            wanted[cert].update(_parse_detail(_get(f"{CMVP_BASE}/certificate/{cert}", ua)))
        except Exception as e:  # keep the list facts; mark the detail as missing
            wanted[cert]["detail_error"] = str(e)[:200]
        sys.stderr.write(f"\r[cmvp] details {n + 1}/{len(wanted)}")
    sys.stderr.write("\n")
    snap = {"source": f"{CMVP_BASE}/validated-modules/search/all",
            "fetched": datetime.date.today().isoformat(),
            "list_rows": len(rows),
            "scope": "Certificates selected by scripts/cmvp.py FAMILIES; details from each certificate page.",
            "modules": [wanted[c] for c in sorted(wanted, reverse=True)]}
    with open(out, "w") as f:
        json.dump(snap, f, indent=1, sort_keys=True)
        f.write("\n")
    return snap


def default_snapshot():
    files = sorted(glob.glob(os.path.join(ROOT, "data", "cmvp", "cmvp-*.json")))
    return files[-1] if files else ""


def load_snapshot(path=""):
    path = path or default_snapshot()
    if not path or not os.path.exists(path):
        return None, ""
    with open(path, "rb") as f:
        raw = f.read()
    snap = json.loads(raw)
    snap["_path"] = os.path.relpath(path, ROOT) if path.startswith(ROOT) else path
    snap["_sha256"] = hashlib.sha256(raw).hexdigest()
    return snap, path


# --- Matching -------------------------------------------------------------------------------
def _props(c):
    return {p.get("name"): p.get("value") for p in c.get("properties", []) or []}


def _pkg_keys(c):
    g, n = (c.get("group") or "").strip().lower(), (c.get("name") or "").strip().lower()
    keys = {n, f"{g}/{n}" if g else n}
    purl = (c.get("purl") or "").lower()
    if purl:
        base = purl.split("@", 1)[0].split("?", 1)[0]
        keys.add(base)
    return keys, purl


def _active(m, today):
    if (m.get("status") or "Active") != "Active":
        return False
    try:
        mm, dd, yy = m.get("sunset", "").split("/")
        return datetime.date(int(yy), int(mm), int(dd)) >= today
    except ValueError:
        return True


def match(bom, snap, today=None):
    """Findings: one per (family, where seen). Candidates carry active certificates from the snapshot."""
    today = today or datetime.date.today()
    mods = (snap or {}).get("modules", [])
    findings = {}

    def add(fam, where, extra=None, certs=None):
        key = (fam["id"], extra or "")
        f = findings.setdefault(key, {"family": fam["id"], "label": fam["label"], "kind": fam["kind"],
                                      "seen": set(), "detail": extra or "",
                                      "confirm": fam.get("confirm", ""), "note": fam.get("note", ""),
                                      "certificates": []})
        f["seen"].add(where)
        if certs is not None:
            f["certificates"] = [{k: m.get(k) for k in ("cert", "vendor", "module", "standard", "level",
                                                         "sunset", "pqc_approved")}
                                 for m in certs if _active(m, today)]

    for c in bom.get("components", []) or []:
        p = _props(c)
        if c.get("type") == "library":
            keys, purl = _pkg_keys(c)
            for fam in FAMILIES:
                pk = [x.lower() for x in fam["match"].get("packages", [])]
                if keys & set(pk) or any(purl.startswith(x + "@") or purl == x for x in pk if x.startswith("pkg:")):
                    ver = c.get("version") or "?"
                    add(fam, f"{c.get('name')} {ver}",
                        certs=family_certs(mods, fam) if fam["kind"] == "candidate" else None)
        elif c.get("type") == "operating-system" and p.get("fedlin:hw_class") == "os":
            os_id, ver = (p.get("fedlin:os_id") or "").lower(), p.get("fedlin:os_version_id") or ""
            fam = FAMILIES[0]
            pat = fam["match"]["os"].get(os_id) or (fam["match"]["os"]["sles"] if os_id.startswith("sle") else None)
            if not pat:
                continue
            rx = re.compile(pat.format(major=re.escape(ver.split(".")[0]), version=re.escape(ver)), re.I)
            certs = [m for m in family_certs(mods, fam) if rx.search(m["module"])]
            fips = p.get("fedlin:fips_enabled", "unknown")
            add(fam, f"{p.get('fedlin:host', '?')} ({os_id} {ver}, FIPS mode {fips})", certs=certs)
        elif p.get("fedlin:hw_class") == "hsm":
            name = (c.get("name") or "").lower()
            for fam in FAMILIES:
                if any(h in name for h in fam["match"].get("hsm", [])):
                    add(fam, c.get("name"), certs=family_certs(mods, fam))
    out = []
    for f in findings.values():
        f["seen"] = sorted(f["seen"])
        out.append(f)
    order = {"candidate": 0, "no-module": 1}
    return sorted(out, key=lambda f: (order.get(f["kind"], 2), f["label"]))


def summary(findings, snap):
    cands = [f for f in findings if f["kind"] == "candidate"]
    return {
        "snapshot": (snap or {}).get("fetched"),
        "snapshot_sha256": (snap or {}).get("_sha256"),
        "implementations_found": len(findings),
        "with_active_certificate": sum(1 for f in cands if f["certificates"]),
        "without_active_certificate": sum(1 for f in cands if not f["certificates"]),
        "no_cmvp_module": sum(1 for f in findings if f["kind"] == "no-module"),
        "pqc_approved_candidates": sum(1 for f in cands if any(c["pqc_approved"] for c in f["certificates"])),
    }


def report_lines(findings, snap):
    """Markdown section for the readiness report."""
    L = ["## FIPS 140-3 validation (CMVP)", ""]
    if not snap:
        L += ["No CMVP snapshot is available (`data/cmvp/`), so validation status was not checked.", ""]
        return L
    L.append(f"Checked against a snapshot of NIST's CMVP validated-modules pages fetched {snap['fetched']} "
             f"(`{snap.get('_path', '')}`, sha256 `{snap.get('_sha256', '')[:16]}…`).")
    L.append("")
    if not findings:
        L += ["No cryptographic implementation in this CBOM maps to a CMVP module family. An endpoint scan "
              "cannot see the server's implementation; run the host collectors or `--repo` to identify "
              "libraries, operating systems and HSMs.", ""]
        return L
    L.append("A certificate listed here is a **candidate**: it shows that an active FIPS 140-3 validation exists "
             "for the module family, not that the deployed build is covered by it. Confirm the version, "
             "operating environment and approved mode against the certificate's Security Policy.")
    L.append("")
    L.append("| Implementation | Seen at | Active certificates | Post-quantum algorithms approved | To confirm |")
    L.append("|---|---|---|---|---|")
    for f in findings:
        seen = "; ".join(f["seen"][:3]) + (f" (+{len(f['seen']) - 3} more)" if len(f["seen"]) > 3 else "")
        if f["kind"] == "no-module":
            L.append(f"| {f['label']} | {seen} | None: no CMVP module | n/a | {f['note']} |")
            continue
        certs = f["certificates"]
        if certs:
            shown = ", ".join(f"#{c['cert']} (sunset {c.get('sunset') or '?'})" for c in certs[:4])
            if len(certs) > 4:
                shown += f", +{len(certs) - 4} more"
            pqc = sorted({a for c in certs for a in (c.get("pqc_approved") or [])})
            L.append(f"| {f['label']} | {seen} | {shown} | {', '.join(pqc) or 'None'} | {f['confirm']} |")
        else:
            L.append(f"| {f['label']} | {seen} | None found in snapshot | n/a | {f['confirm']} |")
    L.append("")
    return L


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot", help="fetch NIST CMVP pages for the curated families into a JSON snapshot")
    s.add_argument("--out", required=True)
    s.add_argument("--delay", type=float, default=1.0, help="seconds between certificate-page requests")
    m = sub.add_parser("match", help="report CMVP candidates for the implementations in a CBOM")
    m.add_argument("--cbom", required=True)
    m.add_argument("--snapshot", default="")
    a = ap.parse_args()
    if a.cmd == "snapshot":
        snap = build_snapshot(a.out, delay=a.delay)
        print(f"[ok] {a.out}: {len(snap['modules'])} certificates from {snap['list_rows']} listed")
        return
    snap, _ = load_snapshot(a.snapshot)
    with open(a.cbom) as f:
        bom = json.load(f)
    found = match(bom, snap)
    print("\n".join(report_lines(found, snap)))
    print(json.dumps(summary(found, snap), indent=2))


if __name__ == "__main__":
    main()
