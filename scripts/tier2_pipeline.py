#!/usr/bin/env python3
"""FEDLIN PQC Toolkit: runtime and endpoint capture -> CycloneDX 1.6 CBOM.

Live-endpoint, SSH and cluster-configuration cryptography has no turnkey CycloneDX
generator, so this converts runtime captures into a tool-generated CBOM (optionally
validated with cyclonedx-cli). Verdicts are made separately by policy.py.

Capture rules: cluster capture reads object NAMES and counts (go-templates over keys,
field-selectors), never secret values. Do not add `-o yaml/json`, `.data` dereferences
or `oc extract` here. What each mode can read is listed in the README ("Access by mode").

Usage:  python3 tier2_pipeline.py --out out/cbom.json [--validate ./bin/cyclonedx]
"""
import argparse
import datetime
import fnmatch
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling modules, also under python -I
import cnsa20_ruleset as cnsa
import evidence as evmod
import policy as policymod
import report as reportmod
import wave as wavemod
import context as ctxmod
import crosswalk

# Optional private modules (FEDLIN engagement kit). The public toolkit runs without them; their flags
# are hidden from --help and refused with a clear message when the module is absent.
try:
    import delta as deltamod  # baseline diff / continuous-monitoring evidence
except ImportError:
    deltamod = None
try:
    import sign as signmod  # SLH-DSA attestation over the deliverable
except ImportError:
    signmod = None
KIT_FLAGS = {
    "sign": signmod is not None, "slh_key": signmod is not None, "slh_variant": signmod is not None,
    "node": signmod is not None,
    "self_serve": reportmod._roadmap is not None,
    "brand": reportmod._whitelabel is not None,
}


# Toolkit release (semantic versioning; see CHANGELOG.md). Keep in sync with the toolkit.lock header.
TOOLKIT_VERSION = "1.8.2"


def run(cmd, timeout=25):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return p.stdout.strip()
    except Exception as e:
        sys.stderr.write(f"[warn] {cmd!r}: {e}\n")
        return ""


# ---------- capture (no secret values read) ----------

def detect_platform(kube="oc"):
    """Return 'openshift', 'kubernetes', or 'unreachable'.

    Lets the runtime tier work on EKS/GKE/AKS/k3s (kubectl): not just OpenShift (`oc`): by
    swapping Route capture for Ingress capture. Critically distinguishes a genuine non-OpenShift
    cluster from an unreachable/RBAC-limited one: if the API server serves NO resources at all,
    we must not silently claim 'generic kubernetes' and capture nothing: we flag it.
    """
    api = run(f"{kube} api-resources -o name 2>/dev/null")
    if not api.strip():
        return "unreachable"  # cluster down, wrong context, or token lacks RBAC to list resources
    return "openshift" if "route.openshift.io" in api else "kubernetes"


def _hsm_indicators(kube):
    hsm_pods = run(f"{kube} get pods -A --no-headers 2>/dev/null | grep -ciE 'hsm|pkcs11|luna|cloudhsm|softhsm'")
    hsm_crds = run(f"{kube} get crd --no-headers 2>/dev/null | grep -ciE 'hsm|pkcs11'")
    n_hsm = _int(hsm_pods) + _int(hsm_crds)
    return n_hsm if n_hsm else "none detected"


def capture_context(kube="oc"):
    ctx = {}
    ctx["ocp_version"] = run(f"{kube} get clusterversion version -o jsonpath='{{.status.desired.version}}'") or "unknown"
    ctx["etcd_encryption"] = run(f"{kube} get apiserver cluster -o jsonpath='{{.spec.encryption.type}}'") or "unset"
    ctx["min_tls"] = run(f"{kube} get ingresscontroller default -n openshift-ingress-operator -o jsonpath='{{.status.tlsProfile.minTLSVersion}}'") or "unknown"
    ciphers = run(f"{kube} get ingresscontroller default -n openshift-ingress-operator -o jsonpath='{{.status.tlsProfile.ciphers}}'")
    ctx["tls_ciphers"] = ciphers
    # HSM indicators (cheap detection: pods/CRDs referencing common HSM/PKCS#11 tech)
    ctx["hsm_indicators"] = _hsm_indicators(kube)
    return ctx


def capture_context_generic(kube="kubectl"):
    """Cluster context for non-OpenShift kubernetes (EKS/GKE/AKS/k3s).

    OpenShift-only surfaces (clusterversion, apiserver encryption CR, ingresscontroller TLS profile)
    are unavailable here: record the server version and the crypto signals that ARE portable
    (HSM indicators), and leave the rest to Ingress + endpoint capture.
    """
    ctx = {"platform": "kubernetes"}
    ver = run(f"{kube} version -o json 2>/dev/null")
    kv = "unknown"
    if ver:
        try:
            kv = json.loads(ver).get("serverVersion", {}).get("gitVersion", "unknown")
        except Exception:
            kv = "unknown"
    ctx["kube_version"] = kv
    ctx["ocp_version"] = "unknown"  # keep the key the downstream report reads; not OpenShift
    ctx["hsm_indicators"] = _hsm_indicators(kube)
    ctx["note"] = ("non-OpenShift kubernetes: Route/ingresscontroller-TLS/etcd-encryption context not "
                   "available; transport TLS captured via Ingress + endpoints.")
    return ctx


# Hostname (RFC 1123 labels), IPv4, or bracketed IPv6. Anything else is rejected before it can
# reach a shell command line.
_HOST_RE = re.compile(
    r"^(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:.]+\])$")


# Kubernetes object name (DNS-1123 subdomain).
_K8S_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$")
# --kube-cli: a command name or path, nothing a shell would interpret.
_CLI_RE = re.compile(r"^[A-Za-z0-9_./+-]{1,255}$")


def valid_host(host):
    return bool(host) and len(host) <= 253 and bool(_HOST_RE.fullmatch(host)) and "\n" not in host


def _hp(host, port):
    """Shell-quoted host:port and host for openssl command lines (host already validated)."""
    return shlex.quote(f"{host}:{int(port)}"), shlex.quote(host)


# s_client prints its handshake summary ("New, <version>, Cipher is <suite>" through the next "---" line) before
# it reads any application data, and everything it prints after that summary can be bytes the server chose to send
# (GHSA-62fw-vjj2-r4p2). Output is parsed only up to the end of that summary, and only from lines s_client itself
# starts (anchored matches), so a server cannot forge a key-exchange group, protocol, cipher or certificate.
_SUMMARY_START = re.compile(r"^(?:New|Reused), (?:TLSv[\d.]+|SSLv\d|\(NONE\)), Cipher is ", re.M)
_SUMMARY_END = re.compile(r"^---$", re.M)
# The same cut for shell pipelines (enumeration, certificate and chain capture): print up to the end of the summary.
_HS_CUT = "awk '{print} /^(New|Reused), /{s=1} s && /^---$/{exit}'"


def _handshake_part(out):
    """The part of s_client output that s_client wrote about the handshake; anything after it is dropped."""
    out = out or ""
    m = _SUMMARY_START.search(out)
    if not m:
        return out  # no summary: the handshake did not complete, so the server could send no application data
    end = _SUMMARY_END.search(out, m.end())
    return out[:end.end()] if end else out


_CIPHER_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")


def _parse_session(out):
    """Negotiated protocol version and cipher suite from openssl s_client output (handshake part only)."""
    out = _handshake_part(out)
    proto = cipher = None
    m = re.search(r"^New, (TLSv[\d.]+|SSLv\d), Cipher is (\S+)$", out, re.M)
    if m:
        proto, cipher = m.group(1), m.group(2)
    m = re.search(r"^\s*Protocol\s*:\s*(TLSv[\d.]+|SSLv\d)\s*$", out, re.M)
    if m:
        proto = m.group(1)
    m = re.search(r"^\s*Cipher\s*:\s*(\S+)\s*$", out, re.M)
    if m and m.group(1) not in ("0000", "(NONE)"):
        cipher = m.group(1)
    if cipher and not _CIPHER_NAME.fullmatch(cipher):
        cipher = None
    return proto, cipher


_KEX_GROUPS = "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:X25519:secp256r1:secp384r1:MLKEM1024:MLKEM768"
# What OpenSSL in FIPS mode will offer: no X25519-based groups.
_KEX_GROUPS_FIPS = "SecP256r1MLKEM768:SecP384r1MLKEM1024:secp256r1:secp384r1:secp521r1"
_PQC_HYBRIDS = ("x25519mlkem768", "secp256r1mlkem768", "secp384r1mlkem1024", "mlkem")


# Key-exchange group names s_client prints (Negotiated TLS1.3 group, or the Temp Key curve or algorithm), lowercase.
# A group name outside this list, or not in a strict charset, is recorded as UNPARSED_GROUP (Manual review), never
# as a name that carries a verdict.
KNOWN_GROUPS = frozenset(x.lower() for x in (
    "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM512", "MLKEM768", "MLKEM1024",
    "X25519", "X448", "secp256r1", "prime256v1", "secp384r1", "secp521r1",
    "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1",
    "brainpoolP256r1tls13", "brainpoolP384r1tls13", "brainpoolP512r1tls13",
    "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192", "DH",
    # legacy TLS 1.2 curves (OpenSSL 3.5 still negotiates them when offered)
    "secp160k1", "secp160r1", "secp160r2", "secp192k1", "secp192r1", "prime192v1", "secp224k1", "secp224r1",
    "secp256k1", "sect163k1", "sect163r1", "sect163r2", "sect193r1", "sect193r2", "sect233k1", "sect233r1",
    "sect239k1", "sect283k1", "sect283r1", "sect409k1", "sect409r1", "sect571k1", "sect571r1"))
UNPARSED_GROUP = "unparsed-kex-group"
_GROUP_NAME = re.compile(r"[A-Za-z0-9_-]{1,40}")
_TEMP_KEY = re.compile(r"([A-Za-z0-9_-]{1,40})(?:, ([A-Za-z0-9_-]{1,40}))?, (\d{1,5}) bits")


def _parse_kex_group(out):
    """Key-exchange group from openssl s_client output (OpenSSL 3.0 to 3.5 formats), handshake part only.

    None: no group line (no handshake, or a key exchange with no group such as static RSA). UNPARSED_GROUP: a group
    line whose value is not a known group name. An ML-KEM group counts only when the same handshake negotiated
    TLS 1.3 (TLS 1.2 has no ML-KEM key exchange)."""
    hs = _handshake_part(out)
    name = None
    m = re.search(r"^Negotiated TLS1\.3 group: (.*)$", hs, re.M)
    if m and m.group(1).strip() not in ("", "<NULL>", "NULL"):
        name = m.group(1).strip()
    else:
        # "Peer Temp Key: ECDH, prime256v1, 256 bits" / "Server Temp Key: X25519, 253 bits" / "DH, 2048 bits"
        m = re.search(r"^(?:Peer|Server) Temp Key: (.*)$", hs, re.M)
        if not m:
            return None
        t = _TEMP_KEY.fullmatch(m.group(1).strip())
        if not t:
            return UNPARSED_GROUP
        first, second = t.group(1), t.group(2)
        name = second if first.upper() == "ECDH" and second else first
    if not _GROUP_NAME.fullmatch(name) or name.lower() not in KNOWN_GROUPS:
        return UNPARSED_GROUP
    if _is_pqc_group(name) and _parse_session(hs)[0] != "TLSv1.3":
        return UNPARSED_GROUP
    return name


def _temp_key_bits(out):
    """Bits on the Temp Key line of the handshake part, or None."""
    m = re.search(r"^(?:Peer|Server) Temp Key: (.*)$", _handshake_part(out), re.M)
    t = _TEMP_KEY.fullmatch(m.group(1).strip()) if m else None
    return int(t.group(3)) if t else None


def _check_mlkem_claim(group, enumeration):
    """(group, note): an ML-KEM group from one handshake is not recorded when the enumeration ran and found the
    server refuses that group (the two observations contradict each other); the key exchange is then unknown."""
    en = enumeration or {}
    if not _is_pqc_group(group) or en.get("status") != "complete":
        return group, None
    state = next((ok for g, ok in (en.get("groups") or {}).items() if g.lower() == group.lower()), None)
    if state is False:
        return UNPARSED_GROUP, (f"a handshake reported {group}, but the enumeration found that the server refuses "
                                f"it; the key exchange is not recorded as ML-KEM")
    return group, None


def _is_pqc_group(g):
    return bool(g) and any(h in g.lower() for h in _PQC_HYBRIDS)


def _container_s_client(host, port, image, groups, version=False):
    """openssl s_client output from inside the probe container (raw text; empty on failure)."""
    inner = (
        # The image must ship OpenSSL >= 3.5; nothing is installed at run time (no unpinned packages).
        f"command -v openssl >/dev/null 2>&1 || {{ echo 'kex-probe-image-has-no-openssl'; exit 3; }}; "
        + ("echo \"TOOL: $(openssl version)\"; " if version else "")
        + f"echo | timeout 8 openssl s_client -connect {_hp(host, port)[0]} "
        f"-servername {_hp(host, port)[1]} -groups {groups} 2>&1"
    )
    try:
        p = subprocess.run(
            ["podman", "run", "--rm", "--pull=never", image, "sh", "-c", inner],
            capture_output=True, text=True, timeout=90
        )
        return p.stdout + p.stderr
    except Exception as e:
        sys.stderr.write(f"[warn] kex container probe {host}: {e}\n")
        return ""


def _probe_kex_group_container(host, port, image):
    """Run kex probe inside a non-FIPS container (Alpine edge ships OpenSSL 3.5 w/ ML-KEM groups)."""
    return _parse_kex_group(_container_s_client(host, port, image, _KEX_GROUPS))


# Built by setup.sh from images/kex-probe/Containerfile (pinned Alpine + openssl 3.5.9-r0); the image
# ID is recorded in toolkit.lock. Used only if present locally; never pulled.
DEFAULT_KEX_PROBE_IMAGE = "localhost/fedlin-kex-probe:0.1"
_probe_image_cache = []


def _default_probe_image():
    if not _probe_image_cache:
        ok = bool(shutil.which("podman")) and subprocess.run(
            ["podman", "image", "exists", DEFAULT_KEX_PROBE_IMAGE], capture_output=True).returncode == 0
        _probe_image_cache.append(DEFAULT_KEX_PROBE_IMAGE if ok else "")
    return _probe_image_cache[0]


def _probe_kex_group(host, port=443):
    """Probe the key-exchange group the server negotiates.

    Returns (group_or_None, method, offer_complete). offer_complete is False when the client could
    not offer every group in _KEX_GROUPS (a FIPS-mode OpenSSL refuses X25519-based groups). A PQC
    hybrid accepted from a reduced offer is still definitive; a classical result from a reduced offer
    says nothing about X25519MLKEM768, and the caller must not record it as the interface's key
    exchange.

    Order: host OpenSSL with the full offer; if the host refuses the offer, the bundled probe OpenSSL
    named by FEDLIN_KEX_PROBE_OPENSSL (set in the toolkit image); then the probe container
    (FEDLIN_KEX_PROBE_IMAGE or the image setup.sh builds); else the host with the FIPS-offerable subset.
    """
    hp, h = _hp(host, port)
    base = f"echo | timeout 8 openssl s_client -connect {hp} -servername {h} -groups "
    out = _handshake_part(run(base + _KEX_GROUPS + " 2>&1"))
    if "SSL_CONF_cmd" not in out:
        grp = _parse_kex_group(out)
        if not grp:     # one retry: a dropped handshake must not turn into an Incomplete verdict (1.7.0)
            out = _handshake_part(run(base + _KEX_GROUPS + " 2>&1"))
            grp = _parse_kex_group(out) if "SSL_CONF_cmd" not in out else None
        return grp, "host", True
    probe = os.environ.get("FEDLIN_KEX_PROBE_OPENSSL", "")
    if probe and os.path.isfile(probe) and os.access(probe, os.X_OK):
        grp = None
        for _ in range(2):      # one retry before falling back (1.7.0)
            pout = _handshake_part(run(f"echo | timeout 8 {shlex.quote(probe)} s_client -connect {hp} "
                                       f"-servername {h} -groups {_KEX_GROUPS} 2>&1"))
            if "SSL_CONF_cmd" in pout:
                break
            grp = _parse_kex_group(pout)
            if grp:
                break
        if grp:
            return grp, "bundled", True
    img = os.environ.get("FEDLIN_KEX_PROBE_IMAGE", "") or _default_probe_image()
    if img:
        grp = _probe_kex_group_container(host, port, img) or _probe_kex_group_container(host, port, img)
        if grp:
            return grp, "container", True
    out = run(base + _KEX_GROUPS_FIPS + " 2>&1")
    return _parse_kex_group(out), "host-fips-subset", False


# Classical-only client for the zero-legacy test (PKI Consortium PQCMM 4.3.1): every group offered is
# classical and TLS 1.2 (which has no PQC key exchange) is allowed, so a completed handshake means the server
# still accepts a key exchange that is not quantum-resistant. One handshake covers both versions. The offer is
# every classical TLS 1.3 group OpenSSL 3.5 implements (`openssl list -tls-groups`), the TLS 1.2 brainpool
# codepoints and every legacy TLS 1.2 curve the probe OpenSSL 3.5.9 accepts in a group list (checked one by one;
# it rejects sect163k1, sect233*, sect283*, sect409* and sect571*): a server that accepts only one of them must
# not pass as refusing classical key exchange. Curves below the client's security level are not sent.
_CLASSICAL_GROUPS = ("X25519:secp256r1:secp384r1:secp521r1:X448:brainpoolP256r1tls13:brainpoolP384r1tls13:"
                     "brainpoolP512r1tls13:brainpoolP256r1:brainpoolP384r1:brainpoolP512r1:"
                     "ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192:"
                     "secp224r1:secp224k1:secp256k1:secp192r1:secp192k1:secp160r1:secp160k1:secp160r2:"
                     "sect163r1:sect193r1:sect193r2:sect239k1")
# A FIPS-mode OpenSSL accepts the brainpool names but cannot compute those keys (the handshake then fails on the
# client side), so its reduced offer leaves them out; a rejection from it is never read as a refusal anyway.
_CLASSICAL_GROUPS_FIPS = ("secp256r1:secp384r1:secp521r1:secp224r1:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:"
                          "ffdhe8192")
_GROUP_SUPPORT = {}  # (binary, group list) -> the names in it that binary accepts


def _accepted_groups(binary, groups):
    """The names in a group list this OpenSSL accepts. OpenSSL rejects a whole -groups list for one name it does not
    know (3.0 and 3.1 have no brainpool*tls13), so each name is tried alone, once per run, against a closed port."""
    key = (binary, groups)
    if key not in _GROUP_SUPPORT:
        _GROUP_SUPPORT[key] = ":".join(
            g for g in groups.split(":")
            if "SSL_CONF_cmd" not in run(f"echo | timeout 3 {binary} s_client -connect 127.0.0.1:9 -groups {g} 2>&1"))
    return _GROUP_SUPPORT[key]


# Alerts that mean the server refused the offered parameters: handshake_failure (40) and
# insufficient_security (71). Any other failure (reset, HTTP on the port, a required client certificate in
# TLS 1.2, rate limiting) says nothing about key exchange and is not counted as a rejection.
_REFUSAL = re.compile(r"alert (handshake failure|insufficient security)|SSL alert number (40|71)\b")
# The server sent its certificate, so it had already chosen classical parameters in its ServerHello.
_PEER_CERT = re.compile(r"^(Server certificate|Certificate chain)$", re.M)


def _classical_result(out):
    """(outcome, protocol, cipher, group) from s_client output offering only classical key exchange.

    accepted: the handshake completed, or the server sent its certificate (it had chosen classical
    parameters even if the handshake then failed, e.g. on a client-certificate request). rejected: the
    server answered with handshake_failure or insufficient_security before sending a certificate.
    inconclusive: connected, but the handshake failed for another reason. None: no TCP connection.
    """
    out = _handshake_part(out)
    proto, cipher = _parse_session(out)
    if cipher:
        return "accepted", proto, cipher, _parse_kex_group(out)
    if "CONNECTED(" not in out:
        return None, None, None, None
    if _PEER_CERT.search(out) and "no peer certificate available" not in out:
        return "accepted", proto, None, _parse_kex_group(out)
    if _REFUSAL.search(out):
        return "rejected", None, None, None
    return "inconclusive", None, None, None


CLASSICAL_PROBE = True  # cleared by --no-classical-probe


def _probe_classical_only(host, port=443):
    """Offer only classical key exchange and record whether the server accepts it.

    Facts only: outcome (accepted / rejected / inconclusive / untested), what was negotiated, the client tool
    and version, and the command as run. Same client order as _probe_kex_group. A client whose OpenSSL
    lacks some names (3.0 and 3.1: the brainpool TLS 1.3 groups) offers the rest, X25519 and X448 included, after
    the bundled and container clients; a FIPS-mode client cannot offer X25519 or X448 and uses its own subset. A
    rejection from any reduced offer is 'inconclusive' (the server may accept a group not offered; the names are
    recorded); an acceptance from it is still an acceptance. A client that ran but got no TCP connection ends
    the probe as 'untested' rather than trying the next client.
    """
    hp, h = _hp(host, port)

    def s_client(binary, groups):
        return f"echo | timeout 8 {binary} s_client -connect {hp} -servername {h} -groups {groups}"

    def result(out, tool, cmd, complete, missing=None):
        outcome, proto, cipher, grp = _classical_result(out)
        outcome = outcome or "untested"
        if outcome == "rejected" and not complete:
            outcome = "inconclusive"
        r = {"outcome": outcome, "protocol": proto, "cipher": cipher, "group": grp,
             "tool": tool or "openssl (version not reported)", "command": cmd, "offer_complete": complete}
        if missing:
            r["not_offered"] = missing
        return r

    cmd = s_client("openssl", _CLASSICAL_GROUPS)
    out = _handshake_part(run(cmd + " 2>&1"))
    if "SSL_CONF_cmd" not in out:
        return result(out, run("openssl version"), cmd, True)
    probe = os.environ.get("FEDLIN_KEX_PROBE_OPENSSL", "")
    if probe and os.path.isfile(probe) and os.access(probe, os.X_OK):
        q = shlex.quote(probe)
        cmd = s_client(q, _CLASSICAL_GROUPS)
        pout = _handshake_part(run(cmd + " 2>&1"))
        if pout and "SSL_CONF_cmd" not in pout:
            return result(pout, run(f"{q} version"), cmd, True)
    img = os.environ.get("FEDLIN_KEX_PROBE_IMAGE", "") or _default_probe_image()
    if img:
        cout = _handshake_part(_container_s_client(host, port, img, _CLASSICAL_GROUPS, version=True))
        m = re.search(r"^TOOL: (.+)$", cout, re.M)
        if m:  # the container ran its OpenSSL; whatever it saw is the answer
            inner = s_client("openssl", _CLASSICAL_GROUPS) + " 2>&1"
            return result(cout, m.group(1).strip(), f"podman run --rm --pull=never {img} sh -c "
                          + shlex.quote(inner), True)
    known = _accepted_groups("openssl", _CLASSICAL_GROUPS).split(":")
    if "X25519" in known:  # an older OpenSSL, not in FIPS mode: offer the names it has
        missing = [g for g in _CLASSICAL_GROUPS.split(":") if g not in known]
        # A build that lacks only legacy curves (RHEL drops the binary sect* curves) still makes a complete modern
        # offer: those names are recorded as not offered, but a rejection stays a rejection (1.7.0; before, one
        # missing legacy name made every rejection "inconclusive").
        complete = all(g in _ENUM_LEGACY_CURVES for g in missing)
        cmd = s_client("openssl", ":".join(known))
        return result(_handshake_part(run(cmd + " 2>&1")), run("openssl version"), cmd, complete, missing)
    cmd = s_client("openssl", _CLASSICAL_GROUPS_FIPS)
    return result(run(cmd + " 2>&1"), run("openssl version"), cmd, False)


# ---------- endpoint enumeration (what the server accepts, not only what one client negotiated) ----------
ENUMERATE = True  # cleared by --no-enumerate
ENUM_PACE = 0.0   # seconds between enumeration handshakes (--enumerate-pace)
NOT_CAPTURED = []  # endpoints that answered but completed no handshake with any scan client
_ENUM_VERSIONS = (("TLSv1", "-tls1"), ("TLSv1.1", "-tls1_1"), ("TLSv1.2", "-tls1_2"), ("TLSv1.3", "-tls1_3"))
_ENUM_TLS13_SUITES = ("TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256",
                      "TLS_AES_128_CCM_SHA256", "TLS_AES_128_CCM_8_SHA256")
_ENUM_GROUPS = ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM512", "MLKEM768", "MLKEM1024",
                "X25519", "X448", "secp256r1", "secp384r1", "secp521r1", "brainpoolP256r1tls13",
                "brainpoolP384r1tls13", "brainpoolP512r1tls13", "brainpoolP256r1", "brainpoolP384r1",
                "brainpoolP512r1", "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192")


def _enum_versions(g):
    """Protocol versions a group is offered in: ML-KEM and the *tls13 brainpool codepoints exist only in TLS 1.3,
    the plain brainpool codepoints only in TLS 1.2; the other classical groups in both (ECDHE / RFC 7919 DHE)."""
    low = g.lower()
    if "mlkem" in low or low.endswith("tls13"):
        return ("13",)
    if low.startswith("brainpool"):
        return ("12",)
    return ("13", "12")
_ENUM_SIGALGS = (("RSA", "rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha256:"
                         "rsa_pkcs1_sha384:rsa_pkcs1_sha512:rsa_pss_pss_sha256"),
                 ("ECDSA", "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512"),
                 ("EdDSA", "ed25519:ed448"),
                 ("ML-DSA", "mldsa44:mldsa65:mldsa87"))
# A TLS 1.3 handshake offering only the pure ML-KEM groups, with the certificate captured: an endpoint that accepts
# nothing else (CNSA 2.0 style) completes no other enumeration handshake and was dropped from the inventory (1.7.0)
_ENUM_PQ_ONLY = "MLKEM1024:MLKEM768:MLKEM512"
# A TLS 1.2 handshake offering only legacy curves (those the client binary accepts, checked in the script), with
# the certificate captured: an endpoint that accepts nothing else completed no other enumeration handshake and was
# recorded only as "answered but refused every handshake" (1.7.0)
_ENUM_LEGACY_CURVES = ("secp224r1", "secp224k1", "secp256k1", "secp192r1", "secp192k1", "secp160r1", "secp160k1",
                       "secp160r2", "sect163r1", "sect193r1", "sect193r2", "sect239k1")
_ENUM_MAX_SUITES = 40  # per protocol version; a server accepting more is recorded as truncated
_LEGACY = "'ALL:COMPLEMENTOFALL:@SECLEVEL=0'"
# Alerts the server sends when it refuses what was offered. Received alerts print "SSL alert number N";
# errors the client raises itself (e.g. "dh key too small") do not, and are never read as a server refusal.
_SERVER_REFUSAL = re.compile(r"SSL alert number (40|47|70|71)\b")
_CERT_MISMATCH = re.compile(r"wrong signature type|wrong certificate type|no suitable signature algorithm|"
                            r"unknown certificate type|unsupported certificate", re.I)
_VERSION_REFUSAL = re.compile(r"SSL alert number 70\b|alert protocol version")


def _enum_script(binary, hp, sni, pace=0.0):
    """POSIX sh that runs every enumeration handshake against one endpoint with one OpenSSL binary and prints
    tagged lines only (no certificate bodies, no private data). Each handshake has its own 6 s timeout."""
    o = f"timeout 6 {binary} s_client -connect {hp} -servername {sni}"
    # Only the handshake part of each output (_HS_CUT), so nothing the server sends as data is kept.
    keep = (_HS_CUT + " | grep -E '^(CONNECTED|New, |Negotiated TLS1.3 group|Peer Temp Key|Server Temp Key)|"
            "^ *Protocol *:|alert|:error:'")
    cert = (f"{_HS_CUT} | {binary} x509 -noout -subject -issuer -dates -fingerprint -sha256 -text 2>/dev/null "
            f"| grep -E "
            f"\"^(subject=|issuer=|notBefore=|notAfter=|sha256 Fingerprint=|SHA256 Fingerprint=)|"
            f"Public Key Algorithm:|Public-Key:|Signature Algorithm:\" | head -12")
    L = [f'echo "TOOL $({binary} version)"',
         f'echo "=== DEFAULT"; echo | {o} 2>&1 | {keep}',
         f'echo "=== LEGACY"; echo | {o} -cipher {_LEGACY} 2>&1 | {keep}']
    for name, flag in _ENUM_VERSIONS:
        sec = "" if name == "TLSv1.3" else f" -cipher {_LEGACY}"
        L.append(f'echo "=== VERSION {name}"; echo | {o} {flag}{sec} 2>&1 | {keep}')
    for suite in _ENUM_TLS13_SUITES:
        L.append(f'echo "=== SUITE TLSv1.3 {suite}"; echo | {o} -tls1_3 -ciphersuites {suite} 2>&1 | {keep}')
    for name, flag in _ENUM_VERSIONS[:3]:  # TLS 1.0-1.2: offer everything, remove what the server picks, repeat
        L.append(f'list={_LEGACY}; n=0; out=""; while [ $n -lt {_ENUM_MAX_SUITES} ]; do '
                 f'out=$(echo | {o} {flag} -cipher "$list" 2>&1); '
                 f'c=$(printf "%s\\n" "$out" | sed -n "s/^New, [^,]*, Cipher is //p" | head -1); '
                 f'case "$c" in ""|"(NONE)") break;; esac; '
                 f'echo "=== ITER {name} $c"; printf "%s\\n" "$out" | {keep}; '
                 f'list="$list:-$c"; n=$((n+1)); done; '
                 f'if [ $n -ge {_ENUM_MAX_SUITES} ]; then echo "=== TRUNCATED {name}"; '
                 f'elif [ $n -gt 0 ] && ! printf "%s\\n" "$out" | {_HS_CUT} | grep -q "SSL alert number"; then '
                 f'echo "=== INCOMPLETE {name}"; fi')
    for g in _ENUM_GROUPS:
        if "13" in _enum_versions(g):
            L.append(f'echo "=== GROUP13 {g}"; echo | {o} -tls1_3 -groups {g} 2>&1 | {keep}')
        if "12" in _enum_versions(g):
            L.append(f'echo "=== GROUP12 {g}"; echo | {o} -tls1_2 -cipher {_LEGACY} -groups {g} 2>&1 | {keep}')
    # Certificate probes keep the server's alerts too, so a probe with no answer is told apart from a refusal.
    for label, algs in _ENUM_SIGALGS:
        L.append(f'echo "=== CERT {label}"; out=$(echo | {o} -cipher {_LEGACY} -sigalgs {algs} 2>&1); '
                 f'printf "%s\\n" "$out" | {keep}; printf "%s\\n" "$out" | {cert}')
    L.append(f'echo "=== CERT ANY"; out=$(echo | {o} -cipher {_LEGACY} 2>&1); '
             f'printf "%s\\n" "$out" | {keep}; printf "%s\\n" "$out" | {cert}')
    L.append('lc=""; for g in ' + " ".join(_ENUM_LEGACY_CURVES) + '; do '
             f'echo | timeout 3 {binary} s_client -connect 127.0.0.1:9 -groups "$g" 2>&1 | grep -q SSL_CONF_cmd '
             '|| lc="$lc${lc:+:}$g"; done; '
             f'if [ -n "$lc" ]; then echo "=== LEGACYCURVES"; out=$(echo | {o} -tls1_2 -cipher {_LEGACY} -groups "$lc" 2>&1); '
             f'printf "%s\\n" "$out" | {keep}; printf "%s\\n" "$out" | {cert}; fi')
    L.append(f'echo "=== PQONLY"; out=$(echo | {o} -tls1_3 -groups {_ENUM_PQ_ONLY} 2>&1); '
             f'printf "%s\\n" "$out" | {keep}; printf "%s\\n" "$out" | {cert}')
    if pace and pace > 0:
        gap = f"; sleep {float(pace):g}; "
        L = [x.replace("n=$((n+1)); done", f"n=$((n+1)); sleep {float(pace):g}; done") for x in L]
        return gap.join(L)
    return "; ".join(L)


def _parse_enum(out):
    """Tagged enumeration output -> facts.

    accepted (True) only when the handshake completed (and, for a group, on that group); refused (False)
    only when the server sent a refusal alert (for a protocol version, the protocol_version alert);
    otherwise None: no answer, or not testable with this client (e.g. the server's only suites are ones the
    client does not implement). None is never read as refused."""
    sections, cur = {}, None
    for line in out.splitlines():
        if line.startswith("=== "):
            cur = line[4:].strip()
            sections[cur] = []
        elif line.startswith("TOOL "):
            sections["TOOL"] = [line[5:].strip()]
        elif cur:
            sections[cur].append(line)
    text = lambda k: "\n".join(sections.get(k, []))  # noqa: E731
    res = {"tool": (sections.get("TOOL") or ["openssl"])[0], "versions": {}, "suites": {}, "groups": {},
           "dh_bits": [], "certs": [], "truncated": [], "incomplete": [], "cert_probes": {}}
    for key in ("default", "legacy"):
        t = text(key.upper())
        proto, cipher = _parse_session(t)
        res[key] = {"protocol": proto, "cipher": cipher, "group": _parse_kex_group(t) if cipher else None}

    res["version_sessions"] = {}
    for name, _ in _ENUM_VERSIONS:
        k = f"VERSION {name}"
        if k in sections:
            t = text(k)
            p_, c_ = _parse_session(t)
            res["versions"][name] = True if c_ else (False if _VERSION_REFUSAL.search(t) else None)
            if c_:
                res["version_sessions"][name] = {"protocol": p_ or name, "cipher": c_, "group": _parse_kex_group(t)}
    # did the server answer at all (TCP + a TLS alert), even if no handshake completed with these clients?
    res["server_answered"] = any("CONNECTED(" in "\n".join(v) and _SERVER_REFUSAL.search("\n".join(v))
                                 for v in sections.values())
    group_states = {}
    for k in sections:
        if k.startswith("SUITE TLSv1.3 ") and _parse_session(text(k))[1]:
            res["suites"].setdefault("TLSv1.3", []).append(k.split()[-1])
        elif k.startswith("ITER "):
            _, ver, suite = k.split(" ", 2)
            res["suites"].setdefault(ver, []).append(suite)
            m = re.search(r"(?:Peer|Server) Temp Key:\s*DH,\s*(\d+) bits", text(k))
            if m:
                res["dh_bits"].append(int(m.group(1)))
        elif k.startswith("TRUNCATED "):
            res["truncated"].append(k.split()[-1])
        elif k.startswith("INCOMPLETE "):
            res["incomplete"].append(k.split()[-1])
        elif k.startswith(("GROUP13 ", "GROUP12 ")):
            g = k.split()[-1]
            t = text(k)
            got = _parse_kex_group(t)
            if _parse_session(t)[1]:
                same = got and (got.lower() == g.lower() or g.lower() in _GROUP_ALIASES.get(got.lower(), ()))
                # TLS 1.3 negotiates finite-field DH only as a named group: "DH, 4096 bits" offered ffdhe4096 alone
                # is that group (TLS 1.2 DHE uses parameters the server picks, so it proves nothing there).
                same = same or (k.startswith("GROUP13 ") and got == "DH" and g.lower().startswith("ffdhe")
                                and _parse_session(t)[0] == "TLSv1.3" and str(_temp_key_bits(t)) == g[5:])
                state = True if same else None  # completed without that group (e.g. static RSA): no evidence
            else:
                state = False if _SERVER_REFUSAL.search(t) else None
            group_states.setdefault(g, []).append(state)
        elif k in ("PQONLY", "LEGACYCURVES"):
            t = text(k)
            p_, c_ = _parse_session(t)
            if c_:
                pq = k == "PQONLY"
                ver = p_ or ("TLSv1.3" if pq else "TLSv1.2")
                sess = {"protocol": ver, "cipher": c_, "group": _parse_kex_group(t)}
                res["pq_only" if pq else "legacy_curves"] = sess
                if res["versions"].get(ver) is not True:
                    res["versions"][ver] = True              # a completed handshake at that version
                    res["version_sessions"].setdefault(ver, sess)
                # accepted, judged as configuration: only a legacy curve the offer named (a server may pick a DHE
                # or static-RSA suite instead, which proves nothing about the curves)
                legacy = {g.lower() for g in _ENUM_LEGACY_CURVES} | {"prime192v1"}
                if not pq and sess["group"] and sess["group"].lower() in legacy:
                    group_states.setdefault(sess["group"], []).append(True)
                elif not pq:
                    res.pop("legacy_curves", None)
                c = _parse_cert_text(t)
                if c and not any(x["fingerprint"] == c["fingerprint"] for x in res["certs"]):
                    c["requested"] = "ML-KEM only" if pq else "legacy curves only"
                    res["certs"].append(c)
        elif k.startswith("CERT "):
            c = _parse_cert_text(text(k))
            # certificate: the server presented one; refused: it sent a refusal alert; None: no answer
            # (a client that aborts because the server sent a certificate of another family was answered too)
            # refused and mismatch need a connection: a client that fails its own setup has asked nothing
            connected = "CONNECTED(" in text(k)
            res["cert_probes"][k.split(" ", 1)[1]] = "certificate" if c else (
                "refused" if connected and _SERVER_REFUSAL.search(text(k)) else
                "mismatch" if connected and _CERT_MISMATCH.search(text(k)) else None)
            if c:
                c["requested"] = k.split(" ", 1)[1]
                res.setdefault("cert_probe_keys", {})[c["requested"]] = c.get("key_alg") or "unparsed"
                if not any(x["fingerprint"] == c["fingerprint"] for x in res["certs"]):
                    res["certs"].append(c)
    for g, states in group_states.items():
        # accepted in any version; refused only if every tested version refused it
        res["groups"][g] = True if True in states else (False if states and all(x is False for x in states) else None)
    res["dh_bits"] = sorted(set(res["dh_bits"]))
    return res


# OpenSSL reports some groups under other names (Temp Key lines)
_GROUP_ALIASES = {"prime256v1": ("secp256r1",), "secp256r1": ("secp256r1",), "secp384r1": ("secp384r1",),
                  "secp521r1": ("secp521r1",), "x25519": ("x25519",), "x448": ("x448",),
                  "brainpoolp256r1": ("brainpoolp256r1", "brainpoolp256r1tls13"),
                  "brainpoolp384r1": ("brainpoolp384r1", "brainpoolp384r1tls13"),
                  "brainpoolp512r1": ("brainpoolp512r1", "brainpoolp512r1tls13")}


def _parse_cert_text(t):
    def g(pat):
        m = re.search(pat, t, re.M)
        return m.group(1).strip() if m else None
    fp = g(r"(?i)sha256 Fingerprint=(\S+)")
    if not fp:
        return None
    bits = g(r"Public-Key:\s*\((\d+)\s*bit\)")
    return {"fingerprint": fp.replace(":", "").lower(), "subject": g(r"^subject=(.*)$"), "issuer": g(r"^issuer=(.*)$"),
            "not_before": _rfc3339(g(r"^notBefore=(.*)$")), "not_after": _rfc3339(g(r"^notAfter=(.*)$")),
            "key_alg": g(r"Public Key Algorithm:\s*(\S+)") or "unparsed-public-key-algorithm",
            "key_bits": int(bits) if bits else None, "sig_alg": g(r"Signature Algorithm:\s*(\S+)")}


def _enum_client():
    """The OpenSSL to enumerate with: one that can offer legacy versions and ML-KEM groups (not FIPS mode).
    Returns (runner, label) or (None, reason)."""
    if "SSL_CONF_cmd" not in run("echo | timeout 3 openssl s_client -connect 127.0.0.1:9 -groups X25519MLKEM768 2>&1"):
        return (lambda script: run(script, timeout=900)), "host"
    probe = os.environ.get("FEDLIN_KEX_PROBE_OPENSSL", "")
    if probe and os.path.isfile(probe) and os.access(probe, os.X_OK):
        return (lambda script: run(script.replace("{OPENSSL}", shlex.quote(probe)), timeout=900)), "bundled"
    img = os.environ.get("FEDLIN_KEX_PROBE_IMAGE", "") or _default_probe_image()
    if img:
        def runner(script):
            try:
                p = subprocess.run(["podman", "run", "--rm", "--pull=never", img, "sh", "-c", script],
                                   capture_output=True, text=True, timeout=900)
                return p.stdout
            except Exception as e:
                sys.stderr.write(f"[warn] enumeration container: {e}\n")
                return ""
        return runner, "container"
    return None, "no OpenSSL able to offer legacy versions and ML-KEM groups (FIPS host without probe image)"


def _extra_certificates(c):
    """Certificates the endpoint serves besides the one the default handshake returned (e.g. an RSA
    certificate next to an ECDSA one), from enumeration. Matched on key type, size, signature and expiry."""
    en = c.get("enumeration") or {}
    out = []
    for x in en.get("certs", []) or []:
        if c.get("fingerprint"):
            same = x.get("fingerprint") == c["fingerprint"]
        else:
            same = (x.get("key_alg"), x.get("key_bits"), x.get("sig_alg"), x.get("not_after")) == \
                   (c.get("key_alg"), c.get("key_bits"), c.get("sig_alg"), c.get("not_after"))
        if not same:
            out.append(dict(x, host=c["host"]))
    return out


def enumerate_endpoint(host, port=443):
    """Every accepted protocol version, cipher suite, key-exchange group and served certificate type.
    Facts only; the policy stage judges them. Returns None when enumeration is off."""
    if not ENUMERATE:
        return None
    runner, how = _enum_client()
    if runner is None:
        return {"status": "untested", "reason": how}
    hp, h = _hp(host, port)
    binary = "{OPENSSL}" if how == "bundled" else "openssl"
    res = _parse_enum(runner(_enum_script(binary, hp, h, ENUM_PACE)))
    res["status"], res["client"] = "complete", how
    if not any(v is True for v in res["versions"].values()):
        res["status"] = "untested"  # no handshake completed at all
    return res


def capture_cert(host, port=443):
    if not valid_host(host):
        sys.stderr.write(f"[warn] endpoint {host!r}: not a valid hostname or IP, skipped\n")
        return None
    hp, h = _hp(host, port)
    base = (f"echo | timeout 8 openssl s_client -connect {hp} -servername {h} 2>/dev/null | {_HS_CUT} "
            f"| openssl x509 -noout")
    meta = run(base + " -subject -issuer -dates -fingerprint -sha256")
    text = run(base + " -text")
    if not text:
        # The host OpenSSL could not complete a handshake (e.g. FIPS mode against a server that only speaks
        # TLS 1.0 or legacy suites). Those are the endpoints that matter most: capture them with the
        # enumeration client instead of dropping them as unreachable.
        return _capture_via_enumeration(host, port)

    def grab(pat, s):
        m = re.search(pat, s)
        return m.group(1).strip() if m else None
    key_bits = grab(r"Public-Key:\s*\((\d+)\s*bit\)", text)
    key_alg = grab(r"Public Key Algorithm:\s*(\S+)", text)
    sig_alg = grab(r"Signature Algorithm:\s*(\S+)", text)
    fp = grab(r"(?i)sha256 Fingerprint=(\S+)", meta)
    # Count only the certificates s_client printed for the handshake: PEM blocks the server sends afterwards as
    # application data would otherwise inflate the chain depth.
    chain = run(f"echo | timeout 8 openssl s_client -connect {hp} -servername {h} "
                f"-showcerts 2>/dev/null | {_HS_CUT} | grep -c '^-----BEGIN CERTIFICATE-----$'")
    tls_protocol, tls_cipher = _parse_session(
        run(f"echo | timeout 8 openssl s_client -connect {hp} -servername {h} 2>&1"))
    kex_group, kex_probe_via, kex_complete = _probe_kex_group(host, port)
    kex_partial = None
    if kex_group and not kex_complete and not _is_pqc_group(kex_group):
        # Reduced (FIPS) offer ended classical: not evidence about X25519MLKEM768. Keep it as partial
        # evidence only; the interface's key exchange stays unknown.
        kex_partial = (f"FIPS-mode client could not offer X25519MLKEM768; server declined "
                       f"SecP256r1MLKEM768/SecP384r1MLKEM1024 and negotiated {kex_group} with this client")
        kex_group = None
    classical_only = _probe_classical_only(host, port) if CLASSICAL_PROBE else None
    enumeration = enumerate_endpoint(host, port)
    if enumeration and enumeration.get("status") == "complete":
        d = _enum_session(enumeration)
        if not tls_cipher:
            # A FIPS-mode host OpenSSL can fail a TLS 1.2 handshake (e.g. no extended master secret); the
            # enumeration client's handshake is the observed session then.
            tls_protocol, tls_cipher = tls_protocol or d.get("protocol"), d.get("cipher")
        if not kex_group and not kex_partial and d.get("group"):
            kex_group, kex_probe_via = d["group"], f"enumeration client ({enumeration.get('client')})"
    if not kex_group and not kex_partial and classical_only and classical_only.get("group") and enumeration \
            and enumeration.get("status") == "complete" and enumeration.get("groups") \
            and not any(ok for g, ok in enumeration["groups"].items() if "mlkem" in g.lower()) \
            and all(ok is False for g, ok in enumeration["groups"].items() if "mlkem" in g.lower()):
        # The server refused every ML-KEM group, so a full-offer client gets a classical group too; the group the
        # classical-only handshake negotiated is an observed key exchange for this endpoint.
        kex_group, kex_probe_via = classical_only["group"], "classical-probe (server refused every ML-KEM group)"
    if not tls_cipher and classical_only and classical_only.get("cipher"):
        # e.g. a server that requests a client certificate: the classical probe saw its session parameters
        tls_protocol, tls_cipher = tls_protocol or classical_only.get("protocol"), classical_only.get("cipher")
    kex_group, kex_note = _check_mlkem_claim(kex_group, enumeration)
    return {
        "host": host if port == 443 else f"{host}:{port}",
        "subject": grab(r"subject=(.*)", meta),
        "issuer": grab(r"issuer=(.*)", meta),
        "not_before": _rfc3339(grab(r"notBefore=(.*)", meta)),
        "not_after": _rfc3339(grab(r"notAfter=(.*)", meta)),
        # Never default to RSA: an unparsed key algorithm is reported as unparsed (Manual review).
        "key_alg": key_alg or "unparsed-public-key-algorithm",
        "key_bits": int(key_bits) if key_bits else None,
        "sig_alg": sig_alg,
        "chain_depth": _int(chain) or None,
        "kex_group": kex_group,
        "tls_protocol": tls_protocol,
        "tls_cipher": tls_cipher,
        "kex_probe_via": kex_probe_via,
        "kex_partial": kex_partial,
        "kex_note": kex_note,
        "classical_only": classical_only,
        "enumeration": enumeration,
        "fingerprint": fp.replace(":", "").lower() if fp else None,
    }


def _enum_session(en):
    """The session the enumeration observed: the modern default offer, else the legacy offer, else the
    highest protocol version that completed."""
    for k in ("default", "legacy"):
        if (en.get(k) or {}).get("cipher"):
            return en[k]
    vs = en.get("version_sessions") or {}
    for name, _ in reversed(_ENUM_VERSIONS):
        if name in vs:
            return vs[name]
    return {}


def _capture_via_enumeration(host, port):
    """Certificate and session from the enumeration client, for endpoints the host OpenSSL cannot reach."""
    if not ENUMERATE:
        return None
    en = enumerate_endpoint(host, port)
    if en and en.get("status") != "complete" and en.get("server_answered"):
        hp_ = host if port == 443 else f"{host}:{port}"
        return {"host": hp_, "no_handshake": "the server answered but refused every handshake from the scan clients; "
                                              "it may offer only suites they do not implement (3DES, RC4, export)"}
    if not en or en.get("status") != "complete" or not en.get("certs"):
        return None
    certs = en["certs"]
    primary = next((c for c in certs if c.get("requested") == "ANY"), certs[0])
    sess = _enum_session(en)
    classical_only = _probe_classical_only(host, port) if CLASSICAL_PROBE else None
    grp, kex_note = _check_mlkem_claim(sess.get("group"), en)
    return {
        "host": host if port == 443 else f"{host}:{port}",
        "subject": primary.get("subject"), "issuer": primary.get("issuer"),
        "not_before": primary.get("not_before"), "not_after": primary.get("not_after"),
        "key_alg": primary.get("key_alg") or "unparsed-public-key-algorithm", "key_bits": primary.get("key_bits"),
        "sig_alg": primary.get("sig_alg"), "chain_depth": None,
        # the enumeration client offers every group; what it negotiated is the endpoint's key exchange
        "kex_group": grp, "tls_protocol": sess.get("protocol"), "tls_cipher": sess.get("cipher"),
        "kex_probe_via": f"enumeration client ({en.get('client')}); the host OpenSSL could not connect",
        "kex_partial": None, "kex_note": kex_note, "classical_only": classical_only, "enumeration": en,
        "fingerprint": primary.get("fingerprint"),
    }


def _rfc3339(s):
    if not s:
        return None
    try:
        dt = datetime.datetime.strptime(s.replace(" GMT", ""), "%b %d %H:%M:%S %Y")
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def capture_routes(kube="oc"):
    hosts = run(f"{kube} get routes -A -o jsonpath='{{range .items[*]}}{{.spec.host}}{{\"\\n\"}}{{end}}'")
    hosts = sorted(set(h for h in hosts.splitlines() if h))
    return capture_endpoints(hosts)  # same bounded thread pool as --endpoints


def capture_ingress(kube="kubectl"):
    """Live TLS capture over generic-kubernetes Ingress hosts (the non-OpenShift Route analogue).

    Reads Ingress rule hosts and TLS hosts (public object fields only), then does the same
    public-certificate handshake capture as the Route path. Works on any k8s
    (EKS/GKE/AKS/k3s) with an Ingress controller.
    """
    rule_hosts = run(f"{kube} get ingress -A -o jsonpath='{{range .items[*]}}{{range .spec.rules[*]}}{{.host}}{{\"\\n\"}}{{end}}{{end}}'")
    tls_hosts = run(f"{kube} get ingress -A -o jsonpath='{{range .items[*]}}{{range .spec.tls[*]}}{{range .hosts[*]}}{{@}}{{\"\\n\"}}{{end}}{{end}}{{end}}'")
    hosts = sorted(set(h for h in (rule_hosts + "\n" + tls_hosts).splitlines() if h))
    return capture_endpoints(hosts)  # same bounded thread pool as --endpoints


def _canon_endpoint(tok):
    """host:443 and host name the same endpoint (one TLS interface, unique bom-refs)."""
    h, sep, p = tok.rpartition(":")
    return h if sep and p == "443" and ":" not in h else tok


def parse_endpoints(values):
    """Expand --endpoints values into a deduped, order-preserving list of host[:port] tokens.

    Each value is either a path to a file (one endpoint per line, '#' comments allowed) or an
    inline comma/space-separated list. Tokens are normalized: scheme and path are stripped, so
    'https://mail.agency.gov/owa' -> 'mail.agency.gov'. This is the no-cluster on-ramp: the
    modal thin-footprint agency hands over a list of hostnames, not a kubeconfig.
    """
    tokens, out, seen = [], [], set()
    for v in values:
        if os.path.exists(v):
            with open(v) as f:
                for ln in f:
                    ln = ln.split("#", 1)[0].strip()
                    if ln:
                        tokens += re.split(r"[,\s]+", ln)
        else:
            tokens += re.split(r"[,\s]+", v)
    for t in tokens:
        t = re.sub(r"^[a-zA-Z]+://", "", t.strip())  # strip scheme
        t = t.split("/", 1)[0]                        # strip any path
        if t.count(":") > 1 and not t.startswith("["):
            try:                                      # a bare IPv6 address: 2001:db8::1 -> [2001:db8::1]
                t = "[" + str(ipaddress.IPv6Address(t)) + "]"
            except ValueError:
                pass
        m = re.match(r"^\[([0-9A-Fa-f:.]+)\](?::(\d+))?$", t)  # [IPv6] or [IPv6]:port
        port = None
        if m:
            host = "[" + m.group(1) + "]"
            port = m.group(2)
            t = host if not port or port == "443" else f"{host}:{port}"
        else:
            t = _canon_endpoint(t)
            host = t.rsplit(":", 1)[0] if t.count(":") == 1 else t
            port = t.rsplit(":", 1)[1] if t.count(":") == 1 else None
        if not t or t in seen:
            continue
        if port is not None and not (port.isdigit() and 1 <= int(port) <= 65535):
            sys.stderr.write(f"[warn] --endpoints: {t!r}: the port must be a number from 1 to 65535, skipped\n")
            continue
        if not valid_host(host):
            sys.stderr.write(f"[warn] --endpoints: {t!r} is not a valid hostname or IP, skipped\n")
            continue
        seen.add(t)
        out.append(t)
    return out


def capture_endpoints(hosts, workers=16):
    """Live TLS cert capture over an explicit host[:port] list (no cluster needed).

    Reuses capture_cert (public certificate metadata only: never a private key or secret value),
    so it inherits the same no-secret-values contract as the cluster-route path.

    Parallelized: the per-host cost is an I/O-bound openssl handshake (and unreachable hosts sit
    on an 8s timeout), so a serial scan of an estate-sized list ran for hours. A bounded thread
    pool cuts that to roughly the slowest single host. Results are returned in INPUT ORDER for
    deterministic, reproducible CBOMs.
    """
    import concurrent.futures as _cf

    def _one(tok):
        host, port = tok, 443
        h, sep, p = tok.rpartition(":")
        if sep and p.isdigit():
            host, port = h, int(p)
        c = capture_cert(host, port)
        if c and c.get("no_handshake"):
            sys.stderr.write(f"[warn] endpoint {tok}: {c['no_handshake']}\n")
            NOT_CAPTURED.append(f"{c['host']}: {c['no_handshake']}")
            return None
        if not c:
            sys.stderr.write(f"[warn] endpoint {tok}: no TLS certificate retrieved "
                             f"(unreachable, or no TLS on :{port})\n")
        return c

    if not hosts:
        return []
    results = [None] * len(hosts)
    with _cf.ThreadPoolExecutor(max_workers=max(1, min(workers, len(hosts)))) as ex:
        futs = {ex.submit(_one, tok): i for i, tok in enumerate(hosts)}
        for fut in _cf.as_completed(futs):
            results[futs[fut]] = fut.result()
    return [c for c in results if c]


def capture_counts(kube="oc"):
    # both APIs are portable: kubernetes.io/tls is a core secret type; sealedsecrets is a CRD if present
    tls = run(f"{kube} get secrets -A --field-selector type=kubernetes.io/tls --no-headers 2>/dev/null | grep -c .")
    sealed = run(f"{kube} get sealedsecrets -A --no-headers 2>/dev/null | grep -c .")
    return {"tls_secrets": _int(tls), "sealed_secrets": _int(sealed)}


def _int(s):
    try:
        return int(s.strip())
    except Exception:
        return 0


def capture_fips(kube="oc", platform="openshift", debug_image=""):
    """Best-effort node FIPS check. INTRUSIVE: spins a short-lived debug pod; gated behind --deep.

    Uses `oc debug node` on OpenShift; falls back to `kubectl debug node` (k8s 1.20+) elsewhere.
    """
    node = run(f"{kube} get nodes -o jsonpath='{{.items[0].metadata.name}}'")
    # The node name comes from the cluster; only a valid Kubernetes name reaches a command line.
    if not node or not _K8S_NAME_RE.match(node):
        return "unknown"
    if platform == "openshift":
        v = run(f"{kube} debug node/{node} --to-namespace=default -q -- "
                f"chroot /host cat /proc/sys/crypto/fips_enabled", timeout=90).strip()
    else:
        # kubectl debug node needs an image. No default: an unpinned image in a privileged node pod is
        # exactly what this toolkit flags elsewhere, so the operator names one, pinned by digest.
        if not debug_image:
            return "not checked (non-OpenShift --deep needs --debug-image <image@sha256:...>)"
        v = run(f"{kube} debug node/{node} -q --image={shlex.quote(debug_image)} -- "
                f"cat /host/proc/sys/crypto/fips_enabled", timeout=90).strip()
    return {"1": "enabled", "0": "disabled"}.get(v, "unknown")


def read_local_fips():
    """FIPS mode of the environment the scan itself runs in (this host / in-boundary container).

    Non-intrusive read of the local kernel flag: no cluster needed. In endpoint/no-runtime mode
    there is no cluster node to probe, but recording whether the assessment *executed* under FIPS is
    real RMF evidence (SC-13). Labelled 'scan host' to distinguish it from the scanned target's FIPS,
    which an endpoint scan cannot observe.
    """
    try:
        with open("/proc/sys/crypto/fips_enabled") as f:
            v = f.read().strip()
    except Exception:
        return "unknown (scan host)"
    return {"1": "enabled (scan host)", "0": "disabled (scan host)"}.get(v, "unknown (scan host)")


def capture_ssh():
    ver = run("ssh -V 2>&1")
    t = run("sudo -n sshd -T 2>/dev/null")
    if not t:
        return None
    def line(prefix):
        for ln in t.splitlines():
            if ln.lower().startswith(prefix):
                return ln.split(None, 1)[1] if len(ln.split(None, 1)) > 1 else ""
        return ""
    # Host key sizes (1.8.0): sshd -T lists each HostKey path; the public half (<path>.pub) gives the type and size.
    # Only the .pub file is read, never the private key.
    sizes = []
    for ln in t.splitlines():
        parts = ln.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "hostkey":
            got = _ssh_key_size(run(f"ssh-keygen -l -f {shlex.quote(parts[1].strip() + '.pub')} 2>/dev/null"))
            if got:
                sizes.append(dict(got, file=parts[1].strip() + ".pub"))
    return {
        "version": ver,
        "kex": [x for x in line("kexalgorithms").split(",") if x],
        "ciphers": [x for x in line("ciphers").split(",") if x],
        "macs": [x for x in line("macs").split(",") if x],
        "hostkeys": [x for x in line("hostkeyalgorithms").split(",") if x],
        "hostkey_sizes": sizes,
    }


# ssh-keygen -l key types -> the name the ruleset judges (the key itself, not a signature scheme: "ssh-rsa" would
# read as an RSA signature with SHA-1)
_SSH_KEY_NAMES = {"RSA": "rsaEncryption", "DSA": "ssh-dss", "ED25519": "ssh-ed25519", "ED448": "ssh-ed448",
                  "ED25519-SK": "ssh-ed25519", "ECDSA-SK": "ecdsa-sha2-nistp256"}


def _ssh_key_size(out):
    """{"type", "bits", "name"} from `ssh-keygen -l` output ("3072 SHA256:... comment (RSA)"), or None."""
    m = re.match(r"^\s*(\d+)\s+\S+.*\(([A-Z0-9-]+)\)\s*$", (out or "").strip().splitlines()[0] if out else "")
    if not m:
        return None
    bits, typ = int(m.group(1)), m.group(2)
    if typ == "ECDSA":
        name = {256: "ecdsa-sha2-nistp256", 384: "ecdsa-sha2-nistp384", 521: "ecdsa-sha2-nistp521"}.get(bits)
    else:
        name = _SSH_KEY_NAMES.get(typ)
    return {"type": typ, "bits": bits, "name": name or f"unparsed-public-key-algorithm ({typ})"}


# ---------- build CycloneDX 1.6 ----------

def default_subject_tag(name, date=None):
    """RFC 4151 tag URI for the deployment. The authority must be a DNS name or e-mail the minter
    controls; without one supplied, '.invalid' (RFC 2606) marks the authority as not a real one."""
    date = date or datetime.datetime.utcnow().strftime("%Y-%m-%d")
    n = (name or "system").strip().lower()
    authority = n if re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", n) else "pqc-toolkit.invalid"
    return f"tag:{authority},{date}:{slug(n) or 'system'}"


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def _identity_props(v, name=None, bits=None):
    """Normalized algorithm identity (a fact about what was observed, not a judgement): the ruleset's
    canonical id and, where unambiguous, the CycloneDX cryptography-registry family and name."""
    out = [{"name": "fedlin:canonical", "value": v["canonical"]}] if v.get("canonical") else []
    fam, reg = cnsa.registry_name(name, bits) if name else (None, None)
    if reg:
        out += [{"name": "fedlin:registry_family", "value": fam}, {"name": "fedlin:registry_name", "value": reg}]
    return out


def _placeholder(name):
    """A name the toolkit wrote because it could not read the real one (no identity to vouch for)."""
    return str(name or "").startswith("unparsed")


def _is_windows_collector(c):
    """A record from FEDLIN's Windows collector (scripts/collect-windows.ps1), merged with --merge-cbom."""
    return any(p.get("name") == "fedlin:source" and str(p.get("value", "")).startswith("windows-collector")
               for p in c.get("properties", []) or [])


class CBOM:
    def __init__(self, system_name, system_ver, context, regime=None):
        # Serial number of this scan's CBOM. Records this run observed carry it as fedlin:observedIn, so a
        # record merged in from another CBOM never counts as observed by this scan (scripts/wave.py).
        self.serial = f"urn:uuid:{uuid.uuid4()}"
        self.components = []
        self.dependencies = []
        self._algo_refs = {}
        self._by_ref = {}            # bom-ref -> component (algorithm records), for evidence on reuse
        self.system_name = system_name
        self.system_ver = system_ver
        self.context = context
        self.regime = regime
        self.subject_tag = None      # RFC 4151 tag URI identifying the deployment (PKIC P3)
        self.coverage = "partial"    # a scan covers only what it was pointed at (PKIC P4)
        self._cert_algos = {}        # host -> [(ref, name)] of the served certificate's key and signature
        self._cert_bits = {}         # host -> certificate key size (EC field size names the curve)
        self._interfaces = 0
        self._ref_owner = {}         # bom-ref -> host, so two hosts that slug alike never share a record id

    def _unique_ref(self, ref, host):
        """ref for this host; a different host whose name slugs to the same ref gets a hash suffix."""
        owner = self._ref_owner.setdefault(ref, host)
        if owner != host:
            import hashlib
            ref = f"{ref}-{hashlib.sha256(host.encode()).hexdigest()[:8]}"
            self._ref_owner[ref] = host
        return ref

    def algo_ref(self, name, bits=None, source=None, location=None):
        """The algorithm's record; `source` adds how it was observed (several sources may share one)."""
        key = slug(f"{name}-{bits or ''}")
        if key in self._algo_refs:
            ref = self._algo_refs[key]
            if source:
                evmod.stamp(self._by_ref[ref], source, location, identify=not _placeholder(name))
            return ref
        ref = f"crypto/algo/{key}"
        v = cnsa.classify(name, bits)
        ap = {"primitive": v["primitive"], "cryptoFunctions": v["crypto_functions"]}
        if bits:
            ap["parameterSetIdentifier"] = str(bits)
        if v["classical_security_level"] is not None:
            ap["classicalSecurityLevel"] = v["classical_security_level"]
        if v["nist_pqc_level"] is not None:
            ap["nistQuantumSecurityLevel"] = v["nist_pqc_level"]
        # Facts only: identity and strength. Verdicts are written by the policy stage (policy.py) into a
        # separate result bound to this CBOM by SHA-256 digest.
        props = _identity_props(v, name, bits)
        comp = {
            "type": "cryptographic-asset", "bom-ref": ref, "name": name,
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": ap},
            "properties": props,
        }
        if source:
            evmod.stamp(comp, source, location, identify=not _placeholder(name))
        self.components.append(comp)
        self._algo_refs[key] = ref
        self._by_ref[ref] = comp
        return ref

    def add_certificate(self, c, extra=None):
        """extra: label of an additional certificate the same endpoint serves (e.g. "RSA" next to ECDSA)."""
        ref = self._unique_ref(f"crypto/cert/{slug(c['host'])}"
                               + (f"-{slug(extra)}-{c['fingerprint'][:12]}" if extra else ""), c["host"])
        src = "probe" if extra else "handshake"
        key_ref = self.algo_ref(c["key_alg"], c.get("key_bits"), src, c["host"])
        deps = [key_ref]
        if not extra:
            self._cert_algos[c["host"]] = [(key_ref, c["key_alg"])] + (
                [(None, c["sig_alg"])] if c.get("sig_alg") else [])
            self._cert_bits[c["host"]] = c.get("key_bits")
        cp = {
            "subjectName": c.get("subject") or "unknown",
            "issuerName": c.get("issuer") or "unknown",
            "certificateFormat": "X.509",
            "subjectPublicKeyRef": key_ref,
        }
        if c.get("sig_alg"):
            sig_ref = self.algo_ref(c["sig_alg"], None, src, c["host"])
            if not extra:
                self._cert_algos[c["host"]][-1] = (sig_ref, c["sig_alg"])
            cp["signatureAlgorithmRef"] = sig_ref
            deps.append(sig_ref)
        if c.get("not_before"):
            cp["notValidBefore"] = c["not_before"]
        if c.get("not_after"):
            cp["notValidAfter"] = c["not_after"]
        comp = {
            "type": "cryptographic-asset", "bom-ref": ref,
            "name": c["host"] + (f" ({extra} certificate)" if extra else ""),
            "cryptoProperties": {"assetType": "certificate", "certificateProperties": cp},
        }
        evmod.stamp(comp, src, c["host"])
        props = [{"name": "fedlin:observedIn", "value": self.serial}]
        if c.get("chain_depth"):
            props.append({"name": "fedlin:chain_depth", "value": str(c["chain_depth"])})
        if extra:
            props += [{"name": "fedlin:host", "value": c["host"]},
                      {"name": "fedlin:certificateSelectedBy", "value": f"client offering {extra} signature schemes only"},
                      {"name": "fedlin:sha256Fingerprint", "value": c["fingerprint"]}]
        elif c.get("fingerprint"):
            props.append({"name": "fedlin:sha256Fingerprint", "value": c["fingerprint"]})
        if props:
            comp["properties"] = props
        self.components.append(comp)
        self.dependencies.append({"ref": ref, "dependsOn": deps})

    def add_tls_kex(self, host, kex_group=None, protocol=None, cipher=None, kex_partial=None,
                    classical_only=None, enumeration=None, kex_note=None):
        """Add one TLS interface per endpoint: negotiated version, cipher suite, key exchange.

        Shaped for the PKI Consortium CBOM interface profiles: the asset is a 'service' interface
        observed from the client side, with protocol, protocolVersion, keyExchange, encryption and
        authentication (the served certificate's key and signature algorithms). Anything the scan did
        not observe is declared 'unknown' rather than left silent. Session properties are scored
        separately from the certificate's algorithms; the version is the one actually negotiated.
        """
        if not (kex_group or protocol or cipher or (enumeration or {}).get("status") == "complete"):
            return
        deps = []
        # The negotiated session is a handshake observation; with no session, only the probes saw it.
        src = "handshake" if (kex_group or protocol or cipher) else "probe"
        for name in (kex_group, cipher, protocol):
            if name:
                deps.append(self.algo_ref(name, None, src, host))
        version = protocol[4:] if protocol and protocol.startswith("TLSv") else None
        ref = self._unique_ref(f"crypto/proto/tls/{slug(host)}", host)
        pp = {"type": "tls"}
        if version:
            pp["version"] = version
        if cipher:
            pp["cipherSuites"] = [{"name": cipher}]
        cert = self._cert_algos.get(host, [])
        related = [r for r in deps if r] + [r for r, _ in cert if r]
        if related:
            pp["cryptoRefArray"] = sorted(set(related))
        P = "pkic:profile:"
        props = [{"name": "fedlin:observedIn", "value": self.serial},
                 {"name": P + "interfaceType", "value": "service"},
                 {"name": P + "lifecycleStage", "value": "observed"},
                 {"name": P + "endpointRole:server", "value": f"endpoint:{host}"},
                 {"name": P + "endpointRole:client", "value": "endpoint:fedlin-pqc-toolkit-scan"},
                 {"name": P + "observationMethod", "value": "active-probe"}]
        if version:
            props.append({"name": P + "protocolVersion", "value": version})
        else:
            props.append({"name": P + "disclosure:protocolVersion", "value": "unknown"})
        # Interface values use CycloneDX cryptography-registry names (the profile's identifier scheme)
        # where the mapping is unambiguous, else the observed name.
        def reg(n, curve_bits=None):
            return cnsa.registry_name(n, None, curve_bits)[1] or n
        cb = self._cert_bits.get(host)
        auth = [reg(n, cb) for r, n in cert if cnsa.registry_name(n, None, cb)[1]] or [n for _, n in cert]
        kex_fact = [reg(kex_group)] if kex_group else []
        if not kex_fact and cipher and cnsa.classify(cipher)["note"].startswith("RSA key transport"):
            # Static-RSA suite: the key exchange is RSA key transport, known from the suite itself.
            kex_fact = ["RSA"]
        facts = {"keyExchange": kex_fact,
                 "encryption": [reg(cipher)] if cipher else [],
                 "authentication": auth}
        for attr, vals in facts.items():
            if vals:
                props += [{"name": P + attr, "value": v} for v in vals]
            else:
                props.append({"name": P + "disclosure:" + attr, "value": "unknown"})
        props.append({"name": P + "disclosure:implementationPurl", "value": "unknown"})
        if kex_partial:
            props.append({"name": "fedlin:kex_partial_evidence", "value": kex_partial})
        if kex_note:
            props.append({"name": "fedlin:kexConflict", "value": kex_note})
        en = enumeration or {}
        if en.get("status"):
            # What the server accepts, from separate handshakes (facts; the policy stage judges them).
            props.append({"name": "fedlin:enumeration", "value": en["status"]})
            if en.get("status") == "complete":
                props.append({"name": "fedlin:enumerationTool", "value": f"{en.get('client')}: {en.get('tool')}"})
                vers = [v for v, ok in (en.get("versions") or {}).items() if ok is True]
                props.append({"name": "fedlin:acceptedProtocolVersions", "value": ",".join(vers) or "none"})
                silent = [v for v, ok in (en.get("versions") or {}).items() if ok is None]
                if silent:
                    props.append({"name": "fedlin:untestedProtocolVersions", "value": ",".join(silent)})
                for v, suites in sorted((en.get("suites") or {}).items()):
                    props.append({"name": f"fedlin:acceptedCipherSuites:{v}", "value": ",".join(suites)})
                g_ok = [g for g, ok in (en.get("groups") or {}).items() if ok is True]
                g_no = [g for g, ok in (en.get("groups") or {}).items() if ok is False]
                g_na = [g for g, ok in (en.get("groups") or {}).items() if ok is None]
                if g_na:
                    props.append({"name": "fedlin:untestedGroups", "value": ",".join(g_na)})
                props.append({"name": "fedlin:acceptedGroups", "value": ",".join(g_ok) or "none"})
                props.append({"name": "fedlin:refusedGroups", "value": ",".join(g_no) or "none"})
                if en.get("dh_bits"):
                    props.append({"name": "fedlin:dhGroupBits", "value": ",".join(str(b) for b in en["dh_bits"])})
                if en.get("cert_probes"):
                    # per signature-scheme family: what the certificate probe got back (none = no answer)
                    props.append({"name": "fedlin:certificateProbes", "value": ",".join(
                        f"{k}:{v or 'none'}" for k, v in en["cert_probes"].items())})
                    # "certificate" above means the probe got one back, not that it is of that family: say which
                    # key it had (1.7.0), e.g. ML-DSA:rsaEncryption when the server ignored the ML-DSA offer
                    if en.get("cert_probe_keys"):
                        props.append({"name": "fedlin:certificateProbeKeys", "value": ",".join(
                            f"{k}:{v}" for k, v in en["cert_probe_keys"].items())})
                if en.get("truncated"):
                    props.append({"name": "fedlin:enumerationTruncated", "value": ",".join(en["truncated"])})
                if en.get("incomplete"):
                    # the suite loop stopped without a server refusal (timeout, reset, rate limit): list is partial
                    props.append({"name": "fedlin:enumerationIncomplete", "value": ",".join(en["incomplete"])})
            elif en.get("reason"):
                props.append({"name": "fedlin:enumerationNote", "value": en["reason"]})
        co = classical_only or {}
        if co.get("outcome"):
            # Second handshake from a client offering only classical key exchange (fact, not a verdict).
            props.append({"name": "fedlin:classicalOnlyOffer", "value": co["outcome"]})
            got = " ".join(x for x in (co.get("protocol"), co.get("cipher"), co.get("group")) if x)
            if got:
                props.append({"name": "fedlin:classicalOnlyNegotiated", "value": got})
            if co.get("offer_complete") is False:
                reduced = ("client OpenSSL lacks " + ",".join(co["not_offered"]) if co.get("not_offered")
                           else "FIPS-mode client: X25519 and X448 not offered")
                props.append({"name": "fedlin:classicalOnlyOfferReduced", "value": reduced})
            elif co.get("not_offered"):
                # complete for every modern group; only legacy curves this client lacks were left out (1.7.0)
                props.append({"name": "fedlin:classicalOnlyNotOffered", "value": ",".join(co["not_offered"])})
            for k, name in (("tool", "fedlin:classicalOnlyTool"), ("command", "fedlin:classicalOnlyCommand")):
                if co.get(k):
                    props.append({"name": name, "value": co[k]})
        comp = {
            "type": "cryptographic-asset", "bom-ref": ref,
            "name": f"TLS {version or '(version not observed)'} - {host}",
            "cryptoProperties": {"assetType": "protocol", "protocolProperties": pp},
            "properties": props,
        }
        # The interface's own facts are the recorded session; what enumeration accepted is in its properties.
        evmod.stamp(comp, src, host)
        self.components.append(comp)
        self.dependencies.append({"ref": ref, "dependsOn": sorted(set(deps))})
        self._interfaces += 1

    def add_ssh(self, ssh):
        algos = []
        for a in ssh.get("kex", []) + ssh.get("hostkeys", []) + ssh.get("ciphers", []) + ssh.get("macs", []):
            if cnsa.is_pseudo(a):  # protocol markers such as ext-info-c, kex-strict-*
                continue
            algos.append(self.algo_ref(a, None, "configuration"))
        for k in ssh.get("hostkey_sizes", []):    # the host keys themselves, with their sizes (1.8.0)
            bits = k["bits"] if k["type"] in ("RSA", "DSA") else None
            algos.append(self.algo_ref(k["name"], bits, "configuration", k.get("file")))
        ref = "crypto/proto/ssh"
        # Configuration evidence (sshd -T on this host), not an observed interface: one PKIC document
        # carries one lifecycle stage, and the TLS interfaces are observed. A remote SSH handshake scan
        # (observed) would make this an interface.
        self.components.append(evmod.stamp({
            "type": "cryptographic-asset", "bom-ref": ref, "name": ssh.get("version", "OpenSSH"),
            "cryptoProperties": {"assetType": "protocol",
                                 "protocolProperties": {"type": "ssh", "version": "2.0"}},
            "properties": [{"name": "fedlin:evidence", "value": "configured (sshd -T, local host)"}],
        }, "configuration", None, "sshd -T"))
        if algos:
            self.dependencies.append({"ref": ref, "dependsOn": sorted(set(algos))})

    def add_sealed_secrets(self, count):
        ref = "crypto/material/sealed-secrets-key"
        key_ref = self.algo_ref("rsaEncryption", 4096, "assumption")
        self.components.append(evmod.stamp({
            "type": "cryptographic-asset", "bom-ref": ref, "name": "sealed-secrets-sealing-key",
            "cryptoProperties": {"assetType": "related-crypto-material",
                                 "relatedCryptoMaterialProperties": {
                                     "type": "private-key", "algorithmRef": key_ref, "state": "active"}},
            "properties": [
                {"name": "fedlin:sealed_secret_crs", "value": str(count)},
                {"name": "fedlin:evidence", "value": "inferred (controller key assumed RSA-4096 from the "
                                                     "SealedSecret object count; key not read)"},
                {"name": "fedlin:hndl_exposure", "value": "RSA-wrapped ciphertext (SealedSecrets are usually committed to version control)"},
            ],
        }, "assumption", None, "key not read; size assumed from the controller default"))
        self.dependencies.append({"ref": ref, "dependsOn": [key_ref]})

    def _subject(self):
        """The deployment this CBOM describes (PKIC P3/P4/P5)."""
        props = [{"name": "pkic:profile:subjectType", "value": "deployment"},
                 {"name": "pkic:profile:coverage", "value": self.coverage}]
        if self._interfaces:
            # An outside scan sees the service listeners it was pointed at, not the administrative
            # surface. PKIC P2 allows 'not-reached' for an observed record with partial coverage.
            props.append({"name": "pkic:profile:managementInterfaceAbsence", "value": "not-reached"})
        if self.subject_tag:
            props.append({"name": "pkic:profile:subjectIdentifier", "value": self.subject_tag})
        return {"type": "platform", "name": self.system_name, "version": self.system_ver,
                "bom-ref": "system", "properties": props}

    def to_dict(self):
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        props = [{"name": f"fedlin:{k}", "value": str(v)} for k, v in self.context.items()]
        return {
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "serialNumber": self.serial, "version": 1,
            "metadata": {
                "timestamp": ts,
                "component": self._subject(),
                "lifecycles": [{"phase": "discovery" if self._interfaces else "build"}],
                "tools": {"components": [{"type": "application", "name": "fedlin-pqc-toolkit",
                                          "version": TOOLKIT_VERSION,
                                          "publisher": "FEDLIN"}]},
                "properties": props,
            },
            "components": self.components,
            "dependencies": self.dependencies,
        }


def generate_deps_sbom(repo, cdxgen_bin, out):
    """Run cdxgen against a source repo/dir -> CycloneDX dependency SBOM."""
    if not os.path.isdir(repo):
        sys.stderr.write(f"[warn] --repo {repo!r}: not a directory; skipping the dependency SBOM\n")
        return False
    sys.stderr.write(f"[deps] cdxgen on {repo} ...\n")
    # Argument list, no shell: the repo path is passed to cdxgen as data, never interpreted.
    try:
        subprocess.run([cdxgen_bin, "--spec-version", "1.6", "-o", out, os.path.abspath(repo)],
                       capture_output=True, text=True, timeout=240)
    except Exception as e:
        sys.stderr.write(f"[warn] cdxgen: {e}\n")
    if os.path.exists(out) and os.path.getsize(out) > 0:
        try:
            with open(out) as f:
                n = len(json.load(f).get("components", []))
            print(f"[ok] cdxgen dependency SBOM: {n} components")
            return True
        except Exception:
            pass
    sys.stderr.write("[warn] cdxgen produced no usable SBOM\n")
    return False


# Known crypto/PQC library packages -> the algorithms they provide (names the ruleset recognizes).
# Lets us infer crypto *capability* from the dependency graph (cdxgen SBOM) when source-API detection
# misses modern libraries (e.g. sonar-cryptography has no rule for @noble/post-quantum).
LIB_CRYPTO = {
    # --- PQC (quantum-resistant / compliant) ---
    "@noble/post-quantum": ["ML-KEM", "ML-DSA", "SLH-DSA"],
    "liboqs": ["ML-KEM", "ML-DSA", "SLH-DSA", "Falcon"],
    "liboqs-python": ["ML-KEM", "ML-DSA", "SLH-DSA", "Falcon"],
    "oqs": ["ML-KEM", "ML-DSA", "SLH-DSA"],
    "pqcrypto": ["ML-KEM", "ML-DSA", "SLH-DSA"],
    "pqclean": ["ML-KEM", "ML-DSA", "SLH-DSA"],
    "crystals-kyber": ["ML-KEM"],
    "kyber-crystals": ["ML-KEM"],
    "dilithium-crystals": ["ML-DSA"],
    # --- classical asymmetric (quantum-vulnerable) ---
    "@noble/curves": ["ECDSA", "ECDH", "Ed25519"],
    "@noble/secp256k1": ["ECDSA"],
    "@noble/ed25519": ["Ed25519"],
    "elliptic": ["ECDSA", "ECDH"],
    "ethers": ["ECDSA"],            # secp256k1
    "web3": ["ECDSA"],
    "ethereumjs-util": ["ECDSA"],
    "tweetnacl": ["Ed25519", "X25519"],
    "node-forge": ["RSA", "AES-256", "ECDSA"],
    "node-rsa": ["RSA"],
    "jsonwebtoken": ["RSA", "ECDSA"],
    "jose": ["RSA", "ECDSA"],
    # --- symmetric / hash (quantum-resistant) ---
    "@noble/ciphers": ["AES-256", "ChaCha20"],
    "@noble/hashes": ["SHA-256", "SHA-3"],
    # --- python (pyca etc.; CBOMkit usually catches these, dep-signal is a backstop) ---
    "cryptography": ["RSA", "ECDSA", "AES-256", "SHA-256"],
    "pynacl": ["Ed25519", "X25519"],
    "pycryptodome": ["RSA", "AES-256", "ECDSA"],
}


def detect_library_crypto(doc):
    """Infer crypto capability from known crypto/PQC library dependencies (cdxgen SBOM).

    Emits deduped algorithm crypto-assets (tagged as dependency-capability) so the overlay
    classifies them: surfacing BOTH compliant (PQC/AES-256/SHA) and non-compliant (RSA/ECDSA)
    crypto that source-API detection misses. Presence != confirmed usage: flagged capability,
    analyst-verifies actual use.
    """
    algo_pkgs = {}
    for c in doc.get("components", []):
        if c.get("type") != "library":
            continue
        g = (c.get("group") or "").strip()
        n = (c.get("name") or "").strip()
        full = (f"{g}/{n}" if g else n).lower()
        algos = LIB_CRYPTO.get(full)
        if not algos:
            continue
        pkg = f"{g}/{n}" if g else n
        for a in algos:
            algo_pkgs.setdefault(a, set()).add(pkg)
    added = 0
    for algo, pkgs in sorted(algo_pkgs.items()):
        comp = {
            "type": "cryptographic-asset", "bom-ref": f"crypto/algo/{slug(algo)}-dep",
            "name": algo,
            "cryptoProperties": {"assetType": "algorithm",
                                 "algorithmProperties": {"primitive": "unknown", "cryptoFunctions": ["unknown"]}},
            "properties": [
                {"name": "fedlin:evidence", "value": "dependency: " + ", ".join(sorted(pkgs))},
                {"name": "fedlin:capability", "value": "true"},
            ],
        }
        evmod.stamp(comp, "dependency", None, ", ".join(sorted(pkgs)))
        doc.setdefault("components", []).append(comp)
        added += 1
    return added


def overlay_untagged(doc, regime=None):
    """Normalize identity facts on algorithm assets that arrived without them.

    Merged-in cdxgen / cbomkit-theia algorithm components (e.g. 'RSA', 'SHA256-RSA') carry only a
    name. This adds the normalized identity (fedlin:canonical) and any missing standard algorithm
    properties (primitive, NIST security category, classical strength). It writes no verdicts:
    those come from the policy stage, for every source alike. `regime` is ignored (kept for callers).
    """
    n = 0
    for c in doc.get("components", []):
        if c.get("type") != "cryptographic-asset":
            continue
        cp = c.get("cryptoProperties", {})
        if cp.get("assetType") != "algorithm":
            continue
        existing = {p["name"] for p in c.get("properties", [])}
        if "fedlin:canonical" in existing:
            continue
        ap = cp.setdefault("algorithmProperties", {})
        # Only a numeric parameterSetIdentifier is a key size. Digits inside the name are left to the
        # ruleset, which reads only family-adjacent sizes (so "SHA256-RSA" is not a 256-bit RSA key).
        bits = ap.get("parameterSetIdentifier")
        v = cnsa.classify(c.get("name", ""), int(bits) if bits and str(bits).isdigit() else None)
        if v["canonical"] is None:
            continue
        if ap.get("primitive") in (None, "", "unknown", "other") and v["primitive"] != "unknown":
            ap["primitive"] = v["primitive"]
        if v["nist_pqc_level"] is not None and "nistQuantumSecurityLevel" not in ap:
            ap["nistQuantumSecurityLevel"] = v["nist_pqc_level"]
        if v["classical_security_level"] is not None and "classicalSecurityLevel" not in ap:
            ap["classicalSecurityLevel"] = v["classical_security_level"]
        c.setdefault("properties", []).extend(
            _identity_props(v, c.get("name", ""), int(bits) if bits and str(bits).isdigit() else None))
        n += 1
    return n


def fallback_cert_scan(theia_dir, doc, openssl_bin="openssl"):
    """Supplement cbomkit-theia, which silently DROPS certificates whose public-key
    OID it can't parse (EdDSA/RFC 8410; ML-DSA/SLH-DSA/2024 OIDs: confirmed in lab
    testing). Parse those with OpenSSL 3.5 (which recognizes them) and add algorithm
    crypto-assets so the overlay classifies them. RSA/EC/DSA are already captured by
    theia and skipped here (no double-count)."""
    import glob as _glob
    if not shutil.which(openssl_bin):
        return 0
    files = []
    for root, _d, _f in os.walk(theia_dir):
        for pat in ("*.crt", "*.pem", "*.cer", "*.der"):
            files += _glob.glob(os.path.join(root, pat))
    comps = doc.setdefault("components", [])
    added = 0
    for f in sorted(set(files)):
        alg = None
        for form in ("PEM", "DER"):
            r = subprocess.run([openssl_bin, "x509", "-in", f, "-inform", form, "-noout", "-text"],
                               capture_output=True, text=True)
            if r.returncode == 0:
                m = re.search(r"Public Key Algorithm:\s*(\S+)", r.stdout)
                alg = m.group(1) if m else None
                break
        if not alg:
            continue
        a = alg.lower()
        if not any(s in a for s in ("ml-dsa", "mldsa", "slh-dsa", "slhdsa", "sphincs",
                                    "ml-kem", "mlkem", "ed25519", "ed448", "falcon", "xmss", "lms")):
            continue  # RSA/EC/DSA already captured by theia
        comps.append({
            "type": "cryptographic-asset",
            "bom-ref": f"fallback-cert-{added}-{slug(alg)}",
            "name": alg,
            "cryptoProperties": {"assetType": "algorithm",
                                 "algorithmProperties": {"primitive": "unknown",
                                                         "cryptoFunctions": ["unknown"]}},
            "evidence": {"occurrences": [{"location": os.path.basename(f)}]},
            "properties": [{"name": "fedlin:source", "value": "fallback-cert-parser (cbomkit-theia OID gap)"}],
        })
        evmod.stamp(comps[-1], "file", None, "OpenSSL x509 parse")
        added += 1
    return added


def filter_excluded(doc, patterns, keep_refs=()):
    """Drop components whose evidence location matches an --exclude glob/substring.

    Location-based, so it cuts noise from any tool that records occurrences (e.g. gitleaks
    hits in docs/, scratch/, *.backup). Components without a location (cdxgen deps) are kept, and so
    are the records this toolkit captured itself (keep_refs): --exclude filters merged file scans,
    never the endpoints, SSH or cluster records the scan observed.
    """
    if not patterns:
        return 0
    keep_refs = set(keep_refs)

    def loc_match(loc, pat):
        if any(ch in pat for ch in "*?["):
            return (fnmatch.fnmatch(loc, pat) or fnmatch.fnmatch(loc, "*/" + pat)
                    or fnmatch.fnmatch(os.path.basename(loc), pat))
        return pat in loc

    kept, dropped, dropped_refs = [], 0, set()
    for c in doc.get("components", []):
        locs = [o.get("location", "") for o in (c.get("evidence", {}).get("occurrences") or []) if o.get("location")]
        if c.get("bom-ref") not in keep_refs and locs and any(loc_match(loc, p) for loc in locs for p in patterns):
            dropped += 1
            if c.get("bom-ref"):
                dropped_refs.add(c["bom-ref"])
            continue
        kept.append(c)
    doc["components"] = kept
    if dropped_refs and doc.get("dependencies"):
        deps = []
        for d in doc["dependencies"]:
            if d.get("ref") in dropped_refs:
                continue
            if d.get("dependsOn"):
                d["dependsOn"] = [r for r in d["dependsOn"] if r not in dropped_refs]
            deps.append(d)
        doc["dependencies"] = deps
    return dropped


def strip_nones(o):
    """Recursively drop null / "null" sentinel values (external tools emit these; they break 1.6 enums)."""
    if isinstance(o, dict):
        return {k: strip_nones(v) for k, v in o.items() if v is not None and v != "null"}
    if isinstance(o, list):
        return [strip_nones(v) for v in o]
    return o


def _cyclonedx(cyclonedx_bin, args):
    """Run cyclonedx-cli; None (with a warning) when it is not installed."""
    try:
        return subprocess.run([cyclonedx_bin, *args], capture_output=True, text=True)
    except OSError as e:
        sys.stderr.write(f"[warn] cyclonedx-cli not available ({cyclonedx_bin}: {e.strerror}); run ./setup.sh "
                         "or pass --cyclonedx\n")
        return None


def convert_bom(cyclonedx_bin, inp, out, version="v1_6"):
    r = _cyclonedx(cyclonedx_bin, ["convert", "--input-file", inp, "--output-file", out,
                                   "--output-version", version])
    return r is not None and r.returncode == 0


def generate_theia_cbom(theia_bin, mode, target, cyclonedx_bin, out):
    """Run cbomkit-theia (dir|image) -> CycloneDX (1.7) -> convert to 1.6 -> out.

    Returns the number of components, or -1 when the tool failed (no output, unreadable output)."""
    sys.stderr.write(f"[theia] cbomkit-theia {mode} {target} ...\n")
    try:
        r = subprocess.run([theia_bin, mode, target], capture_output=True, text=True, timeout=240)
    except Exception as e:
        sys.stderr.write(f"[warn] cbomkit-theia failed: {e}\n")
        return -1
    if not r.stdout.strip():
        sys.stderr.write(f"[warn] cbomkit-theia no output: {r.stderr.strip()[:160]}\n")
        return -1
    raw = out + ".raw.json"
    text = r.stdout
    try:
        # cbomkit-theia parsed these from files: say so on each record it did not describe itself. Stamped
        # on the original input, so evidence restored after the merge includes it.
        tdoc = json.loads(text)
        if evmod.stamp_missing(tdoc, "file"):
            text = json.dumps(tdoc)
    except ValueError:
        pass
    with open(raw, "w") as f:
        f.write(text)
    if not convert_bom(cyclonedx_bin, raw, out):
        shutil.copy(raw, out)
    try:
        with open(out) as f:
            n = len(json.load(f).get("components", []))
        print(f"[ok] cbomkit-theia ({mode}) CBOM: {n} components")
        return n
    except Exception as e:
        sys.stderr.write(f"[warn] cbomkit-theia output unreadable: {e}\n")
        return -1


_LEVEL_KEYS = ("classicalSecurityLevel", "nistQuantumSecurityLevel")


def undo_merge_defaults(doc, source_paths):
    """Remove security levels cyclonedx-cli invents during merge/convert.

    cyclonedx-cli writes 0 for an absent classicalSecurityLevel or nistQuantumSecurityLevel. In CycloneDX
    0 means "no classical security" / "quantum-vulnerable", so an unknown strength would become a false fact.
    A level is kept only if the component's original input (before any cyclonedx-cli step) carried it.
    """
    orig = {}
    for path in source_paths:
        try:
            with open(path) as f:
                for c in json.load(f).get("components", []) or []:
                    ap = ((c.get("cryptoProperties") or {}).get("algorithmProperties") or {})
                    orig[c.get("bom-ref")] = set(ap)
        except (OSError, ValueError):
            continue
    removed = 0
    for c in doc.get("components", []) or []:
        keys = orig.get(c.get("bom-ref"))
        ap = ((c.get("cryptoProperties") or {}).get("algorithmProperties"))
        if keys is None or not isinstance(ap, dict):
            continue
        for k in _LEVEL_KEYS:
            if k in ap and k not in keys:
                del ap[k]
                removed += 1
    return removed


def merge_boms(cyclonedx_bin, inputs, out):
    r = _cyclonedx(cyclonedx_bin, ["merge", "--input-files", *inputs, "--output-file", out,
                                   "--output-version", "v1_6"])
    if r is None:
        sys.stderr.write(f"[warn] cyclonedx-cli is needed to merge {len(inputs) - 1} input(s)\n")
        return False
    if r.returncode != 0:
        sys.stderr.write(f"[warn] merge failed: {r.stderr.strip()}\n")
        return False
    return True


_FILE_SUFFIXES = (".txt", ".csv", ".lst", ".list")


def missing_endpoint_files(values):
    """Values of --endpoints that look like a hosts file but do not exist.

    A file that is not there would otherwise be scanned as a hostname ("hosts.txt"), fail, and leave a
    run with nothing in it. A value is taken as a file when it starts with ./, ../, / or ~, is a path whose
    first part has no dot (lists/hosts), or is a bare name ending in a list-file suffix that is not a domain
    (.txt, .csv, .lst, .list). URLs are never files."""
    out = []
    for v in values:
        if os.path.exists(v):
            continue
        for t in re.split(r"[,\s]+", v):
            if not t or "://" in t:
                continue                       # a URL, not a file
            head = t.split("/", 1)[0]
            if (t.startswith(("./", "../", "/", "~"))
                    or ("/" in t and "." not in head)                       # dir/hosts
                    or ("/" not in t and t.lower().endswith(_FILE_SUFFIXES))):  # hosts.txt
                out.append(t)
    return out


def tool_available(path):
    """True when `path` names an executable file, or a command on PATH."""
    return bool(path) and ((os.path.isfile(path) and os.access(path, os.X_OK)) or shutil.which(path) is not None)


FAIL_ON = ("broken", "vulnerable", "transitional", "unclassified", "incomplete")
EXIT_FAIL_ON = 3


def _fail_on_arg(v):
    """--fail-on value: a set of statuses; an unknown one is an argument error (exit 2)."""
    got = {x.strip().lower() for x in str(v).split(",") if x.strip()}
    bad = sorted(got - set(FAIL_ON))
    if bad:
        raise argparse.ArgumentTypeError(f"unknown status {', '.join(bad)}; use any of {', '.join(FAIL_ON)}")
    return got


def fail_on_hits(result, bom, wanted):
    """{status: count} of what the scan found among the --fail-on statuses."""
    if not wanted:
        return {}
    statuses = [f.get("status") for f in result.get("findings", [])]
    hits = {}
    for w in sorted(wanted - {"incomplete"}):
        n = sum(1 for st in statuses if st == w or (w == "vulnerable" and st == "broken"))
        if n:
            hits[w] = n
    if "incomplete" in wanted:
        n = len(reportmod.score_summary(bom)["kex_unobserved"])
        n += len(NOT_CAPTURED)      # answered but completed no handshake: nothing in the CBOM, still not observed
        if n:
            hits["incomplete"] = n
    return hits


def abort(msg, cleanup=()):
    """A requested source produced nothing: stop with exit code 2 (STABILITY.md), never a CBOM a CI gate reads
    as a pass. Intermediate files from this run are removed; no CBOM, policy result or report is written."""
    for p in cleanup:
        try:
            os.remove(p)
        except OSError:
            pass
    sys.stderr.write(f"[error] {msg}\n")
    sys.exit(2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", action="version",
                    version=f"fedlin-pqc-toolkit {TOOLKIT_VERSION} (ruleset {cnsa.RULESET_VERSION})")
    ap.add_argument("--out", default="out/cbom.json")
    ap.add_argument("--name", default="",
                    help="name of the system scanned, used in the report title and the CBOM subject (default: the "
                         "first endpoint, else the --repo/--theia-dir folder name, else openshift-cluster for a "
                         "cluster scan)")
    ap.add_argument("--repo", default="", help="optional source repo/dir -> cdxgen dependency SBOM, merged in")
    ap.add_argument("--theia-dir", default="", help="optional dir -> cbomkit-theia scan (certificates, keys, secret-hygiene findings; may read key files), merged in")
    ap.add_argument("--theia-image", default="", help="optional container image ref -> cbomkit-theia scan, merged in")
    ap.add_argument("--cdxgen", default="", help="path to cdxgen (default: ../node_modules/.bin/cdxgen)")
    ap.add_argument("--theia", default="", help="path to cbomkit-theia (default: ../bin/cbomkit-theia)")
    ap.add_argument("--cyclonedx", default="", help="path to cyclonedx-cli (for merge + validate)")
    ap.add_argument("--validate", action="store_true", help="validate the final CBOM (needs --cyclonedx)")
    ap.add_argument("--fail-on", default=set(), type=_fail_on_arg, metavar="STATUS[,STATUS]",
                    help="exit 3 when the scan finds any of these (comma-separated): broken, vulnerable "
                         "(includes broken), transitional, unclassified, incomplete (key exchange not observed on "
                         "a TLS endpoint). For CI gates; exit 2 still means the scan itself failed")
    ap.add_argument("--redact", action="append", default=[],
                    help="old=new string replacement on the final CBOM (repeatable), e.g. corp.internal=example.gov")
    ap.add_argument("--profile", choices=list(cnsa.PROFILES), default=cnsa.DEFAULT_PROFILE,
                    help="ruleset profile: civilian (NIST FIPS 203/204/205 + IR 8547, default) or "
                         "nss (NSA CNSA 2.0)")
    ap.add_argument("--subject-tag", default="",
                    help="RFC 4151 tag URI naming the deployment this CBOM describes, e.g. "
                         "tag:example.com,2026-11-14:prod-edge (PKI Consortium profile rule P3). "
                         "Default: tag:<system name if it is a DNS name, else pqc-toolkit.invalid>,<date>:<name>")
    ap.add_argument("--regime", default="", type=str.upper, choices=["", *crosswalk.REGIMES],
                    metavar="{" + ",".join(crosswalk.REGIMES) + "}",
                    help="annotate assets with a regime crosswalk (case does not matter)")
    ap.add_argument("--deep", action="store_true",
                    help="run intrusive checks (FIPS via oc/kubectl debug node: spins a short-lived pod)")
    ap.add_argument("--debug-image", default="",
                    help="image for --deep on non-OpenShift clusters (kubectl debug node); pin by digest")
    ap.add_argument("--kube-cli", default="oc",
                    help="kubernetes CLI for runtime capture: oc (OpenShift) or kubectl (EKS/GKE/AKS/k3s). "
                         "Platform is auto-detected; on non-OpenShift, Route capture becomes Ingress capture.")
    ap.add_argument("--report", action="store_true",
                    help="also emit an executive scorecard + migration roadmap (<out>.report.md)")
    ap.add_argument("--baseline", default="",
                    help="CBOM of an earlier scan: with --wave, regressions at the wave's endpoints; in the "
                         "engagement kit, also the continuous-monitoring delta (<out>.delta.md)")
    ap.add_argument("--context", default="",
                    help="business context (fedlin.pqc-context 1.0 or 1.1): owners, FIPS 199 impact, data lifetime and "
                         "migration time; adds an attention order and urgency flag to the report (implies --report)")
    ap.add_argument("--wave", default="",
                    help="wave file (fedlin.pqc-wave 1.0): after the scan, check each declared item against it "
                         "(writes <out>.wave.json and .wave.md; with --baseline, also lists regressions)")
    ap.add_argument("--merge-cbom", action="append", default=[],
                    help="path to an externally-generated CycloneDX CBOM to fold in (repeatable), e.g. a "
                         "CBOMkit source scan produced out-of-band by scripts/run-cbomkit.sh (source coverage)")
    ap.add_argument("--exclude", action="append", default=[],
                    help="drop assets whose evidence location matches this glob/substring (repeatable), e.g. "
                         "--exclude docs/ --exclude scratch/ --exclude '*.backup': cuts false-positive noise")
    ap.add_argument("--no-dep-crypto", action="store_true",
                    help="disable inferring crypto capability from known library dependencies (cdxgen SBOM)")
    ap.add_argument("--no-enumerate", action="store_true",
                    help="skip enumerating what each TLS endpoint accepts (protocol versions, cipher suites, "
                         "key-exchange groups, certificate types); enumeration takes about 10-15 s per endpoint")
    ap.add_argument("--enumerate-pace", type=float, default=0.0, metavar="SECONDS",
                    help="pause between enumeration handshakes to one endpoint, for servers that rate-limit "
                         "(each handshake that times out is recorded as not tested, never as refused)")
    ap.add_argument("--no-classical-probe", action="store_true",
                    help="skip the second, classical-only handshake per TLS endpoint (PQCMM 4.3.1 evidence); "
                         "it adds about one handshake (2-3 s on a FIPS host using the probe container) per endpoint")
    ap.add_argument("--endpoints", action="append", default=[],
                    help="live TLS endpoint scan WITHOUT a cluster: a file of host[:port] lines (# comments ok) "
                         "and/or an inline comma list, e.g. --endpoints agency-hosts.txt --endpoints www.agency.gov. "
                         "On its own no cluster is scanned; with --cluster it augments the cluster's routes. "
                         "Reads public certificate metadata only.")
    ap.add_argument("--no-runtime", action="store_true",
                    help="never scan a cluster: build the CBOM from --endpoints/--repo/--theia-dir/--merge-cbom "
                         "only. From 1.5.0 this is the default whenever one of those is given")
    ap.add_argument("--cluster", action="store_true",
                    help="also scan the Kubernetes/OpenShift cluster of the current kube context (routes or "
                         "ingresses, TLS secret counts). Needs cluster-wide list on secrets. From 1.5.0 a run "
                         "with a source flag scans a cluster only with this flag")
    ap.add_argument("--local-ssh", action="store_true",
                    help="also record this host's own SSH configuration (sudo -n sshd -T). Off unless given, "
                         "except in a run with no source flag at all (as before 1.5.0)")
    ap.add_argument("--self-serve", action="store_true",
                    help="unattended automated-scan mode: implies --no-runtime and --report; the report carries "
                         "an automated-scan disclaimer and confidence bands")
    ap.add_argument("--brand", default="FEDLIN",
                    help="name the report is issued under")
    ap.add_argument("--sign", action="store_true",
                    help="write a detached SLH-DSA (FIPS 205) attestation over the CBOM, report and delta "
                         "(<out>.attestation.json). Needs a signing key: $SPHINCS_PRIVATE_KEY_B64 or --slh-key.")
    ap.add_argument("--slh-key", default="",
                    help="SLH-DSA private-key file for --sign (default: $SPHINCS_PRIVATE_KEY_B64)")
    ap.add_argument("--slh-variant", default="",
                    help="SLH-DSA variant for --sign (default: slh_dsa_sha2_128f, FIPS 205)")
    ap.add_argument("--node", default="node", help="node binary used by the SLH-DSA signer")
    for action in ap._actions:
        if action.dest in KIT_FLAGS and not KIT_FLAGS[action.dest]:
            action.help = argparse.SUPPRESS
    args = ap.parse_args()
    global CLASSICAL_PROBE, ENUMERATE
    CLASSICAL_PROBE = not args.no_classical_probe
    ENUMERATE = not args.no_enumerate
    global ENUM_PACE
    ENUM_PACE = max(0.0, min(args.enumerate_pace, 10.0))
    for dest, avail in KIT_FLAGS.items():
        val, default = getattr(args, dest, None), ap.get_default(dest)
        if not avail and val not in (None, False, "", [], default):
            ap.error(f"--{dest.replace('_', '-')} is part of the FEDLIN engagement kit and is not in this build")
    cnsa.DEFAULT_PROFILE = args.profile  # every classify() call in this run uses the chosen profile

    # Invalid input stops the run with exit code 2 (STABILITY.md) instead of producing an empty CBOM that a CI
    # gate would read as a pass.
    bad = []
    if args.endpoints and not parse_endpoints(args.endpoints):
        bad.append("--endpoints: no valid hostname or IP in the values given")
    if args.wave:
        try:
            wv = wavemod.load_wave(args.wave)
            if "profile" not in wv and args.profile != "civilian":
                sys.stderr.write(f"[warn] --wave: the wave file names no profile, so it is checked under civilian, "
                                 f"not --profile {args.profile}; add \"profile\" to the wave file\n")
        except wavemod.WaveError as e:
            bad.append(f"--wave: {e}")
        if args.no_enumerate or args.no_classical_probe:
            sys.stderr.write("[warn] --wave with --no-enumerate or --no-classical-probe: items that need what the "
                             "server accepts, its other certificates or the classical-only probe will be "
                             "\"not observed\"\n")
    if args.context:
        try:
            ctxmod.load_context(args.context, [r.split("=", 1) for r in args.redact if "=" in r])
        except ctxmod.ContextError as e:
            bad.append(f"--context: {e}")
    if args.baseline and not os.path.isfile(args.baseline):
        bad.append(f"--baseline {args.baseline}: not a file")
    elif args.baseline and deltamod is None and not args.wave:
        sys.stderr.write("[warn] --baseline does nothing in this build without --wave (the delta report is part "
                         "of the engagement kit)\n")
    for x in args.merge_cbom:
        if not os.path.isfile(x):
            bad.append(f"--merge-cbom {x}: not a file")
    for flag, x in (("--repo", args.repo), ("--theia-dir", args.theia_dir)):
        if x and not os.path.isdir(x):
            bad.append(f"{flag} {x}: not a directory")
    for x in missing_endpoint_files(args.endpoints):
        bad.append(f"--endpoints {x}: no such file (a hosts file must exist; in a container, mount it)")
    here = os.path.dirname(os.path.abspath(__file__))
    cdxgen_bin = args.cdxgen or os.path.join(here, "..", "node_modules", ".bin", "cdxgen")
    cyclonedx_bin = args.cyclonedx or os.path.join(here, "..", "bin", "cyclonedx")
    theia_bin = args.theia or os.path.join(here, "..", "bin", "cbomkit-theia")
    if args.repo and not tool_available(cdxgen_bin):
        bad.append(f"--repo needs cdxgen ({cdxgen_bin}): run ./setup.sh or pass --cdxgen")
    if (args.theia_dir or args.theia_image) and not tool_available(theia_bin):
        bad.append(f"--theia-dir/--theia-image need cbomkit-theia ({theia_bin}): run ./setup.sh or pass --theia")
    if (args.repo or args.theia_dir or args.theia_image or args.merge_cbom) and not tool_available(cyclonedx_bin):
        bad.append(f"--repo, --theia-dir, --theia-image and --merge-cbom need cyclonedx-cli to merge "
                   f"({cyclonedx_bin}): run ./setup.sh or pass --cyclonedx")
    if bad:
        for b in bad:
            sys.stderr.write(f"[error] {b}\n")
        sys.exit(2)

    # Self-serve: deterministic, source-based, gated output.
    if args.self_serve:
        args.no_runtime = True
        args.report = True
        if not (args.repo or args.theia_dir or args.merge_cbom or args.endpoints):
            sys.stderr.write("[error] --self-serve needs a source: pass --endpoints <hosts>, --repo <dir>, "
                             "--theia-dir <dir>, and/or --merge-cbom <cbom.json>\n")
            sys.exit(2)

    # Which targets this run scans (1.5.0). A source flag means a scan of that source only: the cluster of the
    # current kube context and this host's sshd are scanned only when asked for (--cluster, --local-ssh). A
    # run with no source flag at all keeps the pre-1.5.0 behaviour (cluster plus local SSH) and names the
    # context it is about to scan.
    has_source = bool(args.endpoints or args.repo or args.theia_dir or args.theia_image or args.merge_cbom)
    ssh_asked = args.local_ssh
    if args.cluster and args.no_runtime:
        sys.stderr.write("[error] --cluster and --no-runtime contradict each other; pass one\n")
        sys.exit(2)
    if has_source and not args.cluster and not args.no_runtime:
        cluster_only = [f for f, on in (("--deep", args.deep), ("--debug-image", args.debug_image),
                                        ("--kube-cli", args.kube_cli != "oc")) if on]
        if cluster_only:
            sys.stderr.write(f"[error] {', '.join(cluster_only)} appl{'ies' if len(cluster_only) == 1 else 'y'} "
                             "to a cluster scan: add --cluster (from 1.5.0 a run with --endpoints, --repo, "
                             "--theia-dir or --merge-cbom does not scan a cluster unless asked)\n")
            sys.exit(2)
        args.no_runtime = True
    elif not has_source and not args.cluster and not args.no_runtime:
        args.local_ssh = True
        if _CLI_RE.match(args.kube_cli):
            kctx = run(f"{shlex.quote(args.kube_cli)} config current-context 2>/dev/null").strip() or "(none)"
            sys.stderr.write(f"[info] no source flag given, so this run scans the cluster of kube context "
                             f"{kctx!r} and this host's SSH configuration (sudo -n sshd -T). Pass --cluster "
                             "[--local-ssh] to say so explicitly, or --endpoints/--repo/--theia-dir/--merge-cbom "
                             "for a scan without a cluster.\n")

    def local_ssh():
        if not args.local_ssh:
            return None
        got = capture_ssh()
        if got is None and ssh_asked:
            abort("--local-ssh: could not read this host's SSH configuration (needs sshd and passwordless "
                  "sudo for `sshd -T`)")
        return got

    if not args.name:
        eps = parse_endpoints(args.endpoints) if args.endpoints else []
        src = args.repo or args.theia_dir
        if eps:
            m6 = re.match(r"^\[([^\]]+)\]", eps[0])
            args.name = m6.group(1) if m6 else eps[0].rsplit(":", 1)[0]
        elif src:
            args.name = os.path.basename(os.path.normpath(os.path.abspath(src))) or "scan"
        elif args.no_runtime:
            args.name = "scan"
        else:
            args.name = "openshift-cluster"

    # --- runtime capture (cluster): skipped for --no-runtime / --self-serve (source-based) ---
    if args.no_runtime:
        ssh = local_ssh()
        counts = {"tls_secrets": 0, "sealed_secrets": 0}
        hosts = parse_endpoints(args.endpoints)
        certs = capture_endpoints(hosts) if hosts else []
        if hosts and not certs:
            abort(f"--endpoints: none of the {len(hosts)} endpoint(s) completed a TLS handshake, so there is "
                  "nothing to assess (see the warnings above: name, port, firewall or no TLS on that port)")
        if hosts:
            mode = "self-serve" if args.self_serve else "endpoint-scan"
            ctx = {"mode": mode,
                   "capture": f"live TLS endpoint scan, {len(certs)}/{len(hosts)} endpoint(s) reachable",
                   "endpoints_supplied": len(hosts)}
        else:
            ctx = {"mode": "self-serve" if args.self_serve else "no-runtime",
                   "capture": "source/dir only: no runtime endpoint capture"}
        # record the FIPS posture the scan itself ran under (scan host / in-boundary container)
        ctx["fips"] = read_local_fips()
    else:
        if not _CLI_RE.match(args.kube_cli):
            sys.stderr.write(f"[error] --kube-cli {args.kube_cli!r}: must be a command name or path\n")
            sys.exit(2)
        kube = shlex.quote(args.kube_cli)
        platform = detect_platform(kube)
        if platform == "unreachable":
            sys.stderr.write(
                f"[warn] cluster unreachable or RBAC-limited: `{kube} api-resources` returned nothing: wrong "
                "context, cluster down, or the token cannot list resources. The runtime tier captured NO "
                "route/ingress/edge TLS or cluster context. Fix KUBECONFIG/RBAC, or use --endpoints for edge "
                "TLS (and --repo/--theia-dir for code/image crypto).\n")
            ctx = {"mode": "runtime (cluster unreachable)",
                   "capture": f"{kube} api-resources returned nothing: no cluster capture",
                   "ocp_version": "unknown"}
            certs = []
        elif platform == "openshift":
            ctx = capture_context(kube)
            certs = capture_routes(kube)
            if ctx.get("ocp_version", "unknown") == "unknown":
                sys.stderr.write(
                    "[warn] OpenShift route/version APIs returned nothing despite the route API being served "
                    "RBAC-limited or a partial outage. Route/edge TLS and cluster context may be incomplete. "
                    "Use --endpoints for edge TLS.\n")
        else:
            sys.stderr.write(
                f"[info] non-OpenShift kubernetes detected ({kube}); capturing Ingress TLS instead of "
                "Routes. OpenShift-only context (etcd encryption, ingresscontroller TLS profile) is "
                "unavailable: supplement with --endpoints for edge TLS.\n")
            ctx = capture_context_generic(kube)
            certs = capture_ingress(kube)
        hosts = parse_endpoints(args.endpoints)
        if hosts:
            seen = {c["host"] for c in certs}
            ep_certs = capture_endpoints(hosts)
            if not ep_certs:
                abort(f"--endpoints: none of the {len(hosts)} endpoint(s) completed a TLS handshake (see the "
                      "warnings above)")
            for c in ep_certs:
                if c["host"] not in seen:
                    certs.append(c)
                    seen.add(c["host"])
            ctx["endpoints_supplied"] = len(hosts)
        counts = capture_counts(kube)
        ssh = local_ssh()
        ctx.update({"tls_secret_count": counts["tls_secrets"], "sealed_secret_count": counts["sealed_secrets"]})
        ctx["fips"] = capture_fips(kube, platform, args.debug_image) if args.deep else "not checked (use --deep)"
    if args.regime:
        ctx["regime"] = args.regime
    ctx["profile"] = args.profile

    if NOT_CAPTURED:
        ctx["not_captured"] = "; ".join(sorted(NOT_CAPTURED))
    b = CBOM(args.name, ctx.get("ocp_version", "unknown"), ctx, regime=args.regime or None)
    b.subject_tag = args.subject_tag or default_subject_tag(args.name)
    for c in certs:
        b.add_certificate(c)
        b.add_tls_kex(c["host"], c.get("kex_group"), c.get("tls_protocol"), c.get("tls_cipher"),
                      c.get("kex_partial"), c.get("classical_only"), c.get("enumeration"), c.get("kex_note"))
        for x in _extra_certificates(c):
            b.add_certificate(x, extra=x["requested"])
    if certs:
        vias = [c.get("kex_probe_via") for c in certs]
        img = os.environ.get("FEDLIN_KEX_PROBE_IMAGE", "") or _default_probe_image()
        parts = []
        if "host" in vias:
            parts.append("host OpenSSL, full offer")
        if "bundled" in vias:
            parts.append(f"bundled probe OpenSSL {os.environ.get('FEDLIN_KEX_PROBE_OPENSSL', '')}, full offer")
        if "container" in vias:
            parts.append(f"container {img}, full offer")
        if any((v or "").startswith("enumeration client") for v in vias):
            parts.append("enumeration client, for endpoints the host OpenSSL could not connect to")
        if any((v or "").startswith("classical-probe") for v in vias):
            parts.append("classical-only handshake, for endpoints that refused every ML-KEM group in enumeration")
        if "host-fips-subset" in vias:
            parts.append("FIPS host, reduced offer (no X25519MLKEM768); classical results not recorded; "
                         "from source run ./setup.sh (or set FEDLIN_KEX_PROBE_IMAGE); in a container use "
                         "ghcr.io/fedlinllc/fedlin-pqc-toolkit-probe")
        ctx["kex_probe"] = "; ".join(parts) or "not run"
    if ssh:
        b.add_ssh(ssh)
    if counts["sealed_secrets"]:
        b.add_sealed_secrets(counts["sealed_secrets"])
    doc = b.to_dict()

    out_dir = os.path.dirname(args.out) or "."
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as e:
        sys.stderr.write(f"[error] cannot create the output folder {out_dir!r}: {e.strerror}\n")
        sys.exit(2)
    if not os.access(out_dir, os.W_OK):
        sys.stderr.write(
            f"[error] the output folder {out_dir!r} is not writable by this user (uid {os.getuid()}). In a container, "
            "run as your own user: podman run --userns=keep-id --user \"$(id -u):$(id -g)\" ...  or  "
            "docker run --user \"$(id -u):$(id -g)\" ...\n")
        sys.exit(2)
    runtime_tmp = args.out + ".runtime.json"
    with open(runtime_tmp, "w") as f:
        json.dump(doc, f, indent=2)

    n_assets = sum(1 for c in doc["components"] if c["type"] == "cryptographic-asset")
    print(f"[ok] runtime CBOM: {n_assets} crypto-asset components, {len(certs)} certs, "
          f"{counts['tls_secrets']} TLS secrets, "
          f"{counts['sealed_secrets']} sealed secrets")

    # --- optional dependency SBOM (source components) + merge ---
    inputs = [runtime_tmp]
    intermediates = [runtime_tmp]   # unredacted working files; removed when --redact is used
    originals = [runtime_tmp]       # inputs as written before any cyclonedx-cli step
    if args.repo:
        deps_tmp = args.out + ".deps.json"
        intermediates.append(deps_tmp)
        if not generate_deps_sbom(args.repo, cdxgen_bin, deps_tmp):
            abort(f"--repo {args.repo}: cdxgen produced no SBOM (see the warnings above)", intermediates)
        inputs.append(deps_tmp)
        originals.append(deps_tmp)
    if args.theia_dir:
        t = args.out + ".theia-dir.json"
        intermediates += [t, t + ".raw.json"]
        originals.append(t + ".raw.json")
        n = generate_theia_cbom(theia_bin, "dir", args.theia_dir, cyclonedx_bin, t)
        if n < 0:
            abort(f"--theia-dir {args.theia_dir}: cbomkit-theia failed (see the warnings above)", intermediates)
        if n:
            inputs.append(t)
    if args.theia_image:
        t = args.out + ".theia-image.json"
        intermediates += [t, t + ".raw.json"]
        originals.append(t + ".raw.json")
        n = generate_theia_cbom(theia_bin, "image", args.theia_image, cyclonedx_bin, t)
        if n < 0:
            abort(f"--theia-image {args.theia_image}: cbomkit-theia failed (see the warnings above)", intermediates)
        if n:
            inputs.append(t)
    # generic external CycloneDX CBOM ingest (e.g. CBOMkit source scan, run out-of-band)
    for i, extra in enumerate(args.merge_cbom):
        conv = f"{args.out}.merge{i}.json"
        intermediates.append(conv)
        originals.append(extra)
        # normalize to 1.6 (external CBOMs may be 1.7); fall back to raw copy if convert can't
        if not convert_bom(cyclonedx_bin, extra, conv):
            shutil.copy(extra, conv)
        try:
            with open(conv) as f:
                n = sum(1 for c in json.load(f).get("components", [])
                        if c.get("type") == "cryptographic-asset")
            print(f"[ok] merge-cbom {os.path.basename(extra)}: {n} crypto-asset(s) ingested")
            inputs.append(conv)
        except Exception as e:
            abort(f"--merge-cbom {extra}: unreadable ({e})", intermediates)
    if len(inputs) > 1:
        if not merge_boms(cyclonedx_bin, inputs, args.out):
            abort(f"{len(inputs) - 1} input(s) could not be merged into the CBOM (see the warnings above)",
                  intermediates)
        print(f"[ok] merged runtime + dependency SBOM -> {args.out}")
    else:
        shutil.copy(runtime_tmp, args.out)
        print(f"[ok] wrote {args.out} (runtime-only)")

    # --- sanitize (drop null enum fields) + universal overlay + optional redaction ---
    with open(args.out) as f:
        final = strip_nones(json.load(f))
    # cyclonedx-cli drops occurrence detail and reshapes identity: put each input's evidence back verbatim
    evmod.restore(final, originals)
    evmod.normalize(final)
    # A merge can replace metadata.component and drop metadata.lifecycles; the subject and the stage
    # describe what was scanned, so they always come from the runtime builder.
    final.setdefault("metadata", {})["component"] = doc["metadata"]["component"]
    final["serialNumber"] = doc["serialNumber"]   # the scan's identity; fedlin:observedIn refers to it
    # cyclonedx-cli turns each input's metadata.component into a component; the subject's bom-ref ("system")
    # must stay unique (CycloneDX requires unique bom-refs).
    subj = doc["metadata"]["component"].get("bom-ref")
    final["components"] = [c for c in final.get("components", []) if c.get("bom-ref") != subj]
    n_levels = undo_merge_defaults(final, originals)
    if n_levels:
        print(f"[ok] removed {n_levels} security level(s) the CBOM merge invented (absent in the original input)")
    final["metadata"]["lifecycles"] = doc["metadata"]["lifecycles"]
    n_excluded = filter_excluded(final, args.exclude, {c.get("bom-ref") for c in doc.get("components", [])})
    if n_excluded:
        print(f"[ok] --exclude dropped {n_excluded} asset(s) by path filter")
    if not args.no_dep_crypto:
        n_dep = detect_library_crypto(final)
        if n_dep:
            print(f"[ok] dependency-graph crypto detection: {n_dep} algorithm(s) inferred from known libraries "
                  f"(capability: SBOM presence, not confirmed usage)")
    if args.theia_dir:
        n_fb = fallback_cert_scan(args.theia_dir, final)
        if n_fb:
            print(f"[ok] fallback cert parser: recovered {n_fb} modern-OID cert(s) cbomkit-theia dropped "
                  f"(EdDSA/ML-DSA/SLH-DSA)")
    # FEDLIN's Windows collector reads the certificate stores and SCHANNEL configuration of the host.
    evmod.stamp_missing(final, "configuration", _is_windows_collector)
    n_stripped = policymod.strip_verdicts(final)
    if n_stripped:
        print(f"[ok] removed {n_stripped} inline verdict propert(ies) from merged input (facts-only CBOM)")
    n_overlaid = overlay_untagged(final)
    if n_overlaid:
        print(f"[ok] normalized identity on {n_overlaid} merged algorithm asset(s) (cdxgen/cbomkit-theia)")
    text = json.dumps(final, indent=2)
    for r in args.redact:
        if "=" in r:
            old, new = r.split("=", 1)
            if old and any(old in m for m in (evmod.PREFIX, "fedlin:", "pkic:profile:")):
                sys.stderr.write(f"[warn] --redact {old!r} also rewrites the toolkit's own property names and "
                                 "evidence markers; readers will no longer recognize them\n")
            text = text.replace(old, new)
    if args.redact:
        try:
            json.loads(text)
        except ValueError as e:
            sys.stderr.write(f"[error] --redact produced invalid JSON ({e}); nothing written. "
                             "Avoid quotes and backslashes in replacement strings.\n")
            sys.exit(2)
        # The intermediate files hold the unredacted data; remove them.
        removed = 0
        for p in intermediates:
            if os.path.exists(p):
                os.remove(p)
                removed += 1
        print(f"[ok] applied {len(args.redact)} redaction(s); removed {removed} unredacted intermediate file(s)")
    with open(args.out, "w") as f:
        f.write(text)

    # --- policy (verdicts, bound to the CBOM bytes just written by SHA-256 digest) ---
    out_base = args.out.rsplit(".", 1)[0]
    pol_path = out_base + ".policy.json"
    result = policymod.evaluate(args.out, profile=args.profile, regime=args.regime or None)
    with open(pol_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"[ok] policy result: {pol_path}: {result['policy']['policyId']} {result['policy']['version']}, "
          f"{result['summary']}")
    with open(args.out) as f:
        view = policymod.apply(json.load(f), result, args.out)
    fail_hits = fail_on_hits(result, view, args.fail_on)

    # --- report (executive scorecard + migration roadmap) ---
    att_path = out_base + ".attestation.json"
    att_name = os.path.basename(att_path)
    rpt = out_base + ".report.md"
    attention = None
    if os.path.exists(out_base + ".attention.json"):
        os.remove(out_base + ".attention.json")    # never ship a ranking from an earlier run
    if args.context:
        args.report = True
        try:
            # the CBOM on disk is redacted; apply the same replacements to the context (patterns and names)
            attention = ctxmod.rank(args.context, args.out, args.profile,
                                    [r.split("=", 1) for r in args.redact if "=" in r])
            with open(out_base + ".attention.json", "w") as f:
                json.dump(attention, f, indent=2)
            print(f"[ok] context: {len(attention['endpoints'])} endpoint(s) ranked, "
                  f"{sum(1 for r in attention['endpoints'] if r['urgent'] == 'yes')} urgent, "
                  f"{len(attention['noContext'])} without context (horizon {attention['horizon']}) "
                  f"-> {out_base}.attention.json")
        except Exception as e:   # the scan is done; report without context rather than lose the output
            sys.stderr.write(f"[warn] --context could not be applied ({e}); the report has no attention order\n")
            attention = None
    if args.report:
        summ = out_base + ".summary.json"
        try:
            # Always render UNSIGNED first: the "signed" claim is added only after signing
            # actually succeeds (see the --sign block). Fail-closed by construction: nothing on
            # disk ever claims an attestation that does not exist.
            md, summary = reportmod.build_report(view, self_serve=args.self_serve, brand=args.brand,
                                                 signed=False, attention=attention)
            with open(rpt, "w") as f:
                f.write(md + "\n")
            with open(summ, "w") as f:
                json.dump(summary, f, indent=2)
            print(f"[ok] report: {rpt}: score {summary['readiness_score']}{' (incomplete)' if summary['incomplete'] else ''}, "
                  f"algorithms (all lanes): {summary['quantum_vulnerable']} vulnerable / {summary['quantum_resistant']} resistant")
        except Exception as e:
            sys.stderr.write(f"[warn] report generation failed: {e}\n")

    # --- delta vs prior baseline (continuous-monitoring evidence) ---
    if args.baseline and deltamod is not None:
        dpath = args.out.rsplit(".", 1)[0] + ".delta.md"
        dsumm = args.out.rsplit(".", 1)[0] + ".delta.summary.json"
        try:
            # Both snapshots are judged by the same ruleset and profile so the movement is comparable.
            base, _ = policymod.load_view(args.baseline, profile=args.profile, regime=args.regime or None)
            md, summary = deltamod.build_delta(view, base)
            with open(dpath, "w") as f:
                f.write(md + "\n")
            with open(dsumm, "w") as f:
                json.dump(summary, f, indent=2)
            print(f"[ok] delta: {dpath}: score {summary['score_baseline']} -> "
                  f"{summary['score_current']}, {summary['new_vulnerable']} new, "
                  f"{summary['regressions']} regressions")
        except Exception as e:
            sys.stderr.write(f"[warn] delta generation failed: {e}\n")

    # --- migration wave check (each declared item against this scan) ---
    wpath = out_base + ".wave.json"
    for stale in (wpath, out_base + ".wave.md"):
        if os.path.exists(stale):   # never sign or ship a wave result from an earlier run
            os.remove(stale)
    if args.wave:
        try:
            wres = wavemod.check(args.wave, args.out, args.baseline or None)
            with open(wpath, "w") as f:
                json.dump(wres, f, indent=2)
            with open(out_base + ".wave.md", "w") as f:
                f.write(wavemod.markdown(wres))
            s_ = wres["summary"]
            print(f"[{'ok' if wres['passed'] else 'not passed'}] wave check: {s_['pass']}/{s_['items']} passed, "
                  f"{s_['fail']} failed, {s_['not-observed']} not observed -> {wpath}")
        except Exception as e:
            sys.stderr.write(f"[error] wave check failed: {e}\n")
            sys.exit(2)

    # --- sign (detached SLH-DSA attestation over CBOM + report [+ delta] [+ wave result]) ---
    if args.sign:
        dpath = out_base + ".delta.md"

        signer = None

        def _rewrite_report(signed):
            """Re-render the report with/without the attestation claim. Returns True on success."""
            md_, _ = reportmod.build_report(view, self_serve=args.self_serve, brand=args.brand,
                                            signed=signed, attestation_name=att_name if signed else None,
                                            attention=attention, signer=signer if signed else None)
            with open(rpt, "w") as f:
                f.write(md_ + "\n")
            return True

        def _artifacts():
            a = [args.out, pol_path]
            if args.report and os.path.exists(rpt):
                a.append(rpt)
            if args.baseline and os.path.exists(dpath):
                a.append(dpath)
            if args.context and os.path.exists(out_base + ".attention.json"):
                a.append(out_base + ".attention.json")
            if args.wave and os.path.exists(wpath):
                a += [args.wave, wpath, out_base + ".wave.md"]
            return a

        # bind the CBOM's own timestamp so the attestation is deterministic (not a clock read)
        try:
            with open(args.out) as f:
                cbom_ts = json.load(f).get("metadata", {}).get("timestamp")
        except Exception:
            cbom_ts = None
        try:
            # Upgrade the report to CLAIM the attestation, THEN sign so the signature covers that exact
            # text. Order matters: the on-disk report was written UNSIGNED above, so any failure here
            # leaves (or is restored to) an unsigned report: never a false claim.
            # name the key that will sign before the report claims it (FEDLIN only for the published key)
            signer = signmod.signing_identity(key_file=args.slh_key or None, variant=args.slh_variant or None,
                                              node_bin=args.node)
            if args.report and os.path.exists(rpt):
                _rewrite_report(signed=True)
            att = signmod.sign_artifacts(_artifacts(), att_path, signed_at=cbom_ts,
                                         key_file=args.slh_key or None,
                                         variant=args.slh_variant or None,
                                         node_bin=args.node)
            print(f"[ok] attestation: {att_path}: {att['algorithm']}, keyId {att['publicKeyId']}, "
                  f"{len(att['artifacts'])} artifact(s) signed (verify: python3 sign.py verify {att_name})")
        except Exception as e:
            sys.stderr.write(f"[error] signing failed: {e}\n"
                             "  re-run with a valid $SPHINCS_PRIVATE_KEY_B64 or --slh-key.\n")
            # claim discipline (§8): guarantee no unsigned deliverable ships asserting an attestation.
            if args.report and os.path.exists(rpt):
                try:
                    _rewrite_report(signed=False)
                    sys.stderr.write("  report restored WITHOUT the signature claim (unsigned).\n")
                except Exception:
                    # if we cannot guarantee an honest report, ship none rather than a false claim
                    try:
                        os.remove(rpt)
                    except OSError:
                        pass
                    sys.stderr.write("  could not restore an unsigned report: removed it to avoid a false claim.\n")
            if os.path.exists(att_path):  # drop any partial/failed attestation
                try:
                    os.remove(att_path)
                except OSError:
                    pass
            sys.exit(2)

    # --- validate ---
    if args.validate:
        r = _cyclonedx(cyclonedx_bin, ["validate", "--input-file", args.out, "--input-version", "v1_6",
                                       "--fail-on-errors"])
        if r is None:
            sys.exit(2)
        print(r.stdout.strip() or r.stderr.strip())
        if r.returncode:
            sys.exit(r.returncode)
    if fail_hits:
        print(f"[fail-on] the scan found {', '.join(f'{n} {k}' for k, n in fail_hits.items())} "
              f"(--fail-on {','.join(sorted(args.fail_on))}): exit {EXIT_FAIL_ON}")
        sys.exit(EXIT_FAIL_ON)


if __name__ == "__main__":
    main()
