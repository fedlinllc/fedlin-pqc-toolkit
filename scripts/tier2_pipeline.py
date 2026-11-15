#!/usr/bin/env python3
"""FEDLIN PQC Toolkit — runtime and endpoint capture -> CycloneDX 1.6 CBOM.

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
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import uuid

import cnsa20_ruleset as cnsa
import policy as policymod
import report as reportmod

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
    "baseline": deltamod is not None,
    "sign": signmod is not None, "slh_key": signmod is not None, "slh_variant": signmod is not None,
    "node": signmod is not None,
    "self_serve": reportmod._roadmap is not None,
    "brand": reportmod._whitelabel is not None,
}


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

    Lets the runtime tier work on EKS/GKE/AKS/k3s (kubectl) — not just OpenShift (`oc`) — by
    swapping Route capture for Ingress capture. Critically distinguishes a genuine non-OpenShift
    cluster from an unreachable/RBAC-limited one: if the API server serves NO resources at all,
    we must not silently claim 'generic kubernetes' and capture nothing — we flag it.
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
    are unavailable here — record the server version and the crypto signals that ARE portable
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


def valid_host(host):
    return bool(host) and len(host) <= 253 and bool(_HOST_RE.match(host))


def _hp(host, port):
    """Shell-quoted host:port and host for openssl command lines (host already validated)."""
    return shlex.quote(f"{host}:{int(port)}"), shlex.quote(host)


def _parse_session(out):
    """Negotiated protocol version and cipher suite from openssl s_client output."""
    proto = cipher = None
    m = re.search(r"New,\s*(TLSv[\d.]+|SSLv\d),\s*Cipher is\s*(\S+)", out)
    if m:
        proto, cipher = m.group(1), m.group(2)
    m = re.search(r"^\s*Protocol\s*:\s*(TLSv[\d.]+|SSLv\d)", out, re.M)
    if m:
        proto = m.group(1)
    m = re.search(r"^\s*Cipher\s*:\s*(\S+)", out, re.M)
    if m and m.group(1) not in ("0000", "(NONE)"):
        cipher = m.group(1)
    return proto, cipher


_KEX_GROUPS = "X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:X25519:secp256r1:secp384r1"
# What OpenSSL in FIPS mode will offer: no X25519-based groups.
_KEX_GROUPS_FIPS = "SecP256r1MLKEM768:SecP384r1MLKEM1024:secp256r1:secp384r1:secp521r1"
_PQC_HYBRIDS = ("x25519mlkem768", "secp256r1mlkem768", "secp384r1mlkem1024", "mlkem")


def _parse_kex_group(out):
    """Key-exchange group from openssl s_client output (OpenSSL 3.0 to 3.5 formats)."""
    m = re.search(r"Negotiated TLS1\.3 group:\s*([A-Za-z0-9_]+)", out)
    if m and m.group(1) != "NULL":
        return m.group(1)
    # "Peer Temp Key: ECDH, prime256v1, 256 bits" / "Server Temp Key: X25519, 253 bits"
    m = re.search(r"(?:Peer|Server) Temp Key:\s*([^,\n]+)(?:,\s*([A-Za-z0-9_-]+))?", out)
    if m:
        first, second = m.group(1).strip(), (m.group(2) or "").strip()
        if first.upper() in ("ECDH", "DH") and second and not second.isdigit():
            return second
        return first
    return None


def _is_pqc_group(g):
    return bool(g) and any(h in g.lower() for h in _PQC_HYBRIDS)


def _probe_kex_group_container(host, port, image):
    """Run kex probe inside a non-FIPS container (Alpine edge ships OpenSSL 3.5 w/ ML-KEM groups)."""
    inner = (
        # The image must ship OpenSSL >= 3.5; nothing is installed at run time (no unpinned packages).
        f"command -v openssl >/dev/null 2>&1 || {{ echo 'kex-probe-image-has-no-openssl'; exit 3; }}; "
        f"echo | timeout 8 openssl s_client -connect {_hp(host, port)[0]} "
        f"-servername {_hp(host, port)[1]} -groups {_KEX_GROUPS} 2>&1"
    )
    try:
        p = subprocess.run(
            ["podman", "run", "--rm", "--pull=never", image, "sh", "-c", inner],
            capture_output=True, text=True, timeout=90
        )
        return _parse_kex_group(p.stdout + p.stderr)
    except Exception as e:
        sys.stderr.write(f"[warn] kex container probe {host}: {e}\n")
        return None


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

    Order: host OpenSSL with the full offer; if the host refuses the offer and FEDLIN_KEX_PROBE_IMAGE
    names a digest-pinned non-FIPS image with OpenSSL >= 3.5, that container; else the host with
    the FIPS-offerable subset.
    """
    hp, h = _hp(host, port)
    base = f"echo | timeout 8 openssl s_client -connect {hp} -servername {h} -groups "
    out = run(base + _KEX_GROUPS + " 2>&1")
    if "SSL_CONF_cmd" not in out:
        return _parse_kex_group(out), "host", True
    img = os.environ.get("FEDLIN_KEX_PROBE_IMAGE", "") or _default_probe_image()
    if img:
        grp = _probe_kex_group_container(host, port, img)
        if grp:
            return grp, "container", True
    out = run(base + _KEX_GROUPS_FIPS + " 2>&1")
    return _parse_kex_group(out), "host-fips-subset", False


def capture_cert(host, port=443):
    if not valid_host(host):
        sys.stderr.write(f"[warn] endpoint {host!r}: not a valid hostname or IP, skipped\n")
        return None
    hp, h = _hp(host, port)
    base = f"echo | timeout 8 openssl s_client -connect {hp} -servername {h} 2>/dev/null | openssl x509 -noout"
    meta = run(base + " -subject -issuer -dates")
    text = run(base + " -text")
    if not text:
        return None
    def grab(pat, s):
        m = re.search(pat, s)
        return m.group(1).strip() if m else None
    key_bits = grab(r"Public-Key:\s*\((\d+)\s*bit\)", text)
    key_alg = grab(r"Public Key Algorithm:\s*(\S+)", text)
    sig_alg = grab(r"Signature Algorithm:\s*(\S+)", text)
    chain = run(f"echo | timeout 8 openssl s_client -connect {hp} -servername {h} "
                f"-showcerts 2>/dev/null | grep -c 'BEGIN CERTIFICATE'")
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
    certs = []
    for h in hosts:
        c = capture_cert(h)
        if c:
            certs.append(c)
    return certs


def capture_ingress(kube="kubectl"):
    """Live TLS capture over generic-kubernetes Ingress hosts (the non-OpenShift Route analogue).

    Reads Ingress rule hosts and TLS hosts (public object fields only), then does the same
    public-certificate handshake capture as the Route path. Works on any k8s
    (EKS/GKE/AKS/k3s) with an Ingress controller.
    """
    rule_hosts = run(f"{kube} get ingress -A -o jsonpath='{{range .items[*]}}{{range .spec.rules[*]}}{{.host}}{{\"\\n\"}}{{end}}{{end}}'")
    tls_hosts = run(f"{kube} get ingress -A -o jsonpath='{{range .items[*]}}{{range .spec.tls[*]}}{{range .hosts[*]}}{{@}}{{\"\\n\"}}{{end}}{{end}}{{end}}'")
    hosts = sorted(set(h for h in (rule_hosts + "\n" + tls_hosts).splitlines() if h))
    certs = []
    for h in hosts:
        c = capture_cert(h)
        if c:
            certs.append(c)
    return certs


def parse_endpoints(values):
    """Expand --endpoints values into a deduped, order-preserving list of host[:port] tokens.

    Each value is either a path to a file (one endpoint per line, '#' comments allowed) or an
    inline comma/space-separated list. Tokens are normalized: scheme and path are stripped, so
    'https://mail.agency.gov/owa' -> 'mail.agency.gov'. This is the no-cluster on-ramp — the
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
        if not t or t in seen:
            continue
        host = t.rsplit(":", 1)[0] if t.count(":") == 1 or t.startswith("[") else t
        if not valid_host(host):
            sys.stderr.write(f"[warn] --endpoints: {t!r} is not a valid hostname or IP, skipped\n")
            continue
        seen.add(t)
        out.append(t)
    return out


def capture_endpoints(hosts, workers=16):
    """Live TLS cert capture over an explicit host[:port] list (no cluster needed).

    Reuses capture_cert (public certificate metadata only — never a private key or secret value),
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
    """Best-effort node FIPS check. INTRUSIVE — spins a short-lived debug pod; gated behind --deep.

    Uses `oc debug node` on OpenShift; falls back to `kubectl debug node` (k8s 1.20+) elsewhere.
    """
    node = run(f"{kube} get nodes -o jsonpath='{{.items[0].metadata.name}}'")
    if not node:
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

    Non-intrusive read of the local kernel flag — no cluster needed. In endpoint/no-runtime mode
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
    return {
        "version": ver,
        "kex": [x for x in line("kexalgorithms").split(",") if x],
        "ciphers": [x for x in line("ciphers").split(",") if x],
        "hostkeys": [x for x in line("hostkeyalgorithms").split(",") if x],
    }


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


class CBOM:
    def __init__(self, system_name, system_ver, context, regime=None):
        self.components = []
        self.dependencies = []
        self._algo_refs = {}
        self.system_name = system_name
        self.system_ver = system_ver
        self.context = context
        self.regime = regime
        self.subject_tag = None      # RFC 4151 tag URI identifying the deployment (PKIC P3)
        self.coverage = "partial"    # a scan covers only what it was pointed at (PKIC P4)
        self._cert_algos = {}        # host -> [(ref, name)] of the served certificate's key and signature
        self._cert_bits = {}         # host -> certificate key size (EC field size names the curve)
        self._interfaces = 0

    def algo_ref(self, name, bits=None):
        key = slug(f"{name}-{bits or ''}")
        if key in self._algo_refs:
            return self._algo_refs[key]
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
        self.components.append(comp)
        self._algo_refs[key] = ref
        return ref

    def add_certificate(self, c):
        ref = f"crypto/cert/{slug(c['host'])}"
        key_ref = self.algo_ref(c["key_alg"], c.get("key_bits"))
        deps = [key_ref]
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
            sig_ref = self.algo_ref(c["sig_alg"])
            self._cert_algos[c["host"]][-1] = (sig_ref, c["sig_alg"])
            cp["signatureAlgorithmRef"] = sig_ref
            deps.append(sig_ref)
        if c.get("not_before"):
            cp["notValidBefore"] = c["not_before"]
        if c.get("not_after"):
            cp["notValidAfter"] = c["not_after"]
        comp = {
            "type": "cryptographic-asset", "bom-ref": ref, "name": c["host"],
            "cryptoProperties": {"assetType": "certificate", "certificateProperties": cp},
        }
        if c.get("chain_depth"):
            comp["properties"] = [{"name": "fedlin:chain_depth", "value": str(c["chain_depth"])}]
        self.components.append(comp)
        self.dependencies.append({"ref": ref, "dependsOn": deps})

    def add_tls_kex(self, host, kex_group=None, protocol=None, cipher=None, kex_partial=None):
        """Add one TLS interface per endpoint: negotiated version, cipher suite, key exchange.

        Shaped for the PKI Consortium CBOM interface profiles: the asset is a 'service' interface
        observed from the client side, with protocol, protocolVersion, keyExchange, encryption and
        authentication (the served certificate's key and signature algorithms). Anything the scan did
        not observe is declared 'unknown' rather than left silent. Session properties are scored
        separately from the certificate's algorithms; the version is the one actually negotiated.
        """
        if not (kex_group or protocol or cipher):
            return
        deps = []
        for name in (kex_group, cipher, protocol):
            if name:
                deps.append(self.algo_ref(name))
        version = protocol[4:] if protocol and protocol.startswith("TLSv") else None
        ref = f"crypto/proto/tls/{slug(host)}"
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
        props = [{"name": P + "interfaceType", "value": "service"},
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
        self.components.append({
            "type": "cryptographic-asset", "bom-ref": ref,
            "name": f"TLS {version or '(version not observed)'} - {host}",
            "cryptoProperties": {"assetType": "protocol", "protocolProperties": pp},
            "properties": props,
        })
        self.dependencies.append({"ref": ref, "dependsOn": sorted(set(deps))})
        self._interfaces += 1

    def add_ssh(self, ssh):
        algos = []
        for a in ssh.get("kex", []) + ssh.get("hostkeys", []) + ssh.get("ciphers", []):
            if cnsa.is_pseudo(a):  # protocol markers such as ext-info-c, kex-strict-*
                continue
            algos.append(self.algo_ref(a))
        ref = "crypto/proto/ssh"
        # Configuration evidence (sshd -T on this host), not an observed interface: one PKIC document
        # carries one lifecycle stage, and the TLS interfaces are observed. A remote SSH handshake scan
        # (observed) would make this an interface.
        self.components.append({
            "type": "cryptographic-asset", "bom-ref": ref, "name": ssh.get("version", "OpenSSH"),
            "cryptoProperties": {"assetType": "protocol",
                                 "protocolProperties": {"type": "ssh", "version": "2.0"}},
            "properties": [{"name": "fedlin:evidence", "value": "configured (sshd -T, local host)"}],
        })
        if algos:
            self.dependencies.append({"ref": ref, "dependsOn": sorted(set(algos))})

    def add_sealed_secrets(self, count):
        ref = "crypto/material/sealed-secrets-key"
        key_ref = self.algo_ref("rsaEncryption", 4096)
        self.components.append({
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
        })
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
            "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
            "metadata": {
                "timestamp": ts,
                "component": self._subject(),
                "lifecycles": [{"phase": "discovery" if self._interfaces else "build"}],
                "tools": {"components": [{"type": "application", "name": "fedlin-pqc-toolkit",
                                          "version": f"0.5.0-dev (ruleset {cnsa.RULESET_VERSION}, "
                                                     f"profile {cnsa.DEFAULT_PROFILE})",
                                          "publisher": "FEDLIN"}]},
                "properties": props,
            },
            "components": self.components,
            "dependencies": self.dependencies,
        }


def generate_deps_sbom(repo, cdxgen_bin, out):
    """Run cdxgen against a source repo/dir -> CycloneDX dependency SBOM."""
    cmd = f'{cdxgen_bin} --spec-version 1.6 -o {out} "{repo}"'
    sys.stderr.write(f"[deps] cdxgen on {repo} ...\n")
    run(cmd, timeout=240)
    if os.path.exists(out) and os.path.getsize(out) > 0:
        try:
            with open(out) as f:
                n = len(json.load(f).get("components", []))
            print(f"[ok] cdxgen dependency SBOM: {n} components")
            return True
        except Exception:
            pass
    sys.stderr.write("[warn] cdxgen produced no usable SBOM; continuing runtime-only\n")
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
    classifies them — surfacing BOTH compliant (PQC/AES-256/SHA) and non-compliant (RSA/ECDSA)
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
    OID it can't parse (EdDSA/RFC 8410; ML-DSA/SLH-DSA/2024 OIDs — confirmed in lab
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
        added += 1
    return added


def filter_excluded(doc, patterns):
    """Drop components whose evidence location matches an --exclude glob/substring.

    Location-based, so it cuts noise from any tool that records occurrences (e.g. gitleaks
    hits in docs/, scratch/, *.backup). Components without a location (cdxgen deps) are kept.
    """
    if not patterns:
        return 0

    def loc_match(loc, pat):
        if any(ch in pat for ch in "*?["):
            return (fnmatch.fnmatch(loc, pat) or fnmatch.fnmatch(loc, "*/" + pat)
                    or fnmatch.fnmatch(os.path.basename(loc), pat))
        return pat in loc

    kept, dropped, dropped_refs = [], 0, set()
    for c in doc.get("components", []):
        locs = [o.get("location", "") for o in (c.get("evidence", {}).get("occurrences") or []) if o.get("location")]
        if locs and any(loc_match(loc, p) for loc in locs for p in patterns):
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


def convert_bom(cyclonedx_bin, inp, out, version="v1_6"):
    r = subprocess.run([cyclonedx_bin, "convert", "--input-file", inp,
                        "--output-file", out, "--output-version", version],
                       capture_output=True, text=True)
    return r.returncode == 0


def generate_theia_cbom(theia_bin, mode, target, cyclonedx_bin, out):
    """Run cbomkit-theia (dir|image) -> CycloneDX (1.7) -> convert to 1.6 -> out."""
    sys.stderr.write(f"[theia] cbomkit-theia {mode} {target} ...\n")
    try:
        r = subprocess.run([theia_bin, mode, target], capture_output=True, text=True, timeout=240)
    except Exception as e:
        sys.stderr.write(f"[warn] cbomkit-theia failed: {e}\n")
        return False
    if not r.stdout.strip():
        sys.stderr.write(f"[warn] cbomkit-theia no output: {r.stderr.strip()[:160]}\n")
        return False
    raw = out + ".raw.json"
    with open(raw, "w") as f:
        f.write(r.stdout)
    if not convert_bom(cyclonedx_bin, raw, out):
        shutil.copy(raw, out)
    try:
        with open(out) as f:
            n = len(json.load(f).get("components", []))
        print(f"[ok] cbomkit-theia ({mode}) CBOM: {n} components")
        return n > 0
    except Exception:
        return False


def merge_boms(cyclonedx_bin, inputs, out):
    r = subprocess.run([cyclonedx_bin, "merge", "--input-files", *inputs,
                        "--output-file", out, "--output-version", "v1_6"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(f"[warn] merge failed: {r.stderr.strip()}\n")
        return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="out/cbom.json")
    ap.add_argument("--name", default="openshift-cluster")
    ap.add_argument("--repo", default="", help="optional source repo/dir -> cdxgen dependency SBOM, merged in")
    ap.add_argument("--theia-dir", default="", help="optional dir -> cbomkit-theia scan (certificates, keys, secret-hygiene findings; may read key files), merged in")
    ap.add_argument("--theia-image", default="", help="optional container image ref -> cbomkit-theia scan, merged in")
    ap.add_argument("--cdxgen", default="", help="path to cdxgen (default: ../node_modules/.bin/cdxgen)")
    ap.add_argument("--theia", default="", help="path to cbomkit-theia (default: ../bin/cbomkit-theia)")
    ap.add_argument("--cyclonedx", default="", help="path to cyclonedx-cli (for merge + validate)")
    ap.add_argument("--validate", action="store_true", help="validate the final CBOM (needs --cyclonedx)")
    ap.add_argument("--redact", action="append", default=[],
                    help="old=new string replacement on the final CBOM (repeatable), e.g. corp.internal=example.gov")
    ap.add_argument("--profile", choices=list(cnsa.PROFILES), default=cnsa.DEFAULT_PROFILE,
                    help="verdict profile: civilian (NIST FIPS 203/204/205 + IR 8547, default) or "
                         "nss (NSA CNSA 2.0)")
    ap.add_argument("--subject-tag", default="",
                    help="RFC 4151 tag URI naming the deployment this CBOM describes, e.g. "
                         "tag:example.com,2026-11-14:prod-edge (PKI Consortium profile rule P3). "
                         "Default: tag:<system name if it is a DNS name, else pqc-toolkit.invalid>,<date>:<name>")
    ap.add_argument("--regime", default="",
                    help="annotate assets with a regime crosswalk: FISMA|CMMC|HIPAA|PCI-DSS|GLBA|NERC-CIP")
    ap.add_argument("--deep", action="store_true",
                    help="run intrusive checks (FIPS via oc/kubectl debug node — spins a short-lived pod)")
    ap.add_argument("--debug-image", default="",
                    help="image for --deep on non-OpenShift clusters (kubectl debug node); pin by digest")
    ap.add_argument("--kube-cli", default="oc",
                    help="kubernetes CLI for runtime capture: oc (OpenShift) or kubectl (EKS/GKE/AKS/k3s). "
                         "Platform is auto-detected; on non-OpenShift, Route capture becomes Ingress capture.")
    ap.add_argument("--report", action="store_true",
                    help="also emit an executive scorecard + migration roadmap (<out>.report.md)")
    ap.add_argument("--baseline", default="",
                    help="prior CBOM to diff against -> continuous-monitoring delta (<out>.delta.md)")
    ap.add_argument("--merge-cbom", action="append", default=[],
                    help="path to an externally-generated CycloneDX CBOM to fold in (repeatable), e.g. a "
                         "CBOMkit source scan produced out-of-band by scripts/run-cbomkit.sh (source coverage)")
    ap.add_argument("--exclude", action="append", default=[],
                    help="drop assets whose evidence location matches this glob/substring (repeatable), e.g. "
                         "--exclude docs/ --exclude scratch/ --exclude '*.backup' — cuts false-positive noise")
    ap.add_argument("--no-dep-crypto", action="store_true",
                    help="disable inferring crypto capability from known library dependencies (cdxgen SBOM)")
    ap.add_argument("--endpoints", action="append", default=[],
                    help="live TLS endpoint scan WITHOUT a cluster: a file of host[:port] lines (# comments ok) "
                         "and/or an inline comma list, e.g. --endpoints agency-hosts.txt --endpoints www.agency.gov. "
                         "Works with --no-runtime (endpoint-only, the thin-footprint on-ramp) or augments cluster "
                         "routes in a cluster run. Reads public certificate metadata only.")
    ap.add_argument("--no-runtime", action="store_true",
                    help="skip the OCP cluster capture (oc) — build the CBOM from "
                         "--endpoints/--repo/--theia-dir only")
    ap.add_argument("--self-serve", action="store_true",
                    help="Unattended automated-scan mode: implies --no-runtime + --report; emits a GATED report "
                         "(automated-scan disclaimer, confidence bands, engineered roadmap withheld)")
    ap.add_argument("--brand", default="FEDLIN",
                    help="white-label the report deliverable under a reseller's name")
    ap.add_argument("--sign", action="store_true",
                    help="emit a detached SLH-DSA (FIPS 205) attestation over the CBOM + report + delta "
                         "(<out>.attestation.json), making the 'signed, tamper-evident' claim literal. "
                         "Needs a signing key: $SPHINCS_PRIVATE_KEY_B64 or --slh-key.")
    ap.add_argument("--slh-key", default="",
                    help="SLH-DSA private-key file for --sign (default: $SPHINCS_PRIVATE_KEY_B64)")
    ap.add_argument("--slh-variant", default="",
                    help="SLH-DSA variant for --sign (default: slh_dsa_sha2_128f, FIPS 205)")
    ap.add_argument("--node", default="node", help="node binary used by the SLH-DSA signer")
    for action in ap._actions:
        if action.dest in KIT_FLAGS and not KIT_FLAGS[action.dest]:
            action.help = argparse.SUPPRESS
    args = ap.parse_args()
    for dest, avail in KIT_FLAGS.items():
        val, default = getattr(args, dest, None), ap.get_default(dest)
        if not avail and val not in (None, False, "", [], default):
            ap.error(f"--{dest.replace('_', '-')} is part of the FEDLIN engagement kit and is not in this build")
    cnsa.DEFAULT_PROFILE = args.profile  # every classify() call in this run uses the chosen profile

    # Self-serve: deterministic, source-based, gated output.
    if args.self_serve:
        args.no_runtime = True
        args.report = True
        if not (args.repo or args.theia_dir or args.merge_cbom or args.endpoints):
            sys.stderr.write("[error] --self-serve needs a source: pass --endpoints <hosts>, --repo <dir>, "
                             "--theia-dir <dir>, and/or --merge-cbom <cbom.json>\n")
            sys.exit(2)

    here = os.path.dirname(os.path.abspath(__file__))
    cdxgen_bin = args.cdxgen or os.path.join(here, "..", "node_modules", ".bin", "cdxgen")
    cyclonedx_bin = args.cyclonedx or os.path.join(here, "..", "bin", "cyclonedx")
    theia_bin = args.theia or os.path.join(here, "..", "bin", "cbomkit-theia")

    # --- runtime capture (cluster) — skipped for --no-runtime / --self-serve (source-based) ---
    if args.no_runtime:
        ssh = None
        counts = {"tls_secrets": 0, "sealed_secrets": 0}
        hosts = parse_endpoints(args.endpoints)
        certs = capture_endpoints(hosts) if hosts else []
        if hosts:
            mode = "self-serve" if args.self_serve else "endpoint-scan"
            ctx = {"mode": mode,
                   "capture": f"live TLS endpoint scan — {len(certs)}/{len(hosts)} endpoint(s) reachable",
                   "endpoints_supplied": len(hosts)}
        else:
            ctx = {"mode": "self-serve" if args.self_serve else "no-runtime",
                   "capture": "source/dir only — no runtime endpoint capture"}
        # record the FIPS posture the scan itself ran under (scan host / in-boundary container)
        ctx["fips"] = read_local_fips()
    else:
        kube = args.kube_cli
        platform = detect_platform(kube)
        if platform == "unreachable":
            sys.stderr.write(
                f"[warn] cluster unreachable or RBAC-limited: `{kube} api-resources` returned nothing — wrong "
                "context, cluster down, or the token cannot list resources. The runtime tier captured NO "
                "route/ingress/edge TLS or cluster context. Fix KUBECONFIG/RBAC, or use --endpoints for edge "
                "TLS (and --repo/--theia-dir for code/image crypto).\n")
            ctx = {"mode": "runtime (cluster unreachable)",
                   "capture": f"{kube} api-resources returned nothing — no cluster capture",
                   "ocp_version": "unknown"}
            certs = []
        elif platform == "openshift":
            ctx = capture_context(kube)
            certs = capture_routes(kube)
            if ctx.get("ocp_version", "unknown") == "unknown":
                sys.stderr.write(
                    "[warn] OpenShift route/version APIs returned nothing despite the route API being served "
                    "— RBAC-limited or a partial outage. Route/edge TLS and cluster context may be incomplete. "
                    "Use --endpoints for edge TLS.\n")
        else:
            sys.stderr.write(
                f"[info] non-OpenShift kubernetes detected ({kube}); capturing Ingress TLS instead of "
                "Routes. OpenShift-only context (etcd encryption, ingresscontroller TLS profile) is "
                "unavailable — supplement with --endpoints for edge TLS.\n")
            ctx = capture_context_generic(kube)
            certs = capture_ingress(kube)
        hosts = parse_endpoints(args.endpoints)
        if hosts:
            seen = {c["host"] for c in certs}
            for c in capture_endpoints(hosts):
                if c["host"] not in seen:
                    certs.append(c)
                    seen.add(c["host"])
            ctx["endpoints_supplied"] = len(hosts)
        counts = capture_counts(kube)
        ssh = capture_ssh()
        ctx.update({"tls_secret_count": counts["tls_secrets"], "sealed_secret_count": counts["sealed_secrets"]})
        ctx["fips"] = capture_fips(kube, platform, args.debug_image) if args.deep else "not checked (use --deep)"
    if args.regime:
        ctx["regime"] = args.regime
    ctx["profile"] = args.profile

    b = CBOM(args.name, ctx.get("ocp_version", "unknown"), ctx, regime=args.regime or None)
    b.subject_tag = args.subject_tag or default_subject_tag(args.name)
    for c in certs:
        b.add_certificate(c)
        b.add_tls_kex(c["host"], c.get("kex_group"), c.get("tls_protocol"), c.get("tls_cipher"),
                      c.get("kex_partial"))
    if certs:
        vias = [c.get("kex_probe_via") for c in certs]
        img = os.environ.get("FEDLIN_KEX_PROBE_IMAGE", "") or _default_probe_image()
        parts = []
        if "host" in vias:
            parts.append("host OpenSSL, full offer")
        if "container" in vias:
            parts.append(f"container {img}, full offer")
        if "host-fips-subset" in vias:
            parts.append("FIPS host, reduced offer (no X25519MLKEM768); classical results not recorded; "
                         "build images/kex-probe or set FEDLIN_KEX_PROBE_IMAGE")
        ctx["kex_probe"] = "; ".join(parts) or "not run"
    if ssh:
        b.add_ssh(ssh)
    if counts["sealed_secrets"]:
        b.add_sealed_secrets(counts["sealed_secrets"])
    doc = b.to_dict()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    runtime_tmp = args.out + ".runtime.json"
    with open(runtime_tmp, "w") as f:
        json.dump(doc, f, indent=2)

    n_assets = sum(1 for c in doc["components"] if c["type"] == "cryptographic-asset")
    print(f"[ok] runtime CBOM: {n_assets} crypto-asset components, {len(certs)} certs, "
          f"{counts['tls_secrets']} TLS secrets, "
          f"{counts['sealed_secrets']} sealed secrets")

    # --- optional dependency SBOM (source components) + merge ---
    inputs = [runtime_tmp]
    if args.repo:
        deps_tmp = args.out + ".deps.json"
        if generate_deps_sbom(args.repo, cdxgen_bin, deps_tmp):
            inputs.append(deps_tmp)
    if args.theia_dir:
        t = args.out + ".theia-dir.json"
        if generate_theia_cbom(theia_bin, "dir", args.theia_dir, cyclonedx_bin, t):
            inputs.append(t)
    if args.theia_image:
        t = args.out + ".theia-image.json"
        if generate_theia_cbom(theia_bin, "image", args.theia_image, cyclonedx_bin, t):
            inputs.append(t)
    # generic external CycloneDX CBOM ingest (e.g. CBOMkit source scan, run out-of-band)
    for i, extra in enumerate(args.merge_cbom):
        if not os.path.exists(extra):
            sys.stderr.write(f"[warn] --merge-cbom {extra}: not found, skipping\n")
            continue
        conv = f"{args.out}.merge{i}.json"
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
            sys.stderr.write(f"[warn] --merge-cbom {extra}: unreadable ({e}), skipping\n")
    if len(inputs) > 1 and merge_boms(cyclonedx_bin, inputs, args.out):
        print(f"[ok] merged runtime + dependency SBOM -> {args.out}")
    else:
        shutil.copy(runtime_tmp, args.out)
        print(f"[ok] wrote {args.out} (runtime-only)")

    # --- sanitize (drop null enum fields) + universal overlay + optional redaction ---
    with open(args.out) as f:
        final = strip_nones(json.load(f))
    # A merge can replace metadata.component and drop metadata.lifecycles; the subject and the stage
    # describe what was scanned, so they always come from the runtime builder.
    final.setdefault("metadata", {})["component"] = doc["metadata"]["component"]
    final["metadata"]["lifecycles"] = doc["metadata"]["lifecycles"]
    n_excluded = filter_excluded(final, args.exclude)
    if n_excluded:
        print(f"[ok] --exclude dropped {n_excluded} asset(s) by path filter")
    if not args.no_dep_crypto:
        n_dep = detect_library_crypto(final)
        if n_dep:
            print(f"[ok] dependency-graph crypto detection: {n_dep} algorithm(s) inferred from known libraries "
                  f"(capability — SBOM presence, not confirmed usage)")
    if args.theia_dir:
        n_fb = fallback_cert_scan(args.theia_dir, final)
        if n_fb:
            print(f"[ok] fallback cert parser: recovered {n_fb} modern-OID cert(s) cbomkit-theia dropped "
                  f"(EdDSA/ML-DSA/SLH-DSA)")
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
            text = text.replace(old, new)
    if args.redact:
        print(f"[ok] applied {len(args.redact)} redaction(s)")
    with open(args.out, "w") as f:
        f.write(text)

    # --- policy (verdicts, bound to the CBOM bytes just written by SHA-256 digest) ---
    out_base = args.out.rsplit(".", 1)[0]
    pol_path = out_base + ".policy.json"
    result = policymod.evaluate(args.out, profile=args.profile, regime=args.regime or None)
    with open(pol_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"[ok] policy result: {pol_path} — {result['policy']['policyId']} {result['policy']['version']}, "
          f"{result['summary']}")
    with open(args.out) as f:
        view = policymod.apply(json.load(f), result, args.out)

    # --- report (executive scorecard + migration roadmap) ---
    att_path = out_base + ".attestation.json"
    att_name = os.path.basename(att_path)
    rpt = out_base + ".report.md"
    if args.report:
        summ = out_base + ".summary.json"
        try:
            # Always render UNSIGNED first — the "signed" claim is added only after signing
            # actually succeeds (see the --sign block). Fail-closed by construction: nothing on
            # disk ever claims an attestation that does not exist.
            md, summary = reportmod.build_report(view, self_serve=args.self_serve, brand=args.brand,
                                                 signed=False)
            with open(rpt, "w") as f:
                f.write(md + "\n")
            with open(summ, "w") as f:
                json.dump(summary, f, indent=2)
            print(f"[ok] report: {rpt} — score {summary['readiness_score']} ({summary['grade']}), "
                  f"{summary['quantum_vulnerable']} vulnerable / {summary['quantum_resistant']} resistant")
        except Exception as e:
            sys.stderr.write(f"[warn] report generation failed: {e}\n")

    # --- delta vs prior baseline (continuous-monitoring evidence) ---
    if args.baseline:
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
            print(f"[ok] delta: {dpath} — score {summary['score_baseline']} -> "
                  f"{summary['score_current']}, {summary['new_vulnerable']} new, "
                  f"{summary['regressions']} regressions")
        except Exception as e:
            sys.stderr.write(f"[warn] delta generation failed: {e}\n")

    # --- sign (detached SLH-DSA attestation over CBOM + report [+ delta]) ---
    if args.sign:
        dpath = out_base + ".delta.md"

        def _rewrite_report(signed):
            """Re-render the report with/without the attestation claim. Returns True on success."""
            md_, _ = reportmod.build_report(view, self_serve=args.self_serve, brand=args.brand,
                                            signed=signed, attestation_name=att_name if signed else None)
            with open(rpt, "w") as f:
                f.write(md_ + "\n")
            return True

        def _artifacts():
            a = [args.out, pol_path]
            if args.report and os.path.exists(rpt):
                a.append(rpt)
            if args.baseline and os.path.exists(dpath):
                a.append(dpath)
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
            # leaves (or is restored to) an unsigned report — never a false claim.
            if args.report and os.path.exists(rpt):
                _rewrite_report(signed=True)
            att = signmod.sign_artifacts(_artifacts(), att_path, signed_at=cbom_ts,
                                         key_file=args.slh_key or None,
                                         variant=args.slh_variant or None,
                                         node_bin=args.node)
            print(f"[ok] attestation: {att_path} — {att['algorithm']}, keyId {att['publicKeyId']}, "
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
                    sys.stderr.write("  could not restore an unsigned report — removed it to avoid a false claim.\n")
            if os.path.exists(att_path):  # drop any partial/failed attestation
                try:
                    os.remove(att_path)
                except OSError:
                    pass
            sys.exit(2)

    # --- validate ---
    if args.validate:
        r = subprocess.run([cyclonedx_bin, "validate", "--input-file", args.out,
                            "--input-version", "v1_6", "--fail-on-errors"],
                           capture_output=True, text=True)
        print(r.stdout.strip() or r.stderr.strip())
        sys.exit(r.returncode)


if __name__ == "__main__":
    main()
