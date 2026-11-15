#!/usr/bin/env python3
"""
collect-hardware-linux.py — FEDLIN PQC Toolkit hardware posture collector (Linux)

Emits a CycloneDX 1.6 component fragment for OS version, TPM presence, and HSM
presence. Pair the output with merge-hw-cbom.py to insert the components into your
CBOM before running the report stage.

Run on each Linux host in scope — directly or via SSH:
    python3 collect-hardware-linux.py --host fileserver.example.gov --pretty
    ssh root@host python3 < collect-hardware-linux.py -- --host host.example.gov

READS NO SECRETS, BY CONSTRUCTION: reads /etc/os-release, /sys/class/tpm/ sysfs (public
TPM metadata), process names (ps -e comm), and OpenSSL version strings. Never reads
private keys, certificate material, PKCS#11 session state, or TPM key hierarchies.

Network appliances (firewalls, load balancers) are NOT collected here — their PQC
posture is determined by the TLS kex probe in tier2_pipeline.py plus vendor firmware
timelines. Add them manually as hw/net/* components using the sample-agency-cbom.json
schema as a reference.
"""

import argparse
import json
import os
import pathlib
import socket
import subprocess
import sys


def _run(*cmd, timeout=10):
    """Run a command, return stdout string or '' on any failure. Never raises."""
    try:
        r = subprocess.run(list(cmd), capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def _os_release():
    fields = {}
    try:
        for line in pathlib.Path("/etc/os-release").read_text().splitlines():
            k, _, v = line.partition("=")
            fields[k.strip()] = v.strip().strip('"')
    except OSError:
        pass
    return fields


# ---- OS / PQC capability -------------------------------------------------------

def detect_os(hostname):
    osr = _os_release()
    os_id      = osr.get("ID", "").lower()
    os_version = osr.get("VERSION_ID", "")
    os_name    = osr.get("PRETTY_NAME", f"{os_id} {os_version}").strip()

    openssl_ver = _run("openssl", "version")

    # Definitive PQC check: ask OpenSSL whether ML-KEM is present.
    # Names seen in practice: "ML-KEM-768" (pure FIPS 203) and "SecP256r1MLKEM768" (hybrid).
    kem_list = _run("openssl", "list", "-kem-algorithms")
    pqc_available = bool(kem_list and ("ML-KEM" in kem_list or "MLKEM" in kem_list))

    # TLS 1.3: OpenSSL can list TLS 1.3 ciphersuites if TLS 1.3 is compiled in
    tls13_check = _run("openssl", "ciphers", "-s", "-tls1_3")
    tls13_enabled = bool(tls13_check)

    if pqc_available:
        pqc_capable = "true"
        action      = "configure"
        pqc_gate    = "false"
        detail = (
            f"OpenSSL ML-KEM available ({openssl_ver}). "
            "Configure sshd_config KexAlgorithms to include ml-kem-768 or ml-kem-1024 "
            "and verify TLS 1.3 is enabled on all services. "
            "Confirm FIPS 140-3 validation status of the OpenSSL provider before "
            "production use — FIPS-validated PQC requires the OpenSSL 3.5 FIPS provider "
            "with a current CMVP certificate."
        )
    else:
        pqc_capable = "false"
        action      = "upgrade"
        pqc_gate    = "true"

        # Distinguish: OpenSSL 3.5 present but ML-KEM not in active provider
        # (FIPS mode with non-PQC-validated provider) vs older OpenSSL
        import re as _re
        ossl_match = _re.search(r"OpenSSL (\d+)\.(\d+)", openssl_ver or "")
        ossl_major = int(ossl_match.group(1)) if ossl_match else 0
        ossl_minor = int(ossl_match.group(2)) if ossl_match else 0
        has_ossl35 = (ossl_major > 3) or (ossl_major == 3 and ossl_minor >= 5)

        if has_ossl35:
            # OpenSSL 3.5 is present — ML-KEM is compiled in but not exposed by the active provider.
            # Most common cause: FIPS mode + FIPS provider not yet PQC-validated.
            detail = (
                f"OpenSSL 3.5 is installed ({openssl_ver}) but ML-KEM is not available in "
                "the active provider. Most likely cause: FIPS mode with a non-PQC-validated "
                "FIPS provider. "
                "The FIPS 140-3 validated PQC OpenSSL provider is expected in 2026–2027. "
                "Until then, use a FIPS 140-3 validated HSM (Thales TCT Luna T7, CMVP #5450) "
                "for PQC key establishment in FIPS-enforced environments."
            )
        else:
            detail = (
                f"OpenSSL does not expose ML-KEM ({openssl_ver or 'not found'}). "
                "PQC SSH and TLS require OpenSSL 3.5+. "
            )
            try:
                major = int(os_version.split(".")[0]) if os_version else 0
            except ValueError:
                major = 0
            if os_id in ("rhel", "centos", "rocky", "almalinux"):
                if major >= 10:
                    detail += "RHEL 10 ships OpenSSL 3.5 as the default provider; verify the openssl35 module is active."
                elif major == 9:
                    detail += (
                        "RHEL 9.6+ provides OpenSSL 3.5 as an opt-in module (not the default FIPS path). "
                        "Upgrade to RHEL 10 for FIPS-validated PQC as the default provider."
                    )
                else:
                    detail += "RHEL 8 has no PQC path — upgrade to RHEL 9.6+ or RHEL 10."
            elif os_id in ("ubuntu", "debian"):
                detail += "Ubuntu 24.10+ and Debian 13 (Trixie) provide OpenSSL 3.5 as an opt-in; Ubuntu 25.04 ships it as default."
            else:
                detail += "Install OpenSSL 3.5+ and verify 'openssl list -kem-algorithms' includes ML-KEM-768."

    # Check whether AD CS-equivalent (Dogtag, EJBCA) is installed — if so, the OS is a PKI gate
    pki_service = ""
    for proc_name in ("dogtagd", "pki-tomcat", "ejbca"):
        if proc_name in _run("ps", "-e", "-o", "comm="):
            pki_service = proc_name
            break
    if pki_service:
        detail += f" PKI service detected ({pki_service}) — this host is a PKI gate for certificate migration."

    props = [
        {"name": "fedlin:hw_class",       "value": "os"},
        {"name": "fedlin:host",            "value": hostname},
        {"name": "fedlin:hw_pqc_capable",  "value": pqc_capable},
        {"name": "fedlin:hw_action",       "value": action},
        {"name": "fedlin:hw_action_detail","value": detail},
        {"name": "fedlin:hw_pqc_gate",     "value": pqc_gate},
        {"name": "fedlin:tls13_enabled",   "value": str(tls13_enabled).lower()},
    ]
    if openssl_ver:
        props.append({"name": "fedlin:openssl_version", "value": openssl_ver})
    # Facts the CMVP check needs: distribution identity and whether the kernel runs in FIPS mode.
    if os_id:
        props.append({"name": "fedlin:os_id", "value": os_id})
    if os_version:
        props.append({"name": "fedlin:os_version_id", "value": os_version})
    try:
        fips = pathlib.Path("/proc/sys/crypto/fips_enabled").read_text().strip()
    except OSError:
        fips = ""
    props.append({"name": "fedlin:fips_enabled",
                  "value": {"1": "true", "0": "false"}.get(fips, "unknown")})

    slug = _slugify(hostname)
    return {
        "type":     "operating-system",
        "bom-ref":  f"hw/os/{slug}",
        "name":     f"{os_name} — {hostname}",
        "version":  os_version,
        "properties": props,
    }


# ---- TPM -----------------------------------------------------------------------

def detect_tpm(hostname):
    tpm_dir = pathlib.Path("/sys/class/tpm/tpm0")
    if not tpm_dir.exists():
        return None   # no TPM detected

    # Determine version from sysfs (tpm_version_major) or fall back to tpm2_getcap
    version_str = "unknown"
    try:
        major = (tpm_dir / "tpm_version_major").read_text().strip()
        version_str = major  # "1" or "2"
    except OSError:
        # Try tpm2_getcap as a fallback (may not be installed)
        caps = _run("tpm2_getcap", "properties-fixed")
        version_str = "2" if caps else "unknown"

    display_version = f"TPM {version_str}.0" if version_str.isdigit() else "TPM (version unknown)"

    # Vendor: try reading firmware version from sysfs; best-effort only
    vendor = ""
    try:
        # Some kernels expose a human-readable vendor string here
        vendor = (tpm_dir / "device" / "vendor").read_text().strip()
    except OSError:
        pass

    # If no sysfs vendor, try tpm2_getcap (noisier, may not be installed)
    if not vendor and version_str == "2":
        mfr_out = _run("tpm2_getcap", "properties-fixed")
        for line in mfr_out.splitlines():
            if "TPM2_PT_MANUFACTURER" in line or "MANUFACTURER" in line:
                # e.g.  TPM2_PT_MANUFACTURER:  value: 0x49465800 (IFX)
                if "(" in line and ")" in line:
                    vendor = line.split("(")[1].rstrip(")")
                break

    props = [
        {"name": "fedlin:hw_class",        "value": "tpm"},
        {"name": "fedlin:host",             "value": hostname},
        {"name": "fedlin:hw_pqc_capable",   "value": "false"},
        {"name": "fedlin:hw_action",        "value": "replace"},
        {"name": "fedlin:hw_action_detail", "value": (
            "Existing discrete TPM cannot perform ML-KEM or ML-DSA as general operations. "
            "No firmware path for PQC general ops exists for current-gen discrete TPMs. "
            "Replace at next scheduled hardware refresh (2028–2030 lifecycle)."
        )},
        {"name": "fedlin:hw_fips_status", "value": (
            "FIPS 140-2 validated (TPM 2.0 profile); "
            "no FIPS 140-3 PQC validation exists for discrete TPMs"
        )},
    ]
    if vendor:
        props.append({"name": "fedlin:hw_vendor", "value": vendor})

    slug = _slugify(hostname)
    return {
        "type":    "device",
        "bom-ref": f"hw/tpm/{slug}",
        "name":    f"{display_version} — {hostname}",
        "version": f"{version_str}.0" if version_str.isdigit() else version_str,
        "properties": props,
    }


# ---- HSM -----------------------------------------------------------------------

# Process names that indicate a locally-attached or network HSM client daemon
_HSM_PROCS = {
    "nethsmd":    "Thales TCT Luna Network HSM",
    "cfm2d":      "Thales TCT Luna PCIe HSM",
    "cfm2":       "Thales TCT Luna PCIe HSM",
    "hardserver": "Entrust nShield",
    "nshield":    "Entrust nShield",
    "hardd":      "Utimaco SecurityServer",
    "primus":     "Securosys Primus HSM",
    "proteccio":  "Bull/Atos Proteccio NetHSM",
}

# Device nodes indicating a locally-attached HSM
_HSM_DEVS = {
    "/dev/nfast0": "Entrust nShield",
    "/dev/nfast":  "Entrust nShield",
}

# PKCS#11 shared library paths (common install locations)
_PKCS11_LIBS = [
    "/usr/lib/libCryptoki2_64.so",                        # Thales Luna
    "/usr/lib64/libCryptoki2_64.so",
    "/opt/nfast/toolkits/pkcs11/libcknfast.so",           # nShield
    "/usr/lib/libnethsm.so",                               # Thales TCT
    "/usr/lib/libprimuspkcs11.so",                         # Securosys
    "/usr/lib/libcs_pkcs11_R2.so",                         # Utimaco
    "/usr/local/lib/libpkcs11.so",
]


def detect_hsm(hostname):
    found_name = ""

    # 1. Check running process names (comm field only — no args, no secrets)
    running = _run("ps", "-e", "-o", "comm=")
    for proc, name in _HSM_PROCS.items():
        if proc in running:
            found_name = name
            break

    # 2. Check device nodes
    if not found_name:
        for dev, name in _HSM_DEVS.items():
            if pathlib.Path(dev).exists():
                found_name = name
                break

    # 3. Check PKCS#11 shared libraries
    if not found_name:
        for lib in _PKCS11_LIBS:
            if pathlib.Path(lib).exists():
                found_name = f"HSM (PKCS#11: {lib})"
                break

    slug = _slugify(hostname)

    if found_name:
        return {
            "type":    "device",
            "bom-ref": f"hw/hsm/{slug}",
            "name":    f"HSM — {hostname} ({found_name})",
            "properties": [
                {"name": "fedlin:hw_class",        "value": "hsm"},
                {"name": "fedlin:host",             "value": hostname},
                {"name": "fedlin:hw_pqc_capable",   "value": "unknown"},
                {"name": "fedlin:hw_action",        "value": "configure"},
                {"name": "fedlin:hw_action_detail", "value": (
                    f"HSM detected ({found_name}). Verify FIPS 140-3 CMVP validation status "
                    "for PQC operations (ML-KEM-1024 / ML-DSA-87). "
                    "Currently validated: Thales TCT Luna T7 (CMVP #5450). "
                    "Analyst must confirm product version and CMVP certificate number "
                    "before marking PQC-capable."
                )},
                {"name": "fedlin:hw_fips_status", "value": "analyst verification required — see action detail"},
            ],
        }
    else:
        return {
            "type":    "device",
            "bom-ref": f"hw/hsm/absent-{slug}",
            "name":    f"HSM — not detected on {hostname}",
            "properties": [
                {"name": "fedlin:hw_class",        "value": "hsm"},
                {"name": "fedlin:host",             "value": hostname},
                {"name": "fedlin:hw_pqc_capable",   "value": "false"},
                {"name": "fedlin:hw_action",        "value": "procure"},
                {"name": "fedlin:hw_action_detail", "value": (
                    "No HSM detected. PQC key establishment (ML-KEM-1024) requires a "
                    "FIPS 140-3 CMVP-validated HSM. Currently one product meets this bar: "
                    "Thales TCT Luna T7 (CMVP cert #5450). Additional products in CMVP "
                    "pipeline (Entrust nShield 5, Securosys Primus): expected 2027–2028."
                )},
                {"name": "fedlin:hw_pqc_gate",   "value": "true"},
                {"name": "fedlin:hw_fips_status", "value": "n/a — no HSM detected"},
            ],
        }


# ---- util ----------------------------------------------------------------------

def _slugify(s):
    """Lowercase alphanumeric + dot + hyphen, for use in bom-ref."""
    import re
    return re.sub(r"[^a-z0-9.\-]", "-", s.lower()).strip("-")


# ---- main ----------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="FEDLIN hardware PQC posture collector (Linux). "
                    "Outputs CycloneDX 1.6 component JSON to stdout."
    )
    p.add_argument("--host",   default=socket.getfqdn(),
                   help="Hostname / FQDN for bom-ref and display name (default: local FQDN)")
    p.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = p.parse_args()

    hostname   = args.host
    components = []

    components.append(detect_os(hostname))

    tpm = detect_tpm(hostname)
    if tpm:
        components.append(tpm)

    components.append(detect_hsm(hostname))

    out = {"components": components}
    print(json.dumps(out, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
