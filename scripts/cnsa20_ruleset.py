"""FEDLIN PQC ruleset (deterministic, no AI at evaluation time).

Maps a detected algorithm identifier to a verdict: quantum status, NIST security
category, classical strength, migration target, 800-53 controls and priority.

Design (v1.0, replaces the v0.2 substring list):
  1. normalize()  maps an identifier (OpenSSL, OpenSSH, TLS IANA/OpenSSL group or
     suite names, CycloneDX/CBOMkit names) to a canonical algorithm id using an
     exact alias table, then token-bounded patterns. No bare substring matching:
     "ideal" no longer reads as IDEA, "curve25519-sha256" reads as X25519.
  2. Composite identifiers (TLS 1.2 cipher suites, "sha256WithRSAEncryption",
     "ecdsa-with-SHA1") are split into components; the worst component wins and
     every component is reported.
  3. Key size changes the verdict: RSA/DSA/DH below 2048 bits and EC below 224
     bits are classically broken (Critical), not merely quantum-vulnerable.
  4. Verdicts depend on a profile:
       civilian  NIST FIPS 203/204/205 + NIST IR 8547 transition (FCEB / M-26-15,
                 commercial buyers). Default.
       nss       NSA CNSA 2.0 (National Security Systems). Stricter parameter sets.
     Quantum vulnerability is a property of the algorithm and does not change by
     profile. What changes is which quantum-resistant choices count as compliant.
  5. Every rule cites its primary source (SOURCES) so the verdict is auditable.

Output keys kept for existing callers: primitive, crypto_functions,
quantum_vulnerable, nist_pqc_level, cnsa_target, controls, note, algorithm,
classical_security_level, priority. Conventions kept: a compliant target starts
with "None"; a classically broken target contains "Replace now".
"""

import os
import re

RULESET_VERSION = "1.0.0"
PROFILES = ("civilian", "nss")
DEFAULT_PROFILE = os.environ.get("FEDLIN_PQC_PROFILE", "civilian")

# Primary sources. Keep these exact and dated; update CORRECTIONS.md when one changes.
SOURCES = {
    "FIPS203": "NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard (Aug 2024)",
    "FIPS204": "NIST FIPS 204, Module-Lattice-Based Digital Signature Standard (Aug 2024)",
    "FIPS205": "NIST FIPS 205, Stateless Hash-Based Digital Signature Standard (Aug 2024)",
    "FN-DSA": "NIST FN-DSA (FIPS 206) based on FALCON: not yet a final standard",
    "SP800-208": "NIST SP 800-208, Recommendation for Stateful Hash-Based Signature Schemes (LMS, XMSS)",
    "IR8547": "NIST IR 8547 (Final, Oct 2026), Transition to Post-Quantum Cryptography Standards, Tables 2 "
              "and 4: all quantum-vulnerable signature and key-establishment schemes deprecated after 2030, "
              "disallowed after 2035",
    "EO14412": "Executive Order 14412 (Jun 2026) via OMB M-26-15: high value assets and high impact systems "
               "move key establishment to PQC by 2030-12-31 and signatures by 2031-12-31",
    "CNSA2": "NSA Commercial National Security Algorithm Suite 2.0 (ML-KEM-1024, ML-DSA-87, LMS/XMSS, "
             "AES-256, SHA-384/512)",
    "SP800-57": "NIST SP 800-57 Part 1 Rev. 5, Table 2 (comparable security strengths)",
    "SP800-131A": "NIST SP 800-131A Rev. 2, Transitioning the Use of Cryptographic Algorithms and Key Lengths",
    "FIPS186-5": "NIST FIPS 186-5, Digital Signature Standard (DSA no longer approved for signature generation)",
    "RFC8996": "IETF RFC 8996, Deprecating TLS 1.0 and TLS 1.1",
    "RFC7465": "IETF RFC 7465, Prohibiting RC4 Cipher Suites",
    "RFC8446": "IETF RFC 8446, TLS 1.3",
    "TLS-MLKEM": "IETF draft-ietf-tls-ecdhe-mlkem (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024)",
    "TLS-KYBER-DRAFT": "IETF draft-tls-westerbaan-xyber768d00 (X25519Kyber768Draft00, pre-standard, superseded)",
    "SSH-MLKEM": "OpenSSH 9.9 release notes / draft-ietf-sshm-mlkem-hybrid-kex (mlkem768x25519-sha256)",
    "SSH-SNTRUP": "OpenSSH 9.0 release notes (sntrup761x25519-sha512 default; Streamlined NTRU Prime, not NIST-selected)",
    "RFC9142": "IETF RFC 9142, Key Exchange Method Updates for SSH (SHA-1 and 1024-bit DH: SHOULD NOT / MUST NOT)",
    "OPENSSH-RSA-SHA1": "OpenSSH 8.8 release notes (ssh-rsa SHA-1 signatures disabled by default)",
    "NCSC-TLS": "UK NCSC, Using TLS to protect data (v1.2): TLS 1.3 is the only version that supports PQC",
}

# ---------------------------------------------------------------------------
# Canonical algorithm table
# ---------------------------------------------------------------------------
# kind:
#   "qv"      quantum-vulnerable public-key algorithm (Shor)
#   "pqc"     quantum-resistant public-key algorithm
#   "sym"     symmetric cipher / AEAD
#   "hash"    hash / XOF
#   "mac"     MAC
#   "kdf"     KDF / password hash
#   "broken"  classically broken or disallowed now
#   "proto"   protocol version
# compliant: {profile: bool} for non-qv, non-broken entries.
# level: CycloneDX nistQuantumSecurityLevel (0 = vulnerable, 1..5 = NIST category).

def _a(kind, primitive, functions, level=None, strength=None, compliant=None, controls=None,
       note="", cite=(), target=None, family=None, param=None, standard="nist"):
    return {
        "kind": kind, "primitive": primitive, "functions": functions, "level": level,
        "strength": strength, "compliant": compliant or {}, "controls": controls or ["SC-13"],
        "note": note, "cite": list(cite), "target": target or {}, "family": family,
        "param": param, "standard": standard,
    }


_KEM_FN = ["encapsulate", "decapsulate", "keygen"]
_SIG_FN = ["sign", "verify"]
_ENC_FN = ["encrypt", "decrypt"]
_BOTH = {"civilian": True, "nss": True}
_CIV = {"civilian": True, "nss": False}
_NONE = {"civilian": False, "nss": False}

ALGORITHMS = {
    # --- Quantum-resistant KEMs ------------------------------------------------
    "ml-kem-512": _a("pqc", "kem", _KEM_FN, level=1, compliant=_CIV, family="ML-KEM", param="ML-KEM-512",
                     controls=["SC-8", "SC-12", "SC-13"], cite=["FIPS203", "CNSA2"],
                     note="FIPS 203 Category 1. Approved, but NIST recommends ML-KEM-768 as the default.",
                     target={"civilian": "None (FIPS 203 approved; ML-KEM-768 is the NIST default)",
                             "nss": "ML-KEM-1024 (CNSA 2.0)"}),
    "ml-kem-768": _a("pqc", "kem", _KEM_FN, level=3, compliant=_CIV, family="ML-KEM", param="ML-KEM-768",
                     controls=["SC-8", "SC-12", "SC-13"], cite=["FIPS203", "CNSA2"],
                     note="FIPS 203 Category 3, the NIST default parameter set.",
                     target={"civilian": "None (FIPS 203 Category 3)", "nss": "ML-KEM-1024 (CNSA 2.0)"}),
    "ml-kem-1024": _a("pqc", "kem", _KEM_FN, level=5, compliant=_BOTH, family="ML-KEM", param="ML-KEM-1024",
                      controls=["SC-8", "SC-12", "SC-13"], cite=["FIPS203", "CNSA2"],
                      note="FIPS 203 Category 5. The CNSA 2.0 key-establishment algorithm.",
                      target={"civilian": "None (FIPS 203 Category 5)", "nss": "None (CNSA 2.0 KEM)"}),
    "ml-kem": _a("pqc", "kem", _KEM_FN, compliant=_NONE, family="ML-KEM", cite=["FIPS203"],
                 controls=["SC-8", "SC-12", "SC-13"],
                 note="ML-KEM without a parameter set. Quantum-resistant; confirm 512/768/1024.",
                 target={"civilian": "Confirm parameter set", "nss": "Confirm parameter set is ML-KEM-1024"}),
    # Hybrids (TLS groups and SSH KEX)
    "x25519mlkem768": _a("pqc", "kem", _KEM_FN, level=3, compliant=_CIV, family="ML-KEM",
                         param="X25519MLKEM768", controls=["SC-8", "SC-12", "SC-13"],
                         cite=["TLS-MLKEM", "FIPS203", "NCSC-TLS", "CNSA2"],
                         note="Hybrid X25519 + ML-KEM-768. Quantum-resistant key establishment.",
                         target={"civilian": "None (hybrid ML-KEM-768)",
                                 "nss": "SecP384r1MLKEM1024 or ML-KEM-1024 (CNSA 2.0)"}),
    "secp256r1mlkem768": _a("pqc", "kem", _KEM_FN, level=3, compliant=_CIV, family="ML-KEM",
                            param="SecP256r1MLKEM768", controls=["SC-8", "SC-12", "SC-13"],
                            cite=["TLS-MLKEM", "FIPS203", "NCSC-TLS", "CNSA2"],
                            note="Hybrid P-256 + ML-KEM-768. Quantum-resistant key establishment.",
                            target={"civilian": "None (hybrid ML-KEM-768)",
                                    "nss": "SecP384r1MLKEM1024 or ML-KEM-1024 (CNSA 2.0)"}),
    "secp384r1mlkem1024": _a("pqc", "kem", _KEM_FN, level=5, compliant=_BOTH, family="ML-KEM",
                             param="SecP384r1MLKEM1024", controls=["SC-8", "SC-12", "SC-13"],
                             cite=["TLS-MLKEM", "FIPS203", "CNSA2"],
                             note="Hybrid P-384 + ML-KEM-1024.",
                             target={"civilian": "None (hybrid ML-KEM-1024)", "nss": "None (ML-KEM-1024 hybrid)"}),
    "mlkem768x25519-sha256": _a("pqc", "kem", _KEM_FN, level=3, compliant=_CIV, family="ML-KEM",
                                param="mlkem768x25519-sha256", controls=["SC-8", "SC-12", "SC-13"],
                                cite=["SSH-MLKEM", "FIPS203", "CNSA2"],
                                note="SSH hybrid ML-KEM-768 + X25519 key exchange.",
                                target={"civilian": "None (hybrid ML-KEM-768)", "nss": "ML-KEM-1024 based KEX (CNSA 2.0)"}),
    "sntrup761x25519-sha512": _a("pqc", "kem", _KEM_FN, compliant=_NONE, family="NTRU-Prime",
                                 param="sntrup761x25519-sha512", standard="non-nist",
                                 controls=["SC-8", "SC-12"], cite=["SSH-SNTRUP", "SSH-MLKEM"],
                                 note="SSH hybrid Streamlined NTRU Prime + X25519. Quantum-resistant, "
                                      "but not a NIST-standardized KEM.",
                                 target={"civilian": "Prefer mlkem768x25519-sha256 (NIST-standardized hybrid)",
                                         "nss": "ML-KEM-1024 based KEX (CNSA 2.0)"}),
    "x25519kyber768draft00": _a("pqc", "kem", _KEM_FN, compliant=_NONE, family="Kyber",
                                param="X25519Kyber768Draft00", standard="pre-standard",
                                controls=["SC-8", "SC-12"], cite=["TLS-KYBER-DRAFT", "FIPS203"],
                                note="Pre-standard Kyber hybrid codepoint. Not FIPS 203 ML-KEM.",
                                target={"civilian": "Replace with X25519MLKEM768 (FIPS 203 hybrid)",
                                        "nss": "Replace with ML-KEM-1024 based key exchange (CNSA 2.0)"}),
    # --- Quantum-resistant signatures -------------------------------------------
    "ml-dsa-44": _a("pqc", "signature", _SIG_FN, level=2, compliant=_CIV, family="ML-DSA", param="ML-DSA-44",
                    controls=["SC-13", "SC-17"], cite=["FIPS204", "CNSA2"], note="FIPS 204 Category 2.",
                    target={"civilian": "None (FIPS 204 Category 2)", "nss": "ML-DSA-87 (CNSA 2.0)"}),
    "ml-dsa-65": _a("pqc", "signature", _SIG_FN, level=3, compliant=_CIV, family="ML-DSA", param="ML-DSA-65",
                    controls=["SC-13", "SC-17"], cite=["FIPS204", "CNSA2"], note="FIPS 204 Category 3.",
                    target={"civilian": "None (FIPS 204 Category 3)", "nss": "ML-DSA-87 (CNSA 2.0)"}),
    "ml-dsa-87": _a("pqc", "signature", _SIG_FN, level=5, compliant=_BOTH, family="ML-DSA", param="ML-DSA-87",
                    controls=["SC-13", "SC-17"], cite=["FIPS204", "CNSA2"],
                    note="FIPS 204 Category 5. The CNSA 2.0 signature algorithm.",
                    target={"civilian": "None (FIPS 204 Category 5)", "nss": "None (CNSA 2.0 signature)"}),
    "ml-dsa": _a("pqc", "signature", _SIG_FN, compliant=_NONE, family="ML-DSA", cite=["FIPS204"],
                 controls=["SC-13", "SC-17"],
                 note="ML-DSA without a parameter set. Quantum-resistant; confirm 44/65/87.",
                 target={"civilian": "Confirm parameter set", "nss": "Confirm parameter set is ML-DSA-87"}),
    "slh-dsa-128": _a("pqc", "signature", _SIG_FN, level=1, compliant=_CIV, family="SLH-DSA",
                      controls=["SC-13", "SC-17"], cite=["FIPS205", "CNSA2"],
                      note="FIPS 205 Category 1 stateless hash-based signature. Not part of CNSA 2.0.",
                      target={"civilian": "None (FIPS 205)", "nss": "ML-DSA-87, or LMS/XMSS for firmware (CNSA 2.0)"}),
    "slh-dsa-192": _a("pqc", "signature", _SIG_FN, level=3, compliant=_CIV, family="SLH-DSA",
                      controls=["SC-13", "SC-17"], cite=["FIPS205", "CNSA2"],
                      note="FIPS 205 Category 3 stateless hash-based signature. Not part of CNSA 2.0.",
                      target={"civilian": "None (FIPS 205)", "nss": "ML-DSA-87, or LMS/XMSS for firmware (CNSA 2.0)"}),
    "slh-dsa-256": _a("pqc", "signature", _SIG_FN, level=5, compliant=_CIV, family="SLH-DSA",
                      controls=["SC-13", "SC-17"], cite=["FIPS205", "CNSA2"],
                      note="FIPS 205 Category 5 stateless hash-based signature. Not part of CNSA 2.0.",
                      target={"civilian": "None (FIPS 205)", "nss": "ML-DSA-87, or LMS/XMSS for firmware (CNSA 2.0)"}),
    "slh-dsa": _a("pqc", "signature", _SIG_FN, compliant=_CIV, family="SLH-DSA",
                  controls=["SC-13", "SC-17"], cite=["FIPS205", "CNSA2"],
                  note="SLH-DSA without a parameter set. Quantum-resistant (FIPS 205).",
                  target={"civilian": "None (FIPS 205; confirm parameter set)",
                          "nss": "ML-DSA-87, or LMS/XMSS for firmware (CNSA 2.0)"}),
    "lms": _a("pqc", "signature", _SIG_FN, level=5, compliant=_BOTH, family="LMS",
              controls=["SC-13", "SC-17"], cite=["SP800-208", "CNSA2"],
              note="Stateful hash-based signature (SP 800-208). CNSA 2.0 firmware/code-signing algorithm. "
                   "State management is a deployment risk.",
              target={"civilian": "None (SP 800-208)", "nss": "None (CNSA 2.0 firmware/code signing)"}),
    "xmss": _a("pqc", "signature", _SIG_FN, level=5, compliant=_BOTH, family="XMSS",
               controls=["SC-13", "SC-17"], cite=["SP800-208", "CNSA2"],
               note="Stateful hash-based signature (SP 800-208). State management is a deployment risk.",
               target={"civilian": "None (SP 800-208)", "nss": "None (CNSA 2.0 firmware/code signing)"}),
    "fn-dsa": _a("pqc", "signature", _SIG_FN, compliant=_NONE, family="FN-DSA", standard="pre-standard",
                 controls=["SC-13", "SC-17"], cite=["FN-DSA", "CNSA2"],
                 note="FN-DSA (FALCON) is quantum-resistant but its NIST standard is not final.",
                 target={"civilian": "ML-DSA (FIPS 204) until FN-DSA is final",
                         "nss": "ML-DSA-87 (CNSA 2.0)"}),
    # --- Quantum-vulnerable public key --------------------------------------------
    "rsa": _a("qv", "pke", ["sign", "verify", "encrypt", "decrypt"], level=0, family="RSA",
              controls=["SC-12", "SC-13", "SC-17"], cite=["IR8547", "CNSA2", "SP800-57"],
              note="Quantum-vulnerable public-key cryptography."),
    "dsa": _a("broken", "signature", _SIG_FN, level=0, family="DSA",
              controls=["SC-12", "SC-13", "SC-17"], cite=["FIPS186-5", "IR8547"],
              note="DSA is quantum-vulnerable and no longer approved for signature generation (FIPS 186-5)."),
    "ecdsa": _a("qv", "signature", _SIG_FN, level=0, family="ECDSA",
                controls=["SC-12", "SC-17"], cite=["IR8547", "CNSA2", "SP800-57"],
                note="Quantum-vulnerable elliptic-curve signature."),
    "ec": _a("qv", "pke", ["keygen", "sign", "verify"], level=0, family="EC",
             controls=["SC-12", "SC-13", "SC-17"], cite=["IR8547", "CNSA2", "SP800-57"],
             note="Elliptic-curve public key. Quantum-vulnerable."),
    "ecdh": _a("qv", "key-agree", ["keygen"], level=0, family="ECDH",
               controls=["SC-8", "SC-12"], cite=["IR8547", "CNSA2", "SP800-57"],
               note="Elliptic-curve key agreement. Harvest-now-decrypt-later exposure on captured sessions."),
    "x25519": _a("qv", "key-agree", ["keygen"], level=0, strength=128, family="X25519",
                 controls=["SC-8", "SC-12"], cite=["IR8547", "CNSA2", "SP800-57"],
                 note="X25519 key exchange. Harvest-now-decrypt-later exposure."),
    "x448": _a("qv", "key-agree", ["keygen"], level=0, strength=224, family="X448",
               controls=["SC-8", "SC-12"], cite=["IR8547", "CNSA2", "SP800-57"],
               note="X448 key exchange. Harvest-now-decrypt-later exposure."),
    "ed25519": _a("qv", "signature", _SIG_FN, level=0, strength=128, family="EdDSA",
                  controls=["SC-12", "SC-17"], cite=["IR8547", "CNSA2", "FIPS186-5"],
                  note="EdDSA (Ed25519). Quantum-vulnerable signature; deprecated after 2030, disallowed after 2035 (IR 8547)."),
    "ed448": _a("qv", "signature", _SIG_FN, level=0, strength=224, family="EdDSA",
                controls=["SC-12", "SC-17"], cite=["IR8547", "CNSA2", "FIPS186-5"],
                note="EdDSA (Ed448). Quantum-vulnerable signature; deprecated after 2030, disallowed after 2035 (IR 8547)."),
    "eddsa": _a("qv", "signature", _SIG_FN, level=0, family="EdDSA",
                controls=["SC-12", "SC-17"], cite=["IR8547", "CNSA2"],
                note="EdDSA. Quantum-vulnerable signature."),
    "dh": _a("qv", "key-agree", ["keygen"], level=0, family="DH",
             controls=["SC-8", "SC-12"], cite=["IR8547", "CNSA2", "SP800-57"],
             note="Finite-field Diffie-Hellman. Quantum-vulnerable."),
    "mqv": _a("qv", "key-agree", ["keygen"], level=0, family="MQV",
              controls=["SC-8", "SC-12"], cite=["IR8547"], note="(EC)MQV key agreement. Quantum-vulnerable."),
    "elgamal": _a("qv", "pke", _ENC_FN, level=0, family="ElGamal",
                  controls=["SC-12", "SC-13"], cite=["IR8547"], note="ElGamal. Quantum-vulnerable."),
    "sm2": _a("qv", "pke", ["sign", "verify", "encrypt", "decrypt"], level=0, family="SM2", standard="non-nist",
              controls=["SC-12", "SC-13"], cite=["IR8547"], note="SM2 (non-NIST curve). Quantum-vulnerable."),
    # --- Symmetric ------------------------------------------------------------------
    "aes-128": _a("sym", "block-cipher", _ENC_FN, level=1, strength=128, compliant=_CIV, family="AES",
                  param="128", controls=["SC-13", "SC-28"], cite=["SP800-131A", "CNSA2"],
                  note="AES-128. Quantum-resistant for civilian use; CNSA 2.0 requires AES-256.",
                  target={"civilian": "None (AES-128 approved)", "nss": "AES-256 (CNSA 2.0)"}),
    "aes-192": _a("sym", "block-cipher", _ENC_FN, level=3, strength=192, compliant=_CIV, family="AES",
                  param="192", controls=["SC-13", "SC-28"], cite=["SP800-131A", "CNSA2"],
                  note="AES-192. CNSA 2.0 requires AES-256.",
                  target={"civilian": "None (AES-192 approved)", "nss": "AES-256 (CNSA 2.0)"}),
    "aes-256": _a("sym", "block-cipher", _ENC_FN, level=5, strength=256, compliant=_BOTH, family="AES",
                  param="256", controls=["SC-13", "SC-28"], cite=["SP800-131A", "CNSA2"],
                  note="AES-256. Quantum-resistant; the CNSA 2.0 symmetric algorithm.",
                  target={"civilian": "None (AES-256)", "nss": "None (CNSA 2.0)"}),
    "aes": _a("sym", "block-cipher", _ENC_FN, compliant=_NONE, family="AES", controls=["SC-13", "SC-28"],
              cite=["SP800-131A"], note="AES without a key size. Confirm 128/192/256.",
              target={"civilian": "Confirm key size", "nss": "Confirm key size is AES-256"}),
    "chacha20": _a("sym", "stream-cipher", _ENC_FN, level=5, strength=256, compliant=_CIV, family="ChaCha20",
                   standard="non-nist", controls=["SC-13", "SC-28"], cite=["CNSA2"],
                   note="ChaCha20(-Poly1305), 256-bit key. Quantum-resistant; not a CNSA 2.0 algorithm.",
                   target={"civilian": "None (256-bit key)", "nss": "AES-256 (CNSA 2.0)"}),
    "camellia": _a("sym", "block-cipher", _ENC_FN, compliant=_NONE, family="Camellia", standard="non-nist",
                   controls=["SC-13", "SC-28"], cite=["SP800-131A"],
                   note="Non-NIST block cipher. Quantum-resistant at 256-bit keys; not FIPS-approved.",
                   target={"civilian": "AES (FIPS-approved)", "nss": "AES-256 (CNSA 2.0)"}),
    "aria": _a("sym", "block-cipher", _ENC_FN, compliant=_NONE, family="ARIA", standard="non-nist",
               controls=["SC-13", "SC-28"], cite=["SP800-131A"],
               note="Non-NIST block cipher. Not FIPS-approved.",
               target={"civilian": "AES (FIPS-approved)", "nss": "AES-256 (CNSA 2.0)"}),
    "seed": _a("sym", "block-cipher", _ENC_FN, compliant=_NONE, family="SEED", standard="non-nist",
               controls=["SC-13", "SC-28"], cite=["SP800-131A"],
               note="SEED, 128-bit non-NIST block cipher. Not FIPS-approved.",
               target={"civilian": "AES (FIPS-approved)", "nss": "AES-256 (CNSA 2.0)"}),
    "sm4": _a("sym", "block-cipher", _ENC_FN, compliant=_NONE, family="SM4", standard="non-nist",
              controls=["SC-13", "SC-28"], cite=["SP800-131A"],
              note="SM4, 128-bit non-NIST block cipher. Not FIPS-approved.",
              target={"civilian": "AES (FIPS-approved)", "nss": "AES-256 (CNSA 2.0)"}),
    # --- Hashes -----------------------------------------------------------------------
    "sha-224": _a("hash", "hash", ["digest"], level=1, strength=112, compliant=_CIV, family="SHA-2",
                  param="224", cite=["SP800-131A", "CNSA2"], note="SHA-224. Approved; CNSA 2.0 requires SHA-384+.",
                  target={"civilian": "None (approved)", "nss": "SHA-384 or SHA-512 (CNSA 2.0)"}),
    "sha-256": _a("hash", "hash", ["digest"], level=2, strength=128, compliant=_CIV, family="SHA-2",
                  param="256", cite=["SP800-131A", "CNSA2"], note="SHA-256. Approved; CNSA 2.0 requires SHA-384+.",
                  target={"civilian": "None (approved)", "nss": "SHA-384 or SHA-512 (CNSA 2.0)"}),
    "sha-384": _a("hash", "hash", ["digest"], level=4, strength=192, compliant=_BOTH, family="SHA-2",
                  param="384", cite=["SP800-131A", "CNSA2"], note="SHA-384. CNSA 2.0 approved.",
                  target={"civilian": "None (approved)", "nss": "None (CNSA 2.0)"}),
    "sha-512": _a("hash", "hash", ["digest"], level=5, strength=256, compliant=_BOTH, family="SHA-2",
                  param="512", cite=["SP800-131A", "CNSA2"], note="SHA-512. CNSA 2.0 approved.",
                  target={"civilian": "None (approved)", "nss": "None (CNSA 2.0)"}),
    "sha3": _a("hash", "hash", ["digest"], compliant=_CIV, family="SHA-3", cite=["SP800-131A", "CNSA2"],
               note="SHA-3 / SHAKE. Approved; CNSA 2.0 lists SHA-384/512 for general use.",
               target={"civilian": "None (approved)", "nss": "SHA-384 or SHA-512 (CNSA 2.0)"}),
    "blake2": _a("hash", "hash", ["digest"], compliant=_NONE, family="BLAKE2", standard="non-nist",
                 cite=["SP800-131A"], note="BLAKE2. Not FIPS-approved; not a quantum exposure.",
                 target={"civilian": "SHA-2 or SHA-3 (FIPS-approved)", "nss": "SHA-384 or SHA-512 (CNSA 2.0)"}),
    "hmac-sha1": _a("mac", "mac", ["tag"], compliant=_CIV, family="HMAC", param="SHA-1",
                    cite=["SP800-131A", "CNSA2"],
                    note="HMAC-SHA-1 remains acceptable for HMAC under SP 800-131A; SHA-1 collisions do not "
                         "break HMAC. Migrate opportunistically.",
                    target={"civilian": "None (acceptable for HMAC; prefer HMAC-SHA-256)",
                            "nss": "HMAC-SHA-384 (CNSA 2.0)"}),
    # --- KDF / password hashing ----------------------------------------------------------
    "pbkdf2": _a("kdf", "kdf", ["keyderive"], compliant=_CIV, family="PBKDF2", cite=["SP800-131A"],
                 note="PBKDF2 (SP 800-132). Symmetric; not a quantum exposure.",
                 target={"civilian": "None (approved)", "nss": "Confirm underlying hash is SHA-384+"}),
    "password-hash": _a("kdf", "kdf", ["keyderive"], compliant=_NONE, family="password-hash",
                        standard="non-nist", cite=["SP800-131A"],
                        note="bcrypt/scrypt/Argon2. Not FIPS-approved; not a quantum exposure.",
                        target={"civilian": "PBKDF2 where FIPS validation is required",
                                "nss": "PBKDF2 with SHA-384+ where FIPS validation is required"}),
    # --- Classically broken / disallowed now ---------------------------------------------
    "md5": _a("broken", "hash", ["digest"], level=0, family="MD5", cite=["SP800-131A"],
              note="MD5 is broken (collisions)."),
    "md4": _a("broken", "hash", ["digest"], level=0, family="MD4", cite=["SP800-131A"], note="MD4 is broken."),
    "md2": _a("broken", "hash", ["digest"], level=0, family="MD2", cite=["SP800-131A"], note="MD2 is broken."),
    "sha-1": _a("broken", "hash", ["digest"], level=0, family="SHA-1", cite=["SP800-131A"],
                note="SHA-1 is disallowed for digital signatures and collision-resistant uses."),
    "des": _a("broken", "block-cipher", _ENC_FN, level=0, family="DES", cite=["SP800-131A"],
              note="DES (56-bit) is broken."),
    "3des": _a("broken", "block-cipher", _ENC_FN, level=0, family="3DES", cite=["SP800-131A"],
               note="Triple DES is disallowed for encryption (SP 800-131A)."),
    "rc4": _a("broken", "stream-cipher", _ENC_FN, level=0, family="RC4", cite=["RFC7465", "SP800-131A"],
              note="RC4 is broken and prohibited in TLS."),
    "rc2": _a("broken", "block-cipher", _ENC_FN, level=0, family="RC2", cite=["SP800-131A"], note="RC2 is broken."),
    "blowfish": _a("broken", "block-cipher", _ENC_FN, level=0, family="Blowfish", standard="non-nist",
                   cite=["SP800-131A"], note="Blowfish (64-bit block). Not approved; birthday-bound attacks."),
    "cast5": _a("broken", "block-cipher", _ENC_FN, level=0, family="CAST5", standard="non-nist",
                cite=["SP800-131A"], note="CAST5 (64-bit block). Not approved."),
    "idea": _a("broken", "block-cipher", _ENC_FN, level=0, family="IDEA", standard="non-nist",
               cite=["SP800-131A"], note="IDEA (64-bit block). Not approved."),
    "null-cipher": _a("broken", "other", ["other"], level=0, family="NULL", cite=["RFC8446"],
                      note="NULL / export / anonymous cipher: no protection."),
    # --- Protocol versions -----------------------------------------------------------------
    "tls1.3": _a("proto", "other", ["other"], compliant=_BOTH, family="TLS", param="1.3",
                 cite=["RFC8446", "NCSC-TLS"], note="TLS 1.3, the only TLS version that carries PQC key exchange.",
                 target={"civilian": "None (TLS 1.3)", "nss": "None (TLS 1.3)"}),
    "tls1.2": _a("proto", "other", ["other"], compliant=_NONE, family="TLS", param="1.2",
                 cite=["NCSC-TLS", "RFC8446"],
                 note="TLS 1.2 is acceptable classically but cannot carry standardized PQC key exchange.",
                 target={"civilian": "Enable TLS 1.3 (required for PQC key exchange)",
                         "nss": "TLS 1.3 with ML-KEM-1024 key exchange"}),
    "tls-legacy": _a("broken", "other", ["other"], level=0, family="TLS", cite=["RFC8996"],
                     note="SSL 3.0 / TLS 1.0 / TLS 1.1 are deprecated."),
}

# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def _compact(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


# Exact aliases, keyed by compact form (lowercase, alphanumerics only).
_ALIAS_RAW = {
    # PQC KEM
    "ml-kem-512": "ml-kem-512", "mlkem512": "ml-kem-512", "kyber512": "ml-kem-512",
    "ml-kem-768": "ml-kem-768", "mlkem768": "ml-kem-768", "kyber768": "ml-kem-768",
    "ml-kem-1024": "ml-kem-1024", "mlkem1024": "ml-kem-1024", "kyber1024": "ml-kem-1024",
    "ml-kem": "ml-kem", "mlkem": "ml-kem", "kyber": "ml-kem",
    "x25519mlkem768": "x25519mlkem768", "x25519_mlkem768": "x25519mlkem768",
    "secp256r1mlkem768": "secp256r1mlkem768", "p256mlkem768": "secp256r1mlkem768",
    "secp384r1mlkem1024": "secp384r1mlkem1024", "p384mlkem1024": "secp384r1mlkem1024",
    "mlkem768x25519-sha256": "mlkem768x25519-sha256",
    "sntrup761x25519-sha512": "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com": "sntrup761x25519-sha512",
    "x25519kyber768draft00": "x25519kyber768draft00", "x25519_kyber768": "x25519kyber768draft00",
    "x25519kyber768": "x25519kyber768draft00",
    # PQC signatures
    "ml-dsa-44": "ml-dsa-44", "mldsa44": "ml-dsa-44", "dilithium2": "ml-dsa-44",
    "ml-dsa-65": "ml-dsa-65", "mldsa65": "ml-dsa-65", "dilithium3": "ml-dsa-65",
    "ml-dsa-87": "ml-dsa-87", "mldsa87": "ml-dsa-87", "dilithium5": "ml-dsa-87",
    "ml-dsa": "ml-dsa", "mldsa": "ml-dsa", "dilithium": "ml-dsa",
    "slh-dsa": "slh-dsa", "slhdsa": "slh-dsa", "sphincs+": "slh-dsa", "sphincsplus": "slh-dsa", "sphincs": "slh-dsa",
    "lms": "lms", "hss": "lms", "hss/lms": "lms", "xmss": "xmss", "xmssmt": "xmss",
    "falcon": "fn-dsa", "fn-dsa": "fn-dsa", "fndsa": "fn-dsa", "falcon512": "fn-dsa", "falcon1024": "fn-dsa",
    # Quantum-vulnerable public key (OpenSSL names)
    "rsa": "rsa", "rsaencryption": "rsa", "rsassapss": "rsa", "rsassa-pss": "rsa", "rsa-pss": "rsa",
    "rsaes-oaep": "rsa", "rsa-oaep": "rsa", "rsa-sha2-256": "rsa", "rsa-sha2-512": "rsa",
    "dsa": "dsa", "dsaencryption": "dsa", "ssh-dss": "dsa",
    "ecdsa": "ecdsa", "ec": "ec", "idecpublickey": "ec", "ecpublickey": "ec",
    "ecdh": "ecdh", "ecdhe": "ecdh",
    "x25519": "x25519", "curve25519": "x25519", "x448": "x448", "curve448": "x448",
    "ed25519": "ed25519", "ssh-ed25519": "ed25519", "eddsa": "eddsa", "ed448": "ed448", "ssh-ed448": "ed448",
    "dh": "dh", "dhe": "dh", "dhkeyagreement": "dh", "diffie-hellman": "dh", "diffiehellman": "dh", "ffdhe": "dh",
    "mqv": "mqv", "ecmqv": "mqv", "elgamal": "elgamal", "sm2": "sm2",
    # Symmetric
    "chacha20": "chacha20", "chacha20-poly1305": "chacha20", "chacha20-poly1305@openssh.com": "chacha20",
    "xchacha20-poly1305": "chacha20",
    "camellia": "camellia", "aria": "aria", "seed": "seed", "sm4": "sm4",
    "aes": "aes",
    # Hashes
    "sha224": "sha-224", "sha-224": "sha-224", "sha256": "sha-256", "sha-256": "sha-256",
    "sha384": "sha-384", "sha-384": "sha-384", "sha512": "sha-512", "sha-512": "sha-512",
    "sha512/256": "sha-512", "sha-512/256": "sha-512",
    "sha1": "sha-1", "sha-1": "sha-1", "md5": "md5", "md4": "md4", "md2": "md2",
    "blake2b": "blake2", "blake2s": "blake2", "blake2": "blake2",
    "hmac-sha1": "hmac-sha1", "hmacsha1": "hmac-sha1", "hmac-sha1-96": "hmac-sha1",
    "hmac-sha1-etm@openssh.com": "hmac-sha1",
    # KDF
    "pbkdf2": "pbkdf2", "bcrypt": "password-hash", "scrypt": "password-hash", "argon2": "password-hash",
    "argon2id": "password-hash", "argon2i": "password-hash", "argon2d": "password-hash",
    # Broken
    "des": "des", "des-cbc": "des", "3des": "3des", "tripledes": "3des", "des3": "3des", "desede": "3des",
    "3des-cbc": "3des", "des-ede3": "3des", "des-ede3-cbc": "3des", "tdea": "3des",
    "rc4": "rc4", "arcfour": "rc4", "arcfour128": "rc4", "arcfour256": "rc4", "rc2": "rc2",
    "blowfish": "blowfish", "blowfish-cbc": "blowfish", "bf-cbc": "blowfish",
    "cast5": "cast5", "cast128": "cast5", "cast128-cbc": "cast5", "idea": "idea", "idea-cbc": "idea",
    "null": "null-cipher",
    # Protocol versions
    "tls1.3": "tls1.3", "tlsv1.3": "tls1.3", "tls13": "tls1.3",
    "tls1.2": "tls1.2", "tlsv1.2": "tls1.2", "tls12": "tls1.2",
    "tls1.1": "tls-legacy", "tlsv1.1": "tls-legacy", "tls1.0": "tls-legacy", "tlsv1.0": "tls-legacy",
    "tlsv1": "tls-legacy", "tls1": "tls-legacy", "sslv3": "tls-legacy", "sslv2": "tls-legacy", "ssl3": "tls-legacy",
}
ALIASES = {_compact(k): v for k, v in _ALIAS_RAW.items()}

# Curve names -> EC field size in bits (for strength) and whether NIST-approved.
CURVES = {
    "p256": 256, "secp256r1": 256, "prime256v1": 256, "nistp256": 256,
    "p384": 384, "secp384r1": 384, "prime384v1": 384, "nistp384": 384,
    "p521": 521, "secp521r1": 521, "prime521v1": 521, "nistp521": 521,
    "p224": 224, "secp224r1": 224, "nistp224": 224,
    "p192": 192, "secp192r1": 192, "prime192v1": 192, "nistp192": 192,
    "secp256k1": 256, "brainpoolp256r1": 256, "brainpoolp384r1": 384, "brainpoolp512r1": 512,
}
NON_NIST_CURVES = {"secp256k1", "brainpoolp256r1", "brainpoolp384r1", "brainpoolp512r1"}

# SSH key-exchange names (exact, compact form) -> (canonical id, bits or None, extra component)
SSH_KEX = {
    "curve25519sha256": ("x25519", None, None),
    "curve25519sha256libsshorg": ("x25519", None, None),
    "curve448sha512": ("x448", None, None),
    "ecdhsha2nistp256": ("ecdh", 256, None),
    "ecdhsha2nistp384": ("ecdh", 384, None),
    "ecdhsha2nistp521": ("ecdh", 521, None),
    "diffiehellmangroup1sha1": ("dh", 1024, "sha-1"),
    "diffiehellmangroup14sha1": ("dh", 2048, "sha-1"),
    "diffiehellmangroup14sha256": ("dh", 2048, None),
    "diffiehellmangroup16sha512": ("dh", 4096, None),
    "diffiehellmangroup18sha512": ("dh", 8192, None),
    "diffiehellmangroupexchangesha1": ("dh", None, "sha-1"),
    "diffiehellmangroupexchangesha256": ("dh", None, None),
}

# SSH host-key / signature names
SSH_HOSTKEY = {
    "sshrsa": ("rsa", None, "sha-1"),          # ssh-rsa = RSA with SHA-1 signatures
    "rsasha2256": ("rsa", None, None),
    "rsasha2512": ("rsa", None, None),
    "ecdsasha2nistp256": ("ecdsa", 256, None),
    "ecdsasha2nistp384": ("ecdsa", 384, None),
    "ecdsasha2nistp521": ("ecdsa", 521, None),
    "sshdss": ("dsa", 1024, None),
}

# TLS named groups (IANA / OpenSSL)
TLS_GROUPS = {
    "secp256r1": ("ecdh", 256), "secp384r1": ("ecdh", 384), "secp521r1": ("ecdh", 521),
    "prime256v1": ("ecdh", 256), "p256": ("ecdh", 256), "p384": ("ecdh", 384), "p521": ("ecdh", 521),
    "ffdhe2048": ("dh", 2048), "ffdhe3072": ("dh", 3072), "ffdhe4096": ("dh", 4096),
    "ffdhe6144": ("dh", 6144), "ffdhe8192": ("dh", 8192),
}

# Identifiers that are protocol markers, not algorithms (skip, do not score).
_PSEUDO = re.compile(r"^(kex-strict-[cs]-v00@openssh\.com|ext-info-[cs]|kex-strict.*|none)$", re.I)


def is_pseudo(name):
    """True for protocol markers (e.g. OpenSSH ext-info-c) that are not algorithms."""
    return bool(_PSEUDO.match((name or "").strip()))


_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def _tokens(s):
    return [t for t in _TOKEN_SPLIT.split(s.lower()) if t]


def _bits_from(s):
    """Key size written next to the family, e.g. rsa-2048, RSA2048, dh:4096.

    Only family-adjacent numbers count, so the hash in "rsa-sha2-512" is not read as a key size.
    """
    m = re.search(r"(?:rsa|dsa|dh|ffdhe)[-_: ]?(\d{3,5})(?!\d)", s.lower())
    return int(m.group(1)) if m else None


def _curve_in(s):
    c = _compact(s)
    for name in sorted(CURVES, key=len, reverse=True):
        if name in c:
            return name
    return None


def _hash_in(tokens, compact):
    """Return canonical hash id named in an identifier, or None."""
    for t in tokens:
        if t in ("sha1",):
            return "sha-1"
        if t in ("md5",):
            return "md5"
        if t in ("sha224",):
            return "sha-224"
        if t in ("sha256",):
            return "sha-256"
        if t in ("sha384",):
            return "sha-384"
        if t in ("sha512",):
            return "sha-512"
    # e.g. "sha256withrsaencryption" (single token)
    for h, cid in (("sha1", "sha-1"), ("md5", "md5"), ("sha224", "sha-224"), ("sha256", "sha-256"),
                   ("sha384", "sha-384"), ("sha512", "sha-512")):
        if compact.startswith(h + "with") or compact.endswith("with" + h):
            return cid
    return None


def _aes(tokens, compact):
    """AES key size from tokens like aes128, aes-256-gcm, aes_128."""
    m = re.search(r"aes(128|192|256)", compact)
    if m:
        return "aes-" + m.group(1)
    if "aes" in tokens:
        for size in ("128", "192", "256"):
            if size in tokens:
                return "aes-" + size
        return "aes"
    return None


def normalize(name, bits=None):
    """Return (components, bits) where components is a list of (canonical_id, bits, label).

    An empty list means the identifier was not recognized.
    """
    raw = (name or "").strip()
    low = raw.lower()
    c = _compact(raw)
    if not c:
        return [], bits

    # 1. exact alias
    if c in ALIASES:
        cid = ALIASES[c]
        b = bits or (_bits_from(low) if cid in ("rsa", "dsa", "dh") else None)
        return [(cid, b, raw)], b

    # 2. SSH names (strip certificate and security-key suffixes)
    ssh = re.sub(r"-cert-v0[01]@openssh\.com$", "", low)
    ssh = re.sub(r"^sk-", "", ssh)
    ssh = re.sub(r"@openssh\.com$", "", ssh)
    sc = _compact(ssh)
    if sc in SSH_KEX:
        cid, b, extra = SSH_KEX[sc]
        comps = [(cid, b, raw)]
        if extra:
            comps.append((extra, None, raw + " (hash)"))
        return comps, b
    if sc in SSH_HOSTKEY:
        cid, b, extra = SSH_HOSTKEY[sc]
        comps = [(cid, b, raw)]
        if extra:
            comps.append((extra, None, raw + " (signature hash)"))
        return comps, b
    if sc in ALIASES:
        return [(ALIASES[sc], bits, raw)], bits

    # 3. TLS named groups
    if c in TLS_GROUPS:
        cid, b = TLS_GROUPS[c]
        return [(cid, b, raw)], b

    toks = _tokens(low)

    # 4. Explicit PQC parameter sets inside longer names
    m = re.search(r"ml-?kem-?(512|768|1024)", low) or re.search(r"mlkem(512|768|1024)", c)
    if m and not re.search(r"(x25519|secp|p256|p384)", c):
        return [("ml-kem-" + m.group(1), None, raw)], None
    m = re.search(r"ml-?dsa-?(44|65|87)", low) or re.search(r"mldsa(44|65|87)", c)
    if m:
        return [("ml-dsa-" + m.group(1), None, raw)], None
    if "slh" in c or "sphincs" in c:
        m = re.search(r"(128|192|256)[sf]", c)
        return [("slh-dsa-" + m.group(1) if m else "slh-dsa", None, raw)], None
    if re.search(r"kyber", c) and "x25519" in c:
        return [("x25519kyber768draft00", None, raw)], None

    # 5. TLS / OpenSSL cipher suites and composite names -> components
    comps = []
    is_suite = c.startswith("tls") and ("with" in toks or len(toks) >= 4) or \
        any(t in toks for t in ("ecdhe", "dhe", "edh")) and any(t.startswith("aes") or t in ("chacha20", "3des", "des", "rc4") for t in toks)
    if is_suite:
        tok_set = set(toks)
        if tok_set & {"null", "anon", "export", "exp"}:
            comps.append(("null-cipher", None, raw))
        if "ecdhe" in tok_set or "ecdh" in tok_set:
            comps.append(("ecdh", None, raw + " (key exchange)"))
        elif tok_set & {"dhe", "edh", "dh"}:
            comps.append(("dh", None, raw + " (key exchange)"))
        elif "rsa" in tok_set and "with" in tok_set and toks[1] == "rsa":
            comps.append(("rsa", None, raw + " (RSA key transport)"))
        if "rsa" in tok_set and ("ecdhe" in tok_set or "dhe" in tok_set or "edh" in tok_set):
            comps.append(("rsa", None, raw + " (authentication)"))
        if "ecdsa" in tok_set:
            comps.append(("ecdsa", None, raw + " (authentication)"))
        aes = _aes(toks, c)
        if aes:
            comps.append((aes, None, raw + " (cipher)"))
        if "chacha20" in tok_set:
            comps.append(("chacha20", None, raw + " (cipher)"))
        if tok_set & {"3des", "des3"} or ("3des" in c):
            comps.append(("3des", None, raw + " (cipher)"))
        elif "des" in tok_set:
            comps.append(("des", None, raw + " (cipher)"))
        if "rc4" in tok_set:
            comps.append(("rc4", None, raw + " (cipher)"))
        if "camellia" in c:
            comps.append(("camellia", None, raw + " (cipher)"))
        if "aria" in tok_set or re.search(r"aria(128|256)", c):
            comps.append(("aria", None, raw + " (cipher)"))
        h = _hash_in(toks, c)
        if h == "sha-1":
            # SHA-1 in a suite name is the HMAC (CBC suites) or PRF; HMAC-SHA-1 is not broken.
            comps.append(("hmac-sha1", None, raw + " (MAC)"))
        elif h in ("md5",):
            comps.append(("md5", None, raw + " (MAC)"))
        if comps:
            return comps, bits

    # 6. Signature-with-hash names (sha256WithRSAEncryption, ecdsa-with-SHA384, dsa_with_SHA256)
    if "with" in c or "withrsa" in c:
        h = _hash_in(toks, c)
        sig = None
        if "ecdsa" in c:
            sig = "ecdsa"
        elif "rsa" in c:
            sig = "rsa"
        elif "dsa" in c:
            sig = "dsa"
        elif "ed25519" in c:
            sig = "ed25519"
        if sig:
            comps = [(sig, bits, raw)]
            if h in ("sha-1", "md5") or (h and h.startswith("md")):
                comps.append((h, None, raw + " (signature hash)"))
            return comps, bits

    # 7. Token-bounded family patterns
    tok_set = set(toks)
    # HMAC
    if "hmac" in tok_set or c.startswith("hmac"):
        h = _hash_in(toks, c.replace("hmac", ""))
        if h == "sha-1":
            return [("hmac-sha1", None, raw)], None
        if h in ("md5",):
            return [("md5", None, raw)], None
        if h:
            return [(h, None, raw)], None
    # AES
    aes = _aes(toks, c)
    if aes and not (tok_set & {"rsa", "ecdsa", "ecdh", "ecdhe", "dhe"}):
        return [(aes, None, raw)], None
    # Curves on their own or with EC/ECDSA/ECDH words
    curve = _curve_in(raw)
    if "ecdsa" in tok_set or c.startswith("ecdsa"):
        return [("ecdsa", CURVES.get(curve) if curve else bits, raw)], bits
    if tok_set & {"ecdh", "ecdhe"} or c.startswith("ecdh"):
        return [("ecdh", CURVES.get(curve) if curve else bits, raw)], bits
    if curve:
        return [("ec", CURVES[curve], raw)], CURVES[curve]
    # Families by token
    for fam, cid in (("rsa", "rsa"), ("dsa", "dsa"), ("ed25519", "ed25519"), ("ed448", "ed448"),
                     ("x25519", "x25519"), ("x448", "x448"), ("dh", "dh"), ("dhe", "dh"),
                     ("mqv", "mqv"), ("ecmqv", "mqv"), ("elgamal", "elgamal"), ("chacha20", "chacha20"),
                     ("camellia", "camellia"), ("aria", "aria"), ("seed", "seed"), ("sm4", "sm4"),
                     ("sm2", "sm2"), ("3des", "3des"), ("des", "des"), ("rc4", "rc4"), ("rc2", "rc2"),
                     ("md5", "md5"), ("md4", "md4"), ("sha1", "sha-1"), ("sha256", "sha-256"),
                     ("sha384", "sha-384"), ("sha512", "sha-512"), ("sha224", "sha-224"),
                     ("blowfish", "blowfish"), ("idea", "idea"), ("cast5", "cast5"), ("pbkdf2", "pbkdf2"),
                     ("bcrypt", "password-hash"), ("scrypt", "password-hash"), ("argon2", "password-hash"),
                     ("argon2id", "password-hash"), ("falcon", "fn-dsa"), ("lms", "lms"), ("xmss", "xmss")):
        if fam in tok_set:
            b = bits or (_bits_from(low) if cid in ("rsa", "dsa", "dh") else None)
            return [(cid, b, raw)], b
    # Prefix forms like "rsa2048", "dh4096", "sha3-256", "shake256"
    m = re.match(r"^(rsa|dsa|dh)(\d{3,5})$", c)
    if m:
        return [({"rsa": "rsa", "dsa": "dsa", "dh": "dh"}[m.group(1)], int(m.group(2)), raw)], int(m.group(2))
    if c.startswith("sha3") or c.startswith("shake"):
        return [("sha3", None, raw)], None
    if c.startswith("diffiehellman"):
        return [("dh", bits, raw)], bits
    return [], bits


# ---------------------------------------------------------------------------
# Strength and verdicts
# ---------------------------------------------------------------------------

def _ifc_strength(bits):
    """SP 800-57 Pt1 Rev5 Table 2 for RSA / DSA / DH modulus size."""
    if bits is None:
        return None
    if bits < 2048:
        return 80
    if bits < 3072:
        return 112
    if bits < 7680:
        return 128
    if bits < 15360:
        return 192
    return 256


def _ecc_strength(bits):
    if bits is None:
        return None
    if bits < 224:
        return 80
    if bits < 256:
        return 112
    if bits < 384:
        return 128
    if bits < 512:
        return 192
    return 256


def _strength(cid, bits):
    a = ALGORITHMS[cid]
    if a["strength"] is not None:
        return a["strength"]
    if cid in ("rsa", "dsa", "dh", "elgamal"):
        return _ifc_strength(bits)
    if cid in ("ecdsa", "ecdh", "ec", "mqv", "sm2"):
        return _ecc_strength(bits)
    return None


_PRIORITY_RANK = {"Critical": 0, "High": 1, "Review": 2, "Low": 3, "None": 4}

# Scoring lanes. The readiness score covers the public-key lanes (where quantum exposure lives);
# symmetric, hash, kdf and protocol lanes are reported separately.
_LANE_BY_PRIMITIVE = {
    "kem": "key-establishment", "key-agree": "key-establishment", "signature": "signature",
    "pke": "public-key", "block-cipher": "symmetric", "stream-cipher": "symmetric", "ae": "symmetric",
    "mac": "symmetric", "hash": "hash", "kdf": "kdf",
}
PUBLIC_KEY_LANES = ("key-establishment", "signature", "public-key")


def lane_of(canonical, primitive):
    if canonical in ("tls1.3", "tls1.2", "tls-legacy"):
        return "protocol"
    if canonical == "null-cipher":
        return "symmetric"
    return _LANE_BY_PRIMITIVE.get(primitive, "other")


def _verdict_for(cid, bits, profile, label):
    a = ALGORITHMS[cid]
    strength = _strength(cid, bits)
    kind = a["kind"]
    v = {
        "canonical": cid, "family": a["family"], "parameter_set": a["param"] or (str(bits) if bits else None),
        "primitive": a["primitive"], "crypto_functions": list(a["functions"]),
        "nist_pqc_level": a["level"], "controls": list(a["controls"]), "note": a["note"],
        "cite": list(a["cite"]), "standard_status": a["standard"], "label": label,
        "classical_security_level": strength, "classically_broken": False,
        "deprecated_after": None, "disallowed_after": None,
        "lane": lane_of(cid, a["primitive"]),
    }
    # Key-size-dependent breakage of quantum-vulnerable algorithms
    if kind == "qv" and strength is not None and strength < 112:
        kind = "broken"
        v["note"] = a["note"] + f" {bits}-bit key is below 112-bit security (SP 800-57): broken today."
        v["cite"] = sorted(set(v["cite"] + ["SP800-57", "SP800-131A"]))

    if kind == "broken":
        v.update(quantum_vulnerable=True, classically_broken=True, priority="Critical",
                 nist_pqc_level=0,
                 cnsa_target="Replace now (broken or disallowed independent of quantum)")
        if cid == "tls-legacy":
            v["cnsa_target"] = "Replace now: disable SSL 3.0 / TLS 1.0 / TLS 1.1 (RFC 8996); enable TLS 1.3"
        return v

    if kind == "qv":
        v["quantum_vulnerable"] = True
        v["priority"] = "High"
        # IR 8547 final (Oct 2026) deprecates every quantum-vulnerable signature and key-establishment
        # scheme after 2030 regardless of strength (the draft deprecated only 112-bit strength).
        v["deprecated_after"] = 2030
        v["disallowed_after"] = 2035
        sig = a["primitive"] == "signature" or cid in ("ed25519", "ed448", "eddsa")
        kem = a["primitive"] in ("key-agree",) or cid in ("x25519", "x448", "ecdh", "dh", "mqv")
        if profile == "nss":
            if sig:
                t = "ML-DSA-87 (or LMS/XMSS for firmware/code signing) per CNSA 2.0"
            elif kem:
                t = "ML-KEM-1024 key establishment per CNSA 2.0"
            else:
                t = "ML-KEM-1024 (key establishment) / ML-DSA-87 (signature) per CNSA 2.0"
        else:
            when = "deprecated after 2030, disallowed after 2035 (IR 8547)"
            if sig:
                t = f"ML-DSA (FIPS 204) or SLH-DSA (FIPS 205); {when}"
            elif kem:
                t = f"ML-KEM (FIPS 203), e.g. hybrid X25519MLKEM768; {when}"
            else:
                t = f"ML-KEM (FIPS 203) / ML-DSA (FIPS 204); {when}"
        v["cnsa_target"] = t
        v["cite"] = sorted(set(v["cite"] + ["IR8547", "EO14412"]))
        v["deadline_note"] = ("High value assets / high impact systems (EO 14412, M-26-15): key establishment "
                              "by 2030-12-31, signatures by 2031-12-31.")
        return v

    # Quantum-resistant, symmetric, hash, KDF, protocol
    v["quantum_vulnerable"] = False
    compliant = a["compliant"].get(profile, False)
    v["cnsa_target"] = a["target"].get(profile) or ("None" if compliant else "Review")
    if compliant:
        if not v["cnsa_target"].startswith("None"):
            v["cnsa_target"] = "None (" + v["cnsa_target"] + ")"
        v["priority"] = "None"
    else:
        if v["cnsa_target"].startswith("None"):
            v["cnsa_target"] = v["cnsa_target"].replace("None", "Upgrade", 1)
        v["priority"] = "Low"
    if a["family"] in ("ML-KEM", "ML-DSA", "AES") and a["param"] is None:
        v["priority"] = "Review"
    return v


_DEFAULT = {
    "canonical": None, "family": None, "parameter_set": None,
    "primitive": "unknown", "crypto_functions": ["unknown"],
    "quantum_vulnerable": None, "nist_pqc_level": None,
    "cnsa_target": "Manual review", "controls": [],
    "note": "Unrecognized algorithm. Flag for analyst review.", "cite": [],
    "standard_status": None, "classically_broken": False,
    "deprecated_after": None, "disallowed_after": None, "classical_security_level": None,
    "priority": "Review", "lane": None,
}


def classify(name, bits=None, profile=None):
    """Return a verdict dict for an algorithm identifier.

    name    identifier as observed (OpenSSL, OpenSSH, TLS, CBOM name)
    bits    key size when known (RSA/DSA/DH modulus, EC field size)
    profile "civilian" (default, NIST/IR 8547) or "nss" (CNSA 2.0)
    """
    profile = (profile or DEFAULT_PROFILE).lower()
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}; expected one of {PROFILES}")
    try:
        bits = int(bits) if bits not in (None, "") else None
    except (TypeError, ValueError):
        bits = None

    comps, bits = normalize(name, bits)
    if not comps:
        v = dict(_DEFAULT)
        v["algorithm"] = name
        v["profile"] = profile
        v["components"] = []
        v["rule_id"] = None
        return v

    verdicts = [_verdict_for(cid, b if b is not None else bits, profile, label) for cid, b, label in comps]
    worst = min(verdicts, key=lambda x: _PRIORITY_RANK[x["priority"]])
    v = dict(worst)
    if len(verdicts) > 1:
        v["components"] = [{"canonical": x["canonical"], "label": x["label"], "priority": x["priority"],
                            "quantum_vulnerable": x["quantum_vulnerable"]} for x in verdicts]
        v["cite"] = sorted({c for x in verdicts for c in x["cite"]})
        v["controls"] = sorted({c for x in verdicts for c in x["controls"]})
        v["note"] = worst["note"] + " Components: " + ", ".join(
            f"{x['canonical']}={x['priority']}" for x in verdicts) + "."
    else:
        v["components"] = []
    # Non-NIST curve note
    curve = _curve_in(name or "")
    if curve in NON_NIST_CURVES:
        v["note"] += f" {curve} is not a NIST-approved curve."
    v["algorithm"] = name
    v["profile"] = profile
    v["rule_id"] = f"{RULESET_VERSION}:{v['canonical']}"
    v.pop("label", None)
    return v


def classical_level(name, bits=None):
    """Backward-compatible helper: classical security strength in bits, or None."""
    return classify(name, bits)["classical_security_level"]


# ---------------------------------------------------------------------------
# CycloneDX cryptography registry names
# ---------------------------------------------------------------------------
# Registry: third_party/cyclonedx/cryptography-defs.json (CycloneDX/specification 76f185c).
# A name is returned only where the mapping is unambiguous. A bare RSA or EC *key* is not a registry
# family (the registry names schemes), and OpenSSH's sntrup761 hybrid has no entry: those return None
# rather than an invented name.

_REG_DIRECT = {
    # TLS 1.3 key-exchange groups (registry TLS composition names)
    "x25519mlkem768": ("ML-KEM", "X25519MLKEM768"), "secp256r1mlkem768": ("ML-KEM", "SecP256r1MLKEM768"),
    "secp384r1mlkem1024": ("ML-KEM", "SecP384r1MLKEM1024"),
    "x25519": ("ECDH", "x25519"), "x448": ("ECDH", "x448"),
    # PQC
    "ml-kem-512": ("ML-KEM", "ML-KEM-512"), "ml-kem-768": ("ML-KEM", "ML-KEM-768"),
    "ml-kem-1024": ("ML-KEM", "ML-KEM-1024"),
    "ml-dsa-44": ("ML-DSA", "ML-DSA-44"), "ml-dsa-65": ("ML-DSA", "ML-DSA-65"), "ml-dsa-87": ("ML-DSA", "ML-DSA-87"),
    "ed25519": ("EdDSA", "Ed25519"), "ed448": ("EdDSA", "Ed448"),
    # symmetric / hash
    "aes-128": ("AES", "AES-128"), "aes-192": ("AES", "AES-192"), "aes-256": ("AES", "AES-256"),
    "sha-224": ("SHA-2", "SHA-224"), "sha-256": ("SHA-2", "SHA-256"), "sha-384": ("SHA-2", "SHA-384"),
    "sha-512": ("SHA-2", "SHA-512"), "sha-1": ("SHA-1", "SHA-1"), "md5": ("MD5", "MD5"), "md4": ("MD4", "MD4"),
    "md2": ("MD2", "MD2"), "rc4": ("RC4", "RC4"), "3des": ("3DES", "3DES"), "des": ("DES", "DES"),
    "idea": ("IDEA", "IDEA"), "rc2": ("RC2", "RC2"), "blowfish": ("Blowfish", "Blowfish"), "cast5": ("CAST5", "CAST5"),
    "hmac-sha1": ("HMAC", "HMAC-SHA-1"),
}
_TLS13_SUITES = {"tls_aes_128_gcm_sha256", "tls_aes_256_gcm_sha384", "tls_chacha20_poly1305_sha256"}
_CURVE_SECG = {256: "secp256r1", 384: "secp384r1", 521: "secp521r1", 224: "secp224r1", 192: "secp192r1"}
_HASH_REG = {"sha-1": "SHA-1", "sha-224": "SHA-224", "sha-256": "SHA-256", "sha-384": "SHA-384",
             "sha-512": "SHA-512"}


def registry_name(name, bits=None, curve_bits=None):
    """(registry family, registry name) for an observed identifier, or (None, None).

    bits        key size from the asset (RSA modulus, EC field size)
    curve_bits  EC field size of the certificate key, used to name the curve of an ECDSA signature
    """
    raw = (name or "").strip()
    low = raw.lower()
    if low in _TLS13_SUITES:
        return "TLS", raw.upper()
    comps, b = normalize(raw, bits)
    if not comps:
        return None, None
    if len(comps) > 1 and not low.startswith(("sha", "md5", "ecdsa-with", "dsa_with", "id-dsa")) \
            and "withrsa" not in _compact(raw) and not low.startswith(("ssh-", "diffie-", "ecdh-sha2")):
        return None, None  # TLS 1.2 suites and other composites: no single registry name
    cid = comps[0][0]
    b = comps[0][1] or b
    tok = _tokens(low)
    h = _hash_in(tok, _compact(raw))
    m = re.match(r"^ecdsa-sha2-nistp(256|384|521)", low)
    if m:  # RFC 5656: the hash follows the curve
        h = {"256": "sha-256", "384": "sha-384", "521": "sha-512"}[m.group(1)]
    if cid in _REG_DIRECT and cid not in ("x25519",):
        fam, reg = _REG_DIRECT[cid]
        if cid.startswith("aes-"):
            mode = next((m.upper() for m in ("gcm", "ccm", "cbc", "ctr", "ecb", "xts") if m in tok
                         or m in _compact(raw)), None)
            reg = f"{reg}-{mode}" if mode else reg
        return fam, reg
    if cid == "x25519":
        return "ECDH", "x25519"
    if cid == "chacha20":
        return "ChaCha20", "ChaCha20-Poly1305" if "poly1305" in _compact(raw) else "ChaCha20"
    if cid == "ecdh":
        size = b or curve_bits
        return ("ECDH", f"ECDHE-{_CURVE_SECG[size]}") if size in _CURVE_SECG else ("ECDH", "ECDHE")
    if cid == "dh":
        m = re.search(r"ffdhe(\d{4})", _compact(raw))
        return "FFDH", (f"FFDHE-ffdhe{m.group(1)}" if m else "FFDHE")
    if cid == "ecdsa":
        size = b or curve_bits
        parts = ["ECDSA"] + ([_CURVE_SECG[size]] if size in _CURVE_SECG else [])
        if h in _HASH_REG:
            parts.append(_HASH_REG[h])
        return "ECDSA", "-".join(parts)
    if cid == "rsa":
        if "pss" in _compact(raw):
            return "RSASSA-PSS", "RSA-PSS" + (f"-{_HASH_REG[h]}" if h in _HASH_REG else "")
        if "with" in _compact(raw) or low.startswith("rsa-sha2-"):
            hh = h or ("sha-256" if low == "rsa-sha2-256" else "sha-512" if low == "rsa-sha2-512" else None)
            return "RSASSA-PKCS1", "RSA-PKCS1-1.5" + (f"-{_HASH_REG[hh]}" if hh in _HASH_REG else "")
        return None, None  # a bare RSA key: the scheme is not observable from the key alone
    if cid == "dsa":
        return "DSA", "DSA" + (f"-{_HASH_REG[h]}" if h in _HASH_REG else "")
    if cid.startswith("slh-dsa"):
        m = re.search(r"slh-?dsa-?(sha2|shake)-?(128|192|256)([sf])", low)
        return ("SLH-DSA", f"SLH-DSA-{m.group(1).upper()}-{m.group(2)}{m.group(3)}") if m else (None, None)
    if cid == "mqv":
        return "MQV", "ECMQV"
    if cid == "elgamal":
        return "ElGamal", "ElGamal"
    return None, None
