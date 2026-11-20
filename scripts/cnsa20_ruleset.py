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

RULESET_VERSION = "1.0.7"
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
    "CNSA2-FAQ": "NSA, The Commercial National Security Algorithm Suite 2.0 and Quantum Computing FAQ, "
                 "U/OO/194427-22, Ver. 2.0, April 2024: from SP 800-208 only LMS and XMSS are approved for NSS; "
                 "\"the multitree algorithms HSS and XMSSMT are not allowed\" (p. 5)",
    "SP800-57": "NIST SP 800-57 Part 1 Rev. 5, Table 2 (comparable security strengths)",
    "SP800-186": "NIST SP 800-186, Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve "
                 "Domain Parameters (Feb 2023): binary-field curves deprecated",
    "SP800-131A": "NIST SP 800-131A Rev. 2, Transitioning the Use of Cryptographic Algorithms and Key Lengths",
    "SP800-131A-R3-IPD": "NIST SP 800-131A Rev. 3 initial public draft (Oct 2024; still a draft), Tables 12 and 14: "
                         "SHA-1 and the 224-bit hashes (incl. in HMAC generation) deprecated through 2030, "
                         "disallowed after 2030. https://csrc.nist.gov/pubs/sp/800/131/a/r3/ipd",
    "FIPS140-3": "NIST FIPS 140-3 and SP 800-140C (approved security functions): ChaCha20, Camellia, ARIA, "
                 "SEED and SM4 are not approved",
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
    "LAMPS-COMPOSITE": "IETF draft-ietf-lamps-pq-composite-sigs (composite ML-DSA with a classical signature; "
                       "an Internet-Draft, not yet a standard)",
    "RFC5054": "IETF RFC 5054, Using the Secure Remote Password (SRP) Protocol for TLS Authentication "
               "(key exchange over a finite-field Diffie-Hellman group)",
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
    "mlkem768nistp256-sha256": _a("pqc", "kem", _KEM_FN, level=3, compliant=_CIV, family="ML-KEM",
                                  param="mlkem768nistp256-sha256", controls=["SC-8", "SC-12", "SC-13"],
                                  cite=["SSH-MLKEM", "FIPS203", "CNSA2"],
                                  note="SSH hybrid ML-KEM-768 + ECDH P-256 key exchange.",
                                  target={"civilian": "None (hybrid ML-KEM-768)",
                                          "nss": "mlkem1024nistp384-sha384 or ML-KEM-1024 (CNSA 2.0)"}),
    "mlkem1024nistp384-sha384": _a("pqc", "kem", _KEM_FN, level=5, compliant=_BOTH, family="ML-KEM",
                                   param="mlkem1024nistp384-sha384", controls=["SC-8", "SC-12", "SC-13"],
                                   cite=["SSH-MLKEM", "FIPS203", "CNSA2"],
                                   note="SSH hybrid ML-KEM-1024 + ECDH P-384 key exchange.",
                                   target={"civilian": "None (hybrid ML-KEM-1024)",
                                           "nss": "None (ML-KEM-1024 hybrid)"}),
    "x448mlkem1024": _a("pqc", "kem", _KEM_FN, level=5, compliant=_CIV, family="ML-KEM",
                        param="X448MLKEM1024", standard="pre-standard", controls=["SC-8", "SC-12", "SC-13"],
                        cite=["FIPS203", "CNSA2"],
                        note="Hybrid X448 + ML-KEM-1024. Quantum-resistant; not a registered TLS group.",
                        target={"civilian": "None (hybrid ML-KEM-1024)",
                                "nss": "SecP384r1MLKEM1024 or ML-KEM-1024 (CNSA 2.0)"}),
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
    # Pre-standard round-3 submissions. FIPS 203/204/205 changed each algorithm (FIPS 203 Appendix C, FIPS 204
    # Appendix D, FIPS 205 Appendix A: "Differences from the ... submission"), so Kyber, Dilithium and SPHINCS+ are
    # not ML-KEM, ML-DSA or SLH-DSA and do not interoperate with them.
    "kyber": _a("pqc", "kem", _KEM_FN, compliant=_NONE, family="Kyber", standard="pre-standard",
                controls=["SC-8", "SC-12"], cite=["FIPS203", "CNSA2"],
                note="Pre-standard CRYSTALS-Kyber (alone or in a hybrid). Quantum-resistant, but not FIPS 203 "
                     "ML-KEM: FIPS 203 changed the algorithm (Appendix C).",
                target={"civilian": "Replace with ML-KEM (FIPS 203), e.g. hybrid X25519MLKEM768",
                        "nss": "Replace with ML-KEM-1024 based key exchange (CNSA 2.0)"}),
    # Hybrids of ML-KEM with a classical key exchange in a pairing that is not a registered TLS group or SSH method
    # (e.g. X25519MLKEM1024, SecP256r1MLKEM1024). Judged as hybrids: quantum-resistant through the ML-KEM half;
    # CNSA 2.0 compliance is given only to the registered ML-KEM-1024 + P-384 pairings above.
    "hybrid-ml-kem-512": _a("pqc", "kem", _KEM_FN, level=1, compliant=_CIV, family="ML-KEM",
                            param="hybrid ML-KEM-512", standard="pre-standard", controls=["SC-8", "SC-12", "SC-13"],
                            cite=["FIPS203", "CNSA2"],
                            note="Hybrid of ML-KEM-512 and a classical key exchange (not a registered pairing). "
                                 "Quantum-resistant key establishment through its ML-KEM half.",
                            target={"civilian": "None (hybrid ML-KEM-512; ML-KEM-768 is the NIST default)",
                                    "nss": "SecP384r1MLKEM1024 or ML-KEM-1024 (CNSA 2.0)"}),
    "hybrid-ml-kem-768": _a("pqc", "kem", _KEM_FN, level=3, compliant=_CIV, family="ML-KEM",
                            param="hybrid ML-KEM-768", standard="pre-standard", controls=["SC-8", "SC-12", "SC-13"],
                            cite=["FIPS203", "CNSA2"],
                            note="Hybrid of ML-KEM-768 and a classical key exchange (not a registered pairing). "
                                 "Quantum-resistant key establishment through its ML-KEM half.",
                            target={"civilian": "None (hybrid ML-KEM-768)",
                                    "nss": "SecP384r1MLKEM1024 or ML-KEM-1024 (CNSA 2.0)"}),
    "hybrid-ml-kem-1024": _a("pqc", "kem", _KEM_FN, level=5, compliant=_CIV, family="ML-KEM",
                             param="hybrid ML-KEM-1024", standard="pre-standard", controls=["SC-8", "SC-12", "SC-13"],
                             cite=["FIPS203", "CNSA2"],
                             note="Hybrid of ML-KEM-1024 and a classical key exchange other than P-384 (not a "
                                  "registered pairing). Quantum-resistant key establishment through its ML-KEM half.",
                             target={"civilian": "None (hybrid ML-KEM-1024)",
                                     "nss": "SecP384r1MLKEM1024 or ML-KEM-1024 (CNSA 2.0)"}),
    # The initial public drafts (Aug 2023) differ from the final standards (FIPS 203 Appendix C.2, FIPS 204
    # Appendix D.3, FIPS 205 Appendix A.1); an implementation of a draft is not a FIPS implementation.
    "ml-kem-ipd": _a("pqc", "kem", _KEM_FN, compliant=_NONE, family="ML-KEM", param="ML-KEM (FIPS 203 ipd)",
                     standard="pre-standard", controls=["SC-8", "SC-12"], cite=["FIPS203", "CNSA2"],
                     note="ML-KEM from the FIPS 203 initial public draft (2023). Quantum-resistant, but the final "
                          "standard changed key generation (Appendix C.2), so it is not FIPS 203 ML-KEM.",
                     target={"civilian": "Replace with ML-KEM (FIPS 203 final)",
                             "nss": "Replace with ML-KEM-1024 (FIPS 203 final, CNSA 2.0)"}),
    # --- Quantum-resistant signatures -------------------------------------------
    "ml-dsa-ipd": _a("pqc", "signature", _SIG_FN, compliant=_NONE, family="ML-DSA", param="ML-DSA (FIPS 204 ipd)",
                     standard="pre-standard", controls=["SC-13", "SC-17"], cite=["FIPS204", "CNSA2"],
                     note="ML-DSA from the FIPS 204 initial public draft (2023). Quantum-resistant, but the final "
                          "standard changed signing and verification (Appendix D.3), so it is not FIPS 204 ML-DSA.",
                     target={"civilian": "Replace with ML-DSA (FIPS 204 final)",
                             "nss": "Replace with ML-DSA-87 (FIPS 204 final, CNSA 2.0)"}),
    "slh-dsa-ipd": _a("pqc", "signature", _SIG_FN, compliant=_NONE, family="SLH-DSA",
                      param="SLH-DSA (FIPS 205 ipd)", standard="pre-standard", controls=["SC-13", "SC-17"],
                      cite=["FIPS205", "CNSA2"],
                      note="SLH-DSA from the FIPS 205 initial public draft (2023). Quantum-resistant, but the final "
                           "standard added domain separation to signing (Appendix A.1), so it is not FIPS 205 SLH-DSA.",
                      target={"civilian": "Replace with SLH-DSA (FIPS 205 final)",
                              "nss": "ML-DSA-87, or LMS/XMSS for firmware (CNSA 2.0)"}),
    # Composite signatures: ML-DSA together with a classical signature (an Internet-Draft). Judged like the ML-KEM
    # hybrids: quantum-resistant through the ML-DSA half (a forger must break both); compliant under civilian as
    # far as the ML-DSA half is; under nss only ML-DSA-87 with a CNSA-compatible classical half (ECDSA P-384 or
    # RSA of at least 3072 bits).
    "composite-ml-dsa-44": _a("pqc", "signature", _SIG_FN, level=2, compliant=_CIV, family="ML-DSA",
                              param="composite ML-DSA-44", standard="pre-standard", controls=["SC-13", "SC-17"],
                              cite=["LAMPS-COMPOSITE", "FIPS204", "CNSA2"],
                              note="Composite ML-DSA-44 with a classical signature (combination format: IETF draft; ML-DSA is FIPS 204). Quantum-resistant through its "
                                   "ML-DSA half.",
                              target={"civilian": "None (composite ML-DSA-44)", "nss": "ML-DSA-87 (CNSA 2.0)"}),
    "composite-ml-dsa-65": _a("pqc", "signature", _SIG_FN, level=3, compliant=_CIV, family="ML-DSA",
                              param="composite ML-DSA-65", standard="pre-standard", controls=["SC-13", "SC-17"],
                              cite=["LAMPS-COMPOSITE", "FIPS204", "CNSA2"],
                              note="Composite ML-DSA-65 with a classical signature (combination format: IETF draft; ML-DSA is FIPS 204). Quantum-resistant through its "
                                   "ML-DSA half.",
                              target={"civilian": "None (composite ML-DSA-65)", "nss": "ML-DSA-87 (CNSA 2.0)"}),
    "composite-ml-dsa-87": _a("pqc", "signature", _SIG_FN, level=5, compliant=_CIV, family="ML-DSA",
                              param="composite ML-DSA-87", standard="pre-standard", controls=["SC-13", "SC-17"],
                              cite=["LAMPS-COMPOSITE", "FIPS204", "CNSA2"],
                              note="Composite ML-DSA-87 with a classical signature that is not CNSA-compatible "
                                   "(e.g. Ed448); combination format: IETF draft. Quantum-resistant through its ML-DSA half.",
                              target={"civilian": "None (composite ML-DSA-87)",
                                      "nss": "ML-DSA-87, alone or with ECDSA P-384 (CNSA 2.0)"}),
    "composite-ml-dsa-87-cnsa": _a("pqc", "signature", _SIG_FN, level=5, compliant=_BOTH, family="ML-DSA",
                                   param="composite ML-DSA-87 (ECDSA P-384 or RSA-3072+)", standard="pre-standard",
                                   controls=["SC-13", "SC-17"], cite=["LAMPS-COMPOSITE", "FIPS204", "CNSA2"],
                                   note="Composite ML-DSA-87 with ECDSA P-384 or RSA of at least 3072 bits (combination format: IETF draft; ML-DSA is FIPS 204).",
                                   target={"civilian": "None (composite ML-DSA-87)",
                                           "nss": "None (ML-DSA-87 composite)"}),
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
    "dilithium": _a("pqc", "signature", _SIG_FN, compliant=_NONE, family="Dilithium", standard="pre-standard",
                    controls=["SC-13", "SC-17"], cite=["FIPS204", "CNSA2"],
                    note="Pre-standard CRYSTALS-Dilithium. Quantum-resistant, but not FIPS 204 ML-DSA: FIPS 204 "
                         "changed the algorithm (Appendix D).",
                    target={"civilian": "Replace with ML-DSA (FIPS 204)", "nss": "Replace with ML-DSA-87 (CNSA 2.0)"}),
    "sphincs+": _a("pqc", "signature", _SIG_FN, compliant=_NONE, family="SPHINCS+", standard="pre-standard",
                   controls=["SC-13", "SC-17"], cite=["FIPS205", "CNSA2"],
                   note="Pre-standard SPHINCS+. Quantum-resistant, but not FIPS 205 SLH-DSA: FIPS 205 changed the "
                        "algorithm and approves only the simple SHA2 and SHAKE parameter sets (Appendix A), not "
                        "Haraka.",
                   target={"civilian": "Replace with SLH-DSA (FIPS 205, SHA2 or SHAKE parameter sets) or ML-DSA",
                           "nss": "ML-DSA-87, or LMS/XMSS for firmware (CNSA 2.0)"}),
    "lms": _a("pqc", "signature", _SIG_FN, level=5, compliant=_BOTH, family="LMS",
              controls=["SC-13", "SC-17"], cite=["SP800-208", "CNSA2"],
              note="Stateful hash-based signature (SP 800-208). CNSA 2.0 approves LMS and XMSS for software and "
                   "firmware signing only. State management is a deployment risk.",
              target={"civilian": "None (SP 800-208)", "nss": "None (CNSA 2.0 firmware/code signing)"}),
    "xmss": _a("pqc", "signature", _SIG_FN, level=5, compliant=_BOTH, family="XMSS",
               controls=["SC-13", "SC-17"], cite=["SP800-208", "CNSA2"],
               note="Stateful hash-based signature (SP 800-208). CNSA 2.0 approves LMS and XMSS for software and "
                    "firmware signing only. State management is a deployment risk.",
               target={"civilian": "None (SP 800-208)", "nss": "None (CNSA 2.0 firmware/code signing)"}),
    # The multitree variants (1.0.7): SP 800-208 approves them, CNSA 2.0 does not ("HSS and XMSSMT are not allowed",
    # NSA CNSA 2.0 FAQ, April 2024). Before 1.0.7 they were read as LMS / XMSS, compliant under nss.
    "hss": _a("pqc", "signature", _SIG_FN, level=5, compliant=_CIV, family="LMS",
              controls=["SC-13", "SC-17"], cite=["SP800-208", "CNSA2", "CNSA2-FAQ"],
              note="HSS, the multitree form of LMS (SP 800-208). Quantum-resistant; not allowed in NSS (CNSA 2.0 "
                   "approves single-tree LMS and XMSS only). Standards also use the HSS/LMS framing for a single "
                   "level (L=1), which is single-tree LMS: the name alone does not show the level count, so "
                   "confirm it before acting on the NSS verdict. State management is a deployment risk.",
              target={"civilian": "None (SP 800-208)", "nss": "Single-tree LMS or XMSS (CNSA 2.0 firmware/code signing)"}),
    "xmssmt": _a("pqc", "signature", _SIG_FN, level=5, compliant=_CIV, family="XMSS",
                 controls=["SC-13", "SC-17"], cite=["SP800-208", "CNSA2", "CNSA2-FAQ"],
                 note="XMSS^MT, the multitree form of XMSS (SP 800-208). Quantum-resistant; not allowed in NSS "
                      "(CNSA 2.0 approves single-tree LMS and XMSS only). State management is a deployment risk.",
                 target={"civilian": "None (SP 800-208)", "nss": "Single-tree LMS or XMSS (CNSA 2.0 firmware/code signing)"}),
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
    "srp": _a("qv", "key-agree", ["keygen"], level=0, family="SRP", standard="non-nist",
              controls=["SC-8", "SC-12"], cite=["RFC5054", "IR8547"],
              note="SRP key exchange (RFC 5054) runs over a finite-field Diffie-Hellman group: quantum-vulnerable "
                   "(discrete logarithm) and not a NIST-approved key-establishment scheme."),
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
    "chacha20": _a("sym", "stream-cipher", _ENC_FN, level=5, strength=256, compliant=_NONE, family="ChaCha20",
                   standard="non-nist", controls=["SC-13", "SC-28"], cite=["FIPS140-3", "CNSA2"],
                   note="ChaCha20(-Poly1305), 256-bit key. Quantum-resistant, but not a FIPS-approved algorithm "
                        "and not a CNSA 2.0 algorithm.",
                   target={"civilian": "AES-GCM (FIPS-approved)", "nss": "AES-256 (CNSA 2.0)"}),
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
                  param="224", cite=["SP800-131A", "SP800-131A-R3-IPD", "CNSA2"],
                  note="SHA-224. Approved under SP 800-131A Rev. 2; the Rev. 3 draft proposes disallowing the "
                       "224-bit hashes for new protection after 2030. CNSA 2.0 requires SHA-384+.",
                  target={"civilian": "SHA-256 or stronger before 2031 (SP 800-131A Rev. 3 draft)",
                          "nss": "SHA-384 or SHA-512 (CNSA 2.0)"}),
    "sha-256": _a("hash", "hash", ["digest"], level=2, strength=128, compliant=_CIV, family="SHA-2",
                  param="256", cite=["SP800-131A", "CNSA2"], note="SHA-256. Approved; CNSA 2.0 requires SHA-384+.",
                  target={"civilian": "None (approved)", "nss": "SHA-384 or SHA-512 (CNSA 2.0)"}),
    "sha-512/224": _a("hash", "hash", ["digest"], level=1, strength=112, compliant=_CIV, family="SHA-2",
                      param="512/224", cite=["SP800-131A", "SP800-131A-R3-IPD", "CNSA2"],
                      note="SHA-512/224 (224-bit output). Approved under SP 800-131A Rev. 2; the Rev. 3 draft "
                           "proposes disallowing the 224-bit hashes for new protection after 2030. CNSA 2.0 "
                           "requires SHA-384+.",
                      target={"civilian": "SHA-256 or stronger before 2031 (SP 800-131A Rev. 3 draft)",
                              "nss": "SHA-384 or SHA-512 (CNSA 2.0)"}),
    "sha-512/256": _a("hash", "hash", ["digest"], level=2, strength=128, compliant=_CIV, family="SHA-2",
                      param="512/256", cite=["SP800-131A", "CNSA2"],
                      note="SHA-512/256 (256-bit output, 128-bit collision strength). Approved; CNSA 2.0 "
                           "requires SHA-384 or SHA-512.",
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
                    cite=["SP800-131A", "SP800-131A-R3-IPD", "CNSA2"],
                    note="HMAC-SHA-1 is acceptable under SP 800-131A Rev. 2 (SHA-1 collisions do not break "
                         "HMAC). The Rev. 3 draft proposes deprecating HMAC-SHA-1 generation through 2030 and "
                         "disallowing it after 2030.",
                    target={"civilian": "HMAC-SHA-256 before 2031 (SP 800-131A Rev. 3 draft)",
                            "nss": "HMAC-SHA-384 (CNSA 2.0)"}),
    "umac": _a("mac", "mac", ["tag"], compliant=_NONE, family="UMAC", standard="non-nist",
               cite=["FIPS140-3", "CNSA2"],
               note="UMAC (RFC 4418, OpenSSH umac-64/umac-128). Not FIPS-approved; not a quantum exposure.",
               target={"civilian": "HMAC-SHA-256 or HMAC-SHA-512 (FIPS-approved)",
                       "nss": "HMAC-SHA-384 or HMAC-SHA-512 (CNSA 2.0)"}),
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
    "sha-1": _a("broken", "hash", ["digest"], level=0, family="SHA-1", cite=["SP800-131A", "SP800-131A-R3-IPD"],
                note="SHA-1 is disallowed for digital signatures and collision-resistant uses; the SP 800-131A "
                     "Rev. 3 draft proposes disallowing it for all new protection after 2030."),
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
    "ml-kem-512": "ml-kem-512", "mlkem512": "ml-kem-512",
    "ml-kem-768": "ml-kem-768", "mlkem768": "ml-kem-768",
    "ml-kem-1024": "ml-kem-1024", "mlkem1024": "ml-kem-1024",
    "ml-kem": "ml-kem", "mlkem": "ml-kem",
    # Pre-standard Kyber is not FIPS 203 ML-KEM (1.0.4; before, these read as ML-KEM)
    "kyber512": "kyber", "kyber768": "kyber", "kyber1024": "kyber", "kyber": "kyber",
    "x25519mlkem768": "x25519mlkem768", "x25519_mlkem768": "x25519mlkem768",
    "secp256r1mlkem768": "secp256r1mlkem768", "p256mlkem768": "secp256r1mlkem768",
    "secp384r1mlkem1024": "secp384r1mlkem1024", "p384mlkem1024": "secp384r1mlkem1024",
    "mlkem768x25519-sha256": "mlkem768x25519-sha256",
    "mlkem768nistp256-sha256": "mlkem768nistp256-sha256",
    "mlkem1024nistp384-sha384": "mlkem1024nistp384-sha384",
    "x448mlkem1024": "x448mlkem1024", "x448_mlkem1024": "x448mlkem1024",
    "hybrid-ml-kem-512": "hybrid-ml-kem-512", "hybrid-ml-kem-768": "hybrid-ml-kem-768",
    "hybrid-ml-kem-1024": "hybrid-ml-kem-1024", "ml-kem-ipd": "ml-kem-ipd", "ml-dsa-ipd": "ml-dsa-ipd",
    "slh-dsa-ipd": "slh-dsa-ipd", "composite-ml-dsa-44": "composite-ml-dsa-44",
    "composite-ml-dsa-65": "composite-ml-dsa-65", "composite-ml-dsa-87": "composite-ml-dsa-87",
    "composite-ml-dsa-87-cnsa": "composite-ml-dsa-87-cnsa",
    "sntrup761x25519-sha512": "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com": "sntrup761x25519-sha512",
    "x25519kyber768draft00": "x25519kyber768draft00", "x25519_kyber768": "x25519kyber768draft00",
    "x25519kyber768": "x25519kyber768draft00",
    # PQC signatures
    "ml-dsa-44": "ml-dsa-44", "mldsa44": "ml-dsa-44",
    "ml-dsa-65": "ml-dsa-65", "mldsa65": "ml-dsa-65",
    "ml-dsa-87": "ml-dsa-87", "mldsa87": "ml-dsa-87",
    "ml-dsa": "ml-dsa", "mldsa": "ml-dsa",
    # Pre-standard Dilithium and SPHINCS+ are not FIPS 204 ML-DSA or FIPS 205 SLH-DSA (1.0.4)
    "dilithium2": "dilithium", "dilithium3": "dilithium", "dilithium5": "dilithium", "dilithium": "dilithium",
    "slh-dsa": "slh-dsa", "slhdsa": "slh-dsa",
    "sphincs+": "sphincs+", "sphincsplus": "sphincs+", "sphincs": "sphincs+",
    "lms": "lms", "hss": "hss", "hss/lms": "hss", "hsslms": "hss", "xmss": "xmss", "xmssmt": "xmssmt",
    "falcon": "fn-dsa", "fn-dsa": "fn-dsa", "fndsa": "fn-dsa", "falcon512": "fn-dsa", "falcon1024": "fn-dsa",
    "fn-dsa-512": "fn-dsa", "fn-dsa-1024": "fn-dsa",
    # Quantum-vulnerable public key (OpenSSL names)
    "rsa": "rsa", "rsaencryption": "rsa", "rsassapss": "rsa", "rsassa-pss": "rsa", "rsa-pss": "rsa",
    "rsaes-oaep": "rsa", "rsa-oaep": "rsa", "rsa-sha2-256": "rsa", "rsa-sha2-512": "rsa",
    "dsa": "dsa", "dsaencryption": "dsa", "ssh-dss": "dsa",
    "ecdsa": "ecdsa", "ec": "ec", "idecpublickey": "ec", "ecpublickey": "ec",
    "ecdh": "ecdh", "ecdhe": "ecdh",
    "x25519": "x25519", "curve25519": "x25519", "x448": "x448", "curve448": "x448",
    "ed25519": "ed25519", "ssh-ed25519": "ed25519", "eddsa": "eddsa", "ed448": "ed448", "ssh-ed448": "ed448",
    "dh": "dh", "dhe": "dh", "dhkeyagreement": "dh", "diffie-hellman": "dh", "diffiehellman": "dh", "ffdhe": "dh",
    "mqv": "mqv", "ecmqv": "mqv", "elgamal": "elgamal", "sm2": "sm2", "srp": "srp",
    # Symmetric
    "chacha20": "chacha20", "chacha20-poly1305": "chacha20", "chacha20-poly1305@openssh.com": "chacha20",
    "xchacha20-poly1305": "chacha20",
    "camellia": "camellia", "aria": "aria", "seed": "seed", "sm4": "sm4",
    "aes": "aes",
    # Hashes
    "sha224": "sha-224", "sha-224": "sha-224", "sha256": "sha-256", "sha-256": "sha-256",
    "sha384": "sha-384", "sha-384": "sha-384", "sha512": "sha-512", "sha-512": "sha-512",
    "sha512/256": "sha-512/256", "sha-512/256": "sha-512/256", "sha512-256": "sha-512/256",
    "sha-512-256": "sha-512/256", "sha512_256": "sha-512/256",
    "sha512/224": "sha-512/224", "sha-512/224": "sha-512/224", "sha512-224": "sha-512/224",
    "sha-512-224": "sha-512/224", "sha512_224": "sha-512/224",
    "sha1": "sha-1", "sha-1": "sha-1", "md5": "md5", "md4": "md4", "md2": "md2",
    "blake2b": "blake2", "blake2s": "blake2", "blake2": "blake2",
    "hmac-sha1": "hmac-sha1", "hmacsha1": "hmac-sha1", "hmac-sha1-96": "hmac-sha1",
    "hmac-sha1-etm@openssh.com": "hmac-sha1",
    # OpenSSH MAC names; HMAC-SHA-2 is judged by its hash, as hmac-sha256 already is.
    "hmac-sha2-256": "sha-256", "hmac-sha2-256-etm@openssh.com": "sha-256",
    "hmac-sha2-512": "sha-512", "hmac-sha2-512-etm@openssh.com": "sha-512",
    "umac": "umac", "umac-64@openssh.com": "umac", "umac-64-etm@openssh.com": "umac",
    "umac-128@openssh.com": "umac", "umac-128-etm@openssh.com": "umac",
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
    # Legacy SEC 2 / X9.62 / RFC 5639 curves (1.0.6; before, a bare name was unknown and read Review). The size is
    # the field size: under 224 bits is under 112-bit security, Critical (SP 800-57, SP 800-131A).
    "secp160r1": 160, "secp160k1": 160, "secp160r2": 160, "secp192k1": 192, "secp224k1": 224,
    "prime192v2": 192, "prime192v3": 192, "prime239v1": 239, "prime239v2": 239, "prime239v3": 239,
    "brainpoolp160r1": 160, "brainpoolp192r1": 192, "brainpoolp224r1": 224, "brainpoolp320r1": 320,
    "sect163k1": 163, "sect163r1": 163, "sect163r2": 163, "sect193r1": 193, "sect193r2": 193,
    "sect233k1": 233, "sect233r1": 233, "sect239k1": 239, "sect283k1": 283, "sect283r1": 283,
    "sect409k1": 409, "sect409r1": 409, "sect571k1": 571, "sect571r1": 571,
}
BINARY_CURVES = {k for k in CURVES if k.startswith("sect")}
NON_NIST_CURVES = {"secp256k1", "brainpoolp256r1", "brainpoolp384r1", "brainpoolp512r1", "secp160r1", "secp160k1",
                   "secp160r2", "secp192k1", "secp224k1", "prime192v2", "prime192v3", "prime239v1", "prime239v2",
                   "prime239v3", "brainpoolp160r1", "brainpoolp192r1", "brainpoolp224r1", "brainpoolp320r1",
                   "sect163r1", "sect193r1", "sect193r2", "sect239k1"}

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
    # RFC 8734 TLS 1.3 brainpool groups (non-NIST curves; classify() adds that note)
    "brainpoolp256r1tls13": ("ecdh", 256), "brainpoolp384r1tls13": ("ecdh", 384),
    "brainpoolp512r1tls13": ("ecdh", 512),
    # RFC 7027 TLS 1.2 brainpool groups; OpenSSL also names the TLS 1.3 key exchange this way on its Temp Key line
    "brainpoolp256r1": ("ecdh", 256), "brainpoolp384r1": ("ecdh", 384), "brainpoolp512r1": ("ecdh", 512),
    # RFC 8422 / IANA TLS supported groups 1-22, deprecated legacy curves (1.0.6; before, a bare name was unknown
    # or an EC public key): key exchange when named as a TLS group; under 224 bits Critical
    **{n: ("ecdh", CURVES[n]) for n in ("sect163k1", "sect163r1", "sect163r2", "sect193r1", "sect193r2",
                                        "sect233k1", "sect233r1", "sect239k1", "sect283k1", "sect283r1",
                                        "sect409k1", "sect409r1", "sect571k1", "sect571r1", "secp160k1",
                                        "secp160r1", "secp160r2", "secp192k1", "secp192r1", "secp224k1",
                                        "secp224r1", "secp256k1")},
}

# Classical halves of an ML-KEM hybrid name (compact spelling, longest first)
_HYBRID_CLASSICAL = (("brainpoolp256r1", "bp256"), ("brainpoolp384r1", "bp384"), ("brainpoolp512r1", "bp512"),
                     ("curve25519", "x25519"), ("x25519", "x25519"), ("curve448", "x448"), ("x448", "x448"),
                     ("secp256r1", "p256"), ("prime256v1", "p256"), ("nistp256", "p256"), ("p256", "p256"),
                     ("secp384r1", "p384"), ("nistp384", "p384"), ("p384", "p384"),
                     ("secp521r1", "p521"), ("nistp521", "p521"), ("p521", "p521"),
                     ("ffdhe", "dh"), ("ecdh", "ecdh"), ("rsa", "rsa"))

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
        b = b if b is not None else bits  # group-exchange: the size is the one observed, not fixed by the name
        comps = [(cid, b, raw)]
        if extra:
            comps.append((extra, None, raw + " (hash)"))
        return comps, b
    if sc in SSH_HOSTKEY:
        cid, b, extra = SSH_HOSTKEY[sc]
        b = b if b is not None else bits  # e.g. an RSA (certificate) host key: its observed size counts
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

    # 3a. Multitree hash-based signatures in any spelling (XMSS-MT-SHA2_20/2_256, XMSS^MT signature,
    # id-alg-hss-lms-hashsig, LMS/HSS). Checked before the single-tree forms so a separator or suffix cannot turn
    # them into LMS / XMSS (which CNSA 2.0 approves and they are not).
    if re.search(r"(?<![a-z0-9])xmss[-_ ^]?mt(?![a-z])", low):
        return [("xmssmt", None, raw)], None
    if re.search(r"(?<![a-z0-9])hss(?![a-z0-9])", low) and (low.startswith("hss") or "lms" in low):
        return [("hss", None, raw)], None

    # 3b. LMS / HSS / LM-OTS parameter-set names (RFC 8554, SP 800-208: LMS_SHA256_M32_H10, lms-sha256-m24-h20,
    # LMOTS_SHAKE_N32_W8). Before 1.0.6 the hash token won and they read as SHA-256 (hash lane).
    if re.match(r"^(?:hss[-_ ]?)?(?:lms|lmots|lm-ots|hss)[-_ ]?(?:sha-?256|shake(?:256)?)(?:[-_/ ]|$)", low):
        return [("hss" if low.startswith("hss") else "lms", None, raw)], None
    # XMSS / XMSS^MT parameter-set names (RFC 8391, SP 800-208: XMSS-SHA2_10_256, XMSSMT-SHA2_20/2_256)
    if re.match(r"^xmss(?:mt|\^mt)?[-_ ]?(?:sha-?2|shake)", low):
        return [("xmssmt" if re.match(r"^xmss(?:mt|\^mt)", low) else "xmss", None, raw)], None

    # 4. Explicit PQC parameter sets inside longer names. The parameter set must end there: "mlkem10240" is not
    # ML-KEM-1024. A name marked as the 2023 initial public draft ("-ipd") is that draft, not the standard.
    ipd = bool(re.search(r"(?<![a-z])ipd(?![a-z])", low)) or c.endswith("ipd")
    m = re.search(r"mlkem(512|768|1024)(?![0-9])", c)
    if m:
        if ipd:
            return [("ml-kem-ipd", None, raw)], None
        # A classical half makes it a hybrid, judged as one: quantum-resistant through ML-KEM (the classical half
        # never makes it quantum-vulnerable), and compliant only as far as the pairing is (1.0.4; before, any
        # pairing read as pure ML-KEM, e.g. X25519MLKEM1024 as CNSA 2.0 compliant).
        rest = c[:m.start()] + c[m.end():]
        half = next((h for name, h in _HYBRID_CLASSICAL if name in rest), None)
        if half is None:
            return [("ml-kem-" + m.group(1), None, raw)], None
        known = {("x25519", "768"): "x25519mlkem768", ("p256", "768"): "secp256r1mlkem768",
                 ("p384", "1024"): "secp384r1mlkem1024", ("x448", "1024"): "x448mlkem1024"}
        return [(known.get((half, m.group(1)), "hybrid-ml-kem-" + m.group(1)), None, raw)], None
    m = re.search(r"mldsa(44|65|87)(?![0-9])", c)
    if m:
        if ipd:
            return [("ml-dsa-ipd", None, raw)], None
        # A composite (ML-DSA with a classical signature) is judged as one, like the ML-KEM hybrids (1.0.4; before,
        # the classical half was dropped). HashML-DSA ("...-with-SHA512") is ML-DSA.
        rest = c[:m.start()] + c[m.end():]
        # A composite with a SHA-1 or MD5 hash is not a combination the draft defines: reported for review, never
        # judged by its ML-DSA half (round-2 review). "rsa" must start a word in the name as written, so a word
        # that merely contains it ("universal") is not an RSA half.
        if re.search(r"sha1(?![0-9])|md5", rest):
            return [], bits
        rsa = re.search(r"(?<![a-z])rsa[-_ ]?(\d{4})?", low)
        ec = re.search(r"ecdsa|ed25519|ed448|p256|p384|p521|secp\d+r1|nistp\d+|brainpool", rest)
        if not (rsa or ec):
            return [("ml-dsa-" + m.group(1), None, raw)], None
        p384 = re.search(r"ecdsa.*(p384|secp384r1|nistp384)|(p384|secp384r1|nistp384).*ecdsa", rest) \
            and "brainpool" not in rest
        cnsa_half = p384 or (rsa and not ec and rsa.group(1) and int(rsa.group(1)) >= 3072)
        if m.group(1) == "87" and cnsa_half:
            return [("composite-ml-dsa-87-cnsa", None, raw)], None
        return [("composite-ml-dsa-" + m.group(1), None, raw)], None
    # SLH-DSA is FIPS 205's simple SHA2 and SHAKE parameter sets only (FIPS 205 Section 11, Appendix A), pure or
    # pre-hash (HashSLH-DSA, Section 10.2.2) with an approved hash. Any prefix is allowed (id-alg-, CKM_, OpenSSL).
    # SPHINCS+ (the submission, including Haraka) is not SLH-DSA; any other suffix (e.g. "-v2", "-md5") is not
    # recognized and is reported for review (1.0.4).
    if "sphincs" in c:
        return [("sphincs+", None, raw)], None
    sm = re.search(r"(?<![a-z0-9])slh[-_ ]?dsa", low)
    i = (len(_compact(low[:sm.start()])) if sm else
         (c.index("slhdsa") if re.match(r"^(?:id|idalg|idhash|hash)?slhdsa", c) else -1))
    if i >= 0:
        rest = c[i + 6:]
        if "haraka" in rest:
            return [("sphincs+", None, raw)], None
        if ipd:
            return [("slh-dsa-ipd", None, raw)], None
        p = re.fullmatch(r"(?:sha2|shake)?(?:(128|192|256)[sf]?)?(.*)", rest)
        tail = p.group(2)
        prehash = r"(?:with)?(?:sha224|sha256|sha384|sha512|sha512224|sha512256|sha3224|sha3256|sha3384|sha3512|" \
                  r"shake128|shake256)"
        if tail in ("", "pure", "prehash") or re.fullmatch(prehash, tail):
            return [("slh-dsa-" + p.group(1) if p.group(1) else "slh-dsa", None, raw)], None
        return [], bits
    # Pre-standard Kyber and Dilithium, alone or in hybrids, are not ML-KEM or ML-DSA (1.0.4)
    if "kyber" in c:
        return [("x25519kyber768draft00" if "x25519" in c else "kyber", None, raw)], None
    if "dilithium" in c:
        return [("dilithium", None, raw)], None
    # FN-DSA (FIPS 206 draft) and Falcon, in any variant (padded, pre-hash, hybrid): never the classical DSA its name
    # contains (1.0.4; before, FN-DSA-512 read as DSA, Critical)
    if "fndsa" in c or "falcon" in c:
        return [("fn-dsa", None, raw)], None
    # Nothing that names a post-quantum family may fall through to a classical token below ("dsa", "rsa", a curve)
    if any(k in c for k in ("slh", "mldsa", "mlkem")):
        return [], bits

    # 5. TLS / OpenSSL cipher suites and composite names -> components
    comps = []
    is_suite = c.startswith("tls") and ("with" in toks or len(toks) >= 4) or \
        any(t in toks for t in ("ecdhe", "dhe", "edh")) and any(t.startswith("aes") or t in ("chacha20", "3des", "des", "rc4") for t in toks)
    # OpenSSL TLS 1.2 suite names carry no key-exchange token when the key exchange is RSA key
    # transport (AES256-SHA = TLS_RSA_WITH_AES_256_CBC_SHA). No forward secrecy: recorded traffic is
    # decryptable by whoever later recovers the server's RSA key, classically or with a quantum computer.
    static_rsa = (not c.startswith("tls") and len(toks) >= 2
                  and re.match(r"^(aes(128|256)?|camellia(128|256)?|aria(128|256)|des|rc4|idea|seed|null)$", toks[0])
                  and toks[-1] in ("sha", "sha256", "sha384", "md5")
                  and not set(toks) & {"psk", "srp", "kx", "ecdh", "dh", "anon", "adh", "aecdh"})
    # Anonymous (ADH, AECDH: no server authentication) and NULL-encryption suites, in OpenSSL or IANA spelling
    unprotected = len(toks) >= 2 and bool(set(toks) & {"adh", "aecdh", "anon", "null"}) and (
        toks[-1] in ("sha", "sha256", "sha384", "md5") or c.startswith("tls"))
    # PSK and SRP suites (PSK-AES256-CBC-SHA, SRP-RSA-AES-256-CBC-SHA): judged by every component, not by their
    # cipher alone (1.0.4; before, the cipher was the whole verdict and the MAC and key exchange were dropped).
    psk_srp = bool(set(toks) & {"psk", "srp"}) and any(
        re.match(r"^(aes|camellia|aria|chacha20|3des|des|rc4|null|cbc3)", t) for t in toks)
    is_suite = is_suite or bool(static_rsa) or unprotected or psk_srp
    if is_suite:
        tok_set = set(toks)
        if tok_set & {"null", "anon", "export", "exp", "adh", "aecdh"}:
            comps.append(("null-cipher", None, raw))
        if "ecdhe" in tok_set or "ecdh" in tok_set:
            comps.append(("ecdh", None, raw + " (key exchange)"))
        elif tok_set & {"dhe", "edh", "dh"}:
            comps.append(("dh", None, raw + " (key exchange)"))
        elif "srp" in tok_set:
            comps.append(("srp", None, raw + " (key exchange)"))
        elif ("rsa" in tok_set and "with" in tok_set and toks[1] == "rsa") or static_rsa or (
                "psk" in tok_set and toks[0] == "rsa"):
            comps.append(("rsa", None, raw + " (RSA key transport, no forward secrecy)"))
        if "rsa" in tok_set and ("ecdhe" in tok_set or "dhe" in tok_set or "edh" in tok_set or "srp" in tok_set):
            comps.append(("rsa", None, raw + " (authentication)"))
        if "ecdsa" in tok_set:
            comps.append(("ecdsa", None, raw + " (authentication)"))
        aes = _aes(toks, c)
        if aes:
            comps.append((aes, None, raw + " (cipher)"))
        if "chacha20" in tok_set:
            comps.append(("chacha20", None, raw + " (cipher)"))
        if tok_set & {"3des", "des3", "cbc3", "ede3"} or ("3des" in c):
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
        if h is None and "sha" in tok_set:
            h = "sha-1"  # TLS 1.2 suite suffix "SHA" means HMAC-SHA-1
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

    # 6b. Signature names that pair a key type with SHA-1 or MD5 without "with" (RSA-SHA1, rsa_pkcs1_sha1,
    # ecdsa_sha1, RSA-MD5): the hash makes the signature broken, as sha1WithRSAEncryption already is (1.0.4).
    tok_set = set(toks)
    sig = "ecdsa" if "ecdsa" in tok_set else "rsa" if tok_set & {"rsa", "rsassa"} else "dsa" if "dsa" in tok_set \
        else None
    h = _hash_in(toks, c)
    if sig and h in ("sha-1", "md5") and not tok_set & {"oaep", "hmac", "kem"}:
        return [(sig, bits, raw), (h, None, raw + " (signature hash)")], bits

    # 7. Token-bounded family patterns
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
    # Cipher names with the key size fused on ("camellia256", "aria128-gcm")
    for t in toks:
        m = re.match(r"^(camellia|aria)(128|192|256)$", t)
        if m:
            return [(m.group(1), None, raw)], None
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


_RSA_SIG = re.compile(r"withrsa|rsassa|rsapss|^rsasha2|^sshrsa|^rsasha1")


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
    # An RSA name that denotes a signature (sha256WithRSAEncryption, RSASSA-PSS, rsa-sha2-256, ssh-rsa) is a
    # signature, migrated to ML-DSA/SLH-DSA, not public-key encryption.
    if cid == "rsa" and _RSA_SIG.search(_compact(label or "")):
        v.update(primitive="signature", crypto_functions=["sign", "verify"], lane="signature",
                 note="Quantum-vulnerable RSA signature.")
    # Key-size-dependent: below 112-bit security the algorithm is disallowed today (SP 800-131A)
    if kind == "qv" and strength is not None and strength < 112:
        kind = "broken"
        v["note"] = (v["note"] + f" {bits}-bit key is below 112-bit security (SP 800-57) and disallowed by "
                     "SP 800-131A: replace now.")
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
        sig = v["primitive"] == "signature" or cid in ("ed25519", "ed448", "eddsa")
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
        if "key transport" in (label or ""):
            v["primitive"], v["lane"] = "key-agree", "key-establishment"
            v["note"] = ("RSA key transport (static-RSA TLS suite): no forward secrecy, so recorded sessions "
                         "are exposed to harvest-now-decrypt-later.")
            t = ("Disable static-RSA suites; TLS 1.3 with " +
                 ("ML-KEM-1024 key establishment per CNSA 2.0" if profile == "nss"
                  else "hybrid ML-KEM key exchange (e.g. X25519MLKEM768); deprecated after 2030, disallowed after 2035 (IR 8547)"))
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


# Placeholder names the capture stage writes for something it observed but could not read.
PLACEHOLDER_LANES = {"unparsed-kex-group": "key-establishment", "unparsed-public-key-algorithm": "public-key"}

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
        # A name the scan wrote because it could not read the real one still sits in a known lane, so a check of
        # that lane counts it (1.0.4; before, its finding had no lane and a lane-scoped check skipped it).
        lane = PLACEHOLDER_LANES.get((name or "").strip())
        if lane:
            v["lane"] = lane
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
        if v["standard_status"] == "nist":
            v["standard_status"] = "non-nist"
    if curve in BINARY_CURVES:
        v["note"] += f" {curve} is a binary-field curve; NIST SP 800-186 deprecates these."
        v["cite"] = sorted(set(v.get("cite") or []) | {"SP800-186"})
    # A TLS/SSL cipher suite or an OpenSSH transport cipher protects data in transit: SC-8, not SC-28 (data at
    # rest), which the bare cipher carries (1.0.5; before, TLS_AES_256_GCM_SHA384 cited SC-28).
    if _is_transport_name(name, len(verdicts)) and "SC-28" in v["controls"]:
        v["controls"] = sorted((set(v["controls"]) - {"SC-28"}) | {"SC-8"})
    v["algorithm"] = name
    v["profile"] = profile
    v["rule_id"] = f"{RULESET_VERSION}:{v['canonical']}"
    v.pop("label", None)
    return v


def _is_transport_name(name, n_components):
    """A protocol cipher-suite name: TLS_/SSL_ suites, OpenSSL suite names (several components, such as
    ECDHE-RSA-AES256-GCM-SHA384), and OpenSSH ciphers named @openssh.com."""
    n = (name or "").strip()
    return n.upper().startswith(("TLS_", "SSL_")) or n.lower().endswith("@openssh.com") or n_components > 1


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


def name_with_parameter_set(name, parameter_set):
    """The name to judge for a CycloneDX algorithm whose name has no parameter set but whose
    algorithmProperties.parameterSetIdentifier does (ML-KEM + 1024 is ML-KEM-1024). Joined only when the ruleset
    recognises the joined name as something more specific than the bare one: for RSA and EC keys the field holds
    the key size, and rsaEncryption + 2048 stays rsaEncryption (the size is passed as bits instead). 1.0.6."""
    name = (name or "").strip()
    ps = str(parameter_set or "").strip()
    if not ps or re.search(r"\d", name) or not re.fullmatch(r"[0-9A-Za-z]{1,8}", ps):
        return name
    joined = f"{name}-{ps}"
    got = classify(joined).get("canonical")
    return joined if got and got != classify(name).get("canonical") else name
