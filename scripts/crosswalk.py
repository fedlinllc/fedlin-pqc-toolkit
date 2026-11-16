"""FEDLIN compliance crosswalk: v0.1.

Maps the NIST 800-53 SC-family controls the toolkit emits to each vertical's
regime, so the same CBOM speaks the buyer's dialect ("change the language, not the
engine"). 800-53 is the spine; every regime crosswalks to it.

STARTER MAPPINGS: analyst-verified per engagement. CMMC entries are the NIST
800-171 practices (CMMC L2 = 800-171). NERC CIP is objective-based, not crypto-
prescriptive, so there is no clean 1:1 crypto-control mapping; the NERC-CIP column
below was reviewed against CIP-002/005/011/012 (2026-07-09) and firmed up where the
standard's security objective is explicit (CIP-012 transmission, CIP-011 information
protection), but per-entity applicability still needs confirmation. Confirm exact
citations before client collateral.
"""

# 800-53 control -> { regime: reference }
CROSSWALK = {
    "CM-8": {
        "FISMA": "CM-8", "CMMC": "CM.L2-3.4.1 (800-171 3.4.1)",
        "HIPAA": "164.308(a)(1)(ii)(A) (asset/risk analysis)",
        "PCI-DSS": "Req 12.5.1 (asset inventory)",
        "GLBA": "16 CFR 314.4(c)(2) (inventory of data/systems)",
        "NERC-CIP": "CIP-002 (BES Cyber System categorization / identification)",
    },
    "SC-8": {
        "FISMA": "SC-8", "CMMC": "SC.L2-3.13.8 (800-171 3.13.8)",
        "HIPAA": "164.312(e)(1) (transmission security)",
        "PCI-DSS": "Req 4 (strong crypto in transit)",
        "GLBA": "16 CFR 314.4(c)(3) (encryption in transit)",
        "NERC-CIP": "CIP-012 (protect Real-time data transmitted between Control Centers)",
    },
    "SC-12": {
        "FISMA": "SC-12", "CMMC": "SC.L2-3.13.10 (800-171 3.13.10)",
        "HIPAA": "164.312(a)(2)(iv) (encryption/key mgmt)",
        "PCI-DSS": "Req 3.6/3.7 (key management)",
        "GLBA": "16 CFR 314.4(c) (safeguards)",
        "NERC-CIP": "CIP-011 (BES Cyber System Information protection) [approx: key mgmt not explicit in CIP]",
    },
    "SC-13": {
        "FISMA": "SC-13", "CMMC": "SC.L2-3.13.11 (800-171 3.13.11, FIPS crypto)",
        "HIPAA": "164.312(a)(2)(iv) / 164.312(e)(2)(ii) (encryption)",
        "PCI-DSS": "Req 3 & 4 (strong cryptography)",
        "GLBA": "16 CFR 314.4(c)(3) (encryption)",
        "NERC-CIP": "CIP-011 (BES Cyber System Information protection) [approx: CIP is not algorithm-prescriptive]",
    },
    "SC-17": {
        "FISMA": "SC-17", "CMMC": "SC.L2-3.13.15 (800-171 3.13.15, session authenticity)",
        "HIPAA": "164.312(d) (person/entity authentication)",
        "PCI-DSS": "Req 4.2 (trusted certificates)",
        "GLBA": "16 CFR 314.4(c) (safeguards)",
        "NERC-CIP": "CIP-005 R2 (encryption for Interactive Remote Access) [approx: cert/PKI has no direct CIP control]",
    },
    "SC-28": {
        "FISMA": "SC-28", "CMMC": "SC.L2-3.13.16 (800-171 3.13.16, data at rest)",
        "HIPAA": "164.312(a)(2)(iv) (encryption at rest)",
        "PCI-DSS": "Req 3 (protect stored data)",
        "GLBA": "16 CFR 314.4(c)(3) (encryption at rest)",
        "NERC-CIP": "CIP-011 (BES Cyber System Information protection in storage)",
    },
    # --- controls the AI-governance ruleset emits (best-effort sector crosswalk; analyst-verified) ---
    "RA-3": {
        "FISMA": "RA-3", "CMMC": "RA.L2-3.11.1 (800-171 3.11.1, risk assessment)",
        "HIPAA": "164.308(a)(1)(ii)(A) (risk analysis)",
        "PCI-DSS": "Req 12.3.1 (targeted risk analysis)",
        "GLBA": "16 CFR 314.4(b) (risk assessment)",
        "NERC-CIP": "CIP-002 (risk-based categorization)",
    },
    "SR-3": {
        "FISMA": "SR-3", "CMMC": "SR / SA family (800-171 3.14 supply-chain adj.)",
        "HIPAA": "164.308(b) (business associate / third-party)",
        "PCI-DSS": "Req 12.8 (third-party service providers)",
        "GLBA": "16 CFR 314.4(f) (oversee service providers)",
        "NERC-CIP": "CIP-013 (supply-chain risk management)",
    },
    "SR-4": {
        "FISMA": "SR-4", "CMMC": "SR family (provenance)",
        "HIPAA": "164.308(b) (third-party assurance)",
        "PCI-DSS": "Req 6.3.2 (inventory of bespoke/3rd-party software)",
        "GLBA": "16 CFR 314.4(f)",
        "NERC-CIP": "CIP-013 (vendor provenance)",
    },
    "SI-7": {
        "FISMA": "SI-7", "CMMC": "SI.L2-3.14.1 (800-171 3.14.1, integrity)",
        "HIPAA": "164.312(c)(1) (integrity controls)",
        "PCI-DSS": "Req 11.5 (change/integrity detection)",
        "GLBA": "16 CFR 314.4(c)(1)",
        "NERC-CIP": "CIP-010 (baseline / integrity monitoring)",
    },
    "PM-30": {
        "FISMA": "PM-30", "CMMC": "SR family (supply-chain risk strategy)",
        "HIPAA": "164.308(a)(1) (security management process)",
        "PCI-DSS": "Req 12.8 (TPSP management)",
        "GLBA": "16 CFR 314.4(f)",
        "NERC-CIP": "CIP-013",
    },
    "CM-3": {
        "FISMA": "CM-3", "CMMC": "CM.L2-3.4.3 (800-171 3.4.3, change control)",
        "HIPAA": "164.308(a)(8) (evaluation)",
        "PCI-DSS": "Req 6.5.1 (change control)",
        "GLBA": "16 CFR 314.4(c)",
        "NERC-CIP": "CIP-010 (configuration change management)",
    },
    "SA-3": {
        "FISMA": "SA-3", "CMMC": "SA family (SDLC)",
        "HIPAA": "164.308(a)(1) (security management)",
        "PCI-DSS": "Req 6.2 (secure SDLC)",
        "GLBA": "16 CFR 314.4",
        "NERC-CIP": "CIP-010",
    },
    "SA-4": {
        "FISMA": "SA-4", "CMMC": "SA family (acquisition)",
        "HIPAA": "164.308(b) (BA agreements)",
        "PCI-DSS": "Req 12.8.2 (TPSP agreements)",
        "GLBA": "16 CFR 314.4(f)",
        "NERC-CIP": "CIP-013",
    },
    "PT-2": {
        "FISMA": "PT-2 (authority to process PII)", "CMMC": "n/a (PII program is 800-53/privacy)",
        "HIPAA": "164.502 (permitted uses & disclosures)",
        "PCI-DSS": "n/a (PCI scope is CHD, not general PII)",
        "GLBA": "16 CFR 314.4(c)(1) (access controls on customer info)",
        "NERC-CIP": "n/a",
    },
}


# Note: AI-governance findings carry their NIST AI RMF / ISO 42001 / EU AI Act refs directly
# (ai_governance_ruleset stamps them per finding); their 800-53 controls crosswalk to sector
# regimes through regime_refs() below, the same as the crypto side. No separate AI table needed.

REGIMES = ["FISMA", "CMMC", "HIPAA", "PCI-DSS", "GLBA", "NERC-CIP"]


def regime_refs(controls, regime):
    """Map a list of 800-53 controls to the given regime's references (deduped, ordered)."""
    if not regime or regime not in REGIMES:
        return []
    out = []
    for c in controls:
        ref = CROSSWALK.get(c, {}).get(regime)
        if ref and ref not in out:
            out.append(ref)
    return out


CROSSWALK_VERSION = "0.2"
