"""FEDLIN AI-governance overlay ruleset: v0.1 (deterministic / Mode C).

The AI-BOM analogue of cnsa20_ruleset.py: maps a detected AI asset (model / dataset /
pipeline) and its evidence signals to a governance verdict: a risk tier, the NIST AI RMF
subcategories and ISO/IEC 42001 controls it is evidence for, the EU AI Act Annex IV
technical-documentation item it supports, and the NIST 800-53 controls it crosswalks to
(so the SAME crosswalk engine renders sector dialects).

Deterministic and auditable: no AI at evaluation time: a fixed rule set over signals the
detector already extracted. Verdicts are indicative and should be confirmed by an analyst
before anyone relies on them.

A rule fires on a predicate over the asset dict and contributes a finding. An asset's verdict
is the union of its findings' control refs, with priority = the highest-priority finding.
"""

RULESET_VERSION = "0.1"

# priority ordering shared with the crypto side so the report waves line up
_PRIO = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4, "Review": 5}

# Model file formats that deserialize arbitrary code on load (pickle-family): a supply-chain /
# integrity risk independent of model behaviour.
UNSAFE_FORMATS = {"pkl", "pickle", "joblib", "pt", "pth", "bin", "ckpt", "h5", "pb", "caffemodel"}
SAFE_FORMATS = {"safetensors", "onnx", "gguf", "tflite", "mlmodel", "pmml"}

# name/framework signals that a model is a foundation / general-purpose AI model (GPAI): these
# carry the heaviest EU AI Act documentation duties.
GPAI_SIGNALS = ["llm", "gpt", "bert", "llama", "mistral", "falcon", "t5", "roberta", "gemma",
                "phi-", "qwen", "stable-diffusion", "whisper", "transformer", "foundation"]

# dataset name signals of sensitive / regulated data (drives data-governance duties)
PII_SIGNALS = ["pii", "personal", "patient", "health", "phi", "ssn", "biometric", "face",
               "medical", "financial", "customer", "hr-", "payroll", "genom"]


def _finding(risk, note, ai_rmf, iso42001, eu_ai_act, controls):
    return {"risk": risk, "note": note, "ai_rmf": ai_rmf, "iso42001": iso42001,
            "eu_ai_act": eu_ai_act, "controls": controls}


def classify(asset):
    """asset: {kind, name, fmt, has_card, license, framework, signals[list]} -> verdict dict."""
    kind = asset.get("kind", "model")
    name = (asset.get("name") or "").lower()
    fmt = (asset.get("fmt") or "").lower().lstrip(".")
    has_card = bool(asset.get("has_card"))
    license_ = asset.get("license")
    framework = (asset.get("framework") or "").lower()
    sig = " ".join(asset.get("signals", [])).lower() + " " + name + " " + framework

    findings = []

    if kind == "model":
        # every model is an inventory obligation (AI RMF GOVERN / EU AI Act Annex IV(1))
        findings.append(_finding(
            "Low", "Model asset: inventory and general-description obligation.",
            ["GOVERN-1.1 (inventory)"], ["ISO 42001 A.4.2 (AI system inventory)"],
            ["Annex IV(1): general description of the AI system"], ["CM-8"]))

        if fmt in UNSAFE_FORMATS:
            findings.append(_finding(
                "Critical",
                f"Serialized in a code-executing format (.{fmt}); loading it can run arbitrary code: "
                "verify provenance and integrity before load.",
                ["MANAGE-2.1 (risk treatment)"], ["ISO 42001 A.6.2.6 (system operation & monitoring)"],
                ["Annex IV(2)(g): cybersecurity measures"], ["SI-7", "SR-4"]))
        elif fmt in SAFE_FORMATS:
            findings.append(_finding(
                "Low", f"safetensors / non-executing format (.{fmt}).",
                ["MEASURE-2.7 (security & resilience)"], ["ISO 42001 A.6.2.6"],
                ["Annex IV(2)(g): cybersecurity measures"], ["SI-7"]))

        if any(s in sig for s in GPAI_SIGNALS):
            findings.append(_finding(
                "High",
                "General-purpose / foundation model signal: heightened EU AI Act documentation and, "
                "if placed on the EU market, GPAI transparency duties.",
                ["MAP-1.1 (context)", "MEASURE-2.3 (performance)"],
                ["ISO 42001 A.6.2.2 (AI system requirements)"],
                ["Annex IV(2)(b): model design & training methodology", "Art. 53: GPAI obligations"],
                ["RA-3", "PM-30"]))

        if not has_card:
            findings.append(_finding(
                "High",
                "No model card / documentation found: the Annex IV technical documentation and AI RMF "
                "MAP/MEASURE evidence are absent.",
                ["MAP-2.3 (documentation)", "MEASURE-2.1 (evaluation)"],
                ["ISO 42001 A.6.2.8 (AI system documentation)"],
                ["Annex IV(2): detailed description", "Art. 11: technical documentation"],
                ["RA-3", "CM-8"]))

        if not license_:
            findings.append(_finding(
                "Medium",
                "No license / provenance metadata: IP and third-party-component risk unresolved.",
                ["MAP-4.1 (third-party risk)"], ["ISO 42001 A.10.2 (third-party & customer)"],
                ["Annex IV(2)(e): provenance of components"], ["SR-3", "SA-4"]))

    elif kind == "dataset":
        findings.append(_finding(
            "Low", "Dataset asset: data-governance and provenance obligation.",
            ["MAP-2.1 (data & input)"], ["ISO 42001 A.7.2 (data for AI systems)"],
            ["Annex IV(2)(d): data & data governance"], ["CM-8"]))
        if any(s in sig for s in PII_SIGNALS):
            findings.append(_finding(
                "High",
                "Sensitive/regulated-data signal in the dataset: privacy, data-governance and, for "
                "special-category data, DPIA/impact-assessment duties.",
                ["MEASURE-2.10 (privacy)", "MAP-1.6 (impacts)"],
                ["ISO 42001 A.7.4 (data quality)", "ISO 42001 A.5.4 (impact assessment)"],
                ["Annex IV(2)(d): data governance", "Art. 10: data & data governance"],
                ["RA-3", "PT-2"]))
        if not asset.get("license"):
            findings.append(_finding(
                "Medium", "No dataset license / source metadata: usage rights and provenance unverified.",
                ["MAP-4.1 (third-party risk)"], ["ISO 42001 A.7.3 (data acquisition)"],
                ["Annex IV(2)(d): data provenance"], ["SR-3"]))

    elif kind == "pipeline":
        findings.append(_finding(
            "Medium",
            "Training / MLOps pipeline: reproducibility, change-control and lifecycle-governance "
            "obligation (the record of HOW models are produced).",
            ["GOVERN-1.2 (accountability)", "MANAGE-2.2 (monitoring)"],
            ["ISO 42001 A.6.2.4 (AI system development)"],
            ["Annex IV(2)(c): development process & validation"], ["CM-3", "SA-3"]))

    return _summarize(asset, findings)


def _summarize(asset, findings):
    if not findings:
        return {"kind": asset.get("kind"), "name": asset.get("name"), "priority": "Review",
                "risk": "Review", "controls": [], "ai_rmf": [], "iso42001": [], "eu_ai_act": [],
                "notes": ["Unclassified AI asset: analyst review required."], "findings": []}
    # severity-first so notes[0] / the report's top-exposure line is the most serious reason
    findings = sorted(findings, key=lambda f: _PRIO.get(f["risk"], 9))
    priority = findings[0]["risk"]

    def _uniq(key):
        out = []
        for f in findings:
            for v in f[key]:
                if v not in out:
                    out.append(v)
        return out

    return {
        "kind": asset.get("kind"), "name": asset.get("name"),
        "priority": priority, "risk": priority,
        "controls": _uniq("controls"), "ai_rmf": _uniq("ai_rmf"),
        "iso42001": _uniq("iso42001"), "eu_ai_act": _uniq("eu_ai_act"),
        "notes": [f["note"] for f in findings], "findings": findings,
    }


def priority_rank(p):
    return _PRIO.get(p, 9)
