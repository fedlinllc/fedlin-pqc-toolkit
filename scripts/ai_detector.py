#!/usr/bin/env python3
"""FEDLIN PQC Toolkit — AI-BOM detector & builder (Phase 2, on the crypto rails).

The AI analogue of tier2_pipeline.py's CBOM builder: scans a directory tree for AI assets
(models / datasets / pipelines), extracts governance signals, classifies each with the
deterministic ai_governance_ruleset, and emits a schema-valid CycloneDX 1.6 ML-BOM whose
components carry `ai:*` verdict properties — exactly analogous to the crypto CBOM's `cnsa2:*`.

Same rails as the crypto side: CycloneDX 1.6 serialization, the universal-overlay pattern,
crosswalk-to-regime, and (via ai_report) a scorecard + governance roadmap + delta.

DETERMINISTIC (Mode C): a fixed rule set over extracted signals — no AI at evaluation time.
Reads file metadata, extensions, and sidecar docs only; it does not load or execute any model.

Verdicts are indicative and should be confirmed by an analyst before anyone relies on them.

Usage:  python3 ai_detector.py --dir ./project --out out/ai-bom.json --report --regime FISMA
"""
import argparse
import datetime
import json
import os
import re
import sys
import uuid

import ai_governance_ruleset as ai
import crosswalk


MODEL_EXT = {"onnx", "safetensors", "pt", "pth", "pb", "h5", "hdf5", "tflite", "gguf", "ggml",
             "pkl", "pickle", "joblib", "mlmodel", "pmml", "caffemodel", "ckpt"}
DATASET_EXT = {"csv", "parquet", "tfrecord", "npy", "npz", "arrow", "feather"}
DATASET_SIDE = {"dataset_info.json", "dataset_infos.json"}
PIPELINE_FILES = {"mlproject", "dvc.yaml", "params.yaml", "pipeline.yaml", "pipeline.yml",
                  "kubeflow.yaml", "training_pipeline.py", "train.py", "training.py"}
FRAMEWORK_DEP = {
    "torch": "pytorch", "pytorch": "pytorch", "tensorflow": "tensorflow", "keras": "keras",
    "scikit-learn": "scikit-learn", "sklearn": "scikit-learn", "transformers": "transformers",
    "xgboost": "xgboost", "lightgbm": "lightgbm", "onnxruntime": "onnx", "jax": "jax",
    "diffusers": "diffusers", "sentence-transformers": "transformers",
}
CARD_HINTS = ("readme.md", "model_card.md", "modelcard.md", "model-card.md", "config.json",
              "model_index.json")
DATA_LICENSE_HINTS = ("license", "license.txt", "license.md", "licence", "copying")


def _ext(path):
    return os.path.splitext(path)[1].lower().lstrip(".")


def _dir_has(dirpath, names):
    try:
        present = {f.lower() for f in os.listdir(dirpath)}
    except OSError:
        return False
    return any(n in present for n in names)


def _license_in_dir(dirpath):
    try:
        for f in os.listdir(dirpath):
            fl = f.lower()
            if fl in DATA_LICENSE_HINTS or fl.startswith("license") or fl.startswith("licence"):
                return f
    except OSError:
        pass
    return None


def _framework_from_config(dirpath):
    """Read a HF-style config.json (non-executing) for model_type / framework signals."""
    cfg = os.path.join(dirpath, "config.json")
    if not os.path.exists(cfg):
        return None, None, None
    try:
        with open(cfg) as f:
            d = json.load(f)
    except (ValueError, OSError):
        return None, None, None
    model_type = d.get("model_type") or d.get("_class_name")
    fw = "transformers" if (model_type or d.get("architectures")) else None
    lic = d.get("license")
    return fw, model_type, lic


def _scan_requirements(root):
    """Framework capability signal from dependency manifests (analogous to LIB_CRYPTO)."""
    frameworks = set()
    for base in ("requirements.txt", "environment.yml", "environment.yaml", "pyproject.toml", "Pipfile"):
        p = os.path.join(root, base)
        if not os.path.exists(p):
            continue
        try:
            txt = open(p, errors="ignore").read().lower()
        except OSError:
            continue
        for dep, fw in FRAMEWORK_DEP.items():
            if re.search(r"(^|[^a-z])" + re.escape(dep) + r"([^a-z]|$)", txt):
                frameworks.add(fw)
    return sorted(frameworks)


def detect(root):
    """Walk the tree; return a list of AI asset dicts with governance signals extracted."""
    assets = []
    global_frameworks = _scan_requirements(root)
    seen_pipeline_dirs = set()
    for dirpath, _dirs, files in os.walk(root):
        # skip vcs / venv noise
        if any(seg in dirpath for seg in (os.sep + ".git", "site-packages", "node_modules", ".venv")):
            continue
        cfg_fw, cfg_type, cfg_lic = _framework_from_config(dirpath)
        has_card = _dir_has(dirpath, CARD_HINTS)
        dir_license = _license_in_dir(dirpath) or cfg_lic
        for fn in files:
            fl = fn.lower()
            ext = _ext(fn)
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            if ext in MODEL_EXT:
                fw = cfg_fw or (global_frameworks[0] if global_frameworks else None)
                assets.append({
                    "kind": "model", "name": cfg_type or fn, "fmt": ext, "path": rel,
                    "has_card": has_card, "license": dir_license, "framework": fw,
                    "signals": [s for s in (cfg_type, fw, fn) if s],
                })
            elif ext in DATASET_EXT or fl in DATASET_SIDE or ext == "dvc":
                assets.append({
                    "kind": "dataset", "name": fn, "fmt": ext, "path": rel,
                    "has_card": has_card, "license": dir_license, "framework": None,
                    "signals": [fn, rel],
                })
            elif fl in PIPELINE_FILES or ext == "ipynb":
                # one pipeline asset per directory — a dir with several pipeline files (e.g. train.py
                # AND dvc.yaml, or many notebooks) is a single training/MLOps pipeline, not many.
                key = (dirpath, "pipeline")
                if key in seen_pipeline_dirs:
                    continue
                seen_pipeline_dirs.add(key)
                assets.append({
                    "kind": "pipeline", "name": fn, "fmt": ext, "path": rel,
                    "has_card": has_card, "license": dir_license,
                    "framework": ",".join(global_frameworks) or None, "signals": [fn] + global_frameworks,
                })
    return assets, global_frameworks


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-") or "asset"


CDX_TYPE = {"model": "machine-learning-model", "dataset": "data", "pipeline": "application"}


def build_ai_bom(assets, system_name, regime=None, frameworks=None):
    components = []
    for i, a in enumerate(assets):
        v = ai.classify(a)
        props = [
            {"name": "ai:assetType", "value": a["kind"]},
            {"name": "ai:priority", "value": v["priority"]},
            {"name": "ai:risk", "value": v["risk"]},
            {"name": "ai:controls", "value": ",".join(v["controls"])},
            {"name": "ai:ai_rmf", "value": " | ".join(v["ai_rmf"])},
            {"name": "ai:iso42001", "value": " | ".join(v["iso42001"])},
            {"name": "ai:eu_ai_act", "value": " | ".join(v["eu_ai_act"])},
            {"name": "ai:notes", "value": " | ".join(v["notes"])},
            {"name": "fedlin:evidence", "value": a["path"]},
        ]
        if a.get("fmt"):
            props.append({"name": "ai:format", "value": a["fmt"]})
        if a.get("framework"):
            props.append({"name": "ai:framework", "value": a["framework"]})
        if regime:
            refs = crosswalk.regime_refs(v["controls"], regime)
            if refs:
                props.append({"name": f"crosswalk:{regime}", "value": " | ".join(refs)})
        comp = {
            "type": CDX_TYPE.get(a["kind"], "application"),
            "bom-ref": f"ai/{a['kind']}/{i}-{slug(a['name'])}",
            "name": a["name"],
            "properties": props,
        }
        if a.get("fmt"):
            comp["version"] = a["fmt"]
        components.append(comp)

    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    meta_props = [{"name": "fedlin:bom_kind", "value": "ai-bom"}]
    if frameworks:
        meta_props.append({"name": "fedlin:frameworks", "value": ", ".join(frameworks)})
    if regime:
        meta_props.append({"name": "fedlin:regime", "value": regime})
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": ts,
            "component": {"type": "application", "name": system_name, "bom-ref": "ai-system"},
            "tools": {"components": [{"type": "application", "name": "fedlin-pqc-toolkit",
                                      "version": f"ai-detector 0.1 (ruleset {ai.RULESET_VERSION})",
                                      "publisher": "FEDLIN"}]},
            "properties": meta_props,
        },
        "components": components,
        "dependencies": [],
    }


def main():
    ap = argparse.ArgumentParser(description="AI-BOM detector — models/datasets/pipelines -> CycloneDX 1.6")
    ap.add_argument("--dir", required=True, help="project/model directory to scan")
    ap.add_argument("--out", default="out/ai-bom.json", help="output CycloneDX 1.6 AI-BOM")
    ap.add_argument("--name", default="ai-system", help="system name for the BOM metadata")
    ap.add_argument("--regime", default="", help="sector crosswalk: FISMA|CMMC|HIPAA|PCI-DSS|GLBA|NERC-CIP")
    ap.add_argument("--report", action="store_true", help="also emit the AI governance report (<out>.report.md)")
    ap.add_argument("--self-serve", action="store_true", help="gated automated-scan variant")
    ap.add_argument("--validate", action="store_true", help="validate the AI-BOM (needs --cyclonedx)")
    ap.add_argument("--cyclonedx", default="", help="path to cyclonedx-cli for --validate")
    args = ap.parse_args()

    if not os.path.isdir(args.dir):
        sys.stderr.write(f"[error] not a directory: {args.dir}\n")
        sys.exit(2)

    assets, frameworks = detect(args.dir)
    bom = build_ai_bom(assets, args.name, regime=args.regime or None, frameworks=frameworks)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(bom, f, indent=2)
    n = {"model": 0, "dataset": 0, "pipeline": 0}
    for a in assets:
        n[a["kind"]] = n.get(a["kind"], 0) + 1
    print(f"[ok] AI-BOM: {args.out} — {n['model']} model(s), {n['dataset']} dataset(s), "
          f"{n['pipeline']} pipeline(s); frameworks: {', '.join(frameworks) or 'none detected'}")

    if args.report:
        import ai_report
        rpt = args.out.rsplit(".", 1)[0] + ".report.md"
        summ = args.out.rsplit(".", 1)[0] + ".summary.json"
        md, summary = ai_report.build_ai_report(bom, self_serve=args.self_serve)
        with open(rpt, "w") as f:
            f.write(md + "\n")
        with open(summ, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"[ok] AI report: {rpt} — governance score {summary['governance_score']} "
              f"({summary['grade']}), {summary['high_risk']} high-risk asset(s)")

    if args.validate and args.cyclonedx:
        import subprocess
        r = subprocess.run([args.cyclonedx, "validate", "--input-file", args.out,
                            "--input-version", "v1_6", "--fail-on-errors"], capture_output=True, text=True)
        print(r.stdout.strip() or r.stderr.strip())
        sys.exit(r.returncode)


if __name__ == "__main__":
    main()
