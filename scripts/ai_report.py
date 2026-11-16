#!/usr/bin/env python3
"""FEDLIN PQC Toolkit: AI-BOM report stage (Phase 2).

The AI-governance analogue of report.py: turns a CycloneDX 1.6 AI-BOM (as produced by
ai_detector.py) into the deliverable a CAIO / AI-governance owner reads and funds:

  1. an AI-GOVERNANCE SCORECARD: a governance-readiness score, asset inventory, and
     high-risk exposure counts;
  2. a PRIORITIZED GOVERNANCE ROADMAP: assets sequenced by risk against the AI-compliance
     clock (EU AI Act Art. 11 / Annex IV technical documentation, effective 2 Aug 2026;
     NIST AI RMF; ISO/IEC 42001), each with its framework references and the sector crosswalk.

Deterministic: reads only the `ai:*` verdicts the detector stamped. No AI at report time.

Verdicts are indicative and should be confirmed by an analyst before anyone relies on them.

Usage:  python3 ai_report.py --ai-bom out/ai-bom.json --out out/ai-bom.report.md
"""
import argparse
import json
import sys

import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling modules, also under python -I
import crosswalk


# governance roadmap waves, anchored to the AI-compliance clock
WAVES = [
    ("Critical", "Wave 0: Immediate",
     "Ungoverned or unsafe AI assets (e.g. code-executing model formats without verified provenance). "
     "Remediate now, independent of the regulatory timeline."),
    ("High", "Wave 1: Before 2 Aug 2026 (EU AI Act Art. 11 / Annex IV)",
     "Missing technical documentation, general-purpose/foundation-model duties, or absent model cards. "
     "Close before the EU AI Act technical-documentation obligation takes effect."),
    ("Medium", "Wave 2: Provenance & lifecycle governance",
     "Unverified data/model provenance, licensing gaps, and training-pipeline change-control. "
     "Establish the MAP/MANAGE evidence base."),
    ("Low", "Maintain: documented & licensed",
     "Assets with model cards, licenses, and non-executing formats. Maintain the evidence and monitor drift."),
    ("Review", "Analyst review: unclassified assets",
     "Assets the ruleset did not classify. An analyst confirms the verdict before delivery."),
]
PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4, "Review": 5}


def load(path):
    with open(path) as f:
        return json.load(f)


def props(comp):
    return {p["name"]: p["value"] for p in comp.get("properties", [])}


def meta_props(bom):
    return {p["name"]: p["value"] for p in bom.get("metadata", {}).get("properties", [])}


def ai_assets(bom):
    out = []
    for c in bom.get("components", []):
        p = props(c)
        if "ai:assetType" not in p:
            continue
        out.append({
            "name": c.get("name", "?"),
            "kind": p.get("ai:assetType", "?"),
            "priority": p.get("ai:priority", "Review"),
            "risk": p.get("ai:risk", "Review"),
            "controls": [x for x in p.get("ai:controls", "").split(",") if x],
            "ai_rmf": [x for x in p.get("ai:ai_rmf", "").split(" | ") if x],
            "iso42001": [x for x in p.get("ai:iso42001", "").split(" | ") if x],
            "eu_ai_act": [x for x in p.get("ai:eu_ai_act", "").split(" | ") if x],
            "notes": [x for x in p.get("ai:notes", "").split(" | ") if x],
            "evidence": p.get("fedlin:evidence", ""),
            "format": p.get("ai:format", ""),
            "framework": p.get("ai:framework", ""),
            "crosswalk": next((v for k, v in p.items() if k.startswith("crosswalk:")), None),
            "regime": next((k.split(":", 1)[1] for k in p if k.startswith("crosswalk:")), None),
        })
    return out


def grade(score):
    if score is None:
        return "N/A", "no classified AI assets found"
    if score >= 90:
        return "A: Well-governed", "the AI estate is largely documented and low-risk"
    if score >= 70:
        return "B: On track", "a minority of AI assets carry material governance risk"
    if score >= 40:
        return "C: Partial", "roughly half the AI estate carries material governance risk"
    if score >= 15:
        return "D: At risk", "most AI assets carry material governance risk"
    return "F: Ungoverned", "the AI estate is almost entirely undocumented / high-risk"


def score_summary(assets):
    scored = [a for a in assets if a["priority"] != "Review"]
    high = [a for a in scored if a["priority"] in ("Critical", "High")]
    score = round(100 * (len(scored) - len(high)) / len(scored)) if scored else None
    return {"score": score, "scored": scored, "high": high}


def build_ai_report(bom, self_serve=False, brand="FEDLIN"):
    mp = meta_props(bom)
    sysname = bom.get("metadata", {}).get("component", {}).get("name", "ai-system")
    ts = bom.get("metadata", {}).get("timestamp", "")
    assets = ai_assets(bom)
    s = score_summary(assets)
    score, high = s["score"], s["high"]
    g, gnote = grade(score)
    regime = mp.get("fedlin:regime") or (assets[0]["regime"] if assets and assets[0]["regime"] else None)
    frameworks = mp.get("fedlin:frameworks", "")
    kinds = {"model": 0, "dataset": 0, "pipeline": 0}
    for a in assets:
        kinds[a["kind"]] = kinds.get(a["kind"], 0) + 1

    L = []
    if self_serve:
        L.append(f"# AI Governance: Automated Self-Serve Scan: {sysname}")
        L.append("")
        L.append("> **WARNING: AUTOMATED SCAN, NOT AN ASSESSMENT.** A deterministic ruleset over discoverable AI "
                 "assets (model/dataset/pipeline files + sidecar metadata). It does not replace an "
                 "assessment: no analyst verification, no impact assessment, no owner assignment, and no "
                 "runtime/model-registry capture. Every finding is indicative.")
        L.append("")
    else:
        L.append(f"# AI Governance Readiness Report: {sysname}")
        L.append("")
    L.append(f"*Generated by fedlin-pqc-toolkit AI-BOM report stage from a CycloneDX 1.6 AI-BOM (ML-BOM). "
             f"Timestamp: {ts or 'n/a'}.*")
    L.append("")

    if not self_serve:
        L.append("## Bottom line")
        L.append("")
        bits = [f"**{score if score is not None else 'N/A'}"
                f"{'/100' if score is not None else ''} ({g})** on AI-governance readiness"]
        if s["scored"]:
            bits.append(f"{len(high)} of {len(s['scored'])} classified AI assets carry material (High/Critical) risk")
        L.append(f"**{sysname}** scores " + "; ".join(bits) + ".")
        L.append("")
        L.append("This AI-BOM is the machine-readable inventory the EU AI Act Art. 11 / Annex IV technical-"
                 "documentation duty (effective 2 Aug 2026), NIST AI RMF, and ISO/IEC 42001 all presuppose. "
                 "The roadmap below sequences the governance work against that clock.")
        L.append("")

    # ---- scorecard ----
    L.append("## AI-governance scorecard")
    L.append("")
    L.append(f"**AI-governance score: {score if score is not None else 'N/A'}"
             f"{'/100' if score is not None else ''}: grade {g}.** {gnote.capitalize()}.")
    L.append("")
    L.append("| Measure | Value |")
    L.append("|---|---|")
    L.append(f"| System | {sysname} |")
    L.append(f"| Models | {kinds['model']} |")
    L.append(f"| Datasets | {kinds['dataset']} |")
    L.append(f"| Pipelines | {kinds['pipeline']} |")
    L.append(f"| Classified AI assets | {len(s['scored'])} ({len(high)} High/Critical risk) |")
    review = [a for a in assets if a["priority"] == "Review"]
    if review:
        L.append(f"| Awaiting analyst review | {len(review)} |")
    if frameworks:
        L.append(f"| Frameworks detected | {frameworks} |")
    if regime:
        L.append(f"| Compliance dialect | {regime} (crosswalked from NIST 800-53) |")
    L.append("")
    L.append("*Score = share of classified AI assets that do NOT carry High/Critical governance risk. "
             "Assets awaiting analyst review are excluded from the denominator.*")
    L.append("")

    # ---- top exposures ----
    L.append("## Top AI-governance exposures")
    L.append("")
    top = sorted(high, key=lambda a: (PRIORITY_ORDER.get(a["priority"], 9), a["name"]))
    if top:
        for a in top[:8]:
            note = a["notes"][0] if a["notes"] else ""
            L.append(f"- **{a['name']}** ({a['kind']}, {a['priority']}): {note}")
        L.append("")
    else:
        L.append("No High/Critical AI-governance exposures detected among classified assets.")
        L.append("")

    if self_serve:
        L.append("### Not included in this report")
        L.append("")
        L.append("- **Engineered governance sequencing** against the EU AI Act / NIST AI RMF / ISO 42001 timeline.")
        L.append("- **AI impact assessment** and use-context risk classification.")
        L.append("- **Analyst verification** of every finding, and **owner assignments**.")
        L.append("- **Model-registry / runtime capture** (SageMaker / Vertex / MLflow) beyond static files.")
        L.append("- **Per-sector control crosswalk** and Annex IV technical-documentation drafting.")
        L.append("")
    else:
        # ---- governance roadmap ----
        L.append("## Prioritized governance roadmap")
        L.append("")
        L.append("Sequenced against the AI-compliance clock. Each item cites the NIST AI RMF subcategory, the "
                 "ISO/IEC 42001 control, and the EU AI Act anchor it is evidence for"
                 + (f", with the {regime} crosswalk." if regime else "."))
        L.append("")
        for pr, title, blurb in WAVES:
            items = [a for a in assets if a["priority"] == pr]
            if not items:
                continue
            L.append(f"### {title}")
            L.append("")
            L.append(f"*{blurb}*")
            L.append("")
            L.append("| Asset | Kind | NIST AI RMF | ISO 42001 | EU AI Act |" + (f" {regime} |" if regime else ""))
            L.append("|---|---|---|---|---|" + ("---|" if regime else ""))
            for a in sorted(items, key=lambda x: x["name"]):
                rmf = "; ".join(a["ai_rmf"]) or "-"
                iso = "; ".join(a["iso42001"]) or "-"
                eu = "; ".join(a["eu_ai_act"]) or "-"
                row = f"| {a['name']} | {a['kind']} | {rmf} | {iso} | {eu} |"
                if regime:
                    row += f" {(a['crosswalk'] or '-').replace(' | ', '; ')} |"
                L.append(row)
            L.append("")

    # ---- framework alignment ----
    L.append("## Framework alignment")
    L.append("")
    L.append("- **EU AI Act: Art. 11 & Annex IV** (technical documentation), effective **2 Aug 2026** "
             "(possibly extended under the Digital Omnibus): this AI-BOM is the machine-readable inventory "
             "that documentation duty presupposes.")
    L.append("- **NIST AI RMF 1.0**: GOVERN / MAP / MEASURE / MANAGE; each finding cites its subcategory.")
    L.append("- **ISO/IEC 42001**: the AI management-system standard; each finding cites its Annex A control. "
             "*This report is not an ISO/IEC 42001 certification or audit.*")
    L.append("- **CycloneDX 1.6 ML-BOM / SPDX 3.0 AI Profile**: the standards this artifact conforms to.")
    L.append("")
    L.append("*This is AI inventory and governance-planning evidence: not an authorization and not a conformity "
             "assessment. Verdicts are indicative; confirm them before relying on them.*")
    L.append("")

    summary = {
        "system": sysname,
        "governance_score": score,
        "grade": g,
        "models": kinds["model"],
        "datasets": kinds["dataset"],
        "pipelines": kinds["pipeline"],
        "classified": len(s["scored"]),
        "high_risk": len(high),
        "awaiting_review": len(review),
        "regime": regime,
        "self_serve": self_serve,
    }
    md = "\n".join(L)
    if brand and brand != "FEDLIN":
        try:
            import whitelabel  # FEDLIN engagement kit
        except ImportError:
            raise RuntimeError("white-label output (--brand) is part of the FEDLIN engagement kit")
        md = whitelabel.apply(md, brand)
    return md, summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ai-bom", required=True, help="input CycloneDX 1.6 AI-BOM")
    ap.add_argument("--out", default="", help="output Markdown report")
    ap.add_argument("--json", default="", help="optional machine-readable summary JSON")
    ap.add_argument("--self-serve", action="store_true", help="gated automated-scan variant")
    ap.add_argument("--brand", default="FEDLIN", help=argparse.SUPPRESS)
    args = ap.parse_args()

    bom = load(args.ai_bom)
    md, summary = build_ai_report(bom, self_serve=args.self_serve, brand=args.brand)
    out = args.out or (args.ai_bom.rsplit(".", 1)[0] + ".report.md")
    with open(out, "w") as f:
        f.write(md + "\n")
    print(f"[ok] AI report: {out}: governance score {summary['governance_score']} ({summary['grade']}), "
          f"{summary['high_risk']} high-risk / {summary['classified']} classified")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"[ok] summary: {args.json}")


if __name__ == "__main__":
    main()
