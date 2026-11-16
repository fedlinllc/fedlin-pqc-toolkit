#!/usr/bin/env python3
"""
merge-hw-cbom.py: FEDLIN PQC Toolkit

Merges hardware component JSON (output of collect-hardware-linux.py or
collect-hardware-windows.ps1) into an existing CycloneDX 1.6 CBOM.

Merge semantics: components are matched by bom-ref.
  - New bom-ref → appended to the components array.
  - Existing bom-ref → replaced in-place (re-running a collector updates the entry).
  - No bom-ref → always appended (unusual; warn the user).

Usage:
    # Single host
    python3 merge-hw-cbom.py --cbom agency-cbom.json --hw dc01-hw.json

    # Multiple hosts at once
    python3 merge-hw-cbom.py --cbom agency-cbom.json --hw dc01-hw.json --hw fileserver-hw.json

    # Write to a new file (default: overwrite --cbom in-place)
    python3 merge-hw-cbom.py --cbom agency-cbom.json --hw dc01-hw.json --out updated-cbom.json

    # Typical workflow
    python3 collect-hardware-linux.py --host dc01.example.gov > dc01-hw.json
    python3 merge-hw-cbom.py --cbom agency-cbom.json --hw dc01-hw.json
    python3 report.py --cbom agency-cbom.json --html agency-report.html
"""

import argparse
import json
import pathlib
import sys


def load_json(path):
    try:
        return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except Exception as e:
        print(f"error: cannot read {path}: {e}", file=sys.stderr)
        sys.exit(1)


def extract_components(data, source_path):
    """Accept either {"components": [...]} or a bare array."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "components" in data:
        return data["components"]
    print(f"warning: {source_path} has no 'components' key and is not an array: skipped",
          file=sys.stderr)
    return []


def merge(cbom, new_components):
    existing = cbom.setdefault("components", [])
    by_ref = {c.get("bom-ref"): i for i, c in enumerate(existing) if c.get("bom-ref")}

    added = replaced = no_ref = 0
    for comp in new_components:
        ref = comp.get("bom-ref", "")
        if not ref:
            existing.append(comp)
            no_ref += 1
        elif ref in by_ref:
            existing[by_ref[ref]] = comp
            replaced += 1
        else:
            by_ref[ref] = len(existing)
            existing.append(comp)
            added += 1

    return cbom, added, replaced, no_ref


def main():
    p = argparse.ArgumentParser(
        description="Merge hardware collector output into a CycloneDX CBOM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--cbom", required=True,
                   help="Path to existing CBOM JSON file")
    p.add_argument("--hw", action="append", required=True, metavar="HW_JSON",
                   help="Hardware collector output JSON (may be specified multiple times)")
    p.add_argument("--out",
                   help="Output path (default: overwrite --cbom in-place)")
    args = p.parse_args()

    cbom = load_json(args.cbom)

    all_components = []
    for hw_path in args.hw:
        data = load_json(hw_path)
        components = extract_components(data, hw_path)
        if not components:
            print(f"warning: no components found in {hw_path}", file=sys.stderr)
        all_components.extend(components)

    if not all_components:
        print("error: no hardware components found in any input file", file=sys.stderr)
        sys.exit(1)

    cbom, added, replaced, no_ref = merge(cbom, all_components)

    out_path = args.out or args.cbom
    pathlib.Path(out_path).write_text(json.dumps(cbom, indent=2), encoding="utf-8")

    parts = []
    if added:    parts.append(f"{added} added")
    if replaced: parts.append(f"{replaced} replaced")
    if no_ref:   parts.append(f"{no_ref} appended (no bom-ref)")
    print(f"[ok] merged hardware components ({', '.join(parts)}) → {out_path}", file=sys.stderr)
    print(f"[next] python3 report.py --cbom {out_path} --html report.html", file=sys.stderr)


if __name__ == "__main__":
    main()
