"""cyclonedx-cli merge writes 0 for absent security levels; the pipeline must not keep invented values."""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import tier2_pipeline as tp  # noqa: E402


def comp(ref, **levels):
    return {"type": "cryptographic-asset", "bom-ref": ref, "name": ref,
            "cryptoProperties": {"assetType": "algorithm",
                                 "algorithmProperties": dict({"primitive": "kem"}, **levels)}}


class UndoMergeDefaults(unittest.TestCase):
    def test_invented_zero_levels_are_removed(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "runtime.json")
            with open(src, "w") as f:
                json.dump({"components": [comp("hyb", nistQuantumSecurityLevel=3), comp("ec", classicalSecurityLevel=128,
                                                                                       nistQuantumSecurityLevel=0)]}, f)
            merged = {"components": [comp("hyb", nistQuantumSecurityLevel=3, classicalSecurityLevel=0),
                                     comp("ec", classicalSecurityLevel=128, nistQuantumSecurityLevel=0),
                                     comp("foreign", classicalSecurityLevel=0)]}
            self.assertEqual(tp.undo_merge_defaults(merged, [src]), 1)
        ap = {c["bom-ref"]: c["cryptoProperties"]["algorithmProperties"] for c in merged["components"]}
        self.assertNotIn("classicalSecurityLevel", ap["hyb"])
        self.assertEqual(ap["ec"]["nistQuantumSecurityLevel"], 0)   # a real 0 (quantum-vulnerable) stays
        self.assertEqual(ap["foreign"]["classicalSecurityLevel"], 0)  # no original to compare: left alone

    def test_missing_source_files_are_ignored(self):
        doc = {"components": [comp("x", classicalSecurityLevel=0)]}
        self.assertEqual(tp.undo_merge_defaults(doc, ["/nonexistent.json"]), 0)


if __name__ == "__main__":
    unittest.main()
