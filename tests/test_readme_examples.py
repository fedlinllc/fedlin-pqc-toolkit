"""The README's context and wave examples are valid files (1.7.0: they had drifted from what the scan produces)."""
import json
import os
import re
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import context  # noqa: E402
import wave  # noqa: E402


class ReadmeExamples(unittest.TestCase):
    def test_json_examples_load(self):
        readme = os.path.join(ROOT, "public", "README.md")
        if not os.path.exists(readme):          # the public tree has it at the root
            readme = os.path.join(ROOT, "README.md")
        with open(readme) as f:
            blocks = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", f.read(), re.S)]
        seen = set()
        with tempfile.TemporaryDirectory() as d:
            for i, doc in enumerate(blocks):
                p = os.path.join(d, f"{i}.json")
                with open(p, "w") as f:
                    json.dump(doc, f)
                if doc.get("schema") == "fedlin.pqc-wave":
                    wave.load_wave(p)
                    seen.add("wave")
                elif doc.get("schema") == "fedlin.pqc-context":
                    c = context.load_context(p)
                    self.assertTrue(any(context.matches(pat, "example.com") for s in c["systems"]
                                        for pat in s["endpoints"]), "the context example should match the quick start")
                    seen.add("context")
        self.assertEqual(seen, {"wave", "context"})
