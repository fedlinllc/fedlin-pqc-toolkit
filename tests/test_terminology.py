"""Terminology: the toolkit's own text says "quantum-resistant", never "quantum-safe" (see README, Terminology).

Markdown may quote third-party wording inside quotation marks on the same line. In code, where every output
string is a quoted literal, only the exact third-party phrases in THIRD_PARTY are allowed. Vendored and
verbatim third-party files are not scanned.
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCAN = ["README.md", "CHANGELOG.md", "CORRECTIONS.md", "SECURITY.md", "public/*.md",
        "scripts/**/*.py", "scripts/**/*.ps1", "scripts/**/*.sh", "scripts/**/*.mjs", "tests/*.py"]
TERM = re.compile(r"quantum[- ]safe|\bPQC?[- ]safe\b", re.I)
QUOTED = re.compile(r"\"[^\"]*\"|'[^']*'|“[^”]*”")
# Exact wording of the PKI Consortium PQC Maturity Model (criterion 0.1.2), which the toolkit quotes.
THIRD_PARTY = ("no quantum-safe algorithm available",)


class Terminology(unittest.TestCase):
    def test_code_strings_are_checked(self):
        # a quoted literal in code is output text, so it must not be exempt
        self.assertTrue(TERM.search('    print("ML-KEM is quantum-safe")'))

    def test_no_quantum_safe_outside_quotes(self):
        bad = []
        for pattern in SCAN:
            for f in ROOT.glob(pattern):
                if f.name == "test_terminology.py" or not f.is_file():
                    continue
                for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
                    if f.suffix == ".md":
                        text = QUOTED.sub("", line)
                    else:
                        text = line
                        for phrase in THIRD_PARTY:
                            text = text.replace(phrase, "")
                    if TERM.search(text):
                        bad.append(f"{f.relative_to(ROOT)}:{n}: {line.strip()}")
        self.assertEqual(bad, [], "say 'quantum-resistant' (quote third-party wording):\n" + "\n".join(bad))


if __name__ == "__main__":
    unittest.main()


class Dashes(unittest.TestCase):
    """Public text uses no em or en dashes (FEDLIN voice rule). Verbatim third-party files are exempt."""

    def test_no_em_or_en_dashes(self):
        bad = []
        roots = [ROOT / d for d in ("scripts", "tests", "schemas", "data", "public", ".github")]
        files = [f for r in roots if r.is_dir() for f in r.rglob("*")] + [f for f in ROOT.iterdir() if f.is_file()]
        for f in files:
            if not f.is_file() or any(p in f.parts for p in ("vendor-questions", "__pycache__")):
                continue
            if f.suffix not in (".py", ".md", ".ps1", ".sh", ".mjs", ".yml", ".json", ".lock", ".tsv", "") or \
                    f.name in ("pnpm-lock.yaml",):
                continue
            try:
                text = f.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            for n, line in enumerate(text.splitlines(), 1):
                if "\u2014" in line or "\u2013" in line:
                    bad.append(f"{f.relative_to(ROOT)}:{n}")
        self.assertEqual(bad, [], "replace em/en dashes:\n" + "\n".join(bad[:40]))
