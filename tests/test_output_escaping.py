"""Server-controlled and merged-CBOM strings in Markdown and HTML output (1.4.0, GHSA-gmv4-8882-x388). Offline.

A scanned server chooses its certificate subject and issuer; whoever writes a CBOM merged with --merge-cbom chooses
every name in it. None of those strings may add HTML to report.py --html, break a Markdown table (| or a line
break) or add a link, in report.md, the wave check or the context ranking.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import context  # noqa: E402
import policy  # noqa: E402
import report  # noqa: E402
import tier2_pipeline as tp  # noqa: E402
import wave  # noqa: E402

IMG = "<img src=x onerror=alert(1)>"
SCRIPT = "<script>alert(2)</script>"
EVIL = IMG + "|x\n| injected | row |\n[click](javascript:alert(3))"

try:
    import markdown  # noqa: F401
    HAVE_MARKDOWN = True
except ImportError:
    HAVE_MARKDOWN = False


def crafted_cbom(d):
    """A CBOM as a hostile server (certificate names) plus a crafted merged CBOM (algorithm, interface) leave it."""
    b = tp.CBOM("sys " + IMG, "1", {})
    b.add_certificate({"host": "svc.example.org", "subject": "CN=" + IMG + "|x", "issuer": "CN=" + SCRIPT,
                       "key_alg": "rsaEncryption", "key_bits": 2048, "sig_alg": "sha256WithRSAEncryption",
                       "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"})
    b.add_tls_kex("svc.example.org", "X25519", "TLSv1.3", "TLS_AES_256_GCM_SHA384")
    doc = b.to_dict()
    # what --merge-cbom carries in: records named by someone else
    doc["components"].append({"type": "cryptographic-asset", "bom-ref": "crypto/algo/merged-evil", "name": EVIL,
                              "cryptoProperties": {"assetType": "algorithm",
                                                   "algorithmProperties": {"primitive": "pke"}}})
    doc["components"].append({"type": "cryptographic-asset", "bom-ref": "crypto/algo/merged-rsa",
                              "name": "RSA " + SCRIPT + "|x",
                              "cryptoProperties": {"assetType": "algorithm",
                                                   "algorithmProperties": {"primitive": "pke"}}})
    p = os.path.join(d, "cbom.json")
    with open(p, "w") as f:
        json.dump(doc, f)
    return p


def table_rows_ok(md):
    """Every table row has as many unescaped cell separators as its header."""
    width = None
    for line in md.splitlines():
        if not line.startswith("|"):
            width = None
            continue
        n = line.replace("\\|", "").count("|")
        if width is None:
            width = n
        elif n != width:
            return line
    return None


class Report(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.path = crafted_cbom(self.t.name)

    def tearDown(self):
        self.t.cleanup()

    def md(self):
        view, _ = policy.load_view(self.path)
        return report.build_report(view)[0]

    def test_markdown_has_no_raw_html_or_injected_rows(self):
        md = self.md()
        self.assertIn("svc.example.org", md)
        for bad in ("<img", "<script", "\n| injected", "](javascript"):
            self.assertNotIn(bad, md)
        self.assertIsNone(table_rows_ok(md))
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", md)  # shown, as text

    def test_html_fallback_escapes_everything(self):
        with mock.patch.dict(sys.modules, {"markdown": None}):
            out = report.md_to_html("| a |\n|---|\n| " + IMG + " |\n" + SCRIPT, title="R " + SCRIPT)
        self.assertNotIn("<img", out)
        self.assertNotIn("<script", out)
        self.assertIn("&lt;img", out)

    def test_html_title_is_escaped(self):
        with mock.patch.dict(sys.modules, {"markdown": None}):
            self.assertIn("<title>R &lt;script&gt;", report.md_to_html("x", title="R " + SCRIPT))

    @unittest.skipUnless(HAVE_MARKDOWN, "Python-Markdown not installed")
    def test_html_with_markdown_drops_raw_html_and_unsafe_links(self):
        out = report.md_to_html(IMG + "\n\n<div onclick=alert(5)>x</div>\n\n[a](javascript:alert(6)) "
                                "[b](java\tscript:alert(7)) ![c](data:text/html,x) [ok](https://example.org/)")
        for bad in ("<img src", "<div", "javascript:", "data:text"):
            self.assertNotIn(bad, out)
        self.assertIn('href="https://example.org/"', out)

    def test_safe_url(self):
        for u in ("https://example.org/x", "http://x", "mailto:a@example.org", "#top", "rel/path", "javascript\\:x"):
            self.assertTrue(report._safe_url(u), u)
        for u in ("javascript:alert(1)", "JavaScript:x", "java\tscript:x", " javascript:x", "&#106;avascript:x",
                  "data:text/html,x", "vbscript:x"):
            self.assertFalse(report._safe_url(u), u)

    def test_report_cli_html(self):
        out_md = os.path.join(self.t.name, "r.md")
        out_html = os.path.join(self.t.name, "r.html")
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "scripts", "report.py"), "--cbom", self.path,
                            "--out", out_md, "--html", out_html], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        with open(out_html) as f:
            h = f.read()
        for bad in ("<img", "<script", 'href="javascript', "href='javascript"):
            self.assertNotIn(bad, h)
        with open(out_md) as f:
            self.assertIsNone(table_rows_ok(f.read()))

    def test_cbom_itself_is_not_altered(self):
        with open(self.path) as f:
            before = f.read()
        self.md()
        with open(self.path) as f:
            self.assertEqual(f.read(), before)


class Wave(unittest.TestCase):
    def test_wave_markdown_is_inert(self):
        res = {"wave": "w " + IMG, "passed": False, "profile": "civilian", "rulesetVersion": "x",
               "summary": {"pass": 0, "fail": 1, "not-observed": 0, "items": 1, "regressions": 1},
               "items": [{"id": "w1|x", "endpoint": "svc.example.org", "check": "mlkem", "status": "fail",
                          "detail": "negotiated " + EVIL}],
               "regressions": [{"endpoint": "svc.example.org", "name": EVIL, "lane": "x", "status": "s",
                                "priority": "High"}],
               "notCompared": [{"endpoint": "a\\|b", "lanes": ["x"], "reason": SCRIPT}]}
        md = wave.markdown(res)
        for bad in ("<img", "<script", "\n| injected", "](javascript"):
            self.assertNotIn(bad, md)
        self.assertIsNone(table_rows_ok(md))
        self.assertIn("w1\\|x", md)

    def test_md_text(self):
        self.assertEqual(wave.md_text("a\\|b"), "a\\\\\\|b")  # a backslash cannot un-escape the pipe
        self.assertEqual(report.md_text("a|b\nc<d>"), "a&#124;b c&lt;d&gt;")


class Context(unittest.TestCase):
    def test_context_cells_and_lists_are_inert(self):
        att = {"scanYear": 2026, "horizon": 2035, "horizonSource": "IR 8547", "endpoints": [
            {"endpoint": "svc.example.org", "systems": ["S " + IMG], "owners": ["Ops | Sec"], "impact": "high",
             "worstPriority": "High", "exposure": "exposed", "exposureReasons": ["negotiates " + EVIL],
             "urgent": "yes", "urgency": "x"}],
            "noContext": [{"endpoint": SCRIPT, "worstPriority": None}], "notRanked": [], "unusedSystems": [IMG],
            "missingDataLifetime": [], "missingMigrationTime": []}
        md = context.markdown(att)
        for bad in ("<img", "<script", "\n| injected", "](javascript"):
            self.assertNotIn(bad, md)
        self.assertIsNone(table_rows_ok(md))


if __name__ == "__main__":
    unittest.main()
