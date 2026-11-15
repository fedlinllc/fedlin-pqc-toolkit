"""Every CycloneDX cryptography-registry name the toolkit emits must match a pattern in the family it
claims (third_party/cyclonedx/cryptography-defs.json, CycloneDX/specification 76f185c, Apache-2.0),
or be named in the registry's TLS protocol composition."""

import json
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import cnsa20_ruleset as r  # noqa: E402
import tier2_pipeline as tp  # noqa: E402
from test_ruleset import CASES  # noqa: E402

REG = json.loads((ROOT / "third_party/cyclonedx/cryptography-defs.json").read_text())


def to_regex(pattern):
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "[":
            out.append("(?:")
        elif ch == "]":
            out.append(")?")
        elif ch == "{":
            j = pattern.index("}", i)
            out.append(".+?")
            i = j
        elif ch in "()|":
            out.append(ch)
        else:
            out.append(re.escape(ch))
        i += 1
    return re.compile("^(?:" + "".join(out) + ")$")


FAMILY_PATTERNS = {a["family"]: [to_regex(v["pattern"]) for v in a["variant"]] for a in REG["algorithms"]}
TLS_NAMES = {x if isinstance(x, str) else x.get("name")
             for p in REG["protocols"] if p["family"] == "tls"
             for v in p["version"] for c in v.get("composition", []) for x in c["algorithmSet"]}


def conforms(family, name):
    if name in TLS_NAMES:
        return True
    return any(rx.match(name) for rx in FAMILY_PATTERNS.get(family, []))


class Registry(unittest.TestCase):
    def test_registry_file_is_the_pinned_one(self):
        import hashlib
        h = hashlib.sha256((ROOT / "third_party/cyclonedx/cryptography-defs.json").read_bytes()).hexdigest()
        self.assertEqual(h, "d686e6b689d7e5e16e000c63ec9ab38fc8f0329f5a4d16fcf96d7123bce08655")

    def test_every_emitted_name_matches_the_registry(self):
        names = [(n, b) for n, b, *_ in CASES] + [
            ("ecdsa-with-SHA256", None), ("TLS_AES_256_GCM_SHA384", None), ("aes256-gcm@openssh.com", None),
            ("ecdsa-sha2-nistp521", None), ("rsassaPss", None), ("ffdhe3072", None), ("SLH-DSA-SHAKE-256f", None)]
        emitted = 0
        for name, bits in names:
            for cb in (None, 256, 384):
                fam, reg = r.registry_name(name, bits, cb)
                if reg is None:
                    continue
                emitted += 1
                with self.subTest(name=name, curve_bits=cb):
                    self.assertTrue(conforms(fam, reg), f"{name} -> {fam}:{reg} matches no registry pattern")
        self.assertGreater(emitted, 60)

    def test_no_name_is_invented_for_ambiguous_identifiers(self):
        for name, bits in (("rsaEncryption", 2048), ("id-ecPublicKey", 256), ("sntrup761x25519-sha512", None),
                           ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", None), ("unknown-thing", None)):
            self.assertEqual(r.registry_name(name, bits), (None, None), name)

    def test_interface_values_use_registry_names(self):
        b = tp.CBOM("x.example.com", "1", {})
        b.add_certificate({"host": "a.example.com", "subject": "a", "issuer": "CA", "key_alg": "id-ecPublicKey",
                           "key_bits": 384, "sig_alg": "ecdsa-with-SHA384"})
        b.add_tls_kex("a.example.com", "X25519MLKEM768", "TLSv1.3", "TLS_AES_256_GCM_SHA384")
        iface = next(c for c in b.to_dict()["components"] if c["bom-ref"].startswith("crypto/proto/tls/"))
        props = {}
        for p in iface["properties"]:
            props.setdefault(p["name"], []).append(p["value"])
        self.assertEqual(props["pkic:profile:keyExchange"], ["X25519MLKEM768"])
        self.assertEqual(props["pkic:profile:encryption"], ["TLS_AES_256_GCM_SHA384"])
        self.assertEqual(props["pkic:profile:authentication"], ["ECDSA-secp384r1-SHA-384"])


if __name__ == "__main__":
    unittest.main()
