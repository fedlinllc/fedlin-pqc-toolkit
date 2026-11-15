# Vendored: PKI Consortium CBOM profile validator and profiles

Source: https://github.com/pkic/cbom, commit `65a6f4245d09e978fb4fbdbb74e2ecec0ffe133d`
(2026-11-11), `docs/methodology/`. License: MIT, Copyright (c) 2026 PKI Consortium (see `LICENSE`).
Unmodified copies.

| File | SHA-256 |
|---|---|
| `validate_cbom.py` | `eb977baaaad9e8eaf9fd9d4b88bc76af4c950b55053f9dadd8ebad0a84df63cc` |
| `profile-interface-enumeration.rules.json` (v0.3, entry profile) | `d1fc04b98d7f8ac08798762366b21f6259032e84b67aa26abea956ce41b28113` |
| `profile-interface-disclosure.rules.json` (v0.9, baseline) | `3ef3b240eb6bd5e95c3ce32bad4fd70b1a8fa6f10e455b1f6a551fbf6b331b2e` |

The profiles are illustrative working-group drafts (`pkic.example.*`), not ratified standards. Using
them is alignment with a published draft, not an endorsement by the PKI Consortium.

Conformance check (stdlib Python only):

```bash
python3 third_party/pkic-cbom/validate_cbom.py out/cbom.json \
    third_party/pkic-cbom/profile-interface-enumeration.rules.json
```

Run 2026-11-15: CONFORMS for the entry profile (live fedlin.com scan and the offline test CBOM). `tests/test_pkic_conformance.py` runs it on every test run.

Exit 0 conforms, 1 does not conform, 4 refused (carrier version below the profile minimum). CycloneDX
1.6 output is evaluated and flagged as legacy; the profiles target CycloneDX 2.0.

Refresh: re-copy from a newer commit, update the commit and hashes above, and re-run the tests.
