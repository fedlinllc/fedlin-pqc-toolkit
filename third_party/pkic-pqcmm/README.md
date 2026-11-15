# PKI Consortium PQC Maturity Model (vendored)

- Source: https://github.com/pkic/pqcmm, tag `v1.0.1` (commit 5ad816e02cf232ef19b66f6c1b675120f456b7b7), released 2026-11-12.
- `pqcmm-model-1.0.1.yaml`: the released model file, unmodified.
- `pqcmm-model-1.0.1.json`: the same content converted to JSON (PyYAML `safe_load`, then `json.dumps`) so the
  toolkit can read it with the Python standard library. Regenerate it from the YAML; never edit it by hand.
- License: MIT (`LICENSE`), Copyright (c) 2022 PKI Consortium.

`scripts/pqcmm_evidence.py` reads the JSON. Digests of both files are pinned in `toolkit.lock`.
