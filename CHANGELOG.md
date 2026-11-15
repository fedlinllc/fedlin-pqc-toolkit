# Changelog

All notable changes to this toolkit. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0, a minor
release may change output formats.

Two version numbers appear in output. The **toolkit version** (below) is stamped in the CBOM's
`metadata.tools` and printed by `scripts/tier2_pipeline.py --version`. The **ruleset version** is stamped in
the policy result and changes only when a verdict changes; each verdict change is explained in
[CORRECTIONS.md](CORRECTIONS.md) with its primary source.

## [Unreleased]

## [0.7.0] - 2026-11-15

### Added
- PQC Maturity Model evidence (`scripts/pqcmm_evidence.py`): maps a CBOM (and optionally vendor-readiness
  answers) to the PKI Consortium PQCMM v1.0.1 (vendored, MIT, pinned in `toolkit.lock`). Pre-fills the
  model's response fields for 26 of its 72 questions with provenance (observed, derived, snapshot, vendor);
  never awards a level or marks a criterion met. Report plus JSON.

### Fixed
- The container image now includes `third_party/` (PQCMM model, PKI Consortium validator), which the
  vendor-readiness and PQCMM modules read.

## [0.6.1] - 2026-11-15

### Fixed
- CBOMs built with `--merge-cbom`, `--repo`, `--theia-dir` or `--theia-image` could state false security
  levels. cyclonedx-cli writes `0` for an absent `classicalSecurityLevel` or `nistQuantumSecurityLevel`
  during merge, so an unknown strength became "0 bits" (for example X25519MLKEM768 and ecdsa-with-SHA256),
  and a TLS protocol-version asset gained `nistQuantumSecurityLevel: 0`, which CycloneDX reads as
  quantum-vulnerable. The pipeline now removes any level the original input did not carry. Details in
  [CORRECTIONS.md](CORRECTIONS.md).
- `--redact` also removes cbomkit-theia's raw output files.

## [0.6.0] - 2026-11-15

### Added
- Vendor readiness (`scripts/vendor_readiness.py`, `data/vendor-questions/`): the 31 questions of
  "Post-quantum questions to ask your vendors" (ASD's ACSC with CISA and NSA, November 2026, CC BY 4.0) as a
  questionnaire, an answer template and an assessment. Each question is typed as disclosure, capability or
  intent; disclosure answers are checked against the vendor's CBOM (contradictions reported), dates are
  checked against the end of 2030, and the publication's seven common concerns are raised from structured
  fields. Uses the ruleset, the CMVP snapshot and the PKI Consortium validator.

## [0.5.1] - 2026-11-15

### Fixed
- The Linux and Windows hardware collectors no longer write validation claims into the CBOM. Removed:
  a named HSM presented as the only product approved for ML-KEM, a 2026-2027 forecast for a validated PQC
  OpenSSL provider (one was validated 2026-11-13), a claim that ML-KEM key establishment requires an HSM,
  unsourced vendor and distribution timelines, and a blanket "FIPS 140-2 validated" status for TPMs. The
  action text now states what was observed and points to the report's CMVP section, which reads the dated
  snapshot. Details in [CORRECTIONS.md](CORRECTIONS.md).

## [0.5.0] - 2026-11-15

### Added
- FIPS 140-3 (CMVP) check in the report: each detected implementation (distribution OpenSSL, BC-FJA,
  AWS-LC, BoringCrypto, wolfCrypt, Go Cryptographic Module, Luna/nShield/YubiHSM HSMs) is listed with its
  active candidate certificates, sunset dates and approved post-quantum algorithms, from a dated, pinned
  snapshot of NIST's CMVP pages (`scripts/cmvp.py`, `data/cmvp/`). Libraries with no validated module are
  named. Summary JSON gains `cmvp`.
- The Linux host collector records `fedlin:os_id`, `fedlin:os_version_id` and `fedlin:fips_enabled`.

### Fixed
- A missing cyclonedx-cli no longer crashes `--merge-cbom` or `--validate`; the pipeline warns that merged
  inputs were dropped.

## [0.4.3] - 2026-11-15

Ruleset 1.0.2. Details and sources in [CORRECTIONS.md](CORRECTIONS.md).

### Changed
- ChaCha20-Poly1305 is no longer compliant under the `civilian` profile: it is quantum-resistant but not
  a FIPS-approved algorithm. It was already non-compliant under `nss`.
- SHA-512/256 is judged as its own algorithm (256-bit output) and is no longer counted as CNSA 2.0
  approved. SHA-512/224 is recognized.
- HMAC-SHA-1, SHA-1, SHA-224 and SHA-512/224 notes cite the NIST SP 800-131A Rev. 3 draft, which proposes
  disallowing them for new protection after 2030. Verdicts still follow Rev. 2, the final version.
- OpenSSH MAC names (`hmac-sha2-256/512[-etm]`, `umac-64/128[-etm]`) and fused cipher names
  (`aria128-gcm`, `camellia256`) are recognized instead of flagged for review.
- The public `package.json` no longer installs `@noble/post-quantum`, which nothing in the public tree
  uses.

### Security
- `--repo` is passed to cdxgen as an argument, not through a shell. A crafted directory name could
  previously run a command.
- `--kube-cli` must be a command name or path, and a node name read from the cluster must be a valid
  Kubernetes name before it reaches a command line.
- `--redact` deletes the unredacted intermediate files it leaves behind, and refuses a replacement that
  would make the CBOM invalid JSON.

## [0.4.2] - 2026-11-15

### Added
- The toolkit container image bundles the same pinned OpenSSL 3.5.9 as the key-exchange probe image
  (`FEDLIN_KEX_PROBE_OPENSSL`). Endpoint scans from inside the image on a FIPS host now observe
  X25519MLKEM768 instead of reporting key exchange as not observed. The host's FIPS configuration is
  not changed.
- `scripts/tier2_pipeline.py --version`, and this changelog.

### Changed
- The CBOM's `metadata.tools` version is the toolkit version alone. It previously read
  `0.5.0-dev (ruleset …, profile …)`; the profile is a property of the policy result, not of the CBOM.
- `setup.sh` needs no root: pnpm runs through `corepack pnpm`, or from the sha512-checked tarball
  unpacked into `bin/`.
- cbomkit-theia is built from its pinned commit in the digest-pinned Go image the Containerfile uses,
  not with upstream's Dockerfile, which pulls unpinned base images.
- The console summary states that its counts are algorithms across all lanes, and the grade text says
  "scored public-key usages" instead of "classified crypto".

### Fixed
- `setup.sh` was not executable, so the README quick start failed at its first step.

## [0.4.1] - 2026-11-15

Ruleset 1.0.1. Details and sources in [CORRECTIONS.md](CORRECTIONS.md).

### Added
- The NIST-curve ML-KEM hybrids `mlkem768nistp256-sha256` and `mlkem1024nistp384-sha384`, and
  `x448mlkem1024`, are recognized as quantum-resistant.
- Static-RSA TLS suites are reported as RSA key transport with no forward secrecy.
- The report is graded **Incomplete** when key exchange was not observed on a TLS endpoint, with a banner
  stating how many.
- `--debug-image` for `--deep` FIPS checks outside OpenShift.

### Changed
- Mandate text credits the deadlines to EO 14412 and OMB M-26-15.
- README and SECURITY.md describe what each mode reads ("Access by mode") instead of a blanket claim.

## [0.4.0] - 2026-11-14

First public release.

### Added
- CycloneDX 1.6 CBOM of observed facts (TLS endpoints, Kubernetes/OpenShift routes and ingresses, SSH
  configuration, source repositories, Windows certificate stores and AD CS, TPM/HSM presence), conforming
  to the PKI Consortium CBOM entry profile.
- Verdicts in a separate `pkic.cbom.policy-result` file bound to the CBOM by SHA-256, under the `civilian`
  (FIPS 203/204/205, NIST IR 8547) or `nss` (CNSA 2.0) profile. Ruleset 1.0.0.
- Usage-weighted readiness score over public-key usages, and a readiness report.
- Key-exchange probe image so a FIPS scan host can observe X25519MLKEM768.
- Pinned, checksum-verified downloads; CI with tests and Gitleaks.

[Unreleased]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v0.4.3...v0.5.0
[0.4.3]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/fedlinllc/fedlin-pqc-toolkit/releases/tag/v0.4.0
