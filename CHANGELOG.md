# Changelog

All notable changes to this toolkit. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0, a minor
release may change output formats.

Two version numbers appear in output. The **toolkit version** (below) is stamped in the CBOM's
`metadata.tools` and printed by `scripts/tier2_pipeline.py --version`. The **ruleset version** is stamped in
the policy result and changes only when a verdict changes; each verdict change is explained in
[CORRECTIONS.md](CORRECTIONS.md) with its primary source.

## [Unreleased]

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

[Unreleased]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v0.4.2...HEAD
[0.4.2]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/fedlinllc/fedlin-pqc-toolkit/releases/tag/v0.4.0
