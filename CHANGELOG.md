# Changelog

All notable changes to this toolkit. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0, a minor
release may change output formats.

Two version numbers appear in output. The **toolkit version** (below) is stamped in the CBOM's
`metadata.tools` and printed by `scripts/tier2_pipeline.py --version`. The **ruleset version** is stamped in
the policy result and changes only when a verdict changes; each verdict change is explained in
[CORRECTIONS.md](CORRECTIONS.md) with its primary source.

## [Unreleased]

## [1.2.0] - 2026-11-16

### Added
- Migration wave check (`scripts/wave.py`, schema `schemas/wave-1.0.schema.json`, pipeline flag `--wave`): a
  wave file states what a wave promises per endpoint (findings resolved, ML-KEM negotiated or accepted,
  classical-only clients refused, certificate replaced), and the check tests each item against a later scan.
  An item passes only on what that scan itself observed (its own records, a complete enumeration where the
  check needs one); otherwise it is "not observed", never passed. With `--baseline`, regressions at the
  wave's endpoints are listed where both scans could see.
- The primary certificate of each endpoint now records `fedlin:sha256Fingerprint` (additional certificates
  already did), and each certificate and TLS interface records `fedlin:observedIn`, the serial number of the
  scan that observed it. A merged CBOM keeps the scan's own serial number.
- The TLS interface records `fedlin:certificateProbes`: what the certificate probe of each signature-scheme
  family got back (a certificate, a refusal, or no answer). The probes now keep the server's alerts.

### Changed
- `--baseline` is available in the public toolkit for `--wave` regressions; the delta report it also produces
  remains part of the engagement kit.

### Fixed
- Two endpoints whose names differ only in punctuation (a-b.example.com and a.b.example.com) no longer share
  one certificate or interface record.

## [1.1.0] - 2026-11-16

### Added
- How each record was observed: every cryptographic record the toolkit writes carries CycloneDX 1.6
  component evidence (`evidence.identity`, field `name`: technique and confidence; `evidence.occurrences`:
  the endpoint, where there is one). One fixed value per source, an ordinal ranking rather than a
  probability: handshake or enumeration probe 1.0, system configuration or certificate stores 0.8, file or
  image 0.8, dependency capability 0.3, assumption 0.1 (STABILITY.md). Verdicts and the score do not use it.
- Report section "How each record was observed" and `summary.json` key `evidence` (records by their
  strongest source).
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md), a [Code of Conduct](CODE_OF_CONDUCT.md), issue forms
  (verdict challenge with its primary source, bug report, feedback), a pull request template, and a
  Developer Certificate of Origin check on every pull request.

### Changed
- Evidence in a CBOM merged with `--merge-cbom` (and in cbomkit-theia output) is restored verbatim after
  the merge. cyclonedx-cli drops occurrence detail such as line, offset and symbol, and writes identity in the
  deprecated single-object form.
- `--redact` warns when its search text would also rewrite the toolkit's own property names or evidence
  markers.

### Fixed
- A merge no longer leaves duplicate `system` components (cyclonedx-cli copied each input's subject into the
  component list); CycloneDX requires unique bom-refs.

## [1.0.0] - 2026-11-16

First release under the [stability promise](STABILITY.md) for machine-readable outputs. Earlier releases are
listed in [CHANGELOG-0.x.md](CHANGELOG-0.x.md).

### Added
- Verdict table (`scripts/verdict_table.py`, schema `schemas/verdict-table-1.0.schema.json`): the ruleset as
  versioned, deterministic data for other scanners, with verdicts under both profiles taken from the same
  code that writes the policy result. Unknown names stay unknown.
- Local MCP server (`scripts/mcp_server.py`): Model Context Protocol over stdio, standard library only.
  Read-only tools over files under one root folder (verify a policy result, summarize, PQCMM evidence,
  vendor readiness, verdict lookup). It never scans, writes nothing, and marks file-derived text as
  untrusted.
- Endpoint enumeration: TLS 1.0 to 1.3, the cipher suites of each version, the key-exchange groups in the
  probe list (which ML-KEM hybrids are supported), Diffie-Hellman group sizes, and one certificate per
  signature-scheme family, recorded as facts on the TLS interface as accepted, refused (only on a server
  refusal alert) or not tested. A second certificate the server presents becomes its own certificate asset
  and is scored; accepted versions, suites and groups are judged by the policy stage (lane `configuration`)
  and reported in **Server configuration** and as top exposures, without changing the score. Endpoints the
  host OpenSSL cannot reach (FIPS host, TLS 1.0-only server) are captured with the enumeration client.
  `--no-enumerate` skips it. Found missing by a side-by-side run against testssl.sh, sslyze and other open
  tools, and pressure-tested against public TLS test hosts.
- `STABILITY.md`: the 1.x stability promise for machine outputs, enforced by `tests/test_contract.py`.
- Release workflow (`.github/workflows/release.yml`, on version tags): runs the tests, builds the source
  tarball, the verdict table (`verdicts.json`), an SBOM of the toolkit and the container image
  (`ghcr.io/fedlinllc/fedlin-pqc-toolkit`), attests all of them with Sigstore-signed SLSA build provenance,
  and creates the GitHub release with the files and the provenance bundle attached.
- README: a dated table of how far each input has been validated, and sections for the MCP server, the
  verdict table and the stability promise.

### Changed
- Ruleset 1.0.3 (see CORRECTIONS.md): RSA signature names are signatures (target ML-DSA/SLH-DSA, not
  ML-KEM); under-sized keys are described as disallowed by SP 800-131A; LMS/XMSS notes state CNSA 2.0's
  software and firmware signing scope.
- `policy.py verify` checks three things (CBOM digest, same ruleset, every verdict reproduced) and fails on
  any; the report, MCP server and other consumers use a policy result only when it passes.
- Invalid input (no valid `--endpoints`, a missing `--merge-cbom` file, a missing `--repo`/`--theia-dir`)
  stops with exit code 2 and writes no CBOM.
- Report: expired certificates are flagged; TLS sessions with quantum-vulnerable key exchange count as
  harvest-now, decrypt-later exposures; the appendix uses the policy result's status words; mandate text no
  longer claims the report is the M-26-15 plan or the full Phase 1 inventory.
- No em or en dashes in public text, including report output and the `grade` value in `summary.json`.

### Fixed
- A policy result whose verdicts had been edited passed `verify` and was reported as written.
- The verdict table gave the plain verdict for key sizes it did not list (RSA-1536 read as vulnerable, not
  broken) and returned unknown for common cipher-suite, symmetric and hash names.
- Terminology section in the README: the toolkit says "quantum-resistant", never "quantum-safe"; third-party
  wording is quoted as written. `tests/test_terminology.py` enforces it.

[Unreleased]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v0.8.0...v1.0.0
