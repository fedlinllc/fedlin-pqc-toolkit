# Changelog

All notable changes to this toolkit. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0, a minor
release may change output formats.

Two version numbers appear in output. The **toolkit version** (below) is stamped in the CBOM's
`metadata.tools` and printed by `scripts/tier2_pipeline.py --version`. The **ruleset version** is stamped in
the policy result and changes only when a verdict changes; each verdict change is explained in
[CORRECTIONS.md](CORRECTIONS.md) with its primary source.

## [Unreleased]

## [1.0.0-rc.1] - 2026-11-16

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

[Unreleased]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v0.8.0...v1.0.0-rc.1
