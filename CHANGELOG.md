# Changelog

All notable changes to this toolkit. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0.0, a minor
release may change output formats.

Two version numbers appear in output. The **toolkit version** (below) is stamped in the CBOM's
`metadata.tools` and printed by `scripts/tier2_pipeline.py --version`. The **ruleset version** is stamped in
the policy result and changes only when a verdict changes; each verdict change is explained in
[CORRECTIONS.md](CORRECTIONS.md) with its primary source.

## [Unreleased]

## [1.5.2] - 2026-11-19

Ruleset 1.0.5 (unchanged). Vendor readiness fixes from a second buyer-side and vendor-side test, of 1.5.1.

### Fixed
- **No false "consistent" left.** L1 reads its `cbom` claim when a CBOM is supplied ("no CBOM" with one supplied is
  contradicted; a prose-only answer is not-checked). T3 claiming hybrid support with no hybrid in the CBOM is
  not-evidenced, and a PQC-only date that has passed while the CBOM still shows a hybrid is contradicted.
- **Stated dates are reported apart from the CBOM checks**, as `planned`, `past`, `implausible` (before FIPS
  203/204/205 were published), `late` or `missing-date`, never as "consistent". An invalid `ga_date` ("soon",
  "Q5 2027") or one before August 2024 no longer leaves I1 consistent. T3 counts toward the late-dates concern.
- **CBOM reading.** Nested components are read; a name without a parameter set takes the record's
  `parameterSetIdentifier` (ML-KEM + 768 is ML-KEM-768); the NIST OIDs of the ML-KEM, ML-DSA and SLH-DSA parameter
  sets are recognised.
- **A1 with a hybrid.** An honest A1 "yes" for a vendor on X25519MLKEM768 is consistent again: the hybrid's
  classical half is traditional asymmetric cryptography (a regression in 1.5.1).
- **A5 concern from a claim.** The compensating-controls concern is raised from A5's new
  `stronger_traditional_settings` claim, not from the answer text.
- **Report.** Contradictions are stated at the top; "ruleset profile" instead of "verdict profile"; coverage
  wording; a claimed algorithm the ruleset does not know is "not in this toolkit's ruleset", not "not a recognised
  quantum-resistant algorithm". The template carries each question's text and type. The summary adds
  `claims_given` and `evidence_cited`.
- **`--fail-on`.** `assess --fail-on contradicted,late` exits `1` when a question has one of the listed statuses.
- **PQCMM evidence with `--answers`.** The tool-vs-disclosure field lists every disclosure check the CBOM
  contradicts or does not evidence (it compared only A1 and could print "No gap" beside four contradictions, and
  its A1 gap cited certificates); it notes a product or version mismatch between the answers and the CBOM; an
  unreadable file gives `[error]` and exit `2`.

## [1.5.1] - 2026-11-19

Ruleset 1.0.5 (unchanged). Vendor readiness fixes from a buyer-side and vendor-side test of
`vendor_readiness.py`.

### Fixed
- **A1 no longer counts signatures.** A1 asks whether customer data flows rely on traditional asymmetric
  cryptography; it was scored with every quantum-vulnerable algorithm, so ML-KEM traffic authenticated with
  ECDSA read as contradicted. A1 now counts key-establishment and encryption algorithms; signature and
  certificate algorithms stay with A6.
- **L4 counts only cryptographic libraries.** Any library (for example `jackson-databind`) contradicted a "no
  third-party cryptography" answer; now only libraries that provide cryptography do.
- **No "opaque cryptography" label for unrecognised names.** An algorithm name the ruleset does not know (such
  as HQC-128) raised the publication's "proprietary or opaque cryptography" concern against the vendor. Such
  names are now listed for review instead, and that concern is not raised automatically.
- **Pre-standard Kyber hybrids count as hybrid** for T3 (`X25519Kyber768Draft00` was invisible).
- **Wording.** I1 says "meets the profile target", not "compliant". The report opens with its scope, what
  "consistent" and "contradicted" do and do not mean, that it is not a compliance determination, and the tool
  version, ruleset version, run date and SHA-256 of each input. Truncated answers are marked.
- **Dates.** Quarters (Q3 2027), ISO date-times and month ends are read; an invalid value (2026-13) is reported
  as not a date instead of "no date given"; a PQC-only date or GA date after 2030 is "late".
- **A5.** A negative A5 answer ("No.") no longer raises the compensating-controls concern.
- **Robustness.** An answers file or CBOM that is not valid JSON or has the wrong shape, or a `cbom` path that
  does not exist, stops `assess` with an `[error]` and exit code `2` instead of a traceback or a silent
  "no CBOM". Answers with unknown question ids are reported. The summary adds per-question `statuses`,
  `inputs` (file digests), `toolkit_version`, `ruleset_version` and `assessed`.

## [1.5.0] - 2026-11-19

Ruleset 1.0.5 (control mapping only; no verdict or score changes, see CORRECTIONS.md). Behaviour changes for
anyone scripting the pipeline: a run that assessed nothing exits `2`; a source flag no longer scans the current
cluster (add `--cluster`); the report has no letter grade (`summary.json` `grade` is `null`).

### Added
- **NOTICE and TRADEMARKS.md.** A NOTICE file, which Apache-2.0 redistributions must keep (also shipped in the
  image as `/licenses/fedlin-pqc-toolkit.NOTICE`), and a trademark policy: you may say your work uses the
  toolkit and keep the names it writes into its outputs, but you may not suggest FEDLIN performed, reviewed
  or endorsed it.

### Changed
- **No letter grade; the report leads with scope and a disclaimer.** A report opened with, for example,
  "14/100 (F: Not started) … the estate is almost entirely quantum-vulnerable" for three listed hosts, one of
  them already negotiating ML-KEM, and the "not a compliance determination" note came about 150 lines later.
  Because no public CA issues post-quantum certificates yet, almost any public site scored F. The report now
  opens with what the scan covered (only what it was pointed at, not an inventory of the organization) and
  that the score is the toolkit's own measure, not a compliance determination. The score is given as a
  number with what was observed (post-quantum key exchange on N of M TLS endpoints, quantum-resistant usages
  per public-key lane), and "Covered" is marked partial. `summary.json` keeps the `grade` key, now always
  `null`, and adds `incomplete` (which replaces `grade: "Incomplete"`), `tls_endpoints`,
  `tls_endpoints_pq_kex`, `scope` and `disclaimer`.
- **A source flag no longer scans the current cluster or this host's sshd.** Before, any run without
  `--no-runtime` used the cluster of the current kube context (route or ingress capture, cluster-wide
  secret counts) and ran `sudo -n sshd -T` on the scan host, so a quick start adapted without
  `--no-runtime` scanned whatever cluster the user was logged into and mixed the scan host's SSH settings
  into an endpoint report. Now a run with `--endpoints`, `--repo`, `--theia-dir`, `--theia-image` or
  `--merge-cbom` scans only those sources. The new `--cluster` flag adds the cluster, and the new
  `--local-ssh` flag adds this host's SSH configuration (and stops with exit `2` if it cannot be read).
  `--deep`, `--debug-image` and `--kube-cli` in such a run need `--cluster`, and `--cluster --no-runtime`
  is refused. A run with none of those source flags behaves as before (cluster plus local SSH) and now
  names the kube context it is about to scan. `--no-runtime` keeps its meaning.
  If you relied on `--endpoints` or `--repo` adding to a cluster scan, add `--cluster` (and `--local-ssh`).

### Fixed
- **Vendor readiness: CC BY 4.0 attribution.** The questionnaire and the assessment report now give the full
  attribution for the ASD/CISA/NSA questions: copyright, licence link, source, the changes made, and that the
  agencies have not endorsed the tool. NOTICE says the same. The questionnaire's "What a strong answer
  includes" heading is back to the publication's "Key response considerations".
- **Vendor readiness: no false "consistent".** A claim written as text ("No", "false") was skipped, so real
  contradictions read "consistent"; it is now read as true/false. An algorithm list given as a string was read
  one character at a time; it is split on commas. An unrecognised claimed algorithm now counts against the
  answer. An unanswered question is "unanswered" and a prose-only answer "not-checked" instead of
  "consistent". L1 now reads its `cbom` claim. A claim that something is absent is "consistent" only when the
  CBOM declares complete coverage; a partial CBOM gives "not-evidenced", and the report says so. The summary
  gains `cbom_coverage`.
- **Input checks.** `--regime` accepts only the six regimes it knows (any case) and refuses others, which were
  silently ignored; ports outside 1-65535 are refused; a bare IPv6 address (`2001:db8::1`) is accepted, not
  only the `[2001:db8::1]` form.
- **Default name.** Without `--name`, the system is named after the first endpoint (or the `--repo` /
  `--theia-dir` folder) instead of "openshift-cluster"; a cluster scan keeps "openshift-cluster".
- **Invisible and bidirectional characters** (zero-width, LRM/RLM, the embedding, override and isolate
  controls, BOM, tag characters) are removed from CBOM strings in report, wave and context Markdown, as the
  MCP server already did, so a certificate field cannot make text read differently from what it is.
- **MCP server.** A request nested too deeply to parse is answered with a parse error instead of stopping the
  server, and summarizing a large CBOM is no longer quadratic (10,000 components: report 18 s to 1.3 s).
- **Wording.** The report's "Not included in this report" list is now "Limits of these findings", and the
  engagement-kit flags' help no longer reads as sales copy. The README shows how to register the MCP server
  in Claude Code and other clients, and how verdict lookup matches names.
- **Ruleset 1.0.5: cipher suites cite SC-8, not SC-28.** TLS and SSL cipher suites and OpenSSH ciphers carried
  SC-28 (data at rest) from their bare cipher; they now cite SC-8 (data in transit). Verdicts, priorities and
  scores are unchanged; see CORRECTIONS.md.
- **A signed report names the key that signed it.** The attestation section said the report was "signed by
  FEDLIN's holder of the published signing key", although no key was published, and it said so for any key
  that signed. The section now names the signing key's ID and says it is FEDLIN's published key only when it
  is; otherwise it says FEDLIN has not signed or reviewed the files. FEDLIN's key ID and public key are now
  in SECURITY.md. (Signing itself is part of the engagement kit, not this build.)
- **`policy.py verify` compares the whole policy result.** It compared only seven fields of each finding
  (status, target, quantum vulnerability, priority, controls, lane, canonical name), so deprecation and
  disallow dates, security levels, citations, notes, the policy's source texts, `notAsserted` and the
  document record could be changed and verify still printed `[ok]`. It now re-evaluates the CBOM with the
  result's profile and crosswalk regime and compares every field; only `evaluationDate` may differ (it must
  still be a date). A mismatch names the field. A result written by an earlier toolkit version with the same
  ruleset can now fail verify if the result's fields changed shape; the report and the MCP server then
  evaluate the CBOM again, as they do for any result that fails.
- **A run that assessed nothing no longer exits 0.** The pipeline printed `[ok]` lines, wrote an empty CBOM
  and report, and exited 0 when no `--endpoints` entry completed a handshake, when a hosts file name was
  mistyped (it was scanned as a hostname), when `--repo` ran without cdxgen, when cbomkit-theia failed, or when
  a `--merge-cbom` input was dropped because cyclonedx-cli was missing. A CI gate read each of these as a pass.
  Each now stops with exit code `2`, an `[error]` line naming the cause, and no CBOM, policy result or report.
  Missing tools are found before any scanning starts. A run where only some endpoints are reachable still
  exits `0` and the report says how many were reached. STABILITY.md describes the exit codes.

## [1.4.1] - 2026-11-18

Ruleset 1.0.4 (unchanged). A packaging-only patch: no change to scanning, verdicts or output formats.

### Changed
- **Container image labels and licences.** The image now sets its own `name`, `vendor`, `maintainer`,
  `version`, `release`, `summary`, `description`, `url` and `help` labels, and the release build sets the
  build date and commit, so the UBI base image's values (which named Red Hat as vendor) no longer show. It
  ships `/licenses` with the toolkit's licence, the vendored CycloneDX, PKI Consortium and musl licences and
  an index of bundled tools. Red Hat `preflight` failed two checks on 1.4.0 (HasLicense,
  HasNoProhibitedLabels) and passed the other nine; these changes address both.

## [1.4.0] - 2026-11-17

Ruleset 1.0.4. Upgrade if you scan servers you do not control or render reports from CBOMs others produced. A
minor release: it adds a CBOM property, a placeholder value and ruleset canonical IDs; nothing is removed.

### Security
- **Forged key exchange (GHSA-62fw-vjj2-r4p2).** A scanned server could send "Negotiated TLS1.3 group:
  SecP384r1MLKEM1024" as data after the handshake, and the scan recorded a classical handshake as ML-KEM (also
  on TLS 1.2). The scan now reads only what OpenSSL printed about the handshake, up to the end of its
  connection summary, from lines OpenSSL starts; this covers the key-exchange probe, the classical-only probe,
  enumeration, certificate capture and the chain-depth count. A group name must be a known group (strict
  character set); anything else is recorded as `unparsed-kex-group` (Manual review). An ML-KEM group counts
  only when the same handshake negotiated TLS 1.3, and is not recorded when enumeration ran and found that
  the server refuses it (`fedlin:kexConflict`). Such a key exchange counts as not observed: the report is
  marked Incomplete and lists it, and wave checks of the key-establishment lane and `mlkem` are "not observed"
  there, never passed.
- **HTML injection (GHSA-gmv4-8882-x388).** Server-controlled strings (certificate subject and issuer, and
  before the fix above the key-exchange text) and names in a CBOM merged with `--merge-cbom` reached
  report.md, the wave, context and delta Markdown and `report.py --html`, which passed raw HTML through. The
  HTML output now never passes raw HTML (Python-Markdown's raw HTML handling is off, link targets other than
  http(s), mailto and relative ones are removed, the title is escaped once, and the fallback without
  Python-Markdown escapes the whole document). Every CBOM string interpolated into report, wave, context and
  delta Markdown is made inert: no line break, control byte or terminal escape, table-cell separator, raw HTML,
  link target, backslash escape or code span. Machine outputs (`summary.json`, the MCP server) keep the
  values as they are.

### Added
- CBOM property `fedlin:kexConflict` (why a handshake's key-exchange group was not recorded) and the
  placeholder value `unparsed-kex-group` for a key exchange the scan saw but could not read.
- `fedlin:classicalOnlyOfferReduced` also names the groups an older client OpenSSL could not offer.
- Ruleset canonical IDs: `kyber`, `dilithium`, `sphincs+` (pre-standard submissions), `ml-kem-ipd`,
  `ml-dsa-ipd`, `slh-dsa-ipd` (2023 initial public drafts), `hybrid-ml-kem-512/768/1024` (ML-KEM hybrids in
  unregistered pairings), `composite-ml-dsa-44/65/87` and `composite-ml-dsa-87-cnsa` (composite signatures),
  `srp` (SRP key exchange). The verdict table includes common spellings that map to them; a spelling it does
  not list reads as unknown there.

### Fixed
- The classical-only probe offered no brainpool group, no FFDHE above 3072 bits and no legacy TLS 1.2 curve,
  and enumeration no brainpool group, so a server accepting only those passed `refuses-classical-only` and
  read as not exposed. The probe now offers every classical TLS 1.3 group OpenSSL 3.5 implements, the TLS 1.2
  brainpool curves and the legacy TLS 1.2 curves the probe OpenSSL accepts; enumeration offers the brainpool
  groups. A FIPS-mode client adds FFDHE 4096 to 8192 and P-224. A client OpenSSL that lacks some names (3.0
  and 3.1: the brainpool TLS 1.3 groups) offers the rest, X25519 and X448 included, instead of falling back to
  the FIPS subset. Enumeration records a TLS 1.3 FFDHE group from the DH size.
- Ruleset 1.0.4 (details and sources in [CORRECTIONS.md](CORRECTIONS.md)): pre-standard Kyber, Dilithium,
  SPHINCS+ and the FIPS 203/204/205 initial public drafts are no longer read as the standards; SLH-DSA is
  recognized in its prefixed and pre-hash spellings and only for FIPS 205 parameter sets; no post-quantum name
  can fall through to the classical DSA token; PSK and SRP suites are judged by every component (SRP is a
  quantum-vulnerable key exchange); ML-KEM hybrids and composite ML-DSA signatures are judged as hybrids,
  not by their post-quantum half alone; nonsense parameter sets such as `mlkem10240` are unknown; FN-DSA in
  every variant is FN-DSA, not DSA; RSA-SHA1, rsa_pkcs1_sha1, ecdsa_sha1 and RSA-MD5 are Critical; SSH
  group-exchange and certificate host-key names keep the observed key size; brainpool group names are ECDH
  key exchange and are in the verdict table; the scan's placeholder names sit in their lane.
- README: examples pinned 1.0.0 (now 1.4.0); the SLH-DSA release ledger is planned without a version; the
  stale known limit that the hosted quick check does not read the verdict table is removed.

### Changed
- The release workflow tells fedlin.com that a new verdict table is published (a POST to `/api/pqc-scan/` with a
  shared secret). fedlin.com/scan and the MCP hub then judge with the new ruleset; if the call fails they keep
  their last good table. Pre-releases do not trigger it.

## [1.3.0] - 2026-11-16

### Added
- Business context (`scripts/context.py`, schema `schemas/context-1.0.schema.json`, `--context` on the pipeline
  and report): systems with owner, FIPS 199 impact, data confidentiality lifetime, migration time and
  endpoint patterns. The report adds an attention order (impact times worst finding, with owners) and, for
  endpoints exposed to harvest-now-decrypt-later recording (including classical key exchange the server
  accepts), a Mosca urgency flag against a planning horizon (default 2035; a policy date, not a forecast;
  overridable). Exposure and urgency are never claimed where the scan could not see. Verdicts and priorities
  are unchanged; a missing migration time is never assumed. The ranking is written as `<out>.attention.json`
  (`fedlin.pqc-attention` 1.0) and `summary.json` gains `attention`.

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

[Unreleased]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v1.5.2...HEAD
[1.5.2]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v1.4.1...v1.5.0
[1.4.1]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/fedlinllc/fedlin-pqc-toolkit/compare/v0.8.0...v1.0.0
