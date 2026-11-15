# Corrections log

Every change to a verdict, a cited date or a public claim is recorded here with the date, what was
wrong, what it is now, and the source that settled it. Verdicts come from `scripts/cnsa20_ruleset.py`;
each rule cites a source key defined in `SOURCES` in that file.

## 2026-11-14: ruleset 1.0.0 (replaces 0.2)

Found by running real-world identifiers through `classify()` (now `tests/test_ruleset.py`).

| Identifier | Was (0.2) | Now (1.0.0) | Source |
|---|---|---|---|
| `curve25519-sha256` (OpenSSH default key exchange) | Hash, not quantum-vulnerable, Low | X25519 key exchange, quantum-vulnerable, High | IR8547 |
| `sntrup761x25519-sha512` (OpenSSH PQ hybrid) | Quantum-vulnerable, High | Quantum-resistant, not NIST-standardized, Low | SSH-SNTRUP |
| ML-KEM-512, ML-DSA-44, ML-DSA-65, SLH-DSA-128s | NIST Category 5, CNSA-compliant | Their real categories (1/2/3/1); compliant under `civilian`, not under `nss` | FIPS203, FIPS204, FIPS205, CNSA2 |
| Falcon-512 / FN-DSA | Category 5, compliant | Quantum-resistant; standard not final, Low | FN-DSA |
| `X25519Kyber768Draft00` | Category 5, CNSA-compliant | Pre-standard codepoint, Low (replace with X25519MLKEM768) | TLS-KYBER-DRAFT |
| `id-ecPublicKey` (every EC certificate key) | Manual review | Quantum-vulnerable, High | IR8547 |
| RSA/DSA/DH below 2048 bits, EC below 224 bits | High | Classically broken, Critical | SP800-57, SP800-131A |
| DSA at any size | High | Critical (not approved for signature generation) | FIPS186-5 |
| `ssh-rsa` (RSA with SHA-1 signatures) | High | Critical | OPENSSH-RSA-SHA1 |
| `diffie-hellman-group14-sha1` | High | Critical (SHA-1 key exchange) | RFC9142 |
| ECMQV, ElGamal, brainpool, secp256k1 | Manual review | Quantum-vulnerable, High | IR8547 |
| Names containing "idea"/"des" as substrings (e.g. `ideal-mode`) | Critical (false positive) | Not matched (token-bounded matching) | n/a |
| TLS 1.2 cipher suites | One verdict (first match) | Split into key exchange, authentication, cipher, MAC; worst wins | n/a |
| HMAC-SHA1 | Critical | Acceptable for HMAC, None (civilian) / Low (nss) | SP800-131A |
| TLS 1.0 / 1.1 | Manual review | Critical | RFC8996 |
| `rsa-sha2-512` | n/a | High (hash size is not read as a 512-bit key) | n/a |

## 2026-11-14: NIST IR 8547 is final (27 Oct 2026)

- **Was:** dates and wording followed the November 2024 initial public draft.
- **Now:** the final report (Tables 2 and 4) deprecates *every* quantum-vulnerable signature and
  key-establishment scheme after 2030 and disallows them after 2035, at any security strength.
  High value assets and high impact systems face the earlier EO 14412 deadlines (key establishment by
  2030-12-31, signatures by 2031-12-31).
- **EdDSA:** an internal note said IR 8547 left EdDSA acceptable through 2035. The final text lists
  EdDSA in Table 2 with ECDSA and RSA (deprecated after 2030, disallowed after 2035). Corrected in the
  ruleset and README.
- **Source:** https://csrc.nist.gov/pubs/ir/8547/final (PDF sha256
  3049cdfdd7c20417cf588a3d55ace6e8813982d1499502b7ef69e9593b2dc280, retrieved 2026-11-14).

## 2026-11-14: endpoint capture

- `capture_cert` no longer defaults an unparsed public-key algorithm to `rsaEncryption`; it reports
  `unparsed-public-key-algorithm` (Manual review). The old default reported RSA that was never observed.
- TLS assets record the negotiated protocol version and cipher suite. Before, every TLS asset was
  labelled version 1.3 regardless of what was negotiated.

## 2026-11-14: readiness score reworked

- **Was:** score = distinct algorithm *types* rated resistant ÷ (resistant + vulnerable types), across
  every lane. 500 RSA certificates and one AES-256 cipher scored 50/100, and recording TLS 1.3 and an
  AES-256 cipher lifted fedlin.com from 0 to 50 although no PQC key exchange was observed.
- **Now:** score = profile-compliant quantum-resistant **public-key usages** ÷ (compliant +
  quantum-vulnerable public-key usages). A usage is one reference from an asset (a certificate's key or
  signature, a TLS session's key exchange, an offered SSH algorithm). Symmetric, hash, KDF and
  protocol-version usages are reported per lane and do not move the score. Compliance follows the
  CBOM's profile in both profiles (target starting "None"); resistant usages below the target are
  transitional and excluded from the denominator. It is FEDLIN's score, not a PQCMM level.
- **Wording:** "safe" is replaced by "resistant" / "quantum-resistant" in all output. `summary.json`
  key `quantum_safe` is now `quantum_resistant` (breaking change for any consumer of that key).
- **Delta:** warns when baseline and current CBOMs were built with different profiles.
- **Merged assets:** digits inside a merged algorithm name (e.g. `SHA256-RSA`) are no longer read as a
  key size; only a numeric `parameterSetIdentifier` is.
- **Report text:** IR 8547 cited as final (October 2026), not as a draft; targets labelled "Migration
  target" rather than "CNSA 2.0 target" so the civilian profile is not mislabelled.

## 2026-11-14: verdicts moved out of the CBOM

- **Was:** every algorithm component carried verdict properties (`cnsa2:quantum_vulnerable`,
  `cnsa2:target`, `cnsa2:priority`, `crosswalk:*`). A CBOM written once kept those verdicts after the
  guidance moved, so it looked authoritative while going stale.
- **Now:** the CBOM records facts only (algorithm identity, parameter set, NIST category, classical
  strength, certificates, protocol sessions). Verdicts are in `<out>.policy.json`, a
  `pkic.cbom.policy-result` 0.1 document naming the ruleset, its version and SHA-256, the profile, the
  evaluation date, and the CBOM by SHA-256 digest. Re-evaluating the same CBOM under a later ruleset
  gives a new, dated result without changing the CBOM. Follows PKI Consortium CBOM methodology decision
  0002 (github.com/pkic/cbom, MIT).
- **Sealed-secrets key:** its fixed `Critical` mark is now a policy rule (material exposed to
  harvest-now-decrypt-later and wrapped by a quantum-vulnerable algorithm is Critical).
- **Delta:** both snapshots are judged by the current ruleset under one profile, so score movement
  reflects the estate rather than a rules change.
- **Signing:** the attestation covers the policy result as well as the CBOM and report.
- **Legacy CBOMs** with inline verdicts are still read; the pipeline strips inline verdicts from merged
  inputs.

## 2026-11-14: CBOM shaped to the PKI Consortium interface profiles

- **Was:** no declared subject, coverage or lifecycle stage; TLS sessions were bare protocol assets;
  every CBOM said `"type": "platform"` with nothing about what kind of record it was.
- **Now:** `metadata.component` declares `subjectType=deployment`, `coverage=partial` (a scan covers
  only what it was pointed at) and an RFC 4151 tag URI (`--subject-tag`; the default authority is the
  system name when it is a DNS name, else `pqc-toolkit.invalid`). `metadata.lifecycles` is `discovery`
  (observed) for live scans and `build` for source-only scans. Each TLS endpoint is a `service`
  interface carrying protocol, version, key exchange, encryption, authentication, two endpoint roles
  and `observationMethod=active-probe`; what was not observed is declared `unknown`.
- **SSH:** `sshd -T` output is configuration, not an observation, so it is kept as configuration
  evidence and not presented as an interface (one stage per document).
- **Not yet:** algorithm values are the observed names, not CycloneDX cryptography-registry
  identifiers; no SBOM link or VEX reference (baseline R1/R2); `implementationPurl` declared unknown.

## 2026-11-15: PKIC validator run; key-exchange probe fixed

- **Conformance:** the vendored PKI Consortium validator (pkic/cbom 65a6f42) returns **CONFORMS** for
  the entry profile `interface-enumeration` v0.3 on a live scan of fedlin.com and on an offline CBOM
  built in the tests (CycloneDX 1.6, flagged legacy). Against the baseline `interface-disclosure` v0.9
  the remaining MUST failures are `implementationPurl` (an outside scan cannot know the server's
  software) and `keyExchange` when the probe could not observe it. `tests/test_pkic_conformance.py`
  runs the validator on every test run.
- **P2:** an outside scan now states `managementInterfaceAbsence=not-reached`, which the profile
  accepts for an observed record with partial coverage.
- **Key-exchange parsing:** OpenSSL 3.5 reports classical groups as `Peer Temp Key: ECDH, prime256v1`;
  the parser only matched `Server Temp Key`, so classical key exchange was never recorded. Both forms
  are parsed now.
- **FIPS scan hosts:** OpenSSL in FIPS mode refuses any offer containing X25519MLKEM768, so the probe
  learned nothing. It now retries with the FIPS-offerable groups (SecP256r1MLKEM768,
  SecP384r1MLKEM1024, P-256/384/521). A PQC hybrid accepted that way is recorded; a classical result
  is not, because it says nothing about X25519MLKEM768. It is kept as `fedlin:kex_partial_evidence`
  and the interface's key exchange stays `unknown`.
- **Probe image:** the container probe no longer runs `apk add openssl` (an unpinned install at run
  time). `FEDLIN_KEX_PROBE_IMAGE` must name a digest-pinned image that already ships OpenSSL >= 3.5.

## 2026-11-15: key-exchange probe image

- `images/kex-probe/Containerfile`: Alpine 3.22 pinned by digest plus `openssl=3.5.9-r0`, built by
  `setup.sh` as `localhost/fedlin-kex-probe:0.1` (image ID in `toolkit.lock`). The pipeline uses it by
  default when the host OpenSSL refuses the full offer (FIPS mode), and never pulls it.
- With it, a FIPS scan host observes X25519MLKEM768 on fedlin.com, www.fedlin.com, cloudflare.com and
  google.com. fedlin.com moves from 0/100 to 33/100 (2 compliant key-exchange usages, 4
  quantum-vulnerable certificate usages). The baseline PKIC profile's only remaining failure is
  `implementationPurl`, which an outside scan cannot know.
- The report's "Kex probe" line now states which path ran (host full offer, container full offer, or
  FIPS reduced offer) instead of the outdated "skipped" wording.

## 2026-11-15: CycloneDX cryptography-registry names

- **Was:** interface values (key exchange, encryption, authentication) were the observed names
  (`id-ecPublicKey`, `ecdsa-with-SHA256`), which the PKIC profiles' identifier scheme
  (`cyclonedx-cryptography-registry`) does not recognize.
- **Now:** `registry_name()` maps observed identifiers to CycloneDX cryptography-registry names where
  the mapping is unambiguous (e.g. `ECDSA-secp256r1-SHA-256`, `RSA-PKCS1-1.5-SHA-256`, `ECDHE-secp256r1`,
  `X25519MLKEM768`, `AES-256-GCM`, `ML-DSA-65`). Interface values use them, and every algorithm component
  carries `fedlin:registry_family` / `fedlin:registry_name` (CycloneDX 1.6 has no native field).
  A bare RSA or EC key, OpenSSH's sntrup761 hybrid and TLS 1.2 suites get no registry name rather than
  an invented one. Registry vendored in `third_party/cyclonedx` (CycloneDX/specification 76f185c,
  Apache-2.0); `tests/test_registry.py` checks every emitted name against its patterns.

## 2026-11-15: downloads pinned and verified

- **Was:** `setup.sh` and the Containerfile fetched cyclonedx-cli from `releases/latest` with no
  checksum, built on `ubi9/nodejs-22-minimal:latest` and `golang:1.26-alpine` by tag, pulled `oc` from
  the `stable` channel, installed `pnpm@10` (floating), and fell back to an unfrozen `pnpm install` if
  the frozen install failed. `toolkit.lock` described versions the build did not enforce.
- **Now:** cyclonedx-cli v0.32.0 by URL and SHA-256 (matches GitHub's asset digest); `oc` 4.22.0 by
  URL and SHA-256 (from the mirror's `sha256sum.txt`); both base images by digest; pnpm 10.34.9 pinned
  in `package.json` `packageManager` with its sha512 (corepack verifies it); installs are
  `--frozen-lockfile` only. A checksum mismatch aborts setup or the image build.
