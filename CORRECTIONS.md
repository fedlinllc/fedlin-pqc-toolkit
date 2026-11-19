# Corrections log

Every change to a verdict, a cited date or a public claim is recorded here with the date, what was
wrong, what it is now, and the source that settled it. Verdicts come from `scripts/cnsa20_ruleset.py`;
each rule cites a source key defined in `SOURCES` in that file.

## 2026-11-19: ruleset 1.0.5 (newcomer pressure test of v1.4.1)

| Identifier | Was (1.0.4) | Now (1.0.5) | Source |
|---|---|---|---|
| TLS and SSL cipher suites (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `ECDHE-RSA-AES256-GCM-SHA384`, ...) and OpenSSH ciphers named `@openssh.com` | NIST SP 800-53 controls included SC-28 (protection of information at rest), taken from the bare cipher | SC-8 (transmission confidentiality and integrity) in place of SC-28; SC-12, SC-13 and SC-17 unchanged. Status, priority and targets unchanged. A bare cipher name (`AES-256-GCM`) keeps SC-28 | NIST SP 800-53 Rev. 5 (SC-8, SC-28) |

Only the control mapping changed, so scores and verdicts are the same as under 1.0.4.

## 2026-11-16: ruleset 1.0.4 (pressure test of v1.3.0)

| Identifier | Was (1.0.3) | Now (1.0.4) | Source |
|---|---|---|---|
| `kyber512`, `kyber768`, `kyber1024`, `kyber`, Kyber hybrids such as `p256_kyber768` | Read as ML-KEM (`kyber1024` compliant under nss); `p256_kyber768` as an EC key, High | Pre-standard Kyber: quantum-resistant, not FIPS 203, transitional (Low) under both profiles, as `X25519Kyber768Draft00` already was | FIPS203 (Appendix C, differences from the CRYSTALS-KYBER submission) |
| `dilithium2`, `dilithium3`, `dilithium5`, `dilithium` | Read as ML-DSA (`dilithium5` compliant under nss) | Pre-standard Dilithium: not FIPS 204, transitional (Low) | FIPS204 (Appendix D, differences from the CRYSTALS-DILITHIUM submission) |
| SPHINCS+ names (`SPHINCS+-Haraka-128f-robust`, `SPHINCS+-SHA2-128s-simple`, `sphincsplus`) | SLH-DSA, compliant (civilian) | Pre-standard SPHINCS+: not FIPS 205, transitional (Low) | FIPS205 (Section 11 and Appendix A: only the simple SHA2 and SHAKE parameter sets are approved) |
| Any name containing "slh" (e.g. `english-slh`, `xslh-dsa-128s`) | SLH-DSA, compliant (civilian) | Unknown (Manual review) unless "SLH-DSA" stands as its own word | FIPS205 |
| SLH-DSA names with a prefix (`id-alg-slh-dsa-sha2-128s`, `CKM_SLH_DSA`, `CKK_SLH_DSA`, `OpenSSL SLH-DSA-SHA2-128s`) or a pure / pre-hash suffix (`-pure`, `:prehash`, HashSLH-DSA such as `SLH-DSA-SHA2-128s-SHA512` or `...-with-SHA256`, with a FIPS-approved hash or XOF) | SLH-DSA, compliant (civilian) | Unchanged: SLH-DSA | FIPS205 (Sections 10.2 and 11) |
| `SLH-DSA-SHA2-128`, `SLH-DSA-SHAKE-256` and other names with a security category but no `s`/`f` | `slh-dsa` | `slh-dsa-128` / `slh-dsa-256` (the category is kept; same status) | FIPS205 |
| SLH-DSA names with any other suffix (`SLH-DSA-SHA2-128s-v2`, a pre-hash with MD5 or SHA-1) | SLH-DSA, compliant (civilian) | Unknown (Manual review): not a FIPS 205 parameter set or pre-hash | FIPS205 |
| Names marked as the 2023 initial public drafts (`ML-KEM-1024-ipd`, `MLKEM1024-IPD`, `ML-DSA-65-ipd`, `SLH-DSA-...-ipd`) | The final standard's verdict (e.g. ML-KEM-1024 compliant under nss) | Pre-standard: quantum-resistant, not FIPS 203/204/205, transitional (Low) under both profiles | FIPS203 (Appendix C.2), FIPS204 (Appendix D.3), FIPS205 (Appendix A.1) |
| Composite signatures (`MLDSA87-ECDSA-P384-SHA512`, `MLDSA87-Ed448`, `MLDSA65-RSA3072-PSS-SHA512`, ...) | Pure ML-DSA (the classical half dropped) | Judged as composites, like the ML-KEM hybrids: compliant under civilian as far as the ML-DSA half is; under nss only ML-DSA-87 with ECDSA P-384 or RSA of at least 3072 bits (so `MLDSA87-Ed448` and the brainpool composite become transitional); marked pre-standard (an Internet-Draft) | LAMPS-COMPOSITE, FIPS204, CNSA2 |
| Composite and HashML-DSA names with a SHA-1 or MD5 hash (`MLDSA87-ECDSA-P384-SHA1`, `id-hash-ml-dsa-65-with-sha1`), and names where "rsa" is only part of a word (`ML-DSA-87 universal`) | Judged by the ML-DSA part alone (compliant, under nss too for ML-DSA-87); the word read as an RSA half | SHA-1/MD5: Unknown (Manual review); FIPS 204 pre-hashing and the composite draft need an approved hash. "rsa" counts only where it starts a word | FIPS204, LAMPS-COMPOSITE, IR8547 |
| Any name with an ML-KEM, ML-DSA or SLH-DSA token that is not a recognized form (e.g. `mldsa870-dsa`, `slh-dsa-x`) | Could reach the "dsa" family token (DSA, Critical) | Unknown (Manual review): a post-quantum name never falls through to a classical token | FIPS203, FIPS204, FIPS205 |
| `PSK-AES256-CBC-SHA` and other PSK suites | Judged by the cipher alone (compliant under nss); `DHE-PSK-*` / `RSA-PSK-*` with ARIA or Camellia transitional | Every component: HMAC-SHA-1 makes `PSK-AES256-CBC-SHA` transitional under nss; DHE, ECDHE and RSA key transport in PSK suites are quantum-vulnerable (High) | CNSA2, SP800-131A, IR8547 |
| `SRP-AES-256-CBC-SHA` and other SRP suites | Judged by the cipher alone (compliant) | SRP key exchange (RFC 5054, over a finite-field Diffie-Hellman group): quantum-vulnerable, High | RFC5054, IR8547 (Table 4) |
| `X25519MLKEM1024`, `SecP256r1MLKEM1024`, `secp256r1_mlkem1024`, `p521_mlkem1024`, `mlkem1024x448-sha512` | Pure ML-KEM-1024, compliant under nss (the classical half was dropped) | A hybrid: quantum-resistant, compliant under civilian; under nss compliant only for the registered P-384 pairings (`SecP384r1MLKEM1024`, `mlkem1024nistp384-sha384`), as `X448MLKEM1024` already was | FIPS203, CNSA2, TLS-MLKEM |
| `mlkem10240`, `MLKEM768-1024`, `mldsa870` | ML-KEM-1024 / ML-KEM-768 / ML-DSA-87, compliant | Unknown (Manual review): a parameter set must end where the name says it does | FIPS203, FIPS204 |
| `FN-DSA-512`, `FN-DSA-1024`, `id-fn-dsa-512`, `FN-DSA-1024-padded`, `fn-dsa-512-prehash`; Falcon hybrids such as `p256_falcon512` | DSA, Critical (the "dsa" token); the hybrids EC, High | FN-DSA, as `Falcon-512` already was: quantum-resistant, standard not final, transitional (Low) | FN-DSA |
| `RSA-SHA1`, `rsa-sha1`, `rsa_pkcs1_sha1`, `ecdsa_sha1`, `RSA-MD5` | High (the hash was dropped) | Critical: SHA-1 and MD5 signatures are disallowed, as `sha1WithRSAEncryption` and `ecdsa-with-SHA1` already were | SP800-131A |
| `diffie-hellman-group-exchange-sha256`, `rsa-sha2-512-cert-v01@openssh.com` and other SSH names with an observed size | The observed size was dropped: 1024 bits read High | The observed size counts: below 2048 bits is Critical, as plain `rsa-sha2-512` already was | SP800-57, SP800-131A, RFC9142 |
| `brainpoolP256r1tls13`, `brainpoolP384r1tls13`, `brainpoolP512r1tls13` | Not in the verdict table (unknown to consumers) | TLS 1.3 key-exchange groups: ECDH, quantum-vulnerable, High (non-NIST curve noted) | IR8547 |
| `brainpoolP256r1`, `brainpoolP384r1`, `brainpoolP512r1` (TLS 1.2 groups, and OpenSSL's name for the TLS 1.3 key exchange) | EC public key, public-key lane | ECDH key exchange, key-establishment lane; still quantum-vulnerable, High. Brainpool names now carry standard status non-NIST | IR8547 |
| `unparsed-kex-group`, `unparsed-public-key-algorithm` (names the scan writes for what it saw but could not read) | Unknown, no lane | Unknown (Manual review) in the key-establishment / public-key lane, so a check of that lane counts them | n/a |

FN-DSA stays transitional because FIPS 206 is not final; when it is, its verdict will change here with that source.

## 2026-11-15: ruleset 1.0.3 (pressure test and competitive benchmark)

| Identifier | Was (1.0.2) | Now (1.0.3) | Source |
|---|---|---|---|
| RSA signature names (`sha256WithRSAEncryption`, `RSASSA-PSS`, `rsa-sha2-256`, ...) | Public-key encryption, public-key lane, target "ML-KEM / ML-DSA" | Signature, signature lane, target ML-DSA or SLH-DSA (civilian) / ML-DSA-87 (nss); quantum-vulnerable, High, unchanged | FIPS204, FIPS205, CNSA2 |
| RSA, DSA, DH below 2048 bits; EC below 224 bits | Note said "broken today" | Note says below 112-bit security and disallowed by SP 800-131A; status unchanged (Critical) | SP800-57, SP800-131A |
| Anonymous (`ADH-*`, `AECDH-*`, `TLS_DH_anon_*`) and NULL-encryption suites (`*-NULL-*`) | Read as their cipher (compliant) or key exchange (High), some unclassified | Broken, Critical: no server authentication or no encryption | n/a |
| LMS, XMSS | Note named firmware/code signing for LMS only | Both notes state CNSA 2.0 approves them for software and firmware signing only; verdict unchanged | CNSA2 |

Report appendix: the status column now uses the policy result's words (compliant, transitional, vulnerable,
broken, review). It showed TLS 1.2 as "resistant" while the policy result said "transitional".

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

## 2026-11-15: ruleset 1.0.1 and report corrections (adversarial review of the public tree)

- **SSH ML-KEM hybrids over NIST curves.** Was: `mlkem1024nistp384-sha384` and `mlkem768nistp256-sha256`
  classified as quantum-vulnerable EC (High), and under `nss` told to migrate to ML-KEM-1024, the
  algorithm already in use. Now: quantum-resistant hybrids; `mlkem1024nistp384-sha384` is compliant under
  both profiles, `mlkem768nistp256-sha256` under `civilian`. Any other ML-KEM hybrid name is judged by
  its ML-KEM component, never by its classical half. `X448MLKEM1024` is named as a hybrid.
- **Static-RSA TLS suites.** Was: OpenSSL suite names with RSA key transport (`AES256-SHA`,
  `AES128-GCM-SHA256`) were read as plain AES and scored compliant. Now: RSA key transport with no
  forward secrecy, quantum-vulnerable (High) in the key-establishment lane; the TLS interface records
  `keyExchange` = RSA. `DES-CBC3-SHA` is 3DES, not DES. Suite suffix `SHA` is recorded as HMAC-SHA-1.
- **Unobserved key exchange.** Was: a scan that could not observe key exchange (FIPS host without the
  probe image) scored only the certificates and could print 0/100, grade F, "almost entirely
  quantum-vulnerable", for a site negotiating X25519MLKEM768. Now: the report is marked Incomplete,
  says how many endpoints were unobserved, and gives no letter grade.
- **Regulatory text in the report.** Was: credited NSM-10 with the 2030/2031 deadlines; said M-26-15
  supersedes M-23-02; listed SLH-DSA in CNSA 2.0 and called CNSA 2.0 "cited in every target" under the
  civilian profile; called every input CBOM "schema-validated". Now: deadlines attributed to EO 14412
  and OMB M-26-15 (NSM-10 only defines high-impact system); no supersession claim; CNSA 2.0 listed as
  ML-KEM-1024, ML-DSA-87, LMS/XMSS, AES-256, SHA-384/512; "schema-validated" removed.
- **Access and supply-chain claims.** Was: README said the toolkit never reads a private key or secret
  value, and that every download is pinned. Now: an "Access by mode" table states what each mode reads
  and the privilege it needs; the SealedSecrets key is marked inferred. `--deep` on non-OpenShift no
  longer defaults to an unpinned `busybox` (`--debug-image` required); the npm fallback for pnpm checks
  the tarball's sha512; the toolkit image runs as an unprivileged user; podman is optional in setup.

## 2026-11-15: ruleset 1.0.2

- **ChaCha20-Poly1305 (civilian):** was compliant; now not compliant. The civilian profile is FIPS-based,
  and ChaCha20 is not a FIPS 140-3 approved security function (SP 800-140C). It stays quantum-resistant
  (256-bit key) and does not affect the readiness score. Target: AES-GCM. Matches how ARIA, Camellia,
  SEED and SM4 were already judged.
- **SHA-512/256:** was read as SHA-512 and marked CNSA 2.0 approved. It has a 256-bit output (128-bit
  collision strength); CNSA 2.0 requires SHA-384 or SHA-512. Now its own rule: compliant (civilian), not
  compliant (nss). SHA-512/224 added (same treatment as SHA-224).
- **SHA-1 retirement:** NIST SP 800-131A Rev. 3 initial public draft (October 2024; still a draft)
  proposes, in Table 14, deprecating HMAC generation with SHA-1, SHA-224, SHA-512/224 and SHA3-224 through
  2030 and disallowing it after 2030, and in Table 12 the same for applying protection with those hashes.
  Verdicts are unchanged because Rev. 2 is the final text; notes and civilian targets now state the
  proposed 2030 date. Source key `SP800-131A-R3-IPD` (draft PDF sha256
  5ffdb907e0e2375901151579422a370b655e131223a2588ea418c5df1dea6e7f, fetched 2026-11-15).
- **Recognition:** OpenSSH MACs `hmac-sha2-256[-etm]` and `hmac-sha2-512[-etm]` are judged by their hash
  (as `hmac-sha256` already was); `umac-64/128[-etm]` are UMAC, not FIPS-approved. `aria128-gcm` and
  `camellia256` resolve to ARIA and Camellia. All were previously "unrecognized, flag for review".

## 2026-11-15: hardware collector validation claims

The collectors' action text is written into the CBOM, which records facts only. Several statements were
stale or unsourced:

- **"Currently one product meets this bar: Thales TCT Luna T7 (CMVP #5450)"** for ML-KEM key establishment.
  The CMVP snapshot of 2026-11-15 shows other active certificates approving ML-KEM, including software
  modules (for example the OpenSSL FIPS Provider, #5586, validated 2026-11-13). Removed.
- **"The FIPS 140-3 validated PQC OpenSSL provider is expected in 2026-2027."** Superseded by #5586. Removed.
- **"PQC key establishment (ML-KEM-1024) requires a FIPS 140-3 CMVP-validated HSM."** Software modules can be
  validated for ML-KEM. Removed.
- **Vendor and distribution timelines** ("expected 2027-2028", RHEL 10 / Ubuntu default-provider statements)
  had no cited source. Removed.
- **TPM "FIPS 140-2 validated (TPM 2.0 profile)".** Validation is per product, and FIPS 140-2 certificates
  are no longer active. Now "not determined by this collector".

Validation status now comes only from the report's CMVP section (`scripts/cmvp.py`, dated snapshot).

## 2026-11-15: security levels invented by the CBOM merge

- **Was:** when a scan merged other inputs (`--merge-cbom`, `--repo`, `--theia-dir`, `--theia-image`), the
  final CBOM could carry `classicalSecurityLevel: 0` on algorithms whose classical strength the toolkit does
  not record (seen on X25519MLKEM768 and ecdsa-with-SHA256), and `nistQuantumSecurityLevel: 0` on the TLS
  protocol-version asset. These values were not observed: cyclonedx-cli writes 0 for absent integer fields
  when it merges. In CycloneDX, 0 states no classical security and quantum vulnerability.
- **Now:** after merging, any security level that the component's original input did not carry is removed.
  Values the toolkit did record (for example `nistQuantumSecurityLevel: 0` on a quantum-vulnerable key) stay.
  Endpoint-only scans without merged inputs were not affected. Verdicts and scores were not affected: they
  come from the ruleset, not from these fields.
- **Found by:** the PQCMM evidence check of inventory completeness (question 3.2.2), run against a merged CBOM.

