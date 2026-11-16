# fedlin-pqc-toolkit

Find the cryptography a system uses, record it as a CycloneDX CBOM, and judge it against NIST's
post-quantum transition. Built for teams that have to show a customer, an auditor or a federal buyer
what cryptography they run and how they plan to migrate it.

- **Inventory:** live TLS endpoints, Kubernetes/OpenShift routes and ingresses, local SSH
  configuration, source repositories (via cdxgen and cbomkit-theia), Windows certificate stores and
  AD CS, and TPM/HSM presence.
- **CBOM of facts:** a CycloneDX 1.6 CBOM that records what was observed and nothing more. It conforms
  to the PKI Consortium CBOM entry profile (`interface-enumeration` v0.3) and uses CycloneDX
  cryptography-registry names.
- **Verdicts, kept separate:** a policy result bound to the CBOM by SHA-256 digest, under one of two
  profiles: `civilian` (NIST FIPS 203/204/205 and NIST IR 8547) or `nss` (NSA CNSA 2.0).
- **Report:** a readiness score, the quantum-vulnerable algorithms with their standard migration
  targets, NIST SP 800-53 controls with an optional regime crosswalk, certificate renewal exposure,
  and transport posture.

What each mode can read is set out under [Access by mode](#access-by-mode).

## What has been validated, and how

Every input below exists in the code. This table says how far each one has been exercised outside unit
tests, so you know what you are relying on. The unit and conformance tests run on every commit.

| Input | Validation | Date |
|---|---|---|
| Live TLS endpoints, incl. ML-KEM hybrid detection and the classical-fallback probe | Public endpoints (own hosts, a large CDN, and public TLS test hosts); every fallback outcome checked against a live or purpose-built server | 2026-11-15 |
| Endpoint enumeration (accepted versions, suites, groups, DH sizes, each certificate type) | Same public endpoints, compared with testssl.sh, sslyze and five other open tools run side by side | 2026-11-15 |
| FIPS-mode scan host (RHEL 9) with the probe image | RHEL 9.8 in FIPS mode, on a lab host and on a VM in Azure | 2026-07-12, 2026-11-15 |
| OpenShift routes, TLS secret counts, `--deep` FIPS checks | FEDLIN's own FIPS-mode OpenShift lab cluster | 2026-07-08 |
| Kubernetes Ingress (non-OpenShift) | Code path reviewed; not yet run against a non-OpenShift cluster | not yet run |
| Local SSH posture (`sshd -T`) | Lab host: host keys, key exchange (incl. ML-KEM hybrid) and ciphers checked against expected verdicts | 2026-07-12 |
| Certificates and keys in files (`--theia-dir`) | Lab bank of 14 test certificates, incl. ML-DSA and SLH-DSA | 2026-07-12 |
| Dependency libraries (`--repo`, cdxgen) | Unit and end-to-end tests on fixtures | tests only |
| `--merge-cbom` with cyclonedx-cli | Toolkit container image, real cyclonedx-cli | 2026-11-15 |
| Linux hardware posture (OS, TPM, HSM) | RHEL CoreOS 9.8 node of the lab cluster | 2026-07-31 |
| Windows certificate stores, AD CS, hardware posture | Windows Server 2025 VM in Azure: 9/9 hardware and 1/1 AD CS checks passed; a full Windows CBOM has not yet been run end to end through the policy stage | 2026-07-31 |
| Local MCP server | Protocol, boundary and tamper tests; not yet certified against specific agent clients | tests only |

Not covered at all: AWS and GCP services (planned), Azure services such as Key Vault, IPsec/VPN,
Kerberos, code signing, database encryption at rest.

## Quick start: scan your TLS endpoints

No cluster and no source code needed.

```bash
./setup.sh                     # fetch pinned tools (checksums verified) and build the probe image
python3 scripts/tier2_pipeline.py --no-runtime \
  --endpoints example.com,api.example.com \
  --name example.com --report --out out/cbom.json
```

Outputs:

| File | What it is |
|---|---|
| `out/cbom.json` | CycloneDX 1.6 CBOM: facts only |
| `out/cbom.policy.json` | Verdicts in the `pkic.cbom.policy-result` 0.1 format, bound to the CBOM by SHA-256 |
| `out/cbom.report.md` | Readiness report |
| `out/cbom.summary.json` | Machine-readable summary |
| `out/cbom.json.runtime.json` | The capture before merging (an intermediate; `--redact` removes intermediates) |

Check that a policy result can be trusted for a CBOM (the CBOM digest matches, the result names this toolkit's ruleset, and re-evaluating reproduces every verdict): `python3 scripts/policy.py verify --cbom out/cbom.json --policy out/cbom.policy.json`. The report and the MCP server use a policy result only when it passes; otherwise they evaluate the CBOM again.

Or use the published container image, with nothing to install (pin it by the digest in the release notes):

```bash
mkdir -p out
podman run --rm --userns=keep-id --user "$(id -u):$(id -g)" -v "$PWD/out:/out:Z" \
  ghcr.io/fedlinllc/fedlin-pqc-toolkit:1.0.0 \
  --no-runtime --endpoints example.com --name example.com --report --out /out/cbom.json
# Docker: docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/out:/out" ghcr.io/fedlinllc/fedlin-pqc-toolkit:1.0.0 ...
```

## Verify a release

From 1.0.0, every release is built by the [release workflow](.github/workflows/release.yml) from its tag,
and every file and the image carry Sigstore-signed SLSA build provenance that names the workflow and commit
(releases before 1.0.0 are tags only):

```bash
gh attestation verify fedlin-pqc-toolkit-1.0.0.tar.gz --repo fedlinllc/fedlin-pqc-toolkit
gh attestation verify oci://ghcr.io/fedlinllc/fedlin-pqc-toolkit:1.0.0 --repo fedlinllc/fedlin-pqc-toolkit
sha256sum -c --ignore-missing SHA256SUMS   # checks the files you downloaded
```

Each release also carries an SBOM of the toolkit (`*.sbom.cdx.json`), the provenance bundle
(`*.intoto.jsonl`) and the verdict table (`verdicts.json`). These signatures use classical algorithms,
because Sigstore does not yet support post-quantum signatures; a post-quantum (SLH-DSA, FIPS 205)
release ledger is planned for 1.1.

## What an endpoint scan records

For each endpoint the scan records the session a modern client negotiates (protocol version, cipher suite,
key-exchange group, certificate), and then enumerates what the server **accepts**, one handshake at a time:

- TLS 1.0 to 1.3 (SSLv3 is not tested). A version counts as refused only when the server sends a
  protocol-version alert; no answer, or a failure that comes from the client, is recorded as not tested;
- the cipher suites of each version (TLS 1.3 suites one by one; for TLS 1.0 to 1.2 the client offers all
  suites and removes each one the server picks until it refuses, up to 40 per version; a list cut short by
  a timeout is marked partial);
- the key-exchange groups in the probe list: hybrid and pure ML-KEM, X25519, X448, NIST curves and FFDHE,
  in TLS 1.3 and (for classical groups) TLS 1.2. A group counts as accepted only when the server negotiated
  that group, and as refused only when the server sent a refusal alert; Diffie-Hellman group sizes are
  recorded too;
- one certificate per signature-scheme family (RSA, ECDSA, EdDSA, ML-DSA), so a server that presents an
  RSA certificate to some clients and an ECDSA one to others has both recorded;
- a classical-only handshake (see "Classical fallback" below).

Accepted versions, suites and groups are judged by the same ruleset and reported in **Server
configuration**: broken items (TLS 1.0/1.1, anonymous or NULL suites, small DH groups) are listed as top
exposures and static-RSA suites as lacking forward secrecy. They do not change the score. Certificates the
endpoint serves, including additional ones found by enumeration, are certificates in use and are scored.
An endpoint the host OpenSSL cannot reach (for example a FIPS-mode host and a TLS 1.0-only server) is
captured with the enumeration client instead of being dropped.

Enumeration takes about 10 to 20 seconds per endpoint (endpoints run in parallel) and uses the probe
OpenSSL (3.5), which does not implement 3DES, RC4 or export suites, so those are not tested; use
testssl.sh if you need them checked. `--no-enumerate` skips it, and `--enumerate-pace SECONDS` pauses
between handshakes for servers that rate-limit (a handshake that times out is recorded as not tested).

## How each record was observed

Every cryptographic record the toolkit writes says how it was found (a key algorithm it could not parse gets
only a location), as standard CycloneDX 1.6 component
evidence (`evidence.identity`: a technique and a confidence, plus `evidence.occurrences` for the endpoint):

| How observed | Technique | Confidence |
|---|---|---|
| Handshake with the endpoint (its session and certificate), or enumeration probe handshakes | `dynamic-analysis` | 1.0 |
| System configuration or certificate stores (`sshd -T`, Windows stores and SCHANNEL settings) | `other` | 0.8 |
| Parsed from a file or container image | `other` | 0.8 |
| Library in the dependency graph known to provide it (use not confirmed) | `manifest-analysis` | 0.3 |
| Assumed, not observed | `other` | 0.1 |

The confidence ranks how directly a record was observed; it is not a probability. The values are fixed and
listed in [STABILITY.md](STABILITY.md). A record seen several ways carries every method, and its confidence
is the highest. Evidence written by another tool, in a CBOM merged with `--merge-cbom`, is kept verbatim (unless two merged
inputs use the same bom-ref).
Evidence is a fact about the record: it does not change verdicts or the score. The report counts records by
how they were observed.

## Prove a migration wave

A wave file (`fedlin.pqc-wave` 1.0, [schema](schemas/wave-1.0.schema.json)) states what a migration wave
promises, per endpoint. After the work, scan again and check it:

```bash
python3 scripts/wave.py check --wave wave.json --cbom after/cbom.json --baseline before/cbom.json
# or in one step: python3 scripts/tier2_pipeline.py --endpoints ... --wave wave.json --baseline before/cbom.json
```

| Check | Passes when |
|---|---|
| `findings-resolved` | no finding with the given priorities remains at the endpoint (only in the given lanes, if any) |
| `mlkem` | the recorded session negotiated an ML-KEM group meeting the profile (nss: ML-KEM-1024); with `"mode": "accepts"`, or the server accepts one |
| `refuses-classical-only` | a client offering only classical key exchange was refused |
| `certificate-replaced` | the endpoint no longer serves the baseline certificate and, if named, a served certificate has the expected key and signature algorithms (with key size, curve and hash where named) |

An item passes only on what this scan itself observed, and is "not observed" otherwise:

- records count only if this scan run observed them (`fedlin:observedIn`, written from 1.2.0), so records
  merged in from another CBOM never count;
- what the server accepts needs a complete, untruncated enumeration (not `--no-enumerate`), and ML-KEM groups
  it accepts need the group probes to have been answered;
- a statement about every certificate the endpoint serves needs an answer (a certificate or a refusal) from
  the certificate probe of every signature-scheme family, recorded as `fedlin:certificateProbes`;
- a key-exchange item needs the key exchange to have been seen, and `refuses-classical-only` needs the
  classical-only probe; it fails if enumeration shows classical key exchange accepted anyway (a classical
  group offered alone, TLS 1.2 or older, or finite-field DHE).

Verdicts are evaluated afresh with this toolkit's ruleset. With `--baseline`, Critical or High findings at the
wave's endpoints that are new or worse than in the baseline are listed as regressions: anything the server
newly accepts; a new certificate worse than the one in the same slot before (a certificate the baseline already
served, by fingerprint, is never new, and replacing a broken certificate with a quantum-vulnerable one is
progress); a finding that rose in priority, such as an RSA key cut to 1024 bits; a negotiated session that
got worse. They are compared only where both
scans could see, and everything else is listed under `notCompared`, so "no regression" is never claimed for
what was not compared. The baseline must be older and, if the wave names one, the scan it was planned from; a
baseline from toolkit 1.1 is accepted on its evidence. The result (`fedlin.pqc-wave-result` 1.0)
records the SHA-256, serial number, time and toolkit version of each file and the ruleset digest. It is only as
trustworthy as the CBOM it reads; a signed attestation over both is what ties them to the scan.
`scripts/wave.py check` exits `0` passed, `1` not passed, `2` invalid input; in the pipeline the exit code
reflects the scan, so read `passed` in `<out>.wave.json`.

## Verdict profiles

Quantum vulnerability is a property of the algorithm and does not change by profile. What changes is
which quantum-resistant choices count as compliant.

| | `civilian` (default) | `nss` |
|---|---|---|
| Basis | NIST FIPS 203/204/205, NIST IR 8547 (final, October 2026) | NSA CNSA 2.0 |
| ML-KEM-768, X25519MLKEM768 | compliant | quantum-resistant, below target (ML-KEM-1024) |
| ML-DSA-44/65 | compliant | below target (ML-DSA-87) |
| RSA, ECDSA, EdDSA, ECDH, DH | quantum-vulnerable: deprecated after 2030, disallowed after 2035 | quantum-vulnerable: CNSA 2.0 targets |

Every rule cites its primary source. Changes to verdicts are logged in [CORRECTIONS.md](CORRECTIONS.md).

## The readiness score

Compliant quantum-resistant public-key usages divided by (compliant + quantum-vulnerable public-key
usages). A usage is one reference from an asset: a certificate's key or signature, a TLS session's key
exchange, an offered SSH algorithm. Symmetric, hash and protocol-version usages are reported but do not
move the score. It is this toolkit's measure, not a PKI Consortium PQCMM level and not a compliance
determination.

## Other modes

- **Cluster:** run with a kubeconfig and without `--no-runtime` to capture routes or ingresses, TLS
  secret counts and SSH posture. `--deep` adds FIPS checks through a short-lived debug pod.
- **Source:** `--repo <dir>` (dependency SBOM via cdxgen) and `--theia-dir <dir>` (certificates and key
  material via cbomkit-theia).
- **Windows / AD CS:** run `scripts/collect-windows.ps1` and `scripts/collect-hardware-windows.ps1` on
  the host and fold the output in with `--merge-cbom`.
- **AI/ML-BOM:** `scripts/ai_detector.py` inventories models, datasets and pipelines with NIST AI RMF,
  ISO/IEC 42001 and EU AI Act references.

## Use with an AI agent (local MCP server)

`scripts/mcp_server.py` is a Model Context Protocol server over stdio, standard library only. It gives an
agent read-only tools over toolkit outputs in one folder you choose:

| Tool | What it does |
|---|---|
| `list_files` | Lists the `.json` files under the folder |
| `verify_policy` | Checks whether a policy result can be trusted for a CBOM (digest, ruleset, re-evaluation) |
| `summarize` | Readiness summary of a CBOM; a policy result is used only if its verdicts re-check |
| `pqcmm_evidence` | PQC Maturity Model evidence (never a level) |
| `vendor_readiness` | Vendor answers checked against the vendor's CBOM |
| `lookup_verdict` | The ruleset's verdict for one algorithm name under a profile |

```bash
python3 scripts/mcp_server.py --root ./out            # register this command in your MCP client
# or from the image, with no network and the folder read-only:
podman run -i --rm --network none -v "$PWD/out:/data:ro,Z" --entrypoint python3 \
  ghcr.io/fedlinllc/fedlin-pqc-toolkit:1.0.0 scripts/mcp_server.py --root /data
```

The boundary is deliberate. **It never scans and makes no network connections**: you run scans yourself
with the CLI, and the agent works on the results. It reads only `.json` files inside the folder (paths that
leave it, including through symlinks, are refused) and writes nothing. Certificate fields, vendor answers and
third-party CBOMs are written by other people, so every result is marked as untrusted data, and strings are
stripped of control characters and truncated.

## Verdict table for other scanners

`python3 scripts/verdict_table.py build` writes the ruleset as data: the algorithm, group, key-type,
signature and cipher-suite names TLS and certificate scanners report (every TLS cipher suite OpenSSL 3.5
knows, plus legacy ones), with verdicts under both profiles, migration targets and sources, generated by the
same code that writes policy results. Where a verdict depends on key size, the table gives exact size bands
(for example RSA below 2048 bits is broken); look up a certificate key by its key type and size, not its
curve name. It is deterministic for a ruleset version, so its SHA-256
identifies it. Each release publishes it as `verdicts.json`, so the current table is always at
`https://github.com/fedlinllc/fedlin-pqc-toolkit/releases/latest/download/verdicts.json`. The format is fixed by
[schemas/verdict-table-1.0.schema.json](schemas/verdict-table-1.0.schema.json). A name that is not in the
table is unknown, never guessed. `python3 scripts/verdict_table.py lookup X25519MLKEM768 --profile nss`
shows one entry.

## Access by mode

| Mode | What it reads | Privilege |
|---|---|---|
| Endpoints (`--endpoints`) | The TLS handshake and the server's public certificate | None |
| Cluster | Route/ingress objects; TLS and SealedSecret objects are counted, values are not printed | Cluster-wide `list` on secrets (an ISSO should treat this as read access to secrets) |
| `--deep` | FIPS settings on nodes via a short-lived debug pod | Node debug (privileged pod) |
| Local SSH | `sshd -T` effective configuration | `sudo`; sshd loads the host keys in its own process |
| Source (`--repo`, `--theia-dir`) | Files in the directories you name, which can include key files | Read access to those files |
| Windows / AD CS | Certificate stores and CA templates | An account that can read the stores and query the CA |

Some CBOM entries are inferred rather than observed (for example, the SealedSecrets controller key is
recorded from a count of SealedSecret objects); they carry `fedlin:evidence` = `inferred`.

## FIPS-mode scan hosts

OpenSSL in FIPS mode will not offer X25519MLKEM768, so a FIPS host cannot observe the most common
post-quantum key exchange. `setup.sh` builds a small probe image (Alpine pinned by digest, OpenSSL
3.5.9) that the pipeline uses automatically on such hosts, and the toolkit container image bundles the
same OpenSSL. Without either, anything the scan could not observe is recorded as `unknown`, never guessed, and the report is marked **Incomplete** with no letter
grade.

The score credits an endpoint that negotiates a post-quantum hybrid when one is offered. Each endpoint
whose certificate was captured is then contacted a second time by a client offering only classical
key-exchange groups, with TLS 1.2 permitted through the client's default cipher list (on RHEL hosts,
crypto-policies exclude static-RSA suites, so those are not covered). The CBOM records the outcome as
`fedlin:classicalOnlyOffer`:

- **accepted:** the server chose classical parameters (the handshake completed, or the server sent its
  certificate before failing for another reason).
- **rejected:** the server refused with a handshake-failure or insufficient-security alert.
- **inconclusive:** the handshake failed for any other reason (reset, HTTP on the port), or a FIPS-mode
  client, which cannot offer X25519 or X448, was refused.
- **untested:** no connection on the second attempt.

The CBOM also records what was negotiated and the client tool, version and command as run. The report
lists the results under **Classical fallback**; they do not change the score. `--no-classical-probe` skips
the second handshake, which costs about 1 s per endpoint (2-3 s on a FIPS host using the probe container).

## FIPS 140-3 validation (CMVP)

The report checks each cryptographic implementation the CBOM records against a dated snapshot of NIST's
CMVP validated-modules pages (`data/cmvp/`, pinned in `toolkit.lock`): distribution OpenSSL builds
(from `scripts/collect-hardware-linux.py`, which records the OS release and FIPS mode), libraries from
`--repo` (BC-FJA, AWS-LC, BoringCrypto, wolfCrypt, the Go Cryptographic Module), and HSMs. For each it lists
active certificates, their sunset dates, and whether the certificate approves ML-KEM, ML-DSA or SLH-DSA.
Libraries with no validated module (PyPI `cryptography` wheels, `bcprov`, pure-JavaScript crypto) are
named as such.

A listed certificate is a **candidate**, not a validation claim: a certificate covers specific versions
and operating environments in approved mode, which only its Security Policy shows. An endpoint scan alone
cannot see the server's implementation. The snapshot is refreshed deliberately at release time
(`python3 scripts/cmvp.py snapshot --out data/cmvp/cmvp-YYYY-MM-DD.json`); scans never contact NIST.

## Vendor readiness

`scripts/vendor_readiness.py` turns the 31 questions in *Post-quantum questions to ask your vendors*
(ASD's ACSC with CISA and NSA, November 2026, reproduced under CC BY 4.0) into a questionnaire, an answer
template, and an assessment that checks a vendor's answers against the vendor's own CBOM:

```bash
python3 scripts/vendor_readiness.py questionnaire --out vendor-questions.md   # send to the vendor
python3 scripts/vendor_readiness.py template --out answers.json               # fill in answers and claims
python3 scripts/vendor_readiness.py assess --answers answers.json             # report + summary JSON
```

Each question is typed. **Disclosure** answers (inventory, third-party cryptography, data flows and
authentication on traditional asymmetric cryptography, hybrid use, PQC algorithms, library validation) are
compared with the CBOM, and a contradiction is reported as such. **Capability** answers are recorded with
their evidence and hold only for the version assessed. **Intent** answers (dates, roadmaps, licensing) are
recorded and flagged when a date is missing or after 2030; they are never verified. The publication's seven
"common concerns in vendor responses" are raised from structured fields only, not from free-text answers.

## PQC Maturity Model evidence

`scripts/pqcmm_evidence.py --cbom out/cbom.json [--answers answers.json]` maps what a scan observed to the
PKI Consortium PQC Maturity Model (v1.0.1, vendored in `third_party/pkic-pqcmm`, MIT). It pre-fills the
model's own response fields for the questions a CBOM can evidence (algorithms in use, where they are used,
interoperability from an observed handshake, inventory completeness, the classical-only client test for
zero-legacy operation, features that are not quantum-resistant, a draft
harvest-now-decrypt-later register, hybrid use, CMVP candidates, identifiers) and marks where each value came
from: observed, derived, snapshot, or vendor-stated.

It does not award a maturity level or mark any criterion met. The PQCMM assesses a product or service; a scan
observes one deployment, so a capability shown holds only for that configuration, and every criterion is
left for an assessor. The one conclusion it draws is a contradiction: if quantum-resistant algorithms are
observed, the Level 0 criterion "no quantum-safe algorithm available" does not hold.

## Terminology: "quantum-resistant", not "quantum-safe"

The toolkit's own code, output and documentation say **quantum-resistant** (or "post-quantum") and never
"quantum-safe" or "safe". An algorithm is resistant to the attacks known today; "safe" claims a guarantee
no standard makes. NIST, CISA and NSA likewise use "quantum-resistant".

- Verdicts are `quantum_vulnerable` true or false, and a resistant algorithm is "quantum-resistant".
- Third-party text is quoted as written. The PKI Consortium PQC Maturity Model says "quantum-safe" in its
  questions and criteria, and those quotations keep its wording inside quotation marks.
- `tests/test_terminology.py` fails the build if "quantum-safe" appears in the toolkit's own text outside
  a quotation.

## Requirements and footprint

| | |
|---|---|
| Python | 3.9 or later, standard library only (CI tests 3.9 and 3.12; 3.9 is the UBI 9 runtime in the image) |
| Platform | `setup.sh` and the images target Linux x86-64. The endpoint scan itself needs only Python and OpenSSL |
| Optional | Podman (probe image, cbomkit-theia), Node.js via pnpm (cdxgen), `oc` or `kubectl` (cluster mode) |
| Writes | Only the output files you name and, after `setup.sh`, `bin/` and `node_modules/` inside the repository |

**What leaves the host.** Endpoint mode connects only to the hosts you list: TLS handshakes, typically 60 to 100 per
endpoint with enumeration and at most about 170 (`--no-enumerate` and `--no-classical-probe` reduce that to a
few). Cluster mode talks to your cluster's API server.
`--repo` runs cdxgen, which can contact package registries to resolve dependencies. `setup.sh` and image
builds download the pinned tools. Classification, reports, the CMVP check (a dated snapshot in the
repository) and the MCP server make no network connections. Nothing is sent to FEDLIN.

**Uninstall.** Delete the repository folder (it holds `bin/` and `node_modules/`), and remove the images
with `podman rmi localhost/fedlin-kex-probe:0.1` and, if pulled, `ghcr.io/fedlinllc/fedlin-pqc-toolkit`.

## Known limits

Stated so a result is not read as more than it is:

- An outside scan sees the endpoints it is pointed at, so coverage is always declared `partial`.
- The server's implementing software (PKIC `implementationPurl`) cannot be known from outside and is
  declared `unknown`.
- SSH is read from local configuration (`sshd -T`), not from a remote handshake.
- Not yet covered: IPsec/VPN, Kerberos, code signing, cloud KMS, database encryption at rest.
- Windows AD CS template verdicts have been checked by logic inspection; a full Windows CBOM has not yet
  been run end to end through the policy stage.
- The hosted quick check on fedlin.com does not yet read the verdict table, so its verdicts can differ
  from a toolkit run until it does.
- CycloneDX 1.6 output is read as a legacy carrier by the PKIC validator; CycloneDX 2.0 export follows
  the 2.0 release.
- The PKI Consortium CBOM profiles are working-group drafts (`pkic.example` identifiers). "Conforms" means
  the vendored validator reports CONFORMS for the entry profile at the pinned commit.
- `setup.sh` targets Linux x86-64. Podman is needed for the probe image and cbomkit-theia; without it
  setup skips both and endpoint scans fall back as described above.

## Tests

```bash
python3 -I -m unittest discover -s tests -v
```

Standard library only and offline. The suite includes the PKI Consortium CBOM validator (vendored in
`third_party/pkic-cbom`), which must report CONFORMS for the entry profile.

## Versions and stability

Releases are tagged `vMAJOR.MINOR.PATCH` and listed in [CHANGELOG.md](CHANGELOG.md) (0.x releases in
[CHANGELOG-0.x.md](CHANGELOG-0.x.md)). The toolkit version
is stamped in each CBOM and printed by `python3 scripts/tier2_pipeline.py --version`; the ruleset version
is stamped in each policy result and verdict table, and every verdict change is explained in
[CORRECTIONS.md](CORRECTIONS.md). From 1.0.0 the machine-readable outputs (CBOM property names, policy
result, `summary.json`, verdict table, CLI flags and exit codes, MCP tools) follow the promise in
[STABILITY.md](STABILITY.md); verdicts and report wording are not part of it.

## Supply chain

Tool downloads are pinned with SHA-256 sums in `toolkit.lock`, base images by digest (cbomkit-theia is
built from a pinned commit in the same digest-pinned Go image `setup.sh` and the Containerfile share),
and pnpm by version and sha512. A mismatch stops setup or the image build. `setup.sh` installs nothing
outside the repository and needs no root. Exceptions: OS packages installed at build time come from the
distribution repositories (UBI 9 in the toolkit image, Alpine in the probe image and the Go build). `--deep` uses the cluster's own debug
image on OpenShift; elsewhere it needs `--debug-image`, which you should pin by digest.

## Acknowledgements

- PKI Consortium CBOM Profiles working group: profile validator and profiles (MIT), vendored unmodified.
- CycloneDX: cryptography registry (Apache-2.0), vendored unmodified; cdxgen and cyclonedx-cli.
- PQCA cbomkit-theia.
- The approach to evidence and prioritization was informed by the published work of LaMarr Labs
  (fieldguide.lamarrlabs.com).

## Feedback and contributions

Feedback is wanted, especially from people running the toolkit against real estates. Open an issue to
challenge a verdict (with its primary source), report a bug, or say what worked and what did not. Pull
requests are welcome under the Developer Certificate of Origin; see [CONTRIBUTING.md](CONTRIBUTING.md)
and the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md). One maintainer answers on a best-effort basis.

## Commercial support

FEDLIN LLC offers this toolkit as part of assessments run in your own environment, including signed
attestations, baseline-to-baseline deltas, migration roadmaps and OMB M-26-15 plan support. See
https://fedlin.com.

## License

Apache-2.0. See [LICENSE](LICENSE).

Maintained by FEDLIN LLC ([fedlinllc](https://github.com/fedlinllc) on GitHub).
