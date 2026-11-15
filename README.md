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

It reads public certificate metadata, object names and effective configuration. It never reads a
private key or a secret value.

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

Check that a CBOM still matches its verdicts: `python3 scripts/policy.py verify --cbom out/cbom.json --policy out/cbom.policy.json`.

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

## FIPS-mode scan hosts

OpenSSL in FIPS mode will not offer X25519MLKEM768, so a FIPS host cannot observe the most common
post-quantum key exchange. `setup.sh` builds a small probe image (Alpine pinned by digest, OpenSSL
3.5.9) that the pipeline uses automatically on such hosts. Without it, anything the scan could not
observe is recorded as `unknown`, never guessed.

## Known limits

Stated so a result is not read as more than it is:

- An outside scan sees the endpoints it is pointed at, so coverage is always declared `partial`.
- The server's implementing software (PKIC `implementationPurl`) cannot be known from outside and is
  declared `unknown`.
- SSH is read from local configuration (`sshd -T`), not from a remote handshake.
- Not yet covered: IPsec/VPN, Kerberos, code signing, cloud KMS, database encryption at rest.
- Windows AD CS template verdicts have been checked by logic inspection; a full Windows CBOM has not yet
  been run end to end through the policy stage.
- CycloneDX 1.6 output is read as a legacy carrier by the PKIC validator; CycloneDX 2.0 export follows
  the 2.0 release.

## Tests

```bash
python3 -I -m unittest discover -s tests -v
```

Standard library only and offline. The suite includes the PKI Consortium CBOM validator (vendored in
`third_party/pkic-cbom`), which must report CONFORMS for the entry profile.

## Supply chain

Every download is pinned: tool versions and SHA-256 sums in `toolkit.lock`, base images by digest,
pnpm by version and sha512. A mismatch stops setup or the image build.

## Acknowledgements

- PKI Consortium CBOM Profiles working group: profile validator and profiles (MIT), vendored unmodified.
- CycloneDX: cryptography registry (Apache-2.0), vendored unmodified; cdxgen and cyclonedx-cli.
- PQCA cbomkit-theia.
- The approach to evidence and prioritization was informed by the published work of LaMarr Labs
  (fieldguide.lamarrlabs.com).

## Commercial support

FEDLIN LLC offers this toolkit as part of assessments run in your own environment, including signed
attestations, baseline-to-baseline deltas, migration roadmaps and OMB M-26-15 plan support. See
https://fedlin.com.

## License

Apache-2.0. See [LICENSE](LICENSE).

Maintained by FEDLIN LLC.
