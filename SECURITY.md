# Security policy

## Supported versions

Security fixes go into the latest 1.x minor release. Older 0.x and 1.x releases are not patched; upgrade
to the latest release.

## Reporting a vulnerability

Please report security issues privately through GitHub's **Report a vulnerability** (Security
Advisories) on this repository. Do not open a public issue for a vulnerability.

Include the affected version or commit, steps to reproduce, and the impact you observed. We aim to
acknowledge a report within 5 business days.

## Scope

In scope: the toolkit's own code (capture, ruleset, policy stage, report, collectors), its build and
setup scripts, and the probe image definition.

A wrong verdict for an algorithm is a correctness issue rather than a vulnerability; please open a
regular issue and cite the primary source. Confirmed changes are logged in `CORRECTIONS.md`.

## Design commitments

- What each mode reads, and the privilege it needs, is listed in the README under "Access by mode".
  Secret-hygiene findings report locations, never values.
- Hostnames passed to `--endpoints` are validated and shell-quoted before use.
- Tool downloads are pinned and checksum-verified (`toolkit.lock`); the README lists the exceptions.
- The local MCP server never scans or connects to the network, reads only `.json` files under the folder
  it is started with, writes nothing, and marks file-derived text as untrusted.
- A policy result is used only when re-evaluating the CBOM with this toolkit's ruleset reproduces it
  field for field (`policy.py verify`); otherwise the CBOM is evaluated again.
- Releases carry Sigstore-signed SLSA build provenance; see "Verify a release" in the README.

## FEDLIN's report-signing key

Reports FEDLIN delivers in an engagement can come with a detached SLH-DSA (FIPS 205) attestation. A report
says FEDLIN signed it only when the signing key is this one; a report signed with any other key says so and
names that key's ID instead. Compare the key ID in the report, and the one the verifier prints, with:

| | |
|---|---|
| Algorithm | SLH-DSA-SHA2-128f (FIPS 205) |
| Key ID (first 16 hex of SHA-256 over the raw public key) | `c3341db5cacf5295` |
| Public key (base64) | `ZH11mFKd3LlTPsxK6l2IvWpMxxV/U8y/I7A/ZF/2RGw=` |

If this key is ever replaced, the change is announced here and in a GitHub security advisory.
