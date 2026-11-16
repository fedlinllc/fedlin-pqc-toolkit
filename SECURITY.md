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
- A policy result is used only when its verdicts re-check against this toolkit's ruleset
  (`policy.py verify`); otherwise the CBOM is evaluated again.
- Releases carry Sigstore-signed SLSA build provenance; see "Verify a release" in the README.
