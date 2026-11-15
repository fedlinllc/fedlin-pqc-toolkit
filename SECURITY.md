# Security policy

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

- The toolkit reads public certificate metadata, object names and effective configuration only. It
  never reads private keys or secret values, and secret-hygiene findings report locations, never values.
- Hostnames passed to `--endpoints` are validated and shell-quoted before use.
- All downloads are pinned and checksum-verified (`toolkit.lock`).
