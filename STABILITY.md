# Stability promise (1.x)

From version 1.0.0, the machine-readable interfaces below follow [Semantic Versioning](https://semver.org/).
Within 1.x, names and formats listed here are not removed, renamed or given a different meaning. New fields,
properties, flags and tools may be added. A change that breaks any of them requires 2.0.0.
`tests/test_contract.py` fails the build if a listed name disappears.

## Covered

| Interface | What is stable |
|---|---|
| CBOM | CycloneDX 1.6 structure and the `fedlin:*` and `pkic:profile:*` property names the toolkit writes (including the per-version `fedlin:acceptedCipherSuites:<version>` and, from 1.4.0, `fedlin:kexConflict`: why a handshake's key-exchange group was not recorded), with the values they describe; the placeholder names `unparsed-public-key-algorithm` and (from 1.4.0) `unparsed-kex-group` for what a scan observed but could not read |
| Policy result | The `pkic.cbom.policy-result` 0.1 top-level keys, the `policy` block (id, version, profile, ruleset digest) and the finding keys |
| CBOM evidence | From 1.1.0: `evidence.identity` (field `name`) on the cryptographic records the toolkit writes, with one method per source as in the table below; method values start with `fedlin-pqc-toolkit/<source>:` |
| `summary.json` | The keys of the report summary. From 1.5.0 `grade` is always `null` (letter grades were retired; the key is kept), and `incomplete`, `tls_endpoints`, `tls_endpoints_pq_kex`, `scope` and `disclaimer` are added |
| Wave file and result | From 1.2.0: schema `fedlin.pqc-wave` 1.0 ([schema](schemas/wave-1.0.schema.json)) with its four checks (`findings-resolved`, `mlkem`, `refuses-classical-only`, `certificate-replaced`); from 1.7.0 also 1.1 ([schema](schemas/wave-1.1.schema.json)), whose `baseline` may add `serialNumber` and `timestamp`; result `fedlin.pqc-wave-result` 1.0 top-level, document and item keys (item status `pass`, `fail`, `not-observed`); `scripts/wave.py check` exit codes `0` passed, `1` not passed, `2` invalid input |
| Context file | From 1.3.0: schema `fedlin.pqc-context` 1.0 ([schema](schemas/context-1.0.schema.json)): systems with name, owner, FIPS 199 impact, data lifetime, migration time and endpoint patterns; from 1.7.0 also 1.1 ([schema](schemas/context-1.1.schema.json)), which adds the optional `highValueAsset`, and a default horizon of 2030 for high-impact or high-value systems (2035 for others) unless the file sets `horizon`; the attention result adds `highImpactHorizon`, `highImpactHorizonSource`, `systemsOnHighImpactHorizon` and per endpoint `horizon` (the earliest of its systems), `perSystem` (each matched system's impact, data lifetime, migration time and horizon, plus its own `urgent` and `urgency` for an exposed endpoint) and `urgencyDecidedBy`; an endpoint's `impact`, `dataLifetimeYears` and `migrationYears` are maximums across its systems and may come from different systems, so urgency is reproduced from `perSystem`, not from them; the `--context` flag of the pipeline and report; `scripts/context.py rank` (with `--json`) exit codes `0` success, `2` invalid input; the ranking `fedlin.pqc-attention` 1.0 (`<out>.attention.json`) top-level and endpoint keys, exposure values `exposed`, `not exposed`, `undetermined` and urgency values `yes`, `no`, `not assessed`; the `attention` key of `summary.json` (null without context) |
| Verdict table | Schema `fedlin.pqc-verdict-table` 1.0 ([schema](schemas/verdict-table-1.0.schema.json)) and its lookup rule |
| CLI | The flags of `scripts/tier2_pipeline.py` listed in `tests/test_contract.py`, and exit codes: `0` success, `2` invalid input or arguments, or (from 1.5.0) a requested source that produced nothing: no `--endpoints` entry completed a handshake, a hosts file is missing, a tool a requested source needs is missing or failed, or a `--merge-cbom` input could not be merged. Any other non-zero code is passed through from a tool the pipeline ran. A run where some sources produced results and others did not exits `0`; the report says how many endpoints were reachable. From 1.7.0, `--fail-on` with any of `broken`, `vulnerable` (includes `broken`), `transitional`, `unclassified`, `incomplete` exits `3` when the scan found one of them (all output is still written; a failed `--validate` exits with its own code first); an unknown status name exits `2` |
| MCP server | Tool names and argument names of `scripts/mcp_server.py` |

## Evidence sources (from 1.1.0)

How each cryptographic record was observed, written as CycloneDX 1.6 component evidence on the
`cryptographic-asset` records the toolkit writes. One fixed technique and confidence per source. The
confidence is an ordinal ranking of how directly the record was observed, not a calibrated probability. A
change to a value is listed in the CHANGELOG with its reason. Evidence is a fact about the record: in 1.x it
never changes a verdict or the score.

| Source | Technique | Confidence | Meaning |
|---|---|---|---|
| `handshake` | `dynamic-analysis` | 1.0 | Observed in a handshake with the endpoint whose result is recorded as its session or certificate (by the host OpenSSL, the probe image, the enumeration client when the host OpenSSL cannot connect, or the classical-only probe when it alone saw the session) |
| `probe` | `dynamic-analysis` | 1.0 | Found only by enumeration probe handshakes (for example an additional certificate the server presents to other clients) |
| `configuration` | `other` | 0.8 | Read from the system's configuration or certificate stores (`sshd -T`, Windows certificate stores and SCHANNEL registry settings); present, use not confirmed |
| `file` | `other` | 0.8 | Parsed from a file or container image (cbomkit-theia, OpenSSL) |
| `dependency` | `manifest-analysis` | 0.3 | Inferred from a dependency known to provide it; use not confirmed |
| `assumption` | `other` | 0.1 | Assumed, not observed |

A record may carry several methods; `identity.confidence` is the highest of them. A record shared by several
observations (one algorithm used by several endpoints) lists every method and every location, which CycloneDX
cannot tie together. A placeholder name for a key algorithm the scan could not parse gets a location but no
identity evidence. Records from a CBOM merged with `--merge-cbom` keep, verbatim, the evidence their producer
wrote (unless two inputs use the same bom-ref) and get none added, except output of FEDLIN's Windows collector (`configuration`). In `summary.json`,
`evidence` counts records by their strongest source; it can also hold `other tool` (evidence from another
producer), `name not parsed` (a key algorithm the scan could not read: location only) and `not stated` (no
evidence).

## Not covered

- **Verdicts.** What the ruleset says about an algorithm changes when standards or guidance change. Every
  verdict change bumps the ruleset version (stamped in each policy result and verdict table) and is
  explained in [CORRECTIONS.md](CORRECTIONS.md) with its primary source.
- **Report wording and layout.** The Markdown and HTML reports are for people; section text, order and
  tables may change in any release.
- **Scores.** The readiness score's inputs follow the verdicts, so a ruleset change can move a score.
- **Internal Python functions.** Only the command-line programs, files and MCP tools above are interfaces.
