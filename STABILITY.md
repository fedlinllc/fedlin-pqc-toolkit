# Stability promise (1.x)

From version 1.0.0, the machine-readable interfaces below follow [Semantic Versioning](https://semver.org/).
Within 1.x, names and formats listed here are not removed, renamed or given a different meaning. New fields,
properties, flags and tools may be added. A change that breaks any of them requires 2.0.0.
`tests/test_contract.py` fails the build if a listed name disappears.

## Covered

| Interface | What is stable |
|---|---|
| CBOM | CycloneDX 1.6 structure and the `fedlin:*` and `pkic:profile:*` property names the toolkit writes (including the per-version `fedlin:acceptedCipherSuites:<version>`), with the values they describe |
| Policy result | The `pkic.cbom.policy-result` 0.1 top-level keys, the `policy` block (id, version, profile, ruleset digest) and the finding keys |
| `summary.json` | The keys of the report summary |
| Verdict table | Schema `fedlin.pqc-verdict-table` 1.0 ([schema](schemas/verdict-table-1.0.schema.json)) and its lookup rule |
| CLI | The flags of `scripts/tier2_pipeline.py` listed in `tests/test_contract.py`, and exit codes: `0` success, `2` invalid input or arguments, any other non-zero code is passed through from a tool the pipeline ran |
| MCP server | Tool names and argument names of `scripts/mcp_server.py` |

## Not covered

- **Verdicts.** What the ruleset says about an algorithm changes when standards or guidance change. Every
  verdict change bumps the ruleset version (stamped in each policy result and verdict table) and is
  explained in [CORRECTIONS.md](CORRECTIONS.md) with its primary source.
- **Report wording and layout.** The Markdown and HTML reports are for people; section text, order and
  tables may change in any release.
- **Scores.** The readiness score's inputs follow the verdicts, so a ruleset change can move a score.
- **Internal Python functions.** Only the command-line programs, files and MCP tools above are interfaces.
