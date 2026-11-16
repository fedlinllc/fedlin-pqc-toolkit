# Contributing

Feedback, corrections and code are welcome. This project has one maintainer, so responses are best
effort; a short, focused issue or pull request is the fastest way to a decision.

## Ways to help

- **Challenge a verdict.** If the toolkit classifies an algorithm, key size or protocol differently from
  the standard, open a *Verdict challenge* issue and cite the primary source (a NIST, NSA, IETF or
  similar publication, with the section). Confirmed changes bump the ruleset version and are explained
  in [CORRECTIONS.md](CORRECTIONS.md), crediting the reporter unless you ask otherwise.
- **Report a bug.** Use the *Bug report* issue form. Do not paste unredacted CBOMs, reports or logs:
  they can contain internal hostnames, addresses and certificate subjects. Use `--redact` or trim them
  to the lines that show the problem.
- **Report a vulnerability** privately, as described in [SECURITY.md](SECURITY.md). Never in a public
  issue.
- **Send a pull request** for code, tests, test vectors or documentation. For anything larger than a
  small fix, open an issue first so we can agree on the approach before you spend the time.

## Pull request checklist

- Tests pass: `python3 -I -m unittest discover -s tests` (Python 3.9 or later, standard library only,
  offline). New behavior comes with a test.
- No new network access at classification or report time, no telemetry, and nothing that sends scan
  data to a third party.
- A verdict change cites its primary source in the ruleset and adds a CORRECTIONS.md entry.
- Machine-readable outputs follow [STABILITY.md](STABILITY.md): within 1.x, names and formats listed
  there are added to, never removed or renamed.
- Writing rules, enforced by tests: no em or en dashes in public text, and "quantum-resistant", never
  "quantum-safe" (exact third-party names excepted). Never claim or imply a PKI Consortium PQC Maturity
  Model level; the toolkit records evidence for the model and assigns no level.
- Every commit is signed off (see below).

## Sign-off (Developer Certificate of Origin)

Each commit must carry a `Signed-off-by:` line with the commit author's name and email, certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/): you wrote the change or have
the right to submit it under the project's license. `git commit -s` adds the line. A check on every pull
request verifies it; to fix a missing sign-off, run `git commit --amend -s` (or
`git rebase --signoff main`) and force-push your branch.

## License

Contributions are made under the project's [Apache License 2.0](LICENSE) (section 5): what you submit is
licensed to everyone under the same terms as the rest of the code.

## How changes are released

Pull requests are reviewed and merged here, so your commit stays in this repository's history under your
name. Releases are cut from a separate maintainer repository; each merged change is carried into it, with
you recorded as its author, before the next release. A release never silently drops a merged change.

## Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
