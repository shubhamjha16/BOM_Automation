# Security policy

## Reporting a vulnerability

Email **shubhamjha330@gmail.com** with `[BOM Automation security]` in the subject.
Please include the version or commit, what you observed, and how to reproduce it.

We will acknowledge within **3 working days** and give an assessment within
**10 working days**. If we disagree that something is a vulnerability we will say
so and explain why, rather than going quiet.

Please do not open a public issue for a suspected vulnerability, and please do
not test against anyone else's deployment.

## How we describe vulnerabilities in our dependencies

We publish VEX statements for vulnerabilities disclosed in this product's
dependencies, in the same form this product requires of the suppliers it
assesses. Recommendation 7.1.6 defines **four** statuses and they are exhaustive:

| Status | What it means |
|---|---|
| `not_affected` | The vulnerability is present in a dependency and cannot be reached in this product. **Always carries a written justification.** |
| `affected` | The vulnerability is reachable here. |
| `fixed` | Remediated in the named release. |
| `under_investigation` | We have not yet determined the above. |

There is no fifth status. `under_investigation` is what we publish while we are
still working — never silence, and never a provisional `not_affected`, because an
absence of evidence is not a clearance.

Published statements live in [`dist/vex/`](dist/vex/) as CSAF 2.0 documents.

## What this product is not

A conformance assessment produced by this tool states whether a Bill of Materials
meets the minimum elements of a published technical guideline. **It is not a
legal opinion, and a passing score is not an assurance that software is secure**
— it states that the declaration is complete, not that what was declared is safe.

## Our own supply chain

- Dependencies are pinned (`uv.lock`, `yarn.lock`).
- `pip-audit` runs in CI and is blocking: a supply-chain conformance tool
  shipping known-vulnerable dependencies is not defensible.
- We generate and score our own SBOM on every push, and publish the score.
- Our SSDLC maturity is self-assessed and published **including the activities we
  do not meet** — see [`dist/maturity-scorecard.json`](dist/maturity-scorecard.json).

## Dependency adoption policy

Per clause 3.3.1.4, we require of ourselves what we ask of suppliers:

1. A new runtime dependency must be pinned in a lockfile.
2. Its licence must be identifiable — an unlicensed dependency is not adopted.
3. It must be resolvable to a supplying organisation, or the gap is recorded.
4. `pip-audit` must pass with it present.

These are the same obligations clause 4.2 places on a supplier's SBOM, applied to
our own adoption decisions.
