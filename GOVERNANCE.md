# Governance

[MAINTENANCE.md](MAINTENANCE.md) says what you can rely on. This file says who decides, and what happens to the
project if that person stops.

It is written for the case where it matters: someone has adopted kube-noob, the maintainer has gone quiet, and they
need to know what they can do without asking permission. The answer should not require an email.

## Who decides

One maintainer, named in the repository's owner field. There is no second maintainer, no committee and no legal
entity. Decisions are made in pull requests and issues, in public.

This file does not pretend otherwise. A governance document that implies a structure which does not exist is worse
than no document, because it is the thing an adopter would rely on at exactly the moment it fails them.

## How a change gets in

- Anyone may open an issue or a pull request.
- A change needs a test. The repository's own standard is that a bug fix ships with a test that fails before it and
  passes after; see `AGENTS.md` and `docs/guidance.md`, where every entry names the tests that hold it.
- Rule changes additionally need a citation. A rule asserts that something is a defect; the source for that
  assertion is part of the rule.
- `scripts/check.sh` must pass. It is the whole contract: ruff, mypy strict, the test suite and the self-test.

## How to become a co-maintainer

Open an issue saying so, after a few merged changes. The bar is a track record in this repository, not an
introduction. Co-maintainers are added when someone has demonstrably been doing the work, which is the only
signal available to a project with no organization behind it.

If you are reading this because you want the bus factor fixed: this is the mechanism. It is open, and it is unused.

## Rule ids are a public contract

A rule id, once published, is never reused for a different check. A retired rule is marked retired and its id stays
retired. Exception lists, baselines, SARIF alert history and anyone's internal dashboards are keyed on those ids,
and silently repurposing one would corrupt all of them without an error anywhere.

## What a successor needs

[MAINTENANCE.md](MAINTENANCE.md#succession) holds the current list of assets: the repository, the PyPI package, the
Homebrew tap, the container images, the release attestations and the documentation site, and which of them a fork
can replace. That list is the handover, and it is kept there rather than here so it stays beside the support
statement people actually read.

Two things that list implies and this file states outright:

- **A fork needs no permission.** Apache-2.0. The rules, the generator and the generated policies are yours.
- **Attestation history cannot be transferred.** It stays keyed to the account that produced it. A successor
  publishes under their own identity and the provenance chain visibly changes hands. That is the correct outcome:
  a signing identity that silently moved would be worse.

## If the maintainer goes quiet

[MAINTENANCE.md](MAINTENANCE.md#if-maintenance-stops) gives the signals and the recommended response. Nothing in
this project requires the maintainer to be reachable in order for you to keep using it: the generated admission
policies are plain Kubernetes objects that need nothing from kube-noob once applied, and the audit runs offline.

That property is deliberate, and it is the real governance guarantee here. Everything above is process; that is
architecture.
