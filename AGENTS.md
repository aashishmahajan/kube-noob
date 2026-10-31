# Working on kube-noob as an agent

This file is for an AI coding agent (Claude Code, Codex, Cursor and anything that reads `AGENTS.md`). A human
contributor wants [CONTRIBUTING.md](CONTRIBUTING.md); the ground rules there apply here too, and this file adds what
an agent gets wrong.

## The one command that decides whether you are done

```bash
bash scripts/check.sh
```

It runs every gate CI runs: the plugin copy, the Agent Skill build, the safety contract, ruff (lint and format),
mypy and the full test suite, then kube-noob's own self-test. Read its **exit status**, not its last lines. Piping it
through `tail` or `head` replaces the exit status with the pipe's, so a failing gate looks green:

```bash
bash scripts/check.sh > /tmp/gate.log 2>&1; echo "exit: $?"
```

Do not report a change as working until that exit status is 0. "The tests I wrote pass" is not the gate.

## After any change under `src/`

```bash
python scripts/sync_plugin_server.py
python scripts/safety_contract.py --check
```

`src/` is the only source of truth. `plugin/kube-noob/server/kube_noob/` is a **generated copy** — never edit it, and
never add a module to it by hand. The sync script decides which modules ship, and it deliberately leaves some out
(`kube_noob.mustgather`, `kube_noob.rhacs_central`, the image audit): the plugin must read nothing from the user's
machine and hold no credential. If a test fails because something is missing from the plugin, the answer is almost
always that it is meant to be missing.

`scripts/safety_contract.py` regenerates `docs/safety-contract.md` from the code. If it reports a mismatch, the
contract document is stale — regenerate it, do not edit it.

## Tests first, and make them fail first

Write the test, run it, see it red, then fix the code. A test written after the fix tends to assert what the code
does rather than what it should do. Name the test after the behaviour (`test_a_blind_run_is_not_reported_as_a_clean_one`),
not after the function.

## Gates that catch agents specifically

| Gate | What it refuses |
|---|---|
| `tests/test_distribution.py::test_no_source_file_is_ignored_by_git` | a new source file that `.gitignore` would drop, so the wheel ships without it |
| `tests/test_security_hardening.py::test_validators_end_with_backslash_z_not_dollar` | a validation regex ending in `$`, which matches before a trailing newline; use `\Z` |
| `tests/test_distribution.py::test_bundled_yaml_parses_under_every_yaml_parser` | a colon inside an unquoted scalar in a flow collection. Local libyaml accepts `[k:1]`; the libyaml in the browser build does not, so a file that parses in CI breaks a shipped install. Quote it: `["k:1"]` |
| `tests/test_plugin.py::test_bundle_names_no_credential_variables` | a credential variable name (`*_TOKEN`, `*_API_KEY`) appearing anywhere in the plugin copy, **including in a comment** |
| `tests/test_plugin.py::test_manifest_uses_only_fields_the_plugin_reference_defines` | a field the plugin manifest reference does not define |
| `docs/guidance.md` row check | a row whose `file.py::test_name` citation does not resolve. Every behaviour claim in that table must name a test that exists |

## Documentation is part of the change, not a follow-up

A behaviour change updates, in the same commit:

- `CHANGELOG.md` — under `## Unreleased`, saying what was wrong and why it mattered, not what you did
- `docs/guidance.md` — a new `G<n>` row citing the tests that hold the behaviour
- `PRIVACY.md` / `SECURITY.md` — when what leaves the process, or what the process can reach, changed
- `docs/use-cases.md` — when there is a new thing a user can do

## Exit codes are a public contract

`kube_noob/cli.py` means exactly this, and CI pipelines depend on it:

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | findings at or above `--fail-on` |
| 2 | configuration error, or a file that is not there |
| 3 | clarification needed |
| 4 | a kube-noob error, or refused input |
| 5 | the evidence was incomplete (`--require-complete`, unreadable files) |
| 141 | the output pipe closed |

Never add a meaning to an existing code. 5 exists because a gate that crashed used to leave 1, and a pipeline read
that as policy violations.

## Versions

Only `python scripts/bump_version.py <version> "<reason>"` changes a version; it updates PyPI, the MCP Registry
entry, the plugin, the chart and the image metadata together, and `tests/test_distribution.py` enforces that they
agree. Tagging, releasing and publishing are the maintainer's, never an agent's.

## Commits

Sign off every commit (`git commit -s`) to certify the Developer Certificate of Origin. Never force-push, rebase or
rewrite history on a shared branch.
