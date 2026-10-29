# POL4: `kube-noob policy migrate-check` (notes for the lead)

## What was built

Kyverno 1.19 deprecates the `kyverno.io` ClusterPolicy, Policy, CleanupPolicy, ClusterCleanupPolicy and the legacy
PolicyException; 1.20 (Nov 2026, estimated) removes them. `policy migrate-check` lints legacy policies rule by rule
against the `policies.kyverno.io/v1` types. It never applies, converts in place or fetches anything.

- `src/kube_noob/kyverno_migrate.py`: the lint. Every finding has `rule`, `path`, `line`, `verdict`, `target` (the
  CEL kind, `Namespaced*` for a namespaced Policy or CleanupPolicy), `mapsTo`, `reason` and `source`
  (`<doc>: <section>`). The report's `sources` table gives repository, file, commit, date and URL for each doc.
  - Verdicts: `direct` (a documented one-to-one mapping); `inverted` (a `deny`, or a negated pattern value such as
    `!x` or `X(field)`: the CEL validation states what is allowed); `manual` (the guide says where it goes but it
    needs hand work: JMESPath, context lookups (apiCall -> resource.Get/List/Post or http.Get/Post, configMap,
    globalReference, imageRegistry), anchors other than X(), strategic merge patches, podSecurity, foreach with
    context or anchors, wildcard or unknown kinds, exclude by namespace, subjects/roles); `blocked` (no documented
    equivalent: `validate.manifests`, `useServerSideApply` and `skipBackgroundRequests` (the guide links open
    issues #14853 and #14852), and the JMESPath functions the JMESPath-to-CEL guide lists as unsupported:
    multiply, divide, sum, compare, regex_replace_all, regex_replace_all_literal).
  - Mapping tables (`POLICY_FIELDS`, `RULE_FIELDS`, `VALIDATE_FIELDS`, `MUTATE_FIELDS`, `GENERATE_FIELDS`,
    `VERIFY_FIELDS`, `CLEANUP_FIELDS`, `EXCEPTION_FIELDS`, `JMESPATH_TO_CEL`) each cite their file and commit in a code
    comment, and every row names a source key (a test enforces it).
  - Drafts: when every field of a rule is direct or inverted and simple, the rule gets a draft CEL policy as text.
    The draft starts with `# DRAFT, prove with kyverno test`. Drafts cover patterns (presence, literals,
    alternatives, globs, int comparisons, X() negation, one-mapping lists), foreach over a plain
    `request.object` list, deny conditions on `request.object` fields (Equals/NotEquals/In-family/GreaterThan-family),
    legacy `validate.cel` (expressions copied), static `patchesJson6902` (JSONPatch{} entries), CleanupPolicy ->
    (Namespaced)DeletingPolicy, and PolicyException -> policyRefs and matchConditions. The PolicyException kind is
    resolved from a policy given in the same input. Pattern semantics follow Kyverno's own engine
    (`pkg/engine/pattern/pattern.go` @v1.19.2): `|` alternatives are trimmed; a number compares as a quantity, with
    a missing field read as 0; a quantity or duration literal (`1Gi`, `1h`) is manual; a missing field fails a
    string or `!` pattern.
  - kyverno test skeleton per ClusterPolicy/Policy: `<policy>/resources.yaml` holds good and bad resources from the
    rule's own pattern or deny condition (TODO placeholders when no sample can be derived). `<policy>/legacy/` holds
    `kyverno-test.yaml` with `rule:` results plus the legacy policy itself. `<policy>/cel/` holds `kyverno-test.yaml`
    with `isValidatingPolicy`/`isMutatingPolicy`/`isGeneratingPolicy` results plus the drafts. These are two tests
    because kyverno test matches results by policy name only (`commands/test/output.go` @v1.19.2). Mutate and
    generate rules get `patchedResources`/`generatedResource` placeholders; verifyImages rules get none.
- `src/kube_noob/toolkit.py`: `PolicyMigrateCheckIn` (extra=forbid, `policies` up to MAX_MANIFEST_CHARS, `drafts`
  bool) and the read-only ToolSpec `policy_migrate_check`. The stdio MCP server and plugin pick it up automatically
  (plugin copy synced). There is no REST route: `server/rest.py` routes are a curated list with no policy tools.
- `src/kube_noob/cli.py`: `kube-noob policy migrate-check -f FILE|DIR|- [-f ...] [--format json|yaml]
  [--fail-on never|manual|blocked] [--no-drafts] [-o DIR]`. Exit 0 by default; 1 at `--fail-on`. Each `-f` file is
  parsed on its own, so lines stay true to that file; the input caps apply to the files together. `-o` writes the
  drafts and fixtures under a fresh directory from sanitised names and refuses to overwrite any file.
- `src/kube_noob/server/mcp_app.py`: one sentence in the server instructions pointing clients at the tool.
- `scripts/eval_kyverno_migrate.py`: the eval below (reads two local clones; commits nothing from them).
- `tests/test_kyverno_migrate.py` (31 tests) and `tests/fixtures/kyverno-migrate/` (6 files; adapted Apache-2.0
  snippets name their source path and commit; row added to THIRD_PARTY_NOTICES.md).
- `docs/architecture.md`: one trust-boundary bullet. `docs/api/openapi.json` is unchanged (no new REST route).

## Eval (kyverno/policies, measured 2026-10-29)

Method: kyverno/policies removed its legacy samples after the 1.19 branch and recorded every one of them in
`.github/legacy-policy-migration.json` on main. The record gives the status (equivalent 172, partial 122,
missing 168), the `desiredKind` and the replacement CEL files. I ran migrate-check on all 462 legacy samples from
the release-1.19 branch @282e77f6 and compared against main @e107540e.

```
.venv/bin/python scripts/eval_kyverno_migrate.py --legacy <clone of release-1.19> --main <clone of main>
```

| Measure | Result |
|---|---|
| Samples checked without error | 462/462 |
| Target kind = upstream `desiredKind` (all samples) | 462/462 |
| Target kind = kinds of the upstream CEL files (equivalent) | 172/172 |
| Upstream converted it fully, migrate-check calls no rule blocked | 172/172 (0 "blocked but converted") |
| Lookup rules (manual for apiCall/configMap/...) whose upstream CEL uses a lookup library (equivalent + partial) | 10/10 (first run, equivalent only: 2/3; the miss was a real bug, a POST apiCall maps to resource.Post(), now fixed and tested) |
| Draft's matched resources within the upstream policy's resources (equivalent with a draft) | 94/94 |
| Equivalent samples with at least one draft | 94/172 (all samples: 148/462; 169 drafted rules) |
| Policy verdicts, equivalent | direct 85, inverted 8, manual 79, blocked 0 |
| Policy verdicts, partial | direct 23, inverted 4, manual 93, blocked 2 |
| Policy verdicts, missing (says nothing either way) | direct 23, inverted 1, manual 139, blocked 5 |
| Rule verdicts (558 rules) | direct 151, inverted 18, manual 381, blocked 8 |

All 7 blocked samples were checked by hand. Each cites a documented gap: regex_replace_all (2), sum (3), divide (1)
and validate.manifests (1). Kind agreement is high partly by construction (the rule's action decides the kind), but
`desiredKind` was set by upstream independently.

Draft review: I compared about 60 drafted rules side by side with the upstream CEL versions or the legacy rule (45
pattern, deny and JSONPatch drafts across all statuses, plus 14 drafted `-cel` policies). That found 3 bugs, now
fixed with regression tests (`test_pattern_and_condition_semantics_follow_kyverno_not_text`):
1. `"HAProxy | nginx"` kept the spaces around `|`.
2. A quoted number (`runAsUser: "1000"`) was compared as a string to an int field.
3. Deny negations were over-parenthesised (cosmetic).

The same review found that Kyverno reads a missing field as 0 for number patterns, which the drafts now follow.
After the fixes, every reviewed draft states the same check as upstream, apart from upstream's added
`exceptions.allowedValues` hooks and its controller expansion.

## Verification sources (accessed 2026-10-29)

| Fact | Source |
|---|---|
| Field mapping tables (Common Fields, Rule Fields, Validate/Mutate/Generate/Verify Images Rule, CleanupPolicy, PolicyException, Context Variables) | https://github.com/kyverno/website/blob/b0131526d7d8d6e4fa80856adb75aa4d7b2f4c89/src/content/docs/docs/guides/migration-to-cel.md (main, 2026-10-27) |
| JMESPath filters and their CEL equivalents; unsupported filters | .../src/content/docs/docs/guides/jmespath-to-cel.md (same commit) |
| CEL policy types, Namespaced variants, autogen, evaluation, matchImageReferences, credentials limits, DeletingPolicy conditions, GeneratingPolicy evaluation fields | .../src/content/docs/docs/policy-types/{overview.md, validating-policy.mdx, mutating-policy.mdx, generating-policy.mdx, deleting-policy.mdx, image-validating-policy.mdx} (same commit) |
| resource.Get/List/Post, http.Get/Post, globalContext.Get, image.GetMetadata | .../src/content/docs/docs/policy-types/cel-libraries.mdx (same commit) |
| kyverno test file structure, isValidatingPolicy | .../src/content/docs/docs/subprojects/kyverno-cli.mdx (same commit) |
| 1.19 deprecation, 1.20 removal (Nov 2026 est.) | .../src/content/blog/announcing-kyverno-release-1.19/index.md (same commit; post dated 2026-08-20) |
| Legacy semantics: patterns, wildcards, operators, anchors, failure actions | https://github.com/kyverno/website/blob/712382f830a614b4eca6fc04f1b07b65955ef31c/src/content/docs/docs/policy-types/cluster-policy/validate.md (branch release-1-18-0, 2026-07-29) |
| Legacy autogen controllers and when autogen is skipped | .../cluster-policy/autogen.md (same commit) |
| Condition operators, any/all | .../cluster-policy/preconditions.md (same commit) |
| Legacy kyverno test fields (rule, patchedResources, generatedResource, ns/name) | .../subprojects/kyverno-cli.mdx (same commit) |
| CEL autogen default (all six controllers when spec.autogen is unset, pods-only match) | https://github.com/kyverno/kyverno/blob/e63308f1e16c05cd009ac4864be6ec25c66b49be/pkg/cel/policies/vpol/autogen/autogen.go, pkg/cel/autogen/data.go, pkg/cel/autogen/support.go (tag v1.19.2, 2026-10-21) |
| Pattern engine semantics (\| trimming, nil -> 0 for numbers, quantity/duration compare, nil fails string) | .../pkg/engine/pattern/pattern.go, pkg/engine/validate/validate.go, pkg/engine/anchor/handlers.go (same tag) |
| Test result flags isValidatingPolicy/isMutatingPolicy/isGeneratingPolicy/...; result matching by name only | .../cmd/cli/kubectl-kyverno/apis/v1alpha1/test_result.go, cmd/cli/kubectl-kyverno/commands/test/output.go (same tag) |
| isMutatingPolicy and isGeneratingPolicy in practice | https://github.com/kyverno/policies/blob/e107540edad393b2ac88a425bff63c66eda7cc9e/psa-mpol/add-psa-labels/.kyverno-test/kyverno-test.yaml, best-practices-gpol/add-network-policy/.kyverno-test/kyverno-test.yaml (main, 2026-10-27) |
| Eval ground truth | https://github.com/kyverno/policies/blob/e107540edad393b2ac88a425bff63c66eda7cc9e/.github/legacy-policy-migration.json; legacy samples at https://github.com/kyverno/policies/tree/282e77f6d54e1e1a636190ff2dacc3d02c2d689c (release-1.19, 2026-10-01) |

## Not verified / limits (say so in docs)

- The drafts' CEL was not compiled or run. kyverno was not run (as instructed). Fetching a CEL engine into the
  scratchpad (cel-go with the Go checksum DB off, then cel-expr-python from PyPI) was refused by the session's
  sandbox, and I did not work around it. Instead, a test checks that every draft expression built from the test
  fixtures has balanced brackets and quotes and uses only idioms upstream kyverno/policies uses (`.?f`, `[?"k"]`, `.orValue()`, `.hasValue()`,
  `.all()`, `string()`, `startsWith/endsWith/contains/matches`, `JSONPatch{}`; never optional `.value()`). The
  kyverno test skeleton exists to prove each draft.
- The kind table covers built-in Kubernetes kinds plus Route, DeploymentConfig and SCC. Other CRD kinds are manual
  (plural unknown); this is the commonest manual reason after JMESPath preconditions.
- No autogen finding for mutate rules: MutatingPolicy's autogen default was not verified in source.
- Results for namespaced CEL drafts use `<ns>/<name>`. kyverno test compares only the last part of `policy:`
  (output.go), so that form is safe.
- `request.operation` preconditions stay manual: how a CEL policy treats them in background scans is not documented.
- `check.sh` passes on Python 3.12, which is CI's version. On Python 3.14 (what `uv venv` picks by default here)
  the pre-existing `tests/test_red_team_rt1.py::test_deeply_nested_jsonl_cases_are_refused_cleanly` fails: 3.14's
  json parses 20,000-deep nesting without RecursionError. This is unrelated to POL4.
- `site/static/bridge.py` BROWSER_TOOLS (the in-browser tool subset) was not changed. The tool is read-only and
  offline, so it could be added there if wanted.
- `plugin/kube-noob/skills/openshift-platform/SKILL.md` mentions `kubenoob_policy_generate`. A sentence for
  migrate-check could go next to it.

## Suggested CHANGELOG bullets (`## Unreleased`)

- `kube-noob policy migrate-check` (and the read-only MCP tool `policy_migrate_check`): lints legacy Kyverno policies
  (kyverno.io ClusterPolicy, Policy, ClusterCleanupPolicy, CleanupPolicy, PolicyException; removed in Kyverno 1.20)
  rule by rule against the CEL policy types. Each finding is direct, inverted, manual or blocked, with the field
  path, target kind, reason and the Kyverno documentation section at a pinned commit. Rules that map directly get a
  draft CEL policy and a `kyverno test` skeleton that runs the legacy rule and the draft on the same good and bad
  resources. `--fail-on manual|blocked` gates CI; `-o DIR` writes the drafts and fixtures. Nothing is applied or
  rewritten.
- Measured on kyverno/policies' own migration record (462 legacy samples): no rule called blocked in any of the 172
  that upstream converted, target kind right in 462/462, and draft scope within upstream's in 94/94
  (`scripts/eval_kyverno_migrate.py`).

## Suggested docs/guidance.md row

| GXXX | A legacy Kyverno policy is linted, never converted in place: every rule and field gets direct, inverted, manual or blocked with its path, line, target kind, reason and a documentation section pinned to a commit; blocked only where the docs give no CEL equivalent; a draft only when every field of the rule maps, labelled as a draft and paired with a kyverno test skeleton that runs the legacy rule and the draft on the same resources; pattern drafts follow Kyverno's own pattern engine; Secrets are not read, names cannot inject YAML into written files, and `-o` never overwrites | `tests/test_kyverno_migrate.py::test_every_finding_names_rule_path_target_reason_and_a_pinned_source`, `tests/test_kyverno_migrate.py::test_mapping_tables_cite_only_known_sources`, `tests/test_kyverno_migrate.py::test_undocumented_or_unsupported_features_are_blocked`, `tests/test_kyverno_migrate.py::test_label_pattern_is_direct_with_a_labelled_draft`, `tests/test_kyverno_migrate.py::test_kyverno_test_fixture_proves_the_draft_against_the_legacy_rule`, `tests/test_kyverno_migrate.py::test_pattern_and_condition_semantics_follow_kyverno_not_text`, `tests/test_kyverno_migrate.py::test_secrets_are_never_read_and_other_documents_are_listed`, `tests/test_kyverno_migrate.py::test_names_with_newlines_cannot_inject_yaml_into_written_files`, `tests/test_kyverno_migrate.py::test_cli_writes_drafts_and_fixtures_only_into_a_fresh_directory`, `tests/test_kyverno_migrate.py::test_the_module_is_offline_and_never_writes`, `tests/test_kyverno_migrate.py::test_mcp_tool_is_read_only_and_strict` |

## Suggested docs/use-cases.md paragraph

**Move off legacy Kyverno policies before 1.20.** Kyverno 1.19 deprecated ClusterPolicy, Policy, the cleanup
policies and the legacy PolicyException, and 1.20 removes them. `kube-noob policy migrate-check -f policies/` reads
your policies and says, rule by rule, what moves to the CEL types and how. A rule is `direct` when a
`validationFailureAction: Enforce` becomes `validationActions: [Deny]` or a label pattern becomes a CEL check. It is
`inverted` when a `deny` must be rewritten as the allowed case. It is `manual` for JMESPath, API lookups, anchors or
strategic merge patches, and `blocked` when Kyverno documents no CEL equivalent, such as `sum()` or manifest
validation. Each finding points at the line and the Kyverno documentation section. With `-o migration/` it writes a
draft CEL policy for each rule that maps directly, plus a `kyverno test` skeleton that runs the old rule and the draft
on the same good and bad resources; run `kyverno test migration/` and keep a draft only when both pass. In CI,
`--fail-on blocked` stops a pipeline that still depends on something CEL cannot do. Nothing is applied: kube-noob
lints, your Kyverno CLI proves.
