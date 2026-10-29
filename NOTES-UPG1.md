# UPG1: OpenShift update risks from the public update graph, evaluated offline

## What was built

- `scripts/vendor_upgrade_risks.py --repo <clone>`: reads a local clone of openshift/cincinnati-graph-data (refuses a
  clone inside this repository), checks the graph-data schema (stops on anything newer than 1.1.0), keeps the
  `blocked-edges/*.yaml` entries whose `to` is an x.y.z release of OpenShift 4.18 or later, and writes
  `src/kube_noob/data/upgrade_risks/openshift-<minor>-<n>.json` (one shard per target minor, split under 200,000
  bytes). Each record keeps `to`, `from`, `url`, `name`, `message`, `fixedIn`, `matchingRules` and `source` (the
  file's path); each shard records `retrievedAt`, `commit`, `commitDate`, `schemaVersion`, license, attribution and
  `scope` (what was kept and skipped). `--check` validates sizes, JSON, commit, license and that every `from` compiles
  under the safe subset. Re-running it on the same clone reproduces the committed shards byte for byte.
- `src/kube_noob/upgrade_risks.py`:
  - `risks(current, target, arch=None)`: every risk whose `to` equals the target and whose `from` matches the current
    version, each with name, message, url, `fixedIn` (when declared), `from`, the cited source URL at the commit, and
    a verdict: `applies` (`type: Always`), `check` (`appliesWhen`, `decidedBy`, `readOnlyCommands`, `mustGather`
    where the repository's must-gather layout has the file, and the PromQL) or `cannot evaluate offline` (the PromQL
    exactly as upstream wrote it, and why). Also `counts`, `covered` (false for targets older than 4.18 or newer than
    the newest target in the snapshot, with a note), `channelNote` (channels are not vendored, so whether the edge is
    offered is not checked), `verdictsMean` and `knowledge` (date, commit, target range). Output is sorted
    (verdict, name, source) and does not depend on record order.
  - `from` matching follows Cincinnati exactly: an unanchored search (`Regex::is_match`) over the version with its
    architecture suffix (`4.20.3+amd64`). Without `arch`, all five architectures are tried and a risk that matches
    only some says which (`architectures`).
  - Safe regex: `from` never reaches Python's backtracking `re`. A hand-written parser accepts a documented subset
    (literals, `.`, classes with ranges, `\d`, groups, `(?:)`, alternation, `* + ? {m} {m,} {m,n}` with bounds up to
    20, lazy suffixes, `^`, `$`; at most 256 characters, 20 nested groups) and compiles it to a Thompson NFA of at
    most 2,000 states; the search simulates the automaton, so it is linear in the input whatever the pattern.
    Look-around, back-references, inline flags, `\b`, class set operations, nested classes and unbalanced input
    raise `PatternError`; such a risk is listed as `cannot evaluate offline` with `fromEvaluated: false` and the
    reason (never dropped, never guessed). All 356 vendored patterns compile. Why not `re.fullmatch` with a
    "nested quantifier" filter: alternation under a quantifier and long runs of `.*` still backtrack exponentially or
    polynomially without nested quantifiers, and `fullmatch` changes the semantics (see the deviation below).
  - PromQL translation: the query is tokenised (double-quoted strings, numbers, names, operators; anything else, a
    comment included, stops translation) and compared token for token with 12 shapes taken from the vendored data;
    the captured value must pass an allowlist (openshift/api `PlatformType` names, a Kubernetes name, a plain label
    value, a capability name). Shapes and the fact each decides on:
    - `cluster_installer` invoker is / is not X (3 shapes): ConfigMap `openshift-install` (else
      `openshift-install-manifests`) in `openshift-config`, key `invoker`;
    - `cluster_infrastructure_provider` type is X / in X|Y (3 shapes): `infrastructure/cluster`
      `.status.platformStatus.type`;
    - `cluster_operator_conditions` name=X (2 shapes): ClusterOperator X exists;
    - `cluster_version_capability` name=X: capability X in `clusterversion/version`
      `.status.capabilities.enabledCapabilities`;
    - `kube_node_labels` for `label_kubernetes_io_arch` and `label_node_openshift_io_os_id` (one shape each): a node
      with `kubernetes.io/arch=X` / `node.openshift.io/os_id=X`;
    - `ovnkube_clustermanager_num_egress_ips > 0`: an egress IP assigned to a node (`oc get egressips.k8s.ovn.org`).
  - `matchingRules` are walked as the cluster walks them: `Always` applies; a PromQL rule decides (later rules are
    returned as `otherRules`, used by the cluster only if it cannot evaluate the query); `Fleet` is `cannot evaluate
    offline`; unknown types are skipped; no evaluable rule means "not recommended" (`applies`); a blocked edge with
    no rules applies.
- Toolkit: `UpgradeRisksIn` (extra=forbid via `_In`; `current`, `target` bounded to 20 characters and validated by
  `parse_version` with a `\Z`-anchored regex using `[0-9]`, not `\d`; target must be newer; `arch` is a Literal of the
  five architectures), `Toolkit.upgrade_risks` and the read-only, closed-world ToolSpec `upgrade_risks` after
  `known_issues` (MCP name `kubenoob_upgrade_risks`). One sentence added to the MCP server instructions.
- CLI: `kube-noob upgrade-risks --from 4.20.3 --to 4.21.4 [--arch s390x] [--format json|yaml]`. A separate command
  rather than a flag on `known-issues`: `known-issues` takes free text and matches release-note prose, this takes
  two versions and matches graph declarations, and every other lookup by key (`ticket`, `signals`) is its own
  command. Bad versions exit 2 with the flag named (`--from: '4.20' is not an OpenShift release version x.y.z`).
- `knowledge_status`: `upgradeRisksAsOf`, `upgradeRisksCommit`, `upgradeRiskTargets` and the note; `line()` (shown by
  `doctor` and stamped on every MCP result as `knowledgeAsOf`) adds "update risks as of 2026-10-29 for targets 4.18
  to 4.22.17".
- Plugin copy synced (`plugin/kube-noob/server/kube_noob/upgrade_risks.py` and `data/upgrade_risks/`, 5 files, the
  largest 103,193 bytes). No test pins the tool count or the list of bundled data files; none needed a change.
- `THIRD_PARTY_NOTICES.md`: a row for the vendored data.

Not done (not asked; for the lead to decide): a REST route (`server/rest.py` ROUTES is a curated subset and
`docs/api/openapi.json` would change), the site's in-browser tool list (`site/static/bridge.py`), a
`corpus upgrade-risks --online` refresh into the data directory, and docs (lead integrates).

## Proof

- `scripts/check.sh` (venv on Python 3.12.3, as CI's main jobs use) exits 0: plugin copy in sync, ruff, ruff format,
  mypy (134 files), 1520 passed and 1 skipped, selftest 63/63. `tests/test_upgrade_risks.py` adds 31 tests.
- Environment note, not caused by this change: `uv venv` first picked Python 3.14.6, where
  `tests/test_red_team_rt1.py::test_deeply_nested_jsonl_cases_are_refused_cleanly` fails on the untouched base commit
  too (its `json` parses 20,000 nested brackets without a recursion error, so the message differs), and
  `tests/test_policy.py::test_explain_stays_fast_on_hostile_input[text1]` (3.0 s budget) missed by 16 ms once under
  load and passes alone in 2.2 s.
- `kube-noob upgrade-risks --from 4.20.3 --to 4.21.4` prints `EtcdStorageVersion3Migration` (APPLIES) with its link and
  source; `--from 4.21.4 --to 4.20.3` exits 2 ("the target must be newer than the current version").
- A mutation run (the engine's search replaced by a full match, then by a prefix test) fails the tests; a 60,000-pattern
  differential fuzz against Python's `re.search` found no disagreement (a fixed-seed 1,500-pattern version is a test).

## Deviation from the brief: `from` is a search, not `re.fullmatch`

The brief asked for `re.fullmatch`. The upstream README (line 136-138) says `from` is a regex that matches a substring
unless it carries `^` and `$`, compared with the architecture suffix appended, and Cincinnati's code does exactly that
(`from_regex.is_match(from)` on `release.version()` in `add_conditional_edges`). A full match would give wrong answers
on real data:

- 4.18.1 to 4.18.5 `LabeledMachineConfigAndContainerRuntimeConfigBlocksMCO` has
  `from: 4[.](17[.](1[01]|0-.*|[0-9])|18.0-(ec[.].*|rc[.][0-3]))` (no `[+].*` tail): a full match of `4.17.5+amd64`
  fails, so the risk would be missed for every 4.17 cluster. The update service attaches it (search), and because
  `[0-9]` matches the first digit, it attaches it for every 4.17.z, 4.17.20 included. kube-noob reports what the
  update service serves
  (`tests/test_upgrade_risks.py::test_unanchored_patterns_match_as_the_update_service_matches_them`).
- Most patterns end in `[+].*`, which a full match of the bare `4.20.3` never satisfies.

"A version that matches `from` only partially must not match" is kept and tested in the sense that matters: a version
that shares a prefix with the declared range but is not in it (4.20.15 against `4[.]20[.]([0-9]|1[0-4])[+].*`, 4.20.1
and 4.20.120 against `4[.]20[.]12[+].*`, 4.18.1, 4.18.6 and 4.18.160 against `^4[.]18[.]1[6-8][+].*$`) does not match.
A mutation run (search replaced by full match, then by a prefix test) fails the tests in both cases.

## Vendored data

- Source: https://github.com/openshift/cincinnati-graph-data at 7572174a551561c30e07e9b5ca6f156ef5cd513c
  (committed 2026-10-29T18:07:49+00:00, "Merge pull request #11218 ... promote-4.15.70-to-stable"), schema `version`
  1.1.0, Apache-2.0. Retrieved 2026-10-29 (shallow clone in the session scratch area, not in the repository).
- 1,739 `blocked-edges` files: kept 356 (targets 4.18.0 to 4.22.17, 114 distinct targets), skipped 1,299 with older
  targets and 84 with pre-release targets (`-ec.N`, `-rc.N`, including `5.0.0-rc.7`), 0 malformed. Every kept entry
  has exactly one matching rule (166 `Always`, 190 `PromQL`).
- Verdicts over the 356: 103 `applies`, 166 `check`, 87 `cannot evaluate offline`. Checks by fact: invoker is
  hypershift 48, invoker is not hypershift 25, egress IP assigned 21, ClusterOperator aro 21, platform Azure 15,
  node os_id=rhel 11, platform None or BareMetal 9, Console capability 7, node arch s390x 6, platform VSphere or None 3.
- Files: openshift-4.18-1.json 59,303 bytes, 4.19-1 103,193, 4.20-1 24,212, 4.21-1 10,241, 4.22-1 23,790 (220,739
  total).

Upstream observations worth knowing (not changed, reported as is):

- `4.19.x-InvalidArchitectureValueOfMachinesetsAnnotation.yaml` uses `cluster_infrastructure_provider{type="AWS|GCP"}`
  with `=`, an exact match that no platform type satisfies, so as written the query returns 0 everywhere. kube-noob
  leaves it as `cannot evaluate offline` with the query shown (`test_a_mixed_edge_keeps_every_verdict_and_never_guesses_a_query`).
- The only upstream uses of `cluster_feature_set` are compound queries in 4.16/4.17 entries (out of scope), and no
  upstream query uses a network-type metric, so no shape was added for either: there is no real query to check one
  against.

## Verification sources (all read on 2026-10-29)

| Fact | Source |
|---|---|
| Field list, `from` substring semantics and arch suffix, `fixedIn` meaning, schema versioning | https://github.com/openshift/cincinnati-graph-data/blob/7572174a551561c30e07e9b5ca6f156ef5cd513c/README.md ("Schema Version", "Release Names", "Block Edges") |
| `from` applied with `Regex::is_match` to `release.version()`; `to` set for every architecture | https://github.com/openshift/cincinnati/blob/0e1d9356b52d3acee72fa7ec30c324cc02115166/cincinnati/src/plugins/internal/edge_add_remove.rs, `.../graph_builder/openshift_secondary_metadata_parser/plugin.rs`; `multi` arch in `.../release_scrape_dockerv2/registry/mod.rs` |
| matchingRules walk, Always, PromQL 1/0, Fleet | https://github.com/openshift/enhancements/blob/d74f27b2fba2c05689aa50e1ffed2c517bdc7416/enhancements/update/targeted-update-edge-blocking.md |
| CVO runs PromQL on the in-cluster Thanos querier, one sample of 0 or 1 | https://github.com/openshift/cluster-version-operator/blob/1eeb46148a6eabdee90ccd3dabf26646476b0fcf/pkg/clusterconditions/promql/promql.go |
| `cluster_installer` (ConfigMaps `openshift-install`, `openshift-install-manifests` in `openshift-config`, key `invoker`), `cluster_operator_conditions`, `cluster_version_capability` | same CVO commit: pkg/cvo/metrics.go, pkg/internal/constants.go |
| `cluster_infrastructure_provider` type = `status.platformStatus.type`; `cluster_feature_set` | https://github.com/openshift/cluster-kube-apiserver-operator/blob/acb844b0be5fa6c0f92b7455ef6354fc120b85de/pkg/operator/configmetrics/configmetrics.go |
| `PlatformType` values, `FeatureSet` values, `enabledCapabilities`, `Console` capability | https://github.com/openshift/api/blob/7ecc11c5c1b6594f9a79c665c6596392d88dd25a/config/v1/ (types_infrastructure.go, types_feature.go, types_cluster_version.go) |
| `kube_node_labels` label naming (`label_` + key with non-[a-zA-Z0-9_] as `_`) | https://github.com/kubernetes/kube-state-metrics/blob/c201f14480266be82e76ef0150fb8e0c9ff88b3a/internal/store/utils.go |
| `kubernetes.io/arch` | https://github.com/kubernetes/api/blob/65c5b9edb29b2c7673be20c8eed03afb5cfa32f9/core/v1/well_known_labels.go |
| `node.openshift.io/os_id=${ID}` set by the kubelet units | https://github.com/openshift/machine-config-operator/tree/1d6d6726f5967471cc02b72cec1d28b86fc6e0bd/templates (master and worker `01-*-kubelet/*/units/kubelet.service.yaml`) |
| `ovnkube_clustermanager_num_egress_ips` = egress IPs allocated to nodes; EgressIP `status.items`, Assigned EgressIPs column | https://github.com/ovn-kubernetes/ovn-kubernetes/tree/5e2695008e99eac0a5ceaf74806086041f32e192/go-controller (pkg/metrics/cluster_manager.go, pkg/clustermanager/egressip_controller.go, pkg/crd/egressip/v1/types.go) |
| `oc adm upgrade --include-not-recommended` | https://github.com/openshift/oc/blob/027bf0b05d713f85d6fc4674ff2e076684538a74/pkg/cli/admin/upgrade/upgrade.go |
| Must-gather paths `cluster-scoped-resources/config.openshift.io/{infrastructures,clusteroperators,clusterversions}/` and `cluster-scoped-resources/core/nodes/` | this repository's `kube_noob.mustgather.analyse` (`_COLLECTED_BY`) and `sample.py`; not re-checked upstream here, and no must-gather path is given for ConfigMaps, FeatureGate or EgressIPs |
| License | cincinnati-graph-data `LICENSE` (Apache License 2.0) at the commit above |

## Suggested CHANGELOG bullet (Unreleased)

- Update risks before an OpenShift update, offline: `kube-noob upgrade-risks --from 4.20.3 --to 4.21.4` (and the
  `upgrade_risks` MCP tool) lists the risks Red Hat declares for that update in the public update graph
  (openshift/cincinnati-graph-data, 356 risks for targets 4.18.0 to 4.22.17, commit 7572174a, 2026-10-29), as a
  disconnected cluster would see them only through a local OpenShift Update Service. Each risk has its message, link
  and fix version, and says whether it applies to every cluster, which single fact decides it with the read-only
  `oc` command or must-gather file that shows it (installer invoker, platform type, a ClusterOperator, a capability,
  a node label, assigned egress IPs), or that its PromQL cannot be evaluated offline (shown as written). `from` is
  matched as the update service matches it, by a linear-time engine that refuses look-around, back-references and
  oversized patterns. `doctor` and every result's `knowledgeAsOf` show the snapshot date.

## Suggested docs/guidance.md row

| G105 | Update risks are the update service's own: a risk is listed for an update exactly when its `to` is the target and its `from` matches the current version as Cincinnati matches it (an unanchored search over the version with its architecture suffix), a version that only shares a prefix with the range is not matched, `from` patterns are evaluated in linear time and refused outside a safe subset (then listed as not evaluated, never dropped), a PromQL rule is translated only when it is one of the known shapes with an allowed value and otherwise shown as written, every suggested command is read-only and paste-safe, the snapshot is commit-pinned, cited and dated in `doctor`, and output is deterministic | `tests/test_upgrade_risks.py::test_every_vendored_from_pattern_compiles_and_agrees_with_search_semantics`, `tests/test_upgrade_risks.py::test_unanchored_patterns_match_as_the_update_service_matches_them`, `tests/test_upgrade_risks.py::test_a_version_that_matches_from_only_partially_does_not_match`, `tests/test_upgrade_risks.py::test_hostile_from_patterns_are_refused_and_reported`, `tests/test_upgrade_risks.py::test_backtracking_bombs_are_linear`, `tests/test_upgrade_risks.py::test_promql_outside_the_known_shapes_is_shown_verbatim_never_translated`, `tests/test_upgrade_risks.py::test_a_mixed_edge_keeps_every_verdict_and_never_guesses_a_query`, `tests/test_upgrade_risks.py::test_every_suggested_command_is_read_only_and_paste_safe`, `tests/test_upgrade_risks.py::test_vendored_index_is_dated_pinned_cited_and_fits_the_plugin_limits`, `tests/test_upgrade_risks.py::test_output_is_deterministic_whatever_the_record_order` |

## Suggested docs/use-cases.md paragraph (after "Is this a known bug?")

### What could go wrong with this update?

Red Hat attaches known risks to some OpenShift updates ("conditional updates"): a cluster sees them in
`oc adm upgrade --include-not-recommended` when it can reach an update service, and a disconnected cluster only through
a local OpenShift Update Service. `upgrade-risks` answers before you start, with no network: it lists the risks declared
for your update in the public update graph (targets 4.18 and later), with the message, the link and the version that
fixes each. A risk either applies to every cluster, or one fact decides it (the platform type, whether the cluster is a
hosted control plane, a ClusterOperator, an enabled capability, a node label, assigned egress IPs) and you get the
read-only `oc` command or the must-gather file that shows it, or its PromQL query is shown as written because it
cannot be evaluated offline. Whether the update is in your channel is not checked.

```bash
kube-noob upgrade-risks --from 4.20.3 --to 4.21.4
kube-noob upgrade-risks --from 4.18.5 --to 4.19.0 --format json
```

The snapshot is dated and pinned to an upstream commit (`kube-noob doctor` prints it);
`scripts/vendor_upgrade_risks.py` refreshes it from a clone of openshift/cincinnati-graph-data.
