---
id: rhacs-roxctl-ci
title: roxctl in CI pipelines
tags: [rhacs, stackrox, roxctl, ci, junit, image-check, deployment-check]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
# roxctl runs as a plain command in any CI system (RHACS docs: integrate-with-your-ci-pipeline.adoc).
worksWith: [jenkins, gitlab, github actions, tekton]
requires:
  - [rhacs, stackrox, roxctl, acs, central, sensor, collector, scanner, securedcluster]
sources:
  - {title: "RHACS docs: Configuring output format", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/configuring-output-format.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Output format options", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/configuring-output-format-options.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Checking policy compliance - prerequisites (ROX_ENDPOINT)", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/setting-up-environment-variables.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Exporting and saving the API token", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/cli-authentication.adoc", license: Apache-2.0}
  - {title: "RHACS docs: roxctl options inherited from the parent command", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/options-inherited-from-the-parent-command.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Using CircleCI", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/integrate-circle-ci.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Checking deployment YAML files", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/checking-deployment-yaml-files.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Checking images", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/checking-images.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Checking image scan results", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/checking-image-scan-results.adoc", license: Apache-2.0}
  - {title: "RHACS docs: Configuring policy resources (Exclude images)", url: "https://github.com/openshift/openshift-docs/blob/801ccd0dfd1f73aed72188c8c960de5c5bc85cd6/modules/configure-policy-scope.adoc", license: Apache-2.0}
  - {title: "stackrox roxctl image check (check.go)", url: "https://github.com/stackrox/stackrox/blob/69fc953f424bf243362dfaab47c4a1bad55fd83b/roxctl/image/check/check.go", license: Apache-2.0}
  - {title: "stackrox roxctl deployment check (check.go)", url: "https://github.com/stackrox/stackrox/blob/69fc953f424bf243362dfaab47c4a1bad55fd83b/roxctl/deployment/check/check.go", license: Apache-2.0}
  - {title: "stackrox roxctl policy errors (policy_errors.go)", url: "https://github.com/stackrox/stackrox/blob/69fc953f424bf243362dfaab47c4a1bad55fd83b/roxctl/summaries/policy/policy_errors.go", license: Apache-2.0}
  - {title: "StackRox default policy: Fixable Severity at least Important", url: "https://github.com/stackrox/stackrox/blob/69fc953f424bf243362dfaab47c4a1bad55fd83b/pkg/defaults/policies/files/severity_important.json", license: Apache-2.0}
  - {title: "StackRox default policy: Fixable CVSS >= 7", url: "https://github.com/stackrox/stackrox/blob/69fc953f424bf243362dfaab47c4a1bad55fd83b/pkg/defaults/policies/files/cvss_7.json", license: Apache-2.0}
---
# roxctl in CI pipelines

`roxctl deployment check` and `roxctl image check` send a manifest or an image reference to Central, which
evaluates its policies and returns the violations. Both exit non-zero when a violated policy is set to enforce at
that stage, which is what fails the pipeline.

## roxctl deployment check in CI: ROX_ENDPOINT, the API token and -o junit

```sh
export ROX_ENDPOINT=<host:port>
roxctl deployment check --file=<yaml_filename> --token-file <token_file> -o junit
```

- `ROX_ENDPOINT` holds Central's host and port; it is the environment form of `-e` / `--endpoint` (default
  `localhost:8443`).
- The API token comes from the token environment variable described in the RHACS page "Exporting and saving the API
  token", or from a file with `--token-file <token_file>`, which wins over the variable when both are set;
  `--password` also wins over the variable, and `-p` cannot be combined with `--token-file`. Keep the token in your
  CI system's secret store.
- To get image scan results the token needs `read` and `write` on the `Image` resource; the default
  **Continuous Integration** system role already has both.
- A custom CA for Central goes in `--ca` or `ROX_CA_CERT_FILE`.
- In JUnit output each violated policy is a test case: policies that fail the check (enforced) are failures, the
  others are skipped. The suite is named `deployment-check` or `image-check` unless you set `--junit-suite-name`.
- A CI job can download roxctl from Central (`/api/cli/download/roxctl-linux`) with the same token, as the RHACS
  CircleCI example does.

## roxctl output formats: -o json, table, csv or junit

- `roxctl deployment check` and `roxctl image check` take `-o json`, `-o table`, `-o csv` or `-o junit`; without
  `-o` they print `table`.
- `roxctl image scan` defaults to the old JSON format, kept for older CLI versions; use `-o json` for the new
  format. The old format is the one to collect for troubleshooting.
- Format options: `--compact-output` (json); `--headers` and `--no-header` (table, csv); `--merge-output` (table);
  `headers-as-comment` (csv); `--junit-suite-name` (junit); `--row-jsonpath-expressions` (table, csv) picks fields
  with GJSON paths:

```sh
roxctl deployment check --file=<yaml_filename> \
  -o table --headers POLICY-NAME,SEVERITY \
  --row-jsonpath-expressions="{results.#.violatedPolicies.#.name,results.#.violatedPolicies.#.severity}"
```

## roxctl deployment check: what it evaluates and when it fails

```sh
roxctl deployment check --file=<yaml_filename> \
--namespace=<cluster_namespace> \
--cluster=<cluster_name_or_id> \
--verbose
```

- Evaluates build-time and deploy-time policies against the deployments in the YAML file: settings such as resource
  limits and privileges, and the images they use (components, vulnerabilities).
- `--namespace` gives context (network policies, RBAC, services) to deployments whose spec has no namespace; it
  defaults to `default` and never changes a namespace set in the spec. `--cluster` adds a cluster's context.
  `--verbose` prints each deployment's RBAC permission level and the network policies that apply to it.
- It exits non-zero when at least one violated policy has deploy-time enforcement on (the `BREAKS DEPLOY` column in
  table output), with `failed policies found: <n> policies violated that are failing the check`.
- Objects whose schema Central does not know, such as custom resources, are skipped with
  `Ignored object "..." as its schema was not registered.`

## roxctl image check --force: skip Central's cached scan result and re-pull it

- `roxctl image check --image=<image_name>` reports build-time policy violations for an image.
- Without `--force`, Central can answer from its cached result for the image, including the components and
  vulnerabilities it found earlier. `--force` skips that cache: RHACS pulls the image metadata and the scan results
  again from the registry and the scanner. `roxctl deployment check` and `roxctl image scan` take `--force` too:

```sh
roxctl image check --image=<image_name> --force
```

- The token needs `read` and `write` on the `Image` resource (the **Continuous Integration** role has them).
- Other flags: `--retries` (default 3) and `--retry-delay` (default 3 seconds), `--categories` to run only some
  policy categories, `--send-notifications` to notify the notifiers of each violated policy, and `--cluster` /
  `--namespace` to use a secured cluster's pull secrets when the scan is delegated.

## roxctl image check fails the build on "Fixable Severity at least Important"

```
WARN:	A total of 3 policies have been violated
ERROR:	failed policies found: 1 policies violated that are failing the check
ERROR:	Policy "Fixable Severity at least Important" - Possible remediation: "Use your package manager to update to a fixed version ..."
```

- This default policy is enabled, applies to the BUILD and DEPLOY stages, has high severity, and carries build
  enforcement (`FAIL_BUILD_ENFORCEMENT`). Its single rule has two criteria: `Fixed By` matches anything, and
  `Severity` is `>= IMPORTANT`. Any vulnerability rated Important or above that already has a fixed version
  therefore fails `roxctl image check` (the `BREAKS BUILD` column shows `X`). The default policy's criteria are
  locked.
- The other default policy with build enforcement, "Fixable CVSS >= 7", ships disabled.
- Fix it the way the policy's remediation says: update the affected packages to the fixed versions and rebuild, or
  agree a mitigation with your security team.
- For an accepted exception, add the image to the policy's **Exclude images**; namespace and cluster scope do not
  apply to build-time checks.
