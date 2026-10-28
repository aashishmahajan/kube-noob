# Handoff: where the loop stands (for the next session or another model)

Read this first, then `.claude/loop/STATE.md` (the queue, decisions, verification sources, iteration log) and
`.claude/commands/build-loop.md` (how one item is built, verified and shipped). This file says what is in flight
right now; STATE.md says what is done. Updated 2026-10-28.

## Repository and branch

- Repo `aashishmahajan/kube-noob`, work branch `claude/exciting-hawking-pg0uin` (never commit to `main`, never
  force-push, never tag, release or publish: those are owner actions).
- Gate before every commit: `scripts/check.sh` (plugin copy in sync, ruff, ruff format, mypy strict, pytest, selftest).
  Read its exit status; do not pipe it through `tail`. Run `python scripts/sync_plugin_server.py` after any change to
  `src/` so the plugin copy matches.
- CI runs only on `workflow_dispatch` for this branch: `gh workflow run ci.yml --repo aashishmahajan/kube-noob --ref
  claude/exciting-hawking-pg0uin`, then watch with `gh run view <id> --json status,conclusion,jobs`. Job logs are not
  readable from the container (results-receiver host is blocked); read annotations with
  `gh api repos/aashishmahajan/kube-noob/check-runs/<job id>/annotations`.
- Commits: `git commit -s` with the attribution lines the session asks for; push to the work branch.

## Done in this stretch

- BLD2 (CI gate, build/test analytics): done, CI 40661279945 and 40663077885 green.
- VUL1 (R5.1-R5.4) built and pushed in 74aae4a: `src/kube_noob/vuln/` (reports, rpmver, csaf, vex, kev, rank, threat,
  assess, attack), CLI `vuln report` / `vuln threat`, `gate --scanner-report/--vex/--kev`, MCP `vuln_report` /
  `threat_model`, insight routing, RHACS `read_images`, Action/Tekton/GitLab inputs, CI step in `gate-ci`, docs.
  STATE row 15m is `in-progress` until CI is green.

## In flight (finish these first)

1. CI for VUL1: run 40669926452 failed only `test (3.11)`: three Jira sync-lock tests. Root cause found:
   `tests/test_seal.py::test_sync_on_states_its_jittered_schedule` ran `kube-noob serve` with `jira.syncEnabled`
   and left the background sync thread running; 30-600 s later it ran a real sync holding the in-process lock while
   `tests/test_tickets.py` ran. Fixed in the working tree (the test now stops the thread). Commit, push, dispatch CI,
   and mark VUL1 done in STATE when every job is green (gate-ci must show the scanner-report step failing as planned
   with 22 CVEs in SARIF and none of the 12 VEX-excluded).
2. Independent red team of VUL1: a reviewer agent was asked to report reproduced findings (false negatives, crashes,
   injection, gate bypass, leaks). If its report never arrived, rerun it on a detached worktree; fix every reproduced
   finding with a regression test (guidance G57), then log it in STATE.
3. ADM1 (R3.3, STATE row 15n), partly built in the working tree, not committed yet:
   - Done: `src/kube_noob/admission.py` (AdmissionReview v1 review, warn by default, enforce per rule, UPDATE denies
     only new findings, system namespaces and owned Pods/ReplicaSets/Jobs skipped, fails open, exceptions file,
     background `Lookups` cache with jitter for cross-object rules, Starlette app with /validate, /healthz, /readyz,
     /metrics, certificate-rotation watcher), `AdmissionSettings` in `config.py` (`admission.enforce`,
     `excludedNamespaces`, `exceptionsFile`, `lookups`, `maxWarnings`, `version`), CLI `admission serve` and
     `admission review`, `tests/test_admission.py` (45 tests: 1,500-case fuzz never denies in warn mode, every
     enforceable rule denies only itself, p99 well under 50 ms; local p99 is about 1.3 ms).
   - Left: chart templates (`deploy/helm/kube-noob/templates/admission.yaml`: Deployment with 2 replicas and soft
     anti-affinity, PDB minAvailable 1, Service 443->8443, ValidatingWebhookConfiguration with `failurePolicy: Ignore`,
     `timeoutSeconds: 3`, `sideEffects: None`, `admissionReviewVersions: [v1]`, `matchPolicy: Equivalent`, a
     namespaceSelector excluding the system namespaces plus a matchCondition excluding `openshift-*`; certificates by
     `admission.certificates: openshift-service-ca` (Service annotation `service.beta.openshift.io/serving-cert-secret-name`,
     webhook annotation `service.beta.openshift.io/inject-cabundle: "true"`), `cert-manager` (Certificate +
     `cert-manager.io/inject-ca-from: <ns>/<cert>`) or `secret` (operator-provided Secret and caBundle); a read-only
     ClusterRole for lookups only when `admission.lookups`), values + values.schema.json + chart README + chart tests;
     a kind CI job `admission-kind` (CI-generated CA with openssl; warn mode shows `Warning: [KN-S001]` and admits;
     an in-cluster Job sends fuzzed reviews and a 50 rps load for 30 s and asserts never denied and p99 < 50 ms;
     enforce mode denies KN-S001 only; scaling the webhook to 0 does not block `kubectl apply`); docs (CHANGELOG,
     use-cases, architecture trust boundary, SECURITY tier A row, PRIVACY note: no new destination, guidance row,
     README only if words allow under 600).
   - Facts verified for ADM1 (add to STATE verification sources when committing): AdmissionResponse fields and the
     warning guidance ("Limit warnings to 120 characters if possible. Warnings over 256 characters ... may be
     truncated") from kubernetes/api @32a56a94 `admission/v1/types.go`; failurePolicy default Fail, timeoutSeconds
     1-30 default 10, matchPolicy default Equivalent from `admissionregistration/v1/types.go`; OpenShift service CA
     annotations from openshift/service-ca-operator @ed872ba1 `pkg/controller/api/api.go` and its
     `cabundleinjector/admissionwebhook.go`; cert-manager `cert-manager.io/inject-ca-from` from cert-manager @43405a5a
     `pkg/controller/cainjector/sources.go`.
4. Claude plugin directory (owner's 0.5.0 submission): held by directory policy for a reviewer, which is expected
   for any local stdio server; review "In progress" with an Anthropic reviewer. The one new finding against 0.2.3 is
   most likely the kernel FIPS flag read (`/proc/sys/crypto/fips_enabled`) added to `posture.crypto_posture` in 0.5.0.
   Fixed in the working tree: the read moved to `src/kube_noob/host_fips.py`, guarded out of the plugin
   (`scripts/sync_plugin_server.py` GUARDED_IMPORTS), with `tests/test_plugin.py::test_bundle_reads_no_host_system_files`.
   It reaches the directory only with the next release (owner action).

## Queue after that (from STATE.md)

LT1, VUL2, SAST1, RT2, then the older queue (G1, G2, G3, G5, I6, I1, N2, N1, N5, G4, E2, E1, E3, E4b, E5, I2, I9, I8,
P1, P2, GATE1-3, V2, V3, N3, N4, A1-A5, I10, T3, I3, I4, I5, I7, GOV1-3, M13). Every enrichment that fetches anything
must be jittered (random pause between requests, jittered first run and intervals).

## Rules the owner set (do not break)

- Update README (under 600 words, `wc -w`), CHANGELOG, docs/use-cases.md, docs/architecture.md, PRIVACY.md,
  SECURITY.md, docs/guidance.md and THIRD_PARTY_NOTICES.md with every item: the owner asked that READMEs and docs
  are always current.
- Never mark an item done before CI is green. Never write the owner's email into the repo. Never enter credentials or
  sign in for the owner. Public posting, releases, tags, publishing and the skill/plugin listing need the owner.
- Owner actions go at the end of a report as exact copy-paste commands, with no comments inside the code blocks.
