# Build loop state

Read by every iteration of `.claude/commands/build-loop.md`. The loop updates this file and commits it with the work.
Statuses: `todo`, `in-progress`, `done`, `blocked` (reason and the exact question or missing input).

## Work queue (in order; take the first `in-progress`, else the first `todo` whose dependencies are `done`)

| # | ID | Item | Depends on | Status | Evidence / notes |
|---|---|---|---|---|---|
| 1 | F1 | Baseline and loop scaffolding | - | done | check.sh green: 428 passed, 1 skipped, selftest 61/61, 23 s (2026-10-28); toolchain below |
| 2 | F2 | Strategy into the docs (roadmap, editions) | F1 | done | docs/roadmap.md rewritten (principles, M1-M12, frozen, set aside, assumptions); docs/editions.md; check.sh green 428/1 skipped, selftest 61/61 |
| 3 | F3 | Capability tiers framework | F1 | done | kube_noob/tiers.py (R,P,D,W,G; Approval; Writer), settings probe/dryRun/itsm/notify/gate, doctor rows and conflicts, ToolSpec.tier filter, chart rbac-tiers.yaml + guards + schema, KN-S017 extended; tests/test_tiers.py 10 passed; check.sh 438 passed; CI green on the branch (run 40614349955: chart tier guards, kind e2e x4) |
| 4 | S1 | Signal extraction module | F1 | done | kube_noob/signals (core.py, vocab.py with upstream citations), CLI `kube-noob signals`; tests/test_signals.py 11 passed; check.sh 451 passed, selftest 61/61 |
| 5 | S2 | Signal catalogue (verified names only) | S1 | done | data/signals.yaml 74 entries, signals/catalogue.py (entries, get, infer, terms_for); tests/test_signal_catalogue.py 5 passed; check.sh 456 passed |
| 6 | S3 | Known-issue matching with signals plus recall eval | S2 | done | Frozen eval 51 positives (prose, alert, events) / 33 negatives; recall 36/50 + 1 false match before, 48/51 and 0 after; `tests/test_known_issue_recall.py` gates 0.8 and zero; accept command returns OCPBUGS-73881 |
| 7 | S4 | Signals in diagnose, debug, bundle, policy explain; Alertmanager payload input | S3 | done | `diagnose -f alert.json` ranks DBG-ETCD first and lists OCPBUGS-73881 for the payload's 4.21.0 label; `kubenoob_extract_signals` read-only over MCP stdio (33 tools); tests/test_signals_everywhere.py (26) |
| 8 | MEM1 | Memory entry schema | S1 | done | `kube_noob.memory` (model, io), shipped JSON Schema `data/memory/entry.schema.json` (test keeps it equal to the model); tests/test_memory_entry.py (55): schema, round-trip, rejections |
| 9 | MEM2 | `kube-noob memory` CLI incl. validate (poisoning guard) and match | MEM1, S3 | done | init/add/validate/match/outcome/stats/migrate-learning in `kube_noob.memory` (repo, verify, match); tests/test_memory_repo.py (25); `kube-noob demo memory` 0.43 s with poisoned entry rejected |
| 10 | MEM3 | Memory sources: config, ConfigMap, PVC, git init container | MEM2, F3 | in-progress (code done; chart render awaits CI) | `memory.paths` + `KUBE_NOOB_MEMORY_PATHS`; doctor rows with counts; `memory match` default dirs; chart `memory.source` configMap/pvc/git with guards, read-only mounts, git egress CIDRs + EgressFirewall name, offline = in-cluster git only (no `offline.allowedHosts` concept exists, so external git is refused); tests/test_memory_runtime.py (5) + CI chart guards |
| 11 | MEM4 | Memory in answers; `memory_match`, `memory_propose` MCP tools | MEM2 | todo | |
| 12 | MEM5 | Fleet view by cluster | MEM2 | todo | |
| 13 | T1 | Offline ticket importers (ServiceNow, Jira) | MEM2 | todo | |
| 14 | T2 | `memory replay` harness (the 30% gate) | T1 | todo | |
| 15 | V1 | Prompt-injection sanitiser | F1 | todo | |
| 16 | G1 | Must-gather safe ingest | S1 | todo | |
| 17 | G2 | Must-gather analysers | G1, S3 | todo | |
| 18 | G3 | Must-gather report and case draft; demo | G2, MEM4, V1 | todo | |
| 19 | G5 | `analyze_must_gather` MCP tool with path confinement | G3 | todo | |
| 20 | I6 | REST API (minimal routes first) | F3, V1 | todo | |
| 21 | I1 | Alertmanager receiver and reports | S4, MEM4, I6 | todo | |
| 22 | N2 | pcap and pcapng analyser | V1 | todo | |
| 23 | N1 | Tier 1 flow readers (ACL log, Hubble, NetObserv) | F1 | todo | |
| 24 | N5 | `net verify` headline; demo | N1, N2 | todo | |
| 25 | G4 | Custom must-gather image | G3 | todo | |
| 26 | E2 | Installed operator inventory | F3 | todo | |
| 27 | E1 | Operator release notes | E2 | todo | |
| 28 | E3 | Kubernetes and RHACS known issues | S3 | todo | |
| 29 | E4 | Customer-side Jira cache | S3 | done | Shipped on main in 0.5.0 before this loop: `corpus jira` full sync of 28 projects, FTS5 ticket index, verdicts in known-issues/diagnose/watch, `ticket` tool, chart `jira.sync`; live CI on 7,700 OCPBUGS tickets |
| 29b | E4b | Jira matches filtered and ranked by the cluster's components and installed operators (from E2 inventory or a must-gather) | E4, E2, G2 | todo | remainder of E4 |
| 30 | E5 | Customer Portal research doc | - | todo | |
| 31 | I2 | SARIF, GitHub Action, pre-commit, Tekton | F1 | todo | |
| 32 | I9 | runbooks.yaml, report and /metrics, lightspeed-config, diagnose --brief | MEM2 | todo | |
| 33 | I8 | kubectl and oc plugin | F1 | todo | |
| 34 | P1 | Upgrade pre-mortem | E1, E2, MEM2 | todo | |
| 35 | P2 | Offline what-if | G2 | todo | |
| 36 | GATE1 | MCP gate proxy with approvals | F3, V1 | todo | |
| 37 | GATE2 | Tamper-evident gate audit log | GATE1 | todo | |
| 38 | GATE3 | Gate docs and example | GATE2 | todo | |
| 39 | V2 | Server-side dry-run (tier D) | F3 | todo | |
| 40 | V3 | Blast radius | F3 | todo | |
| 41 | N3 | Probe plan and run (tier P) | F3, N5 | todo | |
| 42 | N4 | Capture plan | N2 | todo | |
| 43 | A1 | Egress log | F3 | todo | |
| 44 | A2 | Pre-send preview | A1, V1 | todo | |
| 45 | A3 | Admin model controls | A1 | todo | |
| 46 | A4 | Provider verification (keys needed) | A3 | todo | |
| 47 | A5 | Bench with and without tools | A4 | todo | |
| 48 | I10 | Cowork and plugin skills (security, compliance, manager, CAB) | I9 | todo | |
| 49 | T3 | Online ITSM connectors | T2, F3, A1 | todo | |
| 50 | I3 | Argo CD and GitOps examples | I2 | todo | |
| 51 | I4 | Chat commands without a model | I6 | todo | |
| 52 | I5 | OpenShift console dynamic plugin | I6 | todo | |
| 53 | I7 | Backstage design doc | I6 | todo | |
| 54 | GOV1 | Identity in audit records, OSCAL, KSI doc | I6 | todo | |
| 55 | GOV2 | Read as caller | F3 | todo | |
| 56 | GOV3 | Signed air-gap corpus pack | E4 | todo | |
| 57 | M13 | Release readiness pass | all above | todo | |

When an item is too large for one iteration, split it here into lettered rows (for example `N2a`, `N2b`), each of
which ships tested and documented on its own.

## Decisions (do not re-litigate)

- 2026-10-28: this branch was cut at 4959025, before 0.4.0 (incident watch) and 0.5.0 (Red Hat Jira copy) shipped on
  main; main was merged in (9e4c3f8). Items build on both: the Alertmanager receiver (I1) records into the incident
  ledger (`incidents.json`) instead of a second store, and MEM imports fixes confirmed in incidents as proposed
  entries (`memory migrate-learning` also reads `incidents.json`).
- E4 is done by 0.5.0's Jira copy (REST API only, robots.txt pace, request budget, never redistributed); its
  remaining slice (filter by the cluster's components and operators) is E4b.

- kube-noob has no model inside. The AI is the client or the optional `kube-noob ask`.
- The trained-model track is cut. The grader stays as an evaluation product (`kube-noob bench`).
- The verifier never acts. Gate, probe and dry-run are separate tiers with per-action approval.
- Ship fetchers, not data: Jira, tickets and memory are never redistributed or exported.
- Signals over prose: canonical alert names, event reasons, condition reasons and error templates are the join key;
  BM25 text is the fallback. No embeddings unless an eval proves BM25 plus signals fails.
- Memory is files in the customer's Git, reviewed by pull request; `memory validate` is the poisoning guard.
- Land on disconnected or regulated OpenShift; build moat features vendor-neutral.
- Learner tracks, credits and brand videos are frozen: kept and tested, no new features.
- The plugin's source copy stays (the plugin must run readable, locked code); drift is enforced by
  `scripts/sync_plugin_server.py --check`.
- Open-core line is documentation only (`docs/editions.md`); no licensing code.
- Parked: live outage signals from social or status feeds (conflicts with the offline default), Backstage beyond a
  design doc, a hosted service, embeddings.

## Owner actions (the loop cannot do these; it lists them in its final report)

- Run `kube-noob memory replay` on one team's real last 50 resolved tickets and the following 4 weeks (gate: 30%
  useful matches). This decides whether the memory moat is real.
- Show `doctor`, PRIVACY.md and SECURITY.md to two OpenShift admins; ask whether they would enable tiers P and D.
- Provide API keys (xAI, OpenAI, Anthropic, Azure, Bedrock, Vertex) as environment variables if provider runs are
  wanted (A4, A5).
- Decide on the Customer Portal path after reading E5.
- Provide an OpenShift cluster for CI if `restricted-v2` admission must be proven there.
- Run the headline test: "No AI inside. Works with yours." versus "The ground truth your AI SRE checks against",
  a week apart, compare click-through to the repository.
- Submit the OpenShift Helm catalog pull requests (`docs/openshift-catalog.md`).
- Approve version bumps, tags, releases and pull requests.

## Verification sources (append as facts are verified)

| Fact | Source URL | Verified on | Used in |
|---|---|---|---|
| kubectl debug PATCHes the pods/ephemeralcontainers subresource | https://github.com/kubernetes/kubectl/blob/master/pkg/cmd/debug/debug.go (line 514) | 2026-10-28 | tiers.py, chart rbac-tiers.yaml |
| Dry-run is authorized identically to the real request | https://github.com/kubernetes/website/blob/main/content/en/docs/reference/using-api/api-concepts.md ("Dry-run authorization") | 2026-10-28 | tiers.py, SECURITY.md |
| Workload creation, PV creation are escalation paths | https://github.com/kubernetes/website/blob/main/content/en/docs/concepts/security/rbac-good-practices.md | 2026-10-28 | KN-S017 |
| Alertmanager webhook payload version 4 fields | https://github.com/prometheus/alertmanager/blob/main/docs/configuration.md | 2026-10-28 | signals/core.py |
| kubelet event reasons | https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/events/event.go | 2026-10-28 | signals/vocab.py |
| image and container error reasons | kubelet images/types.go, container/sync_result.go, kuberuntime/kuberuntime_container.go (kubernetes/kubernetes master) | 2026-10-28 | signals/vocab.py |
| FailedScheduling, FailedCreate, Evicted | kubernetes/kubernetes scheduler/schedule_one.go, controller/controller_utils.go, kubelet/eviction/helpers.go | 2026-10-28 | signals/vocab.py |
| OOMKilled, Completed, Error termination reasons | https://github.com/cri-o/cri-o/blob/main/server/container_status.go | 2026-10-28 | signals/vocab.py |
| ClusterOperator condition types | https://github.com/openshift/api/blob/master/config/v1/types_cluster_operator.go | 2026-10-28 | signals/vocab.py |
| etcd, apiserver, kubelet, workload, storage, resource, node alert names | etcd-io/etcd contrib/mixin/alerts/alerts.libsonnet; kubernetes-monitoring/kubernetes-mixin alerts/*.libsonnet and lib/absent_alert.libsonnet; prometheus/node_exporter docs/node-mixin/alerts/alerts.libsonnet | 2026-10-28 | data/signals.yaml |
| OpenShift alert names (etcd, CVO, MCO, ingress, OVN-Kubernetes) | openshift/cluster-etcd-operator manifests/0000_90_etcd-operator_03_prometheusrule.yaml; cluster-version-operator install/0000_90_cluster-version-operator_02_servicemonitor.yaml; machine-config-operator install/0000_90_machine-config_01_prometheus-rules.yaml; cluster-ingress-operator manifests/0000_90_ingress-operator_03_prometheusrules.yaml; cluster-network-operator bindata/network/ovn-kubernetes/{common/alert-rules.yaml,self-hosted/alert-rules-control-plane.yaml} | 2026-10-28 | data/signals.yaml |
| etcd error strings (leader changed, no leader, database space exceeded, apply request took too long) | etcd-io/etcd api/v3rpc/rpctypes/error.go; server/etcdserver/txn/util.go | 2026-10-28 | data/signals.yaml aliases |
| kubelet "pleg was last seen active" | kubernetes/kubernetes pkg/kubelet/pleg/generic.go | 2026-10-28 | data/signals.yaml aliases |

## Blocked and unverified

| ID | What is missing | Exact question or input needed |
|---|---|---|

## Baseline

- 2026-10-28 on 9e4c3f8 (branch with main merged): `scripts/check.sh` passes: plugin copy in sync, ruff, ruff
  format, mypy (76 files), pytest 428 passed and 1 skipped (root ignores file permissions), selftest 61/61. 23 s.
- Toolchain in the cloud container: Python 3.13.17 (project venv), uv 0.13.6, node 22.23 and npm 10.9 (npm registry
  reachable), docker CLI 29.9 without a running daemon, no kind, helm, kubectl, oc or podman (helm downloads are
  refused by the egress proxy). GitHub and raw.githubusercontent.com are reachable from the shell; docs.redhat.com
  is not (read it with web fetch). No model provider keys in the environment.
- CI (GitHub Actions) has helm, kind and docker: chart, image and cluster behaviour is proven there.

## Iteration log (newest first; at most 10 lines per entry)

- 2026-10-28 MEM3: memory.paths (config, KUBE_NOOB_MEMORY_PATHS, max 10) read by CLI/stdio/HTTP; doctor 'memory  <path>: N entries (A approved, P proposed)' or 'unreadable' + warning; chart memory.source configMap (keys MEM-<n>.yaml at /srv/kube-noob/memory/entries), pvc (readOnly claim, safe subPath), git (init container memory-clone: https args exec form, ssh via sh with $MEMORY_URL/$MEMORY_REF env and a 0400 key copy, StrictHostKeyChecking=yes, known_hosts from the Secret; emptyDir mounted read-only in the main container; NetworkPolicy egress to memory.git.egressCIDRs on 443/22/URL port; EgressFirewall dnsName for external hosts; offline: *.svc only). Schema refuses credentials/query strings in the URL, option-like refs, '..' subPaths. Helm is not installable here (get.helm.sh 403; proxy.golang.org unreachable), so rendering is proven by new CI guard assertions. Proof: KUBE_NOOB_MEMORY_PATHS=memrepo:/nope kube-noob doctor -> 'memory  .../memrepo: 1 entries (1 approved, 0 proposed)', 'memory  /nope: unreadable', warning line. Next: MEM4.
- 2026-10-28 CI fix (S4 run 40618967513 failed in pytest on 3.11-3.13): the hostile-input test took 16.8 s under coverage locally, over its 20 s budget on CI. Root causes fixed, not hidden: KnowledgeStore.search looped every chunk for every query token (49M dict lookups for a repetitive 100 KB query) -> inverted postings over distinct terms (scores unchanged: recall gate still 48/51, 0 false); signals parse JSON-looking input as JSON only (YAML on 399 KB of '{' took 1.6 s); playbook patterns scan the text once. Now 5.2 s without coverage; budget 30 s for CI's coverage run.
- 2026-10-28 MEM2: `kube-noob memory` init (README, schema, entries/, GitHub Actions workflow pinned by SHA + shell script; never overwrites) / add (proposed, next id via exclusive create, commands auto-labelled by the classifier, never commits) / validate (schema, stray and misnamed files, duplicate symptom = error, same signals = warning, reviewBy passed = warning or error with --strict, credentials anywhere in the file incl. YAML comments, verifier: patch through analyze() validate+audit+red team HIGH+, manifest grants (cluster-admin binding, wildcard RBAC, use of privileged SCC, privileged SCC objects, hostPath, privileged containers) and grants in changing commands; riskAccepted downgrades to warnings unless expired) / match (signals first, >= 3 distinctive shared words otherwise; approved only; negative = tried, did not work; fixedIn <= version = retired; introduced, platform family and operator ranges filter; payload version label) / outcome (atomic rewrite) / stats --by / migrate-learning (once per note via kn:local-N#0 citation). Found and fixed: dumper wrote &id001 anchors when two dates were equal. Proof: demo memory -> 'ERROR MEM-3 verifier: patch: audit KN-S016 (critical) ClusterRoleBinding grants cluster-admin ...' and '[mem:MEM-1] fix ... matched 3 times, resolved 2; seen on 3 of your clusters, fixed on 2', '[mem:MEM-2] tried, did not work', version 4.21.0 from the alert's label. Next: MEM3.
- 2026-10-28 MEM1: memory entry = frozen Pydantic model (extra=forbid) + deterministic YAML io. Content rules: prose via learn.memory.check_text (now names the store); commands one line, no '#' comment, label == classify_step verdict, never print a Secret (get secret -o yaml, extract secret); patch = manifests with apiVersion+kind, no Secret, no credential, 20 KB; evidence = https URL | ticket key | kn:/mem: citation | bundle:<path> (no '..'); outcomes with opaque ticket and cluster label; versions must be quoted strings (4.20 would read as 4.2) and dumped quoted; file 256 KB, one document, no duplicate keys, name == id. Operator ranges: one or two comparators, build suffixes ignored. Proof: parse_entry(GOOD) -> 'valid MEM-12 approved fix [alert:etcdHighNumberOfLeaderChanges, component:etcd] fixed_for 4.21.2: True'; a read-only label on `oc delete pod ...` -> "must be labelled needs-approval (the playbook classifier's verdict)". Next: MEM2.
- 2026-10-28 S4: diagnose/debug/bundle show signals and rank playbooks (+1 once per playbook a catalogued signal points at, so CrashLoopBackOff + BackOff never outrank OOMKilled); policy explain lists admission signals; new signals/alertmanager.py reads webhook v4 and API v2 alert lists (JSON only, 2 MB, 500 alerts, 64 labels, 2,000 chars, control chars dropped; formats verified in Prometheus docs and alertmanager api/v2/openapi.yaml); version only from an openshift_version/version label naming a 4.x release; known issues match each alert's line + summary (descriptions are rule boilerplate: matching them pulled in OCPBUGS-77921 on 'disruptions'). New DBG-ETCD playbook (etcd FAQ, maintenance guide, etcd wal.go/raft.go/txn/util.go strings, OpenShift etcd-defrag and recommended-etcd-practices) and [K8S] step tag; flag order fixed so `get` steps classify read. MCP `kubenoob_extract_signals` (read-only). Proof: `kube-noob diagnose -f alertmanager-etcd.json` -> input version 4.21.0 (label openshift_version), top DBG-ETCD confidence 1.0 with 'signal alert etcdHighNumberOfLeaderChanges', knownIssues OCPBUGS-73881 'You run 4.21.0: updating to 4.21.1 or later fixes it.' Next: MEM1.
- 2026-10-28 S3: known-issue matching expands the query with signal terms (extract + catalogue.infer), light stems limited to words that exist in the issue corpus or bundled docs, and accepts a candidate only with rare words from the text itself (3, or 1 plus signal terms to 3, or 2 with score >= 40, or 1 with score >= 40 and twice the runner-up). Frozen eval data/evals/known_issue_recall.yaml: 51 positives, 33 negatives incl. the 4 measured etcd cases. Before 36/50 recall, 1 false match (N11 'context deadline exceeded'); after 48/51 = 0.94, 0 false. Misses P21, P33, P35 (prose with no rare overlap; left as is, not tuned to the question). Found and fixed: index build deadlocked on a non-reentrant lock once it consulted the general store. Proof: `kube-noob known-issues 'etcd leader changed frequently, apiserver timeouts after upgrade' --version 4.21.0` -> 'OCPBUGS-73881 Reported and fixed in OpenShift 4.21.1. You run 4.21.0: updating to 4.21.1 or later fixes it.'; at 4.21.2 -> no match. Next: S4.
- 2026-10-28 S2: signal catalogue with 74 entries verified in etcd-io/etcd mixin, openshift/cluster-etcd-operator rules, kubernetes-mixin alerts (apiserver, kubelet, apps, storage, resource; KubeAPIDown from lib/absent_alert), node-exporter mixin, CVO, MCO, ingress-operator and CNO OVN rules, plus the S1 reason sources. Spec names corrected by the sources: MCDDrainError is MCCDrainError; OpenShift splits etcdGRPCRequestsSlow into Read and Write. No unverified names left out. Proof: catalogue.infer('etcd leader changed frequently, apiserver timeouts after upgrade') -> KubeAPIErrorBudgetBurn, etcdHighNumberOfLeaderChanges. Next: S3.
- 2026-10-28 S1: signal extraction for Alertmanager v4 payloads, core/v1 and events.k8s.io/v1 events, ClusterOperator YAML/JSON and `oc get co`, pod status, admission denials, components and normalised error templates (sha256[:12]). Vocab verified in kubelet events.go, images/types.go, sync_result.go, kuberuntime_container.go, schedule_one.go, controller_utils.go, eviction/helpers.go, CRI-O container_status.go, openshift/api types_cluster_operator.go. Found and fixed a shipped bug: redaction quadratic on dashed tokens (240 KB took 136 s, now 0.3 s). Proof: alert payload | kube-noob signals -> 'alert etcdHighNumberOfLeaderChanges', 'component etcd'. Next: S2.
- 2026-10-28 F3: capability tiers framework. Defaults off; doctor prints tier R-G and contradictions; Writer cannot exist with its tier off; Approval bound to one action, 15 min, single use; backends proven write-free. Chart renders probe/dry-run Roles only when enabled (guards in CI). Found and fixed: KN-S017 missed workload creation, ephemeral containers and PV creation (RBAC good practices). Guidance G36 (Jira copy, missing since 0.5.0) and G37 (tiers). Proof: `kube-noob doctor` shows 'tier P off probe (probe.enabled)'. Next: S1.
- 2026-10-28 F2: roadmap rewritten to the moat program with status history kept; trained-model track cut, grader and train bench kept as evaluation; learner tracks, credits, videos frozen; docs/editions.md (documentation only). Proof: tests/test_guidance.py 5 passed; check.sh green. Next: F3.
- 2026-10-28 F1: baseline recorded (above); main merged into the branch; E4 marked done by 0.5.0 with remainder
  E4b; decisions on reusing the incident ledger. M1 gap reproduced: `known-issues 'etcd leader changed frequently,
  apiserver timeouts after upgrade' --version 4.21.0` returns no match (expected OCPBUGS-73881). Next: F2.
