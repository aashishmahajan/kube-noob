# Release readiness: kube-noob 0.1.0

Assessment date: 2026-10-27. Scope: verify end to end before publishing, audit the product, map ROSA HCP gaps, list
free training sources, and set the improvement and distribution plan. Every claim below is backed by a command that was
run, a CI job, or a cited source.

## 1. End-to-end verification

| Area | How it was verified | Result |
|---|---|---|
| Tests | 134 tests on Python 3.11, 3.12 and 3.13 in CI; coverage gate 80 % | pass, 83 % |
| Packaging | wheel + sdist built, `twine check`, installed from the hash-pinned `requirements.lock` into a clean venv, `pip check` | pass |
| CLI | 26 commands run against the installed wheel (audit, validate, fix, redteam, protocol, generate, helm-chart, diagnose, search, rules, explain, learn *, train *, config, corpus *) | pass; `helm-audit` needs the `helm` binary (CI covers it) |
| MCP stdio | SDK client spawning `kube-noob mcp`: 22 tools (19 annotated read-only), 3 prompts, resources; audit, protocol, generate, diagnose, search, grade | pass |
| MCP HTTP | bearer auth (401), Host/Origin checks (421/403), body limit (413, declared and chunked), audit log, live-cluster tools, Secrets refused | pass |
| Kubernetes | CI `e2e-kind`: server-side dry run of generated manifests, legacy removed-API bundle migrated by `fix` and accepted by the API server, image build, Helm install with read-only RBAC, live crash-loop diagnosis, Secrets refused | pass |
| Helm chart | `helm lint --strict`, template + self-audit (Kubernetes and OpenShift 4.22), chart guards (fail-closed NetworkPolicy, fsGroup only off-OpenShift, web flag wired) | pass |
| Air-gapped | Whole workflow inside a network namespace with no route (internet unreachable): audit, fix, protocol, generate, diagnose, search, learn, grade, red team, MCP stdio and HTTP, agent with a local model on loopback | pass |
| Local model | Agent loop against an OpenAI-compatible endpoint: tool call, tool result, cited answer; fabricated citation detected | pass |
| Web (opt-in) | live fetch of an allowlisted domain; non-allowlisted host blocked; disabled mode raises; tool not registered when off | pass |
| Scale | real Git corpus (22,913 chunks): index build 1.9 s; server RSS 77 MB idle, 210 MB with the index; search p50 22 ms in-process, about 40 ms over HTTP | fits the 384-512 Mi limits |
| Release pipeline | `workflow_dispatch` dry run: wheel + `twine check`, multi-arch (amd64 + arm64) UBI image build | pass |
| Corpus refresh | 1,200 public ROX issues for 4.10+ (explicit versions), 17 Git sources, release history | pass |
| Supply chain | `pip-audit` (no known vulnerabilities), CodeQL, OpenSSF Scorecard, SHA-pinned actions | pass |

Not verified here (no access from this environment):
- A live OpenShift or ROSA HCP cluster. Routes, SCCs and OpenShift APIs are covered by strict schemas, audit rules and
  the kind e2e of the generic paths only. Run the ROSA HCP smoke test in section 7 before announcing ROSA support.
- A real Anthropic model call (no API key in this session). The Anthropic provider is unit-tested with a fake client.

## 2. Self-audit: residual risks

| # | Risk | Severity | Status / next step |
|---|---|---|---|
| R1 | One shared static bearer token for the HTTP service; no per-user identity or per-tool authorization | Medium | Front the service with kube-rbac-proxy or the OpenShift OAuth proxy (TokenReview + SubjectAccessReview); add MCP OAuth 2.1 for remote listings |
| R2 | Untrusted text (Jira issues, web pages, cluster annotations and logs) reaches the calling model and can carry prompt injection | Medium | Server is read-only, so the blast radius is bad advice, not actions. Next: wrap untrusted text in explicit envelopes with an `untrusted` flag |
| R3 | Built-in facts age (OCP 4.22, RHACS 5.0 dates) | Medium | Weekly corpus refresh exists; add staleness warnings per document |
| R4 | Lexical (BM25) retrieval misses paraphrases | Low | Optional hybrid retrieval with local embeddings |
| R5 | Reward is a proxy over 16 held-out tasks | Medium (training) | Grow the benchmark, keep it held out, spot-check with the eval-only LLM judge |
| R6 | Rules audit workload manifests, not cluster-level ROSA configuration | Gap | See section 3 |
| R7 | Not run on a real OpenShift / ROSA HCP cluster | High for release claims | Run the smoke test before announcing |
| R8 | In-memory index grows about 6 KB per chunk | Low | On-disk SQLite FTS5 index for large corpora |
| R9 | Jira text is not redistributable | Handled | Marked `redistributable: false`, excluded from exports and the image |

Fixed during this assessment: tools now reject misspelled arguments instead of ignoring them; HTTP bodies over 8 MB are
rejected before parsing; every tool call is audit-logged without content; unreachable or failing model endpoints raise
a clear error instead of a traceback; the release workflow now registers QEMU so the arm64 image can build.

## 3. ROSA HCP: covered vs missing

Covered today: architecture, CIDR defaults, decoupled upgrades and machine-pool skew, EFS vs EBS (`KN-ST001`), no
MachineConfig on ROSA (`KN-V017`), zone spread raised to MEDIUM on ROSA (`KN-C010`), PDBs that block managed upgrades
(`KN-C009`), the `rosa-hcp` generator (efs-sc, Routes, EgressFirewall), the `DBG-ROSA-HCP-NODES` playbook and the
zone-outage red-team scenario.

Missing, grounded in the current openshift-docs ROSA HCP modules:

| Gap | What to add | Docs evidence (openshift-docs `modules/`) |
|---|---|---|
| Cluster-level configuration audit | Validate `rosa create cluster` flags and Terraform `rhcs` resources: machine CIDR size, private + PrivateLink, egress lockdown (egress zero), KMS keys, FIPS roles, shared VPC, external auth + break-glass, no-CNI clusters | `rosa-hcp-egress-zero-*`, `rosa-hcp-creating-cluster-with-aws-kms-key-prereqs`, `rosa-hcp-sts-creating-a-cluster-external-auth-provider-cli`, `rosa-hcp-no-cni-expected-behavior`, `rosa-hcp-sharing-vpc-*` |
| Machine pools | Spot pools and termination queue, Capacity Reservations (no autoscaling), Windows License Included pools, disk sizes, Local Zones edge pools, tuning configs, kubeletconfig, n-2 skew in upgrades | `rosa-hcp-config-spot-instance-*`, `creating-a-machine-pool-cli-capres`, `creating-a-machine-pool-cli-win-li`, `configuring-machine-pool-disk-volume`, `edge-machine-pools-aws-local-zones`, `rosa-creating-node-tuning`, `rosa-hcp-upgrade-machine-pools` |
| AutoNode (Karpenter) | Validate `EC2NodeClass` / `NodePool` resources, discovery tags, readiness conditions; troubleshooting playbook | `autonode-troubleshooting`, `karpenter-resource-readiness`, `rosa-hcp-upgrade-karpenter-managed-nodes` |
| AWS identity for workloads | IAM roles for service accounts (`rosa create iamserviceaccount`), role-arn annotation checks, Secrets Store CSI with the AWS provider | `rosa-by-example-content` |
| Live ROSA data | Read-only `rosa` / OCM backend: describe cluster, machine pools, upgrades, ingress, autoscaler, log forwarders | `rosa-cli-hcp-examples` |
| Control-plane logs | Guidance and checks for `rosa create log-forwarder` (CloudWatch / S3) | `rosa-manage-control-plane-log-forwarding`, `rosa-hcp-set-up-log-forwarding` |
| Upgrade readiness | One report: removed APIs for the target OCP version, PDB blockers, machine-pool skew, operator compatibility | `rosa-hcp-upgrade-options`, `rosa-hcp-upgrade-a-cluster` |
| HCP playbooks | No-CNI not ready, external-auth login failures and break-glass, spot interruptions, Karpenter provisioning failures, egress-lockdown blocked endpoints, private-cluster DNS | modules above |
| Red-team scenarios | Spot interruption, capacity-reservation exhaustion, IdP outage, KMS key disabled, egress dependency blocked | modules above |

## 4. Free sources for retrieval and training

Licenses were checked from each repository's LICENSE file on 2026-10-27.

Already ingested (17 Git sources): Kubernetes docs (CC BY 4.0), OpenShift docs, HyperShift docs, Red Hat Cloud Experts,
rosa CLI, terraform-rhcs ROSA HCP module, StackRox policies and changelog, GitOps catalog, EFS CSI, Kubernetes examples,
Kubernetes The Hard Way, CASL Ansible, kubernetes.core Ansible (Apache-2.0 unless noted), Helm docs and CKAD exercises
(MIT), awesome-kubernetes; plus public ROX Jira issues (retrieval only).

New, redistributable:

| Source | License | Use |
|---|---|---|
| openshift/runbooks | Apache-2.0 | alert -> runbook pairs for debugging |
| kubernetes-monitoring/kubernetes-mixin, prometheus-operator/runbooks | Apache-2.0 | alerts and runbooks |
| kyverno/policies, open-policy-agent/gatekeeper-library | Apache-2.0 | policy <-> rule mapping, admission policy generation |
| stackrox/kube-linter, FairwindsOps/polaris, kubescape/regolibrary | Apache-2.0 | cross-validate and extend audit rules |
| aquasecurity/trivy-checks | MIT | misconfiguration checks |
| falcosecurity/rules | Apache-2.0 | runtime detection knowledge |
| kubernetes/enhancements, openshift/enhancements | Apache-2.0 | design rationale and feature history |
| kubernetes/kubernetes (CHANGELOG, OpenAPI) | Apache-2.0 | API history |
| argoproj/argo-cd, cert-manager/website, kubernetes-sigs/kustomize, operator-framework/operator-sdk, openshift/oc-mirror | Apache-2.0 | ecosystem docs |
| bitnami/charts | Apache-2.0 | real-world charts for Helm audit training |
| Red Hat Security Data (CSAF/VEX, OSV, SPDX SBOMs) | CC BY 4.0 with attribution | offline vulnerability triage |
| github/advisory-database | CC BY 4.0 | language-dependency advisories |

Retrieval only (share-alike or no license): aws/aws-eks-best-practices and OWASP Kubernetes Top Ten (CC BY-SA 4.0),
public Jira projects, Microsoft Threat Matrix for Kubernetes (no LICENSE file). Do not ingest CIS Benchmark text (CIS
terms); reference CIS control ids only.

Turning sources into training data: grounded Q/A with citations, alert -> diagnosis pairs from runbooks, policy ->
(violating manifest, fixed manifest) pairs, VEX -> remediation pairs. Every pair is verified by the deterministic
grader; no LLM-generated labels are exported by default.

## 5. Improvements

### Vulnerability remediation
- Offline vulnerability data: mirror Red Hat CSAF/VEX and OSV into the corpus with version and retrieval date.
- `kube-noob vuln triage` ingesting Trivy, Grype and `roxctl image scan` / `deployment check` JSON.
- Risk = severity x exposure: combine CVE data with audit context (root, privileged, internet-exposed Route/LB,
  NetworkPolicy reachability) to rank what to fix first; honour VEX `not_affected`.
- Remediation outputs: UBI base-image bump by digest, package fix versions, manifest digest pins, and RHACS policy
  exceptions with expiry for accepted risk. MCP tools `kubenoob_vuln_triage` and `kubenoob_vuln_explain`.

### Security assessment
- Framework mapping: NSA/CISA Kubernetes Hardening Guide, CIS control ids, OWASP Kubernetes Top Ten ids.
- Ingest OpenShift Compliance Operator results and RHACS violations through the read-only cluster tools.
- Graphs: RBAC (who can exec, escalate or read Secrets), NetworkPolicy reachability, exposure inventory; red-team
  scenarios as attack paths over the graph.
- Prevent regressions: generate Kyverno, Gatekeeper or ValidatingAdmissionPolicy (CEL) from findings.
- Outputs: SARIF for code scanning, JUnit for CI, Markdown report.

### Sidecar and MCP
- Today: loopback-only sidecar, restricted-v2 compatible, read-only root filesystem, 77-210 MB, about 2 s cold index.
- Identity and authorization: kube-rbac-proxy or OAuth proxy in front of the service; per-tool groups (cluster tools for
  SRE only); MCP OAuth 2.1 metadata for remote clients.
- Rate limits and concurrency caps; untrusted-content envelopes; OpenTelemetry metrics and traces.
- Persisted SQLite FTS5 index; a shared read-only corpus image volume for many sidecars.
- MCP elicitation for Step 1 (Clarify), so the server asks blocking questions interactively.

### Offline, local and frontier models
- Offline triage is the default and is verified in an air-gapped namespace.
- Local models: any OpenAI-compatible endpoint (vLLM, Ollama, llama.cpp, OpenShift AI model serving) via
  `llm.provider: openai-compatible`; plain http only to loopback or `*.svc` unless explicitly allowed.
- Frontier: Anthropic by default (`claude-fable-5-1` with server-side fallbacks); other providers through an
  OpenAI-compatible gateway.
- Real-time search (next): pluggable search backends when `webEnabled` is on, e.g. self-hosted SearXNG (queries stay
  private) or a search API; results still pass the domain allowlist; cached with TTL; answers carry a freshness date.
- Routing (next): keep cluster data on the local model, send design questions to the frontier model, configured per
  data class.
- Fine-tuning path: `train export` -> TRL GRPO with `trl_reward` -> serve on OpenShift AI -> point `llm.baseUrl` at it
  -> `train bench` against the frontier baseline.

## 6. Distribution

In progress: channel-by-channel requirements (Claude Code plugin marketplace, MCP Registry, Claude Desktop bundles,
claude.ai connectors, Red Hat container/Helm/operator certification, OperatorHub) are being verified against official
documentation and will be added here with sources.

## 7. Release gates

| Gate | Status |
|---|---|
| CI green on main | done |
| Release dry run (wheel + multi-arch image) | done |
| PyPI trusted publisher (pending) | done by maintainer |
| Private vulnerability reporting and security fixes enabled | maintainer action |
| ROSA HCP smoke test on a real cluster | maintainer action, recommended before announcing |
| Tag `v0.1.0` | after the gates above |

### ROSA HCP smoke test

Run from a workstation that is logged in to a ROSA HCP cluster with `oc login` (read-only calls only; `openshift-console`
exists on every cluster):

```bash
uvx --from git+https://github.com/aashishmahajan/kube-noob kube-noob debug deployment/console -n openshift-console --platform rosa-hcp --cluster-enabled
oc get deploy,svc,route,pvc,networkpolicy -n openshift-console -o yaml | uvx --from git+https://github.com/aashishmahajan/kube-noob kube-noob audit -f - --platform rosa-hcp --version 4.22
```

Expected: the first command prints pod and event evidence with no write calls; the second prints an audit report.
