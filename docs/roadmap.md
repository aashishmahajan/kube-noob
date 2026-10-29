# Roadmap: enterprise self-help for Kubernetes and OpenShift

Goal: a platform team deploys kube-noob once. Every developer and SRE then gets answers that are safe, cited and
read-only first, about their own clusters and their own runbooks, so the platform team's ticket queue shrinks.
kube-noob has no AI inside: Claude, OpenShift Lightspeed or any MCP client does the talking, and the CLI works with no
model at all. Updated 2026-10-28, after 0.5.0.

## Who it serves

| Who | Job to be done | What they use today | What kube-noob changes |
|---|---|---|---|
| App developer | When my deploy fails on the shared cluster, find out why without opening a ticket | Slack the platform team, search the wiki, paste logs into a public chatbot | `diagnose` and the Lightspeed or Claude tools give the cause and read-only steps, in the company's terms |
| SRE / on-call | Get from symptom to evidence fast, without making it worse | Personal notes, tribal knowledge | Playbooks that read before they change, a redacted evidence `bundle`, confirmed team notes |
| Platform team | Stop answering the same 20 questions; enforce conventions before deploy | Docs nobody reads, admission policies that only say "no" | Org runbooks indexed and cited, audit in CI, a weekly "top issues" signal |
| Security | Allow AI assistants without data leaving the boundary | Ban them | No model inside kube-noob, offline lock, `doctor`, no egress, signed images, nothing exported |

## Status

| Item | Status | Release |
|---|---|---|
| Offline lock, `doctor`, web GET-only and text-only | Done | 0.2.0 |
| Diagnose-first playbooks, redacted bundle, paste-safe commands | Done | 0.2.0 |
| Upgrade-safe learning file; your own runbooks via `corpus add-docs` | Done | 0.2.0 |
| `selftest` (61 questions), demos, use cases, guidance traceability | Done | 0.2.0 |
| "No AI inside" stated and enforced by a test; no model configured by default | Done | 0.2.1 |
| Claude plugin runs bundled source with a hash-pinned `uv.lock` | Done | 0.2.1 |
| PRIVACY.md with every destination; retention, egress and sizing documented | Done | 0.2.1 |
| Two independent red-team reviews, all findings fixed with regression tests | Done | 0.2.1 |
| CI on Kubernetes 1.33 to 1.37 (OpenShift 4.20, 4.21, 4.22, next); sidecar under Pod Security restricted | Done | 0.2.1 |
| Chart: generated token, namespace-scoped RBAC, optional EgressFirewall, signed OCI chart | Done | 0.2.1 |
| Homebrew (Apple silicon, Linux); `diagnose` takes pasted text | Done | 0.2.1 |
| Claude plugin passes the plugin directory's checks (one policy hold: dependencies download at install) | Done | 0.2.2 |
| Release writes the Homebrew formula; CI installs it the way users do (tap, `brew install kube-noob`) | Done | 0.2.3 |
| Reported issues: errors matched to the OpenShift 4.20 to 4.22 release notes with link, fix version and workaround | Done | 0.3.0 |
| Every answer states the knowledge date; live checks read the cluster version; web results marked external | Done | 0.3.0 |
| Red Hat Jira copy: every ticket (any status) of the OpenShift, ROSA, ACM and RHACS projects, synced through the REST API at one request per second; known-issue answers say what became of the ticket (fixed in which release, open, not a bug, won't fix, duplicate) with the workaround from the comments | Done | 0.5.0 |
| Incident watch: always-on, read-only detection in the service or terminal; each incident explained once, with what changed before it and the fix the team confirmed for earlier occurrences | Done | 0.4.0 |
| Audit findings name their NIST SP 800-53 Rev. 5 controls; `doctor` reports FIPS mode; FedRAMP High deployment guide | Done | 0.3.1 |
| Policy debugging: Kyverno, Gatekeeper, ValidatingAdmissionPolicy, Pod Security, SCC, RHACS, quota, LimitRange and RBAC denials explained with the fix; NetworkPolicy reachability (offline or live, read-only) with the smallest allow policy | Done | 0.3.1 |
| OpenShift Helm catalog (community) submission | Not started: needs the owner's fork and pull requests ([openshift-catalog.md](openshift-catalog.md)) | after 0.2.2 |
| Admission under a real `restricted-v2` SCC in CI | At risk: needs an OpenShift cluster for CI | Next |

## Now (0.6.0): lightweight wins that reuse what exists

Each reuses the existing rules, playbooks and counters. None needs new infrastructure or a model.

| Capability | Why it matters | Effort |
|---|---|---|
| Known issues for Kubernetes too (OpenShift release notes and Red Hat Jira are done): Kubernetes changelogs | "Is this a known bug, and which version fixes it?" is the first question on every escalation | Medium |
| `audit --format sarif` plus a GitHub Action and a pre-commit hook | Findings show as code-scanning alerts on the pull request: the cheapest way into every team's workflow | Small |
| Runbook links: map playbook and rule ids to the company's own URLs (`runbooks.yaml`) | Answers point at "our runbook for this", in the company's terms | Small |
| `upgrade-check --to 4.22`: removed APIs, DeploymentConfig, Pod Security and SCC changes for the target version | Every OpenShift upgrade starts with this question | Small |
| `report`: the 10 problems hit most this week, from the id-only counters; a `/metrics` endpoint with the same counts | The platform team fixes root causes (a default, a doc, a quota) instead of tickets | Small |
| `lightspeed-config`: print the OLSConfig snippet and Secret commands for this install | Removes the most error-prone setup step | Small |
| `diagnose --brief`: one cause, one read-only command | Fits a chat reply or a glance at the terminal | Small |

## Next

1. **Org policy packs.** Teams add audit rules in YAML ("images only from registry.acme.com", "label team= required").
2. **Runbooks in the in-cluster service.** An init container indexes a Git repo or ConfigMap of runbooks at start.
3. **Air-gapped corpus pack.** A signed corpus bundle to mirror into disconnected clusters with the image.
4. **`oc kube-noob` plugin** (krew-style), so `oc kube-noob diagnose pod/api` works where people already are.
5. **Regulated environments.** Caller identity in every audit record and per-user authorization behind the OAuth
   proxy; OSCAL assessment results from `audit`; the FedRAMP 20x Key Security Indicator mapping; a FIPS-mode CI
   runner ([compliance.md](compliance.md)).

## Later: bigger bets

1. **Answers scoped to the caller's own permissions.** Pass the caller's OpenShift identity (oauth-proxy or
   Lightspeed's client token) and read the cluster as that user. This is the main blocker for multi-tenant clusters;
   until then the chart reads only its own namespace plus `rbac.namespaces`.
2. **Single sign-on for the HTTP service** (an oauth-proxy option in the chart).
3. **OperatorHub** (Software Catalog) operator bundle, once the Helm community listing has users.

Set aside: Slack or Teams bots (Lightspeed and Claude already give the chat surface), embeddings (BM25 with term joins
passes the self-test, 24 of 25 on unseen paraphrases), a hosted SaaS (it conflicts with the no-egress promise), and a
model inside the kube-noob package (a trained model ships separately: next section).

## Trained-model track (proposed)

A model trained on kube-noob's rules, playbooks, known issues and the team's approved fixes ships as its own signed
artifact, served on OpenShift AI and used by OpenShift Lightspeed, with kube-noob as its MCP tools. kube-noob itself
stays model-free. Each phase ships only when its gate passes.

| Phase | Ships | Gate |
|---|---|---|
| 0.3 | Known-issue matching (OpenShift done), knowledge date on every answer (done), policy debugging (done) | Every match cites a Red Hat or upstream page; no false matches on the evaluation set |
| 0.4 | Chart registers kube-noob in `OLSConfig` (`MCPServer` gate); approved team fixes and runbooks from Git or a ConfigMap, read-only to callers | Lightspeed passes the 61-question selftest through the tools on a test cluster |
| 0.5 | Training pipeline on OpenShift AI from `kube-noob train export`; runs in the model registry; scored with the reward, selftest and safety checks | Beats the base model on the frozen set; no answer changes the cluster first |
| 0.6 | Signed ModelCar image and model card; KServe + vLLM `InferenceService`; `OLSConfig` points at it | Installs on a disconnected cluster within the agreed latency |
| 1.0 | Approved fixes feed scheduled retraining; weekly top-issues report | No regression on the frozen set; a person approves each model release |

## Riskiest assumptions and the cheapest test

| Assumption | Cheapest test |
|---|---|
| Platform teams will let an OSS tool server into the cluster | Show `doctor`, PRIVACY.md and SECURITY.md to two OpenShift admins; ask what blocks approval |
| Developers will ask it before opening a ticket | Turn on the Lightspeed integration for one team; compare ticket counts for the top 5 categories over 4 weeks |
| BM25 over their runbooks is good enough | Run `selftest` plus 20 questions written by the team against their own `add-docs` corpus |
| Read-as-caller is possible without new infrastructure | Prototype with oauth-proxy's `--pass-access-token` on a test cluster |
| "No AI inside" reads as a strength, not a gap | Post two headlines a week apart ("No AI inside. Works with yours." and "The Kubernetes rulebook your AI is missing") and compare click-through to the repo |
