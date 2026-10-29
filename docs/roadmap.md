# Roadmap: the ground truth for Kubernetes and OpenShift operations

Goal: a platform team deploys kube-noob once. Every developer and SRE then gets answers that are safe, cited and
read-only first, about their own clusters, their own runbooks and their own past fixes, so the platform team's ticket
queue shrinks. kube-noob has no AI inside: Claude, OpenShift Lightspeed or any MCP client does the talking, and the
CLI works with no model at all. Updated 2026-10-28, after 0.5.0.

## Principles

- **Models are the commodity layer.** kube-noob competes on what a model cannot supply: the team's own confirmed
  fixes, deterministic checks, evidence in seconds, and what the network actually did.
- **The verifier never acts.** Probes, server-side dry-runs, ticket writes and the gate are separate tiers, off by
  default, each action approved by a person.
- **Ship fetchers, not data.** Red Hat Jira tickets, customer tickets and team memory stay where they were fetched;
  they are never bundled, published or exported to datasets.
- **Signals over prose.** Alert names, event reasons, condition reasons and error templates are the join key between
  an error, a known issue and a past fix; text search is the fallback.
- **Land where AI is banned.** Disconnected and regulated OpenShift first; every feature also works on ROSA, EKS, AKS,
  GKE and upstream Kubernetes.

North star: time from an alert or a must-gather to an evidence pack, offline. Target: 60 seconds. Also tracked:
memory hit rate and tickets answered without escalation.

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

## The program (milestones in build order)

| Milestone | What ships | Why |
|---|---|---|
| M1 Signal-keyed matching | Signal extraction (alerts, event and condition reasons, error templates), a verified signal catalogue, known-issue matching on signals with a recall gate | Plain words miss bugs the release notes describe differently (an etcd leader-change question misses OCPBUGS-73881) |
| M2 Fixes-as-code memory | Reviewed YAML entries in the team's Git, `kube-noob memory` (validate as the poisoning guard, match, outcomes, stats), memory in every answer | The team's own confirmed fixes are the moat no model can copy |
| M3 Ticket seeding and replay | Offline ServiceNow and Jira importers, `memory replay` with a 30% useful-match gate | Tests the riskiest assumption on real tickets before more is built on it |
| M4 Must-gather pre-flight | Safe ingest, analysers, report and case draft, a custom must-gather image | The fastest path to evidence on a disconnected cluster |
| M5 Evidence breadth | Operator release notes, installed-operator inventory, Kubernetes and RHACS known issues, Jira matches filtered by what the cluster runs | Most escalations are about operators, not the core |
| M6 Network truth | Flow readers (OVN ACL log, Hubble, Network Observability), a pcap analyser, probe and capture plans, `net verify` | "Policy says allowed, packets say dropped" |
| M7 Verifier hardening | Prompt-injection sanitiser, server-side dry-run (tier D), blast radius | Text from clusters and tickets reaches models; checks must hold under attack |
| M8 Integrations without AI | Alertmanager receiver, SARIF and CI surfaces, Argo CD, chat commands, console plugin, REST API, `oc kube-noob`, runbook links, `report` and `/metrics` | Reach people where they already work |
| M9 Proactive | Upgrade pre-mortem, offline what-if | Prevent the ticket instead of answering it |
| M10 Optional AI layer | Egress log, pre-send preview, admin model controls, provider docs, bench with and without tools | For teams that bring their own key: see exactly what leaves |
| M11 kube-noob gate | An MCP proxy: kube-noob gate checks agent tool calls, holds writes for approval and keeps a tamper-evident log | The verifier position, without ever acting itself |
| M12 Governance | Identity in audit records, OSCAL, read as caller, a signed air-gap corpus pack | What regulated buyers need; candidates for an enterprise edition ([editions.md](editions.md)) |

Frozen (kept and tested, no new features): learner tracks and credits, brand videos. The grader and
`kube-noob train bench` stay as an evaluation product: they score any model or MCP client against the same tasks.
The trained-model track is cut: kube-noob stays model-free and makes every model better through its tools.

Set aside: embeddings (unless an evaluation shows signals plus BM25 fail), a hosted SaaS (conflicts with the
no-egress promise), Backstage beyond a design doc, and live outage signals from social or status feeds (conflicts with
the offline default).

## Riskiest assumptions and the cheapest test

| Assumption | Cheapest test |
|---|---|
| Team memory gets reused often enough to matter | `kube-noob memory replay` on one team's last 50 resolved tickets and the 4 weeks after: at least 30% useful matches |
| Platform teams will let an OSS tool server into the cluster | Show `doctor`, PRIVACY.md and SECURITY.md to two OpenShift admins; ask what blocks approval and whether they would enable probes and dry-runs |
| Developers will ask it before opening a ticket | Turn on the Lightspeed integration for one team; compare ticket counts for the top 5 categories over 4 weeks |
| Read-as-caller is possible without new infrastructure | Prototype with oauth-proxy's `--pass-access-token` on a test cluster |
| "No AI inside" reads as a strength, not a gap | Post two headlines a week apart ("No AI inside. Works with yours." and "The ground truth your AI SRE checks against") and compare click-through to the repository |
