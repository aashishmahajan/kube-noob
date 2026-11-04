# Roadmap: the ground truth for Kubernetes and OpenShift operations

Goal: a platform team deploys kube-noob once. Every developer and SRE then gets answers that are safe, cited and
read-only first, about their own clusters, their own runbooks and their own past fixes, so the platform team's ticket
queue shrinks. kube-noob has no AI inside: Claude, OpenShift Lightspeed or any MCP client does the talking, and the
CLI works with no model at all. Updated 2026-11-03, after 0.7.1.

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
- **A disclosure is not a decision.** Every defect found in the 2026-11-03 review had one shape: the information
  was present and the decision ignored it. `controlSummary` was computed from a list the exception filter had
  already emptied; `policy reach` named `ClusterNetworkPolicy` under `notEvaluated` and returned `allowed` with
  exit 0; `REMOVED_APIS` answered "nothing removed" for versions nobody had read; compaction hoisted one finding
  list and left the other; `policy_generate` returned 95,000 tokens to a caller that cannot hold them; the weekly
  review left every superseded week open. In each case a careful human reading the whole output would have seen
  the caveat, and the gate, the pipeline or the model consuming it would not. So a caveat belongs in the verdict,
  the exit code or the shape -- the part that is acted on -- and a note beside it is at best a courtesy. When the
  two disagree, the note is the bug.

North star: time from an alert or a must-gather to an evidence pack, offline. Target: 60 seconds. Also tracked:
memory hit rate and tickets answered without escalation.

## Who it serves

| Who | Job to be done | What they use today | What kube-noob changes |
|---|---|---|---|
| App developer | When my deploy fails on the shared cluster, find out why without opening a ticket | Slack the platform team, search the wiki, paste logs into a public chatbot | `diagnose` and the Lightspeed or Claude tools give the cause and read-only steps, in the company's terms |
| SRE / on-call | Get from symptom to evidence fast, without making it worse | Personal notes, tribal knowledge | Playbooks that read before they change, a redacted evidence `bundle`, confirmed team notes |
| Platform team | Stop answering the same 20 questions; enforce conventions before deploy | Docs nobody reads, admission policies that only say "no" | Org runbooks indexed and cited, audit in CI, a weekly "top issues" signal |
| Security | Allow AI assistants without data leaving the boundary | Ban them | No model inside kube-noob, offline lock, `doctor`, no egress, signed images, nothing exported |
| Compliance / GRC | Produce evidence an assessor accepts, from a disconnected cluster | Screenshots, spreadsheets, a console they cannot export from | Findings already named to NIST SP 800-53 Rev. 5 controls, a coverage record that distinguishes clean from unchecked, and OSCAL a tool can import |

## Status

Everything below is in the released code unless the row says otherwise. Dates are release dates.

| Item | Status | Release |
|---|---|---|
| Offline lock, `doctor`, web GET-only and text-only; diagnose-first playbooks; redacted bundle | Done | 0.2.0 |
| "No AI inside" stated and enforced by a test; plugin runs bundled source from a hash-pinned `uv.lock`; PRIVACY.md | Done | 0.2.1 |
| CI on Kubernetes 1.33-1.37 (OpenShift 4.20, 4.21, 4.22, next); sidecar under Pod Security restricted | Done | 0.2.1 |
| Chart: generated token, namespace-scoped RBAC, optional EgressFirewall, signed OCI chart; Homebrew | Done | 0.2.1-0.2.3 |
| Reported issues matched to the OpenShift release notes with link, fix version and workaround | Done | 0.3.0 |
| Audit findings name their NIST SP 800-53 Rev. 5 controls; `doctor` reports FIPS mode; FedRAMP High deployment guide | Done | 0.3.1 |
| Policy debugging: six admission systems explained from a denial, with the smallest fix; NetworkPolicy reachability | Done | 0.3.1 |
| Incident watch: always-on read-only detection, each incident explained once with what changed before it | Done | 0.4.0 |
| Red Hat Jira copy and known-issue answers that say what became of the ticket | Done | 0.5.0 |
| Playbooks for the weakest technologies; triage tuned on a training set and checked on real posts | Done | 0.6.0 |
| `policy migrate-check` for legacy Kyverno; generated safety contract and scorecard; Ceph health codes | Done | 0.7.0 |
| HTTP server hardening: connection-burst 503, per-caller state, health-endpoint abuse, body limit, nesting guard | Done | 0.7.1 |
| ANP -> NetworkPolicy -> BANP precedence evaluated offline, naming the deciding tier, policy and rule | Done | 0.7.1 |
| An unread cluster-scoped policy is `undetermined` and exit 1, for a pasted file and for `policy reach` against the cluster. That covers `ClusterNetworkPolicy`, `CiliumClusterwideNetworkPolicy` (`cilium.io/v2`) and Calico `GlobalNetworkPolicy` (`crd.projectcalico.org/v1`). None of those is parsed. A namespace `CiliumNetworkPolicy` still does not flip pod-to-pod traffic | Done | Unreleased |
| Zero-install path proven: `kubectl apply 2>&1 \| uvx --from kube-noob kube-noob policy explain`, 9 s cold | Done | Unreleased |
| OpenShift Helm catalog (community) submission | **Not started.** The `OWNERS` pull request has never merged; nothing is in `charts.openshift.io`. Blocks the chart PR behind it | after 0.8.0 |
| Claude plugin directory listing | **Held, not actionable.** Ten versions, all "In review". The hold is `Runs a pinned npx or uvx package`, which the directory's own checklist lists as held by design for any launcher. Escalated | - |
| Admission under a real `restricted-v2` SCC in CI | At risk: needs an OpenShift cluster for CI | Next |
| `corpus-refresh`, `db-image` scheduled workflows | **Failing.** Scrubber misses bare Atlassian account ids; the bundler packs a VEX shard its own checker rejects | 0.8.0 |

## The program

Reordered 2026-11-03 after four independent reviews. The order is: **correctness before capability, capability
before reach, reach before breadth.** A verdict that can be wrong costs more than a feature that is missing.

### Now: 0.8.0

| # | Item | State | Why it is first |
|---|---|---|---|
| P0 | **Same-priority `AdminNetworkPolicy` ties are "not determined"** | Shipped | Two policies at one priority were decided by document order, silently. Upstream says the choice is implementation-defined and OVN-Kubernetes raises `ANPWithDuplicatePriority`. The README promises both policy commands "say what they could not determine"; this is the one place they do not |
| P1 | **Coverage record: which rules ran over which objects** | Not started | `controlSummary` lists only controls that have findings, so "clean" and "never evaluated" are indistinguishable. Every compliance output built on top of that would claim satisfaction from silence, which is the exact failure FedRAMP's own guidance names. Nothing else in the compliance arc is honest until this exists |
| P2 | **`kubectl krew` plugin** | Not started | Both `noob` and `kube-noob` are unclaimed in krew-index. A shell script that execs the installed CLI or falls back to `uvx`, mapping kubectl-shaped verbs onto commands that already take stdin. No new binary, no new Python, and it is the index platform engineers actually browse |
| P3 | **OSCAL assessment-results emitter** | Not started | `audit --oscal`, `gate --oscal`. Pure serialisation of data already computed, once P1 makes it honest. Deterministic v5 UUIDs so CI can diff it; `oscal-version: 1.2.1` for trestle interop; validated in CI against the pinned NIST schema with ajv, because Python's `jsonschema` cannot read the token pattern |
| P4 | **`ClusterNetworkPolicy` v1alpha2 evaluated, not just named** | Not started | **The wrong verdict is fixed; the capability is not.** G172 stopped the lie: a v1alpha2 CNP in the input now makes `policy reach` answer `UNDETERMINED` and exit 1, where it used to answer `ALLOWED` and exit 0 with the kind named only under `notEvaluated`. What remains is reading the policy so the answer can be allowed or denied rather than unknown. It is not "mostly a kind and tier mapping": v1alpha2 renamed the action `Allow` to **`Accept`** and replaced the port field with **`protocols`** (`tcp`/`udp`/`sctp`, each with `destinationPort`), so the existing evaluator would read every rule wrong. Budget a week. Calico 3.32 **removed** ANP/BANP enforcement -- "You must migrate to ClusterNetworkPolicy before upgrading to v3.32" (Tigera, 13 May 2026) -- so on a Calico 3.32 cluster the policies kube-noob does evaluate are the ones that no longer apply |
| P5 | **Fix the two failing scheduled workflows** | VEX member sharded; corpus-refresh's latest run is green | The scheduled `db-image.yml` could not pack `redhat-vex.jsonl` (2.78 GB) under `MAX_MEMBER` (300 MB). The cap was not raised. A shard over 250 MB is written as parts and read back as one corpus (G185). `corpus-refresh` is green as of 2026-11-04; the privacy gate still refuses a copy that matches a person-shaped pattern, and that refusal is the gate working |
| P6 | **A version ceiling on the API tables** | Shipped | `REMOVED_APIS` is stated "as of Kubernetes 1.37" and its highest removal is 1.32, and nothing anywhere says what the table has not checked. A question about a later minor is therefore answered "no removals", which is a verdict earned by absence (G163) -- and it stops being hypothetical on **16 December 2026**, when Kubernetes 1.38 is released (kubernetes.dev schedule; cycle began 31 August 2026). A `CHECKED_THROUGH` constant and a `beyondCheckedVersions` note on `validate` and `api_history` when the target minor exceeds it. Hours, and dated |
| P7 | **Calico 3.32 no longer enforces what kube-noob evaluates** | Live read shipped; the inert-ANP case is not | **Reading the object is not the same as knowing the CNI ignores it.** A `GlobalNetworkPolicy` or `CiliumClusterwideNetworkPolicy` on the cluster is now `undetermined`, the same as a pasted one. What is still open is the opposite shape: the input carries an `AdminNetworkPolicy` that kube-noob evaluates, while Calico 3.32 does not enforce it. That takes knowing the CNI and its version. `policy migrate-check` is the right home |

### Next: 0.9.0

| # | Item | Why |
|---|---|---|
| N1 | **Compliance Operator results reader** | `compliancecheckresults` and `rules.compliance.openshift.io` are namespaced, non-secret, get/list. Their `Rule` CRs carry NIST, CIS, SRG and PCI annotations and `checkType: Node\|Platform`. Reading them gives node-level CIS, STIG and PCI results kube-noob can never produce itself, already licensed to the customer, attributed to the operator and never to kube-noob |
| N2 | **Must-gather node configuration** | A standard must-gather carries every rendered `MachineConfig`, including `kubelet.conf`, kernel arguments, `fips`, CRI-O config and the container signature policy. kube-noob opens that bundle and routes eight analyser buckets; this is parsing an artifact already in hand, not a new privilege |
| N3 | **Curated FedRAMP 20x KSI evidence** | FedRAMP's machine-readable crosswalk maps 25 of kube-noob's 27 controls to KSIs, but several of the 27 reachable indicators are absurd as config evidence. Ship a hand-curated allowlist of about ten, each with a sentence on what the finding does and does not show, carrying FedRAMP's own "do not claim compliance from a mapping alone". **Pin the release and exclude the retired indicators.** `FRMR.KSI.key-security-indicators.json` is at release **25.11C** (published 2025-12-01) with 20x at `current_status: Phase 2 Pilot`; the eleven families (AFR, CED, CMT, CNA, IAM, INR, MLA, PIY, RPL, SVC, TPR) are intact, but seven individual indicators now carry `retired: true` -- KSI-CMT-05, KSI-MLA-03, KSI-MLA-04, KSI-MLA-06, KSI-SVC-03, KSI-TPR-01, KSI-TPR-02. An allowlist built without that list would claim evidence for an indicator FedRAMP has withdrawn, which is worse than claiming none; the mapped release string has to ship with the allowlist and be asserted, because this file moves on its own schedule |
| N4 | **Per-namespace standing posture** | `drift diff` already groups open findings `byNamespace`, `byOwner`, `byRule`. With P1 this becomes per-control standing rather than a count |
| N5 | **Rules in the under-served set** | Namespace with no Pod Security `enforce` label; webhook `failurePolicy: Ignore`; workloads with no ResourceQuota or LimitRange; `MachineConfigPool` paused as an SI-2 finding; `Subscription` on automatic approval. Each is something no other tool checks on OpenShift |
| N6 | **Decision chain in the terminal** | A text rendering of what `policy reach` already computes, and of an attack path. Formatting over existing data; makes the wedge visible without a canvas |
| N7 | **Numeric `targetPort` with no declared `containerPort`** | KN-V012 catches the named case. The numeric case is unflagged, and can only be advisory because Kubernetes does not require the declaration |
| N8 | **API-server configuration from a must-gather** | TLS profile, audit policy and effective arguments from `kubeapiservers.operator.openshift.io/cluster`. Field stability across 4.x needs a real bundle first |
| N9 | Generate the rule table in `docs/compliance.md` from code | It is hand-kept and guarded by a test; generation is the same pattern as the safety contract |

### Later, unchanged in intent

M6 network truth (`net verify`: policy says allowed, packets say dropped) stays the insurance on the policy wedge,
and needs an OVN cluster to validate. M7 verifier hardening, M8 integrations, M9 proactive, M10 the optional AI
layer, M11 `kube-noob gate` and M12 governance keep their meaning; identity in audit records and the signed air-gap
pack remain enterprise candidates in [editions.md](editions.md).

## What this refuses to be

Encompassing more means reading more artifacts, emitting more formats and reaching more places. It does not mean
taking privileges the tool has promised not to take, and it does not mean competing on rule count.

| Refused | Why |
|---|---|
| A node agent, DaemonSet, or any `nodes/proxy` or exec read | Breaks the contract every other surface rests on. The Compliance Operator path gives the same evidence read-only |
| Embedding CIS Benchmark text, or claiming "CIS compliance" | The benchmarks are non-commercial-use and not redistributable. Section numbers reach us free through ComplianceAsCode and the Compliance Operator's own annotations |
| A single compliance score, or a percentage of 800-53 | 27 of about 1,189 controls. A percentage invites exactly the misreading FedRAMP warns against |
| Image registry scanning | Network, and Trivy and RHACS own it. Keep ingesting their output |
| Hosted compute, hosted cluster state, or shareable server-side links | "Nothing leaves your device" is the product. The browser playground already delivers zero-install without a backend |
| Any model inside the tool | The positioning, and a test enforces it |
| ISO 27001 mapping, certificate expiry from Secrets, a generic RBAC viewer | No free machine-readable crosswalk; forbidden; already answered by attack paths |

## The honest ceiling on compliance

kube-noob names 27 of NIST SP 800-53 Rev. 5's controls across its 78 rules. The right sentence is **"machine-readable
evidence bearing on these 27 controls, from these object kinds, over this scope, with these rules not applicable and
these inputs unreadable"** — never "compliance coverage", never a percentage. It does not assess the other controls,
it does not scan nodes itself, and it is not a substitute for a continuous posture platform. A GRC team will not
switch to it; they will run it beside what they already have, for the evidence those tools cannot export from a
disconnected cluster.

## Riskiest assumptions and the cheapest test

| Assumption | Cheapest test | State |
|---|---|---|
| Team memory gets reused often enough to matter | `kube-noob memory replay` on one team's last 50 resolved tickets and the 4 weeks after: at least 30% useful matches | **Blocked on a design partner, not on code.** The harness, the gate and the no-hindsight controls exist; "useful" is a human label, so it needs one team's export and a grader |
| Platform teams will let an OSS tool server into the cluster | Show `doctor`, PRIVACY.md and SECURITY.md to two OpenShift admins; ask what blocks approval | Not run |
| Developers will ask it before opening a ticket | Turn on the Lightspeed integration for one team; compare ticket counts for the top 5 categories over 4 weeks | Not run |
| Read-as-caller is possible without new infrastructure | Prototype with oauth-proxy's `--pass-access-token` on a test cluster | Not run |
| "No AI inside" reads as a strength, not a gap | Post two headlines a week apart ("No AI inside. Works with yours." and "The ground truth your AI SRE checks against") and compare click-through to the repository | Not run |
| The two policy questions are ones people actually hit | Publish the counterexample where a NetworkPolicy-only answer is wrong, and watch whether anyone brings their own manifests | Counterexample published (`examples/netpol-admin-tiers.yaml`, README); no external user yet |

The first row is the one that decides whether the ledger is a moat or a feature. Until that number exists and is
written down as pass or fail, kube-noob is a careful linter with two answers no other tool gives.
