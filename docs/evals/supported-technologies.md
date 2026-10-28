# Supported technologies: what kube-noob answers from, and how well it answers

kube-noob has no model inside. Each answer comes from one of four sources, so what it can answer about a technology
is exactly what it carries for that technology:

- **Playbooks**: diagnoses keyed on exact error text, with causes, read-only checks and fixes
  (`src/kube_noob/debug/playbooks.py`).
- **Reported issues**: OpenShift bugs from the release notes with the release that fixed them
  (`src/kube_noob/data/known_issues/`, OpenShift 4.20-4.22 bundled; `kube-noob corpus known-issues` builds more
  minors, `kube-noob corpus jira` syncs Red Hat's public Jira).
- **Knowledge**: hand-written, cited sections searched by shared words (`src/kube_noob/data/knowledge/`).
- **Rules and engines**: the audit rules, schemas and policy explainers (Pod Security, SCC, RBAC, Kyverno,
  Gatekeeper, ValidatingAdmissionPolicy, RHACS policies).

## What is bundled per technology (2026-10-28)

| Technology | Playbooks | Knowledge documents | Reported issues | Rules and engines |
|---|---|---|---|---|
| Kubernetes (upstream, kubectl, kubeadm) | 49 that apply everywhere | 43 (incl. the Helm, RHACS and policy-engine docs), incl. pods, probes, DNS, Services, Ingress, storage, scheduling, RBAC, Pod Security, TLS, kubelet, etcd backup, kubeconfig exec, kubeadm first-day problems, Deployment rollouts, invalid UTF-8 in runtime requests | none (upstream Kubernetes bugs not indexed) | audit rules and strict schemas (Kubernetes 1.35), removed APIs, NetworkPolicy reachability, Pod Security and RBAC denial explainers |
| OpenShift 4.x | 49 shared + 10 OpenShift-only (SCC, Route 503, ClusterOperator, arbitrary UID, EgressIP, build image quota, CNI not ready, OLM OperatorGroup, image prune registry, CRI-O storage) | 13 OpenShift docs (SCC, Routes, operators, DeploymentConfig, EgressFirewall, EgressIP, arbitrary UID, install and bootstrap, ClusterOperator conditions and stuck updates, etcd quota, pod security label sync, service serving certificates, overview) | 921 bugs from the 4.20-4.22 release notes | SCC, Route and EgressFirewall schemas; must-gather analysis; SCC denial explainer |
| ROSA HCP and classic | shared + 9 ROSA playbooks (HCP nodes, OCM5011 capacity, OCM5010 subnet tags, ELB service-linked role, user-role not linked, expired rosa token, Karpenter discovery tag and CreateTags) | 5 (ROSA HCP, EFS, egress zero, HCP lifecycle: console, subnet tags, upgrades, break glass, deletion; troubleshooting: install logs, quota, private NLB) | HyperShift bugs within the OpenShift release notes | ROSA HCP self-test cases |
| Helm 3 | DBG-HELM-LOCK, DBG-HELM-OWNERSHIP, DBG-HELM-REPO-EXISTS, DBG-HELM-REMOVED-API, DBG-HELM-YAML, DBG-IMMUTABLE-SELECTOR | 5 (basics, troubleshooting, values and templates, CLI operations: `--set` syntax, OCI, rollback, three-way merge, paths; chart authoring: `crds/`, hooks, library charts, whitespace, comments) | none | chart audit and generation |
| RHACS / StackRox | DBG-STACKROX-ADMISSION + 6 (break glass, webhook failure policy, Scanner registry and CVE data, Collector to Sensor, roxctl image check) | 6 (overview, admission denials, enforcement, policy rules and scope, roxctl in CI, secured cluster troubleshooting) | none (ROX bugs only through a Jira sync) | RHACS policy comparison, scanner-report and image reads |
| Admission policy engines (Pod Security, VAP, Kyverno, Gatekeeper, SCC) | DBG-PSA, DBG-WEBHOOK, DBG-SCC, DBG-VAP | Pod Security, ValidatingAdmissionPolicy, Kyverno, Gatekeeper, RBAC, SCC, OpenShift pod security sync | none | denial explainers for each engine; generated VAP and Kyverno policies |
| OpenShift Data Foundation, Ceph | storage playbooks (PVC pending, multi-attach, mount) | storage access modes | ODF bugs not indexed | none |

## How well it answers: measured per technology

Graded against accepted answers from the owner's answered-question set (Stack Overflow, Server Fault, forums and
Red Hat Jira resolutions; third-party text, not in this repository). Rows are split once by a hash of their id;
these numbers come only from the **test half** (`scripts/eval_questions.py <csv> --split test`), graded by three
independent agents that saw the question, the accepted answer and kube-noob's answer, never a score.

| Technology | Answered (graded) | Helpful (agrees + partly) | Agrees | Silent rows graded | Silent but should have answered |
|---|---|---|---|---|---|
| Kubernetes | 25 | 9 (36%) | 2 | 10 | 7 |
| OpenShift | 25 | 14 (56%) | 8 | 10 | 6 |
| ROSA HCP | 20 | 7 (35%) | 3 | 8 | 4 |
| Helm | 20 | 2 (10%) | 0 | 8 | 5 |
| ODF / Ceph | 15 | 3 (20%) | 0 | 6 | 5 |
| RHACS | 9 | 2 (22%) | 0 | 8 | 7 |
| Admission policy engines | 8 | 0 | 0 | 8 | 0 |

By answer type across these 180 rows: playbooks helped on 19 of 33, reported issues on 10 of 43 (right when the
bug or its clone is indexed, otherwise a sibling bug), documents on 8 of 46. The graders differ in strictness (one
found no exact agreements in its 60 rows, another found 9), so read the counts as ranges of about plus or minus a
third.

What the graders said kube-noob needed, across the rows it got wrong or left unanswered: a reported-issue entry
for a bug fixed in a named release (69 rows: OpenShift, ROSA HCP, ODF and RHACS bugs outside the 4.20-4.22
release notes), a knowledge document (50 rows: mostly Helm usage and core Kubernetes how-tos) and a playbook with a
specific cause (21 rows).

## Golden questions: what an official-docs reader would ask (baseline 2026-10-28)

`tests/fixtures/golden/` holds 119 questions written for kube-noob from each technology's official documentation
(kubernetes/website, helm/helm-www Helm 3, openshift/openshift-docs for OpenShift, ROSA HCP and RHACS, the Kyverno
and Gatekeeper sites), each with a paraphrased reference answer and the source file at a pinned commit, plus four
questions per technology about another product (Flux, Istio, EKS, Trivy, AWS Lambda...) that should get no answer.
Independent agents wrote them without seeing kube-noob, and other independent agents graded kube-noob's top finding
against the reference: **answers** (cause and fix), **partly**, **wrong** or **silent**. A golden item passes only
when the top finding answers it.

| Technology | In scope | Top finding answers | Partly | Wrong | Silent | Out of scope left unanswered |
|---|---|---|---|---|---|---|
| Kubernetes | 16 | 4 (25%) | 2 | 8 | 2 | 4 of 4 |
| Helm 3 | 16 | 1 (6%) | 1 | 10 | 4 | 2 of 4 |
| OpenShift | 16 | 1 (6%) | 2 | 8 | 5 | 3 of 3 |
| ROSA HCP | 16 | 1 (6%) | 4 | 9 | 2 | 1 of 4 |
| RHACS | 16 | 0 | 3 | 12 | 1 | 2 of 4 |
| Admission policy engines | 16 | 0 | 8 | 6 | 2 | 3 of 4 |
| **All** | **96** | **7 (7%)** | **20** | **53** | **16** | **15 of 23** |

Read this as the size of the gap, not as a verdict on the engine: the community test half (above) is mostly
error text that the playbooks were built for, while the golden questions sample the whole of each technology's
documentation, most of which kube-noob does not carry yet. The graders named what each miss needs (`gap` in each
item): for Kubernetes and Helm mostly a document section or a playbook for a specific error string; for OpenShift,
ROSA HCP and RHACS mostly content kube-noob has none of (OLM, CRI-O, service CA, OCM error codes, auto node, roxctl,
Scanner); for the policy engines a playbook ranked above the one-line policy explanation. Out-of-scope misses are
questions that name ROSA or OpenShift but ask about EKS, AWS Lambda or application code, which the platform words
let through.

`python scripts/eval_golden.py` reruns it; CI fails when a passing item stops passing or an out-of-scope item that
was left unanswered gets an answer. Once a change is made to close a golden gap, that item no longer measures how
well kube-noob generalises: it is kept as a regression test, and generalisation is measured on the community test
half and on fresh questions.

### After QA6: gaps closed for every technology (2026-10-28)

QA6 added the playbooks and documents the graders asked for, each checked against the page they named (CHANGELOG),
first for Kubernetes and Helm, then for OpenShift, ROSA HCP, RHACS and the policy engines (drafted from the cited
pages by separate agents that never saw the golden questions, then reviewed and verified before they went in).
Golden results now, graded again by independent agents:

| Technology | In scope: top finding answers | Out of scope left unanswered |
|---|---|---|
| Kubernetes | 15 of 16 (was 4) | 4 of 4 |
| Helm 3 | 16 of 16 (was 1) | 4 of 4 (was 2) |
| OpenShift | 12 of 16 (was 1) | 3 of 3 |
| ROSA HCP | 16 of 16 (was 1) | 2 of 4 (was 1) |
| RHACS | 14 of 16 (was 0) | 4 of 4 (was 2) |
| Admission policy engines | 11 of 16 (was 0) | 4 of 4 (was 3) |
| **All** | **84 of 96 (was 7)** | **21 of 23 (was 15)** |

OpenShift and ROSA HCP items are now asked with their platform (`platform: openshift` or `rosa-hcp`), as kube-noob
is configured on those clusters; without it, OpenShift-only content stays silent unless the question says OpenShift
(G83), and OpenShift scores 6 of 16 instead of 12 (ROSA HCP questions name ROSA, so they score 16 either way). The
baseline above was measured without a platform.

These golden items said what to add, so their rise is a fit to them, not evidence that kube-noob generalises; they
stay as regression tests. The honest check is the community test half (1,788 answered rows, retired rows left out),
which none of these changes were built from. An independent grader compared each changed answer with the accepted
answer:

| Change | Answers moved | Better | Worse | Neither |
|---|---|---|---|---|
| Kubernetes and Helm content | 36 | 4 | 2 | 30 |
| Bug matcher counts each piece of evidence once | 52 | 12 | 0 | 40 |
| OpenShift, ROSA HCP, RHACS and policy content | 62 | 8 | 3 | 51 |
| Prefixed names match bare; AWS Security Hub gated | 10 | 6 | 2 | 2 |
| Falco and NeuVector questions get no document | 2 | 2 | 0 | 0 |
| Helm namespaced releases and template scope; last-sentence questions | 10 | 5 | 0 | 5 |
| Comments in code blocks no longer split sections | 7 | 1 | 2 | 4 |
| Six documented gap answers; pod, storage and limits documents need their subject's words | 66 | 32 | 12 | 22 |
| 19 frequent documents need their subject's words (answered rows; a random 100 of the rest) | 80; 100 | 60; 84 | 4; 3 | 16; 13 |
| Invalid UTF-8 playbook and its narrowly gated document | 6 | 3 | 3 | 0 |

Most moved answers were wrong both before and after: real questions are dominated by Red Hat bug reports (the
bundled release notes hold the key for few of them) and by products outside the box, which documentation content
does not reach. What helped real posts most was saying less: the bug-matcher change stopped weak matches to
unrelated bugs (letting the answer point at the bug the report itself names), and the subject gates stopped the most
used documents from answering posts about something else. Rarity in the bundled docs is a count of sections (at most 2), not
a share, so adding documents never makes more words rare; as a share it had made four rows that pointed at the
right bug name an unrelated one. A count of documents was tried and measured worse (33 test-half answers moved: 4
better, 24 worse, 5 neither; most rows with no answer started naming an unrelated bug), so it was not kept and those
rows are retired.

## How these numbers move

- Tune on the train half, report on the test half: `python scripts/eval_questions.py <answered.csv> --out <dir>
  --split test`. Never pick changes by reading test-half rows; a test row that informed a change is retired:
  [community-questions-retired.csv](community-questions-retired.csv) lists it with the change it informed, and
  `--split test` leaves it out (`retiredExcluded` in the summary). The QA5 changes below (the Helm values document,
  the image-pull playbook's local-image cause, the SCC wording) were chosen from the graders' notes on the table
  above, so its 28 Helm rows and 5 image-pull and SCC rows are retired and the table is the before picture (QA6 retired 38 more: 5 rows whose regression led to count-based rarity and 33 that showed a count of documents was worse).
- The golden set (`tests/fixtures/golden/`, run by `scripts/eval_golden.py` and `tests/test_golden.py`) is
  original text written from each technology's official documentation, so it lives in the repository and gates CI.
- More answered questions per technology come from the owner (RHACS, Kyverno, Gatekeeper, ROSA HCP and Helm have
  the fewest), and more reported issues from the release notes of more OpenShift minors and a synced Jira copy.
