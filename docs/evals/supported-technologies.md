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
| Kubernetes (upstream, kubectl, kubeadm) | 35 that apply everywhere | 31 (incl. the Helm and RHACS docs), incl. pods, probes, DNS, Services, Ingress, storage, scheduling, RBAC, Pod Security, TLS, kubelet, etcd backup, kubeconfig exec | none (upstream Kubernetes bugs not indexed) | audit rules and strict schemas (Kubernetes 1.35), removed APIs, NetworkPolicy reachability, Pod Security and RBAC denial explainers |
| OpenShift 4.x | 35 shared + 5 OpenShift-only (SCC, Route 503, ClusterOperator, arbitrary UID, EgressIP) | 8 OpenShift docs (SCC, Routes, operators, DeploymentConfig, EgressFirewall, EgressIP, arbitrary UID, overview) | 921 bugs from the 4.20-4.22 release notes | SCC, Route and EgressFirewall schemas; must-gather analysis; SCC denial explainer |
| ROSA HCP and classic | shared + DBG-ROSA-HCP-NODES | 3 (ROSA HCP, EFS, egress zero) | HyperShift bugs within the OpenShift release notes | ROSA HCP self-test cases |
| Helm 3 | DBG-HELM-LOCK, DBG-HELM-OWNERSHIP, DBG-IMMUTABLE-SELECTOR | 3 (Helm basics, Helm troubleshooting, values and templates: precedence, `--reuse-values`, `.` and `$` scope, dashed keys, Helm 3 command changes) | none | chart audit and generation |
| RHACS / StackRox | DBG-STACKROX-ADMISSION | 2 (RHACS overview, admission denials) | none (ROX bugs only through a Jira sync) | RHACS policy comparison, scanner-report and image reads |
| Admission policy engines (Pod Security, VAP, Kyverno, Gatekeeper, SCC) | DBG-PSA, DBG-WEBHOOK, DBG-SCC | Pod Security, RBAC, SCC | none | denial explainers for each engine; generated VAP and Kyverno policies |
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

## How these numbers move

- Tune on the train half, report on the test half: `python scripts/eval_questions.py <answered.csv> --out <dir>
  --split test`. Never pick changes by reading test-half rows; a test row that informed a change is retired:
  [community-questions-retired.csv](community-questions-retired.csv) lists it with the change it informed, and
  `--split test` leaves it out (`retiredExcluded` in the summary). The QA5 changes below (the Helm values document,
  the image-pull playbook's local-image cause, the SCC wording) were chosen from the graders' notes on the table
  above, so its 28 Helm rows and 5 image-pull and SCC rows are retired and the table is the before picture.
- The golden set (`tests/fixtures/golden/`, run by `scripts/eval_golden.py` and `tests/test_golden.py`) is
  original text written from each technology's official documentation, so it lives in the repository and gates CI.
- More answered questions per technology come from the owner (RHACS, Kyverno, Gatekeeper, ROSA HCP and Helm have
  the fewest), and more reported issues from the release notes of more OpenShift minors and a synced Jira copy.
