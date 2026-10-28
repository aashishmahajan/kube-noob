# Community questions eval (QA1 to QA4)

How well kube-noob answers what people actually ask, measured on 25,292 public questions, issues and bug reports
the owner collected (Stack Overflow, Server Fault, GitHub issues and discussions, Red Hat Jira OCPBUGS and ROX,
Kubernetes and Docker forums, AWS re:Post; 2009 to 2026, 90% from 2024 to 2026). The questions are third-party
text and are not in this repository; `scripts/eval_questions.py <csv> --out <dir>` reruns the eval on any CSV with
the same columns and writes per-row results without the question text.

## Method

Every row is pasted into `insight` (title and the 300-character excerpt, as a user would paste them), offline, with
the platform from the row's tags. The CSV has no reference answers, so three things are measured:

- Ground truth where the row names it: a Red Hat Jira row is a reported bug, so the reported-issue matcher should
  return its key in the top 3. Most keys are not in the bundled release-note index (they would be in a synced local
  Jira copy), so recall is also given for the keys the index holds.
- What kind of answer each row gets: a playbook diagnosis, a reported issue, documents, or nothing.
- Misfires that are wrong by construction: an OpenShift release-note bug as the answer to a question about another
  platform, the ROSA playbook on a non-ROSA question, the OpenShift arbitrary-UID playbook off OpenShift.

A stratified sample of 76 rows (4 per topic) was graded by hand: correct lead, partly relevant, wrong, nothing where
kube-noob should have helped, nothing on a Red Hat bug whose key only a synced Jira copy holds, and nothing where
the question is outside what an offline Kubernetes and OpenShift assistant should know. The verdicts are in
[`community-questions-grades.csv`](community-questions-grades.csv) (row ids, kube-noob's answer, verdict and a short
note; no question text).

The graded sample is also the tuning set, so a second sample checks that a change helps beyond it: 40 rows drawn at
random from the 2,424 rows whose answer the QA2 round changed, none of them in the graded sample, graded by an
independent agent that wrote a reference answer for each from the Kubernetes and OpenShift documentation without
seeing earlier verdicts ([`community-questions-heldout.csv`](community-questions-heldout.csv)). The same agent graded
the 76-row sample too: it gave the same verdict on 67 of 76 rows and the same class (helpful, wrong, no answer) on 74;
where it differed it was stricter (four answers it called partly relevant where this file says correct).

## Results (2026-10-28)

| Measure | Before | QA1 | QA2 |
|---|---|---|---|
| OpenShift bug as the answer to a non-Red Hat question | 5,274 | 29 | |
| ROSA playbook on a non-ROSA question | 53 | 0 | |
| Arbitrary-UID playbook off OpenShift | 71 | 9 | |
| Rows with a reported-issue answer | 30.0% | 6.3% | 5.8% |
| Rows with a playbook answer | 5.8% | 5.9% | 5.9% |
| Rows with documents | 17.8% | 15.1% | 11.7% |
| Rows with no answer | 46.3% | 72.7% | 76.6% |
| Jira keys found in the top 3, of keys in the index (71) | 69.0% | 70.4% | 70.4% |
| Jira keys found in the top 3, all 2,943 Jira rows | 1.7% | 1.7% | 1.7% |
| Graded sample: correct or partly relevant answers | 4 | 7 | 12 |
| Graded sample: wrong answers | 16 | 11 | 5 |
| Graded sample: in-scope questions with no answer | 10 | 6 | 5 |
| Graded sample: no answer, Red Hat bug outside the index or out of scope | 46 | 8 + 44 | 9 + 45 |
| Graded sample: helpful share of the answers given | 20% | 39% | 71% |
| Held-out changed rows (40): correct or partly relevant answers | 5 | | 4 |
| Held-out changed rows (40): wrong answers | 33 | | 14 |
| Held-out changed rows (40): helpful share of the answers given | 13% | | 22% |
| Run time for all rows | 114 s | 85 s | 89 s |

The held-out "before" column is this file's own grading of the earlier answers; "QA2" is the independent agent's.
Scaled to the 2,424 rows the round changed, that is roughly 1,150 fewer wrong answers for about 60 fewer helpful
ones: most of what the round removed were wrong documents, and what it added (new knowledge) answers questions the
earlier code got wrong or left unanswered.

What changed: release notes are searched for a text with no platform only when it says it is about OpenShift
(diagnose, insight and the watch; `known-issues` still searches them, being an OpenShift question by definition);
everyday English words, in any inflection, no longer count as rare evidence; OpenShift and ROSA playbooks need
OpenShift or ROSA words when no platform is given (an OpenShift playbook's specific patterns still count); new
trigger phrases for a stuck PVC, DNS trouble in words and `oc get co` rows; documents are offered only when they
share enough specific words with the question; forum posts that ask in their title or a sentence are read as
questions.

QA2 added knowledge for the in-scope questions the graded sample missed or answered wrongly, each fact checked
against the Kubernetes and OpenShift documentation (a Deployment's pods by label selector; a kubelet that will not
start; etcd backup and restore; reaching an Ingress from outside and why an Ingress serves HTTP and HTTPS only;
moving a Compose app with Kompose; a non-root container that cannot write its volume; ports below 1024 on
OpenShift), and gated documents: with no platform given an OpenShift- or ROSA-only doc needs the question to say
OpenShift or ROSA; a doc may declare `requires` word groups in its front matter; a typed question that names
something the knowledge has never seen needs three shared words; and shared words are counted over the whole
section, not the search preview. One idea was measured and dropped: reading a forum post whose title states a
symptom ("... not starting", "... issue") as a question answered 3,013 more rows, and 2 of a random 25 of those
answers helped.

## What the numbers say, and what is next

- Most of the dataset is outside what an offline Kubernetes and OpenShift assistant can know: application code,
  Docker Compose, other clouds' consoles, upstream bug reports and feature requests. Answering nothing there is right.
- The reported-issue matcher is now precise; its recall is bounded by what the index holds. With a synced local
  Jira copy (`kube-noob corpus jira`) the 2,872 Jira rows outside the release notes become findable: the next run
  should measure that.
- Documents are still the weakest answers outside the tuned sample: 14 of the 18 held-out answers were wrong, most
  on questions about other tools (Istio, Argo CD, Trivy, Docker on a laptop) that share Kubernetes words with a
  bundled doc. Knowledge now has 139 chunks (122 before QA2); the in-scope misses the agents named (an OCI runtime
  error at pod start, kubeconfig exec plugins, `kubectl proxy`, finding the Ingresses that route to a Service) are
  the next knowledge to add, each checked against the documentation.
- An accuracy grade needs reference answers. The independent agent's reference answers stand in for them here;
  accepted answers from the sources (Stack Exchange cannot be read from this environment) would replace them.

## Against accepted answers (QA4, 2026-10-28)

The owner then supplied 3,732 of the questions with a high-confidence answer each: 2,598 accepted answers (Stack
Overflow, Server Fault, Unix, AWS re:Post, forums) and 1,125 Jira resolutions or release notes. The answers are
third-party text and stay out of the repository; `scripts/eval_questions.py` reads `answer_text` when the CSV has
it. Two measures:

- Independent grading: an agent compared kube-noob's top finding with the accepted answer for a random sample (70
  rows kube-noob answered, 20 it did not), without seeing any score, and separately for 40 random rows answered from
  the official docs corpus (`kube-noob corpus build --sources k8s-docs,ocp-docs`, then `--data-dir`).
- A lexical score for trends (`answerShare`: the share of the answer's specific words in the top finding;
  `answerAgrees` at 0.15 and at least 3 shared words). Against the independent grading it is right about 6 times in
  10 when it says "agrees" and finds about half of the helpful answers, and it overrates long documents, so it is
  quoted only as a trend; the graded sample is the measure.

| kube-noob's answer (bundled knowledge) | Graded | Agrees | Partly right | Wrong |
|---|---|---|---|---|
| Playbook | 20 | 3 | 11 | 6 |
| Reported issue | 20 | 6 | 0 | 14 |
| Documents | 30 | 0 | 2 | 28 |
| Documents from the official docs corpus | 40 | 1 | 5 | 34 |

Of 20 rows without an answer, 10 were right not to answer and 10 had an answer kube-noob should hold (core
Kubernetes how-tos, and OpenShift bugs fixed in a release).

What this says:

- Playbooks are the reliable answer: 14 of 20 helped, though 11 of those named the symptom without the specific cause
  (CrashLoop, x509, image pull, degraded operator). More playbooks keyed on exact error strings, with the specific
  causes inside them, are the most direct gain.
- Reported issues are right when the bug itself or its clone is in the index (6 of 20) and otherwise name a sibling
  bug in the same component. A synced Jira copy makes the right bug findable; the matcher also needs to prefer the
  same symptom over the same component.
- Documents matched by shared words do not answer real questions: 2 of 30 helped, and loading the full official docs
  does not change that (6 of 40). Half the misses were questions about other products or plain Docker; the other half
  were in-domain questions answered with a different feature that shares a keyword. More text to search does not fix
  word matching; meaning-based matching, or not offering documents for pasted posts, does. That is an owner decision
  (it touches "No AI inside"), recorded in `.claude/loop/STATE.md`.
- After QA4, a question that names another product is answered by a document only if the document mentions it.

## Re-grading after a tuning change

```sh
python scripts/eval_questions.py questions.csv --out ../qa-run --sample-review 76 \
  --grades docs/evals/community-questions-grades.csv --grades docs/evals/community-questions-heldout.csv
```

A verdict carries over only while kube-noob gives the same answer kind and the same top finding for that row.
`summary.json` → `graded` counts the carried verdicts and lists every graded row whose answer moved (`changed`, with
the old verdict and the old and new answers); in `review.csv` those rows keep the old verdict in `previousVerdict`
and an empty `verdict` to fill in. Update the grades file with the new verdicts and commit it with the change, so
the graded numbers above always describe the code next to them.
