# Community questions eval (QA1)

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

A stratified sample of 76 rows (4 per topic) was graded by hand (correct lead, partly relevant, wrong, nothing where
kube-noob should have helped, nothing where the question is outside kube-noob's scope).

## Results (2026-10-28)

| Measure | Before | After |
|---|---|---|
| OpenShift bug as the answer to a non-Red Hat question | 5,274 | 29 |
| ROSA playbook on a non-ROSA question | 53 | 0 |
| Arbitrary-UID playbook off OpenShift | 71 | 9 |
| Rows with a reported-issue answer | 30.0% | 6.3% |
| Rows with a playbook answer | 5.8% | 5.9% |
| Rows with documents | 17.8% | 15.1% |
| Rows with no answer | 46.3% | 72.7% |
| Jira keys found in the top 3, of keys in the index (71) | 69.0% | 70.4% |
| Jira keys found in the top 3, all 2,943 Jira rows | 1.7% | 1.7% |
| Graded sample: correct or partly relevant answers | 4 | 7 |
| Graded sample: wrong answers | 16 | 11 |
| Graded sample: in-scope questions with no answer | 10 | 6 |
| Graded sample: out-of-scope questions with no answer | 46 | 52 |
| Run time for all rows | 114 s | 85 s |

What changed: release notes are searched for a text with no platform only when it says it is about OpenShift
(diagnose, insight and the watch; `known-issues` still searches them, being an OpenShift question by definition);
everyday English words, in any inflection, no longer count as rare evidence; OpenShift and ROSA playbooks need
OpenShift or ROSA words when no platform is given (an OpenShift playbook's specific patterns still count); new
trigger phrases for a stuck PVC, DNS trouble in words and `oc get co` rows; documents are offered only when they
share enough specific words with the question; forum posts that ask in their title or a sentence are read as
questions.

## What the numbers say, and what is next

- Most of the dataset is outside what an offline Kubernetes and OpenShift assistant can know: application code,
  Docker Compose, other clouds' consoles, upstream bug reports and feature requests. Answering nothing there is right.
- The reported-issue matcher is now precise; its recall is bounded by what the index holds. With a synced local
  Jira copy (`kube-noob corpus jira`) the 2,872 Jira rows outside the release notes become findable: the next run
  should measure that.
- Documents are the weakest answers: the bundled knowledge has 122 chunks, so a how-to question ("list the pods of
  a deployment") often has no relevant chunk and lexical overlap picks a wrong one. Wider knowledge is the lever,
  not more matching rules.
- An accuracy grade needs reference answers. Accepted answers for a stratified set (or a person grading the review
  sample) would turn the coverage numbers into an accuracy number.
