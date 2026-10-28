# Handoff: where the loop stands (for the next session or another model)

Read this first, then `.claude/loop/STATE.md` (the queue, decisions, verification sources, iteration log) and
`.claude/commands/build-loop.md` (how one item is built, verified and shipped). This file says what is in flight
right now; STATE.md says what is done. Updated 2026-10-28 16:00 (SAST1, G1-G3, G5, I6, QA1 done; QA2 in CI; QA3 in progress; owner sent 3,732 answered questions: QA4).

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

- VUL1: done after the independent red team (12 findings fixed, G72); CI 40676198576 green.

- BLD2 (CI gate, build/test analytics): done, CI 40661279945 and 40663077885 green.
- VUL1 (R5.1-R5.4) built and pushed in 74aae4a: `src/kube_noob/vuln/` (reports, rpmver, csaf, vex, kev, rank, threat,
  assess, attack), CLI `vuln report` / `vuln threat`, `gate --scanner-report/--vex/--kev`, MCP `vuln_report` /
  `threat_model`, insight routing, RHACS `read_images`, Action/Tekton/GitLab inputs, CI step in `gate-ci`, docs.
  STATE row 15m is `in-progress` until CI is green.

## In flight (finish these first)

1. CI: run 40719517318 on 2353551 (QA3 part + QA4). QA2 is done (CI 40715183769 green). QA3 (row 20s) and QA4
   (row 20t) stay in-progress: QA3 needs error-string playbooks; QA4 needs the owner's decision on document answers.
2. NEW (owner, 2026-10-28 15:29): answer files from Grok, third-party text, never commit them. Copies in the session
   scratchpad `qa2in/hc.csv` (3,732 rows, high-confidence accepted answers) and `qa2in/all.xlsx`; originals at
   /mnt/user-data/attachments/<session>/eb3fa585-questions_with_answers_high_confidence.csv and
   079a2f22-questions_with_answers.xlsx (ask the owner to re-attach in a new session). Columns: the questions.csv
   columns plus answer_text, answer_source_type (accepted_answer...), answer_confidence, answer_url, answer_score,
   answer_author_role, resolution_status, has_answer. Sources: stackoverflow 2,153, OCPBUGS 948, serverfault 150,
   DFBUGS 92, unix 67, repost 66, ROX 43, CMP 41. Plan (QA4): extend scripts/eval_questions.py with
   `--answers <csv>` that scores kube-noob's top finding against answer_text (overlap of commands, flags, resource
   kinds and error strings; report per answer kind, never store answer text in results), grade a stratified sample
   with an independent agent against the accepted answers, then tune on a split (tune half, hold out half).
2b. QA4 results (committed): eval answer scoring + --data-dir; independent grading against accepted answers:
   playbooks 3 agree + 11 partial of 20; reported issues 6 of 20 (else a sibling bug in the same component);
   bundled docs 0 + 2 of 30; official-docs corpus docs 1 + 5 of 40. Word-matched documents do not answer real
   pasted questions; owner decision pending (STATE "Owner actions": keep as related reading / docs only for typed
   questions / offline embeddings). Next levers in order: error-string playbooks with specific causes (mine the
   answered CSV: answer_text names the cause), reported-issue matcher preferring same symptom over same component,
   synced Jira copy, then the owner's doc decision. Agent outputs: scratchpad grade-agents/answers-graded.jsonl,
   corpus-graded.jsonl.
3. Corpus experiment (QA3): built (scratchpad corpusdata: k8s-docs 397 files, ocp-docs 2,338 modules) with
   `KUBE_NOOB_DATA_DIR=<dir> kube-noob corpus build --sources k8s-docs,ocp-docs --online`. Earlier plan: build the optional docs corpus
   (`kube-noob corpus build --sources k8s-docs,ocp-docs --online` into a scratch data dir) and add an eval option to
   reuse that data dir, to measure answers with official docs loaded vs the bundled ~140 chunks.
4. Owner grading page (private artifact): https://claude.ai/artifact/5wagdbnLepUydgbVVHJfxZ . Store `rows` holds
   116 questions (76 `set: graded`, 40 `set: held-out`) with kube-noob's answer and the current verdict; `verdicts`
   (doc id = row id) holds the owner's `{verdict, expected, updatedAt}`. To fold in: `ArtifactData list` on
   `verdicts`; the owner's verdict wins in docs/evals/community-questions-grades.csv or -heldout.csv; paraphrase
   `expected` into `note` (max 300 chars, no question text); rerun the eval with both `--grades`; commit. When an
   answer changes, update that `rows` doc (pin `if_version`). All 116 `rows` docs match the answers at commit 2353551.
5. Stack Overflow pages cannot be read here (search excludes it, api.stackexchange.com blocked); the owner's answer
   files replace that. Independent agents' reference answers (official docs) are in the scratchpad only.
6. QA3 so far (committed with this handoff): DBG-ENTRYPOINT-NOT-FOUND playbook (runc libcontainer
   standard_init_linux.go uses exec.LookPath; Go os/exec error text verified in go1.24.7 src), k8s-kubeconfig-exec
   knowledge (requires group keeps it to kubeconfig questions), README "41 offline playbooks". Still to do in QA3:
   abstain on questions about tools kube-noob does not cover (Istio, Argo CD, Trivy, Docker on a laptop) measured
   on the held-out file; mine frequent error strings from the CSV into playbooks; the corpus experiment.
4. Claude plugin directory (owner's 0.5.0 submission): held by directory policy for a reviewer, expected for any
   local stdio server. The new finding against 0.2.3 is most likely the kernel FIPS flag read, moved to
   `src/kube_noob/host_fips.py` and guarded out of the plugin
   (`tests/test_plugin.py::test_bundle_reads_no_host_system_files`). Reaches the directory with the next release
   (owner action).

## Queue after that (from STATE.md)

QA3, LT1 (blocked: owner's load image), VUL2 (blocked on DB1), RT2, then the older queue (I1, N2, N1, N5, G4, E2, E1, E3, E4b, E5, I2, I9, I8,
P1, P2, GATE1-3, V2, V3, N3, N4, A1-A5, I10, T3, I3, I4, I5, I7, GOV1-3, M13). Every enrichment that fetches anything
must be jittered (random pause between requests, jittered first run and intervals).

## Rules the owner set (do not break)

- Update README (under 600 words, `wc -w`), CHANGELOG, docs/use-cases.md, docs/architecture.md, PRIVACY.md,
  SECURITY.md, docs/guidance.md and THIRD_PARTY_NOTICES.md with every item: the owner asked that READMEs and docs
  are always current.
- Never mark an item done before CI is green. Never write the owner's email into the repo. Never enter credentials or
  sign in for the owner. Public posting, releases, tags, publishing and the skill/plugin listing need the owner.
- Owner actions go at the end of a report as exact copy-paste commands, with no comments inside the code blocks.
