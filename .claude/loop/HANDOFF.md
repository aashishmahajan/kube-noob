# Handoff: where the loop stands (for the next session or another model)

Read this first, then `.claude/loop/STATE.md` (the queue, decisions, verification sources, iteration log) and
`.claude/commands/build-loop.md` (how one item is built, verified and shipped). This file says what is in flight
right now; STATE.md says what is done. Updated 2026-10-28 (SAST1, G1-G3, G5, I6, QA1 done; QA2 waiting on CI; grading page with the owner; QA3 next).

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

1. CI: run 40715183769 on 001b088 (QA2). Green -> mark QA2 (row 20r) done. G5, I6, QA1 and SAST1 are done.
2. Owner grading page (private artifact): https://claude.ai/artifact/5wagdbnLepUydgbVVHJfxZ . Store `rows` holds
   116 questions (76 graded sample, `set: graded`; 40 held-out, `set: held-out`) with kube-noob's answer and the
   current verdict; `verdicts` (doc id = row id) holds the owner's `{verdict, expected, updatedAt}`. To fold the
   owner's grades in: `ArtifactData list` on `verdicts`; for each doc with a verdict set that row's verdict in
   `docs/evals/community-questions-grades.csv` or `docs/evals/community-questions-heldout.csv` (the owner wins), put
   a short paraphrase of `expected` in `note` (max 300 chars, no copied question text), rerun
   `scripts/eval_questions.py <csv> --out <dir> --grades <graded> --grades <heldout>`, update
   docs/evals/community-questions.md, commit. When an answer changes, update that `rows` doc (pin `if_version`).
   The owner's CSV is third-party text: never commit it; ask the owner to re-attach it in a new session.
3. Reference answers: Stack Overflow is unreachable here (search excludes it, api.stackexchange.com is blocked,
   direct fetches need per-URL approval; mirrors are off limits) and the GitHub API covers only attached repos.
   Asked the owner to have Grok add `accepted_answer_summary`, `answer_score`, `answer_url` columns. Meanwhile two
   independent agents graded 116 rows from official docs (agreement with Claude 67/76 exact). Their reference
   answers are in the session scratchpad only (grade-agents/graded-*.jsonl), not in the repo.
3b. QA3 (next tuning round, todo): knowledge for the in-scope misses the agents named, each checked against the
   docs: CreateContainerError / "OCI runtime create failed" at pod start; kubeconfig exec credential plugins
   ("exec: executable aws not found"); stopping `kubectl proxy`; finding the Ingresses that route to a Service;
   is PodSecurityPolicy on (k8s-pss covers removal; the question did not reach it). Held-out wrong answers are
   mostly docs answering questions about other tools (Istio, Argo CD, Trivy, Docker on a laptop): consider a
   `requires` group on broad docs, measured on the held-out file. Measured and dropped: symptom-title posts as
   questions (3,013 more answers, 2 of 25 helpful).
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
