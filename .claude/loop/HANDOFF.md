# Handoff: where the loop stands (for the next session or another model)

Read this first, then `.claude/loop/STATE.md` (the queue, decisions, verification sources, iteration log) and
`.claude/commands/build-loop.md` (how one item is built, verified and shipped). This file says what is in flight
right now; STATE.md says what is done. Updated 2026-10-28 (SAST1, G1, G2, G3 done; G5, I6 and QA1 waiting on CI; QA1 grading page with the owner; QA2 next).

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

1. CI: run 40704545772 on 117ae50 (plugin server crash fix: `toolkit._has_module`, find_spec raises for a missing
   parent package). Green -> mark G5 (row 18) and I6 (row 20) done. Then dispatch CI for 8ad6ffa (QA1 grades) and
   mark QA1 (row 20q) done when green. SAST1 (row 15s) is done (16 red-team findings fixed, each a test_rtN in
   `tests/test_code_redteam.py`).
2. QA1 cowork with the owner. The owner's CSV (25,292 Grok-sourced community questions) is third-party text: it stays
   out of the repo (`/tmp/.../scratchpad/qa/questions.csv` in the session that ran it; ask the owner to re-attach
   it). Committed: `scripts/eval_questions.py` (with `--grades`), `docs/evals/community-questions.md`,
   `docs/evals/community-questions-grades.csv` (76 rows: id, topic, source, answer, top, verdict, note).
   - Grading page for the owner (private artifact): https://claude.ai/artifact/5wagdbnLepUydgbVVHJfxZ . Store
     collection `rows` (seeded by Claude, rule: write admin) holds each question, kube-noob's answer and Claude's
     verdict; collection `verdicts` (doc id = row id) holds the owner's `{verdict, expected, updatedAt}`.
   - To fold the owner's grades in: `ArtifactData list` on `verdicts` (limit 1000); for each doc with a verdict, set
     that row's `verdict` in the grades CSV to the owner's (the owner wins) and put a short paraphrase of
     `expected` in `note` (max 300 chars, no copied question text); rerun the eval with `--grades`; update the
     graded table in docs/evals/community-questions.md; commit.
   - Reference answers cannot be fetched here (api.stackexchange.com blocked; stackoverflow.com fetches need
     per-URL approval). Asked the owner for an accepted-answer column.
3. QA2 (next tuning round, not started): 8 of the 11 wrong answers in the graded sample are documents chosen on
   word overlap from a 122-chunk knowledge base, and the 6 misses are core how-tos. Plan: add knowledge chunks,
   each verified against kubernetes/website or openshift-docs (shallow clones via add_repo read access worked):
   listing a Deployment's pods by label selector; kubelet will not start (journalctl -u kubelet, swap, cgroup
   driver, certificates); etcd backup and restore (etcdctl/etcdutl snapshot; OpenShift cluster-backup.sh);
   exposing an Ingress controller on bare metal (Service type LoadBalancer/NodePort, MetalLB) and its ports;
   CreateContainerError / "OCI runtime create failed"; moving Compose apps to OpenShift. Then tighten the doc
   gate (a shared term in the chunk heading, or 3+ shared specific terms) and re-grade only the `changed` rows.
4. Claude plugin directory (owner's 0.5.0 submission): held by directory policy for a reviewer, expected for any
   local stdio server. The new finding against 0.2.3 is most likely the kernel FIPS flag read, moved to
   `src/kube_noob/host_fips.py` and guarded out of the plugin
   (`tests/test_plugin.py::test_bundle_reads_no_host_system_files`). Reaches the directory with the next release
   (owner action).

## Queue after that (from STATE.md)

QA2, LT1 (blocked: owner's load image), VUL2 (blocked on DB1), RT2, then the older queue (I1, N2, N1, N5, G4, E2, E1, E3, E4b, E5, I2, I9, I8,
P1, P2, GATE1-3, V2, V3, N3, N4, A1-A5, I10, T3, I3, I4, I5, I7, GOV1-3, M13). Every enrichment that fetches anything
must be jittered (random pause between requests, jittered first run and intervals).

## Rules the owner set (do not break)

- Update README (under 600 words, `wc -w`), CHANGELOG, docs/use-cases.md, docs/architecture.md, PRIVACY.md,
  SECURITY.md, docs/guidance.md and THIRD_PARTY_NOTICES.md with every item: the owner asked that READMEs and docs
  are always current.
- Never mark an item done before CI is green. Never write the owner's email into the repo. Never enter credentials or
  sign in for the owner. Public posting, releases, tags, publishing and the skill/plugin listing need the owner.
- Owner actions go at the end of a report as exact copy-paste commands, with no comments inside the code blocks.
