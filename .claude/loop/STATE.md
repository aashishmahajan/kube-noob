# Build loop state

Read by every iteration of `.claude/commands/build-loop.md`. The loop updates this file and commits it with the work.
Statuses: `todo`, `in-progress`, `done`, `blocked` (reason and the exact question or missing input).

## Work queue (in order; take the first `in-progress`, else the first `todo` whose dependencies are `done`)

| # | ID | Item | Depends on | Status | Evidence / notes |
|---|---|---|---|---|---|
| 1 | F1 | Baseline and loop scaffolding | - | todo | |
| 2 | F2 | Strategy into the docs (roadmap, editions) | F1 | todo | |
| 3 | F3 | Capability tiers framework | F1 | todo | |
| 4 | S1 | Signal extraction module | F1 | todo | |
| 5 | S2 | Signal catalogue (verified names only) | S1 | todo | |
| 6 | S3 | Known-issue matching with signals plus recall eval | S2 | todo | |
| 7 | S4 | Signals in diagnose, debug, bundle, policy explain; Alertmanager payload input | S3 | todo | |
| 8 | MEM1 | Memory entry schema | S1 | todo | |
| 9 | MEM2 | `kube-noob memory` CLI incl. validate (poisoning guard) and match | MEM1, S3 | todo | |
| 10 | MEM3 | Memory sources: config, ConfigMap, PVC, git init container | MEM2, F3 | todo | |
| 11 | MEM4 | Memory in answers; `memory_match`, `memory_propose` MCP tools | MEM2 | todo | |
| 12 | MEM5 | Fleet view by cluster | MEM2 | todo | |
| 13 | T1 | Offline ticket importers (ServiceNow, Jira) | MEM2 | todo | |
| 14 | T2 | `memory replay` harness (the 30% gate) | T1 | todo | |
| 15 | V1 | Prompt-injection sanitiser | F1 | todo | |
| 16 | G1 | Must-gather safe ingest | S1 | todo | |
| 17 | G2 | Must-gather analysers | G1, S3 | todo | |
| 18 | G3 | Must-gather report and case draft; demo | G2, MEM4, V1 | todo | |
| 19 | G5 | `analyze_must_gather` MCP tool with path confinement | G3 | todo | |
| 20 | I6 | REST API (minimal routes first) | F3, V1 | todo | |
| 21 | I1 | Alertmanager receiver and reports | S4, MEM4, I6 | todo | |
| 22 | N2 | pcap and pcapng analyser | V1 | todo | |
| 23 | N1 | Tier 1 flow readers (ACL log, Hubble, NetObserv) | F1 | todo | |
| 24 | N5 | `net verify` headline; demo | N1, N2 | todo | |
| 25 | G4 | Custom must-gather image | G3 | todo | |
| 26 | E2 | Installed operator inventory | F3 | todo | |
| 27 | E1 | Operator release notes | E2 | todo | |
| 28 | E3 | Kubernetes and RHACS known issues | S3 | todo | |
| 29 | E4 | Customer-side Jira cache | S3 | todo | |
| 30 | E5 | Customer Portal research doc | - | todo | |
| 31 | I2 | SARIF, GitHub Action, pre-commit, Tekton | F1 | todo | |
| 32 | I9 | runbooks.yaml, report and /metrics, lightspeed-config, diagnose --brief | MEM2 | todo | |
| 33 | I8 | kubectl and oc plugin | F1 | todo | |
| 34 | P1 | Upgrade pre-mortem | E1, E2, MEM2 | todo | |
| 35 | P2 | Offline what-if | G2 | todo | |
| 36 | GATE1 | MCP gate proxy with approvals | F3, V1 | todo | |
| 37 | GATE2 | Tamper-evident gate audit log | GATE1 | todo | |
| 38 | GATE3 | Gate docs and example | GATE2 | todo | |
| 39 | V2 | Server-side dry-run (tier D) | F3 | todo | |
| 40 | V3 | Blast radius | F3 | todo | |
| 41 | N3 | Probe plan and run (tier P) | F3, N5 | todo | |
| 42 | N4 | Capture plan | N2 | todo | |
| 43 | A1 | Egress log | F3 | todo | |
| 44 | A2 | Pre-send preview | A1, V1 | todo | |
| 45 | A3 | Admin model controls | A1 | todo | |
| 46 | A4 | Provider verification (keys needed) | A3 | todo | |
| 47 | A5 | Bench with and without tools | A4 | todo | |
| 48 | I10 | Cowork and plugin skills (security, compliance, manager, CAB) | I9 | todo | |
| 49 | T3 | Online ITSM connectors | T2, F3, A1 | todo | |
| 50 | I3 | Argo CD and GitOps examples | I2 | todo | |
| 51 | I4 | Chat commands without a model | I6 | todo | |
| 52 | I5 | OpenShift console dynamic plugin | I6 | todo | |
| 53 | I7 | Backstage design doc | I6 | todo | |
| 54 | GOV1 | Identity in audit records, OSCAL, KSI doc | I6 | todo | |
| 55 | GOV2 | Read as caller | F3 | todo | |
| 56 | GOV3 | Signed air-gap corpus pack | E4 | todo | |
| 57 | M13 | Release readiness pass | all above | todo | |

When an item is too large for one iteration, split it here into lettered rows (for example `N2a`, `N2b`), each of
which ships tested and documented on its own.

## Decisions (do not re-litigate)

- kube-noob has no model inside. The AI is the client or the optional `kube-noob ask`.
- The trained-model track is cut. The grader stays as an evaluation product (`kube-noob bench`).
- The verifier never acts. Gate, probe and dry-run are separate tiers with per-action approval.
- Ship fetchers, not data: Jira, tickets and memory are never redistributed or exported.
- Signals over prose: canonical alert names, event reasons, condition reasons and error templates are the join key;
  BM25 text is the fallback. No embeddings unless an eval proves BM25 plus signals fails.
- Memory is files in the customer's Git, reviewed by pull request; `memory validate` is the poisoning guard.
- Land on disconnected or regulated OpenShift; build moat features vendor-neutral.
- Learner tracks, credits and brand videos are frozen: kept and tested, no new features.
- The plugin's source copy stays (the plugin must run readable, locked code); drift is enforced by
  `scripts/sync_plugin_server.py --check`.
- Open-core line is documentation only (`docs/editions.md`); no licensing code.
- Parked: live outage signals from social or status feeds (conflicts with the offline default), Backstage beyond a
  design doc, a hosted service, embeddings.

## Owner actions (the loop cannot do these; it lists them in its final report)

- Run `kube-noob memory replay` on one team's real last 50 resolved tickets and the following 4 weeks (gate: 30%
  useful matches). This decides whether the memory moat is real.
- Show `doctor`, PRIVACY.md and SECURITY.md to two OpenShift admins; ask whether they would enable tiers P and D.
- Provide API keys (xAI, OpenAI, Anthropic, Azure, Bedrock, Vertex) as environment variables if provider runs are
  wanted (A4, A5).
- Decide on the Customer Portal path after reading E5.
- Provide an OpenShift cluster for CI if `restricted-v2` admission must be proven there.
- Run the headline test: "No AI inside. Works with yours." versus "The ground truth your AI SRE checks against",
  a week apart, compare click-through to the repository.
- Submit the OpenShift Helm catalog pull requests (`docs/openshift-catalog.md`).
- Approve version bumps, tags, releases and pull requests.

## Verification sources (append as facts are verified)

| Fact | Source URL | Verified on | Used in |
|---|---|---|---|

## Blocked and unverified

| ID | What is missing | Exact question or input needed |
|---|---|---|

## Baseline

Not run yet (F1).

## Iteration log (newest first; at most 10 lines per entry)
