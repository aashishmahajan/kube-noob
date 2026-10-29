# kube-noob build backlog: moat program

This is the complete specification the build loop works from (`.claude/commands/build-loop.md`). Status lives in
`.claude/loop/STATE.md`, never here. Change an item's spec only when a verified fact forces it, and record why in
STATE.md under Decisions.

## Product thesis (why every item exists)

Models are the commodity layer. kube-noob wins on four things a model cannot supply:

1. **Private org memory**: confirmed fixes, negative results and outcomes, keyed by canonical signals, stored as
   reviewed files in the customer's Git. Primary moat.
2. **Verifier position**: deterministic ground truth every AI SRE checks against, and a gate in front of agents that
   change clusters. The verifier never acts itself.
3. **Evidence speed**: from alert or must-gather to an evidence pack in under 60 seconds, offline.
4. **Network truth**: "policy says allowed, packets say dropped" from data the platform already records plus a pcap
   analyser.

Land: disconnected or regulated OpenShift clusters (no Red Hat Insights, AI often banned). Build every moat item
vendor-neutral so it serves mixed fleets (ROSA, EKS, AKS, GKE, upstream).

North-star metric: time from alert to evidence pack (target 60 s). Secondary: memory hit rate, tickets deflected.

## Global acceptance rules (apply to every item)

- Tests first. Include negative and security tests. `scripts/check.sh` passes (plugin copy, ruff, ruff format,
  mypy strict, pytest, selftest).
- A real run of the new CLI command on a fixture, with its output pasted (shortened) into the STATE.md log.
- New MCP tools: a `ToolSpec` in `toolkit.py` with a Pydantic input model (`extra="forbid"`), bounded sizes, and an
  availability gate when the tool needs a tier or network purpose.
- New HTTP routes: bearer auth identical to the MCP route, body size cap, tests for 401, 413 and malformed input.
- Every new parser (tar, pcap, CSV, JSON payloads, YAML) has size, count and depth caps and a fuzz-style test with
  truncated and hostile input.
- Every new outbound destination: a named `kube_noob.net` purpose, off by default, refused under the offline lock,
  listed in `PRIVACY.md` (the test `test_privacy_policy_lists_every_destination` must keep passing), shown by
  `kube-noob doctor`.
- Every new write to a cluster or external system: a separate tier, off by default, per-action approval, separate
  optional RBAC in the chart, shown by `doctor`, documented in `SECURITY.md`.
- New product rules get a row in `docs/guidance.md` with the tests that enforce them (`tests/test_guidance.py`).
- README stays under 600 words and its counts stay true (`test_readme_numbers_match_the_code`). Never write copy
  that `test_positioning_says_no_ai_inside_and_never_claims_otherwise` rejects. Do not write "kube-noob is an
  agent", "kube-noob as a gate for AI agents" or "audit agent". Write "kube-noob gate checks agent tool calls".
- CHANGELOG.md gets an entry under `## Unreleased`. Use-cases, architecture (trust boundaries), PRIVACY, SECURITY and
  operations docs are updated when the item changes what they describe.
- If server modules reachable from `kube_noob.server.stdio` changed: `python scripts/sync_plugin_server.py`.
- Facts need sources: any external format, API, alert name, command or version is verified against a primary source
  (upstream repo, official docs) during the iteration, and the URL is cited in code comments or knowledge front
  matter. If it cannot be verified, the item is `blocked`, not guessed.

---

## M0 Foundations

### F1 Baseline and loop scaffolding
- Run `scripts/check.sh`; record pass/fail counts and duration in STATE.md.
- Confirm the toolchain: Python 3.11+, uv or pip, docker (present in the cloud container), kind/helm/kubectl/oc
  (record which are missing; never install system packages without need; prefer pip/uv for Python tools).
- Accept: STATE.md has a Baseline section; no code change.

### F2 Strategy into the docs
- `docs/roadmap.md`: rewrite to this program (M1 to M12), keep Status history. Remove the trained-model track; keep
  the grader and bench as an evaluation product ("kube-noob bench"). Mark learner tracks, credits and brand videos as
  frozen (kept, tested, no new investment). Record "verifier never acts", "ship fetchers, not data", "signals over
  prose".
- New `docs/editions.md`: the open-core line. Free: everything one team needs. Governance features (SSO, read as
  caller, identity in audit records, memory across clusters, retention, ITSM connectors, gate approvals and audit,
  signed air-gap corpus, FIPS images) are listed as enterprise candidates. Documentation only: no license checks,
  no feature flags, no license change.
- Link editions from roadmap. Keep docs concise (`test_docs_are_concise_and_linked`).
- Accept: guidance and positioning tests pass; roadmap no longer proposes a model inside or a trained model.

### F3 Capability tiers framework
- Config model `tiers` (or extend existing sections) with explicit, default-off switches:
  - `R` read-only cluster (exists: `cluster.enabled`)
  - `P` probe: ephemeral container or probe Job (`probe.enabled`)
  - `D` server-side dry-run (`dryRun.enabled`)
  - `W` external writes: ticket attach, notify forwarders (`itsm.writeEnabled`, `notify.enabled`)
  - `G` gate forwarding to an upstream MCP server (`gate.enabled`)
- A backend split: the existing read-only backend stays unable to write; a separate writer class exists only when a
  write tier is enabled, and every write call takes an approval object (id, approver, reason, expiry).
- `doctor` prints each tier with on/off and the RBAC it needs; exits 1 on contradictions (for example a write tier on
  while the chart RBAC for it is absent, when detectable).
- Chart: `values.yaml` blocks for each tier, all `false`; optional Roles rendered only when enabled; schema updated;
  CI chart guard tests extended.
- Accept: tests prove defaults off, MCP tool list unchanged with defaults, the read-only backend has no write method,
  writer refuses without a valid approval, offline lock unaffected; guidance row "G-tiers" added.

## M1 Signal-keyed matching (fixes the measured recall gap)

Measured gap (2026-10-28, OpenShift 4.20 to 4.22 index): `known-issues 'etcd leader changed frequently, apiserver
timeouts after upgrade' --version 4.21.0` misses OCPBUGS-73881 (fixed 4.21.1); at 4.20.5 it misses OCPBUGS-73876
(fixed 4.20.13). The prose "etcd leader elections keep happening, high disk I/O on masters" at 4.20.5 matches
OCPBUGS-73876. At 4.21.2, no match is correct (already fixed).

### S1 Signal extraction module
- New package `kube_noob/signals/` with `extract(text_or_payload) -> list[Signal]`. Signal kinds:
  `alert` (Prometheus alert names), `event_reason` (Kubernetes event reasons), `co_condition`
  (ClusterOperator type plus reason), `pod_reason` (waiting or terminated reasons: CrashLoopBackOff, OOMKilled,
  ImagePullBackOff, CreateContainerConfigError...), `admission` (policy engine plus rule), `error_template`
  (normalised error line), `component` (etcd, kube-apiserver, ovnkube, kubelet...).
- Normaliser for error templates: strip pod-hash suffixes, UUIDs, IPv4 and IPv6, ports where safe, timestamps,
  durations, hex ids, long numbers; output a stable template string and its sha256 prefix.
- Inputs accepted: free text, Alertmanager webhook JSON, `oc get events -o json`, ClusterOperator YAML or JSON,
  pod status JSON.
- Accept: unit tests per signal kind with real-shaped samples; deterministic output order; size caps.

### S2 Signal catalogue `data/signals.yaml`
- Entries: `id`, `kind`, `name`, `aliases`, `terms` (expansion words used by matchers), `components`, `playbooks`
  (existing DBG ids), `sources` (URL of the repo file defining the alert or reason).
- Initial coverage, each name verified in its source before it is added:
  - etcd: etcdHighNumberOfLeaderChanges, etcdNoLeader, etcdMembersDown, etcdHighFsyncDurations,
    etcdGRPCRequestsSlow, etcdDatabaseQuotaLowSpace (verify in openshift/cluster-etcd-operator and etcd-io mixins).
  - API server: KubeAPIErrorBudgetBurn, KubeAPIDown (kubernetes-monitoring/kubernetes-mixin).
  - Nodes and kubelet: KubeNodeNotReady, KubeNodeUnreachable, KubeletDown, NodeFilesystemSpaceFillingUp,
    NodeFilesystemAlmostOutOfSpace (kubernetes-mixin, node-exporter mixin).
  - Workloads: KubePodCrashLooping, KubePodNotReady, KubeDeploymentReplicasMismatch, KubeJobFailed,
    KubePersistentVolumeFillingUp, KubeHpaMaxedOut.
  - OpenShift platform: ClusterOperatorDown, ClusterOperatorDegraded, ClusterVersionOperatorDown,
    MCDDrainError or current equivalents, plus OVN-Kubernetes and ingress alerts found in their operators' repos.
  - Event reasons: FailedScheduling, FailedMount, FailedAttachVolume, FailedCreate, BackOff, Unhealthy, Evicted,
    NodeNotReady, FailedCreatePodSandBox, NetworkNotReady.
- Any name that cannot be verified is left out and listed in STATE.md as unverified.
- Accept: a schema test (ids unique, every playbook id exists, every entry has a source URL); README unchanged.

### S3 Known-issue matching with signals
- `known_issues.py`: expand the query with signal terms, score signal hits plus the existing rare-word score, keep
  the version filter (introduced or fixed). Precision guard stays: everyday errors never pull in a bug.
- New eval `data/evals/known_issue_recall.yaml`: at least 40 positives (alert-name style, user-prose style, pasted
  events) with expected issue id and version, and at least 30 negatives (OOMKilled, ImagePullBackOff, generic
  CrashLoop, typos) that must not match. Must include the three etcd cases above with their expected outcomes.
- Gate (test): recall at least 0.8 on positives, zero false matches on negatives, selftest still passes. Print the
  numbers in the test failure message.
- Accept: `kube-noob known-issues 'etcd leader changed frequently, apiserver timeouts after upgrade' --version
  4.21.0` returns OCPBUGS-73881.

### S4 Signals everywhere
- `diagnose`, `debug`, `bundle`, `policy explain` show extracted signals and use them to rank playbooks.
- `diagnose` accepts an Alertmanager webhook payload file directly (`-f alert.json`).
- MCP: `extract_signals` tool (read-only).
- Accept: tests that an Alertmanager payload with `etcdHighNumberOfLeaderChanges` ranks the etcd playbook first and
  lists the matching known issues for the payload's version label when present.

## M2 Fixes-as-code memory (primary moat)

### MEM1 Entry schema
- One YAML file per entry: `entries/MEM-<n>.yaml`. JSON Schema shipped in the package plus a Pydantic model.
- Fields: `id`, `status` (proposed, approved, retired), `kind` (fix, negative, runbook), `signals` (S1 kinds and
  names, or template hashes), `symptom` (short prose), `platform`, `versions` (`introduced`, `fixedIn`),
  `operators` (name plus version range), `cause`, `fix` (prose; optional `patch` manifest; optional `commands`, each
  labelled read-only or needs-approval with the existing classifier), `evidence` (references only, never raw logs),
  `outcomes` (date, result resolved/not-resolved/partial, opaque ticket ref, cluster label), `owners`, `sources`,
  `created`, `updated`, `riskAccepted` (owner and reason, required for any fix the verifier flags HIGH).
- Credentials, raw logs and full manifests in prose fields are rejected (reuse the learning-file detectors).
- Accept: schema tests, round-trip tests, rejection tests.

### MEM2 `kube-noob memory` CLI
- `memory init <dir>`: scaffold README, schema copy, `entries/`, and a CI workflow template (GitHub Actions and a
  plain shell script) that runs `memory validate`.
- `memory add <dir> --symptom ... --cause ... --fix ... [--signal ...]`: writes a `proposed` entry; never commits.
- `memory validate <dir>`: schema, duplicates, expired entries, credential scan, verifier on fixes: any `patch` runs
  through validate, audit and red team; any command that changes state must be labelled needs-approval; grants of
  privileged SCC, cluster-admin, hostPath or wildcard RBAC fail unless `riskAccepted` is set. Exit 1 on failure.
  This is the poisoning guard.
- `memory match "<text>" | -f payload [--version v] [--operator name=v] [--include-proposed]`: signals first, BM25
  fallback, approved entries only by default. Entries whose `fixedIn` is at or below the given version are shown as
  retired, not as fixes. Negative entries are shown as "tried, did not work". Output includes
  "matched N times, resolved M" from outcomes.
- `memory outcome <dir> <id> --result resolved --ticket <ref> [--cluster <label>]`.
- `memory stats <dir> [--by cluster|signal|component]`.
- `memory migrate-learning <dir>`: converts confirmed notes in `learning.json` into proposed entries.
- Memory content is never redistributable and never exported to training datasets.
- Accept: tests per subcommand, including a poisoned entry that `validate` rejects, an expired entry that `match`
  marks retired, and determinism. `kube-noob demo memory` (offline, under a second) shows a seeded memory repo,
  a match with outcome counts, a negative entry and a poisoned entry rejected by `validate`.

### MEM3 Memory sources in every runtime
- Config `memory.paths` (list of directories). CLI, stdio MCP and HTTP server read them.
- Chart: `memory.source` one of `configMap`, `pvc`, `git` (init container clone; image, repo URL, ref and deploy-key
  Secret configurable; egress NetworkPolicy limited to the named host; refused under the offline lock unless the
  host is in-cluster or listed in `offline.allowedHosts` if that concept exists, else blocked and recorded).
  Read-only mount.
- Accept: chart render tests for each source; `doctor` lists memory paths and entry counts.

### MEM4 Memory in answers
- `diagnose`, `known-issues`, `debug`, `bundle`, the Alertmanager receiver (I1) and must-gather analysis (G3) include
  memory matches, cited as `[mem:MEM-<n>]`.
- MCP tools: `memory_match` (read-only), `memory_propose` (returns the YAML text and a suggested path; writes only in
  local stdio mode, after explicit user confirmation, mirroring `learning_note_add`).
- Accept: tests that citations appear, that HTTP mode never writes, that proposed entries are hidden by default.

### MEM5 Fleet view
- Outcomes carry a `cluster` label; `memory stats --by cluster`; match output says "seen on N of your clusters,
  fixed on M".
- Accept: test with three clusters' outcomes.

## M3 Ticket seeding and the replay harness (tests the riskiest assumption)

### T1 Offline ticket importers
- `kube-noob memory import <dir> --format servicenow-csv|servicenow-json|jira-json|jira-csv -f export`:
  verify field names against official ServiceNow incident table and Jira REST issue docs before coding.
- Extract signals from description, work notes and close notes; scrub PII (reuse and extend the Jira scrubber:
  emails, account ids, phone numbers, @mentions, names in "Assigned to" style fields are dropped entirely);
  credential scan; write `proposed` entries with outcomes from resolution state. Skipped tickets are listed with
  reasons.
- Accept: synthetic fixtures (at least 50 tickets per format) under `tests/fixtures/tickets/`; tests for PII removal
  and for skipping tickets without a resolution.

### T2 `kube-noob memory replay`
- `memory replay --memory <dir> --tickets <file> --format ... [--labels labels.yaml] [--as-of-ticket-date]`:
  replays tickets in date order against memory; with `--as-of-ticket-date` only entries created before each ticket
  count (no hindsight). Reports hit rate, hits per signal kind, misses with their signals, and, with a labels file
  (ticket ref to useful yes/no), useful-match rate. Prints the gate: useful matches at least 30%.
- Output: Markdown and JSON report.
- Accept: test with a synthetic 50 seed plus 20 replay set with a known expected hit rate; the owner action "run the
  replay on real tickets" is listed in STATE.md.

### T3 Online ITSM connectors (optional, later)
- Read-only pull from the ServiceNow Table API and Jira Service Management REST: net purpose `itsm`, allowlisted host,
  token from env or Secret, offline lock refuses, jittered paging like `sources/jira.py`.
- Attach `bundle.md` or a report to a ticket: tier W, approval required.
- Verify API contracts in official docs first; blocked if unverifiable.
- Accept: tests with a fake HTTP server; PRIVACY.md lists the destinations.

## M4 Must-gather pre-flight (the wedge for disconnected clusters)

### G1 Safe ingest
- `kube-noob must-gather analyze <dir|.tar|.tar.gz|.tgz>`: refuse absolute paths, `..`, symlinks or hardlinks
  leaving the root, device files; caps on total bytes, file count, single file size and nesting; never executes
  anything; never reads files named like Secrets (`secrets.yaml`, `*/secrets/*`) and skips them with a notice.
- Verify the must-gather layout (top-level image directory, `cluster-scoped-resources/`, `namespaces/<ns>/`,
  `timestamp`, `version`) against openshift/must-gather docs first.
- Accept: hostile tarball tests (traversal, symlink escape, bombs by size and count).

### G2 Analysers
- ClusterVersion (current, history, Failing/Progressing), ClusterOperators (Degraded, Available false, reasons),
  nodes (NotReady, pressure), pods (CrashLoop, ImagePull, Pending reasons), events (reasons), MachineConfigPools
  (degraded), OLM CSVs (failed phases), etcd hints from etcd pod logs if present ("leader changed",
  "apply request took too long"). Everything feeds S1 signals.
- Accept: a synthetic must-gather tree fixture under `tests/fixtures/must-gather/` covering each analyser.

### G3 Report and case draft
- `report.md` and `report.json`: summary, ranked findings, known issues with fix version for the detected version,
  memory matches, read-only next steps, `knowledgeAsOf`, redaction via `redact_text`.
- `--case-draft`: `case-draft.md` with headings for problem statement, environment (version, platform, operators),
  timeline placeholders, frequency, business impact placeholders, evidence list, matched bugs, steps already taken.
  Placeholders are marked for the user to fill; nothing is invented.
- Accept: golden-file tests; `kube-noob demo must-gather` demo added (offline, under a second).

### G4 Custom must-gather image
- Verify how `oc adm must-gather --image=` runs custom images (gather script, output directory, ServiceAccount
  privileges) in Red Hat docs first.
- `deploy/must-gather/Containerfile` and `gather` script: collects only the read-only allowlist (never Secrets),
  runs the analyser, writes the report into the must-gather output directory.
- Build with docker in the container if available; otherwise blocked with the reason.
- Document that must-gather pods run with elevated privileges by design and what kube-noob's gather reads.
- Accept: image builds; a test runs the gather script against a fixture directory.

### G5 MCP access
- MCP tool `analyze_must_gather` with a path argument, available only in local stdio mode or when the HTTP server
  has `mustGather.allowedDir` configured (path must resolve inside it).
- Accept: tests for path confinement.

## M5 Evidence breadth (ship fetchers, not data)

### E1 Operator release notes
- Extend `scripts/vendor_known_issues.py` to operator release notes in openshift-docs (verify which operators have
  known-issue and fixed-issue modules, and the license of each file). Records gain `product` and `productVersion`.
- Accept: index rebuilt; tests for at least three operators; `doctor` shows per-product dates.

### E2 Installed operator inventory
- Add `clusterserviceversions` and `subscriptions` (operators.coreos.com) to the read-only allowlist, with size caps.
- `cluster_version` and bundle report the operator inventory; known-issue and memory matching filter by it.
- Accept: redaction and allowlist tests; Secrets still unreachable.

### E3 Kubernetes and RHACS known issues
- Kubernetes CHANGELOG known issues and bug fixes per minor (verify license and structure); RHACS release notes
  known issues (verify source and license). ROX Jira stays non-redistributable and is never bundled.
- Accept: matching eval extended with Kubernetes and RHACS cases.

### E4 Customer-side Jira cache
- Generalise `kube-noob corpus jira` to OCPBUGS and operator projects, filtered by versions and components taken
  from the cluster or a must-gather; cache in `dataDir` as `redistributable: false`; `known-issues` consults the
  cache when present and labels results "from your local Jira cache, fetched <date>".
- Verify anonymous read access and rate limits first; offline lock refuses; `doctor` shows cache date and size.
- Accept: tests with a fake Jira server; export paths exclude the cache.

### E5 Red Hat Customer Portal (research only)
- `docs/design/customer-portal.md`: verified endpoints for the customer's own cases and Knowledgebase search, auth
  (offline token to SSO access token), terms of use constraints, data handling. No implementation unless the API and
  terms are verified and the owner approves in STATE.md.
- Accept: design doc with citations, or `blocked` with the exact question for the owner.

## M6 Network truth

### N1 Tier 1 readers (read-only)
- Offline parsers: OVN-Kubernetes ACL audit log lines (verify format in ovn-kubernetes docs and OpenShift docs),
  Hubble flow JSON (`hubble observe -o json`), Network Observability flow records (verify field names).
- Generated commands to obtain them (enable ACL logging via namespace annotation is a change: labelled needs-approval;
  reading node logs needs elevated permissions: labelled privileged).
- Accept: parser tests with verified sample lines; outputs normalised to one flow-verdict model
  (src, dst, port, protocol, verdict allow/drop, policy name, time).

### N2 Tier 4 pcap analyser (offline, deterministic)
- Pure Python readers for pcap and pcapng (no new dependency unless its license is checked, it is hash-pinned in
  `requirements.lock` and the plugin `uv.lock`, and THIRD_PARTY_NOTICES is updated). Link types: Ethernet, Linux
  cooked SLL and SLL2, raw IP. IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, DNS, TLS record and alert headers.
- Verdicts per flow: SYN_NO_REPLY (drop: policy or firewall), RST_ON_SYN (no listener or wrong port), RST_MIDSTREAM,
  TLS_ALERT with the alert name, DNS_NXDOMAIN, DNS_SERVFAIL, DNS_TIMEOUT, NDOTS_EXPANSION (search-path queries before
  the real name), LARGE_SEGMENT_RETRANSMIT (MTU suspect), ICMP_FRAG_NEEDED or PACKET_TOO_BIG, HANDSHAKE_OK.
  Each verdict maps to a playbook id and read-only next steps.
- Caps: file size, packet count, flows.
- CLI `kube-noob pcap analyze <file> [--host] [--port]`; MCP tool `analyze_capture` (base64 input with a size cap, or a
  path in local stdio mode).
- Accept: tests that build pcap and pcapng bytes programmatically for every verdict; hostile-file tests.

### N3 Tier 2 probe (netcat equivalent, tier P)
- `kube-noob probe plan --from ns/pod --to host:port [--tls] [--dns name]`: always available; prints the
  `kubectl debug -n <ns> <pod> --target=<container> --profile=restricted --image=<digest-pinned image> -- <script>`
  command (verify `--profile=restricted` and ephemeral container semantics in Kubernetes docs) and the script
  (DNS lookup, TCP connect with timeout, TLS handshake, HTTP status) with JSON output.
- `kube-noob probe run ... --approve <reason>`: only with tier P enabled; patches `pods/ephemeralcontainers`, waits,
  reads the container logs, parses JSON. States the caveat: an ephemeral container stays in the pod spec until the
  pod is recreated.
- Alternative mode `--job`: a Job that copies the source pod's labels and ServiceAccount, with a readiness probe that
  never passes (so it never joins Service endpoints), `activeDeadlineSeconds`, `ttlSecondsAfterFinished`.
- `kube-noob probe parse <file>` for results run by a human.
- Chart: optional Role for tier P. `doctor` shows it.
- Accept: tests with a fake backend; probe never runs without tier P and an approval; image reference must be a
  digest.

### N4 Tier 3 capture plan (tcpdump equivalent)
- `kube-noob capture plan --pod ns/pod [--peer host] [--port] [--count] [--seconds]`: prints the exact steps:
  `oc debug node/<node>`, `chroot /host`, `crictl ps` and `crictl inspect` for the PID, `nsenter -t <pid> -n --
  tcpdump -nn -i any -c <count> -w /host/var/tmp/kn-<id>.pcap '<filter>'` with a timeout, retrieval and cleanup.
  Verify against the OpenShift docs on capturing network traffic. Labelled privileged and needs-approval.
  kube-noob never runs these.
- Accept: tests on generated commands (paste-safe rules G07, no shell comments).

### N5 `kube-noob net verify` (the headline)
- Inputs: `--from --to --port`, policies (`-f` or `--live`), and any of `--acl-log`, `--flows`, `--pcap`,
  `--probe-result`.
- Output: predicted (tier 0 `policy reach`) versus observed (N1, N2, N3) with a verdict:
  predicted allow plus observed drop gives "not your NetworkPolicy: check EgressFirewall, AdminNetworkPolicy and
  BaselineAdminNetworkPolicy, OVN ACLs, MTU, DNS, Service endpoints", with read-only next steps; predicted deny plus
  observed allow flags a policy not enforced (CNI without NetworkPolicy support or a wrong namespace label).
- MCP tool `verify_traffic`; `kube-noob demo network` with fixtures; use-cases section.
- Accept: tests for all four predicted/observed combinations.

## M7 Verifier hardening

### V1 Prompt-injection sanitiser
- `kube_noob/sanitize.py`: deterministic detection and neutralisation in text that came from a cluster, must-gather,
  ticket, memory entry, pcap payload or web page: instruction phrases ("ignore previous instructions" and variants),
  role and chat-template markers, tool-call JSON shapes, Markdown image or link exfiltration with query strings,
  Unicode tag characters (U+E0000 to U+E007F), bidi overrides, zero-width characters.
- Every MCP and HTTP result field carrying external text passes through it; results carry `untrusted: true` and
  `injectionSignals` when something was found. Documented as defence in depth, not a guarantee.
- Eval: at least 60 injection cases detected at 95% or better; at least 300 benign lines (playbook samples, fixture
  events and logs) with zero false positives.
- Accept: eval test gates; guidance row added.

### V2 Server-side dry-run (tier D)
- `kube-noob verify apply -f x.yaml --server-dry-run`: only with tier D; sends create or patch with `dryRun=All` and a
  `kube-noob` field manager; parses denials into `policy explain`; shows the server's defaulted object diff.
- Chart: optional Role for tier D limited to named resources and namespaces.
- Accept: tests with a fake API server returning admission denials from Kyverno, Gatekeeper, PSA and SCC shapes
  (verify the real message formats first).

### V3 Blast radius
- Add `roles`, `rolebindings`, `clusterroles`, `clusterrolebindings` to the read-only allowlist.
- `kube-noob redteam blast-radius --pod ns/name [-f bundle] [--live]`: ServiceAccount, effective RBAC (which Secrets
  it could read by name, without reading them; whether it can create pods, exec, bind roles, impersonate), SCC or
  PSA level, host mounts, token automount, reachable services (tier 0). Ranked attack paths; JSON graph and Mermaid.
- Accept: fixture-based tests including an escalation path through pod creation.

## M8 Integrations that need no AI

### I1 Alertmanager receiver
- HTTP `POST /v1/alertmanager` (bearer auth, size cap): parse the webhook payload (verify version 4 schema in the
  Alertmanager docs); per alert: signals, diagnose, known issues for the cluster version, memory matches, and
  read-only evidence when tier R is on and labels name a namespace and pod.
- Store reports in `dataDir/reports/<id>.json` and `.md` with a retention cap; `GET /v1/reports/<id>`.
- Optional forwarders (tier W, purpose `notify`): Slack incoming webhook and generic webhook; allowlisted hosts;
  offline lock refuses non-internal hosts.
- Chart: `alertmanager.enabled`, an AlertmanagerConfig example, NetworkPolicy ingress from the monitoring namespace.
- Measure and print time from receipt to report (north-star metric) in the report.
- Accept: tests with real-shaped payloads; latency under 60 s on fixtures (assert under 5 s offline).

### I2 CI surfaces
- `audit --format sarif` (SARIF 2.1.0: rules with help text, NIST controls as properties, locations with line
  numbers when available).
- `action.yml` (composite GitHub Action, pinned actions by SHA), `.pre-commit-hooks.yaml`, `deploy/tekton/task.yaml`.
- Accept: SARIF validated against the official schema (vendor the schema with provenance, or blocked).

### I3 Argo CD and OpenShift GitOps
- `examples/argocd/`: PreSync hook Job running `kube-noob audit --fail-on high` on the rendered manifests; doc on
  diagnosing a Degraded application with `kube-noob diagnose`.
- Accept: example YAML audits clean with kube-noob itself.

### I4 Chat commands without a model
- `POST /v1/slack/command` with Slack request signing (v0 HMAC, timestamp window; verify in Slack docs) and Teams
  outgoing webhook HMAC (verify); deterministic `diagnose`, `known-issues`, `memory match` replies.
  Config `chatops.enabled`, default off. Update roadmap: the earlier "set aside bots" reason does not hold for orgs
  with no AI.
- Accept: signature tests (valid, expired, wrong).

### I5 OpenShift console dynamic plugin
- `console-plugin/` (TypeScript, the OpenShift dynamic plugin SDK; verify current SDK package and template): a
  Diagnose tab on workloads, report list, reachability view, calling the REST API (I6).
- Only if the npm registry is reachable from the container; else design doc plus OpenAPI contract and `blocked`.
- Accept: `npm run build` passes; chart option to deploy it with a ConsolePlugin resource.

### I6 REST API
- `/v1/diagnose`, `/v1/audit`, `/v1/known-issues`, `/v1/policy/reach`, `/v1/memory/match`, `/v1/reports`,
  `/v1/net/verify`: JSON, bearer auth, same toolkit, OpenAPI document generated and tested for drift.
- Accept: contract tests.

### I7 Backstage (park)
- `docs/design/backstage.md` only.

### I8 kubectl and oc plugin
- `kubectl-kube_noob` entry point (`kubectl kube-noob ...` and `oc kube-noob ...`) and a krew manifest template.
- Accept: test that the entry point dispatches to the CLI.

### I9 Roadmap 0.4 leftovers
- `runbooks.yaml`: map rule, playbook and signal ids to the company's URLs, shown in every answer.
- `kube-noob report`: top 10 problems this week from the id-only counters and memory outcomes; `/metrics`
  (Prometheus text format) with the same counts, no content.
- `kube-noob lightspeed-config`: print the OLSConfig snippet and Secret commands for this install (verify the current
  OLSConfig MCP fields first).
- `diagnose --brief`: one cause, one read-only command.
- Accept: tests for each.

### I10 Cowork and Claude plugin skills for people who never open a terminal
- New skills under `plugin/kube-noob/skills/` (respect the plugin directory limits enforced by
  `scripts/sync_plugin_server.py --check`), each driving existing tools and producing a document:
  - security reviewer: "review this vendor's Helm chart before we accept it" (helm audit, red team, RHACS policy
    mapping, blast radius when V3 exists);
  - compliance: "NIST 800-53 evidence pack for namespace X" (audit with controls; OSCAL when GOV1 exists);
  - engineering manager: "top issues this week and the defaults or docs that would remove them" (I9 report, memory
    stats);
  - change advisory board: "is the upgrade to 4.22 safe for our workloads" (P1 when it exists; removed APIs now).
- Each skill states which tools it calls, what leaves the machine (nothing beyond the chat) and its output format.
- Accept: plugin tests pass; each skill's tool names exist in the toolkit (add a test that checks this).

## M9 Proactive

### P1 Upgrade pre-mortem
- `kube-noob upgrade-check --to 4.22 [--from auto|<version>] [-f manifests | --live | --must-gather dir]`: removed APIs
  for the target Kubernetes minor, DeploymentConfig, Pod Security and SCC changes (cited), known issues open in the
  target and issues fixed after the current version, operator compatibility from E1/E2 data, memory entries whose
  version range covers the target; a documented risk score; a change-advisory-board report in Markdown.
- The upgrade graph service needs network: out of scope offline, stated in the output.
- Accept: fixture tests; `kube-noob demo upgrade`.

### P2 Offline what-if
- `kube-noob whatif -f change.yaml --snapshot <bundle.json | must-gather dir>`: Pod Security labels, SCC rules,
  ResourceQuota and LimitRange arithmetic, NetworkPolicy reach for the new pods, scheduling feasibility (node
  selectors, basic affinity, taints and tolerations, allocatable versus requests). Each check lists its limits.
- Accept: fixture tests per check.

## M10 Optional AI layer (bring your own key)

### A1 Egress log
- Every outbound request (purposes web, llm, itsm, notify, corpus, jira) appends to `dataDir/egress.jsonl`: time,
  purpose, host, method, bytes out, sha256 of the body, status. Never content. `kube-noob egress log`; `doctor` shows
  the path.
- Accept: tests per purpose.

### A2 Pre-send preview
- `kube-noob ask --preview` prints exactly the redacted, sanitised payload that would be sent; `llm.requirePreview`
  forces confirmation.
- Accept: tests that nothing is sent without confirmation when required.

### A3 Admin controls
- `llm.allowedModels`, `llm.allowedBaseUrls`; chart `llm.existingSecret`; `doctor` shows them.
- Accept: refusal tests.

### A4 Provider verification
- Verify from official docs, then document config examples for: xAI (OpenAI-compatible chat completions with tool
  calls), OpenAI, Azure OpenAI, Amazon Bedrock and Google Vertex (only the OpenAI-compatible endpoints that exist).
- Run `kube-noob selftest` and `kube-noob train bench` through a provider only when its key is present in the
  environment; otherwise record "unverified: no key". Never claim a provider works without a run.
- Accept: docs plus recorded runs or recorded gaps.

### A5 Bench with and without tools
- Extend `kube-noob train bench` with `--modes tools,no-tools`: score table (model, date, task-set hash, score per
  mode) in JSON and Markdown; `docs/bench.md` publishes only real runs.
- Accept: test with a fake provider.

## M11 kube-noob gate (category bet; the verifier never acts)

### GATE1 MCP proxy
- `kube-noob gate --upstream-cmd "<command>" | --upstream-url <url> [--policy gate.yaml]` served over stdio or
  streamable HTTP, built with the `mcp` SDK client and server already in use.
- Lists upstream tools and re-exposes them. On each call: classify by policy (tool name patterns to read, write or
  deny; argument inspection for kubectl verbs and embedded manifests). Writes go through the verifier (validate,
  audit, red team, sanitiser on arguments, tier D dry-run when enabled). Blocking findings deny with the explanation.
  Otherwise a pending approval is created and the call returns "approval required" unless policy auto-approves.
- `kube-noob gate approve <id> --reason ...` and `gate deny <id>`; the approved call is forwarded once.
- Upstream results are sanitised (V1) before they reach the calling model.
- Accept: tests with a fake upstream MCP server (read and write tools) proving: reads pass, writes wait for approval,
  a privileged manifest is denied, an approval is single-use and expires.

### GATE2 Tamper-evident audit log
- JSONL with a hash chain: time, caller identity (stdio: local user; HTTP: configured identity header, trusted only
  when `gate.trustIdentityHeader` is set behind an auth proxy), tool, argument hash and redacted arguments,
  classification, verifier verdict, approval id and approver, upstream status.
- `kube-noob gate verify-log` checks the chain; tampering is detected.
- Accept: tamper tests.

### GATE3 Docs, demo and examples
- `kube-noob demo gate`: a bundled fake upstream with one read and one write tool; shows a read passing, a write
  waiting for approval, a privileged manifest denied, and `gate verify-log` passing.
- Example fronting a write-capable Kubernetes MCP server (verify its tool names in its README first). Positioning:
  "kube-noob gate checks agent tool calls; it never acts on its own." Respect the positioning test patterns.

## M12 Governance (enterprise candidates; implemented in the open code unless the owner decides otherwise)

### GOV1 Identity and compliance exports
- Caller identity in every HTTP audit record; OSCAL assessment-results export from `audit` (verify the OSCAL version
  and schema; vendor with provenance); FedRAMP 20x KSI mapping doc.

### GOV2 Read as caller
- Chart option for an OAuth proxy passing the caller's access token; backend uses it for tier R reads when
  `cluster.readAsCaller` is on; token never logged or stored; threat model doc.
- Accept: tests with a fake backend asserting the caller token is used and never persisted.

### GOV3 Signed air-gap corpus pack
- `kube-noob corpus pack` writes a tgz plus sha256 manifest; signing instructions (cosign); `corpus import --verify`
  checks the manifest.

## M13 Release readiness (continuous)
- After each milestone: CHANGELOG `Unreleased` section complete, docs current, demos added, guidance rows added,
  `scripts/risk_review.py` run and its baseline handled per `docs/operations.md`.
- Never bump versions, tag, publish or open pull requests unless the owner asks in STATE.md.
