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
| `corpus-refresh`, `db-image` scheduled workflows | **Failing**, and this row described the first one backwards. The scrubber does NOT miss bare Atlassian account ids: `BARE_ACCOUNT_ID` has matched them since the pattern was written, and `sources/jira.py` folds it into the scrub. The live problem is the opposite -- it over-matches, because any 24-character hex run starting with `5` satisfies it and a `sha256:` digest fragment does too, so the audit reports a finding on text that holds no personal data. [operations.md](operations.md) has both false-positive shapes and says not to narrow the pattern for cosmetics: missing real personal data is worse. So the 123 findings need triage, not a fix. The second half is unchanged: the bundler packs a VEX member its own 300 MB checker rejects | 0.8.0 |

## The program

Reordered 2026-11-03 after four independent reviews. The order is: **correctness before capability, capability
before reach, reach before breadth.** A verdict that can be wrong costs more than a feature that is missing.

### Now: 0.8.0

| # | Item | State | Why it is first |
|---|---|---|---|
| P0 | **Same-priority `AdminNetworkPolicy` ties are "not determined"** | Shipped | Two policies at one priority were decided by document order, silently. Upstream says the choice is implementation-defined and OVN-Kubernetes raises `ANPWithDuplicatePriority`. The README promises both policy commands "say what they could not determine"; this is the one place they do not |
| P1 | **Coverage record: which rules ran over which objects** | Shipped | `controlSummary` lists only controls that have findings, so "clean" and "never evaluated" are indistinguishable. Every compliance output built on top of that would claim satisfaction from silence, which is the exact failure FedRAMP's own guidance names. Nothing else in the compliance arc is honest until this exists |
| P2 | **`kubectl krew` plugin** | Built; the index PR is owner-only | Both `noob` and `kube-noob` were unclaimed in krew-index (both manifest paths 404 on 2026-11-05), and `noob` is the name taken, because krew runs the plugin as `kubectl <name>`. **Shipped in `krew/`:** the entry-point script, a generated manifest whose `sha256` is the digest of a byte-reproducible archive built from that script, release-workflow checks, and 15 tests. The verb table was DELETED rather than written: the script forwards every argument to the CLI unchanged, so it cannot drift when a subcommand moves, and what it adds over installing the CLI is the `uvx` fallback pinned to the plugin's own version -- `kubectl krew install noob` then works with no Python environment set up. **What is left is owner-only:** the krew-index pull request, and `kubectl krew install --manifest=krew/noob.yaml` against the published release asset, which is the step that proves the asset is the archive the manifest describes. Steps are in `krew/README.md`. Nothing in the README advertises the plugin until that PR merges |
| P3 | **OSCAL assessment-results emitter** | Shipped | **`audit --oscal` and `--oscal-import-ap` are shipped.** Pure serialisation of what P1 made honest: the findings as observations, and one OSCAL finding per control, `satisfied` only where that control's rules actually ran and found nothing. A control no rule evaluated is named under `exclude-controls` and never reported satisfied, and with no coverage record at all nothing is reported satisfied. Deterministic v5 UUIDs over the input, so two runs over the same bundle are byte-identical and CI can diff it. `oscal-version: 1.2.3`, taken from the release schema itself. Three corrections the schema forced: a finding may NOT target a control (`finding-target.type` is an enum of `statement-id` and `objective-id` only), so it targets the control's `_obj` id; control ids are catalogue ids, `ac-6.10`, because `AC-6(10)` is not even a legal OSCAL token; and validation is ajv, because OSCAL's `TokenDatatype` uses `\p{L}` and Python's `re` cannot compile a Unicode property escape, so `jsonschema` SKIPS the pattern and calls the document valid. CI asserts the check ran rather than skipping for a missing ajv. `gate --oscal` ships too: the gate already ran `analyze`, so it HAD the coverage record and simply never published it, and without it a document built from the gate could only ever say not-satisfied. The gate report now carries `controlSummary`, `resources` and `kubernetesVersion`, and a test asserts gate and audit agree bucket for bucket when given the same scope -- compared on a directory, because `gate -f rendered.yaml` is documented as a whole rendered namespace while `audit -f one-file.yaml` is a partial bundle by design; validated in CI against the pinned NIST schema with ajv, because Python's `jsonschema` cannot read the token pattern |
| P4 | **`ClusterNetworkPolicy` v1alpha2 evaluated, not just named** | Not started | **The wrong verdict is fixed; the capability is not.** G172 stopped the lie: a v1alpha2 CNP in the input now makes `policy reach` answer `UNDETERMINED` and exit 1, where it used to answer `ALLOWED` and exit 0 with the kind named only under `notEvaluated`. What remains is reading the policy so the answer can be allowed or denied rather than unknown. It is not "mostly a kind and tier mapping": v1alpha2 renamed the action `Allow` to **`Accept`** and replaced the port field with **`protocols`** (`tcp`/`udp`/`sctp`, each with `destinationPort`), so the existing evaluator would read every rule wrong. Budget a week. Calico 3.32 **removed** ANP/BANP enforcement -- "You must migrate to ClusterNetworkPolicy before upgrading to v3.32" (Tigera, 13 May 2026) -- so on a Calico 3.32 cluster the policies kube-noob does evaluate are the ones that no longer apply |
| P5 | **Fix the two failing scheduled workflows** | Diagnosed, not fixed | A red schedule that has been red for days trains everyone to ignore schedules. Both causes are now known, and neither is a bug in the workflow. **The scheduled `db-image.yml`** fails its own member-size gate: `redhat-vex.jsonl` has grown past `db_bundle.MAX_MEMBER` (300 MB), so the upstream VEX feed outgrew a limit this project set. The similarly named `db-image` job in `ci.yml` is green and always was -- it bundles a small public corpus and never downloads the VEX feed, so a green check there says nothing about this. Raising the number is the lazy answer and buys one quarter; the real choice is between sharding the file, filtering the feed to the products kube-noob answers about, and compressing the member. That is a decision, not a fix. **corpus-refresh** fails its privacy audit with 123 person-shaped findings. The gate is right to refuse, and as of G179 its report says which field and what shape matched, so the next run can be triaged from the log. A passphrase mismatch used to start a new copy; as of G182 the run fails and the previous artifact stays the main copy. The privacy findings and the VEX member size are still open |
| P6 | **A version ceiling on the API tables** | Shipped | `REMOVED_APIS` is stated "as of Kubernetes 1.37" and its highest removal is 1.32, and nothing anywhere says what the table has not checked. A question about a later minor is therefore answered "no removals", which is a verdict earned by absence (G163) -- and it stops being hypothetical on **16 December 2026**, when Kubernetes 1.38 is released (kubernetes.dev schedule; cycle began 31 August 2026). A `CHECKED_THROUGH` constant and a `beyondCheckedVersions` note on `validate` and `api_history` when the target minor exceeds it. Hours, and dated |
| P7 | **Calico 3.32 no longer enforces what kube-noob evaluates** | Shipped | **Reading the object is not the same as knowing the CNI ignores it.** Both halves are done. A `GlobalNetworkPolicy` or `CiliumClusterwideNetworkPolicy` in the input or on the cluster makes the answer `undetermined`. The opposite shape -- the input carries an `AdminNetworkPolicy` kube-noob evaluates while the CNI does not enforce it -- is `policy reach --cni NAME[:VERSION]`: `calico:3.32` reports every policy in that tier as inert and lets the NetworkPolicies answer, `cilium:1.18` makes the verdict undetermined because upstream states no support either way, and no flag keeps the OVN-Kubernetes assumption. `kube_noob.debug.cni` holds the table and its two sources, and a red team on it found nine wrong answers, all fixed with regression tests (G209). Not `policy migrate-check` after all: that command is a Kyverno rule-by-rule lint, and the wrong answer was being produced by `policy reach`, which is where it is now fixed (G207). The audit follow-up is shipped too: **KN-N014** reports an inert `AdminNetworkPolicy` or `BaselineAdminNetworkPolicy` at HIGH with `audit --cni` or `gate --cni`, and is NOT EVALUATED without the flag rather than clean, because no manifest states the CNI (G210). The last half shipped as **P9**: `--live` reads `clusterinformations.crd.projectcalico.org` and uses the cluster's own version, so the flag is for the cases a read cannot cover (G213) |
| P8 | **Every countable claim in the docs is generated or guarded** | Not started; four live defects found 2026-11-05 | **A wrong number in a published document is a defect, and four of them are live.** `docs/limits.md` states "47 generated / 31 not generated" for Kubernetes and "54 / 24" for OpenShift 4.20: both pairs sum to 78, the rule count this project retired, because the generated column was updated and the other was not. Measured now: 47 / 44 and 54 / 37, summing to 91. The same paragraph says two hand-kept counts were removed from it "because they were hand-kept ... and one of them was still 78 when the code had 89 rules" -- while carrying four more instances in the table directly above. `docs/use-cases.md` sells the compact report as "105 findings over 19 rules ... 118 631 to 54 694 bytes"; it is 115 over 21, and 141 349 to 69 936. `docs/editions.md` lists "the pcap analyser and `net verify`" under what a team gets free, and neither exists -- `insight.py` says packet capture "is not built yet" and there is no `net` subcommand. And "emits admission policies for most rules" is 47 of 91. The fix is the one that worked for `docs/compliance.md` (G206): generate the table, assert the measurement, and let `scripts/check.sh` fail when the code moves. First in this list because it is the only item here that is wrong rather than missing |
| P9 | **`--live` reads the CNI and its version from the cluster** | Shipped; P7 is complete | `--cni` is the caller's claim. On `--live`, kube-noob can read the fact instead: Calico publishes its version in `clusterinformations.crd.projectcalico.org`, and `debug/cluster.py` already has the `ResourceDef` table and the stubbed-backend tests to add it to. Without it, `policy reach --live` on a Calico 3.32 cluster keeps OVN-Kubernetes semantics and reports a deny that is not happening -- the exact defect P7 exists to prevent, surviving on the one path where the operator cannot read the policies themselves |

### Next: 0.9.0

| # | Item | Why |
|---|---|---|
| N1 | **Compliance Operator results reader** | `compliancecheckresults` and `rules.compliance.openshift.io` are namespaced, non-secret, get/list. Their `Rule` CRs carry NIST, CIS, SRG and PCI annotations and `checkType: Node\|Platform`. Reading them gives node-level CIS, STIG and PCI results kube-noob can never produce itself, already licensed to the customer, attributed to the operator and never to kube-noob |
| N2 | **Must-gather node configuration** | A standard must-gather carries every rendered `MachineConfig`, including `kubelet.conf`, kernel arguments, `fips`, CRI-O config and the container signature policy. kube-noob opens that bundle and routes eight analyser buckets; this is parsing an artifact already in hand, not a new privilege |
| N3 | **Curated FedRAMP 20x KSI evidence** | **Respecified 2026-11-05: the source this item was written against no longer exists.** FedRAMP has consolidated its machine-readable rules into one file, `fedramp-consolidated-rules.json` in `FedRAMP/rules` ("the canonical rules dataset"), at version **2026.11.02.01**, `last_updated` 2026-11-02. Every specific this row and `docs/compliance.md` carried is now wrong: there is no separate `FRMR.KSI.key-security-indicators.json` at 25.11C; there are **ten** families, not eleven (AFR and TPR are gone, SCR is new); there are **46 indicators**, keyed by mnemonic (`KSI-CED-RAT`), not by number (`KSI-CMT-05`), so the seven ids recorded as `retired: true` no longer exist as ids at all; and **no indicator in the current file carries any retirement, withdrawal or deprecation flag** -- every family is `status: stable`. The crosswalk now lives inside each indicator as `controls: [lower-case NIST ids]`, which is the direction this item needs: inverted, **26 of kube-noob's 28 controls map** (not 25), and `SC-6` and `SC-36` map to nothing. So the work is: vendor the file with its version and sha256 and assert both; invert the mapping with the same id transformation `oscal.control_id` already does (`AC-6(10)` -> `ac-6.10`); curate about ten indicators where a kube-noob finding is real config evidence and say in one sentence per indicator what it does and does not show; carry FedRAMP's own instruction to "account for framework applicability, service class, document status, and effective dates", and note that some indicators are `varies_by_class`. **A mapping is evidence, never a compliance claim** -- that caveat is kube-noob's own words, not a quote from FedRAMP, because the consolidated README makes no such statement and attributing one to them would be the defect this item exists to avoid |
| N4 | **Per-namespace standing posture** | **Shipped.** `posture diff` adds `byControl` -- open findings per NIST control with the namespaces each is open in -- and `controlStanding`, which separates a control whose rules ran and found nothing from one nothing evaluated. That separation needed the snapshot to record its coverage, so a snapshot written before this change gets the counts, no standing, and a note saying a control with no open finding there may simply not have been evaluated (G214) |
| N5 | **Rules in the under-served set** | **All five shipped.** `failurePolicy: Ignore` is KN-S030. The Pod Security `enforce` label is KN-S032, and it was NOT the rule the line above assumed: OpenShift's label syncer sets `warn` and `audit` from the SCCs a namespace's service accounts can use and deliberately not `enforce` -- the platform enforces privileged globally and leaves real enforcement to SCCs -- so reporting an absent `enforce` label on OpenShift would report the platform's own design as a defect. The rule is therefore silent on the OpenShift family for an absent label, reports an explicit `enforce: privileged` on every platform, and on vanilla Kubernetes says the level is the cluster's AdmissionConfiguration default rather than claiming the namespace enforces nothing, because no manifest shows that default. KN-C016 (no ResourceQuota or LimitRange) is cross-object and declines to decide on a partial bundle, and it is LOW and advisory because a ClusterResourceQuota or a cluster default can supply either and no manifest in the namespace shows that. KN-S033 reports a paused `MachineConfigPool`, which upstream documents as stopping both the rendered config and the machine update, so OS, kubelet and runtime patches stop for every node in the pool. KN-S034 reports an OLM `Subscription` that upgrades without review, and the non-obvious half is that an ABSENT `installPlanApproval` means Automatic -- upstream's `GetInstallPlanApproval` returns Manual only when the field says Manual -- so omitting it chooses automatic upgrades rather than deferring the decision |
| N6 | **Decision chain in the terminal** | **Shipped, and this row was stale.** `policy reach` prints the deciding tier, the policy and the rule, why every other rule did not match, what was not evaluated and the `NOT ENFORCED` line for an inert tier; `posture scan` prints every attack-path step as `from --edge--> to` with its evidence underneath. Both were already in the terminal when this row still asked for them, which is its own small lesson: a roadmap row that nobody closes is as misleading as a count nobody updates |
| N7 | **Numeric `targetPort` with no declared `containerPort`** | Shipped as KN-V023 (LOW). KN-V012 owns the named case and is HIGH because the name must resolve or the Service gets no endpoints. The numeric case cannot be that, because `containerPort` is informational: a Service pointing at 8080 works whenever something listens there. So the rule fires only where the selected containers DO declare ports and the target is outside that set -- a typo rather than a style -- and says in the finding that it is not proof. A workload that declares no ports at all is silent, which is the absence-read-as-defect case this rule had to avoid. An omitted `targetPort` is checked too: it defaults to `port`, so treating its absence as safe would have been the same defect in the other direction (G208) |
| N8 | **API-server configuration from a must-gather** | TLS profile, audit policy and effective arguments from `kubeapiservers.operator.openshift.io/cluster`. Field stability across 4.x needs a real bundle first |
| N10 | **DRA: what is left after the four rules** | Four rules now cover what a manifest proves: KN-V020 and KN-V021 inside one document, KN-C015 across the bundle, KN-S031 for `adminAccess`. **A `deviceClassName` that names no `DeviceClass` in the bundle is deliberately NOT a rule.** A `DeviceClass` is cluster-scoped and installed by the driver, so it is absent from almost every manifest set; flagging that absence would fire on every correct repository, which is the absence-read-as-defect failure rather than the absence-read-as-pass one. KN-ST001 can check an undeclared StorageClass only because `KNOWN_STORAGE_CLASSES` exists, and there is no comparable catalogue of device classes to build on -- a per-driver one is the only honest route and nobody has asked for it. What remains genuinely open: an admission policy for KN-S031 -- the shape fits, but the API server's own gate is the namespace label, so a generated policy would narrow a grant a cluster admin deliberately made, and nobody has asked for that yet; `spec.devices.constraints` and `config` are unread, and the `firstAvailable` prioritised list is parsed only far enough to know that `adminAccess` does not live there. What a manifest can never decide is the symptom users report -- `cannot allocate all claims` -- since allocation is matched against `ResourceSlice` objects a driver publishes from the hardware it found |
| N9 | Generate the rule table in `docs/compliance.md` from code | Shipped. `scripts/compliance_doc.py` writes the heading's count, the rule table and the control-titles table, `--check` runs in `scripts/check.sh` and in CI, and it found three live defects on the way: a heading reading 78 with 89 rules in the code, seven controls used by rules with no title row, and a guard that only checked one direction (G206) |
| N11 | **`/metrics`, a PrometheusRule, and an Alertmanager receiver route** | Platform requirement R6.5's missing third. The incident watch ships and Alertmanager payloads are parsed, but the HTTP server has no `/metrics`, the chart has no PrometheusRule, and there is no receiver route -- so a platform team cannot alert on a stale corpus, a failing sync or the sidecar itself. No platform team runs a pod it cannot alert on |
| N12 | **Gate findings as pull-request annotations** | **Shipped.** `gate --github-annotations`, on by default in the action. It took more than the four lines this row estimated, and GitHub's cap is why: it shows ten annotations of each kind per step and drops the eleventh silently, so nine are annotated and the tenth says how many are not shown (G215) |
| N13 | **Caller identity in audit records, and reading as the caller** | Ranked first by the FedRAMP High requirements and by every multi-tenant reviewer: today authorization is one shared bearer token and the server logs the tool, argument sizes, outcome and duration but never who asked. It stays an enterprise candidate in [editions.md](editions.md) rather than a 0.9.0 promise, because the honest version needs the OAuth proxy wired to a real identity provider and a cluster to prove it on -- but it is recorded here so the ranking is visible rather than implied |

### The moat backlog, reconciled 2026-11-05

The private build queue (M0-M13, 57 items) was last written on 2026-11-02 and its own tally said 21 done and 36
todo. Re-reading it against the code gives **21 shipped, 7 partial, 29 not started** -- and the seven partials are
the finding, because six of them were recorded as untouched and one as finished:

- **`I6` REST API was marked done and is not.** Twelve routes ship with a generated OpenAPI document and a
  contract test each, but the item's own route list includes `/v1/net/verify`, which cannot exist until the
  network verifier does. Re-opened.
- **`I8` kubectl plugin was marked todo and is shipped** (P2 here) -- deliberately as `kubectl noob`, not
  `kubectl kube-noob`.
- **`I2` CI surfaces**: SARIF, the action, the pre-commit hooks and the Tekton task ship; `audit --format sarif`,
  the NIST controls as SARIF rule properties, and a vendored SARIF schema with a validation test do not. The OSCAL
  work (P3) is the pattern to copy for that last one.
- **`V3` blast radius**: the paths are computed and surfaced by `posture scan`; the pod-anchored entry point, the
  JSON graph and the Mermaid rendering are missing.
- **`GOV1`**: OSCAL shipped; caller identity in audit records did not, and the HTTP server keeps no per-request
  audit record at all. That is N13.
- **`GOV3`**: the bundle, its checksum manifest, the verifier and image signing ship; the named `corpus pack`
  entry point, `corpus import --verify` and signing instructions for the pack do not.
- **`A5`** and **`M13`**: the benchmark runs one mode per invocation, so there is no side-by-side table; the
  milestone demos (`demo network`, `demo upgrade`, `demo gate`) are absent.

None of the work since 2026-11-02 moved a moat item from todo to shipped: it all belongs to the correctness track
above. That is the right order by this file's own principle, and worth saying plainly rather than leaving the two
tallies to imply progress neither of them made.

Next from that queue, in order, with what each already has: **E2** installed-operator inventory (two allowlist
entries; the must-gather analyser already parses ClusterServiceVersions, and E1 and the upgrade pre-mortem both
need the inventory), **I2**'s three missing criteria, **GOV3**'s three, **V3**'s pod-anchored entry, then **I1**
the Alertmanager receiver -- the only item that makes the north-star claim (alert to evidence pack in a minute)
measurable, and every analyser it needs already works.

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
| A single compliance score, or a percentage of 800-53 | 28 of about 1,189 controls. A percentage invites exactly the misreading FedRAMP warns against |
| Image registry scanning | Network, and Trivy and RHACS own it. Keep ingesting their output |
| Hosted compute, hosted cluster state, or shareable server-side links | "Nothing leaves your device" is the product. The browser playground already delivers zero-install without a backend |
| Any model inside the tool | The positioning, and a test enforces it |
| ISO 27001 mapping, certificate expiry from Secrets, a generic RBAC viewer | No free machine-readable crosswalk; forbidden; already answered by attack paths |

## The honest ceiling on compliance

kube-noob names 28 of NIST SP 800-53 Rev. 5's controls across its 91 rules. The right sentence is **"machine-readable
evidence bearing on these 28 controls, from these object kinds, over this scope, with these rules not applicable and
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
