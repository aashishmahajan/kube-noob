# Use cases

Pick your role, run the demo, then try it on your own files. Every demo runs offline in under a second and never
touches your cluster or your saved progress: `kube-noob demo --list`.

## No AI inside: three ways to use it

kube-noob is the rulebook, not the chatbot. Its audit rules, playbooks, docs index and graders give the same answer
every time, and they run where you put them.

1. **With Claude** (plugin in Claude Code or Cowork): ask in your own words and paste YAML, events or logs. Claude
   calls kube-noob's tools and explains the results. Your conversation goes to Claude as usual; kube-noob sends
   nothing.
2. **With OpenShift Lightspeed or another MCP client**: the same tools, served in your cluster
   ([openshift.md](openshift.md)). That client's model does the talking.
3. **With no AI at all**: the CLI below. Audits, diagnoses, cited search, lessons and evidence bundles need no model
   and no network, which suits CI gates and air-gapped clusters.

`kube-noob ask` is the one optional command that uses a model: one you configure, and only a local one under the
offline lock.

## Learner or trainer: practise Kubernetes objects offline

You write YAML and get graded feedback straight away. The grader uses the same rules as a production review, and it
knows the platform: an SCC rejection on OpenShift, a storage class on ROSA HCP.

```bash
kube-noob demo learn
kube-noob learn tracks
kube-noob learn lesson k8s-101-objects
kube-noob learn exercise k8s-ex-hardened-deployment
kube-noob learn submit k8s-ex-hardened-deployment -f my-answer.yaml
```

The [learning guide](learning.md) covers running a class.

## Developer: ship YAML that passes on OpenShift and ROSA HCP

```bash
kube-noob demo audit
kube-noob audit -f k8s/ --platform openshift --version 4.22
kube-noob fix -f k8s/deployment.yaml --platform openshift -o fixed.yaml
kube-noob protocol "deploy orders-api" --blueprint examples/blueprint.yaml
kube-noob helm-chart --name orders-api --namespace shop --image quay.io/acme/orders:1.4.2 --platform rosa-hcp -o charts
```

To gate pull requests, run `kube-noob audit -f k8s/ --fail-on high` in CI. It exits 1 on any HIGH or CRITICAL finding.

## SRE or on-call: diagnose before you change anything

Not sure what you have? `insight` names it first (events, logs, a denial, manifests, a ticket, a build log, a
question; several at once), runs every analyser that applies and merges the answer: findings with their source,
read-only next steps, and what it did not analyse and why. Input with no evidence gets the read-only commands that
collect some.

```bash
kube-noob insight -f whatever-you-copied.txt
oc describe pod web-1 -n shop | kube-noob insight --platform openshift
kube-noob insight 'why does my pod stay Pending?'
kube-noob insight -f trace.pcap --format json
```

1. Paste events, `describe` output or logs into `diagnose`: as quoted text (multi-line is fine; single quotes stop the
   shell expanding `$`), as a file with `-f`, or piped in. An Alertmanager webhook payload works as it is. You get
   the signals it found (alert names, event and container reasons), the likely cause, then read-only steps (get,
   describe, logs, events).
2. Commands that run inside a container are listed next, and changes come last. Both are marked as needing approval.

```bash
kube-noob demo diagnose
kube-noob diagnose 'Back-off restarting failed container api in pod api-1'
kube-noob diagnose -f events.txt
kube-noob diagnose -f alert.json
kube-noob signals -f alert.json
oc get events -n shop --sort-by=.lastTimestamp | kube-noob diagnose
kube-noob bundle deployment/orders-api -n shop --cluster-enabled
```

Signals rank the playbooks: a firing `etcdHighNumberOfLeaderChanges` puts the etcd playbook first even when the
words differ, and a payload's `openshift_version` (or `version`) label, when it names an OpenShift 4 release, picks
the reported issues for that version. `signals` (MCP: `kubenoob_extract_signals`) lists what was found, the alerts the
words imply ("leader changed"), each catalogue entry's upstream source and the playbooks they point at.

An ImagePullBackOff whose pull secret sits in another namespace is named for what it is: kubelet's
`FailedToRetrieveImagePullSecret` event (or the question in those words) ranks the pull-secret playbook first, with the
secret and namespace filled in, read-only checks that list Secret names (never values), and the fixes for each case:
create or sync the secret in the pod's namespace and link it, the OpenShift global pull secret for a registry every
project uses, or `system:image-puller` for another project's internal registry. `audit` catches it before deploy
(KN-C013) when the bundle defines the Secret only in another namespace, and the in-cluster debug reads the pod's and
its ServiceAccount's pull secret names.

```bash
kube-noob diagnose 'ImagePullBackOff when the pull secret sits in a different namespace from the pod'
oc describe pod web-7d9c6b9f5-x2k8p -n shop | kube-noob diagnose --platform openshift
```

`bundle` writes a redacted, read-only evidence pack (`bundle.md` and `bundle.json`) that you can attach to a ticket.
Once a fix is confirmed, save it with `kube-noob learning note`. The team finds it next time as `[kn:local-N#0]`.

### Does it answer our problems? Test it on them

`kube-noob selftest --cases` runs your own problems through the same diagnosis, search, known-issue and audit paths
the CLI and MCP server use, offline. Start with a plain list of questions (one per line, or multi-line pastes
separated by `---`): each is answered and listed for you to label. Add `expect` (the playbook, documents, issues or
rules you expect, phrases the answer must or must not mention) and the case becomes a test with a pass or fail.
YAML, JSONL and CSV (for a spreadsheet export) work too; `examples/problems.yaml` shows every field.

```bash
kube-noob selftest --cases examples/problems.yaml
kube-noob selftest --cases our-problems.txt --out problem-report
kube-noob selftest --cases our-problems.yaml --gate 0.9
```

kube-noob has no model, so nothing is learned by itself: a failed case is fixed with a playbook, signal, rule or
team memory entry that is reviewed like any other change, and then guards against regressions.

### Is this CVE fixed in my OpenShift?

`corpus advisories` keeps Red Hat's VEX statements for the products kube-noob covers, so search answers which
component is fixed by which erratum, which is not affected and why, offline. The public `kube-noob-db` image carries
them already.

```bash
kube-noob corpus advisories --online --cves CVE-2023-44487
kube-noob search 'CVE-2023-44487 openshift haproxy router'
```

### Is this a known bug?

`known-issues` matches an error or symptom against the issues Red Hat lists in the OpenShift 4.20, 4.21 and 4.22 release
notes: known issues, and the issues each update fixed. You get the issue link, whether a fix exists and in which
version, the workaround, and the release-notes file it came from. Pass your version and issues already fixed there are
left out. `diagnose` runs the same check, and on a live cluster `debug` and `bundle` read the version themselves.
A match needs several rare words in common, so everyday errors such as OOMKilled never pull in an unrelated bug.

```bash
kube-noob known-issues 'could not find any suitable subnets for creating the ELB' --version 4.20.8
kube-noob diagnose -f events.txt --platform openshift --version 4.21.4
kube-noob corpus known-issues --online
```

The bundled index is dated (`kube-noob doctor` prints it, and every MCP result carries `knowledgeAsOf`);
`corpus known-issues --online` refreshes it from the release notes on GitHub.

### Has Red Hat seen this error before?

The release notes list only a few hundred issues. Red Hat's public Jira holds every reported ticket, including the ones
closed as Not a Bug, Won't Do or Duplicate, which often answer the question faster than a fix would. `corpus jira`
keeps a local copy of every ticket in the OpenShift, ROSA, ACM and RHACS projects (OCPBUGS, ROX, HOSTEDCP and 25
more; `jira-projects` lists them), whatever its status. After that, `known-issues`, `diagnose`, `debug` and the
incident watch also say what became of each matching ticket:

- fixed, in which release, and whether your version already has the fix ("updating to 4.21.3 or later fixes it");
- open, with a fix merged or proposed;
- closed as Not a Bug (expected behaviour or a configuration issue), Won't Do, Cannot Reproduce, Obsolete, or as a
  duplicate of another ticket, which is then followed;
- the workaround, cause or "why closed" sentence from the latest comments.

The copy keeps each ticket's full description and every comment, so you can audit it yourself; commenters appear as
Commenter A, B and so on (per ticket), and names, emails, phone numbers and account ids are removed.

```bash
kube-noob corpus jira-projects --online
kube-noob corpus jira --online
kube-noob known-issues 'x509: certificate signed by unknown authority' --version 4.21.1
kube-noob ticket OCPBUGS-12345 --version 4.21.1
```

The copy is read through Jira's REST API, never by scraping its web pages, at one request per second or slower (the
site's robots.txt asks for that), with a request budget per run (`--max-requests`, default 600). Each later run
fetches only what changed and resumes where a budget stopped it; a request returns up to 100 tickets, and OCPBUGS alone
has keys past 87,000, so the first copy of the default set completes over several runs. Tickets are public but not
licensed for redistribution: they stay in
your data directory (`corpus/jira-*.jsonl` plus a search index in `jira/`), kube-noob never publishes them, and
`--projects all` or `--projects OCPBUGS,ROX` choose other projects. In the cluster, `jira.sync.enabled` keeps the copy
current from the service; offline clusters import a copy built elsewhere with `corpus import`.

### One main copy for the whole organisation, and what changed since yesterday

Seal the copy with your own key before it goes into an image, and give pods the key from a Secret: a new pod answers
ticket questions from its first minute with no Jira egress, and a wrong key imports nothing and says so. The
`jira-db-image` workflow does this after every refresh and refuses a public repository.

```bash
openssl rand -base64 32 > seed.key
kube-noob corpus jira-snapshot -o jira-snapshot.tgz
kube-noob corpus seal jira-snapshot.tgz -o jira-snapshot.tgz.enc --key-file seed.key
kubectl create secret generic kn-seed-key --from-file=key=seed.key
helm upgrade --install kube-noob deploy/helm/kube-noob --set jira.seed.source=image --set jira.seed.image.repository=quay.io/acme/kube-noob-db-jira --set jira.seed.image.digest=sha256:<digest> --set jira.seed.path=/seed/jira-snapshot.tgz.enc --set jira.seed.keySecret.name=kn-seed-key --set config.offline=true
```


Nobody should wait hours for a first sync. Keep one main copy, refresh it daily (or every two days), and start every
other install from it:

```bash
kube-noob corpus jira --online
kube-noob corpus jira-snapshot -o jira-snapshot.tgz
kube-noob corpus import jira-snapshot.tgz
```

The snapshot holds the tickets, the sync state and the change log; an install that imports it answers at once and its
own sync (if any) only fetches what changed since. A brand-new copy fetches each project's open tickets first, so the
tickets people reconcile arrive in the first run. Every sync records what moved, and reconciliation reads it offline:

```bash
kube-noob corpus jira-changes --since 1d
kube-noob corpus jira-changes --since 2026-10-25 --project OCPBUGS --kind fixed --kind reopened
```

You get the tickets fixed (and in which versions), closed as not a bug, won't fix or duplicate, reopened, given a fix
version or opened, each with its link, and the open tickets per project and verdict. Over MCP the same is the
`kubenoob_ticket_changes` tool. `kube-noob corpus jira-audit` shows what the copy holds: tickets per project and
verdict, comments kept against what Jira reported, tickets cut at the size cap or still in the older format, key
coverage, size, sync state, what the anonymiser replaced, and a self-check that no email, account id or profile link
is left (the daily workflow fails if one is).

The `corpus-refresh` workflow keeps the main copy in GitHub Actions: daily at 05:17 UTC (set the repository variable
`JIRA_EVERY_DAYS` to `2` for every two days), continuing the previous run's copy, with the changes and open tickets in
the run summary, and the new copy uploaded only encrypted with your `CORPUS_PASSPHRASE`. In OpenShift, put the
snapshot in a private image and set `jira.seed` so every new pod starts from it (an init container copies it; the
image needs `cp` and must run as non-root):

```bash
gh run download "$(gh run list --repo aashishmahajan/kube-noob --workflow corpus-refresh.yml --status success --limit 1 --json databaseId --jq '.[0].databaseId')" --repo aashishmahajan/kube-noob -n jira-main-copy-encrypted -D seed
openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -in seed/jira-snapshot.tgz.enc -out seed/jira-snapshot.tgz -pass env:CORPUS_PASSPHRASE
printf 'FROM registry.access.redhat.com/ubi9/ubi-micro:latest\nCOPY --chmod=0444 jira-snapshot.tgz /seed/jira-snapshot.tgz\nUSER 1001\n' > seed/Containerfile
podman build -t registry.example.com/platform/kube-noob-jira-seed:2026-10-28 seed
podman push registry.example.com/platform/kube-noob-jira-seed:2026-10-28
helm upgrade --install kube-noob deploy/helm/kube-noob --reuse-values --set jira.seed.source=image --set jira.seed.image.repository=registry.example.com/platform/kube-noob-jira-seed --set jira.seed.image.tag=2026-10-28
```

`jira.seed.source: pvc` reads the snapshot from a read-only claim instead. Keep the image, bucket or volume private:
the tickets are public but not licensed for redistribution.

### Why was this denied?

`policy explain` reads a denial and explains it policy by policy: Kyverno, OPA Gatekeeper, ValidatingAdmissionPolicy,
Pod Security Admission, OpenShift SCC, RHACS, ResourceQuota, LimitRange and RBAC. You get the policy and rule, the
field that failed, read-only commands with the names filled in, the change that satisfies the policy (a ready patch
for Pod Security and RBAC, scoped to exactly the missing permission) and the audit rules that would have caught it
before deploy. Exceptions, quota increases and new permissions are marked as the policy owner's decision. `diagnose`,
`debug` and `bundle` add the same explanation when a denial is in the text.

```bash
kubectl apply -f deploy.yaml 2>&1 | kube-noob policy explain
kube-noob policy explain -f examples/events-scc.txt --platform openshift
```

### Can pod A reach pod B?

`policy reach` evaluates NetworkPolicies the way Kubernetes does: egress from the source and ingress to the
destination must both allow the port. It names the policy and rule that decide each direction, says for every other
rule whether the peer or the port did not match, and proposes the smallest NetworkPolicy that would allow the traffic.
It exits 1 when the traffic is denied, so CI can assert the paths an application needs. `--live` reads the policies,
namespace labels and workloads from the cluster (read-only). AdminNetworkPolicy, EgressFirewall and CNI-specific
policies are listed as not evaluated.

```bash
kube-noob policy reach --from web/frontend --to shop/orders-api --port 8080 -f examples/netpol-shop.yaml
kube-noob policy reach --from shop/orders-api --to shop/payments --port 9090 -f examples/netpol-shop.yaml
kube-noob policy reach --from shop/orders-api --to shop/payments --port grpc --live --cluster-enabled
```

### What did we learn last time?

`memory` keeps your team's fixes as code: one reviewed YAML file per lesson in a repository you own
(`entries/MEM-<n>.yaml`), with the signals it shows, the cause, the fix and what happened each time someone applied it.
`memory match` puts the entries next to the playbooks: signals first (an alert name in a payload), then distinctive
words. Fixes come first, then runbooks, then what was tried and did not work; an entry whose fix is already in your
version shows as retired. Each match says how often it was applied and how often it resolved the problem.

```bash
kube-noob memory init team-memory
kube-noob memory add team-memory --symptom "etcd leader changes after the update" --cause "catalog sync I/O" --fix "update to 4.21.1" --signal alert:etcdHighNumberOfLeaderChanges --platform openshift
kube-noob memory validate team-memory
kube-noob memory match -f alert.json --dir team-memory --version 4.21.0
kube-noob memory outcome team-memory MEM-1 --result resolved --ticket INC-4211 --cluster prod-east
kube-noob demo memory
```

`validate` is the guard against a poisoned entry, and `init` writes a CI workflow that runs it on every pull request:
every patch is validated, audited and red-teamed, commands must carry the classifier's labels, and grants of the
privileged SCC, cluster-admin, hostPath or wildcard RBAC fail unless the entry records who accepted the risk and why.
`add` writes a proposed entry and never commits; `migrate-learning` turns confirmed learning notes into proposed
entries, and `import --from servicenow-json|servicenow-csv|jira-json|jira-csv -f export` turns resolved tickets into
proposed entries with their outcomes, without the people in them. `replay` answers whether that memory would have
helped: it replays later tickets in order, without hindsight, and reports hits, misses and, with your labels,
how many matches were useful (the gate is 30%). kube-noob reads the repository where it runs and never uploads, bundles or exports it.

Set `memory.paths` (or `KUBE_NOOB_MEMORY_PATHS`) and `diagnose`, `known-issues`, `debug` and `bundle` add the
matching approved entries to every answer, cited as `[mem:MEM-<n>]`. Over MCP, `kubenoob_memory_match` searches
them and `kubenoob_memory_propose` turns a fix the user confirmed into an entry; only a local stdio server saves
it (as proposed, after the user asks), and the HTTP server never writes.

### Always on: the incident watch

`watch` polls your namespaces read-only (pods, events, deployments, replicasets; never Secrets) and turns what it sees
into incidents: crash loops, OOM kills, image pulls, container config errors, pods that cannot be created (with the
policy that denied them), scheduling, mount and probe failures, stuck rollouts and evictions. Each new incident is
explained once (playbook, policy denial, reported OpenShift bug) and gets a "what changed" note when it started soon
after a rollout ("started 4 min after the rollout to revision 2: image 2.7.0 -> 2.7.1; memory limit 256Mi -> 128Mi").

The incident ledger is its memory: how often each incident came back, how long each one lasted, and the fix your team
confirmed, which comes back with the next occurrence and with the same problem in other workloads. Claude or
Lightspeed read it through `kubenoob_incidents`; in the cluster, set `watch.enabled` in the chart.

```bash
kube-noob --cluster-enabled watch -n shop -n payments
kube-noob --cluster-enabled watch -n shop --once
kube-noob incidents
kube-noob incidents show inc-3fa94c0e12
kube-noob incidents confirm inc-3fa94c0e12 --cause "memory limit cut to 128Mi" --fix "restored the 256Mi limit"
```

## Platform admin: run it inside the cluster, locked down

```bash
kube-noob demo posture
helm install kube-noob deploy/helm/kube-noob --set auth.existingSecret=kube-noob-token --set config.offline=true
kube-noob doctor
```

`config.offline=true` (or `KUBE_NOOB_OFFLINE=1`) is an admin lock:

- no web, no corpus downloads, and local models only;
- nothing later in the config chain can lift it;
- the chart refuses to render if web access is also requested.

Start answering from day one without any egress: the public `kube-noob-db` image carries the documentation corpus
(with its licenses), release history and known issues, rebuilt daily and checked to hold no Jira data. Pin it by
digest; pods import it on start when it is newer than what they have.

```bash
cosign verify ghcr.io/aashishmahajan/kube-noob-db@sha256:<digest> --certificate-identity-regexp https://github.com/aashishmahajan/kube-noob/ --certificate-oidc-issuer https://token.actions.githubusercontent.com
helm upgrade --install kube-noob deploy/helm/kube-noob --set db.enabled=true --set db.image.digest=sha256:<digest> --set config.offline=true
kube-noob corpus db-check kube-noob-db.tgz
```

`doctor` prints what the process can reach and exits 1 if the configuration contradicts the lock. To add kube-noob
as a tool in OpenShift Lightspeed, or to run it as a sidecar, follow [openshift.md](openshift.md). Index your own
runbooks with `kube-noob corpus add-docs <folder> --source platform-runbooks`, and prove the answers on your
machine with `kube-noob selftest`.

## Build: from a failed build to the fix

`build diagnose` reads the log your CI system already wrote: GitHub Actions (`gh run view <id> --log-failed`),
Jenkins (the console), Tekton (`tkn pipelinerun logs <run>`) or an OpenShift build (`oc logs build/<name>`). It names
the failing step and why it is that step (the step with `##[error]`, the stage that ran before the skipped ones, the
task that `tkn` reports failed, the STEP buildah stopped at), the error line and its template, the cause class
(dependency fetch, compile, test, image push, registry auth, quota, timeout, out of memory, permissions), reported
issues and team memory for the error lines, and the fix for that system (a BuildConfig push secret, a Tekton step's
`computeResources`, `timeout-minutes`). Quoted lines are redacted.

```bash
gh run view 1234567890 --log-failed > build.log
kube-noob build diagnose -f build.log --format text
oc logs build/web-7 -n shop | kube-noob build diagnose -f - --platform openshift --version 4.20
```

`build audit` checks a Containerfile before it is built and the image after: base images pinned by digest, a
non-root `USER` (on OpenShift: group 0 owns what it writes), no credentials in `ENV`, `ARG`, `LABEL`, `RUN` or copied
files, no download piped into a shell, package caches cleaned, a health check or the workload's probes, a multi-stage
build. With `--context` it lists the credential files `COPY . .` would take; with `--image-layout` it reads the built
image from disk (no pull, no extraction) and finds credentials in its layers, including one a later layer deleted,
and in its config and history. Values are never printed, only the kind and where.

```bash
kube-noob build audit -f Containerfile --context . --manifests k8s/deployment.yaml
skopeo copy docker://quay.io/acme/web:1.8.0 oci:/tmp/web-oci:1.8.0
kube-noob build audit -f Containerfile --image-layout /tmp/web-oci --fail-on high
```

### Gate a release before it deploys

`gate` is one command for CI: the audit rules over manifests and rendered charts, the exception list, whether each
finding would be refused by the generated admission policy in enforce mode, open reported issues in the target
OpenShift release that name a kind you deploy, and the Containerfile checks. It exits 1 at `--fail-on` and writes
SARIF (GitHub code scanning), a Markdown summary and GitLab code quality JSON. Findings in a rendered chart point at
the template file.

```bash
kube-noob gate --chart deploy/helm/shop --values deploy/helm/shop/values-prod.yaml --containerfile Containerfile \
  --platform openshift --version 4.20 --exceptions kube-noob-exceptions.yaml --sarif kube-noob.sarif \
  --summary kube-noob-summary.md
```

GitHub Actions (add `github/codeql-action/upload-sarif` after it to see findings in code scanning):

```yaml
- uses: aashishmahajan/kube-noob@<tag>
  with:
    chart: deploy/helm/shop
    values: deploy/helm/shop/values-prod.yaml
    containerfiles: Containerfile
    platform: openshift
    version: "4.20"
```

Tekton: `oc apply -f deploy/tekton/kube-noob-gate.yaml`, then a pipeline task with `taskRef: {name: kube-noob-gate}`,
the source workspace and `params: [{name: paths, value: k8s}]`. GitLab: include
`deploy/gitlab/kube-noob-gate.gitlab-ci.yml` and extend `.kube-noob-gate` with `KUBE_NOOB_PATHS`; findings show in
the merge request through the code quality report.

## Security: policy-aligned reviews and red-team scenarios

Each audit finding maps to the RHACS (StackRox) policy that would fire. `redteam` shows how an attacker would use a
bundle: escape paths, lateral movement, credential exposure.

```bash
kube-noob redteam -f k8s/ --platform openshift
kube-noob explain KN-S004
```

### What does RHACS check that kube-noob does not, and the other way round?

`rhacs compare` maps every RHACS policy (export them from the RHACS portal with Export policy to JSON, or
`POST /v1/policies/export`) to kube-noob's rules, by the default policy names each rule cites and by the
policy's criteria, and gives each one outcome with the reason. Overlap names the rules and any difference in severity
or scope (RHACS scopes a policy by namespace; kube-noob checks every object). Related means the same risk seen another
way: RHACS records who exec'd into a pod, kube-noob checks who is allowed to (KN-S017); RHACS combines a privileged
container with fixable CVEs, kube-noob checks the privileged part. Gap names a deploy-time setting kube-noob has no
rule for. Outside is what a static manifest check cannot see: image contents and vulnerabilities, processes and
network flows at runtime, API events, label conventions. The report also lists where the two disagree, the default
policies RHACS ships disabled that kube-noob checks, and the kube-noob rules no policy covers. A policy with
criteria kube-noob does not know is unexplained and the command exits 1.

```bash
kube-noob rhacs compare -f policies.json --format text
kube-noob rhacs compare -f policies.json --format text --outcome gap --outcome related
ROX_API_TOKEN=<token> kube-noob --config rhacs.yaml rhacs compare --live
```

`--live` reads Central with `rhacs.enabled: true` and `rhacs.endpoint` in the configuration: GET only, to that host
only, a token that can read policies (the Analyst role is enough), a short random pause between requests; under the
offline lock only an in-cluster Central (`*.svc`).

### Which exposure leads where? Attack paths

`posture scan` follows what is exposed (a Route, an Ingress, a LoadBalancer, NodePort or externalIPs Service) to the
pods it reaches and what an attacker running code in them could do: take the node (a privileged container, a
hostPath volume, the host's PID or network namespace, near-root capabilities) or use the pod's ServiceAccount token
(read Secrets, exec into pods, create workloads that run as any ServiceAccount of the namespace, escalate, bind or
impersonate, the kubelet API, or on OpenShift a privileged SCC plus the right to create pods). Each path scores
exposure (internet 3, node network or a restricted load balancer 2, internal 1) times blast radius (1-10, cluster-wide
above one namespace), lists every step with the field that proves it, and ends with a fix. A pod with
`automountServiceAccountToken: false` has no token step; unexposed pods are not paths. It reads RBAC objects, never
Secrets (Secret objects in a bundle are dropped unread). `--fail-above` makes it a CI gate. NetworkPolicies on the
entry edge are not applied: check a path with `policy reach`.

```bash
kube-noob posture scan -f k8s/
kube-noob posture scan -f k8s/ --fail-above 17
kube-noob --cluster-enabled posture scan --live -n shop -n payments
```

### What changed since yesterday? The daily drift and policy report

`posture snapshot` records every watched object (workloads, Services, Routes, Ingresses, NetworkPolicies, RBAC,
SCCs, PDBs, HPAs, ConfigMaps, StorageClasses, claims and namespaces) as a hash of its desired state plus a short hash
per field, and today's findings with each object's owner (its `owner` or `team` label, else its namespace's). No
values are kept. `posture diff` compares two snapshots: objects added, removed and changed with the fields that
changed, findings new and fixed, and open findings by namespace, owner and rule. Scaling, status, server-set
metadata and the ReplicaSets and pods a controller makes are not drift. `posture report` does both in one step and
keeps the newest snapshots and reports (JSON and Markdown) in a folder; `serve` with `posture.reportEnabled` (chart:
`posture.report.enabled`) writes one a day at a random time, and the MCP tool `posture_report` returns the newest.
Excepted findings (`--exceptions`) are not counted open.

```bash
kube-noob posture snapshot -f k8s/ -o monday.json
kube-noob posture diff monday.json tuesday.json --markdown drift.md
kube-noob --cluster-enabled posture report --live -n shop --exceptions kube-noob-exceptions.yaml
```

### Accept a risk on purpose: exceptions as code

An exception is a file entry, reviewed by pull request like the manifests: the rule, the objects it covers (a
namespace, or a prefix such as `team-*`, optionally a kind and a name pattern; a cluster-scoped object by kind and
exact name), who owns it, why, and when it expires (at most 400 days ahead). `kube-noob audit --exceptions` hides
exactly the findings an active exception covers and lists them as excepted with the owner and expiry; the same rule on
any other object still fails. An expired entry, or one refused for a missing owner or reason, an unknown rule, a scope
wider than a namespace or an expiry too far out, fails the gate (exit 1) with the reason. Exceptions nothing uses are
reported so they can be deleted. `policy generate --exceptions` turns the active entries into exemptions in their
rule's admission policy, including the ReplicaSets and pods the excepted workload makes.

```bash
kube-noob exceptions check examples/kube-noob-exceptions.yaml
kube-noob audit -f k8s/ --exceptions examples/kube-noob-exceptions.yaml
kube-noob policy generate --mode enforce --exceptions examples/kube-noob-exceptions.yaml -o policies.yaml
```

### Enforce the audit rules at admission

`policy generate` turns every audit rule that can be decided from one object into an admission policy: a
ValidatingAdmissionPolicy with its binding (built into Kubernetes 1.30+, so every OpenShift 4.20+), a Kyverno
ValidatingPolicy (`policies.kyverno.io/v1`, Kyverno 1.18+), or both, carrying the same CEL. Each policy is named
after its rule (`kube-noob-kn-s001`), and its message carries the rule id, the fix and the source. Start in audit
mode, which admits and warns (`kubectl` prints the warning; the API audit log and Kyverno reports record it), then
switch a rule to enforce when its warnings are gone.

The policies refuse exactly what `kube-noob audit` reports for that one object at low severity or above, never
more: a test compares both on 2,700 generated objects, and CI applies every policy to a kind cluster and checks
that a server-side dry-run refuses the rule's bad fixture and admits its good one. Four rules check less than the
audit and say so in a `kube-noob.io/limitation` annotation (a `--password` value in the next argument, a
ServiceAccount's token opt-out, an HPA-scaled workload, a budget compared with the replica count). Rules that need
other objects (a Service and its pods, a claim and its StorageClass) or that the API server already enforces are
listed in the file header with the reason. Platform namespaces (`kube-*`, and `openshift-*` on OpenShift) and the
platform's operators are exempt; calibrate rules (probes, resources, replicas) skip objects a controller owns, so a
rollout is never blocked by its own ReplicaSets.

```bash
kube-noob policy generate --platform openshift --version 4.20 --mode audit -o kube-noob-policies.yaml
oc apply -f kube-noob-policies.yaml
kube-noob policy generate --rule KN-S001 --rule KN-S009 --mode enforce --engine vap -o enforce.yaml
kube-noob policy generate --engine kyverno --exclude-namespace legacy-apps -o kyverno.yaml
```

## Claude and MCP users

Install the plugin or add the MCP server (see the [README](../README.md)), then ask for the `getting_started` prompt.
It reads your saved profile, asks for your role and platform, and suggests the first three tools to use.

## Model builders

Build the corpus, score answers with the deterministic reward and export datasets: see [training](training.md).
