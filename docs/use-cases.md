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

1. Paste events, `describe` output or logs into `diagnose`: as quoted text (multi-line is fine; single quotes stop the
   shell expanding `$`), as a file with `-f`, or piped in. You get the likely cause, then read-only steps (get,
   describe, logs, events).
2. Commands that run inside a container are listed next, and changes come last. Both are marked as needing approval.

```bash
kube-noob demo diagnose
kube-noob diagnose 'Back-off restarting failed container api in pod api-1'
kube-noob diagnose -f events.txt
oc get events -n shop --sort-by=.lastTimestamp | kube-noob diagnose
kube-noob bundle deployment/orders-api -n shop --cluster-enabled
```

`bundle` writes a redacted, read-only evidence pack (`bundle.md` and `bundle.json`) that you can attach to a ticket.
Once a fix is confirmed, save it with `kube-noob learning note`. The team finds it next time as `[kn:local-N#0]`.

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

`doctor` prints what the process can reach and exits 1 if the configuration contradicts the lock. To add kube-noob
as a tool in OpenShift Lightspeed, or to run it as a sidecar, follow [openshift.md](openshift.md). Index your own
runbooks with `kube-noob corpus add-docs <folder> --source platform-runbooks`, and prove the answers on your
machine with `kube-noob selftest`.

## Security: policy-aligned reviews and red-team scenarios

Each audit finding maps to the RHACS (StackRox) policy that would fire. `redteam` shows how an attacker would use a
bundle: escape paths, lateral movement, credential exposure.

```bash
kube-noob redteam -f k8s/ --platform openshift
kube-noob explain KN-S004
```

## Claude and MCP users

Install the plugin or add the MCP server (see the [README](../README.md)), then ask for the `getting_started` prompt.
It reads your saved profile, asks for your role and platform, and suggests the first three tools to use.

## Model builders

Build the corpus, score answers with the deterministic reward and export datasets: see [training](training.md).
