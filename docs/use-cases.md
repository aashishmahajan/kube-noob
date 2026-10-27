# Use cases

Pick your role, run the demo, then try it on your own files. Every demo runs offline in under a second and never
touches your cluster or your saved progress: `kube-noob demo --list`.

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

1. Paste events, `describe` output or logs into `diagnose`. You get the likely cause, then read-only steps (get,
   describe, logs, events).
2. Commands that run inside a container are listed next, and changes come last. Both are marked as needing approval.

```bash
kube-noob demo diagnose
kube-noob diagnose -f events.txt
kube-noob bundle deployment/orders-api -n shop --cluster-enabled
```

`bundle` writes a redacted, read-only evidence pack (`bundle.md` and `bundle.json`) that you can attach to a ticket.
Once a fix is confirmed, save it with `kube-noob learning note`. The team finds it next time as `[kn:local-N#0]`.

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
