# Run kube-noob on OpenShift and ROSA

There are three ways to run kube-noob in a cluster. All three serve the same MCP tools, and all three start offline
and read-only.

| Mode | Who calls it | Network exposure | When to use |
|---|---|---|---|
| Service (Helm chart) | MCP clients and OpenShift Lightspeed, over HTTP with a bearer token | ClusterIP; optional Route | One shared instance for a team or the whole cluster |
| Sidecar | Only containers in the same pod, on `127.0.0.1` | none | Your own bot or agent that needs Kubernetes expertise |
| OpenShift Lightspeed tool | Lightspeed's chat in the console calls the Service | in-cluster only | Developers ask in the console; kube-noob supplies audits, diagnoses and cited answers |

## 1. Service mode

```bash
oc new-project kube-noob
oc create secret generic kube-noob-token --from-literal=token="$(openssl rand -hex 32)"
helm install kube-noob deploy/helm/kube-noob -n kube-noob --set auth.existingSecret=kube-noob-token --set config.offline=true --set config.defaultPlatform=rosa-hcp
oc rollout status deployment/kube-noob -n kube-noob
helm test kube-noob -n kube-noob
```

- `config.offline=true` is the admin lock: no web, no corpus downloads, local models only.
- The pod runs under `restricted-v2`. NetworkPolicies allow only the same namespace and the router by default. Egress
  allows DNS only.
- Read-only cluster evidence (`cluster_get`, `cluster_debug_workload`) is opt-in. Set
  `--set config.clusterEnabled=true --set "rbac.namespaces={shop,payments}"` and list the API server CIDRs in
  `networkPolicy.egress.apiServerCIDRs`. The ServiceAccount gets read verbs only, never Secrets, and by default only
  in its own namespace plus `rbac.namespaces`; `rbac.scope=cluster` widens that. Every holder of the token reads
  through this ServiceAccount, so grant only the namespaces its users may see.
- Over HTTP, tools that write the learning file are not offered, because callers share one file. Add team notes with
  `oc exec deploy/kube-noob -- kube-noob learning note ...` (with `persistence.enabled=true` and `replicaCount=1`).
- Persist notes, corpus and progress with `--set persistence.enabled=true --set replicaCount=1` (a ReadWriteOnce
  volume attaches to one node, so the chart uses one replica and the Recreate strategy with it).
- Your own runbooks: `kube-noob corpus add-docs <folder> --source platform-runbooks` indexes them wherever the CLI
  or plugin runs. Loading runbooks into the in-cluster service (an init container that reads a Git repo or a
  ConfigMap) is on the roadmap.

Clients connect to `http://kube-noob.kube-noob.svc:8080/mcp` with `Authorization: Bearer <token>`.

## 2. Sidecar mode

[deploy/sidecar/app-with-kube-noob-sidecar.yaml](../deploy/sidecar/app-with-kube-noob-sidecar.yaml) is a complete
example. kube-noob listens on `127.0.0.1:8080` inside your pod, so no Service, Route or token is needed. Your
container calls `http://127.0.0.1:8080/mcp`. Audit the example with:

```bash
kube-noob audit -f deploy/sidecar/app-with-kube-noob-sidecar.yaml --platform openshift --fail-on medium
```

## 3. OpenShift Lightspeed integration

OpenShift Lightspeed can call external MCP servers when the `MCPServer` feature gate is on. Lightspeed's own model
does the talking; kube-noob answers its tool calls with audits, diagnoses and cited docs, and calls no model itself. The field names below
come from the `OLSConfig` API in the lightspeed-operator. Run `oc explain olsconfig.spec.mcpServers` to confirm the
schema of your installed version.

1. Install kube-noob in service mode (section 1), then let the Lightspeed namespace reach it:

```bash
helm upgrade kube-noob deploy/helm/kube-noob -n kube-noob --reuse-values --set networkPolicy.allowIngressNamespace=openshift-lightspeed
```

2. Give Lightspeed the bearer token. The operator reads the header value from the key `header` of a Secret in its
   own namespace:

```bash
oc create secret generic kube-noob-mcp-auth -n openshift-lightspeed --from-literal=header="Bearer $(oc get secret kube-noob-token -n kube-noob -o jsonpath='{.data.token}' | base64 -d)"
```

3. Register the server and turn on the gate:

```yaml
apiVersion: ols.openshift.io/v1alpha1
kind: OLSConfig
metadata:
  name: cluster
spec:
  featureGates:
    - MCPServer
  mcpServers:
    - name: kube-noob
      url: http://kube-noob.kube-noob.svc:8080/mcp
      timeout: 30
      headers:
        - name: Authorization
          valueFrom:
            type: secret
            secretRef:
              name: kube-noob-mcp-auth
```

Merge this into your existing `OLSConfig` with `oc edit olsconfig cluster`. Applying it as a new object replaces the
LLM provider settings.

4. Check: ask Lightspeed "audit this Deployment for OpenShift 4.22" with a manifest pasted in. The kube-noob audit log
   (`oc logs deploy/kube-noob -n kube-noob`) shows a `tool=kubenoob_...` line for each call.

## Compatibility

OpenShift 4.20 and later (Kubernetes 1.33 and later), including ROSA Classic and ROSA HCP. Every change runs the chart
install, a Helm test, the sidecar example under Pod Security `restricted`, and an MCP end-to-end check on Kubernetes
1.33, 1.34, 1.35 and the newest release (CI job `e2e-kind`). The chart and the sidecar example are audited for
OpenShift 4.20, 4.21 and 4.22. Pods run under `restricted-v2` with an arbitrary UID, no capabilities, `RuntimeDefault`
seccomp and a read-only root filesystem. The only APIs used are stable `v1` ones (`apps`, `networking.k8s.io`,
`policy`, `route.openshift.io`, `rbac.authorization.k8s.io`) plus the optional `k8s.ovn.org/v1` EgressFirewall.

## Sizing

Measured with `scripts/measure_footprint.py` (Python 3.13): about 80 MiB resident at start and 85 MiB peak after
search, audit, diagnose and a full protocol run, the same for stdio and HTTP. Each MB of indexed text (team runbooks,
a corpus) adds about 25 MiB; 3,000 issue-sized documents (11 MB) peaked at 340 MiB. On a cluster, the sidecar
container's cgroup reported 66 MiB current and 68 MiB peak after audit, diagnose and search calls (CI job `e2e-kind`,
Kubernetes 1.35, image built from the `Containerfile` on UBI 9 Python 3.12). The two sets of figures differ in Python
version and in what is counted (process resident memory versus the container's cgroup).

| Mode | Request | Limit |
|---|---|---|
| Sidecar, built-in knowledge | 128Mi | 256Mi |
| Service (chart default), up to about 15 MB of indexed text | 256Mi | 512Mi |
| Larger corpus | 85 MiB plus 25 MiB per MB of text | request plus 50% |

CPU is idle between calls; a call takes 2 to 70 ms.

## Traffic out of the cluster

kube-noob calls no model and, by default, opens no outbound connection. The chart's NetworkPolicy allows egress to
DNS only. `config.clusterEnabled` adds the API server CIDRs you list; `config.webEnabled` adds TCP 443 to public
addresses only (private, carrier-grade NAT and link-local ranges are excepted, so nothing in the cluster), or to your
egress proxy (`networkPolicy.egress.webProxy`), and the application allowlist limits that to documentation domains. To enforce domains at the network layer too, set
`egressFirewall.enabled=true` (OVN-Kubernetes). It allows only the API server (when cluster access is on) and HTTPS
to the allowlisted domains (when web access is on), then denies everything else leaving the cluster. It applies to the
whole namespace, so keep kube-noob in its own. In sidecar mode kube-noob needs no egress; the example's NetworkPolicy
allows DNS only, and you add your app's own destinations.

## Regulated environments

For FedRAMP High and other NIST SP 800-53 based programs (FIPS mode, identity, audit logs, image verification):
[compliance.md](compliance.md).

## Data retention

kube-noob processes requests in memory and keeps nothing from them. It stores only what a user saves on purpose:
learning progress, confirmed notes and indexed documents, in `/var/lib/kube-noob`. With `persistence.enabled=false`
(the default) that is an `emptyDir` and is gone when the pod is deleted; with persistence it stays on the PVC until you
delete it. Each request writes one log line to stdout (tool name, argument sizes, outcome, duration; never argument
contents); your cluster's logging decides how long that is kept. Details: [PRIVACY.md](../PRIVACY.md).

## Status of the public listings

- PyPI: `kube-noob` is published with Trusted Publishing and provenance on every tag.
- MCP Registry: `io.github.aashishmahajan/kube-noob` is published by the release workflow.
- Homebrew: `brew tap aashishmahajan/kube-noob https://github.com/aashishmahajan/kube-noob`, then
  `brew trust --formula aashishmahajan/kube-noob/kube-noob` and `brew install kube-noob`. The release workflow writes the formula once PyPI has the version, and CI installs it
  that way on macOS and Linux after every release and every week. Other ways and fixes: [install.md](install.md).
- Container image: `ghcr.io/aashishmahajan/kube-noob:<version>` is multi-arch and signed with cosign. Verify it
  with the commands in [SECURITY.md](../SECURITY.md).
- Claude plugin: `/plugin marketplace add aashishmahajan/kube-noob`. It runs the bundled server source with
  dependencies pinned by hash in `uv.lock`. The Claude plugin directory listing is a manual submission (see
  [release readiness](release-readiness.md)).
- OpenShift Helm chart catalog: ready to submit to the community tier; steps in [openshift-catalog.md](openshift-catalog.md).
  OperatorHub (Software Catalog) needs an operator bundle and is on the roadmap.
