# Run kube-noob on OpenShift and ROSA

There are three ways to run kube-noob in a cluster. All three serve the same MCP tools, and all three start offline
and read-only.

| Mode | Who calls it | Network exposure | When to use |
|---|---|---|---|
| Service (Helm chart) | MCP clients and OpenShift Lightspeed, over HTTP with a bearer token | ClusterIP; optional Route | One shared instance for a team or the whole cluster |
| Sidecar | Only containers in the same pod, on `127.0.0.1` | none | An in-house assistant or bot that needs Kubernetes expertise |
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
  `--set config.clusterEnabled=true --set rbac.scope=namespace` and list the API server CIDRs in
  `networkPolicy.egress.apiServerCIDRs`. The ServiceAccount gets read verbs only and never Secrets.
- Persist notes, corpus and progress with `--set persistence.enabled=true`.
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

OpenShift Lightspeed can call external MCP servers when the `MCPServer` feature gate is on. The field names below
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

## Status of the public listings

- PyPI: `kube-noob` is published with Trusted Publishing and provenance on every tag.
- MCP Registry: `io.github.aashishmahajan/kube-noob` is published by the release workflow.
- Container image: `ghcr.io/aashishmahajan/kube-noob:<version>` is multi-arch and signed with cosign. Verify it
  with the commands in [SECURITY.md](../SECURITY.md).
- Claude plugin: `/plugin marketplace add aashishmahajan/kube-noob`. The Claude plugin directory listing is a
  manual submission (see [release readiness](release-readiness.md)).
- OpenShift Helm chart catalog and OperatorHub: not submitted yet. The chart carries the `charts.openshift.io`
  annotations; an operator bundle is on the roadmap.
