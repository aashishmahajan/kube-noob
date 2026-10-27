# kube-noob Helm chart

Runs kube-noob as a token-protected MCP service on OpenShift 4.20 and later or Kubernetes 1.33 and later. kube-noob
has no AI inside: OpenShift Lightspeed, Claude or any MCP client calls its tools (audit, diagnose, cited docs,
learning), and it calls no model itself.

## Install

```bash
helm install kube-noob oci://ghcr.io/aashishmahajan/charts/kube-noob -n kube-noob --create-namespace
```

The chart generates a random bearer token in the Secret `<release>-kube-noob-token` and keeps it across
`helm upgrade`. To bring your own, create a Secret with the key `token` and set `auth.existingSecret`; do this with
`helm template` or GitOps (Argo CD, Flux), where the chart cannot look the Secret up and would rotate the token.
Clients connect to `http://<release>-kube-noob.<namespace>.svc:8080/mcp` with `Authorization: Bearer <token>`.

## Secure by default

- Pods run under `restricted-v2` (arbitrary UID, no capabilities, `RuntimeDefault` seccomp, read-only root
  filesystem) and Pod Security `restricted`.
- NetworkPolicy: ingress only from the same namespace and the OpenShift router; egress to DNS only.
- No web access, no cluster access and no model calls unless you turn them on.

## Main values

| Value | Default | Effect |
|---|---|---|
| `auth.existingSecret` | `""` | Your token Secret; empty generates one |
| `config.offline` | `false` | Admin lock: no web, no downloads, local models only |
| `config.webEnabled` | `false` | HTTPS GET to allowlisted documentation domains; opens egress 443 |
| `config.clusterEnabled` | `false` | Read-only cluster tools (never Secrets); needs `networkPolicy.egress.apiServerCIDRs` |
| `rbac.namespaces` | `[]` | Namespaces it may read besides its own (`rbac.scope=cluster` for all) |
| `egressFirewall.enabled` | `false` | OVN-Kubernetes EgressFirewall: API server and allowlisted domains only, then deny (namespace-wide) |
| `persistence.enabled` | `false` | Keep progress, notes and indexed runbooks on a PVC |
| `route.enabled` | `false` | OpenShift Route with edge TLS |
| `resources` | 256Mi request, 512Mi limit | About 85 MiB peak with built-in knowledge, plus about 25 MiB per MB of indexed text |

All values and their schema: `values.yaml` and `values.schema.json`. Guides for service, sidecar and OpenShift
Lightspeed setups: <https://github.com/aashishmahajan/kube-noob/blob/main/docs/openshift.md>.

## Test

```bash
helm test kube-noob -n kube-noob
```
