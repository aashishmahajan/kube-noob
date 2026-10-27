<p align="center">
  <img src="https://raw.githubusercontent.com/aashishmahajan/kube-noob/main/docs/brand/social-preview.png" alt="kube-noob - Learn. Audit. Debug. Offline." width="720">
</p>

# kube-noob

<!-- mcp-name: io.github.aashishmahajan/kube-noob -->

[![ci](https://github.com/aashishmahajan/kube-noob/actions/workflows/ci.yml/badge.svg)](https://github.com/aashishmahajan/kube-noob/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/aashishmahajan/kube-noob/badge)](https://securityscorecards.dev/viewer/?uri=github.com/aashishmahajan/kube-noob)
[![PyPI](https://img.shields.io/pypi/v/kube-noob)](https://pypi.org/project/kube-noob/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/aashishmahajan/kube-noob/blob/main/LICENSE)

Learn, audit and debug Kubernetes, OpenShift, ROSA HCP, Helm and RHACS/StackRox, offline by default.
Use it as an MCP server, a Claude plugin, a CLI, or a sidecar/service on OpenShift.

- **Audit**: 60 rules plus strict schemas (Kubernetes 1.35, Routes, SCCs, EgressFirewall, Gateway API, StackRox),
  removed-API checks, safe auto-fixes, 9 red-team scenarios, RHACS policy mapping.
- **Generate**: hardened manifests and Helm charts for `kubernetes`, `openshift`, `rosa-classic`, `rosa-hcp`, re-audited
  before they are returned.
- **Debug**: 33 offline playbooks, read-only steps first; opt-in, read-only cluster evidence (Secrets are never read,
  values are redacted).
- **Learn**: 5 tracks, 16 lessons, graded exercises and quizzes; remembers confirmed team fixes locally.
- **Cite**: answers reference local knowledge as `[kn:<doc>#<n>]` with source and license.

Every design request runs a 7-step protocol: Clarify, Validate, Research, Audit, Calibrate, Generate, Red Team.

## Quick start

```bash
pipx install kube-noob
kube-noob demo --list
kube-noob audit -f k8s/ --platform openshift --version 4.22
kube-noob diagnose -f events.txt
kube-noob doctor
kube-noob selftest
```

Pick your role in [use cases](https://github.com/aashishmahajan/kube-noob/blob/main/docs/use-cases.md); every demo runs offline.

Generate a hardened app for ROSA HCP from a blueprint:

```yaml
name: orders-api
namespace: shop
image: quay.io/acme/orders@sha256:<digest>
platform: rosa-hcp
storage: {size: 20Gi, accessMode: ReadWriteMany}
exposure: {type: route, host: orders.apps.example.com}
```

```bash
kube-noob protocol "deploy orders-api with shared storage" --blueprint blueprint.yaml
```

## Use with Claude or any MCP client

Claude Code plugin (skills + server):

```
/plugin marketplace add aashishmahajan/kube-noob
/plugin install kube-noob@kube-noob
```

Any MCP client:

```json
{"mcpServers": {"kube-noob": {"command": "uvx", "args": ["--from", "kube-noob==0.2.0", "kube-noob", "mcp"]}}}
```

Tools are prefixed `kubenoob_` (protocol, audit, fix, generate, diagnose, search, learn, grade). Cluster and web
tools appear only when enabled.

## Run on OpenShift

```bash
git clone https://github.com/aashishmahajan/kube-noob && cd kube-noob
oc new-project kube-noob
oc create secret generic kube-noob-token --from-literal=token="$(openssl rand -hex 32)"
helm install kube-noob deploy/helm/kube-noob --set auth.existingSecret=kube-noob-token
```

The service requires a bearer token, ships NetworkPolicies and runs under `restricted-v2`. For a loopback-only sidecar
see [deploy/sidecar](https://github.com/aashishmahajan/kube-noob/blob/main/deploy/sidecar/app-with-kube-noob-sidecar.yaml).

## Safe by default

| Setting | Default | Change with |
|---|---|---|
| Web lookups (HTTPS GET, allowlisted docs, text only) | off | `webEnabled: true` / `KUBE_NOOB_WEB_ENABLED=true` |
| Admin offline lock (overrides web, local models only) | off | `offline: true` / `KUBE_NOOB_OFFLINE=1` / chart `config.offline` |
| Live cluster (read-only, no Secrets) | off | `cluster.enabled: true` / `--cluster-enabled` |
| Local learning file (profile, confirmed notes) | on | `learningEnabled: false` |
| LLM agent (`kube-noob ask`) | Anthropic `claude-fable-5-1` | `llm.provider: openai-compatible` + `llm.baseUrl` for local models |

`kube-noob doctor` prints what the process can reach and exits 1 when the configuration contradicts the lock.

Config comes from `--config`, `$KUBE_NOOB_CONFIG`, `~/.config/kube-noob/config.yaml` or `/etc/kube-noob/config.yaml`,
never implicitly from the current directory. All keys: [kube-noob.example.yaml](https://github.com/aashishmahajan/kube-noob/blob/main/kube-noob.example.yaml).

## Docs

- [Use cases by role](https://github.com/aashishmahajan/kube-noob/blob/main/docs/use-cases.md) and [learning with kube-noob](https://github.com/aashishmahajan/kube-noob/blob/main/docs/learning.md)
- [Run it on OpenShift: service, sidecar, Lightspeed](https://github.com/aashishmahajan/kube-noob/blob/main/docs/openshift.md) and the [enterprise roadmap](https://github.com/aashishmahajan/kube-noob/blob/main/docs/roadmap.md)
- [Architecture and trust boundaries](https://github.com/aashishmahajan/kube-noob/blob/main/docs/architecture.md)
- [Corpus, training and the reward](https://github.com/aashishmahajan/kube-noob/blob/main/docs/training.md)
- [Operations: weekly risk review and releases](https://github.com/aashishmahajan/kube-noob/blob/main/docs/operations.md)
- [Guidance traceability (every rule and its test)](https://github.com/aashishmahajan/kube-noob/blob/main/docs/guidance.md) and [release readiness](https://github.com/aashishmahajan/kube-noob/blob/main/docs/release-readiness.md)
- [Security policy](https://github.com/aashishmahajan/kube-noob/blob/main/SECURITY.md) and [Contributing](https://github.com/aashishmahajan/kube-noob/blob/main/CONTRIBUTING.md)

## Credits

Built on public, credited sources (Kubernetes docs CC BY 4.0, OpenShift docs, Red Hat Cloud Experts, HyperShift,
StackRox, Helm docs and more): see [THIRD_PARTY_NOTICES.md](https://github.com/aashishmahajan/kube-noob/blob/main/THIRD_PARTY_NOTICES.md). Kubernetes, OpenShift, Helm,
ROSA, RHACS and StackRox are trademarks of their owners; kube-noob is independent and not endorsed by them.
Licensed under [Apache-2.0](https://github.com/aashishmahajan/kube-noob/blob/main/LICENSE).
