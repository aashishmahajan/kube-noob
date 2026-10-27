<p align="center">
  <img src="https://raw.githubusercontent.com/aashishmahajan/kube-noob/main/docs/brand/social-preview.png" alt="kube-noob - Learn. Audit. Debug. Offline." width="720">
</p>

# kube-noob

<!-- mcp-name: io.github.aashishmahajan/kube-noob -->

[![ci](https://github.com/aashishmahajan/kube-noob/actions/workflows/ci.yml/badge.svg)](https://github.com/aashishmahajan/kube-noob/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/aashishmahajan/kube-noob/badge)](https://securityscorecards.dev/viewer/?uri=github.com/aashishmahajan/kube-noob)
[![PyPI](https://img.shields.io/pypi/v/kube-noob)](https://pypi.org/project/kube-noob/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/aashishmahajan/kube-noob/blob/main/LICENSE)

**No AI inside. Works with yours.** kube-noob is a Kubernetes, OpenShift, ROSA HCP, Helm and RHACS/StackRox expert
in a box: audit rules, read-only-first playbooks, cited docs and graded exercises. Claude, OpenShift Lightspeed or any
MCP client calls it as tools; the CLI runs it with no AI at all. It makes no network calls unless you turn them on.

- **Audit**: 60 rules plus strict schemas (Kubernetes 1.35, Routes, SCCs, EgressFirewall, Gateway API, StackRox),
  removed-API checks, safe auto-fixes, 9 red-team scenarios, RHACS policy mapping.
- **Generate**: hardened manifests and Helm charts for Kubernetes, OpenShift and ROSA, re-audited before they are
  returned.
- **Debug**: 33 offline playbooks, read-only steps first; opt-in, read-only cluster evidence (Secrets are never read).
- **Learn**: 5 tracks, 16 lessons, graded exercises; remembers confirmed team fixes locally.
- **Cite**: answers reference local knowledge as `[kn:<doc>#<n>]` with source and license.

Every design request runs a 7-step protocol: Clarify, Validate, Research, Audit, Calibrate, Generate, Red Team.

## Who does the thinking

| You use | Who answers | What leaves your machine |
|---|---|---|
| The Claude plugin (Claude Code, Cowork) | Claude, calling kube-noob's tools | What you share with Claude, as in any chat; kube-noob sends nothing |
| OpenShift Lightspeed or another MCP client | That client's model | Whatever that client sends its model; kube-noob sends nothing |
| The CLI | kube-noob's rules, no model | Nothing |
| `kube-noob ask` (optional) | A model you configure: Anthropic or a local one | Your question, to that model only |

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

## Use with Claude or any MCP client

Claude plugin (skills plus the bundled server; runs in Claude Code and Cowork):

```
/plugin marketplace add aashishmahajan/kube-noob
/plugin install kube-noob@kube-noob
```

Any MCP client:

```json
{"mcpServers": {"kube-noob": {"command": "uvx", "args": ["--from", "kube-noob==0.2.0", "kube-noob", "mcp"]}}}
```

Cluster and web tools appear only when enabled.

## Run on OpenShift

As a token-protected service, a loopback-only sidecar, or a tool for OpenShift Lightspeed:
[docs/openshift.md](https://github.com/aashishmahajan/kube-noob/blob/main/docs/openshift.md). The chart ships
NetworkPolicies and runs under `restricted-v2`.

## Safe by default

| Setting | Default | Change with |
|---|---|---|
| Web lookups (HTTPS GET, allowlisted docs, text only) | off | `webEnabled: true` / `KUBE_NOOB_WEB_ENABLED=true` |
| Admin offline lock (overrides web, local models only) | off | `offline: true` / `KUBE_NOOB_OFFLINE=1` / chart `config.offline` |
| Live cluster (read-only, no Secrets) | off | `cluster.enabled: true` / `--cluster-enabled` |
| Local learning file (profile, confirmed notes) | on | `learningEnabled: false` |
| Model for `kube-noob ask` only | Anthropic `claude-fable-5-1` | `llm.provider: openai-compatible` + `llm.baseUrl` |

`kube-noob doctor` prints what the process can reach and exits 1 when the configuration contradicts the lock.

Config is never read from the current directory implicitly. All keys: [kube-noob.example.yaml](https://github.com/aashishmahajan/kube-noob/blob/main/kube-noob.example.yaml).

## Docs

- [Use cases by role](https://github.com/aashishmahajan/kube-noob/blob/main/docs/use-cases.md) and [learning with kube-noob](https://github.com/aashishmahajan/kube-noob/blob/main/docs/learning.md)
- [Enterprise roadmap](https://github.com/aashishmahajan/kube-noob/blob/main/docs/roadmap.md)
- [Architecture and trust boundaries](https://github.com/aashishmahajan/kube-noob/blob/main/docs/architecture.md)
- [Corpus, training and the reward](https://github.com/aashishmahajan/kube-noob/blob/main/docs/training.md)
- [Operations: weekly risk review and releases](https://github.com/aashishmahajan/kube-noob/blob/main/docs/operations.md)
- [Guidance traceability (every rule and its test)](https://github.com/aashishmahajan/kube-noob/blob/main/docs/guidance.md) and [release readiness](https://github.com/aashishmahajan/kube-noob/blob/main/docs/release-readiness.md)
- [Privacy](https://github.com/aashishmahajan/kube-noob/blob/main/PRIVACY.md), [security policy](https://github.com/aashishmahajan/kube-noob/blob/main/SECURITY.md) and [contributing](https://github.com/aashishmahajan/kube-noob/blob/main/CONTRIBUTING.md)

## Credits

Built on public, credited sources: see [THIRD_PARTY_NOTICES.md](https://github.com/aashishmahajan/kube-noob/blob/main/THIRD_PARTY_NOTICES.md). Kubernetes, OpenShift, Helm,
ROSA, RHACS and StackRox are trademarks of their owners; kube-noob is independent and not endorsed by them.
Licensed under [Apache-2.0](https://github.com/aashishmahajan/kube-noob/blob/main/LICENSE).
