# Changelog

## 0.2.2 - 2026-10-27

The Claude plugin passes the plugin directory's checks; releases finish even when the chart push fails; three
animated videos rendered without a video model.

- Claude plugin: `.mcp.json` sets no package-manager variable; the server runs with `uv run --frozen --isolated`
  (a throwaway environment in uv's cache, nothing written to the plugin folder). The plugin ships only the modules
  the stdio server imports: no CLI, model agent, HTTP service or cluster backend, and no code that names or reads a
  credential. Every file is UTF-8 text under 256 KiB (the Kubernetes schema ships as plain JSON parts instead of
  gzip), and `plugin.json` keeps only fields the plugin reference defines. Tests and the sync check enforce all of it.
- Learning notes reject any command pipeline (`|`); describe a fix in words.
- `llm.apiKeyEnv` and `server.authTokenEnv` default to unset; the model client and the HTTP service fall back to
  `ANTHROPIC_API_KEY` and `KUBE_NOOB_HTTP_TOKEN` as before, and `apiKeyEnv` is still validated when the configuration
  loads.
- Release: the chart push to GHCR and its cosign signature run in their own job (cosign now logs in to GHCR itself),
  so a registry problem no longer blocks the GitHub release; each step reports its error as an annotation.
- Homebrew formula updated to 0.2.1 (43 hash-checked wheels, no LLM SDK).
- `demos/video/stage`: the teaser, sidecar and MCP videos in the look of the Grok teaser, with a Piper voice-over
  (LibriTTS voice, CC BY 4.0), generated music and terminal lines copied from real runs.

## 0.2.1 - 2026-10-27

No AI inside, said and enforced; safer to run for a whole team; easier to install.

- No AI inside, said plainly: README, plugin, docs and video copy explain that Claude, OpenShift Lightspeed or any MCP
  client does the talking and kube-noob supplies deterministic tools; only the optional `kube-noob ask` calls a model.
  A test keeps copy from calling kube-noob an AI, assistant or agent.
- The Claude plugin runs the readable server source bundled in `plugin/kube-noob/server` with every dependency pinned
  by hash in `uv.lock` (`uv run --frozen`), installs no LLM SDK, keeps its environment in the plugin data folder, and
  reports no model in its posture. CI checks the copy, the lock, a vulnerability audit and an end-to-end start.
- PRIVACY.md lists what kube-noob reads, stores and sends, per destination; the plugin manifest links it.
- No model is configured by default (`llm.provider: none`); the Anthropic SDK moved to the optional
  `kube-noob[ask]` extra, so the core install, the image, the plugin and Homebrew carry no LLM SDK.
- `kube-noob diagnose` takes the error text itself: quoted, as `-f "<text>"`, from a file or from stdin.
- Security, from a second red-team review: tool failures never log the caller's content; the HTTP token is checked
  before any body is read; caller-supplied grading patterns are literal text (no regex denial of service); HTTP
  servers do not offer learning-file writes; notes reject download-and-run commands and log lines; the plugin runs
  Python isolated (`-I -B`); `kube-noob --config X <command>` is honoured (it was ignored, failing open).
- Chart: generated bearer token when none is given (lints clean for the OpenShift Helm catalog), RBAC limited to
  the release namespace plus `rbac.namespaces` by default, web egress only to public addresses or a set proxy,
  optional OVN-Kubernetes EgressFirewall, and an OCI chart signed with cosign on every release.
- OpenShift 4.20, 4.21, 4.22 and the newest Kubernetes in CI (kind with Pod Security restricted), including the
  sidecar example; sizing measured (`scripts/measure_footprint.py`) and documented with retention and egress.
- Homebrew formula (Apple silicon and Linux) built offline from hash-checked wheels.
- Diagnose and search: client-side x509, RBAC subject, nginx permission errors, kubectl for `--platform
  kubernetes`, scheduling and TLS knowledge; the protocol reads "OpenShift 4.21" from the request.

## 0.2.0 - 2026-10-27

Enterprise self-help release: safe by construction, provable in your environment, and grounded in your own runbooks.

- Admin offline lock (`offline: true`, `KUBE_NOOB_OFFLINE=1`, Helm `config.offline`): overrides `webEnabled`, blocks
  corpus downloads, allows only loopback or `*.svc` model endpoints (no redirects, no proxy environment), and no
  later config source can lift it. `kube-noob doctor` reports the posture and exits 1 on contradictions.
- Web access is HTTPS GET only to allowlisted domains and text content types only, with bounded decompression.
- Diagnose before change: read-only steps first, then container exec and cluster changes, each marked as needing
  approval; commands are paste-safe in zsh; `kube-noob bundle` writes a redacted read-only evidence pack.
- Upgrade-safe learning file (`learning.json`): stated profile, user-confirmed notes cited as `[kn:local-N#0]`,
  id-only counters; credentials, manifests and logs are rejected; cross-process file locking.
- `kube-noob corpus add-docs`: index your own runbooks offline with credentials masked.
- `kube-noob selftest`: 61 real questions across Kubernetes, Helm, OpenShift 4.22, ROSA HCP, RHACS and everyday
  errors; new knowledge (EgressIP, ROSA HCP egress zero, Ingress, DNS, DeploymentConfig migration, everyday
  errors) and four new playbooks.
- `kube-noob demo` (7 offline scenarios), VHS recordings attached to each release, MCP prompt `getting_started`,
  docs for use cases, learning, OpenShift and Lightspeed integration, and a guidance traceability table enforced
  by tests.
- Reward: a citation earns credit only when the cited chunk supports the citing sentence.
- Fixed after an independent security review: 10 findings, 33 regression tests.

## 0.1.1 - 2026-10-27

- First PyPI release. 0.1.0 was tagged but never reached PyPI: the pinned pypa/gh-action-pypi-publish v1.13.0 bundles twine 6.1.0, which rejects Metadata-Version 2.5 from current hatchling. Publish action bumped to v1.14.3 (twine 7.0.0) and scorecard-action to v2.5.0; CI and release now check dists with the exact twine the pinned publish action uses (scripts/check_publishable.sh).

## 0.1.0 - 2026-10-27

First release.
- MCP server (stdio + authenticated streamable HTTP), CLI, Claude plugin with 7 skills, Helm chart and sidecar example.
- 7-step protocol (Clarify, Validate, Research, Audit, Calibrate, Generate, Red Team).
- 60 deterministic audit rules plus strict schema validation (Kubernetes 1.35, Route, SCC, EgressFirewall, Gateway
  API, StackRox CRDs), 9 red-team scenarios, safe auto-fix, RHACS policy mapping.
- Generator for kubernetes / openshift / rosa-classic / rosa-hcp manifests and Helm charts.
- 33 debugging playbooks and read-only live cluster evidence (kubectl/oc or in-cluster ServiceAccount).
- 28 fact-checked knowledge docs (OCP 4.22 = Kubernetes 1.35, Helm 4, RHACS 4.11 -> 5.0, ROSA HCP architecture).
- Learning tracks with graded exercises, quizzes and credits.
- Corpus builder (Git docs with license provenance, release history, jittered Jira pulls), deterministic reward with
  TRL adapter, held-out benchmark, SFT/GRPO export.
- Hardened before release after an independent red-team review: assertion-gated, negation-aware reward with citation
  relevance; config never read implicitly from the working directory; LLM key/endpoint restrictions; redaction of
  credentials in every cluster string; duplicate-key and nesting-depth checks; fixer output that the API server
  accepts (privileged containers, root containers, null securityContexts, duplicate EgressFirewalls).
