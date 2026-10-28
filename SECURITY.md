# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **"Report a vulnerability"** button on the repository's
Security tab (private vulnerability reporting). Do not open a public issue. Expect an acknowledgement within 3 business
days and a fix or mitigation plan within 30 days for confirmed issues.

## Supported versions

The latest minor release receives security fixes.

## Default posture

kube-noob makes no outbound connections and touches no cluster unless you enable it. This is tested in CI and was
verified end to end inside a network namespace with no route (docs/release-readiness.md). With web access enabled it
only performs HTTPS GETs to allowlisted documentation domains, refuses non-text content types (archives, binaries,
scripts), streams at most `web.maxBytes`, never writes the content to disk and never executes it. The admin lock
(`offline: true` / `KUBE_NOOB_OFFLINE=1`) overrides `webEnabled`, blocks corpus downloads and allows only loopback or
in-cluster model endpoints; no later configuration source can lift it. `kube-noob doctor` reports the effective
posture. The local learning file stores only user-confirmed summaries and ids, never logs, manifests or credentials. The MCP server's only subprocesses are read-only `oc`/`kubectl` calls (argv, no shell)
when cluster access is enabled; the maintainer CLI commands `corpus build --online` and `helm-audit` run `git` and
`helm template` locally.

## Security design

| Area | Control |
|---|---|
| Network | `webEnabled: false` by default; all outbound HTTP goes through one guarded client; web requests (and every redirect) must be HTTPS to an allowlisted domain. |
| Cluster access | Opt-in (`cluster.enabled`), read-only verbs on an allowlist of resources, Secrets never readable, ConfigMap values / sensitive env values / token-like log content redacted, strict argument validation, no shell. |
| HTTP server | Refuses to bind non-loopback without a bearer token (constant-time compare) unless explicitly overridden; DNS-rebinding protection with a Host allowlist; health endpoints are the only unauthenticated paths. |
| Input parsing | YAML SafeLoader only, 5 MB / 1000-document caps, alias-expansion budget against billion-laughs. |
| Container | UBI 9, non-root numeric UID, works with OpenShift arbitrary UIDs, read-only root filesystem in the chart, all capabilities dropped, RuntimeDefault seccomp. |
| Supply chain | Hash-pinned dependencies (`requirements.lock`), SHA-pinned Actions, CodeQL, OpenSSF Scorecard, Dependabot, `pip-audit` in CI, PyPI Trusted Publishing, SLSA provenance attestations, SBOM, keyless cosign signatures. |
| Data | Corpus records carry license and redistributability; Jira identities and emails are scrubbed; non-redistributable content is never published unencrypted by CI. Retention and destinations: [PRIVACY.md](PRIVACY.md). |
| Red Hat Jira sync | REST API only (no page scraping, per Atlassian's Acceptable Use Policy); one request per second or slower (robots.txt crawl delay), a request budget per run, backoff on 429 with `Retry-After`; the client can only GET from the Jira host (plus POST to its search endpoint) over HTTPS; project and issue keys are validated before they reach a query; the local ticket index is mode 0600. |
| Claude plugin | Runs the readable stdio server bundled in the plugin with `uv run --frozen --isolated`; every dependency is pinned by version and sha256 in `uv.lock`; no LLM SDK is installed and no package-manager variable is set; only the modules the stdio server imports ship, so nothing in the plugin reads a credential; web, cluster and model calls are off. |
| Sidecar | Binds 127.0.0.1 only, so only containers in the same pod can call it (the pod is the trust boundary); no Service port, no token, no egress needed. CI proves the port is closed on the pod IP. |
| Egress on OpenShift | Chart NetworkPolicy allows DNS only by default; optional OVN-Kubernetes EgressFirewall allows only the API server and allowlisted HTTPS domains, then denies all. |
| Homebrew | The formula installs the release wheel and wheels-only dependencies pinned by hash from the release's `requirements.lock`. |

## Compliance

Audit findings name the NIST SP 800-53 Rev. 5 controls they are evidence about, and `kube-noob doctor` reports FIPS
mode. How to deploy kube-noob inside a FedRAMP High boundary, and what is not covered yet:
[docs/compliance.md](docs/compliance.md).

## Verifying releases

```bash
gh attestation verify dist/kube_noob-*.whl --repo aashishmahajan/kube-noob
cosign verify ghcr.io/aashishmahajan/kube-noob:<version> \
  --certificate-identity-regexp 'https://github.com/aashishmahajan/kube-noob/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
