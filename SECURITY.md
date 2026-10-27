# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **"Report a vulnerability"** button on the repository's
Security tab (private vulnerability reporting). Do not open a public issue. Expect an acknowledgement within 3 business
days and a fix or mitigation plan within 30 days for confirmed issues.

## Supported versions

The latest minor release receives security fixes.

## Security design

| Area | Control |
|---|---|
| Network | `webEnabled: false` by default; all outbound HTTP goes through one guarded client; web requests (and every redirect) must be HTTPS to an allowlisted domain. |
| Cluster access | Opt-in (`cluster.enabled`), read-only verbs on an allowlist of resources, Secrets never readable, ConfigMap values / sensitive env values / token-like log content redacted, strict argument validation, no shell. |
| HTTP server | Refuses to bind non-loopback without a bearer token (constant-time compare) unless explicitly overridden; DNS-rebinding protection with a Host allowlist; health endpoints are the only unauthenticated paths. |
| Input parsing | YAML SafeLoader only, 5 MB / 1000-document caps, alias-expansion budget against billion-laughs. |
| Container | UBI 9, non-root numeric UID, works with OpenShift arbitrary UIDs, read-only root filesystem in the chart, all capabilities dropped, RuntimeDefault seccomp. |
| Supply chain | Hash-pinned dependencies (`requirements.lock`), SHA-pinned Actions, CodeQL, OpenSSF Scorecard, Dependabot, `pip-audit` in CI, PyPI Trusted Publishing, SLSA provenance attestations, SBOM, keyless cosign signatures. |
| Data | Corpus records carry license and redistributability; Jira identities and emails are scrubbed; non-redistributable content is never published unencrypted by CI. |

## Verifying releases

```bash
gh attestation verify dist/kube_noob-*.whl --repo aashishmahajan/kube-noob
cosign verify ghcr.io/aashishmahajan/kube-noob:<version> \
  --certificate-identity-regexp 'https://github.com/aashishmahajan/kube-noob/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
