# Getting kube-noob into OpenShift's catalogs

The fastest credible route is the community tier of the OpenShift Helm charts repository: the chart then appears in
every cluster's console Helm catalog under the "Community" source. Researched 2026-10-27; sources at the end.

| Route | Who can submit | Effort | Where it shows | Status for kube-noob |
|---|---|---|---|---|
| OpenShift Helm charts, community | Anyone listed in the chart's OWNERS file | 1 to 2 days plus a manual review | Console Helm catalog, "Community" | Ready: chart lints with defaults, has a README, schema and test; released as `.tgz` and OCI |
| Artifact Hub | Anyone | Hours | artifacthub.io (search, not the console) | Ready once the OCI chart is published by a release |
| Community operator (Software Catalog, OLM) | Anyone, with DCO sign-off | 1 to 2 weeks (Helm-based operator, bundle, file-based catalog) | Console Software Catalog | Later: only if you want OLM-managed installs |
| Red Hat certification (Partner Connect) | Companies | Weeks | "Certified" badge | Later: needs a company account |
| OpenShift AI MCP catalog | Curated by Red Hat; no public submission path found | n/a | OpenShift AI | Watch; contact Red Hat when there is traction |
| Red Hat Marketplace | Closed on 1 April 2025 | n/a | n/a | Not an option |

OpenShift Lightspeed has no catalog: a cluster admin adds kube-noob in `OLSConfig.spec.mcpServers` ([openshift.md](openshift.md)).

## Submit the Helm chart (community)

1. Tag a release. The release workflow lints and packages the chart, pushes it to `oci://ghcr.io/aashishmahajan/charts`,
   signs it, and attaches `kube-noob-<version>.tgz` to the GitHub release.
2. Fork `openshift-helm-charts/charts` and open a first pull request that adds only
   `charts/community/kube-noob/kube-noob/OWNERS`:

   ```yaml
   chart:
     name: kube-noob
     shortDescription: Kubernetes, OpenShift and ROSA audit, debugging and learning tools as an MCP server
   publicPgpKey: null
   users:
     - githubUsername: aashishmahajan
   vendor:
     label: kube-noob
     name: kube-noob
   ```

3. After it merges, open a second pull request that adds `charts/community/kube-noob/kube-noob/<version>/` with the
   release's `kube-noob-<version>.tgz`. The pipeline runs chart-verifier with the community profile (helm-lint is the
   one mandatory check) and then waits for a manual approval.
4. Once merged, the chart is in the index the OpenShift console reads, under Helm charts, source "Community".

To check locally before submitting, run chart-verifier with the community profile on the packaged chart (command in
the action items of the release checklist, [release-readiness.md](release-readiness.md)).

## Sources

- OpenShift Helm charts submission guide: https://github.com/openshift-helm-charts/charts/blob/main/docs/README.md
- chart-verifier checks and profiles: https://github.com/redhat-certification/chart-verifier/blob/main/docs/helm-chart-checks.md
- Community charts already listed by individuals (index): https://github.com/openshift-helm-charts/charts/blob/gh-pages/index.yaml
- Helm charts in the console: https://docs.redhat.com/en/documentation/openshift_dedicated/4/html/applications/working-with-helm-charts
- Community operators pipeline: https://redhat-openshift-ecosystem.github.io/operator-pipelines/users/contributing-prerequisites/
- Red Hat Marketplace sunset: https://access.redhat.com/articles/7130828
- OpenShift AI MCP catalog: https://www.redhat.com/en/blog/mcp-catalog-here-discover-deploy-and-connect-red-hat-openshift-ai
- Artifact Hub repositories: https://artifacthub.io/docs/topics/repositories/
