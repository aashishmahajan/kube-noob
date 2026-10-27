# Roadmap: an enterprise self-help bot for Kubernetes and OpenShift

Goal: a platform team deploys kube-noob once. Every developer and SRE then gets answers that are safe, cited and
read-only first, about their own clusters and their own runbooks, so the platform team's ticket queue shrinks.

## Who it serves

| Who | Job to be done | What they use today | What kube-noob changes |
|---|---|---|---|
| App developer | When my deploy fails on the shared cluster, find out why without opening a ticket | Slack the platform team, search the wiki, paste logs into a public chatbot | `diagnose` and the Lightspeed or Claude tools give the cause and read-only steps, in the company's terms |
| SRE / on-call | Get from symptom to evidence fast, without making it worse | Personal notes, tribal knowledge | Playbooks that read before they change, a redacted evidence `bundle`, confirmed team notes |
| Platform team | Stop answering the same 20 questions; enforce conventions before deploy | Docs nobody reads, admission policies that only say "no" | Org runbooks indexed and cited, audit in CI, a weekly "top issues" signal from counters |
| Security | Allow AI assistants without data leaving the boundary | Ban them | No model inside kube-noob, offline lock, `doctor`, no egress, signed images, nothing exported |

## Delivered (0.2.0)

- Offline lock, posture report (`doctor`), and web access that is GET-only and reads text only.
- Diagnose-first playbooks, a redacted read-only bundle, and copy-paste-safe commands.
- An upgrade-safe learning file (profile, confirmed notes, counters) and team notes that search can cite.
- Your own runbooks via `kube-noob corpus add-docs`: offline, with credentials masked.
- `kube-noob selftest`: 61 real questions across Kubernetes, Helm, OpenShift 4.22, ROSA HCP, RHACS and everyday
  errors. CI requires 100%.
- Ways to run it: OpenShift service, sidecar, OpenShift Lightspeed MCP tool, Claude plugin, CLI
  ([openshift.md](openshift.md)).

## Next bets, in order

1. **Answers scoped to the caller's own permissions.** In service mode, cluster reads use one ServiceAccount, so
   every caller sees what it sees. Next: pass the caller's OpenShift identity (oauth-proxy, or Lightspeed's client
   token) through, and read the cluster as that user. This is the main blocker for multi-tenant clusters. Until
   then, the chart reads only its own namespace plus `rbac.namespaces`, or leave cluster tools off.
2. **Org policy packs.** Let teams add their own audit rules in YAML (for example "images only from
   registry.acme.com" or "label team= required"), so `audit` enforces company conventions and not only upstream
   best practice.
3. **Runbooks in the in-cluster service.** An init container that indexes a Git repo or ConfigMap of runbooks at
   startup.
4. **Top-issues report.** `kube-noob report` turns the id-only counters into "the 10 problems your developers hit
   this week", so the platform team fixes the root cause (a default, a doc, a quota).
5. **Single sign-on for the HTTP service.** An oauth-proxy option in the chart, so people never handle the bearer
   token directly.

Set aside for now: Slack or Teams bots (Lightspeed and Claude already give the chat surface), embeddings (BM25 with
term joins passes the self-test, 24 of 25 on unseen paraphrases), and a hosted SaaS (it conflicts with the
no-egress promise).

## Riskiest assumptions and the cheapest test

| Assumption | Cheapest test |
|---|---|
| Platform teams will let an OSS tool server into the cluster | Show the `doctor` output and SECURITY.md to two OpenShift admins; ask what blocks approval |
| Developers will ask it before opening a ticket | Turn on Lightspeed integration for one team; compare ticket counts for the top 5 categories over 4 weeks |
| BM25 over their runbooks is good enough | Run `selftest` plus 20 questions written by the team against their own `add-docs` corpus |
| Read-as-caller is possible without new infrastructure | Prototype it with oauth-proxy's `--pass-access-token` on a test cluster |
