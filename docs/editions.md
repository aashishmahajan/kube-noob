# Editions: what is free and what an enterprise edition could hold

kube-noob is Apache-2.0 and stays that way. This page only records where a line could be drawn if a paid edition
ever exists; there are no license checks, feature flags or license changes in the code.

## Free: everything one team needs

Audit, validation and red-team checks; diagnose, debug and the evidence bundle; known issues from the release notes and
the local Red Hat Jira copy; policy debugging and network reachability; the incident watch; team memory in one Git
repository; must-gather analysis; the pcap analyser and `net verify`; the CLI, MCP server, Claude plugin, chart and
sidecar; learning tracks and `selftest`.

## Enterprise candidates: governance at scale

| Capability | Why it is an enterprise need |
|---|---|
| Single sign-on for the HTTP service; answers read as the caller | Multi-tenant clusters where one ServiceAccount must not see every namespace |
| Caller identity in every audit record; OSCAL assessment results; the FedRAMP 20x KSI mapping | Auditors need who asked what, in their formats |
| Memory across many clusters and teams, with retention policies | Fleet operators, not one team |
| Online ITSM connectors (ServiceNow, Jira Service Management) | Ticket history and evidence attachments without exports |
| Gate approvals, roles and the tamper-evident audit log | Change control for agents that act on clusters |
| A signed air-gap corpus pack; FIPS-validated images | Disconnected and regulated environments |
| Support with response times | Production use |

Until the owner decides otherwise, every one of these is built in the open code like everything else.
