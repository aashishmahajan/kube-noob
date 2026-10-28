# Privacy

kube-noob is open-source software that you run yourself: on your computer, in your CI, or in your cluster. The
maintainers run no service and receive nothing from it. There are no accounts, no telemetry and no analytics.

There is no AI inside kube-noob. When you use it from Claude, OpenShift Lightspeed or another MCP client, that client
and its model do the talking and call kube-noob's tools. What you share in that conversation is handled by that
product under its own terms and privacy policy. kube-noob adds no network traffic of its own.

## What it reads

- Text you give it: manifests, events, logs, error messages and questions. It processes them in memory to answer.
- Its bundled knowledge, and documents you index yourself with `kube-noob corpus add-docs`.
- Only if you turn on cluster access: read-only requests to the Kubernetes or OpenShift API of your current
  kubeconfig context. It never reads Secrets and redacts values that look like credentials.

## What it stores, on your machine only

Everything lives in the data directory: `~/.local/share/kube-noob` by default, or `KUBE_NOOB_DATA_DIR`.

| File | Contents | How to remove it |
|---|---|---|
| `progress/<learner>.json` | Lessons read, exercise and quiz results, points. The learner id is a label you choose (default `local`); use a nickname, not an email address | Delete the file |
| `learning.json` | Your profile (platform, versions, team conventions) and fixes you confirmed (symptom, cause, fix). Notes that contain credentials, logs or manifests are rejected. Counters record rule and playbook ids only, never your text | `kube-noob learning forget <id>`, delete the file, or set `learningEnabled: false` |
| `corpus/` | Documents you indexed with `corpus add-docs` (credentials masked), and public corpus data you built or imported | Delete the directory |
| `corpus/jira-*.jsonl`, `jira/` | Only after `kube-noob corpus jira`, `jira.sync.enabled` or importing a snapshot: the public Red Hat Jira tickets of the chosen projects (title, status, versions, the full description and every comment; comment authors appear only as per-ticket pseudonyms such as Commenter A, their names in the text and their @mentions are replaced by the same pseudonym, other mentions become @user, and emails, phone numbers, account ids and profile links are removed; reporter, assignee and author identities are never stored), the sync state, a search index and `jira/changes.jsonl` (each ticket's status, resolution and fix-version changes seen by a sync: key, project, type, when, before and after; no text). Public data, not redistributable: kube-noob never publishes it | Delete the files |
| `corpus/DB_SEED.json`, `known_issues/` | Only after importing the public `kube-noob-db` bundle (`corpus import`, chart `db.enabled`): when the bundle was built and the release-note known issues it carried. The bundle itself holds public documentation and release facts only, never Jira data or anything about you; kube-noob downloads nothing for it: your cluster pulls the image you pinned | Delete the files |
| A Jira snapshot (`kube-noob corpus jira-snapshot -o <file>`, `<dataDir>/seed/*.tgz`) | Only when you make one: the files above in one owner-only archive, for your other installs to import. It holds Red Hat ticket text: keep it inside your organisation (a private image, bucket or volume). The `corpus-refresh` workflow uploads it only encrypted with your `CORPUS_PASSPHRASE` | Delete the file |
| Your team memory repository (`memory.paths`, chart `memory.source`) | Entries your team wrote and reviewed (`entries/MEM-<n>.yaml`). kube-noob reads it where it runs and writes only on `kube-noob memory init`, `add`, `outcome`, `import` and `migrate-learning`; it never uploads, bundles, publishes or exports it. `memory import` reads a ticket export on your machine and keeps no people: assignee, caller and reporter fields are not read, and emails, account ids, @mentions, phone numbers and named people are removed from the text | It is your repository: remove entries in Git |
| `incidents.json` | Only when the incident watch runs (`kube-noob watch`, `watch.enabled`): per incident the namespace, workload, signal, redacted event and status lines, the diagnosis ids and steps, rollout changes (image names, environment variable names, resource values), when it opened and resolved, and fixes a person confirmed. Never log lines, object specs or Secret values. Resolved incidents are dropped after `watch.retentionDays` (30) unless a fix was confirmed | Delete the file |

Nothing from a request is kept after it is answered. What is listed above stays until you delete it; the maintainers
never receive it.

`kube-noob bundle` writes a redacted evidence pack to the folder you name (default `./kube-noob-bundle`). The MCP
server's log line records each tool name, argument sizes and duration, never argument contents.

## What it sends, and where

By default, nothing. Each destination below is off until you turn it on.

| Destination | Turned on by | What is sent |
|---|---|---|
| Your cluster's API server | `cluster.enabled: true` or `--cluster-enabled` | Read-only get, list and logs requests |
| Allowlisted documentation sites (listed below) | `webEnabled: true`; refused under the offline lock | HTTPS GET of the page address; nothing is downloaded to disk or run |
| The model you configure | Only `kube-noob ask`, `kube-noob train bench` and the eval judge | Your question and the tool results; under the offline lock, local models only |
| Your git host (the chart's `memory.git.url`) | `memory.source: git` in the chart; under `config.offline` only an in-cluster `*.svc` host | A shallow `git clone` of your memory repository by the pod's init container at start, through egress opened to `memory.git.egressCIDRs` only; kube-noob itself sends nothing |
| Public GitHub repositories and the public Red Hat Jira | Only `kube-noob corpus build`, `jira`, `jira-projects`, `history` and `known-issues`, and `jira.sync.enabled` in the service; refused under the offline lock | Requests for public data: Jira search queries (project key, an "updated in the last N minutes" or "key below N" filter) through its REST API, at most one per second |

The default web allowlist is kubernetes.io, helm.sh, docs.redhat.com, docs.openshift.com, access.redhat.com,
cloud.redhat.com, developers.redhat.com, redhat.atlassian.net, docs.aws.amazon.com, github.com,
raw.githubusercontent.com, stackrox.io, www.stackrox.io, gateway-api.sigs.k8s.io and kind.sigs.k8s.io, with their
subdomains. You can shorten or replace it with `web.allowedDomains`.

`kube-noob doctor` prints what the running process can reach. Administrators can set `offline: true` (or
`KUBE_NOOB_OFFLINE=1`) to block web access and downloads and to allow only local models; nothing later in the
configuration can lift it.

## The Claude plugin

The plugin starts the bundled server on your computer over stdio, with web access, cluster access and model calls
off. Its Python dependencies are installed from PyPI at the versions and hashes in the plugin's `uv.lock`, into a
throwaway environment in uv's cache (and uv's managed CPython once, if no Python 3.11 or later is installed). The
plugin ships only the modules of the stdio server: no CLI, model agent, HTTP service or cluster access, and it reads
no credentials. Personal data is never requested. If text you paste contains some, it is processed in memory
and not stored, except words you choose to put in a confirmed note or a learner id.

## Children

kube-noob is not directed at children under 18.

## Contact

Security reports: [SECURITY.md](SECURITY.md). Anything else:
[GitHub issues](https://github.com/aashishmahajan/kube-noob/issues).
