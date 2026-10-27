# YouTube walkthrough: script, voice-over and metadata

There are two cuts:

- The **rendered cut** (2:02, 1920x1080, silent) is recorded from real `kube-noob` 0.2.0 output by
  `demos/video/render.sh <out-dir>`. Lay the voice-over below on top of it.
- The **long cut** (about 5 minutes) is a scene list for a video tool such as Astra. It uses the same commands, so
  every on-screen number is real.

## Metadata

**Title options** (the first is strongest for click-through):

1. Your AI Ran `delete` First. Mine Runs `describe`.
2. An Offline AI for Kubernetes, OpenShift and ROSA HCP That Never Touches Your Cluster First
3. Stop Pasting Kubernetes Logs Into Chatbots: An Offline, Cited, Read-Only Assistant

**Thumbnail:** `youtube-thumbnail.png` from the render (`demos/video/thumbnail.html`): "Your AI ran delete first. Mine runs describe." with a
struck-through `oc delete` above `oc get events`, `oc describe` and `oc logs --previous`.

**Description:**

```text
kube-noob is a free, open-source Kubernetes, OpenShift and ROSA HCP assistant that runs offline, reads before it touches anything, and cites its sources. Use it as a CLI, as an MCP server for Claude or OpenShift Lightspeed, or as a sidecar on OpenShift.

pipx install kube-noob
kube-noob demo --list

GitHub: https://github.com/aashishmahajan/kube-noob
PyPI: https://pypi.org/project/kube-noob/

Chapters
0:00 What kube-noob is
0:05 Audit for the platform you run
0:24 Diagnose before you change anything
0:42 Blueprint to audited ROSA HCP manifests
0:53 Learn Kubernetes objects, graded offline
1:09 Remember what your team fixed
1:27 Prove it never leaves your network
1:44 Check it yourself: 61 real questions
1:54 Try it

Kubernetes, OpenShift, Helm, ROSA, RHACS and StackRox are trademarks of their owners; kube-noob is independent and not endorsed by them.
```

**Tags:** kubernetes, openshift, rosa, rosa hcp, helm, rhacs, stackrox, sre, platform engineering, devops, mcp,
claude, openshift lightspeed, kubernetes troubleshooting, crashloopbackoff, scc

## Voice-over for the rendered cut (about 300 words)

Timestamps are approximate (within 2 seconds).

| Time | Voice-over |
|---|---|
| 0:00 | When a pod breaks at 2 a.m., the fastest command is `delete`. It's also the one that destroys your evidence. kube-noob does it the other way round. |
| 0:05 | Here is a Deployment that works on a laptop. On OpenShift 4.22, kube-noob scores it 37 out of 100. The password is hard-coded, the UID is pinned, and privilege escalation is on. Every finding carries the fix and the RHACS policy it would trip. One command applies the safe fixes, and it tells you what it left for a human. |
| 0:24 | Now paste the events. Pods are rejected by a security context constraint. kube-noob gives the cause, then read-only steps first: get, describe, logs. Anything that runs in a container or changes the cluster comes last and asks for approval. The crash-looping pod? It's out of memory, exit code 137. |
| 0:42 | Describe an app for ROSA HCP, and the 7-step protocol generates the Deployment, Route, PodDisruptionBudget, autoscaler and NetworkPolicies, then audits them: 100 out of 100. |
| 0:53 | Learning Kubernetes? Lessons and exercises are graded offline by the same rules. |
| 1:09 | When your team confirms a fix, save it. Next time, search finds your team's note next to the docs, with a citation. Secrets, logs and manifests are rejected. |
| 1:27 | It makes no network calls and reads no cluster unless you allow it. Platform teams can lock it offline, and `doctor` shows exactly what it can reach. |
| 1:44 | Don't trust me. Run the self-test: 61 real questions across Kubernetes, Helm, OpenShift 4.22, ROSA HCP and RHACS. |
| 1:54 | pipx install kube-noob, then kube-noob demo. Link below. |

## Long cut for Astra (about 5 minutes)

Each scene is one shot. "Screen" means a terminal recording of the command shown; generate it with
`kube-noob demo <scenario>` or the rendered cut.

| # | Length | Screen | On-screen text | Voice-over |
|---|---|---|---|---|
| 1 | 0:15 | Thumbnail art, then a terminal typing `oc delete pod api-1` struck through | Your AI ran delete first. | Most assistants jump to the fix. On a shared cluster, the fix is how evidence disappears. |
| 2 | 0:20 | Title card | kube-noob: offline, read-only first, cited | kube-noob is a free, open-source assistant for Kubernetes, OpenShift, ROSA HCP, Helm and RHACS. It runs offline and reads before it touches anything. |
| 3 | 0:40 | `kube-noob audit -f examples/insecure-deployment.yaml --platform openshift --version 4.22` | Score 37/100: 3 HIGH | It audits YAML for the platform you actually run: 60 rules plus strict schemas, each mapped to the RHACS policy that would fire. |
| 4 | 0:30 | `kube-noob fix ...` | 4 safe fixes, 4 left for a human | It fixes what is safe to fix mechanically and tells you what needs a human. |
| 5 | 0:45 | `kube-noob diagnose -f examples/events-scc.txt` | 1. read-only first | Paste events or logs. Read-only steps come first, and anything that changes the cluster asks first. |
| 6 | 0:30 | `kube-noob diagnose -f examples/events-crashloop.txt` | OOMKilled, exit 137 | The specific cause beats the generic symptom: out of memory, not just CrashLoopBackOff. |
| 7 | 0:35 | `kube-noob protocol "Deploy orders-api on ROSA HCP" --blueprint examples/blueprint.yaml` | 7 steps, 100/100 | Clarify, validate, research, audit, calibrate, generate, red team, for every design request. |
| 8 | 0:30 | `kube-noob learn submit ...` | Graded offline | A flight simulator for Kubernetes objects: write YAML, get graded by production rules. |
| 9 | 0:30 | `kube-noob learning note ...` then `kube-noob search ...` | [kn:local-1#0] | Your team's confirmed fixes become cited answers. Secrets and logs are rejected. |
| 10 | 0:30 | `kube-noob doctor` with and without `KUBE_NOOB_OFFLINE=1` | offline lock ON | Off by default, lockable by admins, provable with doctor. |
| 11 | 0:20 | Lightspeed and Claude screenshots (your own) | Claude · Lightspeed · CLI · sidecar | Use it from Claude, from OpenShift Lightspeed, from the CLI, or as a sidecar. |
| 12 | 0:15 | `kube-noob selftest` | 61/61 | Prove it on your machine: 61 real questions. |
| 13 | 0:10 | End card | pipx install kube-noob | Link below. Tell me what it should catch next. |
