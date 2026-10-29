---
id: k8s-kubectl-output
title: kubectl output, queries and scripting - jsonpath, custom-columns, sorting, logs, wait, exec
tags: [kubernetes, openshift, kubectl, jsonpath, custom-columns, jq, logs, scripting, dry-run, diff]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-29
license: Apache-2.0
# A question needs a word of this document's subject (and of Kubernetes, where generic words would pass).
requires:
  - [jsonpath, jq, columns, column, sort, sorted, sorting, dry, diff, wait, exec, cp, logs, log, grep, script, scripts, scripting, output, print, printing, format, delete, deleting, bulk, regex, regexp, tar, last-applied-configuration]
  - [pod, pods, kubectl, oc, kubernetes, k8s, openshift, ocp, rosa, kubelet, kubeadm, deployment, deployments, statefulset, statefulsets, daemonset, daemonsets, replicaset, replicasets, namespace, namespaces, crashloopbackoff, configmap, configmaps, pvc, persistentvolumeclaim, helm, node, nodes, container, containers, initcontainer, initcontainers, job, jobs, cronjob, cronjobs, service, services, secret, secrets, events, manifest, manifests, object, objects]
sources:
  - {title: "Kubernetes: JSONPath Support", url: "https://kubernetes.io/docs/reference/kubectl/jsonpath/", license: CC-BY-4.0}
  - {title: "Kubernetes: kubectl Quick Reference", url: "https://kubernetes.io/docs/reference/kubectl/quick-reference/", license: CC-BY-4.0}
  - {title: "Kubernetes: Command line tool (kubectl)", url: "https://kubernetes.io/docs/reference/kubectl/", license: CC-BY-4.0}
  - {title: "Kubernetes: kubectl Usage Conventions", url: "https://kubernetes.io/docs/reference/kubectl/conventions/", license: CC-BY-4.0}
  - {title: "Kubernetes: kubectl for Docker Users", url: "https://kubernetes.io/docs/reference/kubectl/docker-cli-to-kubectl/", license: CC-BY-4.0}
  - {title: "Kubernetes: Field Selectors", url: "https://kubernetes.io/docs/concepts/overview/working-with-objects/field-selectors/", license: CC-BY-4.0}
  - {title: "Kubernetes: kubectl get", url: "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_get/", license: CC-BY-4.0}
  - {title: "Kubernetes: kubectl logs", url: "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_logs/", license: CC-BY-4.0}
  - {title: "Kubernetes: kubectl wait", url: "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_wait/", license: CC-BY-4.0}
  - {title: "Kubernetes: kubectl delete", url: "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_delete/", license: CC-BY-4.0}
  - {title: "Kubernetes: kubectl exec", url: "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_exec/", license: CC-BY-4.0}
  - {title: "Kubernetes: kubectl cp", url: "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_cp/", license: CC-BY-4.0}
  - {title: "Kubernetes: kubectl run", url: "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_run/", license: CC-BY-4.0}
  - {title: "Kubernetes: kubectl create deployment", url: "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_create/kubectl_create_deployment/", license: CC-BY-4.0}
  - {title: "Kubernetes: kubectl create configmap", url: "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_create/kubectl_create_configmap/", license: CC-BY-4.0}
  - {title: "Kubernetes: kubectl set env", url: "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_set/kubectl_set_env/", license: CC-BY-4.0}
  - {title: "Kubernetes: kubectl expose", url: "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_expose/", license: CC-BY-4.0}
  - {title: "Kubernetes: kubectl diff", url: "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_diff/", license: CC-BY-4.0}
  - {title: "Kubernetes: kubectl apply view-last-applied", url: "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_apply/kubectl_apply_view-last-applied/", license: CC-BY-4.0}
  - {title: "Kubernetes: Logging Architecture", url: "https://kubernetes.io/docs/concepts/cluster-administration/logging/", license: CC-BY-4.0}
  - {title: "Kubernetes: Debugging Kubernetes Nodes With Kubectl", url: "https://kubernetes.io/docs/tasks/debug/debug-cluster/kubectl-node-debug/", license: CC-BY-4.0}
  - {title: "Kubernetes: Managing Kubernetes Objects Using Imperative Commands", url: "https://kubernetes.io/docs/tasks/manage-kubernetes-objects/imperative-command/", license: CC-BY-4.0}
  - {title: "Kubernetes: Declarative Management of Kubernetes Objects Using Configuration Files", url: "https://kubernetes.io/docs/tasks/manage-kubernetes-objects/declarative-config/", license: CC-BY-4.0}
  - {title: "Kubernetes: Get a Shell to a Running Container", url: "https://kubernetes.io/docs/tasks/debug/debug-application/get-shell-running-container/", license: CC-BY-4.0}
  - {title: "Kubernetes: Configure Bind Mount Options", url: "https://kubernetes.io/docs/tasks/configure-pod-container/configure-bind-mount-options/", license: CC-BY-4.0}
  - {title: "Kubernetes: Pod Lifecycle", url: "https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/", license: CC-BY-4.0}
  - {title: "Kubernetes: Deployments", url: "https://kubernetes.io/docs/concepts/workloads/controllers/deployment/", license: CC-BY-4.0}
  - {title: "Kubernetes: ReplicaSet", url: "https://kubernetes.io/docs/concepts/workloads/controllers/replicaset/", license: CC-BY-4.0}
  - {title: "Kubernetes: Jobs", url: "https://kubernetes.io/docs/concepts/workloads/controllers/job/", license: CC-BY-4.0}
  - {title: "Kubernetes: Assign Pods to Nodes using Node Affinity", url: "https://kubernetes.io/docs/tasks/configure-pod-container/assign-pods-nodes-using-node-affinity/", license: CC-BY-4.0}
  - {title: "Kubernetes: Pod Security Standards", url: "https://kubernetes.io/docs/concepts/security/pod-security-standards/", license: CC-BY-4.0}
---
# kubectl output, queries and scripting

By default kubectl prints human-readable plain text. In scripts, ask for a machine-oriented format (`-o name`, `-o json`,
`-o yaml`, `-o jsonpath`, `-o go-template`) and fully qualify the resource type (for example `jobs.v1.batch/myjob`),
so the output does not depend on defaults that can change. The commands below only read, unless a section says it
changes something.

## Print one field, or a label whose key has dots, with -o jsonpath

A JSONPath template is made of expressions in curly braces; text outside them is printed as is, and text inside an
expression is quoted with double quotes. `{range .items[*]}...{end}` loops over a list, so it prints one line per
object. A filter `[?(@.field=="value")]` picks list entries. A dot inside a key (label keys such as
`kubernetes.io/hostname`, ConfigMap keys such as `ca.crt`) must be escaped with a backslash, or it is read as a path
step.

```sh
kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.startTime}{"\n"}{end}'
kubectl get nodes -o jsonpath='{.items[*].status.addresses[?(@.type=="ExternalIP")].address}'
kubectl get pods -o jsonpath='{.items[0].metadata.labels.kubernetes\.io/hostname}'
kubectl get configmap myconfig -o jsonpath='{.data.ca\.crt}'
```

The leading `$` is optional. On Windows, put the whole template in double quotes and use single quotes for literals
inside it. kubectl's JSONPath does not support regular expressions: pipe `-o json` to `jq` for that.

## Sort kubectl get output by a field or a label (--sort-by)

`--sort-by` takes a JSONPath expression, and the field it names must be a string or an integer. A label key with
dots needs the same backslash escape as in `-o jsonpath`. `-L <label>` shows that label as an extra column, so you
can see the sort key.

```sh
kubectl get pods --sort-by='.status.containerStatuses[0].restartCount'
kubectl get events --sort-by=.metadata.creationTimestamp
kubectl get pv --sort-by=.spec.capacity.storage
kubectl get nodes -L kubernetes.io/hostname --sort-by='.metadata.labels.kubernetes\.io/hostname'
kubectl top pod --sort-by=cpu
```

The expression can be written with or without braces (`.metadata.name` or `'{.metadata.name}'`). `[0]` is the
first list entry, so the first command sorts by the restarts of each pod's first container. `kubectl top`
has its own `--sort-by` that accepts `cpu` or `memory`.

## Show chosen fields as a table with custom-columns (images, commands, init containers)

`-o custom-columns=HEADER:<field>,HEADER:<field>` prints one row per object. A field may use `[*]` for every list
entry and a filter such as `[?(@.type=="Ready")]`. A Deployment's `.spec.template` has the Pod schema, so pod fields
such as `affinity` sit under `.spec.template.spec`.

```sh
kubectl get pods -o custom-columns='NAME:.metadata.name,IMAGE:.spec.containers[*].image'
kubectl get pods -o custom-columns='NAME:.metadata.name,CMD:.spec.containers[*].command,ARGS:.spec.containers[*].args'
kubectl get pods -o custom-columns='NAME:.metadata.name,INIT:.spec.initContainers[*].name'
kubectl get deployments -A -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,AFFINITY:.spec.template.spec.affinity'
kubectl get nodes -o custom-columns='NODE:.metadata.name,READY:.status.conditions[?(@.type=="Ready")].status'
```

The leading dot is optional (`DATA:spec.containers[*].image`), and `metadata.*` prints every field under
`metadata`. `--no-headers` drops the header row for scripts. `-o custom-columns-file=<file>` reads the columns
from a file whose first line holds the headers and second line the fields. When the extra default columns are
enough (for pods, the node name), `-o wide` is shorter.

## Filter pods by phase or node with --field-selector

Field selectors filter on the server by a field's value. They support `=`, `==` and `!=` only (no `in`, `notin`
or exists), and a comma joins conditions with AND. Every kind supports `metadata.name` and `metadata.namespace`.
Pods add `spec.nodeName`, `spec.restartPolicy`, `spec.schedulerName`, `spec.serviceAccountName`,
`spec.hostNetwork`, `status.phase`, `status.podIP`, `status.podIPs` and `status.nominatedNodeName`. Any other
field fails with `"<field>" is not a known field selector`.

```sh
kubectl get pods -A --field-selector=status.phase!=Running,spec.restartPolicy=Always
kubectl get pods -A --field-selector=spec.nodeName=<node>
kubectl get events -n <ns> --field-selector=involvedObject.name=<pod>
```

`status.phase` is `Pending`, `Running`, `Succeeded`, `Failed` or `Unknown`. `CrashLoopBackOff` and `Terminating`
appear only in kubectl's STATUS column; they are not phases, so no field selector matches them. Readiness and name
prefixes are not selectable either: filter `-o json` with `jq`, or print the field with JSONPath and use `grep`.

## Pods matching a name pattern, not-ready pods, one line per container (jq and grep)

kubectl's JSONPath has no regular expressions. For pattern matching and for transformations too complex for
JSONPath, pipe `-o json` to `jq`, a separate tool. Its `test()` takes a regular expression, so `^web-` matches
names that start with `web-`:

```sh
kubectl get pods -o json | jq -r '.items[] | select(.metadata.name | test("^web-")).metadata.name'
kubectl get pods -o json | jq -r '.items[] | "\(.metadata.name) \(.spec.containers[].name)"'
kubectl get pods -o json | jq -c 'paths|join(".")'
```

The second command prints one line per pod and container. The third lists every field path, which helps you find
the path to use in JSONPath. To list pods that are not Ready in all namespaces, print each pod's `Ready` condition
(`True`, `False` or `Unknown`) and drop the `True` lines:

```sh
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' | grep -v 'True$'
```

## kubectl logs on a Deployment shows only one pod

To read every pod of a Deployment, add `--all-pods=true`; it also prefixes each line with the pod and container
name. Or select the pods by label. With a selector, `--tail` defaults to the last 10 lines instead of the whole log,
so pass `--tail=-1` before you grep:

```sh
kubectl logs deployment/<name> --all-pods=true
kubectl logs -l app=<app> --all-containers=true --prefix --tail=-1 | grep -i error
kubectl logs -f -l app=<app> --max-log-requests=10
kubectl logs <pod> -c <container> --previous
```

When you follow (`-f`) logs by selector, kubectl opens at most 5 streams by default; raise `--max-log-requests` for
more pods. `--previous` (`-p`) shows the previous, crashed instance of a container. `--since=1h`,
`--since-time=<RFC3339>` and `--timestamps` narrow and date the output. `kubectl logs job/<name>` reads the first
container of a Job's pod.

## Where container logs live on the node, and why kubectl logs is cut short

By default the kubelet has the container runtime write container logs into directories under `/var/log/pods` on
the node. `kubectl logs` goes to the kubelet, which reads the log file. The kubelet rotates these files
(`containerLogMaxSize`, default 10Mi; `containerLogMaxFiles`, default 5) and `kubectl logs` returns only the latest
file: a pod that wrote 40 MiB with rotation at 10 MiB shows at most 10 MiB. After a restart the kubelet keeps one
terminated container with its logs (`--previous`); an evicted pod loses its containers' logs.

To read the files without SSH, start a node debug pod (this creates a pod; delete it with
`kubectl delete pod <debug-pod> --now` afterwards). The node's root filesystem is mounted at `/host`:

```sh
kubectl debug node/<node> -it --image=busybox:1.28
ls /host/var/log/pods
```

On Linux nodes with systemd, the kubelet and container runtime themselves log to journald by default
(`journalctl -u kubelet`); without systemd they write `.log` files in `/var/log`.

## Generate YAML without creating it: --dry-run=client -o yaml

`--dry-run=client` only prints the object kubectl would send. `--dry-run=server` sends it to the API server, which
processes it without saving it. Add `-o yaml` and redirect to a file:

```sh
kubectl create configmap my-config --from-file=app.properties --dry-run=client -o yaml > cm.yaml
kubectl run nginx --image=nginx --dry-run=client -o yaml > pod.yaml
kubectl expose pod valid-pod --port=444 --name=frontend --dry-run=client -o yaml > svc.yaml
kubectl create deployment web --image=nginx --dry-run=client -o yaml | kubectl set env --local -f - LOG_LEVEL=debug -o yaml > deploy.yaml
```

`kubectl create deployment` has no `--env` flag. Pipe its output through `kubectl set env --local`, which edits the
YAML without contacting the API server. On an existing Deployment, `kubectl set env deployment/<name> KEY=value`
changes the pod template, which starts a rollout. `kubectl run` accepts `--env="KEY=value"` and
`--overrides='<json>'`; the override JSON must contain an `apiVersion` field.

## Wait in a script until pods are Ready, or until a pod is gone (kubectl wait)

`kubectl wait` blocks until a condition holds on every selected object, or until `--timeout` runs out (default 30s;
0 checks once; a negative value waits a week).

```sh
kubectl wait --for=condition=Ready pod --all -n <ns> --timeout=300s
kubectl wait --for=condition=Ready pod -l app=<app> -n <ns> --timeout=300s
kubectl wait --for=jsonpath='{.status.phase}'=Running pod/<pod>
kubectl wait --for=delete pod/<pod> --timeout=60s
kubectl wait --for=create secret/<name> --timeout=30s
```

When the condition is met it prints a success line per object; `-o name` or `-o jsonpath` changes that output.
`--for=condition=Ready=false` waits for another value; values are compared without regard to case. Several `--for`
flags must all hold, and `--for=create` is always checked first. Wait with `--for=delete` before you create a new
pod with the same name. `kubectl delete` also waits by default until the object is gone, finalizers included
(`--wait=true`).

## Delete all pods in a namespace, or only pods matching a pattern

This section changes the cluster. List what matches first, then delete:

```sh
kubectl get pods -n <ns> -o name
kubectl delete pods --all -n <ns>
kubectl delete pods -n <ns> -l app=<app>
kubectl delete pods -n <ns> --field-selector=status.phase=Failed
kubectl get pods -n <ns> --no-headers=true | awk '/pattern1|pattern2/{print $1}' | xargs kubectl delete -n <ns> pod
```

`--interactive` deletes only after you confirm; `--dry-run=server` sends the request without deleting anything.
Pods owned by a ReplicaSet (so by a Deployment) or a Job come back: those controllers replace deleted pods. To stop
them, scale or delete the owner. `--now` sets a 1-second grace period. `--force --grace-period=0` removes the pod
from the API without waiting for the node to confirm its processes stopped, so they can keep running.

## Run if/else or pipes inside kubectl exec, and copy files when kubectl cp fails

`kubectl exec` runs the command after `--` with its arguments as given. Do not wrap it in quotes unless that is how
you would run it. Shell syntax (pipes, `&&`, if/else) needs a shell, so run `sh -c` with the script as one argument:

```sh
kubectl exec <pod> -c <container> -- sh -c 'test -f /tmp/ready && echo ready || echo missing'
kubectl exec -i <pod> -- sh < check.sh
kubectl exec deploy/<name> -- date
```

`-i` passes your stdin to the container, so a longer local script can be piped in. `deploy/<name>` runs in the first
pod of the Deployment. Without `-c`, kubectl uses the container named in the `kubectl.kubernetes.io/default-container`
annotation, or the first one.

`kubectl cp` needs a `tar` binary in the container image and fails without it. `<ns>/<pod>:<path>` reaches another
namespace and `--retries` retries a copy from a container. Without tar, read a single file through exec:

```sh
kubectl cp <ns>/<pod>:/tmp/foo ./foo
kubectl exec -n <ns> <pod> -- cat /tmp/foo > foo
```

## See what changed in a live object: kubectl diff and last-applied-configuration

The live object is the configuration the cluster stores (typically in etcd), as opposed to your file.
`kubectl diff` compares it with what it would be after `kubectl apply`. It exits 0 when nothing differs, 1 when
something does, and above 1 on error, so CI can use it as a drift check. It runs a server-side dry run and needs
PATCH, CREATE and UPDATE permission.

```sh
kubectl diff -f configmap.yaml
kubectl diff -f <directory>/
kubectl apply view-last-applied configmap/<name>
```

`kubectl apply` records what it applied in the `kubectl.kubernetes.io/last-applied-configuration` annotation. It
sets the fields in your file and clears fields you removed from it, but keeps fields that were never in it (such as
`replicas` changed by `kubectl scale`). A hand edit to a field your file sets therefore shows in the diff, and the
next apply reverts it. `kubectl apply -f <directory>` (with `-R` for subdirectories) applies every manifest in a
directory and changes the cluster. Do not mix `apply` with `create` or `replace`: they do not keep that annotation.
