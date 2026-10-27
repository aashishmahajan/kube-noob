#!/usr/bin/env bash
# Deploy deploy/sidecar/app-with-kube-noob-sidecar.yaml on a kind cluster with a locally built image, prove the
# sidecar works and stays private, and record every command with its real output to a transcript.
# The app container is a stand-in (the same image, idling) because the example's app image is a placeholder.
# Usage: scripts/demo_sidecar_kind.sh <image> <transcript-file>
set -euo pipefail
image="$1"
out="$2"
here="$(cd "$(dirname "$0")/.." && pwd)"
: > "$out"
cd "$here"

run() {
  printf '\n# %s\n$ %s\n' "$1" "$2" | tee -a "$out"
  bash -o pipefail -c "$2" 2>&1 | tee -a "$out"
}

python3 - "$image" > /tmp/sidecar-kind.yaml <<'PY'
import sys
import yaml

image = sys.argv[1]
docs = list(yaml.safe_load_all(open("deploy/sidecar/app-with-kube-noob-sidecar.yaml")))
for d in docs:
    if d["kind"] == "Deployment":
        for c in d["spec"]["template"]["spec"]["containers"]:
            c["image"] = image
            c["imagePullPolicy"] = "Never"
            if c["name"] == "assistant":
                c["command"] = ["python3", "-c", "import time; time.sleep(10**9)"]
                c.pop("ports", None)
                c.pop("readinessProbe", None)
                c.pop("livenessProbe", None)
    if d["kind"] == "Service":
        d["spec"]["ports"][0]["targetPort"] = 8000
    if d["kind"] == "NetworkPolicy":
        for rule in d["spec"].get("egress", []):
            rule["to"] = [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}]
            rule["ports"] = [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]
yaml.safe_dump_all(docs, sys.stdout, sort_keys=False)
PY

run "Audit the sidecar example for OpenShift 4.20 before deploying it" \
  "kube-noob audit -f deploy/sidecar/app-with-kube-noob-sidecar.yaml --platform openshift --version 4.20 --fail-on medium"
run "A namespace that enforces Pod Security 'restricted'" \
  "kubectl create namespace team-tools && kubectl label namespace team-tools pod-security.kubernetes.io/enforce=restricted"
run "Deploy the app with kube-noob as a sidecar" "kubectl apply -f /tmp/sidecar-kind.yaml"
run "Both containers start under the restricted policy" \
  "kubectl -n team-tools rollout status deploy/assistant --timeout=180s && kubectl -n team-tools get pods"
run "The app calls kube-noob on 127.0.0.1 inside its own pod: audit, diagnose, cited search" \
  "kubectl -n team-tools exec -i deploy/assistant -c assistant -- python3 - < scripts/sidecar_client.py"
run "Nothing outside the pod can reach it: port 8080 on the pod IP is closed" \
  "kubectl -n team-tools exec deploy/assistant -c assistant -- python3 -c \"import socket; ip=socket.gethostbyname(socket.gethostname()); s=socket.socket(); r=s.connect_ex((ip, 8080)); print('pod IP', ip, 'port 8080:', 'closed (listens on 127.0.0.1 only)' if r else 'OPEN'); raise SystemExit(0 if r else 1)\""
run "Memory used by the kube-noob container after those calls" \
  "kubectl -n team-tools exec deploy/assistant -c kube-noob -- python3 -c \"import pathlib as p; f=lambda n: int(p.Path('/sys/fs/cgroup', n).read_text()) // 2**20 if p.Path('/sys/fs/cgroup', n).exists() else None; print('current', f('memory.current'), 'MiB; peak', f('memory.peak'), 'MiB; limit 256 MiB')\""
run "kube-noob runs as non-root with a read-only root filesystem" \
  "kubectl -n team-tools exec deploy/assistant -c kube-noob -- python3 -c \"import os; print('uid', os.getuid(), '- root filesystem writable:', os.access('/', os.W_OK))\""
run "Traffic policy: ingress only to the app port, egress DNS only" \
  "kubectl -n team-tools get networkpolicy assistant -o jsonpath='{.spec.policyTypes}{\"\\n\"}'"
