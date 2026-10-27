"""Classify troubleshooting steps so read-only evidence always comes first.

- ``read``:   observes state without changing it (get, describe, logs, events, can-i, registry inspect, offline audit)
- ``exec``:   runs something inside a container, on a node or against the network (rsh, exec, debug, curl, openssl);
              still non-mutating by intent, but it executes code, so it needs explicit approval
- ``change``: mutates cluster, release or cloud state (apply, delete, patch, scale, rollout, drain, helm upgrade,
              rosa edit ...); always requires approval and never appears in a playbook's checks
Unknown commands are treated as ``exec`` (approval required), never as ``read``.
"""

from __future__ import annotations

import re
from typing import Literal

StepKind = Literal["read", "exec", "change"]

_KUBE_READ = {
    "get",
    "describe",
    "logs",
    "events",
    "explain",
    "api-resources",
    "api-versions",
    "version",
    "whoami",
    "status",
    "top",
    "wait",
}
_KUBE_EXEC = {"rsh", "exec", "debug", "port-forward", "attach", "proxy", "rsync", "cp"}
# `oc adm policy scc-subject-review` / `scc-review` / `who-can` evaluate policy and never grant anything
_ADM_POLICY_READ = re.compile(r"\b(scc-subject-review|scc-review|who-can)\b")
_HELM_READ = {"status", "history", "get", "list", "ls", "show", "template", "lint", "search", "env", "version"}
_ROSA_READ = {"describe", "list", "logs", "verify", "whoami", "version"}
_LOCAL_READ = {"skopeo": {"inspect"}, "roxctl": {"deployment", "image"}}
_NETWORK_EXEC = {"curl", "wget", "openssl", "dig", "nslookup", "nc", "ping", "getent"}


def split_comment(text: str) -> tuple[str, str | None]:
    """Split ``cmd  # why`` into the bare command and its note. A ``#`` inside quotes or glued to a word is data.

    Commands shown to users never carry trailing comments: zsh (the macOS default) passes ``#`` and every word after
    it as arguments unless ``interactivecomments`` is set, so a pasted ``oc logs x  # note`` fails.
    """
    quote: str | None = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1].isspace()):
            why = text[i + 1 :].strip()
            return text[:i].rstrip(), why or None
    return text.rstrip(), None


_RANK = {"read": 0, "exec": 1, "change": 2}
_TEXT_FILTERS = {
    "grep",
    "egrep",
    "fgrep",
    "awk",
    "sort",
    "uniq",
    "head",
    "tail",
    "wc",
    "cut",
    "tr",
    "column",
    "less",
    "more",
    "cat",
    "yq",
    "jq",
    "base64",
    "sed",
    "tee",
    "nl",
    "xxd",
    "true",
}
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S*$")


def _segments(cmd: str) -> list[str]:
    """Split a shell line on |, ||, &&, ; outside quotes."""
    parts: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(cmd):
        ch = cmd[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch in "|;&":
            if ch == "&" and cmd[i : i + 2] != "&&":
                buf.append(ch)
            else:
                parts.append("".join(buf))
                buf = []
                if cmd[i : i + 2] in {"||", "&&"}:
                    i += 1
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def _classify_segment(seg: str) -> StepKind:
    toks = seg.split()
    while toks and _ENV_ASSIGN.match(toks[0]):  # KUBECONFIG=... oc delete ...
        toks = toks[1:]
    if toks and toks[0] in {"sudo", "env", "command", "exec", "time", "nohup"}:
        toks = toks[1:]
        while toks and _ENV_ASSIGN.match(toks[0]):
            toks = toks[1:]
    if not toks:
        return "read"
    tool = toks[0].rsplit("/", 1)[-1]  # /usr/local/bin/oc -> oc
    rest = toks[1:]
    sub = rest[0] if rest else ""
    nxt = rest[1] if len(rest) > 1 else ""
    if tool == "xargs":  # `... | xargs oc delete pod` runs the command that follows
        args = [t for t in rest if not t.startswith("-")]
        return _classify_segment(" ".join(args)) if args else "exec"
    if tool in {"oc", "kubectl"}:
        if sub in _KUBE_READ:
            return "read"
        if sub == "auth":
            return "read" if nxt in {"can-i", "whoami"} else "change"
        if sub == "rollout":
            return "read" if nxt in {"status", "history"} else "change"
        if sub in _KUBE_EXEC:
            return "exec"
        if sub == "adm":
            # must-gather creates a namespace and a privileged pod; it changes the cluster.
            if nxt in {"top", "inspect"} or (nxt == "policy" and _ADM_POLICY_READ.search(seg)):
                return "read"
            return "change"
        return "change"
    if tool == "helm":
        return "read" if sub in _HELM_READ else "change"
    if tool == "rosa":
        return "read" if sub in _ROSA_READ else "change"
    if tool == "kube-noob":
        return "read" if sub not in {"serve", "mcp", "corpus", "ask"} else "exec"
    if tool in _LOCAL_READ:
        allowed = _LOCAL_READ[tool]
        return "read" if allowed is None or sub in allowed else "exec"
    if tool in _TEXT_FILTERS:
        if tool == "sed" and any(t.startswith("-i") or t == "--in-place" for t in rest):
            return "change"
        if tool == "tee":
            return "change"
        return "read"
    if tool in _NETWORK_EXEC:
        return "exec"
    return "exec"


def classify_step(text: str) -> StepKind:
    """Classify a step; a shell line is as dangerous as its most dangerous segment."""
    cmd = split_comment(text)[0].strip().strip("`")
    if not cmd or not re.match(r"^([A-Za-z_][A-Za-z0-9_]*=\S*\s+)*[a-z/][\w./-]*\s", cmd + " "):
        return "read"  # prose guidance such as "Read the policy names ..."
    kinds = [_classify_segment(seg) for seg in _segments(cmd)]
    return max(kinds, key=lambda k: _RANK[k]) if kinds else "read"
