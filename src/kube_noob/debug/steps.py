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
_LOCAL_READ = {"skopeo": {"inspect"}, "roxctl": {"deployment", "image"}, "kube-noob": None, "jq": None}
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


def classify_step(text: str) -> StepKind:
    cmd = split_comment(text)[0].strip().strip("`")
    if not cmd or not re.match(r"^[a-z][\w.-]*\s", cmd + " "):
        return "read"  # prose guidance such as "Read the policy names ..."
    toks = cmd.split()
    tool, rest = toks[0], toks[1:]
    sub = rest[0] if rest else ""
    if tool in {"oc", "kubectl"}:
        if sub in _KUBE_READ:
            return "read"
        nxt = rest[1] if len(rest) > 1 else ""
        if sub == "auth":
            return "read" if nxt in {"can-i", "whoami"} else "change"
        if sub == "rollout":
            return "read" if nxt in {"status", "history"} else "change"
        if sub in _KUBE_EXEC:
            return "exec"
        if sub == "adm":
            if nxt in {"top", "inspect", "must-gather"} or (nxt == "policy" and _ADM_POLICY_READ.search(cmd)):
                return "read"
            return "change"
        return "change"
    if tool == "helm":
        return "read" if sub in _HELM_READ else "change"
    if tool == "rosa":
        return "read" if sub in _ROSA_READ else "change"
    if tool in _LOCAL_READ:
        allowed = _LOCAL_READ[tool]
        if tool == "kube-noob":
            return "read" if sub not in {"serve", "mcp", "corpus", "ask"} else "exec"
        if allowed is None or sub in allowed:
            return "read"
        return "exec"
    if tool in _NETWORK_EXEC:
        return "exec"
    if not cmd[0].isalpha() or cmd[0].isupper():
        return "read"
    return "exec"
