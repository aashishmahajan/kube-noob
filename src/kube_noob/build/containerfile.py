"""Containerfile (Dockerfile) audit, static and offline (requirements R4.2).

Checks, each with a good and a bad fixture in ``tests/fixtures/containerfile/``:

- KN-B001 base image not pinned by digest (``FROM image@sha256:...``)
- KN-B002 the final stage runs as root (no ``USER``, or ``USER root``/``0``)
- KN-B003 a credential in ``ENV``, ``ARG``, ``LABEL`` or a ``RUN`` line (stored in the image config or history)
- KN-B004 a credential file copied into the image (``COPY .env``, ``id_rsa``, ``.npmrc``...; with ``--context``, also
  what ``COPY . .`` would take that ``.containerignore``/``.dockerignore`` does not exclude)
- KN-B005 a download piped into a shell (``curl ... | sh``)
- KN-B006 package manager cache left in the final image (apt lists, dnf/yum/microdnf, apk, pip, zypper)
- KN-B007 no ``HEALTHCHECK`` and no probes (Kubernetes ignores HEALTHCHECK: probes in the pod spec pass the check)
- KN-B008 a single-stage build that ships its build tools (use a multi-stage build)

``kube_noob.build.oci`` adds what only the built image shows: KN-B009 (a credential in a layer, including one
deleted by a later layer) and KN-B010 (one in the image config or history), and the image's real user for KN-B002.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kube_noob.audit.rules import SENSITIVE_ENV
from kube_noob.build import secrets
from kube_noob.catalog import SOURCES

MAX_BYTES = 1_000_000
MAX_LINES = 20_000
MAX_INSTRUCTIONS = 3_000
MAX_CONTEXT_FILES = 50_000
SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class Check:
    rule_id: str
    title: str
    severity: str
    fix: str
    sources: tuple[str, ...]


CHECKS: dict[str, Check] = {
    c.rule_id: c
    for c in (
        Check(
            "KN-B001",
            "Base image not pinned by digest",
            "medium",
            "Pin the base image to a digest: FROM registry/image:tag@sha256:<digest> (find it with skopeo inspect "
            "docker://registry/image:tag); update the digest on purpose, for example with Renovate or Dependabot",
            ("docker-best-practices",),
        ),
        Check(
            "KN-B002",
            "Image runs as root",
            "medium",
            "End the final stage with a numeric non-root USER (USER 1001). On OpenShift the container runs with an "
            "arbitrary UID in group 0: give group 0 the owner's rights on what it writes (chgrp -R 0 <dir> && "
            "chmod -R g=u <dir>)",
            ("docker-best-practices", "rh-arbitrary-uid"),
        ),
        Check(
            "KN-B003",
            "Credential in ENV, ARG, LABEL or RUN",
            "high",
            "Never put a credential in ENV, ARG or LABEL: they are stored in the image config and history. Use a "
            "build secret (RUN --mount=type=secret,id=<id> with podman/buildah --secret or docker build --secret) "
            "and inject runtime credentials from a Secret",
            ("docker-secrets-arg-env", "docker-build-secrets"),
        ),
        Check(
            "KN-B004",
            "Credential file copied into the image",
            "high",
            "Do not COPY credential files; exclude them in .containerignore/.dockerignore and mount them at build "
            "time as a build secret, or at run time from a Secret",
            ("docker-build-secrets", "k8s-secrets-good-practices"),
        ),
        Check(
            "KN-B005",
            "Download piped into a shell",
            "high",
            "Download to a file, verify its checksum or signature, then run it (curl -fsSLo install.sh <url> && "
            "echo '<sha256>  install.sh' | sha256sum -c && sh install.sh), or install from a signed package",
            ("docker-best-practices",),
        ),
        Check(
            "KN-B006",
            "Package manager cache left in the image",
            "low",
            "Clean up in the same RUN that installs: rm -rf /var/lib/apt/lists/* (apt), dnf clean all / yum clean "
            "all / microdnf clean all, apk add --no-cache, pip install --no-cache-dir, zypper clean -a",
            ("docker-best-practices",),
        ),
        Check(
            "KN-B007",
            "No HEALTHCHECK and no probes",
            "low",
            "Define readinessProbe and livenessProbe in the pod spec (Kubernetes and OpenShift ignore HEALTHCHECK); "
            "for podman or Docker hosts add HEALTHCHECK CMD <check> (buildah keeps it only with --format docker)",
            ("k8s-probes",),
        ),
        Check(
            "KN-B008",
            "Single-stage build ships its build tools",
            "low",
            "Use a multi-stage build: compile in a builder stage and COPY --from=<builder> only the artifacts into "
            "a minimal runtime image (ubi-minimal, ubi-micro, distroless)",
            ("docker-best-practices",),
        ),
        Check(
            "KN-B009",
            "Credential in an image layer",
            "critical",
            "Remove the file from the build context and rebuild from a clean context; a file deleted in a later "
            "layer is still in the earlier one. Rotate the credential: anyone who can pull the image has it",
            ("docker-build-secrets", "k8s-secrets-good-practices"),
        ),
        Check(
            "KN-B010",
            "Credential in the image config or history",
            "high",
            "Rebuild without the credential in ENV, ARG or LABEL (build arguments show in the history), and rotate it",
            ("docker-secrets-arg-env",),
        ),
    )
}


@dataclass
class Instruction:
    line: int
    cmd: str
    body: str  # the arguments without the leading --flags
    flags: dict[str, str] = field(default_factory=dict)
    heredoc: str = ""


@dataclass
class Stage:
    index: int
    base: str
    name: str | None
    line: int
    instructions: list[Instruction] = field(default_factory=list)


@dataclass
class Parsed:
    stages: list[Stage]
    global_args: dict[str, str]
    notes: list[str]


class ContainerfileError(ValueError):
    """Not a Containerfile, or too large."""


_DIRECTIVE = re.compile(r"^#\s{0,10}(escape|syntax|check)\s{0,10}=\s{0,10}(\S{1,200})\s*$", re.I)
_HEREDOC = re.compile(r"<<(-?)([\"']?)([A-Za-z_][A-Za-z0-9_]{0,40})\2")
_KEYWORDS = frozenset(
    {
        "FROM",
        "RUN",
        "CMD",
        "LABEL",
        "MAINTAINER",
        "EXPOSE",
        "ENV",
        "ADD",
        "COPY",
        "ENTRYPOINT",
        "VOLUME",
        "USER",
        "WORKDIR",
        "ARG",
        "ONBUILD",
        "STOPSIGNAL",
        "HEALTHCHECK",
        "SHELL",
    }
)


def parse(text: str) -> Parsed:
    if len(text.encode("utf-8", "replace")) > MAX_BYTES:
        raise ContainerfileError(f"larger than {MAX_BYTES} bytes")
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise ContainerfileError(f"more than {MAX_LINES} lines")
    escape = "\\"
    notes: list[str] = []
    i = 0
    while i < len(lines):  # parser directives come first, before anything else
        m = _DIRECTIVE.match(lines[i].strip())
        if not m:
            break
        if m.group(1).lower() == "escape" and m.group(2) in {"\\", "`"}:
            escape = m.group(2)
        i += 1
    stages: list[Stage] = []
    global_args: dict[str, str] = {}
    count = 0
    while i < len(lines):
        raw = lines[i]
        start = i + 1
        i += 1
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        logical = raw.rstrip()
        while logical.endswith(escape) and i < len(lines):
            logical = logical[:-1]
            nxt = lines[i]
            i += 1
            if nxt.lstrip().startswith("#") or not nxt.strip():
                if i >= len(lines):
                    break
                logical += escape  # keep continuing past comments and blank lines, as BuildKit does
                continue
            logical += " " + nxt.strip()
        heredoc_parts: list[str] = []
        for m in _HEREDOC.finditer(logical):
            dash, delim = m.group(1), m.group(3)
            body: list[str] = []
            while i < len(lines):
                cur = lines[i]
                i += 1
                if (cur.lstrip("\t") if dash else cur) == delim:
                    break
                body.append(cur)
            heredoc_parts.append("\n".join(body))
        word, _, rest = logical.strip().partition(" ")
        cmd = word.upper()
        if cmd not in _KEYWORDS:
            notes.append(f"line {start}: {word[:40]!r} is not a Containerfile instruction")
            continue
        count += 1
        if count > MAX_INSTRUCTIONS:
            raise ContainerfileError(f"more than {MAX_INSTRUCTIONS} instructions")
        flags: dict[str, str] = {}
        rest = rest.strip()
        while rest.startswith("--"):
            tok, _, rest = rest.partition(" ")
            key, _, val = tok[2:].partition("=")
            flags[key.lower()] = val
            rest = rest.lstrip()
        ins = Instruction(start, cmd, rest, flags, "\n".join(heredoc_parts))
        if cmd == "FROM":
            parts = rest.split()
            base = parts[0] if parts else ""
            name = parts[2] if len(parts) >= 3 and parts[1].lower() == "as" else None
            stages.append(Stage(len(stages), base, name, start, [ins]))
        elif not stages:
            if cmd == "ARG":
                global_args.update(_kv(rest, arg=True))
            else:
                notes.append(f"line {start}: {cmd} before the first FROM")
        else:
            stages[-1].instructions.append(ins)
    if not stages:
        raise ContainerfileError("no FROM instruction: not a Containerfile")
    return Parsed(stages, global_args, notes)


def _words(text: str) -> list[str]:
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()


def _kv(text: str, *, arg: bool = False) -> dict[str, str]:
    """ENV KEY=VALUE ..., the legacy ENV KEY VALUE, and ARG NAME[=default] ..."""
    words = _words(text)
    if not words:
        return {}
    if not arg and "=" not in words[0]:
        return {words[0]: " ".join(words[1:])}
    out: dict[str, str] = {}
    for w in words:
        k, sep, v = w.partition("=")
        if k:
            out[k] = v if sep else "\x00"  # \x00: an ARG with no default
    return out


_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]{0,60})(?::?[-+]([^}]{0,200}))?\}|\$([A-Za-z_][A-Za-z0-9_]{0,60})")


def _expand(value: str, env: dict[str, str]) -> str:
    def sub(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(3)
        got = env.get(name, "\x00")
        if got != "\x00":
            return got
        return m.group(2) if m.group(2) is not None else m.group(0)

    return _VAR.sub(sub, value)


# -- checks ------------------------------------------------------------------------------------------------------


@dataclass
class Finding:
    rule_id: str
    line: int | None
    message: str
    stage: str | None = None
    severity: str | None = None

    def as_dict(self) -> dict[str, Any]:
        c = CHECKS[self.rule_id]
        out: dict[str, Any] = {
            "ruleId": self.rule_id,
            "title": c.title,
            "severity": self.severity or c.severity,
            "message": self.message,
            "fix": c.fix,
            "sources": [SOURCES[s].as_dict() for s in c.sources if s in SOURCES],
        }
        if self.line is not None:
            out["line"] = self.line
        if self.stage is not None:
            out["stage"] = self.stage
        return out


def _label(st: Stage) -> str:
    return st.name or f"#{st.index}"


_PIPE_SHELL = re.compile(
    r"(?i)\b(?:curl|wget)\b[^|;&\n]{0,800}\|\s{0,5}(?:sudo\s{1,5}(?:-\S{1,20}\s{1,5}){0,3})?(?:env\s{1,5}[^|;&\n]{0,80}"
    r"\s)?(?:ba|z|da|k|fi|a)?sh\b|\b(?:curl|wget)\b[^|;&\n]{0,800}\|\s{0,5}(?:sudo\s{1,5})?(?:python[23]?|perl|ruby|"
    r"node)\b|(?:ba)?sh\s{1,5}(?:-\S{1,10}\s{1,5})?<\(\s{0,5}(?:curl|wget)\b|sh\s{1,5}-c\s{1,5}[\"']\$\(\s{0,5}(?:curl|"
    r"wget)\b"
)
_APT = re.compile(r"\bapt(?:-get)?\s{1,10}(?:-\S{1,40}\s{1,10}){0,10}install\b")
_DNF = re.compile(r"\b(dnf|yum|microdnf|tdnf)\s{1,10}(?:-\S{1,40}\s{1,10}){0,10}install\b")
_APK = re.compile(r"\bapk\s{1,10}(?:-\S{1,40}\s{1,10}){0,10}add\b")
_PIP = re.compile(r"\b(?:pip3?|python3?(?:\.\d{1,2})?\s{1,5}-m\s{1,5}pip)\s{1,10}install\b")
_ZYPPER = re.compile(r"\bzypper\s{1,10}(?:-\S{1,40}\s{1,10}){0,10}(?:in|install)\b")
_TOOLCHAIN = re.compile(
    r"\b(?:gcc|gcc-c\+\+|g\+\+|clang|make|cmake|build-essential|golang|go-toolset|maven|gradle|[\w.+-]{1,60}-devel|"
    r"openjdk-\d{1,2}-jdk|java-\d{1,2}-openjdk-devel|rust|cargo|nodejs-devel)\b"
)
_BUILD_CMD = re.compile(
    r"\b(?:go\s{1,5}build|mvnw?\s{1,5}(?:-\S{1,60}\s{1,5}){0,10}(?:package|install|verify)|gradlew?\s{1,5}"
    r"(?:-\S{1,60}\s{1,5}){0,10}(?:build|assemble|bootJar|jar)|npm\s{1,5}run\s{1,5}build|yarn\s{1,5}build|cargo\s{1,5}"
    r"build|dotnet\s{1,5}publish|tsc\b|make(?:\s{1,5}-j\s{0,2}\d{0,3})?(?:\s{1,5}all)?\s{0,5}(?:$|&&|;))"
)
ROOT_USERS = frozenset({"root", "0", "0:0", "root:root", "root:0", "0:root"})


def _from_base(parsed: Parsed, st: Stage) -> tuple[str, str | None]:
    """The stage's base after ARG substitution, and the stage it builds on (when the base names an earlier stage)."""
    base = _expand(st.base, dict(parsed.global_args))
    earlier = {s.name.lower(): s for s in parsed.stages[: st.index] if s.name}
    if base.lower() in earlier:
        return base, earlier[base.lower()].name
    if base.isdigit() and int(base) < st.index:
        return base, f"#{base}"
    return base, None


def _stage_user(parsed: Parsed, st: Stage, depth: int = 0) -> tuple[str | None, int | None]:
    for ins in reversed(st.instructions):
        if ins.cmd == "USER":
            return (ins.body.strip() or None), ins.line
    _, parent = _from_base(parsed, st)
    if parent and depth < 20:
        ps = next(s for s in parsed.stages if parent in (s.name, f"#{s.index}"))
        return _stage_user(parsed, ps, depth + 1)
    return None, None


def _secret_values(ins: Instruction, where: str) -> list[secrets.Hit]:
    text = "\n".join(x for x in (ins.body, ins.heredoc) if x)
    return secrets.scan_text(text, where, assignments=ins.cmd in {"ENV", "ARG", "LABEL"})


def _ignore_patterns(context: Path) -> list[tuple[bool, re.Pattern[str]]]:
    for name in (".containerignore", ".dockerignore"):
        f = context / name
        if f.is_file() and not f.is_symlink():
            rules = []
            for raw in f.read_text(encoding="utf-8", errors="replace").splitlines()[:5000]:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                neg = line.startswith("!")
                pat = os.path.normpath(line.lstrip("!").strip().lstrip("/")).replace(os.sep, "/")
                rules.append((neg, re.compile(_glob(pat))))
            return rules
    return []


def _glob(pat: str) -> str:
    out = ""
    i = 0
    while i < len(pat):
        if pat.startswith("**", i):
            out += ".*"
            i += 2
            if i < len(pat) and pat[i] == "/":
                out = out[:-2] + "(?:.*/)?"
                i += 1
            continue
        ch = pat[i]
        if ch == "*":
            out += "[^/]*"
        elif ch == "?":
            out += "[^/]"
        elif ch == "[":
            j = pat.find("]", i + 1)
            if j == -1:
                out += re.escape(ch)
            else:
                out += "[" + pat[i + 1 : j].replace("\\", "\\\\").replace("!", "^", 1) + "]"
                i = j
        else:
            out += re.escape(ch)
        i += 1
    return f"^{out}$"


def _ignored(rel: str, rules: list[tuple[bool, re.Pattern[str]]]) -> bool:
    parts = rel.split("/")
    candidates = ["/".join(parts[: n + 1]) for n in range(len(parts))]
    verdict = False
    for neg, rx in rules:
        if any(rx.match(c) for c in candidates):
            verdict = not neg
    return verdict


def _context_files(context: Path, source: str, rules: list[tuple[bool, re.Pattern[str]]]) -> tuple[list[str], bool]:
    """Files under ``context`` that ``COPY <source>`` would take (bounded walk, no symlinks followed)."""
    root = context.resolve()
    src = os.path.normpath(source.lstrip("/")).replace(os.sep, "/")
    out: list[str] = []
    seen = 0
    truncated = False
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        prune = not any(neg for neg, _ in rules)  # an exception (!pattern) can bring back a file under a directory
        dirnames[:] = [
            d for d in dirnames if d != ".git" and not (prune and _ignored(f"{rel_dir}/{d}".lstrip("/"), rules))
        ]
        for fn in filenames:
            seen += 1
            if seen > MAX_CONTEXT_FILES:
                return out, True
            rel = f"{rel_dir}/{fn}".lstrip("/")
            if src not in {".", ""} and not (rel == src or rel.startswith(src + "/") or fnmatch.fnmatch(rel, src)):
                continue
            if not _ignored(rel, rules):
                out.append(rel)
    return out, truncated


def audit(
    text: str,
    *,
    context: Path | None = None,
    probes: bool | None = None,
    image_user: str | None = None,
) -> dict[str, Any]:
    """Run every check. ``probes``: the workload defines readiness or liveness probes (from ``--manifests``).
    ``image_user``: the built image's configured user (from an OCI layout), which decides KN-B002 when the
    Containerfile sets none."""
    parsed = parse(text)
    findings: list[Finding] = []
    not_checked: list[str] = []
    final = parsed.stages[-1]
    env_pip_no_cache = False

    for st in parsed.stages:
        base, parent = _from_base(parsed, st)
        if parent is None and base.lower() != "scratch" and "@sha256:" not in base:
            sev = "medium" if st is final else "low"
            if "$" in base:
                why = f"FROM {st.base}: a build argument with no default; pass a digest with --build-arg"
            elif "$" in st.base:
                why = (
                    f"FROM {st.base} defaults to {base}, a tag that can be moved: make the default a digest, or "
                    "pass one with --build-arg every time"
                )
            else:
                why = f"FROM {base}: a tag can be moved; pin it to a digest"
            findings.append(Finding("KN-B001", st.line, why, _label(st), sev))
        env: dict[str, str] = {}
        for ins in st.instructions:
            where = f"line {ins.line}"
            if ins.cmd in {"ENV", "ARG"}:
                for k, v in _kv(ins.body, arg=ins.cmd == "ARG").items():
                    if ins.cmd == "ENV":
                        env[k] = v
                        if k == "PIP_NO_CACHE_DIR" and v.lower() not in {"0", "false", "off", "no"}:
                            env_pip_no_cache = True
                    if not SENSITIVE_ENV.search(k) or re.search(r"(?i)_(?:FILE|PATH|DIR|URL|HOST|USER(?:NAME)?)$", k):
                        continue
                    if v == "\x00":
                        findings.append(
                            Finding(
                                "KN-B003",
                                ins.line,
                                f"ARG {k} has no default: a value passed with --build-arg is "
                                "recorded in the image history",
                                _label(st),
                                "medium",
                            )
                        )
                    elif v and not v.startswith("$"):
                        findings.append(
                            Finding(
                                "KN-B003",
                                ins.line,
                                f"{ins.cmd} {k} holds a literal value ({secrets.mask(v)}): it is stored in the image",
                                _label(st),
                            )
                        )
            if ins.cmd in {"ENV", "ARG", "LABEL", "RUN"}:
                for hit in _secret_values(ins, where)[:3]:
                    if not any(f.rule_id == "KN-B003" and f.line == ins.line for f in findings):
                        findings.append(
                            Finding("KN-B003", ins.line, f"{ins.cmd} carries a {hit.kind} ({hit.preview})", _label(st))
                        )
            if ins.cmd in {"COPY", "ADD"} and "from" not in ins.flags:
                words = _words(ins.body)
                if words and words[0].startswith("["):
                    try:
                        import json

                        words = [str(w) for w in json.loads(ins.body)]
                    except ValueError:
                        pass
                for src in words[:-1]:
                    kind = secrets.name_kind(src)
                    if kind:
                        findings.append(Finding("KN-B004", ins.line, f"{ins.cmd} {src}: a {kind}", _label(st)))
                    elif context is None:
                        if src in {".", "./"} or "*" in src or src.endswith("/"):
                            not_checked.append(
                                f"line {ins.line}: {ins.cmd} {src} copies from the build context; "
                                "pass --context <dir> to check it for credential files"
                            )
                    else:
                        files, truncated = _context_files(context, src, _ignore_patterns(context))
                        bad = [(f, kd) for f in files if (kd := secrets.name_kind(f))]
                        for f, kd in bad[:10]:
                            findings.append(
                                Finding(
                                    "KN-B004",
                                    ins.line,
                                    f"{ins.cmd} {src} takes {f} (a {kd}): not excluded by "
                                    ".containerignore or .dockerignore",
                                    _label(st),
                                )
                            )
                        if truncated:
                            not_checked.append(f"the build context has more than {MAX_CONTEXT_FILES} files")
            if ins.cmd == "RUN":
                body = "\n".join(x for x in (ins.body, ins.heredoc) if x)
                if _PIPE_SHELL.search(body):
                    findings.append(
                        Finding("KN-B005", ins.line, "RUN pipes a download straight into an interpreter", _label(st))
                    )
                if st is final and ins.flags.get("mount", "").find("type=cache") == -1:
                    for problem in _cache_problems(body, env_pip_no_cache):
                        findings.append(Finding("KN-B006", ins.line, problem, _label(st)))

    user, line = _stage_user(parsed, final)
    if user is None:
        if image_user is not None:
            if image_user.strip() in ROOT_USERS or not image_user.strip():
                findings.append(
                    Finding(
                        "KN-B002",
                        None,
                        "no USER in the Containerfile and the image's config runs "
                        f"as {image_user.strip() or 'root (empty User)'}",
                        _label(final),
                    )
                )
        else:
            findings.append(
                Finding(
                    "KN-B002",
                    final.line,
                    "the final stage sets no USER: it runs as the base "
                    "image's user (root unless the base image changes it; pass --image-layout to "
                    "read the built image's user)",
                    _label(final),
                )
            )
    elif user.strip() in ROOT_USERS:
        findings.append(Finding("KN-B002", line, f"USER {user.strip()} in the final stage", _label(final)))

    health = [i for i in final.instructions if i.cmd == "HEALTHCHECK"]
    if probes is not True and (not health or health[-1].body.strip().upper() == "NONE"):
        findings.append(
            Finding(
                "KN-B007",
                health[-1].line if health else None,
                ("HEALTHCHECK NONE" if health else "no HEALTHCHECK")
                + (
                    "; the manifests define no readiness or liveness probe"
                    if probes is False
                    else "; pass the workload's manifests with --manifests to count its probes"
                ),
                _label(final),
            )
        )

    if len(parsed.stages) == 1:
        runs = [i for i in final.instructions if i.cmd == "RUN"]
        tools = [i for i in runs if (_installs(i.body) and _TOOLCHAIN.search(i.body)) or _BUILD_CMD.search(i.body)]
        if tools:
            findings.append(
                Finding(
                    "KN-B008",
                    tools[0].line,
                    "one stage builds and runs: the compilers and build files ship in the image",
                    _label(final),
                )
            )

    return _report(parsed, findings, not_checked)


def _installs(body: str) -> bool:
    return bool(_APT.search(body) or _DNF.search(body) or _APK.search(body) or _ZYPPER.search(body))


def _cache_problems(body: str, pip_no_cache: bool) -> list[str]:
    out = []
    if _APT.search(body) and "/var/lib/apt/lists" not in body:
        out.append("apt installs without rm -rf /var/lib/apt/lists/* in the same RUN")
    m = _DNF.search(body)
    if m and not re.search(rf"\b{m.group(1)}\s{{1,10}}clean\s{{1,10}}all\b", body) and "/var/cache/" not in body:
        out.append(f"{m.group(1)} installs without {m.group(1)} clean all in the same RUN")
    if _APK.search(body) and "--no-cache" not in body and "/var/cache/apk" not in body:
        out.append("apk add without --no-cache")
    if _PIP.search(body) and "--no-cache-dir" not in body and not pip_no_cache:
        out.append("pip install without --no-cache-dir")
    if _ZYPPER.search(body) and not re.search(r"\bzypper\s{1,10}(?:-\S{1,20}\s{1,10}){0,3}clean\b", body):
        out.append("zypper installs without zypper clean")
    return out


def _report(parsed: Parsed, findings: list[Finding], not_checked: list[str]) -> dict[str, Any]:
    order = {s: i for i, s in enumerate(SEVERITIES)}
    rows = [f.as_dict() for f in findings]
    rows.sort(key=lambda r: (-order[r["severity"]], r.get("line") or 0, r["ruleId"]))
    counts = {s: sum(1 for r in rows if r["severity"] == s) for s in reversed(SEVERITIES)}
    return {
        "stages": [{"index": s.index, "name": s.name, "base": s.base, "line": s.line} for s in parsed.stages],
        "findings": rows,
        "counts": counts,
        "checks": sorted(CHECKS),
        "notChecked": not_checked,
        "notes": parsed.notes,
    }


def failed(report: dict[str, Any], fail_on: str) -> bool:
    if fail_on == "never":
        return False
    floor = SEVERITIES.index(fail_on)
    return any(SEVERITIES.index(r["severity"]) >= floor for r in report["findings"])


def explain(rule_id: str) -> dict[str, Any] | None:
    c = CHECKS.get(rule_id.upper())
    if c is None:
        return None
    return {
        "ruleId": c.rule_id,
        "title": c.title,
        "defaultSeverity": c.severity,
        "stage": "build",
        "input": "Containerfile" if c.rule_id not in {"KN-B009", "KN-B010"} else "image (OCI layout)",
        "remediation": c.fix,
        "citations": [SOURCES[s].as_dict() for s in c.sources if s in SOURCES],
    }
