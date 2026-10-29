"""Which images ship a repository file, and which repository file an image path came from (requirements R4.6, R4.7).

A Containerfile is read with the build audit's parser (``kube_noob.build.containerfile``), stage by stage:

- ``COPY`` and ``ADD`` without ``--from`` take files from the build context. A context file is in the final image
  when the final stage copies it (``copied``, with its path in the image), or when it is copied into a stage the
  final stage builds on (``FROM <stage>``, same) or copies from (``COPY --from=<stage>``): then it is ``built`` into
  the image (compiled, bundled or installed by that stage) unless the copied path covers the file's own destination,
  in which case it is still ``copied``.
- The ``.containerignore`` or ``.dockerignore`` of the context leaves files out, as the build does.
- ``RUN --mount=type=bind`` (the default type) mounts ``source`` (default: the root) of ``from`` (default: the build
  context; or an earlier stage) at ``target`` for that RUN only: what the stage builds from it is ``built`` into the
  image when the final stage is that stage, builds on it or copies from it (the ``docker init`` Go and Rust
  templates build this way). Nothing of the mount itself is committed to the layer.
- ``COPY --from`` an external image, ``ADD`` of a URL or Git repository and heredocs take nothing from the context.
- Relative destinations follow ``WORKDIR``; ``$VAR`` and ``${VAR}`` expand from ``ARG`` defaults and ``ENV``.
- Source wildcards follow Go's ``filepath.Match`` (BuildKit's reference: "matching will be done using Go's
  filepath.Match rules"): ``*`` and ``?`` never cross ``/``.

Paths are repository-relative. ``context`` is the build context's directory in the repository (``.`` for the root);
an absolute context is refused (it would match no repository path and silently mark everything "not shipped").
Traversal of stages is memoised per call, so a stage copying from every earlier stage costs linear work.
"""

from __future__ import annotations

import fnmatch
import json
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any

from kube_noob.build import containerfile as cf

MAX_STAGES = 50
MAX_COPIES = 2_000


class ShipError(ValueError):
    """A Containerfile that cannot be read, or a build description out of bounds."""


@dataclass(frozen=True)
class Copy:
    stage: int
    line: int
    sources: tuple[str, ...]  # context-relative patterns, or paths in the --from stage
    dest: str  # absolute path in the stage's filesystem
    from_stage: int | None = None  # COPY --from=<earlier stage>
    external: bool = False  # COPY --from=<image>, ADD <url>, heredoc: nothing from the context
    dest_is_dir: bool = False
    bind: bool = False  # RUN --mount=type=bind: used to build in this stage, not copied into it


@dataclass(frozen=True)
class Shipped:
    image: str
    containerfile: str
    how: str  # copied | built
    line: int  # the COPY or ADD that takes the file from the context
    image_path: str = ""  # where the file lands, for copied files

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"image": self.image, "containerfile": self.containerfile, "how": self.how}
        out["line"] = self.line
        if self.image_path:
            out["imagePath"] = self.image_path
        return out


@dataclass
class Build:
    containerfile: str  # its path in the repository, as a label
    text: str
    image: str = ""  # the image it builds (registry/repository[:tag]); empty: the Containerfile's path stands in
    context: str = "."  # the build context, repository-relative
    ignore: str = ""  # the context's .containerignore / .dockerignore text
    target: str = ""  # --target stage name
    copies: list[Copy] = field(default_factory=list)
    final: int = 0
    stage_names: dict[str, int] = field(default_factory=dict)
    stage_bases: dict[int, int] = field(default_factory=dict)  # stage -> earlier stage it is FROM
    rules: list[tuple[bool, re.Pattern[str]]] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.image or self.containerfile


def _norm_context(context: str) -> str:
    raw = (context or ".").replace("\\", "/")
    if raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw):
        raise ShipError(f"build context {context!r} is absolute: give it relative to the repository")
    c = posixpath.normpath(raw)
    if c == ".." or c.startswith("../"):
        raise ShipError(f"build context {context!r} is outside the repository")
    return "" if c == "." else c


def _args(ins: cf.Instruction) -> list[str]:
    body = ins.body.strip()
    if body.startswith("["):
        try:
            parts = json.loads(body)
        except ValueError:
            parts = None
        if isinstance(parts, list) and all(isinstance(p, str) for p in parts):
            return [str(p) for p in parts]
    return cf.words(body)


def parse_build(b: Build) -> Build:
    try:
        parsed = cf.parse(b.text)
    except cf.ContainerfileError as exc:
        raise ShipError(f"{b.containerfile}: {exc}") from exc
    if len(parsed.stages) > MAX_STAGES:
        raise ShipError(f"{b.containerfile}: more than {MAX_STAGES} stages")
    b.context = _norm_context(b.context)
    b.rules = cf.ignore_rules(b.ignore) if b.ignore else []
    args = {k: v for k, v in parsed.global_args.items() if v != "\x00"}
    for st in parsed.stages:
        if st.name:
            b.stage_names[st.name.lower()] = st.index
        base = cf.expand(st.base, args).lower()
        if base in b.stage_names and b.stage_names[base] < st.index:
            b.stage_bases[st.index] = b.stage_names[base]
        env = dict(args)
        workdir = "/"
        for ins in st.instructions[1:]:
            if ins.cmd in {"ARG", "ENV"}:
                env.update({k: v for k, v in cf.kv(ins.body, arg=ins.cmd == "ARG").items() if v != "\x00"})
            elif ins.cmd == "WORKDIR":
                w = cf.expand(ins.body.strip().strip('"'), env)
                workdir = posixpath.normpath(posixpath.join(workdir, w)) if w else workdir
            elif ins.cmd in {"COPY", "ADD"} or (ins.cmd == "RUN" and ins.mounts):
                new = (
                    [_copy(st.index, ins, env, workdir, b.stage_names)]
                    if ins.cmd != "RUN"
                    else _binds(st.index, ins, env, workdir, b.stage_names)
                )
                if len(b.copies) + len(new) > MAX_COPIES:
                    raise ShipError(f"{b.containerfile}: more than {MAX_COPIES} COPY, ADD and RUN --mount sources")
                b.copies.extend(new)
    if b.target:
        if b.target.lower() not in b.stage_names:
            raise ShipError(f"{b.containerfile}: no stage named {b.target!r}")
        b.final = b.stage_names[b.target.lower()]
    else:
        b.final = len(parsed.stages) - 1
    return b


def _copy(stage: int, ins: cf.Instruction, env: dict[str, str], workdir: str, names: dict[str, int]) -> Copy:
    parts = [cf.expand(p, env) for p in _args(ins)]
    if ins.heredoc or len(parts) < 2:
        return Copy(stage, ins.line, (), "", external=True)
    *sources, dest_raw = parts
    dest_is_dir = dest_raw.endswith("/") or len(sources) > 1 or dest_raw in {".", "./"}
    dest = posixpath.normpath(posixpath.join(workdir, dest_raw))
    frm = ins.flags.get("from", "")
    if frm:
        key = frm.lower()
        if key in names:
            return Copy(stage, ins.line, tuple(sources), dest, from_stage=names[key], dest_is_dir=dest_is_dir)
        if key.isdigit() and int(key) < stage:
            return Copy(stage, ins.line, tuple(sources), dest, from_stage=int(key), dest_is_dir=dest_is_dir)
        return Copy(stage, ins.line, tuple(sources), dest, external=True)
    if ins.cmd == "ADD" and any(re.match(r"^[a-z][a-z0-9+.-]*://|^git@", s, re.I) for s in sources):
        return Copy(stage, ins.line, (), dest, external=True)
    clean = tuple(posixpath.normpath(s.replace("\\", "/")).lstrip("/") for s in sources)
    return Copy(stage, ins.line, tuple("." if c in {"", "."} else c for c in clean), dest, dest_is_dir=dest_is_dir)


def _binds(stage: int, ins: cf.Instruction, env: dict[str, str], workdir: str, names: dict[str, int]) -> list[Copy]:
    """The bind mounts of one RUN as build inputs of the stage (cache, secret, ssh and tmpfs mounts are not)."""
    out: list[Copy] = []
    for raw in ins.mounts:
        opts: dict[str, str] = {}
        for part in cf.expand(raw, env).split(","):
            k, sep, v = part.strip().partition("=")
            opts[k.strip().lower()] = v.strip().strip("\"'") if sep else "true"
        if opts.get("type", "bind") != "bind":
            continue
        target = opts.get("target") or opts.get("dst") or opts.get("destination") or ""
        dest = posixpath.normpath(posixpath.join(workdir, target)) if target else workdir
        source = posixpath.normpath((opts.get("source") or opts.get("src") or ".").replace("\\", "/")).lstrip("/")
        source = "." if source in {"", "."} else source
        frm = opts.get("from", "")
        if not frm:
            out.append(Copy(stage, ins.line, (source,), dest, dest_is_dir=True, bind=True))
            continue
        key = frm.lower()
        idx = names.get(key, int(key) if key.isdigit() and int(key) < stage else None)
        if idx is not None:
            out.append(Copy(stage, ins.line, (source,), dest, from_stage=idx, dest_is_dir=True, bind=True))
    return out


def _segment_match(rel: str, pattern: str) -> tuple[bool, str]:
    """Go ``filepath.Match`` over leading path segments: (matched, the rest of ``rel`` below the match)."""
    pseg = pattern.split("/")
    rseg = rel.split("/")
    if len(rseg) < len(pseg):
        return False, ""
    for r, p in zip(rseg, pseg, strict=False):
        if not fnmatch.fnmatchcase(r, p):
            return False, ""
    return True, "/".join(rseg[len(pseg) :])


def _match(rel: str, pattern: str) -> tuple[bool, str, bool]:
    """Whether a context-relative file is taken by a COPY source: (taken, its path under the destination, taken as a
    member of a copied directory). A directory source copies its contents, not the directory itself."""
    if pattern == ".":
        return True, rel, True
    if rel == pattern:
        return True, posixpath.basename(rel), False
    if rel.startswith(pattern + "/"):
        return True, rel[len(pattern) + 1 :], True
    if any(ch in pattern for ch in "*?["):
        ok, tail = _segment_match(rel, pattern)
        if ok:
            return (True, tail, True) if tail else (True, rel.rsplit("/", 1)[-1], False)
    return False, "", False


def _dest(c: Copy, under: str, member: bool) -> str:
    if member:
        return posixpath.normpath(posixpath.join(c.dest, under))
    return posixpath.join(c.dest, under) if c.dest_is_dir else c.dest


def _covers(paths: tuple[str, ...], image_path: str) -> bool:
    for p in paths:
        root = posixpath.normpath("/" + p.lstrip("/"))
        if root in {"/", image_path} or image_path.startswith(root.rstrip("/") + "/"):
            return True
    return False


def _in_stage(
    b: Build, stage: int, rel: str, depth: int = 0, memo: dict[int, list[tuple[str, int, str]]] | None = None
) -> list[tuple[str, int, str]]:
    """How a context file reaches ``stage``: (copied|built, line of the COPY from the context, path in the stage).
    ``memo`` holds each stage's answer for this ``rel``, so shared ancestors are walked once."""
    memo = {} if memo is None else memo
    if stage in memo:
        return memo[stage]
    if depth > MAX_STAGES:
        return []
    memo[stage] = []  # a cycle (not possible with earlier-only references) ends here
    out: list[tuple[str, int, str]] = []
    base = b.stage_bases.get(stage)
    if base is not None:
        out += _in_stage(b, base, rel, depth + 1, memo)
    for c in b.copies:
        if c.stage != stage or c.external:
            continue
        if c.bind:
            if c.from_stage is None:
                if any(_match(rel, pattern)[0] for pattern in c.sources):
                    out.append(("built", c.line, ""))
            elif c.from_stage < stage:
                for _how, line, _path in _in_stage(b, c.from_stage, rel, depth + 1, memo):
                    out.append(("built", line, ""))
            continue
        if c.from_stage is None:
            for pattern in c.sources:
                ok, under, member = _match(rel, pattern)
                if ok:
                    out.append(("copied", c.line, _dest(c, under, member)))
        elif c.from_stage < stage:
            for how, line, path in _in_stage(b, c.from_stage, rel, depth + 1, memo):
                if how == "copied" and path and _covers(c.sources, path):
                    src_root = next(posixpath.normpath("/" + s.lstrip("/")) for s in c.sources if _covers((s,), path))
                    tail = path[len(src_root) :].lstrip("/") if src_root != "/" else path.lstrip("/")
                    landed = posixpath.normpath(posixpath.join(c.dest, tail)) if tail else c.dest
                    out.append(("copied", line, landed))
                else:
                    out.append(("built", line, ""))
    memo[stage] = list(dict.fromkeys(out))
    return memo[stage]


def where(builds: list[Build], path: str) -> list[Shipped]:
    """The images that ship a repository file, and how."""
    out: list[Shipped] = []
    for b in builds:
        prefix = (b.context + "/") if b.context else ""
        if prefix and not path.startswith(prefix):
            continue
        rel = path[len(prefix) :]
        if not rel or (b.rules and cf.ignored(rel, b.rules)):
            continue
        seen: set[tuple[str, int, str]] = set()
        for how, line, image_path in _in_stage(b, b.final, rel):
            key = (how, line, image_path)
            if key in seen:
                continue
            seen.add(key)
            out.append(Shipped(b.label, b.containerfile, how, line, image_path))
    copied = [s for s in out if s.how == "copied"]
    built = [s for s in out if s.how == "built" and not any(c.image == s.image for c in copied)]
    return copied + built


def source_of(b: Build, image_path: str) -> list[tuple[str, int]]:
    """Candidate repository files a path in the final image came from (the lockfiles and manifests a scanner read),
    through ``COPY`` from the context and ``COPY --from`` earlier stages: (repository path, line of the COPY that
    took it from the context). Without the file system a source without an extension may be a directory, so
    callers keep the candidates that exist in the repository."""
    found = _source_in(b, b.final, posixpath.normpath("/" + image_path.lstrip("/")), 0, {})
    keep = []
    for path, line in dict.fromkeys(found):
        rel = path[len(b.context) + 1 :] if b.context else path
        if not (b.rules and cf.ignored(rel, b.rules)):
            keep.append((path, line))
    return keep


def _stage_chain(b: Build, stage: int) -> list[int]:
    chain = [stage]
    base = b.stage_bases.get(stage)
    while base is not None and base not in chain:
        chain.append(base)
        base = b.stage_bases.get(base)
    return chain


def _source_in(
    b: Build, stage: int, target: str, depth: int, memo: dict[tuple[int, str], list[tuple[str, int]]]
) -> list[tuple[str, int]]:
    key = (stage, target)
    if key in memo:
        return memo[key]
    if depth > MAX_STAGES:
        return []
    memo[key] = []
    out: list[tuple[str, int]] = []
    stages = set(_stage_chain(b, stage))
    for c in b.copies:
        if c.stage not in stages or c.external or c.bind:
            continue
        if c.from_stage is not None:
            if target == c.dest or target.startswith(c.dest.rstrip("/") + "/"):
                tail = target[len(c.dest) :].lstrip("/")
                for s in c.sources:
                    src = posixpath.normpath("/" + s.lstrip("/"))
                    inner = posixpath.normpath(posixpath.join(src, tail)) if tail else src
                    out += _source_in(b, c.from_stage, inner, depth + 1, memo)
            continue
        for pattern in c.sources:
            glob = any(ch in pattern for ch in "*?[")
            if pattern == "." or (not glob and _looks_dir(pattern)):
                root = c.dest
                if target == root or target.startswith(root.rstrip("/") + "/"):
                    tail = target[len(root) :].lstrip("/")
                    if tail:
                        out.append((_repo(b, tail if pattern == "." else posixpath.join(pattern, tail)), c.line))
            if glob:
                name = posixpath.basename(target)
                if posixpath.dirname(target) == c.dest.rstrip("/") and fnmatch.fnmatchcase(
                    name, posixpath.basename(pattern)
                ):
                    out.append((_repo(b, posixpath.join(posixpath.dirname(pattern), name)), c.line))
            elif pattern != ".":
                landed = posixpath.join(c.dest, posixpath.basename(pattern)) if c.dest_is_dir else c.dest
                if target == posixpath.normpath(landed):
                    out.append((_repo(b, pattern), c.line))
    memo[key] = list(dict.fromkeys(out))
    return memo[key]


def _looks_dir(pattern: str) -> bool:
    """A COPY source without an extension is taken as a directory (``COPY src/ /app/src``, ``COPY app /srv``)."""
    return "." not in posixpath.basename(pattern) or pattern.endswith("/")


def _repo(b: Build, rel: str) -> str:
    return posixpath.normpath(posixpath.join(b.context, rel)) if b.context else rel
