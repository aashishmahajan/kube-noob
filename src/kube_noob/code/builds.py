"""Build descriptions from ``PATH[=IMAGE][,context=DIR][,target=STAGE]`` specs, resolved against the repository.

Shared by ``code report -c`` and ``gate --containerfile`` so both read a build the same way:

- the Containerfile and the context may be given relative to the repository or as absolute paths inside it; both
  become repository-relative (an absolute context matched no SARIF path and marked everything "not shipped");
- the context defaults to the Containerfile's directory (``docker build -f deploy/Containerfile .`` needs
  ``context=.``);
- the ignore file is ``<Containerfile path>.dockerignore`` when it exists (BuildKit reads it in place of the
  context's, moby/buildkit ``frontend/dockerui/config.go``), else the context's ``.containerignore`` or
  ``.dockerignore``; links are never followed;
- files are decoded as UTF-8 with a leading byte order mark dropped, as BuildKit does (``discardBOM``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from kube_noob.code import ship

SPEC = re.compile(r"^(?P<path>[^=,]{1,500})(?:=(?P<image>[^,]{1,500}))?(?P<opts>(?:,[a-z]{1,10}=[^,]{1,500})*)$")
MAX_CONTAINERFILE_BYTES = 1_000_000
MAX_IGNORE_BYTES = 1_000_000
CONTEXT_IGNORE_NAMES = (".containerignore", ".dockerignore")


class BuildSpecError(ValueError):
    """A build spec that cannot be read: bad form, no such file, or outside the repository."""


@dataclass(frozen=True)
class Spec:
    path: str
    image: str = ""
    context: str | None = None
    target: str = ""


def parse_spec(spec: str, repo: Path) -> Spec:
    text = spec.strip()
    if text and (repo / text).is_file():  # a path that itself holds "=" or ","
        return Spec(text)
    m = SPEC.match(text)
    if not m:
        raise BuildSpecError(f"{spec!r}: expected PATH[=IMAGE][,context=DIR][,target=STAGE]")
    opts = dict(o.split("=", 1) for o in m.group("opts").split(",") if o)
    unknown = sorted(set(opts) - {"context", "target"})
    if unknown:
        raise BuildSpecError(f"{spec!r}: unknown option {', '.join(unknown)} (context, target)")
    return Spec(m.group("path").strip(), (m.group("image") or "").strip(), opts.get("context"), opts.get("target", ""))


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _within(given: str, repo_root: Path, what: str) -> tuple[Path, str]:
    full = (repo_root / given).resolve()  # an absolute ``given`` replaces the root
    if not _inside(full, repo_root):
        raise BuildSpecError(f"{what} {given!r} is outside the repository {repo_root}")
    return full, (full.relative_to(repo_root).as_posix() or ".")


def read_text(path: Path, limit: int) -> str:
    with path.open("rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise BuildSpecError(f"{path.name}: larger than {limit} bytes")
    return data.decode("utf-8-sig", errors="replace")


def ignore_for(containerfile: Path, context: Path) -> tuple[str, str]:
    """(ignore file text, its name) for a build: the Containerfile's own ``.dockerignore`` first."""
    for f in (
        containerfile.with_name(containerfile.name + ".dockerignore"),
        *(context / n for n in CONTEXT_IGNORE_NAMES),
    ):
        if f.is_file() and not f.is_symlink():
            return read_text(f, MAX_IGNORE_BYTES)[:MAX_IGNORE_BYTES], f.name
    return "", ""


def load_one(spec: str, repo: Path) -> ship.Build:
    root = repo.resolve()
    s = parse_spec(spec, repo)
    full, rel = _within(s.path, root, "Containerfile")
    if not full.is_file():
        raise BuildSpecError(f"{s.path}: no such Containerfile in {repo}")
    ctx_full, ctx_rel = _within(s.context if s.context is not None else str(full.parent), root, "context")
    if not ctx_full.is_dir():
        raise BuildSpecError(f"{s.path}: context {s.context!r} is not a directory")
    ignore, _ = ignore_for(full, ctx_full)
    try:
        return ship.parse_build(
            ship.Build(rel, read_text(full, MAX_CONTAINERFILE_BYTES), s.image, ctx_rel, ignore, s.target)
        )
    except ship.ShipError as exc:
        raise BuildSpecError(str(exc)) from exc


def load(specs: list[str], repo: Path) -> list[ship.Build]:
    return [load_one(spec, repo) for spec in specs]
