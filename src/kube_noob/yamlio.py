"""Safe multi-document YAML loading with source line tracking.

Defences: input size cap, document count cap, alias/anchor expansion budget (billion-laughs), SafeLoader only.
Every parsed document keeps a map ``path tuple -> 1-based line`` so findings can point at exact lines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml

from kube_noob.errors import ManifestError

MAX_INPUT_BYTES = 5_000_000
MAX_DOCUMENTS = 1000
MAX_NODE_VISITS = 500_000

PathT = tuple[str | int, ...]


@dataclass
class Document:
    index: int
    data: Any
    lines: dict[PathT, int] = field(default_factory=dict)
    start_line: int = 1

    def line_for(self, path: PathT) -> int:
        """Best line for a path: exact match, else nearest existing ancestor, else doc start."""
        p = tuple(path)
        while p:
            if p in self.lines:
                return self.lines[p]
            p = p[:-1]
        return self.start_line

    @property
    def kind(self) -> str:
        return str(self.data.get("kind", "")) if isinstance(self.data, dict) else ""

    @property
    def api_version(self) -> str:
        return str(self.data.get("apiVersion", "")) if isinstance(self.data, dict) else ""

    @property
    def name(self) -> str:
        if isinstance(self.data, dict) and isinstance(self.data.get("metadata"), dict):
            return str(self.data["metadata"].get("name", ""))
        return ""

    @property
    def namespace(self) -> str | None:
        if isinstance(self.data, dict) and isinstance(self.data.get("metadata"), dict):
            ns = self.data["metadata"].get("namespace")
            return str(ns) if ns is not None else None
        return None

    def ref(self) -> str:
        ns = f"{self.namespace}/" if self.namespace else ""
        return f"{self.kind}/{ns}{self.name or '<unnamed>'}"


def _walk(node: yaml.Node, path: PathT, out: dict[PathT, int], budget: list[int], line: int | None = None) -> None:
    budget[0] -= 1
    if budget[0] < 0:
        raise ManifestError("YAML is too complex to process safely (node budget exceeded; possible alias/anchor bomb).")
    out.setdefault(path, line if line is not None else node.start_mark.line + 1)
    if isinstance(node, yaml.MappingNode):
        for key_node, value_node in node.value:
            key = key_node.value if isinstance(key_node, yaml.ScalarNode) else str(key_node.start_mark.line)
            _walk(value_node, (*path, key), out, budget, key_node.start_mark.line + 1)
    elif isinstance(node, yaml.SequenceNode):
        for i, child in enumerate(node.value):
            _walk(child, (*path, i), out, budget)


def load_documents(text: str) -> list[Document]:
    """Parse one or more YAML documents. Empty documents are skipped. ``List`` kinds are flattened."""
    if len(text.encode("utf-8", errors="replace")) > MAX_INPUT_BYTES:
        raise ManifestError(f"Input exceeds {MAX_INPUT_BYTES} bytes; split it into smaller files.")
    loader = yaml.SafeLoader(text)
    docs: list[Document] = []
    budget = [MAX_NODE_VISITS]
    try:
        while loader.check_node():
            node = loader.get_node()
            if node is None:
                continue
            lines: dict[PathT, int] = {}
            _walk(node, (), lines, budget)
            data = loader.construct_document(node)
            if data is None:
                continue
            if len(docs) >= MAX_DOCUMENTS:
                raise ManifestError(f"More than {MAX_DOCUMENTS} YAML documents; split the input.")
            docs.append(Document(index=len(docs), data=data, lines=lines, start_line=node.start_mark.line + 1))
    except yaml.YAMLError as exc:
        raise ManifestError(f"Invalid YAML: {exc}") from exc
    finally:
        loader.dispose()
    return _flatten_lists(docs)


def _flatten_lists(docs: list[Document]) -> list[Document]:
    out: list[Document] = []
    for d in docs:
        if isinstance(d.data, dict) and d.data.get("kind") == "List" and isinstance(d.data.get("items"), list):
            for i, item in enumerate(d.data["items"]):
                prefix: PathT = ("items", i)
                sub = {k[len(prefix) :]: v for k, v in d.lines.items() if k[: len(prefix)] == prefix}
                out.append(Document(index=len(out), data=item, lines=sub, start_line=d.line_for(prefix)))
        else:
            d.index = len(out)
            out.append(d)
    return out


class _Dumper(yaml.SafeDumper):
    pass


def _str_presenter(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_Dumper.add_representer(str, _str_presenter)


def dump_documents(objs: list[Any]) -> str:
    """Deterministic YAML: insertion order preserved, block style, ``---`` separated."""
    parts = [
        yaml.dump(o, Dumper=_Dumper, sort_keys=False, default_flow_style=False, width=120, allow_unicode=True)
        for o in objs
    ]
    return "---\n" + "---\n".join(parts)


def get_path(data: Any, path: PathT) -> Any:
    cur = data
    for p in path:
        if isinstance(p, int):
            if not isinstance(cur, list) or p >= len(cur):
                return None
            cur = cur[p]
        else:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(p)
    return cur


def fmt_path(path: PathT) -> str:
    s = ""
    for p in path:
        s += f"[{p}]" if isinstance(p, int) else (f".{p}" if s else str(p))
    return s
