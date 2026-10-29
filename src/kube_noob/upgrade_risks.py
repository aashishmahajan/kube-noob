"""Known risks for an OpenShift update, from the public update graph, evaluated offline (backlog UPG1).

OpenShift "conditional updates" attach known risks to update edges. Red Hat's update service, and a local OpenShift
Update Service in a disconnected site, serve them from github.com/openshift/cincinnati-graph-data
``blocked-edges/*.yaml``. kube-noob bundles a snapshot of the entries whose target is OpenShift 4.18 or later
(``kube_noob/data/upgrade_risks/``, refreshed with ``scripts/vendor_upgrade_risks.py``) and answers "which known risks
are declared for updating from A to B, and can each be checked from what I have?" with no network.

Semantics, checked on 2026-10-29 against these sources (the URL is the citation):

- The fields ``to``, ``from``, ``url``, ``name``, ``message``, ``fixedIn`` and ``matchingRules``: cincinnati-graph-data
  README.md, "Block Edges", at commit 7572174a551561c30e07e9b5ca6f156ef5cd513c,
  https://github.com/openshift/cincinnati-graph-data/blob/7572174a551561c30e07e9b5ca6f156ef5cd513c/README.md
- ``from`` is a regular expression applied with Rust's ``Regex::is_match``, which is unanchored (a match anywhere
  counts unless the pattern has ``^`` and ``$``), to the source release's version with its architecture build suffix
  (``4.20.3+amd64``): ``add_conditional_edges`` in
  https://github.com/openshift/cincinnati/blob/0e1d9356b52d3acee72fa7ec30c324cc02115166/cincinnati/src/plugins/internal/edge_add_remove.rs
  and the README ("Release version strings will receive the architecture-suffix before being compared"). The
  architectures are amd64 (the default), arm64, ppc64le, s390x and multi (``release_scrape_dockerv2/registry/mod.rs``
  in the same commit). So ``4[.]18[.].*`` covers 4.18.3, and ``^4[.]18[.]1[6-8][+].*$`` covers neither 4.18.1 nor
  4.18.160: a full match of the bare version would miss real risks, a prefix test would invent them.
- ``matchingRules`` are walked in order: an unrecognised type, or a rule that fails to evaluate, passes to the next;
  the first that evaluates decides; when none does, the update is not recommended. ``Always`` always matches;
  ``PromQL`` returns 1 (the risk matches) or 0 (it does not): enhancements/update/targeted-update-edge-blocking.md at
  https://github.com/openshift/enhancements/blob/d74f27b2fba2c05689aa50e1ffed2c517bdc7416/enhancements/update/targeted-update-edge-blocking.md
  The cluster-version operator runs the query against the in-cluster Thanos querier and accepts exactly one sample of
  0 or 1: pkg/clusterconditions/promql/promql.go in openshift/cluster-version-operator at
  1eeb46148a6eabdee90ccd3dabf26646476b0fcf; ``oc adm upgrade --include-not-recommended`` lists the not-recommended
  updates (pkg/cli/admin/upgrade/upgrade.go in openshift/oc at 027bf0b05d713f85d6fc4674ff2e076684538a74).

Verdicts: ``applies`` (``type: Always``), ``check`` (a PromQL query of a shape kube-noob translates into one fact
about the cluster, with the read-only command or must-gather file that shows it) and ``cannot evaluate offline``
(any other query, shown as written). The facts, from the code that emits each metric:

- ``cluster_installer`` ``invoker``: ``gaugeFromInstallConfigMap`` in pkg/cvo/metrics.go and pkg/internal/constants.go
  (cluster-version-operator, commit above): key ``invoker`` of ConfigMap ``openshift-install``, or of
  ``openshift-install-manifests`` when the first does not exist, in namespace ``openshift-config``.
- ``cluster_infrastructure_provider`` ``type``: pkg/operator/configmetrics/configmetrics.go in
  openshift/cluster-kube-apiserver-operator at acb844b0be5fa6c0f92b7455ef6354fc120b85de: ``status.platformStatus.type``
  of Infrastructure ``cluster``; the values are ``PlatformType`` in config/v1/types_infrastructure.go of openshift/api
  at 7ecc11c5c1b6594f9a79c665c6596392d88dd25a.
- ``cluster_operator_conditions`` ``name``: pkg/cvo/metrics.go (a series for each True or False condition of each
  ClusterOperator).
- ``cluster_version_capability`` ``name``: pkg/cvo/metrics.go (1 enabled, 0 known but disabled) and ClusterVersion
  ``status.capabilities.enabledCapabilities`` (openshift/api config/v1/types_cluster_version.go).
- ``kube_node_labels``: kube-state-metrics internal/store/utils.go at c201f14480266be82e76ef0150fb8e0c9ff88b3a names a
  label ``label_`` plus the key with every character outside [a-zA-Z0-9_] replaced by ``_``. That cannot be reversed in
  general, so only two keys are read back: ``kubernetes.io/arch`` (core/v1/well_known_labels.go in kubernetes/api at
  65c5b9edb29b2c7673be20c8eed03afb5cfa32f9) and ``node.openshift.io/os_id`` (the kubelet units of
  openshift/machine-config-operator at 1d6d6726f5967471cc02b72cec1d28b86fc6e0bd pass
  ``--node-labels=...node.openshift.io/os_id=${ID}``).
- ``ovnkube_clustermanager_num_egress_ips``: go-controller/pkg/metrics/cluster_manager.go and
  pkg/clustermanager/egressip_controller.go (``getAllocationTotalCount``, the egress IPs allocated to nodes) in
  ovn-kubernetes at 5e2695008e99eac0a5ceaf74806086041f32e192; ``oc get egressips.k8s.ovn.org`` shows them in its
  Assigned EgressIPs column (crd/egressip/v1/types.go).

A query is translated only when its tokens equal one of ``_SHAPES`` token for token, values aside, and every value
passes a strict check (a known platform type, a Kubernetes name, a plain label value). Anything else, a near miss
included, is ``cannot evaluate offline`` with the query as written: kube-noob never guesses what a query means. Note
that ``type="AWS|GCP"`` is an exact match in PromQL and no platform type has that value, so it is not translated.

``from`` is data from outside and never reaches Python's backtracking ``re``. ``compile_from`` parses a subset of the
syntax (literals, ``.``, classes with ranges, ``\\d``, groups, alternation, ``* + ? {m} {m,} {m,n}`` up to
MAX_REPEAT, ``^``, ``$``; at most MAX_PATTERN characters) into a Thompson automaton of at most MAX_STATES states and
simulates it, so a match costs at most (input length x states) steps whatever the pattern. Look-around,
back-references, flags, word boundaries and anything else are refused, and such a risk is listed as ``cannot evaluate
offline`` with the reason. Versions are x.y.z only, validated with a ``\\Z``-anchored expression.
"""

from __future__ import annotations

import functools
import json
import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import resources
from typing import Any

ARCHITECTURES = ("amd64", "arm64", "multi", "ppc64le", "s390x")
VERDICTS = ("applies", "check", "cannot evaluate offline")
SOURCE = "https://github.com/openshift/cincinnati-graph-data"
MIN_TARGET = "4.18"
MAX_PATTERN = 256  # characters in a `from` pattern
MAX_REPEAT = 20  # largest bound in a counted repetition
MAX_STATES = 2_000  # automaton states for one pattern
MAX_DEPTH = 20  # nested groups
MAX_PROMQL = 4_000  # characters in a query kube-noob tries to translate
MAX_RULES = 20  # matchingRules read per risk
MAX_VERSION = 20

_VERSION = re.compile(r"(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,5})\Z")
_PLAIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?\Z")  # a label value
_K8S_NAME = re.compile(r"[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?\Z")
_CAPABILITY = re.compile(r"[A-Za-z][A-Za-z0-9]{0,62}\Z")
_COUNTED = re.compile(r"([0-9]{1,6})(?:(,)([0-9]{0,6}))?\}")
_PROMQL_TOKEN = re.compile(  # strings (double-quoted, kept with their quotes), numbers, names, operators
    r'\s*(?:"(?:[^"\\\n]|\\.){0,512}"|[0-9]+(?:\.[0-9]+)?|[A-Za-z_:][A-Za-z0-9_:]*'
    r"|=~|!~|!=|==|>=|<=|[=<>*/+%^(){}\[\],-])"
)
PLATFORM_TYPES = frozenset(
    {
        "AWS",
        "Azure",
        "BareMetal",
        "GCP",
        "Libvirt",
        "OpenStack",
        "None",
        "VSphere",
        "oVirt",
        "IBMCloud",
        "KubeVirt",
        "EquinixMetal",
        "PowerVS",
        "AlibabaCloud",
        "Nutanix",
        "External",
    }
)
NODE_LABELS = {
    "label_kubernetes_io_arch": "kubernetes.io/arch",
    "label_node_openshift_io_os_id": "node.openshift.io/os_id",
}
CANNOT_EVALUATE = (
    "kube-noob translates only a few simple PromQL shapes and this is not one of them, so it is shown as written. On "
    "the cluster, the cluster-version operator runs it against the in-cluster Thanos querier: 1 means the risk "
    "matches, 0 that it does not; `oc adm upgrade --include-not-recommended` shows the verdict when the cluster can "
    "reach an update service."
)
VERDICTS_MEAN = {
    "applies": "declared for every cluster making this update (type: Always)",
    "check": "decided by one fact about the cluster: read it with the read-only command or must-gather file given",
    "cannot evaluate offline": "decided by a PromQL query kube-noob does not translate; the query is shown as written",
}


class PatternError(ValueError):
    """A ``from`` pattern outside the subset kube-noob evaluates."""


def parse_version(version: str) -> tuple[int, int, int]:
    """(x, y, z) of an x.y.z release version; anything else raises ValueError."""
    m = _VERSION.match(version) if isinstance(version, str) and len(version) <= MAX_VERSION else None
    if not m:
        shown = version[:MAX_VERSION] if isinstance(version, str) else type(version).__name__
        raise ValueError(f"{shown!r} is not an OpenShift release version x.y.z (for example 4.20.3)")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _vkey(version: str) -> tuple[int, ...]:
    try:
        return parse_version(version)
    except ValueError:
        return (10**9,)


# ---------------------------------------------------------------- the `from` pattern: a linear-time subset


@dataclass(frozen=True)
class _Set:
    ranges: tuple[tuple[str, str], ...]
    negated: bool = False

    def has(self, ch: str) -> bool:
        return any(lo <= ch <= hi for lo, hi in self.ranges) != self.negated


_ANY = _Set((("\n", "\n"),), negated=True)  # `.` matches anything but a newline, as in Rust and Python
_DIGIT = _Set((("0", "9"),))
_ESCAPABLE = frozenset(".^$*+?()[]{}|\\-/")
_QUANTIFIERS = frozenset("*+?{")
_Node = tuple[Any, ...]


class _Parser:
    def __init__(self, pattern: str) -> None:
        self.p = pattern
        self.i = 0
        self.depth = 0

    def parse(self) -> _Node:
        node = self._alt()
        if self.i != len(self.p):
            raise PatternError(f"unexpected {self.p[self.i]!r} at offset {self.i}")
        return node

    def _peek(self) -> str:
        return self.p[self.i] if self.i < len(self.p) else ""

    def _alt(self) -> _Node:
        branches = [self._cat()]
        while self._peek() == "|":
            self.i += 1
            branches.append(self._cat())
        return branches[0] if len(branches) == 1 else ("alt", tuple(branches))

    def _cat(self) -> _Node:
        items: list[_Node] = []
        while self.i < len(self.p) and self.p[self.i] not in "|)":
            items.append(self._repeat())
        return items[0] if len(items) == 1 else ("cat", tuple(items))

    def _repeat(self) -> _Node:
        atom = self._atom()
        if self._peek() and self._peek() in _QUANTIFIERS:
            if atom[0] in {"bol", "eol"}:
                raise PatternError("a quantifier on an anchor")
            lo, hi = self._quantifier()
            if self._peek() == "?":  # lazy: the same yes or no answer
                self.i += 1
            if self._peek() and self._peek() in _QUANTIFIERS:
                raise PatternError("a quantifier on a quantifier")
            atom = ("rep", atom, lo, hi)
        return atom

    def _quantifier(self) -> tuple[int, int | None]:
        c = self.p[self.i]
        self.i += 1
        if c in "*+?":
            return {"*": (0, None), "+": (1, None), "?": (0, 1)}[c]
        m = _COUNTED.match(self.p, self.i)
        if not m:
            raise PatternError("a '{' that does not start a counted repetition")
        self.i = m.end()
        lo = int(m.group(1))
        hi = lo if m.group(2) is None else (int(m.group(3)) if m.group(3) else None)
        if lo > MAX_REPEAT or (hi is not None and (hi > MAX_REPEAT or hi < lo)):
            raise PatternError(f"a counted repetition beyond {MAX_REPEAT} or with its bounds reversed")
        return lo, hi

    def _atom(self) -> _Node:
        c = self.p[self.i]
        if c == "(":
            self.i += 1
            if self.p.startswith("?:", self.i):
                self.i += 2
            elif self._peek() == "?":
                raise PatternError("look-around, inline flags and named groups are not supported")
            self.depth += 1
            if self.depth > MAX_DEPTH:
                raise PatternError(f"groups nested deeper than {MAX_DEPTH}")
            node = self._alt()
            if self._peek() != ")":
                raise PatternError("an unbalanced '('")
            self.i += 1
            self.depth -= 1
            return node
        if c == "[":
            return ("set", self._class())
        if c == "\\":
            e = self._escape(in_class=False)
            return ("set", _DIGIT if e is None else _Set(((e, e),)))
        self.i += 1
        if c == ".":
            return ("set", _ANY)
        if c == "^":
            return ("bol",)
        if c == "$":
            return ("eol",)
        if c in _QUANTIFIERS:
            raise PatternError("a quantifier with nothing to repeat")
        if c in "]}":
            raise PatternError(f"a bare {c!r}")
        return ("set", _Set(((c, c),)))

    def _escape(self, in_class: bool) -> str | None:
        """The character an escape stands for, or None for ``\\d``."""
        if self.i + 1 >= len(self.p):
            raise PatternError("a trailing backslash")
        e = self.p[self.i + 1]
        self.i += 2
        if e == "d":
            return None
        if e in _ESCAPABLE:
            return e
        raise PatternError(f"the escape \\{e} is not supported" + (" in a class" if in_class else ""))

    def _class(self) -> _Set:
        self.i += 1
        negated = self._peek() == "^"
        if negated:
            self.i += 1
        ranges: list[tuple[str, str]] = []
        first = True
        while True:
            if self.i >= len(self.p):
                raise PatternError("an unbalanced '['")
            c = self.p[self.i]
            if c == "]" and not first:
                self.i += 1
                return _Set(tuple(ranges), negated)
            first = False
            if c == "[":
                raise PatternError("nested and POSIX classes are not supported")
            if c in "&~-" and self.p.startswith(c * 2, self.i):
                raise PatternError("class set operations are not supported")
            lo = self._escape(in_class=True) if c == "\\" else self._take()
            ranged = self._peek() == "-" and self.i + 1 < len(self.p) and self.p[self.i + 1] != "]"
            if lo is None:
                if ranged:
                    raise PatternError("a range from \\d")
                ranges.append(("0", "9"))
                continue
            if not ranged:
                ranges.append((lo, lo))
                continue
            self.i += 1
            hi = self._escape(in_class=True) if self._peek() == "\\" else self._take()
            if hi is None or hi < lo:
                raise PatternError("a reversed or invalid range")
            ranges.append((lo, hi))

    def _take(self) -> str:
        c = self.p[self.i]
        self.i += 1
        return c


_CHAR, _SPLIT, _BOL, _EOL, _MATCH = range(5)


class SafeRegex:
    """A ``from`` pattern compiled to a Thompson automaton; ``search`` is linear in the input."""

    def __init__(self, pattern: str) -> None:
        if len(pattern) > MAX_PATTERN:
            raise PatternError(f"longer than {MAX_PATTERN} characters")
        tree = _Parser(pattern).parse()
        self.pattern = pattern
        self._kind: list[int] = []
        self._next: list[int] = []
        self._alt: list[int] = []
        self._set: list[_Set] = []
        self._match = self._add(_MATCH)
        self._start = self._build(tree, self._match)

    def _add(self, kind: int, nxt: int = -1, alt: int = -1, chars: _Set = _ANY) -> int:
        if len(self._kind) >= MAX_STATES:
            raise PatternError(f"the pattern needs more than {MAX_STATES} automaton states")
        self._kind.append(kind)
        self._next.append(nxt)
        self._alt.append(alt)
        self._set.append(chars)
        return len(self._kind) - 1

    def _build(self, node: _Node, nxt: int) -> int:
        """States that match ``node`` and continue at ``nxt``; built back to front."""
        tag = node[0]
        if tag == "set":
            return self._add(_CHAR, nxt, chars=node[1])
        if tag == "bol":
            return self._add(_BOL, nxt)
        if tag == "eol":
            return self._add(_EOL, nxt)
        if tag == "cat":
            for child in reversed(node[1]):
                nxt = self._build(child, nxt)
            return nxt
        if tag == "alt":
            starts = [self._build(child, nxt) for child in node[1]]
            state = starts[-1]
            for start in reversed(starts[:-1]):
                state = self._add(_SPLIT, start, state)
            return state
        _, child, lo, hi = node
        if hi is None:
            loop = self._add(_SPLIT, -1, nxt)
            self._next[loop] = self._build(child, loop)
            tail = loop
        else:
            tail = nxt
            for _ in range(hi - lo):
                tail = self._add(_SPLIT, self._build(child, tail), nxt)
        for _ in range(lo):
            tail = self._build(child, tail)
        return tail

    def _closure(self, states: Iterable[int], pos: int, end: int) -> set[int]:
        out: set[int] = set()
        stack = list(states)
        while stack:
            s = stack.pop()
            if s in out:
                continue
            out.add(s)
            kind = self._kind[s]
            if kind == _SPLIT:
                stack += (self._next[s], self._alt[s])
            elif (kind == _BOL and pos == 0) or (kind == _EOL and pos == end):
                stack.append(self._next[s])
        return out

    def search(self, text: str) -> bool:
        """Whether the pattern matches anywhere in ``text`` (Rust ``Regex::is_match``)."""
        end = len(text)
        current = self._closure([self._start], 0, end)
        for pos, ch in enumerate(text):
            if self._match in current:
                return True
            moved = [self._next[s] for s in current if self._kind[s] == _CHAR and self._set[s].has(ch)]
            current = self._closure([*moved, self._start], pos + 1, end)
        return self._match in current


@functools.lru_cache(maxsize=2048)
def _compiled(pattern: str) -> SafeRegex:
    return SafeRegex(pattern)


def compile_from(pattern: str) -> SafeRegex:
    """A ``from`` pattern compiled for linear-time search; PatternError when it is outside the subset."""
    if not isinstance(pattern, str) or len(pattern) > MAX_PATTERN:
        raise PatternError(f"not a string of at most {MAX_PATTERN} characters")
    return _compiled(pattern)


# ---------------------------------------------------------------- PromQL shapes kube-noob translates

_HOLE = '"$1"'  # in a shape, where the value goes; every hole in one shape takes the same value


@dataclass(frozen=True)
class _Shape:
    tokens: tuple[str, ...]
    fact: str
    op: str
    label: str = ""


def _tokens(text: str) -> list[str] | None:
    """PromQL as tokens (strings keep their quotes), or None when it holds anything the tokenizer does not know."""
    out: list[str] = []
    pos = 0
    while pos < len(text):
        m = _PROMQL_TOKEN.match(text, pos)
        if not m:
            return out if not text[pos:].strip() else None
        out.append(m.group(0).strip())
        pos = m.end()
    return out


@functools.cache
def _shapes() -> tuple[_Shape, ...]:
    installer = "cluster_installer"
    provider = "cluster_infrastructure_provider"
    conditions = "cluster_operator_conditions"
    egress = "ovnkube_clustermanager_num_egress_ips"
    texts: list[tuple[str, str, str, str]] = [
        (
            f'group by (_id, invoker) ({installer}{{_id="",invoker="$1"}}) or 0 * group by (_id, invoker) '
            f'({installer}{{_id=""}})',
            "installer",
            "is",
            "",
        ),
        (
            f'0 * group by (_id, invoker) ({installer}{{_id="",invoker="$1"}}) or group by (_id, invoker) '
            f'({installer}{{_id=""}})',
            "installer",
            "is not",
            "",
        ),
        (
            f'0 * group by (invoker) ({installer}{{_id="",invoker="$1"}}) or on () group by (invoker) '
            f'({installer}{{_id=""}})',
            "installer",
            "is not",
            "",
        ),
        (
            f'( group by (type) ({provider}{{_id="",type="$1"}}) or 0 * group by (type) ({provider}{{_id=""}}) )',
            "platform",
            "is",
            "",
        ),
        (f'group({provider}{{type=~"$1"}}) or 0 * group({provider})', "platform", "in", ""),
        (
            f'topk by (_id) (1, group by (_id, type) ({provider}{{_id="",type=~"$1"}}) or 0 * group by (_id, type) '
            f'({provider}{{_id="",type!~"$1"}}) )',
            "platform",
            "in",
            "",
        ),
        (
            f'topk(1, group by (_id, name) ({conditions}{{_id="",name="$1"}}) or 0 * group by (_id, name) '
            f'({conditions}{{_id=""}}) )',
            "operator",
            "exists",
            "",
        ),
        (f'group({conditions}{{_id="",name="$1"}}) or 0 * group({conditions}{{_id=""}})', "operator", "exists", ""),
        (f'group({egress}{{_id=""}} > 0) or 0 * group({egress}{{_id=""}})', "egress", "any", ""),
        ('max(cluster_version_capability{name="$1"})', "capability", "enabled", ""),
    ]
    for metric_label, key in NODE_LABELS.items():
        texts.append(
            (
                f'topk(1, group by ({metric_label}) (kube_node_labels{{_id="",{metric_label}="$1"}}) or 0 * group by '
                f'({metric_label}) (kube_node_labels{{_id=""}}) )',
                "node_label",
                "has",
                key,
            )
        )
    shapes = []
    for text, fact, op, label in texts:
        tokens = _tokens(text)
        assert tokens, text  # noqa: S101 - the shapes are constants
        shapes.append(_Shape(tuple(tokens), fact, op, label))
    return tuple(shapes)


def _value(tokens: list[str], shape: _Shape) -> str | None:
    """The value in the hole when ``tokens`` are ``shape``, else None."""
    if len(tokens) != len(shape.tokens):
        return None
    value: str | None = None
    for got, want in zip(tokens, shape.tokens, strict=True):
        if want == _HOLE:
            if not got.startswith('"') or "\\" in got:
                return None
            if value is not None and value != got[1:-1]:
                return None
            value = got[1:-1]
        elif got != want:
            return None
    return "" if value is None else value


def _installer(value: str, op: str) -> dict[str, Any] | None:
    if not _PLAIN.match(value):
        return None
    hcp = " (hosted control planes)" if value == "hypershift" else ""
    return {
        "decidedBy": "the installer's invoker: key `invoker` of ConfigMap openshift-install in namespace "
        "openshift-config, or of openshift-install-manifests when openshift-install does not exist (what the "
        "cluster-version operator reports as cluster_installer)",
        "appliesWhen": f'the invoker is {"not " if op == "is not" else ""}"{value}"{hcp}',
        "readOnlyCommands": [
            f"oc get configmap {name} -n openshift-config -o jsonpath='{{.data.invoker}}'"
            for name in ("openshift-install", "openshift-install-manifests")
        ],
    }


def _platform(value: str, op: str) -> dict[str, Any] | None:
    values = list(dict.fromkeys(value.split("|"))) if op == "in" else [value]
    if not all(v in PLATFORM_TYPES for v in values):
        return None
    return {
        "decidedBy": "the platform type: status.platformStatus.type of Infrastructure cluster (what "
        "cluster_infrastructure_provider reports)",
        "appliesWhen": "the platform type is " + " or ".join(values),
        "readOnlyCommands": ["oc get infrastructure cluster -o jsonpath='{.status.platformStatus.type}'"],
        "mustGather": ["cluster-scoped-resources/config.openshift.io/infrastructures/cluster.yaml"],
    }


def _fact(shape: _Shape, value: str) -> dict[str, Any] | None:
    """What decides the query, in words, and how to read it; None when the value is not one kube-noob can vouch for."""
    if shape.fact == "installer":
        return _installer(value, shape.op)
    if shape.fact == "platform":
        return _platform(value, shape.op)
    if shape.fact == "operator" and _K8S_NAME.match(value):
        return {
            "decidedBy": f"whether ClusterOperator {value} exists (cluster_operator_conditions has a series for each "
            "of its True or False conditions)",
            "appliesWhen": f"ClusterOperator {value} exists",
            "readOnlyCommands": [f"oc get clusteroperator {value}"],
            "mustGather": [f"cluster-scoped-resources/config.openshift.io/clusteroperators/{value}.yaml"],
        }
    if shape.fact == "capability" and _CAPABILITY.match(value):
        return {
            "decidedBy": f"whether the {value} capability is enabled: status.capabilities.enabledCapabilities of "
            "ClusterVersion version (cluster_version_capability is 1 when enabled, 0 when known but disabled)",
            "appliesWhen": f"the {value} capability is enabled",
            "readOnlyCommands": [
                "oc get clusterversion version -o jsonpath='{.status.capabilities.enabledCapabilities}'"
            ],
            "mustGather": ["cluster-scoped-resources/config.openshift.io/clusterversions/version.yaml"],
        }
    if shape.fact == "node_label" and _PLAIN.match(value):
        return {
            "decidedBy": f"the {shape.label} label of the nodes (kube_node_labels)",
            "appliesWhen": f"at least one node has {shape.label}={value}",
            "readOnlyCommands": [f"oc get nodes -l {shape.label}={value}"],
            "mustGather": ["cluster-scoped-resources/core/nodes/"],
        }
    if shape.fact == "egress" and value == "":
        return {
            "decidedBy": "whether OVN-Kubernetes has assigned an egress IP to a node (ovnkube_clustermanager_num_"
            "egress_ips counts the assignments, listed in each EgressIP's status.items)",
            "appliesWhen": "at least one egress IP is assigned to a node",
            "readOnlyCommands": ["oc get egressips.k8s.ovn.org"],
        }
    return None


def translate(promql: str) -> dict[str, Any] | None:
    """The one fact a query decides on and how to read it, or None when the query is not a shape kube-noob knows."""
    if not isinstance(promql, str) or len(promql) > MAX_PROMQL:
        return None
    tokens = _tokens(promql)
    if not tokens:
        return None
    for shape in _shapes():
        value = _value(tokens, shape)
        if value is not None:
            fact = _fact(shape, value)
            if fact:
                return fact
    return None


def evaluate(rules: Any) -> dict[str, Any]:
    """The verdict for a risk's ``matchingRules``, walked as the cluster walks them."""
    if not isinstance(rules, list) or not rules:
        return {
            "verdict": "applies",
            "reason": "A blocked edge without matchingRules: the update service drops it for every cluster.",
        }
    for n, rule in enumerate(rules[:MAX_RULES]):
        kind = rule.get("type") if isinstance(rule, dict) else None
        rest = rules[n + 1 : MAX_RULES]
        out: dict[str, Any]
        if kind == "Always":
            return {"verdict": "applies", "reason": "Declared for every cluster making this update (type: Always)."}
        if kind == "PromQL":
            body = rule.get("promql")
            promql = body.get("promql") if isinstance(body, dict) else None
            if not isinstance(promql, str):
                continue  # fails to evaluate on the cluster too: the next rule decides
            fact = translate(promql)
            out = (
                {"verdict": "check", **fact, "promql": promql}
                if fact
                else {"verdict": "cannot evaluate offline", "reason": CANNOT_EVALUATE, "promql": promql}
            )
        elif kind == "Fleet":
            out = {
                "verdict": "cannot evaluate offline",
                "reason": "A Fleet rule: it depends on the fleet the cluster belongs to, which kube-noob cannot tell.",
                "rule": rule,
            }
        else:
            continue  # a type the cluster does not recognise is skipped
        if rest:
            out["otherRules"] = rest  # read by the cluster only when this rule cannot be evaluated there
        return out
    return {
        "verdict": "applies",
        "reason": "No rule of a type the cluster can evaluate: such an update is not recommended.",
    }


# ---------------------------------------------------------------- the index


class Index:
    def __init__(self, records: list[dict[str, Any]], meta: dict[str, Any]) -> None:
        self.meta = meta
        self.records = sorted(records, key=lambda r: (_vkey(str(r.get("to"))), str(r.get("source"))))
        self._by_target: dict[str, list[dict[str, Any]]] = {}
        for r in self.records:
            self._by_target.setdefault(str(r.get("to")), []).append(r)
        targets = [_vkey(t) for t in self._by_target if _VERSION.match(t)]
        self._newest = max(targets) if targets else None

    def knowledge(self) -> dict[str, Any]:
        scope = self.meta.get("scope") or {}
        return {
            "upgradeRisksAsOf": self.meta.get("retrievedAt"),
            "source": self.meta.get("source", SOURCE),
            "commit": self.meta.get("commit"),
            "commitDate": self.meta.get("commitDate"),
            "minTarget": scope.get("minTarget", MIN_TARGET),
            "newestTarget": ".".join(str(p) for p in self._newest) if self._newest else None,
            "targets": len(self._by_target),
            "risks": len(self.records),
        }

    def _risk(
        self, r: dict[str, Any], current: str, arches: tuple[str, ...], arch: str | None
    ) -> dict[str, Any] | None:
        frm = str(r.get("from", ""))
        head: dict[str, Any] = {"name": r.get("name")}
        tail: dict[str, Any] = {"message": r.get("message"), "url": r.get("url")}
        if r.get("fixedIn"):
            tail["fixedIn"] = r["fixedIn"]
        tail["from"] = frm if len(frm) <= MAX_PATTERN else frm[:MAX_PATTERN] + "..."
        tail["source"] = f"{SOURCE}/blob/{self.meta.get('commit') or 'master'}/{r.get('source')}"
        try:
            rx = compile_from(frm)
        except PatternError as exc:
            return {
                **head,
                "verdict": "cannot evaluate offline",
                "fromEvaluated": False,
                "reason": f"The 'from' pattern is outside the regular-expression subset kube-noob evaluates safely "
                f"({exc}), so whether this risk covers {current} is not known: read the pattern and the message.",
                **tail,
            }
        matched = [a for a in arches if rx.search(f"{current}+{a}")]
        if not matched:
            return None
        risk = {**head, **evaluate(r.get("matchingRules")), **tail}
        if arch is None and len(matched) < len(ARCHITECTURES):
            risk["architectures"] = matched
        return risk

    def risks(self, current: str, target: str, arch: str | None = None) -> dict[str, Any]:
        """Every risk declared for the update from ``current`` to ``target`` (x.y.z), with its verdict."""
        cur, tgt = parse_version(current), parse_version(target)
        if tgt <= cur:
            raise ValueError(f"the target {target} is not newer than {current}: updates go to a newer version")
        if arch is not None and arch not in ARCHITECTURES:
            raise ValueError(f"unknown architecture {arch[:20]!r}; one of {', '.join(ARCHITECTURES)}")
        k = self.knowledge()
        arches = (arch,) if arch else ARCHITECTURES
        found = [x for x in (self._risk(r, current, arches, arch) for r in self._by_target.get(target, [])) if x]
        found.sort(key=lambda x: (VERDICTS.index(x["verdict"]), str(x.get("name")), x["source"]))
        counts = {v: sum(1 for x in found if x["verdict"] == v) for v in VERDICTS}
        commit = str(k["commit"] or "")[:12]
        min_target = _vkey(f"{k['minTarget']}.0")
        out: dict[str, Any] = {
            "edge": {"from": current, "to": target, "architecture": arch},
            "risks": found,
            "counts": counts,
            "covered": True,
            "verdictsMean": VERDICTS_MEAN,
            "knowledge": k,
            "channelNote": "kube-noob bundles the risk declarations (blocked-edges), not the channels: it does not "
            f"check that {target} is offered from {current} in your channel.",
        }
        if tgt[:2] < min_target[:2]:
            out["covered"] = False
            out["note"] = (
                f"The snapshot holds risks for update targets in OpenShift {k['minTarget']} and later; {target} is "
                "older, so it was not looked up."
            )
        elif self._newest and tgt > self._newest:
            out["covered"] = False
            out["note"] = (
                f"{target} is newer than every target in this snapshot (newest {k['newestTarget']}); risks declared "
                f"after {k['upgradeRisksAsOf']} are not included."
            )
        elif not found:
            out["note"] = (
                f"No risk is declared in the update graph data for updating from {current} to {target} (snapshot of "
                f"{k['upgradeRisksAsOf']}, cincinnati-graph-data {commit})."
            )
        return out


_lock = threading.Lock()
_cache: dict[str, Index] = {}


def bundled() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    root = resources.files("kube_noob").joinpath("data", "upgrade_risks")
    records: list[dict[str, Any]] = []
    meta: dict[str, Any] = {}
    if not root.is_dir():
        return records, meta
    for f in sorted((p for p in root.iterdir() if p.name.endswith(".json")), key=lambda p: p.name):
        doc = json.loads(f.read_text(encoding="utf-8"))
        records.extend(doc.get("records", []))
        meta = {k: v for k, v in doc.items() if k != "records"} or meta
    return records, meta


def get_index() -> Index:
    with _lock:
        if "" not in _cache:
            _cache[""] = Index(*bundled())
        return _cache[""]


def risks(current: str, target: str, arch: str | None = None) -> dict[str, Any]:
    """Risks declared for updating from ``current`` to ``target`` in the bundled snapshot."""
    return get_index().risks(current, target, arch)
