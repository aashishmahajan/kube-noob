"""Evaluate generated admission policies offline, the way the API server does, with cel-python (dev dependency).

ValidatingAdmissionPolicy semantics implemented here: match by group/resource/operation, skip namespaces the
namespaceSelector excludes (NotIn on kubernetes.io/metadata.name), evaluate variables in order, then every validation;
a validation that does not return true fails the object. CEL evaluation errors raise, so a policy that would error on
the server (and so deny under failurePolicy: Fail) fails the test instead of passing silently. The same evaluation
covers the Kyverno ValidatingPolicy, which carries the same matchConstraints, variables and validations.
"""

from __future__ import annotations

import functools
import sys
from typing import Any

import celpy
from celpy import celtypes, json_to_cel

from kube_noob.generate.policies import TARGETS

_LIMIT = sys.getrecursionlimit()
_ENV = celpy.Environment()  # raises the interpreter's recursion limit to 2500 for every later test: put it back
sys.setrecursionlimit(_LIMIT)


class CelError(AssertionError):
    pass


@functools.lru_cache(maxsize=4096)
def _program(expression: str) -> Any:
    return _ENV.program(_ENV.compile(expression))


def evaluate(expression: str, activation: dict[str, Any]) -> Any:
    try:
        out = _program(expression).evaluate(activation)
    except Exception as exc:
        raise CelError(f"{type(exc).__name__}: {exc} in {expression[:300]}") from exc
    if isinstance(out, celpy.CELEvalError):
        raise CelError(f"{out} in {expression[:300]}")
    return out


def _excluded(spec: dict[str, Any]) -> set[str]:
    sel = spec["matchConstraints"].get("namespaceSelector") or {}
    out: set[str] = set()
    for expr in sel.get("matchExpressions", []):
        if expr["key"] == "kubernetes.io/metadata.name" and expr["operator"] == "NotIn":
            out.update(expr["values"])
    return out


def matches(policy: dict[str, Any], doc: dict[str, Any], operation: str = "CREATE") -> bool:
    target = TARGETS.get(str(doc.get("kind")))
    if target is None:
        return False
    spec = policy["spec"]
    hit = any(
        target.group in r["apiGroups"] and target.resource in r["resources"] and operation in r["operations"]
        for r in spec["matchConstraints"]["resourceRules"]
    )
    if not hit:
        return False
    namespace = (doc.get("metadata") or {}).get("namespace") or "default"
    return not (target.namespaced and namespace in _excluded(spec))


def failures(
    policy: dict[str, Any],
    doc: dict[str, Any],
    *,
    operation: str = "CREATE",
    username: str = "kube:admin",
    cache: dict[tuple[str, str], Any] | None = None,
) -> list[str]:
    """The messages of the validations ``doc`` fails ([] when admitted or not matched). ``cache`` keeps variable
    values between policies evaluated on the same object and request (same name and expression, same value)."""
    if not matches(policy, doc, operation):
        return []
    target = TARGETS[str(doc["kind"])]
    namespace = (doc.get("metadata") or {}).get("namespace") or "default"
    ns_object = {"metadata": {"name": namespace}} if target.namespaced else None
    activation: dict[str, Any] = {
        "object": json_to_cel(doc),
        "oldObject": json_to_cel(None),
        "namespaceObject": json_to_cel(ns_object),
        "request": json_to_cel(
            {
                "operation": operation,
                "namespace": namespace if target.namespaced else "",
                "userInfo": {"username": username},
            }
        ),
    }
    variables: dict[Any, Any] = {}
    for v in policy["spec"].get("variables", []):
        key = (v["name"], v["expression"])
        if cache is not None and key in cache:
            variables[celtypes.StringType(v["name"])] = cache[key]
            continue
        activation["variables"] = celtypes.MapType(variables)
        value = evaluate(v["expression"], activation)
        variables[celtypes.StringType(v["name"])] = value
        if cache is not None:
            cache[key] = value
    activation["variables"] = celtypes.MapType(variables)
    failed: list[str] = []
    for val in policy["spec"]["validations"]:
        result = evaluate(val["expression"], activation)
        if not (isinstance(result, celtypes.BoolType) and bool(result)):
            failed.append(val["message"])
    return failed
