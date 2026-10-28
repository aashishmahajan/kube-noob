"""Fixes-as-code memory, entry schema (MEM1): one YAML file per entry, a Pydantic model and a shipped JSON Schema.

An entry records what a team learned: the signals and symptom, the cause, the fix (prose, an optional patch,
commands labelled by the same classifier the playbooks use), references to evidence, and what happened each time it
was applied. Prose fields are summaries: credentials, raw logs and manifests are rejected with the learning-file
detectors.
"""

from __future__ import annotations

import json
from datetime import date
from importlib import resources
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml
from pydantic import ValidationError

from kube_noob.errors import ManifestError
from kube_noob.memory import MemoryEntry, OperatorRange, dump_entry, entry_path, json_schema, load_entry, parse_entry

GOOD = """\
id: MEM-12
status: approved
kind: fix
signals:
  - {kind: alert, name: etcdHighNumberOfLeaderChanges}
  - {kind: component, name: etcd}
  - {kind: error_template, name: 3f2a9c0d41be}
symptom: etcd leader changes every few minutes after the 4.21.0 update; API requests time out
platform: openshift
versions: {introduced: "4.21.0", fixedIn: "4.21.1"}
operators:
  - {name: operator-lifecycle-manager, range: ">=0.28.0 <0.29.0"}
cause: Catalog sync wrote to the control-plane disks every few seconds, so etcd fsync latency rose above 10 ms.
fix:
  text: Update to 4.21.1. Until then, lower catalog polling to every 60 minutes on the busiest catalog sources.
  patch: |
    apiVersion: operators.coreos.com/v1alpha1
    kind: CatalogSource
    metadata:
      name: redhat-operators
      namespace: openshift-marketplace
    spec:
      updateStrategy:
        registryPoll:
          interval: 60m
  commands:
    - {command: oc get co etcd kube-apiserver, label: read-only}
    - command: oc rsh -n openshift-etcd etcd-master-0 etcdctl endpoint status --cluster -w table
      label: needs-approval
    - {command: oc adm upgrade --to=4.21.1, label: needs-approval}
evidence:
  - {kind: ticket, ref: OCPBUGS-73881}
  - {kind: url, ref: "https://github.com/openshift/openshift-docs/blob/enterprise-4.21/modules/zstream-4-21-1.adoc"}
  - {kind: citation, ref: "kn:ocp-operators#0"}
  - {kind: bundle, ref: "bundle:inc-2026-10-28/bundle.md", note: fsync p99 was 40 ms on all three members}
outcomes:
  - {date: 2026-10-28, result: resolved, ticket: INC-4211, cluster: prod-east}
  - {date: 2026-10-29, result: partial, cluster: prod-west}
owners: [platform-team]
sources: ["https://etcd.io/docs/v3.5/faq/"]
created: 2026-10-28
updated: 2026-10-29
reviewBy: 2027-04-30
"""


def _good(**changes: Any) -> dict[str, Any]:
    doc: dict[str, Any] = yaml.safe_load(GOOD)
    for key, value in changes.items():
        if value is None:
            doc.pop(key, None)
        else:
            doc[key] = value
    return doc


def _yaml(doc: dict[str, Any]) -> str:
    return yaml.safe_dump(doc, sort_keys=False)


def test_a_full_entry_loads_with_camel_case_keys() -> None:
    e = parse_entry(GOOD)
    assert e.id == "MEM-12" and e.number == 12 and e.status == "approved" and e.kind == "fix"
    assert (e.signals[0].kind, e.signals[0].name) == ("alert", "etcdHighNumberOfLeaderChanges")
    assert e.versions.fixed_in == "4.21.1" and e.review_by == date(2027, 4, 30)
    assert e.fix.commands[1].label == "needs-approval" and e.outcomes[0].cluster == "prod-east"
    assert e.fixed_for("4.21.1") and e.fixed_for("4.22") and not e.fixed_for("4.21.0") and not e.fixed_for(None)


def test_round_trip_is_exact_and_deterministic(tmp_path: Path) -> None:
    e = parse_entry(GOOD)
    text = dump_entry(e)
    assert text == dump_entry(parse_entry(text))
    assert parse_entry(text) == e
    assert text.splitlines()[0] == "id: MEM-12" and "fixedIn: '4.21.1'" in text and "reviewBy: 2027-04-30" in text
    path = entry_path(tmp_path, e)
    assert path == tmp_path / "entries" / "MEM-12.yaml"
    path.parent.mkdir()
    path.write_text(text, encoding="utf-8")
    assert load_entry(path) == e
    minimal = parse_entry(_yaml(_good(operators=None, evidence=None, outcomes=None, sources=None, reviewBy=None)))
    assert "\noperators:" not in dump_entry(minimal) and parse_entry(dump_entry(minimal)) == minimal


def test_the_file_name_must_match_the_id(tmp_path: Path) -> None:
    (tmp_path / "MEM-13.yaml").write_text(GOOD, encoding="utf-8")
    with pytest.raises(ValueError, match=r"MEM-13\.yaml holds MEM-12"):
        load_entry(tmp_path / "MEM-13.yaml")


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"symptom": "login fails, password is hunter2xyz"}, "credential"),
        ({"cause": "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMyJ9.abc was expired"}, "credential"),
        ({"cause": "2026-10-28T09:12:41Z etcd leader changed\n2026-10-28T09:12:42Z again"}, "raw log"),
        ({"cause": "Warning  BackOff  3m  kubelet  Back-off restarting failed container"}, "raw log"),
        ({"cause": "panic: runtime error\ngoroutine 1 [running]:"}, "raw log"),
        ({"symptom": "oc get pods | grep etcd shows restarts"}, "pipeline"),
        ({"fix": {"text": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x"}}, "manifest"),
        ({"symptom": "x" * 501}, "longer than 500"),
        ({"id": "MEM-0"}, "id"),
        ({"id": "mem-12"}, "id"),
        ({"status": "accepted"}, "status"),
        ({"kind": "workaround"}, "kind"),
        ({"platform": "eks"}, "platform"),
        ({"versions": {"introduced": 4.2}}, "quote"),
        ({"versions": {"introduced": "4.21.3", "fixedIn": "4.21.1"}}, "after"),
        ({"versions": {"fixedIn": "4.21.x"}}, "version"),
        ({"updated": "2026-10-01"}, "before created"),
        ({"owners": []}, "owners"),
        ({"sources": ["http://example.com/doc"]}, "https"),
        ({"surprise": 1}, "Extra inputs"),
        ({"signals": [{"kind": "alert", "name": "etcd leader changed"}]}, "signal"),
        ({"signals": [{"kind": "error_template", "name": "etcd leader changed"}]}, "signal"),
        ({"signals": [{"kind": "smell", "name": "x"}]}, "kind"),
        ({"signals": [{"kind": "component", "name": "etcd"}] * 21}, "20"),
        ({"operators": [{"name": "olm", "range": ">=4.16 && rm -rf /"}]}, "range"),
        ({"outcomes": [{"date": "2026-10-28", "result": "fixed"}]}, "result"),
        ({"outcomes": [{"date": "2026-10-28", "result": "resolved", "ticket": "INC 42; rm"}]}, "ticket"),
        ({"outcomes": [{"date": "2026-10-28", "result": "resolved", "cluster": "Prod East"}]}, "cluster"),
        ({"evidence": [{"kind": "url", "ref": "2026-10-28T09:12:41Z leader changed"}]}, "evidence"),
        ({"evidence": [{"kind": "ticket", "ref": "see the logs"}]}, "evidence"),
        ({"evidence": [{"kind": "bundle", "ref": "bundle:../../etc/passwd"}]}, "evidence"),
        ({"riskAccepted": {"owner": "sec-team", "reason": "token: abcdef123456 was rotated"}}, "credential"),
    ],
)
def test_bad_entries_are_rejected_with_a_reason(changes: dict[str, Any], message: str) -> None:
    with pytest.raises((ValidationError, ValueError), match=message):
        parse_entry(_yaml(_good(**changes)))


@pytest.mark.parametrize(
    ("command", "label", "message"),
    [
        ("oc delete pod etcd-master-0 -n openshift-etcd", "read-only", "needs-approval"),
        ("oc rsh -n openshift-etcd etcd-master-0 etcdctl alarm list", "read-only", "needs-approval"),
        ("oc get co etcd", "needs-approval", "read-only"),
        ("oc get co etcd  # check the operator", "read-only", "comment"),
        ("oc get co etcd\noc get nodes", "read-only", "one line"),
        ("oc get secret x -o yaml --token=sha256~abcdefghijklmnopqrstuvwxyz0123", "read-only", "credential"),
        ("", "read-only", "empty"),
        ("oc get co \x1b[2J", "read-only", "control"),
        ("oc get secret db -n shop -o yaml", "read-only", "Secret"),
        ("oc extract secret/db -n shop --to=-", "needs-approval", "Secret"),
    ],
)
def test_commands_carry_the_classifiers_label_and_nothing_else(command: str, label: str, message: str) -> None:
    fix = {"text": "Restart the member.", "commands": [{"command": command, "label": label}]}
    with pytest.raises(ValidationError, match=message):
        parse_entry(_yaml(_good(fix=fix)))


@pytest.mark.parametrize(
    ("patch", "message"),
    [
        ("apiVersion: v1\nkind: Secret\nmetadata: {name: x}\nstringData: {password: hunter2hunter2}", "Secret"),
        (
            "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\ndata: {token: ghp_abcdefghijklmnopqrstuvwxyz0123}",
            "credential",
        ),
        ("not: [valid", "YAML"),
        ("just a sentence", "apiVersion and kind"),
        ("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\ndata: {a: '" + "x" * 20_001 + "'}", "20000"),
        (
            "a: &a [1]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: [*b, *b, *b, *b, *b, *b, *b, *b, *b]",
            "apiVersion",
        ),
    ],
)
def test_patches_are_manifests_without_secrets(patch: str, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        parse_entry(_yaml(_good(fix={"text": "Apply the patch.", "patch": patch})))


def test_yaml_level_attacks_are_refused() -> None:
    with pytest.raises((ValueError, ManifestError), match="duplicate"):
        parse_entry(GOOD + "status: proposed\n")
    with pytest.raises(ValueError, match="mapping"):
        parse_entry("- just\n- a list\n")
    with pytest.raises(ValueError, match="bytes"):
        parse_entry(GOOD + "#" + "x" * 300_000)
    with pytest.raises((ValueError, ManifestError)):
        parse_entry(
            "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
            + "".join(f"a{i}: &a{i} [*a, *a, *a, *a, *a, *a]\n" for i in range(12))
        )
    with pytest.raises((ValueError, ManifestError)):
        parse_entry("---\n" + GOOD + "---\n" + GOOD)


def test_operator_ranges() -> None:
    r = OperatorRange(name="operator-lifecycle-manager", range=">=0.28.0 <0.29.0")
    assert r.contains("0.28.4") and not r.contains("0.29.0") and not r.contains("0.27.9")
    assert r.contains("0.28.4-202610011135")
    assert OperatorRange(name="x", range=None).contains("9.9")
    assert OperatorRange(name="x", range="=4.16.2").contains("4.16.2") and not OperatorRange(
        name="x", range="=4.16.2"
    ).contains("4.16.3")
    for bad in ("", "4.16", ">= 4.16 < 4.17 < 4.18", ">=4.16; rm", "~4.16"):
        with pytest.raises(ValidationError):
            OperatorRange(name="x", range=bad)


def test_the_shipped_json_schema_matches_the_model_and_checks_shape() -> None:
    shipped = json.loads(resources.files("kube_noob").joinpath("data/memory/entry.schema.json").read_text())
    assert shipped == json_schema(), (
        "data/memory/entry.schema.json is stale: python -c 'import json; from kube_noob.memory import json_schema; "
        "print(json.dumps(json_schema(), indent=2))' > src/kube_noob/data/memory/entry.schema.json"
    )
    doc = json.loads(json.dumps(yaml.safe_load(GOOD), default=str))
    jsonschema.validate(doc, shipped)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({**doc, "surprise": 1}, shipped)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({**doc, "status": "accepted"}, shipped)


def test_entries_are_frozen_values() -> None:
    e = parse_entry(GOOD)
    with pytest.raises(ValidationError):
        e.status = "retired"  # type: ignore[misc]
    assert isinstance(MemoryEntry.model_validate(e.model_dump(by_alias=True)), MemoryEntry)
