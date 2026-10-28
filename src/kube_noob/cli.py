"""kube-noob command line.

Exit codes: 0 ok | 1 findings at/above --fail-on | 2 usage/config error | 3 clarification needed | 4 runtime error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml

from kube_noob import __version__
from kube_noob.config import Settings, load_settings
from kube_noob.errors import ClarificationNeeded, ConfigError, KubeNoobError

PLATFORMS = ["kubernetes", "openshift", "rosa-classic", "rosa-hcp"]


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    p = Path(path)
    if p.is_dir():
        parts = [f.read_text(encoding="utf-8") for f in sorted(p.rglob("*")) if f.suffix in {".yaml", ".yml"}]
        return "\n---\n".join(parts)
    return p.read_text(encoding="utf-8")


_PATHLIKE = re.compile(r"[/\\]|\.[A-Za-z0-9]{1,5}$")


def _read_text_or_file(value: str, command: str = "diagnose") -> str:
    """For `diagnose`: '-' reads stdin, an existing path is read, anything else is the pasted text itself.

    A single token that looks like a missing file (``events.txt``, ``logs/pod.log``) is an error rather than text, so a
    typo in a file name is reported instead of being diagnosed as the words "events.txt".
    """
    if value == "-":
        if sys.stdin.isatty():
            print("Paste events, describe output or logs, then press Ctrl-D:", file=sys.stderr)
        return sys.stdin.read()
    try:
        is_path = "\n" not in value and Path(value).exists()
    except (OSError, ValueError):  # too long or not a valid path: it is text
        is_path = False
    if is_path:
        return _read(value)
    if not any(c.isspace() for c in value) and _PATHLIKE.search(value):
        raise ConfigError(
            f"no such file: {value}. To read text instead, pass it in quotes: kube-noob {command} '<text>'"
        )
    return value


def _emit(obj: Any, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(obj, indent=2, default=str))
    else:
        print(yaml.safe_dump(obj, sort_keys=False, width=120, allow_unicode=True), end="")


_REMARK_LABELS = {"cause": "cause", "expected": "why closed", "fix": "fix note"}


def _print_insight(res: dict[str, Any]) -> None:
    _tprint("input: " + "; ".join(f"{k['kind']} ({k['evidence']})" for k in res["kinds"]))
    if res.get("ran"):
        _tprint("ran: " + ", ".join(res["ran"]))
    for f in res["findings"]:
        extra = f.get("verdict") or f.get("severity") or f.get("confidence") or f.get("cite") or ""
        _tprint(f"  {f['source']:15} {f.get('id')!s:28} {str(f.get('title') or '')[:90]}  {extra}")
        if f.get("cause"):
            _tprint(f"  {'':15} cause: {f['cause'][:150]}")
    if res.get("readOnlyNextSteps"):
        _tprint("read-only next steps:")
        for st in res["readOnlyNextSteps"]:
            _tprint(f"  {st.get('command') or st.get('step') or st}")
    for sk in res.get("skipped", []):
        _tprint(f"not analysed ({sk['kind']}): {sk['why']}")


def _print_ticket_changes(res: dict[str, Any], opened: dict[str, Any]) -> None:
    counts = ", ".join(f"{n} {k}" for k, n in res["counts"].items()) or "none"
    _tprint(f"changes since {res['since']} (last sync {res['lastSync'] or 'never'}): {counts}")
    for c in res["changes"]:
        before = (c.get("from") or {}).get("verdict")
        after = (c.get("to") or {}).get("verdict")
        fix = ", ".join((c.get("to") or {}).get("fixVersions") or [])
        move = f"{before} -> {after}" if before else after
        _tprint(f"  {c['key']:16} {c['kind']:16} {move}{f' (fix {fix})' if fix else ''}  {c['title'][:70]}")
    if res.get("truncated"):
        _tprint(f"  ... {res['truncated']} more (--limit)")
    if res.get("note"):
        _tprint(res["note"])
    if opened.get("available"):
        per = "; ".join(
            f"{proj} " + ", ".join(f"{n} {v}" for v, n in sorted(vs.items()))
            for proj, vs in opened["byProject"].items()
        )
        _tprint(f"open tickets: {opened['open']} ({per or 'none'})")
        if opened["topComponents"]:
            _tprint("busiest components: " + ", ".join(f"{c} {n}" for c, n in opened["topComponents"][:5]))
    else:
        _tprint(opened["note"])


def _print_ticket_lines(m: dict[str, Any]) -> None:
    if m.get("workaround"):
        _tprint(f"  workaround: {m['workaround']}")
    for r in m.get("remarks") or []:
        if r["kind"] in _REMARK_LABELS:
            _tprint(f"  {_REMARK_LABELS[r['kind']]} ({r.get('date') or r['from']}): {r['text']}")


def _print_known_issues(out: dict[str, Any]) -> None:
    for m in out["matches"]:
        _tprint(f"{m['id']}  {m['status']}")
        _tprint(f"  {m['summary']}")
        if m.get("kind") == "ticket":
            _print_ticket_lines(m)
            _tprint(f"  ticket: {m['url']}  ({m['source']})")
            continue
        if m.get("workaround"):
            _tprint(f"  workaround: {m['workaround']}")
        if m.get("ticket"):
            _tprint(f"  ticket now: {m['ticket']['status']}")
        _tprint(f"  issue: {m['url']}")
        _tprint(f"  release notes: {m['source']}")
    if out.get("note"):
        _tprint(out["note"])
    k = out["knowledge"]
    print(f"index: release-note issues as of {k['knownIssuesAsOf']} for OpenShift {', '.join(k['openshiftReleases'])}")
    jt = k.get("jiraTickets")
    if jt:
        names = ", ".join(jt["projects"][:6]) + ("..." if len(jt["projects"]) > 6 else "")
        print(f"index: {jt['tickets']} Red Hat Jira tickets ({names}) retrieved {jt['asOf']}")
    elif out.get("ticketsNote"):
        _tprint(f"index: no Red Hat Jira tickets: {out['ticketsNote']}")


def _print_report(rep: dict[str, Any]) -> None:
    s = rep["summary"]
    print(
        f"kube-noob audit | platform={rep['platform']} k8s={rep['kubernetesVersion']} | score={s['score']} | "
        + " ".join(f"{k}={v}" for k, v in s["counts"].items() if v)
    )
    for a in rep.get("assumptions", []):
        print(f"  note: {a}")
    for f in rep["findings"]:
        loc = f"L{f['line']}" if f.get("line") else ""
        print(f"[{f['severity'].upper():8}] {f['ruleId']:9} {f['resource']} {loc} {f['path']}")
        print(f"           {f['message']}")
        print(f"           fix: {f['remediation']}")
        if f.get("stackroxPolicies"):
            print(f"           RHACS: {', '.join(f['stackroxPolicies'])}")
    touched = (rep.get("controlSummary") or {}).get("controls") or []
    if touched:
        print("NIST SP 800-53 controls with findings: " + ", ".join(f"{c['id']} ({c['findings']})" for c in touched))
    for sc in rep.get("redTeam", []):
        if sc["verdict"] == "exposed":
            print(f"[RED-TEAM {sc['severity'].upper()}] {sc['scenarioId']}: {sc['question']}")
            for e in sc["evidence"][:4]:
                print(f"           - {e}")


def _blueprint_from_args(a: argparse.Namespace) -> dict[str, Any]:
    if a.blueprint:
        data = yaml.safe_load(_read(a.blueprint)) or {}
        if not isinstance(data, dict):
            raise ConfigError("blueprint file must contain a mapping")
        return data
    if not (a.name and a.namespace and a.image):
        raise ConfigError("provide --blueprint FILE or at least --name, --namespace and --image")
    bp: dict[str, Any] = {
        "name": a.name,
        "namespace": a.namespace,
        "image": a.image,
        "platform": a.platform,
        "replicas": a.replicas,
        "port": a.port,
        "workload": a.workload,
    }
    if a.platform_version:
        bp["platformVersion"] = a.platform_version
    if a.expose != "none":
        bp["exposure"] = {"type": a.expose, **({"host": a.host} if a.host else {})}
    if a.storage_size:
        bp["storage"] = {
            "size": a.storage_size,
            "accessMode": a.access_mode,
            **({"storageClass": a.storage_class} if a.storage_class else {}),
        }
    return bp


def _patch(subparsers: Any, common: argparse.ArgumentParser) -> None:
    original = subparsers.add_parser

    def add_parser(name: str, **kw: Any) -> argparse.ArgumentParser:
        return original(name, parents=[common], **kw)  # type: ignore[no-any-return]

    subparsers.add_parser = add_parser


GLOBAL_DEFAULTS: dict[str, Any] = {"config": None, "web_enabled": False, "cluster_enabled": False, "format": "text"}


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--config", default=argparse.SUPPRESS, help="Path to kube-noob.yaml (default: lookup chain, see docs)"
    )
    common.add_argument(
        "--web-enabled",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Override webEnabled: true for this invocation",
    )
    common.add_argument(
        "--cluster-enabled",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Override cluster.enabled: true (read-only)",
    )
    common.add_argument("--format", choices=["text", "json", "yaml"], default=argparse.SUPPRESS)
    p = argparse.ArgumentParser(
        prog="kube-noob",
        description="Kubernetes/OpenShift/ROSA/Helm/RHACS audit, debugging and learning tools. No AI inside.",
        parents=[common],
    )
    # No set_defaults here: the global options' actions are shared with every subcommand (parents=[common]), so a
    # parser-level default would reset a value given before the subcommand (`kube-noob --config X doctor`).
    # Defaults are filled in after parsing (GLOBAL_DEFAULTS).
    p.add_argument("--version", action="version", version=f"kube-noob {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    _add = sub.add_parser

    def add_parser(name: str, **kw: Any) -> argparse.ArgumentParser:
        return _add(name, parents=[common], **kw)

    sub.add_parser = add_parser  # type: ignore[method-assign]

    def manifests_cmd(name: str, help_: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("-f", "--file", required=True, help="YAML file, directory or '-' for stdin")
        sp.add_argument("--platform", choices=PLATFORMS, default=None)
        sp.add_argument("--version", dest="pversion", help="OpenShift (4.22) or Kubernetes (1.35) version")
        return sp

    a = manifests_cmd("audit", "Validate + audit + calibrate + red-team manifests")
    a.add_argument("--min-severity", default="low", choices=["info", "low", "medium", "high", "critical"])
    a.add_argument("--fail-on", default="high", choices=["info", "low", "medium", "high", "critical", "never"])
    manifests_cmd("validate", "Schema/API/platform validation only")
    manifests_cmd("redteam", "Red-team scenarios only")
    fx = manifests_cmd("fix", "Apply safe mechanical fixes")
    fx.add_argument("-o", "--output", help="Write fixed YAML here (default: stdout)")
    fx.add_argument("--no-harden", action="store_true")

    pr = sub.add_parser("protocol", help="Run the 7-step protocol on a request")
    pr.add_argument("request")
    pr.add_argument("-f", "--file", help="Manifests to review")
    pr.add_argument("--blueprint", help="Blueprint YAML to generate from")
    pr.add_argument("--platform", choices=PLATFORMS)
    pr.add_argument("--version", dest="pversion")
    pr.add_argument("--no-fix", action="store_true")

    for name in ("generate", "helm-chart"):
        g = sub.add_parser(name, help="Generate audited manifests" if name == "generate" else "Generate a Helm chart")
        g.add_argument("--blueprint", help="Blueprint YAML file")
        g.add_argument("--name")
        g.add_argument("--namespace")
        g.add_argument("--image")
        g.add_argument("--platform", choices=PLATFORMS, default="kubernetes")
        g.add_argument("--platform-version")
        g.add_argument("--replicas", type=int, default=3)
        g.add_argument("--port", type=int, default=8080)
        g.add_argument("--workload", choices=["deployment", "statefulset"], default="deployment")
        g.add_argument("--expose", choices=["none", "route", "ingress", "gateway", "loadbalancer"], default="none")
        g.add_argument("--host")
        g.add_argument("--storage-size")
        g.add_argument(
            "--access-mode", default="ReadWriteOnce", choices=["ReadWriteOnce", "ReadWriteMany", "ReadWriteOncePod"]
        )
        g.add_argument("--storage-class")
        g.add_argument("-o", "--output", help="Output file (generate) or directory (helm-chart)")

    ha = sub.add_parser("helm-audit", help="Render a chart with helm and audit the output")
    ha.add_argument("chart")
    ha.add_argument("-f", "--values", action="append", default=[])
    ha.add_argument("--platform", choices=PLATFORMS, default="kubernetes")
    ha.add_argument("--version", dest="pversion")
    ha.add_argument("--namespace", default="default")

    d = sub.add_parser(
        "diagnose",
        help="Diagnose pasted events/logs/errors offline",
        description="Diagnose events, describe output, logs or errors. Pass the text in quotes, a file with -f, or "
        "pipe it in. Examples: kube-noob diagnose 'Back-off restarting failed container' | kube-noob diagnose -f "
        "events.txt | pbpaste | kube-noob diagnose",
    )
    d.add_argument("text", nargs="*", help="the error text; quote multi-line text (single quotes avoid $ expansion)")
    d.add_argument("-f", "--file", default=None, help="a file, '-' for stdin, or the text itself")
    d.add_argument("--platform", choices=PLATFORMS)
    d.add_argument(
        "--version", dest="pversion", help="your OpenShift version, e.g. 4.20.8: leaves out issues already fixed there"
    )

    ins = sub.add_parser(
        "insight",
        help="Paste anything (events, logs, an alert, a denial, a ticket, manifests, a question): it names what it is "
        "and runs every analyser that applies",
        description="Recognises what the input is and merges the diagnosis, reported issues, team memory, policy "
        "explanations, audit findings and documentation that apply. Text in quotes, a file with -f, or stdin.",
    )
    ins.add_argument("text", nargs="*", help="the input; quote multi-line text (single quotes avoid $ expansion)")
    ins.add_argument("-f", "--file", default=None, help="a file (a .pcap is recognised by its header), or '-'")
    ins.add_argument("--platform", choices=PLATFORMS)
    ins.add_argument("--version", dest="pversion", help="your OpenShift version, e.g. 4.20.8")

    kis = sub.add_parser(
        "known-issues",
        help="Is this a reported OpenShift issue? Match an error against the release notes",
        description="Match an error or symptom against the known and fixed issues in the OpenShift release notes. "
        "Example: kube-noob known-issues 'could not find any suitable subnets for creating the ELB' --version 4.20.8",
    )
    kis.add_argument("text", nargs="*", help="the error text or symptom, in quotes")
    kis.add_argument("-f", "--file", default=None, help="a file, '-' for stdin, or the text itself")
    kis.add_argument("--platform", choices=PLATFORMS, default="openshift")
    kis.add_argument("--version", dest="pversion", help="your OpenShift version, e.g. 4.20.8")
    kis.add_argument("--limit", type=int, default=3)

    tik = sub.add_parser(
        "ticket",
        help="Look up a Red Hat Jira ticket in the local copy: what became of it, fix versions, workaround",
        description="Show one ticket from the local copy of Red Hat's public Jira (kube-noob corpus jira --online). "
        "Example: kube-noob ticket OCPBUGS-12345 --version 4.21.1",
    )
    sig = sub.add_parser(
        "signals",
        help="Extract signals: alert names, event and condition reasons, container reasons, admission rules, "
        "components and error templates",
        description="Find the canonical names in an alert payload, events, ClusterOperators, pod status or pasted "
        "text. Example: oc get events -o json | kube-noob signals",
    )
    sig.add_argument("text", nargs="*", help="text to read; or -f FILE; or pipe it in")
    sig.add_argument("-f", "--file", default=None, help="a file, '-' for stdin, or the text itself")
    tik.add_argument("key", help="a Jira key such as OCPBUGS-12345 or ROX-30000")
    tik.add_argument("--version", dest="pversion", help="your OpenShift version: says whether the fix is in it")

    pol = sub.add_parser(
        "policy",
        help="Why was this denied? Would a NetworkPolicy allow this traffic?",
        description="Explain admission denials (Kyverno, Gatekeeper, ValidatingAdmissionPolicy, Pod Security, "
        "OpenShift SCC, RHACS, quota, LimitRange, RBAC) and check NetworkPolicy reachability. Read-only and offline "
        "unless --live is given.",
    )
    psub = pol.add_subparsers(dest="policy_cmd", required=True)
    _patch(psub, common)
    pex = psub.add_parser(
        "explain",
        help="Explain an admission denial, policy by policy",
        description="Pass the error in quotes, a file with -f, or pipe it in. Example: kubectl apply -f deploy.yaml "
        "2>&1 | kube-noob policy explain",
    )
    pex.add_argument("text", nargs="*", help="the denial text; quote it (single quotes avoid $ expansion)")
    pex.add_argument("-f", "--file", default=None, help="a file, '-' for stdin, or the text itself")
    pex.add_argument("--platform", choices=PLATFORMS)
    prc = psub.add_parser(
        "reach",
        help="Would NetworkPolicies let the source reach the destination on a port? (exit 1 when denied)",
        description="Endpoints: namespace/name, namespace/kind/name, namespace:key=value,... or an IP/CIDR. Example: "
        "kube-noob policy reach --from web/frontend --to shop/orders-api --port 8080 -f k8s/",
    )
    prc.add_argument("--from", dest="source", required=True, help="source endpoint")
    prc.add_argument("--to", dest="destination", required=True, help="destination endpoint")
    prc.add_argument("--port", required=True, help="port number or named container port")
    prc.add_argument("--protocol", default="TCP", choices=["TCP", "UDP", "SCTP"])
    prc.add_argument("-f", "--file", action="append", default=[], help="YAML file or directory; repeat for several")
    prc.add_argument("--namespace", dest="default_namespace", default="default", help="for objects without one")
    prc.add_argument("--live", action="store_true", help="read the policies from the cluster (read-only)")
    prc.add_argument("--platform", choices=PLATFORMS)

    wt = sub.add_parser(
        "watch",
        help="Watch namespaces read-only: open, explain and remember incidents (needs cluster access)",
        description="Polls pods, events, deployments and replicasets (get/list only, never Secrets), groups problems "
        "into incidents, explains each new one and records it in the local incident ledger. Example: kube-noob "
        "--cluster-enabled watch -n shop --once",
    )
    wt.add_argument("-n", "--namespace", dest="namespaces", action="append", default=[], help="repeat for several")
    wt.add_argument("--once", action="store_true", help="poll once and exit")
    wt.add_argument("--interval", type=int, default=None, help="seconds between polls (default watch.intervalSeconds)")

    inc = sub.add_parser("incidents", help="Incidents the watch recorded: list, show, or confirm the fix")
    isub = inc.add_subparsers(dest="incidents_cmd")
    _patch(isub, common)
    il = isub.add_parser("list", help="Open incidents (default), or --all")
    il.add_argument("--all", action="store_true", help="include resolved incidents")
    il.add_argument("-n", "--namespace", default=None)
    ish = isub.add_parser("show", help="One incident in full")
    ish.add_argument("incident_id")
    icf = isub.add_parser("confirm", help="Remember the cause and fix that worked (summaries only)")
    icf.add_argument("incident_id")
    icf.add_argument("--cause", required=True)
    icf.add_argument("--fix", required=True)

    dbg = sub.add_parser("debug", help="Collect live read-only evidence for a workload and diagnose it")
    dbg.add_argument("target", help="kind/name, e.g. deployment/orders-api")
    dbg.add_argument("-n", "--namespace", required=True)
    dbg.add_argument("--platform", choices=PLATFORMS)

    bun = sub.add_parser(
        "bundle", help="Write a redacted, read-only diagnostic bundle (Markdown + JSON) for a workload"
    )
    bun.add_argument("target", help="kind/name, e.g. deployment/orders-api")
    bun.add_argument("-n", "--namespace", required=True)
    bun.add_argument("-o", "--out", default="kube-noob-bundle", help="output directory (default: ./kube-noob-bundle)")
    bun.add_argument("--platform", choices=PLATFORMS)

    s = sub.add_parser("search", help="Search local knowledge")
    s.add_argument("query")
    s.add_argument("-n", "--limit", type=int, default=5)
    s.add_argument("--source")

    sub.add_parser("rules", help="List audit rules")
    ex = sub.add_parser("explain", help="Explain a rule")
    ex.add_argument("rule_id")

    lr = sub.add_parser("learn", help="Learning tracks, lessons, exercises, quizzes")
    lsub = lr.add_subparsers(dest="learn_cmd", required=True)
    learner_common = argparse.ArgumentParser(add_help=False, parents=[common])
    learner_common.add_argument("--learner", default=argparse.SUPPRESS, help="Learner id for progress/credits")
    _patch(lsub, learner_common)
    lsub.add_parser("tracks")
    lsn = lsub.add_parser("lesson")
    lsn.add_argument("lesson_id")
    lex = lsub.add_parser("exercise")
    lex.add_argument("exercise_id")
    lsu = lsub.add_parser("submit")
    lsu.add_argument("exercise_id")
    lsu.add_argument("-f", "--file", required=True)
    lq = lsub.add_parser("quiz")
    lq.add_argument("question_id")
    lq.add_argument("--choice", type=int)
    lsub.add_parser("progress")
    lr.set_defaults(learner="local")

    lg = sub.add_parser("learning", help="What kube-noob remembers locally (profile, confirmed notes, counters)")
    lgs = lg.add_subparsers(dest="learning_cmd", required=True)
    _patch(lgs, common)
    lgs.add_parser("show", help="Profile, recent notes and the most frequent playbooks/rules")
    ln = lgs.add_parser("note", help="Save a confirmed symptom -> cause -> fix (summaries only, no secrets)")
    ln.add_argument("--symptom", required=True)
    ln.add_argument("--cause", required=True)
    ln.add_argument("--fix", required=True)
    ln.add_argument("--platform", choices=PLATFORMS)
    ln.add_argument("--tag", action="append", default=[], dest="tags")
    lgf = lgs.add_parser("forget", help="Delete a note by id (local-N)")
    lgf.add_argument("note_id")
    lgp = lgs.add_parser("profile", help="Set your platform, versions and team conventions")
    lgp.add_argument("--platform", choices=PLATFORMS)
    for key in ("kubernetes", "openshift", "helm", "rhacs", "rosa"):
        lgp.add_argument(f"--{key}", metavar="X.Y", help=f"{key} version")
    lgp.add_argument("--convention", action="append", dest="conventions", help="repeat for several")

    mem = sub.add_parser(
        "memory",
        help="Your team's fixes as code: reviewed entries in your own repository, validated and matched",
        description="A memory repository holds entries/MEM-<n>.yaml, one per lesson. kube-noob reads it locally and "
        "never uploads, bundles or exports it. Example: kube-noob memory match 'etcd leader changed' --dir ./memory",
    )
    msub = mem.add_subparsers(dest="memory_cmd", required=True)
    _patch(msub, common)
    mi = msub.add_parser("init", help="Scaffold a repository: README, schema, entries/, CI templates (keeps files)")
    mi.add_argument("dir")
    madd = msub.add_parser("add", help="Write a proposed entry (never commits; review it in a pull request)")
    madd.add_argument("dir")
    madd.add_argument("--symptom", required=True)
    madd.add_argument("--cause", required=True)
    madd.add_argument("--fix", required=True)
    madd.add_argument("--kind", choices=["fix", "negative", "runbook"], default="fix")
    madd.add_argument("--signal", action="append", default=[], help="kind:name, e.g. alert:etcdNoLeader (repeat)")
    madd.add_argument("--command", action="append", default=[], dest="commands", help="one command (repeat)")
    madd.add_argument("--platform", choices=PLATFORMS)
    madd.add_argument("--introduced", metavar="X.Y[.Z]")
    madd.add_argument("--fixed-in", dest="fixed_in", metavar="X.Y[.Z]")
    madd.add_argument("--owner", action="append", default=[], dest="owners", help="team or person (repeat)")
    madd.add_argument("--source", action="append", default=[], dest="sources", help="https URL (repeat)")
    mval = msub.add_parser("validate", help="Schema, duplicates, review dates, credentials and the fix verifier")
    mval.add_argument("dir")
    mval.add_argument("--strict", action="store_true", help="passed review dates are errors")
    mm = msub.add_parser("match", help="Entries for an error, an alert payload or a symptom (approved only)")
    mm.add_argument("text", nargs="*", help="the error or symptom, in quotes")
    mm.add_argument("-f", "--file", default=None, help="a file (e.g. an Alertmanager payload), or '-' for stdin")
    mm.add_argument(
        "--dir", action="append", default=[], dest="dirs", help="memory repository (repeat); default: memory.paths"
    )
    mm.add_argument("--version", dest="pversion", help="your OpenShift version: entries fixed there show as retired")
    mm.add_argument("--platform", choices=PLATFORMS)
    mm.add_argument("--operator", action="append", default=[], help="name=version of an installed operator (repeat)")
    mm.add_argument("--include-proposed", action="store_true")
    mm.add_argument("--limit", type=int, default=5)
    mo = msub.add_parser("outcome", help="Record that an entry was applied, and how it went")
    mo.add_argument("dir")
    mo.add_argument("entry_id", metavar="MEM-N")
    mo.add_argument("--result", required=True, choices=["resolved", "partial", "not-resolved"])
    mo.add_argument("--ticket", help="an opaque ticket reference, e.g. INC-4211")
    mo.add_argument("--cluster", help="a cluster label, e.g. prod-east")
    mo.add_argument("--date", dest="when", metavar="YYYY-MM-DD")
    mst = msub.add_parser("stats", help="Entries and outcomes, optionally per cluster, signal or component")
    mst.add_argument("dir")
    mst.add_argument("--by", choices=["cluster", "signal", "component"])
    mimp = msub.add_parser(
        "import",
        help="Turn resolved tickets from a ServiceNow or Jira export into proposed entries (people removed)",
    )
    mimp.add_argument("dir")
    mimp.add_argument(
        "--from",
        dest="ticket_format",
        required=True,
        choices=["servicenow-json", "servicenow-csv", "jira-json", "jira-csv"],
        help="the export's format (--format stays the output format)",
    )
    mimp.add_argument("-f", "--file", required=True, help="the export file, or '-' for stdin")
    mimp.add_argument("--platform", choices=PLATFORMS)
    mimp.add_argument("--owner", default="unassigned")
    mimp.add_argument("--cluster", help="a cluster label for every imported outcome, e.g. prod-east")
    mimp.add_argument("--dry-run", action="store_true", help="show what would be written; write nothing")
    mrp = msub.add_parser(
        "replay",
        help="Would memory have helped? Replay tickets in date order and report hits, misses and useful matches",
    )
    mrp.add_argument("--memory", required=True, help="the memory repository")
    mrp.add_argument("--tickets", required=True, help="the ticket export to replay")
    mrp.add_argument(
        "--from",
        dest="ticket_format",
        required=True,
        choices=["servicenow-json", "servicenow-csv", "jira-json", "jira-csv"],
        help="the export's format (--format stays the output format)",
    )
    mrp.add_argument("--labels", help="YAML: ticket ref -> true/false (was the match useful?)")
    mrp.add_argument("--as-of-ticket-date", action="store_true", help="only entries created before each ticket count")
    mrp.add_argument("--approved-only", action="store_true", help="ignore proposed entries")
    mrp.add_argument("--out", help="directory for report.md and report.json")
    mmig = msub.add_parser("migrate-learning", help="Turn confirmed learning notes into proposed entries (once)")
    mmig.add_argument("dir")
    mmig.add_argument("--owner", default="unassigned")

    ask = sub.add_parser("ask", help="Optional: ask a model you configure, which calls these tools")
    ask.add_argument("question")

    sub.add_parser("mcp", help="Run the MCP server over stdio")
    sv = sub.add_parser("serve", help="Run the MCP server over streamable HTTP (sidecar/service)")
    sv.add_argument("--host")
    sv.add_argument("--port", type=int)
    sv.add_argument("--allow-unauthenticated", action="store_true")
    sv.add_argument("--watch", action="store_true", help="also run the incident watch (watch.enabled)")

    c = sub.add_parser("corpus", help="Build / inspect the local corpus (network: maintainers & CI)")
    csub = c.add_subparsers(dest="corpus_cmd", required=True)
    _patch(csub, common)
    cb = csub.add_parser("build", help="Ingest public Git sources")
    cb.add_argument("--sources", default="all", help="comma-separated source ids or 'all'")
    cb.add_argument("--limit-per-source", type=int)
    cb.add_argument("--online", action="store_true", help="Required: confirm network ingestion")
    cj = csub.add_parser(
        "jira",
        help="Keep a local copy of Red Hat's public Jira tickets (every status), through its REST API",
        description="Copy every ticket of the chosen projects, whatever its status, into the data folder and index "
        "it for known-issues, diagnose and the incident watch. Paced at one request per second or slower; "
        "--max-requests caps a run and the next run resumes. The copy is not redistributable and never leaves "
        "this machine.",
    )
    cj.add_argument(
        "--projects", help="default (Kubernetes, OpenShift, ROSA, ACM, RHACS), all, or keys such as OCPBUGS,ROX"
    )
    cj.add_argument("--max-requests", type=int, help="request budget for this run (default jira.maxRequests)")
    cj.add_argument("--online", action="store_true")
    cjs = csub.add_parser(
        "jira-snapshot",
        help="Pack the local Jira copy (tickets, sync state, change log) into one file other installs import",
    )
    cjs.add_argument("-o", "--out", default="jira-snapshot.tgz", help="output file (keep it inside your organisation)")
    cjc = csub.add_parser(
        "jira-changes",
        help="Reconcile: tickets fixed, closed, reopened or opened since a date, and the open tickets by project",
    )
    cjc.add_argument("--since", default="2d", help="2d, 36h, 90m or a date such as 2026-10-25 (default 2d)")
    cjc.add_argument("--project", help="one project key, e.g. OCPBUGS")
    cjc.add_argument("--kind", action="append", default=[], help="fixed, not-a-bug, reopened, opened... (repeat)")
    cjc.add_argument("--limit", type=int, default=100)
    cja = csub.add_parser(
        "jira-audit",
        help="What the local Jira copy holds: tickets, comments kept, cut or older tickets, key coverage, and a check "
        "that no people are left in it",
    )
    cja.add_argument("--project", help="one project key, e.g. OCPBUGS")
    cjp = csub.add_parser("jira-projects", help="List the projects on Red Hat's public Jira, marking the default set")
    cjp.add_argument("--online", action="store_true")
    ch = csub.add_parser("history", help="Release timelines from Git tags")
    ch.add_argument("--online", action="store_true")
    cki = csub.add_parser("known-issues", help="Refresh reported OpenShift issues from the release notes (Git)")
    cki.add_argument("--minors", default="4.20,4.21,4.22", help="comma-separated OpenShift minor releases")
    cki.add_argument("--online", action="store_true")
    csub.add_parser("stats")
    csub.add_parser("verify")
    cad = csub.add_parser("add-docs", help="Index your own runbooks (Markdown/AsciiDoc/text folder), offline")
    cad.add_argument("path", help="folder with .md, .adoc, .txt or .rst files (for example a cloned wiki)")
    cad.add_argument("--source", required=True, help="short name, e.g. platform-runbooks")
    cad.add_argument("--base-url", help="link prefix for citations, e.g. https://git.example.com/runbooks/blob/main")
    ci = csub.add_parser(
        "import", help="Import a corpus directory or .tgz (the corpus-refresh artifact, a Jira snapshot, kube-noob-db)"
    )
    ci.add_argument("path")
    cdb = csub.add_parser(
        "db-bundle",
        help="Pack what may be shared (redistributable docs, release history, known issues) into kube-noob-db.tgz",
        description="Shards marked not redistributable and every Jira shard are left out; the archive is checked "
        "before it is written. Example: kube-noob corpus db-bundle -o dist/kube-noob-db.tgz",
    )
    cdb.add_argument("-o", "--output", default="kube-noob-db.tgz", help="the archive to write")
    cdc = csub.add_parser(
        "db-check",
        help="Check a kube-noob-db archive or folder: redistributable records on allowed licenses only, no Jira data, "
        "every file listed with its checksum (exit 1 on any problem)",
    )
    cdc.add_argument("path")

    t = sub.add_parser("train", help="Training enforcer, credit system and dataset export")
    tsub = t.add_subparsers(dest="train_cmd", required=True)
    _patch(tsub, common)
    te = tsub.add_parser("export", help="Export SFT + GRPO datasets")
    te.add_argument("--out", default="dataset")
    te.add_argument(
        "--include-restricted",
        action="store_true",
        help="Include non-redistributable corpus records (local/private training only)",
    )
    te.add_argument("--synthetic-limit", type=int)
    tg = tsub.add_parser("grade", help="Grade a completion against a benchmark task")
    tg.add_argument("--task", required=True)
    tg.add_argument("-f", "--file", required=True)
    tb = tsub.add_parser("bench", help="Run the benchmark through the configured LLM")
    tb.add_argument("--tasks", help="comma-separated task ids")
    tb.add_argument("--no-tools", action="store_true")
    tb.add_argument("--out")
    tsub.add_parser("tasks", help="List benchmark tasks")

    sub.add_parser("config", help="Show the effective configuration")
    sub.add_parser("doctor", help="Show what kube-noob can reach (network, cluster, model); exit 1 on conflicts")
    st = sub.add_parser("selftest", help="Answer a battery of real questions offline and score the results")
    st.add_argument("--category", choices=["kubernetes", "helm", "openshift", "rosa-hcp", "rhacs", "everyday"])
    st.add_argument(
        "--cases",
        help="your own problems instead of the built-in battery: YAML, JSONL, CSV, or plain text (one per line, "
        "or blocks separated by ---)",
    )
    st.add_argument("--gate", type=float, help="with --cases: fail (exit 1) when the pass rate is below this, 0-1")
    st.add_argument("--out", help="with --cases: write report.md and report.json to this folder")
    dm = sub.add_parser("demo", help="Offline walkthroughs of common use cases (no network, no cluster)")
    dm.add_argument("scenario", nargs="?", help="scenario name or 'all' (see --list)")
    dm.add_argument("--list", action="store_true", dest="list_demos")
    return p


def _settings(a: argparse.Namespace) -> Settings:
    overrides: dict[str, Any] = {}
    if a.web_enabled:
        overrides["webEnabled"] = True
    if a.cluster_enabled:
        overrides["cluster"] = {"enabled": True}
    return load_settings(a.config, overrides)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    a = parser.parse_args(argv)
    for key, value in GLOBAL_DEFAULTS.items():
        if not hasattr(a, key):
            setattr(a, key, value)
    try:
        s = _settings(a)
        return _dispatch(a, s)
    except ClarificationNeeded as exc:
        _emit({"status": "needs-clarification", "questions": exc.questions}, "yaml" if a.format == "text" else a.format)
        return 3
    except (ConfigError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (KubeNoobError, KeyError, ValueError) as exc:
        msg = exc.args[0] if isinstance(exc, KeyError) and exc.args else exc
        print(f"error: {msg}", file=sys.stderr)
        return 4
    except BrokenPipeError:
        # `kube-noob ... | head`: the reader went away; exit quietly like other CLI tools.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 141


def _dispatch(a: argparse.Namespace, s: Settings) -> int:
    from kube_noob import toolkit as tk
    from kube_noob.signals import alertmanager

    kit = tk.Toolkit(s)
    fmt = "yaml" if a.format == "text" else a.format
    platform = getattr(a, "platform", None) or s.default_platform

    if a.cmd in {"audit", "validate", "redteam", "fix"}:
        text = _read(a.file)
        if a.cmd == "audit":
            rep = kit.audit(
                tk.AuditIn(manifests=text, platform=platform, version=a.pversion, min_severity=a.min_severity)
            )
            if a.format == "text":
                _print_report(rep)
            else:
                _emit(rep, fmt)
            if a.fail_on == "never":
                return 0
            from kube_noob.audit.model import Severity

            limit = Severity.parse(a.fail_on)
            return 1 if any(Severity.parse(f["severity"]) >= limit for f in rep["findings"]) else 0
        if a.cmd == "validate":
            rep = kit.validate(tk.ManifestsIn(manifests=text, platform=platform, version=a.pversion))
            _print_report(rep) if a.format == "text" else _emit(rep, fmt)
            return 1 if rep["summary"]["counts"]["high"] + rep["summary"]["counts"]["critical"] else 0
        if a.cmd == "redteam":
            _emit(kit.red_team(tk.ManifestsIn(manifests=text, platform=platform, version=a.pversion)), fmt)
            return 0
        res = kit.fix(tk.FixIn(manifests=text, platform=platform, version=a.pversion, harden=not a.no_harden))
        if a.output:
            Path(a.output).write_text(res["manifests"], encoding="utf-8")
        else:
            print(res["manifests"], end="")
        print(
            yaml.safe_dump(
                {"changes": res["changes"], "manualFollowUps": res["manualFollowUps"], "after": res["after"]},
                sort_keys=False,
            ),
            file=sys.stderr,
        )
        return 0

    if a.cmd == "protocol":
        bp = yaml.safe_load(_read(a.blueprint)) if a.blueprint else None
        out = kit.run_protocol(
            tk.ProtocolIn(
                request=a.request,
                manifests=_read(a.file) if a.file else None,
                blueprint=bp,
                platform=getattr(a, "platform", None),
                version=a.pversion,
                apply_fixes=not a.no_fix,
            )
        )
        if a.format == "text" and out.get("status") in {"ready", "blocked"}:
            brief = out["auditValidationBrief"]
            print("## Audit & Validation Brief")
            print(yaml.safe_dump(brief, sort_keys=False), end="")
            print("\n## Production Manifest")
            print(out["productionManifest"], end="")
            print("\n## Red Team Findings & Safeguards")
            print(yaml.safe_dump(out["redTeamFindingsAndSafeguards"], sort_keys=False), end="")
            print("\n## Validate in the cluster")
            print("\n".join(out["validationCommands"]))
        else:
            _emit(out, fmt)
        return {"ready": 0, "blocked": 1, "needs-clarification": 3}.get(out["status"], 0)

    if a.cmd in {"generate", "helm-chart"}:
        from kube_noob.generate.blueprint import Blueprint

        bp_model = Blueprint.model_validate(_blueprint_from_args(a))
        if a.cmd == "generate":
            out = kit.generate(tk.BlueprintIn(blueprint=bp_model))
            if out["status"] != "ok":
                _emit(out, fmt)
                return 3
            if a.output:
                Path(a.output).write_text(out["manifests"], encoding="utf-8")
            else:
                print(out["manifests"], end="")
            print(
                yaml.safe_dump({k: out[k] for k in ("assumptions", "prerequisites", "audit")}, sort_keys=False),
                file=sys.stderr,
            )
            return 0
        from kube_noob.generate.helm import generate_chart

        info = generate_chart(bp_model, a.output or ".")
        _emit({k: v for k, v in info.items() if k != "renderedManifests"}, fmt)
        return 0

    if a.cmd == "helm-audit":
        from kube_noob.generate.helm import audit_chart

        chart_report, lint = audit_chart(a.chart, a.platform, a.pversion, a.values, a.namespace)
        d = chart_report.as_dict()
        d["chartLint"] = lint
        _print_report(d) if a.format == "text" else _emit(d, fmt)
        for issue in lint:
            print(f"[CHART] {issue}")
        top = chart_report.max_severity()
        return 1 if top is not None and top >= 3 else 0

    if a.cmd == "insight":
        from kube_noob import insight as insight_mod

        if a.text and a.file is not None:
            raise ConfigError("pass the text or -f, not both")
        if a.file not in (None, "-") and Path(a.file).is_file():
            data = Path(a.file).read_bytes()[: insight_mod.MAX_TEXT]
            kinds = insight_mod.recognise_bytes(data)
            if [k.kind for k in kinds] == ["packet-capture"]:
                pcap: dict[str, Any] = {
                    "kinds": [k.as_dict() for k in kinds],
                    "ran": [],
                    "findings": [],
                    "skipped": [{"kind": "packet-capture", "why": insight_mod.PENDING["packet-capture"]}],
                }
                _emit(pcap, fmt) if a.format != "text" else _print_insight(pcap)
                return 0
            text = data.decode("utf-8", errors="replace")
        else:
            text = "\n".join(a.text) if a.text else _read_text_or_file(a.file if a.file is not None else "-", "insight")
        if len(text.strip()) < 3:
            raise ConfigError("nothing to read: pass the text in quotes, a file with -f, or pipe it in")
        found = kit.insight(tk.InsightIn(text=text[-tk.MAX_DIAGNOSE_TEXT :], platform=a.platform, version=a.pversion))
        if a.format == "text":
            _print_insight(found)
        else:
            _emit(found, fmt)
        return 0
    if a.cmd == "diagnose":
        if a.text and a.file is not None:
            raise ConfigError("pass the text or -f, not both")
        text = "\n".join(a.text) if a.text else _read_text_or_file(a.file if a.file is not None else "-")
        if len(text.strip()) < 3:
            raise ConfigError("nothing to diagnose: pass the error text in quotes, a file with -f, or pipe it in")
        if len(text) > tk.MAX_DIAGNOSE_TEXT:  # a long Alertmanager payload keeps every alert's labels and summary
            text = alertmanager.compact(text) or text[-tk.MAX_DIAGNOSE_TEXT :]
        _emit(
            kit.diagnose(
                tk.DiagnoseIn(text=text, platform=getattr(a, "platform", None), version=getattr(a, "pversion", None))
            ),
            fmt,
        )
        return 0

    if a.cmd == "known-issues":
        if a.text and a.file is not None:
            raise ConfigError("pass the text or -f, not both")
        text = "\n".join(a.text) if a.text else _read_text_or_file(a.file if a.file is not None else "-")
        if len(text.strip()) < 3:
            raise ConfigError("nothing to match: pass the error text in quotes, a file with -f, or pipe it in")
        out = kit.known_issues(tk.KnownIssuesIn(text=text, platform=a.platform, version=a.pversion, limit=a.limit))
        if a.format == "text":
            _print_known_issues(out)
        else:
            _emit(out, fmt)
        return 0

    if a.cmd == "signals":
        if a.text and a.file is not None:
            raise ConfigError("pass the text or -f, not both")
        text = "\n".join(a.text) if a.text else _read_text_or_file(a.file if a.file is not None else "-")
        if len(text) > tk.MAX_SIGNAL_TEXT:
            text = alertmanager.compact(text) or text[-tk.MAX_SIGNAL_TEXT :]
        out = kit.extract_signals(tk.SignalsIn(text=text))
        if a.format == "text":
            for x in out["signals"]:
                detail = f"  {x['detail']}" if x.get("detail") else ""
                _tprint(f"{x['kind']:15} {x['name']}{detail}")
            for x in out["implied"]:
                _tprint(f"{x['kind']:15} {x['name']}  implied by '{x['detail']}'")
            if out["playbooks"]:
                _tprint(f"playbooks: {', '.join(out['playbooks'])}")
            if not out["signals"] and not out["implied"]:
                print("no signals found")
        else:
            _emit(out, fmt)
        return 0

    if a.cmd == "ticket":
        out = kit.ticket(tk.TicketIn(key=a.key, version=a.pversion))
        if a.format != "text":
            _emit(out, fmt)
        elif not out.get("found"):
            _tprint(out["note"])
        else:
            _tprint(f"{out['id']}  {out['summary']}")
            resolution = out["resolution"] or "Unresolved"
            _tprint(f"  {out['type']} | {out['jiraStatus']} | {resolution} | updated {out['updated'] or 'unknown'}")
            _tprint(f"  {out['status']}")
            _print_ticket_lines(out)
            for link in out.get("related") or []:
                _tprint(f"  {link['relation']} {link['key']}")
            _tprint(f"  {out['url']}  ({out['source']})")
        return 0 if out.get("found") else 1

    if a.cmd == "policy":
        return _policy(a, s, kit, fmt)

    if a.cmd == "watch":
        return _watch(a, s, fmt)

    if a.cmd == "incidents":
        return _incidents(a, kit, fmt)

    if a.cmd == "bundle":
        from kube_noob.debug.diagnose import bundle_markdown

        kind, _, name = a.target.partition("/")
        if not name:
            raise ConfigError("target must be kind/name, e.g. deployment/orders-api")
        if not s.cluster.enabled:
            raise ConfigError("a bundle needs read-only cluster access: pass --cluster-enabled or set cluster.enabled")
        result = kit.cluster_debug(
            tk.ClusterDebugIn(
                namespace=a.namespace, kind=kind.lower(), name=name, platform=getattr(a, "platform", None)
            )
        )
        bundle_dir = Path(a.out)
        bundle_dir.mkdir(parents=True, exist_ok=True)
        (bundle_dir / "bundle.json").write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        (bundle_dir / "bundle.md").write_text(bundle_markdown(result), encoding="utf-8")
        _emit(
            {"bundle": str(bundle_dir), "files": ["bundle.md", "bundle.json"], "diagnoses": len(result["diagnoses"])},
            fmt,
        )
        return 0

    if a.cmd == "debug":
        kind, _, name = a.target.partition("/")
        if not name:
            raise ConfigError("target must be kind/name, e.g. deployment/orders-api")
        if not s.cluster.enabled:
            raise ConfigError("live debugging needs cluster access: pass --cluster-enabled or set cluster.enabled")
        _emit(
            kit.cluster_debug(
                tk.ClusterDebugIn(
                    namespace=a.namespace, kind=kind.lower(), name=name, platform=getattr(a, "platform", None)
                )
            ),
            fmt,
        )
        return 0

    if a.cmd == "search":
        _emit(kit.search(tk.SearchIn(query=a.query, limit=a.limit, source=a.source)), fmt)
        return 0
    if a.cmd == "rules":
        _emit(kit.rules(tk.EmptyIn()), fmt)
        return 0
    if a.cmd == "explain":
        _emit(kit.explain(tk.RuleIn(rule_id=a.rule_id)), fmt)
        return 0

    if a.cmd == "learn":
        lc = a.learn_cmd
        if lc == "tracks":
            _emit(kit.tracks(tk.LearnerIn(learner=a.learner)), fmt)
        elif lc == "lesson":
            out = kit.lesson(tk.LessonIn(lesson_id=a.lesson_id, learner=a.learner))
            if a.format == "text":
                print(f"# {out['title']}\n\n{out['content']}\n")
                for c in out["citations"]:
                    print(f"- source: {c.get('title')} {c.get('url') or ''} ({c.get('license')})")
            else:
                _emit(out, fmt)
        elif lc == "exercise":
            _emit(kit.exercise(tk.ExerciseIn(exercise_id=a.exercise_id)), fmt)
        elif lc == "submit":
            res = kit.submit(tk.SubmitIn(exercise_id=a.exercise_id, answer=_read(a.file), learner=a.learner))
            _emit(res, fmt)
            return 0 if res["passed"] else 1
        elif lc == "quiz":
            _emit(kit.quiz(tk.QuizIn(question_id=a.question_id, choice=a.choice, learner=a.learner)), fmt)
        elif lc == "progress":
            _emit(kit.progress(tk.LearnerIn(learner=a.learner)), fmt)
        return 0

    if a.cmd == "learning":
        return _learning(a, kit, fmt)

    if a.cmd == "memory":
        return _memory(a, s, kit, fmt)

    if a.cmd == "ask":
        from kube_noob.agent.loop import Agent

        answer_res = Agent(s).ask(a.question)
        if a.format == "text":
            print(answer_res.answer)
            for n in answer_res.notes:
                print(f"\n[note] {n}", file=sys.stderr)
            if answer_res.invalid_citations:
                print(f"\n[warning] invalid citations: {answer_res.invalid_citations}", file=sys.stderr)
        else:
            _emit(answer_res.as_dict(), fmt)
        return 0

    if a.cmd == "mcp":
        from kube_noob.server.mcp_app import build_server

        build_server(s).run("stdio")
        return 0

    if a.cmd == "serve":
        import uvicorn

        from kube_noob.server.http import http_app

        if a.host:
            s.server.host = a.host
        if a.port:
            s.server.port = a.port
        from kube_noob.sources import db_bundle
        from kube_noob.sources.jira_snapshot import seed_on_start

        try:  # a pod starts with the public kube-noob-db (docs, known issues) when its image is newer
            db_seeded = db_bundle.seed_on_start(s.data_dir)
        except (OSError, ValueError, KubeNoobError) as exc:
            print(f"kube-noob-db seed not imported: {exc}", file=sys.stderr)
        else:
            if db_seeded:
                print(
                    f"kube-noob-db imported from {db_seeded['seed']} (built {db_seeded['bundle']['builtAt']}): "
                    f"{', '.join(db_seeded['imported'])}",
                    file=sys.stderr,
                )
        try:  # a pod starts with the organisation's Jira copy instead of waiting for a first sync
            seeded = seed_on_start(s.data_dir)
        except (OSError, ValueError, KubeNoobError) as exc:
            print(f"jira seed not imported: {exc}", file=sys.stderr)
        else:
            if seeded:
                print(f"jira seed imported from {seeded['seed']}: {', '.join(seeded['imported'])}", file=sys.stderr)
        app = http_app(s, allow_unauthenticated=a.allow_unauthenticated)
        if a.watch or s.watch.enabled:
            from kube_noob.watch import start_background

            start_background(s)
        if s.jira.sync_enabled:
            from kube_noob.sources.jira import start_background as start_jira_sync

            if s.offline:
                raise ConfigError("jira.syncEnabled downloads tickets; the offline lock forbids it (unset one)")
            start_jira_sync(s)
        uvicorn.run(
            app,
            host=s.server.host,
            port=s.server.port,
            log_level="info",
            proxy_headers=False,
            server_header=False,
            limit_concurrency=64,  # beyond this, new requests get 503 instead of piling up in memory
            timeout_keep_alive=5,
        )
        return 0

    if a.cmd == "corpus":
        return _corpus(a, s, fmt)
    if a.cmd == "train":
        return _train(a, s, fmt)
    if a.cmd == "config":
        _emit(kit.config_status(tk.EmptyIn()), fmt)
        return 0
    if a.cmd == "selftest" and a.cases:
        from kube_noob.evals import problems

        if a.gate is not None and not 0 <= a.gate <= 1:
            raise ConfigError("--gate is a pass rate from 0 to 1, e.g. 0.9")
        try:
            loaded = problems.load(Path(a.cases))
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        prep = problems.run_cases(s, loaded, a.gate)
        md = problems.markdown(prep)
        if a.out:
            out_dir = Path(a.out)
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "report.md").write_text(md, encoding="utf-8")
            (out_dir / "report.json").write_text(json.dumps(prep, indent=2, ensure_ascii=False) + "\n", "utf-8")
        if a.format == "text":
            _tprint(md.rstrip())
        else:
            _emit(prep, fmt)
        failed = any(r["status"] in {"fail", "error"} for r in prep["results"])
        if prep["gate"] is not None:
            return 0 if prep["gate"]["passed"] else 1
        return 1 if failed else 0
    if a.cmd == "selftest":
        from kube_noob.evals.selftest import run as run_selftest

        rep = run_selftest(s, a.category)
        if a.format == "text":
            print(f"kube-noob self-test: {rep['passed']}/{rep['total']} passed")
            for cat, r in rep["byCategory"].items():
                print(f"  {cat:11} {r['passed']}/{r['total']}")
            for f in rep["failures"]:
                print(f"FAIL {f['id']} ({f['kind']}): {f['detail']}")
        else:
            _emit(rep, fmt)
        return 0 if not rep["failures"] else 1
    if a.cmd == "demo":
        from kube_noob import demo

        if a.list_demos or not a.scenario:
            if a.format == "text":
                for d in demo.listing():
                    print(f"{d['name']:10} {d['title']}  [{d['for']}]")
                print("\nRun: kube-noob demo <name>   or   kube-noob demo all")
            else:
                _emit(demo.listing(), fmt)
            return 0
        names = list(demo.SCENARIOS) if a.scenario == "all" else [a.scenario]
        for n in names:
            if n not in demo.SCENARIOS:
                raise KeyError(f"unknown demo {n!r}; choose from {', '.join(demo.SCENARIOS)} or 'all'")
            demo.run(n, s)
            print()
        return 0
    if a.cmd == "doctor":
        from kube_noob.knowledge_status import line, status
        from kube_noob.posture import posture, render_text

        report = posture(s)
        if a.format == "text":
            print(render_text(report))
            print(f"Knowledge: {line(s.data_dir)}")
        else:
            _emit({**report, "knowledge": status(s.data_dir)}, fmt)
        return 1 if report["conflicts"] else 0
    raise ConfigError(f"unknown command {a.cmd}")


_TERMINAL_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _tprint(text: str = "") -> None:
    """Print text that may echo a manifest or a log: control characters (terminal escapes) are dropped."""
    print(_TERMINAL_CONTROL.sub("", text))


def _print_denials(out: dict[str, Any]) -> None:
    for d in out["denials"]:
        name = " / ".join(x for x in (d.get("policy"), d.get("rule")) if x)
        head = (
            f"{d['engineName']}" + (f"  {name}" if name else "") + (f"  ({d['resource']})" if d.get("resource") else "")
        )
        _tprint(("WARN " if d["mode"] == "warn" else "DENY ") + head)
        _tprint(f"  {d['meaning']}")
        if d.get("path"):
            _tprint(f"  at {d['path']}")
        if d.get("readOnlyNextSteps"):
            _tprint("  check (read-only):")
            for step in d["readOnlyNextSteps"]:
                _tprint(f"    {step.get('command') or step.get('instruction')}")
        if d.get("proposedChanges"):
            _tprint("  fix (needs approval):")
            for c in d["proposedChanges"]:
                _tprint(f"    - {c['change']}")
        if d.get("patch"):
            _tprint("  patch:")
            for line in d["patch"].rstrip().splitlines():
                _tprint(f"    {line}")
        if d.get("relatedRules"):
            _tprint(f"  caught before deploy by: {', '.join(d['relatedRules'])} (kube-noob audit)")
        _tprint()
    if out.get("signals"):
        _tprint("signals: " + ", ".join(f"{x['kind']} {x['name']}" for x in out["signals"]))
    _tprint(out.get("summary") or out.get("note", ""))


def _print_reach(out: dict[str, Any]) -> None:
    _tprint(f"{out['verdict'].upper()}  {out['source']} -> {out['destination']}  {out['protocol']} {out['port']}")
    for direction in ("egress", "ingress"):
        r = out[direction]
        _tprint(f"  {direction:7} {'allowed' if r['allowed'] else 'DENIED '}  {r['reason']}")
        for pol in [] if r["allowed"] else r.get("policies", []):
            for rule in pol.get("rules", []):
                if not rule["allows"]:
                    miss = [x for x, ok in (("peer", rule["peerMatches"]), ("port", rule["portMatches"])) if not ok]
                    _tprint(
                        f"          {pol['policy']} rule {rule['rule']}: allows {rule['peer']} on {rule['ports']} "
                        f"(no match: {', '.join(miss)})"
                    )
    if out.get("warning"):
        _tprint(f"  warning: {out['warning']}")
    for c in out.get("proposedChanges", []):
        _tprint(f"\n  fix (needs approval): {c['change']}")
        for line in (c.get("manifest") or "").rstrip().splitlines():
            _tprint(f"    {line}")
    _tprint("\n  check (read-only):")
    for step in out.get("readOnlyNextSteps", []):
        _tprint(f"    {step['command']}")
    _tprint("\n  not evaluated: " + "; ".join(out.get("notEvaluated", [])))


def _policy(a: argparse.Namespace, s: Settings, kit: Any, fmt: str) -> int:
    from kube_noob import toolkit as tk

    if a.policy_cmd == "explain":
        if a.text and a.file is not None:
            raise ConfigError("pass the text or -f, not both")
        text = "\n".join(a.text) if a.text else _read_text_or_file(a.file if a.file is not None else "-")
        if len(text.strip()) < 3:
            raise ConfigError("nothing to explain: pass the denial in quotes, a file with -f, or pipe it in")
        out = kit.explain_denial(tk.PolicyExplainIn(text=text, platform=getattr(a, "platform", None)))
        _print_denials(out) if a.format == "text" else _emit(out, fmt)
        return 0
    port: int | str = int(a.port) if str(a.port).isdigit() else a.port
    platform = getattr(a, "platform", None)
    if a.live:
        if a.file:
            raise ConfigError("pass -f manifests or --live, not both")
        if not s.cluster.enabled:
            raise ConfigError("--live needs read-only cluster access: pass --cluster-enabled or set cluster.enabled")
        out = kit.cluster_check_traffic(
            tk.TrafficIn(source=a.source, destination=a.destination, port=port, protocol=a.protocol, platform=platform)
        )
    else:
        if not a.file:
            raise ConfigError("pass the NetworkPolicies and workloads with -f (repeat for several), or use --live")
        manifests = "\n---\n".join(_read(f) for f in a.file)
        out = kit.check_network_policy(
            tk.NetpolCheckIn(
                manifests=manifests,
                source=a.source,
                destination=a.destination,
                port=port,
                protocol=a.protocol,
                platform=platform,
                default_namespace=a.default_namespace,
            )
        )
    _print_reach(out) if a.format == "text" else _emit(out, fmt)
    return 0 if out["verdict"] == "allowed" else 1


def _print_poll(result: dict[str, Any]) -> None:
    ch = result["changes"]
    _tprint(
        f"{result['polledAt']}  {', '.join(result['namespaces']) or 'nothing readable'}: "
        f"{len(ch['opened'])} new, {len(ch['reopened'])} back again, {len(ch['resolved'])} resolved, "
        f"{len(result['open'])} open"
    )
    for row in result["open"]:
        _tprint(f"  {row['id']}  {row['headline']}")
    for err in result.get("errors", []):
        _tprint(f"  read failed: {err}")


def _watch(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    import threading

    from kube_noob.debug.cluster import get_backend
    from kube_noob.watch import Watcher, resolve_namespaces

    if not s.cluster.enabled:
        raise ConfigError("watch needs read-only cluster access: pass --cluster-enabled or set cluster.enabled")
    if a.interval is not None:
        if not 15 <= a.interval <= 3600:
            raise ConfigError("--interval must be 15 to 3600 seconds")
        s.watch.interval_seconds = a.interval
    watcher = Watcher(s, get_backend(s), resolve_namespaces(s, a.namespaces), getattr(a, "platform", None))
    if a.once:
        result = watcher.poll()
        _print_poll(result) if a.format == "text" else _emit(result, fmt)
        return 0
    stop = threading.Event()
    try:
        while not stop.is_set():
            result = watcher.poll()
            _print_poll(result) if a.format == "text" else _emit(result, fmt)
            sys.stdout.flush()
            stop.wait(s.watch.interval_seconds)
    except KeyboardInterrupt:
        return 0
    return 0


def _incidents(a: argparse.Namespace, kit: Any, fmt: str) -> int:
    from kube_noob import toolkit as tk

    cmd = a.incidents_cmd or "list"
    if cmd == "show":
        out = kit.incident(tk.IncidentIn(id=a.incident_id))
        _emit(out, fmt)
        return 0
    if cmd == "confirm":
        _emit(
            kit.incident_confirm(
                tk.IncidentConfirmIn(id=a.incident_id, cause=a.cause, fix=a.fix, confirmed_by_user=True)
            ),
            fmt,
        )
        return 0
    out = kit.incidents(
        tk.IncidentsIn(
            status="all" if getattr(a, "all", False) else "open", namespace=getattr(a, "namespace", None), limit=100
        )
    )
    if a.format == "text":
        for row in out["incidents"]:
            _tprint(f"{row['id']}  {row['status']:8} x{row['occurrences']}  {row['headline']}")
        if out.get("note"):
            _tprint(out["note"])
    else:
        _emit(out, fmt)
    return 0


def _memory(a: argparse.Namespace, s: Settings, kit: Any, fmt: str) -> int:
    from datetime import date

    from pydantic import ValidationError

    from kube_noob.memory import match as mmatch
    from kube_noob.memory import repo, verify

    cmd = a.memory_cmd
    if cmd == "init":
        out: dict[str, Any] = {"repository": a.dir, **repo.init_repo(Path(a.dir))}
        if a.format == "text":
            for rel in out["created"]:
                _tprint(f"created {rel}")
            for rel in out["kept"]:
                _tprint(f"kept    {rel} (already there)")
            _tprint(f"next: kube-noob memory add {a.dir} --symptom ... --cause ... --fix ...")
        else:
            _emit(out, fmt)
        return 0
    if cmd == "add":
        from kube_noob.debug.steps import classify_step

        signals = []
        for raw in a.signal:
            kind, sep, name = raw.partition(":")
            if not sep:
                raise ConfigError(f"--signal {raw!r}: use kind:name, e.g. alert:etcdNoLeader")
            signals.append({"kind": kind, "name": name})
        fields: dict[str, Any] = {
            "kind": a.kind,
            "signals": signals,
            "symptom": a.symptom,
            "platform": a.platform or s.default_platform or "kubernetes",
            "versions": {k: v for k, v in (("introduced", a.introduced), ("fixedIn", a.fixed_in)) if v},
            "cause": a.cause,
            "fix": {
                "text": a.fix,
                "commands": [
                    {"command": c, "label": "read-only" if classify_step(c) == "read" else "needs-approval"}
                    for c in a.commands
                ],
            },
            "owners": a.owners or ["unassigned"],
            "sources": a.sources,
        }
        try:
            path, entry = repo.add_entry(Path(a.dir), fields)
        except ValidationError as exc:
            raise ValueError(f"entry not written: {repo._reason(exc)}") from None
        out = {"written": str(path), "id": entry.id, "status": entry.status}
        if a.format == "text":
            _tprint(f"wrote {path} ({entry.id}, proposed): review it, then set status: approved")
        else:
            _emit(out, fmt)
        return 0
    if cmd == "validate":
        rep = verify.validate_repo(Path(a.dir), strict=a.strict)
        if a.format == "text":
            for p in rep["errors"] + rep["warnings"]:
                who = p["entry"] or p["file"]
                _tprint(f"{p['level'].upper():7} {who}  {p['check']}: {p['detail']}")
            _tprint(
                f"{rep['entries']} entries ({rep['approved']} approved, {rep['proposed']} proposed, "
                f"{rep['retired']} retired): {len(rep['errors'])} errors, {len(rep['warnings'])} warnings"
            )
        else:
            _emit(rep, fmt)
        return 0 if rep["ok"] else 1
    if cmd == "match":
        if a.text and a.file is not None:
            raise ConfigError("pass the text or -f, not both")
        text = "\n".join(a.text) if a.text else _read_text_or_file(a.file if a.file is not None else "-")
        if len(text.strip()) < 3:
            raise ConfigError("nothing to match: pass the error text in quotes, a file with -f, or pipe it in")
        dirs = a.dirs or [str(d) for d in s.memory.paths]
        if not dirs:
            raise ConfigError("pass the memory repository with --dir (repeat for several) or set memory.paths")
        operators: dict[str, str] = {}
        for raw in a.operator:
            name, sep, ver = raw.partition("=")
            if not sep or not name or not ver:
                raise ConfigError(f"--operator {raw!r}: use name=version")
            operators[name] = ver
        out = mmatch.match(
            [Path(d) for d in dirs],
            text,
            version=a.pversion,
            platform=a.platform,
            operators=operators,
            include_proposed=a.include_proposed,
            limit=max(1, min(a.limit, 50)),
        )
        if a.format == "text":
            _print_memory_matches(out)
        else:
            _emit(out, fmt)
        return 0
    if cmd == "outcome":
        when = date.fromisoformat(a.when) if a.when else None
        try:
            entry = repo.add_outcome(Path(a.dir), a.entry_id, a.result, a.ticket, a.cluster, when)
        except ValidationError as exc:
            raise ValueError(f"outcome not recorded: {repo._reason(exc)}") from None
        o = entry.outcomes[-1]
        out = {"id": entry.id, "outcome": o.model_dump(mode="json", exclude_none=True), "outcomes": len(entry.outcomes)}
        if a.format == "text":
            _tprint(f"{entry.id}: recorded {o.result} on {o.date} ({len(entry.outcomes)} outcomes)")
        else:
            _emit(out, fmt)
        return 0
    if cmd == "stats":
        out = mmatch.stats(Path(a.dir), a.by)
        if a.format == "text":
            _tprint(
                f"{out['entries']} entries: "
                + ", ".join(f"{v} {k}" for k, v in out["byStatus"].items())
                + " | outcomes: "
                + ", ".join(f"{v} {k}" for k, v in out["outcomes"].items())
            )
            for g in out.get("groups", []):
                _tprint(
                    f"  {g['key']:40} {len(g['entries'])} entries, applied {g['applied']}, resolved {g['resolved']}"
                )
        else:
            _emit(out, fmt)
        return 0
    if cmd == "replay":
        from kube_noob.memory.importers import MAX_EXPORT
        from kube_noob.memory.replay import load_labels, markdown, replay

        for f in (a.tickets, a.labels):
            if f and not Path(f).is_file():
                raise ConfigError(f"no file {f}")
        if Path(a.tickets).stat().st_size > MAX_EXPORT:
            raise ConfigError(f"{a.tickets} is larger than {MAX_EXPORT // 1_000_000} MB")
        labels = load_labels(Path(a.labels).read_text(encoding="utf-8")) if a.labels else None
        out = replay(
            Path(a.memory),
            a.ticket_format,
            Path(a.tickets).read_text(encoding="utf-8"),
            labels,
            a.as_of_ticket_date,
            include_proposed=not a.approved_only,
        )
        md = markdown(out)
        if a.out:
            target = Path(a.out)
            target.mkdir(parents=True, exist_ok=True)
            (target / "report.md").write_text(md, encoding="utf-8")
            (target / "report.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        if a.format == "text":
            print(md, end="")
        else:
            _emit(out, fmt)
        return 0
    if cmd == "import":
        from kube_noob.memory.importers import MAX_EXPORT, import_tickets

        if a.file != "-" and not Path(a.file).is_file():
            raise ConfigError(f"no export file {a.file}")
        if a.file != "-" and Path(a.file).stat().st_size > MAX_EXPORT:
            raise ConfigError(f"{a.file} is larger than {MAX_EXPORT // 1_000_000} MB; export fewer tickets at a time")
        text = sys.stdin.read(MAX_EXPORT + 1) if a.file == "-" else Path(a.file).read_text(encoding="utf-8")
        out = import_tickets(
            Path(a.dir),
            a.ticket_format,
            text,
            a.platform or s.default_platform or "kubernetes",
            a.owner,
            a.cluster,
            a.dry_run,
        )
        if a.format == "text":
            verb = "would write" if a.dry_run else "wrote"
            for c in out["created"]:
                _tprint(f"{c['ticket']} -> {c['entry']} ({c['outcome']}, proposed)")
            for sk in out["skipped"]:
                _tprint(f"{sk['ticket']} skipped: {sk['reason']}")
            _tprint(f"{verb} {len(out['created'])} proposed entries; skipped {len(out['skipped'])} tickets")
        else:
            _emit(out, fmt)
        return 0
    notes = kit.learning.notes()
    out = repo.migrate_learning(Path(a.dir), notes, a.owner, s.default_platform or "kubernetes")
    if a.format == "text":
        for c in out["created"]:
            _tprint(f"{c['note']} -> {c['entry']} (proposed)")
        for sk in out["skipped"]:
            _tprint(f"{sk['note']} skipped: {sk['reason']}")
        if not out["created"] and not out["skipped"]:
            _tprint("no confirmed learning notes to migrate")
    else:
        _emit(out, fmt)
    return 0


def _print_memory_matches(out: dict[str, Any]) -> None:
    for m in out["matches"]:
        head = {"fix": "fix", "runbook": "runbook", "tried, did not work": "tried, did not work", "retired": "retired"}
        _tprint(f"{m['citation']} {head[m['state']]} ({m['status']}): {m['symptom']}")
        if m.get("note"):
            _tprint(f"  {m['note']}")
        by = m["matchedBy"]
        _tprint("  matched by: " + ", ".join(by["signals"] + [f"word {w}" for w in by["words"][:5]]))
        _tprint(f"  cause: {m['cause']}")
        _tprint(f"  fix: {m['fix']['text']}")
        for c in m["fix"]["commands"]:
            _tprint(f"    {'check' if c['label'] == 'read-only' else 'needs approval'}: {c['command']}")
        _tprint(f"  {m['outcomes']['summary']}")
        _tprint(f"  {m['repository']}/{m['file']}")
    if out.get("note"):
        _tprint(out["note"])
    q = out["query"]
    _tprint(
        f"memory: {sum(r['entries'] for r in out['repositories'])} entries in {len(out['repositories'])} "
        f"repositor{'y' if len(out['repositories']) == 1 else 'ies'}"
        + (f"; version {q['version']} ({q.get('versionFrom')})" if q.get("version") else "")
    )


def _learning(a: argparse.Namespace, kit: Any, fmt: str) -> int:
    from kube_noob import toolkit as tk

    lc = a.learning_cmd
    if lc == "show":
        out = kit.learning_summary(tk.EmptyIn())
    elif lc == "note":
        out = kit.learning_note_add(
            tk.LearningNoteIn(
                symptom=a.symptom, cause=a.cause, fix=a.fix, platform=a.platform, tags=a.tags, confirmed_by_user=True
            )
        )
    elif lc == "forget":
        if not kit.learning.forget(a.note_id):
            raise KeyError(f"no note {a.note_id}; see `kube-noob learning show`")
        out = {"forgotten": a.note_id}
    else:
        versions = {
            k: getattr(a, k) for k in ("kubernetes", "openshift", "helm", "rhacs", "rosa") if getattr(a, k, None)
        }
        out = kit.learning_profile_set(
            tk.LearningProfileIn(platform=a.platform, versions=versions, conventions=a.conventions)
        )
    _emit(out, fmt)
    return 0


def _corpus(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    from kube_noob.sources.corpus import read_manifest, verify, write_shard

    cc = a.corpus_cmd
    if cc in {"build", "jira", "jira-projects", "history", "known-issues"} and s.offline:
        raise ConfigError(
            "the offline lock is on (offline: true / KUBE_NOOB_OFFLINE); corpus downloads are blocked. "
            "Import a prepared corpus instead: kube-noob corpus import <dir-or-tgz>"
        )
    if cc in {"build", "jira", "jira-projects", "history", "known-issues"} and not (a.online or s.web_enabled):
        raise ConfigError("corpus ingestion uses the network; pass --online (or set webEnabled: true)")
    if cc == "known-issues":
        import tempfile

        from kube_noob.sources.release_notes import fetch, snapshot

        minors = [m.strip() for m in a.minors.split(",") if m.strip()]
        with tempfile.TemporaryDirectory(prefix="kube-noob-rn-") as tmp:
            records, commits = fetch(minors, Path(tmp))
        out_dir = s.data_dir / "known_issues"
        out_dir.mkdir(parents=True, exist_ok=True)
        target = out_dir / "openshift-release-notes.json"
        target.write_text(json.dumps(snapshot(records, commits), ensure_ascii=False) + "\n", encoding="utf-8")
        _emit({"file": str(target), "issues": len(records), "commits": commits}, fmt)
        return 0
    if cc == "build":
        from kube_noob.sources.git_ingest import ingest
        from kube_noob.sources.registry import GIT_SOURCES, by_id

        sources = GIT_SOURCES if a.sources == "all" else tuple(by_id(x.strip()) for x in a.sources.split(","))
        summary = {}
        from kube_noob.sources.pacing import pause

        for i, src in enumerate(sources):
            if i:
                pause()  # jittered gap between clones from the same host
            try:
                recs = list(ingest(src, limit=a.limit_per_source))
                summary[src.source_id] = write_shard(s.data_dir, f"git-{src.source_id}", recs)["records"]
            except KubeNoobError as exc:
                summary[src.source_id] = f"error: {exc}"
            print(f"{src.source_id}: {summary[src.source_id]}", file=sys.stderr)
        _emit({"dataDir": str(s.data_dir), "sources": summary}, fmt)
        return 0 if all(isinstance(v, int) for v in summary.values()) else 4
    if cc in {"jira", "jira-projects"}:
        from kube_noob.jira_catalog import DEFAULT_PROJECTS
        from kube_noob.sources.jira import JiraClient, jira_http, run_sync

        email, api_token = os.environ.get("JIRA_EMAIL"), os.environ.get("JIRA_API_TOKEN")
        if bool(email) != bool(api_token):
            raise ConfigError("Set both JIRA_EMAIL and JIRA_API_TOKEN for an authenticated pull, or neither")
        auth = (email, api_token) if email and api_token else None
        if cc == "jira-projects":
            with jira_http(s, s.jira.base_url) as http:
                projects = JiraClient(http, s.jira.base_url, auth=auth, max_requests=20).projects()
            rows = [{**p, "default": p["key"] in DEFAULT_PROJECTS} for p in projects]
            if a.format == "text":
                for r in rows:
                    _tprint(f"{'*' if r['default'] else ' '} {r['key']:12} {r['name']}")
                print(f"{len(rows)} projects; * = in the default set (kube-noob corpus jira --online)")
            else:
                _emit({"projects": rows}, fmt)
            return 0
        if a.max_requests is not None and not 1 <= a.max_requests <= 100_000:
            raise ConfigError("--max-requests must be 1 to 100000")
        out = run_sync(s, a.projects, a.max_requests, auth)
        if a.format == "text":
            for p in out["projects"]:
                state = "complete" if p.get("complete") else "partial, resumes next run"
                extra = f" ({p['error']})" if p.get("error") else ""
                _tprint(f"{p['project']:10} +{p['fetched']:<6} {p['total']:>7} tickets  {state}{extra}")
            if out["skipped"]:
                print(f"not reached this run (budget): {', '.join(out['skipped'])}")
            idx = out.get("index") or {}
            print(
                f"{out['requests']} requests ({out.get('commentRequests', 0)} for comments), {out['retries']} retries; "
                f"index: {idx.get('tickets', 0)} tickets retrieved {idx.get('asOf')}"
            )
            changed = out.get("changes") or {}
            if changed:
                counts = ", ".join(f"{n} {k}" for k, n in changed.items())
                print(f"changes recorded: {counts} (kube-noob corpus jira-changes --since 1d)")
        else:
            _emit(out, fmt)
        errors = [p for p in out["projects"] if p.get("error")]
        return 4 if errors and len(errors) == len(out["projects"]) else 0
    if cc == "history":
        from kube_noob.sources.history import minor_timeline, tags_with_dates, timeline_record
        from kube_noob.sources.registry import HISTORY_REPOS

        recs = []
        for name, repo in HISTORY_REPOS.items():
            try:
                tl = minor_timeline(tags_with_dates(repo))
                recs.append(timeline_record(name, repo, tl))
                print(f"{name}: {len(tl)} minors", file=sys.stderr)
            except KubeNoobError as exc:
                print(f"{name}: error {exc}", file=sys.stderr)
        _emit(write_shard(s.data_dir, "history", recs), fmt)
        return 0
    if cc == "stats":
        from kube_noob.knowledge.store import get_store

        _emit({"manifest": read_manifest(s.data_dir), "index": get_store(s.data_dir).stats()}, fmt)
        return 0
    if cc == "add-docs":
        from kube_noob.sources.org_docs import ingest_org_docs

        _emit(ingest_org_docs(Path(a.path), s.data_dir, a.source, a.base_url), fmt)
        return 0
    if cc == "jira-audit":
        from kube_noob import jira_audit

        report = jira_audit.audit(s.data_dir, a.project)
        if a.format == "text":
            for line in jira_audit.text_report(report):
                _tprint(line)
        else:
            _emit(report, fmt)
        return 0 if report.get("available") is not False else 1
    if cc == "jira-snapshot":
        from kube_noob.sources.jira_snapshot import export_snapshot

        out = export_snapshot(s.data_dir, Path(a.out))
        if a.format == "text":
            project_list = ", ".join(out["projects"])
            _tprint(
                f"{out['snapshot']}: {out['tickets']} tickets ({project_list}), {out['changes']} changes, "
                f"last sync {out['lastSync']}, {out['bytes'] // 1_000_000} MB"
            )
            _tprint(out["note"])
        else:
            _emit(out, fmt)
        return 0
    if cc == "jira-changes":
        from kube_noob import ticket_changes

        try:
            since = ticket_changes.parse_since(a.since)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        res = ticket_changes.changes(s.data_dir, since, a.project, a.kind, max(1, min(a.limit, 5000)))
        opened = ticket_changes.open_summary(s.data_dir, a.project)
        if a.format == "text":
            _print_ticket_changes(res, opened)
        else:
            _emit({**res, "openTickets": opened}, fmt)
        return 0
    if cc == "import":
        from kube_noob.sources import db_bundle
        from kube_noob.sources.corpus import import_corpus

        where = Path(a.path)
        if not where.exists():
            raise ConfigError(f"no such file or folder: {where}")
        if db_bundle.is_bundle(where):
            _emit(db_bundle.import_bundle(where, s.data_dir), fmt)
        else:
            _emit(import_corpus(where, s.data_dir), fmt)
        return 0
    if cc == "db-bundle":
        from kube_noob.sources import db_bundle

        out = db_bundle.build(s.data_dir, Path(a.output))
        if a.format == "text":
            _tprint(
                f"wrote {out['bundle']} ({out['bytes'] / 1_000_000:.1f} MB, sha256 {out['sha256'][:16]}...): "
                f"{out['records']} records in {len(out['shards'])} shards, {out['knownIssueFiles']} known-issue files"
            )
            _tprint("licenses: " + ", ".join(f"{n} {k}" for k, n in out["licenses"].items()))
            if out["leftOut"]:
                _tprint("left out (not redistributable or Jira): " + ", ".join(out["leftOut"]))
        else:
            _emit(out, fmt)
        return 0
    if cc == "db-check":
        from kube_noob.sources import db_bundle

        where = Path(a.path)
        if not where.exists():
            raise ConfigError(f"no such file or folder: {where}")
        problems = db_bundle.check_archive(where)
        if a.format == "text":
            _tprint(f"{where}: ok" if not problems else f"{where}: {len(problems)} problems")
            for p in problems:
                _tprint(f"  {p}")
        else:
            _emit({"ok": not problems, "problems": problems}, fmt)
        return 1 if problems else 0
    problems = verify(s.data_dir)
    _emit({"ok": not problems, "problems": problems}, fmt)
    return 0 if not problems else 1


def _train(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    tc = a.train_cmd
    if tc == "export":
        from kube_noob.evals.export import export_grpo, export_sft
        from kube_noob.knowledge.store import get_store

        out = Path(a.out)
        res = {
            "sft": export_sft(out / "sft.jsonl", get_store(s.data_dir), a.include_restricted, a.synthetic_limit),
            "grpo": export_grpo(out / "grpo_prompts.jsonl"),
        }
        _emit(res, fmt)
        return 0
    if tc == "grade":
        from kube_noob.evals.reward import grade_by_id
        from kube_noob.knowledge.store import get_store

        _emit(grade_by_id(a.task, _read(a.file), get_store(s.data_dir)).as_dict(), fmt)
        return 0
    if tc == "tasks":
        from kube_noob.evals.reward import benchmark

        _emit([{"id": t["id"], "type": t.get("type"), "prompt": t["prompt"]} for t in benchmark().values()], fmt)
        return 0
    from kube_noob.evals.runner import run_benchmark

    rep = run_benchmark(s, a.tasks.split(",") if a.tasks else None, use_tools=not a.no_tools)
    if a.out:
        Path(a.out).write_text(json.dumps(rep, indent=2, default=str), encoding="utf-8")
    _emit({k: v for k, v in rep.items() if k != "results"} if a.out else rep, fmt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
