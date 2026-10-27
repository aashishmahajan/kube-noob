"""kube-noob command line.

Exit codes: 0 ok | 1 findings at/above --fail-on | 2 usage/config error | 3 clarification needed | 4 runtime error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml

from kube_noob import __version__
from kube_noob.config import Settings, load_settings, set_settings
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


def _emit(obj: Any, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(obj, indent=2, default=str))
    else:
        print(yaml.safe_dump(obj, sort_keys=False, width=120, allow_unicode=True), end="")


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
        description="Offline-first Kubernetes/OpenShift/ROSA/Helm/RHACS learning, audit and debugging agent.",
        parents=[common],
    )
    p.set_defaults(config=None, web_enabled=False, cluster_enabled=False, format="text")
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

    d = sub.add_parser("diagnose", help="Diagnose pasted events/logs/errors offline")
    d.add_argument("-f", "--file", default="-")
    d.add_argument("--platform", choices=PLATFORMS)

    dbg = sub.add_parser("debug", help="Collect live read-only evidence for a workload and diagnose it")
    dbg.add_argument("target", help="kind/name, e.g. deployment/orders-api")
    dbg.add_argument("-n", "--namespace", required=True)
    dbg.add_argument("--platform", choices=PLATFORMS)

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

    ask = sub.add_parser("ask", help="Ask the agent (LLM + local tools)")
    ask.add_argument("question")

    sub.add_parser("mcp", help="Run the MCP server over stdio")
    sv = sub.add_parser("serve", help="Run the MCP server over streamable HTTP (sidecar/service)")
    sv.add_argument("--host")
    sv.add_argument("--port", type=int)
    sv.add_argument("--allow-unauthenticated", action="store_true")

    c = sub.add_parser("corpus", help="Build / inspect the local corpus (network: maintainers & CI)")
    csub = c.add_subparsers(dest="corpus_cmd", required=True)
    _patch(csub, common)
    cb = csub.add_parser("build", help="Ingest public Git sources")
    cb.add_argument("--sources", default="all", help="comma-separated source ids or 'all'")
    cb.add_argument("--limit-per-source", type=int)
    cb.add_argument("--online", action="store_true", help="Required: confirm network ingestion")
    cj = csub.add_parser("jira", help="Pull public Jira issues (jittered, rate-limited)")
    cj.add_argument("--project", default="ROX")
    cj.add_argument("--base-url", default="https://redhat.atlassian.net")
    cj.add_argument("--min-version", default="4.10")
    cj.add_argument("--target", type=int, default=1200)
    cj.add_argument("--max-scan", type=int, default=6000)
    cj.add_argument("--online", action="store_true")
    ch = csub.add_parser("history", help="Release timelines from Git tags")
    ch.add_argument("--online", action="store_true")
    csub.add_parser("stats")
    csub.add_parser("verify")
    ci = csub.add_parser("import", help="Import a corpus directory or .tgz (e.g. the corpus-refresh artifact)")
    ci.add_argument("path")

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
    return p


def _settings(a: argparse.Namespace) -> Settings:
    overrides: dict[str, Any] = {}
    if a.web_enabled:
        overrides["webEnabled"] = True
    if a.cluster_enabled:
        overrides["cluster"] = {"enabled": True}
    s = load_settings(a.config, overrides)
    set_settings(s)
    return s


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    a = parser.parse_args(argv)
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
        print(f"error: {exc}", file=sys.stderr)
        return 4


def _dispatch(a: argparse.Namespace, s: Settings) -> int:
    from kube_noob import toolkit as tk

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

    if a.cmd == "diagnose":
        _emit(kit.diagnose(tk.DiagnoseIn(text=_read(a.file), platform=getattr(a, "platform", None))), fmt)
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

        from kube_noob.server.mcp_app import http_app

        if a.host:
            s.server.host = a.host
        if a.port:
            s.server.port = a.port
        app = http_app(s, allow_unauthenticated=a.allow_unauthenticated)
        uvicorn.run(
            app, host=s.server.host, port=s.server.port, log_level="info", proxy_headers=False, server_header=False
        )
        return 0

    if a.cmd == "corpus":
        return _corpus(a, s, fmt)
    if a.cmd == "train":
        return _train(a, s, fmt)
    if a.cmd == "config":
        _emit(kit.config_status(tk.EmptyIn()), fmt)
        return 0
    raise ConfigError(f"unknown command {a.cmd}")


def _corpus(a: argparse.Namespace, s: Settings, fmt: str) -> int:
    from kube_noob.sources.corpus import read_manifest, verify, write_shard

    cc = a.corpus_cmd
    if cc in {"build", "jira", "history"} and not (a.online or s.web_enabled):
        raise ConfigError("corpus ingestion uses the network; pass --online (or set webEnabled: true)")
    if cc == "build":
        from kube_noob.sources.git_ingest import ingest
        from kube_noob.sources.registry import GIT_SOURCES, by_id

        sources = GIT_SOURCES if a.sources == "all" else tuple(by_id(x.strip()) for x in a.sources.split(","))
        summary = {}
        for src in sources:
            try:
                recs = list(ingest(src, limit=a.limit_per_source))
                summary[src.source_id] = write_shard(s.data_dir, f"git-{src.source_id}", recs)["records"]
            except KubeNoobError as exc:
                summary[src.source_id] = f"error: {exc}"
            print(f"{src.source_id}: {summary[src.source_id]}", file=sys.stderr)
        _emit({"dataDir": str(s.data_dir), "sources": summary}, fmt)
        return 0 if all(isinstance(v, int) for v in summary.values()) else 4
    if cc == "jira":
        from datetime import UTC, datetime

        from kube_noob.net import Purpose, http_client
        from kube_noob.sources.jira import JiraClient, insights, insights_markdown, pull_project

        email, api_token = os.environ.get("JIRA_EMAIL"), os.environ.get("JIRA_API_TOKEN")
        if bool(email) != bool(api_token):
            raise ConfigError("Set both JIRA_EMAIL and JIRA_API_TOKEN for an authenticated pull, or neither")
        auth = (email, api_token) if email and api_token else None
        with http_client(s, Purpose.SOURCES, allow_sources=True, timeout=60) as http:
            client = JiraClient(http, a.base_url, auth=auth)
            res = pull_project(client, a.project, a.min_version, a.target, a.max_scan, a.base_url)
        entry = write_shard(s.data_dir, f"jira-{a.project.lower()}", res.records)
        ins = insights(res.records, a.project)
        now = datetime.now(UTC).isoformat(timespec="seconds")
        write_shard(
            s.data_dir,
            f"jira-{a.project.lower()}-insights",
            [
                {
                    "id": f"insights-jira-{a.project.lower()}",
                    "title": f"{a.project} issue insights ({a.min_version}+)",
                    "text": insights_markdown(ins, now, a.min_version),
                    "url": f"{a.base_url}/browse/{a.project}",
                    "sourceId": f"jira-insights:{a.project}",
                    "license": "aggregate statistics derived by kube-noob",
                    "redistributable": True,
                    "retrievedAt": now,
                }
            ],
        )
        _emit(
            {
                "records": len(res.records),
                "scanned": res.stats.scanned,
                "requests": res.stats.requests,
                "retries": res.stats.retries,
                "strategy": res.stats.strategy,
                "errors": res.stats.errors,
                "versionsConsidered": res.versions_considered,
                "gaFloor": res.ga_floor,
                "shard": entry,
                "insights": ins,
            },
            fmt,
        )
        return 0 if len(res.records) >= min(a.target, 1) else 4
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
    if cc == "import":
        from kube_noob.sources.corpus import import_corpus

        _emit(import_corpus(Path(a.path), s.data_dir), fmt)
        return 0
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
