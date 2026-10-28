"""SAST1 (R4.5-R4.7): SARIF from five tools normalised and merged, code findings followed into images and pods,
language-package vulnerabilities pointed at the dependency line to change."""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import json
import random
import sys
from pathlib import Path
from typing import Any

import pytest

from kube_noob.attack_paths import Inventory, workload_reach
from kube_noob.cli import main
from kube_noob.code import assess, deps, sarif, ship
from kube_noob.config import load_settings
from kube_noob.vuln import reports as vr
from kube_noob.yamlio import load_documents

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "code"
SOURCE_ROOT = "/home/runner/work/shop/shop"
TOOLS = ("semgrep.sarif", "bandit.sarif", "spotbugs.sarif", "eslint.sarif", "codeql.sarif")
SCANS = ("trivy-web.json", "grype-api.json", "cyclonedx-worker.json")
BUILDS = [
    ("web/Containerfile", "quay.io/acme/shop-web", "web"),
    ("ui/Containerfile", "quay.io/acme/shop-ui", "ui"),
    ("api/Containerfile", "quay.io/acme/shop-api", "api"),
    ("worker/Containerfile", "quay.io/acme/shop-worker", "worker"),
]


@pytest.fixture(scope="module")
def fx(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("code")
    spec = importlib.util.spec_from_file_location("code_generate", FIX / "generate.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["code_generate"] = mod
    spec.loader.exec_module(mod)
    mod.main(out)
    return out


def _expected(fx: Path) -> dict[str, Any]:
    return dict(json.loads((fx / "expected.json").read_text()))


def _sarifs(fx: Path, roots: list[str] | None = None) -> list[sarif.SarifReport]:
    return [sarif.parse((fx / n).read_bytes(), n, roots=[SOURCE_ROOT] if roots is None else roots) for n in TOOLS]


def _builds(fx: Path) -> list[ship.Build]:
    repo = fx / "repo"
    out = []
    for cfile, image, ctx in BUILDS:
        ign = repo / ctx / ".dockerignore"
        text = (repo / cfile).read_text()
        out.append(ship.parse_build(ship.Build(cfile, text, image, ctx, ign.read_text() if ign.exists() else "")))
    return out


def _files(fx: Path) -> dict[str, str]:
    repo = fx / "repo"
    return {p.relative_to(repo).as_posix(): p.read_text() for p in repo.rglob("*") if p.is_file()}


def _reach() -> dict[str, Any]:
    text = (FIX / "shop.yaml").read_text()
    return dict(workload_reach(Inventory.from_documents(d.data for d in load_documents(text))))


def _assess(fx: Path) -> dict[str, Any]:
    scans = [vr.parse((fx / n).read_bytes(), n) for n in SCANS]
    return assess.assess(_sarifs(fx), _builds(fx), _reach(), scans, _files(fx), top=50)


# -- R4.5: SARIF from five tools -------------------------------------------------------------------------------------


def test_every_tool_normalises_and_the_same_weakness_merges(fx: Path) -> None:
    out = _assess(fx)
    exp = _expected(fx)["findings"]
    got = {r["finding"]["id"]: r for r in out["ranking"]["ranked"]}
    got.update({x["id"]: {"finding": x, "shipped": []} for x in out["notShipped"]})
    assert set(got) == set(exp)
    for fid, want in exp.items():
        f = got[fid]["finding"]
        assert f["tools"] == want["tools"], fid
        assert f["severity"] == want["severity"], fid
        shipped = [[s["image"], s["how"]] for s in got[fid]["shipped"]]
        assert shipped == want["shipped"], fid
    c = out["counts"]
    assert (c["results"], c["findings"], c["mergedAcrossTools"], c["excluded"], c["quality"]) == (15, 8, 3, 2, 2)
    assert set(out["tools"]) == {
        "Bandit 1.7.10",
        "CodeQL 2.19.1",
        "ESLint 9.12.0",
        "Semgrep OSS 1.95.0",
        "SpotBugs 4.8.6",
    }


def test_tool_shapes(fx: Path) -> None:
    by_tool = {s.tools[0].split()[0]: s for s in _sarifs(fx)}
    spot = by_tool["SpotBugs"].findings[0]
    assert spot.message == "This use of java/sql/Statement.executeQuery(String) can be vulnerable to SQL injection"
    assert spot.cwe == (89,) and spot.location.path == "worker/src/main/java/com/acme/Report.java", "hashed base"
    cq = {f.rule_id: f for f in by_tool["CodeQL"].findings}
    assert cq["py/sql-injection"].title == "SQL query built from user-controlled sources", "rule from extensions[0]"
    assert cq["java/sql-injection"].title == "Query built from user-controlled sources", "rule from extensions[1]"
    assert cq["py/sql-injection"].score == 8.8 and cq["py/sql-injection"].message.endswith("user-provided value.")
    assert cq["py/sql-injection"].fingerprint.startswith("primaryLocationLineHash:")
    es = {f.rule_id: f for f in by_tool["ESLint"].findings}
    assert es["no-unsanitized/property"].location.path == "ui/src/render.js", "file:// URI under the source root"
    assert {f.rule_id for f in by_tool["ESLint"].quality} == {"no-unused-vars"}
    band = {f.rule_id: f for f in by_tool["Bandit"].findings}
    assert band["B608"].severity == "medium" and band["B608"].severity_from == "Bandit issue_severity MEDIUM"
    assert band["B608"].precision == "high" and band["B105"].cwe == (259,)
    sem = by_tool["Semgrep"].findings
    assert sem[0].cwe == (89,) and sem[0].severity == "medium", "CWE-89 from the rule's metadata tag"
    unresolved = sarif.parse((fx / "eslint.sarif").read_bytes(), "eslint.sarif", roots=[])
    assert not unresolved.findings[0].location.resolved and any("--source-root" in n for n in unresolved.notes)


def test_excluded_results_say_why(fx: Path) -> None:
    out = _assess(fx)
    want = _expected(fx)["excluded"]
    got = {e["finding"]["id"]: e["reason"] for e in out["excluded"]}
    assert set(got) == set(want)
    for fid, reason in want.items():
        assert reason in got[fid], (fid, got[fid])


def test_severity_from_security_severity_bands() -> None:
    assert [sarif.severity_from_score(s) for s in (10.0, 9.0, 8.9, 7.0, 6.9, 4.0, 3.9, 0.1, 0.0)] == [
        "critical",
        "critical",
        "high",
        "high",
        "medium",
        "medium",
        "low",
        "low",
        "info",
    ]


def _minimal(results: list[dict[str, Any]], **run: Any) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "x", "rules": [{"id": "r1", "properties": {"tags": ["security"]}}]}},
                    "results": results,
                    **run,
                }
            ],
        }
    )


def _result(path: str = "a.py", **extra: Any) -> dict[str, Any]:
    return {
        "ruleId": "r1",
        "level": "error",
        "message": {"text": "m"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": 3}}}],
        **extra,
    }


def test_suppression_status_kind_and_baseline() -> None:
    cases: list[tuple[dict[str, Any], str]] = [
        ({"suppressions": [{"kind": "external", "status": "accepted"}]}, "suppressed (external)"),
        ({"suppressions": [{"kind": "inSource"}]}, "suppressed (inSource)"),
        ({"suppressions": [{"kind": "external", "status": "rejected"}]}, ""),
        ({"suppressions": [{"kind": "external", "status": "underReview"}]}, ""),
        ({"kind": "pass"}, "not a failure"),
        ({"kind": "notApplicable"}, "not a failure"),
        ({"baselineState": "absent"}, "fixed"),
        ({"baselineState": "unchanged"}, ""),
    ]
    for extra, reason in cases:
        rep = sarif.parse(_minimal([_result(**extra)]), "t", roots=[])
        if reason:
            assert rep.excluded and reason in rep.excluded[0]["reason"], extra
        else:
            assert len(rep.findings) + len(rep.quality) == 1 and not rep.excluded, extra


def test_paths_bases_and_traversal() -> None:
    bases = {
        "SRC": {"uri": "file:///w/repo/"},
        "SUB": {"uri": "lib/", "uriBaseId": "SRC"},
        "LOOP": {"uri": "x/", "uriBaseId": "LOOP"},
    }
    results = [
        _result("a.py", locations=[{"physicalLocation": {"artifactLocation": {"uri": "m.py", "uriBaseId": "SUB"}}}]),
        _result("a.py", locations=[{"physicalLocation": {"artifactLocation": {"uri": "z.py", "uriBaseId": "LOOP"}}}]),
        _result("../../etc/passwd"),
        _result("file:///elsewhere/q.py"),
        _result("https://example.com/x.py"),
        _result("a%20b.py"),
        {"ruleId": "r1", "message": {"text": "no location"}},
    ]
    rep = sarif.parse(_minimal(results, originalUriBaseIds=bases), "t", roots=["/w/repo"])
    paths = [(f.location.path, f.location.resolved) for f in rep.findings]
    assert ("lib/m.py", True) in paths, "a base resolved through another base"
    assert ("x/z.py", True) in paths, "a base that names itself stops"
    assert ("../../etc/passwd", False) in paths and ("/elsewhere/q.py", False) in paths
    assert ("https://example.com/x.py", False) in paths and ("a b.py", True) in paths
    assert any("without a file location" in n for n in rep.notes)


def test_hostile_sarif(monkeypatch: pytest.MonkeyPatch) -> None:
    for bad, why in (
        (b"not json", "not JSON"),
        (b"[]", "not SARIF"),
        (b'{"version": "2.1.0"}', "not SARIF"),
        (b'{"version": "2.0.0", "runs": []}', "2.0.0"),
        (b"[" * 100_000 + b"]" * 100_000, "not JSON"),
    ):
        with pytest.raises(sarif.SarifError, match=why):
            sarif.parse(bad, "t")
    monkeypatch.setattr(sarif, "MAX_RUNS", 2)
    with pytest.raises(sarif.SarifError, match="more than 2 runs"):
        sarif.parse(json.dumps({"version": "2.1.0", "runs": [{}, {}, {}]}), "t")
    monkeypatch.setattr(sarif, "MAX_RESULTS", 3)
    with pytest.raises(sarif.SarifError, match="more than 3 results"):
        sarif.parse(_minimal([_result()] * 4), "t")
    monkeypatch.setattr(sarif, "MAX_BYTES", 100)
    with pytest.raises(sarif.SarifError, match="larger than"):
        sarif.parse(_minimal([_result()]), "t")


def test_fuzzed_sarif_never_crashes(fx: Path) -> None:
    rng = random.Random(20261028)
    base = json.loads((fx / "codeql.sarif").read_text())
    junk: list[Any] = [None, 0, -1, True, "", "x" * 3000, [], {}, [{}], {"a": []}, 1e308, "\u202e\x00"]

    def paths(o: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        out = [prefix]
        if isinstance(o, dict):
            for k, v in o.items():
                out += paths(v, (*prefix, k))
        elif isinstance(o, list):
            for i, v in enumerate(o):
                out += paths(v, (*prefix, i))
        return out

    for _ in range(400):
        doc = copy.deepcopy(base)
        for _ in range(rng.randint(1, 6)):
            p = rng.choice(paths(doc)[1:])
            cur = doc
            for k in p[:-1]:
                cur = cur[k]
            with contextlib.suppress(TypeError, KeyError, IndexError):
                cur[p[-1]] = copy.deepcopy(rng.choice(junk))
        try:
            rep = sarif.parse(json.dumps(doc), "fuzz", roots=[SOURCE_ROOT])
        except sarif.SarifError:
            continue
        for f in rep.findings + rep.quality:
            assert "\n" not in f.message and "\x00" not in f.location.path and len(f.message) <= 1000
        assess.assess([rep])


# -- R4.6: code to image to pod --------------------------------------------------------------------------------------


def test_ranking_and_attack_paths(fx: Path) -> None:
    out = _assess(fx)
    order = [r["finding"]["id"] for r in out["ranking"]["ranked"]]
    assert order == _expected(fx)["ranked"]
    top = out["ranking"]["ranked"][0]
    assert top["score"] == 26.4 and top["factors"]["exposure"]["value"] == 3.0
    assert top["attackPath"]["summary"].startswith(
        "internet -> Route/shop/web -> Service/shop/web -> Deployment/shop/web"
    )
    worker = next(r for r in out["ranking"]["ranked"] if r["finding"]["id"].startswith("worker/"))
    assert worker["factors"]["privileges"]["value"] > 1.0 and "read Secrets" in worker["attackPath"]["summary"]
    assert {x["id"] for x in out["notShipped"]} == {"tools/seed.py:4/CWE-798", "web/tests/test_db.py:10/CWE-703"}
    assert [i["workloads"] for i in out["images"]] == [
        ["Deployment/shop/web"],
        ["Deployment/shop/ui"],
        ["Deployment/shop/api"],
        ["Deployment/shop/worker"],
    ]


def test_without_containerfiles_or_manifests(fx: Path) -> None:
    bare = assess.assess(_sarifs(fx))
    assert bare["counts"]["shipped"] is None and bare["ranking"]["total"] == 8
    assert all(r["shipped"] == "unknown (no Containerfiles given)" for r in bare["ranking"]["ranked"])
    unplaced = assess.assess(_sarifs(fx), _builds(fx))
    assert any("no manifests given" in n for n in unplaced["notes"])
    assert unplaced["ranking"]["ranked"][0]["attackPath"]["summary"].endswith(
        "(not placed: no workload in the input runs this image)"
    )


def test_ship_map() -> None:
    cf = (
        "ARG APP=/srv/app\n"
        "FROM node:20 AS build\n"
        "WORKDIR /b\n"
        "COPY *.json ./\n"
        'COPY ["src", "./src"]\n'
        "ADD https://example.com/x.tgz /tmp/\n"
        "COPY <<EOF /etc/x\nhello\nEOF\n"
        "FROM build AS test\n"
        "COPY test/ ./test/\n"
        "FROM gcr.io/distroless/nodejs20\n"
        "ARG APP\n"
        "WORKDIR ${APP}\n"
        "COPY --from=0 /b/src ./src\n"
        "COPY --from=quay.io/other/image /x /x\n"
        "COPY config.yaml .\n"
    )
    b = ship.parse_build(ship.Build("svc/Containerfile", cf, "quay.io/acme/svc", "svc"))
    w = {
        p: [(s.how, s.image_path) for s in ship.where([b], p)]
        for p in ("svc/src/a.js", "svc/package.json", "svc/test/t.js", "svc/config.yaml", "other/src/a.js")
    }
    assert w["svc/src/a.js"] == [("copied", "/srv/app/src/a.js")]
    assert w["svc/package.json"] == [("built", "")]
    assert w["svc/test/t.js"] == [], "the test stage is not the final image"
    assert w["svc/config.yaml"] == [("copied", "/srv/app/config.yaml")]
    assert w["other/src/a.js"] == [], "outside the build context"
    tb = ship.parse_build(ship.Build("svc/Containerfile", cf, "quay.io/acme/svc", "svc", target="test"))
    assert [s.how for s in ship.where([tb], "svc/test/t.js")] == ["copied"]
    assert ship.source_of(b, "/srv/app/config.yaml") == [("svc/config.yaml", 17)], "heredoc lines count"
    assert ship.source_of(b, "/srv/app/src/a.js") == [("svc/src/a.js", 5)]
    with pytest.raises(ship.ShipError, match="no stage named"):
        ship.parse_build(ship.Build("c", cf, target="nope"))
    with pytest.raises(ship.ShipError, match="outside the repository"):
        ship.parse_build(ship.Build("c", cf, context="../x"))
    with pytest.raises(ship.ShipError, match="no FROM"):
        ship.parse_build(ship.Build("c", "RUN true\n"))
    ignored = ship.parse_build(ship.Build("svc/Containerfile", cf, "i", "svc", ignore="src/*.js\n!src/keep.js\n"))
    assert ship.where([ignored], "svc/src/a.js") == [] and ship.where([ignored], "svc/src/keep.js")


# -- R4.7: dependency fixes ------------------------------------------------------------------------------------------


def test_dependency_vulnerabilities_point_at_the_line(fx: Path) -> None:
    out = _assess(fx)
    want = _expected(fx)["sca"]
    got = {r["cve"]: r for r in out["sca"]}
    assert set(got) == set(want)
    for cve, w in want.items():
        r = got[cve]
        assert [[d["file"], d["line"]] for d in r["declaredIn"]] == w["declaredIn"], cve
        assert [[c["file"], c["line"]] for c in r["copiedFrom"]] == w["copiedFrom"], cve
        assert r["action"] == w["action"], cve
    assert [r["cve"] for r in out["sca"]] == ["CVE-2099-3003", "CVE-2099-3002", "CVE-2099-3001"], "critical first"


def test_scanners_record_where_packages_are(fx: Path) -> None:
    trivy = vr.parse((fx / "trivy-web.json").read_bytes(), "t")
    assert trivy.findings[0].paths == (
        "/opt/app-root/lib64/python3.11/site-packages/requests-2.25.0.dist-info/METADATA",
    )
    grype = vr.parse((fx / "grype-api.json").read_bytes(), "g")
    assert grype.findings[0].paths == (
        "/opt/app-root/src/package-lock.json",
        "/opt/app-root/src/node_modules/lodash/package.json",
    )
    cdx = vr.parse((fx / "cyclonedx-worker.json").read_bytes(), "c")
    assert cdx.findings[0].paths == ("/deployments/worker.jar",) and cdx.findings[0].fix_version == "2.17.1"
    lock = json.loads((fx / "trivy-web.json").read_text())
    lock["Results"][0].update({"Target": "usr/src/app/package-lock.json", "Type": "npm"})
    del lock["Results"][0]["Vulnerabilities"][0]["PkgPath"]
    assert vr.parse(json.dumps(lock), "t").findings[0].paths == ("/usr/src/app/package-lock.json",)


@pytest.mark.parametrize(
    ("eco", "name", "file", "text", "line"),
    [
        ("pypi", "Django", "requirements-prod.txt", "# x\ndjango>=4.2 # web\n", 2),
        ("pypi", "zope.interface", "pyproject.toml", '[project]\ndependencies = ["zope-interface>=6"]\n', 2),
        ("pypi", "requests", "poetry.lock", '[[package]]\nname = "requests"\n', 2),
        ("npm", "@scope/pkg", "yarn.lock", '"@scope/pkg@^1.0.0":\n  version "1.0.0"\n', 1),
        ("npm", "left-pad", "pnpm-lock.yaml", "packages:\n  /left-pad@1.3.0:\n", 2),
        (
            "maven",
            "com.fasterxml.jackson.core:jackson-databind",
            "build.gradle",
            "dependencies {\n implementation 'com.fasterxml.jackson.core:jackson-databind:2.15.0'\n}\n",
            2,
        ),
        ("golang", "github.com/gin-gonic/gin", "go.sum", "github.com/gin-gonic/gin v1.9.0 h1:abc=\n", 1),
        ("gem", "rack", "Gemfile.lock", "GEM\n  specs:\n    rack (2.2.3)\n", 3),
        ("gem", "rails", "Gemfile", "source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\n", 2),
        ("cargo", "serde", "Cargo.toml", '[dependencies]\nserde = { version = "1" }\n', 2),
        (
            "nuget",
            "Newtonsoft.Json",
            "app.csproj",
            '<PackageReference Include="Newtonsoft.Json" Version="12.0.1" />\n',
            1,
        ),
        ("composer", "guzzlehttp/guzzle", "composer.json", '{\n  "require": {\n    "guzzlehttp/guzzle": "^7"\n', 3),
    ],
)
def test_dependency_file_patterns(eco: str, name: str, file: str, text: str, line: int) -> None:
    hits = deps.find({file: text, "other.txt": text}, eco, name)
    assert [(h.file, h.line) for h in hits] == [(file, line)]
    assert deps.find({file: text}, eco, name + "-not") == []


# -- surfaces --------------------------------------------------------------------------------------------------------


def _cli_args(fx: Path) -> list[str]:
    args = ["code", "report", "--repo", str(fx / "repo"), "--source-root", SOURCE_ROOT]
    for n in TOOLS:
        args += ["-s", str(fx / n)]
    for cfile, image, _ in BUILDS:
        args += ["-c", f"{cfile}={image}"]
    args += ["-m", str(FIX / "shop.yaml")]
    for n in SCANS:
        args += ["-r", str(fx / n)]
    return args


def test_cli(fx: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([*_cli_args(fx), "--top", "2"]) == 0
    text = capsys.readouterr().out
    assert "1. 26.4 CWE-89 web/app/db.py:42 (high; Bandit, CodeQL, Semgrep OSS)" in text
    assert "update lodash from 4.17.20 to 4.17.21 in api/package.json:5" in text
    assert main([*_cli_args(fx), "--fail-on", "high"]) == 1
    err = capsys.readouterr().err
    assert "5 code findings at high or above in shipped code" in err
    assert "2 dependency vulnerabilities at high or above that are fixable or known exploited" in err
    assert main([*_cli_args(fx), "--fail-on", "critical", "--format", "json"]) == 1, "the critical log4j fix"
    assert json.loads(capsys.readouterr().out)["counts"]["sca"] == 3
    assert main(["code", "report", "--repo", str(fx / "repo"), "-s", str(fx / "bandit.sarif"), "-c", "nope=x"]) == 2
    assert "no such Containerfile" in capsys.readouterr().err
    assert main(["code", "report", "-s", str(fx / "bandit.sarif"), "-c", "a=b,colour=red"]) == 2
    assert main(["code", "report"]) == 2
    assert main(["code", "report", "-s", str(fx / "bandit.sarif"), "--source-root", "relative"]) == 2


def test_mcp_tool(fx: Path, tmp_path: Path) -> None:
    from kube_noob import toolkit as tk

    kit = tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path)}))
    assert "code_report" in {s.name for s in kit.specs()}
    repo = fx / "repo"
    out = kit.code_report(
        tk.CodeReportIn(
            sarif=[(fx / n).read_text() for n in TOOLS],
            containerfiles=[
                tk.CodeBuildIn(
                    path=c,
                    text=(repo / c).read_text(),
                    image=i,
                    ignore=(repo / ctx / ".dockerignore").read_text()
                    if (repo / ctx / ".dockerignore").exists()
                    else None,
                )
                for c, i, ctx in BUILDS
            ],
            manifests=(FIX / "shop.yaml").read_text(),
            reports=[(fx / n).read_text() for n in SCANS],
            dependency_files={k: v for k, v in _files(fx).items() if deps.is_dependency_file(k)},
            source_roots=[SOURCE_ROOT],
        )
    )
    assert [r["finding"]["id"] for r in out["ranking"]["ranked"]] == _expected(fx)["ranked"]
    assert {r["cve"]: r["action"] for r in out["sca"]}["CVE-2099-3001"].endswith("web/requirements.txt:2")
    with pytest.raises(Exception, match="Extra inputs"):
        tk.CodeReportIn(sarif=["{}"], url="https://example.com")  # type: ignore[call-arg]
    with pytest.raises(Exception, match="String should match pattern"):
        tk.CodeReportIn(sarif=["{}"], source_roots=["relative/path"])
    with pytest.raises(ValueError, match="pass SARIF"):
        kit.code_report(tk.CodeReportIn())
    with pytest.raises(ValueError, match="not SARIF"):
        kit.code_report(tk.CodeReportIn(sarif=['{"a": 1}']))


def test_gate_and_insight(fx: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from kube_noob import gate
    from kube_noob import toolkit as tk
    from kube_noob.insight import insight

    repo = fx / "repo"
    reports = [(n, (fx / n).read_text()) for n in TOOLS]
    cfs = [(c, (repo / c).read_text()) for c, _, _ in BUILDS]
    r = gate.run([], containerfiles=cfs, sarif_reports=reports, source_roots=[SOURCE_ROOT], fail_on="high")
    assert not r["passed"] and any("code finding(s) at high or above in shipped code" in f for f in r["failures"])
    assert r["code"]["findings"] == 8 and r["code"]["notShipped"] == 2
    seed = next(f for f in r["findings"] if f["uri"] == "tools/seed.py")
    assert seed["message"].endswith("not shipped in any image") and seed["severity"] == "high"
    only_seed = [(n, t) for n, t in reports if n == "semgrep.sarif"]
    r2 = gate.run([], containerfiles=cfs, sarif_reports=only_seed, source_roots=[SOURCE_ROOT], fail_on="critical")
    assert r2["passed"], "medium SQLi does not reach critical and the high secret is in unshipped tools/"
    md = gate.markdown(r)
    assert "Code findings from Bandit 1.7.10, CodeQL 2.19.1" in md and "in files no image ships" in md
    sar = gate.sarif(r)
    assert any(x["ruleId"] == "B602" for x in sar["runs"][0]["results"])
    assert not any(n.startswith("code checks") for n in r["notRun"])
    plain = gate.run([], containerfiles=cfs, fail_on="never")
    assert any(n.startswith("code checks") for n in plain["notRun"])
    kit = tk.Toolkit(load_settings(overrides={"dataDir": str(tmp_path)}))
    seen = insight(kit, (fx / "codeql.sarif").read_text())
    assert "code" in seen["ran"] and seen["findings"][0]["source"] == "code"
    assert seen["context"]["code"]["findings"] == 2
    assert not any(s["kind"] == "scanner-report" for s in seen["skipped"])
