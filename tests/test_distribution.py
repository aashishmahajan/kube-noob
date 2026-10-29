"""Release metadata must agree across PyPI, the MCP Registry, the Claude plugin, the image and the chart."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from kube_noob import __version__

ROOT = Path(__file__).resolve().parents[1]
SERVER_NAME = "io.github.aashishmahajan/kube-noob"


def test_mcp_registry_metadata() -> None:
    server = json.loads((ROOT / "server.json").read_text())
    assert server["name"] == SERVER_NAME and server["version"] == __version__
    assert server["packages"][0]["identifier"] == "kube-noob" and server["packages"][0]["version"] == __version__
    assert len(server["description"]) <= 100
    readme = (ROOT / "README.md").read_text()
    assert re.search(rf"mcp-name: {re.escape(SERVER_NAME)}(\s|-->)", readme), "PyPI ownership marker missing"
    assert f'io.modelcontextprotocol.server.name="{SERVER_NAME}"' in (ROOT / "Containerfile").read_text()


def test_plugin_pins_the_release() -> None:
    import tomllib

    plugin = json.loads((ROOT / "plugin/kube-noob/.claude-plugin/plugin.json").read_text())
    market = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())
    assert plugin["version"] == __version__ == market["plugins"][0]["version"]
    assert tomllib.loads((ROOT / "plugin/kube-noob/pyproject.toml").read_text())["project"]["version"] == __version__
    lock = tomllib.loads((ROOT / "plugin/kube-noob/uv.lock").read_text())
    assert next(p for p in lock["package"] if p["name"] == "kube-noob-plugin")["version"] == __version__
    assert (ROOT / "plugin/kube-noob/LICENSE").read_text() == (ROOT / "LICENSE").read_text()
    assert len((ROOT / "plugin/kube-noob/README.md").read_text().split()) >= 40
    pins = re.findall(r"kube-noob==(\d+\.\d+\.\d+)", (ROOT / "README.md").read_text())
    assert pins and set(pins) == {__version__}, "README.md uvx pin for other MCP clients"


def test_chart_and_image_versions() -> None:
    chart = yaml.safe_load((ROOT / "deploy/helm/kube-noob/Chart.yaml").read_text())
    assert chart["appVersion"] == __version__ and chart["annotations"]["charts.openshift.io/name"] == "kube-noob"
    containerfile = (ROOT / "Containerfile").read_text()
    for label in ("name=", "vendor=", "version=", "release=", "summary=", "description=", "maintainer="):
        assert re.search(rf"^(LABEL)?\s+{label}", containerfile, re.MULTILINE), label
    assert "COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /licenses/" in containerfile


def test_image_build_context_has_every_wheel_input() -> None:
    """The Containerfile builds the wheel itself, so it must copy every path the wheel force-includes."""
    import tomllib

    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())
    wheel = cfg["tool"]["hatch"]["build"]["targets"]["wheel"]
    containerfile = (ROOT / "Containerfile").read_text()
    ignored = (ROOT / ".dockerignore").read_text().split()
    for src in list(wheel.get("force-include", {})) + [p.split("/")[0] for p in wheel["packages"]]:
        assert re.search(rf"^COPY .*\b{re.escape(src)}\b", containerfile, re.MULTILINE), src
        assert src not in ignored, src


def test_scheduled_cadences_and_rox_corpus_scope() -> None:
    """Weekly risk review, weekly corpus refresh, and a Red Hat Jira copy that covers ROX (every version, so RHACS
    4.10 onward included) with room for well over 1000 issues."""
    import yaml

    wf = ROOT / ".github" / "workflows"
    risk = yaml.safe_load((wf / "risk-review.yml").read_text())
    corpus_text = (wf / "corpus-refresh.yml").read_text()
    corpus = yaml.safe_load(corpus_text)
    triggers = risk.get("on") or risk.get(True)
    assert re.fullmatch(r"\d+ \d+ \* \* \d", triggers["schedule"][0]["cron"])
    ctriggers = corpus.get("on") or corpus.get(True)
    assert re.fullmatch(r"\d+ \d+ \* \* \d", ctriggers["schedule"][0]["cron"])
    from kube_noob.jira_catalog import DEFAULT_PROJECTS

    assert '--projects "$JIRA_PROJECTS"' in corpus_text and "inputs.jira_projects || 'default'" in corpus_text
    assert "ROX" in DEFAULT_PROJECTS and "OCPBUGS" in DEFAULT_PROJECTS
    assert int(re.search(r"jira_max_requests \|\| '(\d+)'", corpus_text).group(1)) >= 1000  # x100 issues each


def test_ships_as_mcp_plugin_cli_and_openshift_service() -> None:
    import tomllib

    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert cfg["project"]["scripts"]["kube-noob"] == "kube_noob.cli:main"
    assert cfg["project"]["scripts"]["noob"] == "kube_noob.cli:main", "the short form runs the same CLI"
    assert (ROOT / "plugin/kube-noob/.mcp.json").is_file() and (ROOT / ".claude-plugin/marketplace.json").is_file()
    assert (ROOT / "deploy/helm/kube-noob/Chart.yaml").is_file()
    assert "kube-noob" in (ROOT / "deploy/sidecar/app-with-kube-noob-sidecar.yaml").read_text()


def test_chart_egress_firewall_mirrors_the_web_allowlist() -> None:
    from kube_noob.config import DEFAULT_ALLOWED_DOMAINS

    values = yaml.safe_load((ROOT / "deploy/helm/kube-noob/values.yaml").read_text())
    assert values["egressFirewall"]["enabled"] is False, "EgressFirewall is namespace-wide, so it must be opt-in"
    assert values["egressFirewall"]["defaultDomains"] == list(DEFAULT_ALLOWED_DOMAINS)
    assert values["egressFirewall"]["denyCIDRs"] == ["0.0.0.0/0"]
    template = (ROOT / "deploy/helm/kube-noob/templates/egressfirewall.yaml").read_text()
    assert "name: default" in template and "not (.Values.config.offline" in template
    assert "provider: none" in (ROOT / "deploy/helm/kube-noob/templates/configmap.yaml").read_text()


def test_sidecar_is_loopback_only_with_dns_only_egress() -> None:
    docs = list(yaml.safe_load_all((ROOT / "deploy/sidecar/app-with-kube-noob-sidecar.yaml").read_text()))
    dep = next(d for d in docs if d["kind"] == "Deployment")
    kn = next(c for c in dep["spec"]["template"]["spec"]["containers"] if c["name"] == "kube-noob")
    assert kn["args"][kn["args"].index("--host") + 1] == "127.0.0.1" and "ports" not in kn
    env = {e["name"]: e["value"] for e in kn["env"]}
    assert env["KUBE_NOOB_WEB_ENABLED"] == "false" and env["KUBE_NOOB_LLM_PROVIDER"] == "none"
    assert kn["resources"] == {"requests": {"cpu": "50m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}
    svc = next(d for d in docs if d["kind"] == "Service")
    assert all(p["targetPort"] != 8080 for p in svc["spec"]["ports"])
    pol = next(d for d in docs if d["kind"] == "NetworkPolicy")
    assert pol["spec"]["policyTypes"] == ["Ingress", "Egress"]
    assert [p["port"] for rule in pol["spec"]["egress"] for p in rule["ports"]] == [5353, 5353]


def test_homebrew_formula_installs_hash_pinned_wheels() -> None:
    """Homebrew builds offline: every file is a sha256-checked resource; install is pip --no-index of those wheels."""
    formula = (ROOT / "Formula/kube-noob.rb").read_text()
    assert re.search(r'url "https://files\.pythonhosted\.org/packages/[^"]+/kube_noob-\d+\.\d+\.\d+\.tar\.gz"', formula)
    resources = re.findall(r'resource "([^"]+)" do\n\s+url "([^"]+)"\n\s+sha256 "([0-9a-f]{64})"', formula)
    assert len(resources) == formula.count('resource "') and len(resources) > 30
    assert all(url.startswith("https://files.pythonhosted.org/") and url.endswith(".whl") for _, url, _ in resources)
    assert {"kube-noob", "mcp", "pydantic", "pydantic-core", "pyyaml"} <= {name for name, _, _ in resources}
    assert '"install", "--no-index", "--no-deps"' in formula and '"check"' in formula
    assert 'depends_on "python@3.13"' in formula and "depends_on arch: :arm64" in formula and "test do" in formula


def test_homebrew_install_is_documented_tested_and_never_ahead_of_the_package() -> None:
    """Users run `brew tap ...` then `brew install kube-noob`: the README, the install guide and the CI job that
    installs from the public tap use those exact commands, and the formula is never newer than the package."""
    from packaging.version import Version

    import kube_noob

    tap = "brew tap aashishmahajan/kube-noob https://github.com/aashishmahajan/kube-noob"
    brew_wf = (ROOT / ".github/workflows/brew.yml").read_text()
    for text in ((ROOT / "README.md").read_text(), (ROOT / "docs/install.md").read_text(), brew_wf):
        assert tap in text and "brew install kube-noob" in text
        assert "brew trust --formula aashishmahajan/kube-noob/kube-noob" in text, "Homebrew 6 needs tap trust"
    jobs = yaml.safe_load(brew_wf)["jobs"]
    assert "public-tap" in jobs and "kube-noob --version" in str(jobs["public-tap"])
    formula = (ROOT / "Formula/kube-noob.rb").read_text()
    m = re.search(r'^  url ".*/kube_noob-([0-9][0-9.]*)\.tar\.gz"', formula, re.MULTILINE)
    assert m, "formula has no sdist url"
    assert Version(m.group(1)) <= Version(kube_noob.__version__)
    release = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())["jobs"]
    assert release["homebrew"]["needs"] == "publish-pypi"
    assert release["brew"]["uses"] == "./.github/workflows/brew.yml"
