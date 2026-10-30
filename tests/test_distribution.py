"""Release metadata must agree across PyPI, the MCP Registry, the Claude plugin, the image and the chart."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
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


def test_the_plugin_asks_the_user_and_reads_no_secret_from_their_machine() -> None:
    """The plugin directory's review prefers a value the user is asked for (a ``userConfig`` option) over one the
    server reads out of the machine's environment. The plugin asks for one optional path and nothing else: it holds no
    secret-valued option, and it starts the server with the web, the cluster and the model off, so the configuration
    that reads a provider key, an RHACS token or a GitHub token (``apiKeyEnv``, ``rhacs.tokenEnv``,
    ``ci.githubTokenEnv`` in kube_noob.config) is unreachable from it."""
    plugin = json.loads((ROOT / "plugin/kube-noob/.claude-plugin/plugin.json").read_text())
    mcp = json.loads((ROOT / "plugin/kube-noob/.mcp.json").read_text())
    env = mcp["mcpServers"]["kube-noob"]["env"]
    assert env["KUBE_NOOB_WEB_ENABLED"] == "false"
    assert env["KUBE_NOOB_CLUSTER_ENABLED"] == "false"
    assert env["KUBE_NOOB_LLM_PROVIDER"] == "none"
    options = plugin.get("userConfig", {})
    assert not [k for k, v in options.items() if v.get("sensitive")], "the plugin must ask for no secret"
    # every ${user_config.x} the server is started with has to be an option that exists, or the user is handed a
    # variable holding the literal placeholder (config._env ignores one, but a typo would silently do nothing)
    referenced = set(re.findall(r"\$\{user_config\.([A-Za-z0-9_]+)\}", json.dumps(mcp)))
    assert referenced <= set(options), f"{referenced - set(options)} is not in plugin.json userConfig"
    secrets = [k for k in env if k.endswith("_API_KEY") or "TOKEN" in k or "SECRET" in k or "PASSWORD" in k]
    assert secrets == [], f"the plugin server is started with a secret-bearing variable: {secrets}"


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
    """Weekly risk review; the Jira main copy every day (or every 2 days) continuing the previous encrypted copy, with
    a reconciliation summary; the docs corpus weekly; and a Red Hat Jira copy that covers ROX (every version, so RHACS
    4.10 onward included) with room for well over 1000 issues."""
    import yaml

    wf = ROOT / ".github" / "workflows"
    risk = yaml.safe_load((wf / "risk-review.yml").read_text())
    corpus_text = (wf / "corpus-refresh.yml").read_text()
    corpus = yaml.safe_load(corpus_text)
    triggers = risk.get("on") or risk.get(True)
    assert re.fullmatch(r"\d+ \d+ \* \* \d", triggers["schedule"][0]["cron"])
    ctriggers = corpus.get("on") or corpus.get(True)
    crons = [s["cron"] for s in ctriggers["schedule"]]
    assert re.fullmatch(r"\d+ \d+ \* \* \*", crons[0]) and re.fullmatch(r"\d+ \d+ \* \* \d", crons[1])
    assert f"github.event.schedule == '{crons[1]}'" in corpus_text  # the weekly run is the full one
    assert "vars.JIRA_EVERY_DAYS || '1'" in corpus_text and "1|2)" in corpus_text
    assert corpus["permissions"] == {"contents": "read", "actions": "read"}
    assert corpus["concurrency"] == {"group": "corpus-refresh", "cancel-in-progress": False}
    steps = corpus["jobs"]["corpus"]["steps"]
    restore = next(s for s in steps if s.get("name", "").startswith("Restore the previous main copy"))
    assert "-n jira-main-copy-encrypted" in restore["run"] and "openssl enc -d -aes-256-cbc -pbkdf2" in restore["run"]
    assert "kube-noob corpus import previous/jira-snapshot.tgz" in restore["run"]
    assert "rm -f previous/jira-snapshot.tgz" in restore["run"]  # the plain copy never lingers
    recon = next(s for s in steps if s.get("name", "").startswith("Reconciliation"))
    assert "kube-noob corpus jira-changes --since 2d" in recon["run"] and "GITHUB_STEP_SUMMARY" in recon["run"]
    enc = next(s for s in steps if s.get("name", "").startswith("Encrypt the Jira main copy"))
    assert "kube-noob corpus jira-snapshot -o jira-snapshot.tgz" in enc["run"] and "rm jira-snapshot.tgz" in enc["run"]
    uploads = {s["with"]["name"]: s["with"] for s in steps if "upload-artifact" in s.get("uses", "")}
    assert uploads["jira-main-copy-encrypted"]["path"] == "jira-snapshot.tgz.enc"  # never the plain snapshot
    assert uploads["corpus-full-encrypted"]["path"] == "corpus-full.tgz.enc"
    uploaded = [line.strip() for u in uploads.values() for line in str(u["path"]).splitlines()]
    assert not any(path.endswith(".tgz") for path in uploaded), uploaded  # nothing unencrypted
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


def test_no_source_file_is_ignored_by_git() -> None:
    """A .gitignore pattern such as build/ once hid the kube_noob.build package from commits and from the wheel."""
    import shutil
    import subprocess

    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    out = subprocess.run(
        ["git", "ls-files", "--others", "--ignored", "--exclude-standard", "src", "plugin", "tests", "scripts"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    hidden = [p for p in out if "__pycache__" not in p and not p.endswith((".pyc", ".DS_Store"))]
    assert hidden == [], f"ignored by .gitignore, so never committed or packaged: {hidden[:10]}"


# A bundled YAML file is parsed by whatever YAML parser the machine running kube-noob happens to have: the pure-Python
# PyYAML scanner, or libyaml through CSafeLoader (which signals/ceph.py and mustgather/analyse.py prefer for its
# start-up time). Those two do not agree on every document. `src: [healthmon:885]` in data/ceph_health.yaml parses as
# the string "healthmon:885" under the PyYAML scanners this repository's CI happens to have, and under the stricter
# libyaml in the browser runtime (Pyodide) it raises "found unexpected ':'" -- which took out `diagnose` and
# `known_issues` on kube-noob.com's playground and in the plugin on any machine with that libyaml, after 0.7.0 shipped
# the Ceph catalogue. A colon inside an unquoted scalar in a flow collection is ambiguous (it reads as a single-pair
# mapping), so the fix is to quote it and the guard is this test, which reads the text rather than trusting whichever
# parser is installed here.
# `key: value` inside {} is an ordinary flow mapping and portable; the hazard is a colon with no space after it, which
# a flow context may read as a single-pair mapping instead of as part of the scalar. The tokens come from PyYAML's own
# scanner rather than a regular expression, so a bracket inside prose (a folded block scalar, a quoted string) is not
# mistaken for a flow collection.
_GLUED_COLON = re.compile(r":(?!\s|$)")


def _ambiguous_flow_scalars(text: str) -> list[tuple[int, str]]:
    """Every spot in one YAML document where a colon inside a flow collection is open to interpretation.

    Two shapes, because PyYAML resolves the same hazard two different ways. ``[healthmon:885]`` stays one plain
    scalar, so it is caught by looking at the scalar's text. ``[rule:]`` and ``[rule:1, x]`` instead become a
    single-pair mapping inside the sequence, so there is no scalar to look at and the key token is the evidence. A
    stricter libyaml refuses both.
    """
    out: list[tuple[int, str]] = []
    stack: list[str] = []
    for token in yaml.scan(text, Loader=yaml.SafeLoader):
        if isinstance(token, yaml.tokens.FlowSequenceStartToken):
            stack.append("sequence")
        elif isinstance(token, yaml.tokens.FlowMappingStartToken):
            stack.append("mapping")
        elif isinstance(token, yaml.tokens.FlowSequenceEndToken | yaml.tokens.FlowMappingEndToken):
            if stack:
                stack.pop()
        elif isinstance(token, yaml.tokens.KeyToken) and stack and stack[-1] == "sequence":
            out.append((token.start_mark.line + 1, "a key: value pair sitting directly in a [ ] sequence"))
        elif (
            stack
            and isinstance(token, yaml.tokens.ScalarToken)
            and token.style is None
            and _GLUED_COLON.search(token.value)
        ):
            out.append((token.start_mark.line + 1, token.value))
    return out


def _yaml_front_matter(text: str) -> str:
    """The YAML block at the top of a knowledge document, which knowledge/store.py parses at runtime."""
    if not text.startswith("---\n"):
        return ""
    end = text.find("\n---", 3)
    return text[4:end] if end > 0 else ""


def test_bundled_yaml_parses_under_every_yaml_parser() -> None:
    roots = (
        ROOT / "src" / "kube_noob",
        ROOT / "plugin" / "kube-noob" / "server" / "kube_noob",
        ROOT / "examples",
    )
    documents: list[tuple[str, str]] = []
    for root in roots:
        for suffix in ("*.yaml", "*.yml"):
            documents += [(str(p.relative_to(ROOT)), p.read_text(encoding="utf-8")) for p in sorted(root.rglob(suffix))]
        # a knowledge document's front matter is YAML that knowledge/store.py parses at runtime like any other
        for path in sorted(root.rglob("*.md")):
            front = _yaml_front_matter(path.read_text(encoding="utf-8"))
            if front:
                documents.append((f"{path.relative_to(ROOT)} (front matter)", front))
    assert len(documents) > 50, f"only {len(documents)} bundled documents found: this test would pass by doing nothing"
    loaders = [getattr(yaml, name) for name in ("CSafeLoader", "SafeLoader") if hasattr(yaml, name)]
    ambiguous: list[str] = []
    for name, text in documents:
        for number, scalar in _ambiguous_flow_scalars(text):
            ambiguous.append(f"{name}:{number}: {scalar}")
        # cheap, and no more than that: the libyaml on this machine accepts [x:1], so it would not have caught the
        # incident above. The scanner check is what guards it; this only catches a file that is broken everywhere.
        for loader in loaders:
            list(yaml.load_all(text, Loader=loader))
    assert ambiguous == [], (
        "quote these scalars: a colon in an unquoted scalar inside [] or {} is ambiguous, and a stricter "
        f"libyaml than this machine's refuses the file ({len(ambiguous)} found): {ambiguous[:6]}"
    )
