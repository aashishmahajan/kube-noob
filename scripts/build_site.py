#!/usr/bin/env python3
"""Build kube-noob.com, a static site generated from this repository, so it can never drift from the code.

Every page comes from the checkout: the docs (Markdown), the MCP tool surface (the same ToolSpecs the server
registers, with their JSON schemas), the CLI (argparse help), the audit rules, playbooks, knowledge base, release-note
issue index, Helm values, real `kube-noob demo` transcripts, the self-test and the changelog. Two pages run kube-noob
itself in the visitor's browser (Pyodide, served from the site, no CDN): the playground (no model at all) and "Ask"
(the visitor's own Claude key, sent only to api.anthropic.com, with kube-noob's tools running locally).

Usage:
  python scripts/build_site.py --out _site [--clean] [--pyodide pyodide-<v>.tar.bz2|dir] [--wheel dist/x.whl]
                               [--videos dir] [--gifs dir] [--strict]
  node site/bundle.mjs _site        # browser scripts (site, playground, agent) and mermaid, after this script

--strict fails when the runtime, the wheel or the videos are missing (the Pages workflow uses it). Without it the
site still builds and the affected pages say what is missing. Needs `markdown` (in the dev extra).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import html
import io
import json
import os
import re
import shutil
import sys
import tarfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import markdown
import yaml

ROOT = Path(__file__).resolve().parents[1]
SITE_SRC = ROOT / "site"
sys.path.insert(0, str(ROOT / "src"))

DOMAIN = "kube-noob.com"
BASE_URL = f"https://{DOMAIN}"
REPO = "aashishmahajan/kube-noob"
REPO_URL = f"https://github.com/{REPO}"
RAW_PREFIXES = (
    f"https://raw.githubusercontent.com/{REPO}/main/",
    f"{REPO_URL}/blob/main/",
    f"{REPO_URL}/tree/main/",
)
PYODIDE_ROOTS = ("pydantic", "pyyaml", "jsonschema", "httpx", "anyio", "sniffio", "h11", "httpcore", "certifi", "idna")
PYODIDE_CORE = ("pyodide.mjs", "pyodide.asm.mjs", "pyodide.asm.wasm", "python_stdlib.zip", "pyodide-lock.json")
CSP = (
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; "
    "connect-src 'self' https://api.anthropic.com; img-src 'self' data:; media-src 'self'; "
    "style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; form-action 'self'"
)
VIDEOS = ("teaser", "sidecar", "mcp")

# (source, slug, nav group). Titles come from each file's first heading; docs/*.md not listed land in "More".
DOCS: tuple[tuple[str, str, str], ...] = (
    ("README.md", "overview", "Start"),
    ("docs/install.md", "install", "Start"),
    ("docs/use-cases.md", "use-cases", "Start"),
    ("docs/learning.md", "learning", "Start"),
    ("docs/openshift.md", "openshift", "Run it"),
    ("docs/operations.md", "operations", "Run it"),
    ("deploy/helm/kube-noob/README.md", "helm-chart", "Run it"),
    ("plugin/kube-noob/README.md", "claude-plugin", "Run it"),
    ("docs/architecture.md", "architecture", "Trust"),
    ("PRIVACY.md", "privacy", "Trust"),
    ("SECURITY.md", "security", "Trust"),
    ("docs/compliance.md", "compliance", "Trust"),
    ("docs/guidance.md", "guidance", "Trust"),
    ("docs/release-readiness.md", "release-readiness", "Trust"),
    ("docs/roadmap.md", "roadmap", "Project"),
    ("CHANGELOG.md", "changelog", "Project"),
    ("demos/README.md", "demos", "Project"),
    ("docs/training.md", "training", "Project"),
    ("docs/openshift-catalog.md", "openshift-catalog", "Project"),
    ("THIRD_PARTY_NOTICES.md", "third-party-notices", "Trust"),
    ("CONTRIBUTING.md", "contributing", "Project"),
    ("docs/roadmap-0.2.md", "roadmap-0-2", "Project"),
)
REFERENCE = (
    ("/reference/mcp/", "MCP tools"),
    ("/reference/cli/", "CLI"),
    ("/reference/rules/", "Audit rules"),
    ("/reference/playbooks/", "Playbooks"),
    ("/reference/knowledge/", "Knowledge base"),
    ("/reference/known-issues/", "Known issues index"),
    ("/reference/helm-values/", "Helm values"),
)
TOP_NAV = (
    ("/journey/", "Journey"),
    ("/playground/", "Playground"),
    ("/ask/", "Ask"),
    ("/docs/overview/", "Docs"),
    ("/reference/mcp/", "Reference"),
    ("/videos/", "Videos"),
    ("/insights/", "Insights"),
)


@dataclass
class Doc:
    source: str
    slug: str
    group: str
    title: str = ""
    text: str = ""

    @property
    def url(self) -> str:
        return f"/docs/{self.slug}/"


@dataclass
class Build:
    out: Path
    strict: bool
    docs: list[Doc] = field(default_factory=list)
    pages: list[tuple[str, str, str, str]] = field(default_factory=list)  # url, title, headings, text
    missing: list[str] = field(default_factory=list)
    has_runtime: bool = False
    videos: list[dict[str, str]] = field(default_factory=list)
    gifs: list[dict[str, str]] = field(default_factory=list)


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def current(flag: bool) -> str:
    return ' aria-current="page"' if flag else ""


def inline(text: str) -> str:
    """Escape prose and render its `code` spans."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", esc(text))


def write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


def version() -> str:
    from kube_noob import __version__

    return __version__


def strip_tags(fragment: str) -> str:
    text = re.sub(r"(?is)<(script|style|pre class=\"mermaid\")[^>]*>.*?</(script|style|pre)>", " ", fragment)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


# -- page shell -------------------------------------------------------------------------------------------------
def shell(b: Build, url: str, title: str, body: str, *, description: str = "", scripts: tuple[str, ...] = ()) -> str:
    nav = "".join(
        f'<a href="{href}"{current(url.startswith(href.rstrip("/") + "/"))}>{esc(label)}</a>' for href, label in TOP_NAV
    )
    desc = description or (
        "kube-noob: the Kubernetes, OpenShift, ROSA HCP, Helm and RHACS rulebook your AI calls as tools."
    )
    page_title = "kube-noob" if url == "/" else f"{title} · kube-noob"
    extra = "".join(f'<script type="module" src="{esc(s)}"></script>' for s in scripts)
    year = datetime.now(UTC).year
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="referrer" content="strict-origin-when-cross-origin">
<title>{esc(page_title)}</title>
<meta name="description" content="{esc(desc)}">
<link rel="canonical" href="{BASE_URL}{esc(url)}">
<meta property="og:title" content="{esc(page_title)}">
<meta property="og:description" content="{esc(desc)}">
<meta property="og:image" content="{BASE_URL}/brand/social-preview.png">
<meta property="og:url" content="{BASE_URL}{esc(url)}">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="/brand/kube-noob-icon.svg" type="image/svg+xml">
<link rel="icon" href="/brand/kube-noob-32.png" sizes="32x32" type="image/png">
<link rel="apple-touch-icon" href="/brand/kube-noob-256.png">
<link rel="stylesheet" href="/assets/style.css">
<script type="module" src="/assets/site.js"></script>
{extra}
</head>
<body>
<a class="skip" href="#content">Skip to content</a>
<header class="top"><div class="top-inner">
  <a class="logo" href="/"><img src="/brand/kube-noob-icon.svg" alt="" width="30" height="30"><span>kube-noob</span></a>
  <button class="icon-btn menu-toggle" id="menu-toggle" aria-expanded="false" aria-controls="main-nav">Menu</button>
  <nav class="main" id="main-nav" aria-label="Main">{nav}
    <div class="search"><input id="site-search" type="search" placeholder="Search docs" aria-label="Search the site"
      autocomplete="off"><div class="search-results" id="search-results" role="listbox"></div></div>
    <button class="icon-btn" id="theme-toggle" type="button" aria-label="Switch colour theme">Theme</button>
    <a href="{REPO_URL}" rel="noopener">GitHub</a>
  </nav>
</div></header>
<main id="content">
{body}
</main>
<footer class="bottom"><div class="inner">
  <span>kube-noob {esc(version())} · Apache-2.0 · No AI inside. Works with yours.</span>
  <span><a href="/docs/privacy/">Privacy</a> · <a href="/docs/security/">Security</a> ·
    <a href="{REPO_URL}">Source</a> · <a href="https://pypi.org/project/kube-noob/">PyPI</a> · © {year}</span>
  <span>Kubernetes, OpenShift, Helm, ROSA, RHACS and StackRox are trademarks of their owners; kube-noob is independent
    and not endorsed by them.</span>
</div></footer>
</body>
</html>
"""


def emit(b: Build, url: str, title: str, body: str, *, description: str = "", scripts: tuple[str, ...] = ()) -> None:
    target = b.out / url.strip("/") / "index.html" if url != "/" else b.out / "index.html"
    write(target, shell(b, url, title, body, description=description, scripts=scripts))
    headings = " ".join(re.findall(r"(?s)<h[1-3][^>]*>(.*?)</h[1-3]>", body))
    b.pages.append((url, title, strip_tags(headings)[:600], strip_tags(body)[:6000]))


# -- Markdown docs ----------------------------------------------------------------------------------------------
def doc_index(b: Build) -> dict[str, Doc]:
    return {d.source: d for d in b.docs}


def collect_docs(b: Build) -> None:
    listed = {src for src, _, _ in DOCS}
    entries = list(DOCS)
    for path in sorted((ROOT / "docs").glob("*.md")):
        rel = path.relative_to(ROOT).as_posix()
        if rel not in listed:
            entries.append((rel, path.stem.lower().replace(".", "-"), "More"))
    for src, slug, group in entries:
        path = ROOT / src
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        m = re.search(r"^# (.+)$", text, re.MULTILINE)
        title = m.group(1).strip() if m else slug.replace("-", " ").title()
        if src == "README.md":
            title = "Overview"
        b.docs.append(Doc(src, slug, group, title, text))


def resolve_link(b: Build, source: str, href: str) -> str:
    """Repo-relative and GitHub links to documents become site links; other repo files link to GitHub."""
    for prefix in RAW_PREFIXES:
        if href.startswith(prefix):
            href = "/" + href[len(prefix) :]
            break
    parts = urlsplit(href)
    if parts.scheme or parts.netloc or href.startswith(("#", "mailto:")):
        return href
    if href.startswith("/") and not href.startswith("//"):
        target = parts.path.lstrip("/")
    else:
        target = os.path.normpath(os.path.join(os.path.dirname(source), parts.path)).replace(os.sep, "/")
    anchor = f"#{parts.fragment}" if parts.fragment else ""
    docs = doc_index(b)
    if target in docs:
        return docs[target].url + anchor
    if target.startswith("docs/brand/"):
        return "/brand/" + target.removeprefix("docs/brand/")
    if (ROOT / target).is_dir():
        return f"{REPO_URL}/tree/main/{target}"
    if (ROOT / target).exists():
        return f"{REPO_URL}/blob/main/{target}{anchor}"
    return href


def render_markdown(b: Build, source: str, text: str) -> str:
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    out = markdown.markdown(text, extensions=["tables", "fenced_code", "toc", "sane_lists"], output_format="html")
    mermaid = r'<pre><code class="language-mermaid">(.*?)</code></pre>'
    out = re.sub(mermaid, r'<pre class="mermaid">\1</pre>', out, flags=re.DOTALL)
    out = out.replace("<table>", '<div class="table-wrap"><table>').replace("</table>", "</table></div>")

    def fix(m: re.Match[str]) -> str:
        return f'{m.group(1)}="{esc(resolve_link(b, source, html.unescape(m.group(2))))}"'

    out = re.sub(r'\b(href|src)="([^"]*)"', fix, out)
    # Status badges and other remote images would make every visitor's browser call a third party; the site loads
    # nothing from other hosts, so a remote image becomes its alt text (inside its link, if it had one).
    return re.sub(
        r'<img [^>]*?src="https?://[^"]*"[^>]*?alt="([^"]*)"[^>]*>|<img [^>]*?alt="([^"]*)"[^>]*?src="https?://[^"]*"[^>]*>',
        lambda m: f'<span class="badge">{m.group(1) or m.group(2)}</span>',
        out,
    )


def doc_nav(b: Build, here: str) -> str:
    groups: dict[str, list[Doc]] = {}
    for d in b.docs:
        groups.setdefault(d.group, []).append(d)
    parts = []
    for group, docs in groups.items():
        links = "".join(f'<a href="{d.url}"{current(d.url == here)}>{esc(d.title)}</a>' for d in docs)
        parts.append(f"<h4>{esc(group)}</h4>{links}")
    ref = "".join(f'<a href="{u}"{current(u == here)}>{esc(t)}</a>' for u, t in REFERENCE)
    parts.append(f"<h4>Reference</h4>{ref}")
    return f'<nav class="doc-nav" aria-label="Documentation">{"".join(parts)}</nav>'


def build_docs(b: Build) -> None:
    for d in b.docs:
        body = render_markdown(b, d.source, d.text)
        if d.source == "README.md":
            body = re.sub(r"^\s*<p[^>]*>\s*<img[^>]*>\s*</p>", "", body)  # the banner image; the site has a header
            body = f"<h1>Overview</h1>{body}"
        edit = f'<p class="edit-link">Source: <a href="{REPO_URL}/blob/main/{esc(d.source)}">{esc(d.source)}</a></p>'
        page = f'<div class="doc-layout">{doc_nav(b, d.url)}<article class="prose">{body}{edit}</article></div>'
        emit(b, d.url, d.title, page)


def ref_page(b: Build, url: str, title: str, inner: str, description: str = "") -> None:
    article = f'<article class="prose" style="max-width:none">{inner}</article>'
    page = f'<div class="doc-layout">{doc_nav(b, url)}{article}</div>'
    emit(b, url, title, page, description=description)


# -- reference: MCP tools ---------------------------------------------------------------------------------------
def schema_type(prop: dict[str, Any]) -> str:
    if "anyOf" in prop:
        return " | ".join(schema_type(p) for p in prop["anyOf"])
    if "$ref" in prop:
        return prop["$ref"].rsplit("/", 1)[-1]
    if "enum" in prop:
        return " | ".join(json.dumps(e) for e in prop["enum"])
    t = prop.get("type", "any")
    if t == "array":
        return f"array of {schema_type(prop.get('items', {}))}"
    return str(t)


def build_mcp(b: Build) -> None:
    from kube_noob.config import load_settings
    from kube_noob.server.mcp_app import TOOL_PREFIX
    from kube_noob.toolkit import Toolkit

    default = {s.name for s in Toolkit(load_settings(overrides={"offline": True})).specs()}
    full = Toolkit(load_settings(overrides={"webEnabled": True, "cluster": {"enabled": True}})).specs()
    rows, sections = [], []
    for spec in full:
        name = TOOL_PREFIX + spec.name
        gate = "always" if spec.name in default else ("webEnabled" if spec.open_world else "cluster.enabled")
        rows.append(
            f'<tr><td><a href="#{esc(name)}"><code>{esc(name)}</code></a></td><td>{esc(spec.title)}</td>'
            f"<td>{'read-only' if spec.read_only else 'writes local learning file'}</td><td>{esc(gate)}</td></tr>"
        )
        schema = spec.model.model_json_schema(by_alias=True)
        required = set(schema.get("required", []))
        params = "".join(
            f"<tr><td><code>{esc(k)}</code>{' (required)' if k in required else ''}</td>"
            f"<td><code>{esc(schema_type(v))}</code></td>"
            f"<td>{esc(json.dumps(v['default']) if 'default' in v else '')}</td>"
            f"<td>{esc(v.get('description', ''))}</td></tr>"
            for k, v in schema.get("properties", {}).items()
        )
        params_html = (
            '<div class="table-wrap"><table><thead><tr><th>Argument</th><th>Type</th><th>Default</th>'
            f"<th>Description</th></tr></thead><tbody>{params}</tbody></table></div>"
            if params
            else "<p>No arguments.</p>"
        )
        sections.append(
            f'<h2 id="{esc(name)}">{esc(spec.title)}</h2><p><code>{esc(name)}</code> · available: {esc(gate)}</p>'
            f"<p>{esc(spec.description)}</p>{params_html}<details><summary>JSON schema</summary>"
            f"<pre>{esc(json.dumps(schema, indent=2))}</pre></details>"
        )
    inner = (
        "<h1>MCP tools</h1><p>The tool surface every MCP client sees (Claude, OpenShift Lightspeed, Cursor, VS Code). "
        "Generated from the same ToolSpecs the server registers, so the schemas here are the schemas it validates. "
        f"{len(default)} tools are on by default; cluster and web tools appear only when enabled. Prompts: "
        "<code>getting_started</code>, <code>master_controller</code>, <code>debug_session</code>, <code>tutor</code>. "
        "Resources: <code>kubenoob://rules</code>, <code>kubenoob://curriculum</code>, "
        "<code>kubenoob://knowledge/{doc_id}</code>.</p>"
        '<div class="table-wrap"><table><thead><tr><th>Tool</th><th>Title</th><th>Effect</th><th>Available</th></tr>'
        f"</thead><tbody>{''.join(rows)}</tbody></table></div>{''.join(sections)}"
    )
    ref_page(b, "/reference/mcp/", "MCP tools", inner, "Every kube-noob MCP tool with its arguments and JSON schema.")


# -- reference: CLI ---------------------------------------------------------------------------------------------
def build_cli(b: Build) -> None:
    from kube_noob.cli import build_parser

    os.environ["COLUMNS"] = "110"
    parser = build_parser()
    blocks: list[str] = [f"<pre>{esc(parser.format_help())}</pre>"]

    def walk(p: argparse.ArgumentParser, trail: str) -> None:
        for action in p._actions:  # argparse exposes subcommands only through this attribute
            if isinstance(action, argparse._SubParsersAction):
                for name, sub in action.choices.items():
                    full = f"{trail} {name}".strip()
                    blocks.append(f'<h2 id="{esc(full.replace(" ", "-"))}">kube-noob {esc(full)}</h2>')
                    blocks.append(f"<pre>{esc(sub.format_help())}</pre>")
                    walk(sub, full)

    walk(parser, "")
    inner = (
        "<h1>CLI</h1><p>Every command and option, from the CLI's own help. <code>noob</code> is the same program. "
        "None of these call a model except <code>kube-noob ask</code>, and only when you configure one.</p>"
        + "".join(blocks)
    )
    ref_page(b, "/reference/cli/", "CLI reference", inner, "Every kube-noob command and option.")


# -- reference: rules, playbooks, knowledge, known issues -------------------------------------------------------
def build_rules(b: Build) -> None:
    from kube_noob.audit.controls import describe
    from kube_noob.audit.engine import list_rules

    rules = list_rules()
    rows = []
    for r in rules:
        controls = ", ".join(f"{c['id']} {c['title']}" for c in describe(str(r["ruleId"])))
        policies = ", ".join(str(p) for p in r.get("stackroxPolicies", []) or [])  # type: ignore[union-attr]
        rows.append(
            f'<tr id="{esc(r["ruleId"])}"><td><code>{esc(r["ruleId"])}</code></td><td><b>{esc(r["title"])}</b><br>'
            f"{esc(r['description'])}<br><i>Fix:</i> {esc(r['remediation'])}</td>"
            f'<td><span class="sev {esc(r["defaultSeverity"])}">{esc(r["defaultSeverity"])}</span></td>'
            f"<td>{esc(r['stage'])} / {esc(r['category'])}</td><td>{esc(controls)}</td><td>{esc(policies)}</td></tr>"
        )
    inner = (
        f"<h1>Audit rules</h1><p>{len(rules)} rules. Rule ids are a public contract: they never change meaning or get "
        "renumbered. Each names the NIST SP 800-53 Rev. 5 controls it is evidence about and the RHACS (StackRox) "
        'policies that would fire. Try them on your YAML in the <a href="/playground/#audit">playground</a>.</p>'
        '<div class="table-wrap"><table><thead><tr><th>Id</th><th>Rule</th><th>Severity</th><th>Stage / category</th>'
        f"<th>NIST controls</th><th>RHACS policies</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )
    ref_page(b, "/reference/rules/", "Audit rules", inner, f"All {len(rules)} kube-noob audit rules.")


def build_playbooks(b: Build) -> None:
    from kube_noob.debug.playbooks import PLAYBOOKS

    cards = []
    for p in PLAYBOOKS:
        causes = "".join(f"<li>{esc(c)}</li>" for c in p.root_causes)
        checks = "".join(f"<li><code>{esc(c)}</code></li>" for c in p.checks[:6])
        rules = ", ".join(f'<a href="/reference/rules/#{esc(r)}">{esc(r)}</a>' for r in p.related_rules)
        cards.append(
            f'<h2 id="{esc(p.pid)}">{esc(p.title)}</h2><p><code>{esc(p.pid)}</code> · {esc(", ".join(p.platforms))}'
            f"{' · rules ' + rules if rules else ''}</p><p><b>Likely causes</b></p><ul>{causes}</ul>"
            f"<p><b>Read-only checks</b></p><ul>{checks}</ul>"
        )
    inner = (
        f"<h1>Troubleshooting playbooks</h1><p>{len(PLAYBOOKS)} offline playbooks. <code>diagnose</code> matches "
        "pasted events, describe output, logs or CLI errors against them and lists read-only steps before anything "
        'that changes the cluster. Try one in the <a href="/playground/#diagnose">playground</a>.</p>' + "".join(cards)
    )
    ref_page(b, "/reference/playbooks/", "Playbooks", inner, f"{len(PLAYBOOKS)} offline troubleshooting playbooks.")


def knowledge_docs() -> list[dict[str, Any]]:
    out = []
    for path in sorted((ROOT / "src" / "kube_noob" / "data" / "knowledge").glob("*.md")):
        text = path.read_text(encoding="utf-8")
        m = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
        meta = yaml.safe_load(m.group(1)) if m else {}
        out.append({"id": meta.get("id", path.stem), "title": meta.get("title", path.stem), **meta})
    return out


def build_knowledge(b: Build) -> None:
    docs = knowledge_docs()
    rows = []
    for d in docs:
        sources = "<br>".join(
            f'<a href="{esc(s.get("url", ""))}" rel="noopener">{esc(s.get("title", s.get("url", "")))}</a>'
            f" ({esc(s.get('license', ''))})"
            for s in d.get("sources", []) or []
        )
        rows.append(
            f"<tr><td><code>kn:{esc(d['id'])}</code></td><td>{esc(d['title'])}</td>"
            f"<td>{esc(', '.join(d.get('tags', []) or []))}</td><td>{esc(d.get('updated', ''))}</td>"
            f"<td>{sources}</td></tr>"
        )
    inner = (
        f"<h1>Knowledge base</h1><p>{len(docs)} curated documents, indexed with BM25 and cited in answers as "
        "<code>[kn:&lt;doc&gt;#&lt;n&gt;]</code>. Every document lists its sources and their licenses.</p>"
        '<div class="table-wrap"><table><thead><tr><th>Id</th><th>Title</th><th>Tags</th><th>Reviewed</th>'
        f"<th>Sources</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )
    ref_page(b, "/reference/knowledge/", "Knowledge base", inner, "Curated, cited Kubernetes and OpenShift knowledge.")


def known_issue_stats() -> dict[str, Any]:
    by_release: Counter[str] = Counter()
    by_kind: Counter[str] = Counter()
    retrieved = set()
    for path in sorted((ROOT / "src" / "kube_noob" / "data" / "known_issues").glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        retrieved.add(str(data.get("retrievedAt", ""))[:10])
        for rec in data.get("records", []):
            by_release[f"{rec.get('minor', '?')} {rec.get('kind', '?')}"] += 1
            by_kind[str(rec.get("kind", "?"))] += 1
    return {"byRelease": dict(sorted(by_release.items())), "byKind": dict(by_kind), "retrieved": sorted(retrieved)}


def bars(title: str, data: dict[str, int], unit: str = "") -> str:
    """Single-series horizontal bars: one hue, value labels in ink, a native tooltip per row."""
    if not data:
        return ""
    top = max(data.values()) or 1
    rows = "".join(
        f'<div class="bar-row" title="{esc(k)}: {v}{esc(unit)}"><span>{esc(k)}</span><div class="track">'
        f'<div class="fill" style="width:{max(1.0, 100 * v / top):.1f}%"></div></div><span class="v">{v}</span></div>'
        for k, v in data.items()
    )
    return f'<h3>{esc(title)}</h3><div class="bars" role="table" aria-label="{esc(title)}">{rows}</div>'


def build_known_issues(b: Build) -> None:
    s = known_issue_stats()
    total = sum(s["byKind"].values())
    inner = (
        f"<h1>Known issues index</h1><p>{total} issues from the OpenShift release notes (Apache-2.0, openshift-docs), "
        f"retrieved {esc(', '.join(s['retrieved']))}: known issues of each release and the issues each update fixed. "
        "<code>known-issues</code> and <code>diagnose</code> match an error against them and say whether a fix exists "
        "and in which version; issues already fixed in your version are left out. A match needs several rare words in "
        'common, so everyday errors never pull in an unrelated bug. Try it in the <a href="/playground/#known">'
        "playground</a>. A local copy of Red Hat's public Jira (<code>corpus jira --online</code>) adds what became of "
        "each ticket; it is fetched by you and never redistributed.</p>"
        + bars("Issues per OpenShift release and kind", s["byRelease"])
    )
    ref_page(
        b, "/reference/known-issues/", "Known issues index", inner, "OpenShift release-note issues kube-noob matches."
    )


# -- reference: Helm values -------------------------------------------------------------------------------------
def helm_values() -> list[tuple[str, str, str]]:
    """(key path, default, comment) from values.yaml, keeping the comments that document each key."""
    rows: list[tuple[str, str, str]] = []
    stack: list[tuple[int, str]] = []
    pending: list[str] = []
    for line in (ROOT / "deploy" / "helm" / "kube-noob" / "values.yaml").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            pending = []
            continue
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if stripped.startswith("#"):
            pending.append(stripped.lstrip("#").strip())
            continue
        m = re.match(r"^(-\s+)?([A-Za-z0-9_.-]+):\s*(.*)$", stripped)
        if not m or m.group(1):
            pending = []
            continue
        key, rest = m.group(2), m.group(3)
        while stack and stack[-1][0] >= indent:
            stack.pop()
        path = ".".join([k for _, k in stack] + [key])
        value, _, comment = rest.partition(" #")
        if not value.strip():
            stack.append((indent, key))
        notes = " ".join([*pending, comment.strip()]).strip()
        rows.append((path, value.strip(), notes))
        pending = []
    return rows


def build_helm_values(b: Build) -> None:
    rows = "".join(
        f"<tr><td><code>{esc(k)}</code></td><td><code>{esc(v)}</code></td><td>{esc(c)}</td></tr>"
        for k, v, c in helm_values()
    )
    chart = yaml.safe_load((ROOT / "deploy" / "helm" / "kube-noob" / "Chart.yaml").read_text(encoding="utf-8"))
    inner = (
        f"<h1>Helm values</h1><p>Chart <code>{esc(chart.get('name'))}</code> {esc(chart.get('version'))} "
        f"(app {esc(chart.get('appVersion'))}). Defaults are secure: no web access, no cluster access, authenticated "
        "HTTP, NetworkPolicies on, runs under <code>restricted-v2</code>. The chart validates values against "
        f'<a href="{REPO_URL}/blob/main/deploy/helm/kube-noob/values.schema.json">values.schema.json</a>. Install and '
        'operations: <a href="/docs/helm-chart/">Helm chart</a>, <a href="/docs/openshift/">OpenShift</a>.</p>'
        '<div class="table-wrap"><table><thead><tr><th>Key</th><th>Default</th><th>Notes</th></tr></thead>'
        f"<tbody>{rows}</tbody></table></div>"
    )
    ref_page(b, "/reference/helm-values/", "Helm values", inner, "Every value of the kube-noob Helm chart.")


# -- journey ----------------------------------------------------------------------------------------------------
def protocol_steps() -> list[tuple[str, str]]:
    text = (ROOT / "docs" / "architecture.md").read_text(encoding="utf-8")
    section = text.split("## Request flow", 1)[1].split("\n## ", 1)[0]
    steps = []
    for m in re.finditer(r"^\d+\. \*\*([^*]+)\*\* - (.+?)(?=^\d+\. |\Z)", section, re.MULTILINE | re.DOTALL):
        steps.append((m.group(1).strip(), re.sub(r"\s+", " ", m.group(2)).strip()))
    return steps


def demo_transcripts() -> list[dict[str, str]]:
    from kube_noob import demo
    from kube_noob.config import load_settings

    settings = load_settings(overrides={"offline": True})
    out = []
    for name, scenario in demo.SCENARIOS.items():
        lines: list[str] = []
        with contextlib.redirect_stdout(io.StringIO()):
            demo.run(name, settings, lines.append)
        out.append({"name": name, "title": scenario.title, "for": scenario.audience, "text": "\n".join(lines)})
    return out


def releases() -> list[dict[str, str]]:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    out = []
    for m in re.finditer(r"^## (\S+) - (\d{4}-\d{2}-\d{2})\n+(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL):
        body = m.group(3).strip()
        first = body.split("\n\n", 1)[0]
        if first.startswith("- "):
            first = first.split("\n- ", 1)[0].removeprefix("- ")
        out.append({"version": m.group(1), "date": m.group(2), "summary": re.sub(r"\s+", " ", first)})
    return out


CHAPTER_NOTES = {
    "audit": "Paste a Deployment and get findings with the line, the fix, the RHACS policy and the NIST controls; "
    "`fix` applies the safe mechanical changes and audits the result again.",
    "diagnose": "Paste events or logs and get the likely cause, then read-only steps first. Commands that run inside "
    "a container or change the cluster come last, marked as needing approval.",
    "protocol": "A design request runs Clarify, Validate, Research, Audit, Calibrate, Generate and Red Team. Remaining "
    "HIGH or CRITICAL findings mark the result blocked.",
    "learn": "Lessons with objectives and citations, then exercises graded by the same rules as a production review.",
    "search": "Answers cite local knowledge as [kn:<doc>#<n>], with the source URL and license of every chunk.",
    "learning": "A fix the team confirmed is remembered locally and found the next time the symptom appears.",
    "posture": "`doctor` proves what kube-noob can reach (nothing, by default), and the offline lock keeps it "
    "that way.",
}


def build_journey(b: Build) -> None:
    steps = "".join(f"<li><b>{esc(n)}</b><span>{inline(d)}</span></li>" for n, d in protocol_steps())
    chapters = []
    for t in demo_transcripts():
        note = CHAPTER_NOTES.get(t["name"], "")
        chapters.append(
            f'<div class="chapter" id="{esc(t["name"])}"><div><h3>{esc(t["title"])}</h3><p><b>For:</b> {esc(t["for"])}'
            f"</p><p>{inline(note)}</p><p><code>kube-noob demo {esc(t['name'])}</code></p></div>"
            f"<pre>{esc(t['text'])}</pre></div>"
        )
    timeline = "".join(
        f'<div class="rel"><h3>{esc(r["version"])}</h3><div class="date">{esc(r["date"])}</div>'
        f"<p>{esc(r['summary'])}</p></div>"
        for r in releases()
    )
    body = (
        '<div class="prose" style="max-width:900px"><span class="eyebrow">Product journey</span>'
        '<h1>From a broken pod to a cited, read-only fix</h1><p class="lead">kube-noob is the rulebook, not the '
        "chatbot. Below is what it does, step by step, with the real output of <code>kube-noob demo</code> from this "
        "build: offline, in under a second, never touching a cluster.</p></div>"
        '<section class="band"><h2>The 7-step protocol</h2><p class="sub">Every design request runs these steps, '
        "in this "
        f'order.</p><ol class="steps">{steps}</ol></section>'
        f'<section class="band"><h2>What it does, in real output</h2>{"".join(chapters)}</section>'
        f'<section class="band"><h2>How it got here</h2><p class="sub">Every release, newest first, from the changelog.'
        f'</p><div class="timeline">{timeline}</div></section>'
    )
    emit(b, "/journey/", "Product journey", body, description="What kube-noob does, step by step, with real output.")


# -- insights ---------------------------------------------------------------------------------------------------
def count_tests() -> int:
    return sum(
        len(re.findall(r"^def test_", p.read_text(encoding="utf-8"), re.MULTILINE))
        for p in (ROOT / "tests").glob("test_*.py")
    )


def roadmap_status() -> str:
    text = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    m = re.search(r"^## Status\n(.*?)(?=^## )", text, re.MULTILINE | re.DOTALL)
    return m.group(1) if m else ""


def build_insights(b: Build) -> dict[str, Any]:
    from kube_noob.audit.controls import CATALOG
    from kube_noob.audit.engine import list_rules
    from kube_noob.audit.redteam import SCENARIOS
    from kube_noob.config import load_settings
    from kube_noob.debug.playbooks import PLAYBOOKS
    from kube_noob.evals.selftest import run as selftest
    from kube_noob.knowledge_status import status
    from kube_noob.learn.tutor import curriculum
    from kube_noob.toolkit import Toolkit

    settings = load_settings(overrides={"offline": True})
    rules = list_rules()
    st = selftest(settings)
    ki = known_issue_stats()
    tracks = curriculum()["tracks"]
    know = status(settings.data_dir)
    nums = {
        "Version": version(),
        "Audit rules": len(rules),
        "Offline playbooks": len(PLAYBOOKS),
        "Red-team scenarios": len(SCENARIOS),
        "MCP tools (default)": len(Toolkit(settings).specs()),
        "Knowledge documents": len(knowledge_docs()),
        "Release-note issues": sum(ki["byKind"].values()),
        "NIST controls mapped": len(CATALOG),
        "Self-test": f"{st['passed']}/{st['total']}",
        "Tests in the suite": count_tests(),
        "Learning tracks": len(tracks),
        "Kubernetes schema": know["kubernetes"],
    }
    tiles = "".join(
        f'<div class="stat"><div class="n">{esc(v)}</div><div class="l">{esc(k)}</div></div>' for k, v in nums.items()
    )
    by_cat = Counter(str(r["category"]) for r in rules)
    by_sev = Counter(str(r["defaultSeverity"]) for r in rules)
    severities = {s: by_sev[s] for s in ("critical", "high", "medium", "low", "info") if by_sev[s]}
    selftest_rows = {k: round(100 * v["passed"] / v["total"]) for k, v in st["byCategory"].items()}
    status_md = roadmap_status()
    body = (
        '<div class="prose" style="max-width:900px"><span class="eyebrow">Insights</span><h1>kube-noob by the numbers'
        f'</h1><p class="lead">Computed from the code when this site was built ({esc(datetime.now(UTC).date())}). '
        f"{esc(know['note'])}</p></div>"
        f'<section class="band"><div class="stats">{tiles}</div></section>'
        '<section class="band"><div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(360px,1fr))">'
        f'<div class="card">{bars("Audit rules by category", dict(by_cat.most_common()))}</div>'
        f'<div class="card">{bars("Audit rules by default severity", severities)}</div>'
        f'<div class="card">{bars("Self-test score by area (%)", selftest_rows, "%")}</div>'
        f'<div class="card">{bars("Release-note issues by OpenShift release", ki["byRelease"])}</div>'
        "</div></section>"
        f'<section class="band prose" style="max-width:none"><h2>Roadmap status</h2>'
        f'{render_markdown(b, "docs/roadmap.md", status_md)}<p><a href="/docs/roadmap/">Full roadmap</a></p></section>'
    )
    emit(
        b,
        "/insights/",
        "Insights",
        body,
        description="kube-noob's rules, playbooks, tests and coverage, by the numbers.",
    )
    return nums


# -- videos -----------------------------------------------------------------------------------------------------
def collect_media(b: Build, videos: Path | None, gifs: Path | None) -> None:
    meta = json.loads((ROOT / "demos" / "video" / "stage" / "videos.json").read_text(encoding="utf-8"))["videos"]
    if videos and videos.is_dir():
        for name in VIDEOS:
            mp4 = next(iter(sorted(videos.rglob(f"kube-noob-{name}*.mp4"))), None)
            if mp4 is None:
                continue
            poster = mp4.with_suffix(".jpg")
            write(b.out / "videos" / f"kube-noob-{name}.mp4", mp4.read_bytes())
            if poster.is_file():
                write(b.out / "videos" / f"kube-noob-{name}.jpg", poster.read_bytes())
            b.videos.append(
                {
                    "name": name,
                    "title": meta.get(name, {}).get("title", name),
                    "src": f"/videos/kube-noob-{name}.mp4",
                    "poster": f"/videos/kube-noob-{name}.jpg" if poster.is_file() else "",
                }
            )
    if len(b.videos) < len(VIDEOS):
        b.missing.append(f"videos ({len(b.videos)} of {len(VIDEOS)} rendered)")
    if gifs and gifs.is_dir():
        from kube_noob import demo

        titles = {k: v.title for k, v in demo.SCENARIOS.items()} | {"tour": "A tour of every command"}
        for gif in sorted(gifs.glob("*.gif")):
            write(b.out / "demos" / gif.name, gif.read_bytes())
            b.gifs.append({"src": f"/demos/{gif.name}", "title": titles.get(gif.stem, gif.stem)})


def video_tag(v: dict[str, str], *, autoplay: bool = False) -> str:
    poster = f' poster="{esc(v["poster"])}"' if v["poster"] else ""
    flags = " autoplay muted loop playsinline" if autoplay else ' preload="metadata" playsinline'
    return f'<video controls{flags}{poster} src="{esc(v["src"])}" aria-label="{esc(v["title"])}"></video>'


def build_videos(b: Build) -> None:
    cards = "".join(f'<div class="video-card">{video_tag(v)}<h3>{esc(v["title"])}</h3></div>' for v in b.videos) or (
        '<p class="note">The animated videos are rendered by the site workflow '
        "(<code>demos/video/stage/build.sh</code>); this build did not include them.</p>"
    )
    gifs = (
        "".join(
            f'<figure><img src="{esc(g["src"])}" alt="Terminal recording: {esc(g["title"])}" loading="lazy">'
            f"<figcaption>{esc(g['title'])}</figcaption></figure>"
            for g in b.gifs
        )
        or f'<p class="note">Terminal recordings are attached to every <a href="{REPO_URL}/releases/latest">'
        "release</a>.</p>"
    )
    body = (
        '<div class="prose" style="max-width:900px"><span class="eyebrow">Videos</span><h1>See it run</h1>'
        '<p class="lead">Animated, narrated and rendered without a video model: every terminal line in them is copied '
        "from a real run (the CLI, the CI sidecar transcript and a recorded Claude session). Voice: Kokoro-82M "
        "(Apache-2.0); music generated by <code>demos/video/audio_kit.py</code>.</p></div>"
        f'<section class="band"><div class="videos">{cards}</div></section>'
        f'<section class="band"><h2>Terminal recordings</h2><p class="sub">Each <code>kube-noob demo</code> scenario, '
        f'recorded with VHS from the released wheel.</p><div class="gifs">{gifs}</div></section>'
    )
    emit(b, "/videos/", "Videos", body, description="Animated kube-noob videos and terminal recordings.")


# -- home -------------------------------------------------------------------------------------------------------
def readme_section(name: str) -> str:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(rf"^## {re.escape(name)}\n(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL)
    return m.group(1).strip() if m else ""


CAPABILITIES = (
    (
        "Audit",
        "Rules plus strict schemas for Kubernetes 1.35, Routes, SCCs, EgressFirewall, Gateway API and StackRox; "
        "removed APIs; safe auto-fixes; red-team scenarios.",
        "/playground/#audit",
    ),
    (
        "Debug",
        "Offline playbooks, read-only steps first, redacted evidence bundles, and read-only cluster evidence that "
        "never touches Secrets.",
        "/playground/#diagnose",
    ),
    (
        "Known bugs",
        "Errors matched to the issues in the OpenShift release notes, with the fix version and workaround.",
        "/playground/#known",
    ),
    (
        "Policy",
        "Why was this denied? Kyverno, Gatekeeper, VAP, Pod Security, SCC, RHACS, quota and RBAC, with the fix. "
        "Can A reach B? NetworkPolicies evaluated the way Kubernetes does.",
        "/playground/#denied",
    ),
    (
        "Generate",
        "Hardened manifests and Helm charts from a blueprint, audited again before they are returned.",
        "/journey/#protocol",
    ),
    ("Learn", "Tracks, lessons and exercises graded by the same rules as a production review.", "/docs/learning/"),
)


def build_home(b: Build, nums: dict[str, Any]) -> None:
    teaser = next((v for v in b.videos if v["name"] == "teaser"), None)
    media = (
        video_tag(teaser, autoplay=True)
        if teaser
        else ('<img class="poster" src="/brand/social-preview.png" alt="kube-noob: No AI inside. Works with yours.">')
    )
    quick = re.search(r"```bash\n(.*?)```", readme_section("Quick start"), re.DOTALL)
    install = f"<pre><code>{esc(quick.group(1).strip())}</code></pre>" if quick else ""
    caps = "".join(
        f'<div class="card"><h3>{esc(t)}</h3><p>{esc(d)}</p><a class="more" href="{u}">Try it</a></div>'
        for t, d, u in CAPABILITIES
    )
    who = render_markdown(b, "README.md", readme_section("Who does the thinking"))
    mcp = render_markdown(b, "README.md", readme_section("Use with Claude or any MCP client"))
    stats = "".join(
        f'<div class="stat"><div class="n">{esc(nums[k])}</div><div class="l">{esc(k)}</div></div>'
        for k in ("Audit rules", "Offline playbooks", "Release-note issues", "MCP tools (default)", "Self-test")
    )
    body = f"""
<section class="hero">
  <div>
    <span class="eyebrow">Kubernetes · OpenShift · ROSA HCP · Helm · RHACS</span>
    <h1>No AI inside.<br>Works with yours.</h1>
    <p class="lead">kube-noob is the rulebook your AI is missing: audit rules, read-only-first playbooks, known
    OpenShift bugs with their fix versions, policy debugging and cited docs. Claude, OpenShift Lightspeed or any MCP
    client calls it as tools; the CLI runs it with no AI at all. It makes no network calls unless you turn them on.</p>
    <div class="cta">
      <a class="btn primary" href="/playground/">Run it in your browser</a>
      <a class="btn" href="/ask/">Ask with your Claude key</a>
      <a class="btn" href="/docs/install/">Install</a>
    </div>
    <div class="install">{install}</div>
  </div>
  <div>{media}</div>
</section>
<section class="band"><div class="stats">{stats}</div></section>
<section class="band"><h2>What it does</h2><p class="sub">Every answer is deterministic, cited and the same every time.
The playground runs these tools in your browser: nothing is uploaded.</p><div class="grid">{caps}</div></section>
<section class="band prose" style="max-width:none"><h2>Who does the thinking</h2>{who}</section>
<section class="band"><h2>Pick your path</h2><div class="grid">
  <div class="card"><h3>Developer</h3><p>Ship YAML that passes on OpenShift and ROSA HCP; gate pull requests with
  <code>audit --fail-on high</code>.</p><a class="more" href="/docs/use-cases/">Use cases</a></div>
  <div class="card"><h3>SRE or on-call</h3><p>Diagnose before you change anything: cause, read-only steps, a redacted
  evidence bundle.</p><a class="more" href="/journey/#diagnose">See it</a></div>
  <div class="card"><h3>Platform admin</h3><p>Run it in the cluster, locked down: offline lock, <code>doctor</code>,
  NetworkPolicies, <code>restricted-v2</code>.</p><a class="more" href="/docs/openshift/">OpenShift guide</a></div>
  <div class="card"><h3>Security</h3><p>Findings mapped to RHACS policies and NIST SP 800-53 controls; red-team
  scenarios; FIPS reporting.</p><a class="more" href="/docs/compliance/">Compliance</a></div>
</div></section>
<section class="band prose" style="max-width:none"><h2>Use with Claude or any MCP client</h2>{mcp}
<p><a href="/reference/mcp/">Every MCP tool and its schema</a></p></section>
"""
    emit(b, "/", "kube-noob", body)


# -- playground and ask -----------------------------------------------------------------------------------------
def runtime_note(b: Build) -> str:
    if b.has_runtime:
        return ""
    return (
        '<p class="note">This build does not include the in-browser runtime (Pyodide and the kube-noob wheel), so the '
        "tools below cannot start. Build with <code>--pyodide</code> and <code>--wheel</code>.</p>"
    )


def build_playground(b: Build) -> None:
    ex = ROOT / "examples"
    examples = {
        "audit": (ex / "insecure-deployment.yaml").read_text(encoding="utf-8"),
        "diagnose": (ex / "events-crashloop.txt").read_text(encoding="utf-8"),
        "known": "could not find any suitable subnets for creating the ELB",
        "denied": (ex / "events-scc.txt").read_text(encoding="utf-8"),
        "reach": (ex / "netpol-shop.yaml").read_text(encoding="utf-8"),
    }
    data = json.dumps(examples).replace("</", "<\\/")
    body = f"""
<div class="prose" style="max-width:900px"><span class="eyebrow">Playground</span>
<h1>kube-noob, running in your browser</h1>
<p class="lead">These are kube-noob's real tools (the same code as the CLI and the MCP server), compiled to WebAssembly
with Pyodide and running in this tab. No model, no server, no account: what you paste never leaves your device. The
first run downloads the runtime (about 15 MB) from this site, once.</p></div>
{runtime_note(b)}
<p class="status" id="kn-status" aria-live="polite"></p>
<div class="tabs" id="kn-tabs" role="tablist" aria-label="Tools"></div>
<div class="tool-panel" id="kn-panel"></div>
<script type="application/json" id="kn-examples">{data}</script>
"""
    emit(
        b,
        "/playground/",
        "Playground",
        body,
        description="Run kube-noob's audit, diagnose, known-issue and policy "
        "tools in your browser. Nothing is uploaded.",
        scripts=("/assets/playground.js",),
    )


def build_ask(b: Build) -> None:
    suggestions = (
        "My pod is stuck in CrashLoopBackOff with exit code 137 on OpenShift 4.21. What should I check first?",
        "Audit this and tell me what blocks it on OpenShift 4.22: a Deployment running nginx:latest as root with "
        "hostNetwork true.",
        "Is 'could not find any suitable subnets for creating the ELB' a known bug on OpenShift 4.20.8?",
        "Explain rule KN-S013 and the NIST controls it maps to.",
    )
    chips = "".join(
        f'<button class="btn" type="button" data-ask="{esc(s)}">{esc(s[:60])}...</button>' for s in suggestions
    )
    body = f"""
<div class="prose" style="max-width:900px"><span class="eyebrow">Ask, with your own key</span>
<h1>Claude plus kube-noob's tools, in your browser</h1>
<p class="lead">Bring your own Anthropic API key. Claude does the talking; whenever it needs a fact it calls kube-noob's
tools, which run here in this tab. This site has no server and never sees your key or your questions: they go from your
browser straight to <code>api.anthropic.com</code>, billed to your key. kube-noob itself still has no AI
inside.</p></div>
{runtime_note(b)}
<div class="note"><b>Your key:</b> kept in memory for this page, or in this tab's session storage if you tick the box
(cleared when the tab closes). It is never written to local storage, cookies or logs. Use a key with a spending limit.
Create one in the <a href="https://platform.claude.com/" rel="noopener">Claude Console</a>.</div>
<form id="ask-form" autocomplete="off">
  <div class="row">
    <div><label for="ask-key">Anthropic API key</label><input id="ask-key" type="password" placeholder="sk-ant-..."
      spellcheck="false" autocomplete="off"></div>
    <div><label for="ask-model">Model</label><select id="ask-model">
      <option value="claude-opus-5-5" selected>Claude Opus 5.5</option>
      <option value="claude-sonnet-5-5">Claude Sonnet 5.5</option>
      <option value="claude-haiku-5-5">Claude Haiku 5.5</option></select></div>
    <div><label for="ask-effort">Effort</label><select id="ask-effort">
      <option value="low">low</option><option value="medium" selected>medium</option>
      <option value="high">high</option></select></div>
  </div>
  <p><label style="display:inline;font-weight:400"><input type="checkbox" id="ask-remember"> Keep the key for this tab
  </label> · <button class="icon-btn" type="button" id="ask-forget">Forget key and conversation</button></p>
  <div class="chat" id="ask-chat" aria-live="polite"></div>
  <label for="ask-input">Your question (paste YAML, events or errors too)</label>
  <textarea id="ask-input" style="min-height:140px" spellcheck="false"></textarea>
  <p><button class="btn primary" id="ask-send" type="submit">Ask</button></p>
  <p class="status" id="ask-status" aria-live="polite"></p>
</form>
<p>Try:</p><div class="cta">{chips}</div>
<p class="status">Refused requests fall back to another Claude model automatically (server-side fallback). Tool calls
and their results are shown under each answer.</p>
"""
    emit(
        b,
        "/ask/",
        "Ask with your Claude key",
        body,
        description="Claude with kube-noob's tools running in your browser, using your own API key.",
        scripts=("/assets/agent.js",),
    )


# -- runtime, static files, index -------------------------------------------------------------------------------
def vendor_pyodide(b: Build, source: Path | None) -> bool:
    """Copy the Pyodide core and the wheels kube-noob needs (the dependency closure in pyodide-lock.json)."""
    if source is None:
        return False
    dest = b.out / "pyodide"

    def closure(lock: dict[str, Any]) -> set[str]:
        pk = lock["packages"]
        need: set[str] = set()
        todo = list(PYODIDE_ROOTS)
        while todo:
            name = todo.pop().lower().replace("_", "-")
            if name in need or name not in pk:
                continue
            need.add(name)
            todo.extend(pk[name].get("depends", []))
        return {pk[n]["file_name"] for n in need}

    if source.is_dir():
        lock = json.loads((source / "pyodide-lock.json").read_text(encoding="utf-8"))
        for name in sorted(set(PYODIDE_CORE) | closure(lock)):
            write(dest / name, (source / name).read_bytes())
    else:
        with tarfile.open(source) as tf:
            prefix = "pyodide/"
            lock_member = tf.extractfile(prefix + "pyodide-lock.json")
            if lock_member is None:
                raise SystemExit(f"{source}: no pyodide/pyodide-lock.json")
            wanted = set(PYODIDE_CORE) | closure(json.load(lock_member))
            for member in tf.getmembers():
                name = member.name.removeprefix(prefix)
                if name in wanted and member.isfile() and "/" not in name:
                    fh = tf.extractfile(member)
                    if fh is not None:
                        write(dest / name, fh.read())
    missing = [n for n in PYODIDE_CORE if not (dest / n).is_file()]
    if missing:
        raise SystemExit(f"Pyodide distribution is missing {', '.join(missing)}")
    return True


def vendor_wheel(b: Build, wheel: Path | None) -> bool:
    if wheel is None or not wheel.is_file():
        return False
    data = wheel.read_bytes()
    write(b.out / "py" / wheel.name, data)
    write(b.out / "py" / "bridge.py", (SITE_SRC / "static" / "bridge.py").read_bytes())
    manifest = {"wheel": wheel.name, "sha256": hashlib.sha256(data).hexdigest(), "version": version()}
    write(b.out / "py" / "manifest.json", json.dumps(manifest, indent=1))
    return True


def copy_static(b: Build) -> None:
    for name in ("style.css", "kn-worker.js"):
        write(b.out / "assets" / name, (SITE_SRC / "static" / name).read_bytes())
    brand = ROOT / "docs" / "brand"
    for name in (
        "kube-noob-icon.svg",
        "kube-noob-32.png",
        "kube-noob-256.png",
        "kube-noob-512.png",
        "social-preview.png",
    ):
        write(b.out / "brand" / name, (brand / name).read_bytes())
    write(b.out / "CNAME", DOMAIN + "\n")
    write(b.out / ".nojekyll", "")
    write(b.out / "robots.txt", f"User-agent: *\nAllow: /\nSitemap: {BASE_URL}/sitemap.xml\n")


def build_404(b: Build) -> None:
    body = (
        '<div class="prose"><h1>Page not found</h1><p>That page does not exist (or moved). Try the search box, the '
        '<a href="/docs/overview/">docs</a> or the <a href="/">home page</a>.</p></div>'
    )
    write(b.out / "404.html", shell(b, "/404/", "Not found", body))


def finish(b: Build) -> None:
    index = [{"u": u, "t": t, "h": h, "b": text} for u, t, h, text in b.pages]
    write(b.out / "search-index.json", json.dumps(index, separators=(",", ":")))
    urls = "".join(f"<url><loc>{BASE_URL}{esc(u)}</loc></url>" for u, *_ in b.pages)
    write(
        b.out / "sitemap.xml",
        f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}'
        "</urlset>",
    )


def check_links(b: Build) -> list[str]:
    """Every internal link and asset in the generated HTML points at a file that exists."""
    broken = []
    for page in b.out.rglob("*.html"):
        for ref in re.findall(r'(?:href|src)="(/[^"#?]*)', page.read_text(encoding="utf-8")):
            if ref.startswith("//") or ref.startswith(("/assets/site.js", "/assets/playground.js", "/assets/agent.js")):
                continue
            target = b.out / ref.lstrip("/")
            if not (target.is_file() or (target / "index.html").is_file()):
                broken.append(f"{page.relative_to(b.out)} -> {ref}")
    return sorted(set(broken))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=ROOT / "_site")
    ap.add_argument("--clean", action="store_true", help="delete the output directory first")
    ap.add_argument("--pyodide", type=Path, help="Pyodide full distribution: the release .tar.bz2 or an extracted dir")
    ap.add_argument("--wheel", type=Path, help="the kube-noob wheel to run in the browser")
    ap.add_argument("--videos", type=Path, help="directory with kube-noob-<video>.mp4 (and .jpg posters)")
    ap.add_argument("--gifs", type=Path, help="directory with the release's VHS GIFs")
    ap.add_argument("--strict", action="store_true", help="fail if the runtime, the wheel or any video is missing")
    a = ap.parse_args(argv)
    out = a.out.resolve()
    if a.clean and out.exists():
        if out == ROOT or ROOT.is_relative_to(out):
            raise SystemExit(f"refusing to delete {out}")
        shutil.rmtree(out)
    b = Build(out=out, strict=a.strict)
    b.has_runtime = vendor_pyodide(b, a.pyodide) and vendor_wheel(b, a.wheel)
    if not b.has_runtime:
        b.missing.append("in-browser runtime (--pyodide and --wheel)")
    collect_media(b, a.videos, a.gifs)
    if a.strict and b.missing:
        raise SystemExit("missing: " + "; ".join(b.missing))
    copy_static(b)
    collect_docs(b)
    build_docs(b)
    build_mcp(b)
    build_cli(b)
    build_rules(b)
    build_playbooks(b)
    build_knowledge(b)
    build_known_issues(b)
    build_helm_values(b)
    build_journey(b)
    nums = build_insights(b)
    build_videos(b)
    build_home(b, nums)
    build_playground(b)
    build_ask(b)
    build_404(b)
    finish(b)
    broken = check_links(b)
    if broken:
        print("broken internal links:\n  " + "\n  ".join(broken), file=sys.stderr)
        return 1
    print(f"built {len(b.pages)} pages into {out}" + (f" (missing: {'; '.join(b.missing)})" if b.missing else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
