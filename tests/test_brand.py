"""The brand in docs/brand is one source: tokens.json, BRAND.md and the bundled fonts agree, and every video page and
script takes its fonts, colours, tagline and call to action from it (demos/video/brand.js)."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / "docs" / "brand"
VIDEO = ROOT / "demos" / "video"
PAGES = [VIDEO / "player.html", VIDEO / "thumbnail.html", VIDEO / "stage" / "stage.html"]
IMAGES = [BRAND / "social-preview.html", *sorted((BRAND / "linkedin").glob("*.html"))]
SCRIPTS = [
    VIDEO / "stage" / "videos.json",
    ROOT / "demos" / "youtube-walkthrough.md",
    ROOT / "demos" / "ai-video-prompts.md",
]


def _tokens() -> dict[str, Any]:
    return json.loads((BRAND / "tokens.json").read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def test_every_colour_token_is_documented_in_brand_md() -> None:
    t = _tokens()
    rows = [ln for ln in (BRAND / "BRAND.md").read_text(encoding="utf-8").splitlines() if ln.startswith("| `")]
    for name, hex_ in t["colors"].items():
        assert re.fullmatch(r"#[0-9A-F]{6}", hex_), (name, hex_)
        assert any(f"`{name}`" in r and f"`{hex_}`" in r for r in rows), f"BRAND.md has no row for {name} {hex_}"
    assert set(t["status"]) <= set(t["colors"])  # status colours are colours, flagged as not brand colours


def test_tagline_and_call_to_action_match_brand_md() -> None:
    t = _tokens()
    text = (BRAND / "BRAND.md").read_text(encoding="utf-8")
    assert f'**Tagline: "{t["tagline"]}"**' in text
    assert f'Spoken: "{t["spoken"]}"' in text and f"**{t['url']}**" in text


def test_bundled_fonts_match_their_provenance_and_are_noticed() -> None:
    t = _tokens()
    prov = json.loads((BRAND / "fonts" / "PROVENANCE.json").read_text(encoding="utf-8"))
    files = {name: entry for src in prov["sources"] for name, entry in src["files"].items()}
    for name, entry in files.items():
        data = (BRAND / "fonts" / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["sha256"] and len(data) == entry["bytes"], name
    assert {f["file"] for f in t["fonts"]["faces"]} <= set(files)
    assert {f["family"] for f in t["fonts"]["faces"]} == {t["fonts"]["sans"], t["fonts"]["mono"]}
    assert all(src["license"] == "OFL-1.1" for src in prov["sources"])
    assert "Inter-LICENSE.txt" in files and "JetBrainsMono-OFL.txt" in files
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    assert "Inter 4.1" in notices and "JetBrains Mono 2.304" in notices and "docs/brand/fonts/" in notices


def test_video_pages_take_fonts_and_colours_from_the_brand() -> None:
    colors = _tokens()["colors"]
    for page in PAGES:
        text = page.read_text(encoding="utf-8")
        assert "window.__KN_BRAND__" in text and "brand missing" in text, page  # refuses to render without brand.js
        assert "var(--sans)" in text and "var(--mono)" in text, page
        for system_font in ("DejaVu", "Liberation", "Helvetica", "Arial", '"Inter"', "'Inter'", 'font-family="Inter'):
            assert system_font not in text, (page, system_font)  # a machine's fonts never stand in for the brand
        lower = text.lower()
        triples = {tuple(map(int, m.groups())) for m in re.finditer(r"\b(\d{1,3}) ?, ?(\d{1,3}) ?, ?(\d{1,3})\b", text)}
        for name, hex_ in colors.items():
            assert hex_.lower() not in lower, f"{page.name} hard-codes {name} {hex_}; use var(--kn-...) or KN.tokens"
            rgb = tuple(int(hex_[i : i + 2], 16) for i in (1, 3, 5))
            assert rgb not in triples, f"{page.name} copies {name} as rgb{rgb}; use var(--kn-...-rgb) or KN.rgb"
        assert "kube-noob-icon.svg" not in text  # the icon comes from brand.js as a data: URL
    stage = (VIDEO / "stage" / "stage.html").read_text(encoding="utf-8")
    assert "tx: KN.rgb.ink" in stage and "tx: KN.rgb.dangerSoft" in stage  # terminal text is a token


def test_video_scripts_use_the_brand_call_to_action() -> None:
    spoken = _tokens()["spoken"]
    for script in SCRIPTS:
        text = script.read_text(encoding="utf-8")
        assert not re.search(r"link below", text, re.I), script  # the same video plays on the site, YouTube, LinkedIn
        assert "kube-noob dot com" in text, script
    spec = json.loads((VIDEO / "stage" / "videos.json").read_text(encoding="utf-8"))
    assert "end" not in spec  # the end card comes from tokens.json, not a copy
    for v in spec["videos"].values():
        assert not re.search(r"\(\d+ s\)", v["title"]), v["title"]  # the real running time is measured, not typed
    assert sum(spoken in s.get("vo", "") for v in spec["videos"].values() for s in v["scenes"]) >= 3


HEADLINE_UNDER_TEST = "ground truth your AI SRE checks against"  # docs/roadmap.md, the A/B test against the tagline


def test_tagline_never_sits_next_to_the_headline_under_test() -> None:
    assert HEADLINE_UNDER_TEST in (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    assert f'"The {HEADLINE_UNDER_TEST}"' in (BRAND / "BRAND.md").read_text(encoding="utf-8")
    sources = [*PAGES, VIDEO / "stage" / "videos.json", VIDEO / "build_scenes.py", ROOT / "README.md", *IMAGES]
    for f in sources:
        assert HEADLINE_UNDER_TEST.lower() not in f.read_text(encoding="utf-8").lower(), f
    desc = (ROOT / "demos" / "youtube-walkthrough.md").read_text(encoding="utf-8").split("**Description:**", 1)[1]
    desc = desc.split("```", 2)[1]
    lower = desc.lower()
    assert _tokens()["tagline"].lower().rstrip(".") in lower and HEADLINE_UNDER_TEST.lower() not in lower
    assert _tokens()["trademarks"] in desc


def _protocol_steps() -> int:
    from kube_noob.config import load_settings
    from kube_noob.toolkit import ProtocolIn, Toolkit

    blueprint = __import__("yaml").safe_load((ROOT / "examples" / "blueprint.yaml").read_text(encoding="utf-8"))
    kit = Toolkit(load_settings(overrides={"offline": True}))
    return len(kit.run_protocol(ProtocolIn(request="Deploy orders-api on ROSA HCP", blueprint=blueprint))["steps"])


def test_public_copy_counts_match_the_code() -> None:
    import yaml

    from kube_noob.audit.engine import list_rules
    from kube_noob.audit.redteam import SCENARIOS
    from kube_noob.debug.playbooks import PLAYBOOKS

    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    tracks = yaml.safe_load((ROOT / "src" / "kube_noob" / "data" / "curriculum.yaml").read_text())["tracks"]
    for phrase in (
        f"{len(list_rules())} rules",
        f"{len(PLAYBOOKS)} offline playbooks",
        f"{len(SCENARIOS)} red-team scenarios",
        f"{len(tracks)} tracks, {sum(len(t.get('lessons', [])) for t in tracks)} lessons",
        f"{_protocol_steps()}-step protocol",
    ):
        assert phrase in readme, f"README.md should say {phrase!r}"
    assert _tokens()["trademarks"] in readme  # every name the README uses, on every public page


def test_brand_images_take_fonts_colours_and_claims_from_the_brand() -> None:
    colors = _tokens()["colors"]
    for page in IMAGES:
        text = page.read_text(encoding="utf-8")
        assert "brand-page.js" in text and "var(--sans)" in text, page  # filled from the brand, refuses without it
        for system_font in ("DejaVu", "system-ui", '"Inter"', '"Inter Display"'):
            assert system_font not in text, (page, system_font)
        lower = text.lower()
        for name, hex_ in colors.items():
            assert hex_.lower() not in lower, f"{page.name} hard-codes {name} {hex_}"
        assert "cited, offline" not in text and "pipx install" not in text, page  # claims and CTA from BRAND.md
        assert not re.search(r"\b\d+ (audit )?rules\b", text), page  # a static image cannot keep a count true
    assert "window.__KN_BRAND__" in (BRAND / "brand-page.js").read_text(encoding="utf-8")
    render = (BRAND / "render.js").read_text(encoding="utf-8")
    assert "applyBrand" in render and "verifyBrand" in render


def test_walkthrough_cards_carry_no_hard_coded_repository_url() -> None:
    text = (VIDEO / "build_scenes.py").read_text(encoding="utf-8")
    assert "github.com/aashishmahajan/kube-noob" not in text and "<br>" not in text  # url from tokens, plain text


node = shutil.which("node")


@pytest.mark.skipif(node is None, reason="needs node")
def test_brand_js_refuses_a_font_that_does_not_match_its_provenance(tmp_path: Path) -> None:
    script = (
        "const b = require(process.argv[1]); const css = b.brandCSS();"
        " console.log((css.match(/@font-face/g) || []).length);"
    )
    ok = subprocess.run(
        [str(node), "-e", script, str(VIDEO / "brand.js")], capture_output=True, text=True, check=False, timeout=60
    )
    assert ok.returncode == 0 and ok.stdout.strip() == str(len(_tokens()["fonts"]["faces"])), ok.stderr
    copy = tmp_path / "brand"
    shutil.copytree(BRAND, copy)
    font = copy / "fonts" / "InterVariable.woff2"
    data = bytearray(font.read_bytes())
    data[1000] ^= 0xFF
    font.write_bytes(bytes(data))
    bad = subprocess.run(
        [str(node), "-e", script, str(VIDEO / "brand.js")],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
        env={"KN_BRAND_DIR": str(copy), "PATH": "/usr/bin:/bin"},
    )
    assert bad.returncode != 0 and "does not match PROVENANCE.json" in bad.stderr
