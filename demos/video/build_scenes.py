"""Turn real `kube-noob demo` output into the scene list the walkthrough player animates.

Usage: python demos/video/build_scenes.py <out-dir>   (run from the repo root, kube-noob on PATH)
Writes <out-dir>/walkthrough.html with the scenes embedded.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

CHAPTERS = [
    ("audit", "1. Audit for the platform you run", 16),
    ("diagnose", "2. Diagnose before you change anything", 12),
    ("protocol", "3. Blueprint to audited ROSA HCP manifests", 8),
    ("learn", "4. Learn Kubernetes objects, graded offline", 10),
    ("learning", "5. Remember what your team fixed", 6),
    ("posture", "6. No AI inside, no network calls: prove it", 9),
]


def _run(*args: str) -> str:
    return subprocess.run(["kube-noob", *args], capture_output=True, text=True, check=False).stdout  # noqa: S607


def _parse(text: str, max_out: int) -> list[dict[str, object]]:
    steps: list[dict[str, object]] = []
    cur: dict[str, object] | None = None
    for line in text.splitlines():
        if line.startswith("== kube-noob demo:"):
            continue
        if line.startswith("# "):
            cur = {"caption": line[2:], "command": "", "output": []}
            steps.append(cur)
        elif line.startswith("$ ") and cur is not None:
            cur["command"] = line[2:]
        elif cur is not None and (line.strip() or cur["output"]):
            cur["output"].append(line)  # type: ignore[union-attr]
    for s in steps:
        out = s["output"]
        while out and not out[-1].strip():  # type: ignore[index]
            out.pop()  # type: ignore[union-attr]
        s["output"] = out[:max_out]  # type: ignore[index]
    return steps


def main(out_dir: str) -> None:
    here = Path(__file__).parent
    scenes = [{"id": n, "chapter": title, "steps": _parse(_run("demo", n), keep)} for n, title, keep in CHAPTERS]
    scenes.append(
        {
            "id": "selftest",
            "chapter": "7. Check it yourself",
            "steps": [
                {
                    "caption": "61 real questions across Kubernetes, Helm, OpenShift 4.22, ROSA HCP and RHACS",
                    "command": "kube-noob selftest",
                    "output": _run("selftest").splitlines(),
                }
            ],
        }
    )
    html = (here / "player.html").read_text().replace("__SCENES__", json.dumps(scenes))
    Path(out_dir, "walkthrough.html").write_text(html)


if __name__ == "__main__":
    main(sys.argv[1])
