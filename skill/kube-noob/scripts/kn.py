#!/usr/bin/env python3
"""kube-noob as an Agent Skill: run one kube-noob tool and print its JSON result.

    python3 -I kn.py check                     Python version and the four libraries the skill needs
    python3 -I kn.py tools                     every tool, with what it does
    python3 -I kn.py schema TOOL               the tool's arguments, as a JSON schema
    python3 -I kn.py TOOL [ARGS] [--text-file FIELD=PATH ...]
                                               run the tool; ARGS is a JSON object, @file.json or - (stdin);
                                               --text-file puts a file's text in one string field

The tools are the ones kube-noob's MCP server offers, run through the same code path (kube_noob.tool_runner): the
same validation, the same answers, the same cleaning of text shaped like instructions to a model. It runs offline:
the offline lock is on, web lookups and cluster access are off and no model is called, whatever a config file or
KUBE_NOOB_* variable says. It reads only the files named with --text-file or @file.json. Exit 0 with the result, 2
with {"error": ...} for a bad call, 3 when a library is missing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
MAX_INPUT_BYTES = 5 * 1024 * 1024  # the same cap kube-noob puts on manifests and pasted text
NEEDED = (("pydantic", "pydantic"), ("yaml", "PyYAML"), ("jsonschema", "jsonschema"), ("httpx", "httpx"))
# Settings the skill always runs with: these override the config file and the KUBE_NOOB_* variables.
OFFLINE = {"offline": True, "webEnabled": False, "cluster": {"enabled": False}, "llm": {"provider": "none"}}


def _emit(value: Any, code: int = 0) -> int:
    sys.stdout.write(json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str) + "\n")
    return code


def _missing() -> list[str]:
    import importlib.util

    return [pip for mod, pip in NEEDED if importlib.util.find_spec(mod) is None]


def _kit() -> Any:
    if str(HERE) not in sys.path[:1]:
        sys.path.insert(0, str(HERE))
    import kube_noob

    loaded = Path(kube_noob.__file__).resolve().parent
    if loaded != HERE / "kube_noob":
        raise RuntimeError(f"expected the bundled kube-noob in {HERE / 'kube_noob'}, loaded {loaded}")
    from kube_noob import toolkit
    from kube_noob.config import load_settings

    return toolkit.Toolkit(load_settings(overrides=OFFLINE))


def _read(path: str) -> str:
    p = Path(path).expanduser()
    try:
        if p.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError(f"{path} is larger than {MAX_INPUT_BYTES} bytes")
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc.strerror or exc}") from None


def _arguments(rest: list[str]) -> dict[str, Any]:
    args: dict[str, Any] = {}
    files: list[tuple[str, str]] = []
    positional: list[str] = []
    it = iter(rest)
    for item in it:
        if item == "--text-file":
            pair = next(it, "")
            field, sep, path = pair.partition("=")
            if not sep or not field or not path:
                raise ValueError("--text-file needs FIELD=PATH")
            files.append((field, path))
        else:
            positional.append(item)
    if len(positional) > 1:
        raise ValueError("give the arguments as one JSON object, @file.json or -")
    if positional:
        raw = positional[0]
        if raw == "-":
            raw = sys.stdin.read(MAX_INPUT_BYTES + 1)
        elif raw.startswith("@"):
            raw = _read(raw[1:])
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError(f"the arguments are larger than {MAX_INPUT_BYTES} bytes")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = None
        if not isinstance(parsed, dict):
            raise ValueError("the arguments are not a JSON object")
        args.update(parsed)
    for field, path in files:
        args[field] = _read(path)
    return args


def main(argv: list[str]) -> int:
    if sys.version_info < (3, 11):  # noqa: UP036 - the skill runs on whatever Python the sandbox has
        return _emit({"error": f"kube-noob needs Python 3.11 or later, found {sys.version.split()[0]}"}, 3)
    if not argv or argv[0] in {"-h", "--help", "help"}:
        sys.stdout.write(__doc__ or "")
        return 0
    missing = _missing()
    if argv[0] == "check":
        out = {"ok": not missing, "python": sys.version.split()[0], "missing": missing}
        if missing:
            out["install"] = "python3 -m pip install " + " ".join(f'"{m}"' for m in missing)
        return _emit(out, 3 if missing else 0)
    if missing:
        return _emit({"error": "missing libraries", "missing": missing, "install": "run: kn.py check"}, 3)
    kit = _kit()
    specs = {s.name: s for s in kit.specs()}
    if argv[0] == "tools":
        rows = [
            {"name": s.name, "title": s.title, "readOnly": s.read_only, "description": s.description}
            for s in sorted(specs.values(), key=lambda s: s.name)
        ]
        return _emit({"tools": rows})
    if argv[0] == "schema":
        name = argv[1] if len(argv) > 1 else ""
        if name not in specs:
            return _emit({"error": f"unknown tool {name!r}; run: kn.py tools"}, 2)
        return _emit(specs[name].model.model_json_schema())
    name = argv[0]
    if name not in specs:
        return _emit({"error": f"unknown tool {name!r}; run: kn.py tools"}, 2)
    from pydantic import ValidationError

    from kube_noob import tool_runner
    from kube_noob.errors import KubeNoobError
    from kube_noob.knowledge_status import line as knowledge_line

    try:
        args = _arguments(argv[1:])
        result = tool_runner.call(specs[name], args, knowledge_line(kit.settings.data_dir))
    except ValidationError as exc:
        return _emit({"error": f"invalid arguments: {str(exc)[:2000]}", "tool": name}, 2)
    except (KubeNoobError, ValueError, KeyError) as exc:
        detail = exc.args[0] if isinstance(exc, KeyError) and exc.args else exc
        return _emit({"error": str(detail)[:2000], "tool": name}, 2)
    return _emit(result)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
