"""Write docs/api/openapi.json: the REST routes (kube_noob.server.rest) with every optional route offered.

Usage: python scripts/gen_openapi.py           write it
       python scripts/gen_openapi.py --check   exit 1 if the committed document is stale (tests do the same)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from kube_noob.server.rest import full_document

OUT = Path(__file__).resolve().parents[1] / "docs" / "api" / "openapi.json"


def render() -> str:
    return json.dumps(full_document(), indent=1, sort_keys=False) + "\n"


def main(argv: list[str]) -> int:
    text = render()
    if "--check" in argv:
        if not OUT.is_file() or OUT.read_text(encoding="utf-8") != text:
            print(f"{OUT} is stale: run python scripts/gen_openapi.py", file=sys.stderr)
            return 1
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
