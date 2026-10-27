"""Start the kube-noob MCP server for the Claude plugin, over stdio, from the source next to this file.

The plugin's .mcp.json runs this file with ``uv run --frozen --isolated``, so every dependency comes from the
hash-pinned ``uv.lock`` at the plugin root and nothing is downloaded from a package index for kube-noob itself: the
server is the readable copy in ``server/kube_noob`` (the modules the stdio server needs, copied unchanged from
``src/kube_noob`` by scripts/sync_plugin_server.py). It serves over stdio only, reads no credentials and never calls
a language model.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    if str(HERE) not in sys.path[:1]:
        sys.path.insert(0, str(HERE))
    import kube_noob

    loaded = Path(kube_noob.__file__).resolve().parent
    if loaded != HERE / "kube_noob":
        sys.stderr.write(f"kube-noob plugin: expected the bundled server in {HERE / 'kube_noob'}, loaded {loaded}\n")
        return 1
    from kube_noob.server.stdio import main as serve

    return serve()


if __name__ == "__main__":
    raise SystemExit(main())
