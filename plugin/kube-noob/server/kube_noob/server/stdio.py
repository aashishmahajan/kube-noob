"""Serve the MCP server over stdio for local clients: Claude Code, Cowork and other MCP hosts.

This is what the Claude plugin starts. It loads the settings (file and ``KUBE_NOOB_*`` variables, as the CLI does) and
serves the tools; it reads no credentials and never calls a language model.
"""

from __future__ import annotations

import sys

from kube_noob.config import load_settings
from kube_noob.errors import ConfigError
from kube_noob.server.mcp_app import build_server


def main(config: str | None = None) -> int:
    try:
        settings = load_settings(config)
    except ConfigError as exc:
        sys.stderr.write(f"kube-noob: {exc}\n")
        return 2
    build_server(settings).run("stdio")
    return 0
