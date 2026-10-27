"""kube-noob: offline-first Kubernetes / Helm / OpenShift / ROSA HCP / StackRox learning,
manifest-audit and debugging agent.

The package is usable as:
  * an MCP server (``kube-noob mcp`` over stdio, ``kube-noob serve`` over streamable HTTP),
  * a CLI (``kube-noob audit|generate|diagnose|learn|ask ...``),
  * an OpenShift sidecar / standalone service (see ``deploy/``).

Web access is disabled by default (``webEnabled: false``); every answer is grounded in the
local knowledge base and corpus unless the operator explicitly opts in.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
