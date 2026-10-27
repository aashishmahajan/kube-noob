"""Security posture report: what kube-noob can reach with the effective configuration.

Used by ``kube-noob doctor`` and the ``config_status`` tool so an operator can prove the boundary instead of trusting
the defaults. A *conflict* means the configuration asks for something the offline lock forbids; the lock still wins,
but the operator should fix the configuration so intent and behaviour match.
"""

from __future__ import annotations

from typing import Any

from kube_noob.config import Settings, is_local_url


def _model_posture(provider: str, base_url: str | None) -> dict[str, Any]:
    if provider == "none":
        return {"provider": "none", "endpoint": None, "local": True}
    if provider == "anthropic":
        return {"provider": provider, "endpoint": base_url or "https://api.anthropic.com", "local": False}
    return {"provider": provider, "endpoint": base_url, "local": is_local_url(base_url)}


def posture(s: Settings) -> dict[str, Any]:
    from kube_noob import __version__
    from kube_noob.toolkit import READABLE_CONTENT_TYPES

    conflicts: list[str] = []
    warnings: list[str] = []
    if s.web_locked:
        conflicts.append(
            "webEnabled is true (config file, environment or --web-enabled) but the offline lock is on; web access "
            "stays off. Remove webEnabled or the lock so the configuration states what actually happens."
        )

    if s.web_enabled:
        web: dict[str, Any] = {
            "web": "on",
            "allowedDomains": s.web.allowed_domains,
            "methods": ["GET"],
            "schemes": ["https"],
            "contentTypes": sorted(READABLE_CONTENT_TYPES),
            "maxBytes": s.web.max_bytes,
            "writesToDisk": False,
            "executesContent": False,
        }
    else:
        web = {"web": "locked-off" if s.offline else "off"}
    web["corpusDownloads"] = "blocked" if s.offline else "only with --online or webEnabled"

    model = _model_posture(s.llm.provider, s.llm.base_url)
    model["usedBy"] = "kube-noob ask / train bench only; the MCP server never calls a model"
    if s.offline and not model["local"]:
        model["allowedByLock"] = False
        warnings.append(
            f"llm.provider {s.llm.provider!r} is not local, so `kube-noob ask` refuses under the offline lock. Set "
            "llm.provider: none, or openai-compatible with a loopback or *.svc llm.baseUrl."
        )
    judge = _model_posture(s.judge.provider, s.judge.base_url)
    if s.offline and not judge["local"]:
        warnings.append(f"judge.provider {s.judge.provider!r} is not local and will refuse under the offline lock.")

    learning = s.data_dir / "learning.json"
    return {
        "version": __version__,
        "configFile": str(s.source_path) if s.source_path else None,
        "offlineLock": s.offline,
        "network": web,
        "cluster": {
            "enabled": s.cluster.enabled,
            "access": "read-only get/logs/events with the current identity; Secrets refused; values redacted"
            if s.cluster.enabled
            else "none",
            "backend": s.cluster.backend if s.cluster.enabled else None,
        },
        "model": model,
        "judge": judge,
        "dataDir": {"path": str(s.data_dir), "exists": s.data_dir.is_dir(), "learningFile": str(learning)},
        "telemetry": "none",
        "conflicts": conflicts,
        "warnings": warnings,
        "status": "conflict" if conflicts else "ok",
    }


def render_text(p: dict[str, Any]) -> str:
    net = p["network"]
    lines = [
        f"kube-noob {p['version']} posture: {p['status'].upper()}",
        f"  offline lock   {'ON' if p['offlineLock'] else 'off'}",
        f"  web            {net['web']}"
        + (f" (GET-only HTTPS to {', '.join(net['allowedDomains'])})" if net["web"] == "on" else ""),
        f"  corpus         {net['corpusDownloads']}",
        f"  cluster        {'read-only' if p['cluster']['enabled'] else 'none'}",
        f"  agent model    {p['model']['provider']}"
        + (f" -> {p['model']['endpoint']}" if p["model"]["endpoint"] else "")
        + (" (local)" if p["model"]["local"] else " (remote)"),
        f"  data dir       {p['dataDir']['path']}",
        f"  telemetry      {p['telemetry']}",
        f"  config file    {p['configFile'] or 'none (defaults + environment)'}",
    ]
    lines += [f"CONFLICT: {c}" for c in p["conflicts"]]
    lines += [f"warning: {w}" for w in p["warnings"]]
    return "\n".join(lines)
