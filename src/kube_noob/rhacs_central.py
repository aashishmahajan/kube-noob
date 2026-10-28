"""Read RHACS Central, read-only (``rhacs.enabled``): policies (``GET /v1/policies`` then ``GET /v1/policies/{id}``,
https://github.com/stackrox/stackrox/blob/master/proto/api/v1/policy_service.proto) and an image's scan (``GET
/v1/images/{id}`` with the image digest, returning ``storage.Image``: proto/api/v1/image_service.proto and
proto/storage/image.proto at stackrox commit dce8fb594ee287a5386fece8be1df3ee1adedc72).

The only module that reads the RHACS API token. Imported only after ``rhacs.enabled`` is checked; the Claude plugin
ships without it (``scripts/sync_plugin_server.py`` GUARDED_IMPORTS), so the plugin reads no credential.
"""

from __future__ import annotations

import os
import random
import re
import time
from collections.abc import Callable
from typing import Any

from kube_noob.errors import ConfigError, KubeNoobError, WebDisabledError
from kube_noob.rhacs import MAX_BYTES, RhacsError

DEFAULT_TOKEN_ENV = "ROX_API_TOKEN"  # noqa: S105 - the variable roxctl reads; a name, not a token


_POLICY_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class CentralClient:
    """Read-only reader of Central's policy API: ``GET /v1/policies`` then ``GET /v1/policies/{id}`` per policy, with a
    random 0.1-0.3 s pause between requests so a large policy set is not read in one burst."""

    def __init__(
        self,
        http: Any,
        endpoint: str,
        max_policies: int = 500,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self.http = http
        self.endpoint = endpoint.rstrip("/")
        self.max_policies = max_policies
        self.sleep = sleep
        self.rng = rng or random.Random()  # noqa: S311 - pacing jitter, not crypto
        self.requests = 0
        self.skipped = 0

    def _get(self, path: str) -> Any:
        if self.requests:
            self.sleep(self.rng.uniform(0.1, 0.3))
        self.requests += 1
        try:
            resp = self.http.get(self.endpoint + path)
        except KubeNoobError:
            raise
        except Exception as exc:  # connection, TLS and timeout errors surface with the path, never the token
            raise RhacsError(f"GET {path}: {type(exc).__name__}: {str(exc)[:200]}") from exc
        if resp.status_code in (401, 403):
            raise RhacsError(
                f"GET {path}: HTTP {resp.status_code}: Central refused the token; it needs read access to policies "
                "and images "
                "(for example the Analyst role)"
            )
        if resp.status_code != 200:
            raise RhacsError(f"GET {path}: HTTP {resp.status_code}")
        if len(resp.content) > MAX_BYTES:
            raise RhacsError(f"GET {path}: answer larger than {MAX_BYTES} bytes")
        try:
            return resp.json()
        except ValueError as exc:
            raise RhacsError(f"GET {path}: not JSON") from exc

    def policies(self) -> list[dict[str, Any]]:
        listed = self._get("/v1/policies")
        items = listed.get("policies") if isinstance(listed, dict) else None
        if not isinstance(items, list):
            raise RhacsError("GET /v1/policies: no policies list in the answer")
        out: list[dict[str, Any]] = []
        for item in items[: self.max_policies]:
            pid = item.get("id") if isinstance(item, dict) else None
            if not (isinstance(pid, str) and _POLICY_ID.match(pid)):
                self.skipped += 1
                continue
            full = self._get(f"/v1/policies/{pid}")
            if isinstance(full, dict):
                out.append(full)
        self.skipped += max(0, len(items) - self.max_policies)
        return out

    def image(self, digest: str) -> dict[str, Any]:
        """``GET /v1/images/{digest}``: the image with its scan (components and their vulnerabilities)."""
        if not _DIGEST.match(digest):
            raise RhacsError(f"not an image digest (sha256:<64 hex>): {digest[:80]!r}")
        doc = self._get(f"/v1/images/{digest}")
        if not isinstance(doc, dict) or not isinstance(doc.get("scan"), dict):
            raise RhacsError(f"GET /v1/images/{digest}: no scan in the answer (has Central scanned this image?)")
        return doc


def _headers(settings: Any) -> dict[str, str]:
    rh = settings.rhacs
    token_env = rh.token_env or DEFAULT_TOKEN_ENV
    if not (rh.enabled and rh.endpoint):
        raise WebDisabledError(
            "rhacs",
            "Reading RHACS Central is off (rhacs.enabled: false). Set rhacs.enabled: true and rhacs.endpoint, or "
            "compare an exported policy file instead.",
        )
    token = os.environ.get(token_env, "").strip()
    if not token:
        raise ConfigError(
            f"Set {token_env} to an RHACS API token with read access to policies and images (for example the "
            "Analyst role); "
            "kube-noob sends it only to rhacs.endpoint."
        )
    if len(token) > 8192 or any(c.isspace() or not c.isprintable() for c in token):
        raise ConfigError(f"{token_env} does not look like an API token (whitespace or control characters)")
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def read_central(
    settings: Any, *, transport: Any = None, sleep: Callable[[float], None] = time.sleep
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Central's policies (``rhacs.enabled``), with how they were read. The token never leaves this module."""
    from kube_noob.net import Purpose, http_client

    rh = settings.rhacs
    headers = _headers(settings)
    with http_client(settings, Purpose.RHACS, timeout=30, extra_headers=headers, transport=transport) as http:
        reader = CentralClient(http, rh.endpoint, rh.max_policies, sleep=sleep)
        items = reader.policies()
    source = {
        "endpoint": rh.endpoint,
        "requests": reader.requests,
        "policies": len(items),
        "skipped": reader.skipped,
    }
    return items, source


def read_images(
    settings: Any, digests: list[str], *, transport: Any = None, sleep: Callable[[float], None] = time.sleep
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Central's scans of these images (``rhacs.enabled``; the token needs read access to images, e.g. Analyst)."""
    from kube_noob.net import Purpose, http_client

    rh = settings.rhacs
    if len(digests) > 50:
        raise RhacsError("at most 50 images per run")
    headers = _headers(settings)
    with http_client(settings, Purpose.RHACS, timeout=60, extra_headers=headers, transport=transport) as http:
        reader = CentralClient(http, rh.endpoint, rh.max_policies, sleep=sleep)
        docs = [reader.image(d) for d in digests]
    return docs, {"endpoint": rh.endpoint, "requests": reader.requests, "images": len(docs)}
