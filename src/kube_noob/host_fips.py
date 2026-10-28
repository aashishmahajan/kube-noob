"""The kernel's FIPS flag (``/proc/sys/crypto/fips_enabled``), read by ``kube-noob doctor`` and the service.

Kept in a module of its own so the Claude plugin ships without it (``scripts/sync_plugin_server.py``
GUARDED_IMPORTS): the plugin reads nothing from the user's machine beyond its own configuration and data folder.
"""

from __future__ import annotations

from pathlib import Path

FLAG = Path("/proc/sys/crypto/fips_enabled")


def kernel_fips() -> bool | None:
    """True when the kernel runs in FIPS mode, False when it does not, None when the flag cannot be read."""
    try:
        return FLAG.read_text(encoding="ascii").strip() == "1"
    except OSError:
        return None
